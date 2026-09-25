{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Reass (
    takeRecvStreamQwithSize,
    putRxStreamData,
    putRxCryptoData,
    FlowCntl (..),
    tryReassemble,
) where

import qualified Data.ByteString as BS
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq

import Network.QUIC.Imports
import Network.QUIC.Stream.Frag
import Network.QUIC.Stream.Misc
import Network.QUIC.Stream.Queue
import qualified Network.QUIC.Stream.Skew as Skew
import Network.QUIC.Stream.Types
import Network.QUIC.Types

----------------------------------------------------------------

getEndOfStream :: Stream -> IO Bool
getEndOfStream Stream{..} = readIORef $ endOfStream streamRecvQ

setEndOfStream :: Stream -> IO ()
setEndOfStream Stream{..} = writeIORef (endOfStream streamRecvQ) True

readPendingData :: Stream -> IO (Maybe ByteString)
readPendingData Stream{..} = readIORef $ pendingData streamRecvQ

writePendingData :: Stream -> ByteString -> IO ()
writePendingData Stream{..} bs = writeIORef (pendingData streamRecvQ) $ Just bs

clearPendingData :: Stream -> IO ()
clearPendingData Stream{..} = writeIORef (pendingData streamRecvQ) Nothing

----------------------------------------------------------------

takeRecvStreamQwithSize
    :: Stream
    -> Int
    -- ^ Number of bytes to receive.
    -> IO ByteString
takeRecvStreamQwithSize strm siz0 = do
    eos <- getEndOfStream strm
    if eos
        then return ""
        else do
            mb <- readPendingData strm
            case mb of
                Nothing -> do
                    b0 <- takeRecvStreamQ strm
                    if b0 == ""
                        then do
                            setEndOfStream strm
                            return ""
                        else handleBytes b0
                Just b0 -> do
                    clearPendingData strm
                    handleBytes b0
  where
    handleBytes b0 =
        let len = BS.length b0
         in case len `compare` siz0 of
                LT -> tryRead (siz0 - len) (b0 :)
                EQ -> return b0
                GT -> do
                    let (b1, b2) = BS.splitAt siz0 b0
                    writePendingData strm b2
                    return b1
    tryRead siz build = do
        mb <- tryTakeRecvStreamQ strm
        case mb of
            Nothing -> return $ BS.concat $ build []
            Just b -> do
                if b == ""
                    then do
                        setEndOfStream strm
                        return $ BS.concat $ build []
                    else do
                        let len = BS.length b
                        case len `compare` siz of
                            LT -> tryRead (siz - len) (build . (b :))
                            EQ -> return $ BS.concat $ build [b]
                            GT -> do
                                let (b1, b2) = BS.splitAt siz b
                                writePendingData strm b2
                                return $ BS.concat $ build [b1]

----------------------------------------------------------------
----------------------------------------------------------------

data FlowCntl
    = -- | Past the octets the peer is allowed to have outstanding.
      OverLimit
    | -- | Past the number of separate pieces we will hold for one stream.
      TooFragmented
    | Duplicated
    | Reassembled
    deriving (Eq, Show)

putRxStreamData :: Stream -> RxStreamData -> IO FlowCntl
putRxStreamData s rx@(RxStreamData _ off len _) = do
    lim <- getRxMaxStreamData s
    if len + off > lim
        then return OverLimit
        else do
            tryReassemble s rx put putFin
  where
    put "" = return ()
    put d = do
        addRxStreamData s $ BS.length d
        putRecvStreamQ s d
    putFin = putRecvStreamQ s ""

-- | Feed a CRYPTO frame to the reassembly of its stream, refusing anything
--   that would leave us holding more than @lim@ octets past the point the
--   stream has reached in order.
--
-- CRYPTO frames sit outside the flow control that bounds stream data -- they
-- have to, since they carry the handshake that settles those limits -- so
-- this is the only thing standing between a peer and an unbounded pile of
-- fragments at scattered offsets.  Bounding the window bounds the pile: every
-- fragment we keep lies within it.
putRxCryptoData
    :: Stream -> Int -> RxStreamData -> (StreamData -> IO ()) -> IO FlowCntl
putRxCryptoData s lim rx@(RxStreamData _ off len _) put = do
    StreamState off0 _ <- readIORef $ streamStateRx s
    if off + len > off0 + lim
        then return OverLimit
        else tryReassemble s rx put (return ())

-- fin of StreamState off fin means see-fin-already.
tryReassemble
    :: Stream -> RxStreamData -> (StreamData -> IO ()) -> IO () -> IO FlowCntl
tryReassemble Stream{} (RxStreamData "" _ _ False) _ _ = return Duplicated
tryReassemble Stream{..} x@(RxStreamData "" off _ True) _ putFin = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let si1 = si0{streamFin = True}
    if fin0
        then do
            -- stdoutLogger "Illegal Fin" -- fixme
            return Duplicated
        else case off `compare` off0 of
            LT -> return Duplicated
            EQ -> do
                writeIORef streamStateRx si1
                putFin
                return Reassembled
            GT -> do
                writeIORef streamStateRx si1
                hold streamReass x
tryReassemble Stream{..} x@(RxStreamData dat off len False) put putFin = do
    si0@(StreamState off0 _) <- readIORef streamStateRx
    case off `compare` off0 of
        LT -> return Duplicated
        EQ -> do
            put dat
            loop si0 (off0 + len)
            return Reassembled
        GT -> hold streamReass x
  where
    loop si0 xff = do
        mrxs <- atomicModifyIORef' streamReass $ \(n, sk) ->
            let (sk', mrxs) = Skew.deleteMinIf xff sk
             in ((n - maybe 0 length mrxs, sk'), mrxs)
        case mrxs of
            Nothing -> writeIORef streamStateRx si0{streamOffset = xff}
            Just rxs -> do
                mapM_ (put . rxstrmData) rxs
                let xff1 = nextOff rxs
                if hasFin rxs
                    then do
                        putFin
                    else do
                        loop si0 xff1
tryReassemble Stream{..} x@(RxStreamData dat off len True) put putFin = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let si1 = si0{streamFin = True}
    if fin0
        then return Duplicated
        else case off `compare` off0 of
            LT -> return Duplicated
            EQ -> do
                let off1 = off0 + len
                writeIORef streamStateRx si1{streamOffset = off1}
                put dat
                putFin
                return Reassembled
            GT -> do
                writeIORef streamStateRx si1
                hold streamReass x

-- | Keep a fragment that cannot be delivered yet, unless we are already
--   holding as many as we are willing to.
--
-- Flow control bounds the octets, not the pieces, and a peer that sends its
-- window one octet at a time at scattered offsets pays for the octets while
-- we pay for the pieces.
hold :: IORef (Int, Skew.Skew RxStreamData) -> RxStreamData -> IO FlowCntl
hold ref x = atomicModifyIORef' ref $ \st@(n, sk) ->
    if n >= maxReassFragments
        then (st, TooFragmented)
        else ((n + 1, Skew.insert x sk), Reassembled)

hasFin :: Seq RxStreamData -> Bool
hasFin s = case Seq.viewr s of
    Seq.EmptyR -> False
    _ Seq.:> x -> rxstrmFin x
