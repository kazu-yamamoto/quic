{-# LANGUAGE MultiWayIf #-}
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
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

import Network.QUIC.Imports
import Network.QUIC.Stream.Misc
import Network.QUIC.Stream.Queue
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
    | -- | Nothing that had not been delivered or held already.
      Duplicated
    | -- | Taken, with the number of octets which are new.
      Reassembled Int
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

-- | Take the octets of a fragment which are neither delivered nor held,
--   deliver whatever that makes contiguous, and say how many were new.
--
-- What is held is kept disjoint, so a copy sent again with other boundaries
-- -- a retransmission, or a CRYPTO flight repacketized after a PTO -- adds
-- exactly what it brings, and the count of pieces held is the true one.
tryReassemble
    :: Stream -> RxStreamData -> (StreamData -> IO ()) -> IO () -> IO FlowCntl
tryReassemble Stream{..} (RxStreamData dat off len fin) put putFin = do
    StreamState off0 fin0 <- readIORef streamStateRx
    Reass held mfin <- readIORef streamReass
    let new = uncovered held (max off off0) $ BS.drop (off0 - off) dat
        newLen = sum $ map (BS.length . snd) new
        -- 'streamFin' is set by the first FIN, or when we stop receiving.
        finNew = fin && not fin0
        mfin1 = if finNew then Just (off + len) else mfin
        (ready, held1, off1) = deliverable off0 $ foldr (uncurry Map.insert) held new
        done = mfin1 == Just off1
    if
        | newLen == 0 && not finNew -> return Duplicated
        | Map.size held1 > maxReassFragments -> return TooFragmented
        | otherwise -> do
            writeIORef streamReass $ Reass held1 $ if done then Nothing else mfin1
            atomicModifyIORef'' streamStateRx $ \(StreamState _ f) ->
                StreamState off1 (f || fin)
            mapM_ put ready
            when done putFin
            return $ Reassembled newLen

-- | The parts of the octets at an offset which no held piece covers.
uncovered
    :: Map Offset StreamData -> Offset -> StreamData -> [(Offset, StreamData)]
uncovered held = go
  where
    go s d
        | BS.null d = []
        | Just (k, v) <- Map.lookupLE s held
        , k + BS.length v > s =
            let e = k + BS.length v in go e $ BS.drop (e - s) d
        | Just (k, _) <- Map.lookupGT s held
        , k < s + BS.length d =
            let (d1, d2) = BS.splitAt (k - s) d in (s, d1) : go k d2
        | otherwise = [(s, d)]

-- | The pieces which follow on from an offset, without a gap.
deliverable
    :: Offset
    -> Map Offset StreamData
    -> ([StreamData], Map Offset StreamData, Offset)
deliverable o m = case Map.minViewWithKey m of
    Just ((k, d), m')
        | k == o ->
            let (ds, m'', o') = deliverable (o + BS.length d) m'
             in (d : ds, m'', o')
    _ -> ([], m, o)
