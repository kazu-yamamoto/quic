{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Client (handshake) where

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Network.TLS hiding (Context, handshake)

constructInitialPacket :: Context -> [Frame] -> IO ByteString
constructInitialPacket ctx frames = do
    let mycid = myCID ctx
    peercid <- readIORef $ peerCID ctx
    mypn <- getPacketNumber ctx
    pns <- clearInitialPNs ctx
    let frames'
          | pns == [] = frames
          | otherwise = constructAskFrame pns : frames
    let iniPkt = InitialPacket Draft23 peercid mycid "" mypn frames'
    encodePacket ctx iniPkt

constructHandshakePacket :: Context -> [Frame] -> IO ByteString
constructHandshakePacket ctx frames = do
    let mycid = myCID ctx
    peercid <- readIORef $ peerCID ctx
    mypn <- getPacketNumber ctx
    pns <- clearHandshakePNs ctx
    let frames'
          | pns == [] = frames
          | otherwise = constructAskFrame pns : frames
    let hndPkt = HandshakePacket Draft23 peercid mycid mypn frames'
    encodePacket ctx hndPkt

constructShortPacket :: Context -> [Frame] -> IO ByteString
constructShortPacket ctx frames = do
    peercid <- readIORef $ peerCID ctx
    mypn <- getPacketNumber ctx
    pns <- clearApplicationPNs ctx
    let frames'
          | pns == [] = frames
          | otherwise = constructAskFrame pns : frames
    let appPkt = ShortPacket peercid mypn frames'
    encodePacket ctx appPkt

handshake :: Context -> IO ()
handshake ctx = do
    (iniBin, ch) <- createClientInitial ctx
    ctxSend ctx iniBin
    shBin <- ctxRecv ctx
    (eefins, rest) <- handleServerInitial ctx shBin ch
    iniBin2 <- createClientInitial2 ctx eefins
    getNegotiatedProtocol (tlsConetxt ctx) >>= print
    ctxSend ctx iniBin2
    processPacket ctx rest
    ctxRecv ctx >>= processPacket ctx

processPacket :: Context -> ByteString -> IO ()
processPacket _ "" = return ()
processPacket ctx bin = do
    (pkt, rest) <- decodePacket ctx bin
    case pkt of
      InitialPacket   _ _ _ _ pn fs -> do
          addInitialPNs ctx pn
          print fs
          constructInitialPacket ctx [] >>= ctxSend ctx
      HandshakePacket _ _ _   pn fs -> do
          addHandshakePNs ctx pn
          print fs
          constructHandshakePacket ctx [] >>= ctxSend ctx
      ShortPacket     _       pn fs -> do
          addApplicationPNs ctx pn
          print fs
          constructShortPacket ctx [] >>= ctxSend ctx
      _                              -> undefined
    processPacket ctx rest

exampleParameters :: Parameters
exampleParameters = defaultParameters {
    maxStreamDataBidiLocal  =  262144
  , maxStreamDataBidiRemote =  262144
  , maxStreamDataUni        =  262144
  , maxData                 = 1048576
  , maxStreamsBidi          =       1
  , maxStreamsUni           =     100
  , idleTimeout             =   30000
  , activeConnectionIdLimit =       7
  }

createClientInitial :: Context -> IO (ByteString, Handshake13)
createClientInitial ctx = do
    let params = encodeParametersList $ diffParameters exampleParameters
    (ch, chbin) <- makeClientHello13 cparams tlsctx params
    let frames = Crypto 0 chbin :  replicate 963 Padding
    iniBin <- constructInitialPacket ctx frames
    return (iniBin, ch)
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx

handleServerInitial :: Context -> ByteString -> Handshake13 -> IO (ByteString, ByteString)
handleServerInitial ctx shBin ch = do
    (InitialPacket Draft23 dcid0 scid0 _tkn0 pnI frames, hdskPktBin0) <- decodePacket ctx shBin
    addInitialPNs ctx pnI
    when (dcid0 /= myCID ctx) $ error "DCID is not the same"
    peercid <- readIORef $ peerCID ctx
    putStr "My "
    print $ myCID ctx
    if scid0 /= peercid then do
        putStrLn $ "Peer changes " ++ show peercid ++ " to " ++ show scid0
        writeIORef (peerCID ctx) scid0
      else do
        putStr "Peer "
        print scid0
    mapM_ handle frames
    (HandshakePacket Draft23 dcid1 scid1 pnH0 [Crypto _ eefin0], "") <- decodePacket ctx hdskPktBin0
    addHandshakePNs ctx pnH0
    when (dcid1 /= myCID ctx) $ error "DCID is not the same"
    when (scid1 /= scid0) $ error "SCID is not the same"
    (eefins,rest) <- ctxRecvEefin1Bin ctx eefin0
    let ehs = decodeHandshakes13 eefins
    case ehs of
      Right []     -> error "handleServerInitial []"
      Right (ee:_) -> case handleServerEncryptedExtensions ee of
        Nothing -> error "No QUIC params"
        Just bs -> print $ decodeParametersList bs -- fixme: updating params
      Left e       -> print e
    return (eefins, rest)
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx
    handle Padding = return ()
    handle (ConnectionClose _errcode reason) = do
        C8.putStrLn reason
        error "ConnectionClose"
    handle (Crypto _off sh) = do
        (cipher, handSecret, _resuming) <- handleServerHello13 cparams tlsctx ch sh
        setCipher ctx cipher
        writeIORef (handshakeSecret ctx) $ Just handSecret
    handle (Ack _ _ _ _) = return ()
    handle _frame        = error $ show _frame

ctxRecvEefin1Bin :: Context -> ByteString -> IO (ByteString, ByteString)
ctxRecvEefin1Bin ctx eefin0 = do
    check <- handshakeCheck finished eefin0 Start
    case check of
      Done -> return (eefin0, "")
      cont -> loop cont (eefin0 :)
  where
    finished = 20
    loop cont buildB = do
        bin <- ctxRecv ctx
        (HandshakePacket Draft23 _ _ pnH [Crypto _ eefin], rest) <- decodePacket ctx bin
        addHandshakePNs ctx pnH
        check <- handshakeCheck finished eefin cont
        let buildB' = buildB . (eefin :)
        case check of
          Done  -> return (B.concat $ buildB' [], rest)
          cont' -> loop cont' buildB' -- rest should be ""

createClientInitial2 :: Context -> ByteString -> IO ByteString
createClientInitial2 ctx eefin = do
    bin0 <- constructInitialPacket ctx []
    Just handSecret <- readIORef $ handshakeSecret ctx
    (crypto, appSecret) <- makeClientFinished13 cparams tlsctx eefin handSecret False
    writeIORef (applicationSecret ctx) $ Just appSecret
    bin1 <- constructHandshakePacket ctx [Crypto 0 crypto]
    bin2 <- constructShortPacket ctx [Stream 0 0 "GET /\r\n" True]
    return (B.concat [bin0, bin1, bin2])
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx

-- |
-- >>> constructAskFrame [9]
-- Ack 9 0 0 []
-- >>> constructAskFrame [9,8,7]
-- Ack 9 0 2 []
-- >>> constructAskFrame [8,7,3,2]
-- Ack 8 0 1 [(2,1)]
-- >>> constructAskFrame [9,8,7,5,4]
-- Ack 9 0 2 [(0,1)]
constructAskFrame :: [PacketNumber] -> Frame
constructAskFrame []  = error "constructAskFrame"
constructAskFrame [l] = Ack l 0 0 []
constructAskFrame (l:ls)  = ack l ls 0
  where
    ack _ []     fr = Ack l 0 fr []
    ack p (x:xs) fr
      | p - 1 == x  = ack x xs (fr+1)
      | otherwise   = Ack l 0 fr $ ranges x xs (fromIntegral (p - x) - 2) 0
    ranges _ [] g r = [(g, r)]
    ranges p (x:xs) g r
      | p - 1 == x  = ranges x xs g (r+1)
      | otherwise   = (g, r) : ranges x xs (fromIntegral(p - x) - 2) 0
