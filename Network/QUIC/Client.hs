{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Client (
    handshake
  , sendData
  , recvData
  ) where

import Network.QUIC.Imports
import Network.QUIC.Transport

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Network.TLS.QUIC

----------------------------------------------------------------

constructCryptoFrame :: Context -> CryptoData -> IO Frame
constructCryptoFrame ctx crypto = do
    let len = B.length crypto
    off' <- atomicModifyIORef' (cryptoOffset ctx) (\off -> (off+len, off))
    return $ Crypto off' crypto

----------------------------------------------------------------

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

----------------------------------------------------------------

handshake :: Context -> IO ()
handshake ctx = do
    ci <- createClientInitial ctx
    ctxSend ctx ci
    si <- ctxRecv ctx
    (cf, rest) <- handleServerInitial ctx si
    ci2 <- createClientInitial2 ctx cf
    ctxSend ctx ci2
    processPacket ctx rest

----------------------------------------------------------------

processPacket :: Context -> ByteString -> IO ()
processPacket _ "" = return ()
processPacket ctx bin = do
    (pkt, rest) <- decodePacket ctx bin
    case pkt of
      InitialPacket   _ _ _ _ pn fs -> do
          addInitialPNs ctx pn
          putStrLn $ "I: " ++ show fs
          constructInitialPacket ctx [] >>= ctxSend ctx
      HandshakePacket _ _ _   pn fs -> do
          addHandshakePNs ctx pn
          putStrLn $ "H: " ++ show fs
          constructHandshakePacket ctx [] >>= ctxSend ctx
      ShortPacket     _       pn fs -> do
          addApplicationPNs ctx pn
          putStrLn $ "S: " ++ show fs
          -- fixme new session ticket
          constructShortPacket ctx [] >>= ctxSend ctx
      _                              -> undefined
    processPacket ctx rest

----------------------------------------------------------------

createClientInitial :: Context -> IO ByteString
createClientInitial ctx = do
    SendClientHello ch _ <- tlsClientHandshake ctx $ GetClientHello
    cframe <- constructCryptoFrame ctx ch
    let frames = cframe :  replicate 963 Padding
    constructInitialPacket ctx frames

handleServerInitial :: Context -> ByteString -> IO (ByteString,ByteString)
handleServerInitial ctx si = do
    (InitialPacket Draft23 dcid0 scid0 _tkn0 pnI frames, rest) <- decodePacket ctx si
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
    ref <- newIORef Nothing
    mapM_ (handle ref) frames
    mx <- readIORef ref
    case mx of
      Nothing -> handleServerHandshake ctx rest
      Just tlsch -> do
          cframe <- constructCryptoFrame ctx tlsch
          let frames1 = cframe :  replicate 963 Padding
          ci <- constructInitialPacket ctx frames1
          ctxSend ctx ci
          si1 <- ctxRecv ctx
          handleServerInitial ctx si1
  where
    handle _ Padding = return ()
    handle _ (ConnectionClose _errcode reason) = do
        C8.putStrLn reason
        error "ConnectionClose"
    handle ref (Crypto _off sh) = do
        ctl <- tlsClientHandshake ctx $ PutServerHello sh
        case ctl of
          RecvServerHello cipher handSecrets -> do
              writeIORef (handshakeSecret ctx) $ Just handSecrets
              setCipher ctx cipher
          SendClientHello tlsch _ -> do
              writeIORef ref $ Just tlsch
          _ -> error "XXX"
    handle _ (Ack _ _ _ _) = return ()
    handle _ _frame        = error $ show _frame

handleServerHandshake :: Context -> ByteString -> IO (ByteString, ByteString)
handleServerHandshake ctx bs0 = loop bs0
  where
    loop bs = do
        (HandshakePacket Draft23 _dcid1 _scid1 pnH [Crypto _ eefin], rest) <- decodePacket ctx bs
        addHandshakePNs ctx pnH
        ctl <- tlsClientHandshake ctx $ PutServerFinished eefin
        case ctl of
          ClientNeedsMore -> do
              bs1 <- ctxRecv ctx
              loop (rest `B.append` bs1)
          SendClientFinished cf exts alpn appSecrets -> do
              case exts of
                [ExtensionRaw 0xffa5 params] -> do
                    -- fixme: alpn
                    print alpn
                    let Just plist = decodeParametersList params
                    setPeerParameters ctx plist
                _ -> return ()
              writeIORef (applicationSecret ctx) $ Just appSecrets
              return (cf, rest)
          _ -> error "handleServerHandshake"

createClientInitial2 :: Context -> ByteString -> IO ByteString
createClientInitial2 ctx tlscf = do
    bin0 <- constructInitialPacket ctx []
    let cframe = Crypto 0 tlscf -- fixme
    bin1 <- constructHandshakePacket ctx [cframe]
    return (B.concat [bin0, bin1])

sendData :: Context -> ByteString -> IO ()
sendData ctx bs = do
    bin <- constructShortPacket ctx [Stream 0 0 bs True]
    ctxSend ctx bin

recvData :: Context -> IO ()
recvData ctx = do
    ctxRecv ctx >>= processPacket ctx

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
