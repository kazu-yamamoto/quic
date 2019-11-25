{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Receiver where

import Control.Concurrent
import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport
import Network.QUIC.Types

-- |
-- >>> deconstructAckFrame $ Ack 9 0 0 []
-- [9]
-- >>> deconstructAckFrame $ Ack 9 0 2 []
-- [7,8,9]
-- >>> deconstructAckFrame $ Ack 8 0 1 [(2,1)]
-- [2,3,7,8]
-- >>> deconstructAckFrame $ Ack 9 0 2 [(0,1)]
-- [4,5,7,8,9]
deconstructAckFrame :: Frame -> [PacketNumber]
deconstructAckFrame (Ack lpn _ fr grs) = loop grs [stt .. lpn]
  where
    stt = lpn - fromIntegral fr
    loop _          []        = error "loop"
    loop []         acc       = acc
    loop ((g,r):xs) acc@(s:_) = loop xs ([z - fromIntegral r .. z] ++ acc)
      where
        z = s - fromIntegral g - 2
deconstructAckFrame _ = error "deconstructAckFrame"

receiver :: Connection -> IO ()
receiver conn = forever $ do
    bs <- connRecv conn
    processPackets conn bs

processPackets :: Connection -> ByteString -> IO ()
processPackets conn bs0 = loop bs0
  where
    loop "" = return ()
    loop bs = do
        let level = packetEncryptionLevel bs
        checkEncryptionLevel conn level
        (pkt, rest) <- decodePacket conn bs
        processPacket conn pkt
        loop rest

processPacket :: Connection -> Packet -> IO ()
processPacket conn (InitialPacket   _ _ _ _ pn fs) = do
--    putStrLn $ "I: " ++ show fs
    rets <- mapM (processFrame conn Initial) fs
    when (and rets) $ addPNs conn Initial pn
processPacket conn (HandshakePacket _ _ peercid   pn fs) = do
--    putStrLn $ "H: " ++ show fs
    when (isClient conn) $ setPeerCID conn peercid
    rets <- mapM (processFrame conn Handshake) fs
    when (and rets) $ addPNs conn Handshake pn
processPacket conn (ShortPacket     _       pn fs) = do
--    putStrLn $ "S: " ++ show fs
    rets <- mapM (processFrame conn Short) fs
    when (and rets) $ addPNs conn Short pn
processPacket conn (RetryPacket ver _ sCID _ token)  = do
    -- The packet number of first crypto frame is 0.
    -- This ensures that retry can be accepted only once.
    mr <- releaseSegment conn 0
    case mr of
      Just (Retrans (H pt cdat _) _ _) -> do
          -- fixme: many checking
          setPeerCID conn sCID
          setInitialSecrets conn $ initialSecrets ver sCID
          atomically $ writeTQueue (outputQ conn) $ H pt cdat token
      _ -> return ()
processPacket _ _ = undefined

processFrame :: Connection -> PacketType -> Frame -> IO Bool
processFrame _ _ Padding = return True
processFrame conn _ ack@Ack{} = do
    let pns = deconstructAckFrame ack
    segs <- catMaybes <$> mapM (releaseSegment conn) pns
    mapM_ (clearAcks conn) segs
    return True
processFrame conn pt (Crypto _off cdat) = do
    --fixme _off
    case pt of
      Initial   -> do
          atomically $ writeTQueue (inputQ conn) $ H pt cdat emptyToken
          return True
      Handshake -> do
          atomically $ writeTQueue (inputQ conn) $ H pt cdat emptyToken
          return True
      Short
        | isClient conn -> do
              -- fixme: checkint key phase
              control <- getClientController conn
              RecvSessionTicket   <- control $ PutSessionTicket cdat
              ClientHandshakeDone <- control ExitClient
              clearClientController conn
              return True
        | otherwise -> do
              putStrLn "processFrame: Short:Crypto for server"
              return False
      _         -> do
          putStrLn $  "processFrame: invalid packet type " ++ show pt
          return False
processFrame _ _ NewToken{} = do
    putStrLn "FIXME: NewToken"
    return True
processFrame _ _ (NewConnectionID sn _ _ _)  = do
    putStrLn $ "FIXME: NewConnectionID " ++ show sn
    return True
processFrame conn pt (ConnectionCloseQUIC err _ftyp _reason) = do
    case pt of
      Initial   -> atomically $ writeTQueue (inputQ conn) $ E err
      Handshake -> atomically $ writeTQueue (inputQ conn) $ E err
      _         -> return ()
    setConnectionStatus conn Closing
    setCloseReceived conn
    sent <- isCloseSent conn
    let frames
          | sent      = [] -- for acking
          | otherwise = [ConnectionCloseApp NoError ""]
    setCloseSent conn
    atomically $ writeTQueue (outputQ conn) $ C pt frames
    threadDelay 100000 -- fixme
    return True
processFrame conn pt (ConnectionCloseApp err _reason) = do
    putStrLn $ "App: " ++ show err
    setConnectionStatus conn Closing
    setCloseReceived conn
    sent <- isCloseSent conn
    let frames
          | sent      = [] -- for acking
          | otherwise = [ConnectionCloseApp NoError ""]
    setCloseSent conn
    atomically $ writeTQueue (outputQ conn) $ C pt frames
    threadDelay 100000 -- fixme
    return True
processFrame conn Short (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ conn) $ S sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ conn) $ S sid ""
    return True
processFrame _ _ _frame        = do
    putStrLn "FIXME: processFrame"
    print _frame
    return True
