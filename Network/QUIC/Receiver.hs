{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Types

receiver :: Connection -> IO ()
receiver conn = forever $ do
    cpkts <- connRecv conn
    mapM_ (processCryptPacket conn) cpkts

processCryptPacket :: Connection -> CryptPacket -> IO ()
processCryptPacket conn (CryptPacket header crypt) = do
    let level = packetEncryptionLevel header
    checkEncryptionLevel conn level
    when (isClient conn && level == HandshakeLevel) $
        setPeerCID conn $ headerPeerCID header
    statelessReset <- isStateLessreset conn header crypt
    if statelessReset then do
          putStrLn "Connection is reset statelessly"
          setConnectionState conn $ Closing $ CloseState False True
          clearThreads conn
      else do
        eplain <- decryptCrypt conn crypt level
        case eplain of
          Right (Plain _ pn fs) -> do
              rets <- mapM (processFrame conn level) fs
              when (and rets) $ addPNs conn level pn
          Left err -> print err

processFrame :: Connection -> EncryptionLevel -> Frame -> IO Bool
processFrame _ _ Padding{} = return True
processFrame conn _ (Ack ackInfo _) = do
    let pns = fromAckInfo ackInfo
    outs <- catMaybes <$> mapM (releaseOutput conn) pns
    mapM_ (removeAcks conn) outs
    return True
processFrame conn lvl (Crypto off cdat) = do
    case lvl of
      InitialLevel   -> do
          atomically $ writeTQueue (cryptoQ conn) $ InpHandshake lvl cdat off emptyToken
          return True
      RTT0Level -> do
          putStrLn $ "processFrame: invalid packet type " ++ show lvl
          return False
      HandshakeLevel
          | isClient conn -> do
              atomically $ writeTQueue (cryptoQ conn) $ InpHandshake lvl cdat off emptyToken
              return True
         | otherwise -> do
              control <- getServerController conn
              SendSessionTicket nst <- control $ PutClientFinished cdat
              -- fixme: vs sendCryptoData
              atomically $ writeTQueue (outputQ conn) $ OutHndServerNST nst
              ServerHandshakeDone <- control ExitServer
              clearServerController conn
              return True
      RTT1Level
        | isClient conn -> do
              control <- getClientController conn
              RecvSessionTicket   <- control $ PutSessionTicket cdat
              ClientHandshakeDone <- control ExitClient
              clearClientController conn
              return True
        | otherwise -> do
              putStrLn "processFrame: Short:Crypto for server"
              return False
processFrame conn _ (NewToken token) = do
    setNewToken conn token
    return True
processFrame _ _ (NewConnectionID _sn _ _cid _token)  = do
    -- fixme: register stateless token
--    putStrLn $ "FIXME: NewConnectionID " ++ show sn
    return True
processFrame conn _ (ConnectionCloseQUIC err ftyp reason) = do
    atomically $ writeTQueue (inputQ conn)  $ InpTransportError err ftyp reason
    -- to cancel handshake
    atomically $ writeTQueue (cryptoQ conn) $ InpTransportError err ftyp reason
    setConnectionState conn $ Closing $ CloseState True True
    clearThreads conn
    return False
processFrame conn _ (ConnectionCloseApp err reason) = do
    putStrLn $ "App: " ++ show err
    atomically $ writeTQueue (inputQ conn)  $ InpApplicationError err reason
    -- to cancel handshake
    atomically $ writeTQueue (cryptoQ conn) $ InpApplicationError err reason
    setConnectionState conn $ Closing $ CloseState True True
    clearThreads conn
    return False
processFrame conn RTT0Level (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ conn) $ InpStream sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ conn) $ InpStream sid ""
    return True
processFrame conn RTT1Level (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ conn) $ InpStream sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ conn) $ InpStream sid ""
    return True
processFrame conn lvl Ping = do
    atomically $ writeTQueue (outputQ conn) $ OutControl lvl []
    return True
processFrame _ _ _frame        = do
    putStrLn "FIXME: processFrame"
    print _frame
    return True

-- QUIC version 1 uses only short packets for stateless reset.
-- But we should check other packets, too.
isStateLessreset :: Connection -> Header -> Crypt -> IO Bool
isStateLessreset conn header Crypt{..}
  | myCID conn /= headerMyCID header = do
        params <- getPeerParameters conn
        case statelessResetToken params of
          Nothing -> return False
          mtoken  -> do
              let mtoken' = decodeStatelessResetToken cryptPacket
              return (mtoken == mtoken')
  | otherwise = return False
