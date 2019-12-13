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
          setConnectionState conn Closing
          setCloseReceived conn
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
processFrame conn lvl (Crypto _off cdat) = do
    --fixme _off
    case lvl of
      InitialLevel   -> do
          atomically $ writeTQueue (inputQ conn) $ InpHandshake lvl cdat emptyToken
          return True
      RTT0Level -> do
          putStrLn $  "processFrame: invalid packet type " ++ show lvl
          return False
      HandshakeLevel -> do
          atomically $ writeTQueue (inputQ conn) $ InpHandshake lvl cdat emptyToken
          return True
      RTT1Level
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
processFrame _ _ NewToken{} = do
    putStrLn "FIXME: NewToken"
    return True
processFrame _ _ (NewConnectionID sn _ _cid _token)  = do
    -- fixme: register stateless token
    putStrLn $ "FIXME: NewConnectionID " ++ show sn
    return True
processFrame conn _ (ConnectionCloseQUIC err _ftyp _reason) = do
    atomically $ writeTQueue (inputQ conn) $ InpEerror err
    setConnectionState conn Closing
    setCloseReceived conn
    setCloseSent conn
    clearThreads conn
    return False
processFrame conn _ (ConnectionCloseApp err _reason) = do
    putStrLn $ "App: " ++ show err
    atomically $ writeTQueue (inputQ conn) $ InpEerror err
    setConnectionState conn Closing
    setCloseReceived conn
    setCloseSent conn
    clearThreads conn
    return False
processFrame conn RTT1Level (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ conn) $ InpStream sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ conn) $ InpStream sid ""
    return True
processFrame conn lvl Ping = do
    atomically $ writeTQueue (outputQ conn) $ OutControl lvl []
    return True
processFrame _ _ _frame        = do
    -- This includes Ping which should be just acknowledged.
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
