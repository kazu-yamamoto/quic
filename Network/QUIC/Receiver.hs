{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import Network.TLS.QUIC
import System.Timeout

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Types

receiver :: Connection -> IO ()
receiver conn = E.handle (handler "receiver") $ forever
    (connRecv conn >>= processCryptPacket conn)

processCryptPacket :: Connection -> CryptPacket -> IO ()
processCryptPacket conn (CryptPacket header crypt) = do
    let level = packetEncryptionLevel header
    -- If RTT1 comes just after Initial, checkEncryptionLevel
    -- waits forever. To avoid this, timeout used.
    -- If timeout happens, the packet cannot be decrypted
    -- and thrown away.
    mt <- timeout 100000 $ checkEncryptionLevel conn level
    if isNothing mt then
        putStrLn "Timeout: ignoring a packet"
      else do
        when (isClient conn && level == HandshakeLevel) $
            setPeerCID conn $ headerPeerCID header
        mplain <- decryptCrypt conn crypt level
        case mplain of
          Just (Plain _ pn fs) -> do
              -- For Ping, record PPN first, then send an ACK.
              -- fixme: need to check Sec 13.1
              addPeerPacketNumbers conn level pn
              mapM_ (processFrame conn level) fs
          Nothing -> do
              statelessReset <- isStateLessreset conn header crypt
              if statelessReset then do
                  putStrLn "Connection is reset statelessly"
                  setCloseReceived conn
                  clearThreads conn
                else do
                  putStrLn $ "Cannot decrypt: " ++ show level
                  return () -- fixme: sending statelss reset

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn _ (Ack ackInfo _) = do
    let pns = fromAckInfo ackInfo
    mapM_ (releasePlainPacketRemoveAcks conn) pns
processFrame conn lvl (Crypto off cdat) = do
    case lvl of
      InitialLevel   -> do
          putInputCrypto conn lvl off cdat
      RTT0Level -> do
          putStrLn $ "processFrame: invalid packet type " ++ show lvl
      HandshakeLevel
          | isClient conn -> do
              putInputCrypto conn lvl off cdat
         | otherwise -> do
              control <- getServerController conn
              res <- control $ PutClientFinished cdat
              case res of
                SendSessionTicket nst -> do
                    -- aka sendCryptoData
                    putOutput conn $ OutHndServerNST nst
                    ServerHandshakeDone <- control ExitServer
                    clearServerController conn
                    cryptoToken <- generateToken =<< getVersion conn
                    mgr <- getTokenManager conn
                    token <- encryptToken mgr cryptoToken
                    ver <- getVersion conn
                    let frames | ver >= Draft25 = [HandshakeDone,NewToken token]
                               | otherwise      = [NewToken token]
                    putOutput conn $ OutControl RTT1Level frames
                _ -> return ()
      RTT1Level
        | isClient conn -> do
              control <- getClientController conn
              -- RecvSessionTicket or ClientHandshakeDone
              void $ control $ PutSessionTicket cdat
        | otherwise -> do
              putStrLn "processFrame: Short:Crypto for server"
processFrame conn _ (NewToken token) = do
    setNewToken conn token
    putStrLn "processFrame: NewToken"
processFrame _ _ (NewConnectionID _sn _ _cid _token)  = do
    -- fixme: register stateless token
    putStrLn $ "processFrame: NewConnectionID " ++ show _sn
processFrame conn _ (ConnectionCloseQUIC err ftyp reason) = do
    putInput conn $ InpTransportError err ftyp reason
    -- to cancel handshake
    putCrypto conn $ InpTransportError err ftyp reason
    setCloseSent conn
    setCloseReceived conn
    clearThreads conn
processFrame conn _ (ConnectionCloseApp err reason) = do
    putStrLn $ "processFrame: ConnectionCloseApp " ++ show err
    putInput conn $ InpApplicationError err reason
    -- to cancel handshake
    putCrypto conn $ InpApplicationError err reason
    setCloseSent conn
    setCloseReceived conn
    clearThreads conn
processFrame conn RTT0Level (Stream sid off dat fin) = do
    putInputStream conn sid off dat fin
processFrame conn RTT1Level (Stream sid off dat fin) =
    putInputStream conn sid off dat fin
processFrame conn lvl Ping = do
    putOutput conn $ OutControl lvl []
processFrame conn _ HandshakeDone = do
    control <- getClientController conn
    void $ forkIO $ do
        threadDelay 2000000
        ClientHandshakeDone <- control ExitClient
        clearClientController conn
processFrame _ _ _frame        = do
    putStrLn $ "processFrame: " ++ show _frame

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
