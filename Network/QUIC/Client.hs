{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Client (
    ClientRecvQ
  , newClientRecvQ
  , readerClient
  , recvClient
  ) where

import Control.Concurrent.STM
import qualified Control.Exception as E
import Data.IORef
import Network.Socket (Socket)
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.TLS
import Network.QUIC.Types

newtype ClientRecvQ = ClientRecvQ (TQueue CryptPacket)

newClientRecvQ :: IO ClientRecvQ
newClientRecvQ = ClientRecvQ <$> newTQueueIO

readClientRecvQ :: ClientRecvQ -> IO CryptPacket
readClientRecvQ (ClientRecvQ q) = atomically $ readTQueue q

writeClientRecvQ :: ClientRecvQ -> CryptPacket -> IO ()
writeClientRecvQ (ClientRecvQ q) x = atomically $ writeTQueue q x

-- readerClient dies when the socket is closed.
readerClient :: ClientConfig -> Socket -> ClientRecvQ -> IORef (Maybe Connection) -> IO ()
readerClient ClientConfig{..} s q connref = E.handle ignore $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodePackets
    mapM_ putQ pkts
  where
    ignore (E.SomeException _) = return ()
    putQ (PacketIV (VersionNegotiationPacket dCID sCID peerVers)) = do
        mconn <- readIORef connref
        case mconn of
          Nothing   -> return ()
          Just conn -> do
              mr <- releaseOutput conn 0
              let myVers = confVersions ccConfig
              case myVers `intersect` peerVers of
                []    -> return ()
                ver:_ -> do
                    ok <- checkCIDs conn dCID sCID
                    when ok $ case mr of
                      Just (OutHndClientHello cdat mEarydata) -> do
                          setPacketNumber conn 0
                          setVersion conn ver
                          setInitialSecrets conn $ initialSecrets ver sCID
                          putOutput conn $ OutHndClientHello cdat mEarydata
                      _ -> return ()
    putQ (PacketIC pkt) = writeClientRecvQ q pkt
    putQ (PacketIR (RetryPacket ver dCID sCID oCID token))  = do
        -- The packet number of first crypto frame is 0.
        -- This ensures that retry can be accepted only once.
        mconn <- readIORef connref
        case mconn of
          Nothing   -> return ()
          Just conn -> do
              mr <- releaseOutput conn 0
              ok <- checkCIDs conn dCID oCID
              when ok $ case mr of
                Just (OutHndClientHello cdat mEarydata) -> do
                    setPeerCID conn sCID
                    setInitialSecrets conn $ initialSecrets ver sCID
                    setToken conn token
                    setCryptoOffset conn InitialLevel 0
                    setRetried conn True
                    putOutput conn $ OutHndClientHello cdat mEarydata
                _ -> return ()

checkCIDs :: Connection -> CID -> CID -> IO Bool
checkCIDs conn dCID sCID = do
    let localCID = myCID conn
    remoteCID <- getPeerCID conn
    return (dCID == localCID && sCID == remoteCID)

recvClient :: ClientRecvQ -> IO CryptPacket
recvClient = readClientRecvQ
