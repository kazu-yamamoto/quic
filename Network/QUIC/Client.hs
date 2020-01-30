{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client (
    ClientRecvQ
  , newClientRecvQ
  , readerClient
  , recvClient
  ) where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified GHC.IO.Exception as E
import Network.Socket (Socket)
import qualified Network.Socket.ByteString as NSB
import qualified System.IO.Error as E

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
readerClient :: ClientConfig -> Socket -> ClientRecvQ -> Connection -> IO ()
readerClient ClientConfig{..} s q conn = E.handle handler $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodePackets
    mapM_ putQ pkts
  where
    handler se
      | Just (e :: E.IOException) <- E.fromException se =
            when (E.ioeGetErrorType e /= E.InvalidArgument) $ print e
      | otherwise = print se
    putQ (PacketIB BrokenPacket) = return ()
    putQ (PacketIV (VersionNegotiationPacket dCID sCID peerVers)) = do
        let myVers = confVersions ccConfig
        mver <- case myVers `intersect` peerVers of
                  []    -> return Nothing
                  ver:_ -> do
                      ok <- checkCIDs conn dCID (Left sCID)
                      return $ if ok then Just ver else Nothing
        putCrypto conn $ InpVersion mver
    putQ (PacketIC pkt) = writeClientRecvQ q pkt
    putQ (PacketIR (RetryPacket ver dCID sCID token ex)) = do
        -- The packet number of first crypto frame is 0.
        -- This ensures that retry can be accepted only once.
        mr <- releaseOutput conn 0
        ok <- checkCIDs conn dCID ex
        when ok $ case mr of
          Just (OutHndClientHello cdat mEarydata) -> do
              setPeerCID conn sCID
              setInitialSecrets conn $ initialSecrets ver sCID
              setToken conn token
              setCryptoOffset conn InitialLevel 0
              setRetried conn True
              putOutput conn $ OutHndClientHello cdat mEarydata
          _ -> return ()

checkCIDs :: Connection -> CID -> Either CID (ByteString,ByteString) -> IO Bool
checkCIDs conn dCID (Left sCID) = do
    let localCID = myCID conn
    remoteCID <- getPeerCID conn
    return (dCID == localCID && sCID == remoteCID)
checkCIDs conn dCID (Right (pseudo0,tag)) = do
    let localCID = myCID conn
    remoteCID <- getPeerCID conn
    let ok = calculateIntegrityTag remoteCID pseudo0 == tag
    return (dCID == localCID && ok)

recvClient :: ClientRecvQ -> IO CryptPacket
recvClient = readClientRecvQ
