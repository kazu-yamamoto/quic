{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client (
    readerClient
  , recvClient
  ) where

import Network.Socket (Socket)
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Qlog
import Network.QUIC.TLS
import Network.QUIC.Types

-- | readerClient dies when the socket is closed.
readerClient :: [Version] -> Socket -> RecvQ -> Connection -> IO ()
readerClient myVers s q conn = handleLog logAction $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodePackets
    mapM_ putQ pkts
  where
    logAction msg = connDebugLog conn ("readerClient: " ++ msg)
    putQ (PacketIB BrokenPacket) = return ()
    putQ (PacketIV pkt@(VersionNegotiationPacket dCID sCID peerVers)) = do
        qlogReceived conn pkt
        mver <- case myVers `intersect` peerVers of
                  []    -> return Nothing
                  ver:_ -> do
                      ok <- checkCIDs conn dCID (Left sCID)
                      return $ if ok then Just ver else Nothing
        putCrypto conn $ InpVersion mver
    putQ (PacketIC pkt) = writeRecvQ q pkt
    putQ (PacketIR pkt@(RetryPacket ver dCID sCID token ex)) = do
        qlogReceived conn pkt
        -- The packet number of first crypto frame is 0.
        -- This ensures that retry can be accepted only once.
        mppkt <- releasePlainPacket conn 0
        ok <- checkCIDs conn dCID ex
        when ok $ case mppkt of
          Just ppkt -> do
              resetPeerCID conn sCID
              setInitialSecrets conn $ initialSecrets ver sCID
              setToken conn token
              setRetried conn True
              putOutput conn $ OutPlainPacket ppkt []
          _ -> return ()

checkCIDs :: Connection -> CID -> Either CID (ByteString,ByteString) -> IO Bool
checkCIDs conn dCID (Left sCID) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    return (dCID == localCID && sCID == remoteCID)
checkCIDs conn dCID (Right (pseudo0,tag)) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    let ok = calculateIntegrityTag remoteCID pseudo0 == tag
    return (dCID == localCID && ok)

recvClient :: RecvQ -> IO CryptPacket
recvClient = readRecvQ
