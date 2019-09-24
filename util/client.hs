{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Network.QUIC
import Network.Run.UDP
import Network.Socket
import Network.Socket.ByteString
import Network.TLS hiding (Context)
import System.Environment

main :: IO ()
main = do
    [serverName,port] <- getArgs
    runUDPClient serverName port $ quicClient serverName

quicClient :: String -> Socket -> SockAddr -> IO ()
quicClient serverName s peerAddr = do
    let conf = defaultClientConfig {
            ccVersion    = Draft23
          , ccServerName = serverName
          , ccALPN       = return $ Just ["h3-23"]
          }
    ctx <- clientContext conf
    (iniBin, ch) <- createClientInitial ctx
    void $ sendTo s iniBin peerAddr

    let receive = fst <$> recvFrom s 2048
    shBin <- receive
    (pn0, pn1, eefins) <- handleServerInitial ctx shBin ch receive

    iniBin2 <- createClientInitial2 ctx pn0 pn1 eefins
    getNegotiatedProtocol (tlsConetxt ctx) >>= print
    void $ sendTo s iniBin2 peerAddr


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
        mycid = myCID ctx
    peercid <- readIORef $ peerCID ctx
    let iniPkt = InitialPacket Draft23 peercid mycid "" 0 frames
    iniBin <- encodePacket ctx iniPkt
    return (iniBin, ch)
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx

handleServerInitial :: Context -> ByteString -> Handshake13 -> IO ByteString -> IO (PacketNumber, PacketNumber, ByteString)
handleServerInitial ctx shBin ch receive = do
    (InitialPacket Draft23 dcid0 scid0 _tkn0 pn0 frames, eefinBin) <- decodePacket ctx shBin
    when (dcid0 /= myCID ctx) $ error "DCID is not the same"
    peercid <- readIORef $ peerCID ctx
    when (scid0 /= peercid) $ do
        putStrLn $ "Change peer CID from " ++ show peercid ++ " to " ++ show scid0
        writeIORef (peerCID ctx) scid0
    mapM_ handle frames
    (HandshakePacket Draft23 dcid1 scid1 pn1 [Crypto _ eefin0], _rest) <- decodePacket ctx eefinBin
    when (dcid1 /= myCID ctx) $ error "DCID is not the same"
    when (scid1 /= scid0) $ error "SCID is not the same"
    eefins <- recvEefin1Bin ctx eefin0 receive
    let ehs = decodeHandshakes13 eefins
    case ehs of
      Right []     -> error "handleServerInitial []"
      Right (ee:_) -> case handleServerEncryptedExtensions ee of
        Nothing -> error "No QUIC params"
        Just bs -> print $ decodeParametersList bs -- fixme: updating params
      Left e       -> print e
    return (pn0, pn1, eefins)
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

recvEefin1Bin :: Context -> ByteString -> IO ByteString -> IO ByteString
recvEefin1Bin ctx bs receive = do
    check <- handshakeCheck finished bs Start
    case check of
      Done -> return bs
      cont -> loop cont (bs :)
  where
    finished = 20
    loop cont build = do
        bin <- receive
        (HandshakePacket Draft23 _ _ _ [Crypto _ eefin], _fixme) <- decodePacket ctx bin
        check <- handshakeCheck finished eefin cont
        let build' = build . (eefin :)
        case check of
          Done  -> return $ B.concat $ build' []
          cont' -> loop cont' build'

createClientInitial2 :: Context -> PacketNumber -> PacketNumber -> ByteString -> IO ByteString
createClientInitial2 ctx pn0 pn1 eefin = do
    let mycid = myCID ctx
    peercid <- readIORef $ peerCID ctx
    let iniPkt = InitialPacket Draft23 peercid mycid "" 1 [Ack pn0 0 0 []]
    bin0 <- encodePacket ctx iniPkt
    Just handSecret <- readIORef $ handshakeSecret ctx
    (crypto, appSecret) <- makeClientFinished13 cparams tlsctx eefin handSecret False
    writeIORef (applicationSecret ctx) $ Just appSecret
    -- fixme: ACK
    let hndPkt = HandshakePacket Draft23 peercid mycid 0 [Crypto 0 crypto, Ack pn1 0 0 []]
    bin1 <- encodePacket ctx hndPkt
    return (B.concat [bin0, bin1])
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx
