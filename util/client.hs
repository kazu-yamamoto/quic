{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
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
            ccVersion    = Draft22
          , ccServerName = serverName
          , ccALPN       = return $ Just ["h3-22"]
          }
    ctx <- clientContext conf
    (iniBin, exts) <- createClientInitial ctx
    void $ sendTo s iniBin peerAddr

    let receive = fst <$> recvFrom s 2048
    shBin <- receive
    eefins <- handleServerInitial ctx shBin exts receive

    iniBin2 <- createClientInitial2 ctx eefins
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
    let iniPkt = InitialPacket Draft22 peercid mycid "" 0 frames
    iniBin <- encodePacket ctx iniPkt
    return (iniBin, ch)
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx

handleServerInitial :: Context -> ByteString -> Handshake13 -> IO ByteString -> IO ByteString
handleServerInitial ctx shBin ch receive = do
    (InitialPacket Draft22 _ _ _ _ [Crypto _ sh, _ack], eefinBin) <- decodePacket ctx shBin
    (cipher, handSecret, _resuming) <- handleServerHello13 cparams tlsctx ch sh
    setCipher ctx cipher
    writeIORef (handshakeSecret ctx) $ Just handSecret
    (HandshakePacket Draft22 dcid scid _pn [Crypto _ eefin0], _) <- decodePacket ctx eefinBin
    when (dcid /= myCID ctx) $ error "DCID is not the same"
    peercid <- readIORef $ peerCID ctx
    when (scid /= peercid) $ do
        putStrLn $ "Change peer CID to " ++ show peercid
        writeIORef (peerCID ctx) scid
    eefins <- recvEefin1Bin ctx eefin0 receive
    let ehs = decodeHandshakes13 eefins
    case ehs of
      Right []     -> error "handleServerInitial []"
      Right (ee:_) -> case handleServerEncryptedExtensions ee of
        Nothing -> error "No QUIC params"
        Just bs -> print $ decodeParametersList bs -- fixme: updating params
      Left e       -> print e
    return eefins
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx

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
        (HandshakePacket Draft22 _ _ _ [Crypto _ eefin], _fixme) <- decodePacket ctx bin
        check <- handshakeCheck finished eefin cont
        let build' = build . (eefin :)
        case check of
          Done  -> return $ B.concat $ build' []
          cont' -> loop cont' build'

createClientInitial2 :: Context -> ByteString -> IO ByteString
createClientInitial2 ctx eefin = do
    Just handSecret <- readIORef $ handshakeSecret ctx
    (crypto, appSecret) <- makeClientFinished13 cparams tlsctx eefin handSecret False
    writeIORef (applicationSecret ctx) $ Just appSecret
    let mycid = myCID ctx
    peercid <- readIORef $ peerCID ctx
    -- fixme: ACK
    let pkt = HandshakePacket Draft22 peercid mycid 0 [Crypto 0 crypto]
    bin <- encodePacket ctx pkt
    return bin
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx
