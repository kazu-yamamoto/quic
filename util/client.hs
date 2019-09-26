{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Network.QUIC
import Network.Run.UDP
import Network.Socket hiding (Stream)
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
    (pnI, pnHs, eefins, rest) <- handleServerInitial ctx shBin ch receive
    iniBin2 <- createClientInitial2 ctx pnI pnHs eefins
    getNegotiatedProtocol (tlsConetxt ctx) >>= print
    void $ sendTo s iniBin2 peerAddr
    when (rest /= "") (decodePacket ctx rest >>= print)
    receive >>= decodePacket ctx >>= print
    receive >>= decodePacket ctx >>= print
    receive >>= decodePacket ctx >>= print

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

handleServerInitial :: Context -> ByteString -> Handshake13 -> IO ByteString -> IO (PacketNumber, [PacketNumber], ByteString, ByteString)
handleServerInitial ctx shBin ch receive = do
    (InitialPacket Draft23 dcid0 scid0 _tkn0 pnI frames, hdskPktBin0) <- decodePacket ctx shBin
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
    mapM_ handle frames
    (HandshakePacket Draft23 dcid1 scid1 pnH0 [Crypto _ eefin0], "") <- decodePacket ctx hdskPktBin0
    when (dcid1 /= myCID ctx) $ error "DCID is not the same"
    when (scid1 /= scid0) $ error "SCID is not the same"
    (eefins,pnHs,rest) <- recvEefin1Bin ctx eefin0 pnH0 receive
    let ehs = decodeHandshakes13 eefins
    case ehs of
      Right []     -> error "handleServerInitial []"
      Right (ee:_) -> case handleServerEncryptedExtensions ee of
        Nothing -> error "No QUIC params"
        Just bs -> print $ decodeParametersList bs -- fixme: updating params
      Left e       -> print e
    return (pnI, pnHs, eefins, rest)
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
    handle a@(Ack _ _ _ _) = return ()
    handle _frame          = error $ show _frame

recvEefin1Bin :: Context -> ByteString -> PacketNumber -> IO ByteString -> IO (ByteString, [PacketNumber], ByteString)
recvEefin1Bin ctx eefin0 pnH0 receive = do
    check <- handshakeCheck finished eefin0 Start
    case check of
      Done -> return (eefin0, [pnH0], "")
      cont -> loop cont (eefin0 :) (pnH0 :)
  where
    finished = 20
    loop cont buildB buildN = do
        bin <- receive
        (HandshakePacket Draft23 _ _ pnH [Crypto _ eefin], rest) <- decodePacket ctx bin
        check <- handshakeCheck finished eefin cont
        let buildB' = buildB . (eefin :)
            buildN' = buildN . (pnH :)
        case check of
          Done  -> return (B.concat $ buildB' [], buildN' [], rest)
          cont' -> loop cont' buildB' buildN' -- rest should be ""

createClientInitial2 :: Context -> PacketNumber -> [PacketNumber] -> ByteString -> IO ByteString
createClientInitial2 ctx pnI pnHs eefin = do
    let mycid = myCID ctx
    peercid <- readIORef $ peerCID ctx
    let ackI = Ack pnI 0 0 []
        iniPkt = InitialPacket Draft23 peercid mycid "" 1 [ackI]
    bin0 <- encodePacket ctx iniPkt
    Just handSecret <- readIORef $ handshakeSecret ctx
    (crypto, appSecret) <- makeClientFinished13 cparams tlsctx eefin handSecret False
    writeIORef (applicationSecret ctx) $ Just appSecret
    -- fixme: ACK
    let largestACK = last pnHs
        range1 = length pnHs - 1
        ackH = Ack largestACK 0 range1 []
        hndPkt = HandshakePacket Draft23 peercid mycid 0 [Crypto 0 crypto, ackH]
    bin1 <- encodePacket ctx hndPkt
    let appPkt = ShortPacket peercid 0 [Stream 0 0 "GET /\r\n" True]
    bin2 <- encodePacket ctx appPkt
    return (B.concat [bin0, bin1, bin2])
  where
    cparams = tlsClientParams ctx
    tlsctx = tlsConetxt ctx
