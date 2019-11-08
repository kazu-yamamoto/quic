{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver where

import Control.Concurrent.STM
import qualified Data.ByteString.Char8 as C8

import Network.QUIC.Context
import Network.QUIC.Imports
import Network.QUIC.Transport

receiver :: Context -> IO ()
receiver ctx = do
    mbs <- readClearClientInitial ctx
    case mbs of
        Nothing -> loop
        Just bs -> do
            processPackets ctx bs
            loop
  where
    loop = forever $ do
        bs <- ctxRecv ctx
        processPackets ctx bs

processPackets :: Context -> ByteString -> IO ()
processPackets ctx bs0 = loop bs0
  where
    loop "" = return ()
    loop bs = do
        let level = packetEncryptionLevel bs
        checkEncryptionLevel ctx level
        (pkt, rest) <- decodePacket ctx bs
        processPacket ctx pkt
        loop rest

processPacket :: Context -> Packet -> IO ()
processPacket ctx (InitialPacket   _ _ _ _ pn fs) = do
      addPNs ctx Initial pn
--      putStrLn $ "I: " ++ show fs
      mapM_ (processFrame ctx Initial) fs
processPacket ctx (HandshakePacket _ _ peercid   pn fs) = do
      addPNs ctx Handshake pn
--      putStrLn $ "H: " ++ show fs
      when (isClient ctx) $ setPeerCID ctx peercid
      mapM_ (processFrame ctx Handshake) fs
processPacket ctx (ShortPacket     _       pn fs) = do
      addPNs ctx Short pn
--      putStrLn $ "S: " ++ show fs
      mapM_ (processFrame ctx Short) fs
processPacket _ _ = undefined

processFrame :: Context -> PacketType -> Frame -> IO ()
processFrame _ _ Padding = return ()
processFrame _ _ (ConnectionClose _errcode reason) = do
    C8.putStrLn reason
    putStrLn "FIXME: ConnectionClose"
processFrame ctx Short (Stream sid _off dat _fin) = do
    -- fixme _off _fin
    atomically $ writeTQueue (inputQ ctx) $ S sid dat
processFrame ctx pt (Crypto _off cdat) = do
    --fixme _off
    case pt of
      Initial   -> atomically $ writeTQueue (inputQ ctx) $ H pt cdat
      Handshake -> atomically $ writeTQueue (inputQ ctx) $ H pt cdat
      Short     -> putStrLn "FIXME: processFrame Short (new session ticket)"
      _         -> error "processFrame"
processFrame _ _ (Ack _ _ _ _) = return ()
processFrame _ _ _frame        = do
    putStrLn "FIXME: processFrame"
    print _frame
