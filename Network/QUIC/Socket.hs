{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Socket where

import Data.IP hiding (addr)
import qualified GHC.IO.Exception as E
import Network.Socket
import qualified System.IO.Error as E
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

import Network.QUIC.Imports

sockAddrFamily :: SockAddr -> Family
sockAddrFamily SockAddrInet{}  = AF_INET
sockAddrFamily SockAddrInet6{} = AF_INET6
sockAddrFamily _               = error "sockAddrFamily"

anySockAddr :: SockAddr -> SockAddr
anySockAddr (SockAddrInet p _)      = SockAddrInet  p 0
anySockAddr (SockAddrInet6 p f _ s) = SockAddrInet6 p f (0,0,0,0) s
anySockAddr _                       = error "anySockAddr"

isAnyAddr :: IP -> Bool
isAnyAddr (IPv4 a) = a == "0.0.0.0"
isAnyAddr (IPv6 a) = a == "::"

udpServerListenSocket :: (IP, PortNumber) -> IO (Socket, SockAddr, Bool)
udpServerListenSocket ip = E.bracketOnError open close $ \s -> do
    setSocketOption s ReuseAddr 1
    withFdSocket s setCloseOnExecIfNeeded
#if !defined(openbsd_HOST_OS)
    when (family == AF_INET6) $ setSocketOption s IPv6Only 1
#endif
    bind s sa
    let wildcard = isAnyAddr $ fst ip
    return (s,sa,wildcard)
  where
    sa     = toSockAddr ip
    family = sockAddrFamily sa
    open   = socket family Datagram defaultProtocol

udpServerConnectedSocket :: SockAddr -> SockAddr -> Bool -> IO Socket
udpServerConnectedSocket mysa peersa wildcard = E.bracketOnError open close $ \s -> do
    setSocketOption s ReuseAddr 1
    withFdSocket s setCloseOnExecIfNeeded
    let mysa' | wildcard  = mysa
              | otherwise = anySockAddr mysa
    -- wildcard:  (UDP, *.443, *:*) -> (UDP, 127.0.0.1:443, *:*)
    -- otherwise: (UDP, 127.0.0.1:443, *:*) -> (UDP, *:443, *:*)
    bind s mysa'
    -- bind and connect is not atomic
    -- So, bind may results in EADDRINUSE
       `E.catch` postphone (bind s mysa')
    connect s peersa  -- (UDP, 127.0.0.1:443, pa:pp)
    return s
  where
    postphone action e
      | E.ioeGetErrorType e == E.ResourceBusy = threadDelay 10000 >> action
      | otherwise                             = E.throwIO e
    family = sockAddrFamily mysa
    open   = socket family Datagram defaultProtocol

udpClientSocket :: HostName -> ServiceName -> IO (Socket,SockAddr)
udpClientSocket host port = do
    addr <- head <$> getAddrInfo (Just hints) (Just host) (Just port)
    E.bracketOnError (openSocket addr) close $ \s -> do
        let sa = addrAddress addr
        return (s,sa)
 where
    hints = defaultHints { addrSocketType = Datagram }

udpClientConnectedSocket :: HostName -> ServiceName -> IO (Socket,SockAddr)
udpClientConnectedSocket host port = do
    addr <- head <$> getAddrInfo (Just hints) (Just host) (Just port)
    E.bracketOnError (openSocket addr) close $ \s -> do
        let sa = addrAddress addr
        connect s sa
        return (s,sa)
 where
    hints = defaultHints { addrSocketType = Datagram }

udpNATRebindingSocket :: SockAddr -> IO Socket
udpNATRebindingSocket peersa = E.bracketOnError open close $ \s ->
    return s
  where
    family = sockAddrFamily peersa
    open = socket family Datagram defaultProtocol

udpNATRebindingConnectedSocket :: SockAddr -> IO Socket
udpNATRebindingConnectedSocket peersa = E.bracketOnError open close $ \s -> do
    connect s peersa
    return s
  where
    family = sockAddrFamily peersa
    open = socket family Datagram defaultProtocol
