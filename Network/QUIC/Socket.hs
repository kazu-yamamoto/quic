module Network.QUIC.Socket where

import Data.IP
import Network.Socket

sockAddrFamily :: SockAddr -> Family
sockAddrFamily SockAddrInet{}  = AF_INET
sockAddrFamily SockAddrInet6{} = AF_INET6
sockAddrFamily _               = error "sockAddrFamily"

anySockAddr :: SockAddr -> SockAddr
anySockAddr (SockAddrInet p _)      = SockAddrInet  p 0
anySockAddr (SockAddrInet6 p f _ s) = SockAddrInet6 p f (0,0,0,0) s
anySockAddr _                       = error "anySockAddr"

udpServerListenSocket :: (IP, PortNumber) -> IO (Socket, SockAddr)
udpServerListenSocket ip = do
    let sa = toSockAddr ip
        family = sockAddrFamily sa
    s <- socket family Datagram defaultProtocol
    setSocketOption s ReuseAddr 1
--    setSocketOption s IPv6Only 1 -- fixme
    bind s sa
    return (s,sa)

udpServerConnectedSocket :: SockAddr -> SockAddr -> IO Socket
udpServerConnectedSocket mysa peersa = do
    let family = sockAddrFamily mysa
        anysa  = anySockAddr mysa
    s <- socket family Datagram defaultProtocol
    setSocketOption s ReuseAddr 1
    bind s anysa      -- (UDP, *:13443, *:*)
    connect s peersa  -- (UDP, 127.0.0.1:13443, pa:pp)
    return s
