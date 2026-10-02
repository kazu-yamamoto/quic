{-# LANGUAGE CPP #-}

module Network.QUIC.Socket (
    serverSocket,
    clientSocket,
    natRebinding,
) where

import qualified Control.Exception as E
import Data.IP (IP, toSockAddr)
import qualified Data.List.NonEmpty as NE
import Network.Socket

natRebinding :: SockAddr -> IO Socket
natRebinding sa = E.bracketOnError open close return
  where
    family = sockAddrFamily sa
    open = socket family Datagram defaultProtocol

sockAddrFamily :: SockAddr -> Family
sockAddrFamily SockAddrInet{} = AF_INET
sockAddrFamily SockAddrInet6{} = AF_INET6
sockAddrFamily _ = error "sockAddrFamily"

clientSocket :: HostName -> ServiceName -> IO (Socket, SockAddr)
clientSocket host port = do
    addr <- NE.head <$> getAddrInfo (Just hints) (Just host) (Just port)
    E.bracketOnError (openSocket addr) close $ \s -> return (s, addrAddress addr)
  where
    hints = defaultHints{addrSocketType = Datagram, addrFlags = [AI_ADDRCONFIG]}

-- Note [Binding the same port twice]
--
-- A server is replaced by starting its successor while the old process still
-- has the port, so for a moment two processes have the same UDP port bound.
-- What makes that possible, and what happens while it lasts, differs between
-- the platforms.  Both of these were measured, not assumed:
--
-- Linux, SO_REUSEADDR: the second bind succeeds, and the socket bound last
-- receives everything from that moment on.  The old process goes deaf while
-- its socket is still open.  It can still send, which is what the
-- CONNECTION_CLOSE sweep in Network.QUIC.Server.Run relies on.
--
-- macOS and the BSDs, SO_REUSEADDR alone: the second bind is refused with
-- "Address already in use" and the successor cannot start at all.  With
-- SO_REUSEPORT the second bind succeeds, and the socket bound *first* keeps
-- receiving everything until it is closed, at which point the other takes
-- over with nothing lost in between.
--
-- SO_REUSEPORT is deliberately not set on Linux, where it means something
-- else: the kernel load balances datagrams between the two sockets by a hash
-- of the four-tuple, which would split one server's packets across two
-- processes at random.

serverSocket :: (IP, PortNumber) -> IO Socket
serverSocket ip = E.bracketOnError open close $ \s -> do
    setSocketOption s ReuseAddr 1
#if defined(darwin_HOST_OS) || defined(freebsd_HOST_OS) || defined(netbsd_HOST_OS) || defined(openbsd_HOST_OS)
    setSocketOption s ReusePort 1
#endif
    withFdSocket s setCloseOnExecIfNeeded
    bind s sa
    return s
  where
    sa = toSockAddr ip
    family = sockAddrFamily sa
    open = socket family Datagram defaultProtocol
