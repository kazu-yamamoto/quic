module Network.QUIC.Socket (
    serverSocket,
    clientSocket,
    natRebinding,
) where

import qualified Control.Exception as E
import Data.IP (IP, toSockAddr)
import qualified Data.List.NonEmpty as NE
import Network.Socket
import Foreign.C.Types

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
    E.bracketOnError (openSocket addr) close $ \s -> do
      -- RFC9000 Section 14
      -- UDP datagrams MUST NOT be fragmented at the IP layer. In IPv4
      -- [IPv4], the Don't Fragment (DF) bit MUST be set if possible, to
      -- prevent fragmentation on the path.
      fd <- unsafeFdSocket s
      _ <- c_set_dont_fragment_sockopt fd
      return (s, addrAddress addr)
  where
    hints = defaultHints{addrSocketType = Datagram, addrFlags = [AI_ADDRCONFIG]}

serverSocket :: (IP, PortNumber) -> IO Socket
serverSocket ip = E.bracketOnError open close $ \s -> do
    setSocketOption s ReuseAddr 1
    -- RFC9000 Section 14
    -- UDP datagrams MUST NOT be fragmented at the IP layer. In IPv4
    -- [IPv4], the Don't Fragment (DF) bit MUST be set if possible, to
    -- prevent fragmentation on the path.
    fd <- unsafeFdSocket s
    _ <- c_set_dont_fragment_sockopt fd
    withFdSocket s setCloseOnExecIfNeeded
    bind s sa
    return s
  where
    sa = toSockAddr ip
    family = sockAddrFamily sa
    open = socket family Datagram defaultProtocol

foreign import ccall unsafe "set_dont_fragment_sockopt"
    c_set_dont_fragment_sockopt :: CInt -> IO CInt
