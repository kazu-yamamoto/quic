module Network.QUIC.Socket (
    serverSocket,
    clientSocket,
    natRebinding,
) where

import Data.IP (IP, toSockAddr)
import Network.Socket
import qualified UnliftIO.Exception as E

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
    addr <- head <$> getAddrInfo (Just hints) (Just host) (Just port)
    E.bracketOnError (openSocket addr) close $ \s -> return (s, addrAddress addr)
  where
    hints = defaultHints{addrSocketType = Datagram, addrFlags = [AI_ADDRCONFIG]}

serverSocket :: (IP, PortNumber) -> IO Socket
serverSocket ip = E.bracketOnError open close $ \s -> do
    setSocketOption s ReuseAddr 1
    withFdSocket s setCloseOnExecIfNeeded
    bind s sa
    return s
  where
    sa = toSockAddr ip
    family = sockAddrFamily sa
    open = socket family Datagram defaultProtocol
