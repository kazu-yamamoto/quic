module Network.QUIC.Types (
    Bytes,
    Close,
    Direction (..),
    SizedBuffer (..),
    module Network.QUIC.Types.Ack,
    module Network.QUIC.Types.CID,
    module Network.QUIC.Types.Constants,
    module Network.QUIC.Types.Error,
    module Network.QUIC.Types.Exception,
    module Network.QUIC.Types.Frame,
    module Network.QUIC.Types.Integer,
    module Network.QUIC.Types.Packet,
    module Network.QUIC.Types.Queue,
    module Network.QUIC.Types.Resumption,
    module Network.QUIC.Types.Time,
) where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Constants
import Network.QUIC.Types.Error
import Network.QUIC.Types.Exception
import Network.QUIC.Types.Frame

import Network.QUIC.Types.Integer
import Network.QUIC.Types.Packet
import Network.QUIC.Types.Queue
import Network.QUIC.Types.Resumption
import Network.QUIC.Types.Time

{-
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe
import Text.Printf

instance Show SizedBuffer where
    show (SizedBuffer ptr _) = unsafePerformIO $ loop 0 id
      where
        loop 16 b = return $ b []
        loop n b = do
            x <- peek (ptr `plusPtr` n) :: IO Word8
            let b' = b . (printf "%02x " x ++)
            loop (n + 1) b'
-}

type Close = IO ()
data SizedBuffer = SizedBuffer Buffer BufferSize
