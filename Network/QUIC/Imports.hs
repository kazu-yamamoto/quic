{-# LANGUAGE CPP #-}

module Network.QUIC.Imports (
    Bytes,
    ByteString (..),
    ShortByteString (..),
    Builder,
    module Control.Applicative,
    module Control.Monad,
    module Data.Bits,
    module Data.Foldable,
    module Data.IORef,
    module Data.Int,
    module Data.Monoid,
    module Data.Ord,
    module Data.Word,
    module Data.Array,
    module Data.Array.IO,
    module Data.Maybe,
    module Numeric,
    module Network.ByteOrder,
    module Network.QUIC.Utils,
#if !MIN_VERSION_base(4,17,0)
    (!<<.), (!>>.),
#endif
    atomicModifyIORef'',
    copyBS,
    fromThreadId,
) where

import Control.Applicative
import Control.Monad
import Data.Array
import Data.Array.IO
import Data.Bits
import Data.ByteString.Builder (Builder)
import Data.ByteString.Internal (ByteString (..))
import Data.ByteString.Short.Internal (ShortByteString (..))
import Data.Foldable
import Data.IORef
import Data.Int
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.Word
import Foreign.ForeignPtr
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr
import Network.ByteOrder
import Network.QUIC.Utils
import Numeric

#if __GLASGOW_HASKELL__ >= 908
import GHC.Conc.Sync (fromThreadId)
#else
import Control.Concurrent (ThreadId)
#endif

-- | All internal byte sequences.
--   `ByteString` should be used for FFI related stuff.
type Bytes = ShortByteString

#if !MIN_VERSION_base(4,17,0)
infixl 8 !<<.
(!<<.) :: Bits a => a -> Int -> a
(!<<.) = unsafeShiftL

infixl 8 !>>.
(!>>.) :: Bits a => a -> Int -> a
(!>>.) = unsafeShiftR
#endif

atomicModifyIORef'' :: IORef a -> (a -> a) -> IO ()
atomicModifyIORef'' ref f = atomicModifyIORef' ref $ \x -> (f x, ())

copyBS :: Buffer -> ByteString -> IO Int
copyBS dst (PS fptr off len) = withForeignPtr fptr $ \src0 -> do
    let src = src0 `plusPtr` off
    copyBytes dst src len
    return len

#if __GLASGOW_HASKELL__ < 908
fromThreadId :: ThreadId -> Word64
fromThreadId tid = read (drop 9 $ show tid)
#endif
