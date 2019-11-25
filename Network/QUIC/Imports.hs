module Network.QUIC.Imports (
    Bytes
  , ByteString(..)
  , ShortByteString(..)
  , module Control.Applicative
  , module Control.Monad
  , module Data.Bits
  , module Data.List
  , module Data.Foldable
  , module Data.Int
  , module Data.Monoid
  , module Data.Ord
  , module Data.Word
  , module Data.Maybe
  , module Numeric
  , module Network.ByteOrder
  , module Network.QUIC.Utils
  ) where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString.Internal (ByteString(..))
import Data.ByteString.Short.Internal (ShortByteString(..))
import Data.Foldable
import Data.Int
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.Word
import Numeric
import Network.ByteOrder
import Network.QUIC.Utils

-- | All internal byte sequences.
--   `ByteString` should be used for FFI related stuff.
type Bytes = ShortByteString
