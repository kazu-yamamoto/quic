module Network.QUIC.Crypto.Types (
  -- * Types
    PlainText
  , CipherText
  , Key(..)
  , IV(..)
  , CID
  , Secret(..)
  , AssDat(..)
  , Sample(..)
  , Mask(..)
  , Nonce(..)
  , Salt
  , Label(..)
  , Cipher
  , InitialSecret
  , TrafficSecrets
  , ClientTrafficSecret(..)
  , ServerTrafficSecret(..)
  ) where

import qualified Data.ByteString.Char8 as C8
import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

type PlainText  = ByteString
type CipherText = ByteString
type Salt       = ByteString

newtype Key    = Key    ByteString deriving (Eq)
newtype IV     = IV     ByteString deriving (Eq)
newtype Secret = Secret ByteString deriving (Eq)
newtype AssDat = AssDat ByteString deriving (Eq)
newtype Sample = Sample ByteString deriving (Eq)
newtype Mask   = Mask   ByteString deriving (Eq)
newtype Label  = Label  ByteString deriving (Eq)
newtype Nonce  = Nonce  ByteString deriving (Eq)

instance Show Key where
    show (Key x) = "Key=" ++ C8.unpack (enc16 x)
instance Show IV where
    show (IV x) = "IV=" ++ C8.unpack (enc16 x)
instance Show Secret where
    show (Secret x) = "Secret=" ++ C8.unpack (enc16 x)
instance Show AssDat where
    show (AssDat x) = "AssDat=" ++ C8.unpack (enc16 x)
instance Show Sample where
    show (Sample x) = "Sample=" ++ C8.unpack (enc16 x)
instance Show Mask where
    show (Mask x) = "Mask=" ++ C8.unpack (enc16 x)
instance Show Label where
    show (Label x) = "Label=" ++ C8.unpack (enc16 x)
instance Show Nonce where
    show (Nonce x) = "Nonce=" ++ C8.unpack (enc16 x)

data InitialSecret
