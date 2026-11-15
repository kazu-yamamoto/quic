{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveTraversable #-}

-- | Maps keyed by the 62-bit integers of QUIC: an 'IntMap' where 'Int' has
--   64 bits, which loses nothing, and a 'Map' of 'Int64' elsewhere.
module Network.QUIC.Types.Int64Map (
    Int64Map,
    empty,
    singleton,
    insert,
    delete,
    lookup,
    member,
    size,
    null,
    elems,
    keys,
    toList,
    lookupMin,
    foldrWithKey,
    partitionWithKey,
) where

#include "MachDeps.h"

import Data.Int (Int64)
import Prelude hiding (lookup, null)

#if WORD_SIZE_IN_BITS == 64
import qualified Data.IntMap.Strict as M

newtype Int64Map a = Int64Map (M.IntMap a)
    deriving (Eq, Show, Functor, Foldable, Traversable)

key :: Int64 -> Int
key = fromIntegral

unkey :: Int -> Int64
unkey = fromIntegral
#else
import qualified Data.Map.Strict as M

newtype Int64Map a = Int64Map (M.Map Int64 a)
    deriving (Eq, Show, Functor, Foldable, Traversable)

key :: Int64 -> Int64
key = id

unkey :: Int64 -> Int64
unkey = id
#endif

empty :: Int64Map a
empty = Int64Map M.empty

singleton :: Int64 -> a -> Int64Map a
singleton k v = Int64Map $ M.singleton (key k) v

insert :: Int64 -> a -> Int64Map a -> Int64Map a
insert k v (Int64Map m) = Int64Map $ M.insert (key k) v m

delete :: Int64 -> Int64Map a -> Int64Map a
delete k (Int64Map m) = Int64Map $ M.delete (key k) m

lookup :: Int64 -> Int64Map a -> Maybe a
lookup k (Int64Map m) = M.lookup (key k) m

member :: Int64 -> Int64Map a -> Bool
member k (Int64Map m) = M.member (key k) m

size :: Int64Map a -> Int
size (Int64Map m) = M.size m

null :: Int64Map a -> Bool
null (Int64Map m) = M.null m

elems :: Int64Map a -> [a]
elems (Int64Map m) = M.elems m

keys :: Int64Map a -> [Int64]
keys (Int64Map m) = map unkey $ M.keys m

toList :: Int64Map a -> [(Int64, a)]
toList (Int64Map m) = [(unkey k, v) | (k, v) <- M.toList m]

lookupMin :: Int64Map a -> Maybe (Int64, a)
lookupMin (Int64Map m) = (\(k, v) -> (unkey k, v)) <$> M.lookupMin m

foldrWithKey :: (Int64 -> a -> b -> b) -> b -> Int64Map a -> b
foldrWithKey f z (Int64Map m) = M.foldrWithKey (f . unkey) z m

partitionWithKey
    :: (Int64 -> a -> Bool) -> Int64Map a -> (Int64Map a, Int64Map a)
partitionWithKey p (Int64Map m) =
    let (l, r) = M.partitionWithKey (p . unkey) m in (Int64Map l, Int64Map r)
