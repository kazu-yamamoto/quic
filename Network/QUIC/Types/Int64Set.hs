{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- | Sets of the 62-bit integers of QUIC: an 'IntSet' where 'Int' has 64
--   bits, which loses nothing, and a 'Set' of 'Int64' elsewhere.
module Network.QUIC.Types.Int64Set (
    Int64Set,
    empty,
    singleton,
    insert,
    delete,
    member,
    size,
    null,
    toList,
    toDescList,
    fromDistinctAscList,
    maxView,
    split,
    difference,
) where

#include "MachDeps.h"

import Data.Int (Int64)
import Prelude hiding (null)

#if WORD_SIZE_IN_BITS == 64
import qualified Data.IntSet as S

newtype Int64Set = Int64Set S.IntSet
    deriving (Eq, Ord, Show, Semigroup, Monoid)

key :: Int64 -> Int
key = fromIntegral

unkey :: Int -> Int64
unkey = fromIntegral
#else
import qualified Data.Set as S

newtype Int64Set = Int64Set (S.Set Int64)
    deriving (Eq, Ord, Show, Semigroup, Monoid)

key :: Int64 -> Int64
key = id

unkey :: Int64 -> Int64
unkey = id
#endif

empty :: Int64Set
empty = Int64Set S.empty

singleton :: Int64 -> Int64Set
singleton = Int64Set . S.singleton . key

insert :: Int64 -> Int64Set -> Int64Set
insert k (Int64Set s) = Int64Set $ S.insert (key k) s

delete :: Int64 -> Int64Set -> Int64Set
delete k (Int64Set s) = Int64Set $ S.delete (key k) s

member :: Int64 -> Int64Set -> Bool
member k (Int64Set s) = S.member (key k) s

size :: Int64Set -> Int
size (Int64Set s) = S.size s

null :: Int64Set -> Bool
null (Int64Set s) = S.null s

toList :: Int64Set -> [Int64]
toList (Int64Set s) = map unkey $ S.toList s

toDescList :: Int64Set -> [Int64]
toDescList (Int64Set s) = map unkey $ S.toDescList s

fromDistinctAscList :: [Int64] -> Int64Set
fromDistinctAscList = Int64Set . S.fromDistinctAscList . map key

maxView :: Int64Set -> Maybe (Int64, Int64Set)
maxView (Int64Set s) = (\(k, s') -> (unkey k, Int64Set s')) <$> S.maxView s

split :: Int64 -> Int64Set -> (Int64Set, Int64Set)
split k (Int64Set s) = let (l, r) = S.split (key k) s in (Int64Set l, Int64Set r)

difference :: Int64Set -> Int64Set -> Int64Set
difference (Int64Set a) (Int64Set b) = Int64Set $ S.difference a b
