{-# LANGUAGE TupleSections #-}

module Network.QUIC.Stream.Skew (
    Skew(..)
  , empty
  , singleton
  , insert
  , deleteMin
  , deleteMin2
  , null
  , merge
  , minimum
  ) where

import Control.Applicative hiding (empty)
import Data.Maybe
import Prelude hiding (minimum, maximum, null)

----------------------------------------------------------------

data Skew a = Leaf | Node (Skew a) a (Skew a) deriving Show

----------------------------------------------------------------

empty :: Skew a
empty = Leaf

null :: Skew a -> Bool
null Leaf         = True
null (Node _ _ _) = False

singleton :: a -> Skew a
singleton x = Node Leaf x Leaf

----------------------------------------------------------------

-- | Insertion. Worst-case: O(N), amortized: O(log N).
insert :: Ord a => a -> Skew a -> Skew a
insert x t = merge (singleton x) t

----------------------------------------------------------------

-- | Finding the minimum element. Worst-case: O(1).
minimum :: Skew a -> Maybe a
minimum Leaf         = Nothing
minimum (Node _ x _) = Just x

----------------------------------------------------------------

-- | Deleting the minimum element. Worst-case: O(N), amortized: O(log N).
deleteMin :: Ord a => Skew a -> Skew a
deleteMin Leaf         = Leaf
deleteMin (Node l _ r) = merge l r

deleteMin2 :: Ord a => Skew a -> Maybe (a, Skew a)
deleteMin2 Leaf = Nothing
deleteMin2 h    = (, deleteMin h) <$> minimum h

----------------------------------------------------------------

-- | Merging two heaps. Worst-case: O(N), amortized: O(log N).
merge :: Ord a => Skew a -> Skew a -> Skew a
merge t1 Leaf = t1
merge Leaf t2 = t2
merge t1 t2
  | minimum t1 <= minimum t2 = join t1 t2
  | otherwise                = join t2 t1

join :: Ord a => Skew a -> Skew a -> Skew a
join (Node l x r) t = Node r x (merge l t)
join _ _ = error "join"
