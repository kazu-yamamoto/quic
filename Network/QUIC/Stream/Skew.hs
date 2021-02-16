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
import Data.Sequence (Seq(..), viewl, viewr, ViewL(..), ViewR(..), singleton)
import Prelude hiding (minimum, maximum, null)

----------------------------------------------------------------

class Frag a where
    start :: a -> Int
    next  :: a -> Int

instance Frag a => Frag (Seq a) where
    start s = case viewl s of
      EmptyL -> error "Seq is empty"
      x :< _ -> start x
    next s = case viewr s of
      EmptyR -> error "Seq is empty"
      _ :> x -> next x

----------------------------------------------------------------

data Skew a = Leaf | Node (Skew a) (Seq a) (Skew a) deriving Show

----------------------------------------------------------------

empty :: Skew a
empty = Leaf

null :: Skew a -> Bool
null Leaf         = True
null (Node _ _ _) = False

----------------------------------------------------------------

-- | Insertion. Worst-case: O(N), amortized: O(log N).
insert :: Frag a => a -> Skew a -> Skew a
insert x Leaf = Node Leaf (singleton x) Leaf
-- insert x t = merge (singleton x) t
insert x t@(Node l s r)
  | n1 == s2  = Node l (x :<| s) r
  | n2 == s1  = Node l (s :|> x) r
  | n1 <  s2  = Node Leaf (singleton x) t
  | n2 <  s1  = Node r s (merge l (Node Leaf (singleton x) Leaf))
  | otherwise = t
  where
    s1 = start x
    n1 = next x
    s2 = start s
    n2 = next s

----------------------------------------------------------------

-- | Finding the minimum element. Worst-case: O(1).
minimum :: Skew a -> Maybe (Seq a)
minimum Leaf         = Nothing
minimum (Node _ x _) = Just x

----------------------------------------------------------------

-- | Deleting the minimum element. Worst-case: O(N), amortized: O(log N).
deleteMin :: Frag a => Skew a -> Skew a
deleteMin Leaf         = Leaf
deleteMin (Node l _ r) = merge l r

deleteMin2 :: Frag a => Skew a -> Maybe (Seq a, Skew a)
deleteMin2 Leaf = Nothing
deleteMin2 h    = (, deleteMin h) <$> minimum h

----------------------------------------------------------------

-- | Merging two heaps. Worst-case: O(N), amortized: O(log N).
merge :: Frag a => Skew a -> Skew a -> Skew a
merge t1 Leaf = t1
merge Leaf t2 = t2
merge t1@(Node l1 s1 r1) t2@(Node l2 s2 r2)
  | start s2 < start s2 = Node r1 s1 (merge l1 t2)
  | otherwise           = Node r2 s2 (merge l2 t1)
