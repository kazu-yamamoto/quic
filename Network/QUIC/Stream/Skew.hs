{-# LANGUAGE TupleSections #-}

module Network.QUIC.Stream.Skew (
    Skew(..)
  , empty
  , insert
  , deleteMin
--  , deleteMin'
  ) where

import Control.Applicative hiding (empty)
import Data.Maybe
import Data.Sequence (Seq(..), viewl, viewr, ViewL(..), ViewR(..), (<|), (><))
import qualified Data.Sequence as Seq
import Prelude hiding (minimum)

----------------------------------------------------------------

class Frag a where
    start  :: a -> Int
    next   :: a -> Int
    shrink :: a -> Int -> a

instance Frag a => Frag (Seq a) where
    start s = case viewl s of
      EmptyL -> error "Seq is empty"
      x :< _ -> start x
    next s = case viewr s of
      EmptyR -> error "Seq is empty"
      _ :> x -> next x
    shrink = shrinkSeq

shrinkSeq :: Frag a => Seq a -> Int -> Seq a
shrinkSeq s0 n = case viewl s of
  EmptyL  -> error "shrinkSeq"
  x :< xs -> shrink x n <| xs
  where
    s = Seq.dropWhileL (\y -> not (start y <= n && n <= next y)) s0

{-
data F = F Int Int deriving Show

instance Frag F where
    start  (F s _)   = s
    next   (F _ e)   = e
    shrink (F s e) n = if s <= n && n <= e then F n e else error "shrink"
-}

----------------------------------------------------------------

data Skew a = Leaf | Node (Skew a) (Seq a) (Skew a) deriving Show

empty :: Skew a
empty = Leaf

----------------------------------------------------------------

-- | Insertion. Worst-case: O(N), amortized: O(log N).
insert :: Frag a => a -> Skew a -> Skew a
insert x t = merge (Node Leaf (Seq.singleton x) Leaf) t

----------------------------------------------------------------

-- | Finding the minimum element. Worst-case: O(1).
minimum :: Skew a -> Maybe (Seq a)
minimum Leaf         = Nothing
minimum (Node _ f _) = Just f

----------------------------------------------------------------

-- | Deleting the minimum element. Worst-case: O(N), amortized: O(log N).
deleteMin' :: Frag a => Skew a -> Skew a
deleteMin' Leaf         = Leaf
deleteMin' (Node l _ r) = merge l r

deleteMin :: Frag a => Skew a -> Maybe (Seq a, Skew a)
deleteMin Leaf = Nothing
deleteMin h    = (, deleteMin' h) <$> minimum h

----------------------------------------------------------------

-- | Merging two heaps. Worst-case: O(N), amortized: O(log N).
merge :: Frag a => Skew a -> Skew a -> Skew a
merge t1 Leaf = t1
merge Leaf t2 = t2
merge t1@(Node l1 f1 r1) t2@(Node l2 f2 r2)
  | e1 < s2   = Node r1 f1 (merge l1 t2)
  | e2 < s1   = Node r2 f2 (merge l2 t1)
  | otherwise = Node (merge l1 l2) f12 (merge r1 r2)
  where
    s1 = start f1
    e1 = next  f1
    s2 = start f2
    e2 = next  f2
    f12 | e1 == s2             = f1 >< f2
        | s1 == e2             = f2 >< f1
        | s1 <= s2 && e2 <= e1 = f1
        | s2 <= s1 && e1 <= e2 = f2
        | s1 <= s2             = f1 >< (shrink f2 e1)
        | otherwise            = f2 >< (shrink f1 e2)
