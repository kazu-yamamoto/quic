{-# LANGUAGE TupleSections #-}

module Network.QUIC.Stream.Skew (
    Skew(..)
  , empty
  , insert
  , deleteMin
  , deleteMinIf
--  , deleteMin'
--  , showSkew
  ) where

import Data.Maybe
import Data.Sequence (Seq(..), (><))
import qualified Data.Sequence as Seq
import Prelude hiding (minimum)

import Network.QUIC.Stream.Frag

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

deleteMin :: Frag a => Skew a -> (Skew a, Maybe (Seq a))
deleteMin h = (deleteMin' h, minimum h)

deleteMinIf :: Frag a => Int -> Skew a -> (Skew a, Maybe (Seq a))
deleteMinIf off h = case minimum h of
  jf@(Just f) | currOff f <= off -> (deleteMin' h, shrink off <$> jf)
  _                              -> (h, Nothing)

----------------------------------------------------------------

-- | Merging two heaps. Worst-case: O(N), amortized: O(log N).
merge :: Frag a => Skew a -> Skew a -> Skew a
merge t1 Leaf = t1
merge Leaf t2 = t2
merge t1@(Node l1 f1 r1) t2@(Node l2 f2 r2)
  | e1 < s2   = Node r1 f1 (merge l1 t2)
  | e2 < s1   = Node r2 f2 (merge l2 t1)
  | otherwise = let f12 | e1 == s2             = f1 >< f2
                        | s1 == e2             = f2 >< f1
                        | s1 <= s2 && e2 <= e1 = f1
                        | s2 <= s1 && e1 <= e2 = f2
                        | s1 <= s2             = f1 >< (shrink e1 f2)
                        | otherwise            = f2 >< (shrink e2 f1)
                in Node (merge l1 l2) f12 (merge r1 r2)
  where
    s1 = currOff f1
    e1 = nextOff f1
    s2 = currOff f2
    e2 = nextOff f2

{-
showSkew :: Show a => Skew a -> String
showSkew = showSkew' ""

showSkew' :: Show a => String -> Skew a -> String
showSkew' _    Leaf = "\n"
showSkew' pref (Node l x r) = show x ++ "\n"
                           ++ pref ++ "+ " ++ showSkew' pref' l
                           ++ pref ++ "+ " ++ showSkew' pref' r
  where
    pref' = "  " ++ pref
-}
