module Network.QUIC.Stream.Frag where

import Data.Sequence (Seq, ViewL (..), ViewR (..), dropWhileL, viewl, viewr, (<|))

class Frag a where
    currOff :: a -> Int
    nextOff :: a -> Int
    shrink :: Int -> a -> a

instance Frag a => Frag (Seq a) where
    currOff s = case viewl s of
        EmptyL -> error "Seq is empty (1)"
        x :< _ -> currOff x
    nextOff s = case viewr s of
        EmptyR -> error "Seq is empty (2)"
        _ :> x -> nextOff x
    shrink = shrinkSeq

shrinkSeq :: Frag a => Int -> Seq a -> Seq a
shrinkSeq n s0 = case viewl s of
    EmptyL -> error "shrinkSeq"
    x :< xs
        | nextOff x == n -> xs
        | otherwise -> shrink n x <| xs
  where
    s = dropWhileL (\y -> not (currOff y <= n && n <= nextOff y)) s0

data F = F Int Int deriving (Show)

instance Frag F where
    currOff (F s _) = s
    nextOff (F _ e) = e
    shrink n (F s e) = if s <= n && n <= e then F n e else error "shrink"
