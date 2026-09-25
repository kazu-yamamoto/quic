module Network.QUIC.Types.Ack where

import Data.IntSet (IntSet)
import qualified Data.IntSet as IntSet

type PacketNumber = Int

type Range = Int
type Gap = Int

data AckInfo = AckInfo PacketNumber Range [(Gap, Range)]
    deriving (Eq, Show)

ackInfo0 :: AckInfo
ackInfo0 = AckInfo (-1) 0 []

-- | Whether the ranges name packet numbers that could exist.
--
-- RFC 9000 section 19.3.1 walks the ranges downward from the largest
-- acknowledged.  Each gap gives the largest of the next range as
-- @previous_smallest - gap - 2@, and "if the value of the Gap field or the
-- value calculated is negative, an endpoint MUST generate a connection error
-- of type FRAME_ENCODING_ERROR".
--
-- Nothing checked this.  The ranges were turned into a predicate and asked
-- about packets we had sent; ones reaching below zero simply matched nothing.
validAckInfo :: AckInfo -> Bool
validAckInfo (AckInfo lpn fr grs) = lpn >= 0 && fr >= 0 && stt >= 0 && go stt grs
  where
    stt = lpn - fr
    go _ [] = True
    go s ((g, r) : xs)
        | g < 0 || r < 0 = False
        | z < 0 || lo < 0 = False
        | otherwise = go lo xs
      where
        z = s - g - 2
        lo = z - r

-- |
-- >>> toAckInfo [9]
-- AckInfo 9 0 []
-- >>> toAckInfo [9,8,7]
-- AckInfo 9 2 []
-- >>> toAckInfo [8,7,3,2]
-- AckInfo 8 1 [(2,1)]
-- >>> toAckInfo [9,8,7,5,4]
-- AckInfo 9 2 [(0,1)]
toAckInfo :: [PacketNumber] -> AckInfo
toAckInfo [] = error "toAckInfo"
toAckInfo [l] = AckInfo l 0 []
toAckInfo (l : ls) = ack l ls 0
  where
    ack _ [] fr = AckInfo l fr []
    ack p (x : xs) fr
        | p - 1 == x = ack x xs (fr + 1)
        | otherwise = AckInfo l fr $ ranges x xs (fromIntegral (p - x) - 2) 0
    ranges _ [] g r = [(g, r)]
    ranges p (x : xs) g r
        | p - 1 == x = ranges x xs g (r + 1)
        | otherwise = (g, r) : ranges x xs (fromIntegral (p - x) - 2) 0

-- |
-- >>> fromAckInfo $ AckInfo 9 0 []
-- [9]
-- >>> fromAckInfo $ AckInfo 9 2 []
-- [7,8,9]
-- >>> fromAckInfo $ AckInfo 8 1 [(2,1)]
-- [2,3,7,8]
-- >>> fromAckInfo $ AckInfo 9 2 [(0,1)]
-- [4,5,7,8,9]
fromAckInfo :: AckInfo -> [PacketNumber]
fromAckInfo (AckInfo lpn fr grs) = loop grs stt [stt .. lpn]
  where
    stt = lpn - fromIntegral fr
    -- Carrying the smallest of the range just built, rather than reading it
    -- back off the front of the accumulator.  Taking it off the front needs a
    -- clause for the accumulator being empty, which it never is -- and that
    -- clause was an error call sitting on a path the peer's ACK ranges reach.
    loop [] _ acc = acc
    loop ((g, r) : xs) s acc = loop xs lo ([lo .. z] ++ acc)
      where
        z = s - fromIntegral g - 2
        lo = z - fromIntegral r

fromAckInfoToPred :: AckInfo -> (PacketNumber -> Bool)
fromAckInfoToPred (AckInfo lpn fr grs) =
    \x -> any (f x) $ loop grs stt [(stt, lpn)]
  where
    f x (l, u) = l <= x && x <= u
    stt = lpn - fromIntegral fr
    -- As in 'fromAckInfo': carry the smallest of the range just built instead
    -- of reading it back off the accumulator, so there is no empty case to
    -- answer for.  The peer chooses these ranges.
    loop [] _ acc = acc
    loop ((g, r) : xs) s acc = loop xs lo ((lo, z) : acc)
      where
        z = s - fromIntegral g - 2
        lo = z - fromIntegral r

----------------------------------------------------------------

newtype PeerPacketNumbers = PeerPacketNumbers IntSet
    deriving (Eq, Show)

emptyPeerPacketNumbers :: PeerPacketNumbers
emptyPeerPacketNumbers = PeerPacketNumbers IntSet.empty
