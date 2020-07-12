module Network.QUIC.Types.Ack where

import Network.QUIC.Imports

type PacketNumber = Int64

type Range = Int
type Gap   = Int

data AckInfo = AckInfo PacketNumber Range [(Gap,Range)]
             deriving (Eq, Show)

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
toAckInfo []  = error "toAckInfo"
toAckInfo [l] = AckInfo l 0 []
toAckInfo (l:ls)  = ack l ls 0
  where
    ack _ []     fr = AckInfo l fr []
    ack p (x:xs) fr
      | p - 1 == x  = ack x xs (fr+1)
      | otherwise   = AckInfo l fr $ ranges x xs (fromIntegral (p - x) - 2) 0
    ranges _ [] g r = [(g, r)]
    ranges p (x:xs) g r
      | p - 1 == x  = ranges x xs g (r+1)
      | otherwise   = (g, r) : ranges x xs (fromIntegral (p - x) - 2) 0

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
fromAckInfo (AckInfo lpn fr grs) = loop grs [stt .. lpn]
  where
    stt = lpn - fromIntegral fr
    loop _          []        = error "loop"
    loop []         acc       = acc
    loop ((g,r):xs) acc@(s:_) = loop xs ([z - fromIntegral r .. z] ++ acc)
      where
        z = s - fromIntegral g - 2

-- |
-- >>> fromAckInfoWithMin (AckInfo 9 0 []) 1
-- [9]
-- >>> fromAckInfoWithMin (AckInfo 9 2 []) 8
-- [8,9]
-- >>> fromAckInfoWithMin (AckInfo 8 1 [(2,1)]) 3
-- [3,7,8]
-- >>> fromAckInfoWithMin (AckInfo 9 2 [(0,1)]) 8
-- [8,9]
fromAckInfoWithMin :: AckInfo -> PacketNumber -> [PacketNumber]
fromAckInfoWithMin (AckInfo lpn fr grs) lim
  | stt < lim = [lim .. lpn]
  | otherwise = loop grs [stt .. lpn]
  where
    stt = lpn - fromIntegral fr
    loop _          []        = error "loop"
    loop []         acc       = acc
    loop ((g,r):xs) acc@(s:_)
      | z < lim  = acc
      |otherwise = loop xs ([r' .. z] ++ acc)
      where
        z = s - fromIntegral g - 2
        r' = max lim (z - fromIntegral r)

fromAckInfoToPred :: AckInfo -> (PacketNumber -> Bool)
fromAckInfoToPred (AckInfo lpn fr grs) =
    \x -> or $ map (f x) $ loop grs [(stt,lpn)]
  where
    f x (l,u) = l <= x && x <= u
    stt = lpn - fromIntegral fr
    loop _          []        = error "loop"
    loop []         acc       = acc
    loop ((g,r):xs) acc@((s,_):_) = loop xs $ (z - fromIntegral r, z) : acc
      where
        z = s - fromIntegral g - 2
