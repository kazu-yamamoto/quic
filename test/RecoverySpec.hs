{-# LANGUAGE OverloadedStrings #-}

module RecoverySpec where

import Data.ByteString.Short ()
import qualified Data.Sequence as Seq
import Data.UnixTime
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "persistent congestion" $ do
        it "does not find a pair" $ do
            findDuration (Seq.fromList [sp0]) 0 `shouldBe` Nothing
            findDuration (Seq.fromList [sp0,sp1]) 0 `shouldBe` Nothing
            findDuration (Seq.fromList [sp0,sp1,sp2]) 0 `shouldBe` Nothing
            findDuration (Seq.fromList [sp0,sp2,sp2,sp3]) 0 `shouldBe` Nothing
            findDuration (Seq.fromList [sp0,sp2,sp2,sp3,sp4]) 0 `shouldBe` Nothing
            findDuration (Seq.fromList [sp0,sp2,sp2,sp3,sp5]) 0 `shouldBe` Nothing
            findDuration (Seq.fromList [sp0,sp2,sp2,sp3,sp4,sp5]) 2 `shouldBe` Nothing
        it "finds a pair" $ do
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5]) 0 `shouldBe` Just (UnixDiffTime 4 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6]) 0 `shouldBe` Just (UnixDiffTime 4 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7]) 0 `shouldBe` Just (UnixDiffTime 6 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7]) 3 `shouldBe` Just (UnixDiffTime 2 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7,sp8,sp9,sp10]) 2 `shouldBe` Just (UnixDiffTime 5 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7,sp8,sp9]) 0 `shouldBe` Just (UnixDiffTime 6 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7,sp8,sp9,sp10]) 0 `shouldBe` Just (UnixDiffTime 9 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7,sp8,sp9,sp10,sp20,sp21]) 0 `shouldBe` Just (UnixDiffTime 22 0)
            findDuration (Seq.fromList [sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7,sp8,sp9,sp10,sp20,sp21,sp30,sp31,sp32,sp33]) 0 `shouldBe` Just (UnixDiffTime 29 0)

sp0,sp1,sp2,sp3,sp4,sp5,sp6,sp7,sp8,sp9,sp10,sp20,sp21,sp30,sp31,sp32,sp33 :: SentPacket
sp0  = sp  0 False $ UnixTime  0 0
sp1  = sp  1 True  $ UnixTime  1 0
sp2  = sp  2 False $ UnixTime  2 0
sp3  = sp  3 False $ UnixTime  3 0
sp4  = sp  4 False $ UnixTime  4 0
sp5  = sp  5 True  $ UnixTime  5 0
sp6  = sp  6 False $ UnixTime  6 0
sp7  = sp  7 True  $ UnixTime  7 0
sp8  = sp  8 False $ UnixTime  8 0
sp9  = sp  9 False $ UnixTime  9 0
sp10 = sp 10 True  $ UnixTime 10 0
sp20 = sp 20 True  $ UnixTime 22 0
sp21 = sp 21 True  $ UnixTime 44 0
sp30 = sp 30 False $ UnixTime 50 0
sp31 = sp 31 True  $ UnixTime 51 0
sp32 = sp 32 False $ UnixTime 55 0
sp33 = sp 33 True  $ UnixTime 80 0

sp :: PacketNumber -> Bool -> TimeMicrosecond -> SentPacket
sp mypn ackeli tm = spkt { spTimeSent = tm }
  where
    ppkt = PlainPacket (Short $ toCID "") (Plain (Flags 0) 0 [])
    spkt = mkSentPacket mypn InitialLevel ppkt emptyPeerPacketNumbers ackeli
