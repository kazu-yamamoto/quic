module TypesSpec where

import Data.List
import Test.Hspec
import Test.QuickCheck

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "toAckInfo and fromAckInfo" $ do
        it "should be dual" $ property $ \xs -> do
            let rs =
                    nub . sort . map (getSmall . getNonNegative) . getNonEmpty $
                        (xs :: NonEmptyList (NonNegative (Small PacketNumber)))
                rs' = reverse rs
            fromAckInfo (toAckInfo rs') `shouldBe` rs
    describe "validAckInfo" $ do
        -- RFC 9000 Sec 19.3.1 walks the ranges down from the largest
        -- acknowledged; a gap that takes the walk below zero names packets
        -- that cannot exist.
        it "accepts what toAckInfo builds" $ property $ \xs -> do
            let rs =
                    nub . sort . map (getSmall . getNonNegative) . getNonEmpty $
                        (xs :: NonEmptyList (NonNegative (Small PacketNumber)))
            validAckInfo (toAckInfo (reverse rs)) `shouldBe` True
        it "refuses a gap that reaches below zero" $
            validAckInfo (AckInfo 5 0 [(10, 0)]) `shouldBe` False
        it "refuses a first range longer than the largest acknowledged" $
            validAckInfo (AckInfo 3 9 []) `shouldBe` False
        it "refuses a range reaching below zero after a legal gap" $
            validAckInfo (AckInfo 20 0 [(0, 100)]) `shouldBe` False
        it "accepts ranges that stop at zero" $
            validAckInfo (AckInfo 5 0 [(1, 2)]) `shouldBe` True
