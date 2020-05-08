module TypesSpec where

import Data.List
import Test.Hspec
import Test.QuickCheck

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "toAckInfo and fromAckInfo" $ do
        it "should be dual" $ property $ \xs -> do
            let rs = nub . sort . map (getSmall . getNonNegative) . getNonEmpty $  (xs :: NonEmptyList (NonNegative (Small PacketNumber)))
                rs' = reverse rs
            fromAckInfo (toAckInfo rs') `shouldBe` rs
