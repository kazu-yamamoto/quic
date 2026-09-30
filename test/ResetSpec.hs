{-# LANGUAGE OverloadedStrings #-}

module ResetSpec where

import Data.Bits ((.&.))
import qualified Data.ByteString as BS
import Data.List (nub)
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = describe "a stateless reset" $ do
    it "has the two bits RFC 9000 fixes at 01" $ do
        flags <- mapM (const firstByte) [1 .. 200 :: Int]
        -- Header form 0 and the QUIC Bit set.  A peer that has not asked for
        -- that bit to be greased discards anything else before it looks for a
        -- token, and we are answering a packet we have no connection for, so
        -- whether it asked is what we cannot know.
        all (\w -> w .&. 0xc0 == 0x40) flags `shouldBe` True
    it "does not always send the same bits" $ do
        flags <- mapM (const firstByte) [1 .. 200 :: Int]
        length (nub flags) `shouldSatisfy` (> 1)
    it "is read as a short header packet by a peer that greases nothing" $ do
        -- Fifty of them: with one random bit wrong, one reset gets through
        -- half the time.  True here is the peer refusing a cleared QUIC Bit,
        -- which is what a peer that has not asked for greasing does.
        bss <- mapM (const $ makeStatelessReset token) [1 .. 50 :: Int]
        pkts <- concat <$> mapM (`decodePackets` True) bss
        filter broken pkts `shouldBe` []
    it "is 1280 octets, under three times the 428 it answers" $ do
        bs <- makeStatelessReset token
        BS.length bs `shouldBe` 1280
        BS.length bs `shouldSatisfy` (< 3 * 428)
    it "ends with the token" $ do
        bs <- makeStatelessReset token
        BS.drop (BS.length bs - 16) bs `shouldBe` fromStatelessResetToken token
  where
    firstByte = BS.head <$> makeStatelessReset token
    token = StatelessResetToken "0123456789abcdef"
    broken (PacketIB BrokenPacket _) = True
    broken _ = False
