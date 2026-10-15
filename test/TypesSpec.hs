{-# LANGUAGE OverloadedStrings #-}

module TypesSpec where

import Control.Concurrent.STM (atomically)
import Control.Monad (replicateM)
import qualified Data.ByteString.Char8 as C8
import Data.List
import qualified System.Timeout as Timeout
import Test.Hspec
import Test.QuickCheck

import Network.QUIC.Internal

-- | A packet that carries nothing but a number, to tell it from the others.
numbered :: Int -> ReceivedPacket
numbered n =
    mkReceivedPacket
        (CryptPacket (Short (toCID "")) (Crypt 0 (C8.pack $ show n) 0))
        timeMicrosecond0
        1200
        RTT1Level

number :: ReceivedPacket -> Int
number rpkt =
    let CryptPacket _ crypt = rpCryptPacket rpkt
     in read $ C8.unpack $ cryptPacket crypt

spec :: Spec
spec = do
    -- A server queues a packet having read the connection ID, which is in
    -- the clear, and finds out whether the packet is worth anything later,
    -- when the receiver decrypts it.  So the queue has to hold a bound, or
    -- anyone who can see a connection ID can fill it.  See #167.
    describe "RecvQ" $ do
        it "keeps what it has taken and drops what is past the limit" $ do
            q <- newRecvQ
            mapM_ (writeRecvQ q . numbered) [1 .. recvQLimit + 100]
            ns <- replicateM recvQLimit (number <$> readRecvQ q)
            -- The packets kept are the ones that arrived first: what is
            -- dropped is what came after the queue was full, not what the
            -- connection had already taken on.
            ns `shouldBe` [1 .. recvQLimit]
            Timeout.timeout 100000 (readRecvQ q) `shouldReturn` Nothing
        it "takes back a packet it had already taken, full or not" $ do
            q <- newRecvQ
            mapM_ (writeRecvQ q . numbered) [1 .. recvQLimit]
            -- Putting back what was put off for want of keys is not the
            -- same as taking something new on, and the limit does not apply
            -- to it.  Dropping one would lose a packet already accounted
            -- for.
            atomically $ prependRecvQ q $ numbered 0
            number <$> readRecvQ q `shouldReturn` 0
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
