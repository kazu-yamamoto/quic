{-# LANGUAGE OverloadedStrings #-}

module TypesSpec where

import Control.Concurrent.STM (atomically)
import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.List
import Data.Word (Word8)
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

-- | The ACK Delay of an ACK frame whose delay field is the given octets.
ackDelayOf :: [Word8] -> IO Delay
ackDelayOf field = do
    Just [Ack _ d] <-
        decodeFramesBS $ BS.pack $ [0x02, 0x00] ++ field ++ [0x00, 0x00]
    return d

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
            q <- newRecvQ =<< newRecvBudget maxBound
            mapM_ (writeRecvQ q . numbered) [1 .. recvQLimit + 100]
            ns <- replicateM recvQLimit (number <$> readRecvQ q)
            -- The packets kept are the ones that arrived first: what is
            -- dropped is what came after the queue was full, not what the
            -- connection had already taken on.
            ns `shouldBe` [1 .. recvQLimit]
            Timeout.timeout 100000 (readRecvQ q) `shouldReturn` Nothing
        it "takes back a packet it had already taken, full or not" $ do
            q <- newRecvQ =<< newRecvBudget maxBound
            mapM_ (writeRecvQ q . numbered) [1 .. recvQLimit]
            -- Putting back what was put off for want of keys is not the
            -- same as taking something new on, and the limit does not apply
            -- to it.  Dropping one would lose a packet already accounted
            -- for.
            atomically $ prependRecvQ q $ numbered 0
            number <$> readRecvQ q `shouldReturn` 0
        -- #170: what one connection may queue times the number of
        -- connections was a limit on nothing.
        it "shares a budget with the other queues of the endpoint" $ do
            budget <- newRecvBudget 3600 -- three packets of 1200
            q1 <- newRecvQ budget
            q2 <- newRecvQ budget
            mapM_ (writeRecvQ q1 . numbered) [1, 2]
            mapM_ (writeRecvQ q2 . numbered) [3, 4]
            number <$> readRecvQ q1 `shouldReturn` 1
            writeRecvQ q2 $ numbered 5
            number <$> readRecvQ q2 `shouldReturn` 3
            number <$> readRecvQ q2 `shouldReturn` 5
        it "gives back what a closed queue holds and takes no more" $ do
            budget <- newRecvBudget 2400
            q1 <- newRecvQ budget
            q2 <- newRecvQ budget
            mapM_ (writeRecvQ q1 . numbered) [1, 2]
            closeRecvQ q1
            writeRecvQ q1 $ numbered 3
            mapM_ (writeRecvQ q2 . numbered) [4, 5]
            number <$> readRecvQ q2 `shouldReturn` 4
            number <$> readRecvQ q2 `shouldReturn` 5
            Timeout.timeout 100000 (readRecvQ q1) `shouldReturn` Nothing
    -- RFC 9000 Sec 19.3: the field counts units of 2 ^ ack_delay_exponent
    -- microseconds, and it is a varint, so up to 2 ^ 62 - 1 of them.
    describe "ackDelayMicro" $ do
        it "scales the field by the exponent" $ do
            d <- ackDelayOf [0x40, 0x7d] -- 125
            ackDelayMicro 3 d `shouldBe` Microseconds 1000
            ackDelayMicro 0 d `shouldBe` Microseconds 125
        it "saturates instead of overflowing" $ do
            d <- ackDelayOf $ replicate 8 0xff -- 2 ^ 62 - 1
            ackDelayMicro 20 d `shouldBe` Microseconds maxBound
    describe "capAckInfo" $ do
        it "keeps an ACK frame that fits" $ do
            let ai = toAckInfo [9, 8, 7, 5, 4]
            capAckInfo 64 ai `shouldBe` ai
        it "drops the oldest ranges of one that does not" $ do
            let pns = [0, 2 .. 1000] -- 501 ranges
                ai@(AckInfo lpn _ _) = capAckInfo 64 $ toAckInfo $ reverse pns
            bs <- encodeFrames [Ack ai noDelay]
            BS.length bs `shouldSatisfy` (<= 64)
            BS.length bs `shouldSatisfy` (> 60)
            lpn `shouldBe` 1000
            fromAckInfo ai `shouldSatisfy` (`isSuffixOf` pns)
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
