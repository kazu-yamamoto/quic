{-# LANGUAGE OverloadedStrings #-}

module ParametersSpec where

import qualified Data.ByteString as BS
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "decodeParameters" $ do
        -- The list is a key, a length and that many octets, repeated.  Each
        -- integer value is itself one variable-length integer.  Anything that
        -- stops in the middle of one of those used to read off the end, and
        -- since the decoding is done inside unsafeDupablePerformIO, that
        -- arrived as an exception out of a pure value rather than as the
        -- Nothing the type promises.
        it "refuses a parameter list that stops mid-key" $
            decodeParameters (BS.pack [0x40]) `shouldSatisfy` isNothing'
        it "refuses a value shorter than its length says" $
            decodeParameters (BS.pack [0x04, 0x08, 0x01, 0x02]) `shouldSatisfy` isNothing'
        it "refuses an integer parameter with no value" $
            decodeParameters (BS.pack [0x04, 0x00]) `shouldSatisfy` isNothing'
        it "refuses an integer parameter with octets behind the integer" $
            decodeParameters (BS.pack [0x04, 0x02, 0x01, 0x02]) `shouldSatisfy` isNothing'
        it "accepts a whole one" $
            decodeParameters (BS.pack [0x04, 0x01, 0x20]) `shouldSatisfy` isJust'
        it "accepts an empty list" $
            decodeParameters "" `shouldSatisfy` isJust'
        -- RFC 9000 Sec 18.1: an unknown transport parameter is ignored.
        it "accepts an unknown parameter" $
            decodeParameters (BS.pack [0x21, 0x01, 0x00]) `shouldSatisfy` isJust'

-- Parameters has no Eq, so keep only whether one came back.
isNothing' :: Maybe Parameters -> Bool
isNothing' Nothing = True
isNothing' _ = False

isJust' :: Maybe Parameters -> Bool
isJust' = not . isNothing'
