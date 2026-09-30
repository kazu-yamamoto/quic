{-# LANGUAGE OverloadedStrings #-}

module TokenSpec where

import qualified Control.Exception as E
import qualified Crypto.Token as CT
import Network.Socket
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "a token the server issued" $ do
        it "is for the address it was issued to" $ do
            token <- generateToken Version1 3600 $ addr "127.0.0.1" 1234
            isTokenAddress token (addr "127.0.0.1" 1234) `shouldBe` True
        it "is not for another address" $ do
            token <- generateToken Version1 3600 $ addr "127.0.0.1" 1234
            isTokenAddress token (addr "127.0.0.2" 1234) `shouldBe` False
        it "is for the same address on another port" $ do
            -- A NAT hands a client a new port whenever it pleases, and
            -- RFC 9000 Sec 8.1.3 asks about the address.
            token <- generateToken Version1 3600 $ addr "127.0.0.1" 1234
            isTokenAddress token (addr "127.0.0.1" 5678) `shouldBe` True
        it "still knows its address after a round trip" $ do
            let cid = makeCID "01234567"
            withManager $ \mgr -> do
                token <- generateRetryToken Version1 3600 cid cid cid $ addr "127.0.0.1" 1234
                bs <- encryptToken mgr token
                mtoken <- decryptToken mgr bs
                case mtoken of
                    Nothing -> expectationFailure "the token did not come back"
                    Just token' -> do
                        isTokenAddress token' (addr "127.0.0.1" 9999) `shouldBe` True
                        isTokenAddress token' (addr "127.0.0.2" 1234) `shouldBe` False

addr :: String -> Int -> SockAddr
addr ip port = SockAddrInet (fromIntegral port) $ tupleToHostAddress $ quad ip
  where
    quad "127.0.0.1" = (127, 0, 0, 1)
    quad "127.0.0.2" = (127, 0, 0, 2)
    quad _ = error "quad"

withManager :: (CT.TokenManager -> IO a) -> IO a
withManager = E.bracket (CT.spawnTokenManager CT.defaultConfig) CT.killTokenManager
