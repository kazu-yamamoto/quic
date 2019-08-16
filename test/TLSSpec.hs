{-# LANGUAGE OverloadedStrings #-}

-- https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#initial-secrets

module TLSSpec where

import qualified Data.ByteString as B
import Test.Hspec

import Network.QUIC

----------------------------------------------------------------

spec :: Spec
spec = do
    -- https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#test-vectors-initial
    describe "test vector" $ do
        it "describes the examples of Keys" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = CID (dec16 "8394c8f03e515708")
            let client_initial_secret = clientInitialSecret Draft20 dcID
            client_initial_secret `shouldBe` Secret (dec16 "8a3515a14ae3c31b9c2d6d5bc58538ca5cd2baa119087143e60887428dcb52f6")
            let ckey = aeadKey defaultCipher client_initial_secret
            ckey `shouldBe` Key (dec16 "98b0d7e5e7a402c67c33f350fa65ea54")
            let civ = initialVector defaultCipher client_initial_secret
            civ `shouldBe` IV (dec16 "19e94387805eb0b46c03a788")
            let chp = headerProtectionKey defaultCipher client_initial_secret
            chp `shouldBe` Key (dec16 "0edd982a6ac527f2eddcbb7348dea5d7")
            let server_initial_secret = serverInitialSecret Draft20 dcID
            server_initial_secret `shouldBe` Secret (dec16 "47b2eaea6c266e32c0697a9e2a898bdf5c4fb3e5ac34f0e549bf2c58581a3811")
            let skey = aeadKey defaultCipher server_initial_secret
            skey `shouldBe` Key (dec16 "9a8be902a9bdd91d16064ca118045fb4")
            let siv = initialVector defaultCipher server_initial_secret
            siv `shouldBe` IV (dec16 "0a82086d32205ba22241d8dc")
            let shp = headerProtectionKey defaultCipher server_initial_secret
            shp `shouldBe` Key (dec16 "94b9452d2b3c7c7f6da7fdd8593537fd")

        it "describes the examples of Client Initial draft 18" $ do
            let ckey = Key (dec16 "98b0d7e5e7a402c67c33f350fa65ea54")
                civ  = IV  (dec16 "19e94387805eb0b46c03a788")
                chp  = Key (dec16 "0edd982a6ac527f2eddcbb7348dea5d7")
            ----------------------------------------------------------------
            -- payload encryption
            let clientCRYPTOframe = dec16 $ B.concat [
                    "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
                  , "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
                  , "736572766572ff01000100000a00140012001d00170018001901000101010201"
                  , "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
                  , "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
                  , "05030603020308040805080604010501060102010402050206020202002d0002"
                  , "0101001c00024001"
                  ]
            let clientPacketHeader = dec16 "c3ff000012508394c8f03e51570800449f00000002"
            -- c3ff000012508394c8f03e51570800449f00000002
            -- c3 (11000011)    -- flags
            -- ff000012         -- version
            -- 50               -- dcil & scil
            -- 8394c8f03e515708 -- dcid
            -- 00               -- token length
            -- 449f             -- length: decodeInt (dec16 "449f")
                                -- = 1183 = 4 + 1163 + 16
            -- 00000002         -- encoded packet number

            let clientCRYPTOframePadded = clientCRYPTOframe `B.append` B.pack (replicate 963 0)
            let plaintext = clientCRYPTOframePadded
            let nonce = makeNonce civ $ dec16 "00000002"
            let add = AddDat clientPacketHeader
            let ciphertext = encryptPayload defaultCipher ckey nonce plaintext add
            let Just plaintext' = decryptPayload defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (B.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "0000f3a694c75775b4e546172ce9e047")
            let mask = protectionMask defaultCipher chp sample
            mask `shouldBe` Mask (dec16 "020dbc1958a7df52e6bbc9ebdfd07828")
