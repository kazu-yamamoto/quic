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

        it "describes the examples of Client Initial draft 23" $ do
            let dcID = CID (dec16 "8394c8f03e515708")
                client_initial_secret = clientInitialSecret Draft23 dcID
                ckey = aeadKey defaultCipher client_initial_secret
                civ = initialVector defaultCipher client_initial_secret
                chp = headerProtectionKey defaultCipher client_initial_secret
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
            let clientPacketHeader = dec16 "c3ff000017088394c8f03e5157080000449e00000002"
            -- c3ff00001708 8394c8f03e5157080000449e00000002
            -- c3 (11000011)    -- flags
            -- ff000017         -- version draft 23
            -- 08               -- dcid len
            -- 8394c8f03e515708 -- dcid
            -- 00               -- scid len
            -- 00               -- token length
            -- 449e             -- length: decodeInt (dec16 "449e")
                                -- 1182 = 4 + 1162 + 16 (fixme)
            -- 00000002         -- encoded packet number

            bodyLen <- fromIntegral <$> decodeInt (dec16 "449e")
            let padLen = bodyLen
                       - 4  -- packet number length
                       - 16 -- GCM encrypt expansion
                       - B.length clientCRYPTOframe
                clientCRYPTOframePadded = clientCRYPTOframe `B.append` B.pack (replicate padLen 0)
            let plaintext = clientCRYPTOframePadded
            let nonce = makeNonce civ $ dec16 "00000002"
            let add = AddDat clientPacketHeader
            let ciphertext = encryptPayload defaultCipher ckey nonce plaintext add
            let Just plaintext' = decryptPayload defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (B.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "535064a4268a0d9d7b1c9d250ae35516")
            let Mask mask = protectionMask defaultCipher chp sample
            B.take 5 mask `shouldBe` dec16 "833b343aaa"
