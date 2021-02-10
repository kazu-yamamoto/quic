{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TLSSpec where

import qualified Data.ByteString as BS
import Test.Hspec

import Network.QUIC.Internal

----------------------------------------------------------------

instance Eq (ClientTrafficSecret a) where
    ClientTrafficSecret x == ClientTrafficSecret y = x == y

instance Eq (ServerTrafficSecret a) where
    ServerTrafficSecret x == ServerTrafficSecret y = x == y

----------------------------------------------------------------

spec :: Spec
spec = do
    let ver = Draft29
    describe "test vector" $ do
        it "describes the examples of Keys" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = makeCID (dec16s "8394c8f03e515708")
            let client_initial_secret@(ClientTrafficSecret cis) = clientInitialSecret ver dcID
            client_initial_secret `shouldBe` ClientTrafficSecret (dec16 "0088119288f1d866733ceeed15ff9d50902cf82952eee27e9d4d4918ea371d87")
            let ckey = aeadKey defaultCipher (Secret cis)
            ckey `shouldBe` Key (dec16 "175257a31eb09dea9366d8bb79ad80ba")
            let civ = initialVector defaultCipher (Secret cis)
            civ `shouldBe` IV (dec16 "6b26114b9cba2b63a9e8dd4f")
            let chp = headerProtectionKey defaultCipher (Secret cis)
            chp `shouldBe` Key (dec16 "9ddd12c994c0698b89374a9c077a3077")
            let server_initial_secret@(ServerTrafficSecret sis) = serverInitialSecret ver dcID
            server_initial_secret `shouldBe` ServerTrafficSecret (dec16 "006f881359244dd9ad1acf85f595bad67c13f9f5586f5e64e1acae1d9ea8f616")
            let skey = aeadKey defaultCipher (Secret sis)
            skey `shouldBe` Key (dec16 "149d0b1662ab871fbe63c49b5e655a5d")
            let siv = initialVector defaultCipher (Secret sis)
            siv `shouldBe` IV (dec16 "bab2b12a4c76016ace47856d")
            let shp = headerProtectionKey defaultCipher (Secret sis)
            shp `shouldBe` Key (dec16 "c0c499a65a60024a18a250974ea01dfa")

        it "describes the examples of Client Initial" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ClientTrafficSecret cis = clientInitialSecret ver dcID
                ckey = aeadKey defaultCipher (Secret cis)
                civ = initialVector defaultCipher (Secret cis)
                chp = headerProtectionKey defaultCipher (Secret cis)
            ----------------------------------------------------------------
            -- payload encryption
            let clientCRYPTOframe = dec16 $ BS.concat [
                    "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
                  , "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
                  , "736572766572ff01000100000a00140012001d00170018001901000101010201"
                  , "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
                  , "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
                  , "05030603020308040805080604010501060102010402050206020202002d0002"
                  , "0101001c00024001"
                  ]
            let clientPacketHeader = dec16 "c3ff00001d088394c8f03e5157080000449e00000002"
            -- c3ff00001d08 8394c8f03e5157080000449e00000002
            -- c3 (11000011)    -- flags
            -- ff00001d         -- version draft 29
            -- 08               -- dcid len
            -- 8394c8f03e515708 -- dcid
            -- 00               -- scid len
            -- 00               -- token length
            -- 449e             -- length: decodeInt (dec16 "449e")
                                -- 1182 = 4 + 1162 + 16 (fixme)
            -- 00000002         -- encoded packet number

            let bodyLen = fromIntegral $ decodeInt (dec16 "449e")
            let padLen = bodyLen
                       - 4  -- packet number length
                       - 16 -- GCM encrypt expansion
                       - BS.length clientCRYPTOframe
                clientCRYPTOframePadded = clientCRYPTOframe `BS.append` BS.pack (replicate padLen 0)
            let plaintext = clientCRYPTOframePadded
            let nonce = makeNonce civ $ dec16 "00000002"
            let add = AddDat clientPacketHeader
            let ciphertext = BS.concat $ encryptPayload' defaultCipher ckey nonce plaintext add
            let Just plaintext' = decryptPayload' defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "fb66bc5f93032b7ddd89fe0ff15d9c4f")
            let Mask mask = protectionMask defaultCipher chp sample
            BS.take 5 mask `shouldBe` dec16 "d64a952459"
