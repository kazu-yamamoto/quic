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
    describe "test vector for version 1" $ do
        let ver = Version1
        it "describes the examples of Keys" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = makeCID (dec16s "8394c8f03e515708")
            let client_initial_secret@(ClientTrafficSecret cis) = clientInitialSecret ver dcID
            client_initial_secret `shouldBe` ClientTrafficSecret (dec16 "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
            let ckey = aeadKey ver defaultCipher (Secret cis)
            ckey `shouldBe` Key (dec16 "1f369613dd76d5467730efcbe3b1a22d")
            let civ = initialVector ver defaultCipher (Secret cis)
            civ `shouldBe` IV (dec16 "fa044b2f42a3fd3b46fb255c")
            let chp = headerProtectionKey ver defaultCipher (Secret cis)
            chp `shouldBe` Key (dec16 "9f50449e04a0e810283a1e9933adedd2")
            let server_initial_secret@(ServerTrafficSecret sis) = serverInitialSecret ver dcID
            server_initial_secret `shouldBe` ServerTrafficSecret (dec16 "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
            let skey = aeadKey ver defaultCipher (Secret sis)
            skey `shouldBe` Key (dec16 "cf3a5331653c364c88f0f379b6067e37")
            let siv = initialVector ver defaultCipher (Secret sis)
            siv `shouldBe` IV (dec16 "0ac1493ca1905853b0bba03e")
            let shp = headerProtectionKey ver defaultCipher (Secret sis)
            shp `shouldBe` Key (dec16 "c206b8d9b9f0f37644430b490eeaa314")

        it "describes the examples of Client Initial" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ClientTrafficSecret cis = clientInitialSecret ver dcID
                ckey = aeadKey ver defaultCipher (Secret cis)
                civ = initialVector ver defaultCipher (Secret cis)
                chp = headerProtectionKey ver defaultCipher (Secret cis)
            ----------------------------------------------------------------
            -- payload encryption
            let clientCRYPTOframe = dec16 $ BS.concat [
                    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
                  , "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
                  , "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
                  , "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
                  , "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
                  , "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
                  , "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
                  , "75300901100f088394c8f03e51570806048000ffff"
                  ]
            let clientPacketHeader = dec16 "c300000001088394c8f03e5157080000449e00000002"
            -- c3 00000001 08 8394c8f03e515708 00 00 449e 00000002
            -- c3 (11000011)    -- flags
            -- 00000001         -- version 1
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
            let add = AssDat clientPacketHeader
            let Just (hdr,bdy) = niteEncrypt' defaultCipher ckey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let Just plaintext' = niteDecrypt' defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "d1b1c98dd7689fb8ec11d242b123dc9b")
            let Mask mask = protectionMask defaultCipher chp sample
            BS.take 5 mask `shouldBe` dec16 "437b9aec36"

        it "describes the examples of Server Initial" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ServerTrafficSecret sis = serverInitialSecret ver dcID
                skey = aeadKey ver defaultCipher (Secret sis)
                siv = initialVector ver defaultCipher (Secret sis)
                shp = headerProtectionKey ver defaultCipher (Secret sis)
            ----------------------------------------------------------------
            -- payload encryption
            let serverCRYPTOframe = dec16 $ BS.concat [
                    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
                  , "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
                  , "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
                  , "020304"
                  ]
            let serverPacketHeader = dec16 "c1000000010008f067a5502a4262b50040750001"
            -- c1 00000001 00 08 f067a5502a4262b5 00 4075 0001
            -- c1 (11000001)    -- flags
            -- 00000001         -- version 1
            -- 00               -- dcid len
            -- 08               -- scid len
            -- f067a5502a4262b5 -- scid
            -- 00               -- token length
            -- 4075             -- length
            -- 0001             -- encoded packet number

            let bodyLen = fromIntegral $ decodeInt (dec16 "4075")
            let padLen = bodyLen
                       - 2  -- packet number length
                       - 16 -- GCM encrypt expansion
                       - BS.length serverCRYPTOframe
                serverCRYPTOframePadded = serverCRYPTOframe `BS.append` BS.pack (replicate padLen 0)
            let plaintext = serverCRYPTOframePadded
            let nonce = makeNonce siv $ dec16 "0001"
            let add = AssDat serverPacketHeader
            let Just (hdr,bdy) = niteEncrypt' defaultCipher skey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let Just plaintext' = niteDecrypt' defaultCipher skey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 $ BS.drop 2 ciphertext)
            sample `shouldBe` Sample (dec16 "2cd0991cd25b0aac406a5816b6394100")
            let Mask mask = protectionMask defaultCipher shp sample
            BS.take 5 mask `shouldBe` dec16 "2ec0d8356a"

    describe "test vector for version 2" $ do
        let ver = Version2
        it "describes the examples of Keys" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = makeCID (dec16s "8394c8f03e515708")
            let client_initial_secret@(ClientTrafficSecret cis) = clientInitialSecret ver dcID
            client_initial_secret `shouldBe` ClientTrafficSecret (dec16 "9fe72e1452e91f551b770005054034e47575d4a0fb4c27b7c6cb303a338423ae")
            let ckey = aeadKey ver defaultCipher (Secret cis)
            ckey `shouldBe` Key (dec16 "95df2be2e8d549c82e996fc9339f4563")
            let civ = initialVector ver defaultCipher (Secret cis)
            civ `shouldBe` IV (dec16 "ea5e3c95f933db14b7020ad8")
            let chp = headerProtectionKey ver defaultCipher (Secret cis)
            chp `shouldBe` Key (dec16 "091efb735702447d07908f6501845794")
            let server_initial_secret@(ServerTrafficSecret sis) = serverInitialSecret ver dcID
            server_initial_secret `shouldBe` ServerTrafficSecret (dec16 "3c9bf6a9c1c8c71819876967bd8b979efd98ec665edf27f22c06e9845ba0ae2f")
            let skey = aeadKey ver defaultCipher (Secret sis)
            skey `shouldBe` Key (dec16 "15d5b4d9a2b8916aa39b1bfe574d2aad")
            let siv = initialVector ver defaultCipher (Secret sis)
            siv `shouldBe` IV (dec16 "a85e7ac31cd275cbb095c626")
            let shp = headerProtectionKey ver defaultCipher (Secret sis)
            shp `shouldBe` Key (dec16 "b13861cfadbb9d11ff942dd80c8fc33b")

        it "describes the examples of Client Initial" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ClientTrafficSecret cis = clientInitialSecret ver dcID
                ckey = aeadKey ver defaultCipher (Secret cis)
                civ = initialVector ver defaultCipher (Secret cis)
                chp = headerProtectionKey ver defaultCipher (Secret cis)
            ----------------------------------------------------------------
            -- payload encryption
            let clientCRYPTOframe = dec16 $ BS.concat [
                    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
                  , "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
                  , "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
                  , "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
                  , "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
                  , "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
                  , "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
                  , "75300901100f088394c8f03e51570806048000ffff"
                  ]
            let clientPacketHeader = dec16 "d3709a50c4088394c8f03e5157080000449e00000002"
            -- d3 709a50c4 08 8394c8f03e515708 00 00 449e 00000002
            -- d3 (11010011)    -- flags
            -- 709a50c4         -- version 2
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
            let add = AssDat clientPacketHeader
            let Just (hdr,bdy) = niteEncrypt' defaultCipher ckey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let Just plaintext' = niteDecrypt' defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "23b8e610589c83c92d0e97eb7a6e5003")
            let Mask mask = protectionMask defaultCipher chp sample
            BS.take 5 mask `shouldBe` dec16 "8e4391d84a"
