{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TLSSpec where

import Data.Bits
import qualified Data.ByteString as BS
import Data.Maybe
import Network.TLS.Extra.Cipher
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
    ----------------------------------------------------------------
    -- RFC 9001
    --
    describe "test vector for version 1" $ do
        let ver = Version1
        it "describes the examples of Keys (RFC 9001: A.1)" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = makeCID (dec16s "8394c8f03e515708")
            let client_initial_secret@(ClientTrafficSecret cis) = clientInitialSecret ver dcID
            client_initial_secret
                `shouldBe` ClientTrafficSecret
                    (dec16 "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
            let ckey = aeadKey ver defaultCipher (Secret cis)
            ckey `shouldBe` Key (dec16 "1f369613dd76d5467730efcbe3b1a22d")
            let civ = initialVector ver defaultCipher (Secret cis)
            civ `shouldBe` IV (dec16 "fa044b2f42a3fd3b46fb255c")
            let chp = headerProtectionKey ver defaultCipher (Secret cis)
            chp `shouldBe` Key (dec16 "9f50449e04a0e810283a1e9933adedd2")
            let server_initial_secret@(ServerTrafficSecret sis) = serverInitialSecret ver dcID
            server_initial_secret
                `shouldBe` ServerTrafficSecret
                    (dec16 "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
            let skey = aeadKey ver defaultCipher (Secret sis)
            skey `shouldBe` Key (dec16 "cf3a5331653c364c88f0f379b6067e37")
            let siv = initialVector ver defaultCipher (Secret sis)
            siv `shouldBe` IV (dec16 "0ac1493ca1905853b0bba03e")
            let shp = headerProtectionKey ver defaultCipher (Secret sis)
            shp `shouldBe` Key (dec16 "c206b8d9b9f0f37644430b490eeaa314")

        it "describes the examples of Client Initial (RFC 9001: A.2)" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ClientTrafficSecret cis = clientInitialSecret ver dcID
                ckey = aeadKey ver defaultCipher (Secret cis)
                civ = initialVector ver defaultCipher (Secret cis)
                chp = headerProtectionKey ver defaultCipher (Secret cis)
            ----------------------------------------------------------------
            -- payload encryption
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
            let padLen =
                    bodyLen
                        - 4 -- packet number length
                        - 16 -- GCM encrypt expansion
                        - BS.length clientCRYPTOframe
                clientCRYPTOframePadded = clientCRYPTOframe `BS.append` BS.pack (replicate padLen 0)
            let plaintext = clientCRYPTOframePadded
            let nonce = makeNonce civ $ dec16 "00000002"
            let add = AssDat clientPacketHeader
            let (hdr, bdy) = fromJust $ niteEncrypt' defaultCipher ckey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let plaintext' = fromJust $ niteDecrypt' defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "d1b1c98dd7689fb8ec11d242b123dc9b")
            let Mask mask = protectionMask defaultCipher chp sample
            BS.take 5 mask `shouldBe` dec16 "437b9aec36"

        it "describes the examples of Server Initial (RFC 9001: A.3)" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ServerTrafficSecret sis = serverInitialSecret ver dcID
                skey = aeadKey ver defaultCipher (Secret sis)
                siv = initialVector ver defaultCipher (Secret sis)
                shp = headerProtectionKey ver defaultCipher (Secret sis)
            ----------------------------------------------------------------
            -- payload encryption
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
            let padLen =
                    bodyLen
                        - 2 -- packet number length
                        - 16 -- GCM encrypt expansion
                        - BS.length serverCRYPTOframe
                serverCRYPTOframePadded = serverCRYPTOframe `BS.append` BS.pack (replicate padLen 0)
            let plaintext = serverCRYPTOframePadded
            let nonce = makeNonce siv $ dec16 "0001"
            let add = AssDat serverPacketHeader
            let (hdr, bdy) = fromJust $ niteEncrypt' defaultCipher skey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let plaintext' = fromJust $ niteDecrypt' defaultCipher skey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 $ BS.drop 2 ciphertext)
            sample `shouldBe` Sample (dec16 "2cd0991cd25b0aac406a5816b6394100")
            let Mask mask = protectionMask defaultCipher shp sample
            BS.take 5 mask `shouldBe` dec16 "2ec0d8356a"

        it "describes the examples of Retry (RFC 9001: A.4)" $ do
            let wire0 =
                    dec16 "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
            (ipkt, rest) <- decodePacket wire0 True
            rest `shouldBe` ""
            case ipkt of
                PacketIR retrypkt -> do
                    wire1 <- encodeRetryPacket retrypkt
                    let (f0, r0) = fromJust $ BS.uncons wire0
                        (f1, r1) = fromJust $ BS.uncons wire1
                    f0 .&. 0xf0 `shouldBe` f1 .&. 0xf0
                    r0 `shouldBe` r1
                _ -> error "Retry version 1"

{- FOURMOLU_DISABLE -}
#ifndef USE_FUSION
        it
            "describes the examples of ChaCha20-Poly1305 Short Header Packet (RFC 9001: A.5)"
            $ do
                let cipher = cipher13_CHACHA20_POLY1305_SHA256
                    secret =
                        Secret $
                            dec16 "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
                    key = aeadKey ver cipher secret
                    iv = initialVector ver cipher secret
                    hp = headerProtectionKey ver cipher secret
                    ku = nextSecret ver cipher secret
                    payloadCipherText = niteEncrypt cipher key iv (dec16 "01") (AssDat $ dec16 "4200bff4") 654360564
                    sample = Sample $ dec16 "5e5cd55c41f69080575d7999c25a5bfb"
                    mask = protectionMask cipher hp sample
                key
                    `shouldBe` Key (dec16 "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
                iv
                    `shouldBe` IV (dec16 "e0459b3474bdd0e44a41c144")
                hp
                    `shouldBe` Key (dec16 "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
                ku
                    `shouldBe` Secret
                        (dec16 "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
                payloadCipherText
                    `shouldBe` Just (dec16 "65", dec16 "5e5cd55c41f69080575d7999c25a5bfb")
                mask `shouldBe` Mask (dec16 "aefefe7d03")
#endif
{- FOURMOLU_ENSABLE -}

    ----------------------------------------------------------------
    -- RFC 9369
    --
    describe "test vector for version 2 (RFC 9369: A1)" $ do
        let ver = Version2
        it "describes the examples of Keys" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = makeCID (dec16s "8394c8f03e515708")
            let client_initial_secret@(ClientTrafficSecret cis) = clientInitialSecret ver dcID
            client_initial_secret
                `shouldBe` ClientTrafficSecret
                    (dec16 "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b")
            let ckey = aeadKey ver defaultCipher (Secret cis)
            ckey `shouldBe` Key (dec16 "8b1a0bc121284290a29e0971b5cd045d")
            let civ = initialVector ver defaultCipher (Secret cis)
            civ `shouldBe` IV (dec16 "91f73e2351d8fa91660e909f")
            let chp = headerProtectionKey ver defaultCipher (Secret cis)
            chp `shouldBe` Key (dec16 "45b95e15235d6f45a6b19cbcb0294ba9")
            let server_initial_secret@(ServerTrafficSecret sis) = serverInitialSecret ver dcID
            server_initial_secret
                `shouldBe` ServerTrafficSecret
                    (dec16 "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1")
            let skey = aeadKey ver defaultCipher (Secret sis)
            skey `shouldBe` Key (dec16 "82db637861d55e1d011f19ea71d5d2a7")
            let siv = initialVector ver defaultCipher (Secret sis)
            siv `shouldBe` IV (dec16 "dd13c276499c0249d3310652")
            let shp = headerProtectionKey ver defaultCipher (Secret sis)
            shp `shouldBe` Key (dec16 "edf6d05c83121201b436e16877593c3a")

        it "describes the examples of Client Initial (RFC 9369: A2)" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ClientTrafficSecret cis = clientInitialSecret ver dcID
                ckey = aeadKey ver defaultCipher (Secret cis)
                civ = initialVector ver defaultCipher (Secret cis)
                chp = headerProtectionKey ver defaultCipher (Secret cis)
            ----------------------------------------------------------------
            -- payload encryption
            let clientPacketHeader = dec16 "d36b3343cf088394c8f03e5157080000449e00000002"
            -- d3 6b3343cf 08 8394c8f03e515708 00 00 449e 00000002
            -- d3 (11010011)    -- flags
            -- 6b3343cf         -- version 2
            -- 08               -- dcid len
            -- 8394c8f03e515708 -- dcid
            -- 00               -- scid len
            -- 00               -- token length
            -- 449e             -- length: decodeInt (dec16 "449e")
            -- 1182 = 4 + 1162 + 16 (fixme)
            -- 00000002         -- encoded packet number

            let bodyLen = fromIntegral $ decodeInt (dec16 "449e")
            let padLen =
                    bodyLen
                        - 4 -- packet number length
                        - 16 -- GCM encrypt expansion
                        - BS.length clientCRYPTOframe
                clientCRYPTOframePadded = clientCRYPTOframe `BS.append` BS.pack (replicate padLen 0)
            let plaintext = clientCRYPTOframePadded
            let nonce = makeNonce civ $ dec16 "00000002"
            let add = AssDat clientPacketHeader
            let (hdr, bdy) = fromJust $ niteEncrypt' defaultCipher ckey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let plaintext' = fromJust $ niteDecrypt' defaultCipher ckey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 ciphertext)
            sample `shouldBe` Sample (dec16 "ffe67b6abcdb4298b485dd04de806071")
            let Mask mask = protectionMask defaultCipher chp sample
            BS.take 5 mask `shouldBe` dec16 "94a0c95e80"

        it "describes the examples of Server Initial (RFC 9369: A3)" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ServerTrafficSecret sis = serverInitialSecret ver dcID
                skey = aeadKey ver defaultCipher (Secret sis)
                siv = initialVector ver defaultCipher (Secret sis)
                shp = headerProtectionKey ver defaultCipher (Secret sis)
            ----------------------------------------------------------------
            -- payload encryption
            let serverPacketHeader = dec16 "d16b3343cf0008f067a5502a4262b50040750001"
            -- d1 709a50c4 00 08 f067a5502a4262b5 00 4075 0001
            -- d1 (11010001)    -- flags
            -- 709a50c4         -- version 2
            -- 00               -- dcid len
            -- 08               -- scid len
            -- f067a5502a4262b5 -- scid
            -- 00               -- token length
            -- 4075             -- length
            -- 0001             -- encoded packet number

            let bodyLen = fromIntegral $ decodeInt (dec16 "4075")
            let padLen =
                    bodyLen
                        - 2 -- packet number length
                        - 16 -- GCM encrypt expansion
                        - BS.length serverCRYPTOframe
                serverCRYPTOframePadded = serverCRYPTOframe `BS.append` BS.pack (replicate padLen 0)
            let plaintext = serverCRYPTOframePadded
            let nonce = makeNonce siv $ dec16 "0001"
            let add = AssDat serverPacketHeader
            let (hdr, bdy) = fromJust $ niteEncrypt' defaultCipher skey nonce plaintext add
                ciphertext = hdr `BS.append` bdy
            let plaintext' = fromJust $ niteDecrypt' defaultCipher skey nonce ciphertext add
            plaintext' `shouldBe` plaintext

            ----------------------------------------------------------------
            -- header protection
            let sample = Sample (BS.take 16 $ BS.drop 2 ciphertext)
            sample `shouldBe` Sample (dec16 "6f05d8a4398c47089698baeea26b91eb")
            let Mask mask = protectionMask defaultCipher shp sample
            BS.take 5 mask `shouldBe` dec16 "4dd92e91ea"

        it "describes the examples of Retry (RFC 9369: A4)" $ do
            let wire0 =
                    dec16 "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6"
            (ipkt, rest) <- decodePacket wire0 True
            rest `shouldBe` ""
            case ipkt of
                PacketIR retrypkt -> do
                    wire1 <- encodeRetryPacket retrypkt
                    let (f0, r0) = fromJust $ BS.uncons wire0
                        (f1, r1) = fromJust $ BS.uncons wire1
                    f0 .&. 0xf0 `shouldBe` f1 .&. 0xf0
                    r0 `shouldBe` r1
                _ -> error "Retry version 2"

{- FOURMOLU_DISABLE -}
#ifndef USE_FUSION
        it
            "describes the examples of ChaCha20-Poly1305 Short Header Packet (RFC 9369: A.5)"
            $ do
                let cipher = cipher13_CHACHA20_POLY1305_SHA256
                    secret =
                        Secret $
                            dec16 "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
                    key = aeadKey ver cipher secret
                    iv = initialVector ver cipher secret
                    hp = headerProtectionKey ver cipher secret
                    ku = nextSecret ver cipher secret
                    payloadCipherText = niteEncrypt cipher key iv (dec16 "01") (AssDat $ dec16 "4200bff4") 654360564
                    sample = Sample $ dec16 "e7b6b932bc27d786f4bc2bb20f2162ba"
                    mask = protectionMask cipher hp sample
                key
                    `shouldBe` Key (dec16 "3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2")
                iv
                    `shouldBe` IV (dec16 "a6b5bc6ab7dafce30ffff5dd")
                hp
                    `shouldBe` Key (dec16 "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2")
                ku
                    `shouldBe` Secret
                        (dec16 "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88")
                payloadCipherText
                    `shouldBe` Just (dec16 "0a", dec16 "e7b6b932bc27d786f4bc2bb20f2162ba")
                mask `shouldBe` Mask (dec16 "97580e32bf")
#endif
{- FOURMOLU_ENABLE -}

serverCRYPTOframe :: BS.ByteString
serverCRYPTOframe =
    dec16 $
        BS.concat
            [ "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
            , "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
            , "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
            , "020304"
            ]

clientCRYPTOframe :: BS.ByteString
clientCRYPTOframe =
    dec16 $
        BS.concat
            [ "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
            , "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
            , "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
            , "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
            , "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
            , "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
            , "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
            , "75300901100f088394c8f03e51570806048000ffff"
            ]
