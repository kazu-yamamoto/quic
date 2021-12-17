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
    let ver = Version1
    describe "test vector" $ do
        it "describes the examples of Keys" $ do
            ----------------------------------------------------------------
            -- shared keys
            let dcID = makeCID (dec16s "8394c8f03e515708")
            let client_initial_secret@(ClientTrafficSecret cis) = clientInitialSecret ver dcID
            client_initial_secret `shouldBe` ClientTrafficSecret (dec16 "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
            let ckey = aeadKey Version1 defaultCipher (Secret cis)
            ckey `shouldBe` Key (dec16 "1f369613dd76d5467730efcbe3b1a22d")
            let civ = initialVector Version1 defaultCipher (Secret cis)
            civ `shouldBe` IV (dec16 "fa044b2f42a3fd3b46fb255c")
            let chp = headerProtectionKey Version1 defaultCipher (Secret cis)
            chp `shouldBe` Key (dec16 "9f50449e04a0e810283a1e9933adedd2")
            let server_initial_secret@(ServerTrafficSecret sis) = serverInitialSecret ver dcID
            server_initial_secret `shouldBe` ServerTrafficSecret (dec16 "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
            let skey = aeadKey Version1 defaultCipher (Secret sis)
            skey `shouldBe` Key (dec16 "cf3a5331653c364c88f0f379b6067e37")
            let siv = initialVector Version1 defaultCipher (Secret sis)
            siv `shouldBe` IV (dec16 "0ac1493ca1905853b0bba03e")
            let shp = headerProtectionKey Version1 defaultCipher (Secret sis)
            shp `shouldBe` Key (dec16 "c206b8d9b9f0f37644430b490eeaa314")

        it "describes the examples of Client Initial" $ do
            let dcID = makeCID (dec16s "8394c8f03e515708")
                ClientTrafficSecret cis = clientInitialSecret ver dcID
                ckey = aeadKey Version1 defaultCipher (Secret cis)
                civ = initialVector Version1 defaultCipher (Secret cis)
                chp = headerProtectionKey Version1 defaultCipher (Secret cis)
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
            -- c30000000108 8394c8f03e515708 0000449e 00000002
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
