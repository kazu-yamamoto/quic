{-# LANGUAGE OverloadedStrings #-}

module PacketSpec where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.IORef
import qualified Network.Socket as NS
import Test.Hspec

import Network.QUIC
import Network.QUIC.Internal

import Config

spec :: Spec
spec = do
    -- https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#test-vectors-initial
    serverConf <- runIO makeTestServerConfig
    describe "test vector" $ do
        it "describes example of Client Initial draft 29" $ do
            let noLog _ = return ()
            let serverCID = makeCID $ dec16s "8394c8f03e515708"
                clientCID = makeCID ""
                serverAuthCIDs = defaultAuthCIDs { initSrcCID = Just serverCID
                                                 , origDstCID = Just serverCID
                                                 }
                clientAuthCIDs = defaultAuthCIDs { initSrcCID = Just clientCID }
                -- dummy
            let clientConf = testClientConfig
                ver = head $ confVersions $ ccConfig clientConf
            s <- NS.socket NS.AF_INET NS.Stream NS.defaultProtocol
            q <- newRecvQ
            sref <- newIORef (s,q)
            clientConn <- clientConnection clientConf ver clientAuthCIDs serverAuthCIDs noLog noLog defaultHooks sref
            initializeCoder clientConn InitialLevel $ initialSecrets ver serverCID
            serverConn <- serverConnection serverConf ver serverAuthCIDs clientAuthCIDs noLog noLog defaultHooks sref
            initializeCoder serverConn InitialLevel $ initialSecrets ver serverCID
            (PacketIC (CryptPacket header crypt), _) <- decodePacket clientInitialPacketBinary
            Just plain <- decryptCrypt serverConn crypt InitialLevel
            let ppkt = PlainPacket header plain
            clientInitialPacketBinary' <- B.concat <$> encodePlainPacket clientConn ppkt Nothing
            (PacketIC (CryptPacket header' crypt'), _) <- decodePacket clientInitialPacketBinary'
            Just plain' <- decryptCrypt serverConn crypt' InitialLevel
            header' `shouldBe` header
            plainFrames plain' `shouldBe` plainFrames plain

clientInitialPacketBinary :: ByteString
clientInitialPacketBinary = dec16 $ B.concat [
    "c5ff00001d088394c8f03e5157080000449e4a95245bfb66bc5f93032b7ddd89"
  , "fe0ff15d9c4f7050fccdb71c1cd80512d4431643a53aafa1b0b518b44968b18b"
  , "8d3e7a4d04c30b3ed9410325b2abb2dafb1c12f8b70479eb8df98abcaf95dd8f"
  , "3d1c78660fbc719f88b23c8aef6771f3d50e10fdfb4c9d92386d44481b6c52d5"
  , "9e5538d3d3942de9f13a7f8b702dc31724180da9df22714d01003fc5e3d165c9"
  , "50e630b8540fbd81c9df0ee63f94997026c4f2e1887a2def79050ac2d86ba318"
  , "e0b3adc4c5aa18bcf63c7cf8e85f569249813a2236a7e72269447cd1c755e451"
  , "f5e77470eb3de64c8849d292820698029cfa18e5d66176fe6e5ba4ed18026f90"
  , "900a5b4980e2f58e39151d5cd685b10929636d4f02e7fad2a5a458249f5c0298"
  , "a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d0"
  , "7bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c"
  , "7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c"
  , "9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b8"
  , "8fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34"
  , "ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc"
  , "59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce5"
  , "51986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38"
  , "f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f7"
  , "6d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069"
  , "d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948"
  , "c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f"
  , "7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557"
  , "831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a"
  , "8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c"
  , "04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef4"
  , "3045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a"
  , "61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe23"
  , "1da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae"
  , "030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d444"
  , "56269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254"
  , "bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf3"
  , "6b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a"
  , "0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0"
  , "edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872"
  , "a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a566"
  , "8c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09"
  , "089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d48"
  , "43b1ca70a2d8d3f725ead1391377dcc0"
  ]
