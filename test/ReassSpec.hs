{-# LANGUAGE OverloadedStrings #-}

module ReassSpec where

import Test.Hspec

import Network.QUIC.Internal

import Config
import PacketSpec (makeConnections)

spec :: Spec
spec = do
    serverConf <- runIO makeTestServerConfig
    describe "putRxStreamData" $ do
        -- Flow control bounds the octets a stream may hold, not the pieces
        -- they arrive in.  A peer spending its window one octet at a time at
        -- scattered offsets stays inside the only thing that was counted,
        -- while every piece costs a ByteString, a heap node and a place in a
        -- sequence to hold.
        it "refuses to hold a stream in more pieces than the limit" $ do
            strm <- scratchStream serverConf
            let put n = putRxStreamData strm $ RxStreamData "x" (n * 2 + 1) 1 False
            -- Odd offsets, so none of them is ever adjacent to another and
            -- none can be delivered: every one has to be held.
            held <- mapM put [1 .. maxReassFragments]
            map isReassembled held `shouldSatisfy` and
            put (maxReassFragments + 1) `shouldReturn` TooFragmented
        it "keeps taking fragments it can deliver" $ do
            strm <- scratchStream serverConf
            -- In order, so each one goes straight out and nothing is held.
            answers <-
                mapM
                    (\n -> putRxStreamData strm (RxStreamData "x" n 1 False))
                    [0 .. fromIntegral maxReassFragments + 100]
            map isReassembled answers `shouldSatisfy` and

scratchStream :: ServerConfig -> IO Stream
scratchStream serverConf = do
    (conn, _) <- makeConnections serverConf Version1
    newStream conn 0 1000000 1000000

isReassembled :: FlowCntl -> Bool
isReassembled Reassembled = True
isReassembled _ = False
