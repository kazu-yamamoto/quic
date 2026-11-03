{-# LANGUAGE OverloadedStrings #-}

module ReassSpec where

import qualified Data.ByteString as BS
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
        -- A copy sent again with other boundaries brings octets of its own,
        -- and taking none of them leaves a gap that is never filled.
        it "takes the new part of a fragment overlapping delivered data" $ do
            strm <- scratchStream serverConf
            putFrag strm 0 10 False `shouldReturn` Reassembled 10
            putFrag strm 5 20 False `shouldReturn` Reassembled 10
            takeRecvStreamQwithSize strm 100 `shouldReturn` octets 0 20
        it "takes data with a FIN when an earlier FIN is held" $ do
            strm <- scratchStream serverConf
            putFrag strm 10 20 True `shouldReturn` Reassembled 10
            putFrag strm 0 20 True `shouldReturn` Reassembled 10
            takeRecvStreamQwithSize strm 100 `shouldReturn` octets 0 20
            takeRecvStreamQwithSize strm 100 `shouldReturn` ""
        it "delivers past a held piece the others cover" $ do
            strm <- scratchStream serverConf
            mapM_
                (\(s, e) -> putFrag strm s e False)
                [(20, 30), (35, 38), (40, 50), (30, 40), (0, 20)]
            takeRecvStreamQwithSize strm 100 `shouldReturn` octets 0 50
        -- Counting a copy twice would charge the connection's window for
        -- octets it already paid for, and the pieces it holds for nothing.
        it "neither counts nor holds a copy of a held fragment" $ do
            strm <- scratchStream serverConf
            putFrag strm 10 20 False `shouldReturn` Reassembled 10
            answers <- mapM (const $ putFrag strm 12 18 False) [0 .. maxReassFragments]
            answers `shouldSatisfy` all (== Duplicated)
            putFrag strm 5 25 False `shouldReturn` Reassembled 10
            putFrag strm 0 5 False `shouldReturn` Reassembled 5
            takeRecvStreamQwithSize strm 100 `shouldReturn` octets 0 25

-- | The octets from one offset up to another, each its offset modulo 256.
octets :: Int -> Int -> BS.ByteString
octets s e = BS.pack $ map fromIntegral [s .. e - 1]

putFrag :: Stream -> Int -> Int -> Bool -> IO FlowCntl
putFrag strm s e fin = putRxStreamData strm $ RxStreamData (octets s e) s (e - s) fin

scratchStream :: ServerConfig -> IO Stream
scratchStream serverConf = do
    (conn, _) <- makeConnections serverConf Version1
    newStream conn 0 1000000 1000000

isReassembled :: FlowCntl -> Bool
isReassembled (Reassembled _) = True
isReassembled _ = False
