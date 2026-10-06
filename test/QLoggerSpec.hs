{-# LANGUAGE OverloadedStrings #-}

module QLoggerSpec where

import qualified Control.Exception as E
import System.Directory (listDirectory)
import Test.Hspec

import Network.QUIC.Internal

import Config

spec :: Spec
spec = do
    describe "dirQLogger" $ do
        -- A client names its file after the peer CID and a server after the
        -- original destination CID, which for one connection are the same
        -- value.  Both in one process pointed at one directory therefore used
        -- to ask for the same file, and LogFileNoRotate takes a file
        -- exclusively: the second to ask got "openFile: resource busy" thrown
        -- through its connection setup rather than a worse log.
        it "gives the two ends of one connection their own files" $
            withTempDir "quic-qlogger-spec" $ \dir -> do
                now <- getTimeMicrosecond
                let cid = toCID "01234567"
                E.bracket (dirQLogger (Just dir) now cid "client") snd $ \_ ->
                    E.bracket (dirQLogger (Just dir) now cid "server") snd $ \_ ->
                        return ()
                files <- listDirectory dir
                length files `shouldBe` 2
