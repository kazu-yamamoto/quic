{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Control.Monad (forever, void)
import Data.ByteString ()
import qualified System.Timeout as Timeout
import Test.Hspec

import Network.QUIC
import qualified Network.QUIC.Client as C
import Network.QUIC.Internal
import Network.QUIC.Server

import Config
import TransportError

setup :: IO ThreadId
setup = do
    sc' <- makeTestServerConfig
    smgr <- newSessionManager
    let sc =
            sc'
                { scSessionManager = smgr
                , scUse0RTT = True
                }
    tid <- forkIO $ run sc loop
    threadDelay 500000 -- give enough time to the server
    return tid
  where
    -- Answering on what it is given.  A server that only accepts cannot
    -- catch a stream handed to the application before the frame that opened
    -- it was looked over -- the answer is what reaches the peer, for a
    -- stream the peer never opened, and the peer calls that a
    -- STREAM_STATE_ERROR before our FLOW_CONTROL_ERROR arrives.
    loop conn = forever $ do
        strm <- acceptStream conn
        void $ forkIO $ sendStream strm "x"

teardown :: ThreadId -> IO ()
teardown = killThread

spec :: Spec
spec = beforeAll setup $ afterAll teardown $ do
    transportErrorSpec testClientConfig 2000 -- 2 seconds
    -- RFC 9000 Sec 19.15 leaves these to the receiver -- "MAY treat that
    -- receipt as a connection error" -- so they live here and not in
    -- TransportError, which is the MUSTs and is run against other
    -- implementations.
    describe "NEW_CONNECTION_ID" $ do
        it "refuses one connection ID offered under two sequence numbers" $ \_ ->
            runQuietly (hooked oneCIDTwoSeqNums) `shouldThrow` protocolViolation
        it "refuses one sequence number offered for two connection IDs" $ \_ ->
            runQuietly (hooked oneSeqNumTwoCIDs) `shouldThrow` protocolViolation

-- | A client that connects, says nothing, and waits to be closed.
runQuietly :: ClientConfig -> IO (Maybe ())
runQuietly cc = Timeout.timeout 2000000 $ C.run cc $ \conn -> do
    waitEstablished conn
    threadDelay 2000000

hooked :: (EncryptionLevel -> Plain -> Plain) -> ClientConfig
hooked f = cc{ccHooks = (ccHooks cc){onPlainCreated = f}}
  where
    cc = testClientConfig

protocolViolation :: QUICException -> Bool
protocolViolation (TransportErrorIsReceived te _) = te == ProtocolViolation
protocolViolation _ = False

srt1, srt2 :: StatelessResetToken
srt1 = StatelessResetToken "0123456789abcdef"
srt2 = StatelessResetToken "fedcba9876543210"

cid1, cid2 :: CID
cid1 = makeCID "\x01\x01\x01\x01\x01\x01\x01\x01"
cid2 = makeCID "\x02\x02\x02\x02\x02\x02\x02\x02"

-- | Two frames in one packet, the second contradicting the first.  Both go
--   out together so that the peer has no chance to retire the first.
contradict :: CIDInfo -> CIDInfo -> EncryptionLevel -> Plain -> Plain
contradict a b lvl plain
    | lvl == RTT1Level = plain{plainFrames = frames ++ plainFrames plain}
    | otherwise = plain
  where
    frames = [NewConnectionID a 0, NewConnectionID b 0]

oneCIDTwoSeqNums :: EncryptionLevel -> Plain -> Plain
oneCIDTwoSeqNums = contradict (newCIDInfo 10 cid1 srt1) (newCIDInfo 11 cid1 srt1)

oneSeqNumTwoCIDs :: EncryptionLevel -> Plain -> Plain
oneSeqNumTwoCIDs = contradict (newCIDInfo 10 cid1 srt1) (newCIDInfo 10 cid2 srt2)
