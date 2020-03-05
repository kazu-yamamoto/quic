{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Migration (
    getMyCID
  , getPeerCID
  , resetPeerCID
  , getNewMyCID
  , setMyCID
  , retireMyCID
  , retirePeerCID
  , addPeerCID
  , choosePeerCID
  , setPeerStatelessResetToken
  , isStatelessRestTokenValid
  , setChallenges
  , waitResponse
  , checkResponse
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

getMyCID :: Connection -> IO CID
getMyCID Connection{..} = usedCID <$> readIORef myCIDDB

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = usedCID <$> readIORef peerCIDDB

----------------------------------------------------------------

-- | Reseting to Initial CID in the client side.
resetPeerCID :: Connection -> CID -> IO ()
resetPeerCID Connection{..} cid = writeIORef peerCIDDB $ newCIDDB cid

----------------------------------------------------------------

-- | Sending NewConnectionID
getNewMyCID :: Connection -> IO CIDInfo
getNewMyCID Connection{..} = do
    cid <- newCID
    srt <- newStatelessResetToken
    atomicModifyIORef' myCIDDB $ new cid srt

-- | Peer starts using a new CID
setMyCID :: Connection -> CID -> IO Bool
setMyCID Connection{..} ncid = do
    db <- readIORef myCIDDB
    case findByCID ncid (cidInfos db) of
      Nothing      -> return False
      Just cidInfo -> do
          _ <- atomicModifyIORef' myCIDDB $ set cidInfo
          return True

-- | Receiving RetireConnectionID
retireMyCID :: Connection -> Int -> IO ()
retireMyCID Connection{..} n = retireCID myCIDDB n

-- | Sending RetireConnectionID
retirePeerCID :: Connection -> Int -> IO ()
retirePeerCID Connection{..} n = retireCID peerCIDDB n

retireCID :: IORef CIDDB -> Int -> IO ()
retireCID ref n = atomicModifyIORef ref retire
  where
    retire db = (db', ())
      where
        db' = case findBySeq n (cidInfos db) of
          Nothing -> db
          Just cidInfo -> db {
              cidInfos = delete cidInfo $ cidInfos db
            }

----------------------------------------------------------------

-- | Receiving NewConnectionID
addPeerCID :: Connection -> CIDInfo -> IO ()
addPeerCID Connection{..} cidInfo = atomicModifyIORef peerCIDDB $ add cidInfo

-- | Using a new CID and sending RetireConnectionID
choosePeerCID :: Connection -> IO (Maybe Int)
choosePeerCID Connection{..} = do
    db <- readIORef peerCIDDB
    case filterBySeq (usedSeqNum db) (cidInfos db) of
      [] -> return Nothing
      cidInfo:_ -> do
          u <- atomicModifyIORef' peerCIDDB $ set cidInfo
          return $ Just u

----------------------------------------------------------------

filterBySeq :: Int -> [CIDInfo] -> [CIDInfo]
filterBySeq num = filter (\x -> cidInfoSeq x /= num)

findByCID :: CID -> [CIDInfo] -> Maybe CIDInfo
findByCID cid = find (\x -> cidInfoCID x == cid)

findBySeq :: Int -> [CIDInfo] -> Maybe CIDInfo
findBySeq num = find (\x -> cidInfoSeq x == num)

findBySRT :: StatelessResetToken -> [CIDInfo] -> Maybe CIDInfo
findBySRT srt = find (\x -> cidInfoSRT x == srt)

set :: CIDInfo -> CIDDB -> (CIDDB, Int)
set (CIDInfo n cid _) db = (db', u)
  where
    u = usedSeqNum db
    db' = db {
        usedCID = cid
      , usedSeqNum = n
      }

add :: CIDInfo -> CIDDB -> (CIDDB, ())
add cidInfo db = (db', ())
  where
    db' = db {
        cidInfos = insert cidInfo (cidInfos db)
      }

new :: CID -> StatelessResetToken -> CIDDB -> (CIDDB, CIDInfo)
new cid srt db = (db', cidInfo)
  where
   n = nextSeqNum db
   cidInfo = CIDInfo n cid srt
   db' = db {
       nextSeqNum = nextSeqNum db + 1
     , cidInfos = insert cidInfo $ cidInfos db
     }

----------------------------------------------------------------

setPeerStatelessResetToken :: Connection -> StatelessResetToken -> IO ()
setPeerStatelessResetToken Connection{..} srt =
    atomicModifyIORef' peerCIDDB adjust
  where
    adjust db = case cidInfos db of
      CIDInfo 0 cid _:xs -> (db {
            cidInfos = CIDInfo 0 cid srt:xs
          }, ())
      _ -> (db, ())

isStatelessRestTokenValid :: Connection -> StatelessResetToken -> IO Bool
isStatelessRestTokenValid Connection{..} srt =
    isJust . findBySRT srt . cidInfos <$> readIORef peerCIDDB

----------------------------------------------------------------

setChallenges :: Connection -> [PathData] -> IO ()
setChallenges Connection{..} pdats =
    atomically $ writeTVar migrationStatus $ SendChallenge pdats

waitResponse :: Connection -> IO ()
waitResponse Connection{..} = atomically $ do
    state <- readTVar migrationStatus
    check (state == RecvResponse)
    writeTVar migrationStatus NonMigration

checkResponse :: Connection -> PathData -> IO ()
checkResponse Connection{..} pdat = do
    state <- atomically $ readTVar migrationStatus
    case state of
      SendChallenge pdats
        | pdat `elem` pdats -> atomically $ writeTVar migrationStatus RecvResponse
      _ -> return ()
