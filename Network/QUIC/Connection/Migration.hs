{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Migration (
    getMyCID
  , getPeerCID
  , isMyCID
  , resetPeerCID
  , getNewMyCID
  , setMyCID
  , retireMyCID
  , retirePeerCID
  , addPeerCID
  , chooseMyCID
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
getMyCID Connection{..} = cidInfoCID . usedCIDInfo <$> readIORef myCIDDB

isMyCID :: Connection -> CID -> IO Bool
isMyCID Connection{..} cid =
    isJust . findByCID cid . cidInfos <$> readIORef myCIDDB

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = cidInfoCID . usedCIDInfo <$> readIORef peerCIDDB

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
retireCID ref n = atomicModifyIORef ref $ del n

----------------------------------------------------------------

-- | Receiving NewConnectionID
addPeerCID :: Connection -> CIDInfo -> IO ()
addPeerCID Connection{..} cidInfo = atomicModifyIORef peerCIDDB $ add cidInfo

-- | Using a new CID and sending RetireConnectionID
chooseMyCID :: Connection -> IO (Maybe CIDInfo)
chooseMyCID Connection{..} = chooseCID myCIDDB

-- | Using a new CID and sending RetireConnectionID
choosePeerCID :: Connection -> IO (Maybe CIDInfo)
choosePeerCID Connection{..} = chooseCID peerCIDDB

chooseCID :: IORef CIDDB -> IO (Maybe CIDInfo)
chooseCID ref = do
    db <- readIORef ref
    case filter (/= usedCIDInfo db) (cidInfos db) of
      [] -> return Nothing
      cidInfo:_ -> do
          u <- atomicModifyIORef' ref $ set cidInfo
          return $ Just u

----------------------------------------------------------------

findByCID :: CID -> [CIDInfo] -> Maybe CIDInfo
findByCID cid = find (\x -> cidInfoCID x == cid)

findBySeq :: Int -> [CIDInfo] -> Maybe CIDInfo
findBySeq num = find (\x -> cidInfoSeq x == num)

findBySRT :: StatelessResetToken -> [CIDInfo] -> Maybe CIDInfo
findBySRT srt = find (\x -> cidInfoSRT x == srt)

set :: CIDInfo -> CIDDB -> (CIDDB, CIDInfo)
set cidInfo db = (db', u)
  where
    u = usedCIDInfo db
    db' = db {
        usedCIDInfo = cidInfo
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

del :: Int -> CIDDB -> (CIDDB, ())
del num db = (db', ())
  where
    db' = case findBySeq num (cidInfos db) of
      Nothing -> db
      Just cidInfo -> db {
          cidInfos = delete cidInfo $ cidInfos db
        }

----------------------------------------------------------------

setPeerStatelessResetToken :: Connection -> StatelessResetToken -> IO ()
setPeerStatelessResetToken Connection{..} srt =
    atomicModifyIORef' peerCIDDB adjust
  where
    adjust db = (db', ())
      where
        db' = case cidInfos db of
          CIDInfo 0 cid _:xs -> adj xs $ CIDInfo 0 cid srt
          _ -> db
        adj xs cidInfo = case usedCIDInfo db of
                        CIDInfo 0 _ _ -> db { usedCIDInfo = cidInfo
                                            , cidInfos = cidInfo:xs
                                            }
                        _             -> db { cidInfos = cidInfo:xs}


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
