{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Migration (
    getMyCID
  , getMyCIDs
  , getPeerCID
  , isMyCID
  , myCIDsInclude
  , resetPeerCID
  , getNewMyCID
  , getMyCIDSeqNum
  , setMyCID
  , setPeerCIDAndRetireCIDs
  , retirePeerCID
  , retireMyCID
  , addPeerCID
  , choosePeerCID
  , setPeerStatelessResetToken
  , isStatelessRestTokenValid
  , checkResponse
  , validatePath
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

getMyCID :: Connection -> IO CID
getMyCID Connection{..} = cidInfoCID . usedCIDInfo <$> readIORef myCIDDB

getMyCIDs :: Connection -> IO [CID]
getMyCIDs Connection{..} = map cidInfoCID . cidInfos <$> readIORef myCIDDB

getMyCIDSeqNum :: Connection -> IO Int
getMyCIDSeqNum Connection{..} = cidInfoSeq . usedCIDInfo <$> readIORef myCIDDB

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = cidInfoCID . usedCIDInfo <$> readTVarIO peerCIDDB

isMyCID :: Connection -> CID -> IO Bool
isMyCID Connection{..} cid =
    (== cid) . cidInfoCID . usedCIDInfo <$> readIORef myCIDDB

myCIDsInclude :: Connection -> CID -> IO Bool
myCIDsInclude Connection{..} cid =
    isJust . findByCID cid . cidInfos <$> readIORef myCIDDB

----------------------------------------------------------------

-- | Reseting to Initial CID in the client side.
resetPeerCID :: Connection -> CID -> IO ()
resetPeerCID Connection{..} cid = atomically $ writeTVar peerCIDDB $ newCIDDB cid

----------------------------------------------------------------

-- | Sending NewConnectionID
getNewMyCID :: Connection -> IO CIDInfo
getNewMyCID Connection{..} = do
    cid <- newCID
    srt <- newStatelessResetToken
    atomicModifyIORef' myCIDDB $ new cid srt

----------------------------------------------------------------

-- | Receiving NewConnectionID
addPeerCID :: Connection -> CIDInfo -> IO ()
addPeerCID Connection{..} cidInfo = do
    db <- readTVarIO peerCIDDB
    case findBySeq (cidInfoSeq cidInfo) (cidInfos db) of
      Nothing -> atomically $ modifyTVar' peerCIDDB $ add cidInfo
      Just _  -> return ()

-- | Using a new CID and sending RetireConnectionID
choosePeerCID :: Connection -> IO CIDInfo
choosePeerCID conn@Connection{..} = atomically $ do
    let ref = peerCIDDB
    db <- readTVar ref
    mncid <- pickPeerCID conn
    check $ isJust mncid
    let u = usedCIDInfo db
    setPeerCID conn $ fromJust mncid
    return u

pickPeerCID :: Connection -> STM (Maybe CIDInfo)
pickPeerCID Connection{..} = do
    db <- readTVar peerCIDDB
    case filter (/= usedCIDInfo db) (cidInfos db) of
      []        -> return Nothing
      cidInfo:_ -> return $ Just cidInfo

setPeerCID :: Connection -> CIDInfo -> STM ()
setPeerCID Connection{..} cidInfo =
    modifyTVar' peerCIDDB $ set cidInfo

-- | After sending RetireConnectionID
retirePeerCID :: Connection -> Int -> IO ()
retirePeerCID Connection{..} n =
    atomically $ modifyTVar' peerCIDDB $ del n

----------------------------------------------------------------

-- | Receiving NewConnectionID
setPeerCIDAndRetireCIDs :: Connection -> Int -> IO [Int]
setPeerCIDAndRetireCIDs Connection{..} n = atomically $ do
    db <- readTVar peerCIDDB
    let (db', ns) = arrange n db
    writeTVar peerCIDDB db'
    return $ ns

arrange :: Int -> CIDDB -> (CIDDB, [Int])
arrange n db = (db', map cidInfoSeq toDrops)
  where
    (toDrops, cidInfos') = break (\cidInfo -> cidInfoSeq cidInfo >= n) $ cidInfos db
    used = usedCIDInfo db
    used' | cidInfoSeq used >= n = used
          | otherwise            = head cidInfos' -- fixme
    db' = db {
        usedCIDInfo = used'
      , cidInfos    = cidInfos'
      }

----------------------------------------------------------------

-- | Peer starts using a new CID.
--   Old 'usedCIDInfo' is returned to send 'RetireConnectionID'.
setMyCID :: Connection -> CID -> IO ()
setMyCID Connection{..} ncid = do
    db <- readIORef myCIDDB
    case findByCID ncid (cidInfos db) of
      Nothing      -> return ()
      Just cidInfo -> atomicModifyIORef' myCIDDB $ set' cidInfo

-- | Receiving RetireConnectionID
retireMyCID :: Connection -> Int -> IO (Maybe CIDInfo)
retireMyCID Connection{..} n = atomicModifyIORef' myCIDDB $ del' n

----------------------------------------------------------------

findByCID :: CID -> [CIDInfo] -> Maybe CIDInfo
findByCID cid = find (\x -> cidInfoCID x == cid)

findBySeq :: Int -> [CIDInfo] -> Maybe CIDInfo
findBySeq num = find (\x -> cidInfoSeq x == num)

findBySRT :: StatelessResetToken -> [CIDInfo] -> Maybe CIDInfo
findBySRT srt = find (\x -> cidInfoSRT x == srt)

set :: CIDInfo -> CIDDB -> CIDDB
set cidInfo db = db'
  where
    db' = db {
        usedCIDInfo = cidInfo
      }

set' :: CIDInfo -> CIDDB -> (CIDDB, ())
set' cidInfo db = (set cidInfo db, ())

add :: CIDInfo -> CIDDB -> CIDDB
add cidInfo db = db'
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

del :: Int -> CIDDB -> CIDDB
del num db = db'
  where
    db' = case findBySeq num (cidInfos db) of
      Nothing -> db
      Just cidInfo -> db {
          cidInfos = delete cidInfo $ cidInfos db
        }

del' :: Int -> CIDDB -> (CIDDB, Maybe CIDInfo)
del' num db = (db', mcidInfo)
  where
    mcidInfo = findBySeq num (cidInfos db)
    db' = case mcidInfo of
      Nothing -> db
      Just cidInfo -> db {
          cidInfos = delete cidInfo $ cidInfos db
        }

----------------------------------------------------------------

setPeerStatelessResetToken :: Connection -> StatelessResetToken -> IO ()
setPeerStatelessResetToken Connection{..} srt =
    atomically $ modifyTVar' peerCIDDB adjust
  where
    adjust db = db'
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
    isJust . findBySRT srt . cidInfos <$> readTVarIO peerCIDDB

----------------------------------------------------------------

validatePath :: Connection -> Maybe CIDInfo -> IO ()
validatePath conn Nothing = do
    pdat <- newPathData
    setChallenges conn [pdat]
    putOutput conn $ OutControl RTT1Level [PathChallenge pdat]
    waitResponse conn
validatePath conn (Just (CIDInfo retiredSeqNum _ _)) = do
    pdat <- newPathData
    setChallenges conn [pdat]
    putOutput conn $ OutControl RTT1Level [PathChallenge pdat, RetireConnectionID retiredSeqNum]
    waitResponse conn
    retirePeerCID conn retiredSeqNum

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
