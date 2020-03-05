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
import qualified Data.IntMap as IntMap

import Network.QUIC.Connection.Types
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
    n <- atomicModifyIORef' myCIDDB $ new cid srt
    return $ CIDInfo n cid srt
  where
    new cid srt db = (db', n)
     where
       n = nextSeqNum db
       db' = db {
           usedSeqNum = n + 1
         , cids = IntMap.insert n (cid,srt) $ cids db
         }

-- | Peer starts using a new CID
setMyCID :: Connection -> CID -> IO Bool
setMyCID Connection{..} ncid = do
    db <- readIORef myCIDDB
    case findSeqNum $ cids db of
      Nothing -> return False
      Just n  -> do
          atomicModifyIORef' myCIDDB $ set n
          return True
  where
    set n db = (db', ())
      where
        db' = db {
            usedCID = ncid
          , usedSeqNum = n
          }
    findSeqNum cids = IntMap.foldlWithKey match Nothing cids
      where
        match r n (cid,_)
          | cid == ncid = Just n
          | otherwise   = r

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
        db' = db {
            cids = IntMap.delete n $ cids db
          }

----------------------------------------------------------------

-- | Receiving NewConnectionID
addPeerCID :: Connection -> CIDInfo -> IO ()
addPeerCID Connection{..} (CIDInfo n cid srt) = atomicModifyIORef peerCIDDB $ \db ->
  (db { cids = IntMap.insert n (cid,srt) (cids db) }, ())

-- | Using a new CID and sending RetireConnectionID
choosePeerCID :: Connection -> IO (Maybe Int)
choosePeerCID Connection{..} = do
    db <- readIORef peerCIDDB
    case findFresh (usedCID db) (cids db) of
      Nothing -> return Nothing
      Just (n,ncid) -> do
          u <- atomicModifyIORef' peerCIDDB $ set ncid n
          return $ Just u
  where
    set ncid n db = (db', u)
      where
        u = usedSeqNum db
        db' = db {
            usedCID = ncid
          , usedSeqNum = n
          , cids = IntMap.delete u $ cids db
          }
    findFresh ucid cids = IntMap.foldlWithKey match Nothing cids
      where
        match r n (cid,_)
          | cid == ucid = r
          | otherwise   = case r of
              Nothing -> Just (n,cid)
              Just (n0,_)
                | n < n0    -> Just (n,cid)
                | otherwise -> r

----------------------------------------------------------------

setPeerStatelessResetToken :: Connection -> StatelessResetToken -> IO ()
setPeerStatelessResetToken Connection{..} srt = do
    db <- readIORef peerCIDDB
    let db' = db {
            cids = IntMap.adjust (\(cid,_) -> (cid,srt)) 0 $ cids db
          }
    writeIORef peerCIDDB db'

isStatelessRestTokenValid :: Connection -> StatelessResetToken -> IO Bool
isStatelessRestTokenValid Connection{..} srt0 = do
    m <- cids <$> readIORef peerCIDDB
    return $ IntMap.foldl f False m
  where
    f True _ = True
    f _ (_,srt)
      | srt == srt0 = True
      | otherwise   = False

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
