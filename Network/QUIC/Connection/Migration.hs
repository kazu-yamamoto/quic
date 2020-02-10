{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Migration (
    getMyCID
  , getPeerCID
  , setMyCID
  , setPeerCID
  , choosePeerCID
  , getNewMyCID
  , addMyCID
  , addPeerCID
  , resetPeerCID
  , setPeerStatelessResetToken
  , isStatelessRestTokenValid
  , setChallenges
  , waitResponse
  , checkResponse
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Connection.Types
import Network.QUIC.Types

getMyCID :: Connection -> IO CID
getMyCID Connection{..} = currentCID <$> readIORef myCIDDB

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = currentCID <$> readIORef peerCIDDB

getNewMyCID :: Connection -> IO (Int, CID, StatelessResetToken)
getNewMyCID Connection{..} = getNewCID myCIDDB

setMyCID :: Connection -> CID -> IO ()
setMyCID Connection{..} c = atomicModifyIORef' myCIDDB set
  where
    set db = (db', ())
      where
        cc = currentCID db
        ciddb' = go cc $ ciddb db
        db' = db {
            currentCID = c
          , ciddb = ciddb'
          }
    go _ [] = []
    go cc (x@(_,cid,_):xs)
      | cid == cc = xs
      | otherwise = x : go cc xs

setPeerCID :: Connection -> CID -> IO Int
setPeerCID Connection{..} c = atomicModifyIORef' peerCIDDB set
  where
    set db = (db', n)
      where
        cc = currentCID db
        (n,ciddb') = go cc $ ciddb db
        db' = db {
            currentCID = c
          , ciddb = ciddb'
          }
    go _ [] = (0,[])
    go cc (x@(n,cid,_):xs)
      | cid == cc = (n,xs)
      | otherwise = let (m,xs') = go cc xs
                    in (m,x:xs')

-- not delete cid at this moment
choosePeerCID :: Connection -> IO (Maybe CID)
choosePeerCID Connection{..} = do
    db <- readIORef peerCIDDB
    let cid = currentCID db
        xs = ciddb db
    return $ go cid Nothing xs
  where
    go _ r [] = r
    go cid r ((_,c,_):xs)
      | cid == c  = go cid r xs
      | otherwise = go cid (Just c) xs

getNewCID :: IORef CIDDB -> IO (Int,CID,StatelessResetToken)
getNewCID ref = do
    cid <- newCID
    srt <- newStatelessResetToken
    atomicModifyIORef' ref $ get cid srt
  where
    get cid srt db = (db', ent)
      where
        n = nextSeqNum db
        ent = (n, cid, srt)
        db' = db {
            nextSeqNum = n + 1
          , ciddb = ent : ciddb db
          }

addCID :: IORef CIDDB -> (Int,CID,StatelessResetToken) -> IO ()
addCID ref ent = atomicModifyIORef ref $ \db -> (db { ciddb = ent : ciddb db }, ())

addMyCID :: Connection -> (Int,CID,StatelessResetToken) -> IO ()
addMyCID Connection{..} = addCID myCIDDB

addPeerCID :: Connection -> (Int,CID,StatelessResetToken) -> IO ()
addPeerCID Connection{..} = addCID peerCIDDB

resetPeerCID :: Connection -> CID -> IO ()
resetPeerCID Connection{..} cid = writeIORef peerCIDDB $ newCIDDB cid

setPeerStatelessResetToken :: Connection -> StatelessResetToken -> IO ()
setPeerStatelessResetToken Connection{..} srt = do
    db <- readIORef peerCIDDB
    let db' = db {
            ciddb = [(0,currentCID db,srt)]
          }
    writeIORef peerCIDDB db'

isStatelessRestTokenValid :: Connection -> StatelessResetToken -> IO Bool
isStatelessRestTokenValid Connection{..} srt =
    go . ciddb <$> readIORef peerCIDDB
  where
    go [] = False
    go ((_,_,token):xs)
      | token == srt = True
      | otherwise    = go xs

{-
retireCID :: Connection -> Int -> IO ()
retireCID = undefined

retireToCID :: Connection -> Int -> IO ()
retireToCID = undefined
-}

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
