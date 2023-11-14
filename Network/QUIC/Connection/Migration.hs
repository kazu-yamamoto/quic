{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Migration (
    getMyCID,
    getMyCIDs,
    getPeerCID,
    isMyCID,
    myCIDsInclude,
    shouldUpdateMyCID,
    shouldUpdatePeerCID,
    resetPeerCID,
    getNewMyCID,
    getMyCIDSeqNum,
    setMyCID,
    setPeerCIDAndRetireCIDs,
    retirePeerCID,
    retireMyCID,
    addPeerCID,
    waitPeerCID,
    choosePeerCIDForPrivacy,
    setPeerStatelessResetToken,
    isStatelessRestTokenValid,
    setMigrationStarted,
    isPathValidating,
    checkResponse,
    validatePath,
) where

import qualified Data.IntMap.Strict as IntMap
import qualified Data.Map.Strict as Map
import UnliftIO.STM

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Types

----------------------------------------------------------------

getMyCID :: Connection -> IO CID
getMyCID Connection{..} = cidInfoCID . usedCIDInfo <$> readIORef myCIDDB

getMyCIDs :: Connection -> IO [CID]
getMyCIDs Connection{..} = Map.keys . revInfos <$> readIORef myCIDDB

getMyCIDSeqNum :: Connection -> IO Int
getMyCIDSeqNum Connection{..} = cidInfoSeq . usedCIDInfo <$> readIORef myCIDDB

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = cidInfoCID . usedCIDInfo <$> readTVarIO peerCIDDB

isMyCID :: Connection -> CID -> IO Bool
isMyCID Connection{..} cid =
    (== cid) . cidInfoCID . usedCIDInfo <$> readIORef myCIDDB

shouldUpdateMyCID :: Connection -> Int -> IO Bool
shouldUpdateMyCID Connection{..} nseq = do
    useq <- cidInfoSeq . usedCIDInfo <$> readIORef myCIDDB
    return (nseq > useq)

myCIDsInclude :: Connection -> CID -> IO (Maybe Int)
myCIDsInclude Connection{..} cid =
    Map.lookup cid . revInfos <$> readIORef myCIDDB

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
addPeerCID Connection{..} cidInfo = atomically $ do
    db <- readTVar peerCIDDB
    case Map.lookup (cidInfoCID cidInfo) (revInfos db) of
        Nothing -> modifyTVar' peerCIDDB $ add cidInfo
        Just _ -> return ()

shouldUpdatePeerCID :: Connection -> IO Bool
shouldUpdatePeerCID Connection{..} =
    not . triggeredByMe <$> readTVarIO peerCIDDB

-- | Automatic CID update
choosePeerCIDForPrivacy :: Connection -> IO ()
choosePeerCIDForPrivacy conn = do
    mr <- atomically $ do
        mncid <- pickPeerCID conn
        case mncid of
            Nothing -> return ()
            Just ncid -> do
                setPeerCID conn ncid False
                return ()
        return mncid
    case mr of
        Nothing -> return ()
        Just ncid -> qlogCIDUpdate conn $ Remote $ cidInfoCID ncid

-- | Only for the internal "migration" API
waitPeerCID :: Connection -> IO CIDInfo
waitPeerCID conn@Connection{..} = do
    r <- atomically $ do
        let ref = peerCIDDB
        db <- readTVar ref
        mncid <- pickPeerCID conn
        checkSTM $ isJust mncid
        let u = usedCIDInfo db
        setPeerCID conn (fromJust mncid) True
        return u
    qlogCIDUpdate conn $ Remote $ cidInfoCID r
    return r

pickPeerCID :: Connection -> STM (Maybe CIDInfo)
pickPeerCID Connection{..} = do
    db <- readTVar peerCIDDB
    let n = cidInfoSeq $ usedCIDInfo db
        mcidinfo = IntMap.lookup (n + 1) $ cidInfos db
    return mcidinfo

setPeerCID :: Connection -> CIDInfo -> Bool -> STM ()
setPeerCID Connection{..} cidInfo pri =
    modifyTVar' peerCIDDB $ set cidInfo pri

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
    return ns

arrange :: Int -> CIDDB -> (CIDDB, [Int])
arrange n db@CIDDB{..} = (db', dropSeqnums)
  where
    (toDrops, cidInfos') = IntMap.partitionWithKey (\k _ -> k < n) cidInfos
    dropSeqnums = IntMap.foldrWithKey (\k _ ks -> k : ks) [] toDrops
    dropCIDs = IntMap.foldr (\c r -> cidInfoCID c : r) [] toDrops
    -- IntMap.findMin is a partial function.
    -- But receiver guarantees that there is at least one cidinfo.
    usedCIDInfo'
        | cidInfoSeq usedCIDInfo >= n = usedCIDInfo
        | otherwise = snd $ IntMap.findMin cidInfos'
    revInfos' = foldr Map.delete revInfos dropCIDs
    db' =
        db
            { usedCIDInfo = usedCIDInfo'
            , cidInfos = cidInfos'
            , revInfos = revInfos'
            }

----------------------------------------------------------------

-- | Peer starts using a new CID.
setMyCID :: Connection -> CID -> IO ()
setMyCID conn@Connection{..} ncid = do
    r <- atomicModifyIORef' myCIDDB findSet
    when r $ qlogCIDUpdate conn $ Local ncid
  where
    findSet db@CIDDB{..}
        | cidInfoCID usedCIDInfo == ncid = (db, False)
        | otherwise = case Map.lookup ncid revInfos of
            Nothing -> (db, False)
            Just n -> case IntMap.lookup n cidInfos of
                Nothing -> (db, False)
                Just ncidinfo -> (set ncidinfo False db, True)

-- | Receiving RetireConnectionID
retireMyCID :: Connection -> Int -> IO (Maybe CIDInfo)
retireMyCID Connection{..} n = atomicModifyIORef' myCIDDB $ del' n

----------------------------------------------------------------

set :: CIDInfo -> Bool -> CIDDB -> CIDDB
set cidInfo pri db = db'
  where
    db' =
        db
            { usedCIDInfo = cidInfo
            , triggeredByMe = pri
            }

add :: CIDInfo -> CIDDB -> CIDDB
add cidInfo@CIDInfo{..} db@CIDDB{..} = db'
  where
    db' =
        db
            { cidInfos = IntMap.insert cidInfoSeq cidInfo cidInfos
            , revInfos = Map.insert cidInfoCID cidInfoSeq revInfos
            }

new :: CID -> StatelessResetToken -> CIDDB -> (CIDDB, CIDInfo)
new cid srt db@CIDDB{..} = (db', cidInfo)
  where
    cidInfo = CIDInfo nextSeqNum cid srt
    db' =
        db
            { nextSeqNum = nextSeqNum + 1
            , cidInfos = IntMap.insert nextSeqNum cidInfo cidInfos
            , revInfos = Map.insert cid nextSeqNum revInfos
            }

del :: Int -> CIDDB -> CIDDB
del n db@CIDDB{..} = db'
  where
    db' = case IntMap.lookup n cidInfos of
        Nothing -> db
        Just cidInfo ->
            db
                { cidInfos = IntMap.delete n cidInfos
                , revInfos = Map.delete (cidInfoCID cidInfo) revInfos
                }

del' :: Int -> CIDDB -> (CIDDB, Maybe CIDInfo)
del' n db@CIDDB{..} = (db', mcidInfo)
  where
    mcidInfo = IntMap.lookup n cidInfos
    db' = case mcidInfo of
        Nothing -> db
        Just cidInfo ->
            db
                { cidInfos = IntMap.delete n cidInfos
                , revInfos = Map.delete (cidInfoCID cidInfo) revInfos
                }

----------------------------------------------------------------

setPeerStatelessResetToken :: Connection -> StatelessResetToken -> IO ()
setPeerStatelessResetToken Connection{..} srt =
    atomically $ modifyTVar' peerCIDDB adjust
  where
    adjust db@CIDDB{..} = db'
      where
        db' = case IntMap.lookup 0 cidInfos of
            Nothing -> db
            Just cidinfo ->
                let cidinfo' = cidinfo{cidInfoSRT = srt}
                 in db
                        { cidInfos =
                            IntMap.insert 0 cidinfo' $
                                IntMap.delete 0 cidInfos
                        , usedCIDInfo = cidinfo'
                        }

isStatelessRestTokenValid :: Connection -> CID -> StatelessResetToken -> IO Bool
isStatelessRestTokenValid Connection{..} cid srt = srtCheck <$> readTVarIO peerCIDDB
  where
    srtCheck CIDDB{..} = case Map.lookup cid revInfos of
        Nothing -> False
        Just n -> case IntMap.lookup n cidInfos of
            Nothing -> False
            Just (CIDInfo _ _ srt0) -> srt == srt0

----------------------------------------------------------------

validatePath :: Connection -> Maybe CIDInfo -> IO ()
validatePath conn Nothing = do
    pdat <- newPathData
    setChallenges conn [pdat]
    putOutput conn $ OutControl RTT1Level [PathChallenge pdat] $ return ()
    waitResponse conn
validatePath conn (Just (CIDInfo retiredSeqNum _ _)) = do
    pdat <- newPathData
    setChallenges conn [pdat]
    putOutput conn $
        OutControl RTT1Level [PathChallenge pdat, RetireConnectionID retiredSeqNum] $
            return ()
    waitResponse conn
    retirePeerCID conn retiredSeqNum

setChallenges :: Connection -> [PathData] -> IO ()
setChallenges Connection{..} pdats =
    atomically $ writeTVar migrationState $ SendChallenge pdats

setMigrationStarted :: Connection -> IO ()
setMigrationStarted Connection{..} =
    atomically $ writeTVar migrationState MigrationStarted

isPathValidating :: Connection -> IO Bool
isPathValidating Connection{..} = do
    s <- readTVarIO migrationState
    case s of
        SendChallenge _ -> return True
        MigrationStarted -> return True
        _ -> return False

waitResponse :: Connection -> IO ()
waitResponse Connection{..} = atomically $ do
    state <- readTVar migrationState
    checkSTM (state == RecvResponse)
    writeTVar migrationState NonMigration

checkResponse :: Connection -> PathData -> IO ()
checkResponse Connection{..} pdat = do
    state <- readTVarIO migrationState
    case state of
        SendChallenge pdats
            | pdat `elem` pdats -> atomically $ writeTVar migrationState RecvResponse
        _ -> return ()
