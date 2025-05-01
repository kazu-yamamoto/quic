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
    getMyRetirePriorTo,
    setMyRetirePriorTo,
    getPeerRetirePriorTo,
    setPeerRetirePriorTo,
    checkPeerCIDCapacity,
) where

import Control.Concurrent.STM
import qualified Data.IntMap.Strict as IntMap
import qualified Data.Map.Strict as Map

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
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
    let srt = genStatelessResetToken cid
    atomicModifyIORef' myCIDDB $ new cid srt

----------------------------------------------------------------

-- | Receiving NewConnectionID
addPeerCID :: Connection -> CIDInfo -> IO Bool
addPeerCID conn@Connection{..} cidInfo = do
    let lim = activeConnectionIdLimit $ getMyParameters conn
    atomically $ do
        db <- readTVar peerCIDDB
        case Map.lookup (cidInfoCID cidInfo) (revInfos db) of
            Nothing -> do
                let n = Map.size $ revInfos db
                if n >= lim
                    then return False
                    else do
                        modifyTVar' peerCIDDB $ add cidInfo
                        return True
            Just _ -> return True -- maybe retransmitted

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
        check $ isJust mncid
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

checkPeerCIDCapacity :: Connection -> IO Bool
checkPeerCIDCapacity Connection{..} = do
    lim <- activeConnectionIdLimit <$> readIORef peerParameters
    cap <- IntMap.size . cidInfos <$> readIORef myCIDDB
    return (cap < lim)

getMyRetirePriorTo :: Connection -> IO Int
getMyRetirePriorTo Connection{..} = retirePriorTo <$> readIORef myCIDDB

setMyRetirePriorTo :: Connection -> Int -> IO ()
setMyRetirePriorTo Connection{..} rpt =
    modifyIORef' myCIDDB $ \db -> db{retirePriorTo = rpt}

getPeerRetirePriorTo :: Connection -> IO Int
getPeerRetirePriorTo Connection{..} = retirePriorTo <$> readTVarIO peerCIDDB

setPeerRetirePriorTo :: Connection -> Int -> IO ()
setPeerRetirePriorTo Connection{..} rpt =
    atomically $ modifyTVar' peerCIDDB $ \db -> db{retirePriorTo = rpt}

-- | Receiving NewConnectionID
setPeerCIDAndRetireCIDs :: Connection -> Int -> IO [Int]
setPeerCIDAndRetireCIDs Connection{..} rpt = atomically $ do
    db <- readTVar peerCIDDB
    let (db', ns) = arrange rpt db
    writeTVar peerCIDDB db'
    return ns

arrange :: Int -> CIDDB -> (CIDDB, [Int])
arrange rpt db@CIDDB{..} = (db', dropSeqnums)
  where
    (toDrops, cidInfos') = IntMap.partitionWithKey (\k _ -> k < rpt) cidInfos
    dropSeqnums = IntMap.foldrWithKey (\k _ ks -> k : ks) [] toDrops
    dropCIDs = IntMap.foldr (\c r -> cidInfoCID c : r) [] toDrops
    -- IntMap.findMin is a partial function.
    -- But receiver guarantees that there is at least one cidinfo.
    usedCIDInfo'
        | cidInfoSeq usedCIDInfo >= rpt = usedCIDInfo
        | otherwise = snd $ IntMap.findMin cidInfos'
    revInfos' = foldr Map.delete revInfos dropCIDs
    db' =
        db
            { usedCIDInfo = usedCIDInfo'
            , cidInfos = cidInfos'
            , revInfos = revInfos'
            , retirePriorTo = rpt
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
add cidInfo db@CIDDB{..} = db'
  where
    db' =
        db
            { cidInfos = IntMap.insert (cidInfoSeq cidInfo) cidInfo cidInfos
            , revInfos = Map.insert (cidInfoCID cidInfo) (cidInfoSeq cidInfo) revInfos
            }

new :: CID -> StatelessResetToken -> CIDDB -> (CIDDB, CIDInfo)
new cid srt db@CIDDB{..} = (db', cidInfo)
  where
    cidInfo = newCIDInfo nextSeqNum cid srt
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

-- Used in client only.  Stateless reset is independent from
-- Connection because its CID is random.  However, client uses only
-- one Connection.  So, peerCIDDB can be considered a global variable.
-- This function tries to find the target statless reset token in
-- peerCIDDB.
isStatelessRestTokenValid :: Connection -> StatelessResetToken -> IO Bool
isStatelessRestTokenValid Connection{..} srt = srtCheck <$> readTVarIO peerCIDDB
  where
    srtCheck CIDDB{..} = foldr chk False cidInfos
    chk _ True = True
    chk cidInfo _ = cidInfoSRT cidInfo == srt

----------------------------------------------------------------

validatePath :: Connection -> PathInfo -> Maybe CIDInfo -> IO ()
validatePath conn pathInfo Nothing = do
    pdat <- newPathData
    setChallenges conn pathInfo pdat
    putOutput conn $ OutControl RTT1Level [PathChallenge pdat]
    waitResponse conn
validatePath conn pathInfo (Just cidInfo) = do
    pdat <- newPathData
    setChallenges conn pathInfo pdat
    let retiredSeqNum = cidInfoSeq cidInfo
    retirePeerCID conn retiredSeqNum
    extra <-
        if isClient conn
            then do
                -- Cf: controlConnection' ChangeClientCID
                myCidInfo <- getNewMyCID conn
                retirePriorTo' <- (+ 1) <$> getMyCIDSeqNum conn
                setMyRetirePriorTo conn retirePriorTo' -- just for record
                writeIORef (sentRetirePriorTo conn) True
                -- Client tells "My CIDs less than retirePriorTo should be retired".
                return [NewConnectionID myCidInfo retirePriorTo']
            else
                return []
    let frames = extra ++ [PathChallenge pdat, RetireConnectionID retiredSeqNum]
    putOutput conn $ OutControl RTT1Level frames
    waitResponse conn

setChallenges :: Connection -> PathInfo -> PathData -> IO ()
setChallenges Connection{..} pathInfo pdat =
    atomically $ writeTVar migrationState $ SendChallenge pathInfo pdat

setMigrationStarted :: Connection -> IO ()
setMigrationStarted Connection{..} =
    atomically $ writeTVar migrationState MigrationStarted

isPathValidating :: Connection -> IO Bool
isPathValidating Connection{..} = do
    s <- readTVarIO migrationState
    case s of
        SendChallenge{} -> return True
        MigrationStarted -> return True
        _ -> return False

waitResponse :: Connection -> IO ()
waitResponse Connection{..} = atomically $ do
    state <- readTVar migrationState
    check (state == RecvResponse)
    writeTVar migrationState NonMigration

checkResponse :: Connection -> PathData -> IO ()
checkResponse Connection{..} pdat = do
    state <- readTVarIO migrationState
    case state of
        SendChallenge pathInfo pdat'
            | pdat == pdat' -> atomically $ do
                writeTVar migrationState RecvResponse
                writeTVar (addressValidated pathInfo) True
        _ -> return ()
