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
    addPeerCIDAndRetire,
    retirePeerCID,
    retireMyCID,
    isMyCIDSeqNumIssued,
    addPeerCID,
    isPeerCIDConsistent,
    waitPeerCID,
    choosePeerCIDForPrivacy,
    setPeerStatelessResetToken,
    isStatelessRestTokenValid,
    claimMigration,
    abandonMigration,
    checkResponse,
    validatePath,
    validateMigration,
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
import Network.QUIC.Connection.Timeout (timeout)
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Recovery.Persistent (calcPTO)
import Network.QUIC.Recovery.Types (initialRTT)
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

-- | Does this NEW_CONNECTION_ID agree with what the peer has already said?
--
-- RFC 9000 Sec 19.15: a connection ID repeated with a different stateless
-- reset token or a different sequence number, or a sequence number used for
-- a different connection ID, MAY be treated as a connection error of type
-- PROTOCOL_VIOLATION.
--
-- A retransmission says exactly what it said before and is not caught here,
-- which is the point of comparing the whole 'CIDInfo' rather than noting
-- that we have seen the connection ID.  One that has since been retired is
-- no longer in the table and is not caught either; that is the lenient side
-- of a MAY, and the alternative is remembering every sequence number the
-- peer has ever used.
isPeerCIDConsistent :: Connection -> CIDInfo -> IO Bool
isPeerCIDConsistent Connection{..} cidInfo = agree <$> readTVarIO peerCIDDB
  where
    agree CIDDB{..} = ok bySeqNum && ok byCID
      where
        ok = maybe True (== cidInfo)
        bySeqNum = IntMap.lookup (cidInfoSeq cidInfo) cidInfos
        byCID =
            flip IntMap.lookup cidInfos
                =<< Map.lookup (cidInfoCID cidInfo) revInfos

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

-- | Receiving NewConnectionID: adding the CID and retiring those below
--   Retire Prior To in one go.  Retired first, nothing might be left to use;
--   added first, the limit is checked only after the retirement
--   (RFC 9000 Sec 5.1.1).  'Nothing' if the limit is exceeded.
addPeerCIDAndRetire :: Connection -> CIDInfo -> Int -> IO (Maybe [Int])
addPeerCIDAndRetire conn@Connection{..} cidInfo rpt = do
    let lim = activeConnectionIdLimit $ getMyParameters conn
    atomically $ do
        db0 <- readTVar peerCIDDB
        let db1
                | Map.member (cidInfoCID cidInfo) (revInfos db0) = db0 -- retransmitted
                | otherwise = add cidInfo db0
            (db2, ns)
                | rpt >= retirePriorTo db0 = arrange rpt db1
                | otherwise = (db1, [])
        if Map.size (revInfos db2) > lim
            then return Nothing
            else do
                writeTVar peerCIDDB db2
                return $ Just ns

arrange :: Int -> CIDDB -> (CIDDB, [Int])
arrange rpt db@CIDDB{..} = (db', dropSeqnums)
  where
    (toDrops, cidInfos') = IntMap.partitionWithKey (\k _ -> k < rpt) cidInfos
    dropSeqnums = IntMap.foldrWithKey (\k _ ks -> k : ks) [] toDrops
    dropCIDs = IntMap.foldr (\c r -> cidInfoCID c : r) [] toDrops
    -- The caller adds a CID at or above rpt first, so one is left.
    usedCIDInfo'
        | cidInfoSeq usedCIDInfo >= rpt = usedCIDInfo
        | otherwise = maybe usedCIDInfo snd $ IntMap.lookupMin cidInfos'
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
-- | Whether the sequence number is one we have given the peer.
--
-- RFC 9000 Sec 19.16: "Receipt of a RETIRE_CONNECTION_ID frame containing a
-- sequence number greater than any previously sent to the peer MUST be
-- treated as a connection error of type PROTOCOL_VIOLATION."  One we have
-- given and already retired is not that -- the frame may simply have been
-- sent twice -- so it is the ones past everything we have given that are
-- refused.
isMyCIDSeqNumIssued :: Connection -> Int -> IO Bool
isMyCIDSeqNumIssued Connection{..} n = (n <) . nextSeqNum <$> readIORef myCIDDB

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

-- | Validating the path, and whether it was validated.  False when no
--   PATH_RESPONSE came in time: the validation is abandoned.
validatePath :: Connection -> PathInfo -> Maybe CIDInfo -> IO Bool
validatePath conn pathInfo Nothing = do
    pdat <- newPathData
    setChallenges conn pathInfo pdat
    putOutput conn $ challengeOutput conn pathInfo [PathChallenge pdat]
    waitResponse conn pathInfo
validatePath conn pathInfo (Just cidInfo)
    -- RFC 9000 Sec 9.5: the CID of the old path is kept for it until the
    -- new one is validated, so that no CID is sent on both.
    | isServer conn = do
        pdat <- newPathData
        setChallenges conn pathInfo pdat
        putOutput conn $ challengeOutput conn pathInfo [PathChallenge pdat]
        ok <- waitResponse conn pathInfo
        when ok $ retire $ cidInfoSeq cidInfo
        return ok
  where
    retire n = do
        retirePeerCID conn n
        putOutput conn $ OutControl RTT1Level [RetireConnectionID n]
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
    putOutput conn $ challengeOutput conn pathInfo frames
    waitResponse conn pathInfo

-- | A server's part in a client's move to the path given, whether the
--   path is validated.  Both paths are challenged (RFC 9000 Sec 9.3.3).  If
--   the client changed its CID, the new path gets a new CID of the client's
--   and the old path keeps its own (Sec 9.5); the one of the path given up
--   is retired.
validateMigration :: Connection -> PathInfo -> Bool -> IO Bool
validateMigration conn pathInfo cidChanged = do
    mold <-
        if cidChanged
            then timeout (Microseconds 100000) "validateMigration" $ waitPeerCID conn
            else return Nothing -- PathChallenge only, no RetireConnectionID
    oldPathInfo <- getPathInfo conn
    -- assumed that this PathInfo is not stored in PeerInfo
    addPathInfo conn pathInfo
    -- A peer still on the old path answers from it and so ends a spurious
    -- migration at once (Sec 9.3.2).
    oldChallenge <- newPathData
    putOutput conn $
        OutPathProbe oldPathInfo (cidInfoCID <$> mold) [PathChallenge oldChallenge]
    ok <- validatePath conn pathInfo mold
    unless ok $ do
        -- Sec 9.3.2: back to the last validated address.  The one that
        -- failed is forgotten, so that a packet from it starts afresh.
        restorePathInfo conn oldPathInfo
        case mold of
            Nothing -> return ()
            Just old -> do
                spurious <- atomically $ do
                    db <- readTVar $ peerCIDDB conn
                    setPeerCID conn old (triggeredByMe db)
                    return $ usedCIDInfo db
                let n = cidInfoSeq spurious
                retirePeerCID conn n
                putOutput conn $ OutControl RTT1Level [RetireConnectionID n]
    return ok

-- | A server sends the challenge to the path it is for, which may not be
--   the one in use by the time it leaves.  A client's socket may be
--   connected, and so cannot be given an address.
challengeOutput :: Connection -> PathInfo -> [Frame] -> Output
challengeOutput conn pathInfo frames
    | isServer conn = OutPathProbe pathInfo Nothing frames
    | otherwise = OutControl RTT1Level frames

setChallenges :: Connection -> PathInfo -> PathData -> IO ()
setChallenges Connection{..} pathInfo pdat =
    atomically $ writeTVar migrationState $ SendChallenge pathInfo [pdat]

-- | Take on the migration, if no one has it.
--
-- True to the caller that took it, and that caller is then the one to carry
-- it out; False to everyone else, including every later caller until the
-- validation this one starts is finished.
--
-- Test and set together.  Apart, every packet that arrived before the
-- winner had set the state read it as free, and a peer that sends from an
-- address this connection has not seen -- which takes no more than another
-- port -- got a migration for each of those packets rather than one for all
-- of them.
claimMigration :: Connection -> IO Bool
claimMigration Connection{..} = atomically $ do
    s <- readTVar migrationState
    case s of
        SendChallenge{} -> return False
        MigrationStarted -> return False
        _ -> do
            writeTVar migrationState MigrationStarted
            return True

-- | Waiting for the PATH_RESPONSE, for three times the larger of the PTO
--   and the PTO of a new path (RFC 9000 Sec 8.2.4).  It used to wait for
--   ever, and no other migration could start meanwhile.
--
-- A challenge is sent again, with a new payload, every one of those
--   periods (Sec 8.2.1): a lost one is not resent, and with only one a
--   single loss failed the validation.
waitResponse :: Connection -> PathInfo -> IO Bool
waitResponse conn@Connection{..} pathInfo = do
    pto <- getPTO connLDCC
    let period = max pto (calcPTO initialRTT Nothing)
        Microseconds total = 3 * period
        Microseconds every = period
    expired <- registerDelay total
    let loop = do
            again <- registerDelay every
            r <- atomically $ do
                state <- readTVar migrationState
                timedOut <- readTVar expired
                resend <- readTVar again
                if state == RecvResponse || state == MigrationAbandoned || timedOut
                    then do
                        writeTVar migrationState NonMigration
                        return $ Just (state == RecvResponse)
                    else if resend then return Nothing else retry
            case r of
                Just ok -> return ok
                Nothing -> do
                    pdat <- newPathData
                    sent <- atomically $ do
                        state <- readTVar migrationState
                        case state of
                            SendChallenge p pdats -> do
                                writeTVar migrationState $ SendChallenge p (pdat : pdats)
                                return True
                            _ -> return False
                    when sent $
                        putOutput conn $
                            challengeOutput conn pathInfo [PathChallenge pdat]
                    loop
    loop

-- | RFC 9000 Sec 9.3.2: a newer packet from the last validated address
--   ends the validation of the new one, which then fails at once and
--   sends us back there.
abandonMigration :: Connection -> IO ()
abandonMigration Connection{..} = atomically $ do
    s <- readTVar migrationState
    case s of
        SendChallenge{} -> writeTVar migrationState MigrationAbandoned
        _ -> return ()

checkResponse :: Connection -> PathData -> IO ()
checkResponse Connection{..} pdat = do
    state <- readTVarIO migrationState
    case state of
        SendChallenge pathInfo pdats
            | pdat `elem` pdats -> atomically $ do
                writeTVar migrationState RecvResponse
                writeTVar (addressValidated pathInfo) True
        _ -> return ()
