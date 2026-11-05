{-# LANGUAGE OverloadedStrings #-}

-- | Limits against a peer which makes us answer frames.
module Network.QUIC.Connection.RateControl (
    -- * Limits
    PerSecond,
    pathAndCIDFrameLimit,
    pathResponseLimit,
    queuedControlLimit,
    statelessResetLimit,
    statelessResetSize,
    statelessResetSizeFor,

    -- * Enforcing
    enforcePathAndCIDFrameLimit,
    withinPathResponseLimit,
    enforceQueuedControlLimit,
    withinStatelessResetLimit,
) where

import Network.Control (Rate, addRate)

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- | How many events a counting window may hold.  A window starts at its
--   first event and lasts about a second, so a burst at the end of one
--   and the start of the next can reach twice the limit.
--
-- A peer can make us answer frames and keep the answers from leaving by
-- not opening its congestion window (CVE-2023-49295, CVE-2024-22189).
-- The limits are against that.  They are fixed, not configurable.  An
-- @enforce@ limit closes the connection with 'InternalError' when it is
-- exceeded; a @within@ limit drops what is past it, which is done only
-- for what the peer retransmits by itself.
--
-- Frames which must be answered and which another limit already bounds
-- are not rate-controlled.  STOP_SENDING and RESET_STREAM are bounded by
-- MAX_STREAMS, and a peer cancelling many streams at once does nothing
-- wrong.  A STOP_SENDING is answered once per stream.  NEW_CONNECTION_ID
-- is always processed, as dropping it would lose its Retire Prior To.
newtype PerSecond = PerSecond Int deriving (Eq, Ord, Show)

-- | Per connection, PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID and
--   RETIRE_CONNECTION_ID received count together.  Enforced.
pathAndCIDFrameLimit :: PerSecond
pathAndCIDFrameLimit = PerSecond 32

-- | Per connection, PATH_CHALLENGE frames answered.  The rest are
--   dropped: the peer sends a new one if it gets no PATH_RESPONSE.
pathResponseLimit :: PerSecond
pathResponseLimit = PerSecond 10

-- | Per connection, control frames waiting for the sender, those of lost
--   packets to resend included.  Data, which flow control bounds, is not
--   counted.  Enforced.  With what the congestion window lets be in
--   flight, this bounds the RETIRE_CONNECTION_ID frames a NEW_CONNECTION_ID
--   flood asks for.  The value is quic-go's.
queuedControlLimit :: Int
queuedControlLimit = 16384

-- | Per server, stateless resets sent.  The rest are not sent.
statelessResetLimit :: PerSecond
statelessResetLimit = PerSecond 20

-- | The largest stateless reset we send, in octets.
statelessResetSize :: Int
statelessResetSize = 1280

-- | The size of a stateless reset in answer to a packet of this many
--   octets, if one can be sent.
--
-- Always smaller than the packet (RFC 9000, section 10.3.3): a reset looks
-- like a packet for an unknown connection, so two endpoints could answer
-- each other's resets for ever.  Half of it, so that such a loop ends in a
-- few rounds, and one octet less for a packet of 43 octets or fewer
-- (section 10.3).  None below the 21 octets a reset needs.  Being smaller,
-- it is also under three times the packet (section 10.3).
statelessResetSizeFor :: Int -> Maybe Int
statelessResetSizeFor bytes
    | siz < 21 = Nothing
    | otherwise = Just siz
  where
    siz
        | bytes <= 43 = bytes - 1
        | otherwise = min statelessResetSize (bytes `div` 2)

----------------------------------------------------------------

-- Adds n to the window and tells whether it is still within the limit.
-- The count includes what is being added, so the limit itself is let
-- through with '<='.  '<' let one fewer through than the name says.
addWithin :: Rate -> Int -> PerSecond -> IO Bool
addWithin rate n (PerSecond lim) = (<= lim) <$> addRate rate n

-- | Counting the path and CID frames of a packet against
--   'pathAndCIDFrameLimit'.
enforcePathAndCIDFrameLimit :: Connection -> [Frame] -> IO ()
enforcePathAndCIDFrameLimit conn frames = do
    let n = length $ filter isPathOrCID frames
    when (n /= 0) $ do
        ok <- addWithin (pathAndCIDFrameRate conn) n pathAndCIDFrameLimit
        unless ok $
            closeConnection conn InternalError "Too many path or CID frames"
  where
    isPathOrCID PathChallenge{} = True
    isPathOrCID PathResponse{} = True
    isPathOrCID NewConnectionID{} = True
    isPathOrCID RetireConnectionID{} = True
    isPathOrCID _ = False

-- | Whether a PATH_CHALLENGE may be answered under 'pathResponseLimit'.
withinPathResponseLimit :: Connection -> IO Bool
withinPathResponseLimit conn =
    addWithin (pathResponseRate conn) 1 pathResponseLimit

-- | Closing the connection if more control frames than
--   'queuedControlLimit' wait for the sender.
enforceQueuedControlLimit :: Connection -> IO ()
enforceQueuedControlLimit conn = do
    queued <- getQueuedControls conn
    when (queued > queuedControlLimit) $
        closeConnection conn InternalError "Too many control frames queued"

-- | Whether a stateless reset may be sent under 'statelessResetLimit'.
withinStatelessResetLimit :: Rate -> IO Bool
withinStatelessResetLimit rate = addWithin rate 1 statelessResetLimit
