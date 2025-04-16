-- | This main module provides APIs for QUIC clients.
module Network.QUIC.Client (
    -- * Running a QUIC client
    run,

    -- * Configration
    ClientConfig,
    defaultClientConfig,
    ccServerName,
    ccPortName,
    ccALPN,
    ccUse0RTT,
    ccResumption,
    ccCiphers,
    ccGroups,
    ccVersions,
    --  , ccCredentials
    ccValidate,
    ccSockConnected,
    ccWatchDog,

    -- * Resumption
    ResumptionInfo,
    getResumptionInfo,
    isResumptionPossible,
    is0RTTPossible,

    -- * Migration

    -- | If 'ccSockConnected' is 'True', a connected socket is made.
    --   Otherwise, a unconnected socket is made.
    --
    --   For unconnected sockets, a preferred network IF is used
    --   according to packet routing. But since the current peer CID
    --   is used with the new local address, a bad guy can correlate
    --   the old local addresss and the new local address via the
    --   current peer CID.  In other words, migration is trackable.
    --
    --   For connected sockets, the old local address is kept to be
    --   used even if a preferred network IF gets available. Call the
    --   'migrate' API to use the new local address. This ensures that
    --   a new peer CID is used for the new local address. In short,
    --   migration is not trackable.
    --
    --   If 'ccWatchDog' is 'True' on Linux and macOS, a watch dog
    --   thread is spawned and it calls 'migrate' when network-related
    --   events (e.g. a new network IF is attached or the default
    --   route is changed) are observed. This is an experimental
    --   feature.
    migrate,
) where

import Network.QUIC.Client.Run
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Types
