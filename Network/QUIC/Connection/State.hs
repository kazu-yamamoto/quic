{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.State where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types

----------------------------------------------------------------

setConnectionState :: Connection -> ConnectionState -> IO ()
setConnectionState Connection{..} st =
    atomically $ writeTVar connectionState st

isConnectionOpen :: Connection -> IO Bool
isConnectionOpen Connection{..} = atomically $ do
    st <- readTVar connectionState
    return $ st == Open

----------------------------------------------------------------

setCloseSent :: Connection -> IO ()
setCloseSent Connection{..} =
    atomically $ modifyTVar closeState (\s -> s { closeSent = True })

setCloseReceived :: Connection -> IO ()
setCloseReceived Connection{..} =
    atomically $ modifyTVar closeState (\s -> s { closeReceived = True })

isCloseSent :: Connection -> IO Bool
isCloseSent Connection{..} = atomically (closeSent <$> readTVar closeState)

waitClosed :: Connection -> IO ()
waitClosed Connection{..} = atomically $ do
    cs <- readTVar closeState
    check (cs == CloseState True True)
