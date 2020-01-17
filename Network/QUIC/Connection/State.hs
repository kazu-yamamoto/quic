{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.State (
    setConnectionOpen
  , isConnectionOpen
  , setCloseSent
  , setCloseReceived
  , isCloseSent
  , waitClosed
  ) where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types

----------------------------------------------------------------

setConnectionState :: Connection -> ConnectionState -> IO ()
setConnectionState Connection{..} st =
    atomically $ writeTVar connectionState st

----------------------------------------------------------------

setConnectionOpen :: Connection -> IO ()
setConnectionOpen conn = setConnectionState conn Open

isConnectionOpen :: Connection -> IO Bool
isConnectionOpen Connection{..} = atomically $ do
    st <- readTVar connectionState
    return $ st == Open

----------------------------------------------------------------

setCloseSent :: Connection -> IO ()
setCloseSent Connection{..} = atomically $ modifyTVar connectionState modify
  where
    modify (Closing cs) = Closing $ cs { closeSent = True }
    modify _            = Closing $ CloseState { closeSent = True
                                               , closeReceived = False }

setCloseReceived :: Connection -> IO ()
setCloseReceived Connection{..} = atomically $ modifyTVar connectionState modify
  where
    modify (Closing cs) = Closing $ cs { closeReceived = True }
    modify _            = Closing $ CloseState { closeSent = False
                                               , closeReceived = True }

isCloseSent :: Connection -> IO Bool
isCloseSent Connection{..} = atomically (chk <$> readTVar connectionState)
  where
    chk (Closing cs) = closeSent cs
    chk _            = False

waitClosed :: Connection -> IO ()
waitClosed Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs == Closing (CloseState True True))
