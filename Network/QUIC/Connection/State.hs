{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.State (
    isConnectionOpen
  , isConnectionEstablished
  , setConnectionEstablished
  , setCloseSent
  , setCloseReceived
  , isCloseSent
  , waitEstablished
  , waitClosed
  ) where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types

----------------------------------------------------------------

setConnectionState :: Connection -> ConnectionState -> IO ()
setConnectionState Connection{..} st =
    atomically $ writeTVar connectionState st

setConnectionEstablished :: Connection -> IO ()
setConnectionEstablished conn = setConnectionState conn Established

----------------------------------------------------------------

isConnectionEstablished :: Connection -> IO Bool
isConnectionEstablished Connection{..} = atomically $ do
    st <- readTVar connectionState
    return $ st == Established

isConnectionOpen :: Connection -> IO Bool
isConnectionOpen Connection{..} = atomically $ do
    st <- readTVar connectionState
    case st of
      Closing _ -> return False
      _         -> return True

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

waitEstablished :: Connection -> IO ()
waitEstablished Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs == Established)

waitClosed :: Connection -> IO ()
waitClosed Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs == Closing (CloseState True True))
