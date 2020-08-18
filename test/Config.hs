{-# LANGUAGE OverloadedStrings #-}

module Config (
    makeTestServerConfig
  , makeTestServerConfigR
  , testClientConfig
  , testClientConfigR
  ) where

import Network.TLS (Credentials(..), credentialLoadX509)

import Network.QUIC

makeTestServerConfig :: IO ServerConfig
makeTestServerConfig = do
    cred <- either error id <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return testServerConfig {
        scConfig = (scConfig testServerConfig) {
              confCredentials = credentials
            }
      }

testServerConfig :: ServerConfig
testServerConfig = defaultServerConfig {
    scAddresses = [("127.0.0.1",8003)]
  }

makeTestServerConfigR :: IO ServerConfig
makeTestServerConfigR = do
    cred <- either error id <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return testServerConfigR {
        scConfig = (scConfig testServerConfigR) {
              confCredentials = credentials
            }
      }

testServerConfigR :: ServerConfig
testServerConfigR = defaultServerConfig {
    scAddresses = [("127.0.0.1",8003)]
  , scConfig = (scConfig defaultServerConfig) {
        confQLog = Just "dist"
      }
  }

testClientConfig :: ClientConfig
testClientConfig = defaultClientConfig {
    ccPortName = "8003"
  }

testClientConfigR :: ClientConfig
testClientConfigR = defaultClientConfig {
    ccPortName = "8003"
  , ccConfig = (ccConfig defaultClientConfig) {
        confQLog = Just "dist/test"
      }
  }
