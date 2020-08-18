{-# LANGUAGE OverloadedStrings #-}

module Config where

import Network.QUIC

testServerConfig :: ServerConfig
testServerConfig = defaultServerConfig {
    scAddresses = [("127.0.0.1",8003)]
  }

testClientConfig :: ClientConfig
testClientConfig = defaultClientConfig {
    ccPortName = "8003"
  }
