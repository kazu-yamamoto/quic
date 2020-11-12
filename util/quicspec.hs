module Main where

import System.Environment
import qualified Test.Hspec.Core.Runner as H

import Network.QUIC
import Transport

main :: IO ()
main = do
    [host,port] <- getArgs
    let cc = defaultClientConfig {
            ccServerName = host
          , ccPortName   = port
          }
    withArgs [] (H.runSpec (transportSpec cc) H.defaultConfig) >>= H.evaluateSummary
