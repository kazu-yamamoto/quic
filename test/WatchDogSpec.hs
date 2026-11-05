module WatchDogSpec where

import Data.IORef
import qualified System.Timeout as Timeout
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "watchDog" $ do
        it "gives up on a socket it could not open" $ do
            closed <- newIORef False
            r <-
                Timeout.timeout 1000000 $
                    watchDogWith
                        (return (-1))
                        (\_ -> return (-1))
                        (\_ -> writeIORef closed True >> return 0)
                        (return ())
            r `shouldBe` Just ()
            readIORef closed `shouldReturn` False
        it "gives up on a watch that fails" $ do
            -- No descriptor is -1, so the receive fails with EBADF.
            Timeout.timeout 1000000 (watchSocket (-1)) `shouldReturn` Just (-2)
        it "watches again after an interrupted watch" $ do
            n <- newIORef (0 :: Int)
            let watch _ = do
                    i <- atomicModifyIORef' n $ \x -> (x + 1, x)
                    return $ if i < 3 then -1 else -2
            watchDogWith (return 3) watch (\_ -> return 0) (return ())
            readIORef n `shouldReturn` 4
