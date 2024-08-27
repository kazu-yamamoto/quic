module FrameSpec where

import qualified Control.Exception as E
import Data.Word
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils (fillBytes)
import Foreign.Ptr
import Foreign.Storable
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = do
    describe "countZero" $ do
        it "counts 0 correctly" $ do
            let siz = 512
            E.bracket (mallocBytes siz) free $ \beg -> do
                let (+.) = plusPtr
                    end = beg +. siz
                fillBytes beg 0 $ fromIntegral siz
                countZero beg end `shouldReturn` siz
                countZero (beg +. 1) end `shouldReturn` (siz - 1)
                countZero (beg +. 2) end `shouldReturn` (siz - 2)
                countZero (beg +. 3) end `shouldReturn` (siz - 3)
                countZero (beg +. 4) end `shouldReturn` (siz - 4)
                countZero (beg +. 5) end `shouldReturn` (siz - 5)
                countZero (beg +. 6) end `shouldReturn` (siz - 6)
                countZero (beg +. 7) end `shouldReturn` (siz - 7)
                countZero (beg +. 8) end `shouldReturn` (siz - 8)
                poke (end +. (-1)) (1 :: Word8)
                countZero (beg +. 3) end `shouldReturn` (siz - 4)
                poke (end +. (-2)) (2 :: Word8)
                countZero (beg +. 3) end `shouldReturn` (siz - 5)
                poke (end +. (-3)) (3 :: Word8)
                countZero (beg +. 3) end `shouldReturn` (siz - 6)
                countZero (beg +. 1) (beg +. 2) `shouldReturn` 1
                countZero (beg +. 1) (beg +. 3) `shouldReturn` 2
                countZero (beg +. 1) (beg +. 4) `shouldReturn` 3
                countZero (beg +. 1) (beg +. 5) `shouldReturn` 4
                countZero (beg +. 1) (beg +. 6) `shouldReturn` 5
                countZero (beg +. 1) (beg +. 7) `shouldReturn` 6
                countZero (beg +. 1) (beg +. 8) `shouldReturn` 7
                countZero (beg +. 1) (beg +. 9) `shouldReturn` 8
                countZero (beg +. 1) (beg +. 10) `shouldReturn` 9
                countZero (beg +. 1) (beg +. 11) `shouldReturn` 10
                countZero (beg +. 2) (beg +. 3) `shouldReturn` 1
                poke (beg +. 10) (1 :: Word8)
                countZero beg end `shouldReturn` 10
                countZero (beg +. 1) end `shouldReturn` 9
                countZero (beg +. 2) end `shouldReturn` 8
                countZero (beg +. 3) end `shouldReturn` 7
