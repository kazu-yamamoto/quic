module FrameSpec where

import qualified Control.Exception as E
import Control.Monad
import Data.ByteString.Internal (memset)
import Data.Word
import Foreign.Marshal.Alloc
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
                    end  = beg +. siz
                void $ memset beg 0 $ fromIntegral siz
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
