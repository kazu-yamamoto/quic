module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Stream
import Network.QUIC.Types

takeInput :: Connection -> IO Input
takeInput conn = atomically $ readTQueue (inputQ conn)

putInput :: Connection -> Input -> IO ()
putInput conn inp = atomically $ writeTQueue (inputQ conn) inp

takeCrypto :: Connection -> IO Input
takeCrypto conn = atomically $ readTQueue (cryptoQ conn)

putCrypto :: Connection -> Input -> IO ()
putCrypto conn inp = atomically $ writeTQueue (cryptoQ conn) inp

takeOutputSTM :: Connection -> STM Output
takeOutputSTM conn = readTQueue (outputQ conn)

tryPeekOutput :: Connection -> IO (Maybe Output)
tryPeekOutput conn = atomically $ tryPeekTQueue (outputQ conn)

putOutput :: Connection -> Output -> IO ()
putOutput conn out = atomically $ writeTQueue (outputQ conn) out

putOutputPP :: Connection -> (PlainPacket,[PacketNumber]) -> IO ()
putOutputPP conn (ppkt,pns) = atomically $ writeTQueue (outputQ conn) $ OutPlainPacket ppkt pns

takeChunk :: Stream -> IO Chunk
takeChunk strm = atomically $ readTQueue (streamChunkQ strm)

takeChunkSTM :: Connection -> STM Chunk
takeChunkSTM conn = readTQueue (chunkQ conn)

tryPeekChunk :: Stream -> IO (Maybe Chunk)
tryPeekChunk strm = atomically $ tryPeekTQueue (streamChunkQ strm)

putChunk :: Stream -> Chunk -> IO ()
putChunk strm out = atomically $ writeTQueue (streamChunkQ strm) out
