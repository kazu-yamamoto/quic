{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.Frame where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Error
import Network.QUIC.Types.Time

----------------------------------------------------------------

type FrameType = Int

data Direction = Unidirectional | Bidirectional deriving (Eq, Show)

type ReasonPhrase = ShortByteString
type SeqNum = Int

data Frame = Padding Int
           | Ping
           | Ack AckInfo Delay
           | ResetStream StreamId ApplicationProtocolError Int
           | StopSending StreamId ApplicationProtocolError
           | CryptoF Offset CryptoData
           | NewToken Token
           | StreamF StreamId Offset [StreamData] Fin
           | MaxData Int
           | MaxStreamData StreamId Int
           | MaxStreams Direction Int
           | DataBlocked Int
           | StreamDataBlocked StreamId Int
           | StreamsBlocked Direction Int
           | NewConnectionID CIDInfo SeqNum -- retire prior to
           | RetireConnectionID SeqNum
           | PathChallenge PathData
           | PathResponse PathData
           | ConnectionClose     TransportError FrameType ReasonPhrase
           | ConnectionCloseApp  ApplicationProtocolError ReasonPhrase
           | HandshakeDone
           | UnknownFrame Int
           deriving (Eq,Show)

-- | Stream identifier.
--   This should be 62-bit interger.
--   On 32-bit machines, the total number of stream identifiers is limited.
type StreamId = Int

-- | Checking if a stream is client-initiated bidirectional.
isClientInitiatedBidirectional :: StreamId -> Bool
isClientInitiatedBidirectional  sid = (0b11 .&. sid) == 0

-- | Checking if a stream is server-initiated bidirectional.
isServerInitiatedBidirectional :: StreamId -> Bool
isServerInitiatedBidirectional  sid = (0b11 .&. sid) == 1

-- | Checking if a stream is client-initiated unidirectional.
isClientInitiatedUnidirectional :: StreamId -> Bool
isClientInitiatedUnidirectional sid = (0b11 .&. sid) == 2

-- | Checking if a stream is server-initiated unidirectional.
isServerInitiatedUnidirectional :: StreamId -> Bool
isServerInitiatedUnidirectional sid = (0b11 .&. sid) == 3

isClientInitiated :: StreamId -> Bool
isClientInitiated sid = (0b1 .&. sid) == 0

isServerInitiated :: StreamId -> Bool
isServerInitiated sid = (0b1 .&. sid) == 1

isBidirectional :: StreamId -> Bool
isBidirectional sid = (0b10 .&. sid) == 0

isUnidirectional :: StreamId -> Bool
isUnidirectional sid = (0b10 .&. sid) == 2

type Delay = Milliseconds

type Fin = Bool

type CryptoData = ByteString
type StreamData = ByteString

type Token = ByteString -- to be decrypted
emptyToken :: Token
emptyToken = ""

ackEliciting :: Frame -> Bool
ackEliciting Padding{}            = False
ackEliciting Ack{}                = False
ackEliciting ConnectionClose{}    = False
ackEliciting ConnectionCloseApp{} = False
ackEliciting _                    = True

pathValidating :: Frame -> Bool
pathValidating PathChallenge{} = True
pathValidating PathResponse{}  = True
pathValidating _               = False

inFlight :: Frame -> Bool
inFlight Ack{}                = False
inFlight ConnectionClose{}    = False
inFlight ConnectionCloseApp{} = False
inFlight _                    = True
