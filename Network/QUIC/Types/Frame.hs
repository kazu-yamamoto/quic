{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.Frame where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Error

----------------------------------------------------------------

type FrameType = Int

data Direction = Unidirectional | Bidirectional deriving (Eq, Show)

data Frame = Padding Int
           | Ping
           | Ack AckInfo Delay
           | ResetStream -- fixme
           | StopSending StreamId ApplicationError
           | Crypto Offset CryptoData
           | NewToken Token
           | StreamF StreamId Offset [StreamData] Fin
           | MaxData Int
           | MaxStreamData StreamId Int
           | MaxStreams Direction Int
           | DataBlocked -- fixme
           | StreamDataBlocked -- fixme
           | StreamsBlocked -- fixme
           | NewConnectionID CIDInfo Int
           | RetireConnectionID Int
           | PathChallenge PathData
           | PathResponse PathData
           | ConnectionCloseQUIC TransportError FrameType ReasonPhrase
           | ConnectionCloseApp ApplicationError ReasonPhrase
           | HandshakeDone
           | UnknownFrame Int
           deriving (Eq,Show)

-- | Stream identifier.
--   This should be 62-bit interger.
--   On 32-bit machines, the total number of stream identifiers is limited.
type StreamId = Int

isClientInitiatedBidirectional :: StreamId -> Bool
isClientInitiatedBidirectional  sid = (0b11 .&. sid) == 0

isServerInitiatedBidirectional :: StreamId -> Bool
isServerInitiatedBidirectional  sid = (0b11 .&. sid) == 1

isClientInitiatedUnidirectional :: StreamId -> Bool
isClientInitiatedUnidirectional sid = (0b11 .&. sid) == 2

isServerInitiatedUnidirectional :: StreamId -> Bool
isServerInitiatedUnidirectional sid = (0b11 .&. sid) == 3

type Delay = Int

type Fin = Bool

type CryptoData = ByteString
type StreamData = ByteString

type Token = ByteString -- to be decrypted
emptyToken :: Token
emptyToken = ""

ackEliciting :: Frame -> Bool
ackEliciting Padding{}             = False
ackEliciting ConnectionCloseQUIC{} = False
ackEliciting ConnectionCloseApp{}  = False
ackEliciting Ack{}                 = False
ackEliciting _                     = True

retransmittable :: Frame -> Bool
retransmittable Padding{}          = False
retransmittable Ack{}              = False
retransmittable _                  = True

shouldDelay :: Frame -> Bool
shouldDelay Ack{}     = True
shouldDelay StreamF{} = True
shouldDelay Padding{} = True
shouldDelay Ping{}    = True
shouldDelay _         = False
