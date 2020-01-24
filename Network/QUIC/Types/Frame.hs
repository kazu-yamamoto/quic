{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.Frame where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Error

----------------------------------------------------------------

type FrameType = Int

data Frame = Padding Int
           | Ping
           | Ack AckInfo Delay
           | ResetStream -- fixme
           | StopSending StreamID ApplicationError
           | Crypto Offset CryptoData
           | NewToken Token
           | Stream StreamID Offset StreamData Fin
           | MaxData Int
           | MaxStreamData StreamID Int
           | MaxStreams Int
           | DataBlocked -- fixme
           | StreamDataBlocked -- fixme
           | StreamsBlocked -- fixme
           | NewConnectionID Int Int CID StatelessResetToken
           | RetireConnectionID -- fixme
           | PathChallenge PathData
           | PathResponse PathData
           | ConnectionCloseQUIC TransportError FrameType ReasonPhrase
           | ConnectionCloseApp ApplicationError ReasonPhrase
           | HandshakeDone
           | UnknownFrame Int
           deriving (Eq,Show)

type StreamID = Int64
type Delay = Int

type Fin = Bool

type CryptoData = ByteString
type StreamData = ByteString

type PathData = Bytes -- 8 bytes
-- 16 bytes
newtype StatelessResetToken = StatelessResetToken Bytes deriving (Eq,Show)

type Token = ByteString -- to be decrypted
emptyToken :: Token
emptyToken = ""
