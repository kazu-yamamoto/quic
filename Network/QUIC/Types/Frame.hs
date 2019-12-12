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
           | RestStream -- fixme
           | StopSending -- fixme
           | Crypto Offset CryptoData
           | NewToken Token
           | Stream StreamID Offset StreamData Fin
           | MaxData -- fixme
           | MaxStreamData -- fixme
           | MaxStreams -- fixme
           | DataBlocked -- fixme
           | StreamDataBlocked -- fixme
           | StreamsBlocked -- fixme
           | NewConnectionID Int Int CID StatelessResetToken
           | RetireConnectionID -- fixme
           | PathChallenge PathData
           | PathResponse PathData
           | ConnectionCloseQUIC TransportError FrameType ReasonPhrase
           | ConnectionCloseApp  TransportError ReasonPhrase
           deriving (Eq,Show)

type StreamID = Int64
type Delay = Int

type Fin = Bool

type CryptoData = ByteString
type StreamData = ByteString

type PathData = Bytes -- 8 bytes
type ReasonPhrase = Bytes
type StatelessResetToken = Bytes -- 16 bytes

type Token = ByteString -- to be decrypted
emptyToken :: Token
emptyToken = ""
