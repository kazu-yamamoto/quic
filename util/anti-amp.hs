{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Network.Run.UDP
import Network.Socket
import Network.Socket.ByteString

ini :: ByteString
ini =
    BS.concat
        [ "\xcd\x00\x00\x00\x01\x08\xd8\x8d\x1e\x67\x72\x71\xf7\x11\x08\x96"
        , "\xd0\xae\xff\x99\xc7\x27\xc3\x00\x44\xca\x30\x80\x1d\x62\x81\x70"
        , "\xd0\x20\xed\xef\xb1\x2c\xc8\x13\xa0\x6c\xab\xfb\xb1\x34\x28\xd1"
        , "\xb2\x63\xc0\xb9\xb8\x2e\x6c\xa6\x29\x9e\x18\x22\x30\xbf\x4e\x00"
        , "\x9f\xa1\xa9\x5f\xd8\xf7\xb0\x2b\xde\x21\xfb\x98\x2b\x33\x5e\xb1"
        , "\xdb\xcd\x64\x17\xb2\xe1\x5b\x37\xb5\x9a\x5b\x35\x11\x36\x31\x88"
        , "\x31\xc4\xec\xf6\x42\x0b\x0d\x41\xba\xf6\xd2\x25\x72\xd0\xf6\x2c"
        , "\x52\x83\x17\x20\x36\x03\x1b\x75\xa9\xf2\x33\x15\xcb\xd0\x41\x00"
        , "\xd1\x84\xfa\xc4\x67\x97\xf2\xa4\x45\x48\x68\x82\x32\xe4\xa5\x5e"
        , "\xa6\x95\x99\xb2\x36\x04\x86\x84\x4f\x11\xbf\x85\x15\xb7\xb5\x83"
        , "\xa1\x60\x6d\x0b\xe8\x72\x85\x75\xe8\xab\xdd\x99\x78\x97\x2e\xdc"
        , "\xbd\x20\xa6\x87\x2b\x8e\xe4\x73\x8a\x82\xf6\x5e\xba\xa5\xef\x53"
        , "\x8c\x49\x2e\x13\x09\xf9\x47\xf9\x6a\x52\x8a\x41\x2a\x11\x55\x92"
        , "\x30\x3c\x88\xd6\xcf\xed\x79\x57\x14\x0a\x9d\xd1\xde\xf6\x1e\xe5"
        , "\x30\x84\x4f\x70\x56\x35\xf5\xf8\x52\x15\x18\x45\xc5\xec\x8b\x69"
        , "\x05\x55\xd8\x76\x3b\x33\xf6\x52\x37\xbe\xa2\xc2\x54\x92\x18\xf5"
        , "\x61\x90\x51\xa0\x52\x94\x46\x8f\xbb\x75\x78\x11\x2f\x14\xbe\xda"
        , "\x9e\x49\xf5\xab\xb8\xe4\x8a\xc7\x34\x28\x44\x15\x78\xff\x82\x3f"
        , "\x47\xbf\x2b\x73\x83\x54\x17\x3a\x63\x88\xc1\x8f\xc0\x03\x66\xfc"
        , "\xa5\x5b\xb7\x1b\x4f\x44\x18\x71\x3f\xa1\x8a\x97\xa3\x1e\x48\x0f"
        , "\xac\x89\xd2\xc0\x85\xc7\x6b\x32\xcc\xfd\xf2\x46\xd1\xa8\xa7\xf4"
        , "\x92\x07\x8a\xc6\x36\xc8\x59\xb3\xca\x86\xd9\x29\x95\x71\xfe\x09"
        , "\xe9\x14\x8b\x21\xc0\xbe\x48\xc0\xf2\xb4\x5d\x7c\xb2\xd9\xd5\x76"
        , "\xd6\x2c\xe6\x2d\x1a\x70\x26\xc3\xc8\xde\xa2\x1a\x36\x64\x85\x9c"
        , "\xfe\x8a\x70\xf5\x2a\xbe\xbf\x0f\x25\x54\xe9\xc6\x2d\x39\xd2\x09"
        , "\x3c\x80\xd0\x82\xbf\x01\x99\x68\xb1\x05\x72\x04\xad\xa0\x89\x8d"
        , "\x4c\x55\x15\x73\xd5\x61\xb1\x2a\x7a\x8b\x92\xd4\x93\x30\xab\xd0"
        , "\x56\xb4\x86\xe3\xb3\x26\xc2\xb3\x9f\x3b\x45\xa9\xb0\x9e\x9b\x91"
        , "\xb7\x50\x20\xed\x27\x90\x6b\x51\xe2\x1d\x6a\xc2\xeb\x0f\xa8\x36"
        , "\x0d\xcc\xae\x2f\x60\x6b\x4d\xe1\xa6\xf7\xca\x05\xc3\x3e\x82\x03"
        , "\xef\x5a\xfb\x87\x39\x77\xc4\xfe\x44\x8b\xb6\xc9\x9c\x03\xfc\xa7"
        , "\x17\xce\x94\x65\x00\xae\x9c\xf0\x7f\xb3\x11\x9f\x2a\xe6\x24\xe5"
        , "\x70\xe2\xc3\xf7\xe7\x01\x0b\x44\x7e\x7e\x2a\xac\xa0\x03\xd1\x40"
        , "\x4a\x93\x55\x20\xa3\xf6\xbb\x8c\x36\x95\x37\x9d\xc2\xac\xbf\xda"
        , "\x9c\x46\x93\x4d\xf3\x9c\x1c\xbf\xe7\x07\xb6\xd9\x21\xc1\x51\x8c"
        , "\xe0\xcd\xc6\x2c\x65\xf1\xe3\x86\x9c\x9b\xcd\xdc\xea\xf5\x96\xcf"
        , "\xf3\x14\x3a\xa3\x32\x79\xf0\xab\x00\xf2\x3d\x08\x69\x04\x93\xbc"
        , "\x0f\x40\x2c\x9a\xe2\x54\x69\x1f\x17\x3f\x8e\x84\x88\xf9\x03\xd0"
        , "\x44\x0f\xbb\xfd\xac\x29\x86\x6b\x18\x5a\x9d\xf9\x18\x54\x41\x29"
        , "\xa7\x92\xe9\xf7\x39\x3d\xc9\xe3\x96\x13\x6f\x31\xd7\xf0\x98\x48"
        , "\x3a\x35\x73\x73\xdf\xfd\xfa\x87\x05\x3e\x21\xca\x8f\x2a\x8e\xd3"
        , "\xe7\x61\xe6\x58\xf3\x75\x9b\xac\x99\xca\xac\x9d\x16\xd6\x74\xe2"
        , "\x75\x11\xbf\xe6\x3f\x69\xfa\xde\x31\x6e\x77\x4b\x97\xad\xf8\xbe"
        , "\x89\xac\x74\x8e\x28\x47\x58\x29\xb0\x61\x75\x9f\x28\x2e\xe1\x8d"
        , "\x3c\xa0\x6e\x32\x1d\x4c\xaf\x83\xb9\xae\x81\x52\x77\x85\x2e\x26"
        , "\xc7\x9b\x21\x5c\x3f\xc9\x09\xae\x64\x78\x87\x45\x7d\x6d\x15\x4b"
        , "\xb1\x1b\xad\xb4\xd6\x75\x6d\x27\x79\xdc\x9c\xec\x52\x45\x9b\xbf"
        , "\x50\xd3\xca\x42\xe9\xf9\xae\xe6\x99\x2d\xcc\x7e\x0c\x4e\x2e\xaa"
        , "\x88\x69\x06\x39\xe5\x2d\xe7\x23\xdb\x25\x61\xe5\x57\xc8\xa1\xa2"
        , "\xa0\xe9\x9b\x20\x35\x8c\x21\xd3\xb4\x99\xb3\x32\x34\x8d\x54\xb4"
        , "\x16\xf7\x8c\xd0\xfa\x7c\x58\x04\x89\xf8\xed\xaa\x44\x64\xbd\xba"
        , "\xb9\x70\xb6\x10\x07\x16\xca\xf9\x61\x03\xdd\x66\x65\x8d\xab\x78"
        , "\xe4\x04\xb3\x05\x26\x4c\xa1\x8d\x13\x4d\xbc\x4b\x5b\x53\x2a\x34"
        , "\x3f\x37\x42\x38\x2d\x18\xcc\x0b\x54\xa2\xc5\x35\xd8\xa3\xa1\x65"
        , "\x2a\xd7\xaa\xff\x6e\xf6\xb7\x06\x98\xfe\xbd\xb7\x67\xaa\x68\xee"
        , "\x2a\xe6\x36\x02\x42\xd8\x6d\x43\xca\xe7\x43\x70\x10\x06\xf7\x99"
        , "\x25\xea\xdf\xa7\x3d\x36\x43\xd4\x98\xb5\x4c\x8a\xe4\x65\x08\x69"
        , "\xf8\x9e\xf8\xf7\xfd\xfe\xd8\xef\x17\x4f\xb5\x64\xca\x62\xb9\xf2"
        , "\xf4\xe6\x1d\x92\xf4\x45\x8e\x82\x91\x6b\x17\x84\x9c\x9e\x5c\x1f"
        , "\x8a\xad\x8d\x44\xa4\x40\xb4\xab\x89\xcd\x73\xf5\x0b\xff\x5a\x55"
        , "\x82\xb9\x67\x41\xb7\xbe\x2b\x25\x9b\x8f\x77\xc2\xf3\xa0\x48\xbe"
        , "\x9d\x51\xca\x8d\x68\x27\x60\x52\x09\x10\xe5\xc0\x8c\x50\x58\xd9"
        , "\x42\xe6\xd9\x6d\xa5\x7a\xc0\x0b\x5a\x13\xff\x60\xd4\xa7\x4e\xbe"
        , "\x5b\x13\xa7\x3f\xfe\xa3\xe5\x00\x89\x3c\xcf\x56\x59\xd1\xae\x40"
        , "\x92\x8d\x79\xea\x32\x6b\x26\xe1\x59\x26\xa4\x17\x73\xbd\x84\x28"
        , "\x07\x4f\x4f\x79\xe2\xea\x37\x43\x41\xb9\x03\xb3\xe3\x7e\x5b\xca"
        , "\x8c\xf9\x08\xe9\x2d\x46\x05\x57\xf0\x84\x5a\x4a\x56\x54\xe2\x3e"
        , "\x37\xa9\x64\x69\x36\x3d\x8e\xe1\x48\x59\xb5\x3b\x05\xa9\xcb\x1b"
        , "\x81\x3f\x91\x6c\xe5\xc8\x21\xa4\x40\xa1\xdc\x1d\xd5\x26\xd3\x58"
        , "\xaa\xa9\x60\xa2\xa6\xe0\x58\xad\x10\x63\x6a\xa9\x4b\x22\x24\x97"
        , "\x9b\xf4\x2e\x30\x82\xff\x09\x5f\x11\xf3\xb4\x81\x32\x9c\x4e\xb1"
        , "\x3a\x3f\xb8\xdc\xb6\xb9\xd2\xd6\x64\x72\x3d\xdc\xe4\xaf\xac\x4f"
        , "\x99\x6d\x9a\x3d\x4f\x00\x55\x29\x29\x93\x17\x28\x67\x4d\x4f\x2a"
        , "\x9e\xc2\xee\x5b\xb0\x97\x3b\x68\x97\x19\x8a\x62\xbd\xa4\x2f\x9a"
        , "\xb3\x8f\x4e\x90\x4f\xdb\x31\x7f\xe3\x06\x5b\x66\x7e\xb3\x71\xed"
        , "\x95\x8d\x62\x20\x2f\xc1\x51\xbb\x77\x8b\xa3\xf3\x52\x6e\xe4\x24"
        , "\x86\xd6\xb1\xc8\x5d\x35\x72\xb8\xdd\x98\x73\xb7\x47\x3e\xa2\x0c"
        , "\xfc\x4f\x7d\x07\x43\x4a\x2a\xf2\xd2\xe1\x76\x2f\xfa\x71\xc7\x57"
        , "\xcf\xa4\xa4\x3b"
        ]

main :: IO ()
main = runUDPClient "127.0.0.1" "4433" $ \s sa -> do
    sendTo s ini sa >>= print
    threadDelay 100000000
