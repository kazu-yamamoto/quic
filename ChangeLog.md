# ChangeLog

## 0.2.0

* A new server architecture: only wildcard (unconnected) sockets are used.
  [#66](https://github.com/kazu-yamamoto/quic/pull/66)
* Breaking change: `ccAutoMigration` is removed. Clients always use
  unconnected sockets.

## 0.1.28

* Fixing a bug of quic bit.

## 0.1.27

* New API: `runWithSockets` for servers.

## 0.1.26

* fix syntax error, for GHC 9.2
  [#64](https://github.com/kazu-yamamoto/quic/pull/64)

## 0.1.25 (Obsoleted)

* Accidentally release on a wrong branch.

## 0.1.24

* Introducing `onConnectionEstablished` into `Hooks`.
* Preparing for tls v2.1.

## 0.1.23

* Accidentally released using a wrong branch. Deprecated on Hackage.

## 0.1.22

* Incresing activeConnectionIdLimit and fix a bug

## 0.1.21

* Workaround for 0s paddings.
* Another bug fix for packing Fin.

## 0.1.20

* Bug fix for packing Fin.
* Proper handling for MAX_STREAM_DATA
* util/{client,server} are now called util/{quic-client, quic-server}.
* Renaming two command options for util/quic-client.
* Supporting multiple targets in util/quic-client.

## 0.1.19

* Using network-control v0.1.

## 0.1.18

* Fixing a buf of 0-RTT where unidirectionalStream waits for SH.
* Introducing ccVersion to start with Version1.

## 0.1.17

* Garding the new_connection_id attack.

## 0.1.16

* Using tls v2.0.

## 0.1.15

* Support customizing ClientHooks and ServerHooks config from tls

## 0.1.14

* Using crypto-token v0.1

## 0.1.13

* Garding the path_request attack.

## 0.1.12

* Fixing build.

## 0.1.11

* Rescuing GHC 8.10, 9.0 and 9.2.

## 0.1.11

* Adding possibleMyStreams.

## 0.1.10

* Setting proper upper boundaries for the dependencies

## 0.1.9

* Using the network-control package.
* Rate control for some frames.
* Announcing MaxStreams correctly.

## 0.1.8

* Announcing MaxStreams properly.
* Terminating a connection if the peer violates flow controls.

## 0.1.7

* Using System.Timeout.timeout.

## 0.1.6

* Fixing the race condition of `timeout`.

## 0.1.5

* Catching up "tls" v1.9.0.
* Fixing the timing to set resumption tokens.

## 0.1.4

* Fixing the race of socket closure.

## 0.1.3

* Supporting `tls` v1.8.0.

## 0.1.2

* Using "crypton" instead of "cryptonite".

## 0.1.1

* Fix recvStream hanging
  [#54](https://github.com/kazu-yamamoto/quic/pull/54)
* Don't use the fusion crypto on Intel if the CPU does not
  provides enough features.
* Add cabal flag for fusion support
  [#53](https://github.com/kazu-yamamoto/quic/pull/53)

## 0.1.0

* Supporting QUICv2 and version negotiation.
* Supporting CPUs other than Intel.
* Supporting Windows.
* Using the network-udp package

## 0.0.1

* Making Haskell servers friendly with Chrome
  [#20](https://github.com/kazu-yamamoto/quic/pull/20)

## 0.0.0

* Initial version.
