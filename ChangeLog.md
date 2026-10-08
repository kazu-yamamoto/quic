# ChangeLog

## 0.3.16

* Stop waiting for a socket to be readable, and run on Windows.
  [#161](https://github.com/kazu-yamamoto/quic/pull/161)
* Count what arrives after the application has closed a stream.
  [#163](https://github.com/kazu-yamamoto/quic/pull/163)
* Say that Windows needs the native I/O manager.
  [#164](https://github.com/kazu-yamamoto/quic/pull/164)
* Stop forking a thread for every datagram a server receives.
  [#165](https://github.com/kazu-yamamoto/quic/pull/165)

## 0.3.15

* Add `scInstallShutdownHandler` to stop a server.
  [#159](https://github.com/kazu-yamamoto/quic/pull/159)
* Tell the peers when the server stops.
  [#159](https://github.com/kazu-yamamoto/quic/pull/159)
* Send the first CONNECTION_CLOSE before leaving the connection.
  [#159](https://github.com/kazu-yamamoto/quic/pull/159)
* Set `SO_REUSEPORT` on macOS and the BSDs.
  [#159](https://github.com/kazu-yamamoto/quic/pull/159)

## 0.3.14

* Count the frame headers when packing many streams into one packet.
  [#153](https://github.com/kazu-yamamoto/quic/pull/153)
* Hold a client sending 0-RTT to the limits of the previous connection.
  [#156](https://github.com/kazu-yamamoto/quic/pull/156)
* Refuse a NEW_CONNECTION_ID that contradicts an earlier one.
  [#157](https://github.com/kazu-yamamoto/quic/pull/157)
* Refuse a RETIRE_CONNECTION_ID for the connection ID it arrived on.
  [#158](https://github.com/kazu-yamamoto/quic/pull/158)

## 0.3.13

* A debug write can no longer end the connection it describes.
  [#148](https://github.com/kazu-yamamoto/quic/pull/148)
* A qlog write can no longer end the connection either.
  [#150](https://github.com/kazu-yamamoto/quic/pull/150)
* Free what a failed setup took.
  [#149](https://github.com/kazu-yamamoto/quic/pull/149)
* The header protection mask no longer leaks a buffer for every coder.
  [#151](https://github.com/kazu-yamamoto/quic/pull/151)

## 0.3.12

* Tell the peer before waiting for the application.
  [#141](https://github.com/kazu-yamamoto/quic/pull/141)
* Set the QUIC Bit in a Stateless Reset.
  [#137](https://github.com/kazu-yamamoto/quic/pull/137)
* Send INTERNAL_ERROR when a connection ends of an unexpected exception.
  [#140](https://github.com/kazu-yamamoto/quic/pull/140)
* Count what the application never reads against the connection's window.
  [#142](https://github.com/kazu-yamamoto/quic/pull/142)
* Keep the AEAD limits of RFC 9001 Sec 6.6.
  [#145](https://github.com/kazu-yamamoto/quic/pull/145)
  [#147](https://github.com/kazu-yamamoto/quic/pull/147)
* Refuse a RETIRE_CONNECTION_ID we never issued.
  [#144](https://github.com/kazu-yamamoto/quic/pull/144)
* Say which thread ended a server connection.
  [#138](https://github.com/kazu-yamamoto/quic/pull/138)
  [#139](https://github.com/kazu-yamamoto/quic/pull/139)

## 0.3.11

* Bind an address validation token to the address it was issued to.
  [#133](https://github.com/kazu-yamamoto/quic/pull/133)
* Hold a peer to the final size it gave for a stream.
  [#136](https://github.com/kazu-yamamoto/quic/pull/136)
* Open the stream a STREAM_DATA_BLOCKED arrives for.
  [#134](https://github.com/kazu-yamamoto/quic/pull/134)
* The default `initial_max_streams_uni` is 10, where it was 3.
  [#135](https://github.com/kazu-yamamoto/quic/pull/135)
* Say why a server connection ended.
  [#138](https://github.com/kazu-yamamoto/quic/pull/138)

## 0.3.10

* Hand the application a stream only once its first frame is read.
  [#131](https://github.com/kazu-yamamoto/quic/pull/131)
* Keep the Initial keys of the version the client addressed us in.
  [#132](https://github.com/kazu-yamamoto/quic/pull/132)
* Build without warnings.

## 0.3.9

* Keep the peer's open streams within `initial_max_streams`.
  [#124](https://github.com/kazu-yamamoto/quic/pull/124)
* Count what cannot be read against the anti-amplification limit.
  [#128](https://github.com/kazu-yamamoto/quic/pull/128)
* Open the stream a RESET_STREAM arrives for.
  [#129](https://github.com/kazu-yamamoto/quic/pull/129)
* Set the sending part closed on STOP_SENDING, not on RESET_STREAM.
  [#125](https://github.com/kazu-yamamoto/quic/pull/125)
* Tests only.
  [#126](https://github.com/kazu-yamamoto/quic/pull/126)
  [#127](https://github.com/kazu-yamamoto/quic/pull/127)

## 0.3.8

* Tell a stream that was reset from one that ended.
  [#123](https://github.com/kazu-yamamoto/quic/pull/123)

## 0.3.7

* Don't open a closed stream again for a late copy of its data.
  [#118](https://github.com/kazu-yamamoto/quic/pull/118)
* Report a server that could not be started.
  [#119](https://github.com/kazu-yamamoto/quic/pull/119)
* Don't let one datagram take the server's dispatcher down for good.
  [#120](https://github.com/kazu-yamamoto/quic/pull/120)
* Tests only.
  [#117](https://github.com/kazu-yamamoto/quic/pull/117)
  [#121](https://github.com/kazu-yamamoto/quic/pull/121)

## 0.3.6

* Stop treating an undecryptable token as a validated address.
  [#114](https://github.com/kazu-yamamoto/quic/pull/114)
* Let the PTO probe reach a retransmission waiting for the window.
  [#115](https://github.com/kazu-yamamoto/quic/pull/115)
* Spend the PTO probe on data being held back rather than on a PING.
  [#113](https://github.com/kazu-yamamoto/quic/pull/113)
* Count only what is in flight into bytes in flight.
  [#116](https://github.com/kazu-yamamoto/quic/pull/116)
* Use crypton's one-call AES-GCM interface and remove the bundled picotls
  `fusion` engine and its cabal flag.
* ChaCha20-Poly1305 is in `defaultCiphers` on x86-64 again.
  [#111](https://github.com/kazu-yamamoto/quic/pull/111)
* Tests and CI: fix the IOSpec relay and keep qlog for a failed job.
  [#112](https://github.com/kazu-yamamoto/quic/pull/112)

## 0.3.5

* Drop a packet whose header protection sample is not whole.
  [#95](https://github.com/kazu-yamamoto/quic/pull/95)
* Bound the CRYPTO data held out of order.
  [#96](https://github.com/kazu-yamamoto/quic/pull/96)
* Decode the peer's transport parameters without raising BufferOverrun.
  [#97](https://github.com/kazu-yamamoto/quic/pull/97)
* Refuse a transport parameter sent twice, and stream limits past 2^60.
  [#105](https://github.com/kazu-yamamoto/quic/pull/105)
* Stop the sender deadlocking on a congestion window it cannot free.
  [#103](https://github.com/kazu-yamamoto/quic/pull/103)
* Leave the peer a whole header protection sample when encoding.
  [#104](https://github.com/kazu-yamamoto/quic/pull/104)
* Bound a connection id and a Retry packet in the long header decoder.
  [#106](https://github.com/kazu-yamamoto/quic/pull/106)
* Bound how many pieces a stream may be held in.
  [#108](https://github.com/kazu-yamamoto/quic/pull/108)
* Check the ranges of an ACK frame, and refuse an ACK for a packet never
  sent.
  [#109](https://github.com/kazu-yamamoto/quic/pull/109)
* Give the two ends of a connection their own qlog file.
  [#100](https://github.com/kazu-yamamoto/quic/pull/100)
* Remove the partial functions that were worth removing.
  [#107](https://github.com/kazu-yamamoto/quic/pull/107)
* Require crypton 2.0.1.
* `Network.QUIC.Internal` changed.

## 0.3.4

* Add a server option to request client certificates.
  [#94](https://github.com/kazu-yamamoto/quic/pull/94)

## 0.3.3

* RST_STREAM now contains a proper final size.
  [#93](https://github.com/kazu-yamamoto/quic/pull/93)

## 0.3.2

* Support Unreliable Datagrams extension (RFC9221)
  [#92](https://github.com/kazu-yamamoto/quic/pull/92)

## 0.3.1

* Using tls v2.4.0.
* rateLimit is now 32.

## 0.3.0

* Using "ram" instead of "memory".

## 0.2.23

* Supporting ChaCha20Poly1305 for crypton (not for Fusion)
  [#89](https://github.com/kazu-yamamoto/quic/pull/89)

## 0.2.22

* Using tls v2.2 and crypton-x509* v1.8.

## 0.2.21

* Terminating threads properly with event-poll model.

## 0.2.20

* Fix recvStream overflow on pending data.
  [#84](https://github.com/kazu-yamamoto/quic/pull/84)

## 0.2.19

* Compare the minimum packet size on packet size determination.
  [#81](https://github.com/kazu-yamamoto/quic/pull/81)

## 0.2.18

* Don't print debug information on stdout as a daemon has already
  closed it.

## 0.2.17

* Using waitReadSocketSTM properly.

## 0.2.16

* Fixing build on Windows.
  [#80](https://github.com/kazu-yamamoto/quic/pull/80)

## 0.2.15

* Defining `ccUseServerNameIndication`.
* Defining `ccOnServerCertificate`.

## 0.2.14

* Supporting SSLKEYLOGFILE.
* Supporting zer-length CID in the server side.
  [#78](https://github.com/kazu-yamamoto/quic/pull/78)

## 0.2.13

* Necessary transport parameters are now stored in ResumptionInfo.
  [#76](https://github.com/kazu-yamamoto/quic/pull/76)

## 0.2.12

* Dont' send UDP packets of size 0. (Cloudfare)
* Retransmitted NewConnectionID does not reach the limit. (AdGuard)

## 0.2.11

* `ConnectionIsClosed` now takes reason.
* `ConnectionClose NoError` is treated as an error if level is not RTT1.
* Defining `ccServerNameOverride`.
* Removing data-default.

## 0.2.10

* Fix a bug of ACK on retransmission.
* New scheme to pack ACK on handshake.
* Fix a race condition in closure. CC is broken sometime.
* Using Rate instead of TBQueue against DOS.
* Enhancing qlog.
* Cleaning up the code for migration.
* Anti-amplification for migration.
* Respecting active_connection_id_limit.
* If `ccWatchDog` is `True`, a watch dog thread is spawn to call
  `migration` when network configuration changes.
* Connected sockets again for clients. Set `ccSockConnected` to `True`
  to use connected sockets.
* Fixing time representation of qlog.

## 0.2.9

* Don't send Fin if connection is already closed.
* Using clientWantSessionResumeList for multiple tickets.

## 0.2.8

* Proper handling for stateless reset. Servers generate SRTs based on
  their CIDs. Clients check SRTs before dispatching to a Connection.
  Note that the CID of stateless reset is random.
  Test: `quic-server -o 5` and `quic-client -i`/`p`.

## 0.2.7

* Introducing `forkManaged` to manage readers of clients properly.

## 0.2.6

* Using `ServerState` instead of `killThread`.
* Don't catch asynchronous exceptions.

## 0.2.5

* Re-throwing asynchronous exceptions.

## 0.2.4

* Putting `#if` for `threadLabel`.
* Revert Timeout.hs which is accidentally committed.

## 0.2.3

* Supporting tls v2.1.3.
* Labeling threads.
* Using data-default.
* Removing `unliftio`.

## 0.2.2

# Introducing streamNotCreatedYet for STOP_SENDING.

## 0.2.1

* Using recvMsg and sendBufMsg.

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
