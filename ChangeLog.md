# ChangeLog

## 0.3.14

A buffer overrun on many streams at once, 0-RTT sent against no limit at
all, and two frames a receiver was taking on trust.

* Count the frame headers when packing many streams into one packet.
  `sendStreamSmall` fills a packet from the send queue up to 1040 octets
  and was counting only the stream data, but every stream whose turn
  comes needs a STREAM frame of its own and nineteen octets of header
  with it.  Hundreds of streams writing a byte or two each therefore
  built a packet far larger than the buffer it is encoded into, and the
  sender died of `BufferOverrun`.  Seen in Cloud Haskell, where one
  connection carries hundreds of processes.
  [#153](https://github.com/kazu-yamamoto/quic/pull/153)

* Hold a client sending 0-RTT to the limits the previous connection gave
  it.  RFC 9000 Sec 7.4.1 holds it to those until the server's own
  arrive.  `sendStreamMany` had a second road for 0-RTT that put the data
  straight on the queue and told the flow control window about it
  afterwards, so a resuming client could spend a connection window it had
  not been given -- and a server that counts answers that with
  FLOW_CONTROL_ERROR before the handshake has finished.  Both roads go
  through the check now, and the connection's own send limit is seeded
  from the remembered parameters so that 0-RTT still carries data.  It is
  seeded beside the two stream counts that were already seeded there and
  were being taken from `defaultParameters` -- 64 streams and ten
  unidirectional, where a server may have allowed fewer, and since these
  limits only ever rise one set too high stayed too high for the rest of
  the connection.
  [#156](https://github.com/kazu-yamamoto/quic/pull/156)

* Refuse a NEW_CONNECTION_ID that contradicts an earlier one.  RFC 9000
  Sec 19.15 leaves to the receiver a connection ID repeated with a
  different stateless reset token or a different sequence number, and a
  sequence number used for a different connection ID.  Ours looked the
  connection ID up, found it, and took the frame for a retransmission
  without comparing what had come with it.  A retransmission says exactly
  what it said before, so it still passes.
  [#157](https://github.com/kazu-yamamoto/quic/pull/157)

* Refuse a RETIRE_CONNECTION_ID for the connection ID the packet carrying
  it arrived on, which RFC 9000 Sec 19.16 also leaves to the receiver.
  An endpoint has to stop using a connection ID before retiring it, so
  the packet that retires one is addressed to another and nothing correct
  is caught by this.
  [#158](https://github.com/kazu-yamamoto/quic/pull/158)

## 0.3.13

One line of debug output that could end the connection it described, and
three ways a failure or a coder left something behind.

* A debug write can no longer end the connection it describes.  With a
  debug directory set every line goes to the connection's file and also
  to stdout, and a daemon has no stdout to write to: it is closed, or a
  pipe whose reader has gone.  The write then throws in whichever
  protocol thread happened to log, and six of those run under nested
  `concurrently_` and take the rest down with them -- so the connection
  ended over a line of debug output.  The first write of all is the
  original CID, before the connection has been built, so the peer heard
  nothing at all and saw a handshake that never finished; a later one
  arrived as an INTERNAL_ERROR, once 0.3.12 began saying when a
  connection ends of something in here.  Against mighty that was every
  shape we had been chasing at once: the freeze, the CONNECTION_CLOSE
  that never came, and the bursts of connections that died together.  It
  came and went because a stdout that is not a terminal is
  block-buffered and it is the flush that fails.  The writes now drop an
  `IOException` -- only that, an asynchronous exception is not one, so
  cancelling a thread that is logging still cancels it.
  [#148](https://github.com/kazu-yamamoto/quic/pull/148)

* The qlog writer goes the same way and for the same reason.  It is
  called from the sender, the receiver and the closer, the same threads,
  and the disk a qlog directory sits on can fill.
  [#150](https://github.com/kazu-yamamoto/quic/pull/150)

* Free what a failed setup took.  A connection's setup, a client's, and
  the server's own are each the acquire of their own `bracket`, and an
  acquire that throws gets no release.  A server connection was leaving
  two log files, three 2048-byte buffers and a registration in the
  dispatcher; a client the same, less a log file and plus its socket,
  which nothing else closes because on the ordinary path the closer does
  and a connection that never began has no closer; the server itself
  every address it had already bound, the dispatchers on them and the
  token manager thread.  `closure''`, which runs on the way out of every
  connection, left its buffers behind if the CONNECTION_CLOSE could not
  be encoded.  Setup does fail -- a client and a server in one process
  pointed at one qlog directory ask for the same file, and the second is
  told the file is busy -- and the bursts above were leaking two handles
  apiece.
  [#149](https://github.com/kazu-yamamoto/quic/pull/149)

* The header protection mask no longer leaks a buffer for every coder.
  It was taken with `mallocBytes` and freed nowhere: 16 bytes under the
  AES-GCM ciphers and 32 under ChaCha20-Poly1305, four coders to a
  connection at each end, held for the life of the process.  A server
  taking a thousand connections a second lost about 5GB a day.  The
  buffer was raw because `getMask` handed it out and the caller read it
  after the call had returned, which nothing a garbage collector owns
  would survive; the reader is handed in instead now, so the buffer can
  be a `ForeignPtr` held across exactly the use.  This changes
  `Protector` in `Network.QUIC.Internal`.
  [#151](https://github.com/kazu-yamamoto/quic/pull/151)

## 0.3.12

A server that looked frozen, a Stateless Reset half the peers threw away,
two windows that leaked, and the AEAD limits.

* Tell the peer before waiting for the application.  The protocol threads
  and the application run under one `concurrently_`; when the protocol
  threads failed it cancelled the application and then waited for it,
  under `uninterruptibleMask_`, for as long as it took to unwind, and the
  CONNECTION_CLOSE waited with it.  A peer told nothing waits out its own
  idle timeout, so from the outside the server had frozen at the
  handshake.  Seen against mighty, where a transport error the server
  raised correctly never reached the client at all; it is said between
  the two now, which is the one place it can be said.
  [#141](https://github.com/kazu-yamamoto/quic/pull/141)

* Set the bit RFC 9000 fixes in a Stateless Reset.  Sec 10.3 fixes the
  first two bits at 01; the first byte was a random seven bits, so the
  QUIC Bit was clear in half of them.  A peer that has not asked for that
  bit to be greased (RFC 9287) drops such a packet before anything looks
  for a token in it -- and a Stateless Reset answers a packet we have no
  connection for, so whether the peer asked is exactly what we cannot
  know.  Half went unheard, and the peer went on talking to a connection
  that was gone until its idle timeout.
  [#137](https://github.com/kazu-yamamoto/quic/pull/137)

* Tell the peer when a connection ends of something in here.  `closure`
  turned four exceptions into a CONNECTION_CLOSE and rethrew the rest, so
  a connection that ended of anything else -- the application throwing,
  StreamIsClosed, an IOException -- ended in silence.  Those now end with
  an INTERNAL_ERROR.  An idle timeout, a peer that has already closed,
  and an asynchronous exception stay silent, as RFC 9000 Sec 10.1 and
  10.2 have them.
  [#140](https://github.com/kazu-yamamoto/quic/pull/140)

* Count what the application never reads against the connection's window.
  It moved in `recvStream` and nowhere else, so octets an application
  left behind were counted as received and never as consumed, and the
  window we advertise stayed that much smaller for the rest of the
  connection.  A server answering a request without reading its body is
  the ordinary case, and it paid for that body until the connection
  ended.
  [#142](https://github.com/kazu-yamamoto/quic/pull/142)

* The AEAD limits of RFC 9001 Sec 6.6, neither of which was kept.
  AEAD_LIMIT_REACHED was in the error table and nothing raised it.
  Packets that fail authentication are counted now, across all keys, and
  the connection closes past the integrity limit -- 2^52 for the AES-GCM
  ciphers, 2^36 for ChaCha20-Poly1305.  Packets each key protects are
  counted too, and the connection closes past the confidentiality limit,
  2^23 under the AES-GCM ciphers.  **Starting a key update instead of
  closing is the better answer to the second and is not here**: the key
  state holds one phase and the packet number the peer changed it at,
  which is what the responding side needs and not what an initiating one
  does.
  [#145](https://github.com/kazu-yamamoto/quic/pull/145),
  [#147](https://github.com/kazu-yamamoto/quic/pull/147)

* Refuse a RETIRE_CONNECTION_ID we never issued.  RFC 9000 Sec 19.16
  makes a sequence number greater than any we have sent a
  PROTOCOL_VIOLATION; ours looked it up, found nothing and went on.  One
  we did send and have already retired stays ignored, since the frame may
  simply have been sent twice.
  [#144](https://github.com/kazu-yamamoto/quic/pull/144)

* Say which thread ended a server connection.  Six run under nested
  `concurrently_`, which cancels the rest as soon as one fails; only the
  sender and the receiver said why they ended, so a failure in one of the
  other four left a log of two cancelled threads and no reason anywhere.
  That is what made the frozen server above so hard to find.  The other
  half of it -- `runServer` discarding every message handed to its
  `debugLog` -- went out in 0.3.11 unmentioned.
  [#138](https://github.com/kazu-yamamoto/quic/pull/138),
  [#139](https://github.com/kazu-yamamoto/quic/pull/139)

## 0.3.11

A security fix, two things RFC 9000 asks of a receiver that were not
there, and a default that left a peer no room.

* Bind an address validation token to the address it was issued to.
  RFC 9000 Sec 8.1.3: tokens sent in NEW_TOKEN frames MUST carry
  something the server can check the client's address against, and if
  the address has changed the server MUST keep to the anti-amplification
  limit.  Ours carried a version, a lifetime and, for a Retry, the
  connection IDs -- no address -- and a fresh one was taken as proof, so
  a client need only keep the NEW_TOKEN it was given and send it back
  with someone else's address in the header: the server treated that
  address as validated and answered it, certificate and all, having had
  nothing proved to it.  A token from before this cannot be decoded and
  is already treated as no token at all, which is to say as an address
  that has proved nothing.
  [#133](https://github.com/kazu-yamamoto/quic/pull/133)

* Hold a peer to the final size it gave for a stream.  FINAL_SIZE_ERROR
  was in the error table and was never sent: where a stream ends, once
  said, cannot be said differently, and nothing may arrive past it
  (RFC 9000 Sec 4.5), but the final size a RESET_STREAM carries went to
  a hook and nowhere else.  That section also asks a receiver to count
  the final size in its connection-level flow controller, and ours
  counted what arrived; a peer counts the final size, so every stream it
  reset with data still in flight left the two further apart, and the
  window we advertise fell behind what the peer believed it had spent --
  by the tail of every reset, until it had none left.  HTTP/3 cancels
  requests as a matter of course.
  [#136](https://github.com/kazu-yamamoto/quic/pull/136)

* Open the stream a STREAM_DATA_BLOCKED arrives for.  RFC 9000 Sec 3.2
  has the receiving part of a peer's stream created by the first STREAM,
  STREAM_DATA_BLOCKED or RESET_STREAM frame for it; the last was done in
  0.3.10 and this is the other.  Both blocked frames also refuse a
  packet that may not carry them: Table 3 has them in 0-RTT and 1-RTT
  only, and Sec 12.4 makes a frame in a packet that may not carry it a
  PROTOCOL_VIOLATION.
  [#134](https://github.com/kazu-yamamoto/quic/pull/134)

* **The default `initial_max_streams_uni` is 10, where it was 3.**  Three
  is what HTTP/3 needs and no more -- a control stream and the two QPACK
  streams (RFC 9114 Sec 6.2) -- so a peer given three could open nothing
  else: no push stream, no stream of a type from an extension, and none
  of the reserved types it is meant to open now and then so that the
  types stay extensible.  A client on these defaults could never be
  pushed to.  Ten leaves room for those without leaving the peer
  unbounded, since 0.3.9 counts what is open at once and a stream gives
  its place back when it is closed.
  [#135](https://github.com/kazu-yamamoto/quic/pull/135)

* Say why a server connection ended.  `runServer` logged the reason to a
  logger that discards what it is given, so a connection that ended of
  anything `closure` does not turn into a CONNECTION_CLOSE went without
  a word to the peer and without a word in the log -- the peer talking
  on to a connection that is gone until the dispatcher, a second later,
  answers it with a Stateless Reset.  From the outside that looks like a
  server that froze.
  [#138](https://github.com/kazu-yamamoto/quic/pull/138)

## 0.3.10

Two for the server: one that answered on a stream it should never have
been given, and one that made a lost flight cost seconds.

* Hand the application a stream only once its first frame is read.
  `openStream` created the stream and gave it to the application in one
  step, before the frame that opened it had been looked over, so a first
  STREAM frame past the flow control limit was answered by the
  application in the moment before the connection was closed over it.
  An HTTP/3 server sent a response on a stream the peer had never
  opened, and the peer called that a STREAM_STATE_ERROR, as RFC 9000 Sec
  19.8 says to, before the FLOW_CONTROL_ERROR arrived; h3spec's "MUST
  send FLOW_CONTROL_ERROR if a STREAM frame with a large offset is
  received" failed for that reason.  The stream now reaches the
  application after the frame has been checked, so a frame that closes
  the connection closes it with the application none the wiser.
  [#131](https://github.com/kazu-yamamoto/quic/pull/131)

* Keep the Initial keys of the version the client addressed us in.  A
  server that settles on a compatible version answers in it and replaces
  its Initial keys with the ones for that version (RFC 9368), but the
  client hears of the choice only when the answer arrives and until then
  retransmits in the version it started with.  Without the keys for that
  version the server could not pick the handshake up from those and
  waited out its own PTO instead -- a second, then two, then four, with
  the client's retransmissions falling into it unread.  On the test that
  loses the server's whole first flight, the handshake is done at about
  1.4 seconds where it took about 7.0.  This is the other half of #128,
  which stopped the same sequence from hanging for good; what was left
  was the waiting.
  [#132](https://github.com/kazu-yamamoto/quic/pull/132)

* The library builds without a warning: two imports left over from the
  crypton 2.1.0 work are gone.

## 0.3.9

A stream limit the peer could walk past, two ways for a connection to
hang, and the stream states.

* Keep the peer's open streams within `initial_max_streams`.  MAX_STREAMS
  counts streams cumulatively (RFC 9000 Sec 4.6), so the limit should go
  up by one for each of the peer's streams we are done with.  It went up
  by the highest stream the peer had opened plus the initial number,
  every time one closed and the peer was near its limit -- a whole new
  window for one closed stream.  A peer that keeps its streams open could
  have any number open at once: against 0.3.7 with a limit of 64, a
  client whose server closed one stream in ten held 3132 open after three
  seconds, and on an HTTP/3 server each of those is a handler thread.
  The limit for unidirectional streams was taken from
  `initialMaxStreamsBidi` as well, and `closeStream` on a unidirectional
  stream the peer opened sent a FIN on a stream with no sending side, so
  the peer closed the connection with STREAM_STATE_ERROR and those
  streams could not be closed at all.
  [#124](https://github.com/kazu-yamamoto/quic/pull/124)

* Count what cannot be read against the anti-amplification limit.  RFC
  9000 Sec 8.1 says to count all the payload bytes received, "including
  datagrams that contain packets that are discarded"; they were counted
  only for a packet that decrypted.  A server that stops being able to
  read the peer therefore stops earning the credit it needs to answer,
  and its sender waits for good.  Reached by way of compatible version
  negotiation: the server answers in a version of its own and replaces
  its Initial keys, its first flight is lost, the client retransmits in
  the version it started with, and the server -- having sent exactly
  three times what it read -- can neither read those nor send again.  The
  handshake never finishes.
  [#128](https://github.com/kazu-yamamoto/quic/pull/128)

* Open the stream a RESET_STREAM arrives for.  RFC 9000 Sec 3.2 has the
  receiving part of a peer's stream created by the first STREAM,
  STREAM_DATA_BLOCKED or RESET_STREAM frame for it; only a STREAM frame
  created it, and a RESET_STREAM that found none was dropped.  It arrives
  first whenever the peer resets a stream it has just sent on, since the
  sender empties the queue the RESET_STREAM is on before the one the data
  is on -- not a race but the order it works in.  The stream was then
  opened by the data that came after, with nothing to say it had been
  reset and no FIN to end it, and `recvStream` waited on it until the
  idle timeout.  A stream never created is never counted, so each one
  lost this way took a unit of MAX_STREAMS credit with it for good.
  [#129](https://github.com/kazu-yamamoto/quic/pull/129)

* Set the sending part closed on STOP_SENDING, not on RESET_STREAM.  The
  two end opposite directions and were the wrong way round.  A
  RESET_STREAM from the peer closed our sending part as well as the
  receiving one, so a reply to what the peer sent before the reset could
  not go out; a STOP_SENDING left our sending part open, so `sendStream`
  went on working after we had answered with RESET_STREAM.  **This
  changes what callers see**: `sendStream` on a stream the peer stopped
  now raises `StreamIsClosed`, where it used to succeed.  `closeStream`
  and `resetStream` also end the stream for its reader whatever else they
  do -- with the sending part already closed they skipped it, and
  `recvStream` blocked for good on a stream that had left the table and
  could receive nothing more.  And a MAX_STREAMS that does not raise the
  limit is ignored (RFC 9000 Sec 4.6); one reordered or retransmitted
  after a newer one lowered the limit on the streams we may open.
  [#125](https://github.com/kazu-yamamoto/quic/pull/125)

* Tests only: the IOSpec ports moved out of the range the kernel hands
  out for a socket bound to port 0, which is 49152 to 65535 on macOS and
  32768 to 60999 on Linux.  Inside it, the relay's own socket was now and
  then given the very port the test server wanted, and "server never
  became ready" followed -- about one run in three hundred.  Each test
  also waits for its server to stop before the next one starts;
  `killThread` returns once the exception is delivered, not once the
  thread is done with it, so the server outlived it and went on serving.
  [#126](https://github.com/kazu-yamamoto/quic/pull/126),
  [#127](https://github.com/kazu-yamamoto/quic/pull/127)

## 0.3.8

* Tell a stream that was reset from one that ended.  After a
  RESET_STREAM, `recvStream` returns an empty ByteString, just as it does
  at the end of a stream, and nothing else said which it was.  An
  application protocol may have to know: HTTP/3's QPACK decoder has to
  send a Stream Cancellation for a request stream that was reset
  (RFC 9204 Sec 4.4.2), and a reset that lands between two frames looked
  to it exactly like the end of the request.  `resetReceived` answers the
  error code of the peer's RESET_STREAM, or `Nothing` if there was none.
  [#123](https://github.com/kazu-yamamoto/quic/pull/123)

## 0.3.7

* Don't open a closed stream again for a late copy of its data.  A STREAM
  frame for a stream no longer in the table opened it anew, and after the
  stream was closed what arrives is a copy of data already received, sent
  again because the packet carrying it was taken for lost while it was
  only late.  The new stream starts from the initial window, 256K, so a
  copy from past that point was called a flow control error and the
  connection closed with FLOW_CONTROL_ERROR; a copy from within the
  window was worse, handing the application a closed stream as a new one.
  [#118](https://github.com/kazu-yamamoto/quic/pull/118)

* Report a server that could not be started.  `run` and `runWithSockets`
  created their sockets inside a handler whose logger discards what it is
  given, so a failure to bind was swallowed, `onServerReady` was never
  reached, and `run` returned as if all were well.  **This changes what
  callers see**: a `run` that cannot bind now raises where it used to
  return quietly.
  [#119](https://github.com/kazu-yamamoto/quic/pull/119)

* Don't let one datagram take the server's dispatcher down for good.  An
  exception anywhere in the dispatcher loop ended it, and nothing
  restarts it -- the socket stays bound, so the server went on looking
  like a server and answering nothing, with the failure logged to the
  same discarding logger.  Decode and dispatch are guarded per datagram
  now.  No input was found that raises; this is the blast radius being
  closed, not a known hole.
  [#120](https://github.com/kazu-yamamoto/quic/pull/120)

* Tests only: the IOSpec relay no longer connects its sockets, since a
  connected UDP socket turns an ICMP port-unreachable into ECONNREFUSED
  on the next operation and the peers there come and go with every test.
  And qlog is behind a `qlog` flag, off by default, which makes its own
  directory when it is on -- the directory used to be the CI's job, so a
  fresh clone failed 33 examples with `openFile: does not exist`.
  [#117](https://github.com/kazu-yamamoto/quic/pull/117),
  [#121](https://github.com/kazu-yamamoto/quic/pull/121)

## 0.3.6

A security fix and three for a stalled handshake.

* Stop treating a token the server cannot decrypt as a validated address.
  The dispatcher's wildcard caught the decryption failing and passed
  `addrValid = True` on, which turns off the three-times
  anti-amplification limit -- so a peer was better off sending rubbish in
  the Token field than sending nothing, from any source address, with no
  keys and no handshake.  RFC 9000 Sec 8.1.3 says to proceed as if the
  address were not validated.  A token we did issue in NEW_TOKEN now has
  its lifetime honoured as well; only the Retry path was checking expiry.
  [#114](https://github.com/kazu-yamamoto/quic/pull/114)
* Let the PTO probe reach the retransmission that is waiting for the
  window.  A client that sends 1-RTT before the handshake is confirmed
  can deadlock its own handshake: RFC 9001 Sec 5.7 stops the peer
  processing those packets, so they are never acknowledged and never
  leave the congestion window, and the window cannot open until the
  CRYPTO frame the peer is waiting for arrives.  The probe may be sent
  past a full window and was being spent on a bare PING, because a packet
  already declared lost has left the sent-packet database and
  `releaseOldest` cannot see it.  An ACK-only packet no longer waits for
  the window either (RFC 9002 Sec 7), which was blocking the one sender
  thread and everything queued behind it.
  [#115](https://github.com/kazu-yamamoto/quic/pull/115)
* Spend the PTO probe on what is being held back rather than on a PING,
  when the sender is already holding an ack-eliciting packet at the level
  the timer fired for.
  [#113](https://github.com/kazu-yamamoto/quic/pull/113)
* Count only what is in flight into bytes in flight.  RFC 9002 Sec 2:
  a packet is in flight when it is ack-eliciting or contains PADDING.
  Every packet sent was counted, so an ACK-only packet spent congestion
  window it had no business spending -- 177 of 207 such sends in a
  measured run.  The predicate was already in `Types.Frame`, unused.
  [#116](https://github.com/kazu-yamamoto/quic/pull/116)

* AES-GCM goes through crypton's one-call interface, and the bundled picotls
  `fusion` engine is gone with the 11,017 lines of C it came in.  What that
  engine was for is that crypton rebuilt the AES key schedule and the table
  of multiples of H for every packet, and took the header protection mask in
  a second call after the encryption; crypton 2.1 builds the first once per
  key and hands back the mask from the same call as the ciphertext.  Measured
  on an Apple M4, a 100-byte packet goes from 2.25 to 0.16 microseconds and a
  1440-byte one from 2.50 to 0.45.  Against `fusion` itself, measured in C on
  an Intel Haswell where it runs at all, crypton is at 91 to 96 per cent of
  it for the call this makes -- and in Haskell `fusion` needs three foreign
  calls to crypton's one.

* ChaCha20-Poly1305 is in `defaultCiphers` on x86-64 again.  It had been left
  out there because `fusion` did not implement it, so a build with the engine
  offered two suites where every other build offered three.  The RFC 9001 and
  RFC 9369 test vectors for it, skipped under the same condition, now run
  everywhere.
  [#111](https://github.com/kazu-yamamoto/quic/pull/111)

* The `fusion` cabal flag is gone with the engine.  A build passing
  `-f fusion` will now fail on an unknown flag rather than quietly
  selecting something that no longer exists.

* The IOSpec relay no longer latches onto a leftover datagram at the port
  handover, and qlog is kept for a failed CI job.  Tests and CI only, but
  the qlog is what made the stalls above findable at all.
  [#112](https://github.com/kazu-yamamoto/quic/pull/112)

## 0.3.5

Security fixes.  The first four can be reached by a peer that has not
authenticated itself.

* Drop a packet whose header protection sample is not whole.  A sample of 1
  to 15 octets reached the cipher, which raised rather than answering with a
  short mask, and the connection went with it.  One conforming datagram did
  it.
  [#95](https://github.com/kazu-yamamoto/quic/pull/95)
* Bound the CRYPTO data held out of order.  CRYPTO frames sit outside the
  flow control that bounds stream data, so nothing stopped a peer parking
  fragments at scattered offsets and having every one held.
  CryptoBufferExceeded had been defined and never used.
  [#96](https://github.com/kazu-yamamoto/quic/pull/96)
* Decode the peer's transport parameters to the Maybe the type promises,
  rather than raising BufferOverrun out of a pure value.
  [#97](https://github.com/kazu-yamamoto/quic/pull/97)
* Refuse a transport parameter sent twice, and stream limits past 2^60.
  [#105](https://github.com/kazu-yamamoto/quic/pull/105)
* Stop the sender deadlocking on a congestion window it cannot free.
  Padding an ACK-only packet put it in flight, spending window that nothing
  would give back once the loss timer had been cancelled, and the loss timer
  could not be re-armed from another level.
  [#103](https://github.com/kazu-yamamoto/quic/pull/103)
* Leave the peer a whole header protection sample when encoding.
  [#104](https://github.com/kazu-yamamoto/quic/pull/104)
* Bound a connection id and a Retry packet in the long header decoder.
  [#106](https://github.com/kazu-yamamoto/quic/pull/106)
* Bound how many pieces a stream may be held in.  Flow control counts octets,
  not fragments, and a fragment costs far more than the octet it carries.
  [#108](https://github.com/kazu-yamamoto/quic/pull/108)
* Check the ranges an ACK frame carries, and refuse an ACK for a packet never
  sent.
  [#109](https://github.com/kazu-yamamoto/quic/pull/109)
* Give the two ends of a connection their own qlog file.  Pointing both at
  one directory took the server down.
  [#100](https://github.com/kazu-yamamoto/quic/pull/100)
* Remove the partial functions that were worth removing.
  [#107](https://github.com/kazu-yamamoto/quic/pull/107)
* Requiring crypton v2.0.1, whose 2.0.0 dispatched an XOP instruction on
  CPUs without XOP.
  [crypton#202](https://github.com/kazu-yamamoto/crypton/issues/202)
* This is a patch release, but `Network.QUIC.Internal` changed:
  `fromAckInfoWithMin` is gone, `FlowCntl` has `TooFragmented`, and
  `tryReassemble` returns `FlowCntl` rather than `Bool`.

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
