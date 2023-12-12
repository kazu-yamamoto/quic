## 0.1.13

- Garding the path_request attack.

## 0.1.12

- Fixing build.

## 0.1.11

- Rescuing GHC 8.10, 9.0 and 9.2.

## 0.1.11

- Adding possibleMyStreams.

## 0.1.10

- Setting proper upper boundaries for the dependencies

## 0.1.9

- Using the network-control package.
- Rate control for some frames.
- Announcing MaxStreams correctly.

## 0.1.8

- Announcing MaxStreams properly.
- Terminating a connection if the peer violates flow controls.

## 0.1.7

- Using System.Timeout.timeout.

## 0.1.6

- Fixing the race condition of `timeout`.

## 0.1.5

- Catching up "tls" v1.9.0.
- Fixing the timing to set resumption tokens.

## 0.1.4

- Fixing the race of socket closure.

## 0.1.3

- Supporting `tls` v1.8.0.

## 0.1.2

- Using "crypton" instead of "cryptonite".

## 0.1.1

- Fix recvStream hanging
  [#54](https://github.com/kazu-yamamoto/quic/pull/54)
- Don't use the fusion crypto on Intel if the CPU does not
  provides enough features.
- Add cabal flag for fusion support
  [#53](https://github.com/kazu-yamamoto/quic/pull/53)

## 0.1.0

- Supporting QUICv2 and version negotiation.
- Supporting CPUs other than Intel.
- Supporting Windows.
- Using the network-udp package

## 0.0.1

- Making Haskell servers friendly with Chrome
  [#20](https://github.com/kazu-yamamoto/quic/pull/20)

## 0.0.0

- Initial version.
