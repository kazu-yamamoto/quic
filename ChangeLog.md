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
