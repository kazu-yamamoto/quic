## IETF QUIC implementation in Haskell

This package should cover:

- [draft-ietf-quic-transport](https://tools.ietf.org/html/draft-ietf-quic-transport)
- [draft-ietf-quic-tls](https://tools.ietf.org/html/draft-ietf-quic-tls)
- [draft-ietf-quic-recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery)

The followings will be implemented in another package, probably in [`http2`](https://github.com/kazu-yamamoto/http2):

- [draft-ietf-quic-http](https://tools.ietf.org/html/draft-ietf-quic-http)
- [draft-ietf-quic-qpack](https://tools.ietf.org/html/draft-ietf-quic-qpack)

For QUIC APIs in TLS can be found in the [handshake-controller](https://github.com/kazu-yamamoto/hs-tls/tree/handshake-controller) branch. This APIs and this QUIC implementation are based on Haskell lightweight threads while other implementations mostly are based on event-driven model.
