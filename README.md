## IETF QUIC implementation in Haskell

This package implements QUIC based on Haskell lightweight threads.

- APIs are found in the (`Network.QUIC`)[Network/QUIC.hs] module.
- Example client and server are found in the (`util/`)[util/] directory.
- Implementation plan and status are found in #2.

This package should cover:

- [draft-ietf-quic-transport](https://tools.ietf.org/html/draft-ietf-quic-transport)
- [draft-ietf-quic-tls](https://tools.ietf.org/html/draft-ietf-quic-tls)
- [draft-ietf-quic-recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery)

The followings will be implemented in another package, probably in [`http2`](https://github.com/kazu-yamamoto/http2):

- [draft-ietf-quic-http](https://tools.ietf.org/html/draft-ietf-quic-http)
- [draft-ietf-quic-qpack](https://tools.ietf.org/html/draft-ietf-quic-qpack)

### Note

To build this package, some unreleased packages are necessary. So, you are not recommended to try this package at this moment.

For QUIC APIs in TLS can be found in the [handshake-controller](https://github.com/kazu-yamamoto/hs-tls/tree/handshake-controller) branch. This APIs are based on Haskell lightweight threads.
