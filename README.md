## IETF QUIC implementation in Haskell

This package implements QUIC based on Haskell lightweight threads.

- APIs are found in the [`Network.QUIC`](https://github.com/kazu-yamamoto/quic/blob/master/Network/QUIC.hs) module.
- Example client and server are found in the [`util/`](https://github.com/kazu-yamamoto/quic/tree/master/util) directory.
- Implementation plan and status are found in [#2](https://github.com/kazu-yamamoto/quic/issues/2).

This package should cover:

- [draft-ietf-quic-transport](https://tools.ietf.org/html/draft-ietf-quic-transport)
- [draft-ietf-quic-tls](https://tools.ietf.org/html/draft-ietf-quic-tls)
- [draft-ietf-quic-recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery)

The followings are implemented in [`http3`](https://github.com/kazu-yamamoto/http3):

- [draft-ietf-quic-http](https://tools.ietf.org/html/draft-ietf-quic-http)
- [draft-ietf-quic-qpack](https://tools.ietf.org/html/draft-ietf-quic-qpack)

### Note

To build this package, some unreleased packages are necessary. So, you are not recommended to try this package at this moment.
