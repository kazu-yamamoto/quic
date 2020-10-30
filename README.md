## IETF QUIC implementation in Haskell

This package implements QUIC based on Haskell lightweight threads.

- APIs are found in the [`Network.QUIC`](https://github.com/kazu-yamamoto/quic/blob/master/Network/QUIC.hs) module.
- Example client and server are found in the [`util/`](https://github.com/kazu-yamamoto/quic/tree/master/util) directory.
- Implementation plan and status are found in [#2](https://github.com/kazu-yamamoto/quic/issues/2).

This package covers:

- [draft-ietf-quic-transport](https://tools.ietf.org/html/draft-ietf-quic-transport)
- [draft-ietf-quic-tls](https://tools.ietf.org/html/draft-ietf-quic-tls)
- [draft-ietf-quic-recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery)

The followings are implemented in [`http3`](https://github.com/kazu-yamamoto/http3):

- [draft-ietf-quic-http](https://tools.ietf.org/html/draft-ietf-quic-http)
- [draft-ietf-quic-qpack](https://tools.ietf.org/html/draft-ietf-quic-qpack)

Blog articles:

- [The Current Plan for Haskell QUIC](https://kazu-yamamoto.hatenablog.jp/entry/2020/10/23/141648) (2020/10/23)
- [Improving QUIC APIs of the TLS library in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/09/16/150801) (2020/09/16)
- [Developing QUIC Loss Detection and Congestion Control in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/09/15/121613) (2020/09/15)
- [Implementing HTTP/3 in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/06/09/155236) (2020/06/09)
- [Implementation status of QUIC in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/02/18/145038) (2019/09/20)

### Note

To build this package, some unreleased packages are necessary. So, you are not recommended to try this package at this moment.
