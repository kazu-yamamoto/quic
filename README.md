![GitHub Actions status](https://github.com/kazu-yamamoto/quic/workflows/Haskell%20CI/badge.svg)

## IETF QUIC implementation in Haskell

This package implements QUIC based on Haskell lightweight threads.

- APIs are found in the [`Network.QUIC`](https://github.com/kazu-yamamoto/quic/blob/master/Network/QUIC.hs) module.
- Example client and server are found in the [`util/`](https://github.com/kazu-yamamoto/quic/tree/master/util) directory.

This package covers:

- [Version-Independent Properties of QUIC](https://tools.ietf.org/html/rfc8999)
- [QUIC: A UDP-Based Multiplexed and Secure Transport](https://tools.ietf.org/html/rfc9000)
- [Using TLS to Secure QUIC](https://tools.ietf.org/html/rfc9001)
- [QUIC Loss Detection and Congestion Control](https://tools.ietf.org/html/rfc9002)

The followings are implemented in [`http3`](https://github.com/kazu-yamamoto/http3):

- [HTTP/3](https://tools.ietf.org/html/rfc9114)
- [QPACK: Field Compression for HTTP/3](https://tools.ietf.org/html/rfc9204)

Blog articles:

- [Testing QUIC servers with h3spec](https://kazu-yamamoto.hatenablog.jp/entry/2020/11/19/160606) (2020/11/19)
- [The Current Plan for Haskell QUIC](https://kazu-yamamoto.hatenablog.jp/entry/2020/10/23/141648) (2020/10/23)
- [Improving QUIC APIs of the TLS library in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/09/16/150801) (2020/09/16)
- [Developing QUIC Loss Detection and Congestion Control in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/09/15/121613) (2020/09/15)
- [Implementing HTTP/3 in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/06/09/155236) (2020/06/09)
- [Implementation status of QUIC in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/02/18/145038) (2019/09/20)
