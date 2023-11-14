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
- [Greasing the QUIC Bit](https://tools.ietf.org/html/rfc9287)
- [QUIC Version 2](https://tools.ietf.org/html/rfc9369)
- [Compatible Version Negotiation for QUIC](https://tools.ietf.org/html/rfc9368)

The followings are implemented in [`http3`](https://github.com/kazu-yamamoto/http3):

- [HTTP/3](https://tools.ietf.org/html/rfc9114)
- [QPACK: Field Compression for HTTP/3](https://tools.ietf.org/html/rfc9204)

Technical/blog articles:

- [Developing network related libraries in Haskell in 2022FY](https://kazu-yamamoto.hatenablog.jp/entry/2023/03/23/134317) (2023/03/23 blog)
- [Accepting UDP connections](https://kazu-yamamoto.hatenablog.jp/entry/2022/02/25/153122) (2022/02/25 blog)
- [Integrating Fusion and cryptonite in Haskell quic](https://kazu-yamamoto.hatenablog.jp/entry/2021/12/20/152921) (2021/12/20 blog)
- [Implementing QUIC in Haskell](https://www.iij.ad.jp/en/dev/iir/pdf/iir_vol52_focus2_EN.pdf) (2021/11 technical article)
- [Releasing QUIC and HTTP/3 libraries](https://kazu-yamamoto.hatenablog.jp/entry/2021/10/04/153546) (2021/10 blog)
- [Migration API for QUIC clients](https://kazu-yamamoto.hatenablog.jp/entry/2021/06/29/134930) (2021/06 blog)
- [Testing QUIC servers with h3spec](https://kazu-yamamoto.hatenablog.jp/entry/2020/11/19/160606) (2020/11/19 blog)
- [The Current Plan for Haskell QUIC](https://kazu-yamamoto.hatenablog.jp/entry/2020/10/23/141648) (2020/10/23 blog)
- [Improving QUIC APIs of the TLS library in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/09/16/150801) (2020/09/16 blog)
- [Developing QUIC Loss Detection and Congestion Control in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/09/15/121613) (2020/09/15 blog)
- [Implementing HTTP/3 in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/06/09/155236) (2020/06/09 blog)
- [Implementation status of QUIC in Haskell](https://kazu-yamamoto.hatenablog.jp/entry/2020/02/18/145038) (2019/09/20 blog)
