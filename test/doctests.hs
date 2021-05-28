import Test.DocTest

main :: IO ()
main = doctest ["Network.QUIC.Client","Network.QUIC.Server"]
