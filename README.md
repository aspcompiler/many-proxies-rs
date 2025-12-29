# many-proxies-rs

This is a playground to explore many types of proxies, for example:

* TCP proxy: simply pass the packets through so can’t do many. Typically use for load balancing, throttling, etc.
* TLS (transportation level security, not two level system) non pass-through proxy: Leave the TLS handshake to the server but can peek on unencrypted portion of TLS handshake. Typically used for routing using server name indicator (SNI) and application level protocol negotiation (ALPN). Can also authenticate client certificate.
* TLS terminating proxy: Does TLS handshake and thus need server certificate and decrypt TLS traffic. Have the opportunity to work with application protocol, such as Application Load Balancer (ALB).
* gRPC proxy: deserialized and re-serialize gRPC traffic. Can validate/modify the payload.

In order to test the proxies, we borrowed [some gRPC examples from the tonic project](https://github.com/hyperium/tonic/tree/master/examples/src/tls_client_auth)

To run the sample client and server, from separate terminals run:

```
cargo run -p tls-client-auth --bin tls-server
```

```
cargo run -p tls-client-auth --bin tls-client -- [port]
```

Port is optional above.

## TCP Proxy

A proxy that simply forwards TCP packets. To test, run tls-server. Then run the proxy:

```
cargo run -p tcp-proxy
```

Test with client:

```
cargo run -p tls-client-auth --bin tls-client -- 50052
```

## TSL Terminator

A proxy that decrypt TLS traffic and communicates with backend in clear.

Run server in clear:

```
cargo run -p tls-client-auth --bin tls-server -- no-tls
```

Run TLS terminator:

```
cargo run -p tls-term
```

Test with client:

```
cargo run -p tls-client-auth --bin tls-client -- 50052
```

Compare this to the [Java/Netty version](https://github.com/aspcompiler/tlsterm)!

## hyper-https2-proxy

An http2 proxy compatible with gRPC developed using hyper lower level library.

* Optional TLS, mTLS support for the proxy server. The proxy only communicates with the backend in clear.
* Support TLS ALPN since this is expected by some gRPC clients. Otherwise it will not use http/2 protocol.
* Support for gRPC bidirectional streaming by streaming the http trailers, i.e., headers after a part of body.

## pingora-http2-proxy

An http2 proxy compatible with gRPC developed using Pingora library. It has much less code than the
hyper version, but has the limitation that it only supports tls because we have difficulty
upgrade to http2 mode without TLS ALPN with the Pingora library.

* Optional TLS, mTLS support for the proxy server. The proxy only communicates with the backend in clear.
* Support TLS ALPN since this is expected by some gRPC clients. Otherwise it will not use http/2 protocol.
* Support for gRPC bidirectional streaming by streaming the http trailers, i.e., headers after a part of body.
