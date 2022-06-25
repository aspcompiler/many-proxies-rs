# many-proxies-rs

This is a playground to explore many types of proxies, for example:

* TCP proxy: simply pass the packets through so can’t do many. Typically use for load balancing, throttling, etc.
* TLS (transportation level security, not two level system) non pass-through proxy: Leave the TLS handshake to the server but can peek on unencrypted portion of TLS handshake. Typically used for routing using server name indicator (SNI) and application level protocol negotiation (ALPN). Can also authenticate client certificate.
* TLS terminating proxy: Does TLS handshake and thus need server certificate and decrypt TLS traffic. Have the opportunity to work with application protocol, such as Application Load Balancer (ALB).
* gRPC proxy: deserialized and re-serialize gRPC traffic. Can validate/modify the payload.

In order to test the proxies, we borrowed [some gRPC examples from the tonic project](https://github.com/hyperium/tonic/tree/master/examples/src/tls_client_auth)

To run the sample client and server, from separate terminals run:

```
cargo run --bin tls-server
```

```
cargo run --bin tls-client [port]
```

Port is optional above.
