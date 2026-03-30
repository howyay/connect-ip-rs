# connect-ip-rs

A Rust implementation of [RFC 9484 (CONNECT-IP)](https://www.rfc-editor.org/rfc/rfc9484) — Proxying IP in HTTP — over HTTP/3.

This crate provides client and proxy APIs for tunneling IP packets through an HTTP/3 CONNECT-IP session, using HTTP Datagrams ([RFC 9297](https://www.rfc-editor.org/rfc/rfc9297)) as the transport and the MASQUE capsule protocol for address negotiation and route exchange.

## Features

- **Full RFC 9484 implementation**: ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT capsules
- **HTTP Datagram framing**: IP packets carried as HTTP/3 datagrams with Context ID 0
- **Capsule protocol**: RFC 9297 §3 TLV framing with streaming decoder
- **Client + Proxy APIs**: Both sides of the CONNECT-IP tunnel
- **Concurrent I/O**: Split sessions into independent datagram/capsule handles for `tokio::select!`
- **MTU computation**: Effective tunnel MTU from QUIC max datagram size
- **Zero `unsafe`**: Pure safe Rust
- **Cross-implementation interop**: Verified against [connect-ip-go](https://github.com/quic-go/connect-ip-go)

## Architecture

```
┌──────────────────────────────────────────┐
│            connect-ip-rs crate            │
├────────────────┬─────────────────────────┤
│   Client API   │      Proxy API          │
├────────────────┴─────────────────────────┤
│          Session Management              │
│  (address negotiation, route exchange)   │
├──────────────────────────────────────────┤
│         Capsule Protocol Layer           │
│  (encode/decode RFC 9297 capsules)       │
├──────────────────────────────────────────┤
│       IP Datagram Framing Layer          │
│  (Context ID + IP packet in HTTP DG)     │
├──────────────────────────────────────────┤
│     h3 + h3-datagram + h3-quinn          │
├──────────────────────────────────────────┤
│               quinn (QUIC)               │
└──────────────────────────────────────────┘
```

## Usage

### Client

```rust
use connect_ip_rs::{ConnectIpClient, ConnectIpClientSession};

// Establish a QUIC connection, then:
let client_session = ConnectIpClient::connect(
    h3_conn,      // h3_quinn::Connection
    "*",           // target (hostname, IP prefix, or "*")
    "*",           // ip_protocol ("*" for all)
    Some(1200),    // max_datagram_size from quinn
).await?;

// Drive h3 in background
tokio::spawn(async move { client_session.driver.wait_idle().await });

// Send/receive IP packets
client_session.session.send_ip_packet(&ipv4_packet)?;
let packet = client_session.session.recv_ip_packet().await?;
```

### Proxy

```rust
use connect_ip_rs::{ConnectIpProxy, ConnectIpRequest};

// Accept incoming CONNECT-IP requests from an h3 server connection
let request = ConnectIpProxy::accept(&mut h3_conn).await?.unwrap();

// Accept and create a session
let mut session = request.accept(&h3_conn, Some(max_dg_size)).await?;

// Exchange capsules
session.send_address_assign(&assign).await?;
session.send_route_advertisement(&routes).await?;

// Tunnel IP packets
let packet = session.recv_ip_packet().await?;
session.send_ip_packet(&response_packet)?;
```

### Concurrent I/O

For production use, split the session for concurrent datagram + capsule handling:

```rust
let parts = session.into_parts();

tokio::select! {
    pkt = parts.datagram_recv.recv_ip_packet() => {
        // Forward to TUN device
    }
    cap = parts.capsule_recv.recv_capsule() => {
        // Handle control plane message
    }
}
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `quinn` 0.11 | QUIC transport |
| `h3` (git) | HTTP/3 protocol (Extended CONNECT) |
| `h3-quinn` (git) | Quinn transport adapter for h3 |
| `h3-datagram` (git) | HTTP Datagrams (RFC 9297) |
| `tokio` 1.x | Async runtime |
| `bytes` 1.x | Buffer management |

> **Note**: h3 is used from git main because the released version (0.0.8) doesn't include `Protocol::CONNECT_IP`. This will switch to a crates.io release when h3 publishes one with CONNECT-IP support.

## Testing

```bash
# Run all tests (65 tests)
cargo test

# Run with Go interop test (requires Go runtime)
cargo test --features interop
```

### Test Coverage

| Category | Tests | What's Verified |
|----------|-------|-----------------|
| Varint (RFC 9000 §16) | 11 | Official test vectors, boundaries, edge cases |
| Capsule TLV (RFC 9297) | 10 | Roundtrips, truncation, large payloads, unknown types |
| ADDRESS capsules (RFC 9484 §4.7.1-2) | 12 | Encode/decode, validation, invalid inputs |
| ROUTE capsules (RFC 9484 §4.7.3) | 8 | Sorting, overlap, protocols |
| Datagram framing (RFC 9484 §6) | 9 | Context ID, IPv4/IPv6, MTU |
| Integration (loopback) | 8 | Full client↔proxy flows, concurrent I/O, rejection |
| RFC conformance | 23 | Systematic MUST/SHOULD coverage |
| Interop (connect-ip-go) | 1 | Cross-implementation wire compatibility |

## RFCs Implemented

- [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) — Proxying IP in HTTP (CONNECT-IP)
- [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) — HTTP Datagrams and the Capsule Protocol
- [RFC 9000 §16](https://www.rfc-editor.org/rfc/rfc9000#section-16) — Variable-Length Integer Encoding

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
