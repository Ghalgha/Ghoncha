# TLS transport over TURN/TCP

Status: design and implementation contract; no TLS client is implemented yet. The existing `TurnTcpEngine` and `TurnTcpDriver` speak plaintext TURN over an already-connected TCP stream. They must not be described or selected as TURN/TLS until this contract is implemented and tested.

## 1. Scope and protocol layering

The intended stack is:

```text
GHONCHA authenticated tunnel records
  -> TURN client protocol (RFC 8656)
  -> TLS 1.2/1.3 stream protection (RFC 8446; TLS 1.2 only if policy requires)
  -> connected TCP socket
```

TLS protects the client-to-TURN-server hop. It does not replace GHONCHA end-to-end tunnel authentication/encryption and does not make the TURN relay a VPN gateway. TURN still allocates a UDP relay transport unless a separately specified allocation mode is selected. Do not confuse TURN over TLS/TCP with RFC 6062 TCP relay allocations.

The TLS adapter must preserve the exact ordered byte stream expected by TURN. It must not add a GHONCHA record prefix or alter STUN/ChannelData framing.

## 2. TLS implementation choice

Use Rustls 0.23 API through a small runtime-neutral, nonblocking adapter. Keep Rustls types behind the TLS adapter boundary; the shared packet and transport API crates must not depend on Android, JNI, or a particular async runtime.

The caller supplies an already-built, verified `Arc<ClientConfig>` and a validated DNS `ServerName`. The adapter creates a `ClientConnection` and exposes explicit handshake/read/write progress. Do not construct a permissive verifier in the transport crate.

The production configuration must:
- use Rustls safe protocol/cipher defaults supported by the selected crypto provider;
- enable TLS 1.3 and retain TLS 1.2 only where deployment compatibility requires it;
- validate the certificate chain and requested server name;
- reject expired, not-yet-valid, untrusted, name-mismatched and otherwise invalid certificates;
- never accept all certificates, disable hostname checks, or silently fall back to plaintext;
- define ALPN only if the TURN endpoint contract explicitly requires it; do not invent an ALPN identifier;
- avoid logging secrets, session tickets, certificate private material, or user payloads.

The endpoint name used for certificate verification must come from trusted endpoint configuration/provider metadata, not reverse DNS or an unauthenticated redirect. Connecting to an IP literal requires a certificate identity valid for that IP or a separately authenticated DNS name.

## 3. Platform trust

Use `rustls-platform-verifier` 0.7.1 as the current candidate for operating-system trust integration (review its release notes and compatibility again when pinning dependencies).

- Android: initialize the verifier exactly once during native application startup, before any TLS verification can occur. Bundle the required Kotlin component and Gradle/Maven setup, preserve it through R8/ProGuard, and pass a valid Android Context through the documented JNI initialization entry point. Initialization failure must prevent TLS transport startup; there is no insecure fallback.
- iOS/macOS: use the platform Security framework trust path exposed by the verifier crate; verify deployment-target and framework integration in the actual Apple build.
- Windows: use the Windows platform certificate verifier exposed by the same crate.
- Other targets: explicitly choose and document the system/web-PKI root strategy. Do not silently ship an empty root store.

The platform verifier is an OS integration dependency, not a dependency of the portable packet engine. Keep its initialization in each platform bootstrap. The Rust TLS adapter receives a verified `ClientConfig`, making the trust policy injectable without platform conditionals in TURN protocol code.

For Android, test the actual application build and runtime initialization. A successful host Linux test does not validate JNI, Gradle packaging, Android Trust Manager access, or Android ABI compatibility.

## 4. Nonblocking I/O contract

Do not use Rustls `complete_io()` in the event-driven driver: it may block and hides readiness transitions.

The adapter must drive Rustls explicitly:
1. On socket-readable readiness, read a bounded ciphertext chunk into Rustls with `read_tls`.
2. Call `process_new_packets` after each successful TLS input operation.
3. Drain decrypted plaintext through `reader()` into a bounded TURN input buffer, respecting the TURN parser's drain-before-next-read invariant.
4. On socket-writable readiness, call `write_tls` and preserve any unwritten ciphertext across partial writes and `WouldBlock`.
5. Continue handshake progress until `is_handshaking()` is false and pending handshake output has been flushed. Do not expose application data as ready before this condition.
6. After handshake, move TURN bytes through Rustls `writer()` and decrypted bytes to the TURN parser. Preserve strict stream ordering in both directions.
7. Handle close-notify, unexpected EOF, fatal TLS alerts and socket errors as terminal transport events. Never reinterpret truncated TLS as clean TURN shutdown.

The API must expose whether the TLS engine wants socket read or write readiness and whether decrypted TURN bytes are waiting. A single read may produce multiple TLS records or partial TURN messages; bounded draining must handle both without losing data.

## 5. Memory and backpressure

All buffers and queues must have explicit limits. Define limits for:
- ciphertext input chunk;
- pending ciphertext output;
- decrypted plaintext waiting for TURN;
- plaintext queued from TURN pending TLS encryption;
- maximum TLS record size accepted by the adapter;
- total per-connection buffering.

When any bound is reached, stop reading from the socket or stop accepting more TURN plaintext and report backpressure. Do not drop TLS control/handshake bytes. Avoid an unbounded `Vec` accumulation path. Reuse caller-owned buffers where Rustls APIs permit; measure unavoidable internal allocations before optimization.

The TLS layer must not create one OS thread per TURN allocation. It is driven by the same readiness/runtime model as the raw TCP driver. Keep per-allocation buffers bounded and account for their aggregate memory when selecting concurrency.

## 6. Integration with TURN driver

The current `TurnTcpDriver` owns a raw `TurnStreamSocket`. TLS must not be bolted on by wrapping encrypted bytes in the existing raw TURN queue: the TURN engine must see decrypted TURN stream bytes, while the socket sees only TLS ciphertext.

Preferred separation:
- retain `TurnTcpEngine` as the Sans-I/O TURN state machine;
- define a stream-security/I/O adapter that owns Rustls and the raw socket;
- make the driver pump TURN plaintext into the TLS writer and TLS plaintext into the TURN engine;
- preserve TURN frame ordering and parser backpressure;
- expose handshake state and TLS errors distinctly from TURN lifecycle events.

Avoid forcing TLS types into `TurnTcpEngine`. Keep the plaintext TCP driver available for explicitly configured non-TLS test environments only; production policy must prefer TLS where the endpoint requires it.

## 7. Failure and network handover

A TLS connection is bound to its underlying TCP connection and network generation. On network handover, do not move an established TLS session onto a different socket or reuse its traffic keys on a new connection. Establish a new TCP/TLS/TURN path, authenticate it, run a bounded tunnel health check, then migrate traffic and retire the old path.

Certificate verification failure, name mismatch, invalid TLS record, handshake timeout, or failed trust-store initialization is a hard failure for that candidate. Retry with bounded backoff only after correcting transient network conditions; never downgrade to plaintext because TLS failed.

## 8. Required tests and release gates

Unit tests with deterministic mock sockets:
- handshake output retained over partial writes and repeated `WouldBlock`;
- fragmented/coalesced TLS records and TURN messages;
- decrypted data drained before another socket read;
- TLS control traffic progresses while TURN send queues are backpressured;
- bounded ciphertext/plaintext queues and explicit backpressure;
- server-name mismatch, untrusted CA, expired certificate and valid chain;
- fatal alert, close-notify, unexpected EOF and truncated record;
- no application data delivered before handshake completion;
- no plaintext fallback after any TLS failure;
- cancellation and stale network-generation events;
- no data loss or reordering across partial writes.

Integration tests:
- local TLS-enabled TURN server with a test CA and a certificate for the configured server name;
- full unauthenticated Allocate challenge, authenticated Allocate, CreatePermission, ChannelBind, peer data in both directions;
- deliberately split and coalesced TURN messages over TLS;
- Android instrumentation test proving system verifier initialization and trust decisions;
- Android ABI builds for every shipped ABI;
- later iOS and Windows trust-store/build tests.

Performance gates compare plaintext TCP and TLS on identical devices/networks: throughput, p50/p95 latency, CPU time, allocations, peak memory, thermal behavior and battery cost. TLS must not be enabled as a fallback in a release until correctness, trust validation, Android packaging, handover and end-to-end gateway interoperability pass.

## 9. Current implementation status

Implemented:
- Sans-I/O TURN-over-TCP engine with UDP relay allocation;
- bounded raw TCP stream queue and nonblocking driver;
- partial-write preservation, bounded reads, peer endpoint validation and parser-drain guard;
- TCP TURN integration test against a local TURN server.

Not implemented:
- Rustls dependency or TLS adapter;
- platform certificate verifier integration;
- Android Kotlin/Gradle/JNI initialization;
- TLS-enabled TURN integration tests;
- production transport selection and live gateway interoperability.

References:
- [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656)
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [Rustls ClientConnection](https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html)
- [rustls-platform-verifier 0.7.1](https://docs.rs/rustls-platform-verifier/0.7.1/rustls_platform_verifier/)
