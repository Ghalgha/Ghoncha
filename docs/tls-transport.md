# TLS transport over TURN/TCP

Status: partial implementation, not production-ready. Rustls 0.23.46 is pinned in `ghoncha-transport-turn`. `TlsClientEngine` and `TlsStreamSocket` provide a nonblocking TLS client stream for `TurnTcpDriver`. A verified in-memory client/server handshake and negative certificate tests pass. Android system-trust bootstrap is wired into the initial Android app/native layer and cross-compiled for four ABIs; on-device trust verification, TLS-enabled TURN interoperability and end-to-end VPN integration remain unvalidated.

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

Use Rustls 0.23.46 through a runtime-neutral, nonblocking adapter. The exact version is pinned in `crates/transport-turn/Cargo.toml` and locked in `Cargo.lock`. Rustls types stay behind `TlsClientEngine` / `TlsStreamSocket`; the shared packet and transport API crates do not depend on Android, JNI, or a particular async runtime.

The caller supplies an already-built, verified `Arc<ClientConfig>` and a validated DNS `ServerName`. The adapter creates a `ClientConnection` and exposes explicit handshake/read/write progress. Do not construct a permissive verifier in the transport crate.

The production configuration must:
- disable TLS 1.3 early data (0-RTT) for TURN and tunnel records; replayable early data is not acceptable for allocation/authentication state or VPN payloads;
- use Rustls safe protocol/cipher defaults supported by the selected crypto provider;
- enable TLS 1.3 and retain TLS 1.2 only where deployment compatibility requires it;
- validate the certificate chain and requested server name;
- reject expired, not-yet-valid, untrusted, name-mismatched and otherwise invalid certificates;
- never accept all certificates, disable hostname checks, or silently fall back to plaintext;
- define ALPN only if the TURN endpoint contract explicitly requires it; do not invent an ALPN identifier;
- avoid logging secrets, session tickets, certificate private material, or user payloads.

The endpoint name used for certificate verification must come from trusted endpoint configuration/provider metadata, not reverse DNS or an unauthenticated redirect. Connecting to an IP literal requires a certificate identity valid for that IP or a separately authenticated DNS name.

## 3. Platform trust

Use `rustls-platform-verifier` 0.7.1 in the platform bootstrap/application layer, not in `ghoncha-transport-turn`. The portable TURN crate continues to accept a caller-supplied verified `ClientConfig`. Version 0.7.1 (2026-09-24) distributes its Android Kotlin component through the project's GitHub-hosted Maven repository. The Android Gradle build resolves the AAR version from the `Cargo.lock` entry for `rustls-platform-verifier-android`, keeping native and Kotlin components aligned.

- Android: the initial `android/app` module declares the GitHub-hosted Maven repository and the unversioned `org.rustls:rustls-platform-verifier` AAR. Its Gradle `ValueSource` reads `rustls-platform-verifier-android` from the workspace `Cargo.lock`; a Cargo metadata task runs before the Android build. `crates/platform-android` exports a JNI bootstrap that calls `rustls_platform_verifier::android::init_with_env` from `GhonchaApplication.onCreate`, passing the application Context. Initialization failure throws a Java RuntimeException and prevents application startup. The same crate exposes `platform_tls_client_config()`, which refuses to build a client config before successful initialization and explicitly disables TLS early data. The debug APK CI cross-compiles the native library for arm64-v8a, armeabi-v7a, x86_64 and x86. R8 keeps the verifier's JNI Kotlin classes. The app module remains a bootstrap shell; it does not yet contain the VPN service or full client lifecycle. On-device Trust Manager decisions and instrumentation tests remain release gates.
- iOS/macOS: use the platform Security framework trust path exposed by the verifier crate; verify deployment-target and framework integration in the actual Apple build.
- Windows: use the Windows platform certificate verifier exposed by the same crate.
- Other targets: explicitly choose and document the system/web-PKI root strategy. Do not silently ship an empty root store.

The platform verifier is an OS integration dependency, not a dependency of the portable packet engine. Keep its initialization in each platform bootstrap. The Rust TLS adapter receives a verified `ClientConfig`, making the trust policy injectable without platform conditionals in TURN protocol code.

For Android, test the actual application build and runtime initialization. A successful host Linux test does not validate JNI, Gradle packaging, Android Trust Manager access, or Android ABI compatibility.

## 4. Nonblocking I/O contract

Do not use Rustls `complete_io()` in the event-driven driver: it may block and hides readiness transitions.

The implemented engine drives Rustls explicitly and never calls `complete_io()`:
1. `TlsClientEngine::feed_ciphertext` accepts one ciphertext chunk up to 16 KiB, calls `read_tls` and `process_new_packets`, and reports consumed bytes, available plaintext and pending output.
2. `read_plaintext` drains authenticated plaintext from Rustls `reader()` into caller-owned storage.
3. `write_plaintext` accepts at most 16 KiB and refuses application data until the handshake is complete and prior TLS output has been taken.
4. `drain_ciphertext` stages Rustls output into a bounded 256 KiB batch and copies a caller-sized prefix. It never partially writes a TLS record directly into a too-small socket buffer.
5. `wants_read`, `wants_write` and `application_data_ready` expose readiness and handshake state. Handshake completion requires `is_handshaking() == false` and no pending TLS output.
6. `TlsStreamSocket` wraps an already-connected `TurnStreamSocket`, preserves partial ciphertext writes in a fixed 16 KiB output buffer, decrypts reads, and implements the same stream trait consumed by `TurnTcpDriver`.
7. `TurnTcpDriver<TlsStreamSocket<S>>` keeps TURN framing and parser state above TLS. The driver retains TURN bytes when the TLS handshake is not ready; the underlay socket sees only ciphertext.

The wrapper does not create, bind, protect or connect sockets. The platform must still prepare the raw socket and drive read/write readiness. Unexpected EOF, fatal TLS alerts and socket errors retire the stream. The TLS engine has a verified in-memory handshake test; end-to-end handshake through the socket adapter and `TurnTcpDriver`, plus close-notify behavior, remain integration-test work.

The API must expose whether the TLS engine wants socket read or write readiness and whether decrypted TURN bytes are waiting. A single read may produce multiple TLS records or partial TURN messages; bounded draining must handle both without losing data.

## 5. Memory and backpressure

Current explicit limits are: 16 KiB ciphertext input chunks, 16 KiB plaintext writes, 64 KiB Rustls plaintext buffering limit, 256 KiB maximum staged TLS ciphertext batch, and fixed 16 KiB input/output arrays in `TlsStreamSocket`. The staged ciphertext vector grows only as needed and is hard-bounded; overflow retires the TLS connection rather than dropping or replaying a partial record batch.

The current wrapper retains ciphertext across partial socket writes and `WouldBlock`. Aggregate per-connection memory, Rustls internal allocations, and memory under the 30–40 allocation profile still require measurement. Do not treat these constants as final performance tuning.

The TLS layer must not create one OS thread per TURN allocation. It is driven by the same readiness/runtime model as the raw TCP driver. Keep per-allocation buffers bounded and account for their aggregate memory when selecting concurrency.

## 6. Integration with TURN driver

The current `TurnTcpDriver` owns a raw `TurnStreamSocket`. TLS must not be bolted on by wrapping encrypted bytes in the existing raw TURN queue: the TURN engine must see decrypted TURN stream bytes, while the socket sees only TLS ciphertext.

Implemented separation:
- `TurnTcpEngine` remains the Sans-I/O TURN state machine;
- `TlsStreamSocket<S>` owns Rustls plus the already-connected raw socket;
- the existing `TurnTcpDriver` consumes `TlsStreamSocket<S>` through the `TurnStreamSocket` interface, so TURN protocol bytes are plaintext only above the TLS adapter;
- partial ciphertext writes and TLS handshake backpressure are retained without changing TURN framing.

TLS types are not forced into `TurnTcpEngine`. The raw plaintext TCP path remains available only when explicitly selected by endpoint policy; it is not an automatic fallback after TLS failure.

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
- pinned Rustls 0.23.46 dependency and generated lockfile;
- nonblocking `TlsClientEngine` with caller-supplied verified `ClientConfig` and validated `ServerName`;
- rejection of configurations with TLS 1.3 early data enabled;
- explicit handshake/read/write progress without blocking socket I/O;
- bounded ciphertext input, pending output and plaintext write sizes;
- `TlsStreamSocket<S>` adapter that wraps an already-connected TURN TCP socket;
- integration with the existing `TurnTcpDriver` through `TurnStreamSocket`;
- tests for ClientHello generation, a verified in-memory client/server handshake, bidirectional TLS stream data, untrusted-CA and hostname-mismatch rejection, partial TLS output draining, handshake gating, oversized input, early-data rejection, partial socket writes, and TURN driver plaintext isolation;
- Android Cargo cross-build of the JNI verifier bootstrap for arm64-v8a, armeabi-v7a, x86_64 and x86, plus a debug APK build in CI;
- CI formatting, Clippy and tests with all Cargo features enabled.

Not implemented or not yet validated:
- expired-certificate validation test;
- live TLS-enabled TURN server interoperability and end-to-end gateway validation;
- Android instrumentation tests and on-device validation of system Trust Manager decisions;
- Android VPN service, network lifecycle, and complete client-core integration;
- iOS and Windows trust-store integration;
- full TLS-enabled TURN server integration covering Allocate, Permission, ChannelBind and peer data;
- network handover, session resumption policy and production transport selection;
- device-level throughput, latency, memory, thermal and battery benchmarks.

The current code is an implementation foundation, not a release-ready TLS transport. Do not enable it as a production fallback until the missing trust, handshake, server interoperability, handover and device tests pass.
References:
- [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656)
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [Rustls ClientConnection](https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html)
- [rustls-platform-verifier 0.7.1](https://docs.rs/rustls-platform-verifier/0.7.1/rustls_platform_verifier/)
