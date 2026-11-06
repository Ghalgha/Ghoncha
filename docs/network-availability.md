# GHONCHA network availability and restricted-network behavior

Status: design requirements. No transport is assumed to work in every network. A detected restriction is a diagnostic conclusion with a confidence level, not proof of the filtering mechanism.

## Operating assumptions

GHONCHA must not assume that a client can reach an arbitrary public server. The network may have DNS interference, destination IP filtering, port or protocol filtering, TLS/SNI-based filtering, DPI classification, selective UDP/TCP/QUIC restrictions, temporary mobile-data shutdowns, or a strict allowlist. Conditions can differ by carrier, region, access technology, time, and individual network.

Ordinary filtering and strict allowlist operation are distinct cases:

- **Ordinary filtering:** general internet connectivity exists, but selected destinations, protocols, or services fail.
- **Strict allowlist / restricted access:** only a limited set of approved destinations or services may be reachable. A GHONCHA endpoint outside that set may be unreachable regardless of port choice, TLS wrapping, or protocol changes.
- **Network outage:** the radio or link may be present while packet service or usable routing is unavailable.
- **Captive portal / unvalidated network:** a local network exists but public internet access has not been established.

Public reporting on Russia documents mobile internet restrictions and allowlists that vary over time and place; some reports also describe approved resources failing intermittently. These reports are operational context, not a stable machine-readable allowlist. GHONCHA must not hardcode a presumed list of allowed Russian hosts or infer access from country/operator identity.

## Network Availability Manager

Implement a distinct Network Availability Manager (NAM). Android owns observation of platform network state; the Rust core owns endpoint reachability measurements, transport health, retry policy, and the consolidated state machine. A narrow event interface carries network identity changes, capabilities, link properties, probe results, and timestamps. It must not carry packets.

### Android observations

Use `ConnectivityManager` and `NetworkCallback` rather than periodic polling:

- Observe default-network availability and loss.
- Observe capability and link-property changes, including DNS servers, routes, addresses, and transport type.
- Track Wi-Fi/cellular transitions and metered status.
- Treat `NET_CAPABILITY_INTERNET` as configured internet capability, not proof of actual reachability.
- Treat `NET_CAPABILITY_VALIDATED` as Android's recent system validation of public internet access, not proof that the GHONCHA endpoint is reachable.
- Treat captive portal state separately.
- Do not synchronously query `ConnectivityManager` state from inside callbacks where Android documents race conditions; copy callback data and process it off the callback thread.
- Unregister callbacks when their lifecycle ends. Avoid excessive callback registrations.

The system may change the default network while the app is running. On a network change, invalidate transport sockets tied to the old `Network`, re-evaluate routes and DNS, and re-establish only what is necessary. Protect VPN transport sockets with `VpnService.protect()` so they do not recursively enter the TUN tunnel.

### Endpoint diagnostics

Probe only configured GHONCHA infrastructure and a small, operator-controlled set of health endpoints. Do not perform broad host or port scanning.

Separate these observations:

1. **Link state:** Android reports a network interface/network object.
2. **General internet validation:** Android reports validated connectivity, supplemented by a bounded application-level probe where appropriate.
3. **DNS resolution:** configured resolver succeeds, fails, or returns inconsistent results for the configured service name. Record the resolver path and result category, not sensitive query contents.
4. **Endpoint reachability:** the configured GHONCHA endpoint responds to a protocol-specific authenticated health/handshake probe.
5. **Tunnel health:** authenticated tunnel traffic and gateway responses are flowing.
6. **Application data health:** optional low-volume end-to-end checks can detect a tunnel that is up but cannot route useful traffic.

A successful probe to one public endpoint does not prove unrestricted internet access. A failed probe does not by itself prove censorship: routing faults, server outages, DNS faults, captive portals, packet loss, and transient congestion can produce similar symptoms. Report evidence and confidence, not an unsupported claim that DPI or a particular blocking mechanism was detected.

Use independent signals where useful: DNS resolution, TCP/TLS connection establishment, UDP reachability, authenticated protocol response, and a small known-good HTTPS control endpoint. Avoid repeated probes that waste data or battery. Respect metered networks and user settings.

## User-visible network states

Expose a small, honest state model:

1. **Network and GHONCHA server available:** the endpoint is reachable and the authenticated tunnel is established.
2. **Internet available; GHONCHA server unreachable:** general connectivity is validated, but the configured endpoint cannot be reached. The cause may be filtering, routing, server failure, or protocol incompatibility.
3. **Restricted access suspected:** some connectivity exists, but configured GHONCHA endpoints fail while limited control observations succeed. This is an inference, never a definitive identification of a whitelist.
4. **Mobile data / network unavailable:** Android reports loss of the relevant network, or the configured path is unavailable at link/service level.
5. **Network connected; internet unavailable:** link exists, but Android validation and bounded public connectivity probes fail; captive portal is reported separately.
6. **Connecting / recovering:** a bounded connection attempt is in progress.
7. **Configuration unavailable or expired:** no currently valid configuration can safely establish a connection.

The UI should show the last successful connection time, active network type, selected transport, endpoint status, last failure category, and next retry time where relevant. Do not expose private keys, credentials, full packet contents, or unnecessary DNS history.

## Transport evaluation

Treat transports as independently testable adapters behind one policy interface. Evaluate at least:

- **Direct WireGuard over UDP:** lowest framing overhead and a natural datagram fit; often fails where UDP is filtered or unavailable.
- **TURN over UDP:** standardized relay allocation and datagram forwarding; adds framing and relay latency, and requires a reachable TURN service plus a permitted route to it and from it to the gateway.
- **TURN over TCP/TLS:** compatibility path where client-to-TURN UDP is unavailable; TCP head-of-line blocking and retransmissions can increase latency and jitter. It still requires the TURN service to be reachable and the relay to reach the peer.
- **MASQUE CONNECT-UDP (RFC 9298):** proxies UDP over HTTP using HTTP Datagrams and Extended CONNECT where supported. It is a standards-based option, not evidence that an arbitrary HTTP endpoint is allowlisted. HTTP/3/QUIC may itself be blocked; HTTP/2 behavior and server support must be measured.
- **MASQUE CONNECT-IP (RFC 9484):** standardizes IP packet proxying over HTTP and is directly relevant to VPN-style tunnelling. Evaluate its server ecosystem, client implementation maturity, datagram behavior, MTU, flow control, and CPU cost before adoption.
- **VK Calls TURN:** the primary, explicitly provisioned path. It obtains short-lived TURN credentials from a user-authorized VK Calls session, then carries DTLS-SRTP-negotiated RTP/SRTP records through the VK TURN relay to the user's own gateway. The gateway extracts the inner WireGuard datagrams. This is not a generic public Calls SDK DataChannel. Calls-specific credential bootstrap methods may be undocumented and unstable; keep them isolated behind a provider adapter. See `docs/vk-calls-transport.md` and `docs/vk-turn-reference-audit.md`.
- **Other transports:** consider only when there is a concrete deployment requirement and an interoperable, maintained implementation. Avoid adding multiple speculative transports before the core path is measured.

MASQUE is not a magic disguise or a guaranteed route through filtering. It requires a reachable MASQUE proxy, protocol support, valid credentials/policy, and a route from the proxy to the destination. A proxy hosted behind a CDN or on a popular cloud address is not automatically reachable in a strict allowlist, and using a third-party CDN as an unapproved relay creates reliability, policy, and abuse risks.

Do not treat port changes, SNI changes, obfuscation, or protocol camouflage as availability guarantees. Do not silently or endlessly rotate endpoints. Any optional transport must be explicitly deployed, documented, authenticated, and measured.

### Comparative measurements

For every transport and network profile, measure:

- Connection success rate and time-to-connect.
- Sustained and burst throughput in both directions.
- Median, p95, and p99 RTT; jitter; packet loss and reordering.
- CPU time, memory, wakeups, radio-active time, and battery consumption.
- Recovery time after network loss, IP change, NAT rebinding, and sleep/wake.
- Behavior on metered links and low-signal cellular networks.
- MTU behavior, fragmentation, black-hole detection, and IPv4/IPv6 compatibility.

Test across multiple carriers, regions, Wi-Fi providers, and time windows with consent and controlled endpoints. Never publish a universal ranking from a single operator or test location.

## Configuration and recovery

- Cache the last known-good configuration in app-private storage, encrypted where it contains secrets, with authenticated integrity protection.
- Authenticate configuration updates cryptographically. Enforce schema/version validation, expiry, rollback protection, and key rotation.
- A cached configuration may be used only while valid and not revoked. It cannot create reachability where no route exists.
- Keep a minimal bootstrap configuration sufficient to reach the control plane, but do not assume the control-plane host is reachable on a restricted network.
- Separate configuration freshness from data-plane reachability. A valid cached configuration does not mean the endpoint is online.
- Apply bounded exponential backoff with jitter, per-endpoint failure suppression, and a maximum retry budget. Reset backoff only after meaningful success or a material network change.
- Stop active retries when Android reports no usable network. Resume on a network callback or a user action; do not hold a wake lock merely to keep retrying.
- Respect Android background execution limits. Use WorkManager only for deferrable maintenance/configuration refresh, not for a latency-sensitive tunnel loop.
- Do not repeatedly download unchanged configuration or probe all transports on every wakeup.
- Preserve the last failure category and expose a manual retry action.

## Failure classification

Use structured categories rather than one generic "VPN failed" error:

- `NO_NETWORK`
- `CAPTIVE_PORTAL`
- `NO_VALIDATED_INTERNET`
- `DNS_FAILURE`
- `ENDPOINT_UNREACHABLE`
- `TRANSPORT_UNSUPPORTED_OR_BLOCKED`
- `AUTHENTICATION_FAILED`
- `GATEWAY_UNAVAILABLE`
- `TUNNEL_HANDSHAKE_TIMEOUT`
- `TUNNEL_ESTABLISHED_NO_DATA`
- `CONFIGURATION_EXPIRED`
- `CONFIGURATION_INVALID`
- `UNKNOWN_TRANSIENT_FAILURE`

Categories describe the observed failure layer. For example, a TCP timeout must not automatically be labeled "DPI block"; an authenticated gateway error must not be labeled "no internet".

## Security and privacy

- Authenticate all control-plane and transport endpoints; validate certificates and protocol identities.
- Do not accept unauthenticated configuration from captive portals or arbitrary network responses.
- Do not log raw DNS queries, private addresses, user traffic, credentials, or tunnel payloads unless strictly necessary for a user-enabled diagnostic export.
- Make diagnostic export opt-in, bounded, and redacted.
- Do not claim anonymity, censorship resistance, or guaranteed operation under strict allowlists.
- When no route to the configured server exists, state plainly that connection is currently impossible on this network.

## References

- Android network state and validation: https://developer.android.com/develop/connectivity/network-ops/reading-network-state
- Android NetworkCallback: https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback
- TURN: RFC 8656, https://www.rfc-editor.org/rfc/rfc8656
- MASQUE CONNECT-UDP: RFC 9298, https://www.rfc-editor.org/rfc/rfc9298
- MASQUE CONNECT-IP: RFC 9484, https://www.rfc-editor.org/rfc/rfc9484
- Russia mobile internet restrictions and allowlists: https://www.hrw.org/news/2026/03/31/russia-internet-shutdowns-escalate

This document defines requirements only. It does not add a transport implementation or claim that any transport works on a particular carrier or whitelist.
