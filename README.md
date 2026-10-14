# netprobe

Network reachability, TLS certificate, and HTTP security header auditor. Reads and reports; it does not exploit, brute-force, fuzz, or inject.

## Install

```
pip install .
```

Requires Python 3.9+. `reach` and `dns` have no dependencies. Certificate details in `tls` and `web` need `cryptography` 38+:

```
pip install ".[cert]"
```

Without it those two commands still work but report no certificate fields.

## Commands

```
netprobe reach <host...>   TCP reachability, connect latency, resolved peers
netprobe tls   <host...>   protocol version, cipher, chain trust, expiry, SAN
netprobe web   <url...>    HTTP status, security headers, TLS, letter grade
netprobe dns   <host...>   resolver view, A and AAAA, lookup time
```

## Authorization

Every command refuses to run without an explicit acknowledgment:

```
netprobe reach example.com --ack "I have authorization to test this target."
```

Target count is capped at 32 per invocation. Connections are serialized per target with a rate delay and a bounded retry count.

## Examples

```
netprobe reach example.com github.com --port 443 --ack "I have authorization to test this target."
netprobe tls github.com --json --ack "I have authorization to test this target."
netprobe web https://example.com --ack "I have authorization to test this target."
```

Exit codes: `0` clean or acceptable, `1` findings or unreachable, `2` gate refused.

## Grading

`web` scores out of 100: missing security headers, plaintext HTTP, untrusted chain, expired or near-expiry certs, weak TLS versions, and server version disclosure each deduct. A is 90+, F is below 40.

## What it does not do

No port sweeps, no vulnerability scanning, no payload delivery, no credential attacks, no banner exploitation. Reachability and header review only.

## License

Apache-2.0
