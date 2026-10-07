# Ghoti.io TLS design

**Status:** describes what shipped on 2026-10-06 (the client handshake core).
The plan for the rest is `planning/tls.md` in the workspace.

## What it is

The TLS 1.3 handshake of RFC 8446, as a library that is given bytes and returns
bytes. It does not read a socket, write a socket, start a timer, or read the
clock. The caller passes a Unix second to `gtls_conn_feed` for the one thing
that needs it, the certificates' validity.

It produces and consumes **handshake messages, not records**, and exposes the
**traffic secrets by epoch**, with the negotiated suite and the ALPN result.
That is the interface RFC 9001 section 4 asks of a TLS stack for QUIC, and it
is what a record layer, or DTLS, will wrap.

## Standards implemented

| Document | What | Deviation |
| --- | --- | --- |
| RFC 8446 | TLS 1.3, client role, server authentication, (EC)DHE key exchange | no PSK, no early data, no client certificate, no post-handshake authentication, no key update (record layer) |
| RFC 6066 | `server_name`; an IP literal is never sent | no other extension of that RFC |
| RFC 7301 | ALPN, offered and read back | the server's choice must be one that was offered |
| RFC 7685 | padding a ClientHello of 256 to 511 bytes to 512 | |
| RFC 8448 | the known answers | the traces' certificate is refused by the real chain check; see below |

Algorithms are what `security` has: AES-128-GCM, AES-256-GCM,
ChaCha20-Poly1305 (the core needs only each suite's hash and key length);
X25519, P-256, P-384; for CertificateVerify RSA-PSS (rsae), ECDSA P-256 and
P-384, and Ed25519; SHA-256, SHA-384 and HKDF. No FFDHE, no CCM, no
compression, no renegotiation, no SHA-1, and no RSA PKCS#1 in
CertificateVerify (TLS 1.3 forbids it; PKCS#1 stays in the offered
signature_algorithms because certificate chains still use it).

## Layout

| Directory | Holds |
| --- | --- |
| `src/schedule/` | HKDF-Expand-Label, Derive-Secret, the chain of secrets, the transcript hash, `Finished` |
| `src/msg/` | the byte buffer and reader, the ClientHello builder and its retry transform, one parser per received message |
| `src/client/` | the context and connection objects, the state table, reassembly, chain verification |
| `src/core/` | results, limits, allocator, self test |

## The state table

```
NEW -> WAIT_SH -> WAIT_EE -> WAIT_CERT -> WAIT_CV -> WAIT_FIN -> CONNECTED
          |                                                          ^
          +--HelloRetryRequest--> WAIT_SH2 --ServerHello--> WAIT_EE  |
                                                       any state --> FAILED
```

Each waiting state accepts exactly one message type; anything else is
`GTLS_ERR_PROTOCOL` with `unexpected_message`, except a `CertificateRequest`
while waiting for the Certificate, and a `KeyUpdate` once connected, which are
`GTLS_ERR_UNSUPPORTED`. FAILED is terminal. The fuzzers' denominator is this
table: `test_fuzzseeds` fails if the seed corpus does not reach every state,
and `test_state` offers every message type and every epoch in every state.

## Epochs

`feed` and `pending_output` are tagged with the epoch the bytes belong to.
ServerHello and HelloRetryRequest arrive at `INITIAL`; EncryptedExtensions to
Finished at `HANDSHAKE`; post-handshake messages at `APPLICATION`. A message
may arrive in any number of pieces but **may not span a change of epoch**, and
nothing may follow ServerHello or a HelloRetryRequest within its epoch: both
are protocol errors (RFC 8446 section 5.1, RFC 9001 section 4.1.4). The client
sends ClientHello at `INITIAL` and its `Finished` at `HANDSHAKE`.

## What is checked, and the result for each

| Cause | Result | Alert |
| --- | --- | --- |
| Downgrade sentinel in ServerHello.random (checked first) | `GTLS_ERR_DOWNGRADE` | `illegal_parameter` |
| No `supported_versions`, i.e. an older server | `GTLS_ERR_UNSUPPORTED` | `protocol_version` |
| Wrong legacy version, compression, session id echo, suite not offered, key share not in the group sent, bad point, wrong point format | `GTLS_ERR_PROTOCOL` | `illegal_parameter` |
| Extension not offered, in any message | `GTLS_ERR_PROTOCOL` | `unsupported_extension` |
| Message out of order or at the wrong epoch | `GTLS_ERR_PROTOCOL` | `unexpected_message` |
| Truncated, trailing bytes, bad length | `GTLS_ERR_CORRUPT` | `decode_error` |
| Any cap in `GTLS_Limits` on what the peer sent | `GTLS_ERR_LIMIT` | `decode_error` |
| `max_output_bytes`, a cap on what this side queues | `GTLS_ERR_LIMIT` | `internal_error` |
| An empty Certificate list (RFC 8446 section 4.4.2) | `GTLS_ERR_CERT_INVALID` | `decode_error` |
| leaf's extendedKeyUsage excludes serverAuth | `GTLS_ERR_CERT_PURPOSE` | `bad_certificate` |
| no path to an anchor | `GTLS_ERR_CERT_ISSUER` | `unknown_ca` |
| only fitting path expired / not yet valid | `GTLS_ERR_CERT_EXPIRED` / `_NOT_YET_VALID` | `certificate_expired` |
| a path exists and policy or a signature refused it | `GTLS_ERR_CERT_INVALID` | `bad_certificate` |
| certificate does not name the host | `GTLS_ERR_CERT_HOST` | `bad_certificate` |
| CertificateVerify does not verify (wrong transcript, wrong key) | `GTLS_ERR_SIGNATURE` | `decrypt_error` |
| Finished does not verify | `GTLS_ERR_FINISHED` | `decrypt_error` |

The chain is built and validated by `gcert_chain_build`, whose verdict is
`gcert_x509_path`'s; the name by `gcert_x509_verify_host`; the signature by
`gcert_x509_verify_signature` over the 64-space context string and the
transcript hash, which this library builds. This library adds no judgement of
its own and has no mode that skips any of it. The leaf's purpose is asked
first so that a certificate meant for something else is said to be that.

## Secrets

Everything secret a connection holds is in one struct, wiped by one call: on
every failure, on free, and (the private key) the moment ServerHello has been
processed. A retried key share wipes the first. `gtls_conn_secret` refuses
after failure. The comparison of `Finished` is `gsec_equal`; `check-ct` runs
the code from the key to that call under Valgrind with the key marked
undefined and requires it silent, and requires a planted branch to be reported.
`tools/check-secret.py` rejects `memcmp` and `printf` anywhere under `src/`.

Ephemeral private keys are drawn by rejection sampling (zero and values at or
above the curve order are refused, compared without a branch on the value).
The first ClientHello carries one share, for the first group in the context's
list (X25519 by default); a server that wants another answers with a
HelloRetryRequest, whose second ClientHello is the first with the key_share
replaced, the cookie echoed before psk_key_exchange_modes (or last), and the
padding recomputed.

## Known answers and the two seams

RFC 8448 is downloaded once by `tools/fetch.sh`, checked against its SHA-256
pin, committed under `tests/data/rfc8448/`, and parsed by
`tools/extract-rfc8448.py` into `simple-1rtt.vec` and `hrr.vec`. **No value in
those files was typed.** `make check-foundation` re-runs the extractor offline
and fails if a committed vector differs, or if the pin in either script is not
the text's digest. The self test's two constants and the fuzz seeds are
generated from the same vectors.

The tests drive the connection with the RFC's ClientHello and ephemeral keys,
through two seams declared only in `src/client/client_internal.h` and so
neither exported nor reachable by a caller:

1. `gtls_conn_start_raw` hands over a ClientHello this library did not build,
   because the trace's is not the one it builds (the trace offers extensions
   this library does not), and the transcript hash depends on every byte.
2. `gtls_conn_set_hooks` lets a test supply the random source and the verdict
   on the chain. The trace's certificate is a 1024-bit RSA key in a
   certificate whose basicConstraints says it is not a CA; `certificate`
   refuses both, correctly, and `test_rfc8448` shows that the default does
   refuse this certificate (`Rfc8448Chain.TheRealCheckRefusesTheRfcsCertificate`).
   Everything else in the handshake, including verifying the trace's
   CertificateVerify with its 1024-bit key, is the shipped code.

Negative handshakes use a simulated server (`tests/sim.h`) that builds real
chains in memory and signs with Ed25519. It derives its schedule with this
library's own functions, which is safe because the schedule is the part the
RFC vectors check.

## Controls

Every gate is seen to fail against a planted defect before it is believed.
`tools/controls.sh` plants each one, one at a time, in a scratch copy of the
tree and requires the named test to fail: the `Finished` check, the
CertificateVerify check, the downgrade check, the host check, the purpose
check, the label of a traffic secret, the HelloRetryRequest restart of the
transcript, the message-size cap, the wipe on failure, and the epoch rule.

## Not here

The record layer, key update, `close_notify`; the server role; client
authentication and `CertificateRequest`; TLS 1.2; resumption and tickets (a
NewSessionTicket is parsed and discarded); early data; DTLS; revocation in the
handshake; the `http` adapter. `GTLS_ContextConfig` and the message codec
already have room for the server role, TLS 1.2, a PSK and a client certificate,
and `GTLS_Role` and the direction-tagged secrets are written from the local
point of view so that the server is the same calls.
