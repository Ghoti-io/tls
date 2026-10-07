# Ghoti.io TLS design

**Status:** describes what shipped on 2026-10-06: the client handshake core,
and (the same day, a second step) the record layer over a stream and the
server role. The plan for the rest is `planning/tls.md` in the workspace.

## What it is

The TLS 1.3 handshake of RFC 8446, as a library that is given bytes and returns
bytes. It does not read a socket, write a socket, start a timer, or read the
clock. The caller passes a Unix second to `gtls_conn_feed` for the one thing
that needs it, the certificates' validity.

It has two interfaces over one connection type, and a connection is driven
through one of them (the first call decides; mixing is `GTLS_ERR_INVALID`).

- The **message interface** (`conn.h`) produces and consumes **handshake
  messages, not records**, and exposes the **traffic secrets by epoch**, with
  the negotiated suite and the ALPN result. That is the interface RFC 9001
  section 4 asks of a TLS stack for QUIC.
- The **stream interface** (`record.h`) is the TLS 1.3 record layer over a byte
  stream: the caller hands in what arrived, takes what is to be sent, writes
  and reads application data, and the library frames and protects records,
  carries the handshake inside them, changes keys, updates them, closes with
  `close_notify` and reports a stream that ended without one. It is what TLS
  over TCP (HTTP/2, `wss`) needs.

Both roles use both interfaces: `gtls_conn_new` dials, `gtls_conn_new_server`
accepts.

## Standards implemented

| Document | What | Deviation |
| --- | --- | --- |
| RFC 8446 | TLS 1.3, both roles, server authentication, (EC)DHE key exchange, the record layer (section 5), KeyUpdate (4.6.3), alerts (6) | no PSK, no early data, no client certificate and no CertificateRequest, no NewSessionTicket sent, no post-handshake authentication, no record padding sent (accepted and capped), no cookie in a HelloRetryRequest |
| RFC 6066 | `server_name`; an IP literal is never sent; a server chooses its identity by it and acknowledges it | no other extension of that RFC |
| RFC 7301 | ALPN, offered and read back; a server picks the first of its list that the client offered | no overlap with both lists present is fatal (`no_application_protocol`), as the RFC says |
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
| `src/msg/` | the byte buffer and reader, the ClientHello builder and its retry transform, one parser per message a client receives, a builder per message a server sends, a parser per extension a server reads out of a ClientHello |
| `src/record/` | one direction of record protection: the AEAD key, IV and sequence number, seal and open, the key that follows a key |
| `src/client/` | the context and connection objects, the client's state table, reassembly, chain verification, and the stream interface for both roles (`stream.c`) |
| `src/server/` | the server's state table: reading a ClientHello, choosing, building and signing the flight |
| `src/core/` | results, limits, allocator, self test |

## The state table

```
client:
NEW -> WAIT_SH -> WAIT_EE -> WAIT_CERT -> WAIT_CV -> WAIT_FIN -> CONNECTED
          |                                                          ^
          +--HelloRetryRequest--> WAIT_SH2 --ServerHello--> WAIT_EE  |
                                                       any state --> FAILED
server:
NEW -> S_WAIT_CH -> S_WAIT_FIN -> CONNECTED
           |             ^
           +--HelloRetryRequest--> S_WAIT_CH2 --second ClientHello
```

The server builds its whole flight (ServerHello, EncryptedExtensions,
Certificate, CertificateVerify, Finished) in answer to one ClientHello, so it
has only three waiting states.

Each waiting state accepts exactly one message type; anything else is
`GTLS_ERR_PROTOCOL` with `unexpected_message`, except a `CertificateRequest`
while the client waits for the Certificate, and a `KeyUpdate` at the message
interface once connected (QUIC has its own, RFC 9001 section 6), which are
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

## The server

A server context carries one or more **identities**: a chain (copied), the key
that signs for it (borrowed, and it outlives the context), and the names it
answers to. `gtls_context_new` checks that the key is the leaf's
(`gcert_key_matches`) and that the Certificate message and the rest of the
flight fit the queue a connection holds. What a ClientHello makes it choose:

- **Identity**: the first whose names include the client's `server_name`
  (case-insensitively, a leading `*.` standing for exactly one label), else the
  default (the first, or `default_identity`). The `server_name` is
  acknowledged (an empty extension in EncryptedExtensions) only when a name
  matched.
- **Suite**: the server's order, among the client's.
- **Group**: the server's order among the groups the client sent a share for
  (a share in hand saves a round trip, so it wins over a more preferred group
  without one); else the server's first group the client lists, which is a
  HelloRetryRequest. No cookie is sent: the server is stateful. The second
  ClientHello must be the first with only the key_share, the padding, and an
  early_data or cookie this server never accepts changed (RFC 8446 section
  4.1.2), and carry one share, for the group asked for. A second ClientHello
  that still has no usable share is `unexpected_message`; a share for another
  group is `illegal_parameter`.
- **Signature scheme**: the first of the server's own list that TLS 1.3 allows
  in CertificateVerify, that the client listed, and that the key signs.
- **ALPN**: the first of the server's list that the client offered. Both lists
  present and no overlap is `no_application_protocol`; a client that offered
  none, or a server with none, gets none.

It sends no CertificateRequest and no NewSessionTicket. It refuses, with the
alert that names the cause: a hello with no `supported_versions` or none that
offers 1.3 (`protocol_version`); `pre_shared_key` and `early_data`
(`unsupported_extension`, after the checks RFC 8446 section 4.2.11 makes of a
PSK offer, so a malformed one is called that); a cookie it never issued; a
missing `supported_groups`, `signature_algorithms` or `key_share`
(`missing_extension`); nothing in common (`handshake_failure`).

The server writes application data only once the client's Finished has
verified, and reads and writes under the application keys from the moment its
flight has gone out, as OpenSSL does, so an alert after the flight is sealed
under the key the client has switched to.

## The record layer

One record is a five-byte header (type, a legacy version, length) and a body.
Before keys exist (the first flight) the body is the message; from the first
key on, it is the AEAD sealing of `content || inner type || padding` with the
header as additional data, and the outer type says application data
(RFC 8446 section 5.2).

- **The nonce is not the caller's.** It is the static IV xor the 64-bit
  sequence number, built inside `gtls_record_seal` and `gtls_record_open` from
  a counter only they advance. A counter at its limit refuses the record. A
  failed open does not move the counter, so a forged record cannot desynchronise
  the stream.
- **Size**: content at most 2^14, ciphertext at most 2^14 + 256, refused at the
  header with `record_overflow` before the body is read. A handshake message
  may be split across records, but may not span a key change.
- **Padding** is never sent. It is accepted up to `max_record_padding` and a
  record that is nothing but padding has no content type: `unexpected_message`.
- **Keys follow the handshake.** The read keys are for the epoch the handshake
  is waiting for; the write keys change when the first record of a later epoch
  is made, so a record is always sealed under keys the peer has been told
  about. Before the Finished is sent an alert goes in the clear; a receiver
  under keys accepts such a plaintext alert until its own handshake is done.
- **KeyUpdate** (section 4.6.3) is sent on request and answered when it asks
  to be, once. Its message is sealed under the old key and every record after
  it under the new one; the sequence number starts again. A key that has
  protected `max_records_per_key` records (default 2^24, under the AES-GCM
  limit of section 5.5) is replaced by the sending side by itself, one record
  before the counter would run out; a limit under 2 is `GTLS_ERR_LIMIT`.
  Received updates are counted against `max_key_updates`.
- **Closing.** `close_notify` ends this end's writing and is read as the end of
  the peer's. Everything after it is ignored. Any other alert is fatal
  whatever its level says (`user_canceled` excepted), and is
  `GTLS_ERR_ALERT` with `gtls_conn_peer_alert`. A stream that ends without
  `close_notify` is `GTLS_ERR_TRUNCATED`, which is not `GTLS_ERR_CLOSED`, and
  fails the connection without an alert (there is no one to tell).
- **Compatibility mode** (RFC 8446 appendix D.4): a client that asked for it
  sends the dummy change_cipher_spec before its first protected record, and a
  server sends it after its first message when the client's session id was not
  empty. One is accepted from the peer between its hello and its Finished, at
  most twice, and anywhere else it is `unexpected_message`.
- **A short write is not a protocol event.** Output is a buffer: take any
  amount, consume what the socket took. A write takes only as much as
  `max_output_bytes` leaves room for; the caller drains and writes the rest.
  Decrypted data waits in at most `max_app_buffer` bytes, and when it is full
  `gtls_conn_stream_feed` takes no more until it is read.
- A failed connection discards what it had not yet delivered: `gtls_conn_read`
  returns `GTLS_ERR_FAILED`.

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
| (server) no `supported_versions`, or none naming 1.3 | `GTLS_ERR_UNSUPPORTED` | `protocol_version` |
| (server) PSK or early data | `GTLS_ERR_UNSUPPORTED` | `unsupported_extension` |
| (server) required extension missing | `GTLS_ERR_PROTOCOL` | `missing_extension` |
| (server) no suite, group or signature scheme in common | `GTLS_ERR_NO_COMMON` | `handshake_failure` |
| (server) both ALPN lists and no overlap | `GTLS_ERR_ALPN` | `no_application_protocol` |
| (server) a second ClientHello that changes more than allowed, or asks for a group not offered | `GTLS_ERR_PROTOCOL` | `illegal_parameter` |
| (server) a second ClientHello that still needs a retry | `GTLS_ERR_PROTOCOL` | `unexpected_message` |
| (server) the client's Finished does not verify | `GTLS_ERR_FINISHED` | `decrypt_error` |
| a record that does not authenticate | `GTLS_ERR_MISMATCH` | `bad_record_mac` |
| a record past its size, or padding past the cap | `GTLS_ERR_LIMIT` | `record_overflow` |
| a record of nothing but padding, an unknown content type, application data before the handshake is done | `GTLS_ERR_PROTOCOL` | `unexpected_message` |
| a KeyUpdate that is not 0 or 1 | `GTLS_ERR_PROTOCOL` | `illegal_parameter` |
| more KeyUpdates than `max_key_updates` | `GTLS_ERR_LIMIT` | `unexpected_message` |
| the peer sent a fatal alert | `GTLS_ERR_ALERT` | none |
| the stream ended without close_notify | `GTLS_ERR_TRUNCATED` | none |

The chain is built and validated by `gcert_chain_build`, whose verdict is
`gcert_x509_path`'s; the name by `gcert_x509_verify_host`; the signature by
`gcert_x509_verify_signature` over the 64-space context string and the
transcript hash, which this library builds. This library adds no judgement of
its own and has no mode that skips any of it. The leaf's purpose is asked
first so that a certificate meant for something else is said to be that.

## Secrets

Everything secret a connection holds is in one struct, wiped by one call: on
every failure, on free, and (the private key) the moment ServerHello has been
processed. The record keys and the traffic secrets a key update advances are in
that struct too. A retried key share wipes the first. `gtls_conn_secret` refuses
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

## Known answers and the seams

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

The server is checked against the same traces the other way round, through a
third seam (`gtls_conn_set_server_hooks`, also internal): RFC 8448's
certificate is a 1024-bit RSA key whose private half the RFC does not print,
its CertificateVerify is an RSA-PSS signature with a salt this library cannot
be told to reuse, and its EncryptedExtensions carries extensions a server does
not send. So the test supplies the RFC's chain in place of an identity's, a
signer that **checks the RFC's signature against the content the server built**
(under the RFC's public key) and hands it back, and the RFC's extensions to put
first. Fed the RFC's ClientHello with the RFC's random and ephemeral key
scripted, the server's ServerHello, its flight, every secret, and then as
records (the ServerHello as a plain record, the flight as one protected one,
its application data and its `close_notify` at the sequence numbers the trace
used) are the trace's byte for byte. The client is fed the trace's server
records and produces the trace's ClientHello record, its Finished record, its
data and its alert.

Negative handshakes use a simulated server (`tests/sim.h`) that builds real
chains in memory and signs with Ed25519. It derives its schedule with this
library's own functions, which is safe because the schedule is the part the
RFC vectors check. The loopback tests (`tests/loop.h`) need no simulation: a
real client and a real server, joined by a pump that carries bytes in pieces of
any size, on credentials `certificate` really validates (`tests/data/pki`).
The independence of a check from the code it checks is kept where it matters:
the nonce and the next traffic secret are re-derived in the tests from
`security`'s AEAD and HKDF directly.

## Controls

Every gate is seen to fail against a planted defect before it is believed.
`tools/controls.sh` plants each one, one at a time, in a scratch copy of the
tree and requires the named test to fail: the `Finished` check, the
CertificateVerify check, the downgrade check, the host check, the purpose
check, the label of a traffic secret, the HelloRetryRequest restart of the
transcript, the message-size cap, the wipe on failure, the epoch rule, and, for
the record layer and the server, the nonce (and its byte order), the label of the next
traffic secret, padding (stripped, and capped), the sequence limit, the
authentication of a record, the size cap, truncation, the dummy-record limit,
the answer to a KeyUpdate, the automatic update, the alert on a bad record, the
ALPN overlap, the SNI match, the client's Finished, a second retry, early data,
the version check, and the key-fits-scheme choice.

The second gate is **interop** (`make check-interop`, `tools/oracle/`): OpenSSL
`s_server` and `s_client` in a podman container, not linked, against
`examples/echo.c` in both roles, over loopback sockets. See below.

## Interop

`tools/oracle/interop.py` runs OpenSSL in the pinned container image of the
`certificate` oracle, with host networking on the loopback, against
`examples/echo.c`. In both roles, a population of one handshake per suite,
group, signature scheme, ALPN case, HelloRetryRequest, key update and
`close_notify`, each over a real chain from `tests/data/pki`. A handshake the
peer refuses is counted in the denominator, with the reason, and declared
differences are written down in `tools/oracle/DIFFERENCES`. A planted defect
(`tools/oracle/plant.sh`) must make the same run fail.

## Constant time

What this library compares of a secret is the `Finished` (`gsec_equal`, in
`gtls_finished_check`, for both roles: a server checks the client's with the
same function) and the AEAD tag, which `security` compares itself. The review:
`tools/check-secret.py` forbids `memcmp` and kin under `src/`; the padding scan
in `gtls_record_open` runs only on a record that has already authenticated, so
what it learns an attacker chose nothing of; the ALPN and SNI comparisons are of
public names and may branch; the key schedule and the `Finished` run under the
`check-ct` gate as before, the server's check being the same code.

## Not here

Client authentication and `CertificateRequest` (the server never sends one);
TLS 1.2; resumption and tickets (a client parses and discards a
NewSessionTicket; a server sends none); early data; DTLS; revocation in the
handshake; the `http` adapter. `GTLS_ContextConfig` already has room for TLS
1.2, a PSK and a client certificate.
