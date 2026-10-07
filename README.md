# Ghoti.io TLS

TLS 1.3 as a state machine over buffers, for both roles. **It does no I/O and
never touches a clock**: the caller owns the socket, the timers and the
fibers, hands in the bytes that arrived, takes the bytes to send, and passes
in a Unix second when a certificate has to be checked. It has two interfaces
over one connection type: **the record layer over a byte stream** (what TLS
over TCP needs: HTTP/2, `wss`), and **handshake messages by epoch with the
traffic secrets** (what QUIC needs). It is built on `certificate` (chains,
names, signatures) and `security` (the primitives). Client authentication,
TLS 1.2, resumption and early data are later pieces; see [Status](#status).
A server that is offered a PSK or early data (a client that remembers a
ticket from elsewhere) ignores the offer, skips the early records, and does the
full handshake.

## Example

[`examples/echo.c`](examples/echo.c) is an echo server and its client over TCP
on the loopback, the whole shape of a caller that owns a socket (it is also the
peer the OpenSSL interop gate talks to). The core of the client:

```c
#include <ghoti.io/tls/tls.h>

GCERT_TrustStore * trust;
gcert_trust_new(NULL, NULL, &trust);
gcert_trust_add_system(trust, NULL, NULL);        /* the operating system's roots */

GTLS_ContextConfig config;
gtls_context_config_default(&config);
config.trust = trust;
config.alpn = (const char * const[]){"h2", "http/1.1"};
config.alpn_count = 2;
GTLS_Context * context;
gtls_context_new(NULL, &config, &context);

GTLS_Conn * conn;
gtls_conn_new(context, "example.com", 11, &conn); /* SNI, and the name the certificate must carry */
gtls_conn_start(conn);                            /* queues the ClientHello */

for (;;) {
  const unsigned char * out; size_t n;
  gtls_conn_stream_output(conn, &out, &n);        /* records to send: handshake, replies, data, alerts */
  size_t sent = send(fd, out, n, 0);              /* any amount is fine */
  gtls_conn_stream_consume(conn, sent);
  if (gtls_conn_is_failed(conn)) break;           /* gtls_conn_failure, gtls_conn_alert, gtls_conn_peer_alert */

  n = recv(fd, buf, sizeof buf, 0);
  if (n == 0) { gtls_conn_stream_eof(conn); break; }   /* GTLS_ERR_TRUNCATED unless close_notify came first */
  size_t used;
  gtls_conn_stream_feed(conn, buf, n, unix_time, &used);   /* may take less: read, then offer the rest */
  size_t got;
  while (gtls_conn_read(conn, plain, sizeof plain, &got) == GTLS_OK && got) { /* decrypted data */ }

  if (gtls_conn_is_connected(conn)) gtls_conn_write(conn, "hello", 5, &got);
}
```

A server is the same loop with a context made from identities and
`gtls_conn_new_server`:

```c
GTLS_Identity identity = {chain, chain_lens, chain_count, key, names, name_count};
config.role = GTLS_ROLE_SERVER;
config.identities = &identity;       /* more than one: chosen by the client's server_name */
config.identity_count = 1;
config.alpn = ..., config.alpn_count = ...;   /* the first the client offered is selected */
gtls_context_new(NULL, &config, &context);
gtls_conn_new_server(context, &conn);
gtls_conn_start(conn);
```

[`examples/handshake.c`](examples/handshake.c) shows the message interface
without a network.

## Building

```bash
export PKG_CONFIG_PATH="$PWD/../../.local/share/pkgconfig"   # cutil, security and certificate installed
make test PREFIX="$PWD/../../.local"
```

`pkg-config` is the only way this library finds `cutil`, `security` and
`certificate`; there is no sibling-checkout fallback. `make help` lists the
targets. `tools/fetch.sh` re-downloads RFC 8448 and checks it against its pin;
`make test` does not need the network, because the text is committed.

`make check-interop PREFIX=...` runs OpenSSL's `s_server` and `s_client` in a
container (podman, or `$GHOTI_CONTAINER_ENGINE`) against `examples/echo.c` in
both roles; it needs the image `libs/certificate` builds with `make
oracle-build`, and fails rather than skipping when it cannot reach it.
`make interop-plants` plants a defect at a time and requires the same cases to
fail. `make test` runs no container. `make fuzz` runs the six fuzzers
(`clang` with libFuzzer).

## The API in prose

- **`GTLS_Context`**, from a **`GTLS_ContextConfig`** (`gtls_context_config_default`,
  `gtls_context_new`): the role, the trust store (a client's), identities (a
  server's: a chain, the key that signs, and the names it answers to), ALPN
  names, suites, groups, signature schemes and `GTLS_Limits`. Immutable once
  made, shared by any number of connections, and **it outlives them**, as do
  the trust store, the allocator and the private keys it was given. The chains
  are copied. TLS 1.2, a pre-shared key and a client certificate are refused
  with `GTLS_ERR_UNSUPPORTED` rather than ignored.
- **`GTLS_Conn`** (`gtls_conn_new`, `gtls_conn_new_server`, `_start`, `_free`):
  one connection, driven through one interface.
- **The stream interface** (`record.h`): `gtls_conn_stream_feed`,
  `gtls_conn_stream_output` and `_consume`, `gtls_conn_write` and
  `gtls_conn_read`, `gtls_conn_close`, `gtls_conn_key_update`,
  `gtls_conn_stream_eof`. Records of any size arrive in any number of pieces,
  down to one byte; output is drained in any amount, so a short socket write is
  never a protocol event. The nonce is built inside, from a sequence number
  that is never reused; a key that has protected `max_records_per_key` records
  is replaced before the counter runs out. `GTLS_ERR_CLOSED` ends a clean
  stream; `GTLS_ERR_TRUNCATED` is one that ended without `close_notify`.
- **The message interface** (`conn.h`): `gtls_conn_feed`,
  `gtls_conn_pending_output`, `gtls_conn_consume_output`. Handshake bytes in
  and out, tagged with the epoch (`GTLS_EPOCH_INITIAL`, `_HANDSHAKE`,
  `_APPLICATION`), and **`gtls_conn_secret(epoch, direction)`**: the handshake
  secrets once ServerHello is settled and the application secrets once the
  server's Finished has gone out or verified, the direction being the local one.
  `gtls_traffic_keys`, `gtls_hkdf_expand_label` and `gtls_derive_secret` are
  exported for QUIC's own labels (RFC 9001 section 5).
- **What was negotiated**: `gtls_conn_suite`, `_group`, `_alpn`,
  `_server_name_acknowledged`, `_retried`; a server's `gtls_conn_server_name`
  (what the client sent) and `gtls_conn_identity` (which was chosen); a
  client's `gtls_conn_peer_certificate`.
- **Results** are `GTLS_Result`: the suite's nine, and one per reason a
  handshake or a stream is refused (`GTLS_ERR_FINISHED`, `_SIGNATURE`,
  `_DOWNGRADE`, `_CERT_HOST`, `_CERT_EXPIRED`, `_CERT_NOT_YET_VALID`,
  `_CERT_ISSUER`, `_CERT_PURPOSE`, `_CERT_INVALID`, `_PROTOCOL`, `_NO_COMMON`,
  `_ALPN`, `_ALERT`, `_TRUNCATED`, `_CLOSED`, ...). `gtls_conn_alert` is the
  alert this end sent (in stream mode it is already in the output) or would
  send, `gtls_conn_failure` the reason, and `gtls_conn_peer_alert` the peer's.
  A failed connection has wiped every secret.
- **Limits**: every quantity a peer controls is capped by `GTLS_Limits`
  (message size, whole-handshake size, ClientHello size, certificates,
  extensions, signature, ticket and cookie sizes, tickets, padding in a record,
  unread data, key updates, queued output). A cap reached is
  `GTLS_ERR_LIMIT`, never a truncation.

What it checks is in [`documentation/design.md`](documentation/design.md), with
the version and deviations it implements: RFC 8446 (TLS 1.3), RFC 6066 (SNI),
RFC 7301 (ALPN), RFC 7685 (padding), and RFC 8448 for the known answers.

## Status

**Built (2026-10-06):** the TLS 1.3 handshake in both roles: key schedule and
transcript (including HelloRetryRequest), the ClientHello and every message a
client receives, the server's ClientHello reading, choices (identity by SNI,
suite, group, scheme, ALPN) and flight, the state tables, chain and name
verification through `certificate`, secrets by epoch, and the record layer
over a stream with `KeyUpdate`, `close_notify` and a truncation check. Checked
against RFC 8448 byte for byte in both roles and as records (the simple 1-RTT
and HelloRetryRequest traces), against OpenSSL in both roles (`make
check-interop`), against real chains in negative handshakes, with an
allocation-failure sweep over both roles and the stream, a wipe check, a
constant-time gate for `Finished`, six fuzzers (messages, client, server,
records, record streams, and two endpoints with mutated bytes), and the
sanitizer matrix.

**Not built, in the order the plan takes them** (`planning/tls.md`): the `http`
adapter; mutual authentication and revocation in the handshake; TLS 1.2;
session tickets and resumption, then early data; QUIC hardening and DTLS.
Nothing here has run on macOS, and Windows only under wine
(`tools/xwin/tls.sh`; `TODO(windows)` in the Makefile). A server never asks for
a client certificate, and a client that is asked (`CertificateRequest`) is
refused with `GTLS_ERR_UNSUPPORTED`.

Patches are not being accepted at this time; see CONTRIBUTING.md.
