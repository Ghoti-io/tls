# Ghoti.io TLS

The TLS 1.3 handshake as a state machine over buffers. Handshake messages go
in, handshake messages come out, and the traffic secrets are handed out by
epoch. **It does no I/O and never touches a clock**: the caller owns the
socket, the timers and the record layer (or QUIC's CRYPTO frames), and passes
in a Unix second when a certificate has to be checked. Today it is the client
role, server authentication only, over `certificate` (chains, names,
signatures) and `security` (the primitives). Records, the server role, client
authentication, TLS 1.2, resumption and early data are later pieces; see
[Status](#status).

## Example

[`examples/handshake.c`](examples/handshake.c) is the whole shape of a caller
and runs without a network:

```c
#include <ghoti.io/tls/tls.h>

GCERT_TrustStore * trust;
gcert_trust_new(NULL, NULL, &trust);
gcert_trust_add_system(trust, NULL, NULL);        /* the operating system's roots */

GTLS_ContextConfig config;
gtls_context_config_default(&config);
config.trust = trust;
GTLS_Context * context;
gtls_context_new(NULL, &config, &context);

GTLS_Conn * conn;
gtls_conn_new(context, "example.com", 11, &conn); /* SNI, and the name the certificate must carry */
gtls_conn_start(conn);                            /* queues the ClientHello */

/* The caller's loop, over its own socket or QUIC stream: */
const unsigned char * out; size_t n;
gtls_conn_pending_output(conn, GTLS_EPOCH_INITIAL, &out, &n);
/* ... send out[0..n) as handshake bytes, then: */
gtls_conn_consume_output(conn, GTLS_EPOCH_INITIAL, n);
/* ... and for what arrives: */
GTLS_Result r = gtls_conn_feed(conn, epoch, bytes, len, unix_time);
if (r != GTLS_OK) { /* the specific reason; send gtls_conn_alert(conn) */ }
if (gtls_conn_is_connected(conn)) {
  unsigned char secret[GTLS_HASH_MAX]; size_t len;
  gtls_conn_secret(conn, GTLS_EPOCH_APPLICATION, GTLS_DIR_WRITE, secret, sizeof secret, &len);
}
```

## Building

```bash
export PKG_CONFIG_PATH="$PWD/../../.local/share/pkgconfig"   # cutil, security and certificate installed
make test PREFIX="$PWD/../../.local"
```

`pkg-config` is the only way this library finds `cutil`, `security` and
`certificate`; there is no sibling-checkout fallback. `make help` lists the
targets. `tools/fetch.sh` re-downloads RFC 8448 and checks it against its pin;
`make test` does not need the network, because the text is committed.

## The API in prose

- **`GTLS_Context`**, from a **`GTLS_ContextConfig`** (`gtls_context_config_default`,
  `gtls_context_new`): the trust store, ALPN names, suites, groups, signature
  schemes and `GTLS_Limits`. Immutable once made, shared by any number of
  connections, and **it outlives them**, as do the trust store and allocator
  it was given. The config already has the fields later pieces need (the server
  role, TLS 1.2, a pre-shared key, a client certificate and key); they are
  refused with `GTLS_ERR_UNSUPPORTED` today rather than ignored.
- **`GTLS_Conn`** (`gtls_conn_new`, `_start`, `_feed`, `_pending_output`,
  `_consume_output`): one handshake. `feed` takes the bytes of any number of
  handshake messages in any number of pieces, down to one byte, tagged with
  the epoch they arrived at (`GTLS_EPOCH_INITIAL`, `_HANDSHAKE`,
  `_APPLICATION`). Output is queued per epoch. A short socket write is never a
  protocol event: consume what was written and ask again.
- **Secrets**: `gtls_conn_secret(epoch, direction)` returns the handshake
  traffic secrets once ServerHello is accepted and the application secrets
  once the server's `Finished` has verified; before that, or after a failure,
  it refuses. The direction is the local one (`GTLS_DIR_WRITE` protects what
  this end sends), so a server will use the same call. `gtls_traffic_keys`,
  `gtls_hkdf_expand_label` and `gtls_derive_secret` are exported for a record
  layer or for QUIC's own labels (RFC 9001 section 5).
- **Results** are `GTLS_Result`: the suite's nine, and one per reason a
  handshake is refused (`GTLS_ERR_FINISHED`, `_SIGNATURE`, `_DOWNGRADE`,
  `_CERT_HOST`, `_CERT_EXPIRED`, `_CERT_NOT_YET_VALID`, `_CERT_ISSUER`,
  `_CERT_PURPOSE`, `_CERT_INVALID`, `_PROTOCOL`, ...). `gtls_conn_alert` is the
  alert to send, and `gtls_conn_failure` the reason, for as long as the
  connection exists.
- **Limits**: every quantity a peer controls is capped by `GTLS_Limits`
  (message size, whole-handshake size, certificates, extensions, signature,
  ticket and cookie sizes, tickets, queued output). A cap reached is
  `GTLS_ERR_LIMIT`, never a truncation.

What it checks is in [`documentation/design.md`](documentation/design.md), with
the version and deviations it implements: RFC 8446 (TLS 1.3), RFC 6066 (SNI),
RFC 7301 (ALPN), RFC 7685 (padding), and RFC 8448 for the known answers.

## Status

**Built (2026-10-06):** the TLS 1.3 client handshake core. Key schedule and
transcript (including HelloRetryRequest), ClientHello and every message a
client receives, the state table, chain and name verification through
`certificate`, secrets by epoch, ALPN and SNI results, post-handshake
NewSessionTicket parsed and discarded. Checked against RFC 8448 byte for byte
(the simple 1-RTT and HelloRetryRequest traces), against real chains in
negative handshakes, with an allocation-failure sweep, a wipe check, a
constant-time gate for `Finished`, two fuzzers, and the sanitizer matrix.

**Not built, in the order the plan takes them** (`planning/tls.md`): the record
layer over a stream and the server role; mutual authentication and revocation
in the handshake; TLS 1.2; session tickets and resumption, then early data;
QUIC hardening and DTLS. There is no interop test against another stack yet,
and nothing here has run on Windows or macOS (`TODO(windows)` in the
Makefile). A client that is asked for a certificate (`CertificateRequest`) is
refused with `GTLS_ERR_UNSUPPORTED`.

Patches are not being accepted at this time; see CONTRIBUTING.md.
