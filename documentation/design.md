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
| RFC 8446 | TLS 1.3, both roles, server authentication, (EC)DHE key exchange, the record layer (section 5), KeyUpdate (4.6.3), alerts (6) | resumption with `psk_dhe_ke` from a ticket this server sealed (stateless, no server-side cache), no `psk_ke` alone, no external PSK; early data (0-RTT, section 2.3 and 4.2.10) in both roles, off unless the context sets an allowance and, for a server, the replay decision, and an offer a server does not accept is skipped; no client certificate and no CertificateRequest, no post-handshake authentication, no record padding sent (accepted and capped), no cookie in a HelloRetryRequest |
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
           |         ^     ^
           |         |     +---EndOfEarlyData---- S_WAIT_EOED (early data accepted)
           +--HelloRetryRequest--> S_WAIT_CH2 --second ClientHello
```

The server builds its whole flight (ServerHello, EncryptedExtensions,
Certificate, CertificateVerify, Finished) in answer to one ClientHello, so it
has only three waiting states, and a fourth when it has accepted early data:
after its flight it waits in `S_WAIT_EOED`, at the early epoch, for the early
records and `EndOfEarlyData`, and only then for the client's Finished.

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

- **Identity and signature scheme**: an identity whose names include the
  client's `server_name` (case-insensitively, a leading `*.` standing for
  exactly one label). An exact name is preferred to a wildcard, and among equal
  matches the first listed. A match that cannot sign with any scheme the client
  listed is passed over for the next one that can; if none can, the default
  (the first identity, or `default_identity`) is tried, and if it cannot
  either, `GTLS_ERR_NO_COMMON`. The `server_name` is acknowledged (an empty
  extension in EncryptedExtensions) only when the identity used was one whose
  names matched.
- **Suite**: the server's order, among the client's.
- **Group**: the server's order among the groups the client sent a share for
  (a share in hand saves a round trip, so it wins over a more preferred group
  without one); else the server's first group the client lists, which is a
  HelloRetryRequest. No cookie is sent: the server is stateful. The second
  ClientHello must be the first with only the key_share, the padding, an
  early_data dropped and a pre_shared_key refreshed changed (RFC 8446 section
  4.1.2), and carry one share, for the group asked for. A second ClientHello
  that still has no usable share is `unexpected_message`; a share for another
  group is `illegal_parameter`.
- **Signature scheme**: the first of the server's own list that TLS 1.3 allows
  in CertificateVerify, that the client listed, and that the key signs.
- **ALPN**: the first of the server's list that the client offered. Both lists
  present and no overlap is `no_application_protocol`; a client that offered
  none, or a server with none, gets none.

It sends no CertificateRequest. It refuses, with the
alert that names the cause: a hello with no `supported_versions` or none that
offers 1.3 (`protocol_version`); a cookie it never issued; a
missing `supported_groups`, `signature_algorithms` or `key_share`
(`missing_extension`); nothing in common (`handshake_failure`).

**A `pre_shared_key` offer is judged, and `early_data` is accepted only on
the conditions of [Early data](#early-data)** (RFC 8446 sections 4.2.9 to 4.2.11). A `pre_shared_key` must be the last extension
(`illegal_parameter`), `psk_key_exchange_modes` must be there
(`missing_extension`), the identities and the binders must parse, be as many
as each other (`illegal_parameter`), and fit `GTLS_Limits::max_tickets` and
`max_ticket_bytes` (`GTLS_ERR_LIMIT`, `decode_error`). What follows is
[Tickets](#tickets-and-resumption). `early_data` must have an empty body
(`decode_error`) and is rejected, unless every condition of that section holds,
by not echoing it in EncryptedExtensions. The client then sends records protected by
a key this server never had, and section 4.2.10 has the server skip them, so
the skip window opens only when `early_data` comes with a `pre_shared_key`
(early data is encrypted under a key derived from a PSK; without one the
extension is checked and ignored, and a bad record stays a fatal
`bad_record_mac`). While the window is open an `application_data` record that
does not open is discarded, its plaintext counted: a record costs its body less
the 17 bytes of inner type and tag (one, at least), which is what the allowances
count, against the larger of `GTLS_Limits::max_early_skip_bytes` (default one
maximal record) and the context's own `max_early_data`, so a client that stays within
what the server would have allowed is not failed for having been refused (past
the budget is `GTLS_ERR_LIMIT` and `unexpected_message`), and the first record that opens
ends it. A record that does authenticate but is malformed (padding past the
cap, no content type) is not early data and is fatal as ever, and nothing is
skipped while a handshake message is in pieces (`unexpected_message`). The
window also covers the records that arrive between a HelloRetryRequest and
the second ClientHello, where no key exists to try; the second ClientHello
ends it, and may not carry `early_data` itself. Skipped bytes never reach the
application and the sequence number does not move for them.

**A damaged client Finished is not told from early data while the window is
open** (RFC 8446 section 4.2.10): a Finished record that fails to open looks
exactly like an early record, so it is discarded and the handshake stalls
instead of failing at once. It stays discarded until the cap is reached
(`GTLS_ERR_LIMIT`) or a record that opens arrives. The cap is what bounds it.
A server that accepted early data has no such window: a record that does not
open is a `bad_record_mac`.

The server writes application data only once the client's Finished has
verified, and reads and writes under the application keys from the moment its
flight has gone out, as OpenSSL does, so an alert after the flight is sealed
under the key the client has switched to.

## Tickets and resumption

`session.h` is the interface; RFC 8446 sections 2.2, 4.2.11 and 4.6.1 are the
rules. The design is stateless: **no server keeps anything per session.**

**The ticket.** The server seals the state a resumption needs under a key the
caller supplies: the PSK, the suite, `ticket_age_add`, the second it was
issued, its lifetime, the ALPN protocol and the server name of the connection
it came from, and nothing else. A ticket is the 16-byte name of the key, a
random 12-byte nonce, the AES-256-GCM ciphertext and its tag, with a label,
the name and the nonce as additional data. The library generates, stores and
persists no key. `GTLS_ContextConfig::ticket_keys` is a list of up to eight
`GTLS_TicketKey` (name, 32 bytes, a window of Unix seconds): the key that
began last among those valid at the moment seals; every key that has not
expired opens. That is rotation: add a key that begins now, and leave the old one
in the list until the tickets it sealed have run out. Names must differ.
**Rotate well before a key wears out.** The AEAD nonce is drawn at random
(96 bits), so a repeat under one key becomes likely as the square of the
tickets sealed, and NIST SP 800-38D caps random-nonce GCM at 2^32 invocations
per key. The recommended maximum is 2^28 tickets per key (a margin of 16
inside the cap; a repeat has then a chance near 2^-41), and in practice a new
key daily. A server that sends `ticket_count` tickets on every connection, resumed
or not, reaches the figure that many times sooner. How the keys reach the several processes that serve
one name, and where they are kept, is the caller's.
`GTLS_Limits::max_ticket_bytes` must be at least the largest ticket (a
context with keys and a smaller cap is `GTLS_ERR_LIMIT`).

**Issuing.** After the client's Finished has verified, the server sends
`ticket_count` NewSessionTicket messages (default 1; 0 sends none; at most
`max_tickets`, and never above 255, `GTLS_TICKET_COUNT_MAX`: the nonce that
tells the tickets apart is one byte, and a 256th would repeat the first's PSK;
more is `GTLS_ERR_LIMIT` when the context is made) under the application keys, on every connection, resumed or
not. Each carries its own nonce, so each stands for a PSK of its own:
`HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, Hash.length)`,
where the resumption master secret is derived from the transcript through
the client's Finished. The lifetime is `ticket_lifetime` (default six hours,
never above seven days). A server with no key valid now sends none.

**Accepting.** For each identity of the offer, in order, the ticket is opened
and passed over, without an error, if it is not ours or does not decrypt, its key
has expired, its suite is not one the client offered and the server has, its
lifetime has run out, its age is outside the window, its server name is not the
one the ClientHello carries now, or the ALPN protocol it came from is not among
those offered again. An identity longer than `max_ticket_bytes` is not one this
server sealed, so it is passed over like the rest; only the number of identities
(more than `max_tickets`) is an error. `psk_ke` alone (no `psk_dhe_ke` in the modes) is passed
over too. The first identity that qualifies has its binder checked in constant
time, over the transcript so far (empty, or the retry's) and the
ClientHello cut where the binders list begins; **a binder that is wrong, or the
wrong length for the PSK, is fatal** (`GTLS_ERR_MISMATCH`, `decrypt_error`) and
the connection is wiped. A good one gives the abbreviated flight: ServerHello
with `pre_shared_key` naming the identity, EncryptedExtensions, Finished, and
no Certificate, no CertificateVerify, so no signature scheme need be in
common. The suite is the ticket's, not the server's preference (the hash of the
PSK is the hash of the handshake). The ECDHE exchange still happens.
The age check is in milliseconds, in 64-bit arithmetic on values that are
already bounded: the client's age is the obfuscated one minus `age_add`
modulo 2^32, the server's is its own clock minus the issue time, and they must
agree within `ticket_age_window` (default 10 s). The clocks are seconds the
caller passes in; nothing here reads one.

**A HelloRetryRequest.** The first ClientHello's binder is not looked at when
the answer is a retry (the binder that counts is the one in the second hello,
over the transcript with the retry in it). The retry's suite is the one the
ServerHello must name: if the ticket is for another suite by the time the
second hello arrives (it was not good for the first, say), the ticket is passed
over and the handshake is a full one under the retry's suite.

**The client.** After the handshake a connection holds a `GTLS_Session` for
each ticket it was sent (`gtls_conn_session_count`, `gtls_conn_session`): the
ticket, the PSK it stands for, the suite, `age_add`, the lifetime (cut to seven
days), the second it arrived, the host name and the ALPN protocol. The
library keeps nothing across connections: the caller keeps the session
(`gtls_session_serialize` writes a versioned blob with a SHA-256 digest to catch
damage; it holds the PSK in the clear, so it is a secret as a key is) and hands it to
a new connection with `gtls_conn_set_session` before start, with the time. A
session is refused for another host name, for a suite the connection does not
offer, before it arrived and after it has run out. **A session is bound to a
host and a suite and to nothing else, not to the trust store or the
verification hook that authenticated the connection it came from**: a resumed
connection sends no certificate and runs no chain check, so a session carried
into a context with a different (or looser) trust configuration resumes on the
authority of the first. The caller must not share sessions, or their blobs,
across trust configurations. A NewSessionTicket longer than `max_ticket_bytes`
is counted against `max_tickets` and not kept; it does not fail the connection
the server has authenticated. A parsed session whose received time plus its
lifetime would overflow a signed 64-bit is refused, and `gtls_session_info`
saturates `expires`. The ClientHello then
carries `psk_key_exchange_modes` (`psk_dhe_ke`), the ticket as the one
identity, `obfuscated_ticket_age`, and the binder, with `pre_shared_key` last
(the padding moves in front of it). After a HelloRetryRequest the second
hello's age is refreshed and its binder computed again over the transcript with
the retry in it; if the retry names a suite whose hash is not the PSK's the
offer is dropped, the session let go, and the handshake that follows is a full
one. A ServerHello that selects a PSK that was not offered, an index out of
range, or under a suite of another hash is `illegal_parameter`; one that selects
none means a full handshake and the client goes on to check the certificate as
it always does. A resumed client expects no Certificate (`unexpected_message` if one
comes) and `gtls_conn_peer_certificate` is empty for it.

**Wiping.** The PSK and every secret after it live in the connection's secret
block, wiped on failure and on free; a session is wiped when freed; a failed
connection frees its sessions and the offer; the ticket's plaintext, the PSK
on the server's stack and the binder keys are wiped on every path.

## Early data

RFC 8446 sections 2.3, 4.2.10 and 8; `record.h` and `context.h` are the
interface. Early data is application data sent with the first flight of a
resumed connection, under a key from the PSK alone, so anyone who recorded the
connection can send it again. **The library keeps nothing across connections,
so it cannot know whether a ticket was shown before: the caller decides.**

**Turning it on.** Off by default, in both roles. A server sets
`GTLS_ContextConfig::max_early_data` (the allowance its tickets carry, at most
`GTLS_Limits::max_early_data_bytes`) and `anti_replay`, a callback; either alone
is `GTLS_ERR_LIMIT` when the context is made. A client sets `max_early_data` (the
most it will send) and offers early data when a session it resumes permits it;
a client context refuses the callback. A ticket carries the allowance inside the
sealed state: version 2 of the state, with four bytes after the lifetime; a ticket
whose allowance is 0 is sealed as version 1, as it always was, and both open.
Tickets a server sends carry `early_data` with `max_early_data_size`.

**The server accepts** only when all of these hold, and otherwise rejects (the
handshake goes on, the early records are skipped up to `max_early_skip_bytes`,
as before): the ClientHello offered `early_data`; the PSK was accepted and its
binder verified; the context allows it; no HelloRetryRequest was sent (an
`early_data` in a second hello is `illegal_parameter`, and the client drops it
from its own); the ticket carries an allowance; **the PSK selected is the first
one offered** (section 4.2.10: the client keyed its early records to its first
identity); its suite is the one selected;
**the ALPN protocol selected is the ticket's** (both none counts; a ticket with
no protocol and a server that now selects one does not), section 4.2.10; the age
is inside the window (settled while the ticket was opened); **and the callback
says 1**. The callback is last, so it is asked only about a ticket nothing else
rules out, once, and only after the binder has proved the client holds the PSK
(an attacker who has seen a ticket's bytes cannot make the server record it).
It gets `SHA-256(identity)`, a stable 32-byte name for the ticket to key its
store by, the second the ticket was sealed and the age the client reports in
milliseconds. Anything but 1 is a rejection. The store is the caller's: this
library's `examples/echo` keeps an in-memory list for the interop cases.

**The keys.** `client_early_traffic_secret` is derived from the early secret and
the transcript hash through the whole ClientHello, binders included (it is the
only secret taken before the ServerHello); it is the client's, so only a
client's write and a server's read have it, and `gtls_conn_secret` with
`GTLS_EPOCH_EARLY` returns it (it exists from the ClientHello being built, or
accepted, until a rejection wipes it, or until it has done its work: a client wipes it
as it queues `EndOfEarlyData`, a server as it reads it, and the keys copied from it
with it). The early records are protected with the
ticket's suite, with the same nonce rule as every other record. The client's
`EndOfEarlyData` is sealed under the early key too, queued at the early epoch
(a message-interface caller carries it there), before the Finished, and it is
part of what the Finished covers; the application secrets are over the
transcript through the server's Finished without it.

**What the server does with the records.** In `S_WAIT_EOED` it opens records under
the early key. Application data goes to a buffer of its own, read with
`gtls_conn_read_early`; **`gtls_conn_read` never returns it**, so a caller can
treat replayable bytes differently. The bytes are counted against the ticket's
allowance (or the context's, if that is smaller), an empty record counts one, and
one more than the allowance is `GTLS_ERR_LIMIT` with `unexpected_message`.
`EndOfEarlyData` moves the server to the handshake keys; nothing opens under the
early key after it (`bad_record_mac`), a Finished with no `EndOfEarlyData` before it
is `unexpected_message` (the server tries the handshake key on a record that
does not open, to tell this from damage), an `EndOfEarlyData` with a body is
`decode_error` and one sent to a server that did not accept is
`unexpected_message`. At the message interface the same are enforced by epoch.
QUIC forbids `EndOfEarlyData` (RFC 9001 section 8.3); using early data under QUIC
is not what this is.

**The client.** After `gtls_conn_start` and before the server's first message is
fed, `gtls_conn_write_early` seals records under the early key behind the
ClientHello (and behind the dummy `change_cipher_spec` in compatibility mode,
where appendix D.4 puts it). Past the allowance it takes nothing and returns
`GTLS_ERR_LIMIT`, without failing the connection. The client learns the outcome
from the server: a HelloRetryRequest, a ServerHello without the PSK, or an
EncryptedExtensions without `early_data` is a rejection, reported by
`gtls_conn_early_status` (which returns `GTLS_ERR_EARLY_REJECTED`) the moment it
is known, and the early key is wiped; `gtls_conn_early_resend` then hands back the
bytes sent, which the library kept for that, for the caller to send as ordinary
data. An `early_data` that comes back where none was offered, after a retry, after
a ServerHello that took no PSK, with another suite or with another ALPN
protocol than the ticket's is the server's fault (`unsupported_extension` or
`illegal_parameter`). An acceptance makes the client send `EndOfEarlyData`.

**Closing in the early window.** The early key carries application data only (section
2.3), and the server reads nothing else under it. A client that has written early data
and calls `gtls_conn_close` before the handshake is complete therefore says nothing:
the connection ends locally, what was not yet taken from the output is dropped, and
the call returns `GTLS_ERR_CLOSED` with the connection failed (no alert). The server
sees the stream end. Once the client is connected the close is the ordinary one, under
the application key, even if `EndOfEarlyData` and the Finished are still queued
ahead of it.

**Wiping.** The early secret is in the connection's secret block. The buffers of
early bytes, which are plaintext, are given all their room at once so that no
growth leaves a copy in a block that was freed, and are wiped when the connection
fails and when it is freed; what `gtls_conn_read_early` and `gtls_conn_early_resend`
hand over is wiped from the buffer it came from, including the copy the move leaves.

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
  may be split across records, but nothing else may come between its pieces
  (no dummy change_cipher_spec, no alert, no application data: `unexpected_message`)
  and it may not span a key change; a KeyUpdate must be the last message of
  its record (RFC 8446 section 5.1).
- **Padding** is never sent. It is accepted up to `max_record_padding` and a
  record that is nothing but padding has no content type: `unexpected_message`.
- **Keys follow the handshake.** The read keys are for the epoch the handshake
  is waiting for; the write keys change when the first record of a later epoch
  is made, so a record is always sealed under keys the peer has been told
  about. Before the Finished is sent an alert goes in the clear; a receiver
  under keys accepts such a plaintext alert of two bytes until its own
  handshake is done, **as a fatal alert and nothing else**: it is
  `GTLS_ERR_ALERT` whatever its description (`close_notify` included), never a
  clean close and never ignored, because nobody authenticated it. Once the
  handshake is done a plaintext alert is `unexpected_message`.
- **KeyUpdate** (section 4.6.3) is sent on request and answered when it asks
  to be, once. Its message is sealed under the old key and every record after
  it under the new one; the sequence number starts again. A key that has
  protected `max_records_per_key` records (default 2^24, under the AES-GCM
  limit of section 5.5) is replaced by the sending side by itself, one record
  before the counter would run out; a limit under 2 is `GTLS_ERR_LIMIT`
  for a write (handshake records are not counted against it). A request is
  answered once however many arrive before the answer goes out, and not at all
  once this end has sent `close_notify`. `max_key_updates` caps the updates
  that arrive with no application data between them (a flood), not a
  connection's life.
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
| (server) `pre_shared_key` not last, or a binder count that differs | `GTLS_ERR_PROTOCOL` | `illegal_parameter` |
| (server) `pre_shared_key` or `early_data` that does not parse | `GTLS_ERR_CORRUPT` | `decode_error` |
| (server) a binder that does not verify, or is the wrong length for the PSK | `GTLS_ERR_MISMATCH` | `decrypt_error` |
| (client) a ServerHello that selects a PSK never offered, an index out of range, or a suite of another hash | `GTLS_ERR_PROTOCOL` | `illegal_parameter` |
| (server) more identities, or a longer one, than the limits | `GTLS_ERR_LIMIT` | `decode_error` |
| (server) more early-data bytes skipped than the limit | `GTLS_ERR_LIMIT` | `unexpected_message` |
| (server) more early data accepted than the allowance, an empty record counting one | `GTLS_ERR_LIMIT` | `unexpected_message` |
| (server) a record that does not open while early data is accepted | `GTLS_ERR_MISMATCH` | `bad_record_mac` |
| (server) the Finished (or anything under the handshake key) where `EndOfEarlyData` is due; any other message type there; application data in the middle of a handshake message; `EndOfEarlyData` when early data was not accepted | `GTLS_ERR_PROTOCOL` | `unexpected_message` |
| (server) an `EndOfEarlyData` with a body | `GTLS_ERR_CORRUPT` | `decode_error` |
| (client) `early_data` where none is offered, after a retry, or after a ServerHello that took no PSK | `GTLS_ERR_PROTOCOL` | `unsupported_extension` |
| (client) `early_data` accepted with another suite or ALPN protocol than the ticket's | `GTLS_ERR_PROTOCOL` | `illegal_parameter` |
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

**RFC 8448's 0-RTT trace** (section 4, the resumed handshake with early data) is
read by the same extractor into `resumed.vec`. The early secret, the transcript
hash it is derived over (which has to be the whole ClientHello, binders
included, and the test says that hash is not the one over the hello cut before
them), `client_early_traffic_secret`, its key and IV, the sealed early record
and the sealed `EndOfEarlyData` (the second record under that key) are the
trace's, byte for byte, and the server opens them with the keys it derives. A
label of another name, a secret over another range of the transcript, or a
sequence number that does not start at 0 changes the bytes and fails the same
tests.

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
ALPN overlap, the SNI match, the client's Finished, a second retry, the PSK and early-data rules,
the version check, and the key-fits-scheme choice; and, from review, the
plaintext-alert rules, the fragments rule, KeyUpdate's record and its answers,
the key of a server's alert, the client's dummy record, ALPN names compared by
their bytes, what a second ClientHello may change, a context's checks on a chain,
which identity a name picks, the wire's room for a record, and the result of an
allocation failure; and for tickets, the binder (its check, its length, the transcript
it covers), the key name, expiry and choice of a ticket key, the freshness
arithmetic (lifetime, window, `age_add`, a ticket from the future), each of the
checks that passes a ticket over (name, ALPN protocol, suite, `psk_dhe_ke`,
the retry's suite), the suite the ticket chooses, the abbreviated flight (no
Certificate; no signature scheme needed), the number and the nonce of the
tickets, the client's binder (first hello and retry), the age it reports, the hash
it drops an offer for, what it takes of a ServerHello's PSK, what a session is
bound to, and every check of a session blob and of a ticket configuration.
A planted copy that does not compile has caught nothing, and `controls.sh` says
so rather than counting it. The one check on a ticket with no plant is the AEAD
tag: `security` wipes the plaintext of a ciphertext whose tag fails, so the
strict decode of the state refuses it with the check removed or not. A test
pins that dependency (each of the three AEADs this library uses returns an
error and zeroes its output on a bad tag) and the tests that change every bit
of a ticket exercise the check, but no plant can be seen to fail. The decode's
bounds checks on a short authentic state are the same kind: removed, the state
is still refused (the later checks catch an over-read), and only a memory
checker sees the read; their plants run the test under Valgrind.

`make check-controls` runs all of it (slow: it builds a copy per plant; needs
`PREFIX`). `make test` runs `check-controls-anchors`, which needs no build and
fails if a plant's text no longer occurs in the tree exactly once: the code moved
and the plant would otherwise go quietly unmeasured.

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
(`make interop-plants`, `interop.py --plant`) must make the cases it names fail:
four damage what is sent, and five remove a check or a rule (the ALPN failure,
the `supported_versions` check, the no-common-scheme refusal, the plaintext-alert
rule, the identity choice).

**Resumption is in the population, in both roles.** This library's server
issues tickets under a key the example program draws, and a first `s_client`
saves its session (`-sess_out`) for a second connection to offer (`-sess_in`).
This library's client keeps what an `s_server` sends and offers it on a second
connection. Every suite, every group, a HelloRetryRequest (the ticket is looked
at twice, once in each hello) and ALPN are each a case that must resume, with
the evidence from the other stack (`Reused, TLSv1.3` and the PSK in its
ClientHello and ServerHello; or the server's session-cache hits). Six cases
must not resume and must still complete in full, with the ticket offered
and refused: a server whose key changed, one whose key kept its bytes and took
a new name, a server clock a hundred seconds ahead, an ALPN protocol not
offered again, a connection with no server name, and a client whose second
server is a different process. A planted binder (computed wrongly by the
client, or read over the wrong transcript by the server) breaks every
resumption; a removed age window, name match, ALPN match or key-name check
breaks the case that depends on it, and so does a client that takes the PSK for
granted when the server did not select it. (A ticket under a key the server no
longer has is refused by the lookup and by the AEAD alike, so no one plant
breaks that case; `tools/controls.sh` plants the unit tests.)

**Early data is in the population, in both roles** (25 cases; the population is
118, of which 109 interoperate and 9 are refused for their declared reasons).
The second connection of a resumption sends bytes ahead of the server's answer:
accepted for every suite and group, with ALPN and in compatibility mode; refused
by a HelloRetryRequest, by a replay (the third connection offers the first's
ticket again; this library's server refuses it through its in-memory store, and
OpenSSL's cache has already had the ticket so its server does not even resume),
by a callback that says no, by another ALPN protocol than the ticket's, and by a
clock or a key that took the ticket out. The evidence is OpenSSL's own (`Early
data was accepted` / `rejected` from `s_client`; the early data an `s_server`
received, and the client's next line arriving under the application keys, which
only happens if it verified a Finished that covers `EndOfEarlyData`) beside
what each end reports (the status, the bytes delivered or handed back and sent
again, how often the replay decision was asked). `s_server` will not take early
data with `-rev`, so these cases print what arrives and the example client does
not wait for an echo. OpenSSL's server does not insist that `EndOfEarlyData` be
sent, so the interop plants break it by leaving the message out of the
transcript the Finished covers; six plants in all (a server that never accepts,
never asks the callback, does not tie the ALPN protocol, does not wait for the
message; a client that leaves it out of the transcript or keeps `early_data` in
the retry's second hello).

A refusal is judged on **this side's own result**, not on a string: the case
says which alert the library sent (or was sent), and a different alert, or the
right alert for the wrong reason, fails. A full run has a floor on the cases that
ran and the cases that interoperated, so a population that shrank, or an `--only`
that matched nothing, is not a pass. The server role is run with several
identities against `s_client` (the name picks the chain OpenSSL verifies) and
with a requested KeyUpdate (OpenSSL reports the update it was answered with).

## Constant time

What this library compares of a secret is the `Finished` (`gsec_equal`, in
`gtls_finished_check`, for both roles: a server checks the client's with the
same function), a PSK binder (`gtls_binder_check`, the same shape: a MAC under a key
derived from the PSK, compared with `gsec_equal`; the `check-ct` gate runs it
beside `Finished`) and the AEAD tag, which `security` compares itself. The review:
`tools/check-secret.py` forbids `memcmp` and kin under `src/`; the padding scan
in `gtls_record_open` runs only on a record that has already authenticated, so
what it learns an attacker chose nothing of; the ALPN and SNI comparisons are of
public names and may branch. Under the `check-ct` gate is the check of `Finished`
(from the key up to `gsec_equal`; the server's check is the same function): not
the key schedule, the record nonce or the AEAD dispatch, which touch a secret but
never branch on one, and which the review of the source (no branch or index on
secret data, enforced for nothing but `memcmp` by `check-secret`) is all that
covers here. The tag comparison is `security`'s, with its own gate there.

## Not here

Client authentication and `CertificateRequest` (the server never sends one);
TLS 1.2; `psk_ke` without ECDHE; external PSKs; a server-side ticket or session
cache and revocation of tickets (the way to refuse one is to retire its key);
a replay store for early data (the callback is the seam; the store is the
caller's, and a ticket not used for early data may be presented again until it
expires, as RFC 8446 section 8 says of a server with no cache); early data under
QUIC beyond exposing the secret; DTLS; revocation in the handshake; the `http`
adapter.
`GTLS_ContextConfig` already has room for TLS 1.2, an external PSK and a client
certificate.
