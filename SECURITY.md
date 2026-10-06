# Reporting a vulnerability

Email **pennycuff.c@gmail.com** with `ghoti.io-tls` in the subject. A proof of
concept, the commit you tested, and the platform are the three things that
make a report actionable fastest.

There is no bug bounty and no formal service level. What there is: an
acknowledgement, a fix or an explanation of why the behaviour is what it is,
and credit in the commit message unless you would rather not have it.

Please do report anything in the list below. A report is not wasted for being
one of these; they are listed because they are the ones most likely to be
mistaken for intended behaviour.

## Things that are deliberate

- **There is no record layer yet.** This library produces and consumes
  handshake messages. Nothing here encrypts application data, so a program that
  sends data after the handshake has to bring its own record layer; the
  traffic secrets are exposed for that.
- **No client authentication, no resumption, no early data.** A server that
  sends `CertificateRequest` is refused. A `NewSessionTicket` is parsed and
  thrown away.
- **TLS 1.3 only.** A server that answers with an older version is
  `GTLS_ERR_UNSUPPORTED`, or `GTLS_ERR_DOWNGRADE` if it left the sentinel.
- **There is no way to skip certificate verification.** A context needs a
  trust store, and the chain and the name are always checked.
- **The test seams are not API.** `gtls_conn_start_raw` and
  `gtls_conn_set_hooks` are in `src/client/client_internal.h`, are not
  exported, and exist so tests can feed RFC 8448 through the shipped code.
- **Revocation is not checked.** `certificate` has the checks over evidence the
  caller fetched; the handshake does not ask for or apply that evidence yet.
- **No interop test against another stack exists yet.** The handshake is
  checked against RFC 8448 and against its own simulated server.
