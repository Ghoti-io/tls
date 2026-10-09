/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io TLS.
 *
 * Ghoti.io TLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io TLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file handshake.c
 *
 * The shape of a caller: make a context, make a connection, start it, take
 * the ClientHello that is queued, and show how bytes from a peer would go
 * back in. There is no socket here, because the library has none: the caller
 * carries what comes out of gtls_conn_pending_output to the peer and what
 * arrives from the peer into gtls_conn_feed.
 *
 * The trust store is empty, so a real server's chain would be refused with
 * GTLS_ERR_CERT_ISSUER. A program that connects somewhere loads the
 * operating system's roots first, with gcert_trust_add_system.
 *
 *   usage: handshake [host]
 */

#include <ghoti.io/tls/tls.h>

#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv) {
  const char * host = argc > 1 ? argv[1] : "example.com";
  static const char * const protocols[] = {"h2", "http/1.1"};
  GCERT_TrustStore * trust = NULL;
  GTLS_ContextConfig config;
  GTLS_Context * context = NULL;
  GTLS_Conn * conn = NULL;
  const unsigned char * hello = NULL;
  size_t hello_len = 0;
  int status = 1;

  if (gcert_trust_new(NULL, NULL, &trust) != GCERT_OK) {
    return 1;
  }
  gtls_context_config_default(&config);
  config.trust = trust;
  config.alpn = protocols;
  config.alpn_count = 2;
  if (gtls_context_new(NULL, &config, &context) != GTLS_OK ||
      gtls_conn_new(context, host, strlen(host), &conn) != GTLS_OK ||
      gtls_conn_start(conn) != GTLS_OK) {
    goto done;
  }
  /* What would go to the peer, as handshake bytes: the caller frames them as
   * a TLS record, or as a QUIC CRYPTO frame. */
  if (gtls_conn_pending_output(conn, GTLS_EPOCH_INITIAL, &hello, &hello_len) !=
      GTLS_OK) {
    goto done;
  }
  /* check-secret: allow printf -- the example's report of what it built or saw (a host name, a count, a result), never a key */
  printf("ClientHello for %s: %zu bytes, handshake message type %u\n", host,
      hello_len, hello[0]);
  (void)gtls_conn_consume_output(conn, GTLS_EPOCH_INITIAL, hello_len);
  /* The peer's bytes would now go in:
   *   gtls_conn_feed(conn, GTLS_EPOCH_INITIAL, bytes, n, unix_time);
   * and a refusal is a specific result and an alert to send. Feeding
   * something that is not a ServerHello shows it. */
  {
    static const unsigned char junk[4] = {20, 0, 0, 0};
    GTLS_Result r = gtls_conn_feed(conn, GTLS_EPOCH_INITIAL, junk, sizeof junk, 0);

    /* check-secret: allow printf -- the example's report of what it built or saw (a host name, a count, a result), never a key */
    printf("a Finished before ServerHello: %s, alert %u\n", gtls_result_string(r),
        gtls_conn_alert(conn));
  }
  status = 0;
done:
  gtls_conn_free(conn);
  gtls_context_free(context);
  gcert_trust_free(trust);
  return status;
}
