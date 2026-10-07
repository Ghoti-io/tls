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
 * @file echo.c
 *
 * An echo server and its client over TCP on the loopback, built on the
 * record layer (record.h): the whole shape of a caller that owns a socket.
 * The library does no I/O; this program does it all, with poll(), and the
 * library is handed bytes and gives bytes back.
 *
 * It is also the peer the interop gate runs OpenSSL against (tools/oracle):
 * the same program is the server that `openssl s_client` talks to and the
 * client that talks to `openssl s_server`, so every handshake is checked by a
 * second implementation in both roles.
 *
 *   echo server [options] PORT           accept one connection, echo it, close
 *   echo client [options] HOST PORT      connect, send a line, print the echo
 *
 * Options (repeat --chain, --ca and --alpn for more than one):
 *   --chain FILE     a DER certificate to present, leaf first   (server)
 *   --key FILE       the leaf's private key, PKCS#8 DER         (server)
 *   --name NAME      a server name the identity answers to      (server)
 *   --next-identity  start another identity: the --chain, --key and --name
 *                    that follow are its; the first is the default (server)
 *   --ca FILE        a DER trust anchor                         (client)
 *   --server-name N  the name to send and verify, default HOST  (client)
 *   --alpn NAME      a protocol to offer (client) or accept (server)
 *   --suites LIST    comma-separated: aes128, aes256, chacha
 *   --groups LIST    comma-separated: x25519, p256, p384
 *   --sigalgs LIST   comma-separated: pss256, pss384, pss512, p256, p384, ed25519
 *   --message TEXT   the line the client sends, default "hello"
 *   --expect TEXT    what the client expects back, default the message
 *   --key-update     the client updates its key and asks the server to
 *   --compat         ask for middlebox compatibility mode (client)
 *   --time SECONDS   the time to check certificates at, default now
 *
 * On success it prints one line, `ok`, then what was negotiated, and exits 0.
 * On failure it prints `failed`, the reason, and the alerts, and exits 1.
 */

#define _POSIX_C_SOURCE 200809L

#include <ghoti.io/tls/tls.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
int main(void) {
  fprintf(stderr, "echo: this example uses POSIX sockets\n");
  return 2;
}
#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_FILES 16
#define MAX_IDS 4
#define IO_TIMEOUT_MS 15000

typedef struct Options {
  int server;
  const char * host;
  int port;
  struct {
    const char * chain[MAX_FILES];
    size_t chain_count;
    const char * key;
    const char * name;
  } id[MAX_IDS];
  size_t id_count;
  const char * ca[MAX_FILES];
  size_t ca_count;
  const char * server_name;
  const char * alpn[MAX_FILES];
  size_t alpn_count;
  GTLS_Suite suites[3];
  size_t suite_count;
  GTLS_Group groups[3];
  size_t group_count;
  GCERT_SigScheme sigs[9];
  size_t sig_count;
  const char * message;
  const char * expect;
  int key_update;
  int compat;
  int64_t now;
} Options;

static int fail(const char * what) {
  fprintf(stderr, "failed\n%s\n", what);
  return 1;
}

static int read_file(const char * path, unsigned char ** data, size_t * len) {
  FILE * f = fopen(path, "rb");
  unsigned char * buf;
  size_t cap = 4096;
  size_t n = 0;
  size_t got;

  if (f == NULL) {
    return -1;
  }
  buf = malloc(cap);
  while (buf != NULL && (got = fread(buf + n, 1, cap - n, f)) > 0) {
    n += got;
    if (n == cap) {
      unsigned char * bigger = realloc(buf, cap * 2);

      if (bigger == NULL) {
        free(buf);
        buf = NULL;
        break;
      }
      buf = bigger;
      cap *= 2;
    }
  }
  fclose(f);
  if (buf == NULL) {
    return -1;
  }
  *data = buf;
  *len = n;
  return 0;
}

/** Split @p list at commas and map each word through @p names. */
static int parse_list(const char * list, const char * const * names, const int * values,
    size_t count, int * out, size_t * out_count, size_t max) {
  char * copy = strdup(list);
  char * save = NULL;
  char * word;

  *out_count = 0;
  for (word = strtok_r(copy, ",", &save); word != NULL; word = strtok_r(NULL, ",", &save)) {
    size_t i;

    for (i = 0; i < count && strcmp(names[i], word) != 0; i++) {
    }
    if (i == count || *out_count >= max) {
      free(copy);
      return -1;
    }
    out[(*out_count)++] = values[i];
  }
  free(copy);
  return *out_count == 0 ? -1 : 0;
}

static int parse_options(int argc, char ** argv, Options * o) {
  static const char * const suite_names[] = {"aes128", "aes256", "chacha"};
  static const int suite_values[] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
      GTLS_SUITE_CHACHA20_POLY1305_SHA256};
  static const char * const group_names[] = {"x25519", "p256", "p384"};
  static const int group_values[] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1};
  static const char * const sig_names[] = {"pss256", "pss384", "pss512", "p256", "p384", "ed25519"};
  static const int sig_values[] = {GCERT_SIG_RSA_PSS_SHA256, GCERT_SIG_RSA_PSS_SHA384,
      GCERT_SIG_RSA_PSS_SHA512, GCERT_SIG_ECDSA_P256_SHA256, GCERT_SIG_ECDSA_P384_SHA384,
      GCERT_SIG_ED25519};
  int i;
  int positional = 0;

  memset(o, 0, sizeof *o);
  o->id_count = 1;
  o->message = "hello";
  o->now = (int64_t)time(NULL);
  if (argc < 2) {
    return -1;
  }
  if (strcmp(argv[1], "server") == 0) {
    o->server = 1;
  } else if (strcmp(argv[1], "client") != 0) {
    return -1;
  }
  for (i = 2; i < argc; i++) {
    const char * a = argv[i];
    const char * v = i + 1 < argc ? argv[i + 1] : NULL;

    if (strncmp(a, "--", 2) != 0) {
      if (o->server && positional == 0) {
        o->port = atoi(a);
      } else if (!o->server && positional == 0) {
        o->host = a;
      } else if (!o->server && positional == 1) {
        o->port = atoi(a);
      } else {
        return -1;
      }
      positional++;
      continue;
    }
    if (strcmp(a, "--key-update") == 0) {
      o->key_update = 1;
      continue;
    }
    if (strcmp(a, "--compat") == 0) {
      o->compat = 1;
      continue;
    }
    if (strcmp(a, "--next-identity") == 0) {
      if (o->id_count >= MAX_IDS) {
        return -1;
      }
      o->id_count++;
      continue;
    }
    if (v == NULL) {
      return -1;
    }
    i++;
    if (strcmp(a, "--chain") == 0 && o->id[o->id_count - 1].chain_count < MAX_FILES) {
      o->id[o->id_count - 1].chain[o->id[o->id_count - 1].chain_count++] = v;
    } else if (strcmp(a, "--key") == 0) {
      o->id[o->id_count - 1].key = v;
    } else if (strcmp(a, "--name") == 0) {
      o->id[o->id_count - 1].name = v;
    } else if (strcmp(a, "--ca") == 0 && o->ca_count < MAX_FILES) {
      o->ca[o->ca_count++] = v;
    } else if (strcmp(a, "--server-name") == 0) {
      o->server_name = v;
    } else if (strcmp(a, "--alpn") == 0 && o->alpn_count < MAX_FILES) {
      o->alpn[o->alpn_count++] = v;
    } else if (strcmp(a, "--message") == 0) {
      o->message = v;
    } else if (strcmp(a, "--expect") == 0) {
      o->expect = v;
    } else if (strcmp(a, "--time") == 0) {
      o->now = (int64_t)atoll(v);
    } else if (strcmp(a, "--suites") == 0) {
      int tmp[3];

      if (parse_list(v, suite_names, suite_values, 3, tmp, &o->suite_count, 3) != 0) {
        return -1;
      }
      for (size_t k = 0; k < o->suite_count; k++) {
        o->suites[k] = (GTLS_Suite)tmp[k];
      }
    } else if (strcmp(a, "--groups") == 0) {
      int tmp[3];

      if (parse_list(v, group_names, group_values, 3, tmp, &o->group_count, 3) != 0) {
        return -1;
      }
      for (size_t k = 0; k < o->group_count; k++) {
        o->groups[k] = (GTLS_Group)tmp[k];
      }
    } else if (strcmp(a, "--sigalgs") == 0) {
      int tmp[9];

      if (parse_list(v, sig_names, sig_values, 6, tmp, &o->sig_count, 9) != 0) {
        return -1;
      }
      for (size_t k = 0; k < o->sig_count; k++) {
        o->sigs[k] = (GCERT_SigScheme)tmp[k];
      }
    } else {
      return -1;
    }
  }
  if (o->port <= 0 || o->port > 65535 || (!o->server && o->host == NULL)) {
    return -1;
  }
  if (o->expect == NULL) {
    o->expect = o->message;
  }
  if (o->server_name == NULL) {
    o->server_name = o->host;
  }
  return 0;
}

/* ------------------------------------------------------------------ the socket */

static int open_socket(const Options * o) {
  struct sockaddr_in addr;
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if (fd < 0) {
    return -1;
  }
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)o->port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (o->server) {
    int one = 1;
    int conn;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 1) != 0) {
      close(fd);
      return -1;
    }
    {
      struct pollfd p = {fd, POLLIN, 0};

      if (poll(&p, 1, 30000) <= 0) {
        close(fd);
        return -1;
      }
    }
    conn = accept(fd, NULL, NULL);
    close(fd);
    return conn;
  }
  for (int attempt = 0; attempt < 50; attempt++) {
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
      return fd;
    }
    close(fd);
    {
      struct timespec ts = {0, 100 * 1000 * 1000};

      nanosleep(&ts, NULL);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      return -1;
    }
  }
  close(fd);
  return -1;
}

/** Send everything the connection has queued. A short write is only a short write. */
static int flush_out(GTLS_Conn * conn, int fd) {
  for (;;) {
    const unsigned char * p = NULL;
    size_t n = 0;
    ssize_t sent;

    if (gtls_conn_stream_output(conn, &p, &n) != GTLS_OK) {
      return -1;
    }
    if (n == 0) {
      return 0;
    }
    sent = send(fd, p, n, MSG_NOSIGNAL);
    if (sent < 0) {
      return -1;
    }
    if (gtls_conn_stream_consume(conn, (size_t)sent) != GTLS_OK) {
      return -1;
    }
  }
}

static void report_failure(const GTLS_Conn * conn) {
  fprintf(stderr, "failed\n%s\nalert=%u peer_alert=%u\n",
      gtls_result_string(gtls_conn_failure(conn)), gtls_conn_alert(conn),
      gtls_conn_peer_alert(conn));
}

/* ----------------------------------------------------------------- the contexts */

typedef struct IdMaterial {
  GCERT_Key * key;
  unsigned char * files[MAX_FILES];
  size_t lens[MAX_FILES];
  size_t file_count;
  const void * chain[MAX_FILES];
  const char * names[1];
  unsigned char * key_der;
  size_t key_len;
} IdMaterial;

typedef struct Material {
  GCERT_TrustStore * trust;
  IdMaterial id[MAX_IDS];
} Material;

static int load_material(const Options * o, Material * m) {
  size_t i;
  size_t k;

  memset(m, 0, sizeof *m);
  if (o->server) {
    for (k = 0; k < o->id_count; k++) {
      if (o->id[k].chain_count == 0 || o->id[k].key == NULL) {
        return -1;
      }
      for (i = 0; i < o->id[k].chain_count; i++) {
        if (read_file(o->id[k].chain[i], &m->id[k].files[i], &m->id[k].lens[i]) != 0) {
          return -1;
        }
        m->id[k].file_count++;
        m->id[k].chain[i] = m->id[k].files[i];
      }
      if (read_file(o->id[k].key, &m->id[k].key_der, &m->id[k].key_len) != 0 ||
          gcert_key_from_pkcs8(NULL, m->id[k].key_der, m->id[k].key_len, &m->id[k].key) != GCERT_OK) {
        return -1;
      }
    }
  } else {
    if (gcert_trust_new(NULL, NULL, &m->trust) != GCERT_OK) {
      return -1;
    }
    for (i = 0; i < o->ca_count; i++) {
      unsigned char * der = NULL;
      size_t len = 0;

      if (read_file(o->ca[i], &der, &len) != 0 ||
          gcert_trust_add_der(m->trust, der, len) != GCERT_OK) {
        free(der);
        return -1;
      }
      free(der);
    }
  }
  return 0;
}

static void free_material(Material * m) {
  size_t i;
  size_t k;

  for (k = 0; k < MAX_IDS; k++) {
    for (i = 0; i < m->id[k].file_count; i++) {
      free(m->id[k].files[i]);
    }
    if (m->id[k].key_der != NULL) {
      memset(m->id[k].key_der, 0, m->id[k].key_len);
      free(m->id[k].key_der);
    }
    gcert_key_free(m->id[k].key);
  }
  gcert_trust_free(m->trust);
}

int main(int argc, char ** argv) {
  Options o;
  Material m;
  GTLS_ContextConfig config;
  GTLS_Identity identity[MAX_IDS];
  size_t chain_lens[MAX_IDS][MAX_FILES];
  GTLS_Context * context = NULL;
  GTLS_Conn * conn = NULL;
  unsigned char buf[16384];
  unsigned char echo[65536];
  size_t echo_len = 0;
  size_t sent_message = 0;
  size_t got = 0;
  char received[4096];
  size_t received_len = 0;
  int fd;
  int status = 1;
  int closed = 0;
  size_t i;

  if (parse_options(argc, argv, &o) != 0) {
    fprintf(stderr, "usage: echo server [options] PORT | echo client [options] HOST PORT (see the file comment)\n");
    return 2;
  }
  if (load_material(&o, &m) != 0) {
    free_material(&m);
    return fail("could not load the certificates or the key");
  }
  gtls_context_config_default(&config);
  config.role = o.server ? GTLS_ROLE_SERVER : GTLS_ROLE_CLIENT;
  config.trust = m.trust;
  config.alpn = o.alpn_count != 0 ? o.alpn : NULL;
  config.alpn_count = o.alpn_count;
  config.suites = o.suite_count != 0 ? o.suites : NULL;
  config.suite_count = o.suite_count;
  config.groups = o.group_count != 0 ? o.groups : NULL;
  config.group_count = o.group_count;
  config.sig_algs = o.sig_count != 0 ? o.sigs : NULL;
  config.sig_alg_count = o.sig_count;
  config.middlebox_compat = o.compat;
  if (o.server) {
    size_t k;

    for (k = 0; k < o.id_count; k++) {
      for (i = 0; i < o.id[k].chain_count; i++) {
        chain_lens[k][i] = m.id[k].lens[i];
      }
      memset(&identity[k], 0, sizeof identity[k]);
      identity[k].chain = m.id[k].chain;
      identity[k].chain_lens = chain_lens[k];
      identity[k].chain_count = o.id[k].chain_count;
      identity[k].key = m.id[k].key;
      m.id[k].names[0] = o.id[k].name;
      identity[k].names = o.id[k].name != NULL ? m.id[k].names : NULL;
      identity[k].name_count = o.id[k].name != NULL ? 1u : 0u;
    }
    config.identities = identity;
    config.identity_count = o.id_count;
  }
  if (gtls_context_new(NULL, &config, &context) != GTLS_OK) {
    free_material(&m);
    return fail("could not make the context");
  }
  if (o.server ? gtls_conn_new_server(context, &conn) != GTLS_OK
               : gtls_conn_new(context, o.server_name, strlen(o.server_name), &conn) != GTLS_OK) {
    gtls_context_free(context);
    free_material(&m);
    return fail("could not make the connection");
  }
  if (gtls_conn_start(conn) != GTLS_OK) {
    goto done;
  }
  fd = open_socket(&o);
  if (fd < 0) {
    fprintf(stderr, "failed\ncould not open the socket\n");
    goto done;
  }

  for (;;) {
    struct pollfd p;
    ssize_t n;
    size_t off;

    if (flush_out(conn, fd) != 0 && !gtls_conn_is_failed(conn)) {
      fprintf(stderr, "failed\nwrite error\n");
      goto closed_fd;
    }
    if (gtls_conn_is_failed(conn)) {
      report_failure(conn);
      goto closed_fd;
    }
    if (!o.server && gtls_conn_is_connected(conn) && sent_message == 0) {
      size_t w = 0;
      size_t len = strlen(o.message);

      if (gtls_conn_write(conn, o.message, len, &w) != GTLS_OK || w != len ||
          gtls_conn_write(conn, "\n", 1, &w) != GTLS_OK) {
        fprintf(stderr, "failed\nwrite refused\n");
        goto closed_fd;
      }
      sent_message = 1;
      if (o.key_update && gtls_conn_key_update(conn, 1) != GTLS_OK) {
        fprintf(stderr, "failed\nkey update refused\n");
        goto closed_fd;
      }
      if (o.key_update) {
        /* data under the new key, to see the peer took it */
        if (gtls_conn_write(conn, o.message, len, &w) != GTLS_OK ||
            gtls_conn_write(conn, "\n", 1, &w) != GTLS_OK) {
          fprintf(stderr, "failed\nwrite refused\n");
          goto closed_fd;
        }
      }
      continue;
    }
    if (o.server && echo_len > 0) {
      size_t w = 0;

      if (gtls_conn_write(conn, echo, echo_len, &w) != GTLS_OK) {
        fprintf(stderr, "failed\nwrite refused\n");
        goto closed_fd;
      }
      memmove(echo, echo + w, echo_len - w);
      echo_len -= w;
      continue;
    }
    if (o.server && gtls_conn_peer_closed(conn) && !closed && echo_len == 0) {
      (void)gtls_conn_close(conn);
      closed = 1;
      (void)flush_out(conn, fd);
      break;
    }
    if (!o.server && received_len >= strlen(o.expect) + (sent_message ? 1u : 0u) &&
        sent_message && !closed) {
      (void)gtls_conn_close(conn);
      closed = 1;
      (void)flush_out(conn, fd);
      break;
    }
    p.fd = fd;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, IO_TIMEOUT_MS) <= 0) {
      fprintf(stderr, "failed\ntimed out\n");
      goto closed_fd;
    }
    n = recv(fd, buf, sizeof buf, 0);
    if (n <= 0) {
      GTLS_Result r = gtls_conn_stream_eof(conn);

      if (r == GTLS_OK) {
        break;
      }
      fprintf(stderr, "failed\n%s\n", gtls_result_string(r));
      goto closed_fd;
    }
    off = 0;
    while (off < (size_t)n) {
      size_t used = 0;
      GTLS_Result r = gtls_conn_stream_feed(conn, buf + off, (size_t)n - off, o.now, &used);

      off += used;
      for (;;) {
        size_t k = 0;

        if (gtls_conn_read(conn, o.server ? echo + echo_len : (unsigned char *)received + received_len,
                o.server ? sizeof echo - echo_len : sizeof received - received_len - 1u, &k) != GTLS_OK ||
            k == 0) {
          break;
        }
        if (o.server) {
          echo_len += k;
        } else {
          received_len += k;
        }
      }
      if (r != GTLS_OK) {
        break;
      }
      if (used == 0) {
        break;
      }
    }
    if (gtls_conn_is_failed(conn)) {
      (void)flush_out(conn, fd);
      report_failure(conn);
      goto closed_fd;
    }
  }
  /* The client has what it asked for: check it and say what was negotiated. */
  if (!o.server) {
    size_t want = strlen(o.expect);

    received[received_len] = 0;
    if (received_len < want || memcmp(received, o.expect, want) != 0) {
      fprintf(stderr, "failed\nthe echo was not what was sent: got %zu bytes\n", received_len);
      goto closed_fd;
    }
  }
  {
    const unsigned char * alpn = NULL;
    size_t alpn_len = 0;

    (void)gtls_conn_alpn(conn, &alpn, &alpn_len);
    printf("ok suite=%04x group=%04x alpn=%.*s retried=%d\n", (unsigned)gtls_conn_suite(conn),
        (unsigned)gtls_conn_group(conn), (int)alpn_len, alpn != NULL ? (const char *)alpn : "",
        gtls_conn_retried(conn));
    fflush(stdout);
  }
  status = 0;
closed_fd:
  close(fd);
done:
  (void)got;
  gtls_conn_free(conn);
  gtls_context_free(context);
  free_material(&m);
  return status;
}

#endif
