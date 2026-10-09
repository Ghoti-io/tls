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
 *   echo server [options] PORT           accept a connection, echo it, close
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
 *   --tickets N      send N session tickets after each handshake, under a key
 *                    this program draws at random (a caller's job)   (server)
 *   --ticket-lifetime S  how long a ticket is good for, in seconds   (server)
 *   --connections N  serve N connections one after another, from one context,
 *                    so that a ticket from the first can be used by the next
 *                    (server)
 *   --rekey          before each connection after the first, draw a new key
 *                    in a new context: the tickets of the ones before no
 *                    longer open (server)
 *   --rename         the same, but the key keeps its bytes and takes a new
 *                    name (server)
 *   --advance S      the server's clock runs S seconds ahead from the second
 *                    connection on (server)
 *   --resume         connect twice: the second time offering the session the
 *                    first was sent (client)
 *   --gate FILE      with --resume, wait for FILE to exist before the second
 *                    connection (client)
 *   --resumes K      with --resume, connect K more times (default 1), each
 *                    offering the first session again (client)
 *   --early N        early data (0-RTT): a server allows N bytes in its tickets
 *                    and takes the replay decision from --replay; a client
 *                    offers early data when the session permits it
 *   --replay MODE    a server's decision about early data: accept, reject, or
 *                    once (accept a ticket the first time it is seen and never
 *                    again: a store in memory, a caller's job)   (server)
 *   --no-echo        do not wait for the echo: send the line and close, for a
 *                    peer that does not send one back (client)
 *   --early-text T   the bytes a client sends as early data on a resumed
 *                    connection; if the server refuses them it sends them
 *                    again as ordinary data (client)
 *
 * On success it prints one line, `ok`, then what was negotiated, and exits 0
 * (one line for each connection, when there are several). On failure it
 * prints `failed`, the reason, and the alerts, and exits 1.
 */

#define _POSIX_C_SOURCE 200809L

#include <ghoti.io/tls/tls.h>

#include <ghoti.io/security/random.h>

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
  unsigned tickets;
  unsigned ticket_lifetime;
  unsigned connections;
  int rekey;
  int rename_key;
  int64_t advance;
  int resume;
  const char * gate;
  unsigned resumes;
  uint32_t early;
  const char * early_text;
  int replay;   /* 0 accept, 1 reject, 2 once */
  int no_echo;
} Options;

/* A server's replay store, for --replay once. The library keeps none: this is
 * what a caller supplies. */
static struct {
  unsigned char ids[64][32];
  size_t count;
  int mode;
  unsigned calls;
} g_replay;

static int replay_decision(void * user, const unsigned char id[32], int64_t issued, uint32_t age_ms) {
  size_t i;

  (void)user;
  (void)issued;
  (void)age_ms;
  g_replay.calls++;
  if (g_replay.mode == 0) {
    return 1;
  }
  if (g_replay.mode == 1) {
    return 0;
  }
  for (i = 0; i < g_replay.count; i++) {
    if (memcmp(g_replay.ids[i], id, 32) == 0) {
      return 0;
    }
  }
  if (g_replay.count < 64) {
    memcpy(g_replay.ids[g_replay.count++], id, 32);
  }
  return 1;
}

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
  o->connections = 1;
  o->resumes = 1;
  o->replay = 2;
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
    if (strcmp(a, "--no-echo") == 0) {
      o->no_echo = 1;
      continue;
    }
    if (strcmp(a, "--rekey") == 0) {
      o->rekey = 1;
      continue;
    }
    if (strcmp(a, "--rename") == 0) {
      o->rename_key = 1;
      continue;
    }
    if (strcmp(a, "--resume") == 0) {
      o->resume = 1;
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
    } else if (strcmp(a, "--tickets") == 0) {
      o->tickets = (unsigned)atoi(v);
    } else if (strcmp(a, "--ticket-lifetime") == 0) {
      o->ticket_lifetime = (unsigned)atoi(v);
    } else if (strcmp(a, "--connections") == 0) {
      o->connections = (unsigned)atoi(v);
    } else if (strcmp(a, "--gate") == 0) {
      o->gate = v;
    } else if (strcmp(a, "--resumes") == 0) {
      o->resumes = (unsigned)atoi(v);
    } else if (strcmp(a, "--early") == 0) {
      o->early = (uint32_t)atoi(v);
    } else if (strcmp(a, "--early-text") == 0) {
      o->early_text = v;
    } else if (strcmp(a, "--replay") == 0) {
      o->replay = strcmp(v, "accept") == 0 ? 0 : (strcmp(v, "reject") == 0 ? 1 : 2);
    } else if (strcmp(a, "--advance") == 0) {
      o->advance = (int64_t)atoll(v);
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

static int fill_addr(const Options * o, struct sockaddr_in * addr) {
  memset(addr, 0, sizeof *addr);
  addr->sin_family = AF_INET;
  addr->sin_port = htons((unsigned short)o->port);
  addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return 0;
}

/** A server's listening socket, made once for all its connections. */
static int listen_on(const Options * o) {
  struct sockaddr_in addr;
  int one = 1;
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if (fd < 0) {
    return -1;
  }
  fill_addr(o, &addr);
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 1) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int accept_on(int listener) {
  struct pollfd p = {listener, POLLIN, 0};

  if (poll(&p, 1, 30000) <= 0) {
    return -1;
  }
  return accept(listener, NULL, NULL);
}

static int connect_to(const Options * o) {
  struct sockaddr_in addr;
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if (fd < 0) {
    return -1;
  }
  fill_addr(o, &addr);
  for (int attempt = 0; attempt < 100; attempt++) {
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
      m->id[k].names[0] = o->id[k].name;
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

/**
 * A server's ticket key: drawn here, because the library draws none (session.h).
 * @p key holds the last one; @p fresh asks for new bytes, and without it the
 * bytes stay and only the name is new.
 */
static int draw_ticket_key(const Options * o, GTLS_TicketKey * key, int fresh) {
  if (gsec_random_bytes(key->name, sizeof key->name, NULL) != GSEC_OK ||
      (fresh && gsec_random_bytes(key->key, sizeof key->key, NULL) != GSEC_OK)) {
    return -1;
  }
  key->not_before = o->now - 60;
  key->not_after = o->now + 86400;
  return 0;
}

static int build_context(const Options * o, const Material * m, GTLS_TicketKey * ticket_key,
    int fresh_key, GTLS_Context ** context) {
  GTLS_ContextConfig config;
  GTLS_Identity identity[MAX_IDS];
  size_t chain_lens[MAX_IDS][MAX_FILES];
  size_t i;

  gtls_context_config_default(&config);
  config.role = o->server ? GTLS_ROLE_SERVER : GTLS_ROLE_CLIENT;
  config.trust = m->trust;
  config.alpn = o->alpn_count != 0 ? o->alpn : NULL;
  config.alpn_count = o->alpn_count;
  config.suites = o->suite_count != 0 ? o->suites : NULL;
  config.suite_count = o->suite_count;
  config.groups = o->group_count != 0 ? o->groups : NULL;
  config.group_count = o->group_count;
  config.sig_algs = o->sig_count != 0 ? o->sigs : NULL;
  config.sig_alg_count = o->sig_count;
  config.middlebox_compat = o->compat;
  config.max_early_data = o->early;
  if (o->server && o->early != 0) {
    g_replay.mode = o->replay;
    config.anti_replay = replay_decision;
  }
  if (o->server) {
    size_t k;

    for (k = 0; k < o->id_count; k++) {
      for (i = 0; i < o->id[k].chain_count; i++) {
        chain_lens[k][i] = m->id[k].lens[i];
      }
      memset(&identity[k], 0, sizeof identity[k]);
      identity[k].chain = m->id[k].chain;
      identity[k].chain_lens = chain_lens[k];
      identity[k].chain_count = o->id[k].chain_count;
      identity[k].key = m->id[k].key;
      identity[k].names = o->id[k].name != NULL ? m->id[k].names : NULL;
      identity[k].name_count = o->id[k].name != NULL ? 1u : 0u;
    }
    config.identities = identity;
    config.identity_count = o->id_count;
    if (o->tickets != 0) {
      if (draw_ticket_key(o, ticket_key, fresh_key) != 0) {
        return -1;
      }
      config.ticket_keys = ticket_key;
      config.ticket_key_count = 1;
      config.ticket_count = o->tickets;
      config.ticket_lifetime = o->ticket_lifetime;
    } else {
      config.ticket_count = 0;
    }
  }
  return gtls_context_new(NULL, &config, context) == GTLS_OK ? 0 : -1;
}

/** Where @p text occurs in @p data, or NULL. */
static const char * find_text(const char * data, size_t len, const char * text) {
  size_t n = strlen(text);
  size_t i;

  for (i = 0; i + n <= len; i++) {
    if (memcmp(data + i, text, n) == 0) {
      return data + i;
    }
  }
  return NULL;
}

/** The expected echo has come, and the newline after it (data the client sent again may precede it). */
static int echo_arrived(const char * data, size_t len, const char * expect) {
  const char * at = find_text(data, len, expect);

  return at != NULL && (size_t)(at - data) + strlen(expect) < len;
}

/**
 * One connection, from the handshake to the close. A client sends its line and
 * waits for the echo; a server echoes until the peer closes. A client that is
 * asked to keep a session waits for the server's tickets too, and hands the
 * first back in @p keep. Prints the `ok` line. Returns 0 on success.
 */
static int run_connection(const Options * o, GTLS_Context * context, int fd, int64_t now,
    const GTLS_Session * offer, GTLS_Session ** keep) {
  GTLS_Conn * conn = NULL;
  unsigned char buf[16384];
  unsigned char echo[65536];
  size_t echo_len = 0;
  size_t sent_message = 0;
  char received[4096];
  size_t received_len = 0;
  unsigned char early_got[4096];
  size_t early_len = 0;
  size_t resent = 0;
  int status = 1;
  int closed = 0;

  if (o->server ? gtls_conn_new_server(context, &conn) != GTLS_OK
                : gtls_conn_new(context, o->server_name, strlen(o->server_name), &conn) != GTLS_OK) {
    fprintf(stderr, "failed\ncould not make the connection\n");
    return 1;
  }
  if (offer != NULL && gtls_conn_set_session(conn, offer, now) != GTLS_OK) {
    fprintf(stderr, "failed\nthe session was refused\n");
    goto done;
  }
  if (gtls_conn_start(conn) != GTLS_OK) {
    goto done;
  }
  if (!o->server && offer != NULL && o->early_text != NULL) {
    size_t w = 0;

    if (gtls_conn_write_early(conn, o->early_text, strlen(o->early_text), &w) != GTLS_OK ||
        w != strlen(o->early_text)) {
      fprintf(stderr, "failed\nthe early data was refused locally\n");
      goto done;
    }
  }

  for (;;) {
    struct pollfd p;
    ssize_t n;
    size_t off;

    if (flush_out(conn, fd) != 0 && !gtls_conn_is_failed(conn)) {
      fprintf(stderr, "failed\nwrite error\n");
      goto done;
    }
    if (gtls_conn_is_failed(conn)) {
      report_failure(conn);
      goto done;
    }
    if (!o->server && gtls_conn_is_connected(conn) && sent_message == 0) {
      size_t w = 0;
      size_t len = strlen(o->message);

      /* Early data the server refused is sent again, as ordinary data, ahead of the line. */
      if (offer != NULL && o->early_text != NULL) {
        GTLS_EarlyStatus st = GTLS_EARLY_NONE;
        unsigned char back[4096];
        size_t k = 0;

        (void)gtls_conn_early_status(conn, &st);
        if (st == GTLS_EARLY_REJECTED && gtls_conn_early_resend(conn, back, sizeof back, &k) == GTLS_OK &&
            k != 0) {
          if (gtls_conn_write(conn, back, k, &w) != GTLS_OK || w != k) {
            fprintf(stderr, "failed\nwrite refused\n");
            goto done;
          }
          resent = k;
        }
      }

      if (gtls_conn_write(conn, o->message, len, &w) != GTLS_OK || w != len ||
          gtls_conn_write(conn, "\n", 1, &w) != GTLS_OK) {
        fprintf(stderr, "failed\nwrite refused\n");
        goto done;
      }
      sent_message = 1;
      if (o->key_update && gtls_conn_key_update(conn, 1) != GTLS_OK) {
        fprintf(stderr, "failed\nkey update refused\n");
        goto done;
      }
      if (o->key_update) {
        /* data under the new key, to see the peer took it */
        if (gtls_conn_write(conn, o->message, len, &w) != GTLS_OK ||
            gtls_conn_write(conn, "\n", 1, &w) != GTLS_OK) {
          fprintf(stderr, "failed\nwrite refused\n");
          goto done;
        }
      }
      continue;
    }
    if (o->server && echo_len > 0) {
      size_t w = 0;

      if (gtls_conn_write(conn, echo, echo_len, &w) != GTLS_OK) {
        fprintf(stderr, "failed\nwrite refused\n");
        goto done;
      }
      memmove(echo, echo + w, echo_len - w);
      echo_len -= w;
      continue;
    }
    if (o->server && gtls_conn_peer_closed(conn) && !closed && echo_len == 0) {
      (void)gtls_conn_close(conn);
      closed = 1;
      (void)flush_out(conn, fd);
      break;
    }
    if (!o->server && sent_message && !closed &&
        (o->no_echo || echo_arrived(received, received_len, o->expect)) &&
        (keep == NULL || gtls_conn_session_count(conn) > 0)) {
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
      goto done;
    }
    n = recv(fd, buf, sizeof buf, 0);
    if (n <= 0) {
      GTLS_Result r = gtls_conn_stream_eof(conn);

      if (r == GTLS_OK) {
        break;
      }
      fprintf(stderr, "failed\n%s\n", gtls_result_string(r));
      goto done;
    }
    off = 0;
    while (off < (size_t)n) {
      size_t used = 0;
      GTLS_Result r = gtls_conn_stream_feed(conn, buf + off, (size_t)n - off, now, &used);

      off += used;
      if (o->server) {
        for (;;) {
          size_t k = 0;

          if (gtls_conn_read_early(conn, early_got + early_len, sizeof early_got - early_len, &k) != GTLS_OK ||
              k == 0) {
            break;
          }
          early_len += k;
        }
      }
      for (;;) {
        size_t k = 0;

        if (gtls_conn_read(conn, o->server ? echo + echo_len : (unsigned char *)received + received_len,
                o->server ? sizeof echo - echo_len : sizeof received - received_len - 1u, &k) != GTLS_OK ||
            k == 0) {
          break;
        }
        if (o->server) {
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
      goto done;
    }
  }
  /* The client has what it asked for: check it and say what was negotiated. */
  if (!o->server) {
    size_t want = strlen(o->expect);

    received[received_len] = 0;
    if (!o->no_echo && (received_len < want || find_text(received, received_len, o->expect) == NULL)) {
      fprintf(stderr, "failed\nthe echo was not what was sent: got %zu bytes\n", received_len);
      goto done;
    }
  }
  if (keep != NULL && gtls_conn_session_count(conn) > 0 &&
      gtls_conn_session(conn, 0, keep) != GTLS_OK) {
    fprintf(stderr, "failed\nthe session could not be kept\n");
    goto done;
  }
  {
    const unsigned char * alpn = NULL;
    size_t alpn_len = 0;

    GTLS_EarlyStatus early_status = GTLS_EARLY_NONE;
    size_t at;

    (void)gtls_conn_alpn(conn, &alpn, &alpn_len);
    (void)gtls_conn_early_status(conn, &early_status);
    printf("ok suite=%04x group=%04x alpn=%.*s retried=%d resumed=%d sessions=%zu offered=%d"
           " early=%d early_len=%zu replay=%u resent=%zu early_hex=",
        (unsigned)gtls_conn_suite(conn), (unsigned)gtls_conn_group(conn), (int)alpn_len,
        alpn != NULL ? (const char *)alpn : "", gtls_conn_retried(conn), gtls_conn_resumed(conn),
        gtls_conn_session_count(conn), offer != NULL, (int)early_status, early_len, g_replay.calls, resent);
    for (at = 0; at < early_len; at++) {
      printf("%02x", early_got[at]);
    }
    printf("\n");
    fflush(stdout);
  }
  status = 0;
done:
  gtls_conn_free(conn);
  return status;
}

int main(int argc, char ** argv) {
  Options o;
  Material m;
  GTLS_Context * context = NULL;
  GTLS_Session * session = NULL;
  GTLS_TicketKey ticket_key;
  int listener = -1;
  int status = 1;
  unsigned n;

  if (parse_options(argc, argv, &o) != 0) {
    fprintf(stderr, "usage: echo server [options] PORT | echo client [options] HOST PORT (see the file comment)\n");
    return 2;
  }
  if (load_material(&o, &m) != 0) {
    free_material(&m);
    return fail("could not load the certificates or the key");
  }
  memset(&ticket_key, 0, sizeof ticket_key);
  if (build_context(&o, &m, &ticket_key, 1, &context) != 0) {
    free_material(&m);
    return fail("could not make the context");
  }
  if (o.server) {
    listener = listen_on(&o);
    if (listener < 0) {
      fprintf(stderr, "failed\ncould not open the socket\n");
      goto out;
    }
  }
  for (n = 0; n < (o.server ? o.connections : (o.resume ? 1u + o.resumes : 1u)); n++) {
    int64_t now = o.now + (n > 0 ? o.advance : 0);
    int fd;
    int result;

    if (o.server && n > 0 && (o.rekey || o.rename_key)) {
      /* The next context has a key of its own, or the same bytes under a new name:
       * what the last one sealed no longer opens. */
      gtls_context_free(context);
      context = NULL;
      if (build_context(&o, &m, &ticket_key, o.rekey, &context) != 0) {
        fprintf(stderr, "failed\ncould not make the context\n");
        goto out;
      }
    }
    if (!o.server && n > 0 && o.gate != NULL) {
      /* Whoever started the next server says when it is listening. */
      int waited;

      for (waited = 0; waited < 400 && access(o.gate, F_OK) != 0; waited++) {
        struct timespec ts = {0, 50 * 1000 * 1000};

        nanosleep(&ts, NULL);
      }
    }
    fd = o.server ? accept_on(listener) : connect_to(&o);
    if (fd < 0) {
      fprintf(stderr, "failed\ncould not open the socket\n");
      goto out;
    }
    result = run_connection(&o, context, fd, now, n > 0 ? session : NULL,
        (!o.server && o.resume && n == 0) ? &session : NULL);
    close(fd);
    if (result != 0) {
      goto out;
    }
    if (!o.server && o.resume && n == 0 && session == NULL) {
      fprintf(stderr, "failed\nthe server sent no ticket\n");
      goto out;
    }
  }
  status = 0;
out:
  if (listener >= 0) {
    close(listener);
  }
  memset(&ticket_key, 0, sizeof ticket_key);
  gtls_session_free(session);
  gtls_context_free(context);
  free_material(&m);
  return status;
}

#endif
