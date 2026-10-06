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
 * @file client_internal.h
 *
 * The context and connection objects, and the seams tests use.
 *
 * The seams are declared here and nowhere in include/, so the shipped
 * library neither exports them nor lets a caller set them. They exist for
 * two reasons. RFC 8448's server certificate is a 1024-bit RSA key in a
 * certificate that says it is not a CA, which a real chain check rightly
 * refuses, so the known-answer test has to supply its own verdict on the
 * chain; and the trace's ClientHello is not the one this library builds, so
 * the test hands over those bytes and the keys that go with them. Everything
 * after those two substitutions is the code that ships. A test that wants
 * the real chain check does not set the seam, and the default is the only
 * one a caller can reach.
 */

#ifndef GHOTI_IO_GTLS_SRC_CLIENT_CLIENT_INTERNAL_H
#define GHOTI_IO_GTLS_SRC_CLIENT_CLIENT_INTERNAL_H

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/conn.h>
#include <ghoti.io/tls/context.h>

#include "../msg/msg_internal.h"
#include "../schedule/schedule_internal.h"

#define GTLS_ALPN_WIRE_MAX 1024u
#define GTLS_SIG_ALGS_MAX 16u

struct GTLS_Context {
  const GTLS_Allocator * allocator;
  GTLS_Role role;
  unsigned versions;
  const GCERT_TrustStore * trust;
  GTLS_Suite suites[3];
  size_t suite_count;
  GTLS_Group groups[3];
  size_t group_count;
  GCERT_SigScheme sig_algs[GTLS_SIG_ALGS_MAX];
  size_t sig_alg_count;
  unsigned char alpn[GTLS_ALPN_WIRE_MAX];
  size_t alpn_len;
  int middlebox_compat;
  GTLS_Limits limits;
};

/**
 * The states of the client's table, RFC 8446 appendix A.1. The denominator of
 * the state-machine fuzzer is this list.
 */
typedef enum GTLS_State {
  GTLS_STATE_NEW = 0,       /* made, ClientHello not yet built */
  GTLS_STATE_WAIT_SH,       /* ClientHello sent; wants ServerHello or HRR */
  GTLS_STATE_WAIT_SH2,      /* HelloRetryRequest answered; wants ServerHello */
  GTLS_STATE_WAIT_EE,       /* wants EncryptedExtensions */
  GTLS_STATE_WAIT_CERT,     /* wants Certificate */
  GTLS_STATE_WAIT_CV,       /* wants CertificateVerify */
  GTLS_STATE_WAIT_FIN,      /* wants the server's Finished */
  GTLS_STATE_CONNECTED,     /* handshake complete; NewSessionTicket only */
  GTLS_STATE_FAILED,        /* terminal */
  GTLS_STATE_COUNT
} GTLS_State;

/** Everything secret a connection holds, in one place so one call wipes it. */
typedef struct GTLS_Secrets {
  GTLS_Transcript transcript;
  GTLS_Schedule schedule;
  unsigned char x25519[32];
  unsigned char p256[32];
  unsigned char p384[48];
} GTLS_Secrets;

typedef GTLS_Result (*GTLS_RandomFn)(void * user, void * out, size_t n);
typedef GTLS_Result (*GTLS_ChainFn)(void * user, const GTLS_Conn * conn,
    const GTLS_CertificateMsg * certificate, int64_t unix_time);

struct GTLS_Conn {
  const GTLS_Context * context;
  const GTLS_Allocator * allocator;
  GTLS_State state;
  GTLS_Result failure;
  unsigned alert;
  unsigned char * host;
  size_t host_len;
  int host_is_ip;

  GTLS_RandomFn random_fn;
  void * random_user;
  GTLS_ChainFn chain_fn;
  void * chain_user;

  GTLS_Suite suite;
  GTLS_Group group;           /* the group the server's share is in */
  GTLS_Group share_group;     /* the group of the share last sent */
  GTLS_Group hrr_group;
  int retried;

  GTLS_Buf in;                /* the message being assembled, header included */
  GTLS_Buf out[GTLS_EPOCH_COUNT];
  GTLS_Buf hello;             /* the first ClientHello, whole message */
  unsigned char session_id[32];
  size_t session_id_len;
  size_t hs_total;
  unsigned tickets;

  GTLS_Secrets sec;

  unsigned char alpn_selected[255];
  size_t alpn_selected_len;
  int sni_acknowledged;
  unsigned char * leaf;
  size_t leaf_len;
  GTLS_Limits limits;
};

/** The default chain and name check, which is what ships. */
GTLS_Result gtls_verify_chain(void * user, const GTLS_Conn * conn,
    const GTLS_CertificateMsg * certificate, int64_t unix_time);

/** Test seams. See the file comment. */
void gtls_conn_set_hooks(GTLS_Conn * conn, GTLS_RandomFn random_fn,
    void * random_user, GTLS_ChainFn chain_fn, void * chain_user);

/**
 * Start with a ClientHello someone else built (RFC 8448's), and the X25519
 * private key whose public half is in it.
 */
GTLS_Result gtls_conn_start_raw(GTLS_Conn * conn, const void * hello,
    size_t hello_len, const void * x25519_private);

/** The internal state, for the state-table tests. */
GTLS_State gtls_conn_state(const GTLS_Conn * conn);

/** Which secret to read out for tests. */
typedef enum GTLS_SecretId {
  GTLS_SECRET_EARLY = 0,
  GTLS_SECRET_HANDSHAKE,
  GTLS_SECRET_MASTER,
  GTLS_SECRET_CLIENT_HS,
  GTLS_SECRET_SERVER_HS,
  GTLS_SECRET_CLIENT_AP,
  GTLS_SECRET_SERVER_AP
} GTLS_SecretId;

/** Copy out one of the schedule's secrets; the digest length is in @p len. */
GTLS_Result gtls_conn_debug_secret(const GTLS_Conn * conn, GTLS_SecretId id,
    void * out, size_t cap, size_t * len);

/** 1 when every byte of the connection's secrets is zero. */
int gtls_conn_secrets_are_wiped(const GTLS_Conn * conn);

/** The transcript hash so far, under the connection's hash. */
GTLS_Result gtls_conn_debug_transcript(const GTLS_Conn * conn, void * out,
    size_t cap, size_t * len);

#endif /* GHOTI_IO_GTLS_SRC_CLIENT_CLIENT_INTERNAL_H */
