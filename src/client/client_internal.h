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
#include "../record/record_internal.h"
#include "../schedule/schedule_internal.h"
#include "../session/session_internal.h"

/** The most a ClientHello can come to, header included, and so the most a server accepts. */
#define GTLS_HELLO_MAX 65540u
#define GTLS_ALPN_WIRE_MAX 1024u
#define GTLS_SIG_ALGS_MAX 16u

/**
 * One identity a server presents: a chain it owns a copy of, the key that
 * signs for it (borrowed from the caller, who keeps it alive), and the names
 * it is chosen for.
 */
typedef struct GTLS_ServerIdentity {
  unsigned char * chain;          /* the DER certificates, back to back */
  size_t * chain_len;             /* chain_count entries */
  size_t chain_count;
  size_t chain_bytes;
  const GCERT_Key * key;
  uint32_t key_kind;
  unsigned char * names;          /* the names, back to back, lower-cased */
  size_t * name_len;              /* name_count entries */
  size_t name_count;
} GTLS_ServerIdentity;

struct GTLS_Context {
  const GTLS_Allocator * allocator;
  GTLS_Role role;
  unsigned versions;
  const GCERT_TrustStore * trust;
  GTLS_ServerIdentity * identities;
  size_t identity_count;
  size_t default_identity;
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
  /* A server's tickets. */
  GTLS_TicketKey ticket_keys[GTLS_TICKET_KEYS_MAX];
  size_t ticket_key_count;
  unsigned ticket_count;            /* sent after each handshake; 0 sends none */
  uint32_t ticket_lifetime;         /* seconds */
  uint32_t ticket_age_window;       /* seconds */
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
  /* The server's side of the same table, RFC 8446 appendix A.2. */
  GTLS_STATE_S_WAIT_CH,     /* started; wants the first ClientHello */
  GTLS_STATE_S_WAIT_CH2,    /* HelloRetryRequest sent; wants the second ClientHello */
  GTLS_STATE_S_WAIT_FIN,    /* flight sent; wants the client's Finished */
  GTLS_STATE_COUNT
} GTLS_State;

/** Everything secret a connection holds, in one place so one call wipes it. */
typedef struct GTLS_Secrets {
  GTLS_Transcript transcript;
  GTLS_Schedule schedule;
  unsigned char x25519[32];
  unsigned char p256[32];
  unsigned char p384[48];
  /* The record layer's keys and the traffic secrets they came from (the
   * latter are what a key update advances). */
  GTLS_RecordKeys rd;
  GTLS_RecordKeys wr;
  unsigned char rd_secret[GTLS_HASH_MAX];
  unsigned char wr_secret[GTLS_HASH_MAX];
} GTLS_Secrets;

typedef GTLS_Result (*GTLS_RandomFn)(void * user, void * out, size_t n);
typedef GTLS_Result (*GTLS_ChainFn)(void * user, const GTLS_Conn * conn,
    const GTLS_CertificateMsg * certificate, int64_t unix_time);
/** A signature over @p content for CertificateVerify, in place of the identity's key. */
typedef GTLS_Result (*GTLS_SignFn)(void * user, const GTLS_Conn * conn,
    unsigned scheme, const unsigned char * content, size_t content_len,
    unsigned char * out, size_t cap, size_t * out_len);

/** Which interface a connection is driven through; the first call decides. */
typedef enum GTLS_Mode {
  GTLS_MODE_NONE = 0,
  GTLS_MODE_MESSAGE = 1,  /* gtls_conn_feed / pending_output: handshake messages by epoch */
  GTLS_MODE_STREAM = 2    /* gtls_conn_stream_*: records over a byte stream */
} GTLS_Mode;

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
  /* Server-side test seams, see gtls_conn_set_server_hooks. */
  GTLS_SignFn sign_fn;
  void * sign_user;
  const unsigned char * seam_ee_prefix;
  size_t seam_ee_prefix_len;
  const unsigned char * const * seam_chain;
  const size_t * seam_chain_len;
  size_t seam_chain_count;
  unsigned seam_scheme;

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

  /* The server's choices. */
  GTLS_Role role;
  size_t identity_index;
  unsigned scheme;                  /* the CertificateVerify scheme chosen */
  int sni_matched;
  unsigned char * client_sni;       /* the host_name the client sent */
  size_t client_sni_len;

  /* The record layer. */
  GTLS_Mode mode;
  GTLS_Buf rbuf;                    /* the record being assembled, header included */
  GTLS_Buf wire;                    /* records waiting to be sent */
  GTLS_Buf app_in;                  /* decrypted application data not yet read */
  GTLS_Epoch rd_epoch;              /* the epoch of the installed read keys */
  GTLS_Epoch wr_epoch;              /* the epoch of the installed write keys */
  int ccs_sent;
  unsigned ccs_seen;
  int early_skip;             /* server: the first ClientHello offered early_data, which is not accepted, so the records that do not decrypt are skipped */
  size_t early_skipped;       /* server: bytes of records skipped so far */
  int hello_flushed;                /* the first ClientHello has gone out */
  int peer_closed;                  /* close_notify received */
  int local_closed;                 /* close_notify sent */
  unsigned peer_alert;
  unsigned key_updates;             /* KeyUpdates received, in all */
  unsigned ku_run;                  /* ... since application data last arrived */
  unsigned ku_queued;               /* KeyUpdate messages queued, not yet sealed */

  /* Resumption. */
  int resumed;                      /* the handshake is an abbreviated one */
  GTLS_Session * offer;             /* client: the session on offer in the ClientHello in flight, until the ServerHello decides (NULL: none is) */
  int64_t offer_time;               /* client: the second it was handed over */
  GTLS_Session ** sessions;         /* client: the sessions the server has sent */
  size_t session_count;
  size_t session_cap;
};

/* ------------------------------------------------ shared by the two roles */

/** Fail the connection: record the reason and alert, send the alert, wipe. */
GTLS_Result gtls_conn_fail(GTLS_Conn * c, GTLS_Result result, unsigned alert);
/** Failure of a parser or a buffer, with the alert its result calls for. */
GTLS_Result gtls_conn_fail_parse(GTLS_Conn * c, GTLS_Result result);
GTLS_Result gtls_conn_illegal(GTLS_Conn * c);
GTLS_Result gtls_conn_unexpected(GTLS_Conn * c);
/** Queue handshake bytes at @p epoch; a full queue fails the connection. */
GTLS_Result gtls_conn_queue(GTLS_Conn * c, GTLS_Epoch epoch, const void * data,
    size_t n);
/** Random bytes from the seam or the kernel generator. */
GTLS_Result gtls_conn_draw(GTLS_Conn * c, void * out, size_t n);
/** An ephemeral key pair in @p group; the private half is kept in the secrets. */
GTLS_Result gtls_conn_gen_share(GTLS_Conn * c, GTLS_Group group,
    GTLS_KeyShare * share);
/** The shared secret with a peer's share in @p group. */
GTLS_Result gtls_conn_shared_secret(GTLS_Conn * c, GTLS_Group group,
    const unsigned char * kx, size_t kx_len, unsigned char * out,
    size_t * out_len);
/** Wipe the ephemeral private keys. */
void gtls_conn_wipe_kx(GTLS_Conn * c);
/** The connection's limits with the cap on extensions lifted, for parsing our own messages. */
GTLS_Limits gtls_conn_own_limits(const GTLS_Conn * c);
/** The common part of making a connection. */
GTLS_Result gtls_conn_alloc(const GTLS_Context * context, GTLS_Conn ** out);
/** The epoch the next bytes received must be tagged with, in this state. */
GTLS_Epoch gtls_conn_expected_epoch(GTLS_State state);

/**
 * The bytes CertificateVerify signs (RFC 8446 section 4.4.3): 64 spaces, the
 * context string for @p server (1) or the client (0), a zero byte, and the
 * transcript hash @p th of @p hlen bytes. @p out holds at least
 * ::GTLS_CV_CONTENT_MAX. The client verifies over it and the server signs
 * over it, so the string is written once.
 */
/** 1 for a scheme TLS 1.3 allows in CertificateVerify, which has no PKCS#1 and no SHA-1. */
int gtls_cv_scheme_ok(unsigned scheme);

#define GTLS_CV_CONTENT_MAX (64u + 34u + 1u + GTLS_HASH_MAX)
size_t gtls_cv_content(int server, const void * th, size_t hlen,
    unsigned char * out);

/** The message state machine, for the stream layer: ::gtls_conn_feed without the mode check. */
GTLS_Result gtls_conn_feed_stream(GTLS_Conn * c, GTLS_Epoch epoch,
    const void * data, size_t len, int64_t unix_time);

/** Handle one message in the server's table; see server.c. */
GTLS_Result gtls_server_on_message(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now);
/** Start a server: arm it for the first ClientHello. */
GTLS_Result gtls_server_start(GTLS_Conn * c);
/** Handle a KeyUpdate received in stream mode; see stream.c. */
GTLS_Result gtls_conn_on_key_update(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len);
/** Free the record layer's buffers. */
void gtls_stream_free(GTLS_Conn * c);
/** Turn queued handshake output into records. A failed connection sends nothing more. */
GTLS_Result gtls_stream_flush(GTLS_Conn * c);
/** Seal and queue @p alert under the keys in use; for failure, best effort. */
GTLS_Result gtls_stream_send_alert(GTLS_Conn * c, unsigned level, unsigned description);

/** Wipe and free the sessions a connection holds and the one it offered. */
void gtls_conn_drop_sessions(GTLS_Conn * c);

/** The default chain and name check, which is what ships. */
GTLS_Result gtls_verify_chain(void * user, const GTLS_Conn * conn,
    const GTLS_CertificateMsg * certificate, int64_t unix_time);

/**
 * Queue the server's NewSessionTickets for a connected connection (the end of
 * the handshake does it; a test calls it to meet the check that the resumption
 * secret was kept). ::GTLS_ERR_INTERNAL, failing the connection, without it.
 */
GTLS_Result gtls_server_issue_tickets(GTLS_Conn * c, int64_t now);

/** Test seams. See the file comment. */
void gtls_conn_set_hooks(GTLS_Conn * conn, GTLS_RandomFn random_fn,
    void * random_user, GTLS_ChainFn chain_fn, void * chain_user);

/**
 * The server's test seams. RFC 8448's certificate is a 1024-bit RSA key whose
 * private half the RFC does not print, and its CertificateVerify is an
 * RSA-PSS signature with a salt this library cannot be told to reuse; its
 * EncryptedExtensions carries extensions the server does not send. So a test
 * of the server against that trace supplies: the chain to send in place of
 * an identity's, the scheme to name, a signer that stands in for the key
 * (and which the test uses to check the RFC's signature against the content
 * the server built), and extensions to put before its own. Everything else,
 * the transcript, the schedule, the Finished, is the shipped code.
 */
void gtls_conn_set_server_hooks(GTLS_Conn * conn, GTLS_SignFn sign_fn,
    void * sign_user, const unsigned char * const * chain,
    const size_t * chain_len, size_t chain_count, unsigned scheme,
    const unsigned char * ee_prefix, size_t ee_prefix_len);

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
