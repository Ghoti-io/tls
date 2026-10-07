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
 * @file msg_internal.h
 *
 * Handshake messages: a bounded byte buffer, a bounds-checked reader, the
 * ClientHello builder, and a parser for each message a TLS 1.3 client can
 * receive (RFC 8446 section 4).
 *
 * Every parser takes the message body without its 4-byte header, writes its
 * result only on success, and points into its input rather than copying. A
 * length that runs past the end of the data, a vector outside its stated
 * bounds, or trailing bytes is ::GTLS_ERR_CORRUPT; a duplicate extension is
 * ::GTLS_ERR_PROTOCOL; a peer-controlled size past a ::GTLS_Limits cap is
 * ::GTLS_ERR_LIMIT.
 */

#ifndef GHOTI_IO_GTLS_SRC_MSG_MSG_INTERNAL_H
#define GHOTI_IO_GTLS_SRC_MSG_MSG_INTERNAL_H

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/context.h>
#include <ghoti.io/tls/core.h>

#include <stddef.h>
#include <stdint.h>

/* Handshake message types, RFC 8446 section 4. */
#define GTLS_HS_CLIENT_HELLO 1u
#define GTLS_HS_SERVER_HELLO 2u
#define GTLS_HS_NEW_SESSION_TICKET 4u
#define GTLS_HS_END_OF_EARLY_DATA 5u
#define GTLS_HS_ENCRYPTED_EXTENSIONS 8u
#define GTLS_HS_CERTIFICATE 11u
#define GTLS_HS_CERTIFICATE_REQUEST 13u
#define GTLS_HS_CERTIFICATE_VERIFY 15u
#define GTLS_HS_FINISHED 20u
#define GTLS_HS_KEY_UPDATE 24u
#define GTLS_HS_MESSAGE_HASH 254u

/* Extension types, RFC 8446 section 4.2 and the registry. */
#define GTLS_EXT_SERVER_NAME 0u
#define GTLS_EXT_MAX_FRAGMENT_LENGTH 1u
#define GTLS_EXT_STATUS_REQUEST 5u
#define GTLS_EXT_SUPPORTED_GROUPS 10u
#define GTLS_EXT_SIGNATURE_ALGORITHMS 13u
#define GTLS_EXT_USE_SRTP 14u
#define GTLS_EXT_HEARTBEAT 15u
#define GTLS_EXT_ALPN 16u
#define GTLS_EXT_CLIENT_CERT_TYPE 19u
#define GTLS_EXT_SERVER_CERT_TYPE 20u
#define GTLS_EXT_PADDING 21u
#define GTLS_EXT_RECORD_SIZE_LIMIT 28u
#define GTLS_EXT_PRE_SHARED_KEY 41u
#define GTLS_EXT_EARLY_DATA 42u
#define GTLS_EXT_SUPPORTED_VERSIONS 43u
#define GTLS_EXT_COOKIE 44u
#define GTLS_EXT_PSK_KEY_EXCHANGE_MODES 45u
#define GTLS_EXT_KEY_SHARE 51u

/** The most extensions one message is parsed with, whatever the limit says. */
#define GTLS_EXT_MAX 64u

/** The most certificates one Certificate message is parsed with. */
#define GTLS_CERT_MAX 32u

/** A longest key_share entry: a P-384 point in uncompressed form. */
#define GTLS_KX_MAX 97u

/* ------------------------------------------------------------------ buffer */

/**
 * A growing byte buffer with a ceiling. The first failure is remembered in
 * @p err and every later append is a no-op, so a builder can write a whole
 * message and look once at the end.
 */
typedef struct GTLS_Buf {
  unsigned char * data;
  size_t len;
  size_t cap;
  size_t max;
  const GTLS_Allocator * allocator;
  GTLS_Result err;
} GTLS_Buf;

void gtls_buf_init(GTLS_Buf * b, const GTLS_Allocator * allocator, size_t max);
void gtls_buf_free(GTLS_Buf * b);
GTLS_Result gtls_buf_append(GTLS_Buf * b, const void * data, size_t n);
void gtls_buf_u8(GTLS_Buf * b, unsigned v);
void gtls_buf_u16(GTLS_Buf * b, unsigned v);
void gtls_buf_u24(GTLS_Buf * b, unsigned v);
/** Drop the first @p n bytes, keeping the rest. */
void gtls_buf_consume(GTLS_Buf * b, size_t n);
/** Reserve a length field of @p width bytes; returns its offset. */
size_t gtls_buf_begin(GTLS_Buf * b, unsigned width);
/** Fill the length field made by ::gtls_buf_begin with what follows it. */
void gtls_buf_end(GTLS_Buf * b, size_t offset, unsigned width);

/* ------------------------------------------------------------------ reader */

typedef struct GTLS_Reader {
  const unsigned char * p;
  size_t len;
  size_t pos;
} GTLS_Reader;

void gtls_reader_init(GTLS_Reader * r, const void * data, size_t len);
size_t gtls_reader_left(const GTLS_Reader * r);
GTLS_Result gtls_reader_u8(GTLS_Reader * r, unsigned * v);
GTLS_Result gtls_reader_u16(GTLS_Reader * r, unsigned * v);
GTLS_Result gtls_reader_u24(GTLS_Reader * r, unsigned * v);
GTLS_Result gtls_reader_bytes(GTLS_Reader * r, size_t n,
    const unsigned char ** out);
/**
 * A vector with a @p width-byte length prefix, @p min to @p max bytes long
 * (@p max 0 means no upper bound but the prefix). @p sub reads its contents.
 */
GTLS_Result gtls_reader_vector(GTLS_Reader * r, unsigned width, size_t min,
    size_t max, GTLS_Reader * sub);
/** ::GTLS_OK if nothing is left, ::GTLS_ERR_CORRUPT otherwise. */
GTLS_Result gtls_reader_end(const GTLS_Reader * r);

/* -------------------------------------------------------------- extensions */

typedef struct GTLS_Ext {
  uint16_t type;
  const unsigned char * data;
  size_t len;
} GTLS_Ext;

/**
 * Read an extension block (a 2-byte length, then extensions) into @p out.
 * More than @p max_ext, or ::GTLS_EXT_MAX, is ::GTLS_ERR_LIMIT; two of one
 * type is ::GTLS_ERR_PROTOCOL.
 */
GTLS_Result gtls_msg_extensions(GTLS_Reader * r, uint32_t max_ext,
    GTLS_Ext * out, size_t * count);

/** The extension of @p type among @p count, or NULL. */
const GTLS_Ext * gtls_msg_find_ext(const GTLS_Ext * exts, size_t count,
    unsigned type);

/* ------------------------------------------------------------- ClientHello */

/** The fixed-size and vector parts of a ClientHello, as views. */
typedef struct GTLS_ClientHello {
  unsigned legacy_version;
  const unsigned char * random;     /* 32 bytes */
  const unsigned char * session_id;
  size_t session_id_len;
  const unsigned char * suites;     /* 2 bytes each */
  size_t suites_len;
  const unsigned char * compression; /* legacy_compression_methods */
  size_t compression_len;
  size_t prefix_len;                /* body bytes before the extension block */
  GTLS_Ext exts[GTLS_EXT_MAX];
  size_t ext_count;
} GTLS_ClientHello;

/** One key share to offer. @p pub is the key_exchange field as sent. */
typedef struct GTLS_KeyShare {
  uint16_t group;
  unsigned char pub[GTLS_KX_MAX];
  size_t pub_len;
} GTLS_KeyShare;

/** Everything a first ClientHello is built from. */
typedef struct GTLS_HelloParams {
  unsigned char random[32];
  unsigned char session_id[32];
  size_t session_id_len;            /* 0 or 32 */
  const GTLS_Suite * suites;
  size_t suite_count;
  const char * host;                /* SNI; NULL for none */
  size_t host_len;
  const unsigned char * alpn;       /* ProtocolNameList contents */
  size_t alpn_len;
  const GTLS_Group * groups;
  size_t group_count;
  const GCERT_SigScheme * sig_algs;
  size_t sig_alg_count;
  GTLS_KeyShare share;
} GTLS_HelloParams;

/** Build a whole ClientHello message, header included, into @p out. */
GTLS_Result gtls_msg_build_client_hello(const GTLS_HelloParams * params,
    GTLS_Buf * out);

/** Parse a ClientHello body. */
GTLS_Result gtls_msg_parse_client_hello(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_ClientHello * out);

/**
 * Build the second ClientHello from the first (RFC 8446 section 4.1.2): the
 * same, with the key_share replaced by @p share when it is not NULL, a cookie
 * extension carrying @p cookie when @p cookie_len is not 0, and the padding
 * recomputed. @p hello1 is the whole first message, header included.
 *
 * The cookie goes before psk_key_exchange_modes when that extension is there
 * and at the end otherwise; the extension order is otherwise unchanged.
 */
GTLS_Result gtls_msg_retry_client_hello(const void * hello1, size_t hello1_len,
    const GTLS_KeyShare * share, const void * cookie, size_t cookie_len,
    const GTLS_Limits * limits, GTLS_Buf * out);

/* ------------------------------------------------------------- ServerHello */

#define GTLS_SH_FLAG_VERSION 0x01u
#define GTLS_SH_FLAG_KEY_SHARE 0x02u
#define GTLS_SH_FLAG_COOKIE 0x04u
#define GTLS_SH_FLAG_PSK 0x08u
#define GTLS_SH_FLAG_UNKNOWN 0x10u

/** A ServerHello or a HelloRetryRequest; @p is_hrr says which. */
typedef struct GTLS_ServerHello {
  int is_hrr;
  unsigned legacy_version;
  const unsigned char * random;     /* 32 bytes */
  const unsigned char * session_id;
  size_t session_id_len;
  unsigned suite;
  unsigned compression;
  unsigned flags;                   /* GTLS_SH_FLAG_* */
  unsigned selected_version;
  unsigned group;                   /* key_share: the group chosen */
  const unsigned char * key_exchange; /* the server's share; unused in an HRR */
  size_t key_exchange_len;
  const unsigned char * cookie;
  size_t cookie_len;
  unsigned unknown_ext;             /* first extension type not understood */
} GTLS_ServerHello;

/** 1 when @p random is the fixed value that marks a HelloRetryRequest. */
int gtls_msg_is_hrr_random(const unsigned char * random);

/** 1 when @p random ends in a downgrade sentinel, 2 for TLS 1.2's, 3 for 1.1's. */
int gtls_msg_downgrade_sentinel(const unsigned char * random);

GTLS_Result gtls_msg_parse_server_hello(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_ServerHello * out);

/* -------------------------------------------------- EncryptedExtensions etc. */

typedef struct GTLS_EncryptedExtensions {
  GTLS_Ext exts[GTLS_EXT_MAX];
  size_t ext_count;
  int has_alpn;
  const unsigned char * alpn;       /* the one protocol name */
  size_t alpn_len;
  int has_server_name;
} GTLS_EncryptedExtensions;

GTLS_Result gtls_msg_parse_encrypted_extensions(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_EncryptedExtensions * out);

typedef struct GTLS_CertificateMsg {
  const unsigned char * context;
  size_t context_len;
  const unsigned char * der[GTLS_CERT_MAX];
  size_t der_len[GTLS_CERT_MAX];
  size_t count;
  int has_entry_extensions;
} GTLS_CertificateMsg;

GTLS_Result gtls_msg_parse_certificate(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_CertificateMsg * out);

typedef struct GTLS_CertificateVerifyMsg {
  unsigned scheme;
  const unsigned char * signature;
  size_t signature_len;
} GTLS_CertificateVerifyMsg;

GTLS_Result gtls_msg_parse_certificate_verify(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_CertificateVerifyMsg * out);

typedef struct GTLS_NewSessionTicket {
  uint32_t lifetime;
  uint32_t age_add;
  const unsigned char * nonce;
  size_t nonce_len;
  const unsigned char * ticket;
  size_t ticket_len;
  int early_data;
  uint32_t max_early_data;
} GTLS_NewSessionTicket;

GTLS_Result gtls_msg_parse_new_session_ticket(const void * body, size_t len,
    const GTLS_Limits * limits, GTLS_NewSessionTicket * out);

/* ------------------------------------------- ClientHello, as a server reads it */

/** Most entries read out of one list in a ClientHello extension; more is ::GTLS_ERR_LIMIT. */
#define GTLS_CH_LIST_MAX 128u
/** Most key shares read out of one ClientHello. */
#define GTLS_CH_SHARES_MAX 16u
/** Most ALPN protocol names read out of one ClientHello. */
#define GTLS_CH_NAMES_MAX 64u

/** One protocol name or host name, a view into the message. */
typedef struct GTLS_Name {
  const unsigned char * p;
  size_t len;
} GTLS_Name;

/** One entry of a client's key_share extension, a view into the message. */
typedef struct GTLS_ClientShare {
  unsigned group;
  const unsigned char * kx;
  size_t kx_len;
} GTLS_ClientShare;

/**
 * supported_versions in a ClientHello (RFC 8446 section 4.2.1): a one-byte
 * length of 2 to 254 and then 16-bit versions. @p has_tls13 is set when
 * 0x0304 is among them. Odd lengths, empty lists and trailing bytes are
 * ::GTLS_ERR_CORRUPT.
 */
GTLS_Result gtls_msg_parse_ch_versions(const GTLS_Ext * e, int * has_tls13);

/**
 * A u16-length-prefixed list of 16-bit values: supported_groups (section
 * 4.2.7) or signature_algorithms (section 4.2.3). At most @p cap values are
 * stored; more than ::GTLS_CH_LIST_MAX is ::GTLS_ERR_LIMIT, an odd length or
 * an empty list ::GTLS_ERR_CORRUPT.
 */
GTLS_Result gtls_msg_parse_ch_u16_list(const GTLS_Ext * e, uint16_t * out,
    size_t cap, size_t * count);

/**
 * key_share in a ClientHello (section 4.2.8): a list of (group, key
 * exchange). More than ::GTLS_CH_SHARES_MAX entries is ::GTLS_ERR_LIMIT; two
 * for one group is ::GTLS_ERR_PROTOCOL (illegal_parameter). The list may be
 * empty: the client is then asking for a HelloRetryRequest.
 */
GTLS_Result gtls_msg_parse_ch_key_shares(const GTLS_Ext * e,
    GTLS_ClientShare * out, size_t * count);

/**
 * ALPN in a ClientHello (RFC 7301): a list of one-byte-length names, each
 * 1 to 255 bytes. More than ::GTLS_CH_NAMES_MAX is ::GTLS_ERR_LIMIT; an empty
 * list or an empty name is ::GTLS_ERR_CORRUPT.
 */
GTLS_Result gtls_msg_parse_ch_alpn(const GTLS_Ext * e, GTLS_Name * out,
    size_t * count);

/**
 * server_name in a ClientHello (RFC 6066 section 3): the first host_name
 * entry, or none when the list carries only other types. A second host_name
 * is ::GTLS_ERR_PROTOCOL (the RFC allows one of each type). @p host is empty
 * (length 0) when there is no host_name. An empty host name is
 * ::GTLS_ERR_CORRUPT.
 */
GTLS_Result gtls_msg_parse_ch_server_name(const GTLS_Ext * e, GTLS_Name * host);

/** cookie (section 4.2.2): a u16-length-prefixed opaque of 1 to 65535 bytes. */
GTLS_Result gtls_msg_parse_ch_cookie(const GTLS_Ext * e, GTLS_Name * cookie);

/**
 * psk_key_exchange_modes (section 4.2.9): a one-byte-length list of 1 to 255
 * one-byte modes. @p has_dhe_ke is set when psk_dhe_ke (1) is in it.
 */
GTLS_Result gtls_msg_parse_ch_psk_modes(const GTLS_Ext * e, int * has_dhe_ke);

/* ----------------------------------------------- what a server sends */

/** Everything a ServerHello or a HelloRetryRequest is built from. */
typedef struct GTLS_ServerHelloParams {
  int is_hrr;                       /* build a HelloRetryRequest */
  unsigned char random[32];         /* ignored for an HRR, which has a fixed one */
  const unsigned char * session_id; /* echoed from the ClientHello */
  size_t session_id_len;
  unsigned suite;
  unsigned group;                   /* the key_share group */
  const unsigned char * key_exchange; /* the server's share; unused in an HRR */
  size_t key_exchange_len;
  const unsigned char * cookie;     /* HRR only; NULL for none */
  size_t cookie_len;
} GTLS_ServerHelloParams;

/** Build a whole ServerHello or HelloRetryRequest, header included. */
GTLS_Result gtls_msg_build_server_hello(const GTLS_ServerHelloParams * params,
    GTLS_Buf * out);

/** What an EncryptedExtensions message carries. */
typedef struct GTLS_EeParams {
  const unsigned char * prefix;     /* whole extensions to put first (test seam); NULL for none */
  size_t prefix_len;
  int ack_server_name;              /* an empty server_name extension */
  const unsigned char * alpn;       /* the one protocol chosen; NULL for none */
  size_t alpn_len;
} GTLS_EeParams;

GTLS_Result gtls_msg_build_encrypted_extensions(const GTLS_EeParams * params,
    GTLS_Buf * out);

/** A Certificate with an empty request context and no entry extensions. */
GTLS_Result gtls_msg_build_certificate(const unsigned char * const * der,
    const size_t * der_len, size_t count, GTLS_Buf * out);

GTLS_Result gtls_msg_build_certificate_verify(unsigned scheme,
    const void * signature, size_t signature_len, GTLS_Buf * out);

GTLS_Result gtls_msg_build_finished(const void * verify_data, size_t len,
    GTLS_Buf * out);

/** KeyUpdate (section 4.6.3): @p request is 0 or 1. */
GTLS_Result gtls_msg_build_key_update(unsigned request, GTLS_Buf * out);

/** Parse a KeyUpdate body: one byte, 0 or 1, else ::GTLS_ERR_PROTOCOL; wrong length ::GTLS_ERR_CORRUPT. */
GTLS_Result gtls_msg_parse_key_update(const void * body, size_t len,
    unsigned * request);

/**
 * Parse a Finished body: exactly @p hash_len bytes of verify_data, else
 * ::GTLS_ERR_CORRUPT (the peer sent the wrong length: decode_error).
 */
GTLS_Result gtls_msg_parse_finished(const void * body, size_t len,
    size_t hash_len, const unsigned char ** verify_data);

#endif /* GHOTI_IO_GTLS_SRC_MSG_MSG_INTERNAL_H */
