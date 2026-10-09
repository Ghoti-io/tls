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
 * @file session_internal.h
 *
 * The session object, and the ticket a server seals its state into.
 *
 * A ticket is `name || nonce || ciphertext || tag`: the 16-byte name of the
 * key that sealed it, a random 12-byte nonce, and the AES-256-GCM sealing of
 * the state below, with a label, the name and the nonce as additional data,
 * so that nothing in the ticket but the ciphertext is unauthenticated. The
 * state holds what resuming needs and nothing else.
 */

#ifndef GHOTI_IO_GTLS_SRC_SESSION_SESSION_INTERNAL_H
#define GHOTI_IO_GTLS_SRC_SESSION_SESSION_INTERNAL_H

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/session.h>

#include "../schedule/schedule_internal.h"

#include <stddef.h>
#include <stdint.h>

/**
 * Versions of the sealed state. 1 is the state of a ticket that permits no
 * early data; 2 is the same with the early-data allowance (a u32) after the
 * lifetime. A ticket is sealed as 1 when its allowance is 0, so a server that
 * sends no early data seals what it always did; both are opened.
 */
#define GTLS_TICKET_STATE_VERSION 1u
#define GTLS_TICKET_STATE_VERSION_EARLY 2u
/** Largest state: version, suite, PSK, age_add, issued, lifetime, allowance, ALPN, SNI. */
#define GTLS_TICKET_PLAIN_MAX (1u + 2u + 1u + GTLS_HASH_MAX + 4u + 8u + 4u + 4u + 1u + 255u + 1u + 255u)
#define GTLS_TICKET_NONCE_LEN 12u
#define GTLS_TICKET_TAG_LEN 16u
/** Largest ticket this library seals. */
#define GTLS_TICKET_MAX (GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN + GTLS_TICKET_PLAIN_MAX + GTLS_TICKET_TAG_LEN)
/** Smallest ticket this library could have sealed: anything shorter is not one. */
#define GTLS_TICKET_MIN (GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN + 1u + 2u + 1u + 32u + 4u + 8u + 4u + 1u + 1u + GTLS_TICKET_TAG_LEN)

/** Work area for sealing and opening a ticket; the caller owns it so a test can see it is left zero. */
#define GTLS_TICKET_AAD_MAX (22u + GTLS_TICKET_KEY_NAME_LEN + GTLS_TICKET_NONCE_LEN)

/** What a ticket holds. */
typedef struct GTLS_TicketPlain {
  uint32_t suite;
  unsigned char psk[GTLS_HASH_MAX];
  size_t psk_len;
  uint32_t age_add;
  int64_t issued;                   /* Unix second */
  uint32_t lifetime;                /* seconds */
  uint32_t max_early_data;          /* early-data allowance in bytes; 0: none */
  unsigned char alpn[255];
  size_t alpn_len;
  unsigned char sni[255];
  size_t sni_len;
} GTLS_TicketPlain;

/**
 * The temporaries of ::gtls_ticket_seal and ::gtls_ticket_open: the state in
 * the clear, the additional data, and the state as it is decoded. The state is
 * @c GTLS_TICKET_PLAIN_MAX bytes and a ticket's tail is read up to 256 bytes
 * past its end by the decoder, so the array carries that much slack and is
 * zero beyond what was decrypted (it is zero between calls).
 */
typedef struct GTLS_TicketScratch {
  unsigned char plain[GTLS_TICKET_PLAIN_MAX + 256u];
  unsigned char aad[GTLS_TICKET_AAD_MAX];
  GTLS_TicketPlain decoded;
} GTLS_TicketScratch;

/**
 * The key that seals at @p now: of the keys valid then, the one whose window
 * began last (the first listed among equals). NULL when none is valid.
 */
const GTLS_TicketKey * gtls_ticket_sealing_key(const GTLS_TicketKey * keys,
    size_t count, int64_t now);

/**
 * Seal @p p under the sealing key at @p now. @p nonce is 12 bytes, fresh
 * (the caller draws them: this function is deterministic). @p out receives
 * the ticket, at most @p cap bytes.
 *
 * @return ::GTLS_OK; ::GTLS_ERR_INVALID without a key or for a state that
 *   cannot be encoded; ::GTLS_ERR_LIMIT when @p cap is too small.
 */
GTLS_Result gtls_ticket_seal(const GTLS_TicketKey * keys, size_t count,
    int64_t now, const unsigned char * nonce, const GTLS_TicketPlain * p,
    unsigned char * out, size_t cap, size_t * out_len, GTLS_TicketScratch * w);

/**
 * Open a ticket: find the key by its name among those not expired at
 * @p now, verify and decrypt, and decode the state strictly.
 *
 * @return ::GTLS_OK, or ::GTLS_ERR_MISMATCH for anything that is not a good
 *   ticket under a key this server holds: too short, an unknown or expired
 *   key, a tag that fails, a state that does not decode. The caller falls
 *   back to a full handshake; nothing here is an attack on the connection.
 */
GTLS_Result gtls_ticket_open(const GTLS_TicketKey * keys, size_t count,
    int64_t now, const unsigned char * ticket, size_t len, GTLS_TicketPlain * out,
    GTLS_TicketScratch * w);

/**
 * 1 when a ticket issued at @p p->issued, presented at @p now with the
 * obfuscated age @p obfuscated_age, is live and its age is the one the
 * server computes, to within @p window_ms milliseconds. All arithmetic is in
 * 64 bits on values already bounded: nothing here can overflow.
 */
int gtls_ticket_fresh(const GTLS_TicketPlain * p, int64_t now,
    uint32_t obfuscated_age, uint32_t window_ms);

/** The session a client holds. */
struct GTLS_Session {
  const GTLS_Allocator * allocator;
  uint32_t suite;
  uint32_t lifetime;
  uint32_t age_add;
  uint32_t max_early_data;
  int64_t received;
  unsigned char host[255];
  size_t host_len;
  unsigned char alpn[255];
  size_t alpn_len;
  unsigned char psk[GTLS_HASH_MAX];
  size_t psk_len;
  unsigned char * ticket;
  size_t ticket_len;
};

/** A zeroed session with room for a ticket of @p ticket_len bytes, or NULL. */
GTLS_Session * gtls_session_alloc(const GTLS_Allocator * allocator, size_t ticket_len);
/** A copy of @p from, or NULL. */
GTLS_Session * gtls_session_copy(const GTLS_Allocator * allocator, const GTLS_Session * from);

#endif /* GHOTI_IO_GTLS_SRC_SESSION_SESSION_INTERNAL_H */
