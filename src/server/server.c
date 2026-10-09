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
 * @file server.c
 *
 * The server's side of the TLS 1.3 handshake: the ClientHello is read and
 * judged, an identity, a suite, a group, a signature scheme and an ALPN
 * protocol are chosen, and the whole flight (ServerHello through Finished)
 * is built, signed and queued. RFC 8446 sections 4 and 7 and appendix A.2.
 *
 * Every failure goes through gtls_conn_fail(), as the client's do, so none
 * leaves a secret behind. The server sends no CertificateRequest, and refuses
 * anything that does not offer TLS 1.3 with the alert that says so.
 *
 * Tickets (RFC 8446 sections 4.2.9 to 4.2.11 and 4.6.1). After the client's
 * Finished the server sends NewSessionTicket messages sealed under the
 * caller's keyring and keeps nothing. A ClientHello's pre_shared_key is
 * opened: a ticket that is not ours, is expired, is for another name, suite or
 * ALPN protocol, or whose age is off, is passed over and the handshake is
 * the full one it would have been without the offer; one that is good has
 * its binder checked, and a binder that is wrong is fatal. A good offer gives
 * the abbreviated handshake: ServerHello with the selected identity,
 * EncryptedExtensions, Finished. early_data is checked for shape and not
 * accepted: its records are skipped (spec 8b builds the rest).
 */

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/conn.h>

#include "../core/core_internal.h"
#include "../client/client_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

/* ----------------------------------------------------------------- creation */

GTLS_Result gtls_conn_new_server(const GTLS_Context * context, GTLS_Conn ** out) {
  if (context == NULL || out == NULL || context->role != GTLS_ROLE_SERVER) {
    return GTLS_ERR_INVALID;
  }
  return gtls_conn_alloc(context, out);
}

GTLS_Result gtls_server_start(GTLS_Conn * c) {
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->state != GTLS_STATE_NEW) {
    return GTLS_ERR_INVALID;
  }
  c->state = GTLS_STATE_S_WAIT_CH;
  return GTLS_OK;
}

void gtls_conn_set_server_hooks(GTLS_Conn * c, GTLS_SignFn sign_fn,
    void * sign_user, const unsigned char * const * chain,
    const size_t * chain_len, size_t chain_count, unsigned scheme,
    const unsigned char * ee_prefix, size_t ee_prefix_len) {
  c->sign_fn = sign_fn;
  c->sign_user = sign_user;
  c->seam_chain = chain;
  c->seam_chain_len = chain_len;
  c->seam_chain_count = chain_count;
  c->seam_scheme = scheme;
  c->seam_ee_prefix = ee_prefix;
  c->seam_ee_prefix_len = ee_prefix_len;
}

/* ------------------------------------------------------------ what was chosen */

static unsigned char lower(unsigned char ch) {
  return ch >= 'A' && ch <= 'Z' ? (unsigned char)(ch + ('a' - 'A')) : ch;
}

/** Equal, ignoring ASCII case. Names are public, so this may branch. */
static int names_equal(const unsigned char * a, const unsigned char * b, size_t n) {
  size_t i;

  for (i = 0; i < n; i++) {
    if (lower(a[i]) != lower(b[i])) {
      return 0;
    }
  }
  return 1;
}

/**
 * Does the identity's name @p pat serve @p host. A leading "*." stands for
 * exactly one label, as in a certificate (RFC 9525 section 6.3).
 */
static int name_serves(const unsigned char * pat, size_t plen,
    const unsigned char * host, size_t hlen) {
  size_t i;

  if (plen > 2u && pat[0] == '*' && pat[1] == '.') {
    for (i = 0; i < hlen && host[i] != '.'; i++) {
    }
    if (i == 0 || i >= hlen) {
      return 0;
    }
    return plen - 1u == hlen - i && names_equal(pat + 1, host + i, plen - 1u);
  }
  return plen == hlen && names_equal(pat, host, plen);
}

static int has_u16(const uint16_t * list, size_t n, unsigned v) {
  size_t i;

  for (i = 0; i < n; i++) {
    if (list[i] == v) {
      return 1;
    }
  }
  return 0;
}

/** What a ClientHello offers, read once. Views into the message. */
typedef struct Offer {
  GTLS_ClientHello ch;
  uint16_t groups[GTLS_CH_LIST_MAX];
  size_t group_count;
  uint16_t sigs[GTLS_CH_LIST_MAX];
  size_t sig_count;
  GTLS_ClientShare shares[GTLS_CH_SHARES_MAX];
  size_t share_count;
  GTLS_Name alpn[GTLS_CH_NAMES_MAX];
  size_t alpn_count;
  int has_alpn;
  GTLS_Name host;
  int early_data;   /* early_data was offered */
  int psk;          /* pre_shared_key was offered */
  int psk_dhe;      /* ... with psk_dhe_ke among the modes */
  GTLS_PskOffer psk_offer;
  size_t psk_trunc; /* bytes of the message before the binders list */
} Offer;

static GTLS_Result missing(GTLS_Conn * c) {
  return gtls_conn_fail(c, GTLS_ERR_PROTOCOL, GTLS_ALERT_MISSING_EXTENSION);
}

/**
 * Read and judge a ClientHello: the version, the extensions that must be
 * there, the ones this server refuses, and the shape of each one it reads.
 * Nothing is chosen yet.
 */
static GTLS_Result read_offer(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, Offer * o) {
  const GTLS_Ext * e;
  const GTLS_ClientHello * ch = &o->ch;
  GTLS_Result result;
  int tls13 = 0;
  size_t i;

  memset(o, 0, sizeof *o);
  result = gtls_msg_parse_client_hello(msg + 4, msg_len - 4u, &c->limits, &o->ch);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  if (ch->compression_len != 1u || ch->compression[0] != 0) {
    return gtls_conn_illegal(c);
  }
  /* A hello that does not offer TLS 1.3 is a 1.2 (or older) client. */
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_SUPPORTED_VERSIONS);
  if (e == NULL) {
    return gtls_conn_fail(c, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION);
  }
  result = gtls_msg_parse_ch_versions(e, &tls13);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  if (!tls13) {
    return gtls_conn_fail(c, GTLS_ERR_UNSUPPORTED, GTLS_ALERT_PROTOCOL_VERSION);
  }
  /* A PSK offer is validated here and judged later (try_resume, and the
   * binder once the transcript is known). What section 4.2.11 requires of
   * the shape is enforced at once, so a malformed offer is called that:
   * pre_shared_key last, psk_key_exchange_modes present, as many binders as
   * identities. */
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_PRE_SHARED_KEY);
  if (e != NULL) {
    const GTLS_Ext * modes = gtls_msg_find_ext(ch->exts, ch->ext_count,
        GTLS_EXT_PSK_KEY_EXCHANGE_MODES);

    if (ch->exts[ch->ext_count - 1u].type != GTLS_EXT_PRE_SHARED_KEY) {
      return gtls_conn_illegal(c);
    }
    if (modes == NULL) {
      return missing(c);
    }
    result = gtls_msg_parse_ch_psk_modes(modes, &o->psk_dhe);
    if (result != GTLS_OK) {
      return gtls_conn_fail_parse(c, result);
    }
    result = gtls_msg_parse_ch_psk_offer(e, &c->limits, &o->psk_offer);
    if (result != GTLS_OK) {
      return gtls_conn_fail_parse(c, result);
    }
    o->psk_trunc = (size_t)(e->data - msg) + o->psk_offer.binders_off;
    o->psk = 1;
  }
  /* early_data is rejected by not echoing it in EncryptedExtensions (section
   * 4.2.10). Its body is checked either way, but the client's early records
   * are skipped only when a PSK was offered with it: early data is encrypted
   * under a key derived from a PSK, so without one nothing was sent that this
   * server could be expected to skip, and a bad record stays fatal. */
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_EARLY_DATA);
  if (e != NULL) {
    result = gtls_msg_parse_ch_early_data(e);
    if (result != GTLS_OK) {
      return gtls_conn_fail_parse(c, result);
    }
    o->early_data = 1;
  }
  /* The only cookie this server could be sent is one it issued, and it
   * issues none. */
  if (gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_COOKIE) != NULL) {
    return gtls_conn_illegal(c);
  }
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_SUPPORTED_GROUPS);
  if (e == NULL) {
    return missing(c);
  }
  result = gtls_msg_parse_ch_u16_list(e, o->groups, GTLS_CH_LIST_MAX,
      &o->group_count);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_SIGNATURE_ALGORITHMS);
  if (e == NULL) {
    return missing(c);
  }
  result = gtls_msg_parse_ch_u16_list(e, o->sigs, GTLS_CH_LIST_MAX, &o->sig_count);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_KEY_SHARE);
  if (e == NULL) {
    return missing(c);
  }
  result = gtls_msg_parse_ch_key_shares(e, o->shares, &o->share_count);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  for (i = 0; i < o->share_count; i++) {
    /* RFC 8446 section 4.2.8: a share for a group not listed is illegal. */
    if (!has_u16(o->groups, o->group_count, o->shares[i].group)) {
      return gtls_conn_illegal(c);
    }
  }
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_SERVER_NAME);
  if (e != NULL) {
    result = gtls_msg_parse_ch_server_name(e, &o->host);
    if (result != GTLS_OK) {
      return gtls_conn_fail_parse(c, result);
    }
    for (i = 0; i < o->host.len; i++) {
      if (o->host.p[i] == 0 || o->host.p[i] > 0x7fu) {
        return gtls_conn_illegal(c);
      }
    }
    if (o->host.len > 255u) {
      return gtls_conn_illegal(c);
    }
  }
  e = gtls_msg_find_ext(ch->exts, ch->ext_count, GTLS_EXT_ALPN);
  if (e != NULL) {
    result = gtls_msg_parse_ch_alpn(e, o->alpn, &o->alpn_count);
    if (result != GTLS_OK) {
      return gtls_conn_fail_parse(c, result);
    }
    o->has_alpn = 1;
  }
  return GTLS_OK;
}

/**
 * The second ClientHello must be the first, changed only where RFC 8446
 * section 4.1.2 allows: the key_share, the padding, early_data dropped, and
 * a pre_shared_key brought up to date (the binders and ages change with the
 * transcript). Anything else is illegal_parameter, and so is early_data in
 * the second hello (section 4.2.10).
 */
static GTLS_Result check_retry(GTLS_Conn * c, const Offer * o) {
  GTLS_ClientHello first;
  GTLS_Limits l = gtls_conn_own_limits(c);
  size_t i;

  if (o->early_data) {
    return gtls_conn_illegal(c);
  }
  if (gtls_msg_parse_client_hello(c->hello.data + 4, c->hello.len - 4u, &l,
          &first) != GTLS_OK) {
    return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);
  }
  if (first.legacy_version != o->ch.legacy_version ||
      gsec_equal(first.random, o->ch.random, 32) != GSEC_OK ||
      first.session_id_len != o->ch.session_id_len ||
      gsec_equal(first.session_id, o->ch.session_id, first.session_id_len) != GSEC_OK ||
      first.suites_len != o->ch.suites_len ||
      gsec_equal(first.suites, o->ch.suites, first.suites_len) != GSEC_OK ||
      first.compression_len != o->ch.compression_len ||
      gsec_equal(first.compression, o->ch.compression, first.compression_len) != GSEC_OK) {
    return gtls_conn_illegal(c);
  }
  for (i = 0; i < first.ext_count; i++) {
    const GTLS_Ext * a = &first.exts[i];
    const GTLS_Ext * b;

    if (a->type == GTLS_EXT_KEY_SHARE || a->type == GTLS_EXT_PADDING ||
        a->type == GTLS_EXT_EARLY_DATA || a->type == GTLS_EXT_PRE_SHARED_KEY) {
      continue;
    }
    b = gtls_msg_find_ext(o->ch.exts, o->ch.ext_count, a->type);
    if (b == NULL || a->len != b->len || gsec_equal(a->data, b->data, a->len) != GSEC_OK) {
      return gtls_conn_illegal(c);
    }
  }
  for (i = 0; i < o->ch.ext_count; i++) {
    const GTLS_Ext * b = &o->ch.exts[i];

    if (b->type == GTLS_EXT_KEY_SHARE || b->type == GTLS_EXT_PADDING) {
      continue;
    }
    if (gtls_msg_find_ext(first.exts, first.ext_count, b->type) == NULL) {
      return gtls_conn_illegal(c);
    }
  }
  return GTLS_OK;
}

static GTLS_Result copy_sni(GTLS_Conn * c, const GTLS_Name * host) {
  unsigned char * copy = NULL;

  if (host->len != 0) {
    copy = gcu_allocator_malloc(c->allocator, host->len);
    if (copy == NULL) {
      return gtls_conn_fail(c, GTLS_ERR_OOM, GTLS_ALERT_INTERNAL_ERROR);
    }
    memcpy(copy, host->p, host->len);
  }
  gcu_allocator_free(c->allocator, c->client_sni);
  c->client_sni = copy;
  c->client_sni_len = host->len;
  return GTLS_OK;
}

/** 2 when one of the identity's names is exactly @p host, 1 when a wildcard one serves it, else 0. */
static int name_rank(const GTLS_ServerIdentity * id, const unsigned char * host, size_t hlen) {
  size_t off = 0;
  size_t j;
  int best = 0;

  for (j = 0; j < id->name_count; j++) {
    const unsigned char * pat = id->names + off;
    size_t plen = id->name_len[j];

    if (plen == hlen && names_equal(pat, host, plen)) {
      return 2;
    }
    if (name_serves(pat, plen, host, hlen)) {
      best = 1;
    }
    off += plen;
  }
  return best;
}

/** The scheme this identity would sign with for this client, or 0. */
static unsigned scheme_for(const GTLS_Conn * c, const Offer * o, const GTLS_ServerIdentity * id) {
  const GTLS_Context * x = c->context;
  size_t i;

  if (c->seam_scheme != 0) {
    return c->seam_scheme;
  }
  for (i = 0; i < x->sig_alg_count; i++) {
    unsigned s = (unsigned)x->sig_algs[i];

    if (gtls_cv_scheme_ok(s) && has_u16(o->sigs, o->sig_count, s) &&
        gcert_key_scheme_fits((GCERT_SigScheme)s, id->key_kind)) {
      return s;
    }
  }
  return 0;
}

/* ------------------------------------------------------------- resumption */

/** What a good ticket gave: the state it held and which identity of the offer it was. */
typedef struct Resume {
  int active;
  size_t index;
  GTLS_TicketPlain plain;
} Resume;

static int offered_suite(const Offer * o, uint32_t suite) {
  size_t j;

  for (j = 0; j + 1u < o->ch.suites_len; j += 2u) {
    if ((((uint32_t)o->ch.suites[j] << 8) | o->ch.suites[j + 1u]) == suite) {
      return 1;
    }
  }
  return 0;
}

static int context_suite(const GTLS_Context * x, uint32_t suite) {
  size_t i;

  for (i = 0; i < x->suite_count; i++) {
    if ((uint32_t)x->suites[i] == suite) {
      return 1;
    }
  }
  return 0;
}

static int offered_alpn(const Offer * o, const unsigned char * name, size_t len) {
  size_t k;

  for (k = 0; k < o->alpn_count; k++) {
    if (o->alpn[k].len == len && gsec_equal(o->alpn[k].p, name, len) == GSEC_OK) {
      return 1;
    }
  }
  return 0;
}

/**
 * Look for an identity of the offer that this server can resume. Every way a
 * ticket can fail to qualify is quiet: the offer is passed over and the
 * handshake is the full one (RFC 8446 section 4.2.11). The binder is not
 * looked at here; it needs the transcript, and a wrong one is fatal.
 */
static void try_resume(const GTLS_Conn * c, const Offer * o, int64_t now, Resume * r) {
  const GTLS_Context * x = c->context;
  size_t i;

  memset(r, 0, sizeof *r);
  if (!o->psk || !o->psk_dhe || x->ticket_key_count == 0) {
    return; /* psk_ke alone is not built: it falls back to full */
  }
  for (i = 0; i < o->psk_offer.stored; i++) {
    const GTLS_PskEntry * en = &o->psk_offer.entries[i];
    GTLS_TicketPlain t;
    int good;

    if (gtls_ticket_open(x->ticket_keys, x->ticket_key_count, now, en->identity,
            en->identity_len, &t) != GTLS_OK) {
      continue;
    }
    good = offered_suite(o, t.suite) && context_suite(x, t.suite) &&
        gtls_ticket_fresh(&t, now, en->age, x->ticket_age_window * 1000u) &&
        t.sni_len == o->host.len && names_equal(t.sni, o->host.p, t.sni_len) &&
        (t.alpn_len == 0 || offered_alpn(o, t.alpn, t.alpn_len));
    if (good) {
      r->active = 1;
      r->index = i;
      r->plain = t;
      (void)gsec_wipe(&t, sizeof t);
      return;
    }
    (void)gsec_wipe(&t, sizeof t);
  }
}

/**
 * Choose what the connection will use from what the client offered:
 * the identity (by SNI, else the default), the suite, the group, the
 * signature scheme and the ALPN protocol. @p group and @p share come out; a
 * NULL @p share means no share fits and a HelloRetryRequest is needed.
 */
static GTLS_Result choose(GTLS_Conn * c, const Offer * o, int second,
    const Resume * r, GTLS_Group * group, const GTLS_ClientShare ** share) {
  const GTLS_Context * x = c->context;
  size_t i;
  size_t j;
  size_t k;

  /* The suite: the server's preference among the client's, except that a
   * ticket is for one suite and the hash of its PSK is the hash of the
   * handshake (section 4.2.11), and that the one a HelloRetryRequest named
   * is the one the ServerHello must name. */
  if (second) {
    /* c->suite is the retry's */
  } else if (r->active) {
    c->suite = (GTLS_Suite)r->plain.suite;
  } else {
    c->suite = GTLS_SUITE_NONE;
  }
  for (i = 0; i < x->suite_count && c->suite == GTLS_SUITE_NONE; i++) {
    for (j = 0; j + 1u < o->ch.suites_len; j += 2u) {
      if ((((unsigned)o->ch.suites[j] << 8) | o->ch.suites[j + 1u]) ==
          (unsigned)x->suites[i]) {
        c->suite = x->suites[i];
        break;
      }
    }
  }
  if (c->suite == GTLS_SUITE_NONE) {
    return gtls_conn_fail(c, GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* The group. A share the client already sent saves a round trip, so a
   * group with a share is chosen over a more preferred one without. */
  *group = GTLS_GROUP_NONE;
  *share = NULL;
  if (second) {
    if (o->share_count == 0) {
      /* The retry would need another retry, which RFC 8446 does not allow. */
      return gtls_conn_unexpected(c);
    }
    if (o->share_count != 1u || o->shares[0].group != (unsigned)c->hrr_group) {
      return gtls_conn_illegal(c);
    }
    *group = c->hrr_group;
    *share = &o->shares[0];
  } else {
    for (i = 0; i < x->group_count && *share == NULL; i++) {
      if (!has_u16(o->groups, o->group_count, (unsigned)x->groups[i])) {
        continue;
      }
      for (k = 0; k < o->share_count; k++) {
        if (o->shares[k].group == (unsigned)x->groups[i]) {
          *group = x->groups[i];
          *share = &o->shares[k];
          break;
        }
      }
    }
    for (i = 0; i < x->group_count && *group == GTLS_GROUP_NONE; i++) {
      if (has_u16(o->groups, o->group_count, (unsigned)x->groups[i])) {
        *group = x->groups[i];
      }
    }
    if (*group == GTLS_GROUP_NONE) {
      return gtls_conn_fail(c, GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE);
    }
  }

  /* The identity and the signature scheme with it. The identity is the best
   * match for the client's server_name (an exact name before a wildcard),
   * and one that cannot sign with anything the client listed is passed over
   * for the next match; then the default is tried. The scheme is the first
   * of the server's own that TLS 1.3 allows in CertificateVerify, that the
   * client listed, and that the key signs. */
  c->identity_index = x->default_identity;
  c->sni_matched = 0;
  c->scheme = 0;
  {
    int rank;
    int found = 0;

    for (rank = 2; rank >= 1 && !found && o->host.len != 0; rank--) {
      for (i = 0; i < x->identity_count; i++) {
        unsigned s;

        if (name_rank(&x->identities[i], o->host.p, o->host.len) != rank) {
          continue;
        }
        s = scheme_for(c, o, &x->identities[i]);
        if (s != 0) {
          c->identity_index = i;
          c->sni_matched = 1;
          c->scheme = s;
          found = 1;
          break;
        }
      }
    }
    if (!found) {
      c->identity_index = x->default_identity;
      c->scheme = scheme_for(c, o, &x->identities[x->default_identity]);
      c->sni_matched = o->host.len != 0 &&
          name_rank(&x->identities[x->default_identity], o->host.p, o->host.len) != 0;
    }
  }
  if (c->scheme == 0 && !r->active) {
    /* A resumed handshake signs nothing, so it needs no scheme. */
    return gtls_conn_fail(c, GTLS_ERR_NO_COMMON, GTLS_ALERT_HANDSHAKE_FAILURE);
  }

  /* ALPN: the first of the server's list that the client offered. Both
   * lists present and no overlap is fatal (RFC 7301 section 3.2); a client
   * that offered none, or a server with none, gets none. */
  c->alpn_selected_len = 0;
  if (x->alpn_len != 0 && o->has_alpn) {
    size_t off = 0;

    while (off < x->alpn_len && c->alpn_selected_len == 0) {
      size_t n = x->alpn[off];

      for (k = 0; k < o->alpn_count; k++) {
        if (o->alpn[k].len == n && gsec_equal(o->alpn[k].p, x->alpn + off + 1u, n) == GSEC_OK) {
          memcpy(c->alpn_selected, x->alpn + off + 1u, n);
          c->alpn_selected_len = n;
          break;
        }
      }
      off += 1u + n;
    }
    if (c->alpn_selected_len == 0) {
      return gtls_conn_fail(c, GTLS_ERR_ALPN, GTLS_ALERT_NO_APPLICATION_PROTOCOL);
    }
  }
  return GTLS_OK;
}

/* ---------------------------------------------------------------- the flight */

/** Queue a built message at @p epoch and absorb it into the transcript. */
static GTLS_Result emit(GTLS_Conn * c, GTLS_Epoch epoch, GTLS_Buf * m) {
  GTLS_Result result = m->err;

  if (result == GTLS_OK) {
    result = gtls_transcript_update(&c->sec.transcript, m->data, m->len);
  }
  if (result == GTLS_OK) {
    result = gtls_conn_queue(c, epoch, m->data, m->len);
    if (result != GTLS_OK) {
      return result; /* queue() has failed the connection */
    }
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  return GTLS_OK;
}

static GTLS_Result sign_cv(GTLS_Conn * c, const unsigned char * content,
    size_t n, unsigned char * sig, size_t * sig_len) {
  GTLS_Result result;

  if (c->sign_fn != NULL) {
    result = c->sign_fn(c->sign_user, c, c->scheme, content, n, sig, GCERT_SIG_MAX,
        sig_len);
    if (result == GTLS_OK && (*sig_len == 0 || *sig_len > GCERT_SIG_MAX)) {
      return GTLS_ERR_INTERNAL; /* a signer that claims more than it was given room for */
    }
    return result;
  }
  switch (gcert_key_sign(c->context->identities[c->identity_index].key,
      (GCERT_SigScheme)c->scheme, content, n, sig, GCERT_SIG_MAX, sig_len)) {
    case GCERT_OK:
      result = GTLS_OK;
      break;
    case GCERT_ERR_IO:
      result = GTLS_ERR_IO;
      break;
    case GCERT_ERR_OOM:
      result = GTLS_ERR_OOM;
      break;
    default:
      result = GTLS_ERR_INTERNAL;
      break;
  }
  return result;
}

/**
 * ServerHello, then the encrypted flight: EncryptedExtensions, Certificate,
 * CertificateVerify, Finished. Leaves the connection waiting for the
 * client's Finished, with the application secrets derived.
 */

/** Everything the flight derives that must not outlive it, wiped on every path out. */
typedef struct FlightScratch {
  unsigned char ecdhe[GTLS_KX_MAX];
  unsigned char th[GTLS_HASH_MAX];
  unsigned char verify[GTLS_HASH_MAX];
  unsigned char content[GTLS_CV_CONTENT_MAX];
  unsigned char sig[GCERT_SIG_MAX];
} FlightScratch;

/** Certificate and CertificateVerify, the part of the flight a resumed handshake leaves out. */
static GTLS_Result send_authentication(GTLS_Conn * c, FlightScratch * k, GTLS_Hash hash,
    size_t hlen) {
  const GTLS_Context * x = c->context;
  const GTLS_ServerIdentity * id = &x->identities[c->identity_index];
  GTLS_Buf m;
  size_t sig_len = 0;
  size_t n;
  const unsigned char * ptr[GTLS_CERT_MAX];
  size_t lens[GTLS_CERT_MAX];
  const unsigned char * const * chain_ptr;
  const size_t * chain_len;
  size_t chain_count;
  size_t off = 0;
  size_t i;
  GTLS_Result result;

  memset(ptr, 0, sizeof ptr);
  memset(lens, 0, sizeof lens);
  /* Certificate. */
  if (c->seam_chain != NULL) {
    chain_ptr = c->seam_chain;
    chain_len = c->seam_chain_len;
    chain_count = c->seam_chain_count;
  } else {
    for (i = 0; i < id->chain_count; i++) {
      ptr[i] = id->chain + off;
      lens[i] = id->chain_len[i];
      off += id->chain_len[i];
    }
    chain_ptr = ptr;
    chain_len = lens;
    chain_count = id->chain_count;
  }
  gtls_buf_init(&m, c->allocator, c->limits.max_output_bytes);
  result = gtls_msg_build_certificate(chain_ptr, chain_len, chain_count, &m);
  if (result == GTLS_OK) {
    result = emit(c, GTLS_EPOCH_HANDSHAKE, &m);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }

  /* CertificateVerify, over the transcript through Certificate. */
  result = gtls_transcript_snapshot(&c->sec.transcript, hash, k->th);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  n = gtls_cv_content(1, k->th, hlen, k->content);
  result = sign_cv(c, k->content, n, k->sig, &sig_len);
  (void)gsec_wipe(k->content, sizeof k->content);
  if (result != GTLS_OK) {
    (void)gsec_wipe(k->sig, sizeof k->sig);
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  gtls_buf_init(&m, c->allocator, 4096u);
  result = gtls_msg_build_certificate_verify(c->scheme, k->sig, sig_len, &m);
  (void)gsec_wipe(k->sig, sizeof k->sig);
  if (result == GTLS_OK) {
    result = emit(c, GTLS_EPOCH_HANDSHAKE, &m);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }

  return GTLS_OK;
}

static GTLS_Result send_flight_inner(GTLS_Conn * c, const Offer * o, const Resume * r,
    GTLS_Group group, const GTLS_ClientShare * share, FlightScratch * k) {
  GTLS_Hash hash = gtls_suite_hash((uint32_t)c->suite);
  size_t hlen = gtls_hash_len(hash);
  const int resumed = r->active;
  GTLS_ServerHelloParams sp;
  GTLS_KeyShare mine;
  GTLS_EeParams ee;
  GTLS_Buf m;
  size_t ecdhe_len = 0;
  GTLS_Result result;

  memset(&sp, 0, sizeof sp);
  memset(&mine, 0, sizeof mine);
  c->group = group;
  c->resumed = resumed;
  result = gtls_conn_draw(c, sp.random, 32);
  if (result == GTLS_OK) {
    result = gtls_conn_gen_share(c, group, &mine);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  result = gtls_conn_shared_secret(c, group, share->kx, share->kx_len, k->ecdhe,
      &ecdhe_len);
  if (result != GTLS_OK) {
    (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);
    return gtls_conn_illegal(c); /* a point that is not on the curve, or too small */
  }
  sp.session_id = o->ch.session_id;
  sp.session_id_len = o->ch.session_id_len;
  sp.suite = (unsigned)c->suite;
  sp.group = (unsigned)group;
  sp.key_exchange = mine.pub;
  sp.key_exchange_len = mine.pub_len;
  sp.psk = resumed;
  sp.psk_identity = (unsigned)r->index;
  gtls_buf_init(&m, c->allocator, 4096u);
  result = gtls_msg_build_server_hello(&sp, &m);
  if (result == GTLS_OK) {
    result = emit(c, GTLS_EPOCH_INITIAL, &m);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  result = gtls_transcript_snapshot(&c->sec.transcript, hash, k->th);
  if (result == GTLS_OK) {
    result = resumed ? gtls_schedule_early_psk(&c->sec.schedule, hash, r->plain.psk, r->plain.psk_len)
                     : gtls_schedule_early(&c->sec.schedule, hash);
  }
  if (result == GTLS_OK) {
    result = gtls_schedule_handshake(&c->sec.schedule, k->ecdhe, ecdhe_len, k->th);
  }
  (void)gsec_wipe(k->ecdhe, sizeof k->ecdhe);
  gtls_conn_wipe_kx(c);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }

  /* EncryptedExtensions. */
  memset(&ee, 0, sizeof ee);
  ee.prefix = c->seam_ee_prefix;
  ee.prefix_len = c->seam_ee_prefix_len;
  c->sni_acknowledged = c->client_sni_len != 0 && (c->sni_matched || c->seam_chain != NULL);
  ee.ack_server_name = c->sni_acknowledged;
  ee.alpn = c->alpn_selected_len != 0 ? c->alpn_selected : NULL;
  ee.alpn_len = c->alpn_selected_len;
  gtls_buf_init(&m, c->allocator, c->limits.max_output_bytes);
  result = gtls_msg_build_encrypted_extensions(&ee, &m);
  if (result == GTLS_OK) {
    result = emit(c, GTLS_EPOCH_HANDSHAKE, &m);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }

  if (!resumed) {
    result = send_authentication(c, k, hash, hlen);
    if (result != GTLS_OK) {
      return result;
    }
  }

  /* Finished, over the transcript through CertificateVerify. */
  result = gtls_transcript_snapshot(&c->sec.transcript, hash, k->th);
  if (result == GTLS_OK) {
    result = gtls_finished_verify_data(hash, c->sec.schedule.s_hs, k->th, k->verify);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  gtls_buf_init(&m, c->allocator, 4096u);
  result = gtls_msg_build_finished(k->verify, hlen, &m);
  (void)gsec_wipe(k->verify, sizeof k->verify);
  if (result == GTLS_OK) {
    result = emit(c, GTLS_EPOCH_HANDSHAKE, &m);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }

  /* The application secrets come from the transcript through this Finished. */
  result = gtls_transcript_snapshot(&c->sec.transcript, hash, k->th);
  if (result == GTLS_OK) {
    result = gtls_schedule_master(&c->sec.schedule, k->th);
  }
  (void)gsec_wipe(k->th, sizeof k->th);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_S_WAIT_FIN;
  return GTLS_OK;
}


static GTLS_Result send_flight(GTLS_Conn * c, const Offer * o, const Resume * r,
    GTLS_Group group, const GTLS_ClientShare * share) {
  FlightScratch k;
  GTLS_Result result;

  memset(&k, 0, sizeof k);
  result = send_flight_inner(c, o, r, group, share, &k);
  (void)gsec_wipe(&k, sizeof k);
  return result;
}

static GTLS_Result send_retry(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, const Offer * o, GTLS_Group group) {
  GTLS_Hash hash = gtls_suite_hash((uint32_t)c->suite);
  GTLS_ServerHelloParams sp;
  GTLS_Buf m;
  GTLS_Result result;

  memset(&sp, 0, sizeof sp);
  sp.is_hrr = 1;
  sp.session_id = o->ch.session_id;
  sp.session_id_len = o->ch.session_id_len;
  sp.suite = (unsigned)c->suite;
  sp.group = (unsigned)group;
  result = gtls_buf_append(&c->hello, msg, msg_len);
  if (result == GTLS_OK) {
    result = gtls_transcript_init(&c->sec.transcript);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_select(&c->sec.transcript, hash);
  }
  if (result == GTLS_OK) {
    result = gtls_transcript_restart(&c->sec.transcript, hash);
  }
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  gtls_buf_init(&m, c->allocator, 4096u);
  result = gtls_msg_build_server_hello(&sp, &m);
  if (result == GTLS_OK) {
    result = emit(c, GTLS_EPOCH_INITIAL, &m);
  }
  gtls_buf_free(&m);
  if (result != GTLS_OK) {
    return c->state == GTLS_STATE_FAILED ? result
        : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->retried = 1;
  c->hrr_group = group;
  c->state = GTLS_STATE_S_WAIT_CH2;
  return GTLS_OK;
}

/**
 * The binder of the identity the server means to resume, over the transcript
 * so far (nothing, or the retry's) and the ClientHello cut before its binders
 * list. A binder that is wrong, or is the wrong length for the PSK, is fatal:
 * whoever sent the ticket did not hold the PSK (section 4.2.11.2).
 */
static GTLS_Result verify_binder(GTLS_Conn * c, const Offer * o, const Resume * r,
    const unsigned char * msg) {
  const GTLS_PskEntry * en = &o->psk_offer.entries[r->index];
  GTLS_Hash hash = gtls_suite_hash((uint32_t)c->suite);
  unsigned char th[GTLS_HASH_MAX];
  GTLS_Result result;

  result = gtls_binder_transcript(&c->sec.transcript, msg, o->psk_trunc, th);
  if (result == GTLS_OK) {
    result = gtls_binder_check(hash, r->plain.psk, r->plain.psk_len, th, en->binder,
        en->binder_len);
  }
  (void)gsec_wipe(th, sizeof th);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, result == GTLS_ERR_MISMATCH
        ? GTLS_ALERT_DECRYPT_ERROR : GTLS_ALERT_INTERNAL_ERROR);
  }
  return GTLS_OK;
}

static GTLS_Result on_client_hello_inner(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now, Resume * r) {
  const int second = c->state == GTLS_STATE_S_WAIT_CH2;
  Offer o;
  GTLS_Group group = GTLS_GROUP_NONE;
  const GTLS_ClientShare * share = NULL;
  GTLS_Result result;

  result = read_offer(c, msg, msg_len, &o);
  if (result != GTLS_OK) {
    return result;
  }
  if (second) {
    result = check_retry(c, &o);
    if (result != GTLS_OK) {
      return result;
    }
    /* The early data came before the retry was answered, so none follows. */
    c->early_skip = 0;
  } else if (o.early_data && o.psk) {
    c->early_skip = 1;
  }
  result = copy_sni(c, &o.host);
  if (result != GTLS_OK) {
    return result;
  }
  memcpy(c->session_id, o.ch.session_id, o.ch.session_id_len);
  c->session_id_len = o.ch.session_id_len;
  try_resume(c, &o, now, r);
  if (second && r->active && r->plain.suite != (uint32_t)c->suite) {
    /* The retry named a suite and the ticket is for another: the ServerHello
     * must name the retry's, and a PSK of another hash is not used. */
    (void)gsec_wipe(r, sizeof *r);
  }
  result = choose(c, &o, second, r, &group, &share);
  if (result != GTLS_OK) {
    return result;
  }
  if (share == NULL) {
    return send_retry(c, msg, msg_len, &o, group);
  }
  if (!second) {
    result = gtls_transcript_init(&c->sec.transcript);
    if (result == GTLS_OK) {
      result = gtls_transcript_select(&c->sec.transcript,
          gtls_suite_hash((uint32_t)c->suite));
    }
    if (result != GTLS_OK) {
      return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
    }
  }
  /* The binder covers the transcript before this hello and the hello without
   * its binders, so it is checked before the hello is absorbed. */
  if (r->active) {
    result = verify_binder(c, &o, r, msg);
    if (result != GTLS_OK) {
      return result;
    }
  }
  result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  return send_flight(c, &o, r, group, share);
}

static GTLS_Result on_client_hello(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now) {
  Resume r;
  GTLS_Result result;

  memset(&r, 0, sizeof r);
  result = on_client_hello_inner(c, msg, msg_len, now, &r);
  (void)gsec_wipe(&r, sizeof r);
  return result;
}

/**
 * Send the tickets (section 4.6.1): each stands for its own PSK, derived from
 * the resumption master secret and a nonce of its own, sealed with the state
 * a resumption needs. They go out under the application keys, queued at that
 * epoch. A server with no key valid now sends none.
 */
GTLS_Result gtls_server_issue_tickets(GTLS_Conn * c, int64_t now) {
  const GTLS_Context * x = c->context;
  GTLS_Hash hash = gtls_suite_hash((uint32_t)c->suite);
  size_t hlen = gtls_hash_len(hash);
  unsigned i;

  if (x->ticket_count == 0 ||
      gtls_ticket_sealing_key(x->ticket_keys, x->ticket_key_count, now) == NULL) {
    return GTLS_OK;
  }
  if (!c->sec.schedule.has_res) {
    /* Reached only after the client's Finished, which kept the secret. */
    return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);
  }
  for (i = 0; i < x->ticket_count; i++) {
    GTLS_TicketPlain p;
    GTLS_NewSessionTicket t;
    unsigned char ticket[GTLS_TICKET_MAX];
    unsigned char iv[GTLS_TICKET_NONCE_LEN];
    unsigned char age[4];
    unsigned char nonce = (unsigned char)i;
    size_t ticket_len = 0;
    GTLS_Buf m;
    GTLS_Result result;

    memset(&p, 0, sizeof p);
    memset(&t, 0, sizeof t);
    p.suite = (uint32_t)c->suite;
    p.psk_len = hlen;
    result = gtls_resumption_psk(hash, c->sec.schedule.res, &nonce, 1, p.psk);
    if (result == GTLS_OK) {
      result = gtls_conn_draw(c, age, sizeof age);
    }
    if (result == GTLS_OK) {
      result = gtls_conn_draw(c, iv, sizeof iv);
    }
    if (result == GTLS_OK) {
      p.age_add = ((uint32_t)age[0] << 24) | ((uint32_t)age[1] << 16) |
          ((uint32_t)age[2] << 8) | age[3];
      p.issued = now;
      p.lifetime = x->ticket_lifetime;
      memcpy(p.alpn, c->alpn_selected, c->alpn_selected_len);
      p.alpn_len = c->alpn_selected_len;
      if (c->client_sni_len != 0) {
        memcpy(p.sni, c->client_sni, c->client_sni_len);
      }
      p.sni_len = c->client_sni_len;
      result = gtls_ticket_seal(x->ticket_keys, x->ticket_key_count, now, iv, &p,
          ticket, sizeof ticket, &ticket_len);
    }
    if (result == GTLS_OK && ticket_len > c->limits.max_ticket_bytes) {
      result = GTLS_ERR_LIMIT;
    }
    if (result == GTLS_OK) {
      t.lifetime = p.lifetime;
      t.age_add = p.age_add;
      t.nonce = &nonce;
      t.nonce_len = 1;
      t.ticket = ticket;
      t.ticket_len = ticket_len;
      gtls_buf_init(&m, c->allocator, 4096u);
      result = gtls_msg_build_new_session_ticket(&t, &m);
      if (result == GTLS_OK) {
        result = gtls_conn_queue(c, GTLS_EPOCH_APPLICATION, m.data, m.len);
      }
      gtls_buf_free(&m);
    }
    (void)gsec_wipe(&p, sizeof p);
    (void)gsec_wipe(ticket, sizeof ticket);
    (void)gsec_wipe(iv, sizeof iv);
    (void)gsec_wipe(age, sizeof age);
    if (result != GTLS_OK) {
      return c->state == GTLS_STATE_FAILED ? result
          : gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
    }
  }
  return GTLS_OK;
}

static GTLS_Result on_client_finished(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now) {
  GTLS_Hash hash = gtls_suite_hash((uint32_t)c->suite);
  size_t hlen = gtls_hash_len(hash);
  const unsigned char * got = NULL;
  unsigned char th[GTLS_HASH_MAX];
  GTLS_Result result;

  result = gtls_msg_parse_finished(msg + 4, msg_len - 4u, hlen, &got);
  if (result != GTLS_OK) {
    return gtls_conn_fail_parse(c, result);
  }
  result = gtls_transcript_snapshot(&c->sec.transcript, hash, th);
  if (result == GTLS_OK) {
    result = gtls_finished_check(hash, c->sec.schedule.c_hs, th, got, hlen);
  }
  (void)gsec_wipe(th, sizeof th);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, result == GTLS_ERR_FINISHED
        ? GTLS_ALERT_DECRYPT_ERROR : GTLS_ALERT_INTERNAL_ERROR);
  }
  result = gtls_transcript_update(&c->sec.transcript, msg, msg_len);
  /* The resumption secret is over the transcript through the client's Finished. */
  if (result == GTLS_OK) {
    result = gtls_transcript_snapshot(&c->sec.transcript, hash, th);
  }
  if (result == GTLS_OK) {
    result = gtls_schedule_keep_resumption(&c->sec.schedule, th);
  }
  (void)gsec_wipe(th, sizeof th);
  if (result != GTLS_OK) {
    return gtls_conn_fail(c, result, GTLS_ALERT_INTERNAL_ERROR);
  }
  c->state = GTLS_STATE_CONNECTED;
  return gtls_server_issue_tickets(c, now);
}

GTLS_Result gtls_server_on_message(GTLS_Conn * c, const unsigned char * msg,
    size_t msg_len, int64_t now) {
  unsigned type = msg[0];

  switch (c->state) {
    case GTLS_STATE_S_WAIT_CH:
    case GTLS_STATE_S_WAIT_CH2:
      if (type != GTLS_HS_CLIENT_HELLO) {
        return gtls_conn_unexpected(c);
      }
      return on_client_hello(c, msg, msg_len, now);
    case GTLS_STATE_S_WAIT_FIN:
      if (type != GTLS_HS_FINISHED) {
        return gtls_conn_unexpected(c);
      }
      return on_client_finished(c, msg, msg_len, now);
    default:
      break;
  }
  return gtls_conn_fail(c, GTLS_ERR_INTERNAL, GTLS_ALERT_INTERNAL_ERROR);
}

/* ---------------------------------------------------------------- accessors */

GTLS_Result gtls_conn_server_name(const GTLS_Conn * c, const unsigned char ** name,
    size_t * len) {
  if (c == NULL || name == NULL || len == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->role != GTLS_ROLE_SERVER) {
    return GTLS_ERR_INVALID;
  }
  *name = c->client_sni;
  *len = c->client_sni_len;
  return GTLS_OK;
}

GTLS_Result gtls_conn_identity(const GTLS_Conn * c, size_t * index) {
  if (c == NULL || index == NULL) {
    return GTLS_ERR_INVALID;
  }
  if (c->state == GTLS_STATE_FAILED) {
    return GTLS_ERR_FAILED;
  }
  if (c->role != GTLS_ROLE_SERVER) {
    return GTLS_ERR_INVALID;
  }
  if (c->state != GTLS_STATE_S_WAIT_FIN && c->state != GTLS_STATE_CONNECTED) {
    return GTLS_ERR_INVALID; /* not chosen yet */
  }
  *index = c->identity_index;
  return GTLS_OK;
}
