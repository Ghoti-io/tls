/**
 * @file
 *
 * What the fuzzers do with one input, kept in a header so that the unit test
 * test_fuzzseeds can replay the seed corpus through exactly the same code and
 * ask which states of the client's table it reached.
 *
 * No gtest in here: a libFuzzer binary does not link it.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_FUZZ_COMMON_H
#define GHOTI_IO_GTLS_FUZZ_COMMON_H

#include <ghoti.io/tls/tls.h>
#include <ghoti.io/security/security.h>

extern "C" {
#include "../../src/client/client_internal.h"
#include "../../src/core/core_internal.h"
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace gtlsfuzz {

typedef std::vector<unsigned char> Bytes;

/** Bit i is set once state i has been seen after any call. */
inline unsigned & visited() {
  static unsigned mask = 0;
  return mask;
}

inline void note(const GTLS_Conn * c) {
  visited() |= 1u << static_cast<unsigned>(gtls_conn_state(c));
}

inline void die(const char * what) {
  std::fprintf(stderr, "invariant broken: %s\n", what);
  std::abort();
}

inline Bytes from_hex(const std::string & text) {
  Bytes out;
  for (size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back(static_cast<unsigned char>(std::stoi(text.substr(i, 2), nullptr, 16)));
  }
  return out;
}

/** The RFC 8448 vectors the client harness needs, read once. */
struct Trace {
  Bytes ch1, ch2, x25519, p256;
  Bytes cert_der, cv_sig, ee_prefix, sh_random, server_x25519;
  bool ok = false;
};

inline const Trace & trace(bool hrr) {
  static Trace t[2];
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
    for (int i = 0; i < 2; i++) {
      std::map<std::string, Bytes> m;
#ifdef GTLS_TEST_DATA
      const std::string dir = GTLS_TEST_DATA;
#else
      const std::string dir = "tests/data";
#endif
      std::ifstream in(dir + "/rfc8448/" + (i ? "hrr" : "simple-1rtt") + ".vec");
      std::string line;
      while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t sp = line.find(' ');
        m[line.substr(0, sp)] = from_hex(line.substr(sp + 1));
      }
      t[i].ch1 = m["client.construct-a-clienthello-handshake-message.clienthello"];
      t[i].x25519 = m["client.create-an-ephemeral-x25519-key-pair.private-key"];
      t[i].p256 = m["client.create-an-ephemeral-p-256-key-pair.private-key"];
      t[i].ch2 = m["client.construct-a-clienthello-handshake-message@2.clienthello"];
      t[i].server_x25519 = m["server.create-an-ephemeral-x25519-key-pair.private-key"];
      const Bytes & sh = m[i ? "server.construct-a-serverhello-handshake-message@2.serverhello"
                             : "server.construct-a-serverhello-handshake-message.serverhello"];
      if (sh.size() >= 38) t[i].sh_random.assign(sh.begin() + 6, sh.begin() + 38);
      const Bytes & cert = m["server.construct-a-certificate-handshake-message.certificate"];
      if (cert.size() > 11) {
        size_t n = (static_cast<size_t>(cert[8]) << 16) | (static_cast<size_t>(cert[9]) << 8) | cert[10];
        if (11 + n <= cert.size()) t[i].cert_der.assign(cert.begin() + 11, cert.begin() + 11 + n);
      }
      const Bytes & cv = m["server.construct-a-certificateverify-handshake-message.certificateverify"];
      if (cv.size() > 8) t[i].cv_sig.assign(cv.begin() + 8, cv.end());
      const Bytes & ee = m["server.construct-an-encryptedextensions-handshake-message.encryptedextensions"];
      if (ee.size() > 10) t[i].ee_prefix.assign(ee.begin() + 6, ee.end() - 4);
      t[i].ok = !t[i].ch1.empty() && t[i].x25519.size() == 32;
    }
  }
  return t[hrr ? 1 : 0];
}

struct Random {
  Bytes scalar;
  static GTLS_Result fn(void * user, void * out, size_t n) {
    Random * self = static_cast<Random *>(user);
    if (self->scalar.size() != n) {
      std::memset(out, 0x2a, n);
      return GTLS_OK;
    }
    std::memcpy(out, self->scalar.data(), n);
    return GTLS_OK;
  }
};

/** Accept whatever chain there is: the certificate is exercised by test_negative. */
inline GTLS_Result accept(void *, const GTLS_Conn *, const GTLS_CertificateMsg *, int64_t) {
  return GTLS_OK;
}

/**
 * The client against a server stream. Input: an options byte, then segments
 * of [epoch][length high][length low][bytes]. Options: bit 0 picks the
 * HelloRetryRequest trace's ClientHello, bits 1-3 the feed size, bit 4 a
 * small message limit.
 */
inline int client_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  const Trace & tr = trace((opt & 1u) != 0);
  if (!tr.ok) {
    die("the RFC 8448 vectors could not be read");
  }
  static const size_t chunks[8] = {0, 1, 2, 3, 5, 16, 100, 0};
  const size_t chunk = chunks[(opt >> 1) & 7u];

  GCERT_TrustStore * store = nullptr;
  if (gcert_trust_new(nullptr, nullptr, &store) != GCERT_OK) {
    die("trust store");
  }
  GTLS_ContextConfig cfg;
  gtls_context_config_default(&cfg);
  cfg.trust = store;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  if ((opt & 0x10u) != 0) {
    lim.max_handshake_message = 700;
    lim.max_certificates = 1;
    lim.max_extensions = 4;
    lim.max_signature_bytes = 64;
  }
  cfg.limits = &lim;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  if (gtls_context_new(nullptr, &cfg, &ctx) != GTLS_OK ||
      gtls_conn_new(ctx, "server", 6, &conn) != GTLS_OK) {
    die("context or connection");
  }
  Random rnd;
  rnd.scalar = tr.p256;
  gtls_conn_set_hooks(conn, Random::fn, &rnd, accept, nullptr);
  note(conn);
  if (gtls_conn_start_raw(conn, tr.ch1.data(), tr.ch1.size(), tr.x25519.data()) != GTLS_OK) {
    die("start");
  }
  note(conn);

  size_t at = 1;
  while (at + 3 <= size && !gtls_conn_is_failed(conn)) {
    const GTLS_Epoch epoch = static_cast<GTLS_Epoch>(data[at] & 3u);
    size_t len = (static_cast<size_t>(data[at + 1]) << 8) | data[at + 2];
    at += 3;
    if (len > size - at) {
      len = size - at;
    }
    size_t step = chunk == 0 ? len : chunk;
    for (size_t off = 0; off < len && !gtls_conn_is_failed(conn); off += step) {
      size_t n = len - off < step ? len - off : step;
      GTLS_Result r = gtls_conn_feed(conn, epoch, data + at + off, n, 1700000000);
      note(conn);
      if (r != GTLS_OK && !gtls_conn_is_failed(conn)) {
        die("feed failed without failing the connection");
      }
      if (r == GTLS_OK && gtls_conn_is_failed(conn)) {
        die("connection failed on a call that returned OK");
      }
    }
    at += len;
  }
  if (gtls_conn_is_failed(conn)) {
    if (!gtls_conn_secrets_are_wiped(conn)) {
      die("a failed connection kept a secret");
    }
    if (gtls_conn_alert(conn) == GTLS_ALERT_NONE) {
      die("a failed connection has no alert");
    }
    if (gtls_conn_failure(conn) == GTLS_OK) {
      die("a failed connection has no reason");
    }
  }
  /* Accessors never trip, whatever the state. */
  unsigned char buf[GTLS_HASH_MAX];
  size_t n = 0;
  const unsigned char * p = nullptr;
  for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
    (void)gtls_conn_pending_output(conn, static_cast<GTLS_Epoch>(e), &p, &n);
    for (int d = 0; d < 2; d++) {
      (void)gtls_conn_secret(conn, static_cast<GTLS_Epoch>(e), static_cast<GTLS_Direction>(d),
          buf, sizeof buf, &n);
    }
  }
  const unsigned char * q = nullptr;
  (void)gtls_conn_alpn(conn, &q, &n);
  (void)gtls_conn_peer_certificate(conn, &q, &n);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
  gcert_trust_free(store);
  return 0;
}

/**
 * Every parser and builder, with limits taken from the input. Input: an
 * options byte (bits 0-3 pick the parser, bits 4-7 the limits), then the
 * message body.
 */
inline int msg_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  const uint8_t * body = data + 1;
  const size_t len = size - 1;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  lim.max_extensions = 1u + ((opt >> 4) & 15u);
  lim.max_certificates = 1u + ((opt >> 4) & 7u);
  lim.max_certificate_bytes = 16u << ((opt >> 5) & 7u);
  lim.max_signature_bytes = 8u << ((opt >> 5) & 7u);
  lim.max_ticket_bytes = 8u << ((opt >> 4) & 7u);
  lim.max_cookie_bytes = 4u << ((opt >> 4) & 7u);

  auto inside = [&](const void * p, size_t n) {
    const unsigned char * c = static_cast<const unsigned char *>(p);
    return n == 0 || (c >= body && c + n <= body + len);
  };
  switch (opt & 15u) {
    case 0: {
      GTLS_ServerHello s;
      if (gtls_msg_parse_server_hello(body, len, &lim, &s) == GTLS_OK) {
        if (!inside(s.random, 32) || !inside(s.session_id, s.session_id_len) ||
            !inside(s.key_exchange, s.key_exchange_len) || !inside(s.cookie, s.cookie_len)) {
          die("a ServerHello view points outside its input");
        }
        if (s.cookie_len > lim.max_cookie_bytes) die("cookie past its cap");
      }
      break;
    }
    case 1: {
      GTLS_EncryptedExtensions e;
      if (gtls_msg_parse_encrypted_extensions(body, len, &lim, &e) == GTLS_OK) {
        if (e.ext_count > lim.max_extensions) die("extensions past their cap");
        for (size_t i = 0; i < e.ext_count; i++) {
          if (!inside(e.exts[i].data, e.exts[i].len)) die("an extension points outside");
        }
        if (e.has_alpn && (!inside(e.alpn, e.alpn_len) || e.alpn_len == 0)) die("alpn");
      }
      break;
    }
    case 2: {
      GTLS_CertificateMsg c;
      if (gtls_msg_parse_certificate(body, len, &lim, &c) == GTLS_OK) {
        if (c.count > lim.max_certificates || c.count > GTLS_CERT_MAX) die("certificates past the cap");
        for (size_t i = 0; i < c.count; i++) {
          if (!inside(c.der[i], c.der_len[i]) || c.der_len[i] > lim.max_certificate_bytes ||
              c.der_len[i] == 0) {
            die("a certificate view");
          }
        }
      }
      break;
    }
    case 3: {
      GTLS_CertificateVerifyMsg cv;
      if (gtls_msg_parse_certificate_verify(body, len, &lim, &cv) == GTLS_OK) {
        if (!inside(cv.signature, cv.signature_len) || cv.signature_len > lim.max_signature_bytes ||
            cv.signature_len == 0) {
          die("a signature view");
        }
      }
      break;
    }
    case 4: {
      GTLS_NewSessionTicket t;
      if (gtls_msg_parse_new_session_ticket(body, len, &lim, &t) == GTLS_OK) {
        if (!inside(t.ticket, t.ticket_len) || !inside(t.nonce, t.nonce_len) ||
            t.ticket_len > lim.max_ticket_bytes || t.ticket_len == 0) {
          die("a ticket view");
        }
      }
      break;
    }
    case 5: {
      GTLS_ClientHello h;
      if (gtls_msg_parse_client_hello(body, len, &lim, &h) == GTLS_OK) {
        if (!inside(h.random, 32) || !inside(h.suites, h.suites_len) || h.ext_count > lim.max_extensions ||
            !inside(h.compression, h.compression_len) || h.compression_len == 0) {
          die("a ClientHello view");
        }
      }
      break;
    }
    case 6: {
      /* The retry transform takes a whole message, header included: make
       * one of the fuzzer's bytes and see that what it makes parses. */
      Bytes m = {1, static_cast<unsigned char>(len >> 16), static_cast<unsigned char>(len >> 8),
          static_cast<unsigned char>(len)};
      m.insert(m.end(), body, body + len);
      GTLS_Buf out;
      gtls_buf_init(&out, nullptr, 1u << 16);
      GTLS_KeyShare share;
      std::memset(&share, 0, sizeof share);
      share.group = GTLS_GROUP_SECP256R1;
      share.pub_len = 65;
      share.pub[0] = 4;
      unsigned char cookie[4] = {1, 2, 3, 4};
      GTLS_Result r = gtls_msg_retry_client_hello(m.data(), m.size(),
          (opt & 16u) ? &share : nullptr, cookie, (opt & 32u) ? 4 : 0, &lim, &out);
      if (r == GTLS_OK) {
        GTLS_ClientHello h2;
        GTLS_Limits wide;
        gtls_limits_default(&wide);
        wide.max_extensions = GTLS_EXT_MAX;
        if (gtls_msg_parse_client_hello(out.data + 4, out.len - 4, &wide, &h2) != GTLS_OK) {
          die("the retry transform wrote a hello that does not parse");
        }
        if (((static_cast<size_t>(out.data[1]) << 16) | (static_cast<size_t>(out.data[2]) << 8) |
                out.data[3]) != out.len - 4) {
          die("the retry transform's header length is wrong");
        }
      }
      gtls_buf_free(&out);
      break;
    }
    case 7: {
      /* What a server reads out of a ClientHello: every extension through its
       * own parser. Views stay inside the input, counts stay under their caps. */
      GTLS_ClientHello h;
      if (gtls_msg_parse_client_hello(body, len, &lim, &h) != GTLS_OK) {
        break;
      }
      for (size_t i = 0; i < h.ext_count; i++) {
        const GTLS_Ext * e = &h.exts[i];
        switch (e->type) {
          case GTLS_EXT_SUPPORTED_VERSIONS: {
            int has = 0;
            (void)gtls_msg_parse_ch_versions(e, &has);
            break;
          }
          case GTLS_EXT_SUPPORTED_GROUPS:
          case GTLS_EXT_SIGNATURE_ALGORITHMS: {
            uint16_t list[GTLS_CH_LIST_MAX];
            size_t n = 0;
            if (gtls_msg_parse_ch_u16_list(e, list, GTLS_CH_LIST_MAX, &n) == GTLS_OK &&
                (n > GTLS_CH_LIST_MAX || n * 2 > e->len)) {
              die("a list longer than its extension");
            }
            break;
          }
          case GTLS_EXT_KEY_SHARE: {
            GTLS_ClientShare shares[GTLS_CH_SHARES_MAX];
            size_t n = 0;
            if (gtls_msg_parse_ch_key_shares(e, shares, &n) == GTLS_OK) {
              if (n > GTLS_CH_SHARES_MAX) die("shares past their cap");
              for (size_t k = 0; k < n; k++) {
                if (!inside(shares[k].kx, shares[k].kx_len) || shares[k].kx_len == 0) die("a share view");
                for (size_t j = 0; j < k; j++) {
                  if (shares[j].group == shares[k].group) die("two shares for one group");
                }
              }
            }
            break;
          }
          case GTLS_EXT_ALPN: {
            GTLS_Name names[GTLS_CH_NAMES_MAX];
            size_t n = 0;
            if (gtls_msg_parse_ch_alpn(e, names, &n) == GTLS_OK) {
              if (n > GTLS_CH_NAMES_MAX || n == 0) die("alpn names past their cap");
              for (size_t k = 0; k < n; k++) {
                if (!inside(names[k].p, names[k].len) || names[k].len == 0 || names[k].len > 255) {
                  die("an alpn name view");
                }
              }
            }
            break;
          }
          case GTLS_EXT_SERVER_NAME: {
            GTLS_Name host;
            if (gtls_msg_parse_ch_server_name(e, &host) == GTLS_OK && !inside(host.p, host.len)) {
              die("a host name view");
            }
            break;
          }
          case GTLS_EXT_COOKIE: {
            GTLS_Name c;
            if (gtls_msg_parse_ch_cookie(e, &c) == GTLS_OK && (!inside(c.p, c.len) || c.len == 0)) {
              die("a cookie view");
            }
            break;
          }
          case GTLS_EXT_PSK_KEY_EXCHANGE_MODES: {
            int dhe = 0;
            (void)gtls_msg_parse_ch_psk_modes(e, &dhe);
            break;
          }
          default:
            break;
        }
      }
      break;
    }
    case 8: {
      const unsigned char * v = nullptr;
      size_t hlen = (opt & 16u) ? 48 : 32;
      if (gtls_msg_parse_finished(body, len, hlen, &v) == GTLS_OK) {
        if (len != hlen || v != body) die("a Finished view");
      }
      unsigned req = 9;
      if (gtls_msg_parse_key_update(body, len, &req) == GTLS_OK) {
        if (len != 1 || req > 1) die("a KeyUpdate that is not one");
      }
      break;
    }
    default: {
      /* Build from the input's bytes, then parse back what was built. */
      GTLS_Buf b;
      gtls_buf_init(&b, nullptr, 1u << 18);
      size_t n = len < 200 ? len : 200;
      GTLS_Result r;
      switch (opt & 3u) {
        case 0: {
          GTLS_ServerHelloParams p;
          std::memset(&p, 0, sizeof p);
          p.is_hrr = (opt & 16u) != 0;
          std::memcpy(p.random, "0123456789abcdef0123456789abcdef", 32);
          p.session_id = body;
          p.session_id_len = n < 32 ? n : 32;
          p.suite = 0x1301;
          p.group = 0x001d;
          unsigned char kx[32] = {1};
          p.key_exchange = kx;
          p.key_exchange_len = 32;
          r = gtls_msg_build_server_hello(&p, &b);
          if (r == GTLS_OK) {
            GTLS_ServerHello sh;
            if (gtls_msg_parse_server_hello(b.data + 4, b.len - 4, &lim, &sh) == GTLS_OK) {
              if (sh.is_hrr != (p.is_hrr != 0) || sh.suite != 0x1301 || sh.session_id_len != p.session_id_len) {
                die("a built ServerHello does not parse back to itself");
              }
            } else if (lim.max_extensions >= 3) {
              die("a built ServerHello does not parse");
            }
          }
          break;
        }
        case 1: {
          GTLS_EeParams p;
          std::memset(&p, 0, sizeof p);
          p.ack_server_name = (opt & 16u) != 0;
          p.alpn = n > 0 ? body : nullptr;
          p.alpn_len = n < 255 ? n : 255;
          r = gtls_msg_build_encrypted_extensions(&p, &b);
          if (r == GTLS_OK) {
            GTLS_EncryptedExtensions ee;
            if (gtls_msg_parse_encrypted_extensions(b.data + 4, b.len - 4, &lim, &ee) == GTLS_OK) {
              if (ee.has_alpn != (p.alpn_len != 0) || ee.has_server_name != p.ack_server_name) {
                die("built EncryptedExtensions do not parse back to themselves");
              }
            }
          }
          break;
        }
        case 2: {
          const unsigned char * der[3] = {body, body, body};
          size_t dl[3] = {n, n, n};
          r = n > 0 ? gtls_msg_build_certificate(der, dl, 1 + (opt >> 4) % 3, &b) : GTLS_ERR_INVALID;
          if (r == GTLS_OK) {
            GTLS_CertificateMsg c;
            if (gtls_msg_parse_certificate(b.data + 4, b.len - 4, &lim, &c) == GTLS_OK) {
              if (c.count != 1u + (opt >> 4) % 3) die("built Certificate does not parse back");
            }
          }
          break;
        }
        default: {
          r = n > 0 ? gtls_msg_build_certificate_verify(0x0804, body, n, &b) : GTLS_ERR_INVALID;
          if (r == GTLS_OK) {
            GTLS_CertificateVerifyMsg cv;
            if (gtls_msg_parse_certificate_verify(b.data + 4, b.len - 4, &lim, &cv) == GTLS_OK) {
              if (cv.signature_len != n || cv.scheme != 0x0804) die("built CertificateVerify does not parse back");
            }
          }
          break;
        }
      }
      gtls_buf_free(&b);
      break;
    }
  }
  return 0;
}

/* --------------------------------------------------------------- the records */

/**
 * Record protection with the input choosing everything: an options byte
 * (bits 0-1 the suite, bit 2 padding, bit 3 open-only), then bytes. A
 * record sealed from the input must open to it; arbitrary bytes given as a
 * record must never open to more than a record may hold, and never move the
 * counter on failure.
 */
inline int record_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  static const GTLS_Suite suites[3] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
      GTLS_SUITE_CHACHA20_POLY1305_SHA256};
  const GTLS_Suite suite = suites[(opt & 3u) % 3u];
  unsigned char secret[GTLS_HASH_MAX];
  std::memset(secret, 0x5c, sizeof secret);
  GTLS_RecordKeys w, r;
  if (gtls_record_keys_from_secret(&w, suite, secret, 4) != GTLS_OK ||
      gtls_record_keys_from_secret(&r, suite, secret, 4) != GTLS_OK) {
    die("record keys");
  }
  const uint8_t * body = data + 1;
  const size_t len = size - 1;
  unsigned char out[GTLS_RECORD_CIPHER_MAX + 16];
  if ((opt & 8u) == 0) {
    size_t pt_len = len < GTLS_RECORD_PLAIN_MAX ? len : GTLS_RECORD_PLAIN_MAX;
    size_t pad = (opt & 4u) ? (len % 40u) : 0;
    GTLS_Buf b;
    gtls_buf_init(&b, nullptr, 1u << 16);
    unsigned type = 21u + (len % 3u);
    if (gtls_record_seal(&w, type, body, pt_len, pad, &b) == GTLS_OK) {
      size_t n = 0;
      unsigned t = 0;
      if (gtls_record_open(&r, b.data, b.data + 5, b.len - 5, 100, out, &n, &t) != GTLS_OK ||
          n != pt_len || t != type || (pt_len != 0 && std::memcmp(out, body, pt_len) != 0)) {
        die("a sealed record does not open to what was sealed");
      }
      /* the same record again is a replay */
      if (gtls_record_open(&r, b.data, b.data + 5, b.len - 5, 100, out, &n, &t) == GTLS_OK) {
        die("a record opened twice under one number");
      }
      if (b.len > 6) {
        b.data[b.len / 2] ^= 1;
        if (gtls_record_open(&r, b.data, b.data + 5, b.len - 5, 100, out, &n, &t) == GTLS_OK) {
          die("a tampered record opened");
        }
      }
    }
    gtls_buf_free(&b);
  } else if (len >= 5) {
    size_t n = 0;
    unsigned t = 0;
    uint64_t before = r.seq;
    GTLS_Result res = gtls_record_open(&r, body, body + 5, len - 5, 64, out, &n, &t);
    if (res == GTLS_OK) {
      die("an arbitrary record opened");
    }
    if (r.seq != before) die("a failed open moved the counter");
    (void)n;
  }
  return 0;
}

/* ------------------------------------------------- the server and the client, as streams */

inline Bytes read_data(const std::string & name) {
#ifdef GTLS_TEST_DATA
  const std::string dir = GTLS_TEST_DATA;
#else
  const std::string dir = "tests/data";
#endif
  std::ifstream in(dir + "/pki/" + name, std::ios::binary);
  Bytes out;
  char buf[4096];
  while (in.read(buf, sizeof buf) || in.gcount() > 0) {
    const size_t n = static_cast<size_t>(in.gcount());
    for (size_t i = 0; i < n; i++) {
      out.push_back(static_cast<unsigned char>(buf[i]));
    }
  }
  return out;
}

struct Pcg {
  uint64_t state = 0x853c49e6748fea9bull;
  uint64_t inc = 0xda3e39cb94b95bdbull;
  uint32_t next() {
    uint64_t old = state;
    state = old * 6364136223846793005ull + inc;
    uint32_t xs = static_cast<uint32_t>(((old >> 18u) ^ old) >> 27u);
    uint32_t rot = static_cast<uint32_t>(old >> 59u);
    return (xs >> rot) | (xs << ((~rot + 1u) & 31u));
  }
};

/** Deterministic bytes: the first two draws of a server are the RFC trace's, the rest a counter stream. */
struct ServerRandom {
  Bytes first, second;
  int draws = 0;
  Pcg pcg;
  static GTLS_Result fn(void * user, void * out, size_t n) {
    ServerRandom * self = static_cast<ServerRandom *>(user);
    int d = self->draws++;
    if (d == 0 && self->first.size() == n) {
      std::memcpy(out, self->first.data(), n);
      return GTLS_OK;
    }
    if (d == 1 && self->second.size() == n) {
      std::memcpy(out, self->second.data(), n);
      return GTLS_OK;
    }
    unsigned char * p = static_cast<unsigned char *>(out);
    for (size_t i = 0; i < n; i++) p[i] = static_cast<unsigned char>(self->pcg.next() | 1u);
    return GTLS_OK;
  }
};

struct FuzzSign {
  const Bytes * sig;
  static GTLS_Result fn(void * user, const GTLS_Conn *, unsigned, const unsigned char *, size_t,
      unsigned char * out, size_t cap, size_t * len) {
    FuzzSign * self = static_cast<FuzzSign *>(user);
    if (self->sig->size() > cap) return GTLS_ERR_LIMIT;
    std::memcpy(out, self->sig->data(), self->sig->size());
    *len = self->sig->size();
    return GTLS_OK;
  }
};

/** What every connection must satisfy once an input has been run through it. */
inline void check_end_state(GTLS_Conn * conn) {
  if (gtls_conn_is_failed(conn)) {
    if (!gtls_conn_secrets_are_wiped(conn)) die("a failed connection kept a secret");
    GTLS_Result why = gtls_conn_failure(conn);
    if (why == GTLS_OK) die("a failed connection has no reason");
    /* A peer's alert and the end of the stream have nobody to be answered. */
    if (gtls_conn_alert(conn) == GTLS_ALERT_NONE && why != GTLS_ERR_ALERT && why != GTLS_ERR_TRUNCATED) {
      die("a failed connection has no alert");
    }
    unsigned char b[8];
    size_t n = 0;
    if (gtls_conn_read(conn, b, sizeof b, &n) != GTLS_ERR_FAILED && n != 0) die("read after failure");
    size_t w = 0;
    if (gtls_conn_write(conn, b, 1, &w) != GTLS_ERR_FAILED || w != 0) die("write after failure");
    size_t used = 7;
    if (gtls_conn_stream_feed(conn, b, 1, 1700000000, &used) != GTLS_ERR_FAILED || used != 0) {
      die("a record accepted after a failure");
    }
  }
}

/**
 * The server, fed a stream of records. Input: an options byte, then the raw
 * bytes of the stream. Options: bit 0 picks the HelloRetryRequest trace's
 * ClientHellos and keys, bits 1-3 the feed size, bit 4 a server that wants
 * only P-256 (so the RFC's X25519 share is answered with a retry), bit 5
 * has the server act on what it can (write, key update, close) when the
 * handshake completes, bit 6 small limits.
 */
inline int server_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  const Trace & tr = trace((opt & 1u) != 0);
  if (!tr.ok || tr.cert_der.empty()) {
    die("the RFC 8448 vectors could not be read");
  }
  static const size_t chunks[8] = {0, 1, 2, 3, 5, 16, 100, 0};
  const size_t chunk = chunks[(opt >> 1) & 7u];

  /* An identity is needed to make the context; the trace's chain replaces it. */
  static const Bytes cert = read_data("ed-leaf.der");
  static const Bytes pkcs8 = read_data("ed-leaf.pkcs8");
  if (cert.empty() || pkcs8.empty()) {
    die("the test certificates could not be read");
  }
  GCERT_Key * key = nullptr;
  if (gcert_key_from_pkcs8(nullptr, pkcs8.data(), pkcs8.size(), &key) != GCERT_OK) {
    die("key");
  }
  const void * chain[1] = {cert.data()};
  size_t lens[1] = {cert.size()};
  GTLS_Identity id = {chain, lens, 1, key, nullptr, 0};
  GTLS_ContextConfig cfg;
  gtls_context_config_default(&cfg);
  cfg.role = GTLS_ROLE_SERVER;
  cfg.identities = &id;
  cfg.identity_count = 1;
  GTLS_Group p256only[1] = {GTLS_GROUP_SECP256R1};
  if ((opt & 0x10u) != 0) {
    cfg.groups = p256only;
    cfg.group_count = 1;
  }
  static const char * const alpn[] = {"h2", "http/1.1"};
  cfg.alpn = alpn;
  cfg.alpn_count = 2;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  if ((opt & 0x40u) != 0) {
    lim.max_client_hello = 400;   /* the RFC's hello is 192 bytes and 9 extensions: room for a PSK offer */
    lim.max_extensions = 16;
    lim.max_records_per_key = 3;
    lim.max_app_buffer = 20000;
    lim.max_key_updates = 2;
    lim.max_record_padding = 8;
    lim.max_tickets = 1;        /* the PSK offer's caps: one identity of 12 bytes */
    lim.max_ticket_bytes = 12;
  }
  cfg.limits = &lim;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  if (gtls_context_new(nullptr, &cfg, &ctx) != GTLS_OK || gtls_conn_new_server(ctx, &conn) != GTLS_OK) {
    die("context or connection");
  }
  ServerRandom rnd;
  rnd.first = tr.sh_random;
  rnd.second = tr.server_x25519;
  const unsigned char * seam_chain[1] = {tr.cert_der.data()};
  size_t seam_len[1] = {tr.cert_der.size()};
  FuzzSign sign;
  sign.sig = &tr.cv_sig;
  gtls_conn_set_hooks(conn, ServerRandom::fn, &rnd, nullptr, nullptr);
  gtls_conn_set_server_hooks(conn, FuzzSign::fn, &sign, seam_chain, seam_len, 1, 0x0804,
      tr.ee_prefix.data(), tr.ee_prefix.size());
  note(conn);
  if (gtls_conn_start(conn) != GTLS_OK) {
    die("start");
  }
  note(conn);

  const uint8_t * in = data + 1;
  const size_t in_len = size - 1;
  size_t at = 0;
  unsigned char rd[256];
  while (at < in_len && !gtls_conn_is_failed(conn)) {
    size_t n = chunk == 0 ? in_len - at : (in_len - at < chunk ? in_len - at : chunk);
    size_t used = 0;
    GTLS_Result r = gtls_conn_stream_feed(conn, in + at, n, 1700000000, &used);
    note(conn);
    if (r != GTLS_OK && !gtls_conn_is_failed(conn)) die("feed failed without failing the connection");
    if (r == GTLS_OK && gtls_conn_is_failed(conn)) die("connection failed on a call that returned OK");
    if (used > n) die("more consumed than offered");
    at += used;
    size_t k = 0;
    while (gtls_conn_read(conn, rd, sizeof rd, &k) == GTLS_OK && k != 0) {
    }
    const unsigned char * p = nullptr;
    size_t m = 0;
    if (gtls_conn_stream_output(conn, &p, &m) != GTLS_OK) die("output");
    if (m > 0) (void)gtls_conn_stream_consume(conn, m);
    if (used == 0 && r == GTLS_OK) break;
  }
  if ((opt & 0x20u) != 0 && gtls_conn_is_connected(conn)) {
    size_t w = 0;
    unsigned char payload[40000];
    std::memset(payload, 0x61, sizeof payload);
    (void)gtls_conn_write(conn, payload, sizeof payload, &w);
    (void)gtls_conn_key_update(conn, 1);
    (void)gtls_conn_write(conn, payload, 10, &w);
    const unsigned char * p = nullptr;
    size_t m = 0;
    (void)gtls_conn_stream_output(conn, &p, &m);
    (void)gtls_conn_close(conn);
    note(conn);
  }
  if ((opt & 0x80u) != 0) {
    (void)gtls_conn_stream_eof(conn);
    note(conn);
  }
  check_end_state(conn);
  /* accessors never trip */
  unsigned char buf[GTLS_HASH_MAX];
  size_t n = 0;
  for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
    for (int d = 0; d < 2; d++) {
      (void)gtls_conn_secret(conn, static_cast<GTLS_Epoch>(e), static_cast<GTLS_Direction>(d), buf, sizeof buf, &n);
    }
  }
  const unsigned char * q = nullptr;
  size_t ql = 0;
  (void)gtls_conn_alpn(conn, &q, &ql);
  (void)gtls_conn_server_name(conn, &q, &ql);
  size_t index = 0;
  (void)gtls_conn_identity(conn, &index);
  (void)gtls_conn_peer_certificate(conn, &q, &ql);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
  gcert_key_free(key);
  return 0;
}

/**
 * The client, fed a stream of records, in the RFC's own setting. Input: an
 * options byte (bit 0 the retry trace, bits 1-3 the feed size, bit 5 act on
 * a completed handshake, bit 6 small limits), then the stream.
 */
inline int client_stream_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  const Trace & tr = trace((opt & 1u) != 0);
  if (!tr.ok) {
    die("the RFC 8448 vectors could not be read");
  }
  static const size_t chunks[8] = {0, 1, 2, 3, 5, 16, 100, 0};
  const size_t chunk = chunks[(opt >> 1) & 7u];
  GCERT_TrustStore * store = nullptr;
  if (gcert_trust_new(nullptr, nullptr, &store) != GCERT_OK) die("trust store");
  GTLS_ContextConfig cfg;
  gtls_context_config_default(&cfg);
  cfg.trust = store;
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  if ((opt & 0x40u) != 0) {
    lim.max_handshake_message = 700;
    lim.max_certificates = 1;
    lim.max_records_per_key = 3;
    lim.max_app_buffer = 20000;
    lim.max_key_updates = 2;
    lim.max_record_padding = 8;
  }
  cfg.limits = &lim;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  if (gtls_context_new(nullptr, &cfg, &ctx) != GTLS_OK || gtls_conn_new(ctx, "server", 6, &conn) != GTLS_OK) {
    die("context or connection");
  }
  Random rnd;
  rnd.scalar = tr.p256;
  gtls_conn_set_hooks(conn, Random::fn, &rnd, accept, nullptr);
  note(conn);
  if (gtls_conn_start_raw(conn, tr.ch1.data(), tr.ch1.size(), tr.x25519.data()) != GTLS_OK) die("start");
  note(conn);
  const uint8_t * in = data + 1;
  const size_t in_len = size - 1;
  size_t at = 0;
  unsigned char rd[256];
  while (at < in_len && !gtls_conn_is_failed(conn)) {
    size_t n = chunk == 0 ? in_len - at : (in_len - at < chunk ? in_len - at : chunk);
    size_t used = 0;
    GTLS_Result r = gtls_conn_stream_feed(conn, in + at, n, 1700000000, &used);
    note(conn);
    if (r != GTLS_OK && !gtls_conn_is_failed(conn)) die("feed failed without failing the connection");
    if (r == GTLS_OK && gtls_conn_is_failed(conn)) die("connection failed on a call that returned OK");
    if (used > n) die("more consumed than offered");
    at += used;
    size_t k = 0;
    while (gtls_conn_read(conn, rd, sizeof rd, &k) == GTLS_OK && k != 0) {
    }
    const unsigned char * p = nullptr;
    size_t m = 0;
    if (gtls_conn_stream_output(conn, &p, &m) != GTLS_OK) die("output");
    if (m > 0) (void)gtls_conn_stream_consume(conn, m);
    if (used == 0 && r == GTLS_OK) break;
  }
  if ((opt & 0x20u) != 0 && gtls_conn_is_connected(conn)) {
    size_t w = 0;
    (void)gtls_conn_write(conn, "hello", 5, &w);
    (void)gtls_conn_key_update(conn, 1);
    (void)gtls_conn_write(conn, "world", 5, &w);
    (void)gtls_conn_close(conn);
    note(conn);
  }
  if ((opt & 0x80u) != 0) {
    (void)gtls_conn_stream_eof(conn);
    note(conn);
  }
  check_end_state(conn);
  gtls_conn_free(conn);
  gtls_context_free(ctx);
  gcert_trust_free(store);
  return 0;
}

/* ------------------------------------------------- two endpoints and mutated bytes */

struct PumpRandom {
  Pcg pcg;
  static GTLS_Result fn(void * user, void * out, size_t n) {
    PumpRandom * self = static_cast<PumpRandom *>(user);
    unsigned char * p = static_cast<unsigned char *>(out);
    for (size_t i = 0; i < n; i++) p[i] = static_cast<unsigned char>(self->pcg.next() | 1u);
    return GTLS_OK;
  }
};

/**
 * A real client and a real server, with every byte that crosses between them
 * liable to be changed. Input: an options byte, then three-byte entries
 * (a direction bit and a 15-bit offset into that direction's stream, and a
 * byte to xor in there). Options: bits 0-1 the suite (3 is the default
 * order), bits 2-3 the group (3: the default order, a retry when the server
 * wants P-256 only), bit 4 a server that wants P-256 only, bits 5-7 the
 * feed size.
 */
inline int pump_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  static const GTLS_Suite suites[3] = {GTLS_SUITE_AES_128_GCM_SHA256, GTLS_SUITE_AES_256_GCM_SHA384,
      GTLS_SUITE_CHACHA20_POLY1305_SHA256};
  static const GTLS_Group groups[3] = {GTLS_GROUP_X25519, GTLS_GROUP_SECP256R1, GTLS_GROUP_SECP384R1};
  static const size_t chunks[8] = {0, 1, 3, 7, 29, 100, 1000, 0};
  const size_t chunk = chunks[(opt >> 5) & 7u];
  static const Bytes leaf = read_data("ed-leaf.der");
  static const Bytes ca = read_data("ed-ca.der");
  static const Bytes key_der = read_data("ed-leaf.pkcs8");
  if (leaf.empty() || ca.empty() || key_der.empty()) {
    die("the test certificates could not be read");
  }
  GCERT_TrustStore * store = nullptr;
  GCERT_Key * key = nullptr;
  if (gcert_trust_new(nullptr, nullptr, &store) != GCERT_OK ||
      gcert_trust_add_der(store, ca.data(), ca.size()) != GCERT_OK ||
      gcert_key_from_pkcs8(nullptr, key_der.data(), key_der.size(), &key) != GCERT_OK) {
    die("trust or key");
  }
  GTLS_ContextConfig ccfg, scfg;
  gtls_context_config_default(&ccfg);
  gtls_context_config_default(&scfg);
  ccfg.trust = store;
  scfg.role = GTLS_ROLE_SERVER;
  const void * chain[1] = {leaf.data()};
  size_t lens[1] = {leaf.size()};
  const char * names[1] = {"ed.example.com"};
  GTLS_Identity id = {chain, lens, 1, key, names, 1};
  scfg.identities = &id;
  scfg.identity_count = 1;
  static const char * const calpn[] = {"h2", "http/1.1"};
  static const char * const salpn[] = {"http/1.1"};
  ccfg.alpn = calpn;
  ccfg.alpn_count = 2;
  scfg.alpn = salpn;
  scfg.alpn_count = 1;
  GTLS_Suite suite = suites[(opt & 3u) % 3u];
  if ((opt & 3u) != 3u) {
    scfg.suites = &suite;
    scfg.suite_count = 1;
  }
  GTLS_Group group = groups[((opt >> 2) & 3u) % 3u];
  if (((opt >> 2) & 3u) != 3u) {
    ccfg.groups = &group;
    ccfg.group_count = 1;
  }
  GTLS_Group p256only[1] = {GTLS_GROUP_SECP256R1};
  if ((opt & 0x10u) != 0) {
    scfg.groups = p256only;
    scfg.group_count = 1;
    /* A client limited to another group has nothing in common with a server
     * that wants P-256 only, and an unmutated pump must connect. */
    ccfg.groups = nullptr;
    ccfg.group_count = 0;
  }
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  lim.max_records_per_key = 6;
  ccfg.limits = &lim;
  scfg.limits = &lim;
  GTLS_Context * cctx = nullptr;
  GTLS_Context * sctx = nullptr;
  GTLS_Conn * c = nullptr;
  GTLS_Conn * s = nullptr;
  if (gtls_context_new(nullptr, &ccfg, &cctx) != GTLS_OK || gtls_context_new(nullptr, &scfg, &sctx) != GTLS_OK ||
      gtls_conn_new(cctx, "ed.example.com", 14, &c) != GTLS_OK || gtls_conn_new_server(sctx, &s) != GTLS_OK) {
    die("contexts or connections");
  }
  PumpRandom crnd, srnd;
  crnd.pcg.state = 0x1234567;
  srnd.pcg.state = 0x7654321;
  gtls_conn_set_hooks(c, PumpRandom::fn, &crnd, nullptr, nullptr);
  gtls_conn_set_hooks(s, PumpRandom::fn, &srnd, nullptr, nullptr);
  note(c);
  note(s);
  if (gtls_conn_start(c) != GTLS_OK || gtls_conn_start(s) != GTLS_OK) die("start");
  note(c);
  note(s);

  struct Flip {
    int dir;
    size_t at;
    unsigned char xor_;
  };
  std::vector<Flip> flips;
  for (size_t i = 1; i + 3 <= size; i += 3) {
    unsigned v = (static_cast<unsigned>(data[i]) << 8) | data[i + 1];
    flips.push_back(Flip{static_cast<int>(v >> 15), static_cast<size_t>(v & 0x7fffu), data[i + 2]});
  }
  size_t sent[2] = {0, 0};
  GTLS_Conn * ends[2] = {c, s};
  bool wrote = false;
  Bytes expect_up(300, 0x55);
  Bytes got_up;
  for (int round = 0; round < 60; round++) {
    bool moved = false;
    for (int dir = 0; dir < 2; dir++) {
      GTLS_Conn * from = ends[dir];
      GTLS_Conn * to = ends[1 - dir];
      const unsigned char * p = nullptr;
      size_t n = 0;
      if (gtls_conn_stream_output(from, &p, &n) != GTLS_OK) die("output");
      if (n == 0) continue;
      moved = true;
      Bytes wire(p, p + n);
      for (const Flip & f : flips) {
        if (f.dir == dir && f.at >= sent[dir] && f.at < sent[dir] + n) wire[f.at - sent[dir]] ^= f.xor_;
      }
      sent[dir] += n;
      (void)gtls_conn_stream_consume(from, n);
      size_t at = 0;
      while (at < wire.size() && !gtls_conn_is_failed(to)) {
        size_t k = chunk == 0 ? wire.size() - at : (wire.size() - at < chunk ? wire.size() - at : chunk);
        size_t used = 0;
        GTLS_Result r = gtls_conn_stream_feed(to, wire.data() + at, k, 1700000000, &used);
        note(to);
        if (r != GTLS_OK && !gtls_conn_is_failed(to)) die("feed failed without failing the connection");
        if (r == GTLS_OK && gtls_conn_is_failed(to)) die("connection failed on a call that returned OK");
        at += used;
        unsigned char rd[512];
        size_t got = 0;
        while (gtls_conn_read(to, rd, sizeof rd, &got) == GTLS_OK && got != 0) {
          if (to == s) got_up.insert(got_up.end(), rd, rd + got);
        }
        if (used == 0 && r == GTLS_OK) break;
      }
    }
    if (!wrote && gtls_conn_is_connected(c) && gtls_conn_is_connected(s)) {
      wrote = true;
      size_t w = 0;
      for (int i = 0; i < 12; i++) (void)gtls_conn_write(c, expect_up.data(), expect_up.size(), &w);
      (void)gtls_conn_key_update(s, 1);
      (void)gtls_conn_write(s, expect_up.data(), 100, &w);
      moved = true;
    }
    if (!moved) break;
  }
  /* With no mutation at all, the run must have gone through completely. */
  if (flips.empty()) {
    if (!gtls_conn_is_connected(c) || !gtls_conn_is_connected(s)) die("an unmutated pump did not connect");
    if (got_up.size() != 12 * expect_up.size()) die("an unmutated pump lost data");
    (void)gtls_conn_close(c);
    (void)gtls_conn_close(s);
  }
  for (int round = 0; round < 6; round++) {
    for (int dir = 0; dir < 2; dir++) {
      const unsigned char * p = nullptr;
      size_t n = 0;
      (void)gtls_conn_stream_output(ends[dir], &p, &n);
      if (n == 0) continue;
      Bytes wire(p, p + n);
      (void)gtls_conn_stream_consume(ends[dir], n);
      size_t used = 0;
      (void)gtls_conn_stream_feed(ends[1 - dir], wire.data(), wire.size(), 1700000000, &used);
      note(ends[1 - dir]);
    }
  }
  check_end_state(c);
  check_end_state(s);
  gtls_conn_free(c);
  gtls_conn_free(s);
  gtls_context_free(cctx);
  gtls_context_free(sctx);
  gcert_key_free(key);
  gcert_trust_free(store);
  return 0;
}

} /* namespace gtlsfuzz */

#endif /* GHOTI_IO_GTLS_FUZZ_COMMON_H */
