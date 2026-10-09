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
        /* The cap on a ticket is the client's to apply, not the parser's. */
        if (!inside(t.ticket, t.ticket_len) || !inside(t.nonce, t.nonce_len) || t.ticket_len == 0) {
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
      /* With bit 6 the transform is also given a PSK to put in the second hello. */
      GTLS_PskParams pp = {body, len > 0 ? (len % 29) + 1 : 0, 0xdeadbeefu, (opt & 128u) ? 48u : 32u};
      const bool with_psk = (opt & 64u) != 0 && len > 0 && pp.identity_len <= len;
      GTLS_Result r = gtls_msg_retry_client_hello_psk(m.data(), m.size(),
          (opt & 16u) ? &share : nullptr, cookie, (opt & 32u) ? 4 : 0, with_psk ? &pp : nullptr,
          &lim, &out);
      if (r == GTLS_OK && with_psk) {
        GTLS_ClientHello h3;
        GTLS_Limits wide3;
        GTLS_PskOffer offer3;
        gtls_limits_default(&wide3);
        wide3.max_extensions = GTLS_EXT_MAX;
        if (gtls_msg_parse_client_hello(out.data + 4, out.len - 4, &wide3, &h3) != GTLS_OK ||
            h3.ext_count == 0 || h3.exts[h3.ext_count - 1].type != GTLS_EXT_PRE_SHARED_KEY ||
            gtls_msg_parse_ch_psk_offer(&h3.exts[h3.ext_count - 1], &wide3, &offer3) != GTLS_OK ||
            offer3.count != 1 || offer3.entries[0].identity_len != pp.identity_len ||
            offer3.entries[0].age != pp.obfuscated_age ||
            out.len - GTLS_PSK_BINDERS_TAIL(pp.binder_len) !=
                static_cast<size_t>(h3.exts[h3.ext_count - 1].data - (out.data + 4)) + 4 + offer3.binders_off) {
          die("the retry transform's PSK is not the one it was given, last, with the binders where they should be");
        }
      }
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
          case GTLS_EXT_PRE_SHARED_KEY: {
            GTLS_PskOffer o;
            if (gtls_msg_parse_ch_psk_offer(e, &lim, &o) == GTLS_OK) {
              if (o.count > lim.max_tickets || o.stored > GTLS_PSK_MAX || o.stored > o.count ||
                  (o.count <= GTLS_PSK_MAX && o.stored != o.count) || o.count == 0) {
                die("a PSK offer's counts");
              }
              if (o.binders_off < 2 || o.binders_off > e->len) die("the binders offset is outside the extension");
              for (size_t k = 0; k < o.stored; k++) {
                const GTLS_PskEntry & en = o.entries[k];
                if (!inside(en.identity, en.identity_len) || en.identity_len == 0 ||
                    !inside(en.binder, en.binder_len) ||
                    en.binder_len < 32) {
                  die("a PSK entry view");
                }
              }
            }
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
      if ((gtls_msg_parse_end_of_early_data(body, len) == GTLS_OK) != (len == 0)) {
        die("an EndOfEarlyData that has a body, or one that does not parse");
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
          p.early_data = (opt & 32u) != 0;
          p.alpn = n > 0 ? body : nullptr;
          p.alpn_len = n < 255 ? n : 255;
          r = gtls_msg_build_encrypted_extensions(&p, &b);
          if (r == GTLS_OK) {
            GTLS_EncryptedExtensions ee;
            if (gtls_msg_parse_encrypted_extensions(b.data + 4, b.len - 4, &lim, &ee) == GTLS_OK) {
              if (ee.has_alpn != (p.alpn_len != 0) || ee.has_server_name != p.ack_server_name ||
                  ee.has_early_data != p.early_data) {
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

/** The replay decision of the harnesses that accept early data: a verdict the input chose. */
struct FuzzReplay {
  int verdict = 1;
  int calls = 0;
  static int fn(void * user, const unsigned char[32], int64_t, uint32_t) {
    FuzzReplay * self = static_cast<FuzzReplay *>(user);
    self->calls++;
    return self->verdict;
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
    if (gtls_conn_alert(conn) == GTLS_ALERT_NONE && why != GTLS_ERR_ALERT && why != GTLS_ERR_TRUNCATED &&
        why != GTLS_ERR_CLOSED) {
      die("a failed connection has no alert");
    }
    unsigned char b[8];
    size_t n = 0;
    if (gtls_conn_read(conn, b, sizeof b, &n) != GTLS_ERR_FAILED && n != 0) die("read after failure");
    size_t w = 0;
    if (gtls_conn_write(conn, b, 1, &w) != GTLS_ERR_FAILED || w != 0) die("write after failure");
    /* Early data neither side hands out nor takes once the connection has failed. */
    GTLS_Result early = gtls_conn_read_early(conn, b, sizeof b, &n);
    if ((early != GTLS_ERR_FAILED && early != GTLS_ERR_INVALID) || n != 0) die("early data read after failure");
    if (gtls_conn_write_early(conn, b, 1, &w) != GTLS_ERR_FAILED || w != 0) die("early write after failure");
    GTLS_EarlyStatus status = GTLS_EARLY_NONE;
    if (gtls_conn_early_status(conn, &status) != GTLS_ERR_FAILED) die("early status after failure");
    early = gtls_conn_early_resend(conn, b, sizeof b, &n);
    if ((early != GTLS_ERR_FAILED && early != GTLS_ERR_INVALID) || n != 0) die("early data handed back after failure");
    size_t used = 7;
    if (gtls_conn_stream_feed(conn, b, 1, 1700000000, &used) != GTLS_ERR_FAILED || used != 0) {
      die("a record accepted after a failure");
    }
  }
}

/**
 * The server, fed a stream of records. Input: an options byte, then the raw
 * bytes of the stream. Options: bit 0 picks the HelloRetryRequest trace's
 * ClientHellos and keys, bits 1-2 the feed size, bit 3 a server with two
 * suites whose connection cannot issue a ticket, bit 4 a server that wants
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
  static const size_t chunks[4] = {0, 1, 2, 3};
  const size_t chunk = chunks[(opt >> 1) & 3u];
  /* Bit 3: a server that offers two of the three suites (no AES-256) and whose
   * connection will not carry a ticket as large as the smallest it seals, so a
   * ticket for the missing suite meets the context's list and a handshake that
   * finishes meets the cap on issuing. */
  const bool restricted = (opt & 0x08u) != 0;

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
  static const GTLS_Suite two_suites[2] = {GTLS_SUITE_AES_128_GCM_SHA256,
      GTLS_SUITE_CHACHA20_POLY1305_SHA256};
  if (restricted) {
    cfg.suites = two_suites;
    cfg.suite_count = 2;
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
  /* Early data: allowed, with a replay decision the input's size chooses (even
   * accepts, odd refuses), so a seed with a ticket that carries an allowance can
   * be accepted and the same seed a byte longer refused. */
  FuzzReplay replay;
  replay.verdict = (size & 1u) == 0 ? 1 : 0;
  cfg.max_early_data = 1024;
  cfg.anti_replay = FuzzReplay::fn;
  cfg.anti_replay_user = &replay;
  /* A keyring, so that a ticket in an offer is opened. No mutation can seal one;
   * the seeds carry tickets sealed under this key (name and key all 0x6b) by
   * tools/make-fuzz-seeds.py. The small-limits server has a ticket cap too
   * small for one. */
  GTLS_TicketKey ticket_key;
  std::memset(&ticket_key, 0x6b, sizeof ticket_key);
  ticket_key.not_before = 1699990000;
  ticket_key.not_after = 1700100000;
  if ((opt & 0x40u) == 0) {
    cfg.ticket_keys = &ticket_key;
    cfg.ticket_key_count = 1;
  }
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
  if (restricted && (opt & 0x40u) == 0) {
    /* The context refuses a cap below the largest ticket, so the connection's copy is lowered: no
     * ticket (98 bytes at least) fits it. */
    conn->limits.max_ticket_bytes = 90;
  }
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
    k = 0;
    while (gtls_conn_read_early(conn, rd, sizeof rd, &k) == GTLS_OK && k != 0) {
    }
    const unsigned char * p = nullptr;
    size_t m = 0;
    if (gtls_conn_stream_output(conn, &p, &m) != GTLS_OK) die("output");
    if (m > 0) (void)gtls_conn_stream_consume(conn, m);
    if (used == 0 && r == GTLS_OK) break;
  }
  {
    GTLS_EarlyStatus st = GTLS_EARLY_NONE;
    GTLS_Result sr = gtls_conn_early_status(conn, &st);
    if (!gtls_conn_is_failed(conn) && (sr == GTLS_ERR_EARLY_REJECTED) != (st == GTLS_EARLY_REJECTED)) {
      die("the early status and its result disagree");
    }
    if (st == GTLS_EARLY_ACCEPTED && replay.calls != 1) die("early data accepted without one decision");
    if (st != GTLS_EARLY_ACCEPTED && replay.calls > 1) die("the replay decision was asked twice");
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
 *
 * A resume run whose size is 2 more than a multiple of 3 (the flips use whole
 * triples) ends in a byte that picks a hostile peer, by its low three bits (bit 3 has the client
 * write no early data, bit 4 puts it in compatibility mode, bit 5 makes the server's decision yes;
 * 3 and 5 make it yes too):
 *   1 a server that does not take the PSK and says `early_data` in EncryptedExtensions anyway;
 *   2 a session whose suite is another of the same hash than the ticket's, so that the
 *     acceptance the server gives is for a suite the early records were not sealed under;
 *   3 a session whose ALPN protocol is not the ticket's;
 *   4 a server that answers with an ALPN protocol the client never offered;
 *   5 a wire that loses the client's EndOfEarlyData and keeps the Finished behind it;
 *   6 a server that has turned early data off in its context but holds a ticket with an allowance;
 *   7 a client that closes before the handshake is complete.
 * Modes 1-6 make the server's replay decision yes. What each must come to when
 * nothing else is changed is checked at the end of the run.
 */
inline int pump_core(const uint8_t * data, size_t size, bool resume) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  unsigned mode = 0;
  bool no_early = false;
  bool compat = false;
  bool accept = false;
  if (resume && size >= 3 && (size - 1) % 3 == 2) {
    mode = data[size - 1] & 7u;
    no_early = (data[size - 1] & 8u) != 0;   /* the client offers early data and writes none */
    compat = (data[size - 1] & 0x10u) != 0;  /* the client is in compatibility mode */
    accept = (data[size - 1] & 0x20u) != 0;  /* the server's decision is yes */
  }
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
  ccfg.middlebox_compat = compat ? 1 : 0;
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
  GTLS_TicketKey ticket_key;
  std::memset(&ticket_key, 0x6c, sizeof ticket_key);
  ticket_key.not_before = 1699990000;
  ticket_key.not_after = 1700100000;
  scfg.ticket_keys = &ticket_key;      /* every pump server issues tickets; resume mode uses one */
  scfg.ticket_key_count = 1;
  /* Early data on both sides: the tickets carry an allowance, and a resuming
   * client sends some. The server's replay decision is the input's size: even
   * says yes, odd says no. */
  FuzzReplay replay;
  replay.verdict = (size & 1u) == 0 || (mode >= 1 && mode <= 6) || no_early || accept ? 1 : 0;
  scfg.max_early_data = 512;
  scfg.anti_replay = FuzzReplay::fn;
  scfg.anti_replay_user = &replay;
  ccfg.max_early_data = 512;
  GTLS_Context * cctx = nullptr;
  GTLS_Context * sctx = nullptr;
  GTLS_Conn * c = nullptr;
  GTLS_Conn * s = nullptr;
  if (gtls_context_new(nullptr, &ccfg, &cctx) != GTLS_OK || gtls_context_new(nullptr, &scfg, &sctx) != GTLS_OK ||
      gtls_conn_new(cctx, "ed.example.com", 14, &c) != GTLS_OK || gtls_conn_new_server(sctx, &s) != GTLS_OK) {
    die("contexts or connections");
  }
  /* Resume mode: a first handshake, untouched, gives the session the mutated
   * one offers. */
  GTLS_Session * session = nullptr;
  if (resume) {
    GTLS_Conn * c1 = nullptr;
    GTLS_Conn * s1 = nullptr;
    PumpRandom r1, r2;
    r1.pcg.state = 0xabcdef1;
    r2.pcg.state = 0x1fedcba;
    if (gtls_conn_new(cctx, "ed.example.com", 14, &c1) != GTLS_OK || gtls_conn_new_server(sctx, &s1) != GTLS_OK) {
      die("first connections");
    }
    gtls_conn_set_hooks(c1, PumpRandom::fn, &r1, nullptr, nullptr);
    gtls_conn_set_hooks(s1, PumpRandom::fn, &r2, nullptr, nullptr);
    if (gtls_conn_start(c1) != GTLS_OK || gtls_conn_start(s1) != GTLS_OK) die("first start");
    GTLS_Conn * pair[2] = {c1, s1};
    for (int round = 0; round < 20; round++) {
      bool moved = false;
      for (int dir = 0; dir < 2; dir++) {
        const unsigned char * p = nullptr;
        size_t n = 0;
        if (gtls_conn_stream_output(pair[dir], &p, &n) != GTLS_OK) die("first output");
        if (n == 0) continue;
        moved = true;
        Bytes wire(p, p + n);
        (void)gtls_conn_stream_consume(pair[dir], n);
        size_t used = 0;
        if (gtls_conn_stream_feed(pair[1 - dir], wire.data(), wire.size(), 1700000000, &used) != GTLS_OK) {
          die("the first handshake of a resume run failed");
        }
      }
      if (!moved) break;
    }
    if (!gtls_conn_is_connected(c1) || !gtls_conn_is_connected(s1) || gtls_conn_session_count(c1) != 1 ||
        gtls_conn_session(c1, 0, &session) != GTLS_OK) {
      die("the first handshake of a resume run gave no session");
    }
    gtls_conn_free(c1);
    gtls_conn_free(s1);
  }
  /* The hostile servers are made from a context of their own, once the first handshake has given the
   * ticket: one with another ticket key (so the PSK is not taken), one with no ALPN list, one with
   * early data off. */
  static const unsigned char hostile_early[] = {0x00, 0x2a, 0x00, 0x00};
  static const unsigned char hostile_alpn[] = {0x00, 0x10, 0x00, 0x09, 0x00, 0x07, 0x06, 's', 'p', 'd', 'y', '/', '3'};
  const unsigned char * prefix = nullptr;
  size_t prefix_len = 0;
  GTLS_Context * sctx2 = nullptr;
  GTLS_TicketKey ticket_key2;
  if (session != nullptr && (mode == 1 || mode == 4 || mode == 6)) {
    GTLS_ContextConfig scfg2 = scfg;
    std::memset(&ticket_key2, 0x6d, sizeof ticket_key2);
    ticket_key2.not_before = 1699990000;
    ticket_key2.not_after = 1700100000;
    if (mode == 1) {
      scfg2.ticket_keys = &ticket_key2;
      prefix = hostile_early;
      prefix_len = sizeof hostile_early;
    } else if (mode == 4) {
      scfg2.alpn = nullptr;
      scfg2.alpn_count = 0;
      prefix = hostile_alpn;
      prefix_len = sizeof hostile_alpn;
    } else {
      scfg2.max_early_data = 0;
      scfg2.anti_replay = nullptr;
      scfg2.anti_replay_user = nullptr;
    }
    if (gtls_context_new(nullptr, &scfg2, &sctx2) != GTLS_OK) die("the hostile server's context");
    gtls_conn_free(s);
    s = nullptr;
    if (gtls_conn_new_server(sctx2, &s) != GTLS_OK) die("the hostile server");
  }
  /* Sessions that say something the server will not bear out (the early records are sealed under the
   * session's suite and the client believes an acceptance only for it). */
  bool tampered = false;
  if (session != nullptr && mode == 2) {
    if (session->suite == GTLS_SUITE_AES_128_GCM_SHA256) {
      session->suite = GTLS_SUITE_CHACHA20_POLY1305_SHA256;
      tampered = true;
    } else if (session->suite == GTLS_SUITE_CHACHA20_POLY1305_SHA256) {
      session->suite = GTLS_SUITE_AES_128_GCM_SHA256;
      tampered = true;
    }
  }
  if (session != nullptr && mode == 3) {
    std::memcpy(session->alpn, "h2", 2);
    session->alpn_len = 2;
    tampered = true;
  }
  PumpRandom crnd, srnd;
  crnd.pcg.state = 0x1234567;
  srnd.pcg.state = 0x7654321;
  gtls_conn_set_hooks(c, PumpRandom::fn, &crnd, nullptr, nullptr);
  gtls_conn_set_hooks(s, PumpRandom::fn, &srnd, nullptr, nullptr);
  if (prefix != nullptr) {
    gtls_conn_set_server_hooks(s, nullptr, nullptr, nullptr, nullptr, 0, 0, prefix, prefix_len);
  }
  note(c);
  note(s);
  if (session != nullptr && gtls_conn_set_session(c, session, 1700000000) != GTLS_OK) die("set session");
  if (gtls_conn_start(c) != GTLS_OK || gtls_conn_start(s) != GTLS_OK) die("start");
  note(c);
  note(s);
  /* A resuming client sends early data, ahead of anything the server has said. */
  const Bytes early_bytes(200, 0x5a);
  Bytes got_early;
  bool early_sent = false;
  if (session != nullptr) {
    size_t w = 7;
    /* Nothing to write takes nothing and sends nothing; more than any allowance is refused whole. */
    if (gtls_conn_write_early(c, early_bytes.data(), 0, &w) != GTLS_OK || w != 0) {
      die("an empty early write was not taken as nothing");
    }
    if (c->wr_epoch != GTLS_EPOCH_INITIAL || c->wire.len != 0 || c->hello_flushed) {
      die("an empty early write flushed the hello or installed a key");
    }
    static const Bytes too_much(100000, 0x5a);
    w = 7;
    if (gtls_conn_write_early(c, too_much.data(), too_much.size(), &w) != GTLS_ERR_LIMIT || w != 0) {
      die("an early write past the allowance was not refused whole");
    }
    /* A session of another suite has the records sealed under it, which a server that accepts cannot
     * open: it would fail before the client reads what it sent, so that client writes none. */
    if (mode != 2 && !no_early) {
      if (gtls_conn_write_early(c, early_bytes.data(), early_bytes.size(), &w) != GTLS_OK ||
          w != early_bytes.size()) {
        die("early data could not be written by a client resuming a ticket that allows it");
      }
      early_sent = true;
    }
    if (mode == 7 && gtls_conn_close(c) != GTLS_ERR_CLOSED) {
      die("a close in the early window was not told to the caller");
    }
  }

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
  bool dropped = false;
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
      if (mode == 5 && dir == 0 && !dropped && gtls_conn_state(s) == GTLS_STATE_S_WAIT_EOED && wire.size() >= 5) {
        /* The first record of what the client sends now is its EndOfEarlyData. */
        const size_t first = 5 + ((static_cast<size_t>(wire[3]) << 8) | wire[4]);
        if (first < wire.size()) {
          wire.erase(wire.begin(), wire.begin() + static_cast<long>(first));
          dropped = true;
        }
      }
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
        while (to == s && gtls_conn_read_early(to, rd, sizeof rd, &got) == GTLS_OK && got != 0) {
          got_early.insert(got_early.end(), rd, rd + got);
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
  /* What a hostile peer, left alone, must bring about. */
  const bool retried = (opt & 0x10u) != 0;
  if (flips.empty() && mode == 1) {
    if (!gtls_conn_is_failed(c) || gtls_conn_failure(c) != GTLS_ERR_PROTOCOL ||
        gtls_conn_alert(c) != GTLS_ALERT_UNSUPPORTED_EXTENSION) {
      die("early_data from a server that did not take the PSK was believed");
    }
  } else if (flips.empty() && mode == 4) {
    if (!gtls_conn_is_failed(c) || gtls_conn_failure(c) != GTLS_ERR_PROTOCOL ||
        gtls_conn_alert(c) != GTLS_ALERT_ILLEGAL_PARAMETER) {
      die("an ALPN protocol that was never offered was believed");
    }
  } else if (flips.empty() && (mode == 2 || mode == 3) && tampered && !retried) {
    if (!gtls_conn_is_failed(c) || gtls_conn_failure(c) != GTLS_ERR_PROTOCOL ||
        gtls_conn_alert(c) != GTLS_ALERT_ILLEGAL_PARAMETER) {
      die("an acceptance for another suite or protocol than the ticket's was believed");
    }
  } else if (flips.empty() && mode == 5 && !retried) {
    if (!dropped || !gtls_conn_is_failed(s) || gtls_conn_failure(s) != GTLS_ERR_PROTOCOL ||
        gtls_conn_alert(s) != GTLS_ALERT_UNEXPECTED_MESSAGE) {
      die("a Finished with no EndOfEarlyData before it was not unexpected_message");
    }
  } else if (flips.empty() && mode == 6) {
    unsigned char back[256];
    size_t n = 0;
    GTLS_EarlyStatus cs = GTLS_EARLY_NONE;
    GTLS_EarlyStatus ss = GTLS_EARLY_NONE;
    (void)gtls_conn_early_status(c, &cs);
    (void)gtls_conn_early_status(s, &ss);
    if (!gtls_conn_is_connected(c) || !gtls_conn_is_connected(s) || cs != GTLS_EARLY_REJECTED ||
        ss != GTLS_EARLY_REJECTED || !got_early.empty() || replay.calls != 0 ||
        gtls_conn_early_resend(c, back, sizeof back, &n) != GTLS_OK || n != early_bytes.size()) {
      die("a server with early data off did not refuse it and hand it back");
    }
  } else if (flips.empty() && mode == 7) {
    if (!gtls_conn_is_failed(c) || gtls_conn_failure(c) != GTLS_ERR_CLOSED || gtls_conn_alert(c) != GTLS_ALERT_NONE) {
      die("a close in the early window did not end the connection");
    }
    const unsigned char * p = nullptr;
    size_t n = 1;
    if (gtls_conn_stream_output(c, &p, &n) != GTLS_OK || n != 0) die("a close in the early window left output");
  } else if (flips.empty() && !(mode == 5 || ((mode == 2 || mode == 3) && tampered))) {
    /* With no mutation at all, the run must have gone through completely. */
    if (!gtls_conn_is_connected(c) || !gtls_conn_is_connected(s)) die("an unmutated pump did not connect");
    if (got_up.size() != 12 * expect_up.size()) die("an unmutated pump lost data");
    if (resume && (!gtls_conn_resumed(c) || !gtls_conn_resumed(s))) die("an unmutated resume did not resume");
    if (early_sent) {
      /* Accepted and delivered once, or (after a HelloRetryRequest) refused and handed back. */
      GTLS_EarlyStatus cs = GTLS_EARLY_NONE;
      GTLS_EarlyStatus ss = GTLS_EARLY_NONE;
      (void)gtls_conn_early_status(c, &cs);
      (void)gtls_conn_early_status(s, &ss);
      const bool retried_hello = (opt & 0x10u) != 0;
      if (retried_hello || replay.verdict != 1) {
        /* Refused (after a HelloRetryRequest, or by the server's decision): handed back, none delivered,
         * and the decision asked once, or not at all after a retry. */
        unsigned char back[256];
        size_t n = 0;
        if (cs != GTLS_EARLY_REJECTED || ss != GTLS_EARLY_REJECTED || !got_early.empty() ||
            gtls_conn_early_resend(c, back, sizeof back, &n) != GTLS_OK || n != early_bytes.size() ||
            std::memcmp(back, early_bytes.data(), n) != 0 || replay.calls != (retried_hello ? 0 : 1)) {
          die("early data that was refused was not handed back and left undelivered");
        }
      } else if (cs != GTLS_EARLY_ACCEPTED || ss != GTLS_EARLY_ACCEPTED || got_early != early_bytes ||
                 replay.calls != 1) {
        die("an unmutated resume did not deliver its early data once");
      }
    }
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
  gtls_session_free(session);
  gtls_context_free(cctx);
  gtls_context_free(sctx);
  gtls_context_free(sctx2);
  gcert_key_free(key);
  gcert_trust_free(store);
  return 0;
}

inline int pump_one(const uint8_t * data, size_t size) {
  return pump_core(data, size, false);
}

/** The pump, with a first handshake that gives the client a session to offer in the one that is mutated. */
inline int resume_one(const uint8_t * data, size_t size) {
  return pump_core(data, size, true);
}

/* ---------------------------------------------------- sessions and tickets */

/**
 * The session blob and the ticket. Input: an options byte (bits 0-1 which:
 * 0 a blob to parse, 1 bytes to open as a ticket, 2 a state to seal and open,
 * 3 a session to serialise and parse; bits 2-3 the suite; bits 4-6 the cap on
 * a ticket; bit 7, with 2, the clocks of a freshness check taken from the
 * input), then bytes. The tickets of 1 are opened under a key whose name is
 * 0x42 and whose bytes are 0x24; the seeds hold tickets sealed under it with
 * states the sealer would not write.
 */
inline int session_one(const uint8_t * data, size_t size) {
  if (size < 1) {
    return 0;
  }
  const unsigned opt = data[0];
  const uint8_t * body = data + 1;
  const size_t len = size - 1;
  static const uint32_t suites[3] = {0x1301, 0x1302, 0x1303};
  const uint32_t suite = suites[((opt >> 2) & 3u) % 3u];
  GTLS_Limits lim;
  gtls_limits_default(&lim);
  lim.max_ticket_bytes = 64u << ((opt >> 4) & 7u);
  GTLS_TicketKey key;
  std::memset(&key, 0, sizeof key);
  std::memset(key.name, 0x42, sizeof key.name);
  std::memset(key.key, 0x24, sizeof key.key);
  key.not_before = 0;
  key.not_after = 1000;

  switch (opt & 3u) {
    case 0: {
      GTLS_Session * s = nullptr;
      if (gtls_session_parse(nullptr, &lim, body, len, &s) == GTLS_OK) {
        Bytes out(len + 1);
        size_t n = 0;
        GTLS_SessionInfo info;
        if (gtls_session_serialize(s, out.data(), out.size(), &n) != GTLS_OK || n != len ||
            (len != 0 && std::memcmp(out.data(), body, len) != 0)) {
          die("a parsed session does not serialise to its input");
        }
        if (gtls_session_info(s, &info) != GTLS_OK || info.host_len == 0 ||
            info.lifetime > GTLS_TICKET_LIFETIME_MAX || info.expires < info.received) {
          die("a parsed session's description");
        }
        /* A buffer one byte short, and none at all, are limits that say how much is needed. */
        size_t need = 0;
        if (gtls_session_serialize(s, out.data(), n - 1, &need) != GTLS_ERR_LIMIT || need != n ||
            gtls_session_serialize(s, nullptr, 0, &need) != GTLS_ERR_LIMIT || need != n) {
          die("a short buffer for a session was not a limit");
        }
        gtls_session_free(s);
      } else if (s != nullptr) {
        die("a failed parse wrote a session");
      }
      break;
    }
    case 1: {
      GTLS_TicketPlain p;
      if (gtls_ticket_open(&key, 1, 100, body, len, &p) == GTLS_OK) {
        die("arbitrary bytes opened as a ticket");
      }
      /* The same bytes behind the key's own name, which is the one thing a forger has. */
      Bytes named(key.name, key.name + sizeof key.name);
      named.insert(named.end(), body, body + len);
      if (gtls_ticket_open(&key, 1, 100, named.data(), named.size(), &p) == GTLS_OK) {
        die("bytes behind a key's name opened as a ticket");
      }
      break;
    }
    case 2: {
      GTLS_TicketPlain p;
      std::memset(&p, 0, sizeof p);
      p.suite = suite;
      p.psk_len = gtls_hash_len(gtls_suite_hash(suite));
      for (size_t i = 0; i < p.psk_len && i < len; i++) p.psk[i] = body[i];
      p.age_add = len >= 4 ? (static_cast<uint32_t>(body[0]) << 24) | (static_cast<uint32_t>(body[1]) << 16) |
                                 (static_cast<uint32_t>(body[2]) << 8) | body[3]
                           : 7u;
      p.issued = 500;
      p.lifetime = 1u + static_cast<uint32_t>(len % 1000u);
      p.max_early_data = len % 3u == 0 ? 0u : static_cast<uint32_t>(len) * 100u;   /* sealed as state 1 or 2 */
      p.alpn_len = len < 100 ? len : 100;
      std::memcpy(p.alpn, body, p.alpn_len);
      p.sni_len = len < 200 ? len / 2 : 100;
      std::memcpy(p.sni, body, p.sni_len);
      unsigned char nonce[12];
      for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = static_cast<unsigned char>(len + i);
      unsigned char ticket[GTLS_TICKET_MAX];
      size_t n = 0;
      GTLS_TicketPlain back;
      if (gtls_ticket_seal(&key, 1, 500, nonce, &p, ticket, sizeof ticket, &n) != GTLS_OK ||
          n > GTLS_TICKET_MAX || n < GTLS_TICKET_MIN) {
        die("a state could not be sealed");
      }
      if (gtls_ticket_open(&key, 1, 500, ticket, n, &back) != GTLS_OK || back.suite != p.suite ||
          back.psk_len != p.psk_len || std::memcmp(back.psk, p.psk, p.psk_len) != 0 ||
          back.age_add != p.age_add || back.issued != p.issued || back.lifetime != p.lifetime ||
          back.max_early_data != p.max_early_data ||
          back.alpn_len != p.alpn_len || std::memcmp(back.alpn, p.alpn, p.alpn_len) != 0 ||
          back.sni_len != p.sni_len || std::memcmp(back.sni, p.sni, p.sni_len) != 0) {
        die("a sealed state does not open to itself");
      }
      ticket[(len * 7u) % n] ^= static_cast<unsigned char>(1u << (opt & 7u));
      if (gtls_ticket_open(&key, 1, 500, ticket, n, &back) == GTLS_OK) {
        die("a ticket with a bit changed opened");
      }
      /* Freshness never throws or loops, whatever the clocks. */
      (void)gtls_ticket_fresh(&p, static_cast<int64_t>(len) * 123456789 - 1000, p.age_add + static_cast<uint32_t>(len), 10000);
      if ((opt & 0x80u) != 0) {
        /* With bit 7 the lifetime, the issue time, the clock, the age and the window all come from
         * the input: four 8-byte big-endian words, the first holding the lifetime and age_add. */
        auto word = [&](size_t at) {
          uint64_t v = 0;
          for (size_t i = 0; i < 8; i++) v = (v << 8) | (at + i < len ? body[at + i] : 0u);
          return v;
        };
        GTLS_TicketPlain q = p;
        q.lifetime = static_cast<uint32_t>(word(0) >> 32);
        q.age_add = static_cast<uint32_t>(word(0));
        q.issued = static_cast<int64_t>(word(8));
        const int64_t now = static_cast<int64_t>(word(16));
        const int fresh = gtls_ticket_fresh(&q, now, static_cast<uint32_t>(word(24) >> 32),
            static_cast<uint32_t>(word(24)));
        if (fresh && q.lifetime > GTLS_TICKET_LIFETIME_MAX) die("a ticket lived past seven days");
      }
      break;
    }
    default: {
      GTLS_Session * s = gtls_session_alloc(gtls_allocator_default(), 1u + (len % 200u));
      if (s == nullptr) die("alloc");
      s->suite = suite;
      s->psk_len = gtls_hash_len(gtls_suite_hash(suite));
      for (size_t i = 0; i < s->psk_len; i++) s->psk[i] = i < len ? body[i] : static_cast<unsigned char>(i);
      for (size_t i = 0; i < s->ticket_len; i++) s->ticket[i] = i < len ? body[i] : 0;
      s->lifetime = static_cast<uint32_t>(len) % (GTLS_TICKET_LIFETIME_MAX + 1u);
      s->age_add = static_cast<uint32_t>(len) * 2654435761u;
      s->received = static_cast<int64_t>(len) << 20;
      s->host_len = 1u + (len % 255u);
      for (size_t i = 0; i < s->host_len; i++) s->host[i] = static_cast<unsigned char>('a' + i % 26);
      s->alpn_len = len % 8u;
      for (size_t i = 0; i < s->alpn_len; i++) s->alpn[i] = static_cast<unsigned char>('h' + i);
      Bytes blob(1024 + 16384);
      size_t n = 0;
      if (gtls_session_serialize(s, blob.data(), blob.size(), &n) != GTLS_OK) die("serialise");
      GTLS_Limits wide;
      gtls_limits_default(&wide);
      GTLS_Session * back = nullptr;
      if (gtls_session_parse(nullptr, &wide, blob.data(), n, &back) != GTLS_OK) die("a serialised session does not parse");
      if (back->suite != s->suite || back->psk_len != s->psk_len ||
          std::memcmp(back->psk, s->psk, s->psk_len) != 0 || back->ticket_len != s->ticket_len ||
          std::memcmp(back->ticket, s->ticket, s->ticket_len) != 0 || back->host_len != s->host_len ||
          back->received != s->received || back->age_add != s->age_add) {
        die("a session does not parse back to itself");
      }
      /* One byte changed, anywhere, is refused. */
      blob[len % n] ^= 0x10;
      GTLS_Session * bad = nullptr;
      if (gtls_session_parse(nullptr, &wide, blob.data(), n, &bad) == GTLS_OK) die("a damaged session parsed");
      gtls_session_free(back);
      gtls_session_free(s);
      break;
    }
  }
  return 0;
}

} /* namespace gtlsfuzz */

#endif /* GHOTI_IO_GTLS_FUZZ_COMMON_H */
