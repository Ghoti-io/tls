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
  Bytes ch1, x25519, p256;
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
 * Every parser, with limits taken from the input. Input: an options byte
 * (bits 0-2 pick the parser, bits 3-7 the limits), then the message body.
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
  lim.max_extensions = 1u + ((opt >> 3) & 15u);
  lim.max_certificates = 1u + ((opt >> 3) & 7u);
  lim.max_certificate_bytes = 16u << ((opt >> 5) & 7u);
  lim.max_signature_bytes = 8u << ((opt >> 5) & 7u);
  lim.max_ticket_bytes = 8u << ((opt >> 4) & 7u);
  lim.max_cookie_bytes = 4u << ((opt >> 3) & 7u);

  auto inside = [&](const void * p, size_t n) {
    const unsigned char * c = static_cast<const unsigned char *>(p);
    return n == 0 || (c >= body && c + n <= body + len);
  };
  switch (opt & 7u) {
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
        if (!inside(h.random, 32) || !inside(h.suites, h.suites_len) || h.ext_count > lim.max_extensions) {
          die("a ClientHello view");
        }
      }
      break;
    }
    default: {
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
          (opt & 8u) ? &share : nullptr, cookie, (opt & 16u) ? 4 : 0, &lim, &out);
      if (r == GTLS_OK) {
        GTLS_ClientHello h2;
        GTLS_Limits wide;
        gtls_limits_default(&wide);
        wide.max_extensions = GTLS_EXT_MAX;
        if (gtls_msg_parse_client_hello(out.data + 4, out.len - 4, &wide, &h2) != GTLS_OK) {
          die("the retry transform wrote a hello that does not parse");
        }
        if (out.len < 256 || out.len > 511) {
          /* fine: outside the padded range */
        }
        if (((static_cast<size_t>(out.data[1]) << 16) | (static_cast<size_t>(out.data[2]) << 8) |
                out.data[3]) != out.len - 4) {
          die("the retry transform's header length is wrong");
        }
      }
      gtls_buf_free(&out);
      break;
    }
  }
  return 0;
}

} /* namespace gtlsfuzz */

#endif /* GHOTI_IO_GTLS_FUZZ_COMMON_H */
