/**
 * @file
 *
 * What the negative tests need from a server: a small PKI built in memory, a
 * server that answers a ClientHello with a flight the test can corrupt at any
 * message, and an allocator that can fail the Nth allocation and look at what
 * is freed.
 *
 * The simulated server computes its key schedule with the library's own
 * functions. That is deliberate and safe: the schedule is checked against
 * RFC 8448 byte for byte in test_schedule and test_rfc8448, so what these
 * tests are about is how the client behaves when the *messages* are wrong,
 * not whether HKDF is.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_TEST_SIM_H
#define GHOTI_IO_GTLS_TEST_SIM_H

#include "test_helpers.h"

#include <ghoti.io/cutil/allocator.h>

#include <ctime>
#include <memory>
#include <functional>
#include <map>

namespace gtlstest {

/* ------------------------------------------------------------------- DER */

inline Bytes der_len(size_t n) {
  if (n < 128) {
    return Bytes{static_cast<unsigned char>(n)};
  }
  if (n < 256) {
    return Bytes{0x81, static_cast<unsigned char>(n)};
  }
  return Bytes{0x82, static_cast<unsigned char>(n >> 8), static_cast<unsigned char>(n)};
}

inline Bytes tlv(unsigned char tag, const Bytes & body) {
  Bytes out{tag};
  Bytes l = der_len(body.size());
  out.insert(out.end(), l.begin(), l.end());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

inline Bytes seq(const std::vector<Bytes> & parts, unsigned char tag = 0x30) {
  Bytes body;
  for (const Bytes & p : parts) {
    body.insert(body.end(), p.begin(), p.end());
  }
  return tlv(tag, body);
}

inline Bytes oid(const Bytes & content) { return tlv(0x06, content); }

inline Bytes cn_name(const std::string & cn) {
  Bytes atv = seq({oid(Bytes{0x55, 0x04, 0x03}), tlv(0x0c, Bytes(cn.begin(), cn.end()))});
  return seq({tlv(0x31, atv)});
}

inline Bytes der_time(int64_t t) {
  std::time_t tt = static_cast<std::time_t>(t);
  struct tm g;
#ifdef _WIN32
  gmtime_s(&g, &tt);
#else
  gmtime_r(&tt, &g);
#endif
  char buf[32];
  if (g.tm_year + 1900 < 2050) {
    std::snprintf(buf, sizeof buf, "%02d%02d%02d%02d%02d%02dZ", g.tm_year % 100, g.tm_mon + 1,
        g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec);
    return tlv(0x17, Bytes(buf, buf + std::strlen(buf)));
  }
  std::snprintf(buf, sizeof buf, "%04d%02d%02d%02d%02d%02dZ", g.tm_year + 1900, g.tm_mon + 1,
      g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec);
  return tlv(0x18, Bytes(buf, buf + std::strlen(buf)));
}

inline Bytes seed_of(unsigned char tag) { return Bytes(32, tag); }

inline Bytes ed_public(unsigned char tag) {
  Bytes pub(32);
  EXPECT_EQ(gsec_ed25519_public(seed_of(tag).data(), pub.data()), GSEC_OK);
  return pub;
}

/* --------------------------------------------------------- certificates */

const int64_t kNow = 1700000000;
const int64_t kDay = 86400;

struct CertSpec {
  std::string subject = "leaf";
  std::string issuer = "inter";
  unsigned char key_tag = 3;
  unsigned char signer_tag = 2;
  bool ca = false;
  int path_len = -1;
  int64_t not_before = kNow - 30 * kDay;
  int64_t not_after = kNow + 30 * kDay;
  std::string dns;
  Bytes ip;  /* an iPAddress SAN, 4 or 16 bytes */
  bool has_eku = false;
  bool eku_server = false;
  bool eku_client = false;
  unsigned serial = 1;
  bool corrupt_signature = false;
};

inline Bytes make_cert(const CertSpec & s) {
  const Bytes ed_alg = seq({oid(Bytes{0x2b, 0x65, 0x70})});
  std::vector<Bytes> exts;
  Bytes bc_value = s.ca ? (s.path_len >= 0
          ? seq({Bytes{0x01, 0x01, 0xff}, tlv(0x02, Bytes{static_cast<unsigned char>(s.path_len)})})
          : seq({Bytes{0x01, 0x01, 0xff}}))
      : seq({});
  exts.push_back(seq({oid(Bytes{0x55, 0x1d, 0x13}), Bytes{0x01, 0x01, 0xff}, tlv(0x04, bc_value)}));
  if (!s.dns.empty() || !s.ip.empty()) {
    std::vector<Bytes> names;
    if (!s.dns.empty()) {
      names.push_back(tlv(0x82, Bytes(s.dns.begin(), s.dns.end())));
    }
    if (!s.ip.empty()) {
      names.push_back(tlv(0x87, s.ip));
    }
    Bytes san = seq(names);
    exts.push_back(seq({oid(Bytes{0x55, 0x1d, 0x11}), tlv(0x04, san)}));
  }
  if (s.has_eku) {
    std::vector<Bytes> ekus;
    if (s.eku_server) {
      ekus.push_back(oid(Bytes{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01}));
    }
    if (s.eku_client) {
      ekus.push_back(oid(Bytes{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}));
    }
    exts.push_back(seq({oid(Bytes{0x55, 0x1d, 0x25}), tlv(0x04, seq(ekus))}));
  }
  Bytes pub = ed_public(s.key_tag);
  Bytes spki_bits{0x00};
  spki_bits.insert(spki_bits.end(), pub.begin(), pub.end());
  Bytes serial{static_cast<unsigned char>(s.serial >> 8), static_cast<unsigned char>(s.serial)};
  serial = tlv(0x02, Bytes{0x01, static_cast<unsigned char>(s.serial)});
  Bytes tbs = seq({Bytes{0xa0, 0x03, 0x02, 0x01, 0x02}, serial, ed_alg, cn_name(s.issuer),
      seq({der_time(s.not_before), der_time(s.not_after)}), cn_name(s.subject),
      seq({ed_alg, tlv(0x03, spki_bits)}), seq({seq(exts)}, 0xa3)});
  Bytes sig(64);
  EXPECT_EQ(gsec_ed25519_sign(seed_of(s.signer_tag).data(), tbs.data(), tbs.size(), sig.data()),
      GSEC_OK);
  if (s.corrupt_signature) {
    sig[10] ^= 1;
  }
  Bytes sig_bits{0x00};
  sig_bits.insert(sig_bits.end(), sig.begin(), sig.end());
  return seq({tbs, ed_alg, tlv(0x03, sig_bits)});
}

/** PKCS#8 PrivateKeyInfo for an Ed25519 seed. */
inline Bytes ed_pkcs8(unsigned char tag) {
  Bytes out = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
      0x04, 0x22, 0x04, 0x20};
  Bytes seed = seed_of(tag);
  out.insert(out.end(), seed.begin(), seed.end());
  return out;
}

/** root -> inter -> leaf, the leaf naming example.test. Keys are tags 1, 2, 3. */
struct Pki {
  Bytes root;
  Bytes inter;
  Bytes leaf;
  Pki() {
    CertSpec r;
    r.subject = "root";
    r.issuer = "root";
    r.key_tag = 1;
    r.signer_tag = 1;
    r.ca = true;
    root = make_cert(r);
    CertSpec i;
    i.subject = "inter";
    i.issuer = "root";
    i.key_tag = 2;
    i.signer_tag = 1;
    i.ca = true;
    inter = make_cert(i);
    CertSpec l;
    l.subject = "leaf";
    l.issuer = "inter";
    l.key_tag = 3;
    l.signer_tag = 2;
    l.dns = "example.test";
    l.has_eku = true;
    l.eku_server = true;
    leaf = make_cert(l);
  }
};

struct Trust {
  GCERT_TrustStore * store = nullptr;
  explicit Trust(const std::vector<Bytes> & anchors) {
    EXPECT_EQ(gcert_trust_new(nullptr, nullptr, &store), GCERT_OK);
    for (const Bytes & a : anchors) {
      EXPECT_EQ(gcert_trust_add_der(store, a.data(), a.size()), GCERT_OK);
    }
  }
  ~Trust() { gcert_trust_free(store); }
  Trust(const Trust &) = delete;
  Trust & operator=(const Trust &) = delete;
};

/* ----------------------------------------------------------- allocator */

/**
 * An allocator that counts, can fail the Nth allocation, remembers what is
 * live, and shows every block to a callback just before it is freed so a
 * test can look for secrets that were not wiped.
 */
struct TestAlloc {
  GTLS_Allocator a;
  long count = 0;
  long fail_at = -1;     /* fail the allocation with this index, from 0 */
  long live = 0;
  std::map<void *, size_t> blocks;
  std::function<void(const unsigned char *, size_t)> on_free;

  TestAlloc() {
    a.ctx = this;
    a.malloc_fn = [](void * c, size_t n) -> void * { return static_cast<TestAlloc *>(c)->get(nullptr, n, false); };
    a.calloc_fn = [](void * c, size_t n, size_t m) -> void * { return static_cast<TestAlloc *>(c)->get(nullptr, n * m, true); };
    a.realloc_fn = [](void * c, void * p, size_t n) -> void * { return static_cast<TestAlloc *>(c)->get(p, n, false); };
    a.free_fn = [](void * c, void * p) { static_cast<TestAlloc *>(c)->release(p); };
  }
  void * get(void * old, size_t n, bool zero) {
    if (fail_at >= 0 && count++ == fail_at) {
      return nullptr;
    } else if (fail_at < 0) {
      count++;
    }
    if (old != nullptr) {
      size_t was = blocks[old];
      void * p = std::calloc(1, n == 0 ? 1 : n);
      if (p == nullptr) {
        return nullptr;
      }
      std::memcpy(p, old, was < n ? was : n);
      release(old);
      blocks[p] = n;
      live++;
      return p;
    }
    /* Always zeroed, calloc or not: the scan in test_wipe reads whole blocks,
     * and a block with bytes the library never wrote would be reported by
     * Valgrind as the scan branching on uninitialised memory. */
    (void)zero;
    void * p = std::calloc(1, n == 0 ? 1 : n);
    if (p != nullptr) {
      blocks[p] = n;
      live++;
    }
    return p;
  }
  void release(void * p) {
    if (p == nullptr) {
      return;
    }
    auto it = blocks.find(p);
    if (it == blocks.end()) {
      ADD_FAILURE() << "free of a block this allocator did not give";
      return;
    }
    if (on_free) {
      on_free(static_cast<const unsigned char *>(p), it->second);
    }
    blocks.erase(it);
    live--;
    std::free(p);
  }
  ~TestAlloc() {
    for (auto & b : blocks) {
      std::free(b.first);
    }
  }
};

/* -------------------------------------------------------------- the server */

struct SimOptions {
  GTLS_Suite suite = GTLS_SUITE_AES_128_GCM_SHA256;
  GTLS_Group group = GTLS_GROUP_X25519;
  std::vector<Bytes> chain;
  unsigned char cv_key_tag = 3;
  unsigned cv_scheme = 0x0807;
  bool hrr = false;
  GTLS_Group hrr_group = GTLS_GROUP_SECP256R1;
  Bytes cookie;
  Bytes alpn;
  bool ack_sni = true;
  std::vector<Bytes> ee_extras;
  int sentinel = 0; /* 0 none, 2 the TLS 1.2 one, 3 the TLS 1.1 one */
  bool cv_wrong_transcript = false;
  bool bad_finished = false;
  std::function<void(Bytes &)> mut_sh, mut_ee, mut_cert, mut_cv, mut_fin, mut_hrr;
  /* Applied to what the client is sent, after the server has hashed the original. */
  std::function<void(Bytes &)> wire_ee;
};

class SimServer {
 public:
  SimOptions o;
  Bytes hrr_msg, sh_msg, ee_msg, cert_msg, cv_msg, fin_msg;
  Bytes ee_wire;
  Bytes expected_client_finished;
  GTLS_Schedule sched;
  bool retried = false;
  bool wants_retry = false;
  GTLS_Transcript tr;
  GTLS_Hash hash = GTLS_HASH_NONE;
  Bytes session_id;
  bool selected = false;

  explicit SimServer(const SimOptions & opts) : o(opts) {
    std::memset(&sched, 0, sizeof sched);
    gtls_transcript_init(&tr);
  }
  ~SimServer() {
    gtls_schedule_wipe(&sched);
    gtls_transcript_wipe(&tr);
  }

  static void put16(Bytes & b, unsigned v) { b.push_back(v >> 8); b.push_back(v & 255); }
  static void put24(Bytes & b, unsigned v) { b.push_back(v >> 16); b.push_back((v >> 8) & 255); b.push_back(v & 255); }

  static Bytes wrap(unsigned type, const Bytes & body) {
    Bytes m{static_cast<unsigned char>(type)};
    put24(m, body.size());
    m.insert(m.end(), body.begin(), body.end());
    return m;
  }

  static Bytes ext(unsigned type, const Bytes & data) {
    Bytes e;
    put16(e, type);
    put16(e, data.size());
    e.insert(e.end(), data.begin(), data.end());
    return e;
  }

  static Bytes ext_block(const std::vector<Bytes> & exts) {
    Bytes body;
    for (const Bytes & e : exts) {
      body.insert(body.end(), e.begin(), e.end());
    }
    Bytes out;
    put16(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
  }

  void absorb(const Bytes & m) { ASSERT_EQ(gtls_transcript_update(&tr, m.data(), m.size()), GTLS_OK); }

  Bytes th() {
    Bytes out(GTLS_HASH_MAX);
    EXPECT_EQ(gtls_transcript_snapshot(&tr, hash, out.data()), GTLS_OK);
    out.resize(gtls_hash_len(hash));
    return out;
  }

  /** The server's key share in @p group, and the shared secret with @p client. */
  bool exchange(GTLS_Group group, const Bytes & client, Bytes * pub, Bytes * shared) {
    if (group == GTLS_GROUP_X25519) {
      Bytes priv(32, 0x55);
      pub->assign(32, 0);
      shared->assign(32, 0);
      if (gsec_x25519_public(priv.data(), pub->data()) != GSEC_OK) return false;
      return gsec_x25519(priv.data(), client.data(), shared->data()) == GSEC_OK;
    }
    if (group == GTLS_GROUP_SECP256R1) {
      Bytes priv(32, 0x11);
      Bytes raw(64);
      if (gsec_ecdh_p256_public(priv.data(), raw.data()) != GSEC_OK) return false;
      pub->assign(1, 4);
      pub->insert(pub->end(), raw.begin(), raw.end());
      shared->assign(32, 0);
      if (client.size() != 65) return false;
      return gsec_ecdh_p256(priv.data(), client.data() + 1, shared->data()) == GSEC_OK;
    }
    Bytes priv(48, 0x11);
    Bytes raw(96);
    if (gsec_ecdh_p384_public(priv.data(), raw.data()) != GSEC_OK) return false;
    pub->assign(1, 4);
    pub->insert(pub->end(), raw.begin(), raw.end());
    shared->assign(48, 0);
    if (client.size() != 97) return false;
    return gsec_ecdh_p384(priv.data(), client.data() + 1, shared->data()) == GSEC_OK;
  }

  /**
   * Take the client's ClientHello (a whole message). Fills hrr_msg and sets
   * wants_retry, or fills the whole flight.
   */
  void accept_hello(const Bytes & ch) {
    GTLS_Limits lim;
    gtls_limits_default(&lim);
    GTLS_ClientHello h;
    ASSERT_EQ(gtls_msg_parse_client_hello(ch.data() + 4, ch.size() - 4, &lim, &h), GTLS_OK);
    session_id.assign(h.session_id, h.session_id + h.session_id_len);
    hash = gtls_suite_hash(o.suite);
    absorb(ch);
    wants_retry = false;
    if (o.hrr && !retried) {
      Bytes random(32);
      ASSERT_EQ(gsec_sha256("HelloRetryRequest", 17, random.data()), GSEC_OK);
      Bytes exts;
      std::vector<Bytes> list;
      Bytes g;
      put16(g, o.hrr_group);
      if (o.hrr_group != GTLS_GROUP_NONE) {
        list.push_back(ext(GTLS_EXT_KEY_SHARE, g));
      }
      if (!o.cookie.empty()) {
        Bytes c;
        put16(c, o.cookie.size());
        c.insert(c.end(), o.cookie.begin(), o.cookie.end());
        list.push_back(ext(GTLS_EXT_COOKIE, c));
      }
      list.push_back(ext(GTLS_EXT_SUPPORTED_VERSIONS, Bytes{3, 4}));
      Bytes body;
      put16(body, 0x0303);
      body.insert(body.end(), random.begin(), random.end());
      body.push_back(session_id.size());
      body.insert(body.end(), session_id.begin(), session_id.end());
      put16(body, o.suite);
      body.push_back(0);
      Bytes blk = ext_block(list);
      body.insert(body.end(), blk.begin(), blk.end());
      hrr_msg = wrap(GTLS_HS_SERVER_HELLO, body);
      if (o.mut_hrr) o.mut_hrr(hrr_msg);
      /* what the transcript becomes after a retry */
      ASSERT_EQ(gtls_transcript_select(&tr, hash), GTLS_OK);
      ASSERT_EQ(gtls_transcript_restart(&tr, hash), GTLS_OK);
      absorb(hrr_msg);
      retried = true;
      wants_retry = true;
      selected = true;
      return;
    }
    GTLS_Group group = retried && o.hrr_group != GTLS_GROUP_NONE ? o.hrr_group : o.group;
    /* The client's share in the chosen group. */
    const GTLS_Ext * ks = gtls_msg_find_ext(h.exts, h.ext_count, GTLS_EXT_KEY_SHARE);
    ASSERT_NE(ks, nullptr);
    GTLS_Reader r;
    gtls_reader_init(&r, ks->data, ks->len);
    GTLS_Reader list;
    ASSERT_EQ(gtls_reader_vector(&r, 2, 0, 0, &list), GTLS_OK);
    Bytes client_kx;
    while (gtls_reader_left(&list) != 0) {
      unsigned gid;
      GTLS_Reader kx;
      ASSERT_EQ(gtls_reader_u16(&list, &gid), GTLS_OK);
      ASSERT_EQ(gtls_reader_vector(&list, 2, 0, 0, &kx), GTLS_OK);
      if (gid == static_cast<unsigned>(group)) {
        client_kx.assign(kx.p, kx.p + kx.len);
      }
    }
    Bytes pub;
    Bytes shared;
    ASSERT_TRUE(exchange(group, client_kx, &pub, &shared)) << "client share unusable";

    Bytes random(32, 0x99);
    if (o.sentinel != 0) {
      const unsigned char tail[7] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44};
      std::memcpy(random.data() + 24, tail, 7);
      random[31] = o.sentinel == 2 ? 1 : 0;
    }
    Bytes kxe;
    put16(kxe, group);
    put16(kxe, pub.size());
    kxe.insert(kxe.end(), pub.begin(), pub.end());
    Bytes body;
    put16(body, 0x0303);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(session_id.size());
    body.insert(body.end(), session_id.begin(), session_id.end());
    put16(body, o.suite);
    body.push_back(0);
    Bytes blk = ext_block({ext(GTLS_EXT_KEY_SHARE, kxe), ext(GTLS_EXT_SUPPORTED_VERSIONS, Bytes{3, 4})});
    body.insert(body.end(), blk.begin(), blk.end());
    sh_msg = wrap(GTLS_HS_SERVER_HELLO, body);
    if (o.mut_sh) o.mut_sh(sh_msg);
    if (!retried) {
      ASSERT_EQ(gtls_transcript_select(&tr, hash), GTLS_OK);
    }
    absorb(sh_msg);
    ASSERT_EQ(gtls_schedule_early(&sched, hash), GTLS_OK);
    Bytes t = th();
    ASSERT_EQ(gtls_schedule_handshake(&sched, shared.data(), shared.size(), t.data()), GTLS_OK);

    std::vector<Bytes> ees;
    if (o.ack_sni) ees.push_back(ext(GTLS_EXT_SERVER_NAME, Bytes()));
    if (!o.alpn.empty()) {
      Bytes a;
      put16(a, o.alpn.size() + 1);
      a.push_back(o.alpn.size());
      a.insert(a.end(), o.alpn.begin(), o.alpn.end());
      ees.push_back(ext(GTLS_EXT_ALPN, a));
    }
    for (const Bytes & e : o.ee_extras) ees.push_back(e);
    ee_msg = wrap(GTLS_HS_ENCRYPTED_EXTENSIONS, ext_block(ees));
    if (o.mut_ee) o.mut_ee(ee_msg);
    absorb(ee_msg);
    ee_wire = ee_msg;
    if (o.wire_ee) o.wire_ee(ee_wire);

    Bytes entries;
    for (const Bytes & c : o.chain) {
      put24(entries, c.size());
      entries.insert(entries.end(), c.begin(), c.end());
      put16(entries, 0);
    }
    Bytes cbody{0};
    put24(cbody, entries.size());
    cbody.insert(cbody.end(), entries.begin(), entries.end());
    cert_msg = wrap(GTLS_HS_CERTIFICATE, cbody);
    if (o.mut_cert) o.mut_cert(cert_msg);
    absorb(cert_msg);

    static const char label[] = "TLS 1.3, server CertificateVerify";
    Bytes content(64, 0x20);
    content.insert(content.end(), label, label + sizeof label);
    Bytes ct = th();
    if (o.cv_wrong_transcript) ct[0] ^= 1;
    content.insert(content.end(), ct.begin(), ct.end());
    Bytes sig(64);
    ASSERT_EQ(gsec_ed25519_sign(seed_of(o.cv_key_tag).data(), content.data(), content.size(),
                  sig.data()), GSEC_OK);
    Bytes cvb;
    put16(cvb, o.cv_scheme);
    put16(cvb, sig.size());
    cvb.insert(cvb.end(), sig.begin(), sig.end());
    cv_msg = wrap(GTLS_HS_CERTIFICATE_VERIFY, cvb);
    if (o.mut_cv) o.mut_cv(cv_msg);
    absorb(cv_msg);

    Bytes fin(gtls_hash_len(hash));
    Bytes ft = th();
    ASSERT_EQ(gtls_finished_verify_data(hash, sched.s_hs, ft.data(), fin.data()), GTLS_OK);
    if (o.bad_finished) fin[0] ^= 1;
    fin_msg = wrap(GTLS_HS_FINISHED, fin);
    if (o.mut_fin) o.mut_fin(fin_msg);
    absorb(fin_msg);
    Bytes t2 = th();
    ASSERT_EQ(gtls_schedule_master(&sched, t2.data()), GTLS_OK);
    Bytes cfin(gtls_hash_len(hash));
    ASSERT_EQ(gtls_finished_verify_data(hash, sched.c_hs, t2.data(), cfin.data()), GTLS_OK);
    expected_client_finished = wrap(GTLS_HS_FINISHED, cfin);
    selected = true;
  }

  Bytes flight() const {
    Bytes out = ee_wire;
    out.insert(out.end(), cert_msg.begin(), cert_msg.end());
    out.insert(out.end(), cv_msg.begin(), cv_msg.end());
    out.insert(out.end(), fin_msg.begin(), fin_msg.end());
    return out;
  }
};

/** Everything needed to run a real client against a simulated server. */
struct World {
  Pki pki;
  std::unique_ptr<Trust> trust;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  std::string host = "example.test";
  const GTLS_Allocator * allocator = nullptr;
  GTLS_ContextConfig cfg;
  std::vector<const char *> alpn;
  GTLS_Limits limits;
  int64_t now = kNow;
  ScriptedRandom * rnd = nullptr;

  World() {
    trust.reset(new Trust({pki.root}));
    gtls_context_config_default(&cfg);
    gtls_limits_default(&limits);
  }
  ~World() {
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }

  SimOptions server_options() const {
    SimOptions o;
    o.chain = {pki.leaf, pki.inter};
    return o;
  }

  void build() {
    cfg.trust = trust->store;
    cfg.limits = &limits;
    if (!alpn.empty()) {
      cfg.alpn = alpn.data();
      cfg.alpn_count = alpn.size();
    }
    GTLS_Result r = gtls_context_new(allocator, &cfg, &ctx);
    ASSERT_EQ(r, GTLS_OK);
    ASSERT_EQ(gtls_conn_new(ctx, host.data(), host.size(), &conn), GTLS_OK);
  }

  Bytes out(GTLS_Epoch e) {
    const unsigned char * p = nullptr;
    size_t n = 0;
    EXPECT_EQ(gtls_conn_pending_output(conn, e, &p, &n), GTLS_OK);
    return n == 0 ? Bytes() : Bytes(p, p + n);
  }
  void drain(GTLS_Epoch e) {
    Bytes b = out(e);
    EXPECT_EQ(gtls_conn_consume_output(conn, e, b.size()), GTLS_OK);
  }

  GTLS_Result feed(GTLS_Epoch e, const Bytes & b, size_t chunk = 0) {
    if (chunk == 0 || b.empty()) {
      return gtls_conn_feed(conn, e, b.data(), b.size(), now);
    }
    for (size_t at = 0; at < b.size(); at += chunk) {
      size_t n = b.size() - at < chunk ? b.size() - at : chunk;
      GTLS_Result r = gtls_conn_feed(conn, e, b.data() + at, n, now);
      if (r != GTLS_OK) {
        return r;
      }
    }
    return GTLS_OK;
  }

  /**
   * Run the whole handshake against @p server, a message at a time, and
   * return the first result that was not OK. @p chunk splits each feed.
   */
  GTLS_Result run(SimServer & server, size_t chunk = 0) {
    GTLS_Result r = gtls_conn_start(conn);
    if (r != GTLS_OK) {
      return r;
    }
    Bytes ch = out(GTLS_EPOCH_INITIAL);
    drain(GTLS_EPOCH_INITIAL);
    server.accept_hello(ch);
    if (server.wants_retry) {
      r = feed(GTLS_EPOCH_INITIAL, server.hrr_msg, chunk);
      if (r != GTLS_OK) {
        return r;
      }
      Bytes ch2 = out(GTLS_EPOCH_INITIAL);
      drain(GTLS_EPOCH_INITIAL);
      server.accept_hello(ch2);
    }
    r = feed(GTLS_EPOCH_INITIAL, server.sh_msg, chunk);
    if (r != GTLS_OK) {
      return r;
    }
    const Bytes * msgs[] = {&server.ee_wire, &server.cert_msg, &server.cv_msg, &server.fin_msg};
    for (const Bytes * m : msgs) {
      r = feed(GTLS_EPOCH_HANDSHAKE, *m, chunk);
      if (r != GTLS_OK) {
        return r;
      }
    }
    return GTLS_OK;
  }
};

} /* namespace gtlstest */

#endif /* GHOTI_IO_GTLS_TEST_SIM_H */
