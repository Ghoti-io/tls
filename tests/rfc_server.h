/**
 * @file
 *
 * The server driven with RFC 8448's ClientHello: see test_server.cpp.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GTLS_TEST_RFC_SERVER_H
#define GHOTI_IO_GTLS_TEST_RFC_SERVER_H

#include "loop.h"
#include "rfc_run.h"

#include <ghoti.io/tls/record.h>

namespace gtlstest {

/* ------------------------------------------------------- RFC 8448, as a server */

/**
 * A server connection set up to answer the RFC's ClientHello: its random and
 * ephemeral key scripted, the RFC's chain and extensions put in place of an
 * identity's (see gtls_conn_set_server_hooks), and a signer that checks the
 * RFC's signature against what the server built before handing it back.
 */
struct RfcServer {
  Vec v;
  std::unique_ptr<Cred> cred;
  GTLS_Context * ctx = nullptr;
  GTLS_Conn * conn = nullptr;
  ScriptedRandom rnd;
  Bytes cert_der, cv_sig, ee_prefix;
  const unsigned char * chain[1];
  size_t chain_len[1];
  int signed_calls = 0;
  bool signature_verified = false;
  int64_t now = 1700000000;

  static GTLS_Result sign(void * user, const GTLS_Conn *, unsigned scheme,
      const unsigned char * content, size_t n, unsigned char * out, size_t cap, size_t * len) {
    RfcServer * self = static_cast<RfcServer *>(user);
    self->signed_calls++;
    GCERT_X509 leaf;
    if (gcert_x509_parse(self->cert_der.data(), self->cert_der.size(), &leaf) != GCERT_OK) {
      ADD_FAILURE() << "the RFC's certificate does not parse";
      return GTLS_ERR_INTERNAL;
    }
    self->signature_verified = gcert_x509_verify_signature(&leaf, static_cast<GCERT_SigScheme>(scheme),
        content, n, self->cv_sig.data(), self->cv_sig.size()) == GCERT_OK;
    EXPECT_TRUE(self->signature_verified)
        << "the RFC's signature does not verify over what the server built";
    if (self->cv_sig.size() > cap) {
      return GTLS_ERR_LIMIT;
    }
    std::memcpy(out, self->cv_sig.data(), self->cv_sig.size());
    *len = self->cv_sig.size();
    return GTLS_OK;
  }

  explicit RfcServer(const char * trace = "simple-1rtt") : v(trace) {
    cred = ed_cred("rfc.test");
    const Bytes & cert = v["server.construct-a-certificate-handshake-message.certificate"];
    /* type, length, empty context, list length, entry length: 4 + 1 + 3 + 3 */
    size_t n = (static_cast<size_t>(cert[8]) << 16) | (static_cast<size_t>(cert[9]) << 8) | cert[10];
    cert_der.assign(cert.begin() + 11, cert.begin() + 11 + n);
    const Bytes & cv = v["server.construct-a-certificateverify-handshake-message.certificateverify"];
    cv_sig.assign(cv.begin() + 8, cv.end());
    const Bytes & ee = v["server.construct-an-encryptedextensions-handshake-message.encryptedextensions"];
    /* everything in the extension block but the trailing empty server_name */
    ee_prefix.assign(ee.begin() + 6, ee.end() - 4);
    EXPECT_EQ(Bytes(ee.end() - 4, ee.end()), (Bytes{0, 0, 0, 0}));
    chain[0] = cert_der.data();
    chain_len[0] = cert_der.size();

    GTLS_ContextConfig cfg;
    gtls_context_config_default(&cfg);
    cfg.role = GTLS_ROLE_SERVER;
    const void * c1[1] = {cred->chain[0].data()};
    size_t l1[1] = {cred->chain[0].size()};
    GTLS_Identity id = {c1, l1, 1, cred->key, nullptr, 0};
    cfg.identities = &id;
    cfg.identity_count = 1;
    EXPECT_EQ(gtls_context_new(nullptr, &cfg, &ctx), GTLS_OK);
    EXPECT_EQ(gtls_conn_new_server(ctx, &conn), GTLS_OK);
    const Bytes & sh = v["server.construct-a-serverhello-handshake-message.serverhello"];
    rnd.chunks.push_back(Bytes(sh.begin() + 6, sh.begin() + 38));
    rnd.chunks.push_back(v["server.create-an-ephemeral-x25519-key-pair.private-key"]);
    gtls_conn_set_hooks(conn, ScriptedRandom::fn, &rnd, nullptr, nullptr);
    gtls_conn_set_server_hooks(conn, sign, this, chain, chain_len, 1, 0x0804, ee_prefix.data(),
        ee_prefix.size());
    EXPECT_EQ(gtls_conn_start(conn), GTLS_OK);
  }
  ~RfcServer() {
    gtls_conn_free(conn);
    gtls_context_free(ctx);
  }

  Bytes pending(GTLS_Epoch e) {
    const unsigned char * p = nullptr;
    size_t n = 0;
    EXPECT_EQ(gtls_conn_pending_output(conn, e, &p, &n), GTLS_OK);
    return n == 0 ? Bytes() : Bytes(p, p + n);
  }
  Bytes secret(GTLS_SecretId id) {
    Bytes out(GTLS_HASH_MAX);
    size_t n = 0;
    EXPECT_EQ(gtls_conn_debug_secret(conn, id, out.data(), out.size(), &n), GTLS_OK);
    out.resize(n);
    return out;
  }
};


} /* namespace gtlstest */

#endif /* GHOTI_IO_GTLS_TEST_RFC_SERVER_H */
