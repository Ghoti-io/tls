/**
 * @file
 *
 * The state table. Every state the client has is reached, and in each one
 * every handshake message type is offered: the one the state wants gets as
 * far as its parser (and is refused there, for an empty body), every other is
 * an unexpected message. The denominator is the table, not the line count.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "sim.h"

#include <set>

using namespace gtlstest;

namespace {

/* The client's half of the table; test_server.cpp has the server's. */
const GTLS_State kAll[] = {GTLS_STATE_NEW, GTLS_STATE_WAIT_SH, GTLS_STATE_WAIT_SH2,
    GTLS_STATE_WAIT_EE, GTLS_STATE_WAIT_CERT, GTLS_STATE_WAIT_CV, GTLS_STATE_WAIT_FIN,
    GTLS_STATE_CONNECTED, GTLS_STATE_FAILED};
const size_t kServerOnly = 4; /* S_WAIT_CH, S_WAIT_CH2, S_WAIT_FIN, S_WAIT_EOED */

const char * name(GTLS_State s) {
  switch (s) {
    case GTLS_STATE_NEW: return "NEW";
    case GTLS_STATE_WAIT_SH: return "WAIT_SH";
    case GTLS_STATE_WAIT_SH2: return "WAIT_SH2";
    case GTLS_STATE_WAIT_EE: return "WAIT_EE";
    case GTLS_STATE_WAIT_CERT: return "WAIT_CERT";
    case GTLS_STATE_WAIT_CV: return "WAIT_CV";
    case GTLS_STATE_WAIT_FIN: return "WAIT_FIN";
    case GTLS_STATE_CONNECTED: return "CONNECTED";
    case GTLS_STATE_FAILED: return "FAILED";
    default: return "?";
  }
}

/** Bring a fresh world to @p target; the server is kept for what follows. */
struct Driven {
  World w;
  std::unique_ptr<SimServer> s;
  Bytes hrr_ch2;
  explicit Driven(GTLS_State target) {
    w.build();
    SimOptions o = w.server_options();
    o.hrr = target == GTLS_STATE_WAIT_SH2;
    s.reset(new SimServer(o));
    if (target == GTLS_STATE_NEW) {
      return;
    }
    EXPECT_EQ(gtls_conn_start(w.conn), GTLS_OK);
    Bytes ch = w.out(GTLS_EPOCH_INITIAL);
    w.drain(GTLS_EPOCH_INITIAL);
    s->accept_hello(ch);
    if (target == GTLS_STATE_WAIT_SH) {
      return;
    }
    if (target == GTLS_STATE_WAIT_SH2) {
      EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, s->hrr_msg), GTLS_OK);
      return;
    }
    EXPECT_EQ(w.feed(GTLS_EPOCH_INITIAL, s->sh_msg), GTLS_OK);
    const Bytes * msgs[] = {&s->ee_wire, &s->cert_msg, &s->cv_msg, &s->fin_msg};
    GTLS_State states[] = {GTLS_STATE_WAIT_CERT, GTLS_STATE_WAIT_CV, GTLS_STATE_WAIT_FIN,
        GTLS_STATE_CONNECTED};
    if (target == GTLS_STATE_WAIT_EE) {
      return;
    }
    for (int i = 0; i < 4; i++) {
      EXPECT_EQ(w.feed(GTLS_EPOCH_HANDSHAKE, *msgs[i]), GTLS_OK);
      if (states[i] == target) {
        return;
      }
    }
  }
};

GTLS_Epoch epoch_of(GTLS_State s) {
  switch (s) {
    case GTLS_STATE_WAIT_EE:
    case GTLS_STATE_WAIT_CERT:
    case GTLS_STATE_WAIT_CV:
    case GTLS_STATE_WAIT_FIN:
      return GTLS_EPOCH_HANDSHAKE;
    case GTLS_STATE_CONNECTED:
      return GTLS_EPOCH_APPLICATION;
    default:
      return GTLS_EPOCH_INITIAL;
  }
}

unsigned wanted_type(GTLS_State s) {
  switch (s) {
    case GTLS_STATE_WAIT_SH:
    case GTLS_STATE_WAIT_SH2: return GTLS_HS_SERVER_HELLO;
    case GTLS_STATE_WAIT_EE: return GTLS_HS_ENCRYPTED_EXTENSIONS;
    case GTLS_STATE_WAIT_CERT: return GTLS_HS_CERTIFICATE;
    case GTLS_STATE_WAIT_CV: return GTLS_HS_CERTIFICATE_VERIFY;
    case GTLS_STATE_WAIT_FIN: return GTLS_HS_FINISHED;
    case GTLS_STATE_CONNECTED: return GTLS_HS_NEW_SESSION_TICKET;
    default: return 0;
  }
}

}  // namespace

TEST(StateTable, EveryStateIsReachedAndTheTableHasNoOthers) {
  EXPECT_EQ(sizeof kAll / sizeof *kAll + kServerOnly, static_cast<size_t>(GTLS_STATE_COUNT));
  std::set<GTLS_State> visited;
  for (GTLS_State target : kAll) {
    if (target == GTLS_STATE_FAILED) {
      Driven d(GTLS_STATE_WAIT_SH);
      EXPECT_NE(d.w.feed(GTLS_EPOCH_INITIAL, Bytes{GTLS_HS_FINISHED, 0, 0, 0}), GTLS_OK);
      visited.insert(gtls_conn_state(d.w.conn));
      continue;
    }
    Driven d(target);
    EXPECT_EQ(gtls_conn_state(d.w.conn), target) << name(target);
    visited.insert(gtls_conn_state(d.w.conn));
  }
  EXPECT_EQ(visited.size(), static_cast<size_t>(GTLS_STATE_COUNT) - kServerOnly);
}

TEST(StateTable, EveryMessageTypeInEveryWaitingState) {
  const unsigned types[] = {0, GTLS_HS_CLIENT_HELLO, GTLS_HS_SERVER_HELLO, 3,
      GTLS_HS_NEW_SESSION_TICKET, GTLS_HS_END_OF_EARLY_DATA, GTLS_HS_ENCRYPTED_EXTENSIONS,
      GTLS_HS_CERTIFICATE, GTLS_HS_CERTIFICATE_REQUEST, GTLS_HS_CERTIFICATE_VERIFY,
      GTLS_HS_FINISHED, GTLS_HS_KEY_UPDATE, GTLS_HS_MESSAGE_HASH, 255};
  for (GTLS_State state : kAll) {
    if (state == GTLS_STATE_NEW || state == GTLS_STATE_FAILED) {
      continue;
    }
    for (unsigned type : types) {
      Driven d(state);
      ASSERT_EQ(gtls_conn_state(d.w.conn), state);
      Bytes msg = {static_cast<unsigned char>(type), 0, 0, 0};
      GTLS_Result r = d.w.feed(epoch_of(state), msg);
      EXPECT_NE(r, GTLS_OK) << name(state) << " type " << type << ": an empty body is never valid";
      EXPECT_TRUE(gtls_conn_is_failed(d.w.conn)) << name(state) << " type " << type;
      EXPECT_TRUE(gtls_conn_secrets_are_wiped(d.w.conn)) << name(state) << " type " << type;
      if (type == wanted_type(state)) {
        EXPECT_TRUE(r == GTLS_ERR_CORRUPT || r == GTLS_ERR_PROTOCOL || r == GTLS_ERR_FINISHED ||
                    r == GTLS_ERR_CERT_INVALID)
            << name(state) << " got " << gtls_result_string(r)
            << ": the wanted message reached its parser";
        EXPECT_NE(gtls_conn_alert(d.w.conn), GTLS_ALERT_UNEXPECTED_MESSAGE)
            << name(state) << " type " << type;
      } else if (state == GTLS_STATE_WAIT_CERT && type == GTLS_HS_CERTIFICATE_REQUEST) {
        EXPECT_EQ(r, GTLS_ERR_UNSUPPORTED);
      } else if (state == GTLS_STATE_CONNECTED && type == GTLS_HS_KEY_UPDATE) {
        EXPECT_EQ(r, GTLS_ERR_UNSUPPORTED);
      } else {
        EXPECT_EQ(r, GTLS_ERR_PROTOCOL) << name(state) << " type " << type;
        EXPECT_EQ(gtls_conn_alert(d.w.conn), GTLS_ALERT_UNEXPECTED_MESSAGE)
            << name(state) << " type " << type;
      }
    }
  }
}

TEST(StateTable, EveryEpochInEveryWaitingState) {
  for (GTLS_State state : kAll) {
    if (state == GTLS_STATE_NEW || state == GTLS_STATE_FAILED) {
      continue;
    }
    for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
      Driven d(state);
      GTLS_Result r = d.w.feed(static_cast<GTLS_Epoch>(e), Bytes{GTLS_HS_FINISHED, 0, 0, 0});
      if (static_cast<GTLS_Epoch>(e) == epoch_of(state)) {
        EXPECT_NE(r, GTLS_OK) << name(state) << " epoch " << e;
      } else {
        EXPECT_EQ(r, GTLS_ERR_PROTOCOL) << name(state) << " epoch " << e;
        EXPECT_EQ(gtls_conn_alert(d.w.conn), GTLS_ALERT_UNEXPECTED_MESSAGE);
      }
    }
  }
}

TEST(StateTable, TheFailedStateIsTerminalForEveryCall) {
  Driven d(GTLS_STATE_WAIT_FIN);
  ASSERT_NE(d.w.feed(GTLS_EPOCH_HANDSHAKE, Bytes{GTLS_HS_FINISHED, 0, 0, 1, 0}), GTLS_OK);
  ASSERT_EQ(gtls_conn_state(d.w.conn), GTLS_STATE_FAILED);
  for (int e = 0; e < GTLS_EPOCH_COUNT; e++) {
    EXPECT_EQ(d.w.feed(static_cast<GTLS_Epoch>(e), d.s->sh_msg), GTLS_ERR_FAILED);
  }
  EXPECT_EQ(gtls_conn_start(d.w.conn), GTLS_ERR_FAILED);
  EXPECT_EQ(gtls_conn_state(d.w.conn), GTLS_STATE_FAILED);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
