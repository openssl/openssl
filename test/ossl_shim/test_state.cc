/*
* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "test_state.h"

#include <openssl/ssl.h>

DEFINE_LHASH_OF_EX(SSL_SESSION);

using namespace bssl;

static CRYPTO_ONCE g_once = CRYPTO_ONCE_STATIC_INIT;
static int g_state_index = 0;
// Some code treats the zero time special, so initialize the clock to a
// non-zero time.
static timeval g_clock = { 1234, 1234 };

static void TestStateExFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int index, long argl, void *argp) {
  delete static_cast<TestState *>(ptr);
}

static bool InitGlobals() {
  CRYPTO_THREAD_run_once(&g_once, [] {
    g_state_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, TestStateExFree);
  });
  return g_state_index >= 0;
}

struct timeval *GetClock() {
  return &g_clock;
}

void AdvanceClock(unsigned seconds) {
  g_clock.tv_sec += seconds;
}

bool SetTestState(SSL *ssl, std::unique_ptr<TestState> state) {
  if (!InitGlobals()) {
    return false;
  }
  // |SSL_set_ex_data| takes ownership of |state| only on success.
  if (SSL_set_ex_data(ssl, g_state_index, state.get()) == 1) {
    state.release();
    return true;
  }
  return false;
}

TestState *GetTestState(const SSL *ssl) {
  if (!InitGlobals()) {
    return nullptr;
  }
  return static_cast<TestState *>(SSL_get_ex_data(ssl, g_state_index));
}

static void ssl_ctx_add_session(SSL_SESSION *session, void *void_param) {
  SSL_CTX *ctx = reinterpret_cast<SSL_CTX *>(void_param);
  UniquePtr<SSL_SESSION> new_session(SSL_SESSION_dup(session));
  if (new_session != nullptr) {
    SSL_CTX_add_session(ctx, new_session.get());
  }
}

void CopySessions(SSL_CTX *dst, const SSL_CTX *src) {
  if (dst == src) {
    return;
  }

  lh_SSL_SESSION_doall_arg(SSL_CTX_sessions(const_cast<SSL_CTX *>(src)), ssl_ctx_add_session, dst);
}
