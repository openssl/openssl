/*
* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "test_state.h"

static CRYPTO_ONCE g_once = CRYPTO_ONCE_STATIC_INIT;
static int g_state_index = 0;

static void TestStateExFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int index, long argl, void *argp) {
 delete ((TestState *)ptr);
}

static bool InitGlobals() {
 if (CRYPTO_THREAD_run_once(&g_once, [] {
   g_state_index =
       SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, TestStateExFree);
 }) != 1) {
  abort();
 }
 return g_state_index >= 0;
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
 return (TestState *)SSL_get_ex_data(ssl, g_state_index);
}