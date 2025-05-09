/*
* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "handshake_util.h"

#include <assert.h>

#include <functional>
#include <map>
#include <vector>

#include "async_bio.h"
#include "packeted_bio.h"
#include "test_config.h"
#include "test_state.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace bssl;

bool RetryAsync(SSL *ssl, int ret) {
  const TestConfig *config = GetTestConfig(ssl);
  TestState *test_state = GetTestState(ssl);
  if (ret >= 0) {
    return false;
  }

  int ssl_err = SSL_get_error(ssl, ret);
  if (!config->async) {
    // Only asynchronous tests should trigger other retries.
    return false;
  }

  if (test_state->packeted_bio != nullptr &&
      PacketedBioAdvanceClock(test_state->packeted_bio)) {
    int timeout_ret = DTLSv1_handle_timeout(ssl);
    if (timeout_ret >= 0) {
      return true;
    }
    ssl_err = SSL_get_error(ssl, timeout_ret);
  }

  // See if we needed to read or write more. If so, allow one byte through on
  // the appropriate end to maximally stress the state machine.
  switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
      AsyncBioAllowRead(test_state->async_bio, 1);
      return true;
    case SSL_ERROR_WANT_WRITE:
      AsyncBioAllowWrite(test_state->async_bio, 1);
      return true;
    case SSL_ERROR_WANT_X509_LOOKUP:
      test_state->cert_ready = true;
      return true;
    default:
      return false;
  }
}

int CheckIdempotentError(const char *name, SSL *ssl,
                         std::function<int()> func) {
  int ret = func();
  int ssl_err = SSL_get_error(ssl, ret);
  uint32_t err = ERR_peek_error();
  if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_ZERO_RETURN) {
    int ret2 = func();
    int ssl_err2 = SSL_get_error(ssl, ret2);
    uint32_t err2 = ERR_peek_error();
    if (ret != ret2 || ssl_err != ssl_err2 || err != err2) {
      fprintf(stderr, "Repeating %s did not replay the error.\n", name);
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      fprintf(stderr, "Wanted: %d %d %s\n", ret, ssl_err, buf);
      ERR_error_string_n(err2, buf, sizeof(buf));
      fprintf(stderr, "Got:    %d %d %s\n", ret2, ssl_err2, buf);
      // runner treats exit code 90 as always failing. Otherwise, it may
      // accidentally consider the result an expected protocol failure.
      exit(90);
    }
  }
  return ret;
}

