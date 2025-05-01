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

#include "async_bio.h"
#include "packeted_bio.h"
#include "test_config.h"
#include "test_state.h"

bool RetryAsync(SSL *ssl, int ret) {
 // No error; don't retry.
 if (ret >= 0) {
  return false;
 }

 TestState *test_state = GetTestState(ssl);
 assert(GetTestConfig(ssl)->async);

 if (test_state->packeted_bio != nullptr &&
     PacketedBioAdvanceClock(test_state->packeted_bio)) {
  // The DTLS retransmit logic silently ignores write failures. So the test
  // may progress, allow writes through synchronously.
  AsyncBioEnforceWriteQuota(test_state->async_bio, false);
  int timeout_ret = DTLSv1_handle_timeout(ssl);
  AsyncBioEnforceWriteQuota(test_state->async_bio, true);

  if (timeout_ret < 0) {
   fprintf(stderr, "Error retransmitting.\n");
   return false;
  }
  return true;
     }

 // See if we needed to read or write more. If so, allow one byte through on
 // the appropriate end to maximally stress the state machine.
 switch (SSL_get_error(ssl, ret)) {
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