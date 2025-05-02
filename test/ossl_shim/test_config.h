/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_SHIM_TEST_CONFIG_H
#define OSSL_TEST_SHIM_TEST_CONFIG_H

#include <string>
#include <vector>
#include <optional>

#include <openssl/base.h>
#include <openssl/x509.h>

#include "test_state.h"


struct TestConfig {
  int port = 0;
  bool ipv6 = false;
  uint64_t shim_id = 0;
  bool is_server = false;
  bool is_dtls = false;
  int resume_count = 0;
  bool fallback_scsv = false;
  std::string key_file;
  std::string cert_file;
  std::string trust_cert; // Accepted but unused, since certificate trust is not verified by default
  std::string expect_server_name;
  std::vector<uint8_t> expect_certificate_types;
  bool require_any_client_certificate = false;
  std::string advertise_npn;
  std::string expect_next_proto;
  std::string select_next_proto;
  bool async = false;
  bool write_different_record_sizes = false;
  bool partial_write = false;
  bool no_tls13 = false;
  bool no_tls12 = false;
  bool no_tls11 = false;
  bool no_tls1 = false;
  bool shim_writes_first = false;
  std::string host_name;
  std::string advertise_alpn;
  std::string expect_alpn;
  std::string expect_advertised_alpn;
  std::string select_alpn;
  bool decline_alpn = false;
  bool expect_session_miss = false;
  bool expect_extended_master_secret = false;
  std::string psk;
  std::string psk_identity;
  std::string srtp_profiles;
  uint16_t min_version = 0;
  uint16_t max_version = 0;
  int mtu = 0;
  bool implicit_handshake = false;
  std::string cipher;
  bool handshake_never_done = false;
  int export_keying_material = 0;
  std::string export_label;
  std::string export_context;
  bool use_export_context = false;
  bool expect_ticket_renewal = false;
  bool expect_no_session = false;
  bool use_ticket_callback = false;
  bool renew_ticket = false;
  bool check_close_notify = false;
  bool shim_shuts_down = false;
  bool verify_fail = false;
  bool verify_peer = false;
  bool expect_verify_result = false;
  int expect_total_renegotiations = 0;
  bool renegotiate_freely = false;
  bool use_old_client_cert_callback = false;
  bool peek_then_read = false;
  int max_cert_list = 0;
  bool is_handshaker_supported = false;
  bool wait_for_debugger = false;

  bssl::UniquePtr<SSL_CTX> SetupCtx(SSL_CTX *old_ctx) const;
  bssl::UniquePtr<SSL> NewSSL(SSL_CTX *ssl_ctx, SSL_SESSION *session,
                              std::unique_ptr<TestState> test_state) const;
};

bool ParseConfig(int argc, char **argv, bool is_shim, TestConfig *out_initial,
                 TestConfig *out_resume, TestConfig *out_retry);

bool SetTestConfig(SSL *ssl, const TestConfig *config);

const TestConfig *GetTestConfig(const SSL *ssl);

#endif  // OSSL_TEST_SHIM_TEST_CONFIG_H
