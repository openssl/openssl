/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "test_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <openssl/core_names.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "test_state.h"

namespace {

template <typename T>
struct Flag {
  const char *flag;
  T TestConfig::*member;
};

// FindField looks for the flag in |flags| that matches |flag|. If one is found,
// it returns a pointer to the corresponding field in |config|. Otherwise, it
// returns NULL.
template<typename T, size_t N>
T *FindField(TestConfig *config, const Flag<T> (&flags)[N], const char *flag) {
  for (size_t i = 0; i < N; i++) {
    if (strcmp(flag, flags[i].flag) == 0) {
      return &(config->*(flags[i].member));
    }
  }
  return NULL;
}

const Flag<bool> kBoolFlags[] = {
  { "-server", &TestConfig::is_server },
  { "-dtls", &TestConfig::is_dtls },
  { "-fallback-scsv", &TestConfig::fallback_scsv },
  { "-require-any-client-certificate",
    &TestConfig::require_any_client_certificate },
  { "-async", &TestConfig::async },
  { "-write-different-record-sizes",
    &TestConfig::write_different_record_sizes },
  { "-partial-write", &TestConfig::partial_write },
  { "-no-tls13", &TestConfig::no_tls13 },
  { "-no-tls12", &TestConfig::no_tls12 },
  { "-no-tls11", &TestConfig::no_tls11 },
  { "-no-tls1", &TestConfig::no_tls1 },
  { "-shim-writes-first", &TestConfig::shim_writes_first },
  { "-expect-session-miss", &TestConfig::expect_session_miss },
  { "-decline-alpn", &TestConfig::decline_alpn },
  { "-expect-extended-master-secret",
    &TestConfig::expect_extended_master_secret },
  { "-implicit-handshake", &TestConfig::implicit_handshake },
  { "-handshake-never-done", &TestConfig::handshake_never_done },
  { "-use-export-context", &TestConfig::use_export_context },
  { "-expect-ticket-renewal", &TestConfig::expect_ticket_renewal },
  { "-expect-no-session", &TestConfig::expect_no_session },
  { "-use-ticket-callback", &TestConfig::use_ticket_callback },
  { "-renew-ticket", &TestConfig::renew_ticket },
  { "-check-close-notify", &TestConfig::check_close_notify },
  { "-shim-shuts-down", &TestConfig::shim_shuts_down },
  { "-verify-fail", &TestConfig::verify_fail },
  { "-verify-peer", &TestConfig::verify_peer },
  { "-expect-verify-result", &TestConfig::expect_verify_result },
  { "-renegotiate-freely", &TestConfig::renegotiate_freely },
  { "-use-old-client-cert-callback",
    &TestConfig::use_old_client_cert_callback },
  { "-peek-then-read", &TestConfig::peek_then_read },
};

const Flag<std::string> kStringFlags[] = {
  { "-key-file", &TestConfig::key_file },
  { "-cert-file", &TestConfig::cert_file },
  { "-expect-server-name", &TestConfig::expected_server_name },
  { "-advertise-npn", &TestConfig::advertise_npn },
  { "-expect-next-proto", &TestConfig::expected_next_proto },
  { "-select-next-proto", &TestConfig::select_next_proto },
  { "-host-name", &TestConfig::host_name },
  { "-advertise-alpn", &TestConfig::advertise_alpn },
  { "-expect-alpn", &TestConfig::expected_alpn },
  { "-expect-advertised-alpn", &TestConfig::expected_advertised_alpn },
  { "-select-alpn", &TestConfig::select_alpn },
  { "-psk", &TestConfig::psk },
  { "-psk-identity", &TestConfig::psk_identity },
  { "-srtp-profiles", &TestConfig::srtp_profiles },
  { "-cipher", &TestConfig::cipher },
  { "-export-label", &TestConfig::export_label },
  { "-export-context", &TestConfig::export_context },
};

const Flag<std::string> kBase64Flags[] = {
  { "-expect-certificate-types", &TestConfig::expected_certificate_types },
};

const Flag<int> kIntFlags[] = {
  { "-port", &TestConfig::port },
  { "-resume-count", &TestConfig::resume_count },
  { "-min-version", &TestConfig::min_version },
  { "-max-version", &TestConfig::max_version },
  { "-mtu", &TestConfig::mtu },
  { "-export-keying-material", &TestConfig::export_keying_material },
  { "-expect-total-renegotiations", &TestConfig::expect_total_renegotiations },
  { "-max-cert-list", &TestConfig::max_cert_list },
};

}  // namespace

bool ParseConfig(int argc, char **argv, TestConfig *out_config) {
  for (int i = 0; i < argc; i++) {
    bool *bool_field = FindField(out_config, kBoolFlags, argv[i]);
    if (bool_field != NULL) {
      *bool_field = true;
      continue;
    }

    std::string *string_field = FindField(out_config, kStringFlags, argv[i]);
    if (string_field != NULL) {
      const char *val;

      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }

      /*
       * Fix up the -cipher argument. runner uses "DEFAULT:NULL-SHA" to enable
       * the NULL-SHA cipher. However in OpenSSL "DEFAULT" permanently switches
       * off NULL ciphers, so we use "ALL:NULL-SHA" instead.
       */
      if (strcmp(argv[i - 1], "-cipher") == 0
          && strcmp(argv[i], "DEFAULT:NULL-SHA") == 0)
        val = "ALL:NULL-SHA";
      else
        val = argv[i];

      string_field->assign(val);
      continue;
    }

    std::string *base64_field = FindField(out_config, kBase64Flags, argv[i]);
    if (base64_field != NULL) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }
      std::unique_ptr<uint8_t[]> decoded(new uint8_t[strlen(argv[i])]);
      int len = EVP_DecodeBlock(decoded.get(),
                                reinterpret_cast<const uint8_t *>(argv[i]),
                                strlen(argv[i]));
      if (len < 0) {
        fprintf(stderr, "Invalid base64: %s\n", argv[i]);
        return false;
      }
      base64_field->assign(reinterpret_cast<const char *>(decoded.get()), len);
      continue;
    }

    int *int_field = FindField(out_config, kIntFlags, argv[i]);
    if (int_field) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }
      *int_field = atoi(argv[i]);
      continue;
    }

    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    exit(89);
  }

  return true;
}

static int TestConfigExDataIndex() {
  static int index = [&] {
    int ret = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    OPENSSL_assert(ret >= 0);
    return ret;
  }();
  return index;
}

bool SetTestConfig(SSL *ssl, const TestConfig *config) {
  return SSL_set_ex_data(ssl, TestConfigExDataIndex(), (void *)config) == 1;
}

const TestConfig *GetTestConfig(const SSL *ssl) {
  return (const TestConfig *)SSL_get_ex_data(ssl, TestConfigExDataIndex());
}

static int ServerNameCallback(SSL *ssl, int *out_alert, void *arg) {
  // SNI must be accessible from the SNI callback.
  const TestConfig *config = GetTestConfig(ssl);
  const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (server_name == nullptr ||
      std::string(server_name) != config->expected_server_name) {
    fprintf(stderr, "servername mismatch (got %s; want %s)\n", server_name,
            config->expected_server_name.c_str());
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  return SSL_TLSEXT_ERR_OK;
}

static int NextProtoSelectCallback(SSL* ssl, uint8_t** out, uint8_t* outlen,
                                   const uint8_t* in, unsigned inlen, void* arg) {
  const TestConfig *config = GetTestConfig(ssl);
  if (config->select_next_proto.empty()) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  *out = (uint8_t*)config->select_next_proto.data();
  *outlen = config->select_next_proto.size();
  return SSL_TLSEXT_ERR_OK;
}

static int NextProtosAdvertisedCallback(SSL *ssl, const uint8_t **out,
                                        unsigned int *out_len, void *arg) {
  const TestConfig *config = GetTestConfig(ssl);
  if (config->advertise_npn.empty()) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  *out = (const uint8_t*)config->advertise_npn.data();
  *out_len = config->advertise_npn.size();
  return SSL_TLSEXT_ERR_OK;
}

static int TicketKeyCallback(SSL *ssl, uint8_t *key_name, uint8_t *iv,
                             EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hmac_ctx,
                             int encrypt) {
  OSSL_PARAM params[2], *p = params;

  if (!encrypt) {
    if (GetTestState(ssl)->ticket_decrypt_done) {
      fprintf(stderr, "TicketKeyCallback called after completion.\n");
      return -1;
    }

    GetTestState(ssl)->ticket_decrypt_done = true;
  }

  // This is just test code, so use the all-zeros key.
  static const uint8_t kZeros[16] = {0};

  if (encrypt) {
    memcpy(key_name, kZeros, sizeof(kZeros));
    RAND_bytes(iv, 16);
  } else if (memcmp(key_name, kZeros, 16) != 0) {
    return 0;
  }

  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                          const_cast<char *>("SHA256"), 0);
  *p = OSSL_PARAM_construct_end();

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, kZeros, iv, encrypt)
      || !EVP_MAC_init(hmac_ctx, kZeros, sizeof(kZeros), params)) {
    return -1;
  }

  if (!encrypt) {
    return GetTestConfig(ssl)->renew_ticket ? 2 : 1;
  }
  return 1;
}

static int NewSessionCallback(SSL *ssl, SSL_SESSION *session) {
  GetTestState(ssl)->got_new_session = true;
  GetTestState(ssl)->new_session.reset(session);
  return 1;
}

static void InfoCallback(const SSL *ssl, int type, int val) {
  if (type == SSL_CB_HANDSHAKE_DONE) {
    if (GetTestConfig(ssl)->handshake_never_done) {
      fprintf(stderr, "Handshake unexpectedly completed.\n");
      // Abort before any expected error code is printed, to ensure the overall
      // test fails.
      abort();
    }
    GetTestState(ssl)->handshake_done = true;

    // Callbacks may be called again on a new handshake.
    GetTestState(ssl)->ticket_decrypt_done = false;
    GetTestState(ssl)->alpn_select_done = false;
  }
}

static int AlpnSelectCallback(SSL* ssl, const uint8_t** out, uint8_t* outlen,
                              const uint8_t* in, unsigned inlen, void* arg) {
  if (GetTestState(ssl)->alpn_select_done) {
    fprintf(stderr, "AlpnSelectCallback called after completion.\n");
    exit(1);
  }

  GetTestState(ssl)->alpn_select_done = true;

  const TestConfig *config = GetTestConfig(ssl);
  if (config->decline_alpn) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  if (!config->expected_advertised_alpn.empty() &&
      (config->expected_advertised_alpn.size() != inlen ||
       memcmp(config->expected_advertised_alpn.data(),
              in, inlen) != 0)) {
    fprintf(stderr, "bad ALPN select callback inputs\n");
    exit(1);
  }

  *out = (const uint8_t*)config->select_alpn.data();
  *outlen = config->select_alpn.size();
  return SSL_TLSEXT_ERR_OK;
}

static int VerifySucceed(X509_STORE_CTX *store_ctx, void *arg) {
  return 1;
}

static int VerifyFail(X509_STORE_CTX *store_ctx, void *arg) {
  X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
  return 0;
}

static bssl::UniquePtr<X509> LoadCertificate(const std::string &file) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file.c_str())) {
    return nullptr;
  }
  return bssl::UniquePtr<X509>(PEM_read_bio_X509(bio.get(), NULL, NULL, NULL));
}

static bssl::UniquePtr<EVP_PKEY> LoadPrivateKey(const std::string &file) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file.c_str())) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(
      PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL));
}

static bool GetCertificate(SSL *ssl, bssl::UniquePtr<X509> *out_x509,
                           bssl::UniquePtr<EVP_PKEY> *out_pkey) {
  const TestConfig *config = GetTestConfig(ssl);

  if (!config->key_file.empty()) {
    *out_pkey = LoadPrivateKey(config->key_file.c_str());
    if (!*out_pkey) {
      return false;
    }
  }
  if (!config->cert_file.empty()) {
    *out_x509 = LoadCertificate(config->cert_file.c_str());
    if (!*out_x509) {
      return false;
    }
  }
  return true;
}

static int ClientCertCallback(SSL *ssl, X509 **out_x509, EVP_PKEY **out_pkey) {
  if (GetTestConfig(ssl)->async && !GetTestState(ssl)->cert_ready) {
    return -1;
  }

  bssl::UniquePtr<X509> x509;
  bssl::UniquePtr<EVP_PKEY> pkey;
  if (!GetCertificate(ssl, &x509, &pkey)) {
    return -1;
  }

  // Return zero for no certificate.
  if (!x509) {
    return 0;
  }

  // Asynchronous private keys are not supported with client_cert_cb.
  *out_x509 = x509.release();
  *out_pkey = pkey.release();
  return 1;
}

static bool InstallCertificate(SSL *ssl) {
  bssl::UniquePtr<X509> x509;
  bssl::UniquePtr<EVP_PKEY> pkey;
  if (!GetCertificate(ssl, &x509, &pkey)) {
    return false;
  }

  if (pkey && !SSL_use_PrivateKey(ssl, pkey.get())) {
    return false;
  }

  if (x509 && !SSL_use_certificate(ssl, x509.get())) {
    return false;
  }

  return true;
}

bssl::UniquePtr<SSL_CTX> TestConfig::SetupCtx(SSL_CTX *old_ctx) const {
  const char sess_id_ctx[] = "ossl_shim";
  bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(
      is_dtls ? DTLS_method() : TLS_method()));
  if (!ssl_ctx) {
    return nullptr;
  }

  SSL_CTX_set_security_level(ssl_ctx.get(), 0);
#if 0
  /* Disabled for now until we have some TLS1.3 support */
  // Enable TLS 1.3 for tests.
  if (!config->is_dtls &&
      !SSL_CTX_set_max_proto_version(ssl_ctx.get(), TLS1_3_VERSION)) {
    return nullptr;
  }
#else
  /* Ensure we don't negotiate TLSv1.3 until we can handle it */
  if (!is_dtls &&
      !SSL_CTX_set_max_proto_version(ssl_ctx.get(), TLS1_2_VERSION)) {
    return nullptr;
  }
#endif

  std::string cipher_list = "ALL";
  if (!cipher.empty()) {
    cipher_list = cipher;
    SSL_CTX_set_options(ssl_ctx.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);
  }
  if (!SSL_CTX_set_cipher_list(ssl_ctx.get(), cipher_list.c_str())) {
    return nullptr;
  }

  SSL_CTX_set_session_cache_mode(ssl_ctx.get(), SSL_SESS_CACHE_BOTH);

  if (use_old_client_cert_callback) {
    SSL_CTX_set_client_cert_cb(ssl_ctx.get(), ClientCertCallback);
  }

  SSL_CTX_set_npn_advertised_cb(
      ssl_ctx.get(), NextProtosAdvertisedCallback, NULL);
  if (!select_next_proto.empty()) {
    SSL_CTX_set_next_proto_select_cb(ssl_ctx.get(), NextProtoSelectCallback,
                                     NULL);
  }

  if (!select_alpn.empty() || decline_alpn) {
    SSL_CTX_set_alpn_select_cb(ssl_ctx.get(), AlpnSelectCallback, NULL);
  }

  SSL_CTX_set_info_callback(ssl_ctx.get(), InfoCallback);
  SSL_CTX_sess_set_new_cb(ssl_ctx.get(), NewSessionCallback);

  if (use_ticket_callback) {
    SSL_CTX_set_tlsext_ticket_key_evp_cb(ssl_ctx.get(), TicketKeyCallback);
  }

  if (verify_fail) {
    SSL_CTX_set_cert_verify_callback(ssl_ctx.get(), VerifyFail, NULL);
  } else {
    SSL_CTX_set_cert_verify_callback(ssl_ctx.get(), VerifySucceed, NULL);
  }

  if (!SSL_CTX_set_session_id_context(ssl_ctx.get(),
                                      (const unsigned char *)sess_id_ctx,
                                      sizeof(sess_id_ctx) - 1))
    return nullptr;

  if (!expected_server_name.empty()) {
    SSL_CTX_set_tlsext_servername_callback(ssl_ctx.get(), ServerNameCallback);
  }

  return ssl_ctx;
}

static unsigned PskClientCallback(SSL *ssl, const char *hint,
                                  char *out_identity,
                                  unsigned max_identity_len,
                                  uint8_t *out_psk, unsigned max_psk_len) {
  const TestConfig *config = GetTestConfig(ssl);

  if (config->psk_identity.empty()) {
    if (hint != nullptr) {
      fprintf(stderr, "Server PSK hint was non-null.\n");
      return 0;
    }
  } else if (hint == nullptr ||
             strcmp(hint, config->psk_identity.c_str()) != 0) {
    fprintf(stderr, "Server PSK hint did not match.\n");
    return 0;
  }

  // Account for the trailing '\0' for the identity.
  if (config->psk_identity.size() >= max_identity_len ||
      config->psk.size() > max_psk_len) {
    fprintf(stderr, "PSK buffers too small\n");
    return 0;
  }

  OPENSSL_strlcpy(out_identity, config->psk_identity.c_str(),
                  max_identity_len);
  memcpy(out_psk, config->psk.data(), config->psk.size());
  return config->psk.size();
}

static unsigned PskServerCallback(SSL *ssl, const char *identity,
                                  uint8_t *out_psk, unsigned max_psk_len) {
  const TestConfig *config = GetTestConfig(ssl);

  if (strcmp(identity, config->psk_identity.c_str()) != 0) {
    fprintf(stderr, "Client PSK identity did not match.\n");
    return 0;
  }

  if (config->psk.size() > max_psk_len) {
    fprintf(stderr, "PSK buffers too small\n");
    return 0;
  }

  memcpy(out_psk, config->psk.data(), config->psk.size());
  return config->psk.size();
}

static int CertCallback(SSL *ssl, void *arg) {
  const TestConfig *config = GetTestConfig(ssl);

  // Check the CertificateRequest metadata is as expected.
  //
  // TODO(davidben): Test |SSL_get_client_CA_list|.
  if (!SSL_is_server(ssl) &&
      !config->expected_certificate_types.empty()) {
    const uint8_t *certificate_types;
    size_t certificate_types_len =
        SSL_get0_certificate_types(ssl, &certificate_types);
    if (certificate_types_len != config->expected_certificate_types.size() ||
        memcmp(certificate_types,
               config->expected_certificate_types.data(),
               certificate_types_len) != 0) {
      fprintf(stderr, "certificate types mismatch\n");
      return 0;
    }
  }

  // The certificate will be installed via other means.
  if (!config->async ||
      config->use_old_client_cert_callback) {
    return 1;
  }

  if (!GetTestState(ssl)->cert_ready) {
    return -1;
  }
  if (!InstallCertificate(ssl)) {
    return 0;
  }
  return 1;
}

bssl::UniquePtr<SSL> TestConfig::NewSSL(
    SSL_CTX *ssl_ctx, SSL_SESSION *session, std::unique_ptr<TestState> test_state) const {
  bssl::UniquePtr<SSL> ssl(SSL_new(ssl_ctx));
  if (!ssl) {
    return nullptr;
  }

  if (!SetTestConfig(ssl.get(), this) ||
      !SetTestState(ssl.get(), std::unique_ptr<TestState>(new TestState))) {
    return nullptr;
  }

  if (fallback_scsv && !SSL_set_mode(ssl.get(), SSL_MODE_SEND_FALLBACK_SCSV)) {
    return nullptr;
  }
  // Install the certificate synchronously if nothing else will handle it.
  if (!use_old_client_cert_callback && !async &&
      !InstallCertificate(ssl.get())) {
    return nullptr;
  }
  SSL_set_cert_cb(ssl.get(), CertCallback, nullptr);
  if (require_any_client_certificate) {
    SSL_set_verify(ssl.get(), SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                   NULL);
  }
  if (verify_peer) {
    SSL_set_verify(ssl.get(), SSL_VERIFY_PEER, NULL);
  }
  if (partial_write) {
    SSL_set_mode(ssl.get(), SSL_MODE_ENABLE_PARTIAL_WRITE);
  }
  if (no_tls13) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1_3);
  }
  if (no_tls12) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1_2);
  }
  if (no_tls11) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1_1);
  }
  if (no_tls1) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1);
  }
  if (!host_name.empty() &&
      !SSL_set_tlsext_host_name(ssl.get(), host_name.c_str())) {
    return nullptr;
  }
  if (!advertise_alpn.empty() &&
      SSL_set_alpn_protos(ssl.get(),
                          (const uint8_t *)advertise_alpn.data(),
                          advertise_alpn.size()) != 0) {
    return nullptr;
  }
  if (!psk.empty()) {
    SSL_set_psk_client_callback(ssl.get(), PskClientCallback);
    SSL_set_psk_server_callback(ssl.get(), PskServerCallback);
  }
  if (!psk_identity.empty() &&
      !SSL_use_psk_identity_hint(ssl.get(), psk_identity.c_str())) {
    return nullptr;
  }
  if (!srtp_profiles.empty() &&
      SSL_set_tlsext_use_srtp(ssl.get(), srtp_profiles.c_str())) {
    return nullptr;
  }
  if (min_version != 0 &&
      !SSL_set_min_proto_version(ssl.get(), (uint16_t)min_version)) {
    return nullptr;
  }
  if (max_version != 0 &&
      !SSL_set_max_proto_version(ssl.get(), (uint16_t)max_version)) {
    return nullptr;
  }
  if (mtu != 0) {
    SSL_set_options(ssl.get(), SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(ssl.get(), mtu);
  }
  if (renegotiate_freely) {
    // This is always on for OpenSSL.
  }
  if (!check_close_notify) {
    SSL_set_quiet_shutdown(ssl.get(), 1);
  }
  if (max_cert_list > 0) {
    SSL_set_max_cert_list(ssl.get(), max_cert_list);
  }

  if (!async) {
    SSL_set_mode(ssl.get(), SSL_MODE_AUTO_RETRY);
  }

  return ssl;
}
