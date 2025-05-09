/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "test_config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits>

#include <openssl/core_names.h>
#include <openssl/err.h>

#include <openssl/evp.h>
#include <openssl/internal.h>
#include <openssl/rand.h>
#include <openssl/span.h>

#include "test_state.h"

#define GROUP_ID_X25519MLKEM768 0x11ec

static const std::unordered_map<uint16_t, shim_group> kGroups = {
  {0x0015, {NID_secp224r1, "secp224r1"}},
  {0x0017, {NID_X9_62_prime256v1, "secp256r1"}},
  {0x0018, {NID_secp384r1, "secp384r1"}},
  {0x0019, {NID_secp521r1, "secp521r1"}},
  {0x001d, {NID_X25519, "X25519"}},
  {0x11ec, {TLSEXT_nid_unknown | 0x11ec, "X25519MLKEM768"}}
};

std::optional<shim_group> GetGroup(const uint16_t id) {
  if (const auto group = kGroups.find(id); group != kGroups.end()) {
    return {group->second};
  }

  return {};
}

// BoringSSL default signature algorithms for signing
const std::string kDefaultSignatureAlgorithmsSign =
  "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512"
  ":ed25519"
  ":rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512"
  ":rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512"
  ":ecdsa_sha1:rsa_pkcs1_sha1";

// BoringSSL default signature algorithms for verify
const std::string kDefaultSignatureAlgorithmsVerify =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384"
    ":rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512"
    ":rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512"
    ":rsa_pkcs1_sha1";

static const std::unordered_map<uint16_t, std::string> kSignatureAlgorithms = {
  {0x201, "rsa_pkcs1_sha1"},
  {0x401, "rsa_pkcs1_sha256"},
  {0x501, "rsa_pkcs1_sha384"},
  {0x601, "rsa_pkcs1_sha512"},
  {0x203, "ecdsa_sha1"},
  {0x403, "ecdsa_secp256r1_sha256"},
  {0x503, "ecdsa_secp384r1_sha384"},
  {0x603, "ecdsa_secp521r1_sha512"},
  {0x804, "rsa_pss_rsae_sha256"},
  {0x805, "rsa_pss_rsae_sha384"},
  {0x806, "rsa_pss_rsae_sha512"},
  {0x807, "ed25519"}
};

std::optional<std::string> GetSignatureAlgorithm(uint16_t id) {
  if (const auto alg = kSignatureAlgorithms.find(id); alg != kSignatureAlgorithms.end()) {
    return {alg->second};
  }

  return {};
}

std::optional<std::string> GetSignatureAlgorithmList(const std::vector<uint16_t> &ids) {
  std::string sigalgs;

  for (int i = 0; i < ids.size(); ++i) {
    if (i > 0) {
      sigalgs.append(":");
    }
    if (const auto alg = GetSignatureAlgorithm(ids[i])) {
      sigalgs.append(alg.value());
    } else {
      fprintf(stderr, "Unknown signature algorithm %hu\n", ids[i]);
      return {};
    }
  }
  return sigalgs;
}

namespace {

template <typename Config>
struct Flag {
  const char *name;
  bool has_param;
  // skip_handshaker, if true, causes this flag to be skipped when
  // forwarding flags to the handshaker. This should be used with flags
  // that only impact connecting to the runner.
  bool skip_handshaker;
  // If |has_param| is false, |param| will be nullptr.
  std::function<bool(Config *config, const char *param)> set_param;
};

template <typename Config>
Flag<Config> BoolFlag(const char *name, bool Config::*field,
                      bool skip_handshaker = false) {
  return Flag<Config>{name, false, skip_handshaker,
                      [=](Config *config, const char *) -> bool {
                        config->*field = true;
                        return true;
                      }};
}

template <typename Config>
Flag<Config> OptionalBoolTrueFlag(const char *name,
                                  std::optional<bool> Config::*field,
                                  bool skip_handshaker = false) {
  return Flag<Config>{name, false, skip_handshaker,
                      [=](Config *config, const char *) -> bool {
                        config->*field = true;
                        return true;
                      }};
}

template <typename Config>
Flag<Config> OptionalBoolFalseFlag(const char *name,
                                   std::optional<bool> Config::*field,
                                   bool skip_handshaker = false) {
  return Flag<Config>{name, false, skip_handshaker,
                      [=](Config *config, const char *) -> bool {
                        config->*field = false;
                        return true;
                      }};
}

template <typename T>
bool StringToInt(T *out, const char *str) {
  static_assert(std::is_integral<T>::value, "not an integral type");

  // |strtoull| allows leading '-' with wraparound. Additionally, both
  // functions accept empty strings and leading whitespace.
  if (!OPENSSL_isdigit(static_cast<unsigned char>(*str)) &&
      (!std::is_signed<T>::value || *str != '-')) {
    return false;
  }

  errno = 0;
  char *end;
  if (std::is_signed<T>::value) {
    static_assert(sizeof(T) <= sizeof(long long),
                  "type too large for long long");
    long long value = strtoll(str, &end, 10);
    if (value < static_cast<long long>(std::numeric_limits<T>::min()) ||
        value > static_cast<long long>(std::numeric_limits<T>::max())) {
      return false;
    }
    *out = static_cast<T>(value);
  } else {
    static_assert(sizeof(T) <= sizeof(unsigned long long),
                  "type too large for unsigned long long");
    unsigned long long value = strtoull(str, &end, 10);
    if (value >
        static_cast<unsigned long long>(std::numeric_limits<T>::max())) {
      return false;
    }
    *out = static_cast<T>(value);
  }

  // Check for overflow and that the whole input was consumed.
  return errno != ERANGE && *end == '\0';
}

template <typename Config, typename T>
Flag<Config> IntFlag(const char *name, T Config::*field,
                     bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        return StringToInt(&(config->*field), param);
                      }};
}

template <typename Config, typename T>
Flag<Config> OptionalIntFlag(const char *name, std::optional<T> Config::*field,
                             bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        T value;
                        if (!StringToInt(&value, param)) {
                          return false;
                        }
                        config->*field = value;
                        return true;
                      }};
}

template <typename Config, typename T>
Flag<Config> IntVectorFlag(const char *name, std::vector<T> Config::*field,
                           bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        T value;
                        if (!StringToInt(&value, param)) {
                          return false;
                        }
                        (config->*field).push_back(value);
                        return true;
                      }};
}

template <typename Config>
Flag<Config> StringFlag(const char *name, std::string Config::*field,
                        bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        config->*field = param;
                        return true;
                      }};
}

template <typename Config>
Flag<Config> OptionalStringFlag(const char *name,
                                std::optional<std::string> Config::*field,
                                bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        (config->*field).emplace(param);
                        return true;
                      }};
}

bool DecodeBase64(std::vector<uint8_t> *out, const std::string &in) {
  bssl::UniquePtr<EVP_ENCODE_CTX> decode_ctx(EVP_ENCODE_CTX_new());
  EVP_DecodeInit(decode_ctx.get());

  out->resize(EVP_DECODE_LENGTH(in.size()));

  int inlen = in.size();
  int outlen = 0;
  int donelen = 0;
  int read = 0;
  const int chunklen = 80;
  const unsigned char *pin = reinterpret_cast<const uint8_t *>(in.data());
  unsigned char *pout = out->data();

  do {
    int currentlen = inlen > chunklen ? chunklen : inlen;
    if (EVP_DecodeUpdate(decode_ctx.get(), pout+outlen, &read,
      pin+donelen, currentlen) < 0) {
      fprintf(stderr, "Invalid base64: %s.\n", in.c_str());
      return false;
    }

    donelen += currentlen;
    inlen -= currentlen;
    outlen += read;
  } while (inlen>0);

  if (EVP_DecodeFinal(decode_ctx.get(), pout+outlen, &read) != 1) {
    fprintf(stderr, "Failed to decode: %s.\n", in.c_str());
    return false;
  }
  outlen += read;
  out->resize(outlen);
  return true;
}

template <typename Config>
Flag<Config> Base64Flag(const char *name, std::vector<uint8_t> Config::*field,
                        bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        return DecodeBase64(&(config->*field), param);
                      }};
}

template <typename Config>
Flag<Config> OptionalBase64Flag(
    const char *name, std::optional<std::vector<uint8_t>> Config::*field,
    bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        (config->*field).emplace();
                        return DecodeBase64(&*(config->*field), param);
                      }};
}

template <typename Config>
Flag<Config> Base64VectorFlag(const char *name,
                              std::vector<std::vector<uint8_t>> Config::*field,
                              bool skip_handshaker = false) {
  return Flag<Config>{name, true, skip_handshaker,
                      [=](Config *config, const char *param) -> bool {
                        std::vector<uint8_t> value;
                        if (!DecodeBase64(&value, param)) {
                          return false;
                        }
                        (config->*field).push_back(std::move(value));
                        return true;
                      }};
}

template <typename Config>
Flag<Config> StringPairVectorFlag(
    const char *name,
    std::vector<std::pair<std::string, std::string>> Config::*field,
    bool skip_handshaker = false) {
  return Flag<Config>{
      name, true, skip_handshaker,
      [=](Config *config, const char *param) -> bool {
        const char *comma = strchr(param, ',');
        if (!comma) {
          return false;
        }
        (config->*field)
            .push_back(std::make_pair(std::string(param, comma - param),
                                      std::string(comma + 1)));
        return true;
      }};
}

struct FlagNameComparator {
  template <typename Config>
  bool operator()(const Flag<Config> &flag1, const Flag<Config> &flag2) const {
    return strcmp(flag1.name, flag2.name) < 0;
  }

  template <typename Config>
  bool operator()(const Flag<Config> &flag, const char *name) const {
    return strcmp(flag.name, name) < 0;
  }
};

const Flag<TestConfig> *FindFlag(const char *name) {
  static const std::vector<Flag<TestConfig>> flags = [] {
    std::vector<Flag<TestConfig>> ret = {
        IntFlag("-port", &TestConfig::port, /*skip_handshaker=*/true),
        BoolFlag("-ipv6", &TestConfig::ipv6, /*skip_handshaker=*/true),
        IntFlag("-shim-id", &TestConfig::shim_id, /*skip_handshaker=*/true),
        BoolFlag("-server", &TestConfig::is_server),
        BoolFlag("-dtls", &TestConfig::is_dtls),
        IntFlag("-resume-count", &TestConfig::resume_count),
        BoolFlag("-fallback-scsv", &TestConfig::fallback_scsv),
        IntVectorFlag("-verify-prefs", &TestConfig::verify_prefs),
        IntVectorFlag("-curves", &TestConfig::curves),
        StringFlag("-trust-cert", &TestConfig::trust_cert),
        StringFlag("-expect-server-name", &TestConfig::expect_server_name),
        Base64Flag("-expect-certificate-types",
                   &TestConfig::expect_certificate_types),
        BoolFlag("-require-any-client-certificate",
                 &TestConfig::require_any_client_certificate),
        StringFlag("-advertise-npn", &TestConfig::advertise_npn),
        BoolFlag("-advertise-empty-npn", &TestConfig::advertise_empty_npn),
        StringFlag("-expect-next-proto", &TestConfig::expect_next_proto),
        BoolFlag("-expect-no-next-proto", &TestConfig::expect_no_next_proto),
        StringFlag("-select-next-proto", &TestConfig::select_next_proto),
        BoolFlag("-select-empty-next-proto",
                 &TestConfig::select_empty_next_proto),
        BoolFlag("-async", &TestConfig::async),
        BoolFlag("-write-different-record-sizes",
                 &TestConfig::write_different_record_sizes),
        BoolFlag("-partial-write", &TestConfig::partial_write),
        BoolFlag("-no-tls13", &TestConfig::no_tls13),
        BoolFlag("-no-tls12", &TestConfig::no_tls12),
        BoolFlag("-no-tls11", &TestConfig::no_tls11),
        BoolFlag("-no-tls1", &TestConfig::no_tls1),
        BoolFlag("-no-ticket", &TestConfig::no_ticket),
        BoolFlag("-shim-writes-first", &TestConfig::shim_writes_first),
        StringFlag("-host-name", &TestConfig::host_name),
        StringFlag("-advertise-alpn", &TestConfig::advertise_alpn),
        StringFlag("-expect-alpn", &TestConfig::expect_alpn),
        StringFlag("-expect-advertised-alpn",
                   &TestConfig::expect_advertised_alpn),
        StringFlag("-select-alpn", &TestConfig::select_alpn),
        BoolFlag("-decline-alpn", &TestConfig::decline_alpn),
        BoolFlag("-reject-alpn", &TestConfig::reject_alpn),
        BoolFlag("-select-empty-alpn", &TestConfig::select_empty_alpn),
        BoolFlag("-expect-session-miss", &TestConfig::expect_session_miss),
        BoolFlag("-expect-extended-master-secret",
                 &TestConfig::expect_extended_master_secret),
        StringFlag("-psk", &TestConfig::psk),
        StringFlag("-psk-identity", &TestConfig::psk_identity),
        StringFlag("-srtp-profiles", &TestConfig::srtp_profiles),
        BoolFlag("-enable-ocsp-stapling", &TestConfig::enable_ocsp_stapling),
        BoolFlag("-enable-signed-cert-timestamps",
                 &TestConfig::enable_signed_cert_timestamps),
        Base64Flag("-expect-signed-cert-timestamps",
                   &TestConfig::expect_signed_cert_timestamps),
        IntFlag("-min-version", &TestConfig::min_version),
        IntFlag("-max-version", &TestConfig::max_version),
        IntFlag("-expect-version", &TestConfig::expect_version),
        IntFlag("-mtu", &TestConfig::mtu),
        BoolFlag("-implicit-handshake", &TestConfig::implicit_handshake),
        BoolFlag("-fail-cert-callback", &TestConfig::fail_cert_callback),
        StringFlag("-cipher", &TestConfig::cipher),
        BoolFlag("-handshake-never-done", &TestConfig::handshake_never_done),
        IntFlag("-export-keying-material", &TestConfig::export_keying_material),
        StringFlag("-export-label", &TestConfig::export_label),
        StringFlag("-export-context", &TestConfig::export_context),
        BoolFlag("-use-export-context", &TestConfig::use_export_context),
        BoolFlag("-expect-ticket-renewal", &TestConfig::expect_ticket_renewal),
        BoolFlag("-expect-no-session", &TestConfig::expect_no_session),
        BoolFlag("-use-ticket-callback", &TestConfig::use_ticket_callback),
        BoolFlag("-renew-ticket", &TestConfig::renew_ticket),
        BoolFlag("-skip-ticket", &TestConfig::skip_ticket),
        Base64Flag("-expect-ocsp-response", &TestConfig::expect_ocsp_response),
        BoolFlag("-check-close-notify", &TestConfig::check_close_notify),
        BoolFlag("-shim-shuts-down", &TestConfig::shim_shuts_down),
        BoolFlag("-verify-fail", &TestConfig::verify_fail),
        BoolFlag("-verify-peer", &TestConfig::verify_peer),
        BoolFlag("-expect-verify-result", &TestConfig::expect_verify_result),
        IntFlag("-expect-total-renegotiations",
                &TestConfig::expect_total_renegotiations),
        IntFlag("-expect-peer-signature-algorithm",
                &TestConfig::expect_peer_signature_algorithm),
        BoolFlag("-renegotiate-freely", &TestConfig::renegotiate_freely),
        IntFlag("-expect-curve-id", &TestConfig::expect_curve_id),
        BoolFlag("-use-old-client-cert-callback",
                 &TestConfig::use_old_client_cert_callback),
        StringFlag("-use-client-ca-list", &TestConfig::use_client_ca_list),
        StringFlag("-expect-client-ca-list",
                   &TestConfig::expect_client_ca_list),
        BoolFlag("-peek-then-read", &TestConfig::peek_then_read),
        IntFlag("-max-cert-list", &TestConfig::max_cert_list),
        IntFlag("-expect-cipher", &TestConfig::expect_cipher),
        StringFlag("-expect-peer-cert-file",
                   &TestConfig::expect_peer_cert_file),
        IntFlag("-read-size", &TestConfig::read_size),
        BoolFlag("-expect-session-id", &TestConfig::expect_session_id),
        BoolFlag("-expect-no-session-id", &TestConfig::expect_no_session_id),
        BoolFlag("-use-ocsp-callback", &TestConfig::use_ocsp_callback),
        BoolFlag("-set-ocsp-in-callback", &TestConfig::set_ocsp_in_callback),
        BoolFlag("-decline-ocsp-callback", &TestConfig::decline_ocsp_callback),
        BoolFlag("-fail-ocsp-callback", &TestConfig::fail_ocsp_callback),
        BoolFlag("-is-handshaker-supported",
                 &TestConfig::is_handshaker_supported),
        BoolFlag("-server-preference", &TestConfig::server_preference),
        BoolFlag("-key-update", &TestConfig::key_update),
        BoolFlag("-key-update-before-read",
                 &TestConfig::key_update_before_read),
        BoolFlag("-wait-for-debugger", &TestConfig::wait_for_debugger),

        StringFlag("-cert-file", &TestConfig::cert_file),
        StringFlag("-key-file", &TestConfig::key_file),
        IntVectorFlag("-signing-prefs", &TestConfig::signing_prefs),
        Base64Flag("-ocsp-response", &TestConfig::ocsp_response),

        StringFlag("-shim-key-log-file", &TestConfig::shim_key_log_file),
    };
    std::sort(ret.begin(), ret.end(), FlagNameComparator{});
    return ret;
  }();
  auto iter =
      std::lower_bound(flags.begin(), flags.end(), name, FlagNameComparator{});
  if (iter == flags.end() || strcmp(iter->name, name) != 0) {
    return nullptr;
  }
  return &*iter;
}

// RemovePrefix checks if |*str| begins with |prefix| + "-". If so, it advances
// |*str| past |prefix| (but not past the "-") and returns true. Otherwise, it
// returns false and leaves |*str| unmodified.
bool RemovePrefix(const char **str, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  if (strncmp(*str, prefix, strlen(prefix)) == 0 && (*str)[prefix_len] == '-') {
    *str += strlen(prefix);
    return true;
  }
  return false;
}

}  // namespace

bool ParseConfig(int argc, char **argv, bool is_shim, TestConfig *out_initial,
                 TestConfig *out_resume, TestConfig *out_retry) {
  for (int i = 0; i < argc; i++) {
    bool skip = false;
    const char *arg = argv[i];
    const char *name = arg;

    // -on-shim and -on-handshaker prefixes enable flags only on the shim or
    // handshaker.
    if (RemovePrefix(&name, "-on-shim")) {
      if (!is_shim) {
        skip = true;
      }
    } else if (RemovePrefix(&name, "-on-handshaker")) {
      if (is_shim) {
        skip = true;
      }
    }

    // The following prefixes allow different configurations for each of the
    // initial, resumption, and 0-RTT retry handshakes.
    TestConfig *out = nullptr;
    if (RemovePrefix(&name, "-on-initial")) {
      out = out_initial;
    } else if (RemovePrefix(&name, "-on-resume")) {
      out = out_resume;
    } else if (RemovePrefix(&name, "-on-retry")) {
      out = out_retry;
    }

    const Flag<TestConfig> *flag = FindFlag(name);
    if (flag == nullptr) {
      fprintf(stderr, "Unrecognized flag: %s\n", name);
      exit(89);
    }

    const char *param = nullptr;
    if (flag->has_param) {
      if (i >= argc) {
        fprintf(stderr, "Missing parameter for %s\n", name);
        return false;
      }
      i++;
      param = argv[i];
    }

    if (!skip) {
      if (out != nullptr) {
        if (!flag->set_param(out, param)) {
          fprintf(stderr, "Invalid parameter for %s: %s\n", name, param);
          return false;
        }
      } else {
        // Unprefixed flags apply to all three.
        if (!flag->set_param(out_initial, param) ||
            !flag->set_param(out_resume, param) ||
            !flag->set_param(out_retry, param)) {
          fprintf(stderr, "Invalid parameter for %s: %s\n", name, param);
          return false;
        }
      }
    }
  }

  return true;
}

static int TestConfigExDataIndex() {
  static int index = [&] {
    int ret = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    BSSL_CHECK(ret >= 0);
    return ret;
  }();
  return index;
}

bool SetTestConfig(SSL *ssl, const TestConfig *config) {
  return SSL_set_ex_data(ssl, TestConfigExDataIndex(), (void *)config) == 1;
}

const TestConfig *GetTestConfig(const SSL *ssl) {
  return static_cast<const TestConfig *>(
      SSL_get_ex_data(ssl, TestConfigExDataIndex()));
}

static int OCSPCallback(SSL *ssl, void *arg) {
  const TestConfig *config = GetTestConfig(ssl);
  if (!SSL_is_server(ssl)) {
    return !config->fail_ocsp_callback;
  }

  if (!config->ocsp_response.empty() && config->set_ocsp_in_callback) {
    const size_t len = config->ocsp_response.size();
    auto *buf = static_cast<uint8_t *>(OPENSSL_malloc(len));
    if (buf == nullptr) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    OPENSSL_memcpy(buf, config->ocsp_response.data(), len);
    if (!SSL_set_tlsext_status_ocsp_resp(ssl, buf, len)) {
      OPENSSL_free(buf);
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
  }
  if (config->fail_ocsp_callback) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  if (config->decline_ocsp_callback) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}

static int ServerNameCallback(SSL *ssl, int *out_alert, void *arg) {
  // SNI must be accessible from the SNI callback.
  const TestConfig *config = GetTestConfig(ssl);
  const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (server_name == nullptr ||
      std::string(server_name) != config->expect_server_name) {
    fprintf(stderr, "servername mismatch (got %s; want %s).\n", server_name,
            config->expect_server_name.c_str());
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  return SSL_TLSEXT_ERR_OK;
}

static int NextProtoSelectCallback(SSL *ssl, uint8_t **out, uint8_t *outlen,
                                   const uint8_t *in, unsigned inlen,
                                   void *arg) {
  const TestConfig *config = GetTestConfig(ssl);
  *out = (uint8_t *)config->select_next_proto.data();
  *outlen = config->select_next_proto.size();
  return SSL_TLSEXT_ERR_OK;
}

static int NextProtosAdvertisedCallback(SSL *ssl, const uint8_t **out,
                                        unsigned int *out_len, void *arg) {
  const TestConfig *config = GetTestConfig(ssl);
  if (config->advertise_npn.empty() && !config->advertise_empty_npn) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  if (config->advertise_npn.size() > UINT_MAX) {
    fprintf(stderr, "NPN value too large.\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  *out = reinterpret_cast<const uint8_t *>(config->advertise_npn.data());
  *out_len = static_cast<unsigned>(config->advertise_npn.size());
  return SSL_TLSEXT_ERR_OK;
}

static int TicketKeyCallback(SSL *ssl, uint8_t *key_name, uint8_t *iv,
                             EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hmac_ctx,
                             int encrypt) {
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
    if (GetTestConfig(ssl)->skip_ticket) {
      return 0;
    }
    memcpy(key_name, kZeros, sizeof(kZeros));
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);
  } else if (memcmp(key_name, kZeros, 16) != 0) {
    return 0;
  }

  OSSL_PARAM params[3], *p = params;
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                           (void *)kZeros,
                                           sizeof(kZeros));
  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                          const_cast<char *>("sha256"), 0);
  *p = OSSL_PARAM_construct_end();

  if (!EVP_MAC_CTX_set_params(hmac_ctx, params)
      || !EVP_CipherInit_ex2(ctx, EVP_aes_128_cbc(), kZeros, iv,
                             encrypt, nullptr)) {
    return -1;
  }

  if (!encrypt) {
    return GetTestConfig(ssl)->renew_ticket ? 2 : 1;
  }
  return 1;
}

static int NewSessionCallback(SSL *ssl, SSL_SESSION *session) {
  // This callback is called whenever a new session has been negotiated and
  // session caching is enabled. This is different from BoringSSL, since
  // their callback is called as the handshake completes.
  if (SSL_get_session(ssl) == nullptr) {
    fprintf(stderr, "Invalid state for NewSessionCallback.\n");
    abort();
  }

  GetTestState(ssl)->got_new_session = true;
  // Create a duplicate of the session to prevent SSL_CTX_free resetting the
  // resumable flag to false
  GetTestState(ssl)->new_session.reset(SSL_SESSION_dup(session));

  return 0;
}

static void InfoCallback(const SSL *ssl, int type, int val) {
  if (type == SSL_CB_HANDSHAKE_DONE) {
    if (GetTestConfig(ssl)->handshake_never_done) {
      fprintf(stderr, "Handshake unexpectedly completed.\n");
      // Abort before any expected error code is printed, to ensure the overall
      // test fails.
      abort();
    }

    // This callback is called when the handshake completes. |SSL_get_session|
    // must continue to work and |SSL_in_init| must return false.
    if (SSL_in_init(ssl) || SSL_get_session(ssl) == nullptr) {
      fprintf(stderr, "Invalid state for SSL_CB_HANDSHAKE_DONE.\n");
      abort();
    }

    TestState *test_state = GetTestState(ssl);
    test_state->handshake_done = true;
  }
}

static SSL_SESSION *GetSessionCallback(SSL *ssl, const uint8_t *data, int len,
                                       int *copy) {
  TestState *async_state = GetTestState(ssl);
  if (async_state->session) {
    *copy = 0;
    return async_state->session.release();
  }
  if (async_state->pending_session) {
    return async_state->pending_session.release();
  }
  return nullptr;
}

static int AlpnSelectCallback(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                              const uint8_t *in, unsigned inlen, void *arg) {
  if (GetTestState(ssl)->alpn_select_done) {
    fprintf(stderr, "AlpnSelectCallback called after completion.\n");
    exit(1);
  }

  GetTestState(ssl)->alpn_select_done = true;

  const TestConfig *config = GetTestConfig(ssl);
  if (config->decline_alpn) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  if (config->reject_alpn) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  if (!config->expect_advertised_alpn.empty() &&
      bssl::StringAsBytes(config->expect_advertised_alpn) !=
          bssl::Span(in, inlen)) {
    fprintf(stderr, "bad ALPN select callback inputs.\n");
    exit(1);
  }

  assert(config->select_alpn.empty() || !config->select_empty_alpn);
  *out = (const uint8_t *)config->select_alpn.data();
  *outlen = config->select_alpn.size();
  return SSL_TLSEXT_ERR_OK;
}

static bool CheckVerifyCallback(SSL *ssl) {
  // OCSP response not available here

  if (GetTestState(ssl)->cert_verified) {
    fprintf(stderr, "Certificate verified twice.\n");
    return false;
  }

  return true;
}

static int CertVerifyCallback(X509_STORE_CTX *store_ctx, void *arg) {
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(
      store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  const TestConfig *config = GetTestConfig(ssl);
  if (!CheckVerifyCallback(ssl)) {
    return 0;
  }

  GetTestState(ssl)->cert_verified = true;
  if (config->verify_fail) {
    X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
  }

  return 1;
}

bool LoadCertificate(bssl::UniquePtr<X509> *out_x509,
                     bssl::UniquePtr<STACK_OF(X509)> *out_chain,
                     const std::string &file) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file.c_str())) {
    return false;
  }

  out_x509->reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!*out_x509) {
    return false;
  }

  out_chain->reset(sk_X509_new_null());
  if (!*out_chain) {
    return false;
  }

  // Keep reading the certificate chain.
  for (;;) {
    bssl::UniquePtr<X509> cert(
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) {
      break;
    }

    if (!sk_X509_push(out_chain->get(), cert.release())) {
      return false;
    }
  }

  uint32_t err = ERR_peek_last_error();
  if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
      ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
    return false;
  }

  ERR_clear_error();
  return true;
}

bssl::UniquePtr<EVP_PKEY> LoadPrivateKey(const std::string &file) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file.c_str())) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(
      PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL));
}

static bool GetCertificate(SSL *ssl, bssl::UniquePtr<X509> *out_x509,
                           bssl::UniquePtr<STACK_OF(X509)> *out_chain,
                           bssl::UniquePtr<EVP_PKEY> *out_pkey) {
  const TestConfig *config = GetTestConfig(ssl);

  std::string sigalgs = kDefaultSignatureAlgorithmsSign;
  if (!config->signing_prefs.empty()) {
    auto list = GetSignatureAlgorithmList(config->signing_prefs);
    if (list->empty()) {
      return false;
    }
    sigalgs = list.value();
  }
  if (config->is_server) {
    if (!SSL_set1_sigalgs_list(ssl, sigalgs.c_str())) {
      fprintf(stderr, "Failed to set signature algorithms\n");
      return false;
    }
  } else {
    if (!SSL_set1_client_sigalgs_list(ssl, sigalgs.c_str())) {
      fprintf(stderr, "Failed to set client signature algorithms\n");
      return false;
    }
  }

  if (!config->key_file.empty()) {
    *out_pkey = LoadPrivateKey(config->key_file);
    if (!*out_pkey) {
      return false;
    }
  }
  if (!config->cert_file.empty() &&
      !LoadCertificate(out_x509, out_chain, config->cert_file)) {
    return false;
  }
  if (!config->ocsp_response.empty() && !config->set_ocsp_in_callback) {
    const size_t len = config->ocsp_response.size();
    auto *buf = static_cast<uint8_t *>(OPENSSL_malloc(len));
    if (buf == nullptr) {
      return false;
    }
    OPENSSL_memcpy(buf, config->ocsp_response.data(), len);
    if (!SSL_set_tlsext_status_ocsp_resp(ssl, buf, len)) {
      OPENSSL_free(buf);
      return false;
    }
  }
  return true;
}

static bool HexDecode(std::string *out, const std::string &in) {
  if ((in.size() & 1) != 0) {
    return false;
  }

  auto buf = std::make_unique<uint8_t[]>(in.size() / 2);
  for (size_t i = 0; i < in.size() / 2; i++) {
    uint8_t high, low;
    if (!OPENSSL_fromxdigit(&high, in[i * 2]) ||
        !OPENSSL_fromxdigit(&low, in[i * 2 + 1])) {
      return false;
    }
    buf[i] = (high << 4) | low;
  }

  out->assign(reinterpret_cast<const char *>(buf.get()), in.size() / 2);
  return true;
}

static std::vector<std::string> SplitParts(const std::string &in,
                                           const char delim) {
  std::vector<std::string> ret;
  size_t start = 0;

  for (size_t i = 0; i < in.size(); i++) {
    if (in[i] == delim) {
      ret.push_back(in.substr(start, i - start));
      start = i + 1;
    }
  }

  ret.push_back(in.substr(start, std::string::npos));
  return ret;
}

static std::vector<std::string> DecodeHexStrings(
    const std::string &hex_strings) {
  std::vector<std::string> ret;
  const std::vector<std::string> parts = SplitParts(hex_strings, ',');

  for (const auto &part : parts) {
    std::string binary;
    if (!HexDecode(&binary, part)) {
      fprintf(stderr, "Bad hex string: %s.\n", part.c_str());
      return ret;
    }

    ret.push_back(binary);
  }

  return ret;
}

static bssl::UniquePtr<STACK_OF(X509_NAME)> DecodeHexX509Names(
    const std::string &hex_names) {
  const std::vector<std::string> der_names = DecodeHexStrings(hex_names);
  bssl::UniquePtr<STACK_OF(X509_NAME)> ret(sk_X509_NAME_new_null());
  if (!ret) {
    return nullptr;
  }

  for (const auto &der_name : der_names) {
    const uint8_t *const data =
        reinterpret_cast<const uint8_t *>(der_name.data());
    const uint8_t *derp = data;
    bssl::UniquePtr<X509_NAME> name(
        d2i_X509_NAME(nullptr, &derp, der_name.size()));
    if (!name || derp != data + der_name.size()) {
      fprintf(stderr, "Failed to parse X509_NAME.\n");
      return nullptr;
    }

    if (!sk_X509_NAME_push(ret.get(), name.release())) {
      return nullptr;
    }
  }

  return ret;
}

static bool CheckCertificateRequest(SSL *ssl) {
  const TestConfig *config = GetTestConfig(ssl);

  if (!config->expect_certificate_types.empty()) {
    const uint8_t *certificate_types;
    size_t certificate_types_len =
        SSL_get0_certificate_types(ssl, &certificate_types);
    if (bssl::Span(config->expect_certificate_types) !=
        bssl::Span(certificate_types, certificate_types_len)) {
      fprintf(stderr, "certificate types mismatch.\n");
      return false;
    }
  }

  if (!config->expect_client_ca_list.empty()) {
    bssl::UniquePtr<STACK_OF(X509_NAME)> expected =
        DecodeHexX509Names(config->expect_client_ca_list);
    const size_t num_expected = sk_X509_NAME_num(expected.get());

    const STACK_OF(X509_NAME) *received = SSL_get_client_CA_list(ssl);
    const size_t num_received = sk_X509_NAME_num(received);

    if (num_received != num_expected) {
      fprintf(stderr, "expected %zu names in CertificateRequest but got %zu.\n",
              num_expected, num_received);
      return false;
    }

    for (size_t i = 0; i < num_received; i++) {
      if (X509_NAME_cmp(sk_X509_NAME_value(received, i),
                        sk_X509_NAME_value(expected.get(), i)) != 0) {
        fprintf(stderr, "names in CertificateRequest differ at index #%zu.\n",
                i);
        return false;
      }
    }
  }

  return true;
}

static int ClientCertCallback(SSL *ssl, X509 **out_x509, EVP_PKEY **out_pkey) {
  if (!CheckCertificateRequest(ssl)) {
    return -1;
  }

  if (GetTestConfig(ssl)->async && !GetTestState(ssl)->cert_ready) {
    return -1;
  }

  bssl::UniquePtr<X509> x509;
  bssl::UniquePtr<STACK_OF(X509)> chain;
  bssl::UniquePtr<EVP_PKEY> pkey;
  if (!GetCertificate(ssl, &x509, &chain, &pkey)) {
    return -1;
  }

  // Return zero for no certificate.
  if (!x509) {
    return 0;
  }

  // Chains and asynchronous private keys are not supported with client_cert_cb.
  *out_x509 = x509.release();
  *out_pkey = pkey.release();
  return 1;
}

static bool InstallCertificate(SSL *ssl) {
  bssl::UniquePtr<X509> x509;
  bssl::UniquePtr<STACK_OF(X509)> chain;
  bssl::UniquePtr<EVP_PKEY> pkey;
  if (!GetCertificate(ssl, &x509, &chain, &pkey)) {
    return false;
  }

  if (pkey && !SSL_use_PrivateKey(ssl, pkey.get())) {
    return false;
  }

  if (x509 && !SSL_use_certificate(ssl, x509.get())) {
    return false;
  }

  if (sk_X509_num(chain.get()) > 0 && !SSL_set1_chain(ssl, chain.get())) {
    return false;
  }

  return true;
}

void KeylogCallback(const SSL *ssl, const char *line) {
  const TestConfig *config = GetTestConfig(ssl);
  const bssl::UniquePtr<BIO> bio(BIO_new_file(config->shim_key_log_file.c_str(), "a"));
  BIO_printf(bio.get(), "%s\n", line);
}

/*
 * We match BoringSSL's cipher suites and signature algorithms here and
 * groups/curves in |NewSSL|. A number of tests verify the defaults, which is
 * in theory pretty useless for us.
 * However, some of the other tests in the suite (implicitly) assume certain
 * options to be available. A failing defaults-test can easily identify a
 * missing option, while it might be more difficult to debug a failing test
 * not directly related to defaults.
 */
bssl::UniquePtr<SSL_CTX> TestConfig::SetupCtx(SSL_CTX *old_ctx) const {
  bssl::UniquePtr<SSL_CTX> ssl_ctx(
      SSL_CTX_new(is_dtls ? DTLS_method() : TLS_method()));
  if (!ssl_ctx) {
    return nullptr;
  }

  // Enable TLS1.0, TLS1.1, DTLS1.0, 3DES
  SSL_CTX_set_security_level(ssl_ctx.get(), 0);

  // BoringSSL default cipher list
  const std::string kDefaultCipherList =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    ":ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    ":ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    ":ECDHE-RSA-AES128-SHA256"
    ":ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA"
    ":ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA"
    ":ECDHE-PSK-CHACHA20-POLY1305"
    ":ECDHE-PSK-AES128-CBC-SHA:ECDHE-PSK-AES256-CBC-SHA"
    ":AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
    ":PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA"
    ":AES128-GCM-SHA256:AES256-GCM-SHA384";

  std::string cipher_list = kDefaultCipherList;
  if (!cipher.empty()) {
    cipher_list = cipher;
    SSL_CTX_set_options(ssl_ctx.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);
  }
  if (!SSL_CTX_set_cipher_list(ssl_ctx.get(), cipher_list.c_str())) {
    return nullptr;
  }

  if (async && is_server) {
    // Disable the internal session cache. To test asynchronous session lookup,
    // we use an external session cache.
    SSL_CTX_set_session_cache_mode(
        ssl_ctx.get(), SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_get_cb(ssl_ctx.get(), GetSessionCallback);
  } else {
    SSL_CTX_set_session_cache_mode(ssl_ctx.get(), SSL_SESS_CACHE_BOTH);
  }

  if (use_old_client_cert_callback) {
    SSL_CTX_set_client_cert_cb(ssl_ctx.get(), ClientCertCallback);
  }

  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx.get(),
                                        NextProtosAdvertisedCallback, NULL);
  if (!select_next_proto.empty() || select_empty_next_proto) {
    SSL_CTX_set_next_proto_select_cb(ssl_ctx.get(), NextProtoSelectCallback,
                                     NULL);
  }

  if (!select_alpn.empty() || decline_alpn || reject_alpn ||
      select_empty_alpn) {
    SSL_CTX_set_alpn_select_cb(ssl_ctx.get(), AlpnSelectCallback, NULL);
  }

  SSL_CTX_set_info_callback(ssl_ctx.get(), InfoCallback);
  SSL_CTX_sess_set_new_cb(ssl_ctx.get(), NewSessionCallback);

  if (use_ticket_callback) {
    SSL_CTX_set_tlsext_ticket_key_evp_cb(ssl_ctx.get(), TicketKeyCallback);
  }

  constexpr unsigned char kSessionCtx[] = "ossl_shim";
  if (!SSL_CTX_set_session_id_context(ssl_ctx.get(),
                                      kSessionCtx,
                                      sizeof(kSessionCtx) - 1)) {
    return nullptr;
  }

  SSL_CTX_set_cert_verify_callback(ssl_ctx.get(), CertVerifyCallback, NULL);

  if (enable_signed_cert_timestamps &&
      !SSL_CTX_enable_ct(ssl_ctx.get(), SSL_CT_VALIDATION_STRICT)) {
    return nullptr;
  }

  if (!use_client_ca_list.empty()) {
    if (use_client_ca_list == "<NULL>") {
      SSL_CTX_set_client_CA_list(ssl_ctx.get(), nullptr);
    } else if (use_client_ca_list == "<EMPTY>") {
      bssl::UniquePtr<STACK_OF(X509_NAME)> names;
      SSL_CTX_set_client_CA_list(ssl_ctx.get(), names.release());
    } else {
      bssl::UniquePtr<STACK_OF(X509_NAME)> names =
          DecodeHexX509Names(use_client_ca_list);
      SSL_CTX_set_client_CA_list(ssl_ctx.get(), names.release());
    }
  }

  if (!expect_server_name.empty()) {
    SSL_CTX_set_tlsext_servername_callback(ssl_ctx.get(), ServerNameCallback);
  }

  // Trying to match the logic between BoringSSL and OpenSSL is a little
  // confusing. BoringSSL uses defaults for sign and verify (as do the tests),
  // while OpenSSL specifies sigalgs and client_sigalgs. The logic "swaps"
  // between client and server:
  // Client-Verify: list in Client hello (*_set1_sigalgs_list)
  // Server-Sign: selection for Server key exchange (*_set1_sigalgs_list)
  // Server-Verify: list in Certificate request (*_set1_client_sigalgs_list)
  // Client-Sign: selection for Certificate verify (*_set1_client_sigalgs_list)
  std::string sigalgs = kDefaultSignatureAlgorithmsVerify;
  if (!verify_prefs.empty()) {
    auto list = GetSignatureAlgorithmList(verify_prefs);
    if (list->empty()) {
      return nullptr;
    }
    sigalgs = list.value();
  }
  if (is_server) {
    if (!SSL_CTX_set1_client_sigalgs_list(ssl_ctx.get(), sigalgs.c_str())) {
      fprintf(stderr, "Failed to set client signature algorithms\n");
      return nullptr;
    }
  } else {
    if (!SSL_CTX_set1_sigalgs_list(ssl_ctx.get(), sigalgs.c_str())) {
      fprintf(stderr, "Failed to set signature algorithms\n");
      return nullptr;
    }
  }

  // Always set the callback. OCSP response is only sent when the callback
  // is set. We can still choose to set the response elsewhere (GetCertificate)
  SSL_CTX_set_tlsext_status_cb(ssl_ctx.get(), OCSPCallback);

  if (old_ctx) {
    const long len = SSL_CTX_get_tlsext_ticket_keys(old_ctx, nullptr, 0);
    std::vector<uint8_t> keys(len);

    if (!SSL_CTX_get_tlsext_ticket_keys(old_ctx, keys.data(), len) ||
        !SSL_CTX_set_tlsext_ticket_keys(ssl_ctx.get(), keys.data(), len)) {
      return nullptr;
    }
    CopySessions(ssl_ctx.get(), old_ctx);
  }

  if (server_preference) {
    SSL_CTX_set_options(ssl_ctx.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);
  }

  if (!shim_key_log_file.empty()) {
    SSL_CTX_set_keylog_callback(ssl_ctx.get(), KeylogCallback);
  }

  return ssl_ctx;
}

// The callback is called twice during the handshake. First when the client
// hello is written (state TLS_ST_CW_CLNT_HELLO). In that call the hint is
// always NULL.
// Second time is after receiving server key exchange, then the hint is passed.
// See https://docs.openssl.org/master/man3/SSL_CTX_set_psk_client_callback/
static unsigned PskClientCallback(SSL *ssl, const char *hint,
                                  char *out_identity, unsigned max_identity_len,
                                  uint8_t *out_psk, unsigned max_psk_len) {
  // Unable to validate hint
  if (SSL_get_state(ssl) == TLS_ST_CW_CLNT_HELLO) {
    return 0;
  }

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
    fprintf(stderr, "PSK buffers too small.\n");
    return 0;
  }

  OPENSSL_strlcpy(out_identity, config->psk_identity.c_str(), max_identity_len);
  OPENSSL_memcpy(out_psk, config->psk.data(), config->psk.size());
  return static_cast<unsigned>(config->psk.size());
}

static unsigned PskServerCallback(SSL *ssl, const char *identity,
                                  uint8_t *out_psk, unsigned max_psk_len) {
  const TestConfig *config = GetTestConfig(ssl);

  if (strcmp(identity, config->psk_identity.c_str()) != 0) {
    fprintf(stderr, "Client PSK identity did not match.\n");
    return 0;
  }

  if (config->psk.size() > max_psk_len) {
    fprintf(stderr, "PSK buffers too small.\n");
    return 0;
  }

  OPENSSL_memcpy(out_psk, config->psk.data(), config->psk.size());
  return static_cast<unsigned>(config->psk.size());
}

static int CertCallback(SSL *ssl, void *arg) {
  const TestConfig *config = GetTestConfig(ssl);

  // Check the peer certificate metadata is as expected.
  if ((!SSL_is_server(ssl) && !CheckCertificateRequest(ssl))) {
    return -1;
  }

  if (config->fail_cert_callback) {
    return 0;
  }

  // The certificate will be installed via other means.
  if (!config->async) {
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
    SSL_CTX *ssl_ctx, SSL_SESSION *session,
    std::unique_ptr<TestState> test_state) const {
  bssl::UniquePtr<SSL> ssl(SSL_new(ssl_ctx));
  if (!ssl) {
    return nullptr;
  }

  if (!SetTestConfig(ssl.get(), this)) {
    return nullptr;
  }
  if (test_state != nullptr) {
    if (!SetTestState(ssl.get(), std::move(test_state))) {
      return nullptr;
    }
  }

  if (fallback_scsv && !SSL_set_mode(ssl.get(), SSL_MODE_SEND_FALLBACK_SCSV)) {
    return nullptr;
  }
  // Install the certificate synchronously if nothing else will handle it.
  if (!use_old_client_cert_callback && !async &&
      !InstallCertificate(ssl.get())) {
    return nullptr;
  }
  if (!use_old_client_cert_callback) {
    SSL_set_cert_cb(ssl.get(), CertCallback, nullptr);
  }
  int mode = SSL_VERIFY_NONE;
  if (require_any_client_certificate) {
    mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }
  if (verify_peer) {
    mode = SSL_VERIFY_PEER;
  }
  if (mode != SSL_VERIFY_NONE) {
    SSL_set_verify(ssl.get(), mode, NULL);
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
  if (no_ticket) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TICKET);
    // SSL_OP_NO_TICKET doesn't block stateful tickets in TLS 1.3
    if (!SSL_set_num_tickets(ssl.get(), 0)) {
      return nullptr;
    }
  }
  if (!host_name.empty() &&
      !SSL_set_tlsext_host_name(ssl.get(), host_name.c_str())) {
    return nullptr;
  }
  if (!advertise_alpn.empty() &&
      SSL_set_alpn_protos(
          ssl.get(), reinterpret_cast<const uint8_t *>(advertise_alpn.data()),
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
      // 0 on success, 1 on error
      SSL_set_tlsext_use_srtp(ssl.get(), srtp_profiles.c_str())) {
    return nullptr;
  }
  if (enable_ocsp_stapling) {
    SSL_set_tlsext_status_type(ssl.get(), TLSEXT_STATUSTYPE_ocsp);
  }
  if (min_version != 0 && !SSL_set_min_proto_version(ssl.get(), min_version)) {
    return nullptr;
  }
  if (max_version != 0 && !SSL_set_max_proto_version(ssl.get(), max_version)) {
    return nullptr;
  }
  if (mtu != 0) {
    SSL_set_options(ssl.get(), SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(ssl.get(), mtu);
  }
  if (!renegotiate_freely) {
    // Default to no renegotiation
    SSL_set_options(ssl.get(), SSL_OP_NO_RENEGOTIATION);

    // When running as client, we always send the renegotiation (RI) extension
    // for TLS < 1.3. Allow the client to continue when the server doesn't
    // send the RI extension in the server hello.
    // This allows tests for empty server hello to pass
    SSL_set_options(ssl.get(), SSL_OP_LEGACY_SERVER_CONNECT);
  } else {
    // renegotiate_freely is always on for OpenSSL
    // Never resume after renegotiation
    SSL_set_options(ssl.get(), SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  }
  if (!check_close_notify) {
    SSL_set_quiet_shutdown(ssl.get(), 1);
  }
  // If not specified, use the default BoringSSL groups
  std::string groups = "*X25519:*secp256r1:secp384r1";
  if (!curves.empty()) {
    groups = "";
    for (int i = 0; i < curves.size(); ++i) {
      if (auto group = GetGroup(curves[i])) {
        if (i > 0) {
          groups.append(":");
        }
        // Mark for key share
        if (i == 0 || curves[i] == GROUP_ID_X25519MLKEM768) {
          groups.append("*");
        }

        groups.append(group.value().name);
      } else {
        fprintf(stderr, "Unknown curve %hu\n", curves[i]);
        return nullptr;
      }
    }
  }
  if (!SSL_set1_groups_list(ssl.get(), groups.c_str())) {
    return nullptr;
  }

  if (max_cert_list > 0) {
    SSL_set_max_cert_list(ssl.get(), max_cert_list);
  }
  if (session != nullptr) {
    if (!is_server) {
      if (SSL_set_session(ssl.get(), session) != 1) {
        return nullptr;
      }
    } else if (async) {
      // The internal session cache is disabled, so install the session
      // manually.
      SSL_SESSION_up_ref(session);
      GetTestState(ssl.get())->pending_session.reset(session);
    }
  }
  return ssl;
}
