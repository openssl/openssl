/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

#if !defined(OPENSSL_SYS_WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#else
#include <io.h>
OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <winsock2.h>
#include <ws2tcpip.h>
OPENSSL_MSVC_PRAGMA(warning(pop))

OPENSSL_MSVC_PRAGMA(comment(lib, "Ws2_32.lib"))
#endif

#include <inttypes.h>
#include <string.h>

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/internal.h>
#include <openssl/span.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
#include <vector>

#include "async_bio.h"
#include "handshake_util.h"
#include "packeted_bio.h"
#include "test_config.h"
#include "test_state.h"

#if !defined(OPENSSL_WINDOWS)
using Socket = int;
#define INVALID_SOCKET (-1)

static int closesocket(int sock) { return close(sock); }
static void PrintSocketError(const char *func) { perror(func); }
#else
using Socket = SOCKET;

static void PrintSocketError(const char *func) {
  int error = WSAGetLastError();
  char *buffer;
  DWORD len = FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0,
      reinterpret_cast<char *>(&buffer), 0, nullptr);
  std::string msg = "unknown error";
  if (len > 0) {
    msg.assign(buffer, len);
    while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n')) {
      msg.resize(msg.size() - 1);
    }
  }
  LocalFree(buffer);
  fprintf(stderr, "%s: %s (%d)\n", func, msg.c_str(), error);
}
#endif

class OwnedSocket {
 public:
  OwnedSocket() = default;
  explicit OwnedSocket(Socket sock) : sock_(sock) {}
  OwnedSocket(OwnedSocket &&other) { *this = std::move(other); }
  ~OwnedSocket() { reset(); }
  OwnedSocket &operator=(OwnedSocket &&other) {
    drain_on_close_ = other.drain_on_close_;
    reset(other.release());
    return *this;
  }

  bool is_valid() const { return sock_ != INVALID_SOCKET; }
  void set_drain_on_close(bool drain) { drain_on_close_ = drain; }

  void reset(Socket sock = INVALID_SOCKET) {
    if (is_valid()) {
      if (drain_on_close_) {
#if defined(OPENSSL_WINDOWS)
        shutdown(sock_, SD_SEND);
#else
        shutdown(sock_, SHUT_WR);
#endif
        while (true) {
          char buf[1024];
          if (recv(sock_, buf, sizeof(buf), 0) <= 0) {
            break;
          }
        }
      }
      closesocket(sock_);
    }

    drain_on_close_ = false;
    sock_ = sock;
  }

  Socket get() const { return sock_; }

  Socket release() {
    Socket sock = sock_;
    sock_ = INVALID_SOCKET;
    drain_on_close_ = false;
    return sock;
  }

 private:
  Socket sock_ = INVALID_SOCKET;
  bool drain_on_close_ = false;
};

static int Usage(const char *program) {
  fprintf(stderr, "Usage: %s [flags...]\n", program);
  return 1;
}

// Connect returns a new socket connected to the runner, or -1 on error.
static OwnedSocket Connect(const TestConfig *config) {
  sockaddr_storage addr;
  socklen_t addr_len = 0;
  if (config->ipv6) {
    sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(config->port);
    if (!inet_pton(AF_INET6, "::1", &sin6.sin6_addr)) {
      PrintSocketError("inet_pton");
      return OwnedSocket();
    }
    addr_len = sizeof(sin6);
    memcpy(&addr, &sin6, addr_len);
  } else {
    sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(config->port);
    if (!inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)) {
      PrintSocketError("inet_pton");
      return OwnedSocket();
    }
    addr_len = sizeof(sin);
    memcpy(&addr, &sin, addr_len);
  }

  OwnedSocket sock(socket(addr.ss_family, SOCK_STREAM, 0));
  if (!sock.is_valid()) {
    PrintSocketError("socket");
    return OwnedSocket();
  }
  int nodelay = 1;
  if (setsockopt(sock.get(), IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char *>(&nodelay),
                 sizeof(nodelay)) != 0) {
    PrintSocketError("setsockopt");
    return OwnedSocket();
  }

  if (connect(sock.get(), reinterpret_cast<const sockaddr *>(&addr),
              addr_len) != 0) {
    PrintSocketError("connect");
    return OwnedSocket();
  }

  return sock;
}

// DoRead reads from |ssl|, resolving any asynchronous operations. It returns
// the result value of the final |SSL_read| call.
static int DoRead(SSL *ssl, uint8_t *out, size_t max_out) {
  const TestConfig *config = GetTestConfig(ssl);
  int ret;
  do {
    ret = CheckIdempotentError("SSL_peek/SSL_read", ssl, [&]() -> int {
      return config->peek_then_read ? SSL_peek(ssl, out, max_out)
                                    : SSL_read(ssl, out, max_out);
    });
  } while (RetryAsync(ssl, ret));

  if (config->peek_then_read && ret > 0) {
    auto buf = std::make_unique<uint8_t[]>(static_cast<size_t>(ret));

    // SSL_peek should synchronously return the same data.
    int ret2 = SSL_peek(ssl, buf.get(), ret);
    if (ret2 != ret || memcmp(buf.get(), out, ret) != 0) {
      fprintf(stderr, "First and second SSL_peek did not match.\n");
      return -1;
    }

    // SSL_read should synchronously return the same data and consume it.
    ret2 = SSL_read(ssl, buf.get(), ret);
    if (ret2 != ret || memcmp(buf.get(), out, ret) != 0) {
      fprintf(stderr, "SSL_peek and SSL_read did not match.\n");
      return -1;
    }
  }

  return ret;
}

// WriteAll writes |in_len| bytes from |in| to |ssl|, resolving any asynchronous
// operations. It returns the result of the final |SSL_write| call.
static int WriteAll(SSL *ssl, const void *in_, size_t in_len) {
  const uint8_t *in = reinterpret_cast<const uint8_t *>(in_);
  int ret;
  do {
    ret = SSL_write(ssl, in, in_len);
    if (ret > 0) {
      in += ret;
      in_len -= ret;
    }
  } while (RetryAsync(ssl, ret) || (ret > 0 && in_len > 0));
  return ret;
}

// DoShutdown calls |SSL_shutdown|, resolving any asynchronous operations. It
// returns the result of the final |SSL_shutdown| call.
static int DoShutdown(SSL *ssl) {
  int ret;
  do {
    ret = SSL_shutdown(ssl);
  } while (RetryAsync(ssl, ret));
  return ret;
}

static uint16_t GetProtocolVersion(const SSL *ssl) {
  uint16_t version = SSL_version(ssl);
  if (!SSL_is_dtls(ssl)) {
    return version;
  }
  return 0x0201 + ~version;
}

/*
 * Is this |SSL| in early data?
 * This is a BoringSSL-only function, but used many times, so implement our
 * equivalent to keep things aligned.
 */
static bool SSL_in_early_data(SSL *ssl) {
  int state = SSL_get_state(ssl);
  return state == TLS_ST_EARLY_DATA || state == TLS_ST_PENDING_EARLY_DATA_END;
}

// CheckAuthProperties checks, after the initial handshake is completed or
// after a renegotiation, that authentication-related properties match |config|.
static bool CheckAuthProperties(SSL *ssl, bool is_resume,
                                const TestConfig *config) {
  // Runner checks response for initial and resumed session, but OCSP response
  // is not available in a resumed session. Therefor we skip this check
  // on resumption so we can still validate the initial request.
  if (!config->expect_ocsp_response.empty() && !is_resume) {
    const uint8_t *data;
    int len = SSL_get_tlsext_status_ocsp_resp(ssl, &data);
    if (len == -1 ||
      bssl::Span(config->expect_ocsp_response) != bssl::Span(data, len)) {
      fprintf(stderr, "OCSP response mismatch\n");
      return false;
    }
  }

  // Runner checks SCT list for initial and resumed session, but SCTs are
  // not available in a resumed session. Therefor we skip this check
  // on resumption so we can still validate the initial request.
  if (!config->expect_signed_cert_timestamps.empty() && !is_resume) {
    const STACK_OF(SCT) *scts = SSL_get0_peer_scts(ssl);
    if (scts == nullptr) {
      fprintf(stderr, "SCT list mismatch\n");
      return false;
    }

    unsigned char *data = nullptr;
    size_t len = i2o_SCT_LIST(scts, &data);
    bool sct_verify_result = bssl::Span(config->expect_signed_cert_timestamps)
                             == bssl::Span(data, len);
    OPENSSL_free(data);
    if (!sct_verify_result) {
      fprintf(stderr, "SCT list mismatch\n");
      return false;
    }
  }

  if (config->expect_verify_result) {
    int expected_verify_result =
        config->verify_fail ? X509_V_ERR_APPLICATION_VERIFICATION : X509_V_OK;

    if (SSL_get_verify_result(ssl) != expected_verify_result) {
      fprintf(stderr, "Wrong certificate verification result\n");
      return false;
    }
  }

  if (!config->expect_peer_cert_file.empty()) {
    bssl::UniquePtr<X509> expect_leaf;
    bssl::UniquePtr<STACK_OF(X509)> expect_chain;
    if (!LoadCertificate(&expect_leaf, &expect_chain,
                         config->expect_peer_cert_file)) {
      return false;
    }

    // For historical reasons, clients report a chain with a leaf and servers
    // without.
    if (!config->is_server) {
      if (!sk_X509_insert(expect_chain.get(), expect_leaf.get(), 0)) {
        return false;
      }
      X509_up_ref(expect_leaf.get());  // sk_X509_insert takes ownership.
    }

    bssl::UniquePtr<X509> leaf(SSL_get_peer_certificate(ssl));
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if (X509_cmp(leaf.get(), expect_leaf.get()) != 0) {
      fprintf(stderr, "Received a different leaf certificate than expected.\n");
      return false;
    }

    if (sk_X509_num(chain) != sk_X509_num(expect_chain.get())) {
      fprintf(stderr, "Received a chain of length %d instead of %d.\n",
              sk_X509_num(chain), sk_X509_num(expect_chain.get()));
      return false;
    }

    for (size_t i = 0; i < sk_X509_num(chain); i++) {
      if (X509_cmp(sk_X509_value(chain, i),
                   sk_X509_value(expect_chain.get(), i)) != 0) {
        fprintf(stderr, "Chain certificate %zu did not match.\n", i + 1);
        return false;
      }
    }
  }

  return true;
}

// CheckHandshakeProperties checks, immediately after |ssl| completes its
// initial handshake (or False Starts), whether all the properties are
// consistent with the test configuration and invariants.
static bool CheckHandshakeProperties(SSL *ssl, bool is_resume,
                                     const TestConfig *config) {
  TestState *state = GetTestState(ssl);
  if (!CheckAuthProperties(ssl, is_resume, config)) {
    return false;
  }

  if (SSL_get_current_cipher(ssl) == nullptr) {
    fprintf(stderr, "null cipher after handshake\n");
    return false;
  }

  if (config->expect_version != 0 &&
      SSL_version(ssl) != int{config->expect_version}) {
    fprintf(stderr, "want version %04x, got %04x\n", config->expect_version,
            static_cast<uint16_t>(SSL_version(ssl)));
    return false;
  }

  bool expect_resume =
      is_resume && (!config->expect_session_miss || SSL_in_early_data(ssl));
  if (!!SSL_session_reused(ssl) != expect_resume) {
    fprintf(stderr, "session unexpectedly was%s reused\n",
            SSL_session_reused(ssl) ? "" : " not");
    return false;
  }

  bool expect_handshake_done = !SSL_in_early_data(ssl);
  if (expect_handshake_done != state->handshake_done) {
    fprintf(stderr, "handshake was%s completed\n",
            state->handshake_done ? "" : " not");
    return false;
  }

  if (expect_handshake_done && !config->is_server) {
    bool expect_new_session =
        !config->expect_no_session &&
        (!SSL_session_reused(ssl) || config->expect_ticket_renewal) &&
        // Session tickets are sent post-handshake in TLS 1.3.
        GetProtocolVersion(ssl) < TLS1_3_VERSION;
    if (expect_new_session != state->got_new_session) {
      fprintf(stderr,
              "new session was%s cached, but we expected the opposite\n",
              state->got_new_session ? "" : " not");
      return false;
    }
  }

  if (!is_resume) {
    if (config->expect_session_id && !state->got_new_session) {
      fprintf(stderr, "session was not cached on the server.\n");
      return false;
    }
    if (config->expect_no_session_id && state->got_new_session) {
      fprintf(stderr, "session was unexpectedly cached on the server.\n");
      return false;
    }
  }

  if (!config->expect_server_name.empty()) {
    const char *server_name =
        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (server_name == nullptr || std::string(server_name) != config->expect_server_name) {
      fprintf(stderr, "servername mismatch (got %s; want %s)\n", server_name,
              config->expect_server_name.c_str());
      return false;
    }
  }

  if (!config->expect_next_proto.empty() || config->expect_no_next_proto) {
    const uint8_t *next_proto;
    unsigned next_proto_len;
    SSL_get0_next_proto_negotiated(ssl, &next_proto, &next_proto_len);
    if (bssl::StringAsBytes(config->expect_next_proto) !=
        bssl::Span(next_proto, next_proto_len)) {
      fprintf(stderr, "negotiated next proto mismatch\n");
      return false;
    }
  }

  // On the server, the protocol selected in the ALPN callback must be echoed
  // out of |SSL_get0_alpn_selected|. On the client, it should report what the
  // test expected.
  const std::string &expect_alpn =
      config->is_server ? config->select_alpn : config->expect_alpn;
  const uint8_t *alpn_proto;
  unsigned alpn_proto_len;
  SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_proto_len);
  if (bssl::StringAsBytes(expect_alpn) !=
      bssl::Span(alpn_proto, alpn_proto_len)) {
    fprintf(stderr, "negotiated alpn proto mismatch\n");
    return false;
  }

  if (config->expect_extended_master_secret && !SSL_get_extms_support(ssl)) {
    fprintf(stderr, "No EMS for connection when expected\n");
    return false;
  }

  // Peer signature algorithms are not available after resumption
  if (config->expect_peer_signature_algorithm != 0 && !is_resume) {
    const char *name;

    if (!SSL_get0_peer_signature_name(ssl, &name)) {
      fprintf(stderr, "Failed to retrieve peer signature algorithm name\n");
      return false;
    }

    auto expected =
        GetSignatureAlgorithm(config->expect_peer_signature_algorithm);
    if (expected.has_value()) {
      if (strcmp(expected.value().c_str(), name) != 0) {
        fprintf(stderr, "Peer signature algorithm was %s, wanted %s.\n",
                name, expected.value().c_str());
        return false;
      }
    } else {
      fprintf(stderr, "Expected peer signature algorithm unknown\n");
      return false;
    }
  }

  if (config->expect_curve_id != 0) {
    int curve_nid = SSL_get_negotiated_group(ssl);
    if (const auto group = GetGroup(config->expect_curve_id)) {
      if (group.value().nid != curve_nid) {
        fprintf(stderr, "curve_nid was %04x, wanted %04x\n", curve_nid,
                group.value().nid);
        return false;
      }
    } else {
      fprintf(stderr, "Expected curve unknown\n");
      return false;
    }
  }

  uint16_t cipher_id = SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl));
  if (config->expect_cipher != 0 && config->expect_cipher != cipher_id) {
    fprintf(stderr, "Cipher ID was %04x, wanted %04x\n", cipher_id,
            config->expect_cipher);
    return false;
  }

  if (!config->psk.empty()) {
    if (SSL_get_peer_cert_chain(ssl) != nullptr) {
      fprintf(stderr, "Received peer certificate on a PSK cipher.\n");
      return false;
    }
  } else if (!config->is_server || config->require_any_client_certificate) {
    if (SSL_get0_peer_certificate(ssl) == nullptr) {
      fprintf(stderr, "Received no peer certificate but expected one.\n");
      return false;
    }
  }

  return true;
}

static bool DoExchange(bssl::UniquePtr<SSL_SESSION> *out_session,
                       bssl::UniquePtr<SSL> *ssl_uniqueptr,
                       const TestConfig *config, bool is_resume, bool is_retry);

// DoConnection tests an SSL connection against the peer. On success, it returns
// true and sets |*out_session| to the negotiated SSL session. If the test is a
// resumption attempt, |is_resume| is true and |session| is the session from the
// previous exchange.
static bool DoConnection(bssl::UniquePtr<SSL_SESSION> *out_session,
                         SSL_CTX *ssl_ctx, const TestConfig *config,
                         const TestConfig *retry_config, bool is_resume,
                         SSL_SESSION *session) {
  bssl::UniquePtr<SSL> ssl =
      config->NewSSL(ssl_ctx, session, std::make_unique<TestState>());
  if (!ssl) {
    return false;
  }
  if (config->is_server) {
    SSL_set_accept_state(ssl.get());
  } else {
    SSL_set_connect_state(ssl.get());
  }

  OwnedSocket sock = Connect(config);
  if (!sock.is_valid()) {
    return false;
  }

  // Half-close and drain the socket before releasing it. This seems to be
  // necessary for graceful shutdown on Windows. It will also avoid write
  // failures in the test runner.
  sock.set_drain_on_close(true);

  // Windows uses |SOCKET| for socket types, but OpenSSL's API requires casting
  // them to |int|.
  bssl::UniquePtr<BIO> bio(
      BIO_new_socket(static_cast<int>(sock.get()), BIO_NOCLOSE));
  if (!bio) {
    return false;
  }

  uint8_t shim_id[8];
  CRYPTO_store_u64_le(shim_id, config->shim_id);
  if (BIO_write(bio.get(), shim_id, sizeof(shim_id)) != sizeof(shim_id)) {
    return false;
  }

  if (config->is_dtls) {
    bssl::UniquePtr<BIO> packeted = PacketedBioCreate(
        GetClock(),
        [ssl_raw = ssl.get()](timeval *out) -> bool {
          return DTLSv1_get_timeout(ssl_raw, out);
        },
        [ssl_raw = ssl.get()](uint32_t mtu) -> bool {
          return SSL_set_mtu(ssl_raw, mtu);
        });
    if (!packeted) {
      return false;
    }
    GetTestState(ssl.get())->packeted_bio = packeted.get();
    BIO_push(packeted.get(), bio.release());
    bio = std::move(packeted);
  }
  if (config->async) {
    bssl::UniquePtr<BIO> async_scoped =
        config->is_dtls ? AsyncBioCreateDatagram() : AsyncBioCreate();
    if (!async_scoped) {
      return false;
    }
    BIO_push(async_scoped.get(), bio.release());
    GetTestState(ssl.get())->async_bio = async_scoped.get();
    bio = std::move(async_scoped);
  }
  SSL_set_bio(ssl.get(), bio.get(), bio.get());
  bio.release();  // SSL_set_bio takes ownership.

  bool ret = DoExchange(out_session, &ssl, config, is_resume, false);

  if (!ret) {
    // Print the |SSL_get_error| code. Otherwise, some failures are silent and
    // hard to debug.
    int ssl_err = SSL_get_error(ssl.get(), -1);
    if (ssl_err != SSL_ERROR_NONE) {
      fprintf(stderr, "SSL error code: %d\n", ssl_err);
      if (ssl_err == SSL_ERROR_SYSCALL) {
        PrintSocketError("OS error");
      }
    }
    return false;
  }

  if (!GetTestState(ssl.get())->msg_callback_ok) {
    return false;
  }

  return true;
}

static bool DoExchange(bssl::UniquePtr<SSL_SESSION> *out_session,
                       bssl::UniquePtr<SSL> *ssl_uniqueptr,
                       const TestConfig *config, bool is_resume, bool is_retry) {
  int ret;
  SSL *ssl = ssl_uniqueptr->get();
  SSL_CTX *session_ctx = SSL_get_SSL_CTX(ssl);
  TestState *test_state = GetTestState(ssl);

  if (!config->implicit_handshake) {
    do {
      ret = CheckIdempotentError("SSL_do_handshake", ssl, [&]() -> int {
        return SSL_do_handshake(ssl);
      });
    } while (RetryAsync(ssl, ret));

    if (ret != 1 || !CheckHandshakeProperties(ssl, is_resume, config)) {
      return false;
    }

    CopySessions(session_ctx, SSL_get_SSL_CTX(ssl));

    // Reset the state to assert later that the callback isn't called in
    // renegotations.
    test_state->got_new_session = false;
  }

  if (config->export_keying_material > 0) {
    std::vector<uint8_t> result(
        static_cast<size_t>(config->export_keying_material));
    if (!SSL_export_keying_material(
            ssl, result.data(), result.size(), config->export_label.data(),
            config->export_label.size(),
            reinterpret_cast<const uint8_t *>(config->export_context.data()),
            config->export_context.size(), config->use_export_context)) {
      fprintf(stderr, "failed to export keying material\n");
      return false;
    }
    if (WriteAll(ssl, result.data(), result.size()) < 0) {
      return false;
    }
  }

  if (config->write_different_record_sizes) {
    if (config->is_dtls) {
      fprintf(stderr, "write_different_record_sizes not supported for DTLS\n");
      return false;
    }
    // This mode writes a number of different record sizes in an attempt to
    // trip up the CBC record splitting code.
    static const size_t kBufLen = 32769;
    auto buf = std::make_unique<uint8_t[]>(kBufLen);
    memset(buf.get(), 0x42, kBufLen);
    static const size_t kRecordSizes[] = {
        0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769};
    for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kRecordSizes); i++) {
      const size_t len = kRecordSizes[i];
      if (len > kBufLen) {
        fprintf(stderr, "Bad kRecordSizes value.\n");
        return false;
      }
      if (WriteAll(ssl, buf.get(), len) < 0) {
        return false;
      }
    }
  } else {
    static const char kInitialWrite[] = "hello";
    bool pending_initial_write = false;
    if (config->shim_writes_first) {
      if (WriteAll(ssl, kInitialWrite, strlen(kInitialWrite)) < 0) {
        return false;
      }
    }
    if (!config->shim_shuts_down) {
      for (;;) {
        if (config->key_update_before_read &&
            !SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)) {
          fprintf(stderr, "SSL_key_update failed.\n");
          return false;
        }

        // Read only 512 bytes at a time in TLS to ensure records may be
        // returned in multiple reads.
        size_t read_size = config->is_dtls ? 16384 : 512;
        if (config->read_size > 0) {
          read_size = config->read_size;
        }
        auto buf = std::make_unique<uint8_t[]>(read_size);

        int n = DoRead(ssl, buf.get(), read_size);
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN ||
            (n == 0 && err == SSL_ERROR_SYSCALL)) {
          if (n != 0) {
            fprintf(stderr, "Invalid SSL_get_error output\n");
            return false;
          }
          // Stop on either clean or unclean shutdown.
          break;
        } else if (err != SSL_ERROR_NONE) {
          if (n > 0) {
            fprintf(stderr, "Invalid SSL_get_error output\n");
            return false;
          }
          return false;
        }
        // Successfully read data.
        if (n <= 0) {
          fprintf(stderr, "Invalid SSL_get_error output\n");
          return false;
        }

        // After a successful read, with or without False Start, the handshake
        // must be complete unless we are doing early data.
        if (!test_state->handshake_done && SSL_get_early_data_status(ssl)
                                           != SSL_EARLY_DATA_ACCEPTED) {
          fprintf(stderr, "handshake was not completed after SSL_read\n");
          return false;
        }

        // Clear the initial write, if unfinished.
        if (pending_initial_write) {
          if (WriteAll(ssl, kInitialWrite, strlen(kInitialWrite)) < 0) {
            return false;
          }
          pending_initial_write = false;
        }

        if (config->key_update &&
            !SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED)) {
          fprintf(stderr, "SSL_key_update failed.\n");
          return false;
        }

        for (int i = 0; i < n; i++) {
          buf[i] ^= 0xff;
        }
        if (WriteAll(ssl, buf.get(), n) < 0) {
          return false;
        }
      }
    }
  }

  if (!config->is_server && !config->implicit_handshake &&
      // Session tickets are sent post-handshake in TLS 1.3.
      GetProtocolVersion(ssl) < TLS1_3_VERSION && test_state->got_new_session) {
    fprintf(stderr, "new session was established after the handshake\n");
    return false;
  }

  if (GetProtocolVersion(ssl) >= TLS1_3_VERSION && !config->is_server) {
    bool expect_new_session =
        !config->expect_no_session && !config->shim_shuts_down;
    if (expect_new_session != test_state->got_new_session) {
      fprintf(stderr,
              "new session was%s cached, but we expected the opposite\n",
              test_state->got_new_session ? "" : " not");
      return false;
    }
  }

  if (out_session) {
    *out_session = std::move(test_state->new_session);
  }

  ret = DoShutdown(ssl);

  if (config->shim_shuts_down && config->check_close_notify) {
    // We initiate shutdown, so |SSL_shutdown| will return in two stages. First
    // it returns zero when our close_notify is sent, then one when the peer's
    // is received.
    if (ret != 0) {
      fprintf(stderr, "Unexpected SSL_shutdown result: %d != 0\n", ret);
      return false;
    }
    ret = DoShutdown(ssl);
  }

  if (ret != 1) {
    fprintf(stderr, "Unexpected SSL_shutdown result: %d != 1\n", ret);
    return false;
  }

  if (SSL_total_renegotiations(ssl) > 0) {
    if (SSL_SESSION_is_resumable(SSL_get_session(ssl))) {
      fprintf(stderr,
              "Renegotiations should never produce resumable sessions.\n");
      return false;
    }

    if (SSL_session_reused(ssl)) {
      fprintf(stderr, "Renegotiations should never resume sessions.\n");
      return false;
    }

    // Re-check authentication properties after a renegotiation. The reported
    // values should remain unchanged even if the server sent different SCT
    // lists.
    if (!CheckAuthProperties(ssl, is_resume, config)) {
      return false;
    }
  }

  if (SSL_total_renegotiations(ssl) != config->expect_total_renegotiations) {
    fprintf(stderr, "Expected %d renegotiations, got %ld\n",
            config->expect_total_renegotiations, SSL_total_renegotiations(ssl));
    return false;
  }

  return true;
}

class StderrDelimiter {
 public:
  ~StderrDelimiter() { fprintf(stderr, "--- DONE ---\n"); }
};

int main(int argc, char **argv) {
  // To distinguish ASan's output from ours, add a trailing message to stderr.
  // Anything following this line will be considered an error.
  StderrDelimiter delimiter;

#if defined(OPENSSL_WINDOWS)
  // Initialize Winsock.
  WORD wsa_version = MAKEWORD(2, 2);
  WSADATA wsa_data;
  int wsa_err = WSAStartup(wsa_version, &wsa_data);
  if (wsa_err != 0) {
    fprintf(stderr, "WSAStartup failed: %d\n", wsa_err);
    return 1;
  }
  if (wsa_data.wVersion != wsa_version) {
    fprintf(stderr, "Didn't get expected version: %x\n", wsa_data.wVersion);
    return 1;
  }
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  TestConfig initial_config, resume_config, retry_config;
  if (!ParseConfig(argc - 1, argv + 1, /*is_shim=*/true, &initial_config,
                   &resume_config, &retry_config)) {
    return Usage(argv[0]);
  }

  if (initial_config.is_handshaker_supported) {
    printf("No\n");
    return 0;
  }

  if (initial_config.wait_for_debugger) {
#if defined(OPENSSL_WINDOWS)
    fprintf(stderr, "-wait-for-debugger is not supported on Windows.\n");
    return 1;
#else
#if defined(OPENSSL_LINUX)
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
#endif
    // The debugger will resume the process.
    raise(SIGSTOP);
#endif
  }

  bssl::UniquePtr<SSL_CTX> ssl_ctx;
  bssl::UniquePtr<SSL_SESSION> session;
  for (int i = 0; i < initial_config.resume_count + 1; i++) {
    bool is_resume = i > 0;
    TestConfig *config = is_resume ? &resume_config : &initial_config;
    ssl_ctx = config->SetupCtx(ssl_ctx.get());
    if (!ssl_ctx) {
      ERR_print_errors_fp(stderr);
      return 1;
    }

    if (is_resume && !initial_config.is_server && !session) {
      fprintf(stderr, "No session to offer.\n");
      return 1;
    }

    bssl::UniquePtr<SSL_SESSION> offer_session = std::move(session);
    bool ok = DoConnection(&session, ssl_ctx.get(), config, &retry_config,
                           is_resume, offer_session.get());
    if (!ok) {
      fprintf(stderr, "Connection %d failed.\n", i + 1);
      ERR_print_errors_fp(stderr);
      return 1;
    }
  }

  return 0;
}

