/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif

#include "packeted_bio.h"
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

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
#include <vector>

#include "async_bio.h"
#include "handshake_util.h"
#include "test_config.h"
#include "test_state.h"

namespace bssl {

#if !defined(OPENSSL_SYS_WINDOWS)
static int closesocket(int sock) {
  return close(sock);
}

static void PrintSocketError(const char *func) {
  perror(func);
}
#else
static void PrintSocketError(const char *func) {
  fprintf(stderr, "%s: %d\n", func, WSAGetLastError());
}
#endif

static int Usage(const char *program) {
  fprintf(stderr, "Usage: %s [flags...]\n", program);
  return 1;
}

template<typename T>
struct Free {
  void operator()(T *buf) {
    free(buf);
  }
};

// Connect returns a new socket connected to localhost on |port| or -1 on
// error.
static int Connect(uint16_t port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    PrintSocketError("socket");
    return -1;
  }
  int nodelay = 1;
  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
          reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) != 0) {
    PrintSocketError("setsockopt");
    closesocket(sock);
    return -1;
  }
  sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  if (!inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)) {
    PrintSocketError("inet_pton");
    closesocket(sock);
    return -1;
  }
  if (connect(sock, reinterpret_cast<const sockaddr*>(&sin),
              sizeof(sin)) != 0) {
    PrintSocketError("connect");
    closesocket(sock);
    return -1;
  }
  return sock;
}

class SocketCloser {
 public:
  explicit SocketCloser(int sock) : sock_(sock) {}
  ~SocketCloser() {
    // Half-close and drain the socket before releasing it. This seems to be
    // necessary for graceful shutdown on Windows. It will also avoid write
    // failures in the test runner.
#if defined(OPENSSL_SYS_WINDOWS)
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
    closesocket(sock_);
  }

 private:
  const int sock_;
};

// DoRead reads from |ssl|, resolving any asynchronous operations. It returns
// the result value of the final |SSL_read| call.
static int DoRead(SSL *ssl, uint8_t *out, size_t max_out) {
  const TestConfig *config = GetTestConfig(ssl);
  TestState *test_state = GetTestState(ssl);
  int ret;
  do {
    ret = config->peek_then_read ? SSL_peek(ssl, out, max_out)
                                 : SSL_read(ssl, out, max_out);
  } while (config->async && RetryAsync(ssl, ret));

  if (config->peek_then_read && ret > 0) {
    std::unique_ptr<uint8_t[]> buf(new uint8_t[static_cast<size_t>(ret)]);

    // SSL_peek should synchronously return the same data.
    int ret2 = SSL_peek(ssl, buf.get(), ret);
    if (ret2 != ret ||
        memcmp(buf.get(), out, ret) != 0) {
      fprintf(stderr, "First and second SSL_peek did not match.\n");
      return -1;
    }

    // SSL_read should synchronously return the same data and consume it.
    ret2 = SSL_read(ssl, buf.get(), ret);
    if (ret2 != ret ||
        memcmp(buf.get(), out, ret) != 0) {
      fprintf(stderr, "SSL_peek and SSL_read did not match.\n");
      return -1;
    }
  }

  return ret;
}

// WriteAll writes |in_len| bytes from |in| to |ssl|, resolving any asynchronous
// operations. It returns the result of the final |SSL_write| call.
static int WriteAll(SSL *ssl, const uint8_t *in, size_t in_len) {
  const TestConfig *config = GetTestConfig(ssl);
  int ret;
  do {
    ret = SSL_write(ssl, in, in_len);
    if (ret > 0) {
      in += ret;
      in_len -= ret;
    }
  } while ((config->async && RetryAsync(ssl, ret)) || (ret > 0 && in_len > 0));
  return ret;
}

// DoShutdown calls |SSL_shutdown|, resolving any asynchronous operations. It
// returns the result of the final |SSL_shutdown| call.
static int DoShutdown(SSL *ssl) {
  const TestConfig *config = GetTestConfig(ssl);
  int ret;
  do {
    ret = SSL_shutdown(ssl);
  } while (config->async && RetryAsync(ssl, ret));
  return ret;
}

static uint16_t GetProtocolVersion(const SSL *ssl) {
  uint16_t version = SSL_version(ssl);
  if (!SSL_is_dtls(ssl)) {
    return version;
  }
  return 0x0201 + ~version;
}

// CheckHandshakeProperties checks, immediately after |ssl| completes its
// initial handshake (or False Starts), whether all the properties are
// consistent with the test configuration and invariants.
static bool CheckHandshakeProperties(SSL *ssl, bool is_resume) {
  const TestConfig *config = GetTestConfig(ssl);

  if (SSL_get_current_cipher(ssl) == nullptr) {
    fprintf(stderr, "null cipher after handshake\n");
    return false;
  }

  if (is_resume &&
      (!!SSL_session_reused(ssl) == config->expect_session_miss)) {
    fprintf(stderr, "session was%s reused\n",
            SSL_session_reused(ssl) ? "" : " not");
    return false;
  }

  if (!GetTestState(ssl)->handshake_done) {
    fprintf(stderr, "handshake was not completed\n");
    return false;
  }

  if (!config->is_server) {
    bool expect_new_session =
        !config->expect_no_session &&
        (!SSL_session_reused(ssl) || config->expect_ticket_renewal) &&
        // Session tickets are sent post-handshake in TLS 1.3.
        GetProtocolVersion(ssl) < TLS1_3_VERSION;
    if (expect_new_session != GetTestState(ssl)->got_new_session) {
      fprintf(stderr,
              "new session was%s cached, but we expected the opposite\n",
              GetTestState(ssl)->got_new_session ? "" : " not");
      return false;
    }
  }

  if (!config->expect_server_name.empty()) {
    const char *server_name =
        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (server_name == nullptr ||
            std::string(server_name) != config->expect_server_name) {
      fprintf(stderr, "servername mismatch (got %s; want %s)\n",
              server_name, config->expect_server_name.c_str());
      return false;
    }
  }

  if (!config->expect_next_proto.empty()) {
    const uint8_t *next_proto;
    unsigned next_proto_len;
    SSL_get0_next_proto_negotiated(ssl, &next_proto, &next_proto_len);
    if (next_proto_len != config->expect_next_proto.size() ||
        memcmp(next_proto, config->expect_next_proto.data(),
               next_proto_len) != 0) {
      fprintf(stderr, "negotiated next proto mismatch\n");
      return false;
    }
  }

  if (!config->expect_alpn.empty()) {
    const uint8_t *alpn_proto;
    unsigned alpn_proto_len;
    SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_proto_len);
    if (alpn_proto_len != config->expect_alpn.size() ||
        memcmp(alpn_proto, config->expect_alpn.data(),
               alpn_proto_len) != 0) {
      fprintf(stderr, "negotiated alpn proto mismatch\n");
      return false;
    }
  }

  if (config->expect_extended_master_secret) {
    if (!SSL_get_extms_support(ssl)) {
      fprintf(stderr, "No EMS for connection when expected");
      return false;
    }
  }

  if (config->expect_verify_result) {
    int expected_verify_result = config->verify_fail ?
      X509_V_ERR_APPLICATION_VERIFICATION :
      X509_V_OK;

    if (SSL_get_verify_result(ssl) != expected_verify_result) {
      fprintf(stderr, "Wrong certificate verification result\n");
      return false;
    }
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

// DoExchange runs a test SSL exchange against the peer. On success, it returns
// true and sets |*out_session| to the negotiated SSL session. If the test is a
// resumption attempt, |is_resume| is true and |session| is the session from the
// previous exchange.
static bool DoExchange(bssl::UniquePtr<SSL_SESSION> *out_session,
                       SSL_CTX *ssl_ctx, const TestConfig *config,
                       bool is_resume, SSL_SESSION *session) {
  bssl::UniquePtr<SSL> ssl =
      config->NewSSL(ssl_ctx, session, std::make_unique<TestState>());
  if (!ssl) {
    return false;
  }

  int sock = Connect(config->port);
  if (sock == -1) {
    return false;
  }
  SocketCloser closer(sock);

  bssl::UniquePtr<BIO> bio(BIO_new_socket(sock, BIO_NOCLOSE));
  if (!bio) {
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

  if (session != NULL) {
    if (!config->is_server) {
      if (SSL_set_session(ssl.get(), session) != 1) {
        return false;
      }
    }
  }

#if 0
  // KNOWN BUG: OpenSSL's SSL_get_current_cipher behaves incorrectly when
  // offering resumption.
  if (SSL_get_current_cipher(ssl.get()) != nullptr) {
    fprintf(stderr, "non-null cipher before handshake\n");
    return false;
  }
#endif

  int ret;
  if (config->implicit_handshake) {
    if (config->is_server) {
      SSL_set_accept_state(ssl.get());
    } else {
      SSL_set_connect_state(ssl.get());
    }
  } else {
    do {
      if (config->is_server) {
        ret = SSL_accept(ssl.get());
      } else {
        ret = SSL_connect(ssl.get());
      }
    } while (config->async && RetryAsync(ssl.get(), ret));
    if (ret != 1 ||
        !CheckHandshakeProperties(ssl.get(), is_resume)) {
      fprintf(stderr, "resumption check failed\n");
      return false;
    }

    // Reset the state to assert later that the callback isn't called in
    // renegotiations.
    GetTestState(ssl.get())->got_new_session = false;
  }

  if (config->export_keying_material > 0) {
    std::vector<uint8_t> result(
        static_cast<size_t>(config->export_keying_material));
    if (SSL_export_keying_material(
            ssl.get(), result.data(), result.size(),
            config->export_label.data(), config->export_label.size(),
            reinterpret_cast<const uint8_t*>(config->export_context.data()),
            config->export_context.size(), config->use_export_context) != 1) {
      fprintf(stderr, "failed to export keying material\n");
      return false;
    }
    if (WriteAll(ssl.get(), result.data(), result.size()) < 0) {
      fprintf(stderr, "writing exported key material failed\n");
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
    std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufLen]);
    memset(buf.get(), 0x42, kBufLen);
    static const size_t kRecordSizes[] = {
        0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769};
    for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kRecordSizes); i++) {
      const size_t len = kRecordSizes[i];
      if (len > kBufLen) {
        fprintf(stderr, "Bad kRecordSizes value.\n");
        return false;
      }
      if (WriteAll(ssl.get(), buf.get(), len) < 0) {
        return false;
      }
    }
  } else {
    if (config->shim_writes_first) {
      if (WriteAll(ssl.get(), reinterpret_cast<const uint8_t *>("hello"),
                   5) < 0) {
        fprintf(stderr, "shim_writes_first write failed\n");
        return false;
      }
    }
    if (!config->shim_shuts_down) {
      for (;;) {
        static const size_t kBufLen = 16384;
        std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufLen]);

        // Read only 512 bytes at a time in TLS to ensure records may be
        // returned in multiple reads.
        int n = DoRead(ssl.get(), buf.get(), config->is_dtls ? kBufLen : 512);
        int err = SSL_get_error(ssl.get(), n);
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
          fprintf(stderr, "Unexpected entry in error queue\n");
          return false;
        }
        // Successfully read data.
        if (n <= 0) {
          fprintf(stderr, "Invalid SSL_get_error output\n");
          return false;
        }

        // After a successful read, with or without False Start, the handshake
        // must be complete.
        if (!GetTestState(ssl.get())->handshake_done) {
          fprintf(stderr, "handshake was not completed after SSL_read\n");
          return false;
        }

        for (int i = 0; i < n; i++) {
          buf[i] ^= 0xff;
        }
        if (WriteAll(ssl.get(), buf.get(), n) < 0) {
          fprintf(stderr, "write of inverted bitstream failed\n");
          return false;
        }
      }
    }
  }

  if (!config->is_server &&
      !config->implicit_handshake &&
      // Session tickets are sent post-handshake in TLS 1.3.
      GetProtocolVersion(ssl.get()) < TLS1_3_VERSION &&
      GetTestState(ssl.get())->got_new_session) {
    fprintf(stderr, "new session was established after the handshake\n");
    return false;
  }

  if (GetProtocolVersion(ssl.get()) >= TLS1_3_VERSION && !config->is_server) {
    bool expect_new_session =
        !config->expect_no_session && !config->shim_shuts_down;
    if (expect_new_session != GetTestState(ssl.get())->got_new_session) {
      fprintf(stderr,
              "new session was%s cached, but we expected the opposite\n",
              GetTestState(ssl.get())->got_new_session ? "" : " not");
      return false;
    }
  }

  if (out_session) {
    *out_session = std::move(GetTestState(ssl.get())->new_session);
  }

  ret = DoShutdown(ssl.get());

  if (config->shim_shuts_down && config->check_close_notify) {
    // We initiate shutdown, so |SSL_shutdown| will return in two stages. First
    // it returns zero when our close_notify is sent, then one when the peer's
    // is received.
    if (ret != 0) {
      fprintf(stderr, "Unexpected SSL_shutdown result: %d != 0\n", ret);
      return false;
    }
    ret = DoShutdown(ssl.get());
  }

  if (ret != 1) {
    fprintf(stderr, "Unexpected SSL_shutdown result: %d != 1\n", ret);
    return false;
  }

  if (SSL_total_renegotiations(ssl.get()) !=
      config->expect_total_renegotiations) {
    fprintf(stderr, "Expected %d renegotiations, got %ld\n",
            config->expect_total_renegotiations,
            SSL_total_renegotiations(ssl.get()));
    return false;
  }

  return true;
}

class StderrDelimiter {
 public:
  ~StderrDelimiter() { fprintf(stderr, "--- DONE ---\n"); }
};

static int Main(int argc, char **argv) {
  // To distinguish ASan's output from ours, add a trailing message to stderr.
  // Anything following this line will be considered an error.
  StderrDelimiter delimiter;

#if defined(OPENSSL_SYS_WINDOWS)
  /* Initialize Winsock. */
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

  bssl::UniquePtr<SSL_CTX> ssl_ctx = initial_config.SetupCtx(nullptr);
  if (!ssl_ctx) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  bssl::UniquePtr<SSL_SESSION> session;
  for (int i = 0; i < initial_config.resume_count + 1; i++) {
    bool is_resume = i > 0;
    if (is_resume && !initial_config.is_server && !session) {
      fprintf(stderr, "No session to offer.\n");
      return 1;
    }

    bssl::UniquePtr<SSL_SESSION> offer_session = std::move(session);
    if (!DoExchange(&session, ssl_ctx.get(), &initial_config, is_resume,
                    offer_session.get())) {
      fprintf(stderr, "Connection %d failed.\n", i + 1);
      ERR_print_errors_fp(stderr);
      return 1;
    }
  }

  return 0;
}

}  // namespace bssl

int main(int argc, char **argv) {
  return bssl::Main(argc, argv);
}
