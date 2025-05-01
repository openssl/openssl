/*
 * Copyright 1998-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_SHIM_INCLUDE_OPENSSL_BASE_H
#define OSSL_TEST_SHIM_INCLUDE_OPENSSL_BASE_H

/* Needed for BORINGSSL_MAKE_DELETER */
# include <openssl/bio.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/ssl.h>

# define OPENSSL_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

// BSSL_CHECK aborts if |condition| is not true.
#define BSSL_CHECK(condition) \
  do {                        \
    if (!(condition)) {       \
      abort();                \
    }                         \
  } while (0);

extern "C++" {

#include <memory>

namespace bssl {

namespace internal {

// The Enable parameter is ignored and only exists so specializations can use
// SFINAE.
template <typename T, typename Enable = void>
struct DeleterImpl {};

struct Deleter {
template <typename T>
void operator()(T *ptr) {
  // Rather than specialize Deleter for each type, we specialize
  // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
  // including base.h as long as the destructor is not emitted. This matches
  // std::unique_ptr's behavior on forward-declared types.
  //
  // DeleterImpl itself is specialized in the corresponding module's header
  // and must be included to release an object. If not included, the compiler
  // will error that DeleterImpl<T> does not have a method Free.
  DeleterImpl<T>::Free(ptr);
}
};

template <typename T, typename CleanupRet, void (*init)(T *),
          CleanupRet (*cleanup)(T *)>
class StackAllocated {
 public:
  StackAllocated() { init(&ctx_); }
  ~StackAllocated() { cleanup(&ctx_); }

  StackAllocated(const StackAllocated &) = delete;
  StackAllocated &operator=(const StackAllocated &) = delete;

  T *get() { return &ctx_; }
  const T *get() const { return &ctx_; }

  T *operator->() { return &ctx_; }
  const T *operator->() const { return &ctx_; }

  void Reset() {
    cleanup(&ctx_);
    init(&ctx_);
  }

 private:
  T ctx_;
};

}  // namespace internal

#define BORINGSSL_MAKE_DELETER(type, deleter)     \
  namespace internal {                            \
  template <>                                     \
  struct DeleterImpl<type> {                      \
    static void Free(type *ptr) { deleter(ptr); } \
  };                                              \
  }

// This makes a unique_ptr to STACK_OF(type) that owns all elements on the
// stack, i.e. it uses sk_pop_free() to clean up.
#define BORINGSSL_MAKE_STACK_DELETER(type, deleter) \
  namespace internal {                              \
  template <>                                       \
  struct DeleterImpl<STACK_OF(type)> {              \
    static void Free(STACK_OF(type) *ptr) {         \
      sk_##type##_pop_free(ptr, deleter);           \
    }                                               \
  };                                                \
  }

// Holds ownership of heap-allocated BoringSSL structures. Sample usage:
//   bssl::UniquePtr<RSA> rsa(RSA_new());
//   bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
template <typename T>
using UniquePtr = std::unique_ptr<T, internal::Deleter>;

BORINGSSL_MAKE_DELETER(BIO, BIO_free)
BORINGSSL_MAKE_DELETER(EVP_ENCODE_CTX, EVP_ENCODE_CTX_free)
BORINGSSL_MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)
BORINGSSL_MAKE_DELETER(SSL, SSL_free)
BORINGSSL_MAKE_DELETER(SSL_CTX, SSL_CTX_free)
BORINGSSL_MAKE_DELETER(SSL_SESSION, SSL_SESSION_free)
BORINGSSL_MAKE_DELETER(X509, X509_free)
BORINGSSL_MAKE_STACK_DELETER(X509, X509_free)

}  // namespace bssl

}  /* extern C++ */


#endif  /* OSSL_TEST_SHIM_INCLUDE_OPENSSL_BASE_H */
