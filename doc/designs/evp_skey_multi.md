Simultaneous derivation of several EVP_SKEY objects
===================================================

There are situations where we need to derive several symmetric keys
simultaneously.  The most relevant one for OpenSSL is TLS protocol, when we
need to derive 2-4 keys, depending on the protocol version. With raw bytes
buffer, the approach was to derive a combined buffer of the necessary length
and chop it. It doesn't work this way for EVP_SKEY objects.

This document proposes API and a general approach to deal with such situations.

Proposed API to derive an EVP_SKEY objects
------------------------------------------

The API is designed from the perspective of being a transparent wrapper for
PKCS#11 mechanisms for simultaneous key generation.

Proposed function

```C
STACK_OF(EVP_SKEY *) *EVP_KDF_derive_SKEYs(EVP_KDF_CTX *ctx, EVP_SKEYMGMT *mgmt,
                                           const char *propquery, const OSSL_PARAM params[]);
```

is similar to the existing one

```C
EVP_SKEY *EVP_KDF_derive_SKEY(EVP_KDF_CTX *ctx, EVP_SKEYMGMT *mgmt,
                              const char *key_type, const char *propquery,
                              size_t keylen, const OSSL_PARAM params[]);
```

The new function returns a pointer to a stack of EVP_SKEY objects. The order of
objects in the stack is specific for a particular KDF and is documented. The
amount of objects in stack can be different depending on purpose.

TLS mechanisms
--------------

In case of TLS protocol IVs should also be returned as EVP_SKEY objects for API
clarity.  It means that we either need to extend EVP_CIPHER API to accept
EVP_SKEY objects for IV or ensure that IV bytes are always exportable.

