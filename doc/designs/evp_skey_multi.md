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

As all the objects are derived in one transaction, we can store a single opaque
pointer keeping all the keys inside in the EVP_KDF_CTX object, and provide the
API for access to a particular object.

However, this will require extending the API on the libcrypto/libssl side and
complications on a provider side.

Model use case
--------------

TLS 1.2 and below requires simultaneous derivation of 2 IVs and 2 or 4 keys (2 for
ciphers and 2 for MACs).  IVs are public and can be accessed directly, keys are
returned as EVP_SKEY objects.

The API is designed from the perspective of being a transparent wrapper for
PKCS#11 mechanisms for simultaneous key generation and avoid the extra calls to
token API from the provider.

Libcrypto API
-------------

The initialization of EVP_KDF_CTX for simultaneous derivation is done via
call to `EVP_KDF_CTX_set_params`.

To derive the opaque keys and and bytes buffers, we use the function

```C
int EVP_KDF_derive_SKEYs(EVP_KDF_CTX *ctx, EVP_SKEYMGMT *mgmt,
                         const char **key_types, const size_t *keylengths, size_t keynum,
                         const size_t *ivlengths, size_t ivnum,
                         const char *propquery, const OSSL_PARAM params[]);
```

This function doesn't return the opaque objects directly but stores all of them
in the provider context (`algctx`) of the EVP_KDF_CTX object.

To access the individual EVP_SKEY values, we introduce the functions

```C
EVP_SKEY *EVP_KDF_CTX_get0_SKEY(EVP_KDF_CTX *ctx, const char *purpose);
EVP_SKEY *EVP_KDF_CTX_get1_SKEY(EVP_KDF_CTX *ctx, const char *purpose);
```

where the `purpose` argument is a documented name of the particular EVP_SKEY
purpose (e.g. "client_MAC_key", "server_CIPHER_key").

To access the particular IV, the proposed API is

```C
unsigned char *EVP_KDF_CTX_get0_IV(EVP_KDF_CTX *ctx, const char *purpose, size_t *pIVlen);
```

where the `purpose` argument is a documented name of the particular IV
purpose (e.g. "client_IV").

Provider API
------------

We extend the EVP_KDF structure with the following member functions:

```C
OSSL_CORE_MAKE_FUNC(int, kdf_derive_multi, (void *kctx,
                    const char **key_types, const size_t *keylengths, size_t keynum,
                    const size_t *ivlengths, size_t ivnum,
                    const OSSL_PARAM params[]))

OSSL_CORE_MAKE_FUNC(int, kdf_get_skey,
                    (void *kctx, void *skeydata, const char *purpose, bool incr_refcount))

OSSL_CORE_MAKE_FUNC(unsigned char *, kdf_get_iv,
                    (void *kctx, const char *purpose))

```
