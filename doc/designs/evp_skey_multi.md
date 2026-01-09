Simultaneous derivation of several EVP_SKEY objects
===================================================

There are situations where we need to derive several symmetric keys
simultaneously.  The most relevant one for OpenSSL is TLS protocol, when we
need to derive 2-4 keys, depending on the protocol version. With raw bytes
buffer, the approach was to derive a combined buffer of the necessary length
and chop it. It doesn't work this way for EVP_SKEY objects.

This document proposes API and a general approach to deal with such situations.

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

As all the objects are derived in one transaction, we can store a single opaque
pointer keeping all the keys inside in the EVP_KDF_CTX object, and provide the
API for access to a particular object.

To derive the opaque keys and and bytes buffers, we use the function

```C
int EVP_KDF_derive_SKEYs(EVP_KDF_CTX *ctx, EVP_SKEYMGMT *mgmt,
                         const char *propquery, const OSSL_PARAM params[]);
```

This function doesn't directly return objects when this functions succeeds,
they are stored in the EVP_KDF_CTX object.

The options that define key types and sizes, number of keys or IVs and their
length can generally be specified by passing appropriate parameters in the
`params` argument. If no params are provided, defaults may be used by specific
KDF operations.

The params can also be set by a preceding call to `EVP_KDF_CTX_set_params`.

To access the individual EVP_SKEY values, we introduce the functions

```C
EVP_SKEY *EVP_KDF_CTX_get0_SKEY(EVP_KDF_CTX *ctx, const char *purpose);
EVP_SKEY *EVP_KDF_CTX_get1_SKEY(EVP_KDF_CTX *ctx, const char *purpose);
```

where the `purpose` argument is a name of the particular EVP_SKEY purpose (e.g.
"client_MAC_key", "server_CIPHER_key") as specified by the documentation of the
specific KDF operation that was executed.

To access an IV, the proposed API is

```C
int EVP_KDF_CTX_get0_IV(EVP_KDF_CTX *ctx, const char *purpose,
                        unsigned char **pIV, size_t *pIVlen);
```

where the `purpose` argument is a documented name of the particular IV purpose
(e.g. "client_IV") and `pIVlen` argument is a way to get the length of
generated IV.

Provider API
------------

We extend the EVP_KDF structure with the following member functions:

```C
OSSL_CORE_MAKE_FUNC(int, kdf_derive_multi, (void *kctx,
                    const OSSL_PARAM params[]))

OSSL_CORE_MAKE_FUNC(int, kdf_get_skey,
                    (void *kctx, void *skeydata, const char *purpose, bool incr_refcount))

OSSL_CORE_MAKE_FUNC(unsigned char *, kdf_get_iv,
                    (void *kctx, const char *purpose))

```

Providers may either imply some KDF-specific defaults when it's obvious from
the KDF specification or throw an error otherwise.
