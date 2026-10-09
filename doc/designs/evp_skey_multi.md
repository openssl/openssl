Simultaneous derivation of several EVP_SKEY objects
===================================================

There are situations where we need to derive several symmetric keys
simultaneously.  The most relevant one for OpenSSL is TLS protocol, when we
need to derive 2-4 keys, depending on the protocol version. With raw bytes
buffer, the approach was to derive a combined buffer of the necessary length
and chop it. It doesn't work this way for EVP_SKEY objects.

This document describes the API and the general approach used to deal with
such situations.

Model use case
--------------

TLS 1.2 and below requires simultaneous derivation of 2 IVs and 2 or 4 keys (2 for
ciphers and 2 for MACs).  IVs are public and can be accessed directly, keys are
returned as EVP_SKEY objects.

The API is designed from the perspective of being a transparent wrapper for
PKCS#11 mechanisms for simultaneous key generation and avoid the extra calls to
token API from the provider.

The shape of the API follows `CKM_TLS12_KEY_AND_MAC_DERIVE` closely.  Its
`CK_TLS12_KEY_MAT_PARAMS` carries three sizes -- `ulMacSizeInBits`,
`ulKeySizeInBits` and `ulIVSizeInBits` -- one per *kind* of output rather than
one per direction, and its `CK_SSL3_KEY_MAT_OUT` returns four key handles
alongside two plain IV buffers.  Two consequences run through the whole design:
sizes and key types are chosen per kind of key, because the two directions of a
connection always agree on them; and IVs are not key objects.

Libcrypto API
-------------

As all the objects are derived in one transaction, the provider derives them
together and keeps them in its own context, and we provide the API for access
to a particular object.

To derive the opaque keys and bytes buffers, we use the function

```C
int EVP_KDF_derive_SKEYs(EVP_KDF_CTX *ctx, const OSSL_PARAM params[]);
```

This function doesn't directly return objects when it succeeds; they are held
by the provider and discarded by the next derivation on the same context, or by
`EVP_KDF_CTX_reset()` or `EVP_KDF_CTX_free()`.

The options that define key types and sizes, number of keys or IVs and their
length are specified by passing appropriate parameters in the `params`
argument. If no params are provided, defaults may be used by specific KDF
operations.

The params can also be set by a preceding call to `EVP_KDF_CTX_set_params`.

The key type is not given as an EVP_SKEYMGMT name.  Instead the caller names
the algorithm the key is *for* -- the `"cipher"` and `"mac"` parameters, e.g.
`"AES-128-CBC"` and `"HMAC"` -- and the provider decides which of its own key
types that calls for.  This is what allows a PKCS#11 provider to give an HMAC
key a distinct type while the default provider treats it as a generic secret.
A named cipher also states the length of its own key, so `"cipher_key_len"` is
then unnecessary; a MAC does not, since for HMAC the length is a property of
the TLS ciphersuite rather than of the algorithm, so `"mac_key_len"` is always
given explicitly.  The IV length is likewise explicit, because the IV in a TLS
1.2 key block is whatever the protocol says it is -- for an AEAD suite the
implicit nonce rather than the cipher's full IV.

Validating the request is the provider's job and happens as part of the
derivation, so a key length that disagrees with the cipher named for it is
reported by `EVP_KDF_derive_SKEYs()` rather than later when the key is
collected.  This is also where a provider backed by a token naturally refuses
a template, which is why the check belongs there rather than in libcrypto: an
earlier revision had libcrypto build every key eagerly to catch the same
mistake, but once the provider was given the cipher name it could check the
length itself, and the eager pass had nothing left to catch.

To access the individual EVP_SKEY values, we introduce the function

```C
EVP_SKEY *EVP_KDF_CTX_get1_SKEY(EVP_KDF_CTX *ctx, const char *purpose,
                                const char *propquery);
```

where the `purpose` argument is a name of the particular EVP_SKEY purpose (e.g.
"client_MAC_key", "server_cipher_key") as specified by the documentation of the
specific KDF operation that was executed. The returned EVP_SKEY has its reference
count incremented and must be freed by the caller.  Each purpose carries its own
key type, so the keys of one derivation need not all be alike; `propquery`
selects the EVP_SKEYMGMT implementation for whichever type this one uses.

A derivation may legitimately produce no key for some purpose the algorithm
defines, in which case retrieving it fails: a TLS 1.2 key block for an AEAD
ciphersuite contains no MAC keys.

To access an IV, the API is

```C
int EVP_KDF_CTX_get0_IV(EVP_KDF_CTX *ctx, const char *purpose,
                        const unsigned char **pIV, size_t *pIVlen);
```

where the `purpose` argument is a documented name of the particular IV purpose
(e.g. "client_iv") and `pIVlen` argument is a way to get the length of
generated IV.  IVs are not keys and are returned as raw bytes owned by the
derivation result; the caller must not free them.

Provider API
------------

The derived keys and IVs stay in the provider's own KDF context, beside the
inputs they were derived from. An earlier revision had `derive_multi` return a
separate result object that libcrypto owned, but that object needed its own
free, dup and parameter accessors, each duplicating one the KDF context already
had; keeping the results in the context removes all four.

```C
OSSL_CORE_MAKE_FUNC(int, kdf_derive_multi,
                    (void *kctx, const OSSL_PARAM params[]))

OSSL_CORE_MAKE_FUNC(void *, kdf_get_skey,
                    (void *kctx, const char *purpose, void *provctx,
                     OSSL_FUNC_skeymgmt_import_fn *import))

OSSL_CORE_MAKE_FUNC(int, kdf_get_iv,
                    (void *kctx, const char *purpose,
                     const unsigned char **pIV, size_t *pIVlen))
```

`kdf_freectx` releases the derived keys along with the rest of the context and
`kdf_dupctx` copies them; a provider whose keys exist only as handles on a token
and cannot be copied fails the latter, so that a caller never receives a context
that has silently lost its keys.

The key type settled on for each purpose is reported through the ordinary
`kdf_get_ctx_params`, in a parameter named after that purpose, and that call
fails for a purpose no key was produced for — which is how libcrypto learns a
slot is absent. Resolving the type this way, rather than fixing one
EVP_SKEYMGMT for the whole derivation, is what permits an AES cipher key and a
generic-secret MAC key to come out of the same call.

`kdf_get_skey` receives the import function of the EVP_SKEYMGMT libcrypto
resolved from the reported type. A provider that already holds the key as a
native object may ignore it and return that object instead, so a token's keys
never have to exist as raw bytes.

Providers may either imply some KDF-specific defaults when it's obvious from
the KDF specification or throw an error otherwise.
