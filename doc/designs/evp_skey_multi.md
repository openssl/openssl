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
                                           const char **key_types,
                                           const size_t *keylengths, size_t keynum,
                                           char **ivptrs,
                                           const size_t *ivlengths, size_t ivnum,
                                           const char *propquery, const OSSL_PARAM params[]);
```

is insipred by the existing one

```C
EVP_SKEY *EVP_KDF_derive_SKEY(EVP_KDF_CTX *ctx, EVP_SKEYMGMT *mgmt,
                              const char *key_type, const char *propquery,
                              size_t keylen, const OSSL_PARAM params[]);
```

For keys we specify the list of algorithms for which the keys would be used,
the lengths of the required keys, and the total amount of generated keys.

For IVs we specify the pointers to the byte arrays to befreed after use, the
expected lengths, and the amount of IVs to be derived.

The new function returns a pointer to a stack of EVP_SKEY objects or NULL on
error. The order of objects in the stack is specific for a particular KDF and
is documented. The number of objects in stack can be different depending on
purpose.

If the number of keys or number of IVs doesn't match the provider
implementation, the function returns NULL.


An alternative approach
-----------------------

In theory, as all the objects are derived in one transaction, the other
approach is possible.  We can return a single EVP_SKEY object keeping all the
keys inside, and modify the API for setting a particular object internally.
Until it doesn't imply export-import dance (that means that a KDF and
cipher/MAC should come from the same provider), it can be manageable.

However, this will require extending the API on the libcrypto/libssl side and
complications on a provider side.
