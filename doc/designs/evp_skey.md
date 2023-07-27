EVP_SKEY Design
===============

The current API assumes a byte buffer is always available and sufficient to
represent a symmetric key. It may be not available for hardware-backed
providers, such as PKCS#11 or TPM, in case when the key is generated on the
token and can't be exported.

This design proposes the use of an opaque type to represent symmetric keys. It
doesn't cover any extra parameters (e.g. AEAD-related nonces).

When a provider allows key exporting, the internal representation of the
EVP_SKEY may be "a bunch of bytes", that can be cached and made detached to any
provider, and become useful to any current cipher supporting the symmetric key
in byte form. Otherwise it may happen to be a set of provider-specific
parameters, compatible only with the particular provider.

For the clarity, speaking about cipher algorithm below, we understand that
*any* algorithm accepting a symmetric key should be suitable to deal with
an EVP_SKEY object.

We do **not** plan using EVP_PKEY for this purpose. It has too many legacy
parameters. EVP_SKEY, being designed from scratch, inherits only the necessary
ones.

Libcrypto perspective
---------------------

EVP_SKEY object can be either a wrapper around the raw key having the key
management set to NULL or the key management-backed object.

Wrapper EVP_SKEY object has a buffer containing the key and the key length set.
The key management-backed EVP_SKEY object contains 2 pointers: a pointer to an
EVP_KEYMGMT object and an opaque pointer to some internal representation.
EVP_KEYMGMT specifies what parameters are acceptable by the chosen provider and
may be used by specific algorithms of this provider. These parameters are
represented as an array of OSSL_PARAM. We create an API to manage the lifecycle
of EVP_SKEY objects (see below).

Being created, the EVP_SKEY object will be used in the functions we currently
use the raw key. The new API for this purpose is designed to match the existing
one but use an EVP_SKEY object as an argument. For usability reasons we keep IV
and IV length as separate arguments in the new API despite it could be passed
as an element of OSSL_PARAM array.

There are other parameters that some but not all ciphers take. You'll find a
substantial list in the manual for EVP_CipherInit(), and they are suitable for
passing via OSSL_PARAM. The difference here is that *those* params are not
provider-specific but algorithm-specific or operation-specific.

Things that were previously passed to backend implementations with ctrl
functions have become EVP_CIPHER_CTX level OSSL_PARAM items with providers.

The providers callbacks differ when the EVP_SKEY is a wrapper object (the
traditional raw bytes-oriented callbacks are used) and when it has the
associated key management (the new callbacks are used).

Provider perspective
--------------------

On the provider end, encryption and decryption implementations would receive an
opaque pointer similar to the provkey pointer used with asymmetric operations.
They expected to know how to deal with the structure. This pointer is a result
of processing an array of OSSL_PARAM by the EVP_KEYMGMT import operation.

Once created by import, the EVP_SKEY structure can be exported to the extent
the provider and EVP_KEYMGMT suports it. There is no guarantee that the result
of export-import operation is the same as the initial set of the parameters.

The EVP_SKEY object *can* have an algorithm association. It should be a
provider-specific decision or maybe an information that could be associated to
an EVP_SKEY any time later. Whether it starts with being algorithm specific or
not depends on how it was created. If it's a result of obtaining a PKCS#11
secret key, then it will most likely be algorithm specific from the start.

We do not see why we would want to assign an algorithm immediately during
the creation of an EVP_SKEY as result of derive() operation, if the operation
just creates bunch of bytes that can be used as a key equally well for HMAC or
AES encryption.

Objects relationships
---------------------

We have an EVP_CIPHER object associated with a particular provider. An EVP_SKEY
object should be compatible with the particular EVP_CIPHER object (the check is
done via comparing the providers). After that it can be used within a
EVP_CIPHER_CTX object associated with the same EVP_CIPHER object.

The way to reuse the key within the other provider is through the export/import
dance. As mentioned before, it may fail. The way to reuse it with a different
cipher context is `EVP_SKEY_up_ref`.

Key management
--------------

The provider operating EVP_SKEY objects has to implement a separate key
management to deal with the opaque object. We already have a MAC legacy key
management and it looks suitable for dealing with EVP_SKEY objects.

There is a special case: if the EVP_SKEY object doesn't have an associated key
management, it carries a raw representation of the key on board.

Allocation and freeing
----------------------

```C
EVP_SKEY *EVP_SKEY_new(OSSL_LIB_CTX *libctx, const char *keymgmtname, const char *propquery);
EVP_SKEY *EVP_SKEY_new_raw(OSSL_LIB_CTX *libctx, const char *key, size_t keylen);
int EVP_SKEY_up_ref(EVP_SKEY *skey);
void EVP_SKEY_free(EVP_SKEY *skey);
```

Importing and exporting parameters
----------------------------------

```C
int EVP_SKEY_import(EVP_SKEY *pskey, const OSSL_PARAM *params);
int EVP_SKEY_export(const EVP_SKEY *skey, int selection,
                    OSSL_CALLBACK *export_cb, void *export_cbarg);
```

Importing the parameters is the only way to set key data. We don't provide any
API to modify key data after being set.

Using EVP_SKEY in cipher operations
-----------------------------------

We provide a function

```C
int EVP_CipherInit_skey(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                        const EVP_SKEY *skey, const unsigned char *iv,
                        size_t ev_len, int enc, const OSSL_PARAM params[]);
```

similar to `EVP_CipherInit_ex2`.

Using EVP_SKEY with EVP_MAC
---------------------------

```C
int EVP_MAC_init_skey(EVP_MAC_CTX *ctx, const EVP_SKEY *skey,
                      const OSSL_PARAM params[]);
```

similar to `EVP_MAC_init`

API to derive an EVP_SKEY object
--------------------------------

The derived key can be algorithm-specific or algorithm-agnostic. To specify the
algorithm binding, the params argument can be used.

```C
int EVP_PKEY_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *skey,
                         OSSL_PARAM params[]);
int EVP_KDF_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *skey,
                        OSSL_PARAM params[]);
```

similar to `EVP_PKEY_derive/EVP_KDF_derive`
