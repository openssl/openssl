EVP_SKEY Design
===============

We currently presume that symmetric keys are represented as octet buffer. It
may be not relevant for the situation of hardware-backed providers, such as
PKCS#11 or TPM.

This is a design of using opaque usage in symmetric encryption.

If the provider allows key exporting, the internal representation of the
EVP_SKEY is "a bunch of bytes", that can be cached and made unattached to any
provider, and become useful to any current cipher supporting the symmetric key
in byte form.

For the clarity, speaking about cipher algorithm below, we understand that
*any* algorithm accepting a symmetric key should be suitable to deal with
EVP_SKEY object.

We do **not** plan using EVP_PKEY for this purpose.

Libcrypto perspective
---------------------

The way we have used OSSL_PARAM is for things that are (or should be) unknown
from a libcrypto perspective, while we have made function arguments from what
is known.

Among the things that are known is that all ciphers take a key,
unconditionally. With that in mind, it's logical that it has become a function
argument. At the time, we didn't think that a key would ever be anything but "a
bunch of bytes", which is why it's an `unsigned char *`. IV is also a separate
argument for historical reasons.

There are other parameters that some but not all ciphers take. You'll find a
substantial list in the manual for EVP_CipherInit(), and they are suitable for
OSSL_PARAM. The difference here is that *those* params are not
provider-specific but algorithm-specific.

Things that were previously passed to backend implementations with ctrl
functions have become EVP_CIPHER_CTX level OSSL_PARAM items with providers.

To allow for the diverse uses we can see so far, an EVP_SKEY would conceptually
be a union of "a bunch of bytes" (with no particular algorithm in mind) and a
reference to a provider-backed symmetric key (which will have to be specific to
a key type / base algo).

Provider perspective
--------------------

On the provider end, encryption and decryption implementations would receive an
opaque pointer similar to the provkey pointer used with asymmetric operations.
They expected to know how to deal with the structure.

The structure is the result of processing an array of OSSL_PARAM on the
provider level. The exact set of those params is provider-specific.

It should be possible to export/import the raw algorithm-specific
keydata of an EVP_SKEY from a provider to another provider. Of course a
provider could refuse the export operation if the key is unexportable.

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

We have EVP_CIPHER object associated with a particular provider. A EVP_SKEY
object is derived for the particular EVP_CIPHER object. After that it is used
within a EVP_CIPHER_CTX object associated with the same EVP_CIPHER object.

The way to reuse the key within the other provider is through the export/import
dance. As mentioned before, it may fail.

Key management
--------------

The provider operating EVP_SKEY objects has to implement a separate key
management to deal with opaque object. We already have MAC legacy key
management and it looks suitable for dealing with EVP_SKEY objects.

Allocation and freeing
--------

```C
EVP_SKEY * EVP_SKEY_new(void);
void EVP_SKEY_free(EVP_SKEY *key);
```

Importing and exporting parameters
----------------------------------

```C
int EVP_SKEY_import(EVP_CIPHER *cipher, EVP_SKEY **pskey, OSSL_PARAM params[]);
int EVP_SKEY_export(const EVP_SKEY *key, OSSL_PARAM **params,
                    OSSL_CALLBACK *export_cb, void *export_cbarg);
```

A parameter `raw_bytes` can be used if we try to get a key in classical raw
bytes implementation.

To find out the parameters supported by a particular EVP_CIPHER object,
we need a function

```C
const OSSL_PARAM *EVP_SKEY_fromdata_settable(EVP_CIPHER *cipher);
```

similar to `EVP_PKEY_fromdata_settable`

API to derive a symmetric key
-----------------------------

The derived key can be algorithm-specific or algorithm-agnostic. To specify the
algorithm binding, the params argument can be used.

```C
int EVP_PKEY_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *pskey,
                         OSSL_PARAM params[]);
int EVP_KDF_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *pskey,
                        OSSL_PARAM params[]);
```

similar to `EVP_PKEY_derive/EVP_KDF_derive`

Duplicating the EVP_SKEY object
-------------------------------

**Open question:** do we need it?

```C
EVP_SKEY * EVP_SKEY_dup(const EVP_SKEY * skey);
```

Using in cipher operations
--------------------------

We already have the function

```C
EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv,
                   int enc, const OSSL_PARAM params[]);
```

To set the skey object to the context, we invoke `EVP_CipherInit_ex2` with NULL
key ptr and invoke `EVP_CIPHER_CTX_set1_EVP_SKEY`.

An alternate approach will be providing a function

```C
EVP_CipherInit_skey(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const EVP_SKEY *key,
                   const unsigned char *iv, size_t iv_len,
                   int enc, const OSSL_PARAM ctx_params[]);
```

altogether with `EVP_EncryptInit_skey/EVP_DecryptInit_skey` wrappers.

Accessing the current key object
--------------------------------

To get/set the currently set key as a EVP_SKEY object, we introduce the API

```C
EVP_SKEY * EVP_CIPHER_CTX_get1_EVP_SKEY(const EVP_CIPHER_CTX *ctx);
EVP_SKEY * EVP_MAC_CTX_get1_EVP_SKEY(const EVP_MAC_CTX *ctx, EVP_SKEY *skey);
EVP_SKEY * EVP_KDF_CTX_get1_EVP_SKEY(const EVP_KDF_CTX *ctx, EVP_SKEY *skey);
int EVP_CIPHER_CTX_set1_EVP_SKEY(const EVP_CIPHER_CTX *ctx, EVP_SKEY *skey);
int EVP_MAC_CTX_set1_EVP_SKEY(const EVP_MAC_CTX *ctx, EVP_SKEY *skey);
int EVP_KDF_CTX_set1_EVP_SKEY(const EVP_KDF_CTX *ctx, EVP_SKEY *skey);
```

The object returned by getter should be freed by `EVP_SKEY_free` function.

**Open question:** do we need get0 methods?
