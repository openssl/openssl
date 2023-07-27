EVP_SKEY Design
===============

We currently presume that symmetric keys are represnted as octet buffer. It may
be not relevant for the situation of hardware-backed providers, such as
PKCS#11 or TPM.

This is a design of using opaque usage in symmetric encryption.

Key management
--------------

The provider operating EVP_SKEY objects has to implement a separate key
management to deal with opaque object. We already have MAC key management and
it looks suitable for dealing with EVP_SKEY objects.

Allocation and freeing
--------

```C
EVP_SKEY * EVP_SKEY_new(void);
void EVP_SKEY_free(EVP_SKEY *key);
```

Importing and exporting parameters
----------------------------------

```C
int EVP_SKEY_fromdata(EVP_CIPHER_CTX *ctx, EVP_SKEY **pskey, OSSL_PARAM params[]);
int EVP_SKEY_assign(EVP_CIPHER_CTX *ctx, EVP_SKEY *pskey, OSSL_PARAM params[]);
int EVP_SKEY_todata(const EVP_SKEY *key, OSSL_PARAM **params);
int EVP_SKEY_export(const EVP_SKEY *key, OSSL_PARAM **params,
                    OSSL_CALLBACK *export_cb, void *export_cbarg);
```

API to derive a symmetric key
-----------------------------

```C
int EVP_PKEY_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *pskey);
int EVP_KDF_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *pskey);
```

similar to `EVP_PKEY_derive/EVP_KDF_derive`

Duplicating the EVP_SKEY object
-------------------------------

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

and can introduce

```C
EVP_CipherInit_ex3(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const EVP_SKEY *skey, const unsigned char *iv,
                   int enc, const OSSL_PARAM params[]);
```

(we definitely need a better name for it) with corresponding
`EVP_EncryptInit_ex3/EVP_DecryptInit_ex3`

To find out the parameters supported by a particular EVP_CIPHER object,
we need a function

```C
const OSSL_PARAM *EVP_CIPHER_settable(EVP_CIPHER *cipher);
```

similar to `EVP_PKEY_fromdata_settable`

Accessing the current key object
--------------------------------

To get/set the currently set key as a EVP_SKEY object, we introduce the API

```C
EVP_SKEY * EVP_CIPHER_CTX_get1_EVP_SKEY(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set1_EVP_SKEY(const EVP_CIPHER_CTX *ctx, EVP_SKEY *skey);
```

The object returned by getter should be freed by `EVP_SKEY_free` function.
