EVP_SKEY Design
===============

We currently presume that symmetric keys are represnted as octet buffer. It may
be not relevant for the situation of hardware-backed providers, such as
PKCS#11 or TPM.

This is a design of using opaque usage in symmetric encryption.

Creation
--------
```
EVP_SKEY * EVP_SKEY_new(void)
```
creates an empty `EVP_SKEY` object.

API to set parameters
---------------------
```
int EVP_SKEY_fromdata(EVP_CIPHER_CTX *ctx, EVP_SKEY **pskey, OSSL_PARAM params[]);
int EVP_SKEY_assign(EVP_CIPHER_CTX *ctx, EVP_SKEY *pskey, OSSL_PARAM params[]);
```

API to derive a symmetric key
-----------------------------
```
int EVP_PKEY_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEY *pskey);
```
similar to `EVP_PKEY_derive`

We already have the function
```
EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv,
                   int enc, const OSSL_PARAM params[]);
```

and can introduce

```
EVP_CipherInit_ex3(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const EVP_SKEY *skey, const unsigned char *iv,
                   int enc, const OSSL_PARAM params[]);
```
(we definitely need a better name for it)

To find out the parameters supported by a particular EVP_CIPHER object,
we need a function

```
const OSSL_PARAM *EVP_CIPHER_settable(EVP_CIPHER *cipher);
```

similar to `EVP_PKEY_fromdata_settable`

Accessing the current key object
--------------------------------

To get/set the currently set key as a EVP_SKEY object, we introduce the API

```
EVP_SKEY * EVP_CIPHER_CTX_get_EVP_SKEY(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set_EVP_SKEY(const EVP_CIPHER_CTX *ctx, const EVP_SKEY *skey);
```
The getter should create a new EVP_SKEY object to be freed by `EVP_SKEY_free` function.

Accessing the current key parameters
------------------------------------
To get the currently set parameters, we use
```
int EVP_SKEY_todata(const EVP_SKEY *key, OSSL_PARAM **params);
int EVP_SKEY_export(const EVP_SKEY *key, OSSL_PARAM **params, OSSL_CALLBACK *export_cb, void *export_cbarg);
```

Duplicating the EVP_SKEY object
-------------------------------
```
EVP_SKEY * EVP_SKEY_dup(const EVP_SKEY * skey);
```

Free function
-------------
```
void EVP_SKEY_free(EVP_SKEY *key);
```
