Passing AgorithmIdentifier parameters to operations
===================================================

Quick background
----------------

We currently only support passing the AlgorithmIdentifier (`X509_ALGOR`)
parameter field to symmetric cipher provider implementations.

We do support passing them to legacy implementations of other types of
operation algorithms as well, but it's done in a way that can't be supported
with providers, because it involves sharing specific structures between
libcrypto and the backend implementation.

For a longer background and explanation, see
[Background / tl;dr](#background-tldr) at the end of this design.

Establish an OSSL_PARAM key that any algorithms may become aware of
-------------------------------------------------------------------

We already have a parameter key, but it's currently only specified for
`EVP_CIPHER`, in support of `EVP_CIPHER_param_to_asn1()` and
`EVP_CIPHER_asn1_to_param()`.

"alg_id_param", also known as the macro `OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS`

This parameter can be used in the exact same manner with other operations,
with the value of the AlgorithmIdentifier parameter as an octet string, to
be interpreted by the implementations in whatever way they see fit.

Applications can choose to add these in an `OSSL_PARAM` array, to be passed
with the multitude of initialization functions that take such an array, or
using specific operation `OSSL_PARAM` setters and getters (such as
`EVP_PKEY_CTX_set_params`), or using other available convenience functions
(see below).

Public convenience API
----------------------

For convenience, the following set of functions would be added to pass the
AlgorithmIdentifier parameter data to diverse operations, or to retrieve
such parameter data from them.

``` C
/*
 * These two would essentially be aliases for EVP_CIPHER_param_to_asn1()
 * and EVP_CIPHER_asn1_to_param().
 */
EVP_CIPHER_CTX_set_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);
EVP_CIPHER_CTX_get_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);

EVP_MD_CTX_set_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);
EVP_MD_CTX_get_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);

EVP_MAC_CTX_set_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);
EVP_MAC_CTX_get_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);

EVP_KDF_CTX_set_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);
EVP_KDF_CTX_get_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);

EVP_PKEY_CTX_set_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);
EVP_PKEY_CTX_get_algor_param(EVP_PKEY_CTX *ctx, X509_ALGOR *alg);
```

Note that all might not need to be added immediately, depending on if they
are considered useful or not.  For future proofing, however, they should
probably all be added.

Requirements on the providers
-----------------------------

Providers that implement ciphers or any operation that uses asymmetric keys
will have to implement support for passing AlgorithmIdentifier parameter
data, and will to process that data in whatever manner that's necessary to
meet the standards for that operation.

Fallback strategies
-------------------

There are no possible fallback strategies, which is fine, considering that
current provider functionality doesn't support passing AlgorithmIdentifier
parameter data at all (except for `EVP_CIPHER`), and therefore do not work
at all when such parameter data needs to be passed.

-----

-----

Background / tl;dr
------------------

### AlgorithmIdenfier parameter and how it's used

OpenSSL has historically done a few tricks to not have to pass
AlgorithmIdenfier parameter data to the backend implementations of
cryptographic operations:

- In some cases, they were passed as part of the lower level key structure
  (for example, the `RSA` structure can also carry RSA-PSS parameters).
- In the `EVP_CIPHER` case, there is functionality to pass the parameter
  data specifically.
- For asymmetric key operations, PKCS#7 and CMS support was added as
  `EVP_PKEY` ctrls.

With providers, some of that support was retained, but not others.  Most
crucially, the `EVP_PKEY` ctrls for PKCS#7 and CMS were not retained,
because the way they were implemented violated the principle that provider
implementations *MUST NOT* share complex OpenSSL specific structures with
libcrypto.
