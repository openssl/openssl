Functions for explicitly fetched PKEY algorithms
================================================

Quick background
----------------

There are several proposed designs that end up revolving around the same
basic need, explicitly fetched signature algorithms.  The following method
type is affected by this document:

- `EVP_SIGNATURE`

Public API - Add variants of `EVP_PKEY_CTX` functionality
---------------------------------------------------------

Through OTC discussions, it's been determined that the most suitable APIs to
touch is the collection of `EVP_PKEY_` functions.  In this case, it involves
`EVP_PKEY_sign()`, `EVP_PKEY_verify()`, `EVP_PKEY_verify_recover()` with
associated functions.  They can be extended to accept an explicitly fetched
algorithm of the right type, and to be able to process infinite amounts of
data if the fetched algorithm permits it (typically, algorithms like ED25519
or RSA-SHA256).

It must be made clear that the added functionality can not be used to
compose an algorithm from different parts.  For example, it's not possible
to specify a `EVP_SIGNATURE` "RSA" and combine it with a parameter that
specifies the hash "SHA256" to get the "RSA-SHA256" functionality.  For an
`EVP_SIGNATURE` "RSA", the input is still expected to be a digest, or some
other input that's limited to the modulus size of the RSA pkey.

### Making things less confusing with distinct function names

So far, `EVP_PKEY_sign()` and friends are only expected to act as
"primitive" functions.  This design essentially proposes an extension to
also allow streaming functionality through an *update* and a *final*
function.  Discussions have revealed that it is potentially confusing to
confound "primitive" functionality with "streaming" functionality into the
same name, so this design also includes a naming proposal that distinguishes
the two uses.

### Making it possible to verify with an early signature

There are newer verifying algorithms that need to receive the signature
before processing the data.  This is particularly important for streaming
functionality.  This design proposes a mechanism to accomodate this, which
is different than the mechanism you get with `EVP_PKEY_verify()`.

Public API - API Reference
--------------------------

### For signing with `EVP_SIGNATURE`

#### Primitive / Limit size oneshot

``` C
int EVP_PKEY_sign_primitive_init(EVP_PKEY_CTX *pctx,
                                 EVP_SIGNATURE *algo,
                                 const OSSL_PARAM params[]);
int EVP_PKEY_sign_primitive(EVP_PKEY_CTX *ctx,
                            unsigned char *sig, size_t *siglen, size_t sigsize,
                            const unsigned char *tbs, size_t tbslen);
```

#### Streaming

``` C
int EVP_PKEY_sign_data_init(EVP_PKEY_CTX *pctx, EVP_SIGNATURE *algo,
                            const OSSL_PARAM params[]);
int EVP_PKEY_sign_data_update(EVP_PKEY_CTX *ctx,
                              const unsigned char *in, size_t inlen);
int EVP_PKEY_sign_data_final(EVP_PKEY_CTX *ctx,
                             unsigned char *sig, size_t *siglen, size_t sigsize);
```

### For verifying with `EVP_SIGNATURE`

#### Primitive / Limit size oneshot

``` C
/* Initializers */
int EVP_PKEY_verify_primitive_init(EVP_PKEY_CTX *pctx,
                                   EVP_SIGNATURE *algo,
                                   const OSSL_PARAM params[]);
int EVP_PKEY_verify_recover_primitive_init(EVP_PKEY_CTX *pctx,
                                           EVP_SIGNATURE *algo,
                                           const OSSL_PARAM params[]);
/* Oneshot functions */
int EVP_PKEY_verify_primitive(EVP_PKEY_CTX *pctx,
                              const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_recover_primitive(EVP_PKEY_CTX *pctx,
                                      unsigned char *rout, size_t *routlen,
                                      size_t routsize,
                                      cnnst unsigned char *sig, size_t siglen);
```

#### Streaming

Do note that there's no proposed streaming definition for verify recover
functionality.

``` C
/* Initializers */
int EVP_PKEY_verify_data_init(EVP_PKEY_CTX *pctx, EVP_SIGNATURE *algo,
                              const OSSL_PARAM params[]);
/* Signature setter */
int EVP_PKEY_CTX_set_signature(EVP_PKEY_CTX *pctx,
                               unsigned char *sig, size_t siglen,
                               size_t sigsize);
/* Update and final */
int EVP_PKEY_verify_data_update(EVP_PKEY_CTX *ctx,
                                const unsigned char *in, size_t inlen);
int EVP_PKEY_verify_data_final(EVP_PKEY_CTX *ctx);
```


Requirements on the providers
-----------------------------

Because it's not immediately obvious from a composite algorithm name what
key type it requires / supports, at least in code, allowing the use of an
explicitly fetched implementation of a composite algorithm requires that
providers cooperate by declaring what key type is required / supported by
each algorithm.

For non-composite operation algorithms (like "RSA"), this is not necessary,
see the fallback strategies below.

This is to be implemented through an added provider function that would work
like keymgmt's `query_operation_name` function, but would return a NULL
terminated array of key type name instead:

``` C
# define OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPE         26
OSSL_CORE_MAKE_FUNC(const char **, signature_query_key_type, (void))
```

Furthermore, the public API above requires added provider functionality:

``` C
# define OSSL_FUNC_SIGNATURE_SIGN_UPDATE            26
# define OSSL_FUNC_SIGNATURE_SIGN_FINAL             27
OSSL_CORE_MAKE_FUNC(int, signature_sign_update, (void *ctx,
                                                 const unsigned char *in,
                                                 size_t inlen))
OSSL_CORE_MAKE_FUNC(int, signature_sign_final, (void *ctx,  unsigned char *sig,
                                                size_t *siglen, size_t sigsize))

# define OSSL_FUNC_SIGNATURE_VERIFY_UPDATE          28
# define OSSL_FUNC_SIGNATURE_VERIFY_FINAL           29
OSSL_CORE_MAKE_FUNC(int, signature_verify_update,
                    (void *ctx, const unsigned char *in, size_t inlen))
/*
 * signature_verify_final requires that the signature to be verified against
 * is specified via an OSSL_PARAM.
 */
OSSL_CORE_MAKE_FUNC(int, signature_verify_final, (void *ctx))
```

Fallback strategies
-------------------

Because existing providers haven't been updated to respond to the key type
query, some fallback strategies will be needed to find out if the `EVP_PKEY`
key type is possible to use with the fetched algorithm.  This is only
possible to do with simple (non-composite) algorithms.

-   Check if the fetched operation name matches the key type (keymgmt name)
    of the `EVP_PKEY` that's involved in the operation.  For example, this
    is useful when someone fetched the `EVP_SIGNATURE` "RSA".  This requires
    very little modification, as this is already done with the initializer
    functions that fetch the algorithm implicitly.
-   Check if the fetched algorithm name matches the name returned by the
    keymgmt's `query_operation_name` function.  For example, this is useful
    when someone fetched the `EVP_SIGNATURE` "ECDSA", for which the key type
    to use is "EC".  This requires very little modification, as this is
    already done with the initializer functions that fetch the algorithm
    implicitly.

If none of these strategies work out, the operation initialization should
fail.
