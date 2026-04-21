PKCS#12 Java Keytool Support Extension — Alternative Approach
=============================================================

Problem Statement
-----------------

OpenSSL cannot parse PKCS#12 files created by Java's keytool utility that
contain symmetric secret keys. Java keytool stores symmetric keys in
`secretBag` structures containing `pkcs8ShroudedKeyBag` with encrypted key
material. OpenSSL's PKCS#12 parser ignores `NID_secretBag` entirely.

Approach: Bag-Level API + Parse Context
---------------------------------------

The key insight: follow the existing OpenSSL pattern where each bag type has
its own `PKCS12_SAFEBAG_get1_*()` extractor, and use an opaque context for the
high-level parse API.

Design Principles
-----------------

- **Opaque parse context**: `PKCS12_PARSE_CTX` tells `PKCS12_parse_ex()` which
  object types to extract. Adding a new type means adding a struct field and a
setter — no function signature changes.
- **Bag-level extraction**: Add `PKCS8_PRIV_KEY_INFO_get1_skey()` in `p12_sbag.c`,
  following the `get1_cert` / `get1_crl` pattern. This is the single source of
truth for secret bag decryption — both the parser and the CLI tool call it.
- **Minimal internal churn**: `parse_bag()` handles `NID_secretBag` by calling
  the public bag-level API, just like it calls `PKCS12_SAFEBAG_get1_cert_ex()`
for `NID_certBag`. Internal functions pass `PKCS12_PARSE_CTX *` instead of
individual pointer parameters.

Implementation Plan
-------------------

1. OID Registration

Registering OID for generic AES algorithm as most important for our purposes.

2. Bag-Level Secret Key API (following private key pattern)

Two functions, mirroring `PKCS12_decrypt_skey_ex()` + `EVP_PKCS82PKEY_ex()`:

Decrypt: `PKCS12_decrypt_secretbag`

**File**: `crypto/pkcs12/p12_add.c` (alongside `PKCS12_decrypt_skey_ex`)

```c
PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_secretbag(const PKCS12_SAFEBAG *bag,
    const char *pass, int passlen,
    OSSL_LIB_CTX *ctx, const char *propq);
```

Implementation:
1. Check `PKCS12_SAFEBAG_get_nid(bag) == NID_secretBag`
2. Check `PKCS12_SAFEBAG_get_bag_nid(bag) == NID_pkcs8ShroudedKeyBag`
3. Get bag object via `PKCS12_SAFEBAG_get0_bag_obj()`, verify `V_ASN1_OCTET_STRING`
4. Parse as `X509_SIG` via `d2i_X509_SIG()`
5. Decrypt via `PKCS8_decrypt_ex()` and return `PKCS8_PRIV_KEY_INFO`

Convert: `PKCS8_PRIV_KEY_INFO_get1_skey`

**File**: `crypto/pkcs12/p12_sbag.c`

```c
EVP_SKEY *PKCS8_PRIV_KEY_INFO_get1_skey(const PKCS8_PRIV_KEY_INFO *p8inf,
    OSSL_LIB_CTX *libctx, const char *propq);
```

Implementation:
1. Extract key bytes via `PKCS8_pkey_get0()`, determine key type from algorithm OID
2. Create and return `EVP_SKEY` via `EVP_SKEY_import_raw_key()`

This follows the private key pattern: `PKCS12_decrypt_skey_ex()` +
`EVP_PKCS82PKEY_ex()` → `PKCS12_decrypt_secretbag()` +
`PKCS8_PRIV_KEY_INFO_get1_skey()`.

3. Parse Context API and PKCS12_parse_ex()

**Files**: `crypto/pkcs12/p12_kiss.c`, `include/openssl/pkcs12.h.in`, `crypto/pkcs12/p12_local.h`

PKCS12_PARSE_CTX

Introduce an opaque context structure that tells `PKCS12_parse_ex()` what to extract:

```c
/* In p12_local.h (internal definition) */
struct pkcs12_parse_ctx_st {
    EVP_PKEY **pkey;
    X509 **cert;
    STACK_OF(X509) **ca;
    EVP_SKEY **skey;
    /* internal: temporary cert collection used during parsing */
    STACK_OF(X509) *ocerts;
};
```

Public API:

```c
PKCS12_PARSE_CTX *PKCS12_PARSE_CTX_new(void);
void PKCS12_PARSE_CTX_free(PKCS12_PARSE_CTX *ctx);

/* Setters — each tells the parser to extract that object type */
void PKCS12_PARSE_CTX_set_pkey(PKCS12_PARSE_CTX *ctx, EVP_PKEY **pkey);
void PKCS12_PARSE_CTX_set_cert(PKCS12_PARSE_CTX *ctx, X509 **cert);
void PKCS12_PARSE_CTX_set_ca(PKCS12_PARSE_CTX *ctx, STACK_OF(X509) **ca);
void PKCS12_PARSE_CTX_set_skey(PKCS12_PARSE_CTX *ctx, EVP_SKEY **skey);
```

Internal functions `parse_pk12()`, `parse_bags()`, `parse_bag()` accept
`PKCS12_PARSE_CTX *ctx` instead of individual pointer parameters. This replaces
the current `EVP_PKEY **pkey, STACK_OF(X509) *ocerts` signatures and is
extensible — adding a new object type means adding a field to the struct and a
setter, not changing every internal function signature.

PKCS12_parse_ex()

```c
int PKCS12_parse_ex(PKCS12 *p12, const char *pass,
    PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq);
```

The context tells the parser which output slots to fill. Slots not set via
setters are ignored. On error, all set slots are cleaned up (freed and set to
NULL).

`PKCS12_parse()` is deprecated, as it doesn't accept libctx/propq and it cannot
be extended for other object types.

4. Command-Line Tool

**File**: `apps/pkcs12.c`

Add `-raw` option (`OPT_RAW`) for raw binary output.

For `-info` mode, add `dump_secret_bag_info()` — displays bag type, encryption
algorithm, encrypted data length on stderr.

`dump_skey_output()` handles three output modes:
- `-raw`: raw binary via `EVP_SKEY_get0_raw_key()` → `BIO_write()`
- `-noenc`/`-nodes`: bag attributes + algorithm + key length + hex key data
- default: bag attributes + algorithm + key length + "use -noenc to output" message

5. OSSL_STORE Integration

**File**: `crypto/store/store_result.c`

Update `try_pkcs12()` to use a `PKCS12_PARSE_CTX` object requesting pkey, cert,
ca, and skey
