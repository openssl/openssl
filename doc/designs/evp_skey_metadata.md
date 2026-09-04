EVP_SKEY metadata support for PKCS#12 symmetric keys
====================================================

Problem
-------

When parsing PKCS#12 files, the resulting object should be created with both
raw key bytes and other attributes (the friendly name, local key ID, original
AlgorithmIdentifier with parameters etc).

We can store metadata in the provider-side `PROV_SKEY` structure and manage it
through the `EVP_SKEYMGMT` import/export mechanism. This keeps `evp_skey_st`
opaque to metadata details and lets providers handle metadata naturally through
`OSSL_PARAM`.

The alias (friendly name) is returned through the existing `EVP_SKEY_get0_key_id`
API, which dispatches to `skeymgmt->get_key_id`.

Binary metadata (local key ID, algorithm parameters) uses byte-pointer + length
pairs.

OSSL_PARAM names for metadata
------------------------------

New parameter name constants in `include/openssl/core_names.h`:

```c
#define OSSL_SKEY_PARAM_ALIAS            "skey-alias"
#define OSSL_SKEY_PARAM_LOCAL_KEYID      "skey-local-keyid"
#define OSSL_SKEY_PARAM_ALGORITHM_OID    "skey-algorithm-oid"
#define OSSL_SKEY_PARAM_ALGORITHM_PARAMS "skey-algorithm-params"
```

- `OSSL_SKEY_PARAM_ALIAS` — UTF-8 string, the friendly name / key identifier.
  Used as the return value from `skeymgmt->get_key_id`.
- `OSSL_SKEY_PARAM_LOCAL_KEYID` — octet string, the PKCS#12 local key ID.
- `OSSL_SKEY_PARAM_ALGORITHM_OID` — octet string, the DER-encoded algorithm
  OID from the AlgorithmIdentifier.
- `OSSL_SKEY_PARAM_ALGORITHM_PARAMS` — octet string, the DER-encoded algorithm
  parameters from the AlgorithmIdentifier.

PROV_SKEY changes
-----------------

Extend `struct prov_skey_st` in `include/internal/skey.h`:

```c
struct prov_skey_st {
    OSSL_LIB_CTX *libctx;
    int type;
    unsigned char *data;
    size_t length;

    /* Metadata — set during import, returned during export / get_key_id */
    char *alias;                    /* friendly name, may be NULL */
    unsigned char *local_keyid;     /* local key ID, may be NULL */
    size_t local_keyid_len;
    unsigned char *algorithm_oid;   /* DER-encoded algorithm OID, may be NULL */
    size_t algorithm_oid_len;
    unsigned char *algorithm_params; /* DER-encoded alg params, may be NULL */
    size_t algorithm_params_len;
};
```

All metadata fields are optional (NULL when not provided). `generic_free()`
must free them with `OPENSSL_free()`.

EVP_SKEYMGMT implementation changes
------------------------------------

### generic skeymgmt

- **Import**: decode new `OSSL_SKEY_PARAM_*` parameters from the import params
  and store them in the `PROV_SKEY` fields.
- **Export**: include metadata params alongside `OSSL_SKEY_PARAM_RAW_BYTES`
  when the corresponding fields are non-NULL.
- **get_key_id**: implement `OSSL_FUNC_SKEYMGMT_GET_KEY_ID` — return
  `prov_skey->alias`. This makes `EVP_SKEY_get0_key_id()` return the
  friendly name.
- **get_local_keyid**: implement `OSSL_FUNC_SKEYMGMT_GET_LOCAL_KEYID` —
  return `prov_skey->local_keyid` and its length. This makes
  `EVP_SKEY_get0_local_keyid()` work via dispatch.
- **get_algorithm_id**: implement `OSSL_FUNC_SKEYMGMT_GET_ALGORITHM_ID` —
  return DER-encoded OID and parameters from `prov_skey`. This makes
  `EVP_SKEY_get0_algorithm_id()` work via dispatch.
- **Import settable params**: update `generic_skey_import_list` to include
  the new params.
- **free**: free all metadata fields.

### AES skeymgmt

Inherits generic import/export/free for metadata handling. No AES-specific
metadata logic needed — the base `generic_import` already stores the fields.

EVP_SKEY metadata accessors
----------------------------

We implement the following accessors:

- **Alias**: `EVP_SKEY_get0_key_id()` (existing API, no changes).
  Returns `const char *` — the friendly name from the provider.

- **Local key ID**: new accessor via export:

  ```c
  int EVP_SKEY_get0_local_keyid(const EVP_SKEY *skey,
                                 const unsigned char **id, size_t *len);
  ```

  Returns 1 on success (with `*id` and `*len` set), 0 if not available.

- **Algorithm identifier**: new accessor that returns both the DER-encoded OID
  and the DER-encoded parameters:

  ```c
  int EVP_SKEY_get0_algorithm_id(const EVP_SKEY *skey,
                                  const unsigned char **oid,
                                  size_t *oid_len,
                                  const unsigned char **params,
                                  size_t *params_len);
  ```

  Returns 1 on success. Either output pointer may be NULL if the caller
  doesn't need that part.

These accessors use dedicated `OSSL_FUNC_SKEYMGMT_GET_LOCAL_KEYID` and
`OSSL_FUNC_SKEYMGMT_GET_ALGORITHM_ID` dispatch functions, following the
pattern of `EVP_SKEY_get0_key_id()`.

PKCS8_PRIV_KEY_INFO_get1_skey changes
--------------------------------------

The function gains two new parameters:

```c
EVP_SKEY *PKCS8_PRIV_KEY_INFO_get1_skey(const PKCS8_PRIV_KEY_INFO *p8inf,
                                          OSSL_LIB_CTX *libctx,
                                          const char *propq,
                                          const OSSL_PARAM *extra_params,
                                          int strict);
```

- **`extra_params`**: caller-built `OSSL_PARAM` array containing metadata
  from bag attributes (local key ID and friendly name). May be NULL.
  The function merges these with the params it builds from the PKCS8
  structure (raw key bytes, algorithm identifier, algorithm parameters).

- **`strict`**: controls how unrecognized algorithm OIDs are handled.
  The function always attempts to match an algorithm-specific SKEYMGMT
  based on the AlgorithmIdentifier OID (e.g. `OSSL_SKEY_TYPE_AES` for
  AES NIDs).
  - `0` (permissive, default): unrecognized OIDs fall back to
    `OSSL_SKEY_TYPE_GENERIC`.
  - non-zero (strict): unrecognized OIDs cause the function to return
    NULL.

The function now also:
1. Extracts the full `X509_ALGOR` from the PKCS8 structure (via `PKCS8_pkey_get0`).
2. DER-encodes the algorithm OID and adds it as
   `OSSL_SKEY_PARAM_ALGORITHM_OID`.
3. DER-encodes the algorithm parameters (if present) and adds them as
   `OSSL_SKEY_PARAM_ALGORITHM_PARAMS`.
4. Merges with `extra_params` (lkid, fname from caller).
5. Calls `EVP_SKEY_import()` with the combined parameter set.

Caller changes in p12_kiss.c
-----------------------------

In the `NID_secretBag` case in `parse_bag()`, the caller builds an
`OSSL_PARAM` array with the friendly name and local key ID extracted
from bag attributes, and passes it to `PKCS8_PRIV_KEY_INFO_get1_skey`
via `extra_params`:

```c
case NID_secretBag:
{
    OSSL_PARAM extra[3];
    int nparams = 0;
    unsigned char *fname_utf8 = NULL;
    int fname_utf8_len = 0;

    if (fname) {
        fname_utf8_len = ASN1_STRING_to_UTF8(&fname_utf8, fname);
        if (fname_utf8_len >= 0) {
            extra[nparams++] = OSSL_PARAM_construct_utf8_string(
                OSSL_SKEY_PARAM_ALIAS,
                (char *)fname_utf8, fname_utf8_len);
        }
    }
    if (lkid) {
        extra[nparams++] = OSSL_PARAM_construct_octet_string(
            OSSL_SKEY_PARAM_LOCAL_KEYID,
            lkid->data, lkid->length);
    }
    extra[nparams] = OSSL_PARAM_construct_end();

    skey = PKCS8_PRIV_KEY_INFO_get1_skey(p8, ctx, propq, extra, 0);
    OPENSSL_free(fname_utf8);
    if (skey == NULL)
        goto err;

    /* push skey to stack ... */
}
```
