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

The implementation is in general provider-dependent. If the corresponding
callback is not implemented for the EVP_SKEYMGMT, 0 is returned. However, as
metadata is completely optional, the success doesn't indicate that the data is
available.
