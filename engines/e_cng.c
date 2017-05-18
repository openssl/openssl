/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * wincrypt.h includes ncrypt.h on platforms where that one is present.
 * All we need to do to check that ncrypt.h was in fact included it to
 * check for the presence of a known NCRYPT macro, such as NCRYPT_SILENT_FLAG
 */
#ifdef _WIN32
# include <windows.h>
# include <wincrypt.h>
# ifndef OPENSSL_NO_CNGENG
#  if defined(NCRYPT_SILENT_FLAG)
#   define __COMPILE_CNGENG
#  endif
# endif
#endif

#ifdef __COMPILE_CNGENG

# pragma comment(lib,"ncrypt")

# include <openssl/crypto.h>
# include <openssl/engine.h>
# include <openssl/store.h>
# include <openssl/evp.h>
# include <openssl/rsa.h>

# include "e_cng.h"
# include "e_cng_err.h"
# include "e_cng_err.c"

/* Mingw seems to lack this one */
# ifndef NTE_NO_MORE_ITEMS
#  define NTE_NO_MORE_ITEMS 0x8009002A
# endif

static const char *cng_id = "cng";
static const char *cng_name = "NCrypt ENGINE";
static const char cng_scheme[] = "cng";

static int loader_idx = -1;
static int rsa_idx = -1;

static size_t hex_encode_inline(char *dst, char *src, size_t src_len);
static char *url_decode(char *str);
static char *url_encode(char *str, int encode_reserved);
static void cng_adderror(DWORD err);
static char *to_asc(LPCWSTR in);
static LPWSTR to_wide(const char *in);
static EVP_PKEY *cng_get_pkey(const ENGINE *engine, NCRYPT_KEY_HANDLE khandle);

typedef struct cng_ctx_st {
    NCRYPT_KEY_HANDLE khandle;   /* Used with keys */
} CNG_CTX;
static CNG_CTX *cng_ctx_new(void);
static void cng_ctx_free(CNG_CTX *ctx);

/*-
 * STORE section
 * -------------
 *
 * All made in such a way that we can support the old style access via ENGINE
 * ctrls as well
 *
 * (proposed) Base URI syntax:
 *
 * cng-uri      = "cng:" cng-path [ "?" cng-query ]
 * cng-path     = cng-attr *( ";" cng-attr )
 * cng-attr     = cng-provider / cng-store / cng-keyname / cng-certid
 * cng-provider = "provider" "=" *cng-pchar     ; Key provider name.
 * cng-store    = "store" "=" *cng-pchar        ; Cert store name.
 * cng-keyname  = "keyname" "=" *cng-pchar      ; Key name, implies key lookup.
 * cng-certid   = "certid" "=" *cng-pchar       ; CERT_ID_HASH_SHA1 hashId,
 *                                              ; implies cert lookup.
 *
 * If cng-provider isn't given or cng-keyname and cng-certid aren't given,
 * STORE_load() will enumerate URIs for the parts that are missing.  You
 * can thereby get a list of all providers, a list of all keys and certs
 * found in a specific provider, or a list of providers that hold a given
 * key name or cert id.
 * If cng-provider and one of cng-keyname or cng-certid are given, STORE_load
 * will return the contents of the indicated object (one or more PKEY or CERT
 * objects).
 */

/* Base support functions */

/* The loader functions */

struct store_lookup_info_st {
    char *provider;
    char *store;
    char *keyname;               /* When looking for a key */
    char *certid;                /* When looking for a cert */
};
struct store_loader_ctx_st {
    struct store_lookup_info_st info;
    const STORE_LOADER *loader;

    void *data;
    STACK_OF(STORE_LOOKUP_FNS) *meths;

    int errcnt;
};

/* Key loader */
struct store_key_data_st {
    struct store_lookup_info_st info;
    int errcnt;
    STORE_LOADER_CTX *loader_ctx;
    NCRYPT_PROV_HANDLE phandle;
    NCRYPT_KEY_HANDLE khandle;
};
static void *cng_store_get_keys_init(STORE_LOADER_CTX *ctx)
{
    struct store_key_data_st *ret = NULL;
    void *provider = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL
        || (provider = to_wide(ctx->info.provider)) == NULL) {
        goto err;
    }
    if (NCryptOpenStorageProvider(&ret->phandle, provider, 0)
        != ERROR_SUCCESS) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_GET_KEYS_INIT,
               CNG_R_NCRYPTOPENSTORAGEPROVIDER_ERROR);
        cng_adderror(err);
        goto err;
    }
    OPENSSL_free(provider);

    ret->info = ctx->info;
    ret->loader_ctx = ctx;

    return ret;
 err:
    OPENSSL_free(ret);
    OPENSSL_free(provider);
    return NULL;
}
static int cng_store_get_keys_eof(void *lookup_ctx)
{
    struct store_key_data_st *lctx = lookup_ctx;

    /* If we already loaded the available key... */
    return lctx->khandle != 0;
}
static int cng_store_get_keys_error(void *lookup_ctx)
{
    struct store_key_data_st *lctx = lookup_ctx;

    return lctx->errcnt > 0;
}
static STORE_INFO *cng_store_get_keys_load(void *lookup_ctx)
{
    struct store_key_data_st *lctx = lookup_ctx;
    void *keyname = NULL;
    EVP_PKEY *pkey = NULL;
    STORE_INFO *res = NULL;

    if (cng_store_get_keys_error(lctx) || cng_store_get_keys_eof(lctx))
        return NULL;

    if ((keyname = to_wide(lctx->info.provider)) == NULL)
        goto err;

    /*
     * TODO: The last parameter is dwFlags, and can have NCRYPT_MACHINE_KEY_FLAG
     * and NCRYPT_SILENT_FLAG.  Should any of them be set?
     */
    if (NCryptOpenKey(lctx->phandle, &lctx->khandle, keyname, 0, 0)
        != ERROR_SUCCESS) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_GET_KEYS_LOAD, CNG_R_NCRYPTOPENKEY_ERROR);
        cng_adderror(err);
        goto err;
    }

    if ((pkey = cng_get_pkey(STORE_LOADER_get0_engine(lctx->loader_ctx->loader),
                             lctx->khandle)) == NULL
        || (res = STORE_INFO_new_PKEY(pkey)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_GET_KEYS_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    OPENSSL_free(keyname);
    return res;
 err:
    lctx->errcnt++;
    OPENSSL_free(keyname);
    STORE_INFO_free(res);
    return NULL;
}
static int cng_store_get_keys_clean(void *lookup_ctx)
{
    struct store_key_data_st *lctx = lookup_ctx;

    NCryptFreeObject(lctx->khandle);
    NCryptFreeObject(lctx->phandle);
    OPENSSL_free(lookup_ctx);
    return 1;
}
static const struct store_lookup_fns_st cng_store_get_keys = {
    cng_store_get_keys_init,
    cng_store_get_keys_load,
    cng_store_get_keys_eof,
    cng_store_get_keys_error,
    cng_store_get_keys_clean
};

/* Key enumerator */
struct store_key_lookup_st {
    struct store_lookup_info_st info;
    int errcnt;
    int eof_reached;
    NCRYPT_PROV_HANDLE phandle;
    void *enum_state;
};
static void *cng_store_enum_keys_init(STORE_LOADER_CTX *ctx)
{
    struct store_key_lookup_st *ret = NULL;
    void *provider = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL
        || (provider = to_wide(ctx->info.provider)) == NULL) {
        goto err;
    }
    if (NCryptOpenStorageProvider(&ret->phandle, provider, 0)
        != ERROR_SUCCESS) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_ENUM_KEYS_INIT,
               CNG_R_NCRYPTOPENSTORAGEPROVIDER_ERROR);
        cng_adderror(err);
        goto err;
    }
    OPENSSL_free(provider);

    ret->info = ctx->info;

    return ret;
 err:
    OPENSSL_free(ret);
    OPENSSL_free(provider);
    return NULL;
}
static int cng_store_enum_keys_eof(void *lookup_ctx)
{
    struct store_key_lookup_st *lctx = lookup_ctx;

    return lctx->eof_reached;
}
static int cng_store_enum_keys_error(void *lookup_ctx)
{
    struct store_key_lookup_st *lctx = lookup_ctx;

    return lctx->errcnt > 0;
}
static STORE_INFO *cng_store_enum_keys_load(void *lookup_ctx)
{
    struct store_key_lookup_st *lctx = lookup_ctx;
    NCryptKeyName *keyname = NULL;
    char *name = NULL;
    STORE_INFO *ret = NULL;

    if (cng_store_enum_keys_error(lctx) || cng_store_enum_keys_eof(lctx))
        return NULL;

    switch (NCryptEnumKeys(lctx->phandle, NULL, &keyname, &lctx->enum_state,
                           0)) {
    case ERROR_SUCCESS:
        break;
    case NTE_NO_MORE_ITEMS:
        NCryptFreeBuffer(lctx->enum_state);
        lctx->eof_reached = 1;
        return NULL;
    default:
        {
            int err = GetLastError();

            CNGerr(CNG_F_CNG_STORE_ENUM_KEYS_LOAD, CNG_R_NCRYPTENUMKEYS_ERROR);
            cng_adderror(err);
        }
        lctx->errcnt++;
        goto err;
    }

    if ((name = url_encode(to_asc(keyname->pszName), 1)) == NULL
        || (ret = STORE_INFO_new_NAME(name)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_ENUM_KEYS_LOAD, ERR_R_MALLOC_FAILURE);
        lctx->errcnt++;
        goto err;
    }

    NCryptFreeBuffer(keyname);
    return ret;
 err:
    return NULL;
}
static int cng_store_enum_keys_clean(void *lookup_ctx)
{
    struct store_key_lookup_st *lctx = lookup_ctx;

    NCryptFreeObject(lctx->phandle);
    OPENSSL_free(lookup_ctx);
    return 1;
}
static const struct store_lookup_fns_st cng_store_enum_keys = {
    cng_store_enum_keys_init,
    cng_store_enum_keys_load,
    cng_store_enum_keys_eof,
    cng_store_enum_keys_error,
    cng_store_enum_keys_clean
};

/* Provider enumerator */
struct store_provider_lookup_st {
    int errcnt;
    NCryptProviderName *key_providers;
    DWORD key_provider_count;
    DWORD current_key_provider;
};
static void *cng_store_enum_providers_init(STORE_LOADER_CTX *ctx)
{
    struct store_provider_lookup_st *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        CNGerr(CNG_F_CNG_STORE_ENUM_PROVIDERS_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (NCryptEnumStorageProviders(&ret->key_provider_count,
                                   &ret->key_providers, 0) != ERROR_SUCCESS) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_ENUM_PROVIDERS_INIT,
               CNG_R_NCRYPTENUMSTORAGEPROVIDERS_ERROR);
        cng_adderror(err);
        goto err;
    }

    return ret;
 err:
    OPENSSL_free(ret);
    return NULL;
}
static int cng_store_enum_providers_eof(void *lookup_ctx)
{
    struct store_provider_lookup_st *lctx = lookup_ctx;

    return lctx->current_key_provider == lctx->key_provider_count;
}
static int cng_store_enum_providers_error(void *lookup_ctx)
{
    struct store_provider_lookup_st *lctx = lookup_ctx;

    return lctx->errcnt > 0;
}
static STORE_INFO *cng_store_enum_providers_load(void *lookup_ctx)
{
    struct store_provider_lookup_st *lctx = lookup_ctx;
    char *name = NULL;
    char *info = NULL;
    NCryptProviderName *providername = NULL;

    if (cng_store_enum_providers_error(lctx)
        || cng_store_enum_providers_eof(lctx))
        return NULL;

    providername = &lctx->key_providers[lctx->current_key_provider++];

    name = url_encode(to_asc(providername->pszName), 1);
    if (providername->pszComment != NULL)
        info = to_asc(providername->pszComment);

    if (name != NULL) {
        char *uri = NULL;
        size_t urilen = 4        /* "cng:" */
            + 9                  /* "provider=" */
            + strlen(name)       /* name */
            + 1;                 /* NUL */
        STORE_INFO *ret = NULL;

        if ((uri = OPENSSL_malloc(urilen)) == NULL)
            goto memerr;
        OPENSSL_strlcpy(uri, "cng:", urilen);
        OPENSSL_strlcat(uri, "provider=", urilen);
        OPENSSL_strlcat(uri, name, urilen);

        if ((ret = STORE_INFO_new_NAME(uri)) == NULL
            || (info != NULL && !STORE_INFO_set0_NAME_description(ret, info)))
            goto memerr;

        return ret;
    }

 memerr:
    lctx->errcnt++;
    OPENSSL_free(name);
    OPENSSL_free(info);
    CNGerr(CNG_F_CNG_STORE_ENUM_PROVIDERS_LOAD, ERR_R_MALLOC_FAILURE);
    return NULL;
}
static int cng_store_enum_providers_clean(void *lookup_ctx)
{
    struct store_provider_lookup_st *lctx = lookup_ctx;

    NCryptFreeBuffer(lctx->key_providers);
    return 1;
}
static const struct store_lookup_fns_st cng_store_enum_providers = {
    cng_store_enum_providers_init,
    cng_store_enum_providers_load,
    cng_store_enum_providers_eof,
    cng_store_enum_providers_error,
    cng_store_enum_providers_clean
};

/* Cert loader */
struct store_cert_data_st {
    struct store_lookup_info_st info;
    int errcnt;
    int eof_reached;
    HCERTSTORE shandle;
    PCCERT_CONTEXT cert_ctx;
    CERT_ID criterium;
};
static void *cng_store_get_certs_init(STORE_LOADER_CTX *ctx)
{
    struct store_cert_data_st *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        CNGerr(CNG_F_CNG_STORE_GET_CERTS_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((ret->shandle = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                      CERT_SYSTEM_STORE_CURRENT_USER,
                                      ctx->info.store)) == NULL
        && (ret->shandle = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                         CERT_SYSTEM_STORE_LOCAL_MACHINE,
                                         ctx->info.store)) == NULL) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_GET_CERTS_INIT, CNG_R_CERTOPENSTORE_ERROR);
        cng_adderror(err);
        goto err;
    }

    ret->info = ctx->info;
    ret->criterium.HashId.pbData =
        OPENSSL_hexstr2buf(ctx->info.certid,
                           (long *)&ret->criterium.HashId.cbData);
    if (ret->criterium.HashId.pbData == NULL
        || ret->criterium.HashId.cbData != 20) {
        CNGerr(CNG_F_CNG_STORE_GET_CERTS_INIT, CNG_R_BAD_CERT_ID);
        goto err;
    }
    ret->criterium.dwIdChoice = CERT_ID_SHA1_HASH;

    return ret;
 err:
    if (ret != NULL)
        OPENSSL_free(ret->criterium.HashId.pbData);
    OPENSSL_free(ret);
    return NULL;
}
static int cng_store_get_certs_eof(void *lookup_ctx)
{
    struct store_cert_data_st *lctx = lookup_ctx;

    return lctx->eof_reached;
}
static int cng_store_get_certs_error(void *lookup_ctx)
{
    struct store_cert_data_st *lctx = lookup_ctx;

    return lctx->errcnt > 0;
}
static STORE_INFO *cng_store_get_certs_load(void *lookup_ctx)
{
    struct store_cert_data_st *lctx = lookup_ctx;
    X509 *x = NULL;
    const unsigned char *p;
    STORE_INFO *ret = NULL;

    if (cng_store_get_certs_error(lctx) || cng_store_get_certs_eof(lctx))
        return NULL;

    lctx->cert_ctx = CertFindCertificateInStore(lctx->shandle,
                                                X509_ASN_ENCODING, 0,
                                                CERT_FIND_CERT_ID,
                                                &lctx->criterium,
                                                lctx->cert_ctx);

    if (lctx->cert_ctx == NULL) {
        lctx->eof_reached = 1;
        return NULL;
    }

    p = lctx->cert_ctx->pbCertEncoded;
    if ((x = d2i_X509(NULL, &p, lctx->cert_ctx->cbCertEncoded)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_GET_CERTS_LOAD, CNG_R_CAN_NOT_PARSE_CERTIFICATE);
        goto err;
    }

    if ((ret = STORE_INFO_new_CERT(x)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_GET_CERTS_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return ret;
 err:
    lctx->errcnt++;
    X509_free(x);
    return NULL;
}
static int cng_store_get_certs_clean(void *lookup_ctx)
{
    struct store_cert_data_st *lctx = lookup_ctx;

    OPENSSL_free(lctx->criterium.HashId.pbData);
    OPENSSL_free(lookup_ctx);
    return 1;
}
static const struct store_lookup_fns_st cng_store_get_certs = {
    cng_store_get_certs_init,
    cng_store_get_certs_load,
    cng_store_get_certs_eof,
    cng_store_get_certs_error,
    cng_store_get_certs_clean
};

/* Cert enumerator */
struct store_cert_lookup_st {
    struct store_lookup_info_st info;
    int errcnt;
    int eof_reached;
    HCERTSTORE shandle;
    PCCERT_CONTEXT cert_ctx;
};
static void *cng_store_enum_certs_init(STORE_LOADER_CTX *ctx)
{
    struct store_cert_lookup_st *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((ret->shandle = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                      CERT_SYSTEM_STORE_CURRENT_USER,
                                      ctx->info.store)) == NULL
        && (ret->shandle = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                         CERT_SYSTEM_STORE_LOCAL_MACHINE,
                                         ctx->info.store)) == NULL) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_INIT, CNG_R_CERTOPENSTORE_ERROR);
        cng_adderror(err);
        goto err;
    }

    ret->info = ctx->info;

    return ret;
 err:
    OPENSSL_free(ret);
    return NULL;
}
static int cng_store_enum_certs_eof(void *lookup_ctx)
{
    struct store_cert_lookup_st *lctx = lookup_ctx;

    return lctx->eof_reached;
}
static int cng_store_enum_certs_error(void *lookup_ctx)
{
    struct store_cert_lookup_st *lctx = lookup_ctx;

    return lctx->errcnt > 0;
}
static STORE_INFO *cng_store_enum_certs_load(void *lookup_ctx)
{
    struct store_cert_lookup_st *lctx = lookup_ctx;
    void *cert_id_buf = NULL;
    DWORD cert_id_size = 0;
    char *uri = NULL;
    size_t urilen;
    STORE_INFO *ret = NULL;

    if (cng_store_enum_certs_error(lctx) || cng_store_enum_certs_eof(lctx))
        return NULL;

    lctx->cert_ctx = CertEnumCertificatesInStore(lctx->shandle, lctx->cert_ctx);
    if (lctx->cert_ctx == NULL) {
        lctx->eof_reached = 1;
        return NULL;
    }

    if (!CertGetCertificateContextProperty(lctx->cert_ctx, CERT_HASH_PROP_ID,
                                           cert_id_buf, &cert_id_size)) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_LOAD,
               CNG_R_CERTGETCERTIFICATECONTEXTPROPERTY_ERROR);
        cng_adderror(err);
        goto err;
    }
    if ((cert_id_buf = OPENSSL_zalloc(cert_id_size)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!CertGetCertificateContextProperty(lctx->cert_ctx, CERT_HASH_PROP_ID,
                                           cert_id_buf, &cert_id_size)) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_LOAD,
               CNG_R_CERTGETCERTIFICATECONTEXTPROPERTY_ERROR);
        cng_adderror(err);
        goto err;
    }

    urilen = 4                   /* "cng:" */
        + 6                      /* "store=" */
        + strlen(lctx->info.store)
        + 1                      /* ";" */
        + 7                      /* "certid=" */
        + cert_id_size * 2
        + 1;                     /* NUL */
    if ((uri = OPENSSL_zalloc(urilen)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    OPENSSL_strlcpy(uri, "cng:store=", urilen);
    OPENSSL_strlcat(uri, lctx->info.store, urilen);
    OPENSSL_strlcat(uri, ";certid=", urilen);
    hex_encode_inline(uri + strlen(uri), cert_id_buf, cert_id_size);

    OPENSSL_free(cert_id_buf);
    cert_id_buf = NULL;

    if ((ret = STORE_INFO_new_NAME(uri)) == NULL) {
        CNGerr(CNG_F_CNG_STORE_ENUM_CERTS_LOAD, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return ret;
 err:
    lctx->errcnt++;
    OPENSSL_free(uri);
    OPENSSL_free(cert_id_buf);
    return NULL;
}
static int cng_store_enum_certs_clean(void *lookup_ctx)
{
    OPENSSL_free(lookup_ctx);
    return 1;
}
static const struct store_lookup_fns_st cng_store_enum_certs = {
    cng_store_enum_certs_init,
    cng_store_enum_certs_load,
    cng_store_enum_certs_eof,
    cng_store_enum_certs_error,
    cng_store_enum_certs_clean
};

/* Store enumerator */
struct store_store_lookup_st {
    int errcnt;
    STACK_OF(LPWSTR) *cert_stores;
    LPWSTR last_cert_store;        /* To check for duplicates */
};
static void free_cert_store(LPWSTR cert_store)
{
    OPENSSL_free(cert_store);
}
static int cmp_cert_store(const WCHAR * const *a, const WCHAR * const *b)
{
    return wcscmp(*a, *b);
}
static BOOL WINAPI cng_store_enum_stores_init_cb(const void *systemstore,
                                                 DWORD flags,
                                                 PCERT_SYSTEM_STORE_INFO si,
                                                 void *reserved,
                                                 void *cb_arg)
{
    STACK_OF(LPWSTR) *names = cb_arg;
    LPWSTR storename = NULL;

    if ((storename = OPENSSL_memdup(systemstore,
                                    (wcslen((LPCWSTR)systemstore) + 1)
                                    * sizeof(WCHAR))) == NULL
        || sk_LPWSTR_push(names, storename) == 0) {
        OPENSSL_free(storename);
        return FALSE;
    }
    return TRUE;
}
static void *cng_store_enum_stores_init(STORE_LOADER_CTX *ctx)
{
    struct store_store_lookup_st *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL
        || (ret->cert_stores = sk_LPWSTR_new(cmp_cert_store)) == NULL
        /* Find the usual cert stores */
        || !CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL,
                                ret->cert_stores,
                                cng_store_enum_stores_init_cb)
        || !CertEnumSystemStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL,
                                ret->cert_stores,
                                cng_store_enum_stores_init_cb)) {
        CNGerr(CNG_F_CNG_STORE_ENUM_STORES_INIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    sk_LPWSTR_sort(ret->cert_stores);
    return ret;
 err:
    if (ret != NULL)
        sk_LPWSTR_pop_free(ret->cert_stores, free_cert_store);
    OPENSSL_free(ret);
    return NULL;
}
static int cng_store_enum_stores_eof(void *lookup_ctx)
{
    struct store_store_lookup_st *lctx = lookup_ctx;

    return sk_LPWSTR_num(lctx->cert_stores) == 0;
}
static int cng_store_enum_stores_error(void *lookup_ctx)
{
    struct store_store_lookup_st *lctx = lookup_ctx;

    return lctx->errcnt > 0;
}
static STORE_INFO *cng_store_enum_stores_load(void *lookup_ctx)
{
    struct store_store_lookup_st *lctx = lookup_ctx;
    char *name = NULL;
    char *info = NULL;
    STORE_INFO *ret = NULL;

    if (cng_store_enum_stores_error(lctx) || cng_store_enum_stores_eof(lctx))
        return NULL;

    while (sk_LPWSTR_num(lctx->cert_stores) > 0) {
        LPWSTR wstr = sk_LPWSTR_shift(lctx->cert_stores);

        if (lctx->last_cert_store != NULL
            && wcscmp(lctx->last_cert_store, wstr) == 0)
            continue;

        OPENSSL_free(lctx->last_cert_store);
        lctx->last_cert_store = wstr;
        if ((name = url_encode(to_asc(wstr), 1)) == NULL)
            goto memerr;
        break;
    }

    if (name != NULL) {
        char *uri = NULL;
        size_t urilen = 4        /* "cng:" */
            + 6                  /* "store=" */
            + strlen(name)       /* name */
            + 1;                 /* NUL */

        if ((uri = OPENSSL_malloc(urilen)) == NULL)
            goto memerr;
        OPENSSL_strlcpy(uri, "cng:", urilen);
        OPENSSL_strlcat(uri, "store=", urilen);
        OPENSSL_strlcat(uri, name, urilen);

        if ((ret = STORE_INFO_new_NAME(uri)) == NULL
            || (info != NULL && !STORE_INFO_set0_NAME_description(ret, info)))
            goto memerr;
    }

    return ret;
 memerr:
    lctx->errcnt++;
    OPENSSL_free(name);
    OPENSSL_free(info);
    CNGerr(CNG_F_CNG_STORE_ENUM_STORES_LOAD, ERR_R_MALLOC_FAILURE);
    return NULL;
}
static int cng_store_enum_stores_clean(void *lookup_ctx)
{
    struct store_store_lookup_st *ctx = lookup_ctx;

    sk_LPWSTR_pop_free(ctx->cert_stores, free_cert_store);
    return 1;
}
static const struct store_lookup_fns_st cng_store_enum_stores = {
    cng_store_enum_stores_init,
    cng_store_enum_stores_load,
    cng_store_enum_stores_eof,
    cng_store_enum_stores_error,
    cng_store_enum_stores_clean
};

static STORE_LOADER_CTX *cng_store_open(const STORE_LOADER *loader,
                                        const char *uri, const UI_METHOD *uim,
                                        void *uid)
{
    const char *path = NULL;
    STORE_LOADER_CTX *ctx = NULL;

    OPENSSL_assert(_strnicmp(uri, "cng:", 4) == 0);

    if (strncmp(&uri[4], "//localhost/", 12) == 0) {
        uri = &uri[16];
    } else if (strncmp(&uri[4], "///", 3) == 0) {
        uri = &uri[7];
    } else if (strncmp(&uri[4], "//", 2) != 0) {
        uri = &uri[4];
    } else {
        CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_URI_AUTHORITY_UNSUPPORED);
        return NULL;
    }

    for (path = uri; *path != '\0' && *path != '?' && *path != '#'; path++)
        ;
    if (*path == '?') {
        CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_URI_QUERY_UNSUPPORED);
        goto err;
    }
    if (*path == '#') {
        CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_URI_FRAGMENT_UNSUPPORED);
        goto err;
    }
    if (*path != '\0') {
        CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_EMPTY_URI);
        goto err;
    }

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        CNGerr(CNG_F_CNG_STORE_OPEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    path = uri;
    while (*path != '\0') {
        const char *key = path;
        const char *val = NULL;
        char **valp = NULL;

        while (*path != '=' && *path != '\0')
            path++;
        if (path == key) {
            CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_EMPTY_KEY);
            goto err;
        }
        if (*path == '\0') {
            CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_UNASSIGNED_KEY);
            ERR_add_error_data(2, "Key=", key);
            goto err;
        }
        val = ++path;
        while (*path != ';' && *path != '\0')
            path++;
        if (path == key) {
            CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_EMPTY_VALUE);
            goto err;
        }

        if (strncmp(key, "provider=", 9) == 0)
            valp = &ctx->info.provider;
        else if (strncmp(key, "store=", 6) == 0)
            valp = &ctx->info.store;
        else if (strncmp(key, "keyname=", 8) == 0)
            valp = &ctx->info.keyname;
        else if (strncmp(key, "certid=", 7) == 0)
            valp = &ctx->info.certid;

        if (valp == NULL) {
            CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_UNKNOWN_KEY);
            ERR_add_error_data(2, "Key=", key);
            goto err;
        }
        if (valp != NULL && *valp != NULL) {
            CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_DUPLICATE_KEY);
            ERR_add_error_data(2, "Key=", key);
            goto err;
        }
        {
            char *duplicate = NULL;

            if ((duplicate = OPENSSL_strndup(val, path - val)) == NULL) {
                CNGerr(CNG_F_CNG_STORE_OPEN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if ((*valp = url_decode(duplicate)) == NULL) {
                OPENSSL_free(duplicate);
                CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_BAD_URL_ENCODING);
                ERR_add_error_data(2, "Value=", duplicate);
                goto err;
            }
        }

        if (*path == ';')
            path++;

    }

    if ((ctx->meths = sk_STORE_LOOKUP_FNS_new_null()) == NULL) {
        CNGerr(CNG_F_CNG_STORE_OPEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (ctx->info.provider != NULL) {
        if (ctx->info.keyname != NULL) {
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_get_keys);
        } else {
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_enum_keys);
        }
    } else {
        if (ctx->info.keyname != NULL) {
# if 0                           /* To be supported */
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_enum_key_providers);
# endif
        } else if (ctx->info.store == NULL) {
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_enum_providers);
        }
    }
    if (ctx->info.store != NULL) {
        if (ctx->info.certid != NULL) {
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_get_certs);
        } else {
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_enum_certs);
        }
    } else {
        if (ctx->info.certid != NULL) {
# if 0                           /* To be supported */
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_enum_cert_stores);
# endif
        } else if (ctx->info.provider == NULL) {
            sk_STORE_LOOKUP_FNS_push(ctx->meths, &cng_store_enum_stores);
        }
    }

    if (sk_STORE_LOOKUP_FNS_num(ctx->meths) == 0) {
        CNGerr(CNG_F_CNG_STORE_OPEN, CNG_R_NOT_YET_SUPPORTED);
        goto err;
    }

    ctx->loader = loader;

    return ctx;
 err:
    if (ctx != NULL) {
        sk_STORE_LOOKUP_FNS_free(ctx->meths);
        OPENSSL_free(ctx->info.provider);
        OPENSSL_free(ctx->info.store);
        OPENSSL_free(ctx->info.keyname);
        OPENSSL_free(ctx->info.certid);
    }
    OPENSSL_free(ctx);
    return NULL;
}

int cng_store_eof(STORE_LOADER_CTX *ctx);
int cng_store_error(STORE_LOADER_CTX *ctx);
static STORE_INFO *cng_store_load(STORE_LOADER_CTX *ctx,
                                  const UI_METHOD *ui_method, void *ui_data)
{
    STORE_INFO *ret = NULL;

 again:
    if (!cng_store_eof(ctx) && !cng_store_error(ctx)) {
        const STORE_LOOKUP_FNS *meth = sk_STORE_LOOKUP_FNS_value(ctx->meths, 0);

        if (ctx->data == NULL) {
            if ((ctx->data = meth->init(ctx)) == NULL) {
                CNGerr(CNG_F_CNG_STORE_LOAD, ERR_R_MALLOC_FAILURE);
                ctx->errcnt++;
                return NULL;
            }
        }

        STORE_INFO_free(ret);
        if ((ret = meth->load(ctx->data)) == NULL) {
            if (meth->error(ctx->data))
                ctx->errcnt++;
            if (!meth->clean(ctx->data)) {
                STORE_INFO_free(ret);
                ctx->errcnt++;
            }
            if (cng_store_error(ctx))
                return NULL;

            /* OK, we reached EOF for this method, time to try the next */
            ctx->data = NULL;
            (void)sk_STORE_LOOKUP_FNS_shift(ctx->meths);
            goto again;
        }

    }
    return ret;
}

int cng_store_eof(STORE_LOADER_CTX *ctx)
{
    return sk_STORE_LOOKUP_FNS_num(ctx->meths) == 0;
}

int cng_store_error(STORE_LOADER_CTX *ctx)
{
    return ctx->errcnt > 0;
}

int cng_store_close(STORE_LOADER_CTX *ctx)
{
    OPENSSL_free(ctx);
    return 1;
}

static STORE_LOADER *cng_store_new(ENGINE *e)
{
    STORE_LOADER *res = NULL;

    if ((res = STORE_LOADER_new(e, cng_scheme)) == NULL
        || !STORE_LOADER_set_open(res, cng_store_open)
        || !STORE_LOADER_set_load(res, cng_store_load)
        || !STORE_LOADER_set_eof(res, cng_store_eof)
        || !STORE_LOADER_set_error(res, cng_store_error)
        || !STORE_LOADER_set_close(res, cng_store_close)) {
        CNGerr(CNG_F_CNG_STORE_NEW, ERR_R_MALLOC_FAILURE);
        STORE_LOADER_free(res);
        res = NULL;
    }
    return res;
}

static void cng_store_free(STORE_LOADER *loader)
{
    STORE_LOADER_free(loader);
}

/*-
 * INIT / FINISH
 * -------------
 */

static int cng_init(ENGINE *e)
{
    return 1;
}

static int cng_finish(ENGINE *e)
{
    return 1;
}

/*-
 * LOAD / UNLOAD
 * -------------
 */

static int cng_destroy(ENGINE *e)
{
    STORE_LOADER *loader = ENGINE_get_ex_data(e, loader_idx);

    STORE_unregister_loader(cng_scheme);
    cng_store_free(loader);
    /* Why is there no ENGINE_free_ex_index() et al??? */
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_ENGINE, loader_idx);
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_idx);
    ERR_unload_CNG_strings();
    return 1;
}

static int bind_cng(ENGINE *e)
{
    STORE_LOADER *loader = NULL;
    /* Ensure the afalg error handling is set up */
    ERR_load_CNG_strings();

    if (!ENGINE_set_id(e, cng_id)
        || !ENGINE_set_name(e, cng_name)
        || !ENGINE_set_destroy_function(e, cng_destroy)
        || !ENGINE_set_init_function(e, cng_init)
        || !ENGINE_set_finish_function(e, cng_finish)
        || (loader_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0)) < 0
        || (rsa_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0)) < 0
        || (loader = cng_store_new(e)) == NULL
        || !STORE_register_loader(loader)) {
        CNGerr(CNG_F_BIND_CNG, CNG_R_BIND_FAILED);
        cng_store_free(loader);
        cng_destroy(e);
        return 0;
    }

    ENGINE_set_ex_data(e, loader_idx, loader);

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, cng_id) != 0))
        return 0;

    return bind_cng(e);
}
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# else
void engine_load_cng_int(void)
{
    ENGINE *toadd;

    /* Possible checks to add here */

    if ((toadd = ENGINE_new()) == NULL
        || !bind_cng(toadd)) {
        ENGINE_free(toadd);
        return NULL;
    }
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
# endif

/*-
 * Utility functions
 * -----------------
 */

static const char hexdig[] =
    "0123456789abcdef";

static size_t hex_encode_inline(char *dst, char *src, size_t src_len)
{
    size_t cnt = 0;

    while (src_len-- > 0) {
        *dst++ = hexdig[(*src >> 4) & 0xf];
        *dst++ = hexdig[*src & 0xf];
        cnt += 2;
        src++;
    }

    return cnt;
}

static char *url_decode(char *str)
{
    char *p1 = str, *p2 = str;

    while (*p2 != '\0') {
        if (*p2 != '%') {
            *p1++ = *p2++;
        } else {
            int h1 = OPENSSL_hexchar2int(*++p2);
            int h2 = OPENSSL_hexchar2int(*++p2);

            if (h1 < 0 || h2 < 0)
                return NULL;
            *p1++ = (char)((h1 << 4) | h2);
            p2++;
        }
    }

    *p1++ = *p2++;               /* Copy the NUL byte */

    return str;
}

static const char unreserved[] =
    "0123456789-_.~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const char reserved[] =
    "!*'();:@&=+$,/?#[]";

static char *url_encode(char *str, int encode_reserved)
{
    /* Worst case scenario, we need 3 chars per byte */
    char *new = OPENSSL_zalloc((strlen(str) + 1) * 3);
    char *p1 = new, *p2 = str;

    if (new == NULL)
        return NULL;

    while (*p2 != '\0') {
        if (strchr(unreserved, *p2) == NULL
            && (encode_reserved || strchr(reserved, *p2) == NULL)) {
            *p1++ = '%';
            p1 += hex_encode_inline(p1, p2++, 1);
        } else {
            *p1++ = *p2++;
        }
    }
    *p1++ = '\0';

    return new;
}

static void cng_adderror(DWORD err)
{
    char errstr[20];

    BIO_snprintf(errstr, sizeof(errstr), "%lX", err);
    ERR_add_error_data(2, "Error code=0x", errstr);
}

static CNG_CTX *cng_ctx_new(void)
{
    return OPENSSL_zalloc(sizeof(CNG_CTX));
}

static void cng_ctx_free(CNG_CTX *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->khandle != 0)
        NCryptFreeObject(ctx->khandle);
    OPENSSL_free(ctx);
}

static char *to_asc(LPCWSTR in)
{
    char *str;
    int outsize;

    outsize = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
    if (outsize == 0) {
        int err = GetLastError();

        CNGerr(CNG_F_TO_ASC,CNG_R_WIDECHARTOMULTIBYTE_ERROR);
        cng_adderror(err);
        return NULL;
    }
    str = OPENSSL_malloc(outsize);
    if (str == NULL) {
        CNGerr(CNG_F_TO_ASC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!WideCharToMultiByte(CP_UTF8, 0, in, -1, str, outsize, NULL, NULL)) {
        int err = GetLastError();

        OPENSSL_free(str);
        CNGerr(CNG_F_TO_ASC,CNG_R_WIDECHARTOMULTIBYTE_ERROR);
        cng_adderror(err);
        return NULL;
    }
    return str;
}

static LPWSTR to_wide(const char *in)
{
    LPWSTR str;
    int outsize;

    outsize = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    if (outsize == 0) {
        int err = GetLastError();

        CNGerr(CNG_F_TO_WIDE,CNG_R_MULTIBYTETOWIDECHAR_ERROR);
        cng_adderror(err);
        return NULL;
    }
    str = OPENSSL_malloc(outsize * sizeof(WCHAR));
    if (str == NULL) {
        CNGerr(CNG_F_TO_WIDE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!MultiByteToWideChar(CP_UTF8, 0, in, -1, str, outsize)) {
        int err = GetLastError();

        OPENSSL_free(str);
        CNGerr(CNG_F_TO_WIDE,CNG_R_MULTIBYTETOWIDECHAR_ERROR);
        cng_adderror(err);
        return NULL;
    }
    return str;
}

static EVP_PKEY *cng_get_pkey(const ENGINE *engine, NCRYPT_KEY_HANDLE khandle)
{
    union {
        BCRYPT_KEY_BLOB info;
        BCRYPT_DH_KEY_BLOB dh;
        BCRYPT_DSA_KEY_BLOB dsa;
# if _WIN32_WINNT >= 0x0602      /* Win 8 */
        BCRYPT_DSA_KEY_BLOB_V2 dsa2;
# endif
        BCRYPT_ECCKEY_BLOB ecc;
        BCRYPT_RSAKEY_BLOB rsa;
        unsigned char data[1];   /* Used to reach the data after the blobs */
    } *exported = NULL;
    DWORD size;
    EVP_PKEY *res = NULL;

    if (NCryptExportKey(khandle, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL, NULL, 0,
                        &size, 0) != ERROR_SUCCESS) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_NCRYPTEXPORTKEY_ERROR);
        cng_adderror(err);
        goto err;
    }
    if ((exported = OPENSSL_zalloc(size)) == NULL) {
        CNGerr(CNG_F_CNG_GET_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (NCryptExportKey(khandle, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL,
                        (PBYTE)exported, size, NULL, 0) != ERROR_SUCCESS) {
        int err = GetLastError();

        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_NCRYPTEXPORTKEY_ERROR);
        cng_adderror(err);
        goto err;
    }
    switch (exported->info.Magic) {
    case BCRYPT_DH_PUBLIC_MAGIC:
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_TEMPORARLY_UNSUPPORTED_KEY_TYPE);
        {
            char keytypestr[20];
            BIO_snprintf(keytypestr, 19, "%lX", exported->info.Magic);
            ERR_add_error_data(2, "Magic=0x", keytypestr);
        }
        break;
    case BCRYPT_DSA_PUBLIC_MAGIC:
        if (exported->dsa.cbKey >= 512 / 8 && exported->dsa.cbKey <= 1024 / 8) {
            /* BCRYPT_DSA_KEY_BLOB */
# if _WIN32_WINNT >= _WIN32_WINNT_WIN8
        } else if  (exported->dsa.cbKey > 1024 / 8
                    && exported->dsa.cbKey <= 3072 / 8) {
            /* BCRYPT_DSA_KEY_BLOB_V2 */
# endif
        } else {
            /* WHAT??? */
        }
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_TEMPORARLY_UNSUPPORTED_KEY_TYPE);
        {
            char keytypestr[20];
            BIO_snprintf(keytypestr, 19, "%lX", exported->info.Magic);
            ERR_add_error_data(2, "Magic=0x", keytypestr);
        }
        break;
    case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
    case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
    case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
    case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
    case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
    case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_TEMPORARLY_UNSUPPORTED_KEY_TYPE);
        {
            char keytypestr[20];
            BIO_snprintf(keytypestr, 19, "%lX", exported->info.Magic);
            ERR_add_error_data(2, "Magic=0x", keytypestr);
        }
        break;
    case BCRYPT_RSAPUBLIC_MAGIC:
        {
            size_t off_e = sizeof(exported->rsa);
            size_t off_n = off_e + exported->rsa.cbPublicExp;
            BIGNUM *e = NULL;
            BIGNUM *n = NULL;
            RSA *rsa = NULL;
            CNG_CTX *ctx = NULL;

            if ((e = BN_bin2bn(&exported->data[off_e],
                               exported->rsa.cbPublicExp,
                               NULL)) == NULL
                || (n = BN_bin2bn(&exported->data[off_n],
                                  exported->rsa.cbModulus,
                                  NULL)) == NULL) {
                CNGerr(CNG_F_CNG_GET_PKEY, ERR_R_BN_LIB);
                goto rsaerr;
            }
            /* RSA_new_method should take a const ENGINE * */
            if ((rsa = RSA_new_method((ENGINE *)engine)) == NULL
                || !RSA_set0_key(rsa, n, e, NULL)) {
                CNGerr(CNG_F_CNG_GET_PKEY, ERR_R_RSA_LIB);
                goto rsaerr;
            }
            if ((ctx = cng_ctx_new()) == NULL) {
                CNGerr(CNG_F_CNG_GET_PKEY, ERR_R_MALLOC_FAILURE);
                goto rsaerr;
            }
            ctx->khandle = khandle;
            RSA_set_ex_data(rsa, rsa_idx, ctx);
            if ((res = EVP_PKEY_new()) == NULL
                || !EVP_PKEY_set1_RSA(res, rsa)) {
                CNGerr(CNG_F_CNG_GET_PKEY, ERR_R_EVP_LIB);
                goto rsaerr;
            }
            break;

         rsaerr:
            cng_ctx_free(ctx);
            EVP_PKEY_free(res);
            RSA_free(rsa);
            BN_free(n);
            BN_free(e);
            res = NULL;
        }
        break;
    default:
        CNGerr(CNG_F_CNG_GET_PKEY, CNG_R_UNSUPPORTED_KEY_TYPE);
        {
            char keytypestr[20];
            BIO_snprintf(keytypestr, 19, "%lX", exported->info.Magic);
            ERR_add_error_data(2, "Magic=0x", keytypestr);
        }
        break;
    }

 err:
    OPENSSL_free(exported);
    return res;
}

#else                           /* !__COMPILE_CNGENG */

# include <openssl/engine.h>

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns);
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns)
{
    return 0;
}

# else
void engine_load_cng_int(void);
void engine_load_cng_int(void)
{
}
# endif
#endif

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif
