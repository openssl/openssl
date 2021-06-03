/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/params.h>
#include <prov/providercommon.h>
#include "pkcs11_ctx.h"
#include <dlfcn.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

/* provider entry point (fixed name, exported) */
OSSL_provider_init_fn OSSL_provider_init;

/************************************************************************
 * Parameters we provide to the core.
 * The parameters in this list can be used with this provider.
 * Implementation for retrieving those parameters are implemented in 
 * my_get_params.
 */
static const OSSL_PARAM pkcs11_get_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME,       OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION,    OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO,  OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS,     OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pkcs11_set_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_SLOT,     OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_TOKEN,     OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_MODULE, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

/************************************************************************/

/************************************************************************
 * Static fprivate functions definition
 */
void pkcs11_unload_module(PKCS11_CTX *ctx);
int pkcs11_load_module(PKCS11_CTX *ctx, const char* libname);
/************************************************************************/

/************************************************************************
 * Defining the dispatch table.
 * Forward declarations to ensure that interface functions are correctly
 * defined. Those interface functions are provided to the core using
 * my_dispatch_table.
 */
static OSSL_FUNC_provider_gettable_params_fn pkcs11_gettable_params;
static OSSL_FUNC_provider_get_params_fn pkcs11_get_params;
static OSSL_FUNC_provider_settable_params_fn pkcs11_settable_params;
static OSSL_FUNC_provider_set_params_fn pkcs11_set_params;
static OSSL_FUNC_provider_query_operation_fn pkcs11_query;
static OSSL_FUNC_provider_get_reason_strings_fn pkcs11_get_reason_strings;
static OSSL_FUNC_provider_teardown_fn pkcs11_teardown;

#define SET_PKCS11_PROV_ERR(ctx, reasonidx) \
    pkcs11_set_error(ctx, reasonidx, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, NULL)
static void pkcs11_set_error(PKCS11_CTX *ctx, int reason, const char *file, int line,
                        const char *func, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ctx->core_vset_error(NULL, ERR_PACK(ERR_LIB_PROV, 0, reason), fmt, ap);
    ctx->core_set_error_debug(NULL, file, line, func);
    va_end(ap);
}

/* Define the reason string table */
static const OSSL_ITEM reason_strings[] = {
#define REASON_STRING(ckr) {ckr, #ckr}
    REASON_STRING(CKR_CANCEL),
    REASON_STRING(CKR_HOST_MEMORY),
    REASON_STRING(CKR_SLOT_ID_INVALID),
    REASON_STRING(CKR_GENERAL_ERROR),
    REASON_STRING(CKR_FUNCTION_FAILED),
    REASON_STRING(CKR_ARGUMENTS_BAD),
    REASON_STRING(CKR_NO_EVENT),
    REASON_STRING(CKR_NEED_TO_CREATE_THREADS),
    REASON_STRING(CKR_CANT_LOCK),
    REASON_STRING(CKR_ATTRIBUTE_READ_ONLY),
    REASON_STRING(CKR_ATTRIBUTE_SENSITIVE),
    REASON_STRING(CKR_ATTRIBUTE_TYPE_INVALID),
    REASON_STRING(CKR_ATTRIBUTE_VALUE_INVALID),
    REASON_STRING(CKR_ACTION_PROHIBITED),
    REASON_STRING(CKR_DATA_INVALID),
    REASON_STRING(CKR_DATA_LEN_RANGE),
    REASON_STRING(CKR_DEVICE_ERROR),
    REASON_STRING(CKR_DEVICE_MEMORY),
    REASON_STRING(CKR_DEVICE_REMOVED),
    REASON_STRING(CKR_ENCRYPTED_DATA_INVALID),
    REASON_STRING(CKR_ENCRYPTED_DATA_LEN_RANGE),
    REASON_STRING(CKR_AEAD_DECRYPT_FAILED),
    REASON_STRING(CKR_FUNCTION_CANCELED),
    REASON_STRING(CKR_FUNCTION_NOT_PARALLEL),
    REASON_STRING(CKR_FUNCTION_NOT_SUPPORTED),
    REASON_STRING(CKR_KEY_HANDLE_INVALID),
    REASON_STRING(CKR_KEY_SIZE_RANGE),
    REASON_STRING(CKR_KEY_TYPE_INCONSISTENT),
    REASON_STRING(CKR_KEY_NOT_NEEDED),
    REASON_STRING(CKR_KEY_CHANGED),
    REASON_STRING(CKR_KEY_NEEDED),
    REASON_STRING(CKR_KEY_INDIGESTIBLE),
    REASON_STRING(CKR_KEY_FUNCTION_NOT_PERMITTED),
    REASON_STRING(CKR_KEY_NOT_WRAPPABLE),
    REASON_STRING(CKR_KEY_UNEXTRACTABLE),
    REASON_STRING(CKR_MECHANISM_INVALID),
    REASON_STRING(CKR_MECHANISM_PARAM_INVALID),
    REASON_STRING(CKR_OBJECT_HANDLE_INVALID),
    REASON_STRING(CKR_OPERATION_ACTIVE),
    REASON_STRING(CKR_OPERATION_NOT_INITIALIZED),
    REASON_STRING(CKR_PIN_INCORRECT),
    REASON_STRING(CKR_PIN_INVALID),
    REASON_STRING(CKR_PIN_LEN_RANGE),
    REASON_STRING(CKR_PIN_EXPIRED),
    REASON_STRING(CKR_PIN_LOCKED),
    REASON_STRING(CKR_SESSION_CLOSED),
    REASON_STRING(CKR_SESSION_COUNT),
    REASON_STRING(CKR_SESSION_HANDLE_INVALID),
    REASON_STRING(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
    REASON_STRING(CKR_SESSION_READ_ONLY),
    REASON_STRING(CKR_SESSION_EXISTS),
    REASON_STRING(CKR_SESSION_READ_ONLY_EXISTS),
    REASON_STRING(CKR_SESSION_READ_WRITE_SO_EXISTS),
    REASON_STRING(CKR_SIGNATURE_INVALID),
    REASON_STRING(CKR_SIGNATURE_LEN_RANGE),
    REASON_STRING(CKR_TEMPLATE_INCOMPLETE),
    REASON_STRING(CKR_TEMPLATE_INCONSISTENT),
    REASON_STRING(CKR_TOKEN_NOT_PRESENT),
    REASON_STRING(CKR_TOKEN_NOT_RECOGNIZED),
    REASON_STRING(CKR_TOKEN_WRITE_PROTECTED),
    REASON_STRING(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
    REASON_STRING(CKR_UNWRAPPING_KEY_SIZE_RANGE),
    REASON_STRING(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
    REASON_STRING(CKR_USER_ALREADY_LOGGED_IN),
    REASON_STRING(CKR_USER_NOT_LOGGED_IN),
    REASON_STRING(CKR_USER_PIN_NOT_INITIALIZED),
    REASON_STRING(CKR_USER_TYPE_INVALID),
    REASON_STRING(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
    REASON_STRING(CKR_USER_TOO_MANY_TYPES),
    REASON_STRING(CKR_WRAPPED_KEY_INVALID),
    REASON_STRING(CKR_WRAPPED_KEY_LEN_RANGE),
    REASON_STRING(CKR_WRAPPING_KEY_HANDLE_INVALID),
    REASON_STRING(CKR_WRAPPING_KEY_SIZE_RANGE),
    REASON_STRING(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
    REASON_STRING(CKR_RANDOM_SEED_NOT_SUPPORTED),
    REASON_STRING(CKR_RANDOM_NO_RNG),
    REASON_STRING(CKR_DOMAIN_PARAMS_INVALID),
    REASON_STRING(CKR_CURVE_NOT_SUPPORTED),
    REASON_STRING(CKR_BUFFER_TOO_SMALL),
    REASON_STRING(CKR_SAVED_STATE_INVALID),
    REASON_STRING(CKR_INFORMATION_SENSITIVE),
    REASON_STRING(CKR_STATE_UNSAVEABLE),
    REASON_STRING(CKR_CRYPTOKI_NOT_INITIALIZED),
    REASON_STRING(CKR_CRYPTOKI_ALREADY_INITIALIZED),
    REASON_STRING(CKR_MUTEX_BAD),
    REASON_STRING(CKR_MUTEX_NOT_LOCKED),
    REASON_STRING(CKR_NEW_PIN_MODE),
    REASON_STRING(CKR_NEXT_OTP),
    REASON_STRING(CKR_EXCEEDED_MAX_ITERATIONS),
    REASON_STRING(CKR_FIPS_SELF_TEST_FAILED),
    REASON_STRING(CKR_LIBRARY_LOAD_FAILED),
    REASON_STRING(CKR_PIN_TOO_WEAK),
    REASON_STRING(CKR_PUBLIC_KEY_INVALID),
    REASON_STRING(CKR_FUNCTION_REJECTED),
    REASON_STRING(CKR_TOKEN_RESOURCE_EXCEEDED),
#undef REASON_STRING
    {0, NULL}
};


/* Functions we provide to the core */
static const OSSL_DISPATCH my_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_SETTABLE_PARAMS, (void (*)(void))pkcs11_settable_params },
    { OSSL_FUNC_PROVIDER_SET_PARAMS, (void (*)(void))pkcs11_set_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))pkcs11_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))pkcs11_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pkcs11_query },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))pkcs11_get_reason_strings },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))pkcs11_teardown },
    { 0, NULL }
};

/************************************************************************/

#define SEARCH_PARAM "provider=my_provider"

/************************************************************************/

/************************************************************************/

/* Implementation for the OSSL_FUNC_PROVIDER_GETTABLE_PARAMS function */
static const OSSL_PARAM *pkcs11_gettable_params(void *provctx)
{
    printf("- my_provider: %s (%d)\n", __FUNCTION__, __LINE__);
    fflush(stdout);
    return pkcs11_get_param_types;
}

/* Implementation for the OSSL_FUNC_PROVIDER_GET_PARAMS function */
static int pkcs11_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    printf("- my_provider: %s (%d)\n", __FUNCTION__, __LINE__);
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "PKCS11 Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
            
    return 1;
}

/* Implementation for the OSSL_FUNC_PROVIDER_GETTABLE_PARAMS function */
static const OSSL_PARAM *pkcs11_settable_params(void *provctx)
{
    printf("- my_provider: %s (%d)\n", __FUNCTION__, __LINE__);
    fflush(stdout);
    return pkcs11_set_param_types;
}

/* Implementation for the OSSL_FUNC_PROVIDER_GET_PARAMS function */
static int pkcs11_set_params(void *provctx, const OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    PKCS11_CTX *ctx = (PKCS11_CTX*)provctx;
    int ival = 0;
    const char* module = NULL;

    p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_PROV_PARAM_PKCS11_SLOT);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ival))
        return 0;
    else {
        ctx->slot = ival;
    }
    p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_PROV_PARAM_PKCS11_TOKEN);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ival))
        return 0;
    else {
        ctx->token = ival;
    }
    p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_PROV_PARAM_PKCS11_MODULE);
    if (p != NULL && !OSSL_PARAM_get_utf8_ptr(p, &module))
        return 0;
    else {
        if (!pkcs11_load_module(ctx, module))
            return 0;
    }

    return 1;
}

/* Implementation of the OSSL_FUNC_PROVIDER_QUERY_OPERATION function */
static const OSSL_ALGORITHM *pkcs11_query(void *provctx,
                                          int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    printf("- my_provider: %s (%d)\n", __FUNCTION__, __LINE__);
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        printf("- my_provider: %s (%d) returning my_digests list\n", __FUNCTION__, __LINE__);
        fflush(stdout);
        return NULL;
    case OSSL_OP_CIPHER:
        printf("- my_provider: %s (%d) returning my_ciphers list\n", __FUNCTION__, __LINE__);
        fflush(stdout);
        return NULL;
    }
    return NULL;
}

static const OSSL_ITEM *pkcs11_get_reason_strings(void *provctx)
{
    if (provctx == NULL)
        return NULL;

    return reason_strings;
}

/* Implementation for the OSSL_FUNC_PROVIDER_TEARDOWN function */
static void pkcs11_teardown(void *provctx)
{
    PKCS11_CTX *ctx = (PKCS11_CTX*)provctx;
    pkcs11_unload_module(ctx);
    CRYPTO_THREAD_lock_free(ctx->lock);
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    OPENSSL_free(ctx);
}

/* Implementation of the OSSL_provider_init function
 * This method is basically the entry point of the provider library.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    PKCS11_CTX* ctx = NULL;
    int ret = 0;

    if (handle == NULL || in == NULL || out == NULL || provctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    ctx = (PKCS11_CTX*)OPENSSL_zalloc(sizeof(PKCS11_CTX));
    if (ctx == NULL
        || (libctx = OSSL_LIB_CTX_new()) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        pkcs11_teardown(ctx);
        *provctx = NULL;
        return 0;
    }
    /* Asign the core function to the context object */
    for (; in->function_id != 0; in++)
    {
        switch(in->function_id)
        {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            ctx->core_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            ctx->core_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            ctx->core_thread_start = OSSL_FUNC_core_thread_start(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            ctx->core_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            ctx->core_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            ctx->core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            ctx->core_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            ctx->core_set_error_mark = OSSL_FUNC_core_set_error_mark(in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            ctx->core_clear_last_error_mark = OSSL_FUNC_core_clear_last_error_mark(in);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            ctx->core_pop_error_to_mark = OSSL_FUNC_core_pop_error_to_mark(in);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            ctx->CRYPTO_malloc = OSSL_FUNC_CRYPTO_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            ctx->CRYPTO_zalloc = OSSL_FUNC_CRYPTO_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            ctx->CRYPTO_free = OSSL_FUNC_CRYPTO_free(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            ctx->CRYPTO_clear_free = OSSL_FUNC_CRYPTO_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            ctx->CRYPTO_realloc = OSSL_FUNC_CRYPTO_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            ctx->CRYPTO_clear_realloc = OSSL_FUNC_CRYPTO_clear_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            ctx->CRYPTO_secure_zalloc = OSSL_FUNC_CRYPTO_secure_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            ctx->CRYPTO_secure_zalloc = OSSL_FUNC_CRYPTO_secure_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            ctx->CRYPTO_secure_free = OSSL_FUNC_CRYPTO_secure_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            ctx->CRYPTO_secure_clear_free = OSSL_FUNC_CRYPTO_secure_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            ctx->CRYPTO_secure_allocated = OSSL_FUNC_CRYPTO_secure_allocated(in);
            break;
        case OSSL_FUNC_OPENSSL_CLEANSE:
            ctx->OPENSSL_cleanse = OSSL_FUNC_OPENSSL_cleanse(in);
            break;
        case OSSL_FUNC_BIO_NEW_FILE:
            ctx->BIO_new_file = OSSL_FUNC_BIO_new_file(in);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            ctx->BIO_new_membuf = OSSL_FUNC_BIO_new_membuf(in);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            ctx->BIO_read_ex = OSSL_FUNC_BIO_read_ex(in);
            break;
        case OSSL_FUNC_BIO_FREE:
            ctx->BIO_free = OSSL_FUNC_BIO_free(in);
            break;
        case OSSL_FUNC_BIO_VPRINTF:
            ctx->BIO_vprintf = OSSL_FUNC_BIO_vprintf(in);
            break;
        case OSSL_FUNC_SELF_TEST_CB:
            ctx->self_test_cb = OSSL_FUNC_self_test_cb(in);
            break;
        }
    }
    /* Check required core functions. */
    if (ctx->core_get_params == NULL
        || ctx->core_get_libctx == NULL)
    {
        SET_PKCS11_PROV_ERR(ctx, CKR_FUNCTION_REJECTED);
        pkcs11_teardown(ctx);
        goto end;
    }

    /* Save corectx. */
    ctx->corectx = ctx->core_get_libctx(handle);
    *provctx = ctx;

    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ctx->lock = CRYPTO_THREAD_lock_new();

    *out = my_dispatch_table;
    ret = 1;
end:
    return ret;
}

/************************************************************************
 * Helper Functions
 */

int pkcs11_do_GetFunctionList(PKCS11_CTX *ctx, char* libname)
{
    CK_RV(*pfunc) ();
    int ret = 0;

    ctx->lib_handle = dlopen(libname, RTLD_NOW);
    if (ctx->lib_handle == NULL)
        goto ret;

    *(void **)(&pfunc) = dlsym(ctx->lib_handle, "C_GetFunctionList");
    if (pfunc == NULL)
        goto ret;

    if (pfunc(&ctx->lib_functions) != CKR_OK)
        goto ret;

    ret = 1;
ret:
    if (!ret)
        pkcs11_unload_module(ctx);

    return ret;
}

int pkcs11_load_module(PKCS11_CTX *ctx, const char* libname)
{
    int ret = 0;
    CK_C_INITIALIZE_ARGS cinit_args = {0};

    if (ctx == NULL || libname == NULL || strlen(libname) <= 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    pkcs11_unload_module(ctx);

    if (!pkcs11_do_GetFunctionList(ctx, (char*)libname))
        goto end;

    // Initialize
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    if ((ctx->lib_functions->C_Initialize(&cinit_args)) != CKR_OK)
        goto end;

    ret = 1;
end:
    if (!ret)
        pkcs11_unload_module(ctx);

    return ret;
}

void pkcs11_unload_module(PKCS11_CTX *ctx)
{
    if (ctx->lib_handle)
    {
        dlclose(ctx->lib_handle);
        ctx->lib_handle = NULL;
        free(ctx->module_filename);
        ctx->module_filename = NULL;
    }
}
/************************************************************************/

