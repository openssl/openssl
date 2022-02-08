/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include "pkcs11_ctx.h"
#include "pkcs11_kmgmt.h"
#include "pkcs11_sign.h"
#include "pkcs11_digest.h"
#include "pkcs11_store.h"
#include <dlfcn.h>

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <internal/provider.h>
#include <prov/providercommon.h>
#include <prov/names.h>
#include "pkcs11_utils.h"
#include <prov/implementations.h>

extern const OSSL_DISPATCH pkcs11_store_functions[];
extern const OSSL_ALGORITHM defltp11_store[];

/* provider entry point (fixed name, exported) */
OSSL_provider_init_fn OSSL_provider_init;


/*
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
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_SLOT,    OSSL_PARAM_INTEGER,      NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_TOKEN,   OSSL_PARAM_INTEGER,      NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_MODULE,  OSSL_PARAM_UTF8_PTR,     NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_PKCS11_USERPIN, OSSL_PARAM_OCTET_STRING, NULL, 0),
    OSSL_PARAM_END
};

/* Private functions definition */
void pkcs11_unload_module(PKCS11_CTX *ctx);
int pkcs11_load_module(PKCS11_CTX *ctx, const char *libname);
int pkcs11_generate_dispatch_tables(PKCS11_CTX *ctx);
int pkcs11_generate_mechanism_tables(PKCS11_CTX *ctx);
PKCS11_SLOT *pkcs11_get_slot(PKCS11_CTX *provctx);
void pkcs11_free_slots(PKCS11_CTX *ctx);

static OSSL_FUNC_provider_gettable_params_fn    pkcs11_gettable_params;
static OSSL_FUNC_provider_get_params_fn         pkcs11_get_params;
static OSSL_FUNC_provider_settable_params_fn    pkcs11_settable_params;
static OSSL_FUNC_provider_set_params_fn         pkcs11_set_params;
static OSSL_FUNC_provider_query_operation_fn    pkcs11_query;
static OSSL_FUNC_provider_get_reason_strings_fn pkcs11_get_reason_strings;
static OSSL_FUNC_provider_teardown_fn           pkcs11_teardown;

/* Define the reason string table */

static const OSSL_ITEM pkcs11_reason_strings[] = {
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
    REASON_STRING(ERR_PKCS11_NO_USERPIN_SET),
    REASON_STRING(ERR_PKCS11_MEM_ALLOC_FAILED),
    REASON_STRING(ERR_PKCS11_NO_TOKENS_AVAILABLE),
    REASON_STRING(ERR_PKCS11_GET_LIST_OF_SLOTS_FAILED),
#undef REASON_STRING
    {0, NULL}
};

/* Functions we provide to the core */
static const OSSL_DISPATCH pkcs11_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_SETTABLE_PARAMS, (void (*)(void))pkcs11_settable_params },
    { OSSL_FUNC_PROVIDER_SET_PARAMS, (void (*)(void))pkcs11_set_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))pkcs11_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))pkcs11_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pkcs11_query },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))pkcs11_get_reason_strings },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))pkcs11_teardown },
    { 0, NULL }
};

/* Implementation for the OSSL_FUNC_PROVIDER_GETTABLE_PARAMS function */
static const OSSL_PARAM *pkcs11_gettable_params(void *provctx)
{
    return pkcs11_get_param_types;
}

/* Implementation for the OSSL_FUNC_PROVIDER_GET_PARAMS function */
static int pkcs11_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

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
    return pkcs11_set_param_types;
}

/* Implementation for the OSSL_FUNC_PROVIDER_GET_PARAMS function */
static int pkcs11_set_params(void *provctx, const OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;
    PKCS11_CTX *ctx = (PKCS11_CTX *)provctx;
    int ival = 0;
    const char *strval = NULL;
    unsigned char *ustrval = NULL;
    size_t str_len;

    p = OSSL_PARAM_locate((OSSL_PARAM *)params, OSSL_PROV_PARAM_PKCS11_SLOT);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &ival))
            return 0;
        else {
            ctx->sel_slot = ival;
            pkcs11_generate_dispatch_tables(ctx);
        }
    }

    p = OSSL_PARAM_locate((OSSL_PARAM *)params, OSSL_PROV_PARAM_PKCS11_TOKEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &ival))
            return 0;
        else
            ctx->token = ival;
    }

    p = OSSL_PARAM_locate((OSSL_PARAM *)params, OSSL_PROV_PARAM_PKCS11_USERPIN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ustrval, 0, &str_len)) {
            return 0;
        } else {
            if (ctx->userpin != NULL)
                OPENSSL_clear_free(ctx->userpin, strlen((const char*)ctx->userpin));
            ctx->userpin = OPENSSL_zalloc(str_len + 1);
            if (ctx->userpin == NULL)
                return 0;
            memcpy(ctx->userpin, ustrval, str_len);
        }
    }

    p = OSSL_PARAM_locate((OSSL_PARAM *)params, OSSL_PROV_PARAM_PKCS11_MODULE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_utf8_ptr(p, &strval))
            return 0;
        else {
            /* Not allowing having a module multiple times.
             * This would change the algorithm tables pointer addresses.
             */
            if (ctx->lib_handle != NULL)
                return 0;
            if (!pkcs11_load_module(ctx, strval))
                return 0;
        }
    }

    return 1;
}

/* Implementation of the OSSL_FUNC_PROVIDER_QUERY_OPERATION function */
static const OSSL_ALGORITHM *pkcs11_query(void *provctx,
                                          int operation_id,
                                          int *no_cache)
{
    PKCS11_CTX *ctx = (PKCS11_CTX *)provctx;
    PKCS11_SLOT *slot = pkcs11_get_slot(ctx);
    *no_cache = 0;

    if (slot != NULL) {
        switch (operation_id) {
        case OSSL_OP_DIGEST:
            fprintf(stdout, "@@ %s, %p\n", __FUNCTION__, slot->digest.algolist);
            fflush(stdout);
            return slot->digest.algolist;
        case OSSL_OP_CIPHER:
            return NULL;
        case OSSL_OP_KEYMGMT:
            fprintf(stdout, "@@ %s, %p\n", __FUNCTION__, slot->keymgmt.algolist);
            fflush(stdout);
            return slot->keymgmt.algolist;
        case OSSL_OP_SIGNATURE:
            fprintf(stdout, "@@ %s, %p\n", __FUNCTION__, slot->signature.algolist);
            fflush(stdout);
            return slot->signature.algolist;
        case OSSL_OP_STORE:
            fprintf(stdout, "@@ %s, %p\n", __FUNCTION__, slot->store.algolist);
            fflush(stdout);
            return slot->store.algolist;
        }
    }
    return NULL;
}

static const OSSL_ITEM *pkcs11_get_reason_strings(void *provctx)
{
    if (provctx == NULL)
        return NULL;

    return pkcs11_reason_strings;
}

/* Implementation for the OSSL_FUNC_PROVIDER_TEARDOWN function */
static void pkcs11_teardown(void *provctx)
{
    PKCS11_CTX *ctx = (PKCS11_CTX *)provctx;
    pkcs11_unload_module(ctx);
    if (ctx->search_str != NULL)
        OPENSSL_free(ctx->search_str);
    if (ctx->userpin != NULL)
        OPENSSL_clear_free(ctx->userpin, strlen((const char *)ctx->userpin));
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
    OSSL_PROVIDER *prov = NULL;
    PKCS11_CTX *ctx = NULL;
    const char *searchfm = "provider=%s";
    int ret = 0;

    if (handle == NULL || in == NULL || out == NULL || provctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    *provctx = NULL;
    prov = (OSSL_PROVIDER *)handle;

    ctx = (PKCS11_CTX *)OPENSSL_zalloc(sizeof(PKCS11_CTX));
    if (ctx == NULL) {
        OPENSSL_free(ctx);
        goto end;
    }

    if ((libctx = OSSL_LIB_CTX_new()) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        goto end;
    }

    /* Asign the core function to the context object */
    for (; in->function_id != 0; in++)
    {
        switch(in->function_id)
        {
        case OSSL_FUNC_CORE_NEW_ERROR:
            ctx->core_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            ctx->core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            ctx->core_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        }
    }
    ctx->search_str = OPENSSL_zalloc(strlen(searchfm) + strlen( ossl_provider_name(prov)));
    if (ctx->search_str == NULL) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        goto end;
    }

    sprintf(ctx->search_str, searchfm, ossl_provider_name(prov));
    *provctx = ctx;

    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    *out = pkcs11_dispatch_table;
    ret = 1;
end:
    return ret;
}

/* Helper Functions */
typedef CK_RV get_func_list (CK_FUNCTION_LIST **);
int pkcs11_do_GetFunctionList(PKCS11_CTX *ctx, char *libname)
{
    CK_RV rv = CKR_CANCEL;
    get_func_list *fun_ptr = NULL;
    int ret = 0;

    ctx->lib_handle = DSO_load(NULL, libname, NULL, 0);
    if (ctx->lib_handle == NULL)
        goto ret;

    fun_ptr = (get_func_list *)DSO_bind_func(ctx->lib_handle, "C_GetFunctionList");
    if (fun_ptr == NULL)
        goto ret;

    rv = fun_ptr((CK_FUNCTION_LIST **)&ctx->lib_functions);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto ret;
    }
    fprintf(stdout, "@@@ Provname: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle));
    fprintf(stdout, "@@@ - %s lib_functions ptr %p\n", __FUNCTION__, ctx->lib_functions);
    fflush(stdout);

    ret = 1;
ret:
    if (!ret)
        pkcs11_unload_module(ctx);

    return ret;
}

int pkcs11_load_module(PKCS11_CTX *ctx, const char *libname)
{
    int ret = 0;
    CK_RV rv = CKR_CANCEL;
    CK_C_INITIALIZE_ARGS cinit_args = {0};
    CK_FLAGS flags;

    if (ctx == NULL || libname == NULL || strlen(libname) <= 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    if (!pkcs11_do_GetFunctionList(ctx, (char *)libname))
        goto end;

    cinit_args.flags = CKF_OS_LOCKING_OK;
    fprintf(stdout, "@@@ Provname: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle));
    fprintf(stdout, "@@@ - %s lib_functions ptr %p\n", __FUNCTION__, ctx->lib_functions);
    fflush(stdout);
    rv = ctx->lib_functions->C_Initialize(&cinit_args);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    if (!pkcs11_generate_mechanism_tables(ctx))
        goto end;

    if (!pkcs11_generate_dispatch_tables(ctx))
        goto end;

    fprintf(stdout, "@@@ - %s lib_functions ptr %p\n", __FUNCTION__, ctx->lib_functions);
    fflush(stdout);
    /* Open a user R/W session: all future sessions will be user sessions. */
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = ctx->lib_functions->C_OpenSession(ctx->sel_slot, flags, NULL, NULL, &ctx->session);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }
    fprintf(stdout, "@@@ - %s lib_functions ptr %p\n", __FUNCTION__, ctx->lib_functions);
    fflush(stdout);
    fprintf(stdout, "@@@ Create session %s %lu\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle), ctx->session);
    fflush(stdout);

    if (ctx->userpin == NULL) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_NO_USERPIN_SET);
        goto end;
    }

    rv = ctx->lib_functions->C_Login(ctx->session, CKU_USER,
                                     ctx->userpin,
                                     strlen((char *)ctx->userpin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }
    fprintf(stdout, "@@@ - %s lib_functions ptr %p\n", __FUNCTION__, ctx->lib_functions);
    fflush(stdout);

    ctx->module_filename = OPENSSL_zalloc(strlen(libname) + 1);
    if (ctx->module_filename == NULL) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        goto end;
    }
    strncpy((char *)ctx->module_filename, libname, strlen(libname));
    ret = 1;
    fprintf(stdout, "@@@ Provname: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle));
    fprintf(stdout, "@@@ - %s lib_functions ptr %p\n", __FUNCTION__, ctx->lib_functions);
    fflush(stdout);

end:
    if (!ret)
        pkcs11_unload_module(ctx);

    return ret;
}

int pkcs11_generate_mechanism_tables(PKCS11_CTX *ctx)
{
    int                 ret = 0;
    CK_ULONG            i = 0;
    CK_RV               rv = 0;
    CK_ULONG            mechcount = 0;
    CK_ULONG            slot_count = 0;
    CK_SLOT_ID_PTR      slot_list = NULL;
    CK_MECHANISM_TYPE   *mechlist = NULL;
    CK_MECHANISM_INFO   *mechinfo = NULL;

    /* Find out how many slots are present in slots */
    rv = ctx->lib_functions->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    if (slot_count == 0) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_NO_TOKENS_AVAILABLE);
        goto end;
    }

    slot_list = (CK_SLOT_ID_PTR) malloc(slot_count * sizeof(CK_SLOT_ID));
    if (slot_list == NULL) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        goto end;
    }

    rv = ctx->lib_functions->C_GetSlotList(TRUE, slot_list, &slot_count);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_GET_LIST_OF_SLOTS_FAILED);
        goto end;
    }

    if (slot_count > 0)
        ctx->slots = OPENSSL_sk_new_null();

    for (i = 0; i < slot_count; i++) {
        CK_SLOT_ID          slot = slot_list[i];
        PKCS11_SLOT         *pkcs11_slot = (PKCS11_SLOT *)OPENSSL_zalloc(sizeof(PKCS11_SLOT));

        if (pkcs11_slot == NULL) {
            SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
            goto end;
        }

        pkcs11_slot->slotid = slot;

        /* Cache the slot's mechanism list. */
        rv = ctx->lib_functions->C_GetMechanismList(slot, NULL, &mechcount);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }
        mechlist = (CK_MECHANISM_TYPE *)OPENSSL_zalloc(mechcount * sizeof(CK_MECHANISM_TYPE));
        if (mechlist == NULL)
            goto end;

        rv = ctx->lib_functions->C_GetMechanismList(slot, mechlist, &mechcount);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }

        mechinfo = OPENSSL_zalloc(mechcount * sizeof(CK_MECHANISM_INFO));
        pkcs11_slot->keymgmt.items = OPENSSL_sk_new_null();
        if (pkcs11_slot->keymgmt.items == NULL) {
            SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
            goto end;
        }
        pkcs11_slot->signature.items = OPENSSL_sk_new_null();
        if (pkcs11_slot->signature.items == NULL) {
            SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
            goto end;
        }
        pkcs11_slot->digest.items = OPENSSL_sk_new_null();
        if (pkcs11_slot->digest.items == NULL) {
            SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
            goto end;
        }
        pkcs11_slot->store.items = OPENSSL_sk_new_null();
        if (pkcs11_slot->store.items == NULL) {
            SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_MEM_ALLOC_FAILED);
            goto end;
        }

        /* Cache the slot's mechanism info structure for each mechanism. */
        for (i = 0; i < mechcount; i++) {
            rv = ctx->lib_functions->C_GetMechanismInfo(slot,
                                                        mechlist[i], &mechinfo[i]);
            if (rv != CKR_OK) {
                SET_PKCS11_PROV_ERR(ctx, rv);
                goto end;
            }

            if (mechinfo[i].flags & CKF_GENERATE_KEY_PAIR) {
                PKCS11_TYPE_DATA_ITEM *item = OPENSSL_zalloc(sizeof(*item));
                if (item) {
                    item->info = mechinfo[i];
                    item->type = mechlist[i];
                    OPENSSL_sk_push(pkcs11_slot->keymgmt.items, item);
                }
            }
            if (mechinfo[i].flags & CKF_SIGN) {
                PKCS11_TYPE_DATA_ITEM *item = OPENSSL_zalloc(sizeof(*item));
                if (item) {
                    item->info = mechinfo[i];
                    item->type = mechlist[i];
                    OPENSSL_sk_push(pkcs11_slot->signature.items, item);
                }
            }
            if (mechinfo[i].flags & CKF_DIGEST) {
                PKCS11_TYPE_DATA_ITEM *item = OPENSSL_zalloc(sizeof(*item));
                if (item) {
                    item->info = mechinfo[i];
                    item->type = mechlist[i];
                    OPENSSL_sk_push(pkcs11_slot->digest.items, item);
                }
            }
        }
        PKCS11_TYPE_DATA_ITEM *item = OPENSSL_zalloc(sizeof(*item));
        if (item) {
            item->type = CKF_STORE;
            OPENSSL_sk_push(pkcs11_slot->store.items, item);
        }
        OPENSSL_sk_push(ctx->slots, pkcs11_slot);
        OPENSSL_free(mechlist);
        OPENSSL_free(mechinfo);
        mechlist = NULL;
        mechinfo = NULL;
    }

    ret = 1;
end:
    OPENSSL_free(slot_list);
    OPENSSL_free(mechlist);
    OPENSSL_free(mechinfo);
    if (!ret)
        pkcs11_free_slots(ctx);

    return ret;
}

void pkcs11_free_slots(PKCS11_CTX *ctx)
{
    int i = 0;
    int ii = 0;
    PKCS11_SLOT *slot = NULL;
    PKCS11_TYPE_DATA_ITEM *item = NULL;

    if (ctx->slots != NULL) {
        for (i = 0; i < OPENSSL_sk_num(ctx->slots); i++) {
            slot = (PKCS11_SLOT *)OPENSSL_sk_value(ctx->slots, i);
            if (slot != NULL) {
                if (slot->keymgmt.items != NULL) {
                    for (ii = 0; ii < OPENSSL_sk_num(slot->keymgmt.items); ii++) {
                        item = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->keymgmt.items, ii);
                        OPENSSL_free(item);
                    }
                    OPENSSL_sk_free(slot->keymgmt.items);
                }
                OPENSSL_free(slot->keymgmt.algolist);

                if (slot->signature.items != NULL) {
                    for (ii = 0; ii < OPENSSL_sk_num(slot->signature.items); ii++) {
                        item = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->signature.items, ii);
                        OPENSSL_free(item);
                    }
                    OPENSSL_sk_free(slot->signature.items);
                }
                OPENSSL_free(slot->signature.algolist);

                if (slot->digest.items != NULL) {
                    for (ii = 0; ii < OPENSSL_sk_num(slot->digest.items); ii++) {
                        item = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->digest.items, ii);
                        OPENSSL_free(item);
                    }
                    OPENSSL_sk_free(slot->digest.items);
                }
                OPENSSL_free(slot->digest.algolist);

                if (slot->store.items != NULL) {
                    for (ii = 0; ii < OPENSSL_sk_num(slot->store.items); ii++) {
                        item = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->store.items, ii);
                        OPENSSL_free(item);
                    }
                    OPENSSL_sk_free(slot->store.items);
                }
                OPENSSL_free(slot->store.algolist);

                OPENSSL_free(slot);
            }
        }
        OPENSSL_sk_free(ctx->slots);
        ctx->slots = NULL;
    }
}

void pkcs11_unload_module(PKCS11_CTX *ctx)
{
    if (ctx->lib_handle != NULL)
    {
        if (ctx->lib_functions != NULL) {
            fprintf(stdout, "@@@ Provname: %s\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle));
            fprintf(stdout, "@@@ Close session %s %lu\n", OSSL_PROVIDER_name((OSSL_PROVIDER *)ctx->ctx.handle), ctx->session);
            fflush(stdout);
            if (ctx->session) {
                ctx->lib_functions->C_CloseSession(ctx->session);
                ctx->session = 0;
            }
            ctx->lib_functions->C_Logout(ctx->session);
            ctx->lib_functions->C_Finalize(NULL);
            ctx->lib_functions = NULL;
        }
        DSO_free(ctx->lib_handle);
        ctx->lib_handle = NULL;
        if (ctx->module_filename)
            OPENSSL_free(ctx->module_filename);
        ctx->module_filename = NULL;
    }
    pkcs11_free_slots(ctx);
}

int pkcs11_generate_dispatch_tables(PKCS11_CTX *ctx)
{
    PKCS11_SLOT *slot = NULL;
    const char* id = NULL;

    id = ctx->search_str;
    slot = pkcs11_get_slot(ctx);
    if (slot != NULL) {
        if (slot->keymgmt.algolist == NULL)
            slot->keymgmt.algolist = pkcs11_keymgmt_get_algo_tbl(slot->keymgmt.items, id);
        if (slot->signature.algolist == NULL)
            slot->signature.algolist = pkcs11_sign_get_algo_tbl(slot->signature.items, id);
        if (slot->digest.algolist == NULL)
            slot->digest.algolist = pkcs11_digest_get_algo_tbl(slot->digest.items, id);
        if (slot->store.algolist == NULL)
            slot->store.algolist = pkcs11_store_get_algo_tbl(slot->store.items, id);
    }
    return 1;
}

PKCS11_SLOT *pkcs11_get_slot(PKCS11_CTX *provctx)
{
    int i = 0;
    PKCS11_SLOT *slot = NULL;

    for (i = 0; i < OPENSSL_sk_num(provctx->slots); i++) {
        slot = (PKCS11_SLOT *)OPENSSL_sk_value(provctx->slots, i);
        if (slot->slotid == provctx->sel_slot)
            return slot;
    }
    return NULL;
}


