/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_pkcs11.h"
#include "e_pkcs11_err.c"
#include <internal/dso.h>
#include <internal/nelem.h>
#include <openssl/bn.h>

typedef CK_RV pkcs11_pFunc(CK_FUNCTION_LIST **pkcs11_funcs);
static CK_RV pkcs11_load_functions(const char *library_path);
static CK_FUNCTION_LIST *pkcs11_funcs;
static int pkcs11_get_key(OSSL_STORE_LOADER_CTX *store_ctx,
                          CK_OBJECT_HANDLE obj);
static int pkcs11_get_cert(OSSL_STORE_LOADER_CTX *store_ctx,
                           CK_OBJECT_HANDLE obj);

int pkcs11_rsa_sign(int alg, const unsigned char *md,
                    unsigned int md_len, unsigned char *sigret,
                    unsigned int *siglen, const RSA *rsa)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM sign_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    CK_SESSION_HANDLE session = 0;
    unsigned char *tmps = NULL;
    int encoded_len = 0;
    const unsigned char *encoded = NULL;
    CK_OBJECT_HANDLE key = 0;

    ctx = pkcs11_get_ctx(rsa);

    if (!ctx->session) {
        return RSA_meth_get_sign(RSA_PKCS1_OpenSSL())
            (alg, md, md_len, sigret, siglen, rsa);
    }

    session = ctx->session;

    num = RSA_size(rsa);
    if (!RSA_encode_pkcs1(&tmps, &encoded_len, alg, md, md_len))
        goto err;
    encoded = tmps;
    if ((unsigned int)encoded_len > (num - RSA_PKCS1_PADDING_SIZE)) {
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN,
                  PKCS11_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto err;
    }

    sign_mechanism.mechanism = CKM_RSA_PKCS;
    key = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa, rsa_pkcs11_idx);

    rv = pkcs11_funcs->C_SignInit(session, &sign_mechanism, key);

    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);
    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate
        && !pkcs11_login(session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    /* Sign */
    rv = pkcs11_funcs->C_Sign(session, (CK_BYTE *) encoded, encoded_len,
                              sigret, &num);

    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, PKCS11_R_SIGN_FAILED);
        goto err;
    }
    *siglen = num;

    return 1;

 err:
    return 0;
}

int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM enc_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_TRUE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = 0;
    int useSign = 0;

    ctx = pkcs11_get_ctx(rsa);

    if (!ctx->session) {
        return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
            (flen, from, to, rsa, padding);
    }

    session = ctx->session;

    num = RSA_size(rsa);

    enc_mechanism.mechanism = CKM_RSA_PKCS;
    CRYPTO_THREAD_write_lock(ctx->lock);

    key = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa, rsa_pkcs11_idx);
    rv = pkcs11_funcs->C_EncryptInit(session, &enc_mechanism, key);

    if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        PKCS11_trace("C_EncryptInit failed try SignInit, error: %#08X\n", rv);
        rv = pkcs11_funcs->C_SignInit(session, &enc_mechanism, key);

        if (rv != CKR_OK) {
            PKCS11_trace("C_SignInit failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_INIT_FAILED);
            goto err;
        }
        useSign = 1;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if (bAwaysAuthentificate
        && !pkcs11_login(session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    if (!useSign) {
        /* Encrypt */
        rv = pkcs11_funcs->C_Encrypt(session, (CK_BYTE *) from,
                                     flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Encrypt failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_ENCRYPT_FAILED);
            goto err;
        }
    } else {
        /* Sign */
        rv = pkcs11_funcs->C_Sign(session, (CK_BYTE *) from,
                                  flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Sign failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_ENC, PKCS11_R_SIGN_FAILED);
            goto err;
        }
    }

    CRYPTO_THREAD_unlock(ctx->lock);

    /* FIXME useless call */
    ERR_load_PKCS11_strings();
    ERR_unload_PKCS11_strings();

    return num;

 err:
    return 0;
}

int pkcs11_rsa_priv_dec(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    CK_ULONG num;
    CK_MECHANISM enc_mechanism = { 0 };
    CK_BBOOL bAwaysAuthentificate = CK_FALSE;
    CK_ATTRIBUTE keyAttribute[1] = {{ 0 }};
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = 0;
    int useVerify = 0;

    ctx = pkcs11_get_ctx(rsa);

    if (!ctx->session) {
        return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
            (flen, from, to, rsa, padding);
    }

    session = ctx->session;

    num = RSA_size(rsa);

    enc_mechanism.mechanism = CKM_RSA_PKCS;
    CRYPTO_THREAD_write_lock(ctx->lock);

    key = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa, rsa_pkcs11_idx);
    rv = pkcs11_funcs->C_DecryptInit(session, &enc_mechanism, key);

    if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        PKCS11_trace("C_DecryptInit failed try VerifyInit, error: %#08X\n", rv);
        rv = pkcs11_funcs->C_VerifyInit(session, &enc_mechanism, key);

        if (rv != CKR_OK) {
            PKCS11_trace("C_VerifyInit failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_DEC, PKCS11_R_VERIFY_INIT_FAILED);
            goto err;
        }
        useVerify = 1;
    }

    keyAttribute[0].type = CKA_ALWAYS_AUTHENTICATE;
    keyAttribute[0].pValue = &bAwaysAuthentificate;
    keyAttribute[0].ulValueLen = sizeof(bAwaysAuthentificate);

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           keyAttribute,
                                           OSSL_NELEM(keyAttribute));

    if (bAwaysAuthentificate
        && !pkcs11_login(session, ctx, CKU_CONTEXT_SPECIFIC))
        goto err;

    if (!useVerify) {
        /* Decrypt */
        rv = pkcs11_funcs->C_Decrypt(session, (CK_BYTE *) from,
                                     flen, to, &num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Decrypt failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_DEC, PKCS11_R_DECRYPT_FAILED);
            goto err;
        }
    } else {
        /* Verify */
        rv = pkcs11_funcs->C_Verify(session, (CK_BYTE *) from,
                                    flen, to, num);
        if (rv != CKR_OK) {
            PKCS11_trace("C_Verify failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_RSA_PRIV_DEC, PKCS11_R_VERIFY_FAILED);
            goto err;
        }
    }

    CRYPTO_THREAD_unlock(ctx->lock);

    return num;

 err:
    return 0;
}

/**
 * Load the PKCS#11 functions into global function list.
 * @param library_path
 * @return
 */
static CK_RV pkcs11_load_functions(const char *library_path)
{
    CK_RV rv;
    DSO *pkcs11_dso = NULL;
    pkcs11_pFunc *pFunc;

    pkcs11_dso = DSO_load(NULL, library_path, NULL, 0);

    if (pkcs11_dso == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS,
                  PKCS11_R_LIBRARY_PATH_NOT_FOUND);
        return CKR_GENERAL_ERROR;
    }

    pFunc = (pkcs11_pFunc *)DSO_bind_func(pkcs11_dso, "C_GetFunctionList");

    if (pFunc == NULL) {
        PKCS11_trace("C_GetFunctionList() not found in module %s\n",
                     library_path);
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS,
                  PKCS11_R_GETFUNCTIONLIST_NOT_FOUND);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rv = pFunc(&pkcs11_funcs);
    return rv;
}

/**
 * Initialize the PKCS#11 library.
 * This loads the function list and initializes PKCS#11.
 * @param library_path
 * @return
 */
CK_RV pkcs11_initialize(const char *library_path)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args = { 0 };

    if (library_path == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        PKCS11_trace("Getting PKCS11 function list failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE,
                  PKCS11_R_GETTING_FUNCTION_LIST_FAILED);
        return rv;
    }

    args.flags = CKF_OS_LOCKING_OK;
    rv = pkcs11_funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Initialize failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE, PKCS11_R_INITIALIZE_FAILED);
        return rv;
    }

    return CKR_OK;
}

void pkcs11_finalize(void)
{
    pkcs11_funcs->C_Finalize(NULL);
}

int pkcs11_get_slot(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_ULONG slotCount;
    CK_SLOT_ID slotId;
    CK_SLOT_ID_PTR slotList = NULL;
    CK_TOKEN_INFO tokenInfo;
    unsigned int i;
    int match = 1;

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, NULL, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        goto err;
    }

    if (slotCount == 0) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_SLOT_NOT_FOUND);
        goto err;
    }

    slotList = OPENSSL_malloc(sizeof(CK_SLOT_ID) * slotCount);

    if (slotList == NULL) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        OPENSSL_free(slotList);
        goto err;
    }

    slotId = slotList[0]; /* Default value if slot not set*/
    if (ctx->slotid > 0) {
        for (i = 1; i < slotCount; i++) {
            if (ctx->slotid == slotList[i])
                slotId = slotList[i];
        }
    } else {
        if (ctx->model[0] != 0 || ctx->token[0] != 0
            || ctx->serial[0] != 0 || ctx->manufacturer[0] != 0) {
            match = 0;
            for (i = 0; i < slotCount; i++) {
                rv = pkcs11_funcs->C_GetTokenInfo(slotList[i], &tokenInfo);
                if (rv != CKR_OK)
                    continue;
                if (ctx->model[0] != 0 && memcmp(ctx->model, tokenInfo.model,
                    sizeof(ctx->model)))
                    continue;
                if (ctx->token[0] != 0 && memcmp(ctx->token, tokenInfo.label,
                    sizeof(ctx->token)))
                    continue;
                if (ctx->serial[0] != 0 && memcmp(ctx->serial,
                    tokenInfo.serialNumber, sizeof(ctx->serial)))
                    continue;
                if (ctx->manufacturer[0] != 0 && memcmp(ctx->manufacturer,
                    tokenInfo.manufacturerID, sizeof(ctx->manufacturer)))
                    continue;
                slotId = slotList[i];
                match = 1;
                break;
            }
        }
    }
    OPENSSL_free(slotList);

    if (!match)
        return 0;

    ctx->slotid = slotId;
    return 1;

 err:
    return 0;
}

int pkcs11_start_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE *session)
{
    CK_RV rv;
    CK_SESSION_HANDLE s = 0;

    rv = pkcs11_funcs->C_OpenSession(ctx->slotid, CKF_SERIAL_SESSION, NULL,
                                     NULL, &s);
    if (rv != CKR_OK) {
        PKCS11_trace("C_OpenSession failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_START_SESSION,
                  PKCS11_R_OPEN_SESSION_ERROR);
        return 0;
    }
    *session = s;
    return 1;
}

int pkcs11_login(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                 CK_USER_TYPE userType)
{
    /* Binary pins not supported */
    CK_RV rv;
    if (ctx->pin != NULL) {
        rv = pkcs11_funcs->C_Login(session, userType, ctx->pin, ctx->pinlen);
        if (rv == CKR_GENERAL_ERROR && userType == CKU_CONTEXT_SPECIFIC) {
            rv = pkcs11_funcs->C_Login(session, CKU_USER, ctx->pin,
                                       ctx->pinlen);
        }
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            PKCS11_trace("C_Login failed, error: %#08X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_LOGIN, PKCS11_R_LOGIN_FAILED);
            return 0;
        }
    } else {
        PKCS11_trace("C_Login failed, PIN empty\n");
        return 0;
    }
    return 1;
}

int pkcs11_logout(CK_SESSION_HANDLE session)
{
    CK_RV rv;

    rv = pkcs11_funcs->C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_OK) {
        PKCS11_trace("C_Logout failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOGOUT, PKCS11_R_LOGOUT_FAILED);
        return 0;
    }
    return 1;
}

void pkcs11_end_session(CK_SESSION_HANDLE session)
{
    pkcs11_funcs->C_CloseSession(session);
}

CK_OBJECT_HANDLE pkcs11_find_private_key(CK_SESSION_HANDLE session,
                                         PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    unsigned long count;
    CK_ATTRIBUTE tmpl[3];
    CK_OBJECT_HANDLE key = 0;

    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &key_class;
    tmpl[0].ulValueLen = sizeof(key_class);
    tmpl[1].type = CKA_KEY_TYPE;
    tmpl[1].pValue = &key_type;
    tmpl[1].ulValueLen = sizeof(key_type);

    if (ctx->id != NULL) {
        tmpl[2].type = CKA_ID;
        tmpl[2].pValue = ctx->id;
        tmpl[2].ulValueLen = ctx->idlen;
    } else {
        tmpl[2].type = CKA_LABEL;
        tmpl[2].pValue = ctx->label;
        tmpl[2].ulValueLen = (CK_ULONG)strlen((char *)ctx->label);
    }

    rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl, OSSL_NELEM(tmpl));

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(session, &key, 1, &count);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjectsFinal(session);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsFinal failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FINAL_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           tmpl, OSSL_NELEM(tmpl));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PRIVATE_KEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    return key;

 err:
    return 0;
}

CK_OBJECT_HANDLE pkcs11_find_public_key(CK_SESSION_HANDLE session,
                                        PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    unsigned long count;
    CK_ATTRIBUTE tmpl[3];
    CK_OBJECT_HANDLE key = 0;

    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &key_class;
    tmpl[0].ulValueLen = sizeof(key_class);
    tmpl[1].type = CKA_KEY_TYPE;
    tmpl[1].pValue = &key_type;
    tmpl[1].ulValueLen = sizeof(key_type);

    if (ctx->id != NULL) {
        tmpl[2].type = CKA_ID;
        tmpl[2].pValue = ctx->id;
        tmpl[2].ulValueLen = ctx->idlen;
    } else {
        tmpl[2].type = CKA_LABEL;
        tmpl[2].pValue = ctx->label;
        tmpl[2].ulValueLen = (CK_ULONG)strlen((char *)ctx->label);
    }

    rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl, OSSL_NELEM(tmpl));

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PUBLIC_KEY,
                  PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(session, &key, 1, &count);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PUBLIC_KEY,
                  PKCS11_R_FIND_OBJECT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjectsFinal(session);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsFinal failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PUBLIC_KEY,
                  PKCS11_R_FIND_OBJECT_FINAL_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           tmpl, OSSL_NELEM(tmpl));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_FIND_PUBLIC_KEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    return key;

 err:
    return 0;
}

EVP_PKEY *pkcs11_load_pkey(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                           CK_OBJECT_HANDLE key)
{
    EVP_PKEY *k = NULL;
    CK_RV rv;
    CK_ATTRIBUTE rsa_attributes[2];
    RSA *rsa = NULL;

    rsa_attributes[0].type = CKA_MODULUS;
    rsa_attributes[0].pValue = NULL;
    rsa_attributes[0].ulValueLen = 0;
    rsa_attributes[1].type = CKA_PUBLIC_EXPONENT;
    rsa_attributes[1].pValue = NULL;
    rsa_attributes[1].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           rsa_attributes,
                                           OSSL_NELEM(rsa_attributes));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }
    if  (rsa_attributes[0].ulValueLen == 0
         || rsa_attributes[1].ulValueLen == 0)
        goto err;

    rsa_attributes[0].pValue = OPENSSL_malloc(rsa_attributes[0].ulValueLen);
    if (rsa_attributes[0].pValue == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rsa_attributes[1].pValue = OPENSSL_malloc(rsa_attributes[1].ulValueLen);
    if (rsa_attributes[1].pValue == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           rsa_attributes,
                                           OSSL_NELEM(rsa_attributes));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#08X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    k = EVP_PKEY_new();
    rsa = RSA_new();

    if (k == NULL || rsa == NULL) {
        PKCS11err(PKCS11_F_PKCS11_LOAD_PKEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    RSA_set_ex_data(rsa, rsa_pkcs11_idx, (void *) key);
    RSA_set0_key(rsa,
                 BN_bin2bn(rsa_attributes[0].pValue,
                           rsa_attributes[0].ulValueLen, NULL),
                 BN_bin2bn(rsa_attributes[1].pValue,
                           rsa_attributes[1].ulValueLen, NULL),
                 NULL);

    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
    EVP_PKEY_assign_RSA(k, rsa);
    rsa = NULL;

    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    ctx->session = session;
    return k;

 err:
    OPENSSL_free(rsa_attributes[0].pValue);
    OPENSSL_free(rsa_attributes[1].pValue);
    return NULL;
}

int pkcs11_search_next_ids(OSSL_STORE_LOADER_CTX *ctx, char **name,
                           char **description)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key;
    CK_ULONG ulObj = 1;
    unsigned int i;
    CK_ATTRIBUTE template[3];
    CK_BYTE_PTR id;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_CLASS key_class;

    session = ctx->session;
    rv = pkcs11_funcs->C_FindObjects(session, &key,
                                     1, &ulObj);
    if (rv != CKR_OK || ulObj == 0) {
        *name = NULL;
        *description = NULL;
        /* return eof */
        return 1;
    }

    template[0].type = CKA_CLASS;
    template[0].pValue = &key_class;
    template[0].ulValueLen = sizeof(key_class);
    template[1].type = CKA_LABEL;
    template[1].pValue = NULL;
    template[1].ulValueLen = 0;
    template[2].type = CKA_ID;
    template[2].pValue = NULL;
    template[2].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        *name = NULL;
        *description = NULL;
        /* return no eof, search next id */
        return 0;
    }

    template[1].pValue = OPENSSL_malloc(template[1].ulValueLen);

    id = (CK_BYTE_PTR) OPENSSL_malloc(template[2].ulValueLen);
    template[2].pValue = id;

    rv = pkcs11_funcs->C_GetAttributeValue(session, key,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    *name = template[1].pValue;
    *(*name + template[1].ulValueLen) = '\0';

    *description = OPENSSL_malloc(template[2].ulValueLen * 3 + 23);

    if (key_class == CKO_CERTIFICATE)
        strncpy(*description, "Certificate ID: ", 17);
    else if (key_class == CKO_PUBLIC_KEY)
        strncpy(*description, "Public Key  ID: ", 17);
    else if (key_class == CKO_PRIVATE_KEY)
        strncpy(*description, "Private Key ID: ", 17);
    else
        strncpy(*description, "Data        ID: ", 17);

    for (i=0; i < template[2].ulValueLen; i++)
          *(*description + i + 16) = id[i];

    *(*description + template[2].ulValueLen + 16) = '\0';
    strncat(*description, " hex: ", 7);

    for (i=0; i < template[2].ulValueLen; i++) {
          *(*description + 22 + template[2].ulValueLen + (i*2)) = \
           "0123456789abcdef"[id[i] >> 4];
          *(*description + 23 + template[2].ulValueLen + (i*2)) = \
           "0123456789abcdef"[id[i] % 16];
    }
    *(*description + 22 + (template[2].ulValueLen * 3)) = '\0';
    OPENSSL_free(template[2].pValue);
    return 0;

 end:
    OPENSSL_free(template[2].pValue);
    return 1;
}

int pkcs11_search_next_object(OSSL_STORE_LOADER_CTX *ctx,
                              CK_OBJECT_CLASS *class)
{
    CK_RV rv;
    CK_ATTRIBUTE template[1];
    CK_OBJECT_HANDLE obj;
    CK_ULONG nObj = 0;
    CK_OBJECT_CLASS key_class;
    int ret = 0;

    template[0].type = CKA_CLASS;
    template[0].pValue = &key_class;
    template[0].ulValueLen = sizeof(key_class);

    rv = pkcs11_funcs->C_FindObjects(ctx->session, &obj,
                                     1, &nObj);
    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects: Error = 0x%.8lX\n", rv);
        return 1;
    }

    if (nObj == 0)
        return 1;

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, obj,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        return 1;
    }
    if (key_class == CKO_CERTIFICATE)
        ret = pkcs11_get_cert(ctx, obj);
    else if (key_class == CKO_PUBLIC_KEY)
        ret = pkcs11_get_key(ctx, obj);

    *class = key_class;
    return ret;
}

int pkcs11_search_next_cert(OSSL_STORE_LOADER_CTX *ctx,
                            CK_BYTE **id, CK_ULONG *idlen)
{
    CK_RV rv;
    CK_ATTRIBUTE template[2];
    CK_OBJECT_HANDLE obj;
    CK_ULONG nObj = 0;
    CK_OBJECT_CLASS key_class = CKO_CERTIFICATE;
    int ret = 0;

    template[0].type = CKA_CLASS;
    template[0].pValue = &key_class;
    template[0].ulValueLen = sizeof(key_class);
    template[1].type = CKA_ID;
    template[1].pValue = NULL;
    template[1].ulValueLen = 0;

    rv = pkcs11_funcs->C_FindObjects(ctx->session, &obj,
                                     1, &nObj);
    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects: Error = 0x%.8lX\n", rv);
        return 1;
    }

    if (nObj == 0)
        return 1;

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, obj,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        return 1;
    }

    template[1].pValue = OPENSSL_malloc(template[1].ulValueLen);

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, obj,
                                           template,
                                           OSSL_NELEM(template));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        return 1;
    }

    ret = pkcs11_get_cert(ctx, obj);
    *id = (CK_BYTE *) template[1].pValue;
    *idlen = (CK_ULONG) template[1].ulValueLen;
    return ret;
}

void pkcs11_close_operation(CK_SESSION_HANDLE session)
{
    CK_RV rv;

    rv = pkcs11_funcs->C_FindObjectsFinal(session);
    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsFinal failed, error: %#08X\n", rv);
    }
}

static int pkcs11_get_cert(OSSL_STORE_LOADER_CTX *store_ctx,
                           CK_OBJECT_HANDLE obj)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_CERTIFICATE;
    CK_ATTRIBUTE tmpl_cert[2];
    const unsigned char *tmpcert = NULL;

    tmpl_cert[0].type = CKA_CLASS;
    tmpl_cert[0].pValue = &key_class;
    tmpl_cert[0].ulValueLen = sizeof(key_class);
    tmpl_cert[1].type = CKA_VALUE;
    tmpl_cert[1].pValue = NULL;
    tmpl_cert[1].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_cert,
                                           OSSL_NELEM(tmpl_cert));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    tmpl_cert[1].pValue = OPENSSL_malloc(tmpl_cert[1].ulValueLen);

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_cert,
                                           OSSL_NELEM(tmpl_cert));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    if (tmpl_cert[1].ulValueLen > 0) {
        tmpcert= tmpl_cert[1].pValue;
        store_ctx->cert = d2i_X509(NULL, &tmpcert,
                                   tmpl_cert[1].ulValueLen);
        return 0;
    } else {
        PKCS11_trace("Certificate is empty\n");
        OPENSSL_free(tmpl_cert[1].pValue);
    }

 end:
    return 1;
}

static int pkcs11_get_key(OSSL_STORE_LOADER_CTX *store_ctx,
                         CK_OBJECT_HANDLE obj)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE tmpl_key[3];
    CK_BYTE_PTR pMod, pExp;
    EVP_PKEY* pRsaKey = NULL;
    RSA* rsa;

    tmpl_key[0].type = CKA_CLASS;
    tmpl_key[0].pValue = &key_class;
    tmpl_key[0].ulValueLen = sizeof(key_class);
    tmpl_key[1].type = CKA_MODULUS;
    tmpl_key[1].pValue = NULL;
    tmpl_key[1].ulValueLen = 0;
    tmpl_key[2].type = CKA_PUBLIC_EXPONENT;
    tmpl_key[2].pValue = NULL;
    tmpl_key[2].ulValueLen = 0;

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_key,
                                           OSSL_NELEM(tmpl_key));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    pMod = (CK_BYTE_PTR) OPENSSL_malloc(tmpl_key[1].ulValueLen);
    tmpl_key[1].pValue = pMod;

    pExp = (CK_BYTE_PTR) OPENSSL_malloc(tmpl_key[2].ulValueLen);
    tmpl_key[2].pValue = pExp;

    rv = pkcs11_funcs->C_GetAttributeValue(store_ctx->session, obj,
                                           tmpl_key,
                                           OSSL_NELEM(tmpl_key));
    if (rv != CKR_OK) {
        PKCS11_trace("C_GetAttributeValue: \
                      rv = 0x%.8lX\n", rv);
        goto end;
    }

    pRsaKey = EVP_PKEY_new();
    if (pRsaKey == NULL)
        goto end;

    rsa = RSA_new();
    RSA_set0_key(rsa,
                 BN_bin2bn(tmpl_key[1].pValue,
                           tmpl_key[1].ulValueLen, NULL),
                 BN_bin2bn(tmpl_key[2].pValue,
                           tmpl_key[2].ulValueLen, NULL),
                 NULL);

    EVP_PKEY_set1_RSA(pRsaKey, rsa);

    if (pRsaKey != NULL) {
        store_ctx->key = pRsaKey;
        return 0;
    } else {
        PKCS11_trace("Public Key is empty\n");
        OPENSSL_free(pMod);
        OPENSSL_free(pExp);
    }

 end:
    return 1;
}

int pkcs11_search_start(OSSL_STORE_LOADER_CTX *store_ctx,
                        PKCS11_CTX *pkcs11_ctx)
{
    CK_RV rv;
    CK_ATTRIBUTE tmpl[2];
    CK_SESSION_HANDLE session;
    CK_OBJECT_CLASS key_class;
    int idx = 0;

    session = store_ctx->session;

    if (pkcs11_ctx->type != NULL) {
        if (strncmp(pkcs11_ctx->type, "public", 6) == 0)
           key_class = CKO_PUBLIC_KEY;
        else if (strncmp(pkcs11_ctx->type, "cert", 4) == 0)
           key_class = CKO_CERTIFICATE;
        else if (strncmp(pkcs11_ctx->type, "private", 7) == 0)
           key_class = CKO_PRIVATE_KEY;
        else
           pkcs11_ctx->type = NULL;
    }

    if (pkcs11_ctx->type != NULL) {
        tmpl[0].type = CKA_CLASS;
        tmpl[0].pValue = &key_class;
        tmpl[0].ulValueLen = sizeof(key_class);
    }

    if (pkcs11_ctx->id != NULL) {
        idx++;
        tmpl[idx].type = CKA_ID;
        tmpl[idx].pValue = pkcs11_ctx->id;
        tmpl[idx].ulValueLen = pkcs11_ctx->idlen;
    } else if (pkcs11_ctx->label != NULL) {
        idx++;
        tmpl[idx].type = CKA_LABEL;
        tmpl[idx].pValue = pkcs11_ctx->label;
        tmpl[idx].ulValueLen = (CK_ULONG)strlen((char *)pkcs11_ctx->label);
    }

    if (pkcs11_ctx->pin != NULL) {
        if (!pkcs11_login(session, pkcs11_ctx, CKU_USER))
            goto err;
    }

    if (pkcs11_ctx->type == NULL && pkcs11_ctx->id == NULL
        && pkcs11_ctx->label == NULL)
        rv = pkcs11_funcs->C_FindObjectsInit(session, NULL_PTR, 0);
    else
        rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl, idx + 1);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit: Error = 0x%.8lX\n", rv);
        goto err;
    }
    return 1;
 err:
    return 0;
}
