#ifndef PKSC11_CTX_H
#define PKSC11_CTX_H

#ifndef CK_PTR
# define CK_PTR *
#endif

#ifndef CK_BOOL
  typedef unsigned char CK_BOOL;
#endif                          /* CK_BOOL */

#ifndef CK_DECLARE_FUNCTION
# define CK_DECLARE_FUNCTION(returnType, name) \
         returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
         returnType (CK_PTR name)
#endif

#ifndef CK_CALLBACK_FUNCTION
# define CK_CALLBACK_FUNCTION(returnType, name) \
         returnType (CK_PTR name)
#endif

#ifndef NULL_PTR
# include <stddef.h> /* provides NULL */
# define NULL_PTR NULL
#endif

#ifndef PKCS11UNPACKED /* for PKCS11 modules that dont pack */
# pragma pack(push, 1)
#endif

#include "pkcs11-v30/pkcs11.h" /* official PKCS11 3.0 header */

#ifndef PKCS11UNPACKED
# pragma pack(pop)
#endif


#include <openssl/core.h>
#include <openssl/core_names.h>
/*
 * Copyright 2000-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include "internal/refcount.h"
#include "internal/thread_once.h"
#include "prov/provider_ctx.h"

typedef struct CK_OPENCRYPTOKI_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
} CK_OPENCRYPTOKI_FUNCTION_LIST;

typedef struct pkcs11_type_item_st {
    CK_MECHANISM_TYPE type;
    CK_MECHANISM_INFO info;
}PKCS11_TYPE_DATA_ITEM;

typedef struct pkcs11_type_st {
    OSSL_ALGORITHM *algolist;
    PKCS11_TYPE_DATA_ITEM *items;
    int len;
}PKCS11_TYPE_DATA;

struct pkcs11_st {
    PROV_CTX ctx;

    int name_id;
    char *type_name;
    const char *description;

    const OSSL_CORE_HANDLE *handle;
    OPENSSL_CORE_CTX *corectx;

    /* default core params */
    unsigned char *openssl_version;
    unsigned char *provider_name;
    unsigned char *module_filename;
    unsigned char *userpin;

    /* pkcs11 module data */
    void *lib_handle;
    CK_OPENCRYPTOKI_FUNCTION_LIST *lib_functions;
    CK_SLOT_ID slot;
    int token;

    PKCS11_TYPE_DATA keymgmt;

    CK_SESSION_HANDLE session;
    CK_BBOOL tokobjs;

    /* operation dispatch tables */
    OSSL_ALGORITHM *digest;
    OSSL_ALGORITHM *cipher;
    OSSL_ALGORITHM *mac;
    OSSL_ALGORITHM *kdf;
    OSSL_ALGORITHM *keyexch;
    OSSL_ALGORITHM *signature;
    OSSL_ALGORITHM *asym_cipher;
    OSSL_ALGORITHM *serializer;

    /* Error functions */
    OSSL_FUNC_core_new_error_fn             *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn       *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn            *core_vset_error;

   /* functions offered by libcrypto to the providers */
/*    OSSL_FUNC_core_gettable_params_fn       *core_gettable_params;
    OSSL_FUNC_core_get_params_fn            *core_get_params;
    OSSL_FUNC_core_thread_start_fn          *core_thread_start;
    OSSL_FUNC_core_get_libctx_fn            *core_get_libctx;
    OSSL_FUNC_core_new_error_fn             *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn       *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn            *core_vset_error;
    OSSL_FUNC_core_set_error_mark_fn        *core_set_error_mark;
    OSSL_FUNC_core_clear_last_error_mark_fn *core_clear_last_error_mark;
    OSSL_FUNC_core_pop_error_to_mark_fn     *core_pop_error_to_mark;
    OSSL_FUNC_CRYPTO_malloc_fn              *CRYPTO_malloc;
    OSSL_FUNC_CRYPTO_zalloc_fn              *CRYPTO_zalloc;
    OSSL_FUNC_CRYPTO_free_fn                *CRYPTO_free;
    OSSL_FUNC_CRYPTO_clear_free_fn          *CRYPTO_clear_free;
    OSSL_FUNC_CRYPTO_realloc_fn             *CRYPTO_realloc;
    OSSL_FUNC_CRYPTO_clear_realloc_fn       *CRYPTO_clear_realloc;
    OSSL_FUNC_CRYPTO_secure_malloc_fn       *CRYPTO_secure_malloc;
    OSSL_FUNC_CRYPTO_secure_zalloc_fn       *CRYPTO_secure_zalloc;
    OSSL_FUNC_CRYPTO_secure_free_fn         *CRYPTO_secure_free;
    OSSL_FUNC_CRYPTO_secure_clear_free_fn   *CRYPTO_secure_clear_free;
    OSSL_FUNC_CRYPTO_secure_allocated_fn    *CRYPTO_secure_allocated;
    OSSL_FUNC_OPENSSL_cleanse_fn            *OPENSSL_cleanse;
    OSSL_FUNC_BIO_new_file_fn               *BIO_new_file;
    OSSL_FUNC_BIO_new_membuf_fn             *BIO_new_membuf;
    OSSL_FUNC_BIO_read_ex_fn                *BIO_read_ex;
    OSSL_FUNC_BIO_free_fn                   *BIO_free;
    OSSL_FUNC_BIO_vprintf_fn                *BIO_vprintf;
    OSSL_FUNC_self_test_cb_fn               *self_test_cb;*/
};



#endif // PKSC11_CTX_H
