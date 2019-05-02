/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/store.h>
#include <openssl/rsa.h>

#define MAX 32
#define CK_PTR *

#ifdef _WIN32
# pragma pack(push, cryptoki, 1)
# define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#else
# define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#ifndef NULL_PTR
# define NULL_PTR 0
#endif

#include "pkcs11.h"

#ifdef _WIN32
# pragma pack(pop, cryptoki)
#endif

#define PKCS11_CMD_MODULE_PATH            ENGINE_CMD_BASE
#define PKCS11_CMD_PIN                    (ENGINE_CMD_BASE + 1)
#define PKCS11_CMD_LOAD_CERT_CTRL         (ENGINE_CMD_BASE + 2)

static const ENGINE_CMD_DEFN pkcs11_cmd_defns[] = {
    {PKCS11_CMD_MODULE_PATH,
     "MODULE_PATH",
     "Module path",
     ENGINE_CMD_FLAG_STRING},
    {PKCS11_CMD_PIN,
     "PIN",
     "PIN",
     ENGINE_CMD_FLAG_STRING},
    {PKCS11_CMD_LOAD_CERT_CTRL,
     "LOAD_CERT_CTRL",
     "Get certificate",
     ENGINE_CMD_FLAG_INTERNAL},
    {0, NULL, NULL, 0}
};

typedef struct PKCS11_CTX_st {
    CK_BYTE *id;
    CK_ULONG idlen;
    CK_BYTE *label;
    CK_BYTE *pin;
    CK_ULONG pinlen;
    CK_UTF8CHAR token[32];
    CK_CHAR serial[16];
    CK_UTF8CHAR model[16];
    CK_UTF8CHAR manufacturer[32];
    char *type;
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    char *module_path;
    CRYPTO_RWLOCK *lock;
    const UI_METHOD *ui_method;
    void *callback_data;
} PKCS11_CTX;

struct ossl_store_loader_ctx_st {
    int error;
    int eof;
    int listflag;
    X509 *cert;
    EVP_PKEY *key;
    CK_SESSION_HANDLE session;
};

CK_RV pkcs11_initialize(const char *library_path);
int pkcs11_start_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE *session);
int pkcs11_login(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                 CK_USER_TYPE userType);
EVP_PKEY *pkcs11_load_pkey(CK_SESSION_HANDLE session, PKCS11_CTX *ctx,
                           CK_OBJECT_HANDLE key);
int pkcs11_rsa_sign(int alg, const unsigned char *md,
                    unsigned int md_len, unsigned char *sigret,
                    unsigned int *siglen, const RSA *rsa);
int pkcs11_rsa_priv_enc(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
int pkcs11_rsa_priv_dec(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
int pkcs11_get_slot(PKCS11_CTX *ctx);
CK_OBJECT_HANDLE pkcs11_find_private_key(CK_SESSION_HANDLE session,
                                         PKCS11_CTX *ctx);
CK_OBJECT_HANDLE pkcs11_find_public_key(CK_SESSION_HANDLE session,
                                        PKCS11_CTX *ctx);
void PKCS11_trace(char *format, ...);
PKCS11_CTX *pkcs11_get_ctx(const RSA *rsa);
int pkcs11_search_next_ids(OSSL_STORE_LOADER_CTX *ctx, char **name,
                           char **description);
int pkcs11_search_next_object(OSSL_STORE_LOADER_CTX *ctx,
                              CK_OBJECT_CLASS *class);
int pkcs11_search_next_cert(OSSL_STORE_LOADER_CTX *ctx,
                            CK_BYTE **id, CK_ULONG *idlen);
int pkcs11_search_start(OSSL_STORE_LOADER_CTX *store_ctx,
                        PKCS11_CTX *pkcs11_ctx);
void pkcs11_finalize(void);
void pkcs11_end_session(CK_SESSION_HANDLE session);
int pkcs11_logout(CK_SESSION_HANDLE session);
void pkcs11_close_operation(CK_SESSION_HANDLE session);
extern int rsa_pkcs11_idx;
