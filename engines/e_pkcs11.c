#include <openssl/engine.h>
#include <string.h>
#include <openssl/err.h>
#include <internal/dso.h>
#include "e_pkcs11_err.c"

#define CK_PTR *

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
#else
#define DEBUG
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
#endif

#ifdef _WIN32
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#else
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#endif

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#define PKCS11_CMD_MODULE_PATH            ENGINE_CMD_BASE
#define PKCS11_CMD_PIN                    (ENGINE_CMD_BASE + 1)

static void pkcs11_finalize(void);
static void pkcs11_end_session(CK_SESSION_HANDLE session);
static int pkcs11_logout(CK_SESSION_HANDLE session);
static CK_RV pkcs11_initialize(const char *library_path);
static CK_SESSION_HANDLE pkcs11_start_session(CK_SLOT_ID slotId);
static CK_RV pkcs11_load_functions(const char *library_path);
static int pkcs11_parse_uri(const char *path, char *token, char **value);
static char pkcs11_hex_int(char nib1, char nib2);
static int pkcs11_rsa_enc(int flen, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding);
static RSA_METHOD *pkcs11_rsa(void);
static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data);
static int pkcs11_bind(ENGINE *e, const char *id);
static void PKCS11_trace(char *format, ...);
static int pkcs11_destroy(ENGINE *e);

typedef CK_RV pkcs11_pFunc(CK_FUNCTION_LIST **pkcs11_funcs);

CK_FUNCTION_LIST *pkcs11_funcs;

typedef struct PKCS11_CTX_st PKCS11_CTX;

static void pkcs11_ctx_free(PKCS11_CTX *ctx);
static int pkcs11_login(PKCS11_CTX *ctx, CK_USER_TYPE userType);
static CK_OBJECT_HANDLE pkcs11_get_private_key(PKCS11_CTX *ctx);
static int pkcs11_finish(ENGINE *e);
static CK_SLOT_ID pkcs11_get_slot(PKCS11_CTX *ctx);
static PKCS11_CTX *pkcs11_ctx_new(void);

struct PKCS11_CTX_st {
    CK_BYTE *id;
    CK_BYTE *pin;
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    char *module_path;
};

static const char *engine_id = "pkcs11";
static const char *engine_name = "A minimal PKCS#11 engine only for sign";
static int pkcs11_idx = -1;

static int pkcs11_init(ENGINE *e)
{
    PKCS11_CTX *ctx;

    if (pkcs11_idx < 0) {
        pkcs11_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (pkcs11_idx < 0)
            goto memerr;
    }

    ctx = pkcs11_ctx_new();
    if (ctx == NULL)
        goto memerr;

    ENGINE_set_ex_data(e, pkcs11_idx, ctx);
    return 1;

 memerr:
    PKCS11err(PKCS11_F_PKCS11_INIT, ERR_R_MALLOC_FAILURE);
    return 0;
}

static int pkcs11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    char *tmpstr;

    PKCS11_CTX *ctx;

    if (pkcs11_idx == -1) {
        PKCS11err(PKCS11_F_PKCS11_CTRL, PKCS11_R_ENGINE_NOT_INITIALIZED);
        return 0;
    }
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);

    /* TODO: Read config file */

    switch (cmd) {
    case PKCS11_CMD_MODULE_PATH:
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->module_path = tmpstr;
            PKCS11_trace("Setting module path to %s\n", ctx->module_path);
        } else {
            PKCS11err(PKCS11_F_PKCS11_CTRL, ERR_R_MALLOC_FAILURE);
            ret = 0;
        }
        break;

    case PKCS11_CMD_PIN:
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->pin = (CK_BYTE *) tmpstr;
            PKCS11_trace("Setting pin\n");
        } else {
            PKCS11err(PKCS11_F_PKCS11_CTRL, ERR_R_MALLOC_FAILURE);
            ret = 0;
        }
        break;
    }
    return ret;
}

static int pkcs11_rsa_enc(int flen, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding)
{
    CK_RV rv;
    PKCS11_CTX *ctx;
    ENGINE *e;
    CK_ULONG signatureLen = 0;
    CK_MECHANISM sign_mechanism = { 0 };

    sign_mechanism.mechanism = CKM_RSA_PKCS;
    e = ENGINE_by_id("pkcs11");
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    rv = pkcs11_funcs->C_SignInit(ctx->session, &sign_mechanism, ctx->key);

    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    if (!pkcs11_login(ctx, CKU_CONTEXT_SPECIFIC)) goto err;

    /* Get length of signature */
    rv = pkcs11_funcs->C_Sign(ctx->session, (CK_BYTE *) from, flen, NULL,
                              &signatureLen);

    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_FAILED);
        goto err;
    }

    /* Sign */
    rv = pkcs11_funcs->C_Sign(ctx->session, (CK_BYTE *) from, flen, to,
                              &signatureLen);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_FAILED);
        goto err;
    }

    pkcs11_logout(ctx->session);
    pkcs11_end_session(ctx->session);
    pkcs11_finalize();
    return 1;

 err:
    return 0;
}

static RSA_METHOD *pkcs11_rsa()
{
    static RSA_METHOD *pkcs11_rsa = NULL;
    pkcs11_rsa = RSA_meth_new("PKCS#11 RSA method", 0);
    RSA_meth_set_priv_enc(pkcs11_rsa, pkcs11_rsa_enc);
    return pkcs11_rsa;
}

/**
 * Load the PKCS#11 functions into global function list.
 * @param library_path
 * @return
 */
static CK_RV pkcs11_load_functions(const char *library_path)
{
    CK_RV rv;
    static DSO *pkcs11_dso = NULL;
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
static CK_RV pkcs11_initialize(const char *library_path)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;

    if (library_path == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        PKCS11_trace("Getting PKCS11 function list failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE,
                  PKCS11_R_GETTING_FUNCTION_LIST_FAILED);
        return rv;
    }

    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = pkcs11_funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Initialize failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE, PKCS11_R_INITIALIZE_FAILED);
        return rv;
    }

    return CKR_OK;
}

static void pkcs11_finalize(void)
{
    pkcs11_funcs->C_Finalize(NULL);
}

static CK_SLOT_ID pkcs11_get_slot(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_SLOT_ID slotId;
    CK_ULONG slotCount;
    CK_SLOT_ID_PTR slotList;
    int i;

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, NULL, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        goto err;
    }

    if (slotCount == 0) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_SLOT_NOT_FOUND);
        goto err;
    }

    slotList = OPENSSL_malloc(sizeof(CK_SLOT_ID) * slotCount);

    if (slotList == NULL) {
        goto err;
    }

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        goto err;
    }

    slotId = slotList[0];

    for (i = 0; i < slotCount; i++) {
        slotId = slotList[i];
        if (ctx->slotid == slotList[i]) {
            slotId = slotList[i];
            break;
        }
    }

    OPENSSL_free(slotList);
    return slotId;

 err:
    return -1;
}

static CK_SESSION_HANDLE pkcs11_start_session(CK_SLOT_ID slotId)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    rv = pkcs11_funcs->C_OpenSession(slotId, CKF_SERIAL_SESSION, NULL,
                                     NULL, &session);
    if (rv != CKR_OK) {
        PKCS11_trace("C_OpenSession failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_START_SESSION,
                  PKCS11_R_OPEN_SESSION_ERROR);
        goto err;
    }
    return session;

 err:
    return 0;
}

static int pkcs11_login(PKCS11_CTX *ctx, CK_USER_TYPE userType)
{
    /* Binary pins not supported */
    CK_RV rv;

    if (ctx->pin) {
        rv = pkcs11_funcs->C_Login(ctx->session, userType, ctx->pin,
                                   strlen((char *)ctx->pin));
        if (rv != CKR_OK) {
            PKCS11_trace("C_Login failed, error: %#04X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_LOGIN, PKCS11_R_LOGIN_FAILED);
            goto err;
        }
    return 1;
    }
 err:
    return 0;
}

static int pkcs11_logout(CK_SESSION_HANDLE session)
{
    CK_RV rv;

    rv = pkcs11_funcs->C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN && rv != CKR_OK) {
        PKCS11_trace("C_Logout failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_LOGOUT, PKCS11_R_LOGOUT_FAILED);
        goto err;
    }
    return 1;

 err:
    return 0;
}

static void pkcs11_end_session(CK_SESSION_HANDLE session)
{
    pkcs11_funcs->C_CloseSession(session);
}

CK_OBJECT_HANDLE pkcs11_get_private_key(PKCS11_CTX *ctx)
{
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_OBJECT_HANDLE objhandle;
    size_t len_kc, len_kt, id_len;
    unsigned long count;

    id_len = strlen((char *)ctx->id);
    len_kc = sizeof(key_class);
    len_kt = sizeof(key_type);
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, len_kc },
        { CKA_KEY_TYPE, &key_type, len_kt },
        { CKA_ID, ctx->id, id_len }
    };

    rv = pkcs11_funcs->C_FindObjectsInit(ctx->session, tmpl,
                                         sizeof(tmpl) / sizeof(CK_ATTRIBUTE) );

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(ctx->session, &objhandle, 1, &count);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_FAILED);
        goto err;
    }
    return objhandle;

 err:
    return -1;
}

static char pkcs11_hex_int(char nib1, char nib2)
{
    int ret = (nib1-(nib1 <= 57 ? 48 : (nib1 < 97 ? 55 : 87)))*16;
    ret += (nib2-(nib2 <= 57 ? 48 : (nib2 < 97 ? 55 : 87)));
    return ret;
}

static int pkcs11_parse_uri(const char *path, char *token, char **value)
{
    char *tmp, *end, *hex2bin;
    size_t vlen, i, j = 0;

    if ((tmp = strstr(path, token)) == NULL)
        return 0;
    tmp += strlen(token);
    *value = OPENSSL_malloc(strlen(tmp) + 1);

    if (*value == NULL) goto err;

    end = strpbrk(tmp, ";");

    snprintf(*value, end == NULL ? strlen(tmp) + 1 :
             (size_t) (end - tmp + 1), "%s", tmp);
    hex2bin = OPENSSL_malloc(strlen(*value) + 1);

    if (hex2bin == NULL) goto err;

    vlen = strlen(*value);
    for (i = 0; i < vlen; i++) {
        if (*(*value+i) == '%' && i < (strlen(*value)-2)) {
            *(hex2bin+j) = pkcs11_hex_int(*(*value+i+1), *(*value+i+2));
            i += 2;
        } else {
            *(hex2bin+j) = *(*value+i);
        }
        j++;
    }
    *(hex2bin+j) = '\0';
    *value = hex2bin;
    return 1;

 err:
    return 0;
}

static int pkcs11_get_console_pin(char **pin)
{
    int i, ret = 0;

#ifndef OPENSSL_NO_UI_CONSOLE

    char *strbuf = NULL;

    strbuf = OPENSSL_malloc(512);
    for (;;) {
        char prompt[200];
        BIO_snprintf(prompt, sizeof(prompt), "Enter PIN: ");
        strbuf[0] = '\0';
        i = EVP_read_pw_string((char *)strbuf, 512, prompt, 1);
        if (i == 0) {
            if (strbuf[0] == '\0') {
                goto err;
            }
            *pin = strbuf;
            return 1;
        }
        if (i < 0) {
            PKCS11_trace("bad password read\n");
            goto err;
        }
    }

 err:
    OPENSSL_free(strbuf);
#endif

    return ret;
}

static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data)
{
    CK_ULONG kt, class;
    size_t len_kt, len_class;

    len_kt = sizeof(kt);
    len_class = sizeof(class);
    CK_ATTRIBUTE key_type[] = {
        { CKA_CLASS,    &class, len_class },
        { CKA_KEY_TYPE, &kt,    len_kt }
    };
    EVP_PKEY *k = NULL;
    CK_RV rv;
    CK_SLOT_ID slot;
    PKCS11_CTX *ctx;

    char *id, *pin, *module_path, *slotid;

    if (strncmp(path, "pkcs11:", 7) == 0) {
        path += 7;

	if (!pkcs11_parse_uri(path,"module-path=", &module_path))
           goto err;
	if (!pkcs11_parse_uri(path,"id=", &id))
           goto err;
	if (!pkcs11_parse_uri(path,"slot-id=", &slotid)) {
           slotid = OPENSSL_malloc(2);
           slotid[0] = '0';
        }
	if (!pkcs11_parse_uri(path,"pin-value=", &pin) &&
            !pkcs11_get_console_pin(&pin) )
           goto err;

    } else {
        PKCS11_trace("String pkcs11: not found\n");
        goto err;
    }
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);

    ctx->id = (CK_BYTE *) id;
    ctx->pin = (CK_BYTE *) pin;
    ctx->slotid = (CK_SLOT_ID) atoi(slotid);

    rv = pkcs11_initialize(module_path);

    if (rv != CKR_OK) goto err;

    slot = pkcs11_get_slot(ctx);
    if (slot < 0) goto err;

    ctx->session = pkcs11_start_session(slot);

    if (!pkcs11_login(ctx, CKU_USER)) goto err;

    ctx->key = pkcs11_get_private_key(ctx);
    if (ctx->key < 0) goto err;

    rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key, key_type, 2);

    if (rv != CKR_OK || class != CKO_PRIVATE_KEY) {
        PKCS11_trace("C_GetAttributeValue failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_ENGINE_LOAD_PRIVATE_KEY,
                  PKCS11_R_GETATTRIBUTEVALUE_FAILED);
        goto err;
    }

    if(kt == CKK_RSA) {
        CK_ATTRIBUTE rsa_attributes[] = {
            { CKA_MODULUS, NULL, 0 },
            { CKA_PUBLIC_EXPONENT, NULL, 0 }
        };
        RSA *rsa = RSA_new();

        rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                               rsa_attributes, 2);

        if (rv != CKR_OK) {
            PKCS11_trace("C_GetAttributeValue failed, error: %#04X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_ENGINE_LOAD_PRIVATE_KEY, 
                      PKCS11_R_GETATTRIBUTEVALUE_FAILED);
            goto err;
        }

        if  (rsa_attributes[0].ulValueLen == 0 ||
             rsa_attributes[1].ulValueLen == 0) goto err;

        rsa_attributes[0].pValue = OPENSSL_malloc(rsa_attributes[0].ulValueLen);
        rsa_attributes[1].pValue = OPENSSL_malloc(rsa_attributes[1].ulValueLen);

        if (rsa_attributes[0].pValue == NULL ||
            rsa_attributes[1].pValue == NULL) {
            OPENSSL_free(rsa_attributes[0].pValue);
            OPENSSL_free(rsa_attributes[1].pValue);
            goto err;
        }

        rv = pkcs11_funcs->C_GetAttributeValue(ctx->session, ctx->key,
                                               rsa_attributes, 2);

        if (rv != CKR_OK) {
            PKCS11_trace("C_GetAttributeValue failed, error: %#04X\n", rv);
            PKCS11err(PKCS11_F_PKCS11_ENGINE_LOAD_PRIVATE_KEY,
                      PKCS11_R_GETATTRIBUTEVALUE_FAILED);
            goto err;
        }

        RSA_set0_key(rsa,
                     BN_bin2bn(rsa_attributes[0].pValue,
                               rsa_attributes[0].ulValueLen, NULL),
                     BN_bin2bn(rsa_attributes[1].pValue,
                               rsa_attributes[1].ulValueLen, NULL),
                     NULL);
        if((k = EVP_PKEY_new()) != NULL) {
            EVP_PKEY_set1_RSA(k, rsa);
        }

        OPENSSL_free(rsa_attributes[0].pValue);
        OPENSSL_free(rsa_attributes[1].pValue);
    }
    return k;

 err:
    PKCS11_trace("pkcs11_engine_load_private_key failed\n");
    return 0;
}

static int pkcs11_bind(ENGINE *e, const char *id)
{
  int ret = 0;

  if (!ENGINE_set_id(e, engine_id)
      || !ENGINE_set_name(e, engine_name)
      || !ENGINE_set_RSA(e, pkcs11_rsa())
      || !ENGINE_set_load_privkey_function(e, pkcs11_engine_load_private_key)
      || !ENGINE_set_destroy_function(e, pkcs11_destroy)
      || !ENGINE_set_init_function(e, pkcs11_init)
      || !ENGINE_set_finish_function(e, pkcs11_finish)
      || !ENGINE_set_ctrl_function(e, pkcs11_ctrl))
      goto end;

  ERR_load_PKCS11_strings();

  ret = 1;
 end:
  return ret;
}

static void PKCS11_trace(char *format, ...)
{

    BIO *out;
    va_list args;

    out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (out == NULL) {
        PKCS11err(PKCS11_F_PKCS11_TRACE, PKCS11_R_FILE_OPEN_ERROR);
        return;
    }

    va_start(args, format);
    BIO_vprintf(out, format, args);
    va_end(args);
    BIO_free(out);
}

static PKCS11_CTX *pkcs11_ctx_new(void)
{
    PKCS11_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL) {
        PKCS11err(PKCS11_F_PKCS11_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ctx;
}

static int pkcs11_finish(ENGINE *e)
{
    PKCS11_CTX *ctx;
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    pkcs11_ctx_free(ctx);
    ENGINE_set_ex_data(e, pkcs11_idx, NULL);
    return 1;
}

static int pkcs11_destroy(ENGINE *e)
{
    /* TODO: RSA_meth_free ecc. */

    ERR_unload_PKCS11_strings();
    return 1;
}

static void pkcs11_ctx_free(PKCS11_CTX *ctx)
{
    PKCS11_trace("Calling pkcs11_ctx_free with %lx\n", ctx);
    if (!ctx)
        return;
    OPENSSL_free(ctx);
}

IMPLEMENT_DYNAMIC_BIND_FN(pkcs11_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
