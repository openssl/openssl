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

static void pkcs11_finalize(void);
static void pkcs11_end_session(CK_SESSION_HANDLE session);
static int pkcs11_login(CK_SESSION_HANDLE session, CK_BYTE *pin,
                        CK_USER_TYPE userType);
static int pkcs11_logout(CK_SESSION_HANDLE session);
static CK_SLOT_ID pkcs11_get_slot(void);
static CK_RV pkcs11_initialize(char *library_path);
static CK_SESSION_HANDLE pkcs11_start_session(CK_SLOT_ID slotId);
static CK_OBJECT_HANDLE pkcs11_get_private_key(CK_SESSION_HANDLE session,
                                               CK_BYTE *id, size_t id_len);
static CK_RV pkcs11_load_functions(char *library_path);
int pkcs11_parse_uri(const char *path, char *token, char **value);
char pkcs11_hex_int(char nib1, char nib2);

int pkcs11_rsa_enc(int flen, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding);
static RSA_METHOD *pkcs11_rsa(void);
static CK_SLOT_ID pkcs11_get_slot(void);
static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data);
static int pkcs11_bind(ENGINE *e, const char *id);
static void PKCS11_trace(char *format, ...);
static int pkcs11_destroy(ENGINE *e);

typedef CK_RV pkcs11_pFunc(CK_FUNCTION_LIST **pkcs11_funcs);

CK_FUNCTION_LIST *pkcs11_funcs;

typedef struct st_pkcs11 {
    CK_BYTE *id;
    CK_BYTE *pin;
    CK_SLOT_ID slotid;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
} PKCS11;

static PKCS11 pkcs11st;
static const char *engine_id = "pkcs11";
static const char *engine_name = "A minimal PKCS#11 engine only for sign";

int pkcs11_rsa_enc(int flen, const unsigned char *from,
                   unsigned char *to, RSA *rsa, int padding)
{
    CK_RV rv;
    CK_MECHANISM sign_mechanism;
    sign_mechanism.mechanism = CKM_RSA_PKCS;
    sign_mechanism.pParameter = 0;
    sign_mechanism.ulParameterLen = 0;
    CK_ULONG signatureLen;

    signatureLen = 0;
    rv = pkcs11_funcs->C_SignInit(pkcs11st.session,
                                  &sign_mechanism, pkcs11st.key);
    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }

    pkcs11_login(pkcs11st.session, pkcs11st.pin, CKU_CONTEXT_SPECIFIC);

    /* Get length of signature */
    rv = pkcs11_funcs->C_Sign(pkcs11st.session, (CK_BYTE *) from, flen, NULL,
                              &signatureLen);

    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_FAILED);
        goto err;
    }

    /* Sign */
    rv = pkcs11_funcs->C_Sign(pkcs11st.session, (CK_BYTE *) from, flen, to,
                              &signatureLen);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_FAILED);
        goto err;
    }

    pkcs11_logout(pkcs11st.session);
    pkcs11_end_session(pkcs11st.session);
    pkcs11_finalize();
    return 1;

 err:
    return 0;
}

RSA_METHOD *pkcs11_rsa()
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
CK_RV pkcs11_load_functions(char *library_path)
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
CK_RV pkcs11_initialize(char *library_path)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;

    if (!library_path) {
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

static CK_SLOT_ID pkcs11_get_slot()
{
    CK_RV rv;
    CK_SLOT_ID slotId;
    CK_ULONG slotCount;
    CK_SLOT_ID_PTR slotList;
    int i;

    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, 0, &slotCount);

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
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_MEMORY_ALLOCATION_FAILED);
        OPENSSL_free(slotList);
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
        if (pkcs11st.slotid == slotList[i]) {
            slotId = slotList[i];
            break;
        }
    }

    OPENSSL_free(slotList);
    return slotId;

 err:
    return 0;
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

static int pkcs11_login(CK_SESSION_HANDLE session, CK_BYTE *pin,
                        CK_USER_TYPE userType)
{
    /* Binary pins not supported */
    CK_RV rv;

    if (pin) {
        rv = pkcs11_funcs->C_Login(session, userType, pin,
                                   strlen((char *)pin));
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

CK_OBJECT_HANDLE pkcs11_get_private_key(CK_SESSION_HANDLE session,
                                 CK_BYTE *id, size_t id_len) {
    CK_RV rv;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    size_t len_kc, len_kt;

    len_kc = sizeof(key_class);
    len_kt = sizeof(key_type);
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, len_kc },
        { CKA_KEY_TYPE, &key_type, len_kt },
        { CKA_ID, id, id_len }
    };
    unsigned long count;
    CK_OBJECT_HANDLE objhandle;

    rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl,
                                  sizeof (tmpl) / sizeof (CK_ATTRIBUTE) );

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#04X\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_PRIVATE_KEY,
                  PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(session, &objhandle, 1, &count);

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

char pkcs11_hex_int(char nib1, char nib2)
{
    int ret = (nib1-(nib1 <= 57 ? 48 : (nib1 < 97 ? 55 : 87)))*16;
    ret += (nib2-(nib2 <= 57 ? 48 : (nib2 < 97 ? 55 : 87)));
    return ret;
}

int pkcs11_parse_uri(const char *path, char *token, char **value)
{
    char *tmp, *end, *hex2bin;
    size_t i, j = 0;

    if ((tmp = strstr(path, token)) == NULL)
        return 0;
    tmp += strlen(token);
    *value = OPENSSL_malloc(strlen(tmp) + 1);
    end = strpbrk(tmp, ";");

    snprintf(*value, end == NULL ? strlen(tmp) + 1 :
             (size_t) (end - tmp + 1), "%s", tmp);
    hex2bin = OPENSSL_malloc(strlen(*value) + 1);
    for (i = 0; i < strlen(*value); i++) {
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
    char *id, *pin, *module_path, *slotid;

    if (strncmp(path, "pkcs11:", 7) == 0) {
        path += 7;

	if (!pkcs11_parse_uri(path,"module-path=", &module_path))
           goto err;
	if (!pkcs11_parse_uri(path,"id=", &id))
           goto err;
	if (!pkcs11_parse_uri(path,"slot-id=", &slotid))
           slotid[0] = '0';
	if (!pkcs11_parse_uri(path,"pin-value=", &pin))
           goto err;

    } else {
        PKCS11_trace("String pkcs11: not found\n");
        goto err;
    }

    pkcs11st.id = (CK_BYTE *) id;
    pkcs11st.pin = (CK_BYTE *) pin;
    pkcs11st.slotid = (CK_SLOT_ID) atoi(slotid);

    rv = pkcs11_initialize(module_path);

    if (rv != CKR_OK) {
        goto err;
    }

    pkcs11st.session = pkcs11_start_session(pkcs11_get_slot());
    pkcs11_login(pkcs11st.session, pkcs11st.pin, CKU_USER);
    pkcs11st.key = pkcs11_get_private_key(pkcs11st.session, pkcs11st.id,
                                          strlen((char *)pkcs11st.id));

    rv = pkcs11_funcs->C_GetAttributeValue(pkcs11st.session,
                                    pkcs11st.key, key_type, 2);

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

        rv = pkcs11_funcs->C_GetAttributeValue(pkcs11st.session,
                                               pkcs11st.key, rsa_attributes, 2);

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

        rv = pkcs11_funcs->C_GetAttributeValue(pkcs11st.session,
                                               pkcs11st.key, rsa_attributes, 2);

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
    return 0;
}

static int pkcs11_bind(ENGINE *e, const char *id)
{
  int ret = 0;

  if (!ENGINE_set_id(e, engine_id)
      || !ENGINE_set_name(e, engine_name)
      || !ENGINE_set_RSA(e, pkcs11_rsa())
      || !ENGINE_set_load_privkey_function(e, pkcs11_engine_load_private_key)
      || !ENGINE_set_destroy_function(e, pkcs11_destroy))
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

static int pkcs11_destroy(ENGINE *e)
{
    /* TODO: RSA_meth_free ecc. */

    ERR_unload_PKCS11_strings();
    return 1;
}


IMPLEMENT_DYNAMIC_BIND_FN(pkcs11_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
