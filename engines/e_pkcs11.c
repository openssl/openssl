#include <openssl/engine.h>
#include <string.h>
#include <openssl/err.h>
#include "e_pkcs11_err.c"

#define CK_PTR *

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#include <windows.h>
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
#else
#define DEBUG
#include <dlfcn.h>
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

static void pkcs11_finalize();
static void pkcs11_end_session(CK_SESSION_HANDLE session);
static int pkcs11_login(CK_SESSION_HANDLE session, CK_BYTE *pin);
static int pkcs11_logout(CK_SESSION_HANDLE session);
static CK_SLOT_ID pkcs11_get_slot();
static CK_RV pkcs11_initialize(char *library_path);
static CK_SESSION_HANDLE pkcs11_start_session(CK_SLOT_ID slotId);
static CK_OBJECT_HANDLE pkcs11_get_private_key(CK_SESSION_HANDLE session,
                                 CK_BYTE *id, size_t id_len);
static CK_RV pkcs11_load_functions(char *library_path);

int pkcs11_rsa_enc(int flen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding);
static RSA_METHOD *pkcs11_rsa();

static CK_SLOT_ID pkcs11_get_slot();
static int pkcs11_parse_attribute(const char *attr, int attrlen, unsigned char **field);
static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                         UI_METHOD * ui_method,
                                         void *callback_data);
static int pkcs11_bind(ENGINE *e, const char *id);
static void PKCS11_trace(char *format, ...);
static int pkcs11_destroy(ENGINE *e);

CK_FUNCTION_LIST *pkcs11_funcs;

typedef struct st_pkcs11 {
    CK_BYTE *id;
    CK_BYTE *pin;
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
    CK_ULONG signatureLen = sizeof(to);

    rv = pkcs11_funcs->C_SignInit(pkcs11st.session, &sign_mechanism, pkcs11st.key);

    if (rv != CKR_OK) {
        PKCS11_trace("C_SignInit failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_RSA_ENC, PKCS11_R_SIGN_INIT_FAILED);
        goto err;
    }
    rv = pkcs11_funcs->C_Sign(pkcs11st.session, (CK_BYTE *) from, flen, to,
                              &signatureLen);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Sign failed, error: %#02x\n", rv);
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

#ifdef WIN32
    HMODULE d = LoadLibraryA(library_path);
#else
    CK_RV(*pFunc)();
    void *d;
    d = dlopen(library_path, RTLD_NOW | RTLD_GLOBAL);
#endif

    if (d == NULL) {
        PKCS11_trace("%s not found in LD_LIBRARY_PATH\n", library_path);
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS, PKCS11_R_LIBRARY_PATH_NOT_FOUND);
        return CKR_GENERAL_ERROR;
    }

#ifdef WIN32
    CK_C_GetFunctionList pFunc = (CK_C_GetFunctionList)
                           GetProcAddress(d, "C_GetFunctionList");
#else
    pFunc = (CK_RV (*)()) dlsym(d, "C_GetFunctionList");
#endif

    if (pFunc == NULL) {
        PKCS11_trace("C_GetFunctionList() not found in module %s\n", library_path);
        PKCS11err(PKCS11_F_PKCS11_LOAD_FUNCTIONS, PKCS11_R_GETFUNCTIONLIST_NOT_FOUND);
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

    if (!library_path) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        PKCS11_trace("Getting PKCS11 function list failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE, PKCS11_R_GETTING_FUNCTION_LIST_FAILED);
        return rv;
    }

    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = pkcs11_funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        PKCS11_trace("C_Initialize failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_INITIALIZE, PKCS11_R_INITIALIZE_FAILED);
        return rv;
    }

    return CKR_OK;
}

static void pkcs11_finalize()
{
    pkcs11_funcs->C_Finalize(NULL);
}

static CK_SLOT_ID pkcs11_get_slot()
{
    CK_RV rv;
    CK_SLOT_ID slotId;
    CK_ULONG slotCount = 10;
    CK_SLOT_ID *slotIds = OPENSSL_malloc(sizeof(CK_SLOT_ID) * slotCount);
    rv = pkcs11_funcs->C_GetSlotList(CK_TRUE, slotIds, &slotCount);

    if (rv != CKR_OK) {
        PKCS11_trace("C_GetSlotList failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_GET_SLOTLIST_FAILED);
        goto err;
    }

    if (slotCount < 1) {
        PKCS11err(PKCS11_F_PKCS11_GET_SLOT, PKCS11_R_SLOT_NOT_FOUND);
        goto err;
    }

    slotId = slotIds[0];
    OPENSSL_free(slotIds);
    return slotId;

 err:
    free(slotIds);
    return 0;
}

static CK_SESSION_HANDLE pkcs11_start_session(CK_SLOT_ID slotId)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    rv = pkcs11_funcs->C_OpenSession(slotId, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        PKCS11_trace("C_OpenSession failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_START_SESSION, PKCS11_R_OPEN_SESSION_ERROR);
        goto err;
    }
    return session;

 err:
    return 0;
}

static int pkcs11_login(CK_SESSION_HANDLE session, CK_BYTE *pin)
{
    CK_RV rv;
    if (pin) {
        rv = pkcs11_funcs->C_Login(session, CKU_USER, pin, strlen((char *)pin));
        if (rv != CKR_OK) {
            PKCS11_trace("C_Login failed, error: %#02x\n", rv);
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
    if (rv != CKR_USER_NOT_LOGGED_IN) {
        PKCS11_trace("C_Logout failed, error: %#02x\n", rv);
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
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_ID, id, id_len }
    };
    unsigned long count;
    CK_OBJECT_HANDLE objhandle;
    rv = pkcs11_funcs->C_FindObjectsInit(session, tmpl,
                                  sizeof (tmpl) / sizeof (CK_ATTRIBUTE) );

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjectsInit failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_PRIVATE_KEY, PKCS11_R_FIND_OBJECT_INIT_FAILED);
        goto err;
    }

    rv = pkcs11_funcs->C_FindObjects(session, &objhandle, 1, &count);

    if (rv != CKR_OK) {
        PKCS11_trace("C_FindObjects failed, error: %#02x\n", rv);
        PKCS11err(PKCS11_F_PKCS11_GET_PRIVATE_KEY, PKCS11_R_FIND_OBJECT_FAILED);
        goto err;
    }
    return objhandle;

 err:
    return -1;
}

static int pkcs11_hex_to_bin(const char *in, unsigned char *out, size_t *outlen)
{
    size_t left, count = 0;

    if (in == NULL || *in == '\0') {
        *outlen = 0;
        return 1;
    }

    left = *outlen;

    while (*in != '\0') {
        int byte = 0, nybbles = 2;

        while (nybbles-- && *in && *in != ':') {
            char c;
            byte <<= 4;
            c = *in++;
            if ('0' <= c && c <= '9') c -= '0';
            else if ('a' <= c && c <= 'f') c = c - 'a' + 10;
            else if ('A' <= c && c <= 'F') c = c - 'A' + 10;
            else {
                *outlen = 0;
                return 0;
            }
            byte |= c;
        }
        if (*in == ':') in++;
        if (left == 0) {
            *outlen = 0;
            return 0;
        }
        out[count++] = (unsigned char)byte;
        left--;
    }
    *outlen = count;
    return 1;
}

static int pkcs11_parse_attribute(const char *attr, int attrlen, unsigned char **field)
{
    size_t max, outlen = 0;
    unsigned char *out;
    int ret = 1;
    out = OPENSSL_malloc(attrlen + 1);
    if (out == NULL) return 0;
    max = attrlen + 1;

    while (ret && attrlen && outlen < max) {
        if (*attr == '%') {
            if (attrlen < 3) {
                ret = 0;
            } else {
                char tmp[3];
                size_t l = 1;

                tmp[0] = attr[1];
                tmp[1] = attr[2];
                tmp[2] = 0;
                ret = pkcs11_hex_to_bin(tmp, &out[outlen++], &l);
                attrlen -= 3;
                attr += 3;
            }
        } else {
            out[outlen++] = *(attr++);
            attrlen--;
        }
    }
    if (attrlen && outlen == max) ret = 0;
    if (ret) {
        out[outlen] = 0;
        *field = out;
    } else {
        OPENSSL_free(out);
    }
    return ret;
}


static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data)
{
    CK_ULONG kt, class;
    CK_ATTRIBUTE key_type[] = {
        { CKA_CLASS,    &class, sizeof(class) },
        { CKA_KEY_TYPE, &kt,    sizeof(kt)    }
    };
    EVP_PKEY *k = NULL;
    CK_RV rv;
    const char *end, *parse;
    int ret = 1;
    unsigned char *id, *pin;
    char *module_path;

    end = path + 6;
    while (ret && end[0] && end[1]) {
        parse = end + 1;
        end = strpbrk(parse, ";?&");
        if (end == NULL) end = parse + strlen(parse);
        if (!strncmp(parse, "id=", 3)) {
	    parse += 3;
            ret = pkcs11_parse_attribute(parse, end - parse, (void *)&id);
        } else if (!strncmp(parse, "pin-value=", 10)) {
            parse += 10;
	    ret = pkcs11_parse_attribute(parse, end - parse, (void *)&pin);
        } else if (!strncmp(parse, "module-path=", 12)) {
            parse += 12;
	    ret = pkcs11_parse_attribute(parse, end - parse, (void *)&module_path);
        }
    }
    pkcs11st.id = id;
    pkcs11st.pin = pin;

    rv = pkcs11_initialize(module_path);

    if (rv != CKR_OK) {
        goto err;
    }

    pkcs11st.session = pkcs11_start_session(pkcs11_get_slot());
    pkcs11_login(pkcs11st.session, pkcs11st.pin);
    pkcs11st.key = pkcs11_get_private_key(pkcs11st.session, pkcs11st.id,
                                          strlen((char *)pkcs11st.id));

    rv = pkcs11_funcs->C_GetAttributeValue(pkcs11st.session,
                                    pkcs11st.key, key_type, 2);

    if(rv != CKR_OK || class != CKO_PRIVATE_KEY) {
        return k;
    }

    if(kt == CKK_RSA) {
        CK_ATTRIBUTE rsa_attributes[] = {
            { CKA_MODULUS, NULL, 0 },
            { CKA_PUBLIC_EXPONENT, NULL, 0 }
        };
        RSA *rsa = RSA_new();

        if(((rv = pkcs11_funcs->C_GetAttributeValue(pkcs11st.session, pkcs11st.key,
             rsa_attributes, 2)) == CKR_OK) &&
             (rsa_attributes[0].ulValueLen > 0) &&
             (rsa_attributes[1].ulValueLen > 0) &&
             ((rsa_attributes[0].pValue = OPENSSL_malloc(rsa_attributes[0].ulValueLen))
             != NULL) &&
             ((rsa_attributes[1].pValue = OPENSSL_malloc(rsa_attributes[1].ulValueLen))
             != NULL) &&
             ((rv = pkcs11_funcs->C_GetAttributeValue(pkcs11st.session, pkcs11st.key,
             rsa_attributes, 2)) == CKR_OK) && (rsa != NULL)) {

            RSA_set0_key(rsa,
                         BN_bin2bn(rsa_attributes[0].pValue,
                                   rsa_attributes[0].ulValueLen, NULL),
                         BN_bin2bn(rsa_attributes[1].pValue,
                                   rsa_attributes[1].ulValueLen, NULL),
                         NULL);
            if((k = EVP_PKEY_new()) != NULL) {
                EVP_PKEY_set1_RSA(k, rsa);
            }
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
      || !ENGINE_set_destroy_function(e, pkcs11_destroy(e)))
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
    RSA_meth_free(pkcs11_rsa);
    pkcs11_rsa = NULL;
    ERR_unload_PKCS11_strings();
    return 1;
}


IMPLEMENT_DYNAMIC_BIND_FN(pkcs11_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
