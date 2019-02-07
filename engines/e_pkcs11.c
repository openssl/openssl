#include <openssl/engine.h>
#include <string.h>

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

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

void assert(CK_RV rv, const char *message);
void finalize();
void end_session(CK_SESSION_HANDLE session);
void login(CK_SESSION_HANDLE session, CK_BYTE *pin);
void logout(CK_SESSION_HANDLE session);
CK_SLOT_ID get_slot();
CK_RV initialize(char *library_path);
CK_SESSION_HANDLE start_session(CK_SLOT_ID slotId);
CK_OBJECT_HANDLE get_private_key(CK_SESSION_HANDLE session,
                                 CK_BYTE *id, size_t id_len);
CK_RV load_functions(char *library_path);
CK_FUNCTION_LIST *funcs;

static const char *engine_id = "pkcs11";
static const char *engine_name = "A minimal PKCS#11 engine only for sign";

typedef struct st_pkcs11 {
    CK_BYTE *id;
    CK_BYTE *pin;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
} PKCS11;

static PKCS11 pkcs11st;

int pkcs11_rsa_enc(int flen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding) {
    CK_RV rv;
    CK_ULONG signatureLen = 128;
    CK_BYTE *signature = malloc(signatureLen);
    CK_MECHANISM sign_mechanism;
    sign_mechanism.mechanism = CKM_RSA_PKCS;
    sign_mechanism.pParameter = 0;
    sign_mechanism.ulParameterLen = 0;

    rv = funcs->C_SignInit(pkcs11st.session, &sign_mechanism, pkcs11st.key);
    assert(rv, "sign init");
    rv = funcs->C_Sign(pkcs11st.session, (CK_BYTE *) from, flen, to,
                       &signatureLen);
    assert(rv, "sign final");

    logout(pkcs11st.session);
    end_session(pkcs11st.session);

    return 1;
}

RSA_METHOD *pkcs11_rsa() {
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
CK_RV load_functions(char *library_path) {
    CK_RV rv;

#ifdef WIN32
    HMODULE d = LoadLibraryA(library_path);
#else
    CK_RV(*pFunc)();
    void *d;
    d = dlopen(library_path, RTLD_NOW | RTLD_GLOBAL);
#endif

    if (d == NULL) {
#ifdef DEBUG
        fprintf(stderr,"%s not found in LD_LIBRARY_PATH\n", library_path);
#endif
        return CKR_GENERAL_ERROR;
    }

#ifdef WIN32
    CK_C_GetFunctionList pFunc = (CK_C_GetFunctionList)
                           GetProcAddress(d, "C_GetFunctionList");
#else
    pFunc = (CK_RV (*)()) dlsym(d, "C_GetFunctionList");
#endif

    if (pFunc == NULL) {
#ifdef DEBUG
        fprintf(stderr,"C_GetFunctionList() not found in module %s\n",
                library_path);
#endif
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rv = pFunc(&funcs);
    if (rv != CKR_OK) {
#ifdef DEBUG
        fprintf(stderr,"C_GetFunctionList() did not initialize correctly\n");
#endif
        return rv;
    }

    return CKR_OK;
}

/**
 * Initialize the PKCS#11 library.
 * This loads the function list and initializes PKCS#11.
 * @param library_path
 * @return
 */
CK_RV initialize(char *library_path) {
    CK_RV rv;

    if (!library_path) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = load_functions(library_path);
    if (rv != CKR_OK) {
#ifdef DEBUG
        fprintf(stderr,"Getting PKCS11 function list failed!\n");
#endif
        return rv;
    }

    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
#ifdef DEBUG
        fprintf(stderr, "Failed to initialize\n");
#endif
        return rv;
    }

    return CKR_OK;
}

void finalize() {
    funcs->C_Finalize(NULL);
}

CK_SLOT_ID get_slot() {
    CK_RV rv;
    CK_SLOT_ID slotId;
    CK_ULONG slotCount = 10;
    CK_SLOT_ID *slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);
    rv = funcs->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
    assert(rv, "get slot list");

    if (slotCount < 1) {
#ifdef DEBUG
        fprintf(stderr, "Error; could not find any slots\n");
#endif
        exit(1);
    }

    slotId = slotIds[0];
    free(slotIds);
    return slotId;
}

void assert(CK_RV rv, const char *message) {
    if (rv != CKR_OK) {
#ifdef DEBUG
        fprintf(stderr, "Error at %s: %u\n",
        message, (unsigned int)rv);
#endif
        exit(EXIT_FAILURE);
    }
}

CK_SESSION_HANDLE start_session(CK_SLOT_ID slotId) {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    rv = funcs->C_OpenSession(slotId, CKF_SERIAL_SESSION, NULL, NULL, &session);
    assert(rv, "open session");
    return session;
}

void login(CK_SESSION_HANDLE session, CK_BYTE *pin) {
    CK_RV rv;
    if (pin) {
        rv = funcs->C_Login(session, CKU_USER, pin, strlen((char *)pin));
        assert(rv, "log in");
    }
}

void logout(CK_SESSION_HANDLE session) {
    CK_RV rv;
    rv = funcs->C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN) {
        assert(rv, "log out");
    }
}

void end_session(CK_SESSION_HANDLE session) {
    CK_RV rv;
    rv = funcs->C_CloseSession(session);
    assert(rv, "close session");
}

CK_OBJECT_HANDLE get_private_key(CK_SESSION_HANDLE session,
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
    rv = funcs->C_FindObjectsInit(session, tmpl,
                                  sizeof (tmpl) / sizeof (CK_ATTRIBUTE) );
    rv = funcs->C_FindObjects(session, &objhandle, 1, &count);
    return objhandle;
}

static int hex_to_bin(const char *in, unsigned char *out, size_t *outlen) {
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

static int parse_attribute(const char *attr, int attrlen, unsigned char **field) {
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
                ret = hex_to_bin(tmp, &out[outlen++], &l);
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


static EVP_PKEY *engine_load_private_key(ENGINE * e, const char *path,
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
    unsigned char *id, *pin, *module_path;

    end = path + 6;
    while (ret && end[0] && end[1]) {
        parse = end + 1;
        end = strpbrk(parse, ";?&");
        if (end == NULL) end = parse + strlen(parse);
        if (!strncmp(parse, "id=", 3)) {
	    parse += 3;
            ret = parse_attribute(parse, end - parse, (void *)&id);
        } else if (!strncmp(parse, "pin-value=", 10)) {
            parse += 10;
	    ret = parse_attribute(parse, end - parse, (void *)&pin);
        } else if (!strncmp(parse, "module-path=", 12)) {
            parse += 12;
	    ret = parse_attribute(parse, end - parse, (void *)&module_path);
        }
    }
    pkcs11st.id = id;
    pkcs11st.pin = pin;

    rv = initialize(module_path);
    assert(rv, "module path");
    pkcs11st.session = start_session(get_slot());
    login(pkcs11st.session, pkcs11st.pin);
    pkcs11st.key = get_private_key(pkcs11st.session, pkcs11st.id,
                                   strlen(pkcs11st.id));

    rv = funcs->C_GetAttributeValue(pkcs11st.session,
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

        if(((rv = funcs->C_GetAttributeValue(pkcs11st.session, pkcs11st.key,
             rsa_attributes, 2)) == CKR_OK) &&
             (rsa_attributes[0].ulValueLen > 0) &&
             (rsa_attributes[1].ulValueLen > 0) &&
             ((rsa_attributes[0].pValue = malloc(rsa_attributes[0].ulValueLen))
             != NULL) &&
             ((rsa_attributes[1].pValue = malloc(rsa_attributes[1].ulValueLen))
             != NULL) &&
             ((rv = funcs->C_GetAttributeValue(pkcs11st.session, pkcs11st.key,
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

        free(rsa_attributes[0].pValue);
        free(rsa_attributes[1].pValue);
    }
    return k;
}

static int bindpkcs11(ENGINE *e, const char *id)
{
  int ret = 0;

  if (!ENGINE_set_id(e, engine_id)) {
#ifdef DEBUG
    fprintf(stderr, "ENGINE_set_id failed\n");
#endif
    goto end;
  }
  if (!ENGINE_set_name(e, engine_name)) {
#ifdef DEBUG
    fprintf(stderr,"ENGINE_set_name failed\n");
#endif
    goto end;
  }
  if (!ENGINE_set_RSA(e, pkcs11_rsa())) {
#ifdef DEBUG
    fprintf(stderr,"ENGINE_set_RSA failed\n");
#endif
    goto end;
  }
  if (!ENGINE_set_load_privkey_function(e, engine_load_private_key)) {
#ifdef DEBUG
    fprintf(stderr,"ENGINE_set_load_privkey_function failed\n");
#endif
    goto end;
  }

  ret = 1;
 end:
  return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bindpkcs11)
IMPLEMENT_DYNAMIC_CHECK_FN()
