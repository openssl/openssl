#ifndef PKSC11_UTILS_H
#define PKSC11_UTILS_H

#include <openssl/stack.h>
#include <openssl/core_dispatch.h>
#include <openssl/objects.h>
#include "pkcs11_ctx.h"

#define ERR_PKCS11_NO_USERPIN_SET (CKR_TOKEN_RESOURCE_EXCEEDED + 1)
#define ERR_PKCS11_MEM_ALLOC_FAILED (CKR_TOKEN_RESOURCE_EXCEEDED + 2)
#define ERR_PKCS11_NO_TOKENS_AVAILABLE (CKR_TOKEN_RESOURCE_EXCEEDED + 3)
#define ERR_PKCS11_GET_LIST_OF_SLOTS_FAILED (CKR_TOKEN_RESOURCE_EXCEEDED + 4)

int pkcs11_add_algorithm(OPENSSL_STACK *stack, const char *algoname,
                         const char *searchstr, const OSSL_DISPATCH *dispatch, const char* description);
int pkcs11_add_attribute(OPENSSL_STACK *stack, CK_ATTRIBUTE_TYPE type,
                         CK_VOID_PTR pValue, CK_ULONG ulValueLen);
int pkcs11_get_byte_array(BIGNUM *num, CK_BYTE_PTR *out);
void pkcs11_set_error(PKCS11_CTX *ctx, int reason, const char *file, int line,
                      const char *func, const char *fmt, ...);
#define SET_PKCS11_PROV_ERR(ctx, reasonidx) \
    pkcs11_set_error(ctx, reasonidx, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, NULL)

int pkcs11_nid2mechanism_digest(int nid);

#endif /* PKSC11_UTILS_H */
