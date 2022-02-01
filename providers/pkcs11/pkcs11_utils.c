#include "pkcs11_utils.h"

void pkcs11_set_error(PKCS11_CTX *ctx, int reason, const char *file, int line,
                             const char *func, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (ctx != NULL) {
        if (ctx->core_new_error != NULL)
            ctx->core_new_error(ctx->ctx.handle);
        if (ctx->core_set_error_debug != NULL)
            ctx->core_set_error_debug(ctx->ctx.handle, file, line, func);
        if (ctx->core_vset_error != NULL)
            ctx->core_vset_error(ctx->ctx.handle, reason, fmt, ap);
    }
    va_end(ap);
}

int pkcs11_add_algorithm(OPENSSL_STACK *stack, const char *algoname,
                         const char *searchstr, const OSSL_DISPATCH *dispatch, const char* description)
{
    OSSL_ALGORITHM *algo = (OSSL_ALGORITHM *)OPENSSL_zalloc(sizeof(OSSL_ALGORITHM));
    if (algo == NULL)
        return 0;
    algo->algorithm_names = algoname;
    algo->property_definition = searchstr;
    algo->implementation = dispatch;
    algo->algorithm_description = description;
    if (!OPENSSL_sk_push(stack, algo)){
        OPENSSL_free(algo);
        return 0;
    }
    return 1;
}

int pkcs11_add_attribute(OPENSSL_STACK *stack, CK_ATTRIBUTE_TYPE type,
                         CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
    CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)OPENSSL_zalloc(sizeof(CK_ATTRIBUTE));
    if (attr == NULL)
        return 0;
    attr->type = type;
    attr->pValue = pValue;
    attr->ulValueLen = ulValueLen;
    if (!OPENSSL_sk_push(stack, attr)){
        OPENSSL_free(attr);
        return 0;
    }
    return 1;
}

int pkcs11_get_byte_array(BIGNUM *num, CK_BYTE_PTR *out)
{
    CK_BYTE_PTR val = NULL;
    int len = BN_num_bytes(num);
    if (len == 0) 
        goto end;
    val = (CK_BYTE*)OPENSSL_zalloc(len);
    if (val == NULL)
        goto end;
    len = BN_bn2bin(num, val);
    *out = val;
    return len;
end:
    return -1;
}

const char *pkcs11_mechanism2name_digest(int mechanism)
{
    switch (mechanism) {
        case CKM_MD5:
            return SN_md5;
        case CKM_SHA_1:
            return SN_sha1;
        case CKM_SHA224:
            return SN_sha224;
        case CKM_SHA256:
            return SN_sha256;
        case CKM_SHA384:
            return SN_sha384;
        case CKM_SHA512:
            return SN_sha512;
        case CKM_SHA512_224:
            return SN_sha512_224;
        case CKM_SHA512_256:
            return SN_sha512_256;
    }
    return NULL;
}

int pkcs11_nid2mechanism_digest(int nid)
{
    switch (nid) { 
        case NID_md5:
            return CKM_MD5;
        case NID_sha1:
            return CKM_SHA_1;
        case NID_sha224:
            return CKM_SHA224;
        case NID_sha256:
            return CKM_SHA256;
        case NID_sha384:
            return CKM_SHA384;
        case NID_sha512:
            return CKM_SHA512;
        case NID_sha512_224:
            return CKM_SHA512_224;
        case NID_sha512_256:
            return CKM_SHA512_256;
    }
    return NID_undef;
}
