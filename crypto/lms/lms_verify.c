#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "crypto/lms.h"

#define MAX_DIGEST_SIZE 32
#define HSS_MIN_L 1
#define HSS_MAX_L 8

static unsigned char D_LEAF[] = { 0x82, 0x82 };
static unsigned char D_INTR[] = { 0x83, 0x83 };

int ossl_lms_sig_verify_init(LMS_VALIDATE_CTX *ctx)
{
    int ret;

    ret = ossl_lm_ots_ctx_pubkey_init(ctx->pubctx, ctx->md, &ctx->sig->sig,
                                      ctx->pub->ots_params, ctx->pub->I,
                                      ctx->sig->q);
    if (ret) {
        if (!ossl_lms_sig_up_ref(ctx->sig))
            return 0;
        if (!ossl_lms_key_up_ref(ctx->pub)) {
            ossl_lms_sig_free(ctx->sig);
            return 0;
        }
    }
    return ret;
}

int ossl_lms_sig_verify_update(LMS_VALIDATE_CTX *ctx,
                               const unsigned char *msg, size_t msglen)
{
    int ret = ossl_lm_ots_ctx_pubkey_update(ctx->pubctx, msg, msglen);

    if (!ret) {
        ossl_lms_sig_free(ctx->sig);
        ossl_lms_key_up_ref(ctx->pub);
    }
    return ret;
}

int ossl_lms_sig_verify_final(LMS_VALIDATE_CTX *vctx)
{
    EVP_MD_CTX *ctx = vctx->pubctx->mdctx;
    EVP_MD_CTX *ctxI = vctx->pubctx->mdctxIq;
    const LMS_KEY *key = vctx->pub;
    const LMS_SIG *lms_sig = vctx->sig;
    unsigned char Kc[LMS_MAX_DIGEST_SIZE];
    unsigned char Tc[LMS_MAX_DIGEST_SIZE];
    unsigned char buf[4];
    const LMS_PARAMS *lmsParams;
    uint32_t node_num, m;
    const unsigned char *path;
    int ret = 0;

    if (!ossl_lm_ots_ctx_pubkey_final(vctx->pubctx, Kc))
        goto err;

    /* Compute the candidate LMS root value Tc */
    lmsParams = key->lms_params;
    m = lmsParams->n;
    node_num = (1 << lmsParams->h) + lms_sig->q;

    U32STR(buf, node_num);
    if (!EVP_DigestInit_ex2(ctx, NULL, NULL)
        || !EVP_DigestUpdate(ctx, key->I, LMS_ISIZE)
        || !EVP_MD_CTX_copy_ex(ctxI, ctx)
        || !EVP_DigestUpdate(ctx, buf, sizeof(buf))
        || !EVP_DigestUpdate(ctx, D_LEAF, sizeof(D_LEAF))
        || !EVP_DigestUpdate(ctx, Kc, m)
        || !EVP_DigestFinal_ex(ctx, Tc, NULL))
        goto err;

    path = lms_sig->paths;
    while (node_num > 1) {
        int odd = node_num & 1;

        node_num = node_num >> 1;
        U32STR(buf, node_num);

        if (!EVP_MD_CTX_copy_ex(ctx, ctxI)
            || !EVP_DigestUpdate(ctx, buf, sizeof(buf))
            || !EVP_DigestUpdate(ctx, D_INTR, sizeof(D_INTR)))
            goto err;

        if (odd) {
            if (!EVP_DigestUpdate(ctx, path, m)
                || !EVP_DigestUpdate(ctx, Tc, m))
                goto err;
        } else {
            if (!EVP_DigestUpdate(ctx, Tc, m)
                || !EVP_DigestUpdate(ctx, path, m))
                goto err;
        }
        if (!EVP_DigestFinal_ex(ctx, Tc, NULL))
            goto err;
        path += m;
    }
    ret = (memcmp(key->K, Tc, m) == 0);
err:
    ossl_lms_sig_free(vctx->sig);
    ossl_lms_key_free(vctx->pub);
    return ret;
}
