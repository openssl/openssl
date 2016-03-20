/*
 * Written by Rob Stradling (rob@comodo.com) and Stephen Henson
 * (steve@openssl.org) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>

#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "ct_locl.h"

typedef enum sct_signature_type_t {
    SIGNATURE_TYPE_NOT_SET = -1,
    SIGNATURE_TYPE_CERT_TIMESTAMP,
    SIGNATURE_TYPE_TREE_HASH
} SCT_SIGNATURE_TYPE;

/*
 * Update encoding for SCT signature verification/generation to supplied
 * EVP_MD_CTX.
 */
static int sct_ctx_update(EVP_MD_CTX *ctx, const SCT_CTX *sctx, const SCT *sct)
{
    unsigned char tmpbuf[12];
    unsigned char *p, *der;
    size_t derlen;
    /*+
     * digitally-signed struct {
     *   (1 byte) Version sct_version;
     *   (1 byte) SignatureType signature_type = certificate_timestamp;
     *   (8 bytes) uint64 timestamp;
     *   (2 bytes) LogEntryType entry_type;
     *   (? bytes) select(entry_type) {
     *     case x509_entry: ASN.1Cert;
     *     case precert_entry: PreCert;
     *   } signed_entry;
     *   (2 bytes + sct->ext_len) CtExtensions extensions;
     * }
     */
    if (sct->entry_type == CT_LOG_ENTRY_TYPE_NOT_SET)
        return 0;
    if (sct->entry_type == CT_LOG_ENTRY_TYPE_PRECERT && sctx->ihash == NULL)
        return 0;

    p = tmpbuf;
    *p++ = sct->version;
    *p++ = SIGNATURE_TYPE_CERT_TIMESTAMP;
    l2n8(sct->timestamp, p);
    s2n(sct->entry_type, p);

    if (!EVP_DigestUpdate(ctx, tmpbuf, p - tmpbuf))
        return 0;

    if (sct->entry_type == CT_LOG_ENTRY_TYPE_X509) {
        der = sctx->certder;
        derlen = sctx->certderlen;
    } else {
        if (!EVP_DigestUpdate(ctx, sctx->ihash, sctx->ihashlen))
            return 0;
        der = sctx->preder;
        derlen = sctx->prederlen;
    }

    /* If no encoding available, fatal error */
    if (der == NULL)
        return 0;

    /* Include length first */
    p = tmpbuf;
    l2n3(derlen, p);

    if (!EVP_DigestUpdate(ctx, tmpbuf, 3))
        return 0;
    if (!EVP_DigestUpdate(ctx, der, derlen))
        return 0;

    /* Add any extensions */
    p = tmpbuf;
    s2n(sct->ext_len, p);
    if (!EVP_DigestUpdate(ctx, tmpbuf, 2))
        return 0;

    if (sct->ext_len && !EVP_DigestUpdate(ctx, sct->ext, sct->ext_len))
        return 0;

    return 1;
}

int SCT_verify(const SCT_CTX *sctx, const SCT *sct)
{
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (!SCT_is_complete(sct) || sctx->pkey == NULL ||
        sct->entry_type == CT_LOG_ENTRY_TYPE_NOT_SET ||
        (sct->entry_type == CT_LOG_ENTRY_TYPE_PRECERT && sctx->ihash == NULL)) {
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_NOT_SET);
        return 0;
    }
    if (sct->version != SCT_VERSION_V1) {
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_UNSUPPORTED_VERSION);
        return 0;
    }
    if (sct->log_id_len != sctx->pkeyhashlen ||
        memcmp(sct->log_id, sctx->pkeyhash, sctx->pkeyhashlen) != 0) {
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_LOG_ID_MISMATCH);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto end;

    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, sctx->pkey))
        goto end;

    if (!sct_ctx_update(ctx, sctx, sct))
        goto end;

    /* Verify signature */
    ret = EVP_DigestVerifyFinal(ctx, sct->sig, sct->sig_len);
    /* If ret < 0 some other error: fall through without setting error */
    if (ret == 0)
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_INVALID_SIGNATURE);

end:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int SCT_verify_v1(SCT *sct, X509 *cert, X509 *preissuer,
                  X509_PUBKEY *log_pubkey, X509 *issuer_cert)
{
    int ret = 0;
    SCT_CTX *sctx = NULL;

    if (!SCT_is_complete(sct)) {
        CTerr(CT_F_SCT_VERIFY_V1, CT_R_SCT_NOT_SET);
        return 0;
    }

    if (sct->version != 0) {
        CTerr(CT_F_SCT_VERIFY_V1, CT_R_SCT_UNSUPPORTED_VERSION);
        return 0;
    }

    sctx = SCT_CTX_new();
    if (sctx == NULL)
        goto done;

    if (!SCT_CTX_set1_pubkey(sctx, log_pubkey))
        goto done;

    if (!SCT_CTX_set1_cert(sctx, cert, preissuer))
        goto done;

    if (sct->entry_type == CT_LOG_ENTRY_TYPE_PRECERT &&
        !SCT_CTX_set1_issuer(sctx, issuer_cert))
        goto done;

    ret = SCT_verify(sctx, sct);
done:
    SCT_CTX_free(sctx);
    return ret;
}
