/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "x509_local.h"

#include <crypto/asn1.h>
#include <crypto/x509.h>

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
    long argl, char **ret);
static int by_file_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argc,
    long argl, char **ret, OSSL_LIB_CTX *libctx,
    const char *propq);

static X509_LOOKUP_METHOD x509_file_lookup = {
    "Load file into cache",
    NULL, /* new_item */
    NULL, /* free */
    NULL, /* init */
    NULL, /* shutdown */
    by_file_ctrl, /* ctrl */
    NULL, /* get_by_subject */
    NULL, /* get_by_issuer_serial */
    NULL, /* get_by_fingerprint */
    NULL, /* get_by_alias */
    NULL, /* get_by_subject_ex */
    by_file_ctrl_ex, /* ctrl_ex */
};

X509_LOOKUP_METHOD *X509_LOOKUP_file(void)
{
    return &x509_file_lookup;
}

static int by_file_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argp,
    long argl, char **ret, OSSL_LIB_CTX *libctx,
    const char *propq)
{
    int ok = 0;
    const char *file;

    switch (cmd) {
    case X509_L_FILE_LOAD:
        if (argl == X509_FILETYPE_DEFAULT) {
            file = ossl_safe_getenv(X509_get_default_cert_file_env());
            if (file)
                ok = (X509_load_cert_crl_file_ex(ctx, file, X509_FILETYPE_PEM,
                          libctx, propq)
                    != 0);
            else
                ok = (X509_load_cert_crl_file_ex(
                          ctx, X509_get_default_cert_file(),
                          X509_FILETYPE_PEM, libctx, propq)
                    != 0);

            if (!ok)
                ERR_raise(ERR_LIB_X509, X509_R_LOADING_DEFAULTS);
        } else {
            if (argl == X509_FILETYPE_PEM)
                ok = (X509_load_cert_crl_file_ex(ctx, argp, X509_FILETYPE_PEM,
                          libctx, propq)
                    != 0);
            else
                ok = (X509_load_cert_file_ex(ctx, argp, (int)argl, libctx,
                          propq)
                    != 0);
        }
        break;
    }
    return ok;
}

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd,
    const char *argp, long argl, char **ret)
{
    return by_file_ctrl_ex(ctx, cmd, argp, argl, ret, NULL, NULL);
}

int X509_load_cert_file_ex(X509_LOOKUP *ctx, const char *file, int type,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    BIO *in = NULL;
    int count = 0;
    X509 *x = NULL;

    if (file == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    in = BIO_new(BIO_s_file());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        ERR_raise(ERR_LIB_X509, ERR_R_BIO_LIB);
        goto err;
    }

    x = X509_new_ex(libctx, propq);
    if (x == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }

    if (type == X509_FILETYPE_PEM) {
        /*
         * A pending CertificatePropertyList from a "CERTIFICATE PROPERTIES"
         * block, to attach to the certificate that follows it (section 7 of
         * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
         * Read blocks generically rather than via PEM_read_bio_X509_AUX(), so a
         * properties block is seen rather than silently skipped.
         */
        ASN1_OCTET_STRING *props = NULL;

        for (;;) {
            char *pnm = NULL, *phdr = NULL;
            unsigned char *pdata = NULL;
            long plen = 0;
            int fail = 0;

            ERR_set_mark();
            if (!PEM_read_bio(in, &pnm, &phdr, &pdata, &plen)) {
                if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE
                    && count > 0 && props == NULL) {
                    ERR_pop_to_mark();
                    break;
                }
                ERR_clear_last_mark();
                ERR_raise(ERR_LIB_X509, count == 0 ? X509_R_NO_CERTIFICATE_FOUND : ERR_R_PEM_LIB);
                count = 0;
                ASN1_OCTET_STRING_free(props);
                goto err;
            }
            ERR_clear_last_mark();

            if (strcmp(pnm, "CERTIFICATE PROPERTIES") == 0) {
                /* Only one property list may precede a certificate. */
                if (props != NULL
                    || (props = ASN1_OCTET_STRING_new()) == NULL
                    || !ASN1_OCTET_STRING_set(props, pdata, (int)plen))
                    fail = 1;
            } else if (strcmp(pnm, PEM_STRING_X509) == 0
                || strcmp(pnm, PEM_STRING_X509_OLD) == 0
                || strcmp(pnm, PEM_STRING_X509_TRUSTED) == 0) {
                const unsigned char *p = pdata;

                if (d2i_X509_AUX(&x, &p, plen) == NULL
                    || (props != NULL
                        && !ossl_x509_set1_certificate_properties(x,
                            ASN1_STRING_get0_data(props),
                            ASN1_STRING_get_length(props)))
                    || !X509_STORE_add_cert(ctx->store_ctx, x)) {
                    fail = 1;
                } else {
                    ASN1_OCTET_STRING_free(props);
                    props = NULL;
                    /*
                     * X509_STORE_add_cert() added a reference rather than a
                     * copy, so we need a fresh X509 object.
                     */
                    X509_free(x);
                    if ((x = X509_new_ex(libctx, propq)) == NULL)
                        fail = 1;
                    else
                        count++;
                }
            }
            /* Any other block type is skipped, as before. */

            OPENSSL_free(pnm);
            OPENSSL_free(phdr);
            OPENSSL_free(pdata);

            if (fail) {
                ERR_raise(ERR_LIB_X509, ERR_R_PEM_LIB);
                count = 0;
                ASN1_OCTET_STRING_free(props);
                goto err;
            }
        }
        ASN1_OCTET_STRING_free(props);
    } else if (type == X509_FILETYPE_ASN1) {
        if (d2i_X509_bio(in, &x) == NULL) {
            ERR_raise(ERR_LIB_X509, X509_R_NO_CERTIFICATE_FOUND);
            goto err;
        }
        count = X509_STORE_add_cert(ctx->store_ctx, x);
    } else {
        ERR_raise(ERR_LIB_X509, X509_R_BAD_X509_FILETYPE);
        goto err;
    }
err:
    X509_free(x);
    BIO_free(in);
    return count;
}

int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type)
{
    return X509_load_cert_file_ex(ctx, file, type, NULL, NULL);
}

int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    BIO *in = NULL;
    int count = 0;
    X509_CRL *x = NULL;

    if (file == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    in = BIO_new(BIO_s_file());

    if ((in == NULL) || (BIO_read_filename(in, file) <= 0)) {
        ERR_raise(ERR_LIB_X509, ERR_R_BIO_LIB);
        goto err;
    }

    if (type == X509_FILETYPE_PEM) {
        for (;;) {
            x = PEM_read_bio_X509_CRL(in, NULL, NULL, "");
            if (x == NULL) {
                if ((ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) && (count > 0)) {
                    ERR_clear_error();
                    break;
                } else {
                    if (count == 0) {
                        ERR_raise(ERR_LIB_X509, X509_R_NO_CRL_FOUND);
                    } else {
                        ERR_raise(ERR_LIB_X509, ERR_R_PEM_LIB);
                        count = 0;
                    }
                    goto err;
                }
            }
            if (!X509_STORE_add_crl(ctx->store_ctx, x)) {
                count = 0;
                goto err;
            }
            count++;
            X509_CRL_free(x);
            x = NULL;
        }
    } else if (type == X509_FILETYPE_ASN1) {
        x = d2i_X509_CRL_bio(in, NULL);
        if (x == NULL) {
            ERR_raise(ERR_LIB_X509, X509_R_NO_CRL_FOUND);
            goto err;
        }
        count = X509_STORE_add_crl(ctx->store_ctx, x);
    } else {
        ERR_raise(ERR_LIB_X509, X509_R_BAD_X509_FILETYPE);
        goto err;
    }
err:
    X509_CRL_free(x);
    BIO_free(in);
    return count;
}

int X509_load_cert_crl_file_ex(X509_LOOKUP *ctx, const char *file, int type,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    STACK_OF(X509_INFO) *inf = NULL;
    X509_INFO *itmp = NULL;
    BIO *in = NULL;
    int i, count = 0;

    if (type != X509_FILETYPE_PEM)
        return X509_load_cert_file_ex(ctx, file, type, libctx, propq);
#if defined(OPENSSL_SYS_WINDOWS)
    in = BIO_new_file(file, "rb");
#else
    in = BIO_new_file(file, "r");
#endif
    if (in == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_BIO_LIB);
        return 0;
    }
    inf = PEM_X509_INFO_read_bio_ex(in, NULL, NULL, "", libctx, propq);
    BIO_free(in);
    if (inf == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PEM_LIB);
        return 0;
    }
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            if (!X509_STORE_add_cert(ctx->store_ctx, itmp->x509)) {
                count = 0;
                goto err;
            }
            count++;
        }
        if (itmp->crl) {
            if (!X509_STORE_add_crl(ctx->store_ctx, itmp->crl)) {
                count = 0;
                goto err;
            }
            count++;
        }
    }
    if (count == 0)
        ERR_raise(ERR_LIB_X509, X509_R_NO_CERTIFICATE_OR_CRL_FOUND);
err:
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    return count;
}

int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    return X509_load_cert_crl_file_ex(ctx, file, type, NULL, NULL);
}
