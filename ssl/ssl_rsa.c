/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "tls_local.h"
#include "internal/packet.h"
#include <opentls/bio.h>
#include <opentls/objects.h>
#include <opentls/evp.h>
#include <opentls/x509.h>
#include <opentls/pem.h>

static int tls_set_cert(CERT *c, X509 *x509);
static int tls_set_pkey(CERT *c, EVP_PKEY *pkey);

#define  SYNTHV1CONTEXT     (tls_EXT_TLS1_2_AND_BELOW_ONLY \
                             | tls_EXT_CLIENT_HELLO \
                             | tls_EXT_TLS1_2_SERVER_HELLO \
                             | tls_EXT_IGNORE_ON_RESUMPTION)

int tls_use_certificate(tls *tls, X509 *x)
{
    int rv;
    if (x == NULL) {
        tlserr(tls_F_tls_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    rv = tls_security_cert(tls, NULL, x, 0, 1);
    if (rv != 1) {
        tlserr(tls_F_tls_USE_CERTIFICATE, rv);
        return 0;
    }

    return tls_set_cert(tls->cert, x);
}

int tls_use_certificate_file(tls *tls, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_tls_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_tls_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == tls_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == tls_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, tls->default_passwd_callback,
                              tls->default_passwd_callback_userdata);
    } else {
        tlserr(tls_F_tls_USE_CERTIFICATE_FILE, tls_R_BAD_tls_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        tlserr(tls_F_tls_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = tls_use_certificate(tls, x);
 end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

int tls_use_certificate_ASN1(tls *tls, const unsigned char *d, int len)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        tlserr(tls_F_tls_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = tls_use_certificate(tls, x);
    X509_free(x);
    return ret;
}

#ifndef OPENtls_NO_RSA
int tls_use_RSAPrivateKey(tls *tls, RSA *rsa)
{
    EVP_PKEY *pkey;
    int ret;

    if (rsa == NULL) {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((pkey = EVP_PKEY_new()) == NULL) {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return 0;
    }

    RSA_up_ref(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return 0;
    }

    ret = tls_set_pkey(tls->cert, pkey);
    EVP_PKEY_free(pkey);
    return ret;
}
#endif

static int tls_set_pkey(CERT *c, EVP_PKEY *pkey)
{
    size_t i;

    if (tls_cert_lookup_by_pkey(pkey, &i) == NULL) {
        tlserr(tls_F_tls_SET_PKEY, tls_R_UNKNOWN_CERTIFICATE_TYPE);
        return 0;
    }

    if (c->pkeys[i].x509 != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get0_pubkey(c->pkeys[i].x509);
        if (pktmp == NULL) {
            tlserr(tls_F_tls_SET_PKEY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pktmp, pkey);
        ERR_clear_error();

#ifndef OPENtls_NO_RSA
        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA
            && RSA_flags(EVP_PKEY_get0_RSA(pkey)) & RSA_METHOD_FLAG_NO_CHECK) ;
        else
#endif
        if (!X509_check_private_key(c->pkeys[i].x509, pkey)) {
            X509_free(c->pkeys[i].x509);
            c->pkeys[i].x509 = NULL;
            return 0;
        }
    }

    EVP_PKEY_free(c->pkeys[i].privatekey);
    EVP_PKEY_up_ref(pkey);
    c->pkeys[i].privatekey = pkey;
    c->key = &c->pkeys[i];
    return 1;
}

#ifndef OPENtls_NO_RSA
int tls_use_RSAPrivateKey_file(tls *tls, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == tls_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == tls_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         tls->default_passwd_callback,
                                         tls->default_passwd_callback_userdata);
    } else {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY_FILE, tls_R_BAD_tls_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = tls_use_RSAPrivateKey(tls, rsa);
    RSA_free(rsa);
 end:
    BIO_free(in);
    return ret;
}

int tls_use_RSAPrivateKey_ASN1(tls *tls, const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    RSA *rsa;

    p = d;
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, (long)len)) == NULL) {
        tlserr(tls_F_tls_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = tls_use_RSAPrivateKey(tls, rsa);
    RSA_free(rsa);
    return ret;
}
#endif                          /* !OPENtls_NO_RSA */

int tls_use_PrivateKey(tls *tls, EVP_PKEY *pkey)
{
    int ret;

    if (pkey == NULL) {
        tlserr(tls_F_tls_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ret = tls_set_pkey(tls->cert, pkey);
    return ret;
}

int tls_use_PrivateKey_file(tls *tls, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_tls_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_tls_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == tls_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       tls->default_passwd_callback,
                                       tls->default_passwd_callback_userdata);
    } else if (type == tls_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        tlserr(tls_F_tls_USE_PRIVATEKEY_FILE, tls_R_BAD_tls_FILETYPE);
        goto end;
    }
    if (pkey == NULL) {
        tlserr(tls_F_tls_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = tls_use_PrivateKey(tls, pkey);
    EVP_PKEY_free(pkey);
 end:
    BIO_free(in);
    return ret;
}

int tls_use_PrivateKey_ASN1(int type, tls *tls, const unsigned char *d,
                            long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        tlserr(tls_F_tls_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = tls_use_PrivateKey(tls, pkey);
    EVP_PKEY_free(pkey);
    return ret;
}

int tls_CTX_use_certificate(tls_CTX *ctx, X509 *x)
{
    int rv;
    if (x == NULL) {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    rv = tls_security_cert(NULL, ctx, x, 0, 1);
    if (rv != 1) {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE, rv);
        return 0;
    }
    return tls_set_cert(ctx->cert, x);
}

static int tls_set_cert(CERT *c, X509 *x)
{
    EVP_PKEY *pkey;
    size_t i;

    pkey = X509_get0_pubkey(x);
    if (pkey == NULL) {
        tlserr(tls_F_tls_SET_CERT, tls_R_X509_LIB);
        return 0;
    }

    if (tls_cert_lookup_by_pkey(pkey, &i) == NULL) {
        tlserr(tls_F_tls_SET_CERT, tls_R_UNKNOWN_CERTIFICATE_TYPE);
        return 0;
    }
#ifndef OPENtls_NO_EC
    if (i == tls_PKEY_ECC && !EC_KEY_can_sign(EVP_PKEY_get0_EC_KEY(pkey))) {
        tlserr(tls_F_tls_SET_CERT, tls_R_ECC_CERT_NOT_FOR_SIGNING);
        return 0;
    }
#endif
    if (c->pkeys[i].privatekey != NULL) {
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);
        ERR_clear_error();

#ifndef OPENtls_NO_RSA
        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if (EVP_PKEY_id(c->pkeys[i].privatekey) == EVP_PKEY_RSA
            && RSA_flags(EVP_PKEY_get0_RSA(c->pkeys[i].privatekey)) &
            RSA_METHOD_FLAG_NO_CHECK) ;
        else
#endif                          /* OPENtls_NO_RSA */
        if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
            /*
             * don't fail for a cert/key mismatch, just free current private
             * key (when switching to a different cert & key, first this
             * function should be used, then tls_set_pkey
             */
            EVP_PKEY_free(c->pkeys[i].privatekey);
            c->pkeys[i].privatekey = NULL;
            /* clear error queue */
            ERR_clear_error();
        }
    }

    X509_free(c->pkeys[i].x509);
    X509_up_ref(x);
    c->pkeys[i].x509 = x;
    c->key = &(c->pkeys[i]);

    return 1;
}

int tls_CTX_use_certificate_file(tls_CTX *ctx, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == tls_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == tls_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
    } else {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE_FILE, tls_R_BAD_tls_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = tls_CTX_use_certificate(ctx, x);
 end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

int tls_CTX_use_certificate_ASN1(tls_CTX *ctx, int len, const unsigned char *d)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        tlserr(tls_F_tls_CTX_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = tls_CTX_use_certificate(ctx, x);
    X509_free(x);
    return ret;
}

#ifndef OPENtls_NO_RSA
int tls_CTX_use_RSAPrivateKey(tls_CTX *ctx, RSA *rsa)
{
    int ret;
    EVP_PKEY *pkey;

    if (rsa == NULL) {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((pkey = EVP_PKEY_new()) == NULL) {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return 0;
    }

    RSA_up_ref(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return 0;
    }

    ret = tls_set_pkey(ctx->cert, pkey);
    EVP_PKEY_free(pkey);
    return ret;
}

int tls_CTX_use_RSAPrivateKey_file(tls_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == tls_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == tls_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         ctx->default_passwd_callback,
                                         ctx->default_passwd_callback_userdata);
    } else {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY_FILE, tls_R_BAD_tls_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = tls_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);
 end:
    BIO_free(in);
    return ret;
}

int tls_CTX_use_RSAPrivateKey_ASN1(tls_CTX *ctx, const unsigned char *d,
                                   long len)
{
    int ret;
    const unsigned char *p;
    RSA *rsa;

    p = d;
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, (long)len)) == NULL) {
        tlserr(tls_F_tls_CTX_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = tls_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);
    return ret;
}
#endif                          /* !OPENtls_NO_RSA */

int tls_CTX_use_PrivateKey(tls_CTX *ctx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        tlserr(tls_F_tls_CTX_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return tls_set_pkey(ctx->cert, pkey);
}

int tls_CTX_use_PrivateKey_file(tls_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_tls_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_tls_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == tls_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata);
    } else if (type == tls_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        tlserr(tls_F_tls_CTX_USE_PRIVATEKEY_FILE, tls_R_BAD_tls_FILETYPE);
        goto end;
    }
    if (pkey == NULL) {
        tlserr(tls_F_tls_CTX_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = tls_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
 end:
    BIO_free(in);
    return ret;
}

int tls_CTX_use_PrivateKey_ASN1(int type, tls_CTX *ctx,
                                const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        tlserr(tls_F_tls_CTX_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = tls_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * Read a file that contains our certificate in "PEM" format, possibly
 * followed by a sequence of CA certificates that should be sent to the peer
 * in the Certificate message.
 */
static int use_certificate_chain_file(tls_CTX *ctx, tls *tls, const char *file)
{
    BIO *in;
    int ret = 0;
    X509 *x = NULL;
    pem_password_cb *passwd_callback;
    void *passwd_callback_userdata;

    ERR_clear_error();          /* clear error stack for
                                 * tls_CTX_use_certificate() */

    if (ctx != NULL) {
        passwd_callback = ctx->default_passwd_callback;
        passwd_callback_userdata = ctx->default_passwd_callback_userdata;
    } else {
        passwd_callback = tls->default_passwd_callback;
        passwd_callback_userdata = tls->default_passwd_callback_userdata;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        tlserr(tls_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        tlserr(tls_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(in, NULL, passwd_callback,
                              passwd_callback_userdata);
    if (x == NULL) {
        tlserr(tls_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    if (ctx)
        ret = tls_CTX_use_certificate(ctx, x);
    else
        ret = tls_use_certificate(tls, x);

    if (ERR_peek_error() != 0)
        ret = 0;                /* Key/certificate mismatch doesn't imply
                                 * ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to the CA
         * certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        if (ctx)
            r = tls_CTX_clear_chain_certs(ctx);
        else
            r = tls_clear_chain_certs(tls);

        if (r == 0) {
            ret = 0;
            goto end;
        }

        while ((ca = PEM_read_bio_X509(in, NULL, passwd_callback,
                                       passwd_callback_userdata))
               != NULL) {
            if (ctx)
                r = tls_CTX_add0_chain_cert(ctx, ca);
            else
                r = tls_add0_chain_cert(tls, ca);
            /*
             * Note that we must not free ca if it was successfully added to
             * the chain (while we must free the main certificate, since its
             * reference count is increased by tls_CTX_use_certificate).
             */
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
        }
        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM
            && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0;            /* some real error */
    }

 end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

int tls_CTX_use_certificate_chain_file(tls_CTX *ctx, const char *file)
{
    return use_certificate_chain_file(ctx, NULL, file);
}

int tls_use_certificate_chain_file(tls *tls, const char *file)
{
    return use_certificate_chain_file(NULL, tls, file);
}

static int serverinfo_find_extension(const unsigned char *serverinfo,
                                     size_t serverinfo_length,
                                     unsigned int extension_type,
                                     const unsigned char **extension_data,
                                     size_t *extension_length)
{
    PACKET pkt, data;

    *extension_data = NULL;
    *extension_length = 0;
    if (serverinfo == NULL || serverinfo_length == 0)
        return -1;

    if (!PACKET_buf_init(&pkt, serverinfo, serverinfo_length))
        return -1;

    for (;;) {
        unsigned int type = 0;
        unsigned long context = 0;

        /* end of serverinfo */
        if (PACKET_remaining(&pkt) == 0)
            return 0;           /* Extension not found */

        if (!PACKET_get_net_4(&pkt, &context)
                || !PACKET_get_net_2(&pkt, &type)
                || !PACKET_get_length_prefixed_2(&pkt, &data))
            return -1;

        if (type == extension_type) {
            *extension_data = PACKET_data(&data);
            *extension_length = PACKET_remaining(&data);;
            return 1;           /* Success */
        }
    }
    /* Unreachable */
}

static int serverinfoex_srv_parse_cb(tls *s, unsigned int ext_type,
                                     unsigned int context,
                                     const unsigned char *in,
                                     size_t inlen, X509 *x, size_t chainidx,
                                     int *al, void *arg)
{

    if (inlen != 0) {
        *al = tls_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}

static int serverinfo_srv_parse_cb(tls *s, unsigned int ext_type,
                                   const unsigned char *in,
                                   size_t inlen, int *al, void *arg)
{
    return serverinfoex_srv_parse_cb(s, ext_type, 0, in, inlen, NULL, 0, al,
                                     arg);
}

static int serverinfoex_srv_add_cb(tls *s, unsigned int ext_type,
                                   unsigned int context,
                                   const unsigned char **out,
                                   size_t *outlen, X509 *x, size_t chainidx,
                                   int *al, void *arg)
{
    const unsigned char *serverinfo = NULL;
    size_t serverinfo_length = 0;

    /* We only support extensions for the first Certificate */
    if ((context & tls_EXT_TLS1_3_CERTIFICATE) != 0 && chainidx > 0)
        return 0;

    /* Is there serverinfo data for the chosen server cert? */
    if ((tls_get_server_cert_serverinfo(s, &serverinfo,
                                        &serverinfo_length)) != 0) {
        /* Find the relevant extension from the serverinfo */
        int retval = serverinfo_find_extension(serverinfo, serverinfo_length,
                                               ext_type, out, outlen);
        if (retval == -1) {
            *al = tls_AD_INTERNAL_ERROR;
            return -1;          /* Error */
        }
        if (retval == 0)
            return 0;           /* No extension found, don't send extension */
        return 1;               /* Send extension */
    }
    return 0;                   /* No serverinfo data found, don't send
                                 * extension */
}

static int serverinfo_srv_add_cb(tls *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 int *al, void *arg)
{
    return serverinfoex_srv_add_cb(s, ext_type, 0, out, outlen, NULL, 0, al,
                                   arg);
}

/*
 * With a NULL context, this function just checks that the serverinfo data
 * parses correctly.  With a non-NULL context, it registers callbacks for
 * the included extensions.
 */
static int serverinfo_process_buffer(unsigned int version,
                                     const unsigned char *serverinfo,
                                     size_t serverinfo_length, tls_CTX *ctx)
{
    PACKET pkt;

    if (serverinfo == NULL || serverinfo_length == 0)
        return 0;

    if (version != tls_SERVERINFOV1 && version != tls_SERVERINFOV2)
        return 0;

    if (!PACKET_buf_init(&pkt, serverinfo, serverinfo_length))
        return 0;

    while (PACKET_remaining(&pkt)) {
        unsigned long context = 0;
        unsigned int ext_type = 0;
        PACKET data;

        if ((version == tls_SERVERINFOV2 && !PACKET_get_net_4(&pkt, &context))
                || !PACKET_get_net_2(&pkt, &ext_type)
                || !PACKET_get_length_prefixed_2(&pkt, &data))
            return 0;

        if (ctx == NULL)
            continue;

        /*
         * The old style custom extensions API could be set separately for
         * server/client, i.e. you could set one custom extension for a client,
         * and *for the same extension in the same tls_CTX* you could set a
         * custom extension for the server as well. It seems quite weird to be
         * setting a custom extension for both client and server in a single
         * tls_CTX - but theoretically possible. This isn't possible in the
         * new API. Therefore, if we have V1 serverinfo we use the old API. We
         * also use the old API even if we have V2 serverinfo but the context
         * looks like an old style <= TLSv1.2 extension.
         */
        if (version == tls_SERVERINFOV1 || context == SYNTHV1CONTEXT) {
            if (!tls_CTX_add_server_custom_ext(ctx, ext_type,
                                               serverinfo_srv_add_cb,
                                               NULL, NULL,
                                               serverinfo_srv_parse_cb,
                                               NULL))
                return 0;
        } else {
            if (!tls_CTX_add_custom_ext(ctx, ext_type, context,
                                        serverinfoex_srv_add_cb,
                                        NULL, NULL,
                                        serverinfoex_srv_parse_cb,
                                        NULL))
                return 0;
        }
    }

    return 1;
}

int tls_CTX_use_serverinfo_ex(tls_CTX *ctx, unsigned int version,
                              const unsigned char *serverinfo,
                              size_t serverinfo_length)
{
    unsigned char *new_serverinfo;

    if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_EX, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!serverinfo_process_buffer(version, serverinfo, serverinfo_length,
                                   NULL)) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_EX, tls_R_INVALID_SERVERINFO_DATA);
        return 0;
    }
    if (ctx->cert->key == NULL) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_EX, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    new_serverinfo = OPENtls_realloc(ctx->cert->key->serverinfo,
                                     serverinfo_length);
    if (new_serverinfo == NULL) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_EX, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ctx->cert->key->serverinfo = new_serverinfo;
    memcpy(ctx->cert->key->serverinfo, serverinfo, serverinfo_length);
    ctx->cert->key->serverinfo_length = serverinfo_length;

    /*
     * Now that the serverinfo is validated and stored, go ahead and
     * register callbacks.
     */
    if (!serverinfo_process_buffer(version, serverinfo, serverinfo_length,
                                   ctx)) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_EX, tls_R_INVALID_SERVERINFO_DATA);
        return 0;
    }
    return 1;
}

int tls_CTX_use_serverinfo(tls_CTX *ctx, const unsigned char *serverinfo,
                           size_t serverinfo_length)
{
    return tls_CTX_use_serverinfo_ex(ctx, tls_SERVERINFOV1, serverinfo,
                                     serverinfo_length);
}

int tls_CTX_use_serverinfo_file(tls_CTX *ctx, const char *file)
{
    unsigned char *serverinfo = NULL;
    unsigned char *tmp;
    size_t serverinfo_length = 0;
    unsigned char *extension = 0;
    long extension_length = 0;
    char *name = NULL;
    char *header = NULL;
    static const char namePrefix1[] = "SERVERINFO FOR ";
    static const char namePrefix2[] = "SERVERINFOV2 FOR ";
    unsigned int name_len;
    int ret = 0;
    BIO *bin = NULL;
    size_t num_extensions = 0, contextoff = 0;

    if (ctx == NULL || file == NULL) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }

    bin = BIO_new(BIO_s_file());
    if (bin == NULL) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, ERR_R_BUF_LIB);
        goto end;
    }
    if (BIO_read_filename(bin, file) <= 0) {
        tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    for (num_extensions = 0;; num_extensions++) {
        unsigned int version;

        if (PEM_read_bio(bin, &name, &header, &extension, &extension_length)
            == 0) {
            /*
             * There must be at least one extension in this file
             */
            if (num_extensions == 0) {
                tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE,
                       tls_R_NO_PEM_EXTENSIONS);
                goto end;
            } else              /* End of file, we're done */
                break;
        }
        /* Check that PEM name starts with "BEGIN SERVERINFO FOR " */
        name_len = strlen(name);
        if (name_len < sizeof(namePrefix1) - 1) {
            tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, tls_R_PEM_NAME_TOO_SHORT);
            goto end;
        }
        if (strncmp(name, namePrefix1, sizeof(namePrefix1) - 1) == 0) {
            version = tls_SERVERINFOV1;
        } else {
            if (name_len < sizeof(namePrefix2) - 1) {
                tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE,
                       tls_R_PEM_NAME_TOO_SHORT);
                goto end;
            }
            if (strncmp(name, namePrefix2, sizeof(namePrefix2) - 1) != 0) {
                tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE,
                       tls_R_PEM_NAME_BAD_PREFIX);
                goto end;
            }
            version = tls_SERVERINFOV2;
        }
        /*
         * Check that the decoded PEM data is plausible (valid length field)
         */
        if (version == tls_SERVERINFOV1) {
            /* 4 byte header: 2 bytes type, 2 bytes len */
            if (extension_length < 4
                    || (extension[2] << 8) + extension[3]
                       != extension_length - 4) {
                tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, tls_R_BAD_DATA);
                goto end;
            }
            /*
             * File does not have a context value so we must take account of
             * this later.
             */
            contextoff = 4;
        } else {
            /* 8 byte header: 4 bytes context, 2 bytes type, 2 bytes len */
            if (extension_length < 8
                    || (extension[6] << 8) + extension[7]
                       != extension_length - 8) {
                tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, tls_R_BAD_DATA);
                goto end;
            }
        }
        /* Append the decoded extension to the serverinfo buffer */
        tmp = OPENtls_realloc(serverinfo, serverinfo_length + extension_length
                                          + contextoff);
        if (tmp == NULL) {
            tlserr(tls_F_tls_CTX_USE_SERVERINFO_FILE, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        serverinfo = tmp;
        if (contextoff > 0) {
            unsigned char *sinfo = serverinfo + serverinfo_length;

            /* We know this only uses the last 2 bytes */
            sinfo[0] = 0;
            sinfo[1] = 0;
            sinfo[2] = (SYNTHV1CONTEXT >> 8) & 0xff;
            sinfo[3] = SYNTHV1CONTEXT & 0xff;
        }
        memcpy(serverinfo + serverinfo_length + contextoff,
               extension, extension_length);
        serverinfo_length += extension_length + contextoff;

        OPENtls_free(name);
        name = NULL;
        OPENtls_free(header);
        header = NULL;
        OPENtls_free(extension);
        extension = NULL;
    }

    ret = tls_CTX_use_serverinfo_ex(ctx, tls_SERVERINFOV2, serverinfo,
                                    serverinfo_length);
 end:
    /* tls_CTX_use_serverinfo makes a local copy of the serverinfo. */
    OPENtls_free(name);
    OPENtls_free(header);
    OPENtls_free(extension);
    OPENtls_free(serverinfo);
    BIO_free(bin);
    return ret;
}

static int tls_set_cert_and_key(tls *tls, tls_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                                STACK_OF(X509) *chain, int override)
{
    int ret = 0;
    size_t i;
    int j;
    int rv;
    CERT *c = tls != NULL ? tls->cert : ctx->cert;
    STACK_OF(X509) *dup_chain = NULL;
    EVP_PKEY *pubkey = NULL;

    /* Do all security checks before anything else */
    rv = tls_security_cert(tls, ctx, x509, 0, 1);
    if (rv != 1) {
        tlserr(tls_F_tls_SET_CERT_AND_KEY, rv);
        goto out;
    }
    for (j = 0; j < sk_X509_num(chain); j++) {
        rv = tls_security_cert(tls, ctx, sk_X509_value(chain, j), 0, 0);
        if (rv != 1) {
            tlserr(tls_F_tls_SET_CERT_AND_KEY, rv);
            goto out;
        }
    }

    pubkey = X509_get_pubkey(x509); /* bumps reference */
    if (pubkey == NULL)
        goto out;
    if (privatekey == NULL) {
        privatekey = pubkey;
    } else {
        /* For RSA, which has no parameters, missing returns 0 */
        if (EVP_PKEY_missing_parameters(privatekey)) {
            if (EVP_PKEY_missing_parameters(pubkey)) {
                /* nobody has parameters? - error */
                tlserr(tls_F_tls_SET_CERT_AND_KEY, tls_R_MISSING_PARAMETERS);
                goto out;
            } else {
                /* copy to privatekey from pubkey */
                EVP_PKEY_copy_parameters(privatekey, pubkey);
            }
        } else if (EVP_PKEY_missing_parameters(pubkey)) {
            /* copy to pubkey from privatekey */
            EVP_PKEY_copy_parameters(pubkey, privatekey);
        } /* else both have parameters */

        /* Copied from tls_set_cert/pkey */
#ifndef OPENtls_NO_RSA
        if ((EVP_PKEY_id(privatekey) == EVP_PKEY_RSA) &&
            ((RSA_flags(EVP_PKEY_get0_RSA(privatekey)) & RSA_METHOD_FLAG_NO_CHECK)))
            /* no-op */ ;
        else
#endif
        /* check that key <-> cert match */
        if (EVP_PKEY_cmp(pubkey, privatekey) != 1) {
            tlserr(tls_F_tls_SET_CERT_AND_KEY, tls_R_PRIVATE_KEY_MISMATCH);
            goto out;
        }
    }
    if (tls_cert_lookup_by_pkey(pubkey, &i) == NULL) {
        tlserr(tls_F_tls_SET_CERT_AND_KEY, tls_R_UNKNOWN_CERTIFICATE_TYPE);
        goto out;
    }

    if (!override && (c->pkeys[i].x509 != NULL
                      || c->pkeys[i].privatekey != NULL
                      || c->pkeys[i].chain != NULL)) {
        /* No override, and something already there */
        tlserr(tls_F_tls_SET_CERT_AND_KEY, tls_R_NOT_REPLACING_CERTIFICATE);
        goto out;
    }

    if (chain != NULL) {
        dup_chain = X509_chain_up_ref(chain);
        if  (dup_chain == NULL) {
            tlserr(tls_F_tls_SET_CERT_AND_KEY, ERR_R_MALLOC_FAILURE);
            goto out;
        }
    }

    sk_X509_pop_free(c->pkeys[i].chain, X509_free);
    c->pkeys[i].chain = dup_chain;

    X509_free(c->pkeys[i].x509);
    X509_up_ref(x509);
    c->pkeys[i].x509 = x509;

    EVP_PKEY_free(c->pkeys[i].privatekey);
    EVP_PKEY_up_ref(privatekey);
    c->pkeys[i].privatekey = privatekey;

    c->key = &(c->pkeys[i]);

    ret = 1;
 out:
    EVP_PKEY_free(pubkey);
    return ret;
}

int tls_use_cert_and_key(tls *tls, X509 *x509, EVP_PKEY *privatekey,
                         STACK_OF(X509) *chain, int override)
{
    return tls_set_cert_and_key(tls, NULL, x509, privatekey, chain, override);
}

int tls_CTX_use_cert_and_key(tls_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                             STACK_OF(X509) *chain, int override)
{
    return tls_set_cert_and_key(NULL, ctx, x509, privatekey, chain, override);
}
