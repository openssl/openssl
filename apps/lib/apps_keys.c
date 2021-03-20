/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps_keys.h"
#include "apps_ui.h"
#include "apps_libctx.h"
#include "apps_propq.h"
#include "apps_os_wrapper.h"
#include "engine.h"
#include <openssl/bio.h>
#include <openssl/store.h>
#include <fmt.h>
#include <string.h>
#include <openssl/err.h>

/*
 * Load those types of credentials for which the result pointer is not NULL.
 * Reads from stdio if uri is NULL and maybe_stdin is nonzero.
 * For non-NULL ppkey, pcert, and pcrl the first suitable value found is loaded.
 * If pcerts is non-NULL and *pcerts == NULL then a new cert list is allocated.
 * If pcerts is non-NULL then all available certificates are appended to *pcerts
 * except any certificate assigned to *pcert.
 * If pcrls is non-NULL and *pcrls == NULL then a new list of CRLs is allocated.
 * If pcrls is non-NULL then all available CRLs are appended to *pcerts
 * except any CRL assigned to *pcrl.
 * In any case (also on error) the caller is responsible for freeing all members
 * of *pcerts and *pcrls (as far as they are not NULL).
 */
int load_key_certs_crls(const char *uri, int maybe_stdin,
                        const char *pass, const char *desc,
                        EVP_PKEY **ppkey, EVP_PKEY **ppubkey,
                        EVP_PKEY **pparams,
                        X509 **pcert, STACK_OF(X509) **pcerts,
                        X509_CRL **pcrl, STACK_OF(X509_CRL) **pcrls)
{
    PW_CB_DATA uidata;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_LIB_CTX *libctx = app_get0_libctx();
    const char *propq = app_get0_propq();
    int ncerts = 0;
    int ncrls = 0;
    const char *failed =
        ppkey != NULL ? "key" : ppubkey != NULL ? "public key" :
        pparams != NULL ? "params" : pcert != NULL ? "cert" :
        pcrl != NULL ? "CRL" : pcerts != NULL ? "certs" :
        pcrls != NULL ? "CRLs" : NULL;
    int cnt_expectations = 0;
    int expect = 0;
    /* TODO make use of the engine reference 'eng' when loading pkeys */

    if (ppkey != NULL) {
        *ppkey = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_PKEY;
    }
    if (ppubkey != NULL) {
        *ppubkey = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_PUBKEY;
    }
    if (pparams != NULL) {
        *pparams = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_PARAMS;
    }
    if (pcert != NULL) {
        *pcert = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CERT;
    }
    if (failed == NULL) {
        BIO_printf(bio_err, "Internal error: nothing to load into from %s\n",
                   uri != NULL ? uri : "<stdin>");
        return 0;
    }

    if (pcerts != NULL) {
        if (*pcerts == NULL && (*pcerts = sk_X509_new_null()) == NULL) {
            BIO_printf(bio_err, "Out of memory loading");
            goto end;
        }
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CERT;
    }
    if (pcrl != NULL) {
        *pcrl = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CRL;
    }
    if (pcrls != NULL) {
        if (*pcrls == NULL && (*pcrls = sk_X509_CRL_new_null()) == NULL) {
            BIO_printf(bio_err, "Out of memory loading");
            goto end;
        }
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CRL;
    }

    uidata.password = pass;
    uidata.prompt_info = uri;

    if (uri == NULL) {
        BIO *bio;

        if (!maybe_stdin) {
            BIO_printf(bio_err, "No filename or uri specified for loading");
            goto end;
        }
        uri = "<stdin>";
        unbuffer(stdin);
        bio = BIO_new_fp(stdin, 0);
        if (bio != NULL)
            ctx = OSSL_STORE_attach(bio, "file", libctx, propq,
                                    get_ui_method(), &uidata, NULL, NULL);
    } else {
        ctx = OSSL_STORE_open_ex(uri, libctx, propq, get_ui_method(), &uidata,
                                 NULL, NULL);
    }
    if (ctx == NULL) {
        BIO_printf(bio_err, "Could not open file or uri for loading");
        goto end;
    }

    if (cnt_expectations != 1)
        expect = 0;
    if (!OSSL_STORE_expect(ctx, expect))
        goto end;

    failed = NULL;
    while (cnt_expectations > 0 && !OSSL_STORE_eof(ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        int type, ok = 1;

        /*
         * This can happen (for example) if we attempt to load a file with
         * multiple different types of things in it - but the thing we just
         * tried to load wasn't one of the ones we wanted, e.g. if we're trying
         * to load a certificate but the file has both the private key and the
         * certificate in it. We just retry until eof.
         */
        if (info == NULL) {
            if (OSSL_STORE_error(ctx)) {
                ERR_print_errors(bio_err);
                ERR_clear_error();
            }
            continue;
        }

        type = OSSL_STORE_INFO_get_type(info);
        switch (type) {
        case OSSL_STORE_INFO_PKEY:
            if (ppkey != NULL && *ppkey == NULL) {
                ok = (*ppkey = OSSL_STORE_INFO_get1_PKEY(info)) != NULL;
                cnt_expectations -= ok;
            }
            /*
             * An EVP_PKEY with private parts also holds the public parts,
             * so if the caller asked for a public key, and we got a private
             * key, we can still pass it back.
             */
            if (ok && ppubkey != NULL && *ppubkey == NULL) {
                ok = ((*ppubkey = OSSL_STORE_INFO_get1_PKEY(info)) != NULL);
                cnt_expectations -= ok;
            }
            break;
        case OSSL_STORE_INFO_PUBKEY:
            if (ppubkey != NULL && *ppubkey == NULL) {
                ok = ((*ppubkey = OSSL_STORE_INFO_get1_PUBKEY(info)) != NULL);
                cnt_expectations -= ok;
            }
            break;
        case OSSL_STORE_INFO_PARAMS:
            if (pparams != NULL && *pparams == NULL) {
                ok = ((*pparams = OSSL_STORE_INFO_get1_PARAMS(info)) != NULL);
                cnt_expectations -= ok;
            }
            break;
        case OSSL_STORE_INFO_CERT:
            if (pcert != NULL && *pcert == NULL) {
                ok = (*pcert = OSSL_STORE_INFO_get1_CERT(info)) != NULL;
                cnt_expectations -= ok;
            }
            else if (pcerts != NULL)
                ok = X509_add_cert(*pcerts,
                                   OSSL_STORE_INFO_get1_CERT(info),
                                   X509_ADD_FLAG_DEFAULT);
            ncerts += ok;
            break;
        case OSSL_STORE_INFO_CRL:
            if (pcrl != NULL && *pcrl == NULL) {
                ok = (*pcrl = OSSL_STORE_INFO_get1_CRL(info)) != NULL;
                cnt_expectations -= ok;
            }
            else if (pcrls != NULL)
                ok = sk_X509_CRL_push(*pcrls, OSSL_STORE_INFO_get1_CRL(info));
            ncrls += ok;
            break;
        default:
            /* skip any other type */
            break;
        }
        OSSL_STORE_INFO_free(info);
        if (!ok) {
            failed = info == NULL ? NULL : OSSL_STORE_INFO_type_string(type);
            BIO_printf(bio_err, "Error reading");
            break;
        }
    }

 end:
    OSSL_STORE_close(ctx);
    if (failed == NULL) {
        int any = 0;

        if ((ppkey != NULL && *ppkey == NULL)
            || (ppubkey != NULL && *ppubkey == NULL)) {
            failed = "key";
        } else if (pparams != NULL && *pparams == NULL) {
            failed = "params";
        } else if ((pcert != NULL || pcerts != NULL) && ncerts == 0) {
            if (pcert == NULL)
                any = 1;
            failed = "cert";
        } else if ((pcrl != NULL || pcrls != NULL) && ncrls == 0) {
            if (pcrl == NULL)
                any = 1;
            failed = "CRL";
        }
        if (failed != NULL)
            BIO_printf(bio_err, "Could not read");
        if (any)
            BIO_printf(bio_err, " any");
    }
    if (failed != NULL) {
        if (desc != NULL && strstr(desc, failed) != NULL) {
            BIO_printf(bio_err, " %s", desc);
        } else {
            BIO_printf(bio_err, " %s", failed);
            if (desc != NULL)
                BIO_printf(bio_err, " of %s", desc);
        }
        if (uri != NULL)
            BIO_printf(bio_err, " from %s", uri);
        BIO_printf(bio_err, "\n");
        ERR_print_errors(bio_err);
    }
    return failed == NULL;
}

EVP_PKEY *load_key(const char *uri, int format, int may_stdin,
                   const char *pass, ENGINE *e, const char *desc)
{
    EVP_PKEY *pkey = NULL;
    char *allocated_uri = NULL;

    if (desc == NULL)
        desc = "private key";

    if (format == FORMAT_ENGINE) {
        uri = allocated_uri = make_engine_uri(e, uri, desc);
    }
    (void)load_key_certs_crls(uri, may_stdin, pass, desc,
                              &pkey, NULL, NULL, NULL, NULL, NULL, NULL);

    OPENSSL_free(allocated_uri);
    return pkey;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv = 0;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp == NULL)
        goto err;

    *vtmp = 0;
    vtmp++;
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);

 err:
    OPENSSL_free(stmp);
    return rv;
}

static int do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (pkey_ctrl_string(pkctx, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int def_nid;

    if (ctx == NULL)
        return 0;
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
            && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    return EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey)
        && do_pkey_ctx_init(pkctx, sigopts);
}


