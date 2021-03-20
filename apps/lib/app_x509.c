/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include "app_x509.h"
#include "apps_globals.h"
#include "apps_config.h"
#include "apps_keys.h"
#include <openssl/http.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/ocsp.h>
#include "opt.h"
#include <string.h>
//#include "apps.h"

//#include <ctype.h>
//#include <openssl/x509v3.h>
//#include "apps.h"
//#include "apps_config.h"
//#include "apps_propq.h"
//#include "apps_libctx.h"
//#include "apps_globals.h"
//#include "apps_opts.h"
//#include "apps_keys.h"


//# include <openssl/txt_db.h>
//# include <openssl/http.h>
//# include <signal.h>
//# include "fmt.h"
//# include "apps_ui.h"
//# include "platform.h"

/*
 * X509_ctrl_str() is sorely lacking in libcrypto, but is still needed to
 * allow the application to process verification options in a manner similar
 * to signature or other options that pass through EVP_PKEY_CTX_ctrl_str(),
 * for uniformity.
 *
 * As soon as more stuff is added, the code will need serious rework.  For
 * the moment, it only handles the FIPS 196 / SM2 distinguishing ID.
 */
#ifdef EVP_PKEY_CTRL_SET1_ID
static ASN1_OCTET_STRING *mk_octet_string(void *value, size_t value_n)
{
    ASN1_OCTET_STRING *v = ASN1_OCTET_STRING_new();

    if (v == NULL) {
        BIO_printf(bio_err, "error: allocation failed\n");
    } else if (!ASN1_OCTET_STRING_set(v, value, value_n)) {
        ASN1_OCTET_STRING_free(v);
        v = NULL;
    }
    return v;
}
#endif

static int x509_ctrl(void *object, int cmd, void *value, size_t value_n)
{
    switch (cmd) {
#ifdef EVP_PKEY_CTRL_SET1_ID
    case EVP_PKEY_CTRL_SET1_ID:
        {
            ASN1_OCTET_STRING *v = mk_octet_string(value, value_n);

            if (v == NULL) {
                BIO_printf(bio_err,
                           "error: setting distinguishing ID in certificate failed\n");
                return 0;
            }

            X509_set0_distinguishing_id(object, v);
            return 1;
        }
#endif
    default:
        break;
    }
    return -2;     /* typical EVP_PKEY return for "unsupported" */
}

static int x509_req_ctrl(void *object, int cmd, void *value, size_t value_n)
{
    switch (cmd) {
#ifdef EVP_PKEY_CTRL_SET1_ID
    case EVP_PKEY_CTRL_SET1_ID:
        {
            ASN1_OCTET_STRING *v = mk_octet_string(value, value_n);

            if (v == NULL) {
                BIO_printf(bio_err,
                           "error: setting distinguishing ID in certificate signing request failed\n");
                return 0;
            }

            X509_REQ_set0_distinguishing_id(object, v);
            return 1;
        }
#endif
    default:
        break;
    }
    return -2;     /* typical EVP_PKEY return for "unsupported" */
}

static int do_x509_ctrl_string(int (*ctrl)(void *object, int cmd,
                                           void *value, size_t value_n),
                               void *object, const char *value)
{
    int rv = 0;
    char *stmp, *vtmp = NULL;
    size_t vtmp_len = 0;
    int cmd = 0; /* Will get command values that make sense somehow */

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp != NULL) {
        *vtmp = 0;
        vtmp++;
        vtmp_len = strlen(vtmp);
    }

    if (strcmp(stmp, "distid") == 0) {
#ifdef EVP_PKEY_CTRL_SET1_ID
        cmd = EVP_PKEY_CTRL_SET1_ID; /* ... except we put it in X509 */
#endif
    } else if (strcmp(stmp, "hexdistid") == 0) {
        if (vtmp != NULL) {
            void *hexid;
            long hexid_len = 0;

            hexid = OPENSSL_hexstr2buf((const char *)vtmp, &hexid_len);
            OPENSSL_free(stmp);
            stmp = vtmp = hexid;
            vtmp_len = (size_t)hexid_len;
        }
#ifdef EVP_PKEY_CTRL_SET1_ID
        cmd = EVP_PKEY_CTRL_SET1_ID; /* ... except we put it in X509 */
#endif
    }

    rv = ctrl(object, cmd, vtmp, vtmp_len);

    OPENSSL_free(stmp);
    return rv;
}

int x509_ctrl_string(X509 *x, const char *value)
{
    return do_x509_ctrl_string(x509_ctrl, x, value);
}

int x509_req_ctrl_string(X509_REQ *x, const char *value)
{
    return do_x509_ctrl_string(x509_req_ctrl, x, value);
}

/* imported from apps_extracted.c */

#define IS_HTTP(uri) ((uri) != NULL \
        && strncmp(uri, OSSL_HTTP_PREFIX, strlen(OSSL_HTTP_PREFIX)) == 0)
#define IS_HTTPS(uri) ((uri) != NULL \
        && strncmp(uri, OSSL_HTTPS_PREFIX, strlen(OSSL_HTTPS_PREFIX)) == 0)

X509 *load_cert_pass(const char *uri, int maybe_stdin,
                     const char *pass, const char *desc)
{
    X509 *cert = NULL;

    if (desc == NULL)
        desc = "certificate";
    if (IS_HTTPS(uri))
        BIO_printf(bio_err, "Loading %s over HTTPS is unsupported\n", desc);
    else if (IS_HTTP(uri))
        cert = X509_load_http(uri, NULL, NULL, 0 /* timeout */);
    else
        (void)load_key_certs_crls(uri, maybe_stdin, pass, desc,
                                  NULL, NULL, NULL, &cert, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Unable to load %s\n", desc);
        ERR_print_errors(bio_err);
    }
    return cert;
}

X509_CRL *load_crl(const char *uri, const char *desc)
{
    X509_CRL *crl = NULL;

    if (desc == NULL)
        desc = "CRL";
    if (IS_HTTPS(uri))
        BIO_printf(bio_err, "Loading %s over HTTPS is unsupported\n", desc);
    else if (IS_HTTP(uri))
        crl = X509_CRL_load_http(uri, NULL, NULL, 0 /* timeout */);
    else
        (void)load_key_certs_crls(uri, 0, NULL, desc,
                                  NULL, NULL,  NULL, NULL, NULL, &crl, NULL);
    if (crl == NULL) {
        BIO_printf(bio_err, "Unable to load %s\n", desc);
        ERR_print_errors(bio_err);
    }
    return crl;
}

X509_REQ *load_csr(const char *file, int format, const char *desc)
{
    X509_REQ *req = NULL;
    BIO *in;

    if (desc == NULL)
        desc = "CSR";
    in = bio_open_default(file, 'r', format);
    if (in == NULL)
        goto end;

    if (format == FORMAT_ASN1)
        req = d2i_X509_REQ_bio(in, NULL);
    else if (format == FORMAT_PEM)
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    else
        print_format_error(format, OPT_FMT_PEMDER);

 end:
    if (req == NULL) {
        BIO_printf(bio_err, "Unable to load %s\n", desc);
        ERR_print_errors(bio_err);
    }
    BIO_free(in);
    return req;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts;
    int i, ret = 0;

    if (x == NULL || req == NULL)
        return 0;
    if (copy_type == EXT_COPY_NONE)
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        int idx = X509_get_ext_by_OBJ(x, obj, -1);

        /* Does extension exist in target? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                X509_EXTENSION_free(X509_delete_ext(x, idx));
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }
    ret = 1;

 end:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ret;
}

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where + can be used instead of / to form multi-valued RDNs if canmulti
 * and characters may be escaped by \
 */
X509_NAME *parse_name(const char *cp, int chtype, int canmulti,
                      const char *desc)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "%s: %s name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   opt_getprog(), desc, --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL) {
        BIO_printf(bio_err, "%s: Out of memory\n", opt_getprog());
        return NULL;
    }
    work = OPENSSL_strdup(cp);
    if (work == NULL) {
        BIO_printf(bio_err, "%s: Error copying %s name input\n",
                   opt_getprog(), desc);
        goto err;
    }

    while (*cp != '\0') {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp != '\0' && *cp != '=')
            *bp++ = *cp++;
        *bp++ = '\0';
        if (*cp == '\0') {
            BIO_printf(bio_err,
                       "%s: Missing '=' after RDN type string '%s' in %s name string\n",
                       opt_getprog(), typestr, desc);
            goto err;
        }
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp != '\0' && *cp != '/'; *bp++ = *cp++) {
            /* unescaped '+' symbol string signals further member of multiRDN */
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                BIO_printf(bio_err,
                           "%s: Escape character at end of %s name string\n",
                           opt_getprog(), desc);
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp != '\0')
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(bio_err,
                       "%s: Skipping unknown %s name attribute \"%s\"\n",
                       opt_getprog(), desc, typestr);
            if (ismulti)
                BIO_printf(bio_err,
                           "Hint: a '+' in a value string needs be escaped using '\\' else a new member of a multi-valued RDN is expected\n");
            continue;
        }
        if (*valstr == '\0') {
            BIO_printf(bio_err,
                       "%s: No value provided for %s name attribute \"%s\", skipped\n",
                       opt_getprog(), desc, typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0)) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err,
                       "%s: Error adding %s name attribute \"/%s=%s\"\n",
                       opt_getprog(), desc, typestr ,valstr);
            goto err;
        }
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

static int do_x509_init(X509 *x, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (x509_ctrl_string(x, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

static int do_x509_req_init(X509_REQ *x, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (x509_req_ctrl_string(x, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

static int adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx,
                           const char *name, const char *value, int add_default)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    X509_EXTENSION *new_ext = X509V3_EXT_nconf(NULL, ext_ctx, name, value);
    int idx, rv = 0;

    if (new_ext == NULL)
        return rv;

    idx = X509v3_get_ext_by_OBJ(exts, X509_EXTENSION_get_object(new_ext), -1);
    if (idx >= 0) {
        X509_EXTENSION *found_ext = X509v3_get_ext(exts, idx);
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(found_ext);
        int disabled = ASN1_STRING_length(data) <= 2; /* config said "none" */

        if (disabled) {
            X509_delete_ext(cert, idx);
            X509_EXTENSION_free(found_ext);
        } /* else keep existing key identifier, which might be outdated */
        rv = 1;
    } else  {
        rv = !add_default || X509_add_ext(cert, new_ext, -1);
    }
    X509_EXTENSION_free(new_ext);
    return rv;
}

/* Ensure RFC 5280 compliance, adapt keyIDs as needed, and sign the cert info */
int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int self_sign;
    int rv = 0;

    if (sk_X509_EXTENSION_num(exts /* may be NULL */) > 0) {
        /* Prevent X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 */
        if (!X509_set_version(cert, 2)) /* Make sure cert is X509 v3 */
            goto end;

        /*
         * Add default SKID before such that default AKID can make use of it
         * in case the certificate is self-signed
         */
        /* Prevent X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER */
        if (!adapt_keyid_ext(cert, ext_ctx, "subjectKeyIdentifier", "hash", 1))
            goto end;
        /* Prevent X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER */
        ERR_set_mark();
        self_sign = X509_check_private_key(cert, pkey);
        ERR_pop_to_mark();
        if (!adapt_keyid_ext(cert, ext_ctx, "authorityKeyIdentifier",
                             "keyid, issuer", !self_sign))
            goto end;

        /* TODO any further measures for ensuring default RFC 5280 compliance */
    }

    if (mctx != NULL && do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_sign_ctx(cert, mctx) > 0);
 end:
    EVP_MD_CTX_free(mctx);
    return rv;
}

/* Sign the certificate request info */
int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv = 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if (do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_REQ_sign_ctx(x, mctx) > 0);
    EVP_MD_CTX_free(mctx);
    return rv;
}

/* Sign the CRL info */
int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv = 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if (do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_CRL_sign_ctx(x, mctx) > 0);
    EVP_MD_CTX_free(mctx);
    return rv;
}

int do_X509_verify(X509 *x, EVP_PKEY *pkey, STACK_OF(OPENSSL_STRING) *vfyopts)
{
    int rv = 0;

    if (do_x509_init(x, vfyopts) > 0)
        rv = (X509_verify(x, pkey) > 0);
    return rv;
}

int do_X509_REQ_verify(X509_REQ *x, EVP_PKEY *pkey,
                       STACK_OF(OPENSSL_STRING) *vfyopts)
{
    int rv = 0;

    if (do_x509_req_init(x, vfyopts) > 0)
        rv = (X509_REQ_verify(x, pkey) > 0);
    return rv;
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            const char *uptr = (const char *)ASN1_STRING_get0_data(uri);

            if (IS_HTTP(uptr)) /* can/should not use HTTPS here */
                return uptr;
        }
    }
    return NULL;
}

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr)
            return load_crl(urlptr, "CRL via CDP");
    }
    return NULL;
}

/*
 * Example of downloading CRLs from CRLDP:
 * not usable for real world as it always downloads and doesn't cache anything.
 */

static STACK_OF(X509_CRL) *crls_http_cb(const X509_STORE_CTX *ctx,
                                        const X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;

    crls = sk_X509_CRL_new_null();
    if (!crls)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl) {
        sk_X509_CRL_free(crls);
        return NULL;
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

void store_setup_crl_download(X509_STORE *st)
{
    X509_STORE_set_lookup_crls_cb(st, crls_http_cb);
}

int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days)
{
    if (startdate == NULL || strcmp(startdate, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
        if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), startdate))
            return 0;
    }
    if (enddate == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL)
            == NULL)
            return 0;
    } else if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(x), enddate)) {
        return 0;
    }
    return 1;
}

int set_crl_lastupdate(X509_CRL *crl, const char *lastupdate)
{
    int ret = 0;
    ASN1_TIME *tm = ASN1_TIME_new();

    if (tm == NULL)
        goto end;

    if (lastupdate == NULL) {
        if (X509_gmtime_adj(tm, 0) == NULL)
            goto end;
    } else {
        if (!ASN1_TIME_set_string_X509(tm, lastupdate))
            goto end;
    }

    if (!X509_CRL_set1_lastUpdate(crl, tm))
        goto end;

    ret = 1;
end:
    ASN1_TIME_free(tm);
    return ret;
}

int set_crl_nextupdate(X509_CRL *crl, const char *nextupdate,
                       long days, long hours, long secs)
{
    int ret = 0;
    ASN1_TIME *tm = ASN1_TIME_new();

    if (tm == NULL)
        goto end;

    if (nextupdate == NULL) {
        if (X509_time_adj_ex(tm, days, hours * 60 * 60 + secs, NULL) == NULL)
            goto end;
    } else {
        if (!ASN1_TIME_set_string_X509(tm, nextupdate))
            goto end;
    }

    if (!X509_CRL_set1_nextUpdate(crl, tm))
        goto end;

    ret = 1;
end:
    ASN1_TIME_free(tm);
    return ret;
}

