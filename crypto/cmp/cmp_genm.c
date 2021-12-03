/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2022
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cmp_local.h"
#include <openssl/cmp_util.h>

static const X509_VERIFY_PARAM *get0_trustedStore_vpm(const OSSL_CMP_CTX *ctx)
{
    const X509_STORE *ts = OSSL_CMP_CTX_get0_trustedStore(ctx);

    return ts == NULL ? NULL : X509_STORE_get0_param(ts);
}

static void cert_msg(const char *func, const char *file, int lineno,
                     OSSL_CMP_severity level, OSSL_CMP_CTX *ctx,
                     const char *source, X509 *cert, const char *msg)
{
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

    ossl_cmp_print_log(level, ctx, func, file, lineno,
                       level == OSSL_CMP_LOG_WARNING ? "WARN" : "ERR",
                       "certificate from '%s' with subject '%s' %s",
                       source, subj, msg);
    OPENSSL_free(subj);
}

/* use |type_CA| -1 (no CA type check) or 0 (must be EE) or 1 (must be CA) */
static int ossl_X509_check(OSSL_CMP_CTX *ctx, const char *source, X509 *cert,
                           int type_CA, const X509_VERIFY_PARAM *vpm)
{
    uint32_t ex_flags = X509_get_extension_flags(cert);
    int res = X509_cmp_timeframe(vpm, X509_get0_notBefore(cert),
                                 X509_get0_notAfter(cert));
    int ret = res == 0;
    OSSL_CMP_severity level =
        vpm == NULL ? OSSL_CMP_LOG_WARNING : OSSL_CMP_LOG_ERR;

    if (!ret)
        cert_msg(OPENSSL_FUNC, OPENSSL_FILE, OPENSSL_LINE, level, ctx,
                 source, cert, res > 0 ? "has expired" : "not yet valid");
    if (type_CA >= 0 && (ex_flags & EXFLAG_V1) == 0) {
        int is_CA = (ex_flags & EXFLAG_CA) != 0;

        if ((type_CA != 0) != is_CA) {
            cert_msg(OPENSSL_FUNC, OPENSSL_FILE, OPENSSL_LINE, level, ctx,
                     source, cert,
                     is_CA ? "is not an EE cert" : "is not a CA cert");
            ret = 0;
        }
    }
    return ret;
}

static int ossl_X509_check_all(OSSL_CMP_CTX *ctx, const char *source,
                               STACK_OF(X509) *certs,
                               int type_CA, const X509_VERIFY_PARAM *vpm)
{
    int i;
    int ret = 1;

    for (i = 0; i < sk_X509_num(certs /* may be NULL */); i++)
        ret = ossl_X509_check(ctx, source,
                              sk_X509_value(certs, i), type_CA, vpm)
            && ret; /* Having 'ret' after the '&&', all certs are checked. */
    return ret;
}

static OSSL_CMP_ITAV *get_genm_itav(OSSL_CMP_CTX *ctx,
                                    OSSL_CMP_ITAV *req, /* gets consumed */
                                    int expected, const char *desc)
{
    STACK_OF(OSSL_CMP_ITAV) *itavs = NULL;
    int i, n;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_unspecified) {
        ERR_raise_data(ERR_LIB_CMP, CMP_R_UNCLEAN_CTX,
                       "client context in unsuitable state; should call CMPclient_reinit() before");
        goto err;
    }

    if (!OSSL_CMP_CTX_push0_genm_ITAV(ctx, req))
        goto err;
    req = NULL;
    itavs = OSSL_CMP_exec_GENM_ses(ctx);
    if (itavs == NULL) {
        if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_request)
            ERR_raise_data(ERR_LIB_CMP, CMP_R_GETTING_GENP,
                           "with infoType %s", desc);
        return NULL;
    }

    if ((n = sk_OSSL_CMP_ITAV_num(itavs)) <= 0) {
        ERR_raise_data(ERR_LIB_CMP, CMP_R_INVALID_GENP,
                       "response on genm requesting infoType %s does not include suitable value", desc);
        sk_OSSL_CMP_ITAV_free(itavs);
        return NULL;
    }

    if (n > 1)
        ossl_cmp_log2(WARN, ctx,
                      "response on genm contains %d ITAVs; will use the first ITAV with infoType id-it-%s",
                      n, desc);
    for (i = 0; i < n; i++) {
        OSSL_CMP_ITAV *itav = sk_OSSL_CMP_ITAV_shift(itavs);
        ASN1_OBJECT *obj = OSSL_CMP_ITAV_get0_type(itav);
        char name[128] = "genp contains InfoType '";
        size_t offset = strlen(name);

        if (OBJ_obj2nid(obj) == expected) {
            for (i++; i < n; i++)
                OSSL_CMP_ITAV_free(sk_OSSL_CMP_ITAV_shift(itavs));
            sk_OSSL_CMP_ITAV_free(itavs);
            return itav;
        }

        if (OBJ_obj2txt(name + offset, sizeof(name) - offset, obj, 0) < 0)
            strcat(name, "<unknown>");
        ossl_cmp_log2(WARN, ctx, "%s' while expecting 'id-it-%s'", name, desc);
        OSSL_CMP_ITAV_free(itav);
    }
    ERR_raise_data(ERR_LIB_CMP, CMP_R_INVALID_GENP,
                   "could not find any ITAV for %s", desc);

 err:
    sk_OSSL_CMP_ITAV_free(itavs);
    OSSL_CMP_ITAV_free(req);
    return NULL;
}

int OSSL_CMP_get_caCerts(OSSL_CMP_CTX *ctx, STACK_OF(X509) **out)
{
    OSSL_CMP_ITAV *req, *itav;
    STACK_OF(X509) *certs = NULL;
    int ret = 0;

    if (out == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    *out = NULL;

    if ((req = OSSL_CMP_ITAV_new_caCerts(NULL)) == NULL)
        return 0;
    if ((itav = get_genm_itav(ctx, req, NID_id_it_caCerts, "caCerts")) == NULL)
        return 0;
    if (!OSSL_CMP_ITAV_get0_caCerts(itav, &certs))
        goto end;
    ret = 1;
    if (certs == NULL) /* no CA certificate available */
        goto end;

    if (!ossl_X509_check_all(ctx, "genp", certs, 1 /* CA */,
                             get0_trustedStore_vpm(ctx))) {
        ret = 0;
        goto end;
    }
    *out = sk_X509_new_reserve(NULL, sk_X509_num(certs));
    if (!X509_add_certs(*out, certs,
                        X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP)) {
        sk_X509_pop_free(*out, X509_free);
        *out = NULL;
        ret = 0;
    }

 end:
    OSSL_CMP_ITAV_free(itav);
    return ret;
}
