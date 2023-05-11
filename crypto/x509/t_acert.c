/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509_acert.h>

static int print_attribute(BIO *bp, X509_ATTRIBUTE *a)
{
    ASN1_TYPE *at;
    ASN1_BIT_STRING *bs = NULL;
    ASN1_OBJECT *aobj;
    int i, j, type = 0, count = 0;
    int ret = 0;

    aobj = X509_ATTRIBUTE_get0_object(a);
    if (BIO_printf(bp, "%12s", "") <= 0)
        goto err;

    if ((j = i2a_ASN1_OBJECT(bp, aobj)) <= 0)
        goto err;

    count = X509_ATTRIBUTE_count(a);
    if (count == 0) {
        ERR_raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES);
        goto err;
    }

    if (BIO_printf(bp, "%*s", 25 - j, " ") <= 0)
        goto err;

    if (BIO_puts(bp, ":") <= 0)
        goto err;

    for (i = 0; i < count; i++) {
        at = X509_ATTRIBUTE_get0_type(a, i);
        type = at->type;
        bs = at->value.asn1_string;

        switch (type) {
        case V_ASN1_PRINTABLESTRING:
        case V_ASN1_T61STRING:
        case V_ASN1_NUMERICSTRING:
        case V_ASN1_UTF8STRING:
        case V_ASN1_IA5STRING:
            bs = at->value.asn1_string;
            if (BIO_write(bp, (char *)bs->data, bs->length) != bs->length)
                goto err;
            if (BIO_puts(bp, "\n") <= 0)
                goto err;
            break;
        case V_ASN1_SEQUENCE:
            if (BIO_puts(bp, "\n") <= 0)
                goto err;
            ASN1_parse_dump(bp, at->value.sequence->data,
                            at->value.sequence->length, i, 1);
            break;
        default:
            if (BIO_puts(bp, "unable to print attribute\n") <= 0)
                goto err;
            break;
        }
    }
    ret = 1;
err:
    return ret;
}

int X509_ACERT_print_ex(BIO *bp, X509_ACERT *x, unsigned long nmflags,
                        unsigned long cflag)
{
    int i;
    char mlch = ' ';

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
    }

    if ((cflag & X509_FLAG_NO_HEADER) == 0) {
        if (BIO_printf(bp, "Attribute Certificate:\n") <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }

    if ((cflag & X509_FLAG_NO_VERSION) == 0) {
        long l;

        l = X509_ACERT_get_version(x);
        if (l == X509_ACERT_VERSION_2) {
            if (BIO_printf(bp, "%8sVersion: %ld (0x%lx)\n", "", l + 1,
                           (unsigned long)l) <= 0)
                goto err;
        } else {
            if (BIO_printf(bp, "%8sVersion: Unknown (%ld)\n", "", l) <= 0)
                goto err;
        }
    }

    if ((cflag & X509_FLAG_NO_SERIAL) == 0) {
        ASN1_INTEGER *serial;
        char *serial_str;

        serial = X509_ACERT_get0_serialNumber(x);
        serial_str = i2s_ASN1_INTEGER(NULL, serial);
        if (serial_str == NULL)
            goto err;

        if (BIO_printf(bp, "%8sSerial Number: %s\n", "", serial_str) <= 0) {
            OPENSSL_free(serial_str);
            goto err;
        }
        OPENSSL_free(serial_str);
    }

    if ((cflag & X509_FLAG_NO_SUBJECT) == 0) {
        const GENERAL_NAMES *holderEntities;
        OSSL_ISSUER_SERIAL *holder_bcid;
        X509_NAME *holderIssuer = NULL;

        if (BIO_printf(bp, "        Holder:\n") <= 0)
            goto err;

        holderEntities = X509_ACERT_get0_holder_entityName(x);
        if (holderEntities != NULL) {
            GENERAL_NAME *entity = NULL;
            /*
             * Just display the first name in the sequence.  Any others
             * are ignored.
             */
            if (sk_GENERAL_NAME_num(holderEntities) >= 1)
                entity = sk_GENERAL_NAME_value(holderEntities, 0);

            if (entity != NULL) {
                if (BIO_printf(bp, "            Name:%c", mlch) <= 0)
                    goto err;

                if (GENERAL_NAME_print(bp, entity) <= 0)
                    goto err;
            }
            if (BIO_write(bp, "\n", 1) <= 0)
                goto err;
        }

        if ((holder_bcid = X509_ACERT_get0_holder_baseCertId(x)) != NULL)
            holderIssuer = OSSL_ISSUER_SERIAL_get0_issuer(holder_bcid);

        if (holderIssuer != NULL) {
            char *serial_s;
            ASN1_INTEGER *holder_serial;
            ASN1_BIT_STRING *iuid;
            holder_serial = OSSL_ISSUER_SERIAL_get0_serial(holder_bcid);

            if (BIO_printf(bp, "            Issuer:%c", mlch) <= 0)
                goto err;

            if (X509_NAME_print(bp, holderIssuer, 0) <= 0)
                goto err;

            if (BIO_write(bp, "\n", 1) <= 0)
                goto err;

            if (BIO_printf(bp, "            Serial: ") <= 0)
                goto err;

            serial_s = i2s_ASN1_INTEGER(NULL, holder_serial);
            if (serial_s == NULL)
                goto err;

            if (BIO_printf(bp, "%s", serial_s) <= 0) {
                OPENSSL_free(serial_s);
                goto err;
            }
            OPENSSL_free(serial_s);

            iuid = OSSL_ISSUER_SERIAL_get0_issuerUID(holder_bcid);
            if (iuid != NULL) {
                if (BIO_printf(bp, "            Issuer UID: ") <= 0)
                    goto err;
                if (!X509_signature_dump(bp, iuid, 24))
                    goto err;
            }
            if (BIO_write(bp, "\n", 1) <= 0)
                goto err;
        }
    }

    if ((cflag & X509_FLAG_NO_ISSUER) == 0) {
        if (BIO_printf(bp, "        Issuer:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, X509_ACERT_get0_issuerName(x), 0, nmflags)
            < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }

    if ((cflag & X509_FLAG_NO_VALIDITY) == 0) {
        if (BIO_write(bp, "        Validity\n", 17) <= 0)
            goto err;
        if (BIO_write(bp, "            Not Before: ", 24) <= 0)
            goto err;
        if (ASN1_GENERALIZEDTIME_print(bp, X509_ACERT_get0_notBefore(x)) == 0)
            goto err;
        if (BIO_write(bp, "\n            Not After : ", 25) <= 0)
            goto err;
        if (ASN1_GENERALIZEDTIME_print(bp, X509_ACERT_get0_notAfter(x)) == 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }

    if ((cflag & X509_FLAG_NO_ATTRIBUTES) == 0) {
        if (BIO_printf(bp, "%8sAttributes:\n", "") <= 0)
            goto err;

        if (X509_ACERT_get_attr_count(x) == 0) {
            if (BIO_printf(bp, "%12s(none)\n", "") <= 0)
                goto err;
        } else {
            for (i = 0; i < X509_ACERT_get_attr_count(x); i++) {
                if (print_attribute(bp, X509_ACERT_get_attr(x, i)) == 0)
                    goto err;
            }
        }
    }

    if ((cflag & X509_FLAG_NO_EXTENSIONS) == 0) {
        const STACK_OF(X509_EXTENSION) *exts;

        exts = X509_ACERT_get0_extensions(x);
        if (exts != NULL) {
            if (BIO_printf(bp, "%8sExtensions:\n", "") <= 0)
                goto err;
            for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
                ASN1_OBJECT *obj;
                X509_EXTENSION *ex;
                int critical;
                ex = sk_X509_EXTENSION_value(exts, i);
                if (BIO_printf(bp, "%12s", "") <= 0)
                    goto err;
                obj = X509_EXTENSION_get_object(ex);
                if (i2a_ASN1_OBJECT(bp, obj) <= 0)
                    goto err;
                critical = X509_EXTENSION_get_critical(ex);
                if (BIO_printf(bp, ": %s\n", critical ? "critical" : "") <= 0)
                    goto err;
                if (!X509V3_EXT_print(bp, ex, cflag, 20)) {
                    if (BIO_printf(bp, "%16s", "") <= 0
                        || ASN1_STRING_print(bp,
                                             X509_EXTENSION_get_data(ex)) <= 0)
                        goto err;
                }
                if (BIO_write(bp, "\n", 1) <= 0)
                    goto err;
            }
        }
    }

    if ((cflag & X509_FLAG_NO_SIGDUMP) == 0) {
        const X509_ALGOR *sig_alg;
        const ASN1_BIT_STRING *sig;

        X509_ACERT_get0_signature(x, &sig, &sig_alg);
        if (!X509_signature_print(bp, sig_alg, sig))
            goto err;
    }

    return 1;

err:
    ERR_raise(ERR_LIB_X509, ERR_R_BUF_LIB);
    return 0;
}

int X509_ACERT_print(BIO *bp, X509_ACERT *x)
{
    return X509_ACERT_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}
