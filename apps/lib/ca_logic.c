/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <ca_logic.h>
#include <openssl/x509.h>
#include <apps.h>

int do_updatedb(CA_DB *db)
{
    ASN1_TIME *a_tm = NULL;
    int i, cnt = 0;
    char **rrow;

    a_tm = ASN1_TIME_new();
    if (a_tm == NULL)
        return -1;

    if (X509_gmtime_adj(a_tm, 0) == NULL) {
        ASN1_TIME_free(a_tm);
        return -1;
    }

    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        rrow = sk_OPENSSL_PSTRING_value(db->db->data, i);

        if (rrow[DB_type][0] == DB_TYPE_VAL) {
            ASN1_TIME *exp_date = NULL;

            exp_date = ASN1_TIME_new();
            if (exp_date == NULL) {
                ASN1_TIME_free(a_tm);
                return -1;
            }

            if (!ASN1_TIME_set_string(exp_date, rrow[DB_exp_date])) {
                ASN1_TIME_free(a_tm);
                ASN1_TIME_free(exp_date);
                return -1;
            }

            if (ASN1_TIME_compare(exp_date, a_tm) <= 0) {
                rrow[DB_type][0] = DB_TYPE_EXP;
                rrow[DB_type][1] = '\0';
                cnt++;

                BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
            }
            ASN1_TIME_free(exp_date);
        }
    }

    ASN1_TIME_free(a_tm);
    return cnt;
}

