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

int do_updatedb(CA_DB *db, time_t *now)
{
    ASN1_TIME *a_tm = NULL;
    int i, cnt = 0;
    char **rrow;

    a_tm = ASN1_TIME_new();
    if (a_tm == NULL)
        return -1;

    if (X509_time_adj(a_tm, 0, now) == NULL) {
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

time_t iso8601_utc_to_time_t(const char *dateStr)
{
    struct tm t;
    time_t t1 = time(NULL);
    long timezone;

    /* calculate difference to GMT manually */
    localtime_r(&t1, &t);
    timezone = t.tm_gmtoff;

    int success = sscanf(dateStr, "%d-%d-%dT%d:%dZ",
        &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min);

    if (success != 5) {
        return 0;
    }

    t.tm_year = t.tm_year - 1900;
    t.tm_mon = t.tm_mon - 1;
    t.tm_sec = 0;
    t.tm_wday = 0;
    t.tm_yday = 0;
    t.tm_isdst = 0;

    time_t localTime = mktime(&t);
    time_t utcTime = localTime + timezone;
    return utcTime;
}


