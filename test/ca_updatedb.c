/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef OPENSSL_SYS_UNIX
# include <unistd.h>
#endif
#include "../apps/include/ca.h"
#include "../apps/include/ca_logic.h"
#include "../apps/include/apps.h"

/* tweaks needed for Windows */
#ifdef _WIN32
# define access _access
# define timezone _timezone
#endif

char *default_config_file = NULL;

ASN1_TIME *string_to_ASN1_TIME(char *string)
{
    size_t len;
    ASN1_TIME *tmps = NULL;
    char *p;

    len = strlen(string)+1;
    tmps = ASN1_STRING_new();
    if (tmps == NULL)
        return NULL;

    if (!ASN1_STRING_set(tmps, NULL, len))
    {
        ASN1_STRING_free(tmps);
        return NULL;
    }

    if (strlen(string) == 13)
    	tmps->type = V_ASN1_UTCTIME;
    else
        tmps->type = V_ASN1_GENERALIZEDTIME;
    p = (char*)tmps->data;

    tmps->length = BIO_snprintf(p, len, "%s", string);

    return tmps;
}

int main(int argc, char *argv[])
{
    CA_DB *db = NULL;
    BIO *channel;
    ASN1_TIME *testdate_asn1 = NULL;
    struct tm *testdate_tm = NULL;
    time_t *testdatelocal = NULL;
    time_t *testdateutc = NULL;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s indexfile testdate\n", argv[0]);
        fprintf(stderr, "       testdate format: YYYY-MM-DDThh:mm\n");
	exit(EXIT_FAILURE);
    }

    if (access(argv[1], F_OK) != 0) {
        fprintf(stderr, "Error: dbfile '%s' is not readable\n", argv[1]);
	exit(EXIT_FAILURE);
    }

    testdate_asn1 = string_to_ASN1_TIME(argv[2]);
    if (testdate_asn1 == NULL)
        exit(EXIT_FAILURE);

    testdate_tm = app_malloc(sizeof(struct tm), "testdate_tm");

    if (!(ASN1_TIME_to_tm(testdate_asn1, testdate_tm))) {
        free(testdate_tm);
        ASN1_STRING_free(testdate_asn1);
        fprintf(stderr, "Error: testdate '%s' is invalid\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    testdatelocal = app_malloc(sizeof(time_t), "testdatelocal");
    *testdatelocal = mktime(testdate_tm);
    free(testdate_tm);

    testdateutc = app_malloc(sizeof(time_t), "testdateutc");
    *testdateutc = *testdatelocal - timezone;
    free(testdatelocal);

    channel = BIO_push(BIO_new(BIO_f_prefix()), dup_bio_err(FORMAT_TEXT));
    bio_err = dup_bio_err(FORMAT_TEXT);

    default_config_file = CONF_get1_default_config_file();
    if (default_config_file == NULL) {
        ASN1_STRING_free(testdate_asn1);
        BIO_free_all(bio_err);
        BIO_free_all(channel);
        free(testdateutc);
        fprintf(stderr, "Error: could not get default config file\n");
        exit(EXIT_FAILURE);
    }

    db = load_index(argv[1], NULL);

    do_updatedb(db, testdateutc);

    ASN1_STRING_free(testdate_asn1);
    free(default_config_file);
    free_index(db);
    free(testdateutc);
    BIO_free_all(bio_err);
    BIO_free_all(channel);
    exit(EXIT_SUCCESS);
}
