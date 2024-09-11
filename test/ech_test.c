/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/hpke.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

#ifndef OPENSSL_NO_ECH

static int verbose = 0;

/* general test vector values */

/* standard x25519 ech key pair with public key example.com */
static const char pem_kp1[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEILDIeo9Eqc4K9/uQ0PNAyMaP60qrxiSHT2tNZL3ksIZS\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/* standard x25519 ECHConfigList with public key example.com */
static const char pem_pk1[] =
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/*
 * This ECHConfigList has 4 entries with different versions,
 * from drafts: 13,10,13,9 - since our runtime no longer supports
 * version 9 or 10, we should see 2 configs loaded.
 */
static const char pem_4_to_2[] =
    "-----BEGIN ECHCONFIG-----\n"
    "APv+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS4K\n"
    "hu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACB3xsNUtSgi\n"
    "piYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAEAAQALZXhhbXBsZS5jb20AAP4J\n"
    "ADsAC2V4YW1wbGUuY29tACCjJCv5w/yaHjbOc6nVuM/GksIGLgDR+222vww9dEk8\n"
    "FwAgAAQAAQABAAAAAA==\n"
    "-----END ECHCONFIG-----\n";

/* single-line base64(ECHConfigList) form of pem_pk1 */
static const char ecl_pk1[] =
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA"
    "AQALZXhhbXBsZS5jb20AAA==";

/* single-line base64(ECHConfigList) form of pem_6_to3 */
static const char ecl_6_to_3[] =
    "AXn+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS"
    "4Khu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+CQA7AAtleGFtcGxlL"
    "mNvbQAgoyQr+cP8mh42znOp1bjPxpLCBi4A0ftttr8MPXRJPBcAIAAEAAEAAQAA"
    "AAD+DQA6QwAgACB3xsNUtSgipiYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADwDACAAIH0BoAdiJCX88gv8nYpGVX5BpGBa9y"
    "T0Pac3Kwx6i8URAAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACDcZIAx7"
    "OcOiQuk90VV7/DO4lFQr5I3Zw9tVbK8MGw1dgAEAAEAAQALZXhhbXBsZS5jb20A"
    "AA==";

/* base64(ECHConfigList) with corrupt ciphersuite length and public_name */
static const char ecl_bad_cs[] =
    "AD7+DQA6uAAgACAogff+HZbirYdQCfXI01GBPP8AEKYyK/D/0DoeXD84fgAQAAE"
    "AAQgLZXhhbUNwbGUuYwYAAAAAQwA=";

/* struct for ingest test vector and results */
typedef struct INGEST_TV_T {
    const char *tv; /* string form test vector */
    int pemenc; /* whether PEM encoded (1) or not (0) */
    int read; /* result expected from read function on tv */
    int keysb4; /* the number of private keys expected before downselect */
    int entsb4; /* the number of public keys b4 */
    int index; /* the index to use for downselect */
    int expected; /* the result expected from a downselect */
    int keysaftr; /* the number of keys expected after downselect */
    int entsaftr; /* the number of public keys after */
} ingest_tv_t;

static ingest_tv_t ingest_tvs[] = {
    /* PEM test vectors */
    /* tv,      pem, read, k-b4, e-b4,   ind,              exp, kaftr, eaftr */
    { pem_kp1,    1,   1,    1,    1,    OSSL_ECHSTORE_LAST, 1,   1,      1 },
    { pem_pk1,    1,   1,    0,    1,    0,                  1,   0,      1 },
    { pem_pk1,    1,   1,    0,    1,    2,                  0,   0,      1 },
    /* downselect from the 3, at each position */
    { pem_4_to_2, 1,   1,    0,    2,    0,                  1,   0,      1 },
    { pem_4_to_2, 1,   1,    0,    2,    1,                  1,   0,      1 },
    /* in the next, downselect fails, so we still have 2 entries */
    { pem_4_to_2, 1,   1,    0,    2,    3,                  0,   0,      2 },

    /* non-PEM test vectors */
    /* tv,      pem, read, k-b4, e-b4,   ind,              exp, kaftr, eaftr */
    { ecl_pk1,    0,   1,    0,    1,    OSSL_ECHSTORE_LAST, 1,   0,      1 },
    { ecl_6_to_3, 0,   1,    0,    3,    2,                  1,   0,      1 },
    { ecl_bad_cs, 0,   0,    0,    0,    0,                  0,   0,      0 },
};

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH tests\n" },
        { NULL }
    };
    return test_options;
}

/*
 * For the relevant test vector in our array above:
 * - try decode
 * - if not expected to decode, we're done
 * - check we got the right number of keys/ECHConfig values
 * - do some calls with getting info, downselecting etc. and
 *   check results as expected
 * - do a write_pem call on the results
 * - flush keys 'till now and check they're all gone
 */
static int ech_ingest_test(int run)
{
    OSSL_ECHSTORE *es = NULL;
    OSSL_ECH_INFO *ei = NULL;
    BIO *in = NULL, *out = NULL;
    int rv = 0, keysb4, keysaftr, entsb4, entsaftr;
    ingest_tv_t *tv = &ingest_tvs[run];
    time_t now = 0;

    if ((in = BIO_new(BIO_s_mem())) == NULL
        || BIO_write(in, tv->tv, strlen(tv->tv)) <= 0
        || (out = BIO_new(BIO_s_mem())) == NULL
        || (es = OSSL_ECHSTORE_new(NULL, NULL)) == NULL)
        goto end;
    if (verbose)
        TEST_info("Iteration: %d\n%s", run + 1, tv->tv);
    /* just in case of bad edits to table */
    if (tv->pemenc != 1 && tv->pemenc != 0) {
        TEST_info("Bad test vector entry");
        goto end;
    }
    if (tv->pemenc == 1
        && !TEST_int_eq(OSSL_ECHSTORE_read_pem(es, in, OSSL_ECH_NO_RETRY),
                        tv->read)) {
        TEST_info("OSSL_ECSTORE_read_pem unexpected fail");
        goto end;
    }
    if (tv->pemenc != 1
        && !TEST_int_eq(OSSL_ECHSTORE_read_echconfiglist(es, in),
                        tv->read)) {
        TEST_info("OSSL_ECSTORE_read_echconfiglist unexpected fail");
        goto end;
    }
    /* if we provided a deliberately bad tv then we're done */
    if (tv->read != 1) {
        rv = 1;
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysb4), 1)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(keysb4, tv->keysb4)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected number of keys (b4)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_get1_info(es, &ei, &entsb4), 1)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected fail");
        goto end;
    }
    OSSL_ECH_INFO_free(ei, entsb4);
    ei = NULL;
    if (!TEST_int_eq(entsb4, tv->entsb4)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected number of entries (b4)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_downselect(es, tv->index), tv->expected)) {
        TEST_info("OSSL_ECSTORE_downselect unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysaftr), 1)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(keysaftr, tv->keysaftr)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected number of keys (aftr)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_get1_info(es, &ei, &entsaftr), 1)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected fail");
        goto end;
    }
    OSSL_ECH_INFO_free(ei, entsaftr);
    ei = NULL;
    if (!TEST_int_eq(entsaftr, tv->entsaftr)) {
        TEST_info("OSSL_ECSTORE_get1_info unexpected number of entries (aftr)");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_write_pem(es, OSSL_ECHSTORE_ALL, out), 1)) {
        TEST_info("OSSL_ECSTORE_write_pem unexpected fail");
        goto end;
    }
    now = time(0);
    if (!TEST_int_eq(OSSL_ECHSTORE_flush_keys(es, now), 1)) {
        TEST_info("OSSL_ECSTORE_flush_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysaftr), 1)) {
        TEST_info("OSSL_ECSTORE_num_keys unexpected fail");
        goto end;
    }
    if (!TEST_int_eq(keysaftr, 0)) {
        TEST_info("OSSL_ECSTORE_flush_keys unexpected non-zero");
        goto end;
    }
    rv = 1;
end:
    OSSL_ECHSTORE_free(es);
    BIO_free_all(in);
    BIO_free_all(out);
    return rv;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    ADD_ALL_TESTS(ech_ingest_test, OSSL_NELEM(ingest_tvs));
    /* TODO(ECH): we'll add more test code once other TODO's settle */
    return 1;
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    ;
#endif
}
