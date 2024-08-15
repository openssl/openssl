/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hpke.h>

#include <openssl/objects.h>
#include <openssl/x509.h>

#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_KEYGEN_MODE    0 /* default: generate a key pair/ECHConfig */
# define OSSL_ECH_SELPRINT_MODE  1 /* we can print/down-select ECHConfigList */

# define PEM_SELECT_ALL    -1 /* to indicate we're not downselecting another */

typedef enum OPTION_choice {
    /* standard openssl options */
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_VERBOSE,
    OPT_PEMOUT,
    /* ECHConfig specifics */
    OPT_PUBLICNAME, OPT_ECHVERSION,
    OPT_MAXNAMELENGTH, OPT_HPKESUITE
} OPTION_CHOICE;

const OPTIONS ech_options[] = {
    OPT_SECTION("General options"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-', "Provide additional output"},
    OPT_SECTION("Key generation"),
    {"pemout", OPT_PEMOUT, '>',
     "Private key and ECHConfig [default echconfig.pem]"},
    {"public_name", OPT_PUBLICNAME, 's', "public_name value"},
    {"max_name_len", OPT_MAXNAMELENGTH, 'n',
     "Maximum host name length value [default: 0]"},
    {"suite", OPT_HPKESUITE, 's', "HPKE ciphersuite: e.g. \"0x20,1,3\""},
    {"ech_version", OPT_ECHVERSION, 'n',
     "ECHConfig version [default 0xff0d (13)]"},
    {NULL}
};

/**
 * @brief map version string like 0xff01 or 65291 to uint16_t
 * @param arg is the version string, from command line
 * @return is the uint16_t value (with zero for error cases)
 */
static uint16_t verstr2us(char *arg)
{
    long lv = strtol(arg, NULL, 0);
    uint16_t rv = 0;

    if (lv < 0xffff && lv > 0) {
        rv = (uint16_t)lv;
    }
    return rv;
}

int ech_main(int argc, char **argv)
{
    char *prog = NULL;
    OPTION_CHOICE o;
    int verbose = 0;
    char *pemfile = NULL;
    char *public_name = NULL;
    char *suitestr = NULL;
    uint16_t ech_version = OSSL_ECH_CURRENT_VERSION;
    uint8_t max_name_length = 0;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    int mode = OSSL_ECH_KEYGEN_MODE; /* key generation */

    prog = opt_init(argc, argv, ech_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ech_options);
            goto end;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_PEMOUT:
            pemfile = opt_arg();
            break;
        case OPT_PUBLICNAME:
            public_name = opt_arg();
            break;
        case OPT_ECHVERSION:
            ech_version = verstr2us(opt_arg());
            break;
        case OPT_MAXNAMELENGTH:
            {
                long tmp = strtol(opt_arg(), NULL, 10);

                if (tmp < 0 || tmp > OSSL_ECH_MAX_MAXNAMELEN) {
                    BIO_printf(bio_err,
                               "max name length out of range [0,%d] (%ld)\n",
                               OSSL_ECH_MAX_MAXNAMELEN, tmp);
                    goto opthelp;
                } else {
                    max_name_length = (uint8_t)tmp;
                }
            }
            break;
        case OPT_HPKESUITE:
            suitestr = opt_arg();
            break;
        }
    }

    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_printf(bio_err, "%s: Unknown parameter %s\n", prog, argv[0]);
        goto opthelp;
    }

    /*
     * Check ECH-specific inputs
     */
    switch (ech_version) {
    case OSSL_ECH_RFCXXXX_VERSION: /* fall through */
    case 13:
        ech_version = OSSL_ECH_RFCXXXX_VERSION;
        break;
    default:
        BIO_printf(bio_err, "Un-supported version (0x%04x)\n", ech_version);
        goto end;
    }

    if (max_name_length > TLSEXT_MAXLEN_host_name) {
        BIO_printf(bio_err, "Weird max name length (0x%04x) - biggest is "
                   "(0x%04x) - exiting\n", max_name_length,
                   TLSEXT_MAXLEN_host_name);
        ERR_print_errors(bio_err);
        goto end;
    }

    if (suitestr != NULL) {
        if (OSSL_HPKE_str2suite(suitestr, &hpke_suite) != 1) {
            BIO_printf(bio_err, "Bad OSSL_HPKE_SUITE (%s)\n", suitestr);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    /* Set default if needed */
    if (pemfile == NULL)
        pemfile = "echconfig.pem";

    if (mode == OSSL_ECH_KEYGEN_MODE) {
        OSSL_ECHSTORE *es = NULL;
        BIO *ecf = NULL;

        if (verbose)
            BIO_printf(bio_err, "Calling OSSL_ECHSTORE_new_config\n");
        if ((ecf = BIO_new_file(pemfile, "w")) == NULL 
            || (es = OSSL_ECHSTORE_new(NULL, NULL)) == NULL
            || OSSL_ECHSTORE_new_config(es, ech_version, max_name_length,
                                        public_name, hpke_suite) != 1
            || OSSL_ECHSTORE_write_pem(es, 0, ecf) != 1) {
            BIO_printf(bio_err, "OSSL_ECHSTORE_new_config error\n");
            goto end;
        }
        if (verbose)
            BIO_printf(bio_err, "OSSL_ECHSTORE_new_config success\n");
        OSSL_ECHSTORE_free(es);
        BIO_free_all(ecf);
        return 1;
    }

opthelp:
    BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
    goto end;

end:
    return 0;
}

#endif
