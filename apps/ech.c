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

/* size for some local crypto vars */
# define OSSL_ECH_CRYPTO_VAR_SIZE 1024

# define OSSL_ECH_KEYGEN_MODE    0 /* default: generate a key pair/ECHConfig */
# define OSSL_ECH_SELPRINT_MODE  1 /* we can print/down-select ECHConfigList */

# define PEM_SELECT_ALL    -1 /* to indicate we're not downselecting another */

typedef enum OPTION_choice {
    /* standard openssl options */
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_VERBOSE,
    OPT_PUBOUT, OPT_PRIVOUT, OPT_PEMOUT,
    /* ECHConfig specifics */
    OPT_PUBLICNAME, OPT_ECHVERSION,
    OPT_MAXNAMELENGTH, OPT_HPKESUITE,
    OPT_EXTFILE,
    /* key print/select */
    OPT_PEMIN, OPT_SELECT
} OPTION_CHOICE;

const OPTIONS ech_options[] = {
    OPT_SECTION("General options"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-',
     "Provide additional output (though not much:-)"},
    OPT_SECTION("Key generation"),
    {"pemout", OPT_PEMOUT, '>', "Private key and ECHConfig [echconfig.pem]"},
    {"pubout", OPT_PUBOUT, '>', "Public key output file"},
    {"privout", OPT_PRIVOUT, '>', "Private key output file"},
    {"public_name", OPT_PUBLICNAME, 's', "public_name value"},
    {"mlen", OPT_MAXNAMELENGTH, 'n', "Maximum name length value"},
    {"suite", OPT_HPKESUITE, 's', "HPKE ciphersuite: e.g. \"0x20,1,3\""},
    {"ech_version", OPT_ECHVERSION, 'n', "ECHConfig version [0xff0d (13)]"},
    {"extfile", OPT_EXTFILE, 's', "Input file with encoded ECH extensions\n"},
    OPT_SECTION("ECHConfig print/down-selection"),
    {"pemin", OPT_PEMIN, '>', "File with optional private key and ECHConfig"},
    {"select", OPT_SELECT, 'n', "Output only n-th ECHConfig from input file"},
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
    BIO *pemf = NULL;
    char *prog = NULL;
    OPTION_CHOICE o;
    int verbose = 0;
    int filedone = 0;
    char *echconfig_file = NULL;
    char *keyfile = NULL;
    char *pemfile = NULL;
    char *inpemfile = NULL;
    int pemselect = PEM_SELECT_ALL;
    char *public_name = NULL;
    char *suitestr = NULL;
    char *extfile = NULL;
    unsigned char extvals[OSSL_ECH_MAX_ECHCONFIGEXT_LEN];
    size_t extlen = OSSL_ECH_MAX_ECHCONFIGEXT_LEN;
    uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
    uint16_t max_name_length = 0;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    size_t echconfig_len = OSSL_ECH_MAX_ECHCONFIG_LEN;
    unsigned char echconfig[OSSL_ECH_MAX_ECHCONFIG_LEN];
    unsigned char priv[OSSL_ECH_CRYPTO_VAR_SIZE];
    size_t privlen = OSSL_ECH_CRYPTO_VAR_SIZE;
    int rv = 0;
    int mode = OSSL_ECH_KEYGEN_MODE; /* key generation */
    SSL_CTX *con = NULL;
    SSL *s = NULL;
    const SSL_METHOD *meth = TLS_client_method();
    char *pname = NULL;
    char *pheader = NULL;
    unsigned char *pdata = NULL;
    long plen;
    BIO *pem_in = NULL;

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
        case OPT_PUBOUT:
            echconfig_file = opt_arg();
            break;
        case OPT_PRIVOUT:
            keyfile = opt_arg();
            break;
        case OPT_PEMOUT:
            pemfile = opt_arg();
            break;
        case OPT_PEMIN:
            inpemfile = opt_arg();
            mode = OSSL_ECH_SELPRINT_MODE; /* print/select */
            break;
        case OPT_SELECT:
            pemselect = atoi(opt_arg());
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

                if (tmp < 0 || tmp > 65535) {
                    BIO_printf(bio_err,
                               "max name length out of range [0,65553] (%ld)\n",
                               tmp);
                    goto opthelp;
                } else {
                    max_name_length = (uint16_t)tmp;
                }
            }
            break;
        case OPT_HPKESUITE:
            suitestr = opt_arg();
            break;
        case OPT_EXTFILE:
            extfile = opt_arg();
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

    if (extfile != NULL) {
        int bio_read_rv = 0;
        BIO *eb = BIO_new_file(extfile, "rb");

        if (eb == NULL) {
            BIO_printf(bio_err, "Can't open ECH extensions file %s\n", extfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        bio_read_rv = BIO_read(eb, extvals, extlen);
        BIO_free(eb);
        if (bio_read_rv <= 0) {
            BIO_printf(bio_err, "Error reading ECH extensions file %s\n",
                       extfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        extlen = (size_t) bio_read_rv;
    } else {
        extlen = 0;
    }

    /* Set default if needed */
    if (pemfile == NULL) {
        pemfile = "echconfig.pem";
    }

    if (mode == OSSL_ECH_KEYGEN_MODE) {
        /* Generate a new key/ECHConfigList and spit that out */
        rv = OSSL_ech_make_echconfig(echconfig, &echconfig_len, priv, &privlen,
                                     ech_version, max_name_length, public_name,
                                     hpke_suite, extvals, extlen);
        if (rv != 1) {
            BIO_printf(bio_err, "ech_make_echconfig error: %d\n", rv);
            goto end;
        }
        /* Write stuff to files */
        if (echconfig_file != NULL) {
            BIO *ecf = BIO_new_file(echconfig_file, "w");

            if (ecf == NULL)
                goto end;
            BIO_write(ecf, echconfig, echconfig_len);
            BIO_printf(ecf, "\n");
            BIO_free_all(ecf);
            BIO_printf(bio_err, "Wrote ECHConfig to %s\n", echconfig_file);
        }
        if (keyfile != NULL) {
            BIO *kf = BIO_new_file(keyfile, "w");

            if (kf == NULL)
                goto end;
            BIO_write(kf, priv, privlen);
            BIO_free_all(kf);
            BIO_printf(bio_err, "Wrote ECH private key to %s\n", keyfile);
        }
        /* If we didn't write out either of the above, create a PEM file */
        if (keyfile == NULL && echconfig_file == NULL) {
            if ((pemf = BIO_new_file(pemfile, "w")) == NULL)
                goto end;
            BIO_write(pemf, priv, privlen);
            BIO_printf(pemf, "-----BEGIN ECHCONFIG-----\n");
            BIO_write(pemf, echconfig, echconfig_len);
            BIO_printf(pemf, "\n");
            BIO_printf(pemf, "-----END ECHCONFIG-----\n");
            BIO_free_all(pemf);
            BIO_printf(bio_err, "Wrote ECH key pair to %s\n", pemfile);
        } else {
            if (keyfile == NULL)
                BIO_printf(bio_err, "Didn't write private key anywhere!\n");
            if (echconfig_file == NULL)
                BIO_printf(bio_err, "Didn't write ECHConfig anywhere!\n");
        }
        return 1;
    }

    if (mode == OSSL_ECH_SELPRINT_MODE) {
        int nechs = 0;
        OSSL_ECH_INFO *ed = NULL;

        if (inpemfile == NULL) {
            BIO_printf(bio_err, "no input PEM file supplied - exiting\n");
            goto end;
        }
        con = SSL_CTX_new_ex(app_get0_libctx(), app_get0_propq(), meth);
        if (con == NULL)
            goto end;
        /* Input could be key pair */
        rv = SSL_CTX_ech_server_enable_file(con, inpemfile,
                                            SSL_ECH_USE_FOR_RETRY);
        if (rv != 1) {
            /* Or it could be just an encoded ECHConfigList */
            pem_in = BIO_new(BIO_s_file());
            if (pem_in == NULL
                || BIO_read_filename(pem_in, inpemfile) <= 0
                || PEM_read_bio(pem_in, &pname, &pheader, &pdata, &plen) <= 0
                || pname == NULL
                || strlen(pname) == 0
                || strncmp(PEM_STRING_ECHCONFIG, pname, strlen(pname)))
                goto end;
            OPENSSL_free(pname);
            pname = NULL;
            OPENSSL_free(pheader);
            pheader = NULL;
            s = SSL_new(con);
            if (s == NULL)
                goto end;
            /* Try decode that ECHConfigList */
            rv = SSL_ech_set1_echconfig(s, pdata, plen);
            if (rv != 1) {
                BIO_printf(bio_err, "Failed loading ECHConfigList from: %s\n",
                           inpemfile);
                goto end;
            }
            filedone = 1;
            BIO_free_all(pem_in);
            OPENSSL_free(pdata);
            BIO_printf(bio_err, "Loaded ECHConfigList from: %s\n", inpemfile);
        } else {
            filedone = 1;
            s = SSL_new(con);
            if (s == NULL)
                goto end;
            BIO_printf(bio_err, "Loaded Key+ECHConfigList from: %s\n",
                       inpemfile);
        }

        if (pemselect != PEM_SELECT_ALL) {
            rv = SSL_ech_reduce(s, pemselect);
            if (rv != 1) {
                BIO_printf(bio_err, "Error selecting config %d\n", pemselect);
                goto end;
            }
            BIO_printf(bio_err, "selecting config %d\n", pemselect);
        }

        rv = SSL_ech_get_info(s, &ed, &nechs);
        if (rv != 1 || ed == NULL)
            goto end;

        rv = OSSL_ECH_INFO_print(bio_err, ed, nechs);
        if (rv != 1)
            goto end;
        OSSL_ECH_INFO_free(ed, nechs);
        SSL_free(s);
        SSL_CTX_free(con);
        return 1;
    }

opthelp:
    BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
    goto end;

end:
    if (filedone == 0 && verbose == 1) {
        BIO_printf(bio_err, "failed to load %s\n", inpemfile);
    }
    SSL_free(s);
    SSL_CTX_free(con);
    BIO_free_all(pem_in);
    OPENSSL_free(pdata);
    return 0;
}

#endif
