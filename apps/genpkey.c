/*
 * Copyright 2006-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static int verbose = 1;

static int init_keygen_file(EVP_PKEY_CTX **pctx, const char *file, ENGINE *e,
                            OSSL_LIB_CTX *libctx, const char *propq);
typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_ENGINE, OPT_OUTFORM, OPT_OUT, OPT_PASS, OPT_PARAMFILE,
    OPT_ALGORITHM, OPT_PKEYOPT, OPT_GENPARAM, OPT_TEXT, OPT_CIPHER,
    OPT_VERBOSE, OPT_QUIET, OPT_CONFIG,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS genpkey_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"paramfile", OPT_PARAMFILE, '<', "Parameters file"},
    {"algorithm", OPT_ALGORITHM, 's', "The public key algorithm"},
    {"verbose", OPT_VERBOSE, '-', "Output status while generating keys"},
    {"quiet", OPT_QUIET, '-', "Do not output status while generating keys"},
    {"pkeyopt", OPT_PKEYOPT, 's',
     "Set the public key algorithm option as opt:value"},
     OPT_CONFIG_OPTION,

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "output format (DER or PEM)"},
    {"pass", OPT_PASS, 's', "Output file pass phrase source"},
    {"genparam", OPT_GENPARAM, '-', "Generate parameters, not key"},
    {"text", OPT_TEXT, '-', "Print the in text"},
    {"", OPT_CIPHER, '-', "Cipher to use to encrypt the key"},

    OPT_PROV_OPTIONS,

    /* This is deliberately last. */
    {OPT_HELP_STR, 1, 1,
     "Order of options may be important!  See the documentation.\n"},
    {NULL}
};

static const char *param_datatype_2name(unsigned int type, int *ishex)
{
    *ishex = 0;

    switch (type) {
    case OSSL_PARAM_INTEGER: return "int";
    case OSSL_PARAM_UNSIGNED_INTEGER: return "uint";
    case OSSL_PARAM_REAL: return "float";
    case OSSL_PARAM_OCTET_STRING: *ishex = 1; return "string";
    case OSSL_PARAM_UTF8_STRING: return "string";
    default:
        return NULL;
    }
}

static void show_gen_pkeyopt(const char *algname, OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY_CTX *ctx = NULL;
    const OSSL_PARAM *params;
    int i, ishex = 0;

    if (algname == NULL)
        return;
    ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, propq);
    if (ctx == NULL)
        return;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto cleanup;
    params = EVP_PKEY_CTX_settable_params(ctx);
    if (params == NULL)
        goto cleanup;

    BIO_printf(bio_err, "\nThe possible -pkeyopt arguments are:\n");
    for (i = 0; params[i].key != NULL; ++i) {
        const char *name = param_datatype_2name(params[i].data_type, &ishex);

        if (name != NULL)
            BIO_printf(bio_err, "    %s%s:%s\n", ishex ? "hex" : "", params[i].key, name);
    }
cleanup:
    EVP_PKEY_CTX_free(ctx);
}

int genpkey_main(int argc, char **argv)
{
    CONF *conf = NULL;
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *outfile = NULL, *passarg = NULL, *pass = NULL, *prog, *p;
    const char *ciphername = NULL, *paramfile = NULL, *algname = NULL;
    EVP_CIPHER *cipher = NULL;
    OPTION_CHOICE o;
    int outformat = FORMAT_PEM, text = 0, ret = 1, rv, do_param = 0;
    int private = 0, i;
    OSSL_LIB_CTX *libctx = app_get0_libctx();
    STACK_OF(OPENSSL_STRING) *keyopt = NULL;

    opt_set_unknown_name("cipher");
    prog = opt_init(argc, argv, genpkey_options);
    keyopt = sk_OPENSSL_STRING_new_null();
    if (keyopt == NULL)
        goto end;
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(genpkey_options);
            show_gen_pkeyopt(algname, libctx, app_get0_propq());
            goto end;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PARAMFILE:
            if (do_param == 1)
                goto opthelp;
            paramfile = opt_arg();
            break;
        case OPT_ALGORITHM:
            algname = opt_arg();
            break;
        case OPT_PKEYOPT:
            if (!sk_OPENSSL_STRING_push(keyopt, opt_arg()))
                goto end;
            break;
        case OPT_QUIET:
            verbose = 0;
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_GENPARAM:
            do_param = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_CIPHER:
            ciphername = opt_unknown();
            break;
        case OPT_CONFIG:
            conf = app_load_config_modules(opt_arg());
            if (conf == NULL)
                goto end;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }

    /* No extra arguments. */
    if (!opt_check_rest_arg(NULL))
        goto opthelp;

    /* Fetch cipher, etc. */
    if (paramfile != NULL) {
        if (!init_keygen_file(&ctx, paramfile, e, libctx, app_get0_propq()))
            goto end;
    }
    if (algname != NULL) {
        if (!init_gen_str(&ctx, algname, e, do_param, libctx, app_get0_propq()))
            goto end;
    }
    if (ctx == NULL)
        goto opthelp;

    for (i = 0; i < sk_OPENSSL_STRING_num(keyopt); i++) {
        p = sk_OPENSSL_STRING_value(keyopt, i);
        if (pkey_ctrl_string(ctx, p) <= 0) {
            BIO_printf(bio_err, "%s: Error setting %s parameter:\n", prog, p);
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (!opt_cipher(ciphername, &cipher))
        goto opthelp;
    if (ciphername != NULL && do_param == 1) {
        BIO_printf(bio_err, "Cannot use cipher with -genparam option\n");
        goto opthelp;
    }

    private = do_param ? 0 : 1;

    if (!app_passwd(passarg, NULL, &pass, NULL)) {
        BIO_puts(bio_err, "Error getting password\n");
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (verbose)
        EVP_PKEY_CTX_set_cb(ctx, progress_cb);
    EVP_PKEY_CTX_set_app_data(ctx, bio_err);

    pkey = do_param ? app_paramgen(ctx, algname)
                    : app_keygen(ctx, algname, 0, 0 /* not verbose */);

    if (do_param) {
        rv = PEM_write_bio_Parameters(out, pkey);
    } else if (outformat == FORMAT_PEM) {
        assert(private);
        rv = PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass);
    } else if (outformat == FORMAT_ASN1) {
        assert(private);
        rv = i2d_PrivateKey_bio(out, pkey);
    } else {
        BIO_printf(bio_err, "Bad format specified for key\n");
        goto end;
    }

    ret = 0;

    if (rv <= 0) {
        BIO_puts(bio_err, "Error writing key\n");
        ret = 1;
    }

    if (text) {
        if (do_param)
            rv = EVP_PKEY_print_params(out, pkey, 0, NULL);
        else
            rv = EVP_PKEY_print_private(out, pkey, 0, NULL);

        if (rv <= 0) {
            BIO_puts(bio_err, "Error printing key\n");
            ret = 1;
        }
    }

 end:
    sk_OPENSSL_STRING_free(keyopt);
    if (ret != 0)
        ERR_print_errors(bio_err);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    BIO_free_all(out);
    BIO_free(in);
    release_engine(e);
    OPENSSL_free(pass);
    NCONF_free(conf);
    return ret;
}

static int init_keygen_file(EVP_PKEY_CTX **pctx, const char *file, ENGINE *e,
                            OSSL_LIB_CTX *libctx, const char *propq)
{
    BIO *pbio;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    if (*pctx) {
        BIO_puts(bio_err, "Parameters already set!\n");
        return 0;
    }

    pbio = BIO_new_file(file, "r");
    if (pbio == NULL) {
        BIO_printf(bio_err, "Can't open parameter file %s\n", file);
        return 0;
    }

    pkey = PEM_read_bio_Parameters_ex(pbio, NULL, libctx, propq);
    BIO_free(pbio);

    if (pkey == NULL) {
        BIO_printf(bio_err, "Error reading parameter file %s\n", file);
        return 0;
    }

    if (e != NULL)
        ctx = EVP_PKEY_CTX_new(pkey, e);
    else
        ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq);
    if (ctx == NULL)
        goto err;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    EVP_PKEY_free(pkey);
    *pctx = ctx;
    return 1;

 err:
    BIO_puts(bio_err, "Error initializing context\n");
    ERR_print_errors(bio_err);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;

}

int init_gen_str(EVP_PKEY_CTX **pctx,
                 const char *algname, ENGINE *e, int do_param,
                 OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY_CTX *ctx = NULL;
    int pkey_id;

    if (*pctx) {
        BIO_puts(bio_err, "Algorithm already set!\n");
        return 0;
    }

    pkey_id = get_legacy_pkey_id(libctx, algname, e);
    if (pkey_id != NID_undef)
        ctx = EVP_PKEY_CTX_new_id(pkey_id, e);
    else
        ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, propq);

    if (ctx == NULL)
        goto err;
    if (do_param) {
        if (EVP_PKEY_paramgen_init(ctx) <= 0)
            goto err;
    } else {
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto err;
    }

    *pctx = ctx;
    return 1;

 err:
    BIO_printf(bio_err, "Error initializing %s context\n", algname);
    ERR_print_errors(bio_err);
    EVP_PKEY_CTX_free(ctx);
    return 0;

}

