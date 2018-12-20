/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/evp.h>
#include <openssl/provider.h>

#define BUFSIZE 4096
#define DEFAULT_MAC_NAME "HMAC"

/* Configuration file values */
#define FIPS_SECTION "[fips_check_section]"
#define VERSION_KEY  "version"
#define VERSION_VAL  "1"
#define MODULE_MAC_KEY "module.mac"
#define INSTALL_MAC_KEY "install.mac"
#define INSTALL_STATUS_KEY "install.status"
#define INSTALL_STATUS_VAL "INSTALL_SELF_TEST_KATS_RUN"

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_IN, OPT_OUT, OPT_MACOPT, OPT_VERIFY,
    OPT_MAC
} OPTION_CHOICE;

const OPTIONS fipsinstall_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    { OPT_MORE_STR, 0, 0, "e.g: openssl fipsinstall -in libfips.so -out "
      "fips.conf -mac HMAC -macopt digest:SHA256 -macopt hexkey:00"},
    {"in", OPT_IN, 's', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"mac", OPT_MAC, 's', "MAC name"},
    {"macopt", OPT_MACOPT, 's', "MAC algorithm control parameters in n:v form. "
                                "See 'Supported Controls' in the EVP_MAC_ docs"},
    {"verify", OPT_VERIFY, '-', "Verify the installed status is correct"},

    {NULL}
};

static int mac_ctrl_string(EVP_MAC_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp != NULL) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_MAC_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}

static int do_mac(EVP_MAC_CTX *ctx, unsigned char *tmp, BIO *in,
                  unsigned char *out, size_t *out_len)
{
    int ret = 0;
    int i;

    if (!EVP_MAC_init(ctx))
        goto err;
    if (EVP_MAC_size(ctx) > *out_len)
        goto end;
    for (;;) {
        i = BIO_read(in, (char *)tmp, BUFSIZE);
        if (i < 0)
            goto err;
        if (i == 0)
            break;
        if (!EVP_MAC_update(ctx, tmp, i))
            goto err;
    }
end:
    if (!EVP_MAC_final(ctx, out, out_len))
        goto err;
    ret = 1;
err:
    return ret;
}

static int print_mac(BIO *bio, const char *label, unsigned char *mac,
                     size_t len)
{
    size_t i;

    if (!BIO_printf(bio, "%s = ", label))
        return 0;
    for (i = 0; i < len; ++i) {
        if (!BIO_printf(bio, "%02X", mac[i]))
            return 0;
    }
    return BIO_printf(bio, "\n");
}

static int load_fips_prov_and_run_self_test(const char *module_filename)
{
    int ret = 0;
    OSSL_PROVIDER *prov = NULL;

    prov = OSSL_PROVIDER_load(NULL, module_filename);
    if (prov == NULL) {
        BIO_printf(bio_err, "Failed to load fips module\n");
        goto end;
    }
    /*
     * TODO - make sure self tests arte activated here
     * It must return NULL if the self tests fails.
     */
    ret = 1;
end:
    OSSL_PROVIDER_unload(prov);
    return ret;
}

/*
 * Outputs a fips related config file that contains entries for the fips
 * module checksum and the installation indicator checksum.
 *
 * Returns 1 if the config file is written otherwise it returns 0 on error.
 */
static int write_config(const char *outfile,
                        unsigned char *module_mac, size_t module_mac_len,
                        unsigned char *install_mac, size_t install_mac_len)
{
    BIO *out = NULL;
    int ret = 0;

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL) {
        BIO_printf(bio_err, "Failed to open file\n");
        goto end;
    }

    if (!(BIO_printf(out, "%s\n",FIPS_SECTION) > 0
          && BIO_printf(out, "%s = %s\n", VERSION_KEY, VERSION_VAL) > 0
          && print_mac(out, MODULE_MAC_KEY, module_mac, module_mac_len)
          && print_mac(out, INSTALL_MAC_KEY, install_mac, install_mac_len)
          && BIO_printf(out, "%s = %s\n", INSTALL_STATUS_KEY,
                        INSTALL_STATUS_VAL) > 0)) {
        BIO_printf(bio_err, "Failed writing to %s\n", outfile);
        goto end;
    }
    ret = 1;
end:
    BIO_free(out);
    return ret;
}

/*
 * Returns 1 if the config file entries match the passed in module_mac and
 * install_mac values, otherwise it returns 0.
 */
static int verify_config(const char *infile,
                         unsigned char *module_mac, size_t module_mac_len,
                         unsigned char *install_mac, size_t install_mac_len)
{
    int ret = 0;
    char *s = NULL;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    long len;
    CONF *conf = NULL;

    /* read in the existing values and check they match the saved values */
    conf = app_load_config(infile);
    if (conf == NULL)
        goto end;

    s = NCONF_get_string(conf, NULL, VERSION_KEY);
    if (s == NULL || strcmp(s, VERSION_VAL) != 0) {
        BIO_printf(bio_err, "version not found\n");
        goto end;
    }
    s = NCONF_get_string(conf, NULL, INSTALL_STATUS_KEY);
    if (s == NULL || strcmp(s, INSTALL_STATUS_VAL) != 0) {
        BIO_printf(bio_err, "install status not found\n");
        goto end;
    }
    s = NCONF_get_string(conf, NULL, MODULE_MAC_KEY);
    if (s == NULL) {
        BIO_printf(bio_err, "Module integrity MAC not found\n");
        goto end;
    }
    buf1 = OPENSSL_hexstr2buf(s, &len);
    if (buf1 == NULL
            || (size_t)len != module_mac_len
            || memcmp(module_mac, buf1, module_mac_len) != 0) {
        BIO_printf(bio_err, "Module integrity mismatch\n");
        goto end;
    }
    s = NCONF_get_string(conf, NULL, INSTALL_MAC_KEY);
    if (s == NULL) {
        BIO_printf(bio_err, "Install indicator MAC not found\n");
        goto end;
    }
    buf2 = OPENSSL_hexstr2buf(s, &len);
    if (buf2 == NULL
            || (size_t)len != install_mac_len
            || memcmp(install_mac, buf2, install_mac_len) != 0) {
        BIO_printf(bio_err, "Install indicator status mismatch\n");
        goto end;
    }
    ret = 1;
end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    NCONF_free(conf);
    return ret;
}

int fipsinstall_main(int argc, char **argv)
{
    int ret = 0, verify = 0, i;
    BIO *in = NULL, *mem_bio = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    static const char *mac_name = DEFAULT_MAC_NAME;
    EVP_MAC_CTX *ctx = NULL, *ctx2 = NULL;
    STACK_OF(OPENSSL_STRING) *opts = NULL;
    OPTION_CHOICE o;
    unsigned char *read_buffer = NULL;
    unsigned char module_mac[EVP_MAX_MD_SIZE];
    size_t module_mac_len = EVP_MAX_MD_SIZE;
    unsigned char install_mac[EVP_MAX_MD_SIZE];
    size_t install_mac_len = EVP_MAX_MD_SIZE;
    const EVP_MAC *mac = NULL;

    prog = opt_init(argc, argv, fipsinstall_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(fipsinstall_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_MACOPT:
            if (opts == NULL)
                opts = sk_OPENSSL_STRING_new_null();
            if (opts == NULL || !sk_OPENSSL_STRING_push(opts, opt_arg()))
                goto opthelp;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        case OPT_MAC:
            mac_name = opt_arg();
            break;
        }
    }
    argc = opt_num_rest();
    if (infile == NULL || outfile == NULL || opts == NULL || argc != 0)
        goto opthelp;

    in = bio_open_default(infile, 'r', FORMAT_BINARY);
    if (in == NULL) {
        BIO_printf(bio_err, "Failed to open file\n");
        goto end;
    }

    read_buffer = app_malloc(BUFSIZE, "I/O buffer");
    if (read_buffer == NULL)
        goto end;

    mac = EVP_get_macbyname(mac_name);
    if (mac == NULL) {
        BIO_printf(bio_err, "Unable to get MAC of type %s\n", mac_name);
        goto end;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for module check\n");
        goto end;
    }

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);

        if (mac_ctrl_string(ctx, opt) <= 0) {
            BIO_printf(bio_err, "mac_opt for %s failed\n", opt);
            goto end;
        }
    }

    ctx2 = EVP_MAC_CTX_new(mac);
    if (ctx2 == NULL || !EVP_MAC_CTX_copy(ctx2, ctx)) {
        BIO_printf(bio_err, "Unable to create MAC CTX for install indicator\n");
        goto end;
    }

    if (!do_mac(ctx, read_buffer, in, module_mac, &module_mac_len))
        goto end;

    mem_bio = BIO_new_mem_buf((const void *)INSTALL_STATUS_VAL,
                              strlen(INSTALL_STATUS_VAL));
    if (mem_bio == NULL) {
        BIO_printf(bio_err, "Unable to create memory BIO\n");
        goto end;
    }
    if (!do_mac(ctx2, read_buffer, mem_bio, install_mac, &install_mac_len))
        goto end;

    if (verify == 0) {
        if (!load_fips_prov_and_run_self_test(infile))
            goto end;
        if (!write_config(outfile, module_mac, module_mac_len, install_mac,
                          install_mac_len))
            goto end;

    } else {
        if (!verify_config(outfile, module_mac, module_mac_len, install_mac,
                           install_mac_len))
            goto end;
    }

    ret = 1;
end:
    if (ret == 0) {
        BIO_printf(bio_err, "%s FAILED\n", verify ? "VERIFY" : "INSTALL");
        ERR_print_errors(bio_err);
    }

    BIO_free(mem_bio);
    BIO_free(in);
    sk_OPENSSL_STRING_free(opts);
    EVP_MAC_CTX_free(ctx2);
    EVP_MAC_CTX_free(ctx);
    OPENSSL_free(read_buffer);
    return ret;
}
