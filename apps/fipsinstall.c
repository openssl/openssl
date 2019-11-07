/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/fips_names.h>
#include "apps.h"
#include "progs.h"

#define BUFSIZE 4096
#define DEFAULT_MAC_NAME "HMAC"
#define DEFAULT_FIPS_SECTION "fips_check_section"

/* Configuration file values */
#define VERSION_KEY  "version"
#define VERSION_VAL  "1"
#define INSTALL_STATUS_VAL "INSTALL_SELF_TEST_KATS_RUN"

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_IN, OPT_OUT, OPT_MODULE,
    OPT_PROV_NAME, OPT_SECTION_NAME, OPT_MAC_NAME, OPT_MACOPT, OPT_VERIFY
} OPTION_CHOICE;

const OPTIONS fipsinstall_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verify", OPT_VERIFY, '-', "Verification mode, i.e verify a config file "
     "instead of generating one"},
    {"module", OPT_MODULE, '<', "File name of the provider module"},
    {"provider_name", OPT_PROV_NAME, 's', "FIPS provider name"},
    {"section_name", OPT_SECTION_NAME, 's',
     "FIPS Provider config section name (optional)"},

    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input config file, used when verifying"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output config file, used when generating"},
    {"mac_name", OPT_MAC_NAME, 's', "MAC name"},
    {"macopt", OPT_MACOPT, 's', "MAC algorithm parameters in n:v form. "
                                "See 'PARAMETER NAMES' in the EVP_MAC_ docs"},
    {NULL}
};

static int do_mac(EVP_MAC_CTX *ctx, unsigned char *tmp, BIO *in,
                  unsigned char *out, size_t *out_len)
{
    int ret = 0;
    int i;
    size_t outsz = *out_len;

    if (!EVP_MAC_init(ctx))
        goto err;
    if (EVP_MAC_size(ctx) > outsz)
        goto end;
    while ((i = BIO_read(in, (char *)tmp, BUFSIZE)) != 0) {
        if (i < 0 || !EVP_MAC_update(ctx, tmp, i))
            goto err;
    }
end:
    if (!EVP_MAC_final(ctx, out, out_len, outsz))
        goto err;
    ret = 1;
err:
    return ret;
}

static int load_fips_prov_and_run_self_test(const char *prov_name)
{
    int ret = 0;
    OSSL_PROVIDER *prov = NULL;

    prov = OSSL_PROVIDER_load(NULL, prov_name);
    if (prov == NULL) {
        BIO_printf(bio_err, "Failed to load FIPS module\n");
        goto end;
    }
    ret = 1;
end:
    OSSL_PROVIDER_unload(prov);
    return ret;
}

static int print_mac(BIO *bio, const char *label, const unsigned char *mac,
                     size_t len)
{
    int ret;
    char *hexstr = NULL;

    hexstr = OPENSSL_buf2hexstr(mac, (long)len);
    if (hexstr == NULL)
        return 0;
    ret = BIO_printf(bio, "%s = %s\n", label, hexstr);
    OPENSSL_free(hexstr);
    return ret;
}

static int write_config_header(BIO *out, const char *prov_name,
                               const char *section)
{
    return BIO_printf(out, "openssl_conf = openssl_init\n\n")
           && BIO_printf(out, "[openssl_init]\n")
           && BIO_printf(out, "providers = provider_section\n\n")
           && BIO_printf(out, "[provider_section]\n")
           && BIO_printf(out, "%s = %s\n\n", prov_name, section);
}

/*
 * Outputs a fips related config file that contains entries for the fips
 * module checksum and the installation indicator checksum.
 *
 * Returns 1 if the config file is written otherwise it returns 0 on error.
 */
static int write_config_fips_section(BIO *out, const char *section,
                                     unsigned char *module_mac,
                                     size_t module_mac_len,
                                     unsigned char *install_mac,
                                     size_t install_mac_len)
{
    int ret = 0;

    if (!(BIO_printf(out, "[%s]\n", section) > 0
          && BIO_printf(out, "activate = 1\n") > 0
          && BIO_printf(out, "%s = %s\n", OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
                        VERSION_VAL) > 0
          && print_mac(out, OSSL_PROV_FIPS_PARAM_MODULE_MAC, module_mac,
                       module_mac_len)))
        goto end;

    if (install_mac != NULL) {
        if (!(print_mac(out, OSSL_PROV_FIPS_PARAM_INSTALL_MAC, install_mac,
                      install_mac_len)
              && BIO_printf(out, "%s = %s\n",
                            OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
                            INSTALL_STATUS_VAL) > 0))
        goto end;
    }
    ret = 1;
end:
    return ret;
}

static CONF *generate_config_and_load(const char *prov_name,
                                      const char *section,
                                      unsigned char *module_mac,
                                      size_t module_mac_len)
{
    BIO *mem_bio = NULL;
    CONF *conf = NULL;

    mem_bio = BIO_new(BIO_s_mem());
    if (mem_bio  == NULL)
        return 0;
    if (!write_config_header(mem_bio, prov_name, section)
         || !write_config_fips_section(mem_bio, section, module_mac,
                                       module_mac_len, NULL, 0))
        goto end;

    conf = app_load_config_bio(mem_bio, NULL);
    if (conf == NULL)
        goto end;

    if (!CONF_modules_load(conf, NULL, 0))
        goto end;
    BIO_free(mem_bio);
    return conf;
end:
    NCONF_free(conf);
    BIO_free(mem_bio);
    return NULL;
}

static void free_config_and_unload(CONF *conf)
{
    if (conf != NULL) {
        NCONF_free(conf);
        CONF_modules_unload(1);
    }
}

/*
 * Returns 1 if the config file entries match the passed in module_mac and
 * install_mac values, otherwise it returns 0.
 */
static int verify_config(const char *infile, const char *section,
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

    s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_INSTALL_VERSION);
    if (s == NULL || strcmp(s, VERSION_VAL) != 0) {
        BIO_printf(bio_err, "version not found\n");
        goto end;
    }
    s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_INSTALL_STATUS);
    if (s == NULL || strcmp(s, INSTALL_STATUS_VAL) != 0) {
        BIO_printf(bio_err, "install status not found\n");
        goto end;
    }
    s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_MODULE_MAC);
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
    s = NCONF_get_string(conf, section, OSSL_PROV_FIPS_PARAM_INSTALL_MAC);
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
    int ret = 1, verify = 0;
    BIO *module_bio = NULL, *mem_bio = NULL, *fout = NULL;
    char *in_fname = NULL, *out_fname = NULL, *prog, *section_name = NULL;
    char *prov_name = NULL, *module_fname = NULL;
    static const char *mac_name = DEFAULT_MAC_NAME;
    EVP_MAC_CTX *ctx = NULL, *ctx2 = NULL;
    STACK_OF(OPENSSL_STRING) *opts = NULL;
    OPTION_CHOICE o;
    unsigned char *read_buffer = NULL;
    unsigned char module_mac[EVP_MAX_MD_SIZE];
    size_t module_mac_len = EVP_MAX_MD_SIZE;
    unsigned char install_mac[EVP_MAX_MD_SIZE];
    size_t install_mac_len = EVP_MAX_MD_SIZE;
    EVP_MAC *mac = NULL;
    CONF *conf = NULL;

    section_name = DEFAULT_FIPS_SECTION;

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
            in_fname = opt_arg();
            break;
        case OPT_OUT:
            out_fname = opt_arg();
            break;
        case OPT_PROV_NAME:
            prov_name = opt_arg();
            break;
        case OPT_MODULE:
            module_fname = opt_arg();
            break;
        case OPT_SECTION_NAME:
            section_name = opt_arg();
            break;
        case OPT_MAC_NAME:
            mac_name = opt_arg();
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
        }
    }
    argc = opt_num_rest();
    if (module_fname == NULL
        || (verify && in_fname == NULL)
        || (!verify && (out_fname == NULL || prov_name == NULL))
        || opts == NULL
        || argc != 0)
        goto opthelp;

    module_bio = bio_open_default(module_fname, 'r', FORMAT_BINARY);
    if (module_bio == NULL) {
        BIO_printf(bio_err, "Failed to open module file\n");
        goto end;
    }

    read_buffer = app_malloc(BUFSIZE, "I/O buffer");
    if (read_buffer == NULL)
        goto end;

    mac = EVP_MAC_fetch(NULL, mac_name, NULL);
    if (mac == NULL) {
        BIO_printf(bio_err, "Unable to get MAC of type %s\n", mac_name);
        goto end;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for module check\n");
        goto end;
    }

    if (opts != NULL) {
        int ok = 1;
        OSSL_PARAM *params =
            app_params_new_from_opts(opts, EVP_MAC_settable_ctx_params(mac));

        if (params == NULL)
            goto end;

        if (!EVP_MAC_CTX_set_params(ctx, params)) {
            BIO_printf(bio_err, "MAC parameter error\n");
            ERR_print_errors(bio_err);
            ok = 0;
        }
        app_params_free(params);
        if (!ok)
            goto end;
    }

    ctx2 = EVP_MAC_CTX_dup(ctx);
    if (ctx2 == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for install indicator\n");
        goto end;
    }

    if (!do_mac(ctx, read_buffer, module_bio, module_mac, &module_mac_len))
        goto end;

    mem_bio = BIO_new_mem_buf((const void *)INSTALL_STATUS_VAL,
                              strlen(INSTALL_STATUS_VAL));
    if (mem_bio == NULL) {
        BIO_printf(bio_err, "Unable to create memory BIO\n");
        goto end;
    }
    if (!do_mac(ctx2, read_buffer, mem_bio, install_mac, &install_mac_len))
        goto end;

    if (verify) {
        if (!verify_config(in_fname, section_name, module_mac, module_mac_len,
                           install_mac, install_mac_len))
            goto end;
        BIO_printf(bio_out, "VERIFY PASSED\n");
    } else {

        conf = generate_config_and_load(prov_name, section_name, module_mac,
                                        module_mac_len);
        if (conf == NULL)
            goto end;
        if (!load_fips_prov_and_run_self_test(prov_name))
            goto end;

        fout = bio_open_default(out_fname, 'w', FORMAT_TEXT);
        if (fout == NULL) {
            BIO_printf(bio_err, "Failed to open file\n");
            goto end;
        }
        if (!write_config_fips_section(fout, section_name, module_mac,
                                       module_mac_len, install_mac,
                                       install_mac_len))
            goto end;
        BIO_printf(bio_out, "INSTALL PASSED\n");
    }

    ret = 0;
end:
    if (ret == 1) {
        BIO_printf(bio_err, "%s FAILED\n", verify ? "VERIFY" : "INSTALL");
        ERR_print_errors(bio_err);
    }

    BIO_free(fout);
    BIO_free(mem_bio);
    BIO_free(module_bio);
    sk_OPENSSL_STRING_free(opts);
    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx2);
    EVP_MAC_CTX_free(ctx);
    OPENSSL_free(read_buffer);
    free_config_and_unload(conf);
    return ret;
}
