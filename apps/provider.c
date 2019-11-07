/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include "apps.h"
#include "app_params.h"
#include "progs.h"
#include "names.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/safestack.h>
#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_V = 100, OPT_VV, OPT_VVV
} OPTION_CHOICE;

const OPTIONS provider_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] provider...\n"},
    {OPT_HELP_STR, 1, '-', "  provider... Providers to load\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Output"),
    {"v", OPT_V, '-', "List the algorithm names of specified provider"},
    {"vv", OPT_VV, '-', "List the algorithm names of specified providers,"},
    {OPT_MORE_STR, 0, '-', "categorised by operation type"},
    {"vvv", OPT_VVV, '-', "List the algorithm names of specified provider"},
    {OPT_MORE_STR, 0, '-', "one at a time, and list all known parameters"},
    {NULL}
};

typedef struct info_st INFO;
typedef struct meta_st META;

struct info_st {
    void (*collect_names_fn)(void *method, STACK_OF(OPENSSL_CSTRING) *names);
    void *method;
    const OSSL_PARAM *gettable_params;
    const OSSL_PARAM *gettable_ctx_params;
    const OSSL_PARAM *settable_ctx_params;
};

struct meta_st {
    int first;                   /* For prints */
    int total;
    int indent;
    int subindent;
    int verbose;
    const char *label;
    OSSL_PROVIDER *prov;
    void (*fn)(META *meta, INFO *info);
};

static void collect_cipher_names(void *method,
                                 STACK_OF(OPENSSL_CSTRING) *names)
{
    EVP_CIPHER_names_do_all(method, collect_names, names);
}

static void collect_digest_names(void *method,
                                 STACK_OF(OPENSSL_CSTRING) *names)
{
    EVP_MD_names_do_all(method, collect_names, names);
}

static void collect_mac_names(void *method,
                              STACK_OF(OPENSSL_CSTRING) *names)
{
    EVP_MAC_names_do_all(method, collect_names, names);
}

static void collect_keymgmt_names(void *method,
                                  STACK_OF(OPENSSL_CSTRING) *names)
{
    EVP_KEYMGMT_names_do_all(method, collect_names, names);
}

static void collect_keyexch_names(void *method,
                                  STACK_OF(OPENSSL_CSTRING) *names)
{
    EVP_KEYEXCH_names_do_all(method, collect_names, names);
}

static void collect_signature_names(void *method,
                                  STACK_OF(OPENSSL_CSTRING) *names)
{
    EVP_SIGNATURE_names_do_all(method, collect_names, names);
}

static void print_method_names(BIO *out, INFO *info)
{
    STACK_OF(OPENSSL_CSTRING) *names = sk_OPENSSL_CSTRING_new(name_cmp);

    info->collect_names_fn(info->method, names);
    print_names(out, names);
    sk_OPENSSL_CSTRING_free(names);
}

static void print_caps(META *meta, INFO *info)
{
    switch (meta->verbose) {
    case 1:
        if (!meta->first)
            BIO_printf(bio_out, "; ");
        print_method_names(bio_out, info);
        break;
    case 2:
        if (meta->first) {
            if (meta->total > 0)
                BIO_printf(bio_out, "\n");
            BIO_printf(bio_out, "%*s%ss:", meta->indent, "", meta->label);
        }
        BIO_printf(bio_out, " ");
        print_method_names(bio_out, info);
        break;
    case 3:
    default:
        BIO_printf(bio_out, "%*s%s ", meta->indent, "", meta->label);
        print_method_names(bio_out, info);
        BIO_printf(bio_out, "\n");
        print_param_types("retrievable algorithm parameters",
                          info->gettable_params, meta->subindent);
        print_param_types("retrievable operation parameters",
                          info->gettable_ctx_params, meta->subindent);
        print_param_types("settable operation parameters",
                          info->settable_ctx_params, meta->subindent);
        break;
    }
    meta->first = 0;
}

static void do_method(void *method,
                      void (*collect_names_fn)(void *method,
                                               STACK_OF(OPENSSL_CSTRING) *names),
                      const OSSL_PARAM *gettable_params,
                      const OSSL_PARAM *gettable_ctx_params,
                      const OSSL_PARAM *settable_ctx_params,
                      META *meta)
{
    INFO info;

    info.collect_names_fn = collect_names_fn;
    info.method = method;
    info.gettable_params = gettable_params;
    info.gettable_ctx_params = gettable_ctx_params;
    info.settable_ctx_params = settable_ctx_params;
    meta->fn(meta, &info);
    meta->total++;
}

static void do_cipher(EVP_CIPHER *cipher, void *meta)
{
    do_method(cipher, collect_cipher_names,
              EVP_CIPHER_gettable_params(cipher),
              EVP_CIPHER_gettable_ctx_params(cipher),
              EVP_CIPHER_settable_ctx_params(cipher),
              meta);
}

static void do_digest(EVP_MD *digest, void *meta)
{
    do_method(digest, collect_digest_names,
              EVP_MD_gettable_params(digest),
              EVP_MD_gettable_ctx_params(digest),
              EVP_MD_settable_ctx_params(digest),
              meta);
}

static void do_mac(EVP_MAC *mac, void *meta)
{
    do_method(mac, collect_mac_names,
              EVP_MAC_gettable_params(mac),
              EVP_MAC_gettable_ctx_params(mac),
              EVP_MAC_settable_ctx_params(mac),
              meta);
}

static void do_keymgmt(EVP_KEYMGMT *keymgmt, void *meta)
{
    do_method(keymgmt, collect_keymgmt_names,
/*
 * TODO(3.0) Enable when KEYMGMT and KEYEXCH have gettables and settables
 */
#if 0
              EVP_KEYMGMT_gettable_params(keymgmt),
              EVP_KEYMGMT_gettable_ctx_params(keymgmt),
              EVP_KEYMGMT_settable_ctx_params(keymgmt),
#else
              NULL, NULL, NULL,
#endif
              meta);
}

static void do_keyexch(EVP_KEYEXCH *keyexch, void *meta)
{
    do_method(keyexch, collect_keyexch_names,
/*
 * TODO(3.0) Enable when KEYMGMT and KEYEXCH have gettables and settables
 */
#if 0
              EVP_KEYEXCH_gettable_params(keyexch),
              EVP_KEYEXCH_gettable_ctx_params(keyexch),
              EVP_KEYEXCH_settable_ctx_params(keyexch),
#else
              NULL, NULL, NULL,
#endif
              meta);
}

static void do_signature(EVP_SIGNATURE *signature, void *meta)
{
    do_method(signature, collect_signature_names,
/*
 * TODO(3.0) Enable when KEYMGMT and SIGNATURE have gettables and settables
 */
#if 0
              EVP_SIGNATURE_gettable_params(signature),
              EVP_SIGNATURE_gettable_ctx_params(signature),
              EVP_SIGNATURE_settable_ctx_params(signature),
#else
              NULL, NULL, NULL,
#endif
              meta);
}

int provider_main(int argc, char **argv)
{
    int ret = 1, i;
    int verbose = 0;
    STACK_OF(OPENSSL_CSTRING) *providers = sk_OPENSSL_CSTRING_new_null();
    OPTION_CHOICE o;
    char *prog;

    prog = opt_init(argc, argv, provider_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        default: /* Catching OPT_ERR & covering OPT_EOF which isn't possible */
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(provider_options);
            ret = 0;
            goto end;
        case OPT_VVV:
        case OPT_VV:
        case OPT_V:
            /* Convert to an integer from one to four. */
            i = (int)(o - OPT_V) + 1;
            if (verbose < i)
                verbose = i;
            break;
        }
    }

    /* Allow any trailing parameters as provider names. */
    argc = opt_num_rest();
    argv = opt_rest();
    for ( ; *argv; argv++) {
        if (**argv == '-') {
            BIO_printf(bio_err, "%s: Cannot mix flags and provider names.\n",
                       prog);
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        }
        sk_OPENSSL_CSTRING_push(providers, *argv);
    }

    ret = 0;
    for (i = 0; i < sk_OPENSSL_CSTRING_num(providers); i++) {
        const char *name = sk_OPENSSL_CSTRING_value(providers, i);
        OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, name);

        if (prov != NULL) {
            BIO_printf(bio_out, verbose == 0 ? "%s\n" :  "[ %s ]\n", name);

            if (verbose > 0) {
                META data;

                data.total = 0;
                data.first = 1;
                data.verbose = verbose;
                data.prov = prov;
                data.fn = print_caps;

                switch (verbose) {
                case 1:
                    BIO_printf(bio_out, "    ");
                    break;
                case 2:
                    data.indent = 4;
                    break;
                case 3:
                default:
                    data.indent = 4;
                    data.subindent = 10;
                    break;
                }

                if (verbose > 1) {
                    data.first = 1;
                    data.label = "Cipher";
                }
                EVP_CIPHER_do_all_provided(NULL, do_cipher, &data);
                if (verbose > 1) {
                    data.first = 1;
                    data.label = "Digest";
                }
                EVP_MD_do_all_provided(NULL, do_digest, &data);
                if (verbose > 1) {
                    data.first = 1;
                    data.label = "MAC";
                }
                EVP_MAC_do_all_provided(NULL, do_mac, &data);

                if (verbose > 1) {
                    data.first = 1;
                    data.label = "Key manager";
                }
                EVP_KEYMGMT_do_all_provided(NULL, do_keymgmt, &data);
                if (verbose > 1) {
                    data.first = 1;
                    data.label = "Key exchange";
                }
                EVP_KEYEXCH_do_all_provided(NULL, do_keyexch, &data);
                if (verbose > 1) {
                    data.first = 1;
                    data.label = "Signature";
                }
                EVP_SIGNATURE_do_all_provided(NULL, do_signature, &data);

                switch (verbose) {
                default:
                    break;
                case 2:
                case 1:
                    BIO_printf(bio_out, "\n");
                    break;
                }
            }
            OSSL_PROVIDER_unload(prov);
        } else {
            ERR_print_errors(bio_err);
            ret = 1;
            /*
             * Just because one provider module failed, there's no reason to
             * stop, if there are more to try.
             */
        }
    }

 end:

    ERR_print_errors(bio_err);
    sk_OPENSSL_CSTRING_free(providers);
    return ret;
}
