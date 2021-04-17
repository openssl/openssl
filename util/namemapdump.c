/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "opt.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/store.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/safestack.h>
#include "internal/namemap.h"

static void dump_name(const char *name, void *data)
{
    int *first = data;

    printf("%s%s", (*first ? "" : ", "), name);
    *first = 0;
}

static void dump_num(int number, void *data)
{
    OSSL_NAMEMAP *namemap = data;
    int first = 1;

    printf("%8d: ", number);
    (void)ossl_namemap_doall_names(namemap, number, dump_name, &first);
    printf("\n");
}

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_PROV_ENUM,
    OPT_ANY, OPT_CIPHER, OPT_DIGEST, OPT_ASYM_CIPHER, OPT_SIGNATURE,
    OPT_KEX, OPT_KEM, OPT_KDF, OPT_KEYMGMT, OPT_MAC, OPT_RAND, OPT_STORE
} OPTION_CHOICE;

static const OPTIONS options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options]\n"},

    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_PROV_OPTIONS,

    OPT_SECTION("Fetching - only to fill the namemap"),
    {"any", OPT_ANY, '-', "Fetch everything available"},
    {"cipher", OPT_CIPHER, 's', "Fetch a cipher implementation"},
    {"digest", OPT_DIGEST, 's', "Fetch a digest implementation"},
    {"asym-cipher", OPT_ASYM_CIPHER, 's',
     "Fetch an asymmetric cipher implementation"},
    {"signature", OPT_SIGNATURE, 's', "Fetch an signature implementation"},
    {"kex", OPT_KEX, 's', "Fetch a key exchange implementation"},
    {"kem", OPT_KEM, 's', "Fetch a key encapsulation implementation"},
    {"kdf", OPT_KDF, 's', "Fetch a key derivation implementation"},
    {"keymgmt", OPT_KEYMGMT, 's', "Fetch a keypair implementation"},
    {"mac", OPT_MAC, 's', "Fetch a message authentication code implementation"},
    {"rand", OPT_RAND, 's', "Fetch a pseudo-random number implementation"},
    {"store", OPT_STORE, 's', "Fetch a STORE loader implementation"}
};

DEFINE_STACK_OF(OSSL_PROVIDER)

static void provider_free(OSSL_PROVIDER *prov)
{
    OSSL_PROVIDER_unload(prov);
}

int opt_printf_stderr(const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vfprintf(stderr, fmt, ap);
    va_end(ap);
    return ret;
}

int main(int argc, char **argv)
{
    const char *prog = NULL;
    const char *propq = NULL;
    static STACK_OF(OSSL_PROVIDER) *providers = NULL;
    OSSL_NAMEMAP *namemap;
    OPTION_CHOICE o;
    int ret = EXIT_FAILURE;

#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
    argv = copy_argv(&argc, argv);
#elif defined(_WIN32)
    /*
     * Replace argv[] with UTF-8 encoded strings.
     */
    win32_utf8argv(&argc, &argv);
#endif

    /* Default initialization with configuration file */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    if ((prog = opt_init(argc, argv, options)) == NULL)
        goto end;
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            fprintf(stderr, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(options);
            ret = EXIT_SUCCESS;
            goto end;
        case OPT_PROV__FIRST:
        case OPT_PROV__LAST:
            goto end;
        case OPT_PROV_PROVIDER: {
            const char *provider_name = opt_arg();
            OSSL_PROVIDER * prov = OSSL_PROVIDER_load(NULL, provider_name);

            if (prov == NULL) {
                fprintf(stderr, "%s: unable to load provider %s\n",
                        prog, provider_name);
                goto end;
            }
            if (providers == NULL)
                providers = sk_OSSL_PROVIDER_new_null();
            if (providers == NULL
                || !sk_OSSL_PROVIDER_push(providers, prov)) {
                OSSL_PROVIDER_unload(prov);
                goto end;
            }

            break;
        }
        case OPT_PROV_PROVIDER_PATH:
            if (!OSSL_PROVIDER_set_default_search_path(NULL, opt_arg()))
                goto end;
            break;
        case OPT_PROV_PROPQUERY:
            propq = opt_arg();
            break;
        case OPT_ANY:
            /* This fetches anything that's available, filling up the namemap */
            EVP_CIPHER_do_all_provided(NULL, NULL, NULL);
            EVP_MD_do_all_provided(NULL, NULL, NULL);
            EVP_ASYM_CIPHER_do_all_provided(NULL, NULL, NULL);
            EVP_SIGNATURE_do_all_provided(NULL, NULL, NULL);
            EVP_KEYEXCH_do_all_provided(NULL, NULL, NULL);
            EVP_KEM_do_all_provided(NULL, NULL, NULL);
            EVP_KDF_do_all_provided(NULL, NULL, NULL);
            EVP_KEYMGMT_do_all_provided(NULL, NULL, NULL);
            EVP_MAC_do_all_provided(NULL, NULL, NULL);
            EVP_RAND_do_all_provided(NULL, NULL, NULL);
            OSSL_STORE_LOADER_do_all_provided(NULL, NULL, NULL);
            break;
        case OPT_CIPHER: {
            EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, opt_arg(), propq);

            EVP_CIPHER_free(cipher);
            break;
        }
        case OPT_DIGEST: {
            EVP_MD *md = EVP_MD_fetch(NULL, opt_arg(), propq);

            EVP_MD_free(md);
            break;
        }
        case OPT_ASYM_CIPHER: {
            EVP_ASYM_CIPHER *asymcipher = EVP_ASYM_CIPHER_fetch(NULL, opt_arg(), propq);

            EVP_ASYM_CIPHER_free(asymcipher);
            break;
        }
        case OPT_SIGNATURE: {
            EVP_SIGNATURE *signature = EVP_SIGNATURE_fetch(NULL, opt_arg(), propq);

            EVP_SIGNATURE_free(signature);
            break;
        }
        case OPT_KEX: {
            EVP_KEYEXCH *kex = EVP_KEYEXCH_fetch(NULL, opt_arg(), propq);

            EVP_KEYEXCH_free(kex);
            break;
        }
        case OPT_KEM: {
            EVP_KEM *kem = EVP_KEM_fetch(NULL, opt_arg(), propq);

            EVP_KEM_free(kem);
            break;
        }
        case OPT_KDF: {
            EVP_KDF *kdf = EVP_KDF_fetch(NULL, opt_arg(), propq);

            EVP_KDF_free(kdf);
            break;
        }
        case OPT_KEYMGMT: {
            EVP_KEYMGMT *keymgmt = EVP_KEYMGMT_fetch(NULL, opt_arg(), propq);

            EVP_KEYMGMT_free(keymgmt);
            break;
        }
        case OPT_MAC: {
            EVP_MAC *mac = EVP_MAC_fetch(NULL, opt_arg(), propq);

            EVP_MAC_free(mac);
            break;
        }
        case OPT_RAND: {
            EVP_RAND *rand = EVP_RAND_fetch(NULL, opt_arg(), propq);

            EVP_RAND_free(rand);
            break;
        }
        case OPT_STORE: {
            OSSL_STORE_LOADER *store =
                OSSL_STORE_LOADER_fetch(opt_arg(), NULL, propq);

            OSSL_STORE_LOADER_free(store);
            break;
        }
        }
    }

    if (opt_num_rest() > 0)
        fprintf(stderr, "%s: Ignoring trailing arguments\n", prog);

    namemap = ossl_namemap_stored(NULL);
    if (!ossl_namemap_doall_nums(namemap, dump_num, namemap))
        goto end;

    ret = EXIT_SUCCESS;

 end:
    sk_OSSL_PROVIDER_pop_free(providers, provider_free);
    ERR_print_errors_fp(stderr);
    return ret;
}
