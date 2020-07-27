/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/safestack.h>
#include <openssl/kdf.h>
#include <openssl/serializer.h>
#include <openssl/deserializer.h>
#include <openssl/core_names.h>
#include "apps.h"
#include "app_params.h"
#include "progs.h"
#include "opt.h"
#include "names.h"

DEFINE_STACK_OF_CSTRING()

static int verbose = 0;

static void legacy_cipher_fn(const EVP_CIPHER *c,
                             const char *from, const char *to, void *arg)
{
    if (c != NULL) {
        BIO_printf(arg, "  %s\n", EVP_CIPHER_name(c));
    } else {
        if (from == NULL)
            from = "<undefined>";
        if (to == NULL)
            to = "<undefined>";
        BIO_printf(arg, "  %s => %s\n", from, to);
    }
}

DEFINE_STACK_OF(EVP_CIPHER)
static int cipher_cmp(const EVP_CIPHER * const *a,
                      const EVP_CIPHER * const *b)
{
    int ret = EVP_CIPHER_number(*a) - EVP_CIPHER_number(*b);

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(EVP_CIPHER_provider(*a)),
                     OSSL_PROVIDER_name(EVP_CIPHER_provider(*b)));

    return ret;
}

static void collect_ciphers(EVP_CIPHER *cipher, void *stack)
{
    STACK_OF(EVP_CIPHER) *cipher_stack = stack;

    if (sk_EVP_CIPHER_push(cipher_stack, cipher) > 0)
        EVP_CIPHER_up_ref(cipher);
}

static void list_ciphers(void)
{
    STACK_OF(EVP_CIPHER) *ciphers = sk_EVP_CIPHER_new(cipher_cmp);
    int i;

    if (ciphers == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Legacy:\n");
    EVP_CIPHER_do_all_sorted(legacy_cipher_fn, bio_out);

    BIO_printf(bio_out, "Provided:\n");
    EVP_CIPHER_do_all_provided(NULL, collect_ciphers, ciphers);
    sk_EVP_CIPHER_sort(ciphers);
    for (i = 0; i < sk_EVP_CIPHER_num(ciphers); i++) {
        const EVP_CIPHER *c = sk_EVP_CIPHER_value(ciphers, i);
        STACK_OF(OPENSSL_CSTRING) *names =
            sk_OPENSSL_CSTRING_new(name_cmp);

        EVP_CIPHER_names_do_all(c, collect_names, names);

        BIO_printf(bio_out, "  ");
        print_names(bio_out, names);
        BIO_printf(bio_out, " @ %s\n",
                   OSSL_PROVIDER_name(EVP_CIPHER_provider(c)));

        sk_OPENSSL_CSTRING_free(names);

        if (verbose) {
            print_param_types("retrievable algorithm parameters",
                              EVP_CIPHER_gettable_params(c), 4);
            print_param_types("retrievable operation parameters",
                              EVP_CIPHER_gettable_ctx_params(c), 4);
            print_param_types("settable operation parameters",
                              EVP_CIPHER_settable_ctx_params(c), 4);
        }
    }
    sk_EVP_CIPHER_pop_free(ciphers, EVP_CIPHER_free);
}

static void list_md_fn(const EVP_MD *m,
                       const char *from, const char *to, void *arg)
{
    if (m != NULL) {
        BIO_printf(arg, "  %s\n", EVP_MD_name(m));
    } else {
        if (from == NULL)
            from = "<undefined>";
        if (to == NULL)
            to = "<undefined>";
        BIO_printf((BIO *)arg, "  %s => %s\n", from, to);
    }
}

DEFINE_STACK_OF(EVP_MD)
static int md_cmp(const EVP_MD * const *a, const EVP_MD * const *b)
{
    int ret = EVP_MD_number(*a) - EVP_MD_number(*b);

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(EVP_MD_provider(*a)),
                     OSSL_PROVIDER_name(EVP_MD_provider(*b)));

    return ret;
}

static void collect_digests(EVP_MD *md, void *stack)
{
    STACK_OF(EVP_MD) *digest_stack = stack;

    if (sk_EVP_MD_push(digest_stack, md) > 0)
        EVP_MD_up_ref(md);
}

static void list_digests(void)
{
    STACK_OF(EVP_MD) *digests = sk_EVP_MD_new(md_cmp);
    int i;

    if (digests == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Legacy:\n");
    EVP_MD_do_all_sorted(list_md_fn, bio_out);

    BIO_printf(bio_out, "Provided:\n");
    EVP_MD_do_all_provided(NULL, collect_digests, digests);
    sk_EVP_MD_sort(digests);
    for (i = 0; i < sk_EVP_MD_num(digests); i++) {
        const EVP_MD *m = sk_EVP_MD_value(digests, i);
        STACK_OF(OPENSSL_CSTRING) *names =
            sk_OPENSSL_CSTRING_new(name_cmp);

        EVP_MD_names_do_all(m, collect_names, names);

        BIO_printf(bio_out, "  ");
        print_names(bio_out, names);
        BIO_printf(bio_out, " @ %s\n",
                   OSSL_PROVIDER_name(EVP_MD_provider(m)));

        sk_OPENSSL_CSTRING_free(names);

        if (verbose) {
            print_param_types("retrievable algorithm parameters",
                              EVP_MD_gettable_params(m), 4);
            print_param_types("retrievable operation parameters",
                              EVP_MD_gettable_ctx_params(m), 4);
            print_param_types("settable operation parameters",
                              EVP_MD_settable_ctx_params(m), 4);
        }
    }
    sk_EVP_MD_pop_free(digests, EVP_MD_free);
}

DEFINE_STACK_OF(EVP_MAC)
static int mac_cmp(const EVP_MAC * const *a, const EVP_MAC * const *b)
{
    int ret = EVP_MAC_number(*a) - EVP_MAC_number(*b);

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(EVP_MAC_provider(*a)),
                     OSSL_PROVIDER_name(EVP_MAC_provider(*b)));

    return ret;
}

static void collect_macs(EVP_MAC *mac, void *stack)
{
    STACK_OF(EVP_MAC) *mac_stack = stack;

    if (sk_EVP_MAC_push(mac_stack, mac) > 0)
        EVP_MAC_up_ref(mac);
}

static void list_macs(void)
{
    STACK_OF(EVP_MAC) *macs = sk_EVP_MAC_new(mac_cmp);
    int i;

    if (macs == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Provided MACs:\n");
    EVP_MAC_do_all_provided(NULL, collect_macs, macs);
    sk_EVP_MAC_sort(macs);
    for (i = 0; i < sk_EVP_MAC_num(macs); i++) {
        const EVP_MAC *m = sk_EVP_MAC_value(macs, i);
        STACK_OF(OPENSSL_CSTRING) *names =
            sk_OPENSSL_CSTRING_new(name_cmp);

        EVP_MAC_names_do_all(m, collect_names, names);

        BIO_printf(bio_out, "  ");
        print_names(bio_out, names);
        BIO_printf(bio_out, " @ %s\n",
                   OSSL_PROVIDER_name(EVP_MAC_provider(m)));

        sk_OPENSSL_CSTRING_free(names);

        if (verbose) {
            print_param_types("retrievable algorithm parameters",
                              EVP_MAC_gettable_params(m), 4);
            print_param_types("retrievable operation parameters",
                              EVP_MAC_gettable_ctx_params(m), 4);
            print_param_types("settable operation parameters",
                              EVP_MAC_settable_ctx_params(m), 4);
        }
    }
    sk_EVP_MAC_pop_free(macs, EVP_MAC_free);
}

/*
 * KDFs and PRFs
 */
DEFINE_STACK_OF(EVP_KDF)
static int kdf_cmp(const EVP_KDF * const *a, const EVP_KDF * const *b)
{
    int ret = EVP_KDF_number(*a) - EVP_KDF_number(*b);

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(EVP_KDF_provider(*a)),
                     OSSL_PROVIDER_name(EVP_KDF_provider(*b)));

    return ret;
}

static void collect_kdfs(EVP_KDF *kdf, void *stack)
{
    STACK_OF(EVP_KDF) *kdf_stack = stack;

    sk_EVP_KDF_push(kdf_stack, kdf);
    EVP_KDF_up_ref(kdf);
}

static void list_kdfs(void)
{
    STACK_OF(EVP_KDF) *kdfs = sk_EVP_KDF_new(kdf_cmp);
    int i;

    if (kdfs == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Provided KDFs and PDFs:\n");
    EVP_KDF_do_all_provided(NULL, collect_kdfs, kdfs);
    sk_EVP_KDF_sort(kdfs);
    for (i = 0; i < sk_EVP_KDF_num(kdfs); i++) {
        const EVP_KDF *k = sk_EVP_KDF_value(kdfs, i);
        STACK_OF(OPENSSL_CSTRING) *names =
            sk_OPENSSL_CSTRING_new(name_cmp);

        EVP_KDF_names_do_all(k, collect_names, names);

        BIO_printf(bio_out, "  ");
        print_names(bio_out, names);
        BIO_printf(bio_out, " @ %s\n",
                   OSSL_PROVIDER_name(EVP_KDF_provider(k)));

        sk_OPENSSL_CSTRING_free(names);

        if (verbose) {
            print_param_types("retrievable algorithm parameters",
                              EVP_KDF_gettable_params(k), 4);
            print_param_types("retrievable operation parameters",
                              EVP_KDF_gettable_ctx_params(k), 4);
            print_param_types("settable operation parameters",
                              EVP_KDF_settable_ctx_params(k), 4);
        }
    }
    sk_EVP_KDF_pop_free(kdfs, EVP_KDF_free);
}

/*
 * RANDs
 */
DEFINE_STACK_OF(EVP_RAND)

static int rand_cmp(const EVP_RAND * const *a, const EVP_RAND * const *b)
{
    int ret = strcasecmp(EVP_RAND_name(*a), EVP_RAND_name(*b));

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(EVP_RAND_provider(*a)),
                     OSSL_PROVIDER_name(EVP_RAND_provider(*b)));

    return ret;
}

static void collect_rands(EVP_RAND *rand, void *stack)
{
    STACK_OF(EVP_RAND) *rand_stack = stack;

    sk_EVP_RAND_push(rand_stack, rand);
    EVP_RAND_up_ref(rand);
}

static void list_random_generators(void)
{
    STACK_OF(EVP_RAND) *rands = sk_EVP_RAND_new(rand_cmp);
    int i;

    if (rands == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Provided RNGs and seed sources:\n");
    EVP_RAND_do_all_provided(NULL, collect_rands, rands);
    sk_EVP_RAND_sort(rands);
    for (i = 0; i < sk_EVP_RAND_num(rands); i++) {
        const EVP_RAND *m = sk_EVP_RAND_value(rands, i);

        BIO_printf(bio_out, "  %s", EVP_RAND_name(m));
        BIO_printf(bio_out, " @ %s\n",
                   OSSL_PROVIDER_name(EVP_RAND_provider(m)));

        if (verbose) {
            print_param_types("retrievable algorithm parameters",
                              EVP_RAND_gettable_params(m), 4);
            print_param_types("retrievable operation parameters",
                              EVP_RAND_gettable_ctx_params(m), 4);
            print_param_types("settable operation parameters",
                              EVP_RAND_settable_ctx_params(m), 4);
        }
    }
    sk_EVP_RAND_pop_free(rands, EVP_RAND_free);
}

/*
 * Serializers
 */
DEFINE_STACK_OF(OSSL_SERIALIZER)
static int serializer_cmp(const OSSL_SERIALIZER * const *a,
                          const OSSL_SERIALIZER * const *b)
{
    int ret = OSSL_SERIALIZER_number(*a) - OSSL_SERIALIZER_number(*b);

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(OSSL_SERIALIZER_provider(*a)),
                     OSSL_PROVIDER_name(OSSL_SERIALIZER_provider(*b)));
    return ret;
}

static void collect_serializers(OSSL_SERIALIZER *serializer, void *stack)
{
    STACK_OF(OSSL_SERIALIZER) *serializer_stack = stack;

    sk_OSSL_SERIALIZER_push(serializer_stack, serializer);
    OSSL_SERIALIZER_up_ref(serializer);
}

static void list_serializers(void)
{
    STACK_OF(OSSL_SERIALIZER) *serializers;
    int i;

    serializers = sk_OSSL_SERIALIZER_new(serializer_cmp);
    if (serializers == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Provided SERIALIZERs:\n");
    OSSL_SERIALIZER_do_all_provided(NULL, collect_serializers, serializers);
    sk_OSSL_SERIALIZER_sort(serializers);

    for (i = 0; i < sk_OSSL_SERIALIZER_num(serializers); i++) {
        OSSL_SERIALIZER *k = sk_OSSL_SERIALIZER_value(serializers, i);
        STACK_OF(OPENSSL_CSTRING) *names =
            sk_OPENSSL_CSTRING_new(name_cmp);

        OSSL_SERIALIZER_names_do_all(k, collect_names, names);

        BIO_printf(bio_out, "  ");
        print_names(bio_out, names);
        BIO_printf(bio_out, " @ %s (%s)\n",
                   OSSL_PROVIDER_name(OSSL_SERIALIZER_provider(k)),
                   OSSL_SERIALIZER_properties(k));

        sk_OPENSSL_CSTRING_free(names);

        if (verbose) {
            print_param_types("settable operation parameters",
                              OSSL_SERIALIZER_settable_ctx_params(k), 4);
        }
    }
    sk_OSSL_SERIALIZER_pop_free(serializers, OSSL_SERIALIZER_free);
}

/*
 * Deserializers
 */
DEFINE_STACK_OF(OSSL_DESERIALIZER)
static int deserializer_cmp(const OSSL_DESERIALIZER * const *a,
                            const OSSL_DESERIALIZER * const *b)
{
    int ret = OSSL_DESERIALIZER_number(*a) - OSSL_DESERIALIZER_number(*b);

    if (ret == 0)
        ret = strcmp(OSSL_PROVIDER_name(OSSL_DESERIALIZER_provider(*a)),
                     OSSL_PROVIDER_name(OSSL_DESERIALIZER_provider(*b)));
    return ret;
}

static void collect_deserializers(OSSL_DESERIALIZER *deserializer, void *stack)
{
    STACK_OF(OSSL_DESERIALIZER) *deserializer_stack = stack;

    sk_OSSL_DESERIALIZER_push(deserializer_stack, deserializer);
    OSSL_DESERIALIZER_up_ref(deserializer);
}

static void list_deserializers(void)
{
    STACK_OF(OSSL_DESERIALIZER) *deserializers;
    int i;

    deserializers = sk_OSSL_DESERIALIZER_new(deserializer_cmp);
    if (deserializers == NULL) {
        BIO_printf(bio_err, "ERROR: Memory allocation\n");
        return;
    }
    BIO_printf(bio_out, "Provided DESERIALIZERs:\n");
    OSSL_DESERIALIZER_do_all_provided(NULL, collect_deserializers,
                                      deserializers);
    sk_OSSL_DESERIALIZER_sort(deserializers);

    for (i = 0; i < sk_OSSL_DESERIALIZER_num(deserializers); i++) {
        OSSL_DESERIALIZER *k = sk_OSSL_DESERIALIZER_value(deserializers, i);
        STACK_OF(OPENSSL_CSTRING) *names =
            sk_OPENSSL_CSTRING_new(name_cmp);

        OSSL_DESERIALIZER_names_do_all(k, collect_names, names);

        BIO_printf(bio_out, "  ");
        print_names(bio_out, names);
        BIO_printf(bio_out, " @ %s (%s)\n",
                   OSSL_PROVIDER_name(OSSL_DESERIALIZER_provider(k)),
                   OSSL_DESERIALIZER_properties(k));

        sk_OPENSSL_CSTRING_free(names);

        if (verbose) {
            print_param_types("settable operation parameters",
                              OSSL_DESERIALIZER_settable_ctx_params(k), 4);
        }
    }
    sk_OSSL_DESERIALIZER_pop_free(deserializers, OSSL_DESERIALIZER_free);
}

static void list_missing_help(void)
{
    const FUNCTION *fp;
    const OPTIONS *o;

    for (fp = functions; fp->name != NULL; fp++) {
        if ((o = fp->help) != NULL) {
            /* If there is help, list what flags are not documented. */
            for ( ; o->name != NULL; o++) {
                if (o->helpstr == NULL)
                    BIO_printf(bio_out, "%s %s\n", fp->name, o->name);
            }
        } else if (fp->func != dgst_main) {
            /* If not aliased to the dgst command, */
            BIO_printf(bio_out, "%s *\n", fp->name);
        }
    }
}

static void list_objects(void)
{
    int max_nid = OBJ_new_nid(0);
    int i;
    char *oid_buf = NULL;
    int oid_size = 0;

    /* Skip 0, since that's NID_undef */
    for (i = 1; i < max_nid; i++) {
        const ASN1_OBJECT *obj = OBJ_nid2obj(i);
        const char *sn = OBJ_nid2sn(i);
        const char *ln = OBJ_nid2ln(i);
        int n = 0;

        /*
         * If one of the retrieved objects somehow generated an error,
         * we ignore it.  The check for NID_undef below will detect the
         * error and simply skip to the next NID.
         */
        ERR_clear_error();

        if (OBJ_obj2nid(obj) == NID_undef)
            continue;

        if ((n = OBJ_obj2txt(NULL, 0, obj, 1)) == 0) {
            BIO_printf(bio_out, "# None-OID object: %s, %s\n", sn, ln);
            continue;
        }
        if (n < 0)
            break;               /* Error */

        if (n > oid_size) {
            oid_buf = OPENSSL_realloc(oid_buf, n + 1);
            if (oid_buf == NULL) {
                BIO_printf(bio_err, "ERROR: Memory allocation\n");
                break;           /* Error */
            }
            oid_size = n + 1;
        }
        if (OBJ_obj2txt(oid_buf, oid_size, obj, 1) < 0)
            break;               /* Error */
        if (ln == NULL || strcmp(sn, ln) == 0)
            BIO_printf(bio_out, "%s = %s\n", sn, oid_buf);
        else
            BIO_printf(bio_out, "%s = %s, %s\n", sn, ln, oid_buf);
    }

    OPENSSL_free(oid_buf);
}

static void list_options_for_command(const char *command)
{
    const FUNCTION *fp;
    const OPTIONS *o;

    for (fp = functions; fp->name != NULL; fp++)
        if (strcmp(fp->name, command) == 0)
            break;
    if (fp->name == NULL) {
        BIO_printf(bio_err, "Invalid command '%s'; type \"help\" for a list.\n",
                command);
        return;
    }

    if ((o = fp->help) == NULL)
        return;

    for ( ; o->name != NULL; o++) {
        char c = o->valtype;

        if (o->name == OPT_PARAM_STR)
            break;

        if (o->name == OPT_HELP_STR
                || o->name == OPT_MORE_STR
                || o->name == OPT_SECTION_STR
                || o->name[0] == '\0')
            continue;
        BIO_printf(bio_out, "%s %c\n", o->name, c == '\0' ? '-' : c);
    }
    /* Always output the -- marker since it is sometimes documented. */
    BIO_printf(bio_out, "- -\n");
}

static void list_type(FUNC_TYPE ft, int one)
{
    FUNCTION *fp;
    int i = 0;
    DISPLAY_COLUMNS dc;

    memset(&dc, 0, sizeof(dc));
    if (!one)
        calculate_columns(functions, &dc);

    for (fp = functions; fp->name != NULL; fp++) {
        if (fp->type != ft)
            continue;
        if (one) {
            BIO_printf(bio_out, "%s\n", fp->name);
        } else {
            if (i % dc.columns == 0 && i > 0)
                BIO_printf(bio_out, "\n");
            BIO_printf(bio_out, "%-*s", dc.width, fp->name);
            i++;
        }
    }
    if (!one)
        BIO_printf(bio_out, "\n\n");
}

static void list_pkey(void)
{
    int i;

    for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        int pkey_id, pkey_base_id, pkey_flags;
        const char *pinfo, *pem_str;
        ameth = EVP_PKEY_asn1_get0(i);
        EVP_PKEY_asn1_get0_info(&pkey_id, &pkey_base_id, &pkey_flags,
                                &pinfo, &pem_str, ameth);
        if (pkey_flags & ASN1_PKEY_ALIAS) {
            BIO_printf(bio_out, "Name: %s\n", OBJ_nid2ln(pkey_id));
            BIO_printf(bio_out, "\tAlias for: %s\n",
                       OBJ_nid2ln(pkey_base_id));
        } else {
            BIO_printf(bio_out, "Name: %s\n", pinfo);
            BIO_printf(bio_out, "\tType: %s Algorithm\n",
                       pkey_flags & ASN1_PKEY_DYNAMIC ?
                       "External" : "Builtin");
            BIO_printf(bio_out, "\tOID: %s\n", OBJ_nid2ln(pkey_id));
            if (pem_str == NULL)
                pem_str = "(none)";
            BIO_printf(bio_out, "\tPEM string: %s\n", pem_str);
        }

    }
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
static void list_pkey_meth(void)
{
    size_t i;
    size_t meth_count = EVP_PKEY_meth_get_count();

    for (i = 0; i < meth_count; i++) {
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_get0(i);
        int pkey_id, pkey_flags;

        EVP_PKEY_meth_get0_info(&pkey_id, &pkey_flags, pmeth);
        BIO_printf(bio_out, "%s\n", OBJ_nid2ln(pkey_id));
        BIO_printf(bio_out, "\tType: %s Algorithm\n",
                   pkey_flags & ASN1_PKEY_DYNAMIC ?  "External" : "Builtin");
    }
}
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
static void list_engines(void)
{
# ifndef OPENSSL_NO_ENGINE
    ENGINE *e;

    BIO_puts(bio_out, "Engines:\n");
    e = ENGINE_get_first();
    while (e) {
        BIO_printf(bio_out, "%s\n", ENGINE_get_id(e));
        e = ENGINE_get_next(e);
    }
# else
    BIO_puts(bio_out, "Engine support is disabled.\n");
# endif
}
#endif

static void list_disabled(void)
{
    BIO_puts(bio_out, "Disabled algorithms:\n");
#ifdef OPENSSL_NO_ARIA
    BIO_puts(bio_out, "ARIA\n");
#endif
#ifdef OPENSSL_NO_BF
    BIO_puts(bio_out, "BF\n");
#endif
#ifdef OPENSSL_NO_BLAKE2
    BIO_puts(bio_out, "BLAKE2\n");
#endif
#ifdef OPENSSL_NO_CAMELLIA
    BIO_puts(bio_out, "CAMELLIA\n");
#endif
#ifdef OPENSSL_NO_CAST
    BIO_puts(bio_out, "CAST\n");
#endif
#ifdef OPENSSL_NO_CMAC
    BIO_puts(bio_out, "CMAC\n");
#endif
#ifdef OPENSSL_NO_CMS
    BIO_puts(bio_out, "CMS\n");
#endif
#ifdef OPENSSL_NO_COMP
    BIO_puts(bio_out, "COMP\n");
#endif
#ifdef OPENSSL_NO_DES
    BIO_puts(bio_out, "DES\n");
#endif
#ifdef OPENSSL_NO_DGRAM
    BIO_puts(bio_out, "DGRAM\n");
#endif
#ifdef OPENSSL_NO_DH
    BIO_puts(bio_out, "DH\n");
#endif
#ifdef OPENSSL_NO_DSA
    BIO_puts(bio_out, "DSA\n");
#endif
#if defined(OPENSSL_NO_DTLS)
    BIO_puts(bio_out, "DTLS\n");
#endif
#if defined(OPENSSL_NO_DTLS1)
    BIO_puts(bio_out, "DTLS1\n");
#endif
#if defined(OPENSSL_NO_DTLS1_2)
    BIO_puts(bio_out, "DTLS1_2\n");
#endif
#ifdef OPENSSL_NO_EC
    BIO_puts(bio_out, "EC\n");
#endif
#ifdef OPENSSL_NO_EC2M
    BIO_puts(bio_out, "EC2M\n");
#endif
#if defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    BIO_puts(bio_out, "ENGINE\n");
#endif
#ifdef OPENSSL_NO_GOST
    BIO_puts(bio_out, "GOST\n");
#endif
#ifdef OPENSSL_NO_IDEA
    BIO_puts(bio_out, "IDEA\n");
#endif
#ifdef OPENSSL_NO_MD2
    BIO_puts(bio_out, "MD2\n");
#endif
#ifdef OPENSSL_NO_MD4
    BIO_puts(bio_out, "MD4\n");
#endif
#ifdef OPENSSL_NO_MD5
    BIO_puts(bio_out, "MD5\n");
#endif
#ifdef OPENSSL_NO_MDC2
    BIO_puts(bio_out, "MDC2\n");
#endif
#ifdef OPENSSL_NO_OCB
    BIO_puts(bio_out, "OCB\n");
#endif
#ifdef OPENSSL_NO_OCSP
    BIO_puts(bio_out, "OCSP\n");
#endif
#ifdef OPENSSL_NO_PSK
    BIO_puts(bio_out, "PSK\n");
#endif
#ifdef OPENSSL_NO_RC2
    BIO_puts(bio_out, "RC2\n");
#endif
#ifdef OPENSSL_NO_RC4
    BIO_puts(bio_out, "RC4\n");
#endif
#ifdef OPENSSL_NO_RC5
    BIO_puts(bio_out, "RC5\n");
#endif
#ifdef OPENSSL_NO_RMD160
    BIO_puts(bio_out, "RMD160\n");
#endif
#ifdef OPENSSL_NO_RSA
    BIO_puts(bio_out, "RSA\n");
#endif
#ifdef OPENSSL_NO_SCRYPT
    BIO_puts(bio_out, "SCRYPT\n");
#endif
#ifdef OPENSSL_NO_SCTP
    BIO_puts(bio_out, "SCTP\n");
#endif
#ifdef OPENSSL_NO_SEED
    BIO_puts(bio_out, "SEED\n");
#endif
#ifdef OPENSSL_NO_SM2
    BIO_puts(bio_out, "SM2\n");
#endif
#ifdef OPENSSL_NO_SM3
    BIO_puts(bio_out, "SM3\n");
#endif
#ifdef OPENSSL_NO_SM4
    BIO_puts(bio_out, "SM4\n");
#endif
#ifdef OPENSSL_NO_SOCK
    BIO_puts(bio_out, "SOCK\n");
#endif
#ifdef OPENSSL_NO_SRP
    BIO_puts(bio_out, "SRP\n");
#endif
#ifdef OPENSSL_NO_SRTP
    BIO_puts(bio_out, "SRTP\n");
#endif
#ifdef OPENSSL_NO_SSL3
    BIO_puts(bio_out, "SSL3\n");
#endif
#ifdef OPENSSL_NO_TLS1
    BIO_puts(bio_out, "TLS1\n");
#endif
#ifdef OPENSSL_NO_TLS1_1
    BIO_puts(bio_out, "TLS1_1\n");
#endif
#ifdef OPENSSL_NO_TLS1_2
    BIO_puts(bio_out, "TLS1_2\n");
#endif
#ifdef OPENSSL_NO_WHIRLPOOL
    BIO_puts(bio_out, "WHIRLPOOL\n");
#endif
#ifndef ZLIB
    BIO_puts(bio_out, "ZLIB\n");
#endif
}

/* Unified enum for help and list commands. */
typedef enum HELPLIST_CHOICE {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ONE, OPT_VERBOSE,
    OPT_COMMANDS, OPT_DIGEST_COMMANDS, OPT_MAC_ALGORITHMS, OPT_OPTIONS,
    OPT_DIGEST_ALGORITHMS, OPT_CIPHER_COMMANDS, OPT_CIPHER_ALGORITHMS,
    OPT_PK_ALGORITHMS, OPT_PK_METHOD, OPT_DISABLED,
    OPT_KDF_ALGORITHMS, OPT_RANDOM_GENERATORS, OPT_SERIALIZERS,
    OPT_DESERIALIZERS,
    OPT_MISSING_HELP, OPT_OBJECTS,
#ifndef OPENSSL_NO_DEPRECATED_3_0
    OPT_ENGINES, 
#endif
    OPT_PROV_ENUM
} HELPLIST_CHOICE;

const OPTIONS list_options[] = {

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Output"),
    {"1", OPT_ONE, '-', "List in one column"},
    {"verbose", OPT_VERBOSE, '-', "Verbose listing"},
    {"commands", OPT_COMMANDS, '-', "List of standard commands"},
    {"standard-commands", OPT_COMMANDS, '-', "List of standard commands"},
    {"digest-commands", OPT_DIGEST_COMMANDS, '-',
     "List of message digest commands"},
    {"digest-algorithms", OPT_DIGEST_ALGORITHMS, '-',
     "List of message digest algorithms"},
    {"kdf-algorithms", OPT_KDF_ALGORITHMS, '-',
     "List of key derivation and pseudo random function algorithms"},
    {"random-generators", OPT_RANDOM_GENERATORS, '-',
      "List of random number generators"},
    {"mac-algorithms", OPT_MAC_ALGORITHMS, '-',
     "List of message authentication code algorithms"},
    {"cipher-commands", OPT_CIPHER_COMMANDS, '-', "List of cipher commands"},
    {"cipher-algorithms", OPT_CIPHER_ALGORITHMS, '-',
     "List of cipher algorithms"},
    {"serializers", OPT_SERIALIZERS, '-', "List of serialization methods" },
    {"deserializers", OPT_DESERIALIZERS, '-',
      "List of deserialization methods" },
    {"public-key-algorithms", OPT_PK_ALGORITHMS, '-',
     "List of public key algorithms"},
#ifndef OPENSSL_NO_DEPRECATED_3_0
    {"public-key-methods", OPT_PK_METHOD, '-',
     "List of public key methods"},
    {"engines", OPT_ENGINES, '-',
     "List of loaded engines"},
#endif
    {"disabled", OPT_DISABLED, '-', "List of disabled features"},
    {"missing-help", OPT_MISSING_HELP, '-',
     "List missing detailed help strings"},
    {"options", OPT_OPTIONS, 's',
     "List options for specified command"},
    {"objects", OPT_OBJECTS, '-',
     "List built in objects (OID<->name mappings)"},

    OPT_PROV_OPTIONS,
    {NULL}
};

int list_main(int argc, char **argv)
{
    char *prog;
    HELPLIST_CHOICE o;
    int one = 0, done = 0;
    struct {
        unsigned int commands:1;
        unsigned int random_generators:1;
        unsigned int digest_commands:1;
        unsigned int digest_algorithms:1;
        unsigned int kdf_algorithms:1;
        unsigned int mac_algorithms:1;
        unsigned int cipher_commands:1;
        unsigned int cipher_algorithms:1;
        unsigned int serializer_algorithms:1;
        unsigned int deserializer_algorithms:1;
        unsigned int pk_algorithms:1;
        unsigned int pk_method:1;
#ifndef OPENSSL_NO_DEPRECATED_3_0
        unsigned int engines:1;
#endif
        unsigned int disabled:1;
        unsigned int missing_help:1;
        unsigned int objects:1;
        unsigned int options:1;
    } todo = { 0, };

    verbose = 0;                 /* Clear a possible previous call */

    prog = opt_init(argc, argv, list_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:  /* Never hit, but suppresses warning */
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            return 1;
        case OPT_HELP:
            opt_help(list_options);
            break;
        case OPT_ONE:
            one = 1;
            break;
        case OPT_COMMANDS:
            todo.commands = 1;
            break;
        case OPT_DIGEST_COMMANDS:
            todo.digest_commands = 1;
            break;
        case OPT_DIGEST_ALGORITHMS:
            todo.digest_algorithms = 1;
            break;
        case OPT_KDF_ALGORITHMS:
            todo.kdf_algorithms = 1;
            break;
        case OPT_RANDOM_GENERATORS:
            todo.random_generators = 1;
            break;
        case OPT_MAC_ALGORITHMS:
            todo.mac_algorithms = 1;
            break;
        case OPT_CIPHER_COMMANDS:
            todo.cipher_commands = 1;
            break;
        case OPT_CIPHER_ALGORITHMS:
            todo.cipher_algorithms = 1;
            break;
        case OPT_SERIALIZERS:
            todo.serializer_algorithms = 1;
            break;
        case OPT_DESERIALIZERS:
            todo.deserializer_algorithms = 1;
            break;
        case OPT_PK_ALGORITHMS:
            todo.pk_algorithms = 1;
            break;
        case OPT_PK_METHOD:
            todo.pk_method = 1;
            break;
#ifndef OPENSSL_NO_DEPRECATED_3_0
        case OPT_ENGINES:
            todo.engines = 1;
            break;
#endif
        case OPT_DISABLED:
            todo.disabled = 1;
            break;
        case OPT_MISSING_HELP:
            todo.missing_help = 1;
            break;
        case OPT_OBJECTS:
            todo.objects = 1;
            break;
        case OPT_OPTIONS:
            list_options_for_command(opt_arg());
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                return 1;
            break;
        }
        done = 1;
    }
    if (opt_num_rest() != 0) {
        BIO_printf(bio_err, "Extra arguments given.\n");
        goto opthelp;
    }

    if (todo.commands)
        list_type(FT_general, one);
    if (todo.random_generators)
        list_random_generators();
    if (todo.digest_commands)
        list_type(FT_md, one);
    if (todo.digest_algorithms)
        list_digests();
    if (todo.kdf_algorithms)
        list_kdfs();
    if (todo.mac_algorithms)
        list_macs();
    if (todo.cipher_commands)
        list_type(FT_cipher, one);
    if (todo.cipher_algorithms)
        list_ciphers();
    if (todo.serializer_algorithms)
        list_serializers();
    if (todo.deserializer_algorithms)
        list_deserializers();
    if (todo.pk_algorithms)
        list_pkey();
#ifndef OPENSSL_NO_DEPRECATED_3_0
    if (todo.pk_method)
        list_pkey_meth();
    if (todo.engines)
        list_engines();
#endif
    if (todo.disabled)
        list_disabled();
    if (todo.missing_help)
        list_missing_help();
    if (todo.objects)
        list_objects();

    if (!done)
        goto opthelp;

    return 0;
}
