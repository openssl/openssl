/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#ifdef OPENSSL_SYS_WINDOWS
# define timegm _mkgmtime
#else
# ifndef _DEFAULT_SOURCE
#  define _DEFAULT_SOURCE /* for timegm() from time.h */
# endif
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_acert.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <crypto/x509_acert.h>
#include <crypto/x509.h>

#define ATTRIBUTES         "attributes"
#define V3_EXTENSIONS      "extensions"
#define UTF8_IN            "utf8"

#define DEFAULT_KEY_LENGTH 2048
#define MIN_KEY_LENGTH     512
#define DEFAULT_DAYS       1 /* default cert validity period in days */

static int make_ACERT(X509_ACERT *acert, X509 *holder,
                      X509 *issuer, int holder_name, int holder_basecertid);
static int set_acert_validity(X509_ACERT *acert, char *notBefore,
                              char *notAfter, int days);
static int add_config_attributes(CONF *conf, X509_ACERT *acert,
                                 unsigned long chtype);

static const char *section = "acert";
static CONF *acert_conf = NULL;
static CONF *addext_conf = NULL;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE,
    OPT_NEW, OPT_CONFIG, OPT_KEYFORM, OPT_IN, OPT_OUT,
    OPT_SIGOPT, OPT_VERIFY, OPT_NOOUT, OPT_VERBOSE, OPT_UTF8,
    OPT_NAMEOPT, OPT_HOLDER, OPT_CERTOPT, OPT_TEXT,
    OPT_HOLDER_BASECERTID, OPT_HOLDER_NAME,
    OPT_AA, OPT_AAKEY, OPT_PASSIN,
    OPT_DAYS, OPT_SET_SERIAL, OPT_STARTDATE, OPT_ENDDATE,
    OPT_ADDEXT, OPT_ACERTEXTS,
    OPT_SECTION,
    OPT_PROV_ENUM, OPT_MD,
    OPT_ASSERTED_BEFORE, OPT_TARGET_CERT
} OPTION_CHOICE;

const OPTIONS acert_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"in", OPT_IN, '<', "attribute certificate input file"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"verify", OPT_VERIFY, '-', "Verify signature on the attribue certificate"},

    OPT_SECTION("Certificate"),
    {"new", OPT_NEW, '-', "New Attribute Certificate"},
    {"config", OPT_CONFIG, '<', "Attribute certificate template file"},
    {"section", OPT_SECTION, 's', "Config section to use (default \"acert\")"},
    {"utf8", OPT_UTF8, '-', "Input characters are UTF8 (default ASCII)"},
    {"nameopt", OPT_NAMEOPT, 's', "Certificate holder/issuer name printing options"},
    {"certopt", OPT_CERTOPT, 's', "Various certificate text printing options"},
    {"text", OPT_TEXT, '-', "Text form of request"},
    {"AA", OPT_AA, '<', "Attribtue authority (issuer) certificate to use"},
    {"AAkey", OPT_AAKEY, 's',
     "Attribute authority Issuer private key to use; default is -AA arg"},
    {"keyform", OPT_KEYFORM, 'f', "File format of AAkey"},
    {"passin", OPT_PASSIN, 's', "Private key and cert file pass-phrase source"},
    {"holder", OPT_HOLDER, '<', "Attribute holder certificate"},
    {"use-holder-basecertid", OPT_HOLDER_BASECERTID, '-',
     "Specify holder certificate using base certifiate id (default)"},
    {"use-holder-name", OPT_HOLDER_NAME, '-',
     "Specify holder certificate using certificate subject name"},
    {"startdate", OPT_STARTDATE, 's', "Cert notBefore, YYYYMMDDHHMMSSZ"},
    {"enddate", OPT_ENDDATE, 's',
     "YYYYMMDDHHMMSSZ cert notAfter (overrides -days)"},
    {"days", OPT_DAYS, 'p', "Number of days cert is valid for"},
    {"set_serial", OPT_SET_SERIAL, 's', "Serial number to use"},
    {"addext", OPT_ADDEXT, 's',
     "Additional cert extension key=value pair (may be given more than once)"},
    {"acertexts", OPT_ACERTEXTS, 's',
     "Attribute certificate extension section (override value in config file)"},
    {"asserted-before", OPT_ASSERTED_BEFORE, '-',
     "Fail verification if the attribute certificate contains the singleUse extension."},
    {"target-cert", OPT_TARGET_CERT, '<',
     "The target certificate path to check against the targetingInformation extension"},

    OPT_SECTION("Signing"),
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"", OPT_MD, '-', "Any supported digest, used for signing and printing"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output"},
    {"noout", OPT_NOOUT, '-', "Do not output attribute certificate"},

    OPT_PROV_OPTIONS,
    {NULL}
};

/*
 * An LHASH of strings, where each string is an extension name.
 */
static unsigned long ext_name_hash(const OPENSSL_STRING *a)
{
    return OPENSSL_LH_strhash((const char *)a);
}

static int ext_name_cmp(const OPENSSL_STRING *a, const OPENSSL_STRING *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void exts_cleanup(OPENSSL_STRING *x)
{
    OPENSSL_free((char *)x);
}

/*
 * Is the |kv| key already duplicated? This is remarkably tricky to get right.
 * Return 0 if unique, -1 on runtime error; 1 if found or a syntax error.
 */
static int duplicated(LHASH_OF(OPENSSL_STRING) *addexts, char *kv)
{
    char *p;
    size_t off;

    /* Check syntax. */
    /* Skip leading whitespace, make a copy. */
    while (*kv && isspace(*kv))
        if (*++kv == '\0')
            return 1;
    if ((p = strchr(kv, '=')) == NULL)
        return 1;
    off = p - kv;
    if ((kv = OPENSSL_strdup(kv)) == NULL)
        return -1;

    /* Skip trailing space before the equal sign. */
    for (p = kv + off; p > kv; --p)
        if (!isspace(p[-1]))
            break;
    if (p == kv) {
        OPENSSL_free(kv);
        return 1;
    }
    *p = '\0';

    /* Finally have a clean "key"; see if it's there [by attempt to add it]. */
    p = (char *)lh_OPENSSL_STRING_insert(addexts, (OPENSSL_STRING *)kv);
    if (p != NULL) {
        OPENSSL_free(p);
        return 1;
    } else if (lh_OPENSSL_STRING_error(addexts)) {
        OPENSSL_free(kv);
        return -1;
    }

    return 0;
}

int acert_main(int argc, char **argv)
{
    ASN1_INTEGER *serial = NULL;
    BIO *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *AAkey = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL, *sigopts = NULL;
    LHASH_OF(OPENSSL_STRING) *addexts = NULL;
    X509 *AAcert = NULL, *holder = NULL, *target_x509 = NULL;
    TARGET_CERT *target_cert = NULL;
    OSSL_ISSUER_SERIAL *target_iss_ser = NULL;
    GENERAL_NAME *target_cert_name = NULL;
    TARGET *target = NULL;
    X509_ACERT *acert = NULL;
    BIO *addext_bio = NULL;
    const char *infile = NULL, *AAfile = NULL, *AAkeyfile = NULL;
    const char *holderfile = NULL, *targetfile = NULL;
    int hldr_basecertid = 0, hldr_entity = 0;
    char *outfile = NULL, *digest = NULL;
    char *keyalgstr = NULL, *p, *prog;
    char *passin = NULL, *passinarg = NULL;
    char *acert_exts = NULL;
    X509_NAME *fsubj = NULL, *target_subj = NULL;
    char *template = default_config_file;
    OPTION_CHOICE o;
    int days = DEFAULT_DAYS;
    int ret = 1, i = 0, newacert = 0, verbose = 0, asserted_before = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyform = FORMAT_UNDEF;
    int verify = 0, noout = 0, text = 0;
    unsigned long chtype = MBSTRING_ASC, certflag = 0;
    char *startdate = NULL, *enddate = NULL;

    opt_set_unknown_name("digest");
    prog = opt_init(argc, argv, acert_options);

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(acert_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_NEW:
            newacert = 1;
            break;
        case OPT_CONFIG:
            template = opt_arg();
            break;
        case OPT_SECTION:
            section = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_UTF8:
            chtype = MBSTRING_UTF8;
            break;
        case OPT_NAMEOPT:
            if (!set_nameopt(opt_arg()))
                goto opthelp;
            break;
        case OPT_CERTOPT:
            if (!set_cert_ex(&certflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_HOLDER:
            holderfile = opt_arg();
            break;
        case OPT_HOLDER_BASECERTID:
            hldr_basecertid = 1;
            break;
        case OPT_HOLDER_NAME:
            hldr_entity = 1;
            break;
        case OPT_AA:
            AAfile = opt_arg();
            break;
        case OPT_AAKEY:
            AAkeyfile = opt_arg();
            break;
        case OPT_STARTDATE:
            startdate = opt_arg();
            break;
        case OPT_ENDDATE:
            enddate = opt_arg();
            break;
        case OPT_ASSERTED_BEFORE:
            asserted_before = 1;
            break;
        case OPT_TARGET_CERT:
            targetfile = opt_arg();
            break;
        case OPT_DAYS:
            days = atoi(opt_arg());
            if (days < -1) {
                BIO_printf(bio_err, "%s: -days parameter arg must be >= -1\n",
                           prog);
                goto end;
            }
            break;
        case OPT_SET_SERIAL:
            if (serial != NULL) {
                BIO_printf(bio_err, "Serial number supplied twice\n");
                goto opthelp;
            }
            serial = s2i_ASN1_INTEGER(NULL, opt_arg());
            if (serial == NULL)
                goto opthelp;
            break;
        case OPT_ADDEXT:
            p = opt_arg();
            if (addexts == NULL) {
                addexts = lh_OPENSSL_STRING_new(ext_name_hash, ext_name_cmp);
                addext_bio = BIO_new(BIO_s_mem());
                if (addexts == NULL || addext_bio == NULL)
                    goto end;
            }
            i = duplicated(addexts, p);
            if (i == 1) {
                BIO_printf(bio_err, "Duplicate extension: %s\n", p);
                goto opthelp;
            }
            if (i < 0 || BIO_printf(addext_bio, "%s\n", p) < 0)
                goto end;
            break;
        case OPT_ACERTEXTS:
            acert_exts = opt_arg();
            break;
        case OPT_MD:
            digest = opt_unknown();
            break;
        }
    }

    /* No extra arguments. */
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    if ((acert_conf = app_load_config_verbose(template, verbose)) == NULL)
        goto end;
    if (addext_bio != NULL) {
        if (verbose)
            BIO_printf(bio_err,
                       "Using additional configuration from -addext options\n");
        if ((addext_conf = app_load_config_bio(addext_bio, NULL)) == NULL)
            goto end;
    }
    if (template != default_config_file && !app_load_modules(acert_conf))
        goto end;

    if (acert_conf != NULL) {
        p = NCONF_get_string(acert_conf, NULL, "oid_file");
        if (p == NULL)
            ERR_clear_error();
        if (p != NULL) {
            BIO *oid_bio;

            oid_bio = BIO_new_file(p, "r");
            if (oid_bio == NULL) {
                if (verbose) {
                    BIO_printf(bio_err,
                               "Problems opening '%s' for extra OIDs\n", p);
                    ERR_print_errors(bio_err);
                }
            } else {
                OBJ_create_objects(oid_bio);
                BIO_free(oid_bio);
            }
        }
    }
    if (!add_oid_section(acert_conf))
        goto end;

    if (digest == NULL) {
        p = NCONF_get_string(acert_conf, section, "default_md");
        if (p == NULL)
            ERR_clear_error();
        else
            digest = p;
    }

    if (addext_conf != NULL) {
        /* Check syntax of command line extensions */
        X509V3_CTX ctx;

        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, addext_conf);
        if (!X509V3_EXT_ACERT_add_nconf(addext_conf, &ctx, "default", NULL)) {
            BIO_printf(bio_err, "Error checking extensions defined using -addext\n");
            goto end;
        }
    }

    if (chtype != MBSTRING_UTF8) {
        p = NCONF_get_string(acert_conf, section, UTF8_IN);
        if (p == NULL)
            ERR_clear_error();
        else if (strcmp(p, "yes") == 0)
            chtype = MBSTRING_UTF8;
    }

    if (acert_exts == NULL) {
        acert_exts = NCONF_get_string(acert_conf, section, V3_EXTENSIONS);
        if (acert_exts == NULL)
            ERR_clear_error();
    }
    if (acert_exts != NULL) {
        /* Check syntax of file */
        X509V3_CTX ctx;

        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, acert_conf);
        if (!X509V3_EXT_ACERT_add_nconf(acert_conf, &ctx, acert_exts, NULL)) {
            BIO_printf(bio_err,
                       "Error checking request extension section %s\n",
                       acert_exts);
            goto end;
        }
    }

    if (!newacert) {
        BIO *in;
        in = bio_open_default(infile, 'r', informat);
        if (informat == FORMAT_ASN1)
            acert = d2i_X509_ACERT_bio(in, NULL);
        else if (informat == FORMAT_PEM)
            acert = PEM_read_bio_X509_ACERT(in, NULL, NULL, NULL);
        else
            print_format_error(informat, OPT_FMT_PEMDER);

        BIO_free(in);
        if (acert == NULL)
            goto end;
    } else {
        if (AAkeyfile == NULL)
            AAkeyfile = AAfile;
        if (AAkeyfile != NULL) {
            if (AAfile == NULL) {
                BIO_printf(bio_err,
                           "Ignoring -AAkey option since -AA is not given\n");
            } else {
                if ((AAkey = load_key(AAkeyfile, FORMAT_UNDEF, 0, passin, e,
                                      "issuer private key")) == NULL)
                    goto end;
            }
        }
    }

    if (AAfile != NULL) {
        if ((AAcert = load_cert_pass(AAfile, FORMAT_UNDEF, 1, passin,
                                     "issuer certificate")) == NULL)
            goto end;
        if (AAkey && !X509_check_private_key(AAcert, AAkey)) {
            BIO_printf(bio_err,
                       "Issuer certificate and key do not match\n");
            goto end;
        }
    }

    if (holderfile) {
        if ((holder = load_cert_pass(holderfile, FORMAT_UNDEF, 1, passin,
                                     "holder certificate")) == NULL)
            goto end;
    }

    if (newacert) {
        X509V3_CTX ext_ctx;

        if (holder == NULL) {
            BIO_printf(bio_err,
                       "Must specify 'holder' to create new certificate\n");
            goto end;
        }

        if (AAcert == NULL) {
            BIO_printf(bio_err,
                       "Must specify 'AA' to create new certificate\n");
            goto end;
        }

        /* TODO: _ex variant not implented yet */
        acert = X509_ACERT_new();
        if (acert == NULL) {
            goto end;
        }

        if ((hldr_entity == 0) && (hldr_basecertid == 0))
            hldr_basecertid = 1;

        if (!make_ACERT(acert, holder, AAcert, hldr_entity, hldr_basecertid)) {
            BIO_printf(bio_err, "Error making attribute certificate\n");
            goto end;
        }

        if (serial != NULL) {
            if (!X509_ACERT_set1_serialNumber(acert, serial))
                goto end;
        } else {
            if (!rand_serial(NULL, X509_ACERT_get0_serialNumber(acert)))
                goto end;
        }

        if (!set_acert_validity(acert, startdate, enddate, days)) {
            BIO_printf(bio_err, "Invalid validity period start(%s) or end(%s)\n",
                       startdate, enddate);
            goto end;
        }

        /* Set up V3 context struct */
        X509V3_set_ctx(&ext_ctx, AAcert,
                       NULL, NULL, NULL, X509V3_CTX_REPLACE);

        if (acert_exts != NULL
            && !X509V3_EXT_ACERT_add_nconf(acert_conf, &ext_ctx,
                                           acert_exts, acert)) {
            BIO_printf(bio_err, "Error adding extensions from section %s\n",
                       acert_exts);
            goto end;
        }

        if (addext_conf != NULL
            && !X509V3_EXT_ACERT_add_nconf(addext_conf, &ext_ctx, "default",
                                           acert)) {
            BIO_printf(bio_err, "Error adding extensions defined via -addext\n");
            goto end;
        }

        if (!add_config_attributes(acert_conf, acert, chtype))
            goto end;

        if (!do_X509_ACERT_sign(acert, AAkey, digest, sigopts))
            goto end;
    }

    if (verify) {
        if (targetfile) {
            if ((target_x509 = load_cert_pass(targetfile, FORMAT_UNDEF, 1, passin,
                                        "target certificate")) == NULL)
                goto end;
            target_iss_ser = OSSL_ISSUER_SERIAL_new();
            if (OSSL_ISSUER_SERIAL_set1_issuer(target_iss_ser, X509_get_issuer_name(target_x509)) == 0)
                goto end;
            if (OSSL_ISSUER_SERIAL_set1_serial(target_iss_ser, X509_get_serialNumber(target_x509)) == 0)
                goto end;

            target_cert_name = GENERAL_NAME_new();
            target_subj = X509_NAME_dup(X509_get_subject_name(target_x509));
            if (target_subj == NULL)
                goto end;
            GENERAL_NAME_set0_value(target_cert_name, GEN_DIRNAME, target_subj);
            target_cert = TARGET_CERT_new();
            target_cert->targetCertificate = target_iss_ser;
            target_cert->targetName = target_cert_name;
            target = TARGET_new();
            target->type = TGT_TARGET_CERT;
            target->choice.targetCert = target_cert;
        }
        ret = X509_attr_cert_verify_ex(acert, AAcert, holder, target, asserted_before);
        if (ret != X509_V_OK) {
            BIO_printf(bio_err, "Attribute certificate is invalid.\n");
            goto end;
        } else {
            BIO_printf(bio_err, "Attribute certificate is valid.\n");
        }
    }

    if (noout && !text) {
        ret = 0;
        goto end;
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (text) {
        ret = X509_ACERT_print_ex(out, acert, get_nameopt(), certflag);
        if (ret == 0) {
            BIO_printf(bio_err, "Error printing attribute certificate\n");
        }
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_ACERT_bio(out, acert);
        else
            i = PEM_write_bio_X509_ACERT(out, acert);
        if (!i) {
            BIO_printf(bio_err, "Unable to write attribute certificate\n");
            goto end;
        }
    }
    ret = 0;
 end:
    if (ret) {
        ERR_print_errors(bio_err);
    }
    NCONF_free(acert_conf);
    NCONF_free(addext_conf);
    BIO_free(addext_bio);
    BIO_free_all(out);
    EVP_PKEY_CTX_free(genctx);
    sk_OPENSSL_STRING_free(pkeyopts);
    sk_OPENSSL_STRING_free(sigopts);
    lh_OPENSSL_STRING_doall(addexts, exts_cleanup);
    lh_OPENSSL_STRING_free(addexts);
    OPENSSL_free(keyalgstr);
    X509_ACERT_free(acert);
    X509_NAME_free(fsubj);
    X509_free(holder);
    X509_free(AAcert);
    EVP_PKEY_free(AAkey);
    ASN1_INTEGER_free(serial);
    release_engine(e);
    return ret;
}

static int add_config_attributes(CONF *conf, X509_ACERT *acert,
                                 unsigned long chtype)
{
    char *attr_sect;
    attr_sect = NCONF_get_string(conf, section, ATTRIBUTES);
    if (attr_sect == NULL) {
        ERR_clear_error();
        return 1;
    }

    if (!X509_ACERT_add_attr_nconf(conf, attr_sect, chtype, acert)) {
        BIO_printf(bio_err,
                   "Unable to add attributes from section '%s'\n", attr_sect);
        return 0;
    }
    return 1;
}

static int make_ACERT(X509_ACERT *acert, X509 *holder,
                      X509 *issuer, int holder_name, int holder_basecertid)
{
    int ret = 0;
    OSSL_ISSUER_SERIAL *isss = NULL;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name = NULL;
    X509_NAME *holder_subj = NULL;

    if (!X509_ACERT_set_version(acert, X509_ACERT_VERSION_2))
        goto err;

    if (holder_basecertid == 1) {
        isss = OSSL_ISSUER_SERIAL_new();
        if (OSSL_ISSUER_SERIAL_set1_issuer(isss, X509_get_issuer_name(holder)) == 0)
            goto err;

        if (OSSL_ISSUER_SERIAL_set1_serial(isss, X509_get_serialNumber(holder)) == 0)
            goto err;

        X509_ACERT_set0_holder_baseCertId(acert, isss);
    }

    if (holder_name == 1) {
        holder_subj = X509_NAME_dup(X509_get_subject_name(holder));
        if (holder_subj == NULL)
            goto err;

        names = sk_GENERAL_NAME_new_null();
        if (names == NULL)
            goto err;

        name = GENERAL_NAME_new();
        if (name == NULL)
            goto err;

        if (sk_GENERAL_NAME_push(names, name) <= 0)
            goto err;

        GENERAL_NAME_set0_value(name, GEN_DIRNAME, holder_subj);
        X509_ACERT_set0_holder_entityName(acert, names);
    }

    if (X509_ACERT_set1_issuerName(acert, X509_get_subject_name(issuer)) == 0)
        goto err;

    return 1;
 err:
    OSSL_ISSUER_SERIAL_free(isss);
    GENERAL_NAME_free(name);
    GENERAL_NAMES_free(names);
    X509_NAME_free(holder_subj);
    return ret;
}

static int set_acert_validity(X509_ACERT *acert, char *notBefore,
                              char *notAfter, int days)
{
    int ret = 0;
    ASN1_GENERALIZEDTIME *tmp_time;

    tmp_time = ASN1_GENERALIZEDTIME_new();
    if (tmp_time == NULL)
        return 0;

    if (notBefore) {
        if (!ASN1_GENERALIZEDTIME_set_string(tmp_time, notBefore))
            goto err;
    } else {
        time_t now = time(NULL);
        if (!ASN1_GENERALIZEDTIME_set(tmp_time, now))
            goto err;
    }
    X509_ACERT_set1_notBefore(acert, tmp_time);

    if (notAfter) {
        if (!ASN1_GENERALIZEDTIME_set_string(tmp_time, notAfter))
            goto err;
    } else {
        struct tm tm;
        time_t start_tm;
        ASN1_TIME_to_tm(tmp_time, &tm);
        start_tm = timegm(&tm);
        if (!X509_time_adj_ex(tmp_time, days, 0, &start_tm))
            goto err;
    }
    X509_ACERT_set1_notAfter(acert, tmp_time);

    ret = 1;
err:
    ASN1_GENERALIZEDTIME_free(tmp_time);
    return ret;
}