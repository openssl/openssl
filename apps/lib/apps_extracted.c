/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#ifndef W_OK
# ifdef OPENSSL_SYS_VMS
#  include <unistd.h>
# elif !defined(OPENSSL_SYS_VXWORKS) && !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_TANDEM)
#  include <sys/file.h>
# endif
#endif

#include "apps.h"
#include "apps_config.h"
#include "apps_propq.h"

static BIO *bio_open_default_(const char *filename, char mode, int format,
                              int quiet);
#define PASS_SOURCE_SIZE_MAX 4

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;

static OSSL_LIB_CTX *app_libctx = NULL;

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);
static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);

static unsigned long nmflag = 0;
static char nmflag_set = 0;

int set_nameopt(const char *arg)
{
    int ret = set_name_ex(&nmflag, arg);

    if (ret)
        nmflag_set = 1;

    return ret;
}

unsigned long get_nameopt(void)
{
    return (nmflag_set) ? nmflag : XN_FLAG_ONELINE;
}

static char *app_get_pass(const char *arg, int keepbio);

int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2)
{
    int same = arg1 != NULL && arg2 != NULL && strcmp(arg1, arg2) == 0;

    if (arg1 != NULL) {
        *pass1 = app_get_pass(arg1, same);
        if (*pass1 == NULL)
            return 0;
    } else if (pass1 != NULL) {
        *pass1 = NULL;
    }
    if (arg2 != NULL) {
        *pass2 = app_get_pass(arg2, same ? 2 : 0);
        if (*pass2 == NULL)
            return 0;
    } else if (pass2 != NULL) {
        *pass2 = NULL;
    }
    return 1;
}

static char *app_get_pass(const char *arg, int keepbio)
{
    static BIO *pwdbio = NULL;
    char *tmp, tpass[APP_PASS_LEN];
    int i;

    /* PASS_SOURCE_SIZE_MAX = max number of chars before ':' in below strings */
    if (strncmp(arg, "pass:", 5) == 0)
        return OPENSSL_strdup(arg + 5);
    if (strncmp(arg, "env:", 4) == 0) {
        tmp = getenv(arg + 4);
        if (tmp == NULL) {
            BIO_printf(bio_err, "No environment variable %s\n", arg + 4);
            return NULL;
        }
        return OPENSSL_strdup(tmp);
    }
    if (!keepbio || pwdbio == NULL) {
        if (strncmp(arg, "file:", 5) == 0) {
            pwdbio = BIO_new_file(arg + 5, "r");
            if (pwdbio == NULL) {
                BIO_printf(bio_err, "Can't open file %s\n", arg + 5);
                return NULL;
            }
#if !defined(_WIN32)
            /*
             * Under _WIN32, which covers even Win64 and CE, file
             * descriptors referenced by BIO_s_fd are not inherited
             * by child process and therefore below is not an option.
             * It could have been an option if bss_fd.c was operating
             * on real Windows descriptors, such as those obtained
             * with CreateFile.
             */
        } else if (strncmp(arg, "fd:", 3) == 0) {
            BIO *btmp;
            i = atoi(arg + 3);
            if (i >= 0)
                pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
            if ((i < 0) || !pwdbio) {
                BIO_printf(bio_err, "Can't access file descriptor %s\n", arg + 3);
                return NULL;
            }
            /*
             * Can't do BIO_gets on an fd BIO so add a buffering BIO
             */
            btmp = BIO_new(BIO_f_buffer());
            pwdbio = BIO_push(btmp, pwdbio);
#endif
        } else if (strcmp(arg, "stdin") == 0) {
            pwdbio = dup_bio_in(FORMAT_TEXT);
            if (pwdbio == NULL) {
                BIO_printf(bio_err, "Can't open BIO for stdin\n");
                return NULL;
            }
        } else {
            /* argument syntax error; do not reveal too much about arg */
            tmp = strchr(arg, ':');
            if (tmp == NULL || tmp - arg > PASS_SOURCE_SIZE_MAX)
                BIO_printf(bio_err,
                           "Invalid password argument, missing ':' within the first %d chars\n",
                           PASS_SOURCE_SIZE_MAX + 1);
            else
                BIO_printf(bio_err,
                           "Invalid password argument, starting with \"%.*s\"\n",
                           (int)(tmp - arg + 1), arg);
            return NULL;
        }
    }
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    if (keepbio != 1) {
        BIO_free_all(pwdbio);
        pwdbio = NULL;
    }
    if (i <= 0) {
        BIO_printf(bio_err, "Error reading password from BIO\n");
        return NULL;
    }
    tmp = strchr(tpass, '\n');
    if (tmp != NULL)
        *tmp = 0;
    return OPENSSL_strdup(tpass);
}

OSSL_LIB_CTX *app_get0_libctx(void)
{
    return app_libctx;
}

//static const char *app_propq = NULL;
//
//int app_set_propq(const char *arg)
//{
//    app_propq = arg;
//    return 1;
//}
//
//const char *app_get0_propq(void)
//{
//    return app_propq;
//}

OSSL_LIB_CTX *app_create_libctx(void)
{
    /*
     * Load the NULL provider into the default library context and create a
     * library context which will then be used for any OPT_PROV options.
     */
    if (app_libctx == NULL) {

        if (!app_provider_load(NULL, "null")) {
            BIO_puts(bio_err, "Failed to create null provider\n");
            return NULL;
        }
        app_libctx = OSSL_LIB_CTX_new();
    }
    if (app_libctx == NULL)
        BIO_puts(bio_err, "Failed to create library context\n");
    return app_libctx;
}

CONF *app_load_config_bio(BIO *in, const char *filename)
{
    long errorline = -1;
    CONF *conf;
    int i;

    conf = NCONF_new_ex(app_libctx, NULL);
    i = NCONF_load_bio(conf, in, &errorline);
    if (i > 0)
        return conf;

    if (errorline <= 0) {
        BIO_printf(bio_err, "%s: Can't load ", opt_getprog());
    } else {
        BIO_printf(bio_err, "%s: Error on line %ld of ", opt_getprog(),
                   errorline);
    }
    if (filename != NULL)
        BIO_printf(bio_err, "config file \"%s\"\n", filename);
    else
        BIO_printf(bio_err, "config input");

    NCONF_free(conf);
    return NULL;
}

CONF *app_load_config_verbose(const char *filename, int verbose)
{
    if (verbose) {
        if (*filename == '\0')
            BIO_printf(bio_err, "No configuration used\n");
        else
            BIO_printf(bio_err, "Using configuration from %s\n", filename);
    }
    return app_load_config_internal(filename, 0);
}

CONF *app_load_config_internal(const char *filename, int quiet)
{
    BIO *in = NULL; /* leads to empty config in case filename == "" */
    CONF *conf;

    if (*filename != '\0'
        && (in = bio_open_default_(filename, 'r', FORMAT_TEXT, quiet)) == NULL)
        return NULL;
    conf = app_load_config_bio(in, filename);
    BIO_free(in);
    return conf;
}

int app_load_modules(const CONF *config)
{
    CONF *to_free = NULL;

    if (config == NULL)
        config = to_free = app_load_config_quiet(default_config_file);
    if (config == NULL)
        return 1;

    if (CONF_modules_load(config, NULL, 0) <= 0) {
        BIO_printf(bio_err, "Error configuring OpenSSL modules\n");
        ERR_print_errors(bio_err);
        NCONF_free(to_free);
        return 0;
    }
    NCONF_free(to_free);
    return 1;
}

int add_oid_section(CONF *conf)
{
    char *p;
    STACK_OF(CONF_VALUE) *sktmp;
    CONF_VALUE *cnf;
    int i;

    if ((p = NCONF_get_string(conf, NULL, "oid_section")) == NULL) {
        ERR_clear_error();
        return 1;
    }
    if ((sktmp = NCONF_get_section(conf, p)) == NULL) {
        BIO_printf(bio_err, "problem loading oid section %s\n", p);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
        cnf = sk_CONF_VALUE_value(sktmp, i);
        if (OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
            BIO_printf(bio_err, "problem creating object %s=%s\n",
                       cnf->name, cnf->value);
            return 0;
        }
    }
    return 1;
}

#define IS_HTTP(uri) ((uri) != NULL \
        && strncmp(uri, OSSL_HTTP_PREFIX, strlen(OSSL_HTTP_PREFIX)) == 0)
#define IS_HTTPS(uri) ((uri) != NULL \
        && strncmp(uri, OSSL_HTTPS_PREFIX, strlen(OSSL_HTTPS_PREFIX)) == 0)

X509 *load_cert_pass(const char *uri, int maybe_stdin,
                     const char *pass, const char *desc)
{
    X509 *cert = NULL;

    if (desc == NULL)
        desc = "certificate";
    if (IS_HTTPS(uri))
        BIO_printf(bio_err, "Loading %s over HTTPS is unsupported\n", desc);
    else if (IS_HTTP(uri))
        cert = X509_load_http(uri, NULL, NULL, 0 /* timeout */);
    else
        (void)load_key_certs_crls(uri, maybe_stdin, pass, desc,
                                  NULL, NULL, NULL, &cert, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Unable to load %s\n", desc);
        ERR_print_errors(bio_err);
    }
    return cert;
}

X509_CRL *load_crl(const char *uri, const char *desc)
{
    X509_CRL *crl = NULL;

    if (desc == NULL)
        desc = "CRL";
    if (IS_HTTPS(uri))
        BIO_printf(bio_err, "Loading %s over HTTPS is unsupported\n", desc);
    else if (IS_HTTP(uri))
        crl = X509_CRL_load_http(uri, NULL, NULL, 0 /* timeout */);
    else
        (void)load_key_certs_crls(uri, 0, NULL, desc,
                                  NULL, NULL,  NULL, NULL, NULL, &crl, NULL);
    if (crl == NULL) {
        BIO_printf(bio_err, "Unable to load %s\n", desc);
        ERR_print_errors(bio_err);
    }
    return crl;
}

X509_REQ *load_csr(const char *file, int format, const char *desc)
{
    X509_REQ *req = NULL;
    BIO *in;

    if (desc == NULL)
        desc = "CSR";
    in = bio_open_default(file, 'r', format);
    if (in == NULL)
        goto end;

    if (format == FORMAT_ASN1)
        req = d2i_X509_REQ_bio(in, NULL);
    else if (format == FORMAT_PEM)
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    else
        print_format_error(format, OPT_FMT_PEMDER);

 end:
    if (req == NULL) {
        BIO_printf(bio_err, "Unable to load %s\n", desc);
        ERR_print_errors(bio_err);
    }
    BIO_free(in);
    return req;
}

void cleanse(char *str)
{
    if (str != NULL)
        OPENSSL_cleanse(str, strlen(str));
}

EVP_PKEY *load_key(const char *uri, int format, int may_stdin,
                   const char *pass, ENGINE *e, const char *desc)
{
    EVP_PKEY *pkey = NULL;
    char *allocated_uri = NULL;

    if (desc == NULL)
        desc = "private key";

    if (format == FORMAT_ENGINE) {
        uri = allocated_uri = make_engine_uri(e, uri, desc);
    }
    (void)load_key_certs_crls(uri, may_stdin, pass, desc,
                              &pkey, NULL, NULL, NULL, NULL, NULL, NULL);

    OPENSSL_free(allocated_uri);
    return pkey;
}

/*
 * Load those types of credentials for which the result pointer is not NULL.
 * Reads from stdio if uri is NULL and maybe_stdin is nonzero.
 * For non-NULL ppkey, pcert, and pcrl the first suitable value found is loaded.
 * If pcerts is non-NULL and *pcerts == NULL then a new cert list is allocated.
 * If pcerts is non-NULL then all available certificates are appended to *pcerts
 * except any certificate assigned to *pcert.
 * If pcrls is non-NULL and *pcrls == NULL then a new list of CRLs is allocated.
 * If pcrls is non-NULL then all available CRLs are appended to *pcerts
 * except any CRL assigned to *pcrl.
 * In any case (also on error) the caller is responsible for freeing all members
 * of *pcerts and *pcrls (as far as they are not NULL).
 */
int load_key_certs_crls(const char *uri, int maybe_stdin,
                        const char *pass, const char *desc,
                        EVP_PKEY **ppkey, EVP_PKEY **ppubkey,
                        EVP_PKEY **pparams,
                        X509 **pcert, STACK_OF(X509) **pcerts,
                        X509_CRL **pcrl, STACK_OF(X509_CRL) **pcrls)
{
    PW_CB_DATA uidata;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_LIB_CTX *libctx = app_get0_libctx();
    const char *propq = app_get0_propq();
    int ncerts = 0;
    int ncrls = 0;
    const char *failed =
        ppkey != NULL ? "key" : ppubkey != NULL ? "public key" :
        pparams != NULL ? "params" : pcert != NULL ? "cert" :
        pcrl != NULL ? "CRL" : pcerts != NULL ? "certs" :
        pcrls != NULL ? "CRLs" : NULL;
    int cnt_expectations = 0;
    int expect = 0;
    /* TODO make use of the engine reference 'eng' when loading pkeys */

    if (ppkey != NULL) {
        *ppkey = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_PKEY;
    }
    if (ppubkey != NULL) {
        *ppubkey = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_PUBKEY;
    }
    if (pcert != NULL) {
        *pcert = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CERT;
    }
    if (failed == NULL) {
        BIO_printf(bio_err, "Internal error: nothing to load into from %s\n",
                   uri != NULL ? uri : "<stdin>");
        return 0;
    }

    if (pcerts != NULL) {
        if (*pcerts == NULL && (*pcerts = sk_X509_new_null()) == NULL) {
            BIO_printf(bio_err, "Out of memory loading");
            goto end;
        }
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CERT;
    }
    if (pcrl != NULL) {
        *pcrl = NULL;
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CRL;
    }
    if (pcrls != NULL) {
        if (*pcrls == NULL && (*pcrls = sk_X509_CRL_new_null()) == NULL) {
            BIO_printf(bio_err, "Out of memory loading");
            goto end;
        }
        cnt_expectations++;
        expect = OSSL_STORE_INFO_CRL;
    }

    uidata.password = pass;
    uidata.prompt_info = uri;

    if (uri == NULL) {
        BIO *bio;

        if (!maybe_stdin) {
            BIO_printf(bio_err, "No filename or uri specified for loading");
            goto end;
        }
        uri = "<stdin>";
        unbuffer(stdin);
        bio = BIO_new_fp(stdin, 0);
        if (bio != NULL)
            ctx = OSSL_STORE_attach(bio, "file", libctx, propq,
                                    get_ui_method(), &uidata, NULL, NULL);
    } else {
        ctx = OSSL_STORE_open_ex(uri, libctx, propq, get_ui_method(), &uidata,
                                 NULL, NULL);
    }
    if (ctx == NULL) {
        BIO_printf(bio_err, "Could not open file or uri for loading");
        goto end;
    }

    if (cnt_expectations != 1)
        expect = 0;
    if (!OSSL_STORE_expect(ctx, expect))
        goto end;

    failed = NULL;
    while (!OSSL_STORE_eof(ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        int type, ok = 1;

        /*
         * This can happen (for example) if we attempt to load a file with
         * multiple different types of things in it - but the thing we just
         * tried to load wasn't one of the ones we wanted, e.g. if we're trying
         * to load a certificate but the file has both the private key and the
         * certificate in it. We just retry until eof.
         */
        if (info == NULL) {
            if (OSSL_STORE_error(ctx)) {
                ERR_print_errors(bio_err);
                ERR_clear_error();
            }
            continue;
        }

        type = OSSL_STORE_INFO_get_type(info);
        switch (type) {
        case OSSL_STORE_INFO_PKEY:
            if (ppkey != NULL && *ppkey == NULL)
                ok = (*ppkey = OSSL_STORE_INFO_get1_PKEY(info)) != NULL;

            /*
             * An EVP_PKEY with private parts also holds the public parts,
             * so if the caller asked for a public key, and we got a private
             * key, we can still pass it back.
             */
            if (ok && ppubkey != NULL && *ppubkey == NULL)
                ok = ((*ppubkey = OSSL_STORE_INFO_get1_PKEY(info)) != NULL);
            break;
        case OSSL_STORE_INFO_PUBKEY:
            if (ppubkey != NULL && *ppubkey == NULL)
                ok = ((*ppubkey = OSSL_STORE_INFO_get1_PUBKEY(info)) != NULL);
            break;
        case OSSL_STORE_INFO_PARAMS:
            if (pparams != NULL && *pparams == NULL)
                ok = ((*pparams = OSSL_STORE_INFO_get1_PARAMS(info)) != NULL);
            break;
        case OSSL_STORE_INFO_CERT:
            if (pcert != NULL && *pcert == NULL)
                ok = (*pcert = OSSL_STORE_INFO_get1_CERT(info)) != NULL;
            else if (pcerts != NULL)
                ok = X509_add_cert(*pcerts,
                                   OSSL_STORE_INFO_get1_CERT(info),
                                   X509_ADD_FLAG_DEFAULT);
            ncerts += ok;
            break;
        case OSSL_STORE_INFO_CRL:
            if (pcrl != NULL && *pcrl == NULL)
                ok = (*pcrl = OSSL_STORE_INFO_get1_CRL(info)) != NULL;
            else if (pcrls != NULL)
                ok = sk_X509_CRL_push(*pcrls, OSSL_STORE_INFO_get1_CRL(info));
            ncrls += ok;
            break;
        default:
            /* skip any other type */
            break;
        }
        OSSL_STORE_INFO_free(info);
        if (!ok) {
            failed = info == NULL ? NULL : OSSL_STORE_INFO_type_string(type);
            BIO_printf(bio_err, "Error reading");
            break;
        }
    }

 end:
    OSSL_STORE_close(ctx);
    if (failed == NULL) {
        int any = 0;

        if ((ppkey != NULL && *ppkey == NULL)
            || (ppubkey != NULL && *ppubkey == NULL)) {
            failed = "key";
        } else if (pparams != NULL && *pparams == NULL) {
            failed = "params";
        } else if ((pcert != NULL || pcerts != NULL) && ncerts == 0) {
            if (pcert == NULL)
                any = 1;
            failed = "cert";
        } else if ((pcrl != NULL || pcrls != NULL) && ncrls == 0) {
            if (pcrl == NULL)
                any = 1;
            failed = "CRL";
        }
        if (failed != NULL)
            BIO_printf(bio_err, "Could not read");
        if (any)
            BIO_printf(bio_err, " any");
    }
    if (failed != NULL) {
        if (desc != NULL && strstr(desc, failed) != NULL) {
            BIO_printf(bio_err, " %s", desc);
        } else {
            BIO_printf(bio_err, " %s", failed);
            if (desc != NULL)
                BIO_printf(bio_err, " of %s", desc);
        }
        if (uri != NULL)
            BIO_printf(bio_err, " from %s", uri);
        BIO_printf(bio_err, "\n");
        ERR_print_errors(bio_err);
    }
    return failed == NULL;
}

#define X509V3_EXT_UNKNOWN_MASK         (0xfL << 16)
/* Return error for unknown extensions */
#define X509V3_EXT_DEFAULT              0
/* Print error for unknown extensions */
#define X509V3_EXT_ERROR_UNKNOWN        (1L << 16)
/* ASN1 parse unknown extensions */
#define X509V3_EXT_PARSE_UNKNOWN        (2L << 16)
/* BIO_dump unknown extensions */
#define X509V3_EXT_DUMP_UNKNOWN         (3L << 16)

#define X509_FLAG_CA (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | \
                         X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION)

int set_cert_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL cert_tbl[] = {
        {"compatible", X509_FLAG_COMPAT, 0xffffffffl},
        {"ca_default", X509_FLAG_CA, 0xffffffffl},
        {"no_header", X509_FLAG_NO_HEADER, 0},
        {"no_version", X509_FLAG_NO_VERSION, 0},
        {"no_serial", X509_FLAG_NO_SERIAL, 0},
        {"no_signame", X509_FLAG_NO_SIGNAME, 0},
        {"no_validity", X509_FLAG_NO_VALIDITY, 0},
        {"no_subject", X509_FLAG_NO_SUBJECT, 0},
        {"no_issuer", X509_FLAG_NO_ISSUER, 0},
        {"no_pubkey", X509_FLAG_NO_PUBKEY, 0},
        {"no_extensions", X509_FLAG_NO_EXTENSIONS, 0},
        {"no_sigdump", X509_FLAG_NO_SIGDUMP, 0},
        {"no_aux", X509_FLAG_NO_AUX, 0},
        {"no_attributes", X509_FLAG_NO_ATTRIBUTES, 0},
        {"ext_default", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK},
        {"ext_error", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"ext_parse", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"ext_dump", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {NULL, 0, 0}
    };
    return set_multi_opts(flags, arg, cert_tbl);
}

int set_name_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL ex_tbl[] = {
        {"esc_2253", ASN1_STRFLGS_ESC_2253, 0},
        {"esc_2254", ASN1_STRFLGS_ESC_2254, 0},
        {"esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
        {"esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
        {"use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
        {"utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
        {"ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
        {"show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
        {"dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
        {"dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
        {"dump_der", ASN1_STRFLGS_DUMP_DER, 0},
        {"compat", XN_FLAG_COMPAT, 0xffffffffL},
        {"sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
        {"sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
        {"dn_rev", XN_FLAG_DN_REV, 0},
        {"nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
        {"sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
        {"lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
        {"align", XN_FLAG_FN_ALIGN, 0},
        {"oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
        {"space_eq", XN_FLAG_SPC_EQ, 0},
        {"dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
        {"RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
        {"oneline", XN_FLAG_ONELINE, 0xffffffffL},
        {"multiline", XN_FLAG_MULTILINE, 0xffffffffL},
        {"ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
        {NULL, 0, 0}
    };
    if (set_multi_opts(flags, arg, ex_tbl) == 0)
        return 0;
    if (*flags != XN_FLAG_COMPAT
        && (*flags & XN_FLAG_SEP_MASK) == 0)
        *flags |= XN_FLAG_SEP_CPLUS_SPC;
    return 1;
}

int set_ext_copy(int *copy_type, const char *arg)
{
    if (strcasecmp(arg, "none") == 0)
        *copy_type = EXT_COPY_NONE;
    else if (strcasecmp(arg, "copy") == 0)
        *copy_type = EXT_COPY_ADD;
    else if (strcasecmp(arg, "copyall") == 0)
        *copy_type = EXT_COPY_ALL;
    else
        return 0;
    return 1;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts;
    int i, ret = 0;

    if (x == NULL || req == NULL)
        return 0;
    if (copy_type == EXT_COPY_NONE)
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        int idx = X509_get_ext_by_OBJ(x, obj, -1);

        /* Does extension exist in target? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                X509_EXTENSION_free(X509_delete_ext(x, idx));
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }
    ret = 1;

 end:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return ret;
}

static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *val;
    int i, ret = 1;
    if (!arg)
        return 0;
    vals = X509V3_parse_list(arg);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        val = sk_CONF_VALUE_value(vals, i);
        if (!set_table_opts(flags, val->name, in_tbl))
            ret = 0;
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return ret;
}

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    char c;
    const NAME_EX_TBL *ptbl;
    c = arg[0];

    if (c == '-') {
        c = 0;
        arg++;
    } else if (c == '+') {
        c = 1;
        arg++;
    } else {
        c = 1;
    }

    for (ptbl = in_tbl; ptbl->name; ptbl++) {
        if (strcasecmp(arg, ptbl->name) == 0) {
            *flags &= ~ptbl->mask;
            if (c)
                *flags |= ptbl->flag;
            else
                *flags &= ~ptbl->flag;
            return 1;
        }
    }
    return 0;
}

int parse_yesno(const char *str, int def)
{
    if (str) {
        switch (*str) {
        case 'f':              /* false */
        case 'F':              /* FALSE */
        case 'n':              /* no */
        case 'N':              /* NO */
        case '0':              /* 0 */
            return 0;
        case 't':              /* true */
        case 'T':              /* TRUE */
        case 'y':              /* yes */
        case 'Y':              /* YES */
        case '1':              /* 1 */
            return 1;
        }
    }
    return def;
}

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where + can be used instead of / to form multi-valued RDNs if canmulti
 * and characters may be escaped by \
 */
X509_NAME *parse_name(const char *cp, int chtype, int canmulti,
                      const char *desc)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "%s: %s name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   opt_getprog(), desc, --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL) {
        BIO_printf(bio_err, "%s: Out of memory\n", opt_getprog());
        return NULL;
    }
    work = OPENSSL_strdup(cp);
    if (work == NULL) {
        BIO_printf(bio_err, "%s: Error copying %s name input\n",
                   opt_getprog(), desc);
        goto err;
    }

    while (*cp != '\0') {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp != '\0' && *cp != '=')
            *bp++ = *cp++;
        *bp++ = '\0';
        if (*cp == '\0') {
            BIO_printf(bio_err,
                       "%s: Missing '=' after RDN type string '%s' in %s name string\n",
                       opt_getprog(), typestr, desc);
            goto err;
        }
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp != '\0' && *cp != '/'; *bp++ = *cp++) {
            /* unescaped '+' symbol string signals further member of multiRDN */
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                BIO_printf(bio_err,
                           "%s: Escape character at end of %s name string\n",
                           opt_getprog(), desc);
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp != '\0')
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(bio_err,
                       "%s: Skipping unknown %s name attribute \"%s\"\n",
                       opt_getprog(), desc, typestr);
            if (ismulti)
                BIO_printf(bio_err,
                           "Hint: a '+' in a value string needs be escaped using '\\' else a new member of a multi-valued RDN is expected\n");
            continue;
        }
        if (*valstr == '\0') {
            BIO_printf(bio_err,
                       "%s: No value provided for %s name attribute \"%s\", skipped\n",
                       opt_getprog(), desc, typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0)) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err,
                       "%s: Error adding %s name attribute \"/%s=%s\"\n",
                       opt_getprog(), desc, typestr ,valstr);
            goto err;
        }
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv = 0;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp == NULL)
        goto err;

    *vtmp = 0;
    vtmp++;
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);

 err:
    OPENSSL_free(stmp);
    return rv;
}

static int do_pkey_ctx_init(EVP_PKEY_CTX *pkctx, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (pkey_ctrl_string(pkctx, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

static int do_x509_init(X509 *x, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (x509_ctrl_string(x, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

static int do_x509_req_init(X509_REQ *x, STACK_OF(OPENSSL_STRING) *opts)
{
    int i;

    if (opts == NULL)
        return 1;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);
        if (x509_req_ctrl_string(x, opt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", opt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }

    return 1;
}

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int def_nid;

    if (ctx == NULL)
        return 0;
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
            && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    return EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey)
        && do_pkey_ctx_init(pkctx, sigopts);
}

static int adapt_keyid_ext(X509 *cert, X509V3_CTX *ext_ctx,
                           const char *name, const char *value, int add_default)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    X509_EXTENSION *new_ext = X509V3_EXT_nconf(NULL, ext_ctx, name, value);
    int idx, rv = 0;

    if (new_ext == NULL)
        return rv;

    idx = X509v3_get_ext_by_OBJ(exts, X509_EXTENSION_get_object(new_ext), -1);
    if (idx >= 0) {
        X509_EXTENSION *found_ext = X509v3_get_ext(exts, idx);
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(found_ext);
        int disabled = ASN1_STRING_length(data) <= 2; /* config said "none" */

        if (disabled) {
            X509_delete_ext(cert, idx);
            X509_EXTENSION_free(found_ext);
        } /* else keep existing key identifier, which might be outdated */
        rv = 1;
    } else  {
        rv = !add_default || X509_add_ext(cert, new_ext, -1);
    }
    X509_EXTENSION_free(new_ext);
    return rv;
}

/* Ensure RFC 5280 compliance, adapt keyIDs as needed, and sign the cert info */
int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts, X509V3_CTX *ext_ctx)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int self_sign;
    int rv = 0;

    if (sk_X509_EXTENSION_num(exts /* may be NULL */) > 0) {
        /* Prevent X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 */
        if (!X509_set_version(cert, 2)) /* Make sure cert is X509 v3 */
            goto end;

        /*
         * Add default SKID before such that default AKID can make use of it
         * in case the certificate is self-signed
         */
        /* Prevent X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER */
        if (!adapt_keyid_ext(cert, ext_ctx, "subjectKeyIdentifier", "hash", 1))
            goto end;
        /* Prevent X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER */
        ERR_set_mark();
        self_sign = X509_check_private_key(cert, pkey);
        ERR_pop_to_mark();
        if (!adapt_keyid_ext(cert, ext_ctx, "authorityKeyIdentifier",
                             "keyid, issuer", !self_sign))
            goto end;

        /* TODO any further measures for ensuring default RFC 5280 compliance */
    }

    if (mctx != NULL && do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_sign_ctx(cert, mctx) > 0);
 end:
    EVP_MD_CTX_free(mctx);
    return rv;
}

/* Sign the certificate request info */
int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv = 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if (do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_REQ_sign_ctx(x, mctx) > 0);
    EVP_MD_CTX_free(mctx);
    return rv;
}

/* Sign the CRL info */
int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv = 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if (do_sign_init(mctx, pkey, md, sigopts) > 0)
        rv = (X509_CRL_sign_ctx(x, mctx) > 0);
    EVP_MD_CTX_free(mctx);
    return rv;
}

int do_X509_verify(X509 *x, EVP_PKEY *pkey, STACK_OF(OPENSSL_STRING) *vfyopts)
{
    int rv = 0;

    if (do_x509_init(x, vfyopts) > 0)
        rv = (X509_verify(x, pkey) > 0);
    return rv;
}

int do_X509_REQ_verify(X509_REQ *x, EVP_PKEY *pkey,
                       STACK_OF(OPENSSL_STRING) *vfyopts)
{
    int rv = 0;

    if (do_x509_req_init(x, vfyopts) > 0)
        rv = (X509_REQ_verify(x, pkey) > 0);
    return rv;
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            const char *uptr = (const char *)ASN1_STRING_get0_data(uri);

            if (IS_HTTP(uptr)) /* can/should not use HTTPS here */
                return uptr;
        }
    }
    return NULL;
}

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr)
            return load_crl(urlptr, "CRL via CDP");
    }
    return NULL;
}

/*
 * Example of downloading CRLs from CRLDP:
 * not usable for real world as it always downloads and doesn't cache anything.
 */

static STACK_OF(X509_CRL) *crls_http_cb(const X509_STORE_CTX *ctx,
                                        const X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;

    crls = sk_X509_CRL_new_null();
    if (!crls)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl) {
        sk_X509_CRL_free(crls);
        return NULL;
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

void store_setup_crl_download(X509_STORE *st)
{
    X509_STORE_set_lookup_crls_cb(st, crls_http_cb);
}

int app_isdir(const char *name)
{
    return opt_isdir(name);
}

/*
 * Centralized handling of input and output files with format specification
 * The format is meant to show what the input and output is supposed to be,
 * and is therefore a show of intent more than anything else.  However, it
 * does impact behavior on some platforms, such as differentiating between
 * text and binary input/output on non-Unix platforms
 */
BIO *dup_bio_in(int format)
{
    return BIO_new_fp(stdin,
                      BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
}

BIO *dup_bio_out(int format)
{
    BIO *b = BIO_new_fp(stdout,
                        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
    void *prefix = NULL;

#ifdef OPENSSL_SYS_VMS
    if (FMT_istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif

    if (FMT_istext(format)
        && (prefix = getenv("HARNESS_OSSL_PREFIX")) != NULL) {
        b = BIO_push(BIO_new(BIO_f_prefix()), b);
        BIO_set_prefix(b, prefix);
    }

    return b;
}

BIO *dup_bio_err(int format)
{
    BIO *b = BIO_new_fp(stderr,
                        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
#ifdef OPENSSL_SYS_VMS
    if (FMT_istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif
    return b;
}

void unbuffer(FILE *fp)
{
/*
 * On VMS, setbuf() will only take 32-bit pointers, and a compilation
 * with /POINTER_SIZE=64 will give off a MAYLOSEDATA2 warning here.
 * However, we trust that the C RTL will never give us a FILE pointer
 * above the first 4 GB of memory, so we simply turn off the warning
 * temporarily.
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment save
# pragma message disable maylosedata2
#endif
    setbuf(fp, NULL);
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment restore
#endif
}

static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return FMT_istext(format) ? "a" : "ab";
    case 'r':
        return FMT_istext(format) ? "r" : "rb";
    case 'w':
        return FMT_istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

static const char *modeverb(char mode)
{
    switch (mode) {
    case 'a':
        return "appending";
    case 'r':
        return "reading";
    case 'w':
        return "writing";
    }
    return "(doing something)";
}

/*
 * Open a file for writing, owner-read-only.
 */
BIO *bio_open_owner(const char *filename, int format, int private)
{
    FILE *fp = NULL;
    BIO *b = NULL;
    int fd = -1, bflags, mode, textmode;

    if (!private || filename == NULL || strcmp(filename, "-") == 0)
        return bio_open_default(filename, 'w', format);

    mode = O_WRONLY;
#ifdef O_CREAT
    mode |= O_CREAT;
#endif
#ifdef O_TRUNC
    mode |= O_TRUNC;
#endif
    textmode = FMT_istext(format);
    if (!textmode) {
#ifdef O_BINARY
        mode |= O_BINARY;
#elif defined(_O_BINARY)
        mode |= _O_BINARY;
#endif
    }

#ifdef OPENSSL_SYS_VMS
    /* VMS doesn't have O_BINARY, it just doesn't make sense.  But,
     * it still needs to know that we're going binary, or fdopen()
     * will fail with "invalid argument"...  so we tell VMS what the
     * context is.
     */
    if (!textmode)
        fd = open(filename, mode, 0600, "ctx=bin");
    else
#endif
        fd = open(filename, mode, 0600);
    if (fd < 0)
        goto err;
    fp = fdopen(fd, modestr('w', format));
    if (fp == NULL)
        goto err;
    bflags = BIO_CLOSE;
    if (textmode)
        bflags |= BIO_FP_TEXT;
    b = BIO_new_fp(fp, bflags);
    if (b)
        return b;

 err:
    BIO_printf(bio_err, "%s: Can't open \"%s\" for writing, %s\n",
               opt_getprog(), filename, strerror(errno));
    ERR_print_errors(bio_err);
    /* If we have fp, then fdopen took over fd, so don't close both. */
    if (fp)
        fclose(fp);
    else if (fd >= 0)
        close(fd);
    return NULL;
}

static BIO *bio_open_default_(const char *filename, char mode, int format,
                              int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        BIO_printf(bio_err,
                   "Can't open %s, %s\n",
                   mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        BIO_printf(bio_err,
                   "Can't open \"%s\" for %s, %s\n",
                   filename, modeverb(mode), strerror(errno));
    }
    ERR_print_errors(bio_err);
    return NULL;
}

BIO *bio_open_default(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 0);
}

BIO *bio_open_default_quiet(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 1);
}

int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days)
{
    if (startdate == NULL || strcmp(startdate, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
        if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), startdate))
            return 0;
    }
    if (enddate == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL)
            == NULL)
            return 0;
    } else if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(x), enddate)) {
        return 0;
    }
    return 1;
}

int set_crl_lastupdate(X509_CRL *crl, const char *lastupdate)
{
    int ret = 0;
    ASN1_TIME *tm = ASN1_TIME_new();

    if (tm == NULL)
        goto end;

    if (lastupdate == NULL) {
        if (X509_gmtime_adj(tm, 0) == NULL)
            goto end;
    } else {
        if (!ASN1_TIME_set_string_X509(tm, lastupdate))
            goto end;
    }

    if (!X509_CRL_set1_lastUpdate(crl, tm))
        goto end;

    ret = 1;
end:
    ASN1_TIME_free(tm);
    return ret;
}

int set_crl_nextupdate(X509_CRL *crl, const char *nextupdate,
                       long days, long hours, long secs)
{
    int ret = 0;
    ASN1_TIME *tm = ASN1_TIME_new();

    if (tm == NULL)
        goto end;

    if (nextupdate == NULL) {
        if (X509_time_adj_ex(tm, days, hours * 60 * 60 + secs, NULL) == NULL)
            goto end;
    } else {
        if (!ASN1_TIME_set_string_X509(tm, nextupdate))
            goto end;
    }

    if (!X509_CRL_set1_nextUpdate(crl, tm))
        goto end;

    ret = 1;
end:
    ASN1_TIME_free(tm);
    return ret;
}

void make_uppercase(char *string)
{
    int i;

    for (i = 0; string[i] != '\0'; i++)
        string[i] = toupper((unsigned char)string[i]);
}

