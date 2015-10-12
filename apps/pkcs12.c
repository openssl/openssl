/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/opensslconf.h>
#if !defined(OPENSSL_NO_DES)

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/pkcs12.h>

# define NOKEYS          0x1
# define NOCERTS         0x2
# define INFO            0x4
# define CLCERTS         0x8
# define CACERTS         0x10

int get_cert_chain(X509 *cert, X509_STORE *store, STACK_OF(X509) **chain);
int dump_certs_keys_p12(BIO *out, PKCS12 *p12, char *pass, int passlen,
                        int options, char *pempass, const EVP_CIPHER *enc);
int dump_certs_pkeys_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags,
                          char *pass, int passlen, int options, char *pempass,
                          const EVP_CIPHER *enc);
int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bags, char *pass,
                         int passlen, int options, char *pempass,
                         const EVP_CIPHER *enc);
int print_attribs(BIO *out, STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name);
void hex_prin(BIO *out, unsigned char *buf, int len);
static int alg_print(X509_ALGOR *alg);
int cert_load(BIO *in, STACK_OF(X509) *sk);
static int set_pbe(int *ppbe, const char *str);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_CIPHER, OPT_NOKEYS, OPT_KEYEX, OPT_KEYSIG, OPT_NOCERTS, OPT_CLCERTS,
    OPT_CACERTS, OPT_NOOUT, OPT_INFO, OPT_CHAIN, OPT_TWOPASS, OPT_NOMACVER,
    OPT_DESCERT, OPT_EXPORT, OPT_NOITER, OPT_MACITER, OPT_NOMACITER,
    OPT_NOMAC, OPT_LMK, OPT_NODES, OPT_MACALG, OPT_CERTPBE, OPT_KEYPBE,
    OPT_RAND, OPT_INKEY, OPT_CERTFILE, OPT_NAME, OPT_CSP, OPT_CANAME,
    OPT_IN, OPT_OUT, OPT_PASSIN, OPT_PASSOUT, OPT_PASSWORD, OPT_CAPATH,
    OPT_CAFILE, OPT_NOCAPATH, OPT_NOCAFILE, OPT_ENGINE
} OPTION_CHOICE;

OPTIONS pkcs12_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"nokeys", OPT_NOKEYS, '-', "Don't output private keys"},
    {"keyex", OPT_KEYEX, '-', "Set MS key exchange type"},
    {"keysig", OPT_KEYSIG, '-', "Set MS key signature type"},
    {"nocerts", OPT_NOCERTS, '-', "Don't output certificates"},
    {"clcerts", OPT_CLCERTS, '-', "Only output client certificates"},
    {"cacerts", OPT_CACERTS, '-', "Only output CA certificates"},
    {"noout", OPT_NOOUT, '-', "Don't output anything, just verify"},
    {"info", OPT_INFO, '-', "Print info about PKCS#12 structure"},
    {"chain", OPT_CHAIN, '-', "Add certificate chain"},
    {"twopass", OPT_TWOPASS, '-', "Separate MAC, encryption passwords"},
    {"nomacver", OPT_NOMACVER, '-', "Don't verify MAC"},
# ifndef OPENSSL_NO_RC2
    {"descert", OPT_DESCERT, '-',
     "Encrypt output with 3DES (default RC2-40)"},
    {"certpbe", OPT_CERTPBE, 's',
     "Certificate PBE algorithm (default RC2-40)"},
# else
    {"descert", OPT_DESCERT, '-', "Encrypt output with 3DES (the default)"},
    {"certpbe", OPT_CERTPBE, 's', "Certificate PBE algorithm (default 3DES)"},
# endif
    {"export", OPT_EXPORT, '-', "Output PKCS12 file"},
    {"noiter", OPT_NOITER, '-', "Don't use encryption iteration"},
    {"maciter", OPT_MACITER, '-', "Use MAC iteration"},
    {"nomaciter", OPT_NOMACITER, '-', "Don't use MAC iteration"},
    {"nomac", OPT_NOMAC, '-', "Don't generate MAC"},
    {"LMK", OPT_LMK, '-',
     "Add local machine keyset attribute to private key"},
    {"nodes", OPT_NODES, '-', "Don't encrypt private keys"},
    {"macalg", OPT_MACALG, 's',
     "Digest algorithm used in MAC (default SHA1)"},
    {"keypbe", OPT_KEYPBE, 's', "Private key PBE algorithm (default 3DES)"},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"inkey", OPT_INKEY, '<', "Private key if not infile"},
    {"certfile", OPT_CERTFILE, '<', "Load certs from file"},
    {"name", OPT_NAME, 's', "Use name as friendly name"},
    {"CSP", OPT_CSP, 's', "Microsoft CSP name"},
    {"caname", OPT_CANAME, 's',
     "Use name as CA friendly name (can be repeated)"},
    {"in", OPT_IN, '<', "Input filename"},
    {"out", OPT_OUT, '>', "Output filename"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"password", OPT_PASSWORD, 's', "Set import/export password source"},
    {"CApath", OPT_CAPATH, '/', "PEM-format directory of CA's"},
    {"CAfile", OPT_CAFILE, '<', "PEM-format file of CA's"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int pkcs12_main(int argc, char **argv)
{
    char *infile = NULL, *outfile = NULL, *keyname = NULL, *certfile = NULL;
    char *name = NULL, *csp_name = NULL;
    char pass[2048], macpass[2048];
    int export_cert = 0, options = 0, chain = 0, twopass = 0, keytype = 0;
    int iter = PKCS12_DEFAULT_ITER, maciter = PKCS12_DEFAULT_ITER;
# ifndef OPENSSL_NO_RC2
    int cert_pbe = NID_pbe_WithSHA1And40BitRC2_CBC;
# else
    int cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
# endif
    int key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    int ret = 1, macver = 1, noprompt = 0, add_lmk = 0, private = 0;
    char *passinarg = NULL, *passoutarg = NULL, *passarg = NULL;
    char *passin = NULL, *passout = NULL, *inrand = NULL, *macalg = NULL;
    char *cpass = NULL, *mpass = NULL, *CApath = NULL, *CAfile = NULL;
    char *prog;
    int noCApath = 0, noCAfile = 0;
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL;
    PKCS12 *p12 = NULL;
    STACK_OF(OPENSSL_STRING) *canames = NULL;
    const EVP_CIPHER *enc = EVP_des_ede3_cbc();
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, pkcs12_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkcs12_options);
            ret = 0;
            goto end;
        case OPT_NOKEYS:
            options |= NOKEYS;
            break;
        case OPT_KEYEX:
            keytype = KEY_EX;
            break;
        case OPT_KEYSIG:
            keytype = KEY_SIG;
            break;
        case OPT_NOCERTS:
            options |= NOCERTS;
            break;
        case OPT_CLCERTS:
            options |= CLCERTS;
            break;
        case OPT_CACERTS:
            options |= CACERTS;
            break;
        case OPT_NOOUT:
            options |= (NOKEYS | NOCERTS);
            break;
        case OPT_INFO:
            options |= INFO;
            break;
        case OPT_CHAIN:
            chain = 1;
            break;
        case OPT_TWOPASS:
            twopass = 1;
            break;
        case OPT_NOMACVER:
            macver = 0;
            break;
        case OPT_DESCERT:
            cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
            break;
        case OPT_EXPORT:
            export_cert = 1;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        case OPT_NOITER:
            iter = 1;
            break;
        case OPT_MACITER:
            maciter = PKCS12_DEFAULT_ITER;
            break;
        case OPT_NOMACITER:
            maciter = 1;
            break;
        case OPT_NOMAC:
            maciter = -1;
            break;
        case OPT_MACALG:
            macalg = opt_arg();
            break;
        case OPT_NODES:
            enc = NULL;
            break;
        case OPT_CERTPBE:
            if (!set_pbe(&cert_pbe, opt_arg()))
                goto opthelp;
            break;
        case OPT_KEYPBE:
            if (!set_pbe(&key_pbe, opt_arg()))
                goto opthelp;
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_INKEY:
            keyname = opt_arg();
            break;
        case OPT_CERTFILE:
            certfile = opt_arg();
            break;
        case OPT_NAME:
            name = opt_arg();
            break;
        case OPT_LMK:
            add_lmk = 1;
            break;
        case OPT_CSP:
            csp_name = opt_arg();
            break;
        case OPT_CANAME:
            if (canames == NULL
                && (canames = sk_OPENSSL_STRING_new_null()) == NULL)
                goto end;
            sk_OPENSSL_STRING_push(canames, opt_arg());
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_PASSWORD:
            passarg = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    private = 1;

    if (passarg) {
        if (export_cert)
            passoutarg = passarg;
        else
            passinarg = passarg;
    }

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    if (!cpass) {
        if (export_cert)
            cpass = passout;
        else
            cpass = passin;
    }

    if (cpass) {
        mpass = cpass;
        noprompt = 1;
    } else {
        cpass = pass;
        mpass = macpass;
    }

    if (export_cert || inrand) {
        app_RAND_load_file(NULL, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                       app_RAND_load_files(inrand));
    }

    if (twopass) {
        if (EVP_read_pw_string
            (macpass, sizeof macpass, "Enter MAC Password:", export_cert)) {
            BIO_printf(bio_err, "Can't read Password\n");
            goto end;
        }
    }

    if (export_cert) {
        EVP_PKEY *key = NULL;
        X509 *ucert = NULL, *x = NULL;
        STACK_OF(X509) *certs = NULL;
        const EVP_MD *macmd = NULL;
        unsigned char *catmp = NULL;
        int i;

        if ((options & (NOCERTS | NOKEYS)) == (NOCERTS | NOKEYS)) {
            BIO_printf(bio_err, "Nothing to do!\n");
            goto export_end;
        }

        if (options & NOCERTS)
            chain = 0;

        if (!(options & NOKEYS)) {
            key = load_key(keyname ? keyname : infile,
                           FORMAT_PEM, 1, passin, e, "private key");
            if (!key)
                goto export_end;
        }

        /* Load in all certs in input file */
        if (!(options & NOCERTS)) {
            certs = load_certs(infile, FORMAT_PEM, NULL, e,
                               "certificates");
            if (!certs)
                goto export_end;

            if (key) {
                /* Look for matching private key */
                for (i = 0; i < sk_X509_num(certs); i++) {
                    x = sk_X509_value(certs, i);
                    if (X509_check_private_key(x, key)) {
                        ucert = x;
                        /* Zero keyid and alias */
                        X509_keyid_set1(ucert, NULL, 0);
                        X509_alias_set1(ucert, NULL, 0);
                        /* Remove from list */
                        (void)sk_X509_delete(certs, i);
                        break;
                    }
                }
                if (!ucert) {
                    BIO_printf(bio_err,
                               "No certificate matches private key\n");
                    goto export_end;
                }
            }

        }

        /* Add any more certificates asked for */
        if (certfile) {
            STACK_OF(X509) *morecerts = NULL;
            if ((morecerts = load_certs(certfile, FORMAT_PEM, NULL, e,
                                        "certificates from certfile")) == NULL)
                goto export_end;
            while (sk_X509_num(morecerts) > 0)
                sk_X509_push(certs, sk_X509_shift(morecerts));
            sk_X509_free(morecerts);
        }

        /* If chaining get chain from user cert */
        if (chain) {
            int vret;
            STACK_OF(X509) *chain2;
            X509_STORE *store;
            if ((store = setup_verify(CAfile, CApath, noCAfile, noCApath))
                    == NULL)
                goto export_end;

            vret = get_cert_chain(ucert, store, &chain2);
            X509_STORE_free(store);

            if (!vret) {
                /* Exclude verified certificate */
                for (i = 1; i < sk_X509_num(chain2); i++)
                    sk_X509_push(certs, sk_X509_value(chain2, i));
                /* Free first certificate */
                X509_free(sk_X509_value(chain2, 0));
                sk_X509_free(chain2);
            } else {
                if (vret >= 0)
                    BIO_printf(bio_err, "Error %s getting chain.\n",
                               X509_verify_cert_error_string(vret));
                else
                    ERR_print_errors(bio_err);
                goto export_end;
            }
        }

        /* Add any CA names */

        for (i = 0; i < sk_OPENSSL_STRING_num(canames); i++) {
            catmp = (unsigned char *)sk_OPENSSL_STRING_value(canames, i);
            X509_alias_set1(sk_X509_value(certs, i), catmp, -1);
        }

        if (csp_name && key)
            EVP_PKEY_add1_attr_by_NID(key, NID_ms_csp_name,
                                      MBSTRING_ASC, (unsigned char *)csp_name,
                                      -1);

        if (add_lmk && key)
            EVP_PKEY_add1_attr_by_NID(key, NID_LocalKeySet, 0, NULL, -1);

        if (!noprompt &&
            EVP_read_pw_string(pass, sizeof pass, "Enter Export Password:",
                               1)) {
            BIO_printf(bio_err, "Can't read Password\n");
            goto export_end;
        }
        if (!twopass)
            BUF_strlcpy(macpass, pass, sizeof macpass);

        p12 = PKCS12_create(cpass, name, key, ucert, certs,
                            key_pbe, cert_pbe, iter, -1, keytype);

        if (!p12) {
            ERR_print_errors(bio_err);
            goto export_end;
        }

        if (macalg) {
            if (!opt_md(macalg, &macmd))
                goto opthelp;
        }

        if (maciter != -1)
            PKCS12_set_mac(p12, mpass, -1, NULL, 0, maciter, macmd);

        assert(private);

        out = bio_open_owner(outfile, FORMAT_PKCS12, private);
        if (out == NULL)
            goto end;

        i2d_PKCS12_bio(out, p12);

        ret = 0;

 export_end:

        EVP_PKEY_free(key);
        sk_X509_pop_free(certs, X509_free);
        X509_free(ucert);

        goto end;

    }

    in = bio_open_default(infile, 'r', FORMAT_PKCS12);
    if (in == NULL)
        goto end;
    out = bio_open_owner(outfile, FORMAT_PEM, private);
    if (out == NULL)
        goto end;

    if ((p12 = d2i_PKCS12_bio(in, NULL)) == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (!noprompt
        && EVP_read_pw_string(pass, sizeof pass, "Enter Import Password:",
                              0)) {
        BIO_printf(bio_err, "Can't read Password\n");
        goto end;
    }

    if (!twopass)
        BUF_strlcpy(macpass, pass, sizeof macpass);

    if ((options & INFO) && p12->mac)
        BIO_printf(bio_err, "MAC Iteration %ld\n",
                   p12->mac->iter ? ASN1_INTEGER_get(p12->mac->iter) : 1);
    if (macver) {
        /* If we enter empty password try no password first */
        if (!mpass[0] && PKCS12_verify_mac(p12, NULL, 0)) {
            /* If mac and crypto pass the same set it to NULL too */
            if (!twopass)
                cpass = NULL;
        } else if (!PKCS12_verify_mac(p12, mpass, -1)) {
            BIO_printf(bio_err, "Mac verify error: invalid password?\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    assert(private);
    if (!dump_certs_keys_p12(out, p12, cpass, -1, options, passout, enc)) {
        BIO_printf(bio_err, "Error outputting keys and certificates\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    PKCS12_free(p12);
    if (export_cert || inrand)
        app_RAND_write_file(NULL);
    BIO_free(in);
    BIO_free_all(out);
    sk_OPENSSL_STRING_free(canames);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    return (ret);
}

int dump_certs_keys_p12(BIO *out, PKCS12 *p12, char *pass,
                        int passlen, int options, char *pempass,
                        const EVP_CIPHER *enc)
{
    STACK_OF(PKCS7) *asafes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    int ret = 0;
    PKCS7 *p7;

    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL)
        return 0;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
            if (options & INFO)
                BIO_printf(bio_err, "PKCS7 Data\n");
        } else if (bagnid == NID_pkcs7_encrypted) {
            if (options & INFO) {
                BIO_printf(bio_err, "PKCS7 Encrypted data: ");
                alg_print(p7->d.encrypted->enc_data->algorithm);
            }
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags)
            goto err;
        if (!dump_certs_pkeys_bags(out, bags, pass, passlen,
                                   options, pempass, enc)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto err;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
    }
    ret = 1;

 err:
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    return ret;
}

int dump_certs_pkeys_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags,
                          char *pass, int passlen, int options, char *pempass,
                          const EVP_CIPHER *enc)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!dump_certs_pkeys_bag(out,
                                  sk_PKCS12_SAFEBAG_value(bags, i),
                                  pass, passlen, options, pempass, enc))
            return 0;
    }
    return 1;
}

int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, char *pass,
                         int passlen, int options, char *pempass,
                         const EVP_CIPHER *enc)
{
    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8;
    X509 *x509;

    switch (M_PKCS12_bag_type(bag)) {
    case NID_keyBag:
        if (options & INFO)
            BIO_printf(bio_err, "Key bag\n");
        if (options & NOKEYS)
            return 1;
        print_attribs(out, bag->attrib, "Bag Attributes");
        p8 = bag->value.keybag;
        if ((pkey = EVP_PKCS82PKEY(p8)) == NULL)
            return 0;
        print_attribs(out, p8->attributes, "Key Attributes");
        PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_free(pkey);
        break;

    case NID_pkcs8ShroudedKeyBag:
        if (options & INFO) {
            BIO_printf(bio_err, "Shrouded Keybag: ");
            alg_print(bag->value.shkeybag->algor);
        }
        if (options & NOKEYS)
            return 1;
        print_attribs(out, bag->attrib, "Bag Attributes");
        if ((p8 = PKCS12_decrypt_skey(bag, pass, passlen)) == NULL)
            return 0;
        if ((pkey = EVP_PKCS82PKEY(p8)) == NULL) {
            PKCS8_PRIV_KEY_INFO_free(p8);
            return 0;
        }
        print_attribs(out, p8->attributes, "Key Attributes");
        PKCS8_PRIV_KEY_INFO_free(p8);
        PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_free(pkey);
        break;

    case NID_certBag:
        if (options & INFO)
            BIO_printf(bio_err, "Certificate bag\n");
        if (options & NOCERTS)
            return 1;
        if (PKCS12_get_attr(bag, NID_localKeyID)) {
            if (options & CACERTS)
                return 1;
        } else if (options & CLCERTS)
            return 1;
        print_attribs(out, bag->attrib, "Bag Attributes");
        if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
            return 1;
        if ((x509 = PKCS12_certbag2x509(bag)) == NULL)
            return 0;
        dump_cert_text(out, x509);
        PEM_write_bio_X509(out, x509);
        X509_free(x509);
        break;

    case NID_safeContentsBag:
        if (options & INFO)
            BIO_printf(bio_err, "Safe Contents bag\n");
        print_attribs(out, bag->attrib, "Bag Attributes");
        return dump_certs_pkeys_bags(out, bag->value.safes, pass,
                                     passlen, options, pempass, enc);

    default:
        BIO_printf(bio_err, "Warning unsupported bag type: ");
        i2a_ASN1_OBJECT(bio_err, bag->type);
        BIO_printf(bio_err, "\n");
        return 1;
    }
    return 1;
}

/* Given a single certificate return a verified chain or NULL if error */

/* Hope this is OK .... */

int get_cert_chain(X509 *cert, X509_STORE *store, STACK_OF(X509) **chain)
{
    X509_STORE_CTX store_ctx;
    STACK_OF(X509) *chn;
    int i = 0;

    /*
     * FIXME: Should really check the return status of X509_STORE_CTX_init
     * for an error, but how that fits into the return value of this function
     * is less obvious.
     */
    X509_STORE_CTX_init(&store_ctx, store, cert, NULL);
    if (X509_verify_cert(&store_ctx) <= 0) {
        i = X509_STORE_CTX_get_error(&store_ctx);
        if (i == 0)
            /*
             * avoid returning 0 if X509_verify_cert() did not set an
             * appropriate error value in the context
             */
            i = -1;
        chn = NULL;
        goto err;
    } else
        chn = X509_STORE_CTX_get1_chain(&store_ctx);
 err:
    X509_STORE_CTX_cleanup(&store_ctx);
    *chain = chn;

    return i;
}

static int alg_print(X509_ALGOR *alg)
{
    PBEPARAM *pbe;
    const unsigned char *p = alg->parameter->value.sequence->data;

    pbe = d2i_PBEPARAM(NULL, &p, alg->parameter->value.sequence->length);
    if (!pbe)
        return 1;
    BIO_printf(bio_err, "%s, Iteration %ld\n",
               OBJ_nid2ln(OBJ_obj2nid(alg->algorithm)),
               ASN1_INTEGER_get(pbe->iter));
    PBEPARAM_free(pbe);
    return 1;
}

/* Load all certificates from a given file */

int cert_load(BIO *in, STACK_OF(X509) *sk)
{
    int ret;
    X509 *cert;
    ret = 0;
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
        ret = 1;
        sk_X509_push(sk, cert);
    }
    if (ret)
        ERR_clear_error();
    return ret;
}

/* Generalised attribute print: handle PKCS#8 and bag attributes */

int print_attribs(BIO *out, STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name)
{
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *av;
    char *value;
    int i, attr_nid;
    if (!attrlst) {
        BIO_printf(out, "%s: <No Attributes>\n", name);
        return 1;
    }
    if (!sk_X509_ATTRIBUTE_num(attrlst)) {
        BIO_printf(out, "%s: <Empty Attributes>\n", name);
        return 1;
    }
    BIO_printf(out, "%s\n", name);
    for (i = 0; i < sk_X509_ATTRIBUTE_num(attrlst); i++) {
        ASN1_OBJECT *attr_obj;
        attr = sk_X509_ATTRIBUTE_value(attrlst, i);
        attr_obj = X509_ATTRIBUTE_get0_object(attr);
        attr_nid = OBJ_obj2nid(attr_obj);
        BIO_printf(out, "    ");
        if (attr_nid == NID_undef) {
            i2a_ASN1_OBJECT(out, attr_obj);
            BIO_printf(out, ": ");
        } else
            BIO_printf(out, "%s: ", OBJ_nid2ln(attr_nid));

        if (X509_ATTRIBUTE_count(attr)) {
            av = X509_ATTRIBUTE_get0_type(attr, 0);
            switch (av->type) {
            case V_ASN1_BMPSTRING:
                value = OPENSSL_uni2asc(av->value.bmpstring->data,
                                        av->value.bmpstring->length);
                BIO_printf(out, "%s\n", value);
                OPENSSL_free(value);
                break;

            case V_ASN1_OCTET_STRING:
                hex_prin(out, av->value.octet_string->data,
                         av->value.octet_string->length);
                BIO_printf(out, "\n");
                break;

            case V_ASN1_BIT_STRING:
                hex_prin(out, av->value.bit_string->data,
                         av->value.bit_string->length);
                BIO_printf(out, "\n");
                break;

            default:
                BIO_printf(out, "<Unsupported tag %d>\n", av->type);
                break;
            }
        } else
            BIO_printf(out, "<No Values>\n");
    }
    return 1;
}

void hex_prin(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        BIO_printf(out, "%02X ", buf[i]);
}

static int set_pbe(int *ppbe, const char *str)
{
    if (!str)
        return 0;
    if (strcmp(str, "NONE") == 0) {
        *ppbe = -1;
        return 1;
    }
    *ppbe = OBJ_txt2nid(str);
    if (*ppbe == NID_undef) {
        BIO_printf(bio_err, "Unknown PBE algorithm %s\n", str);
        return 0;
    }
    return 1;
}

#endif
