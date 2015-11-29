/* crypto/x509/t_x509.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "internal/asn1_int.h"

#ifndef OPENSSL_NO_STDIO
int X509_print_fp(FILE *fp, X509 *x)
{
    return X509_print_ex_fp(fp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int X509_print_ex_fp(FILE *fp, X509 *x, unsigned long nmflag,
                     unsigned long cflag)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        X509err(X509_F_X509_PRINT_EX_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = X509_print_ex(b, x, nmflag, cflag);
    BIO_free(b);
    return (ret);
}
#endif

int X509_print(BIO *bp, X509 *x)
{
    return X509_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}

int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflags,
                  unsigned long cflag)
{
    long l;
    int ret = 0, i;
    char *m = NULL, mlch = ' ';
    int nmindent = 0;
    ASN1_INTEGER *bs;
    EVP_PKEY *pkey = NULL;
    const char *neg;

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
        nmindent = 12;
    }

    if (nmflags == X509_FLAG_COMPAT)
        nmindent = 16;

    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (BIO_write(bp, "Certificate:\n", 13) <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        l = X509_get_version(x);
        if (BIO_printf(bp, "%8sVersion: %lu (0x%lx)\n", "", l + 1, l) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SERIAL)) {

        if (BIO_write(bp, "        Serial Number:", 22) <= 0)
            goto err;

        bs = X509_get_serialNumber(x);
        if (bs->length <= (int)sizeof(long)) {
                ERR_set_mark();
                l = ASN1_INTEGER_get(bs);
                ERR_pop_to_mark();
        } else {
            l = -1;
        }
        if (l != -1) {
            if (bs->type == V_ASN1_NEG_INTEGER) {
                l = -l;
                neg = "-";
            } else
                neg = "";
            if (BIO_printf(bp, " %s%lu (%s0x%lx)\n", neg, l, neg, l) <= 0)
                goto err;
        } else {
            neg = (bs->type == V_ASN1_NEG_INTEGER) ? " (Negative)" : "";
            if (BIO_printf(bp, "\n%12s%s", "", neg) <= 0)
                goto err;

            for (i = 0; i < bs->length; i++) {
                if (BIO_printf(bp, "%02x%c", bs->data[i],
                               ((i + 1 == bs->length) ? '\n' : ':')) <= 0)
                    goto err;
            }
        }

    }

    if (!(cflag & X509_FLAG_NO_SIGNAME)) {
        X509_ALGOR *tsig_alg = X509_get0_tbs_sigalg(x);
        if (X509_signature_print(bp, tsig_alg, NULL) <= 0)
            goto err;
    }

    if (!(cflag & X509_FLAG_NO_ISSUER)) {
        if (BIO_printf(bp, "        Issuer:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, X509_get_issuer_name(x), nmindent, nmflags)
            < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VALIDITY)) {
        if (BIO_write(bp, "        Validity\n", 17) <= 0)
            goto err;
        if (BIO_write(bp, "            Not Before: ", 24) <= 0)
            goto err;
        if (!ASN1_TIME_print(bp, X509_get_notBefore(x)))
            goto err;
        if (BIO_write(bp, "\n            Not After : ", 25) <= 0)
            goto err;
        if (!ASN1_TIME_print(bp, X509_get_notAfter(x)))
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        if (BIO_printf(bp, "        Subject:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex
            (bp, X509_get_subject_name(x), nmindent, nmflags) < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_PUBKEY)) {
        X509_PUBKEY *xpkey = X509_get_X509_PUBKEY(x);
        ASN1_OBJECT *xpoid;
        X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, xpkey);
        if (BIO_write(bp, "        Subject Public Key Info:\n", 33) <= 0)
            goto err;
        if (BIO_printf(bp, "%12sPublic Key Algorithm: ", "") <= 0)
            goto err;
        if (i2a_ASN1_OBJECT(bp, xpoid) <= 0)
            goto err;
        if (BIO_puts(bp, "\n") <= 0)
            goto err;

        pkey = X509_get_pubkey(x);
        if (pkey == NULL) {
            BIO_printf(bp, "%12sUnable to load Public Key\n", "");
            ERR_print_errors(bp);
        } else {
            EVP_PKEY_print_public(bp, pkey, 16, NULL);
            EVP_PKEY_free(pkey);
        }
    }

    if (!(cflag & X509_FLAG_NO_IDS)) {
        ASN1_BIT_STRING *iuid, *suid;
        X509_get0_uids(&iuid, &suid, x);
        if (iuid != NULL) {
            if (BIO_printf(bp, "%8sIssuer Unique ID: ", "") <= 0)
                goto err;
            if (!X509_signature_dump(bp, iuid, 12))
                goto err;
        }
        if (suid != NULL) {
            if (BIO_printf(bp, "%8sSubject Unique ID: ", "") <= 0)
                goto err;
            if (!X509_signature_dump(bp, suid, 12))
                goto err;
        }
    }

    if (!(cflag & X509_FLAG_NO_EXTENSIONS))
        X509V3_extensions_print(bp, "X509v3 extensions",
                                X509_get0_extensions(x), cflag, 8);

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        X509_ALGOR *sig_alg;
        ASN1_BIT_STRING *sig;
        X509_get0_signature(&sig, &sig_alg, x);
        if (X509_signature_print(bp, sig_alg, sig) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_AUX)) {
        if (!X509_aux_print(bp, x, 0))
            goto err;
    }
    ret = 1;
 err:
    OPENSSL_free(m);
    return (ret);
}

int X509_ocspid_print(BIO *bp, X509 *x)
{
    unsigned char *der = NULL;
    unsigned char *dertmp;
    int derlen;
    int i;
    unsigned char SHA1md[SHA_DIGEST_LENGTH];
    ASN1_BIT_STRING *keybstr;
    X509_NAME *subj;

    /*
     * display the hash of the subject as it would appear in OCSP requests
     */
    if (BIO_printf(bp, "        Subject OCSP hash: ") <= 0)
        goto err;
    subj = X509_get_subject_name(x);
    derlen = i2d_X509_NAME(subj, NULL);
    if ((der = dertmp = OPENSSL_malloc(derlen)) == NULL)
        goto err;
    i2d_X509_NAME(subj, &dertmp);

    if (!EVP_Digest(der, derlen, SHA1md, NULL, EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_printf(bp, "%02X", SHA1md[i]) <= 0)
            goto err;
    }
    OPENSSL_free(der);
    der = NULL;

    /*
     * display the hash of the public key as it would appear in OCSP requests
     */
    if (BIO_printf(bp, "\n        Public key OCSP hash: ") <= 0)
        goto err;

    keybstr = X509_get0_pubkey_bitstr(x);

    if (keybstr == NULL)
        goto err;

    if (!EVP_Digest(ASN1_STRING_data(keybstr), ASN1_STRING_length(keybstr),
                    SHA1md, NULL, EVP_sha1(), NULL))
        goto err;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (BIO_printf(bp, "%02X", SHA1md[i]) <= 0)
            goto err;
    }
    BIO_printf(bp, "\n");

    return (1);
 err:
    OPENSSL_free(der);
    return (0);
}

int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent)
{
    const unsigned char *s;
    int i, n;

    n = sig->length;
    s = sig->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0) {
            if (BIO_write(bp, "\n", 1) <= 0)
                return 0;
            if (BIO_indent(bp, indent, indent) <= 0)
                return 0;
        }
        if (BIO_printf(bp, "%02x%s", s[i], ((i + 1) == n) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_write(bp, "\n", 1) != 1)
        return 0;

    return 1;
}

int X509_signature_print(BIO *bp, X509_ALGOR *sigalg, ASN1_STRING *sig)
{
    int sig_nid;
    if (BIO_puts(bp, "    Signature Algorithm: ") <= 0)
        return 0;
    if (i2a_ASN1_OBJECT(bp, sigalg->algorithm) <= 0)
        return 0;

    sig_nid = OBJ_obj2nid(sigalg->algorithm);
    if (sig_nid != NID_undef) {
        int pkey_nid, dig_nid;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (OBJ_find_sigid_algs(sig_nid, &dig_nid, &pkey_nid)) {
            ameth = EVP_PKEY_asn1_find(NULL, pkey_nid);
            if (ameth && ameth->sig_print)
                return ameth->sig_print(bp, sigalg, sig, 9, 0);
        }
    }
    if (sig)
        return X509_signature_dump(bp, sig, 9);
    else if (BIO_puts(bp, "\n") <= 0)
        return 0;
    return 1;
}

int X509_aux_print(BIO *out, X509 *x, int indent)
{
    char oidstr[80], first;
    STACK_OF(ASN1_OBJECT) *trust, *reject;
    const unsigned char *alias, *keyid;
    int keyidlen;
    int i;
    if (X509_trusted(x) == 0)
        return 1;
    trust = X509_get0_trust_objects(x);
    reject = X509_get0_reject_objects(x);
    if (trust) {
        first = 1;
        BIO_printf(out, "%*sTrusted Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_ASN1_OBJECT_num(trust); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof oidstr,
                        sk_ASN1_OBJECT_value(trust, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_printf(out, "%*sNo Trusted Uses.\n", indent, "");
    if (reject) {
        first = 1;
        BIO_printf(out, "%*sRejected Uses:\n%*s", indent, "", indent + 2, "");
        for (i = 0; i < sk_ASN1_OBJECT_num(reject); i++) {
            if (!first)
                BIO_puts(out, ", ");
            else
                first = 0;
            OBJ_obj2txt(oidstr, sizeof oidstr,
                        sk_ASN1_OBJECT_value(reject, i), 0);
            BIO_puts(out, oidstr);
        }
        BIO_puts(out, "\n");
    } else
        BIO_printf(out, "%*sNo Rejected Uses.\n", indent, "");
    alias = X509_alias_get0(x, NULL);
    if (alias)
        BIO_printf(out, "%*sAlias: %s\n", indent, "", alias);
    keyid = X509_keyid_get0(x, &keyidlen);
    if (keyid) {
        BIO_printf(out, "%*sKey Id: ", indent, "");
        for (i = 0; i < keyidlen; i++)
            BIO_printf(out, "%s%02X", i ? ":" : "", keyid[i]);
        BIO_write(out, "\n", 1);
    }
    return 1;
}
