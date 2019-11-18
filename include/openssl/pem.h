/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_PEM_H
# define OPENSSL_PEM_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_PEM_H
# endif

# include <openssl/e_os2.h>
# include <openssl/bio.h>
# include <openssl/safestack.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pemerr.h>
# include <openssl/serializer.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define PEM_BUFSIZE             1024

# define PEM_STRING_X509_OLD     "X509 CERTIFICATE"
# define PEM_STRING_X509         "CERTIFICATE"
# define PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"
# define PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"
# define PEM_STRING_X509_REQ     "CERTIFICATE REQUEST"
# define PEM_STRING_X509_CRL     "X509 CRL"
# define PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
# define PEM_STRING_PUBLIC       "PUBLIC KEY"
# define PEM_STRING_RSA          "RSA PRIVATE KEY"
# define PEM_STRING_RSA_PUBLIC   "RSA PUBLIC KEY"
# define PEM_STRING_DSA          "DSA PRIVATE KEY"
# define PEM_STRING_DSA_PUBLIC   "DSA PUBLIC KEY"
# define PEM_STRING_PKCS7        "PKCS7"
# define PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"
# define PEM_STRING_PKCS8        "ENCRYPTED PRIVATE KEY"
# define PEM_STRING_PKCS8INF     "PRIVATE KEY"
# define PEM_STRING_DHPARAMS     "DH PARAMETERS"
# define PEM_STRING_DHXPARAMS    "X9.42 DH PARAMETERS"
# define PEM_STRING_SSL_SESSION  "SSL SESSION PARAMETERS"
# define PEM_STRING_DSAPARAMS    "DSA PARAMETERS"
# define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
# define PEM_STRING_ECPARAMETERS "EC PARAMETERS"
# define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
# define PEM_STRING_PARAMETERS   "PARAMETERS"
# define PEM_STRING_CMS          "CMS"

# define PEM_TYPE_ENCRYPTED      10
# define PEM_TYPE_MIC_ONLY       20
# define PEM_TYPE_MIC_CLEAR      30
# define PEM_TYPE_CLEAR          40

/*
 * These macros make the PEM_read/PEM_write functions easier to maintain and
 * write. Now they are all implemented with either: IMPLEMENT_PEM_rw(...) or
 * IMPLEMENT_PEM_rw_cb(...)
 */

# ifdef OPENSSL_NO_STDIO

#  define IMPLEMENT_PEM_read_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) /**/
#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) /**/
#  endif
#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) /**/
#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) /**/
#  endif
# else

#  define IMPLEMENT_PEM_read_fp(name, type, str, asn1)                  \
    type *PEM_read_##name(FILE *fp, type **x, pem_password_cb *cb, void *u) \
    {                                                                   \
        return PEM_ASN1_read((d2i_of_void *)d2i_##asn1, str, fp,        \
                             (void **)x, cb, u);                        \
    }

#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1)                 \
    int PEM_write_##name(FILE *fp, const type *x)                       \
    {                                                                   \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1, str, fp,       \
                              x, NULL, NULL, 0, NULL, NULL);            \
    }

#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)  \
    IMPLEMENT_PEM_write_fp(name, type, str, asn1)
#  endif

#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)              \
    int PEM_write_##name(FILE *fp, const type *x,                       \
                         const EVP_CIPHER *enc,                         \
                         const unsigned char *kstr, int klen,           \
                         pem_password_cb *cb, void *u)                  \
    {                                                                   \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1, str, fp,       \
                              x, enc, kstr, klen, cb, u);               \
    }

#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)       \
    IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)
#  endif
# endif

# define IMPLEMENT_PEM_read_bio(name, type, str, asn1)                  \
    type *PEM_read_bio_##name(BIO *bp, type **x,                        \
                              pem_password_cb *cb, void *u)             \
    {                                                                   \
        return PEM_ASN1_read_bio((d2i_of_void *)d2i_##asn1, str, bp,    \
                                 (void **)x, cb, u);                    \
    }

# define IMPLEMENT_PEM_write_bio(name, type, str, asn1)                 \
    int PEM_write_bio_##name(BIO *bp, const type *x)                    \
    {                                                                   \
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1, str, bp,   \
                                  x, NULL,NULL,0,NULL,NULL);            \
    }

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define IMPLEMENT_PEM_write_bio_const(name, type, str, asn1)   \
    IMPLEMENT_PEM_write_bio(name, type, str, asn1)
# endif

# define IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)              \
    int PEM_write_bio_##name(BIO *bp, const type *x,                    \
                             const EVP_CIPHER *enc,                     \
                             const unsigned char *kstr, int klen,       \
                             pem_password_cb *cb, void *u)              \
    {                                                                   \
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1, str, bp,   \
                                  x, enc, kstr, klen, cb, u);           \
    }

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1)  \
    IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)
# endif

# define IMPLEMENT_PEM_write(name, type, str, asn1) \
        IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_write_fp(name, type, str, asn1)

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define IMPLEMENT_PEM_write_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)
# endif

# define IMPLEMENT_PEM_write_cb(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define IMPLEMENT_PEM_write_cb_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)
# endif

# define IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_read_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_read_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_rw(name, type, str, asn1) \
        IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_write(name, type, str, asn1)

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define IMPLEMENT_PEM_rw_const(name, type, str, asn1) \
        IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_write_const(name, type, str, asn1)
# endif

# define IMPLEMENT_PEM_rw_cb(name, type, str, asn1) \
        IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb(name, type, str, asn1)

/* Alternatives using provided serializers */

# define IMPLEMENT_PEM_write_fnsig(name, type, OUTTYPE, writename)      \
    int PEM_##writename##_##name(OUTTYPE *out, const type *x)
# define IMPLEMENT_PEM_write_cb_fnsig(name, type, OUTTYPE, writename)   \
    int PEM_##writename##_##name(OUTTYPE *out, const type *x,           \
                             const EVP_CIPHER *enc,                     \
                             const unsigned char *kstr, int klen,       \
                             pem_password_cb *cb, void *u)
# define IMPLEMENT_PEM_provided_write_body_vars(type, asn1)             \
    int ret = 0;                                                        \
    const char *pq = OSSL_SERIALIZER_##asn1##_TO_PEM_PQ;                \
    OSSL_SERIALIZER_CTX *ctx = OSSL_SERIALIZER_CTX_new_by_##type(x, pq); \
                                                                        \
    if (ctx != NULL && OSSL_SERIALIZER_CTX_get_serializer(ctx) == NULL) { \
        OSSL_SERIALIZER_CTX_free(ctx);                                  \
        goto legacy;                                                    \
    }
# define IMPLEMENT_PEM_provided_write_body_pass()                       \
    ret = 1;                                                            \
    if (kstr == NULL && cb == NULL) {                                   \
        if (u != NULL) {                                                \
            kstr = u;                                                   \
            klen = strlen(u);                                           \
        } else {                                                        \
            cb = PEM_def_callback;                                      \
        }                                                               \
    }                                                                   \
    if (kstr != NULL                                                    \
        && !OSSL_SERIALIZER_CTX_set_passphrase(ctx, kstr, klen))        \
        ret = 0;                                                        \
    else if (cb != NULL                                                 \
             && !OSSL_SERIALIZER_CTX_set_passphrase_cb(ctx, 1, cb, u))  \
        ret = 0;                                                        \
    else if (enc != NULL                                                \
             && !OSSL_SERIALIZER_CTX_set_cipher_name(ctx,               \
                                                     EVP_CIPHER_name(enc))) \
        ret = 0;                                                        \
    if (!ret) {                                                         \
        OSSL_SERIALIZER_CTX_free(ctx);                                  \
        return 0;                                                       \
    }
# define IMPLEMENT_PEM_provided_write_body_main(type, outtype)          \
    ret = OSSL_SERIALIZER_to_##outtype(ctx, out);                       \
    OSSL_SERIALIZER_CTX_free(ctx);                                      \
    return ret
# define IMPLEMENT_PEM_provided_write_body_fallback(str, asn1,          \
                                                    writename)          \
    legacy:                                                             \
    return PEM_ASN1_##writename((i2d_of_void *)i2d_##asn1, str, out,    \
                                  x, NULL, NULL, 0, NULL, NULL)
# define IMPLEMENT_PEM_provided_write_body_fallback_cb(str, asn1,       \
                                                       writename)       \
    legacy:                                                             \
    return PEM_ASN1_##writename((i2d_of_void *)i2d_##asn1, str, out,    \
                                x, enc, kstr, klen, cb, u)

# define IMPLEMENT_PEM_provided_write_to(name, type, str, asn1,         \
                                         OUTTYPE, outtype, writename)   \
    IMPLEMENT_PEM_write_fnsig(name, type, OUTTYPE, writename)           \
    {                                                                   \
        IMPLEMENT_PEM_provided_write_body_vars(type, asn1);             \
        IMPLEMENT_PEM_provided_write_body_main(type, outtype);          \
        IMPLEMENT_PEM_provided_write_body_fallback(str, asn1,           \
                                                   writename);          \
    }


# define IMPLEMENT_PEM_provided_write_cb_to(name, type, str, asn1,      \
                                            OUTTYPE, outtype, writename) \
    IMPLEMENT_PEM_write_cb_fnsig(name, type, OUTTYPE, writename)        \
    {                                                                   \
        IMPLEMENT_PEM_provided_write_body_vars(type, asn1);             \
        IMPLEMENT_PEM_provided_write_body_pass();                       \
        IMPLEMENT_PEM_provided_write_body_main(type, outtype);          \
        IMPLEMENT_PEM_provided_write_body_fallback_cb(str, asn1,        \
                                                      writename);       \
    }

# ifdef OPENSSL_NO_STDIO

#  define IMPLEMENT_PEM_provided_write_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_provided_write_cb_fp(name, type, str, asn1) /**/

# else

#  define IMPLEMENT_PEM_provided_write_fp(name, type, str, asn1)        \
    IMPLEMENT_PEM_provided_write_to(name, type, str, asn1, FILE, fp, write)
#  define IMPLEMENT_PEM_provided_write_cb_fp(name, type, str, asn1)     \
    IMPLEMENT_PEM_provided_write_cb_to(name, type, str, asn1, FILE, fp, write)

# endif

# define IMPLEMENT_PEM_provided_write_bio(name, type, str, asn1)        \
    IMPLEMENT_PEM_provided_write_to(name, type, str, asn1, BIO, bio, write_bio)
# define IMPLEMENT_PEM_provided_write_cb_bio(name, type, str, asn1)     \
    IMPLEMENT_PEM_provided_write_cb_to(name, type, str, asn1, BIO, bio, write_bio)

# define IMPLEMENT_PEM_provided_write(name, type, str, asn1)    \
    IMPLEMENT_PEM_provided_write_bio(name, type, str, asn1)     \
    IMPLEMENT_PEM_provided_write_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_provided_write_cb(name, type, str, asn1) \
    IMPLEMENT_PEM_provided_write_cb_bio(name, type, str, asn1)  \
    IMPLEMENT_PEM_provided_write_cb_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_provided_rw(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)                   \
    IMPLEMENT_PEM_provided_write(name, type, str, asn1)

# define IMPLEMENT_PEM_provided_rw_cb(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)                   \
    IMPLEMENT_PEM_provided_write_cb(name, type, str, asn1)

/* These are the same except they are for the declarations */

# if defined(OPENSSL_NO_STDIO)

#  define DECLARE_PEM_read_fp(name, type) /**/
#  define DECLARE_PEM_write_fp(name, type) /**/
#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define DECLARE_PEM_write_fp_const(name, type) /**/
#  endif
#  define DECLARE_PEM_write_cb_fp(name, type) /**/
# else

#  define DECLARE_PEM_read_fp(name, type)                               \
    type *PEM_read_##name(FILE *fp, type **x, pem_password_cb *cb, void *u);

#  define DECLARE_PEM_write_fp(name, type)              \
    IMPLEMENT_PEM_write_fnsig(name, type, FILE, write);

#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define DECLARE_PEM_write_fp_const(name, type)        \
    IMPLEMENT_PEM_write_fnsig(name, type, FILE, write);
#  endif

#  define DECLARE_PEM_write_cb_fp(name, type)                   \
    IMPLEMENT_PEM_write_cb_fnsig(name, type, FILE, write);

# endif

#  define DECLARE_PEM_read_bio(name, type)                      \
    type *PEM_read_bio_##name(BIO *bp, type **x,                \
                              pem_password_cb *cb, void *u);

#  define DECLARE_PEM_write_bio(name, type)             \
    IMPLEMENT_PEM_write_fnsig(name, type, BIO, write_bio);

#  ifndef OPENSSL_NO_DEPRECATED_3_0
#   define DECLARE_PEM_write_bio_const(name, type)       \
    IMPLEMENT_PEM_write_fnsig(name, type, BIO, write_bio);
#  endif

#  define DECLARE_PEM_write_cb_bio(name, type)                          \
    IMPLEMENT_PEM_write_cb_fnsig(name, type, BIO, write_bio);

# define DECLARE_PEM_write(name, type) \
        DECLARE_PEM_write_bio(name, type) \
        DECLARE_PEM_write_fp(name, type)
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define DECLARE_PEM_write_const(name, type) \
        DECLARE_PEM_write_bio_const(name, type) \
        DECLARE_PEM_write_fp_const(name, type)
# endif
# define DECLARE_PEM_write_cb(name, type) \
        DECLARE_PEM_write_cb_bio(name, type) \
        DECLARE_PEM_write_cb_fp(name, type)
# define DECLARE_PEM_read(name, type) \
        DECLARE_PEM_read_bio(name, type) \
        DECLARE_PEM_read_fp(name, type)
# define DECLARE_PEM_rw(name, type) \
        DECLARE_PEM_read(name, type) \
        DECLARE_PEM_write(name, type)
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define DECLARE_PEM_rw_const(name, type) \
        DECLARE_PEM_read(name, type) \
        DECLARE_PEM_write_const(name, type)
# endif
# define DECLARE_PEM_rw_cb(name, type) \
        DECLARE_PEM_read(name, type) \
        DECLARE_PEM_write_cb(name, type)

int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
                  pem_password_cb *callback, void *u);

int PEM_read_bio(BIO *bp, char **name, char **header,
                 unsigned char **data, long *len);
#   define PEM_FLAG_SECURE             0x1
#   define PEM_FLAG_EAY_COMPATIBLE     0x2
#   define PEM_FLAG_ONLY_B64           0x4
int PEM_read_bio_ex(BIO *bp, char **name, char **header,
                    unsigned char **data, long *len, unsigned int flags);
int PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
                              const char *name, BIO *bp, pem_password_cb *cb,
                              void *u);
int PEM_write_bio(BIO *bp, const char *name, const char *hdr,
                  const unsigned char *data, long len);
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                       const char *name, BIO *bp, pem_password_cb *cb,
                       void *u);
void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                        pem_password_cb *cb, void *u);
int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp,
                       const void *x, const EVP_CIPHER *enc,
                       const unsigned char *kstr, int klen,
                       pem_password_cb *cb, void *u);

STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk,
                                            pem_password_cb *cb, void *u);
int PEM_X509_INFO_write_bio(BIO *bp, const X509_INFO *xi, EVP_CIPHER *enc,
                            const unsigned char *kstr, int klen,
                            pem_password_cb *cd, void *u);

#ifndef OPENSSL_NO_STDIO
int PEM_read(FILE *fp, char **name, char **header,
             unsigned char **data, long *len);
int PEM_write(FILE *fp, const char *name, const char *hdr,
              const unsigned char *data, long len);
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
                    pem_password_cb *cb, void *u);
int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp,
                   const void *x, const EVP_CIPHER *enc,
                   const unsigned char *kstr, int klen,
                   pem_password_cb *callback, void *u);
STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
                                        pem_password_cb *cb, void *u);
#endif

int PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
int PEM_SignUpdate(EVP_MD_CTX *ctx, const unsigned char *d, unsigned int cnt);
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey);

/* The default pem_password_cb that's used internally */
int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, const char *str);

# include <openssl/symhacks.h>

DECLARE_PEM_rw(X509, X509)
DECLARE_PEM_rw(X509_AUX, X509)
DECLARE_PEM_rw(X509_REQ, X509_REQ)
DECLARE_PEM_write(X509_REQ_NEW, X509_REQ)
DECLARE_PEM_rw(X509_CRL, X509_CRL)
DECLARE_PEM_rw(X509_PUBKEY, X509_PUBKEY)
DECLARE_PEM_rw(PKCS7, PKCS7)
DECLARE_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE)
DECLARE_PEM_rw(PKCS8, X509_SIG)
DECLARE_PEM_rw(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO)
# ifndef OPENSSL_NO_RSA
DECLARE_PEM_rw_cb(RSAPrivateKey, RSA)
DECLARE_PEM_rw(RSAPublicKey, RSA)
DECLARE_PEM_rw(RSA_PUBKEY, RSA)
# endif
# ifndef OPENSSL_NO_DSA
DECLARE_PEM_rw_cb(DSAPrivateKey, DSA)
DECLARE_PEM_rw(DSA_PUBKEY, DSA)
DECLARE_PEM_rw(DSAparams, DSA)
# endif
# ifndef OPENSSL_NO_EC
DECLARE_PEM_rw(ECPKParameters, EC_GROUP)
DECLARE_PEM_rw_cb(ECPrivateKey, EC_KEY)
DECLARE_PEM_rw(EC_PUBKEY, EC_KEY)
# endif
# ifndef OPENSSL_NO_DH
DECLARE_PEM_rw(DHparams, DH)
DECLARE_PEM_write(DHxparams, DH)
# endif
DECLARE_PEM_rw_cb(PrivateKey, EVP_PKEY)
DECLARE_PEM_rw(PUBKEY, EVP_PKEY)

int PEM_write_bio_PrivateKey_traditional(BIO *bp, const EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         const unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u);

/* Why do these take a signed char *kstr? */
int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, const EVP_PKEY *x, int nid,
                                      const char *kstr, int klen,
                                      pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *, const EVP_PKEY *, const EVP_CIPHER *,
                                  const char *kstr, int klen,
                                  pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_bio(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
                            const char *kstr, int klen,
                            pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, const EVP_PKEY *x, int nid,
                                const char *kstr, int klen,
                                pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u);

# ifndef OPENSSL_NO_STDIO
int i2d_PKCS8PrivateKey_fp(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
                           const char *kstr, int klen,
                           pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, const EVP_PKEY *x, int nid,
                               const char *kstr, int klen,
                               pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, const EVP_PKEY *x, int nid,
                                  const char *kstr, int klen,
                                  pem_password_cb *cb, void *u);

EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                                 void *u);

int PEM_write_PKCS8PrivateKey(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
                              const char *kstr, int klen,
                              pem_password_cb *cd, void *u);
# endif
EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, const EVP_PKEY *x);

# ifndef OPENSSL_NO_DSA
EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PrivateKey_bio(BIO *in);
EVP_PKEY *b2i_PublicKey_bio(BIO *in);
int i2b_PrivateKey_bio(BIO *out, const EVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, const EVP_PKEY *pk);
#  ifndef OPENSSL_NO_RC4
EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
int i2b_PVK_bio(BIO *out, const EVP_PKEY *pk, int enclevel,
                pem_password_cb *cb, void *u);
#  endif
# endif

# ifdef  __cplusplus
}
# endif
#endif
