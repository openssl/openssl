/*
 * Copyright 2014-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_X509_H
# define OSSL_INTERNAL_X509_H
# pragma once

#include <internal/hashtable.h>

/*
 * This structure holds all parameters associated with a verify operation by
 * including an X509_VERIFY_PARAM structure in related structures the
 * parameters used can be customized
 */

struct X509_VERIFY_PARAM_st {
    char *name;
    time_t check_time;          /* Time to use */
    uint32_t inh_flags;         /* Inheritance flags */
    unsigned long flags;        /* Various verify flags */
    int purpose;                /* purpose to check untrusted certificates */
    int trust;                  /* trust setting to check */
    int depth;                  /* Verify depth */
    int auth_level;             /* Security level for chain verification */
    STACK_OF(ASN1_OBJECT) *policies; /* Permissible policies */
    /* Peer identity details */
    STACK_OF(OPENSSL_STRING) *hosts; /* Set of acceptable names */
    unsigned int hostflags;     /* Flags to control matching features */
    char *peername;             /* Matching hostname in peer certificate */
    char *email;                /* If not NULL email address to match */
    size_t emaillen;
    unsigned char *ip;          /* If not NULL IP address to match */
    size_t iplen;               /* Length of IP address */
};

/*
 * This is used to hold everything.  It is used for all certificate
 * validation.  Once we have a certificate chain, the 'verify' function is
 * then called to actually check the cert chain.
 */
struct x509_store_st {
    /* The following is a cache of trusted certs */
    int cache;                  /* if true, stash any hits */
    /* Maps X509_NAME -> STACK_OF(X509_OBJECT) */
    HT *objs_ht;
    /*
     * Deprecated. Used only in the X509_STORE_get0_objects() for backward
     * compatibility.
     */
    STACK_OF(X509_OBJECT) *objs;
    /* These are external lookup methods */
    STACK_OF(X509_LOOKUP) *get_cert_methods;
    X509_VERIFY_PARAM *param;
    /* Callbacks for various operations */
    /* called to verify a certificate */
    int (*verify) (X509_STORE_CTX *ctx);
    /* error callback */
    int (*verify_cb) (int ok, X509_STORE_CTX *ctx);
    /* get issuers cert from ctx */
    int (*get_issuer) (X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
    /* check issued */
    int (*check_issued) (X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
    /* Check revocation status of chain */
    int (*check_revocation) (X509_STORE_CTX *ctx);
    /* retrieve CRL */
    int (*get_crl) (X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
    /* Check CRL validity */
    int (*check_crl) (X509_STORE_CTX *ctx, X509_CRL *crl);
    /* Check certificate against CRL */
    int (*cert_crl) (X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
    /* Check policy status of the chain */
    int (*check_policy) (X509_STORE_CTX *ctx);
    STACK_OF(X509) *(*lookup_certs) (X509_STORE_CTX *ctx,
                                     const X509_NAME *nm);
    /* cannot constify 'ctx' param due to lookup_certs_sk() in x509_vfy.c */
    STACK_OF(X509_CRL) *(*lookup_crls) (const X509_STORE_CTX *ctx,
                                        const X509_NAME *nm);
    int (*cleanup) (X509_STORE_CTX *ctx);
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
};


#endif
