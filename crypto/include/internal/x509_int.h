/* x509_int.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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

/* Internal X509 structures and functions: not for application use */

struct X509_name_entry_st {
    ASN1_OBJECT *object;
    ASN1_STRING *value;
    int set;
    int size;                   /* temp variable */
};

/* we always keep X509_NAMEs in 2 forms. */
struct X509_name_st {
    STACK_OF(X509_NAME_ENTRY) *entries;
    int modified;               /* true if 'bytes' needs to be built */
    BUF_MEM *bytes;
/*      unsigned long hash; Keep the hash around for lookups */
    unsigned char *canon_enc;
    int canon_enclen;
} /* X509_NAME */ ;

/*
 * This stuff is certificate "auxiliary info" it contains details which are
 * useful in certificate stores and databases. When used this is tagged onto
 * the end of the certificate itself
 */

struct x509_cert_aux_st {
    STACK_OF(ASN1_OBJECT) *trust; /* trusted uses */
    STACK_OF(ASN1_OBJECT) *reject; /* rejected uses */
    ASN1_UTF8STRING *alias;     /* "friendly name" */
    ASN1_OCTET_STRING *keyid;   /* key id of private key */
    STACK_OF(X509_ALGOR) *other; /* other unspecified info */
};

struct X509_req_info_st {
    ASN1_ENCODING enc;
    ASN1_INTEGER *version;
    X509_NAME *subject;
    X509_PUBKEY *pubkey;
    /*  d=2 hl=2 l=  0 cons: cont: 00 */
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
};

struct X509_req_st {
    X509_REQ_INFO *req_info;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int references;
};

struct X509_crl_info_st {
    ASN1_INTEGER *version;
    X509_ALGOR *sig_alg;
    X509_NAME *issuer;
    ASN1_TIME *lastUpdate;
    ASN1_TIME *nextUpdate;
    STACK_OF(X509_REVOKED) *revoked;
    STACK_OF(X509_EXTENSION) /* [0] */ *extensions;
    ASN1_ENCODING enc;
};

struct X509_crl_st {
    /* actual signature */
    X509_CRL_INFO *crl;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int references;
    int flags;
    /* Copies of various extensions */
    AUTHORITY_KEYID *akid;
    ISSUING_DIST_POINT *idp;
    /* Convenient breakdown of IDP */
    int idp_flags;
    int idp_reasons;
    /* CRL and base CRL numbers for delta processing */
    ASN1_INTEGER *crl_number;
    ASN1_INTEGER *base_crl_number;
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    STACK_OF(GENERAL_NAMES) *issuers;
    const X509_CRL_METHOD *meth;
    void *meth_data;
};
