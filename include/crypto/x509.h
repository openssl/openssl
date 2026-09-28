/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_X509_H
#define OSSL_CRYPTO_X509_H
#pragma once

#include "internal/refcount.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/conf.h>
#include "crypto/types.h"

#include <crypto/asn1.h>
#include <crypto/siphash.h>

/*
 * Size in bytes of the internal X509 / X509_CRL fingerprint, see
 * ossl_x509_internal_fingerprint(). The fingerprint only short-circuits
 * X509_cmp() and X509_CRL_match(), which compare the encodings on a match,
 * so a collision costs one extra memcmp. With 64 bits a collision among
 * n objects has probability about n^2 / 2^65: one in 10^12 for 10,000
 * certificates, and even odds only at around 2^32 of them. The SipHash key
 * is fixed, so an attacker can craft certificates that collide, but gains
 * only that memcmp per colliding pair on certificates they had to supply.
 */
#define OSSL_X509_FINGERPRINT_SIZE SIPHASH_MIN_DIGEST_SIZE

/* Internal X509 structures and functions: not for application use */

/* Note: unless otherwise stated a field pointer is mandatory and should
 * never be set to NULL: the ASN.1 code and accessors rely on mandatory
 * fields never being NULL.
 */

/*
 * name entry structure, equivalent to AttributeTypeAndValue defined
 * in RFC5280 et al.
 */
struct X509_name_entry_st {
    ASN1_OBJECT *object; /* AttributeType */
    ASN1_STRING *value; /* AttributeValue */
    int set; /* index of RDNSequence for this entry */
    int size; /* temp variable */
};

/* Name from RFC 5280. */
struct X509_name_st {
    STACK_OF(X509_NAME_ENTRY) *entries; /* DN components */
    int modified; /* true if 'bytes' needs to be built */
    BUF_MEM *bytes; /* cached encoding: cannot be NULL */
    /* canonical encoding used for rapid Name comparison */
    unsigned char *canon_enc;
    int canon_enclen;
} /* X509_NAME */;

/* Signature info structure */

struct x509_sig_info_st {
    /* NID of message digest */
    int mdnid;
    /* NID of public key algorithm */
    int pknid;
    /* Security bits */
    int secbits;
    /* Various flags */
    uint32_t flags;
};

/* PKCS#10 certificate request */

struct X509_req_info_st {
    ASN1_ENCODING enc; /* cached encoding of signed part */
    ASN1_INTEGER *version; /* version, defaults to v1(0) so can be NULL */
    X509_NAME *subject; /* certificate request DN */
    X509_PUBKEY *pubkey; /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(X509_ATTRIBUTE) *attributes;
};

struct X509_req_st {
    X509_REQ_INFO req_info; /* signed certificate request data */
    X509_ALGOR sig_alg; /* signature algorithm */
    ASN1_BIT_STRING *signature; /* signature */
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;

    /* Set on live certificates for authentication purposes */
    ASN1_OCTET_STRING *distinguishing_id;
    OSSL_LIB_CTX *libctx;
    char *propq;
};

struct X509_crl_info_st {
    ASN1_INTEGER *version; /* version: defaults to v1(0) so may be NULL */
    X509_ALGOR sig_alg; /* signature algorithm */
    X509_NAME *issuer; /* CRL issuer name */
    ASN1_TIME *lastUpdate; /* lastUpdate field */
    ASN1_TIME *nextUpdate; /* nextUpdate field: optional */
    STACK_OF(X509_REVOKED) *revoked; /* revoked entries: optional */
    STACK_OF(X509_EXTENSION) *extensions; /* extensions: optional */
    ASN1_ENCODING enc; /* encoding of signed portion of CRL */
};

struct X509_crl_st {
    X509_CRL_INFO crl; /* signed CRL data */
    X509_ALGOR sig_alg; /* CRL signature algorithm */
    ASN1_BIT_STRING signature; /* CRL signature */
    CRYPTO_REF_COUNT references;
    int flags;
    /*
     * Cached copies of decoded extension values, since extensions
     * are optional any of these can be NULL.
     */
    AUTHORITY_KEYID *akid;
    ISSUING_DIST_POINT *idp;
    /* Convenient breakdown of IDP */
    int idp_flags;
    int idp_reasons;
    /* CRL and base CRL numbers for delta processing */
    ASN1_INTEGER *crl_number;
    ASN1_INTEGER *base_crl_number;
    STACK_OF(GENERAL_NAMES) *issuers;
    /*
     * Internal-use fingerprint for X509_CRL_match(), see
     * ossl_x509_internal_fingerprint(). Not cryptographically secure and
     * not collision free: a match is confirmed by comparing the CRLs.
     */
    unsigned char fingerprint[OSSL_X509_FINGERPRINT_SIZE];
    /* alternative method to handle this CRL */
    const X509_CRL_METHOD *meth;
    void *meth_data;
    CRYPTO_RWLOCK *lock;

    OSSL_LIB_CTX *libctx;
    char *propq;
};

struct x509_revoked_st {
    ASN1_INTEGER serialNumber; /* revoked entry serial number */
    ASN1_TIME *revocationDate; /* revocation date */
    STACK_OF(X509_EXTENSION) *extensions; /* CRL entry extensions: optional */
    /* decoded value of CRLissuer extension: set if indirect CRL */
    STACK_OF(GENERAL_NAME) *issuer;
    /* revocation reason: set to CRL_REASON_NONE if reason extension absent */
    int reason;
    /*
     * CRL entries are reordered for faster lookup of serial numbers. This
     * field contains the original load sequence for this entry.
     */
    int sequence;
};

/*
 * This stuff is certificate "auxiliary info": it contains details which are
 * useful in certificate stores and databases. When used this is tagged onto
 * the end of the certificate itself. OpenSSL specific structure not defined
 * in any RFC.
 */

struct x509_cert_aux_st {
    STACK_OF(ASN1_OBJECT) *trust; /* trusted uses */
    STACK_OF(ASN1_OBJECT) *reject; /* rejected uses */
    ASN1_UTF8STRING *alias; /* "friendly name" */
    ASN1_OCTET_STRING *keyid; /* key id of private key */
    STACK_OF(X509_ALGOR) *other; /* other unspecified info */
};

struct x509_cinf_st {
    ASN1_INTEGER *version; /* [ 0 ] default of v1 */
    ASN1_INTEGER serialNumber;
    X509_ALGOR signature;
    X509_NAME *issuer;
    X509_VAL validity;
    X509_NAME *subject;
    X509_PUBKEY *key;
    ASN1_BIT_STRING *issuerUID; /* [ 1 ] optional in v2 */
    ASN1_BIT_STRING *subjectUID; /* [ 2 ] optional in v2 */
    STACK_OF(X509_EXTENSION) *extensions; /* [ 3 ] optional in v3 */
    ASN1_ENCODING enc;
};

struct x509_st {
    X509_CINF cert_info;
    X509_ALGOR sig_alg;
    ASN1_BIT_STRING signature;
    CRYPTO_REF_COUNT references;
    CRYPTO_EX_DATA ex_data;
    /* These contain copies of various extension values */
    long ex_pathlen;
    long ex_pcpathlen;
    uint32_t ex_flags;
    uint32_t ex_kusage;
    uint32_t ex_xkusage;
    uint32_t ex_nscert;
    ASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    X509_POLICY_CACHE *policy_cache;
    STACK_OF(DIST_POINT) *crldp;
    STACK_OF(GENERAL_NAME) *altname;
    NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
    STACK_OF(IPAddressFamily) *rfc3779_addr;
    struct ASIdentifiers_st *rfc3779_asid;
#endif
    /*
     * Internal-use fingerprint for X509_cmp(), see
     * ossl_x509_internal_fingerprint(). Not cryptographically secure and
     * not collision free: a match is confirmed by comparing the certificates.
     */
    unsigned char fingerprint[OSSL_X509_FINGERPRINT_SIZE];
    X509_CERT_AUX *aux;
    CRYPTO_RWLOCK *lock;
    volatile int ex_cached;

    /* Set on live certificates for authentication purposes */
    ASN1_OCTET_STRING *distinguishing_id;

    /*
     * The certificate's CertificatePropertyList, captured from an accompanying
     * CERTIFICATE PROPERTIES block at load time (see
     * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
     * In-memory state only; not part of the certificate encoding.
     */
    ASN1_OCTET_STRING *properties;

    OSSL_LIB_CTX *libctx;
    char *propq;
} /* X509 */;

/*
 * This is a used when verifying cert chains.  Since the gathering of the
 * cert chain can take some time (and have to be 'retried', this needs to be
 * kept and passed around.
 */
struct x509_store_ctx_st { /* X509_STORE_CTX */
    X509_STORE *store;
    /* The following are set by the caller */
    /* The cert to check */
    X509 *cert; /* XXX should really be made const */
    /* chain of X509s - untrusted - passed in */
    STACK_OF(X509) *untrusted;
    /* set of CRLs passed in */
    STACK_OF(X509_CRL) *crls;
    STACK_OF(OCSP_RESPONSE) *ocsp_resp;
    X509_VERIFY_PARAM *param;
    /* Other info for use with get_issuer() */
    void *other_ctx;
    /* Callbacks for various operations */
    /* called to verify a certificate */
    int (*verify)(X509_STORE_CTX *ctx);
    /* error callback */
    int (*verify_cb)(int ok, X509_STORE_CTX *ctx);
    /* get issuers cert from ctx */
    X509_STORE_CTX_get_issuer_fn get_issuer;
    /* check issued */
    X509_STORE_CTX_check_issued_fn check_issued;
    /* Check revocation status of chain */
    int (*check_revocation)(X509_STORE_CTX *ctx);
    /* retrieve CRL */
    int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
    /* Check CRL validity */
    int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl);
    /* Check certificate against CRL */
    int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
    /* Check policy status of the chain */
    int (*check_policy)(X509_STORE_CTX *ctx);
    STACK_OF(X509) *(*lookup_certs)(const X509_STORE_CTX *ctx,
        const X509_NAME *nm);
    /* cannot constify 'ctx' param due to lookup_certs_sk() in x509_vfy.c */
    STACK_OF(X509_CRL) *(*lookup_crls)(const X509_STORE_CTX *ctx,
        const X509_NAME *nm);
    int (*cleanup)(X509_STORE_CTX *ctx);
    /* The following is built up */
    /* if 0, rebuild chain */
    int valid;
    /* number of untrusted certs */
    int num_untrusted;
    /* chain of X509s - built up and trusted */
    STACK_OF(X509) *chain;
    /* Valid policy tree */
    X509_POLICY_TREE *tree;
    /* Require explicit policy value */
    int explicit_policy;
    /* When something goes wrong, this is why */
    int error_depth;
    int error;
    X509 *current_cert; /* XXX should really be made const */
    /* cert currently being tested as valid issuer */
    X509 *current_issuer;
    /* current CRL */
    X509_CRL *current_crl;
    /* score of current CRL */
    int current_crl_score;
    /* Reason mask */
    unsigned int current_reasons;
    /* For CRL path validation: parent context */
    X509_STORE_CTX *parent;
    CRYPTO_EX_DATA ex_data;
    SSL_DANE *dane;
    /* signed via bare TA public key, rather than CA certificate */
    int bare_ta_signed;
    /* Raw Public Key */
    EVP_PKEY *rpk;

    OSSL_LIB_CTX *libctx;
    char *propq;
};

/* PKCS#8 private key info structure */

struct pkcs8_priv_key_info_st {
    ASN1_INTEGER *version;
    X509_ALGOR *pkeyalg;
    ASN1_OCTET_STRING *pkey;
    STACK_OF(X509_ATTRIBUTE) *attributes;
    ASN1_OCTET_STRING *kpub;
};

struct X509_sig_st {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *digest;
};

struct x509_object_st {
    /* one of the above types */
    X509_LOOKUP_TYPE type;
    union {
        X509 *x509;
        X509_CRL *crl;
    } data;
};

int ossl_a2i_ipadd(unsigned char *ipout, const char *ipasc);
int ossl_x509_set1_time(int *modified, ASN1_TIME **ptm, const ASN1_TIME *tm);
int ossl_x509_print_ex_brief(BIO *bio, const X509 *cert, unsigned long neg_cflags);

/* In-memory CertificatePropertyList carried on a loaded certificate. */
int ossl_x509_set1_certificate_properties(X509 *x, const uint8_t *props,
    size_t props_len);
int ossl_x509_get0_certificate_properties(const X509 *x, const uint8_t **props,
    size_t *props_len);
int ossl_x509v3_cache_extensions(const X509 *x);

/**
 * @brief Compute the internal-use fingerprint of a DER-encodable object.
 *
 * The fingerprint is cached in X509 / X509_CRL fingerprint and used only for
 * internal identity comparison (X509_cmp(), X509_CRL_match()); it is never
 * returned to callers, so the algorithm is an implementation detail
 * (currently SipHash-2-4 with a fixed key and 64-bit output; a collision
 * only costs the callers a fall through to their encoding comparison).
 * Callers hash the whole signed object (X509, X509_CRL). No algorithm
 * is fetched, so the result depends on neither the library context nor the
 * property query string of the object and stays valid if the object is
 * moved to another library context. It fails only if the object cannot be
 * DER encoded, for instance a certificate still under construction, or on
 * an allocation failure in the encoder.
 *
 * @param it the ASN1_ITEM describing @p val
 * @param val the object to encode and hash
 * @param hash output buffer for the fingerprint, OSSL_X509_FINGERPRINT_SIZE
 *             bytes
 * @returns 1 on success, 0 on failure
 */
int ossl_x509_internal_fingerprint(const ASN1_ITEM *it, const void *val,
    unsigned char *hash);

int ossl_x509_set0_libctx(X509 *x, OSSL_LIB_CTX *libctx, const char *propq);
int ossl_x509_crl_set0_libctx(X509_CRL *x, OSSL_LIB_CTX *libctx,
    const char *propq);
int ossl_x509_req_set0_libctx(X509_REQ *x, OSSL_LIB_CTX *libctx,
    const char *propq);
int ossl_asn1_item_digest_ex(const ASN1_ITEM *it, const EVP_MD *type,
    void *data, unsigned char *md, unsigned int *len,
    OSSL_LIB_CTX *libctx, const char *propq);
int ossl_x509_add_cert_new(STACK_OF(X509) **sk, const X509 *cert, int flags);
int ossl_x509_add_certs_new(STACK_OF(X509) **p_sk, const STACK_OF(X509) *certs, int flags);

STACK_OF(X509_ATTRIBUTE) *ossl_x509at_dup(const STACK_OF(X509_ATTRIBUTE) *x);
STACK_OF(X509_EXTENSION) *
ossl_x509_req_get1_extensions_by_nid(const X509_REQ *req, int nid);

int ossl_x509_PUBKEY_get0_libctx(OSSL_LIB_CTX **plibctx, const char **ppropq,
    const X509_PUBKEY *key);
/* Calculate default key identifier according to RFC 5280 section 4.2.1.2 (1) */
ASN1_OCTET_STRING *ossl_x509_pubkey_hash(X509_PUBKEY *pubkey);

X509_PUBKEY *ossl_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp,
    long len, OSSL_LIB_CTX *libctx,
    const char *propq);
void ossl_X509_PUBKEY_INTERNAL_free(X509_PUBKEY *xpub);

RSA *ossl_d2i_RSA_PSS_PUBKEY(RSA **a, const unsigned char **pp, long length);
int ossl_i2d_RSA_PSS_PUBKEY(const RSA *a, unsigned char **pp);
#ifndef OPENSSL_NO_DSA
DSA *ossl_d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length);
#endif /* OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DH
DH *ossl_d2i_DH_PUBKEY(DH **a, const unsigned char **pp, long length);
int ossl_i2d_DH_PUBKEY(const DH *a, unsigned char **pp);
DH *ossl_d2i_DHx_PUBKEY(DH **a, const unsigned char **pp, long length);
int ossl_i2d_DHx_PUBKEY(const DH *a, unsigned char **pp);
#endif /* OPENSSL_NO_DH */
#ifndef OPENSSL_NO_EC
ECX_KEY *ossl_d2i_ED25519_PUBKEY(ECX_KEY **a,
    const unsigned char **pp, long length);
int ossl_i2d_ED25519_PUBKEY(const ECX_KEY *a, unsigned char **pp);
ECX_KEY *ossl_d2i_ED448_PUBKEY(ECX_KEY **a,
    const unsigned char **pp, long length);
int ossl_i2d_ED448_PUBKEY(const ECX_KEY *a, unsigned char **pp);
ECX_KEY *ossl_d2i_X25519_PUBKEY(ECX_KEY **a,
    const unsigned char **pp, long length);
int ossl_i2d_X25519_PUBKEY(const ECX_KEY *a, unsigned char **pp);
ECX_KEY *ossl_d2i_X448_PUBKEY(ECX_KEY **a,
    const unsigned char **pp, long length);
int ossl_i2d_X448_PUBKEY(const ECX_KEY *a, unsigned char **pp);
#endif /* OPENSSL_NO_EC */

EVP_PKEY *ossl_d2i_PUBKEY_legacy(EVP_PKEY **a, const unsigned char **pp,
    long length);
int ossl_x509_check_private_key(const EVP_PKEY *k, const EVP_PKEY *pkey);

int x509v3_add_len_value_uchar(const char *name, const unsigned char *value,
    size_t vallen, STACK_OF(CONF_VALUE) **extlist);
/* Attribute addition functions not checking for duplicate attributes */
STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
    const X509_ATTRIBUTE *attr);
STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE) **x,
    const ASN1_OBJECT *obj,
    int type,
    const unsigned char *bytes,
    int len);
STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE) **x,
    int nid, int type,
    const unsigned char *bytes,
    int len);
STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE) **x,
    const char *attrname,
    int type,
    const unsigned char *bytes,
    int len);

int ossl_print_attribute_value(BIO *out,
    int obj_nid,
    const ASN1_TYPE *av,
    int indent);

int ossl_serial_number_print(BIO *out, const ASN1_INTEGER *bs, int indent);
int ossl_bio_print_hex(BIO *out, unsigned char *buf, int len);
int ossl_x509_compare_asn1_time(const X509_VERIFY_PARAM *vpm,
    const ASN1_TIME *time, int *comparison);
/* No error callback if depth < 0 */
int ossl_x509_check_cert_time(X509_STORE_CTX *ctx, X509 *x, int depth);
/**
 * @brief Return a certificate's cached TBSCertificate DER encoding.
 *
 * Returns the encoding of the signed part captured when x was parsed, so it is
 * available without re-encoding and without modifying x.  It fails if x has no
 * cached encoding, that is, if x was modified or built in memory rather than
 * parsed from DER.
 *
 * This is a stopgap that reaches into X509's internal cached encoding.  It
 * should go away once accessing the single cached TBSCertificate copy directly,
 * without a copy, is a first-class API.
 *
 * @param x the certificate
 * @param tbs set to the cached TBSCertificate bytes, owned by x
 * @param tbs_len set to the length of the bytes
 * @returns 1 on success, 0 if no cached encoding is available.
 * @see https://github.com/openssl/openssl/issues/30162
 */
int ossl_x509_get0_tbs(const X509 *x, const uint8_t **tbs, size_t *tbs_len);
/**
 * @brief Verify cert as a Merkle Tree Certificate: the proof (section 7.2) and
 *        the generic X.509 leaf checks.
 * @param ctx the verification context (the certificate, the trusted MTC CAs
 *        and cosigners on its store, and the verification parameters)
 * @param quorum how many of the store's trusted cosigners, besides the CA
 *        cosigner, must have cosigned a standalone certificate's subtree
 * @returns 1 if verified, 0 otherwise, with the reason in ctx->error.
 */
int ossl_x509_verify_mtc(X509_STORE_CTX *ctx, size_t quorum);
/**
 * @brief Apply the generic X.509 leaf checks a Merkle Tree Certificate is
 *        subject to: validity times, the identity and purpose the caller asked
 *        for, and the certificate's own well-formedness.
 *
 * ossl_x509_verify_mtc() calls this once the proof has been verified; it is
 * separate so that these checks can be exercised on their own.
 *
 * @param ctx the verification context (the certificate and the verification
 *        parameters; the store and the trusted CAs are not consulted)
 * @returns 1 if the certificate passes, 0 otherwise, with the reason in
 *          ctx->error.
 */
int ossl_x509_mtc_leaf_checks(X509_STORE_CTX *ctx);
/**
 * @brief Return the trusted Merkle Tree Certificate CAs configured on a store.
 *
 * These are the CAs added with X509_STORE_trust_mtc_ca().  The returned stack
 * is borrowed from the store (not reference-counted) and may be NULL if none
 * have been configured.  It is intended to let libssl advertise the configured
 * CA identifiers in the TLS trust_anchors extension
 * (https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/); a
 * Merkle Tree Certificate CA ID serves as the trust anchor ID (section 8.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/).
 *
 * The caller must not mutate the store concurrently, matching the other get0
 * store accessors: the trusted-CA set is expected to be configured before the
 * store is shared across handshakes.
 *
 * @param store the certificate store
 * @returns the stack of trusted MTC CAs, or NULL if none are configured.
 */
STACK_OF(OSSL_MTC_CA) *ossl_x509_store_get0_mtc_cas(const X509_STORE *store);

/*
 * Return the trust anchor IDs collected from loaded certificates'
 * CertificatePropertyLists, as the wire contents of a RequestedTrustAnchorList
 * (a run of u8-length-prefixed IDs).  Borrowed from the store; may be NULL.
 */
int ossl_x509_store_get0_trust_anchor_ids(const X509_STORE *store,
    const uint8_t **ids, size_t *ids_len);
int ossl_x509_check_crl_time(X509_STORE_CTX *ctx, X509_CRL *crl, int notify);
/**
 * @brief Whether a CRL issued by x's issuer covers x: the CRL's issuing
 *        distribution point, if any, admits x's kind of certificate and
 *        names a distribution point x's CRL distribution points name, or x
 *        has none and the CRL is the issuer's complete CRL (RFC 5280 6.3.3).
 * @param x the certificate
 * @param crl a CRL whose issuer name is x's issuer name
 * @returns 1 if crl covers x, 0 otherwise
 */
int ossl_x509_crl_covers(X509 *x, X509_CRL *crl);
int ossl_posix_to_asn1_time(int64_t posix_time, ASN1_TIME **out_time);
void ossl_x509_verify_param_set_time_posix(X509_VERIFY_PARAM *param, int64_t t);
int ossl_x509_check_host(const X509 *x, const char *chk, size_t chklen,
    unsigned int flags, char **peername);
int ossl_x509_check_ip(const X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);

#endif /* OSSL_CRYPTO_X509_H */
