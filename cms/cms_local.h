/*
 * Copyright 2008-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_CMS_LOCAL_H
#define OSSL_CRYPTO_CMS_LOCAL_H

#include <assert.h>
#include <openssl/cms.h>
#include <openssl/x509.h>

static ossl_inline int cms_assert(int expr)
{
    assert(expr);
    return expr;
}

/* Local copies of the libcrypto-internal buffer-size limits (internal/sizes.h) */
#define CMS_MAX_NAME_SIZE 50 /* Algorithm name */
#define CMS_MAX_ALGORITHM_ID_SIZE 256 /* AlgorithmIdentifier DER */

/*
 * Cryptographic message syntax (CMS) structures: taken from RFC3852
 */

/* Forward references */

typedef struct CMS_IssuerAndSerialNumber_st CMS_IssuerAndSerialNumber;
typedef struct CMS_EncapsulatedContentInfo_st CMS_EncapsulatedContentInfo;
typedef struct CMS_SignerIdentifier_st CMS_SignerIdentifier;
typedef struct CMS_OtherRevocationInfoFormat_st CMS_OtherRevocationInfoFormat;
typedef struct CMS_OriginatorInfo_st CMS_OriginatorInfo;
typedef struct CMS_EncryptedContentInfo_st CMS_EncryptedContentInfo;
typedef struct CMS_DigestedData_st CMS_DigestedData;
typedef struct CMS_EncryptedData_st CMS_EncryptedData;
typedef struct CMS_AuthenticatedData_st CMS_AuthenticatedData;
typedef struct CMS_AuthEnvelopedData_st CMS_AuthEnvelopedData;
typedef struct CMS_CompressedData_st CMS_CompressedData;
typedef struct CMS_OtherCertificateFormat_st CMS_OtherCertificateFormat;
typedef struct CMS_KeyTransRecipientInfo_st CMS_KeyTransRecipientInfo;
typedef struct CMS_OriginatorPublicKey_st CMS_OriginatorPublicKey;
typedef struct CMS_OriginatorIdentifierOrKey_st CMS_OriginatorIdentifierOrKey;
typedef struct CMS_KeyAgreeRecipientInfo_st CMS_KeyAgreeRecipientInfo;
typedef struct CMS_RecipientKeyIdentifier_st CMS_RecipientKeyIdentifier;
typedef struct CMS_KeyAgreeRecipientIdentifier_st CMS_KeyAgreeRecipientIdentifier;
typedef struct CMS_KEKIdentifier_st CMS_KEKIdentifier;
typedef struct CMS_KEKRecipientInfo_st CMS_KEKRecipientInfo;
typedef struct CMS_PasswordRecipientInfo_st CMS_PasswordRecipientInfo;
typedef struct CMS_OtherRecipientInfo_st CMS_OtherRecipientInfo;
typedef struct CMS_KEMRecipientInfo_st CMS_KEMRecipientInfo;
typedef struct CMS_ReceiptsFrom_st CMS_ReceiptsFrom;
typedef struct CMS_CTX_st CMS_CTX;

struct CMS_CTX_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
};

struct CMS_ContentInfo_st {
    ASN1_OBJECT *contentType;
    union {
        ASN1_OCTET_STRING *data;
        CMS_SignedData *signedData;
        CMS_EnvelopedData *envelopedData;
        CMS_DigestedData *digestedData;
        CMS_EncryptedData *encryptedData;
        CMS_AuthEnvelopedData *authEnvelopedData;
        CMS_AuthenticatedData *authenticatedData;
        CMS_CompressedData *compressedData;
        ASN1_TYPE *other;
        /* Other types ... */
        void *otherData;
    } d;
    CMS_CTX ctx;
    /*-
     * Set when the content octet string is empty and is to be filled at
     * dataFinal time from the memory BIO ossl_cms_content_bio() returns.
     * Cleared:
     * - once the string has been filled;
     * - when the content is detached;
     * - when streaming is set up, where the encoder writes the content out
     *   and records its position in the string rather than filling it.
     */
    int contentIncomplete;
};

DEFINE_STACK_OF(CMS_CertificateChoices)

struct CMS_SignedData_st {
    int32_t version;
    STACK_OF(X509_ALGOR) *digestAlgorithms;
    CMS_EncapsulatedContentInfo *encapContentInfo;
    /* untrusted certificates for chain building, may include signer certs: */
    STACK_OF(CMS_CertificateChoices) *certificates;
    STACK_OF(CMS_RevocationInfoChoice) *crls;
    STACK_OF(CMS_SignerInfo) *signerInfos;
};

struct CMS_EncapsulatedContentInfo_st {
    ASN1_OBJECT *eContentType;
    ASN1_OCTET_STRING *eContent;
    /* Set to 1 if incomplete structure only part set up */
    int partial;
};

struct CMS_SignerInfo_st {
    int32_t version;
    CMS_SignerIdentifier *sid;
    X509_ALGOR *digestAlgorithm;
    STACK_OF(X509_ATTRIBUTE) *signedAttrs;
    X509_ALGOR *signatureAlgorithm;
    ASN1_OCTET_STRING *signature;
    STACK_OF(X509_ATTRIBUTE) *unsignedAttrs;
    /* Signing certificate and key */
    X509 *signer;
    EVP_PKEY *pkey;
    /* Digest and public key context for alternative parameters */
    EVP_MD_CTX *mctx;
    EVP_PKEY_CTX *pctx;
    const CMS_CTX *cms_ctx;
    /* Set to 1 if signing time attribute is to be omitted */
    int omit_signing_time;
    /* Remember which aspects have been verified */
    int verify_result; /* for this SignerInfo, all attempted verification aspects succeeded */
    int cert_verified; /* the certificate was verified successfully */
    int attr_verified; /* any given signed attributes were verified successfully */
    int content_verified; /* the signature over the content was verified successfully */
};

struct CMS_SignerIdentifier_st {
    int type;
    union {
        CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
        ASN1_OCTET_STRING *subjectKeyIdentifier;
    } d;
};

struct CMS_EnvelopedData_st {
    int32_t version;
    CMS_OriginatorInfo *originatorInfo;
    STACK_OF(CMS_RecipientInfo) *recipientInfos;
    CMS_EncryptedContentInfo *encryptedContentInfo;
    STACK_OF(X509_ATTRIBUTE) *unprotectedAttrs;
};

struct CMS_OriginatorInfo_st {
    STACK_OF(CMS_CertificateChoices) *certificates;
    STACK_OF(CMS_RevocationInfoChoice) *crls;
};

struct CMS_EncryptedContentInfo_st {
    ASN1_OBJECT *contentType;
    X509_ALGOR *contentEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedContent;
    /* Content encryption algorithm, key and tag */
    const EVP_CIPHER *cipher;
    unsigned char *key;
    size_t keylen;
    /* Borrowed from the AuthEnvelopedData mac, not owned here */
    const unsigned char *tag;
    size_t taglen;
    /* Set to 1 if we are debugging decrypt and don't fake keys for MMA */
    int debug;
    /* Set to 1 if we have no cert and need extra safety measures for MMA */
    int havenocert;
    /* Set to 1 if key length mismatch can be reported without an MMA risk */
    int harderr;
};

struct CMS_RecipientInfo_st {
    /*
     * Type which the RecipientInfo is encoded with. OtherRecipientInfo
     * encompasses different types, specified by 'type' below.
     */
    int encoded_type;
    union {
        CMS_KeyTransRecipientInfo *ktri;
        CMS_KeyAgreeRecipientInfo *kari;
        CMS_KEKRecipientInfo *kekri;
        CMS_PasswordRecipientInfo *pwri;
        CMS_OtherRecipientInfo *ori;
    } d;
    /* internal type, including ORI types */
    int type;
};

typedef CMS_SignerIdentifier CMS_RecipientIdentifier;

struct CMS_KeyTransRecipientInfo_st {
    int32_t version;
    CMS_RecipientIdentifier *rid;
    X509_ALGOR *keyEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedKey;
    /* Recipient Key and cert */
    X509 *recip;
    EVP_PKEY *pkey;
    /* Public key context for this operation */
    EVP_PKEY_CTX *pctx;
    const CMS_CTX *cms_ctx;
};

struct CMS_KeyAgreeRecipientInfo_st {
    int32_t version;
    CMS_OriginatorIdentifierOrKey *originator;
    ASN1_OCTET_STRING *ukm;
    X509_ALGOR *keyEncryptionAlgorithm;
    STACK_OF(CMS_RecipientEncryptedKey) *recipientEncryptedKeys;
    /* Public key context associated with current operation */
    EVP_PKEY_CTX *pctx;
    /* Cipher context for CEK wrapping */
    EVP_CIPHER_CTX *ctx;
    const CMS_CTX *cms_ctx;
};

struct CMS_OriginatorIdentifierOrKey_st {
    int type;
    union {
        CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
        ASN1_OCTET_STRING *subjectKeyIdentifier;
        CMS_OriginatorPublicKey *originatorKey;
    } d;
};

struct CMS_OriginatorPublicKey_st {
    X509_ALGOR *algorithm;
    ASN1_BIT_STRING *publicKey;
};

struct CMS_RecipientEncryptedKey_st {
    CMS_KeyAgreeRecipientIdentifier *rid;
    ASN1_OCTET_STRING *encryptedKey;
    /* Public key associated with this recipient */
    EVP_PKEY *pkey;
};

struct CMS_KeyAgreeRecipientIdentifier_st {
    int type;
    union {
        CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
        CMS_RecipientKeyIdentifier *rKeyId;
    } d;
};

struct CMS_RecipientKeyIdentifier_st {
    ASN1_OCTET_STRING *subjectKeyIdentifier;
    ASN1_GENERALIZEDTIME *date;
    CMS_OtherKeyAttribute *other;
};

struct CMS_KEKRecipientInfo_st {
    int32_t version;
    CMS_KEKIdentifier *kekid;
    X509_ALGOR *keyEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedKey;
    /* Extra info: symmetric key to use */
    unsigned char *key;
    size_t keylen;
    const CMS_CTX *cms_ctx;
};

struct CMS_KEKIdentifier_st {
    ASN1_OCTET_STRING *keyIdentifier;
    ASN1_GENERALIZEDTIME *date;
    CMS_OtherKeyAttribute *other;
};

struct CMS_PasswordRecipientInfo_st {
    int32_t version;
    X509_ALGOR *keyDerivationAlgorithm;
    X509_ALGOR *keyEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedKey;
    /* Extra info: password to use */
    unsigned char *pass;
    size_t passlen;
    const CMS_CTX *cms_ctx;
};

struct CMS_OtherRecipientInfo_st {
    ASN1_OBJECT *oriType;
    union {
        /* NID_id_smime_ori_kem */
        CMS_KEMRecipientInfo *kemri;
        /* anything else */
        ASN1_TYPE *other;
    } d;
};

struct CMS_KEMRecipientInfo_st {
    int32_t version;
    CMS_RecipientIdentifier *rid;
    X509_ALGOR *kem;
    ASN1_OCTET_STRING *kemct;
    X509_ALGOR *kdf;
    uint32_t kekLength;
    ASN1_OCTET_STRING *ukm;
    X509_ALGOR *wrap;
    ASN1_OCTET_STRING *encryptedKey;
    /* Public key context associated with current operation */
    EVP_PKEY_CTX *pctx;
    /* Cipher context for CEK wrapping */
    EVP_CIPHER_CTX *ctx;
    const CMS_CTX *cms_ctx;
};

struct CMS_DigestedData_st {
    int32_t version;
    X509_ALGOR *digestAlgorithm;
    CMS_EncapsulatedContentInfo *encapContentInfo;
    ASN1_OCTET_STRING *digest;
};

struct CMS_EncryptedData_st {
    int32_t version;
    CMS_EncryptedContentInfo *encryptedContentInfo;
    STACK_OF(X509_ATTRIBUTE) *unprotectedAttrs;
};

struct CMS_AuthenticatedData_st {
    int32_t version;
    CMS_OriginatorInfo *originatorInfo;
    STACK_OF(CMS_RecipientInfo) *recipientInfos;
    X509_ALGOR *macAlgorithm;
    X509_ALGOR *digestAlgorithm;
    CMS_EncapsulatedContentInfo *encapContentInfo;
    STACK_OF(X509_ATTRIBUTE) *authAttrs;
    ASN1_OCTET_STRING *mac;
    STACK_OF(X509_ATTRIBUTE) *unauthAttrs;
};

struct CMS_AuthEnvelopedData_st {
    int32_t version;
    CMS_OriginatorInfo *originatorInfo;
    STACK_OF(CMS_RecipientInfo) *recipientInfos;
    CMS_EncryptedContentInfo *authEncryptedContentInfo;
    STACK_OF(X509_ATTRIBUTE) *authAttrs;
    ASN1_OCTET_STRING *mac;
    STACK_OF(X509_ATTRIBUTE) *unauthAttrs;
};

struct CMS_CompressedData_st {
    int32_t version;
    X509_ALGOR *compressionAlgorithm;
    STACK_OF(CMS_RecipientInfo) *recipientInfos;
    CMS_EncapsulatedContentInfo *encapContentInfo;
};

struct CMS_RevocationInfoChoice_st {
    int type;
    union {
        X509_CRL *crl;
        CMS_OtherRevocationInfoFormat *other;
    } d;
};

#define CMS_REVCHOICE_CRL 0
#define CMS_REVCHOICE_OTHER 1

struct CMS_OtherRevocationInfoFormat_st {
    ASN1_OBJECT *otherRevInfoFormat;
    ASN1_TYPE *otherRevInfo;
};

struct CMS_CertificateChoices {
    int type;
    union {
        X509 *certificate;
        ASN1_STRING *extendedCertificate; /* Obsolete */
        ASN1_STRING *v1AttrCert; /* Left encoded for now */
        ASN1_STRING *v2AttrCert; /* Left encoded for now */
        CMS_OtherCertificateFormat *other;
    } d;
};

#define CMS_CERTCHOICE_CERT 0
#define CMS_CERTCHOICE_EXCERT 1
#define CMS_CERTCHOICE_V1ACERT 2
#define CMS_CERTCHOICE_V2ACERT 3
#define CMS_CERTCHOICE_OTHER 4

struct CMS_OtherCertificateFormat_st {
    ASN1_OBJECT *otherCertFormat;
    ASN1_TYPE *otherCert;
};

/*
 * This is also defined in pkcs7.h but we duplicate it to allow the CMS code
 * to be independent of PKCS#7
 */

struct CMS_IssuerAndSerialNumber_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serialNumber;
};

struct CMS_OtherKeyAttribute_st {
    ASN1_OBJECT *keyAttrId;
    ASN1_TYPE *keyAttr;
};

/* ESS structures */

struct CMS_ReceiptRequest_st {
    ASN1_OCTET_STRING *signedContentIdentifier;
    CMS_ReceiptsFrom *receiptsFrom;
    STACK_OF(GENERAL_NAMES) *receiptsTo;
};

struct CMS_ReceiptsFrom_st {
    int type;
    union {
        int32_t allOrFirstTier;
        STACK_OF(GENERAL_NAMES) *receiptList;
    } d;
};

struct CMS_Receipt_st {
    int32_t version;
    const ASN1_OBJECT *contentType;
    ASN1_OCTET_STRING *signedContentIdentifier;
    ASN1_OCTET_STRING *originatorSignatureValue;
};

DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)
DECLARE_ASN1_ITEM(CMS_SignerInfo)
DECLARE_ASN1_ITEM(CMS_EncryptedContentInfo)
DECLARE_ASN1_ITEM(CMS_IssuerAndSerialNumber)
DECLARE_ASN1_ITEM(CMS_Attributes_Sign)
DECLARE_ASN1_ITEM(CMS_Attributes_Verify)
/* The authAttrs AAD encoding matches the signed-attributes one */
#define CMS_Attributes_AadEncrypt_it CMS_Attributes_Sign_it
#define CMS_Attributes_AadDecrypt_it CMS_Attributes_Verify_it
DECLARE_ASN1_ITEM(CMS_RecipientInfo)
DECLARE_ASN1_ITEM(CMS_PasswordRecipientInfo)
DECLARE_ASN1_ALLOC_FUNCTIONS(CMS_IssuerAndSerialNumber)

#define CMS_SIGNERINFO_ISSUER_SERIAL 0
#define CMS_SIGNERINFO_KEYIDENTIFIER 1

#define CMS_RECIPINFO_ISSUER_SERIAL 0
#define CMS_RECIPINFO_KEYIDENTIFIER 1

#define CMS_REK_ISSUER_SERIAL 0
#define CMS_REK_KEYIDENTIFIER 1

#define CMS_OIK_ISSUER_SERIAL 0
#define CMS_OIK_KEYIDENTIFIER 1
#define CMS_OIK_PUBKEY 2

/**
 * @brief Create the BIO for the encapsulated content of cms.
 * A null BIO for detached content, a memory BIO for content being created,
 * and a read-only memory BIO over content that was decoded.
 * @param cms the CMS structure
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_content_bio(CMS_ContentInfo *cms);
/**
 * @brief Get the CMS context of a CMS structure.
 * @param cms the CMS structure, may be NULL
 * @returns the context, owned by cms, or NULL if cms is NULL
 */
const CMS_CTX *ossl_cms_get0_cmsctx(const CMS_ContentInfo *cms);
/**
 * @brief Get the library context of a CMS context.
 * @param ctx the CMS context, may be NULL
 * @returns the library context, or NULL
 */
OSSL_LIB_CTX *ossl_cms_ctx_get0_libctx(const CMS_CTX *ctx);
/**
 * @brief Get the property query of a CMS context.
 * @param ctx the CMS context, may be NULL
 * @returns the property query, or NULL
 */
const char *ossl_cms_ctx_get0_propq(const CMS_CTX *ctx);
/**
 * @brief Point every SignerInfo and RecipientInfo of ci at its CMS context.
 * @param ci the CMS structure
 */
void ossl_cms_infos_set_cmsctx(CMS_ContentInfo *ci);

/**
 * @brief Create a CMS structure of type data with embedded content.
 * @param libctx the library context, NULL for the default
 * @param propq the property query, may be NULL
 * @returns the structure, or NULL on error
 */
CMS_ContentInfo *ossl_cms_Data_create(OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Finalize cms after its content has been written through cmsbio.
 * Stores content being created and completes the type-specific processing.
 * @param cms the CMS structure
 * @param cmsbio the BIO chain returned by CMS_dataInit()
 * @param data the content, for signers that sign it directly, may be NULL
 * @param precomp_md a precomputed message digest, may be NULL
 * @param precomp_mdlen the length of precomp_md
 * @returns 1 on success, 0 on error
 */
int ossl_cms_DataFinal(CMS_ContentInfo *cms, BIO *cmsbio, BIO *data,
    const unsigned char *precomp_md,
    unsigned int precomp_mdlen);
/**
 * @brief Prepare the content of cms for indefinite-length streaming.
 * The content octet string is created if it is not already present, and the
 * content is recorded as created here rather than read in via d2i.
 * @param cms the CMS_ContentInfo to prepare for streaming
 * @returns 1 on success, 0 on failure
 */
int ossl_cms_stream(CMS_ContentInfo *cms);

/**
 * @brief Create a CMS structure of type digestedData.
 * @param md the digest algorithm
 * @param libctx the library context, NULL for the default
 * @param propq the property query, may be NULL
 * @returns the structure, or NULL on error
 */
CMS_ContentInfo *ossl_cms_DigestedData_create(const EVP_MD *md,
    OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Create the digest BIO for a digestedData structure.
 * @param cms the CMS structure
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_DigestedData_init_bio(const CMS_ContentInfo *cms);
/**
 * @brief Store or verify the digest of a digestedData structure.
 * @param cms the CMS structure
 * @param chain the BIO chain holding the digest BIO
 * @param verify 1 to verify the stored digest, 0 to store it
 * @returns 1 on success, 0 on error or verification failure
 */
int ossl_cms_DigestedData_do_final(const CMS_ContentInfo *cms,
    BIO *chain, int verify);

/**
 * @brief Create a chain of digest BIOs for the digest algorithms of signedData.
 * @param cms the CMS structure
 * @returns the BIO chain, or NULL on error
 */
BIO *ossl_cms_SignedData_init_bio(CMS_ContentInfo *cms);
/**
 * @brief Sign the content with each SignerInfo of a signedData structure.
 * @param cms the CMS structure
 * @param chain the BIO chain holding the digest BIOs
 * @param data the content, for signers that sign it directly, may be NULL
 * @param precomp_md a precomputed message digest, may be NULL
 * @param precomp_mdlen the length of precomp_md
 * @returns 1 on success, 0 on error
 */
int ossl_cms_SignedData_final(CMS_ContentInfo *cms, BIO *chain, BIO *data,
    const unsigned char *precomp_md,
    unsigned int precomp_mdlen);
/**
 * @brief Set a SignerIdentifier to identify a certificate.
 * @param sid the SignerIdentifier
 * @param cert the certificate
 * @param type CMS_SIGNERINFO_ISSUER_SERIAL or CMS_SIGNERINFO_KEYIDENTIFIER
 * @returns 1 on success, 0 on error
 */
int ossl_cms_set1_SignerIdentifier(CMS_SignerIdentifier *sid, X509 *cert,
    int type);
/**
 * @brief Get the identifying fields of a SignerIdentifier.
 * Only the outputs for the identifier type are set.
 * @param sid the SignerIdentifier
 * @param keyid receives the subject key identifier, may be NULL
 * @param issuer receives the issuer name, may be NULL
 * @param sno receives the serial number, may be NULL
 * @returns 1 on success, 0 for an unknown identifier type
 */
int ossl_cms_SignerIdentifier_get0_signer_id(CMS_SignerIdentifier *sid,
    ASN1_OCTET_STRING **keyid,
    X509_NAME **issuer,
    ASN1_INTEGER **sno);
/**
 * @brief Compare a SignerIdentifier with a certificate.
 * @param sid the SignerIdentifier
 * @param cert the certificate
 * @returns 0 if they match, nonzero if not, -1 for an unknown identifier type
 */
int ossl_cms_SignerIdentifier_cert_cmp(CMS_SignerIdentifier *sid, X509 *cert);

/**
 * @brief Create a CMS structure of type compressedData.
 * @param comp_nid the compression algorithm, only NID_zlib_compression
 * @param libctx the library context, NULL for the default
 * @param propq the property query, may be NULL
 * @returns the structure, or NULL on error
 */
CMS_ContentInfo *ossl_cms_CompressedData_create(int comp_nid,
    OSSL_LIB_CTX *libctx,
    const char *propq);
/**
 * @brief Create the zlib BIO for a compressedData structure.
 * @param cms the CMS structure
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_CompressedData_init_bio(const CMS_ContentInfo *cms);

/**
 * @brief Create a digest BIO for a digest algorithm.
 * @param digestAlgorithm the digest algorithm
 * @param ctx the CMS context to fetch the digest with
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_DigestAlgorithm_init_bio(X509_ALGOR *digestAlgorithm,
    const CMS_CTX *ctx);
/**
 * @brief Copy the digest context for an algorithm from a BIO chain.
 * @param mctx receives a copy of the matching digest context
 * @param chain the BIO chain to search
 * @param mdalg the digest algorithm to find
 * @returns 1 on success, 0 if none matches or on error
 */
int ossl_cms_DigestAlgorithm_find_ctx(EVP_MD_CTX *mctx, BIO *chain,
    X509_ALGOR *mdalg);

/**
 * @brief Compare an IssuerAndSerialNumber with a certificate.
 * @param ias the IssuerAndSerialNumber
 * @param cert the certificate
 * @returns 0 if they match, else nonzero
 */
int ossl_cms_ias_cert_cmp(CMS_IssuerAndSerialNumber *ias, X509 *cert);
/**
 * @brief Compare a key identifier with the subject key identifier of a
 * certificate.
 * @param keyid the key identifier
 * @param cert the certificate
 * @returns 0 if they match, nonzero if not, -1 if cert has no key identifier
 */
int ossl_cms_keyid_cert_cmp(ASN1_OCTET_STRING *keyid, X509 *cert);
/**
 * @brief Replace *pias with the issuer and serial number of a certificate.
 * @param pias the IssuerAndSerialNumber to replace
 * @param cert the certificate
 * @returns 1 on success, 0 on error
 */
int ossl_cms_set1_ias(CMS_IssuerAndSerialNumber **pias, X509 *cert);
/**
 * @brief Replace *pkeyid with the subject key identifier of a certificate.
 * @param pkeyid the key identifier to replace
 * @param cert the certificate
 * @returns 1 on success, 0 on error or if cert has no key identifier
 */
int ossl_cms_set1_keyid(ASN1_OCTET_STRING **pkeyid, X509 *cert);

/**
 * @brief Decode the RFC 5084 GCMParameters of an AEAD content cipher.
 * @param param the content-encryption algorithm parameter
 * @param iv buffer receiving the nonce
 * @param iv_max the size of iv in bytes
 * @param iv_len receives the length of the nonce
 * @returns 1 on success, 0 on failure
 */
int ossl_cms_get_aead_params(const ASN1_TYPE *param, unsigned char *iv,
    size_t iv_max, int *iv_len);
/**
 * @brief Create the cipher BIO for an EncryptedContentInfo.
 * @param ec the EncryptedContentInfo
 * @param cms_ctx the CMS context to fetch the cipher with
 * @param auth 1 for authEnvelopedData, 0 otherwise
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec,
    const CMS_CTX *cms_ctx, int auth);
/**
 * @brief Create the cipher BIO for an encryptedData structure.
 * @param cms the CMS structure
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_EncryptedData_init_bio(const CMS_ContentInfo *cms);
/**
 * @brief Set the cipher and key of an EncryptedContentInfo.
 * @param ec the EncryptedContentInfo
 * @param cipher the content cipher, may be NULL
 * @param key the content key, copied, may be NULL
 * @param keylen the length of key
 * @returns 1 on success, 0 on error
 */
int ossl_cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec,
    const EVP_CIPHER *cipher,
    const unsigned char *key, size_t keylen);

/**
 * @brief Verify a signed receipt against the signed request it answers.
 * cms must already have passed CMS_verify().
 * @param cms the signed receipt
 * @param req_cms the signedData that requested it
 * @returns 1 on success, 0 on error or verification failure
 */
int ossl_cms_Receipt_verify(CMS_ContentInfo *cms, CMS_ContentInfo *req_cms);
/**
 * @brief Add a msgSigDigest attribute for src to the signed attributes of dest.
 * @param dest the SignerInfo to add the attribute to
 * @param src the SignerInfo whose signed attributes are digested
 * @returns 1 on success, 0 on error
 */
int ossl_cms_msgSigDigest_add1(CMS_SignerInfo *dest, CMS_SignerInfo *src);
/**
 * @brief Encode the Receipt for the receipt request in a SignerInfo.
 * @param si the SignerInfo carrying the receipt request
 * @returns the DER encoding, owned by the caller, or NULL on error
 */
ASN1_OCTET_STRING *ossl_cms_encode_Receipt(CMS_SignerInfo *si);

/**
 * @brief Create the cipher BIO for an envelopedData structure.
 * Sets up encryption if a content cipher is set, else decryption.
 * @param cms the CMS structure
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_EnvelopedData_init_bio(CMS_ContentInfo *cms);
/**
 * @brief Finalize an envelopedData structure after its content is processed.
 * @param cms the CMS structure
 * @param chain the BIO chain holding the cipher BIO
 * @returns 1 on success, 0 on error
 */
int ossl_cms_EnvelopedData_final(CMS_ContentInfo *cms, BIO *chain);
/**
 * @brief Create the cipher BIO for an authEnvelopedData structure.
 * @param cms the CMS structure
 * @returns the BIO, or NULL on error
 */
BIO *ossl_cms_AuthEnvelopedData_init_bio(CMS_ContentInfo *cms);
/**
 * @brief Store the authentication tag of an authEnvelopedData being encrypted.
 * @param cms the CMS structure
 * @param cmsbio the cipher BIO
 * @returns 1 on success, 0 on error
 */
int ossl_cms_AuthEnvelopedData_final(CMS_ContentInfo *cms, BIO *cmsbio);
/**
 * @brief Get the envelopedData of a CMS structure.
 * @param cms the CMS structure
 * @returns the envelopedData, owned by cms, or NULL if cms is of another type
 */
CMS_EnvelopedData *ossl_cms_get0_enveloped(CMS_ContentInfo *cms);
/**
 * @brief Get the authEnvelopedData of a CMS structure.
 * @param cms the CMS structure
 * @returns the authEnvelopedData, owned by cms, or NULL if cms is of another
 *          type
 */
CMS_AuthEnvelopedData *ossl_cms_get0_auth_enveloped(CMS_ContentInfo *cms);
/**
 * @brief Get the EncryptedContentInfo of an (auth)envelopedData structure.
 * @param cms the CMS structure
 * @returns the EncryptedContentInfo, owned by cms, or NULL
 */
CMS_EncryptedContentInfo *ossl_cms_get0_env_enc_content(const CMS_ContentInfo *cms);

/* RecipientInfo routines */
/**
 * @brief Run the key-type specific processing of a RecipientInfo.
 * @param ri the RecipientInfo
 * @param cmd 0 for encryption, 1 for decryption
 * @returns 1 on success, 0 on error
 */
int ossl_cms_env_asn1_ctrl(CMS_RecipientInfo *ri, int cmd);
/**
 * @brief Get the RecipientInfo type a key supports.
 * @param pk the key
 * @returns a CMS_RECIPINFO_* type; CMS_RECIPINFO_TRANS if it cannot be
 *          determined
 */
int ossl_cms_pkey_get_ri_type(EVP_PKEY *pk);
/**
 * @brief Check whether a key supports a RecipientInfo type.
 * @param pk the key
 * @param ri_type the CMS_RECIPINFO_* type
 * @returns 1 if it does, else 0
 */
int ossl_cms_pkey_is_ri_type_supported(EVP_PKEY *pk, int ri_type);

/**
 * @brief Point every RecipientInfo of cms at its CMS context.
 * @param cms the CMS structure
 */
void ossl_cms_RecipientInfos_set_cmsctx(CMS_ContentInfo *cms);
/**
 * @brief Set the key wrap cipher of a kari or kemri RecipientInfo.
 * A wrap cipher already set is kept.
 * @param ri the RecipientInfo
 * @param cipher the content cipher the wrap cipher is chosen for
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_wrap_init(CMS_RecipientInfo *ri, const EVP_CIPHER *cipher);

/* KARI routines */
/**
 * @brief Initialize a key agreement RecipientInfo.
 * An ephemeral originator key is generated when originator and
 * originatorPrivKey are both NULL.
 * @param ri the RecipientInfo
 * @param recip the recipient certificate
 * @param recipPubKey the recipient public key
 * @param originator the originator certificate, may be NULL
 * @param originatorPrivKey the originator private key, may be NULL
 * @param flags CMS_USE_KEYID and CMS_USE_ORIGINATOR_KEYID select key
 *        identifiers over issuer and serial number
 * @param ctx the CMS context
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_kari_init(CMS_RecipientInfo *ri, X509 *recip,
    EVP_PKEY *recipPubKey, X509 *originator,
    EVP_PKEY *originatorPrivKey,
    unsigned int flags,
    const CMS_CTX *ctx);
/**
 * @brief Encrypt the content key for each recipient of a kari RecipientInfo.
 * @param cms the CMS structure
 * @param ri the RecipientInfo
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_kari_encrypt(const CMS_ContentInfo *cms,
    CMS_RecipientInfo *ri);

/* KEMRI routines */
/**
 * @brief Get the KEK length and wrap algorithm of a kemri RecipientInfo.
 * @param ri the RecipientInfo
 * @param pkekLength receives a pointer to the KEK length, may be NULL
 * @param pwrap receives the wrap algorithm, may be NULL
 * @returns 1 on success, 0 if ri is not a kemri
 */
int ossl_cms_RecipientInfo_kemri_get0_alg(CMS_RecipientInfo *ri,
    uint32_t **pkekLength,
    X509_ALGOR **pwrap);
/**
 * @brief Initialize a KEM RecipientInfo.
 * @param ri the RecipientInfo
 * @param recip the recipient certificate
 * @param recipPubKey the recipient public key
 * @param flags CMS_USE_KEYID selects a key identifier over issuer and serial
 * @param ctx the CMS context
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_kemri_init(CMS_RecipientInfo *ri, X509 *recip,
    EVP_PKEY *recipPubKey, unsigned int flags,
    const CMS_CTX *ctx);
/**
 * @brief Encapsulate and wrap the content key for a kemri RecipientInfo.
 * @param cms the CMS structure
 * @param ri the RecipientInfo
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_kemri_encrypt(const CMS_ContentInfo *cms,
    CMS_RecipientInfo *ri);
/**
 * @brief Decapsulate and unwrap the content key of a kemri RecipientInfo.
 * @param cms the CMS structure
 * @param ri the RecipientInfo
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_kemri_decrypt(const CMS_ContentInfo *cms,
    CMS_RecipientInfo *ri);
/**
 * @brief DER-encode a CMSORIforKEMOtherInfo.
 * @param pder receives the encoding as for i2d functions
 * @param wrap the wrap algorithm
 * @param ukm the user keying material, may be NULL
 * @param keylen the KEK length
 * @returns the length of the encoding, or a value <= 0 on error
 */
int CMS_CMSORIforKEMOtherInfo_encode(unsigned char **pder, X509_ALGOR *wrap,
    ASN1_OCTET_STRING *ukm, int keylen);

/* PWRI routines */
/**
 * @brief Wrap or unwrap the content key of a password RecipientInfo.
 * @param cms the CMS structure
 * @param ri the RecipientInfo
 * @param en_de 1 to wrap, 0 to unwrap
 * @returns 1 on success, 0 on error
 */
int ossl_cms_RecipientInfo_pwri_crypt(const CMS_ContentInfo *cms,
    CMS_RecipientInfo *ri, int en_de);
/* SignerInfo routines */
/**
 * @brief Check that the attributes of a SignerInfo obey the CMS rules.
 * @param si the SignerInfo
 * @returns 1 if they do, else 0
 */
int ossl_cms_si_check_attributes(const CMS_SignerInfo *si);
/**
 * @brief Point every SignerInfo of cms at its CMS context.
 * @param cms the CMS structure
 */
void ossl_cms_SignerInfos_set_cmsctx(CMS_ContentInfo *cms);

/* ESS routines */
/**
 * @brief Check the ESS signing certificate attributes of a SignerInfo.
 * @param si the SignerInfo
 * @param chain the signer certificate chain
 * @returns 1 if they match the chain, else 0
 */
int ossl_cms_check_signing_certs(const CMS_SignerInfo *si,
    const STACK_OF(X509) *chain);

/**
 * @brief Run the DH key agreement processing of a RecipientInfo.
 * @param ri the RecipientInfo
 * @param decrypt 1 for decryption, 0 for encryption
 * @returns 1 on success, 0 on error
 */
int ossl_cms_dh_envelope(CMS_RecipientInfo *ri, int decrypt);
/**
 * @brief Run the ECDH key agreement processing of a RecipientInfo.
 * @param ri the RecipientInfo
 * @param decrypt 1 for decryption, 0 for encryption
 * @returns 1 on success, 0 on error
 */
int ossl_cms_ecdh_envelope(CMS_RecipientInfo *ri, int decrypt);
/**
 * @brief Run the RSA key transport processing of a RecipientInfo.
 * @param ri the RecipientInfo
 * @param decrypt 1 for decryption, 0 for encryption
 * @returns 1 on success, 0 on error
 */
int ossl_cms_rsa_envelope(CMS_RecipientInfo *ri, int decrypt);
/**
 * @brief Run the RSA signature processing of a SignerInfo.
 * @param si the SignerInfo
 * @param verify 1 for verification, 0 for signing
 * @returns 1 on success, 0 on error
 */
int ossl_cms_rsa_sign(CMS_SignerInfo *si, int verify);
/**
 * @brief Run the KEM processing of a RecipientInfo.
 * @param ri the RecipientInfo
 * @param decrypt 1 for decryption, 0 for encryption
 * @returns 1 on success, 0 on error
 */
int ossl_cms_kem_envelope(CMS_RecipientInfo *ri, int decrypt);

/**
 * @brief Get the certificates of a CMS structure.
 * @param cms the CMS structure
 * @param certs receives the certificates, owned by the caller; NULL on error
 * @returns 1 on success, 0 on error
 */
int ossl_cms_get1_certs_ex(CMS_ContentInfo *cms, STACK_OF(X509) **certs);
/**
 * @brief Get the CRLs of a CMS structure.
 * @param cms the CMS structure
 * @param crls receives the CRLs, owned by the caller; NULL on error
 * @returns 1 on success, 0 on error
 */
int ossl_cms_get1_crls_ex(CMS_ContentInfo *cms, STACK_OF(X509_CRL) **crls);

DECLARE_ASN1_ITEM(CMS_CertificateChoices)
DECLARE_ASN1_ITEM(CMS_DigestedData)
DECLARE_ASN1_ITEM(CMS_EncryptedData)
DECLARE_ASN1_ITEM(CMS_EnvelopedData)
DECLARE_ASN1_ITEM(CMS_AuthEnvelopedData)
DECLARE_ASN1_ITEM(CMS_KEKRecipientInfo)
DECLARE_ASN1_ITEM(CMS_KEMRecipientInfo)
DECLARE_ASN1_ITEM(CMS_KeyAgreeRecipientInfo)
DECLARE_ASN1_ITEM(CMS_KeyTransRecipientInfo)
DECLARE_ASN1_ITEM(CMS_OriginatorPublicKey)
DECLARE_ASN1_ITEM(CMS_OtherKeyAttribute)
DECLARE_ASN1_ITEM(CMS_OtherRecipientInfo)
DECLARE_ASN1_ITEM(CMS_Receipt)
DECLARE_ASN1_ITEM(CMS_ReceiptRequest)
DECLARE_ASN1_ITEM(CMS_RecipientEncryptedKey)
DECLARE_ASN1_ITEM(CMS_RecipientKeyIdentifier)
DECLARE_ASN1_ITEM(CMS_RevocationInfoChoice)
DECLARE_ASN1_ITEM(CMS_SignedData)
DECLARE_ASN1_ITEM(CMS_CompressedData)

#endif
