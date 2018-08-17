/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#ifndef OSSL_HEADER_CMP_INT_H
# define OSSL_HEADER_CMP_INT_H

# include <openssl/ossl_typ.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/safestack.h>

# include "internal/cryptlib.h" /* for DECIMAL_SIZE */

# include <openssl/crmf.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * ##########################################################################
 * ASN.1 DECLARATIONS
 * ##########################################################################
 */

/*
 * this structure is used to store the context for CMP sessions
 * partly using OpenSSL ASN.1 types in order to ease handling it - such ASN.1
 * entries must be given first, in same order as ASN1_SEQUENCE(OSSL_CMP_CTX)
 */
struct OSSL_cmp_ctx_st {
    /* "reference and secret" for MSG_MAC_ALG */
    ASN1_OCTET_STRING *referenceValue;
    ASN1_OCTET_STRING *secretValue;

    X509 *srvCert; /* certificate used to identify the server */
    X509 *validatedSrvCert; /* stores the server Cert as soon as its
                               trust chain has been validated */
    X509 *clCert;
    /* current client certificate used to identify and sign for MSG_SIG_ALG */
    X509 *oldClCert; /* for KUR: certificate to be updated;
                        for RR: certificate to be revoked */
    X509_REQ *p10CSR; /* for P10CR: PKCS#10 CSR to be sent */
    X509_NAME *issuer;  /* issuer name to used in cert template */
    X509_NAME *subjectName; /* subject name to be used in the cert template.
                               NB: could also be taken from clcert */
    STACK_OF(GENERAL_NAME) *subjectAltNames;  /* names to be added to the
                            cert template as the subjectAltName extension */
    CERTIFICATEPOLICIES *policies; /* policies to be included in extensions */
    X509_EXTENSIONS *reqExtensions; /* exts to be added to cert template */
    STACK_OF(X509) *extraCertsOut; /* to be included in PKI messages */
    STACK_OF(X509) *extraCertsIn; /* extraCerts received from server */
    STACK_OF(X509) *caPubs; /* CA certs received from server (in IP message) */
#if 0
    OSSL_CMP_PKIFREETEXT *freeText; /* textis intended for human consumption,
                   this may be used to indicate context-specific instructions */
#endif
    OSSL_CMP_PKIFREETEXT *lastStatusString;
    X509 *newClCert; /* *new* CLIENT certificate received from the CA
     * TODO: this should be a stack since there could be more than one */
    X509_NAME *recipient; /* to set in recipient in pkiheader */
    X509_NAME *expected_sender; /* expected sender in pkiheader of response */
    ASN1_OCTET_STRING *transactionID; /* the current transaction ID */
    ASN1_OCTET_STRING *recipNonce; /* last nonce received */
    ASN1_OCTET_STRING *last_senderNonce; /* last nonce sent */
    STACK_OF(OSSL_CMP_ITAV) *geninfo_itavs;
    STACK_OF(OSSL_CMP_ITAV) *genm_itavs;

    /* non-OpenSSL ASN.1 members starting here */
    EVP_PKEY *pkey;    /* EVP_PKEY holding the *current* key pair
                        * Note: this is not an ASN.1 type */
    EVP_PKEY *newPkey; /* EVP_PKEY holding the *new* key pair
                        * Note: this is not an ASN.1 type */

    /* PBMParameters */
    size_t pbm_slen;
    int pbm_owf;
    long pbm_itercnt;
    int pbm_mac;

    int days; /* Number of days new certificates are asked to be valid for */
    int SubjectAltName_nodefault;
    int setSubjectAltNameCritical;
    int setPoliciesCritical;
    int digest; /* NID of digest used in MSG_SIG_ALG, defaults to SHA256 */
    int popoMethod;  /* Proof-of-posession mechanism used.
                        Defaults to signature (POPOsigningKey) */
    int revocationReason; /* Revocation reason code to be included in RR */
    int permitTAInExtraCertsForIR; /* whether to include root certs from
                     extracerts when validating? Used for 3GPP-style E.7 */

    int implicitConfirm;  /* set implicitConfirm in IR/KUR/CR messages */
    int disableConfirm;  /* disable confirmation messages in IR/KUR/CR
                            message exchanges to cope with broken server */
    int unprotectedSend; /* send unprotected PKI messages */
    int unprotectedErrors; /* accept unprotected error responses */
    int ignore_keyusage; /* ignore key usage entry in certs */
    long lastPKIStatus; /* PKIStatus of last received IP/CP/KUP/RP, or -1 */
    /* TODO: this should be a stack since there could be more than one */
    unsigned long failInfoCode; /* failInfoCode of last received IP/CP/KUP */
    /* TODO: this should be a stack since there could be more than one */
    OSSL_cmp_log_cb_t log_cb; /* log callback for error/debug/etc. output */
    OSSL_cmp_certConf_cb_t certConf_cb;   /* callback for letting the user check
                           the received certificate and reject if necessary */
    void *certConf_cb_arg; /* allows to store an argument individual to cb */
    X509_STORE *trusted_store;    /* store for trusted (root) certificates and
                                     possibly CRLs and cert verify callback */
    STACK_OF(X509) *untrusted_certs;  /* untrusted (intermediate) certs */

    /* HTTP transfer related settings */
    char *serverName;
    int serverPort;
    char *serverPath;
    char *proxyName;
    int proxyPort;
    int msgtimeout; /* maximum time in seconds to wait for
                       each CMP message round trip to complete */
    int totaltimeout; /* maximum number seconds an enrollment may take, incl.
         attempts polling for a response if a 'waiting' PKIStatus is received */
    time_t end_time;
    OSSL_cmp_http_cb_t http_cb;
    void *http_cb_arg; /* allows to store optional argument to cb */
    OSSL_cmp_transfer_cb_t transfer_cb;
    void *transfer_cb_arg; /* allows to store optional argument to cb */
} /* OSSL_CMP_CTX */;

/*-
 *   RevAnnContent ::= SEQUENCE {
 *       status              PKIStatus,
 *       certId              CertId,
 *       willBeRevokedAt     GeneralizedTime,
 *       badSinceDate        GeneralizedTime,
 *       crlDetails          Extensions  OPTIONAL
 *       -- extra CRL details (e.g., crl number, reason, location, etc.)
 *   }
 */
typedef struct OSSL_cmp_revanncontent_st {
    ASN1_INTEGER *status;
    OSSL_CRMF_CERTID *certId;
    ASN1_GENERALIZEDTIME *willBeRevokedAt;
    ASN1_GENERALIZEDTIME *badSinceDate;
    X509_EXTENSIONS *crlDetails;
} OSSL_CMP_REVANNCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_REVANNCONTENT)

/*-
 *   Challenge ::= SEQUENCE {
 *       owf                 AlgorithmIdentifier  OPTIONAL,
 *
 *       -- MUST be present in the first Challenge; MAY be omitted in
 *       -- any subsequent Challenge in POPODecKeyChallContent (if
 *       -- omitted, then the owf used in the immediately preceding
 *       -- Challenge is to be used).
 *
 *       witness             OCTET STRING,
 *       -- the result of applying the one-way function (owf) to a
 *       -- randomly-generated INTEGER, A.  [Note that a different
 *       -- INTEGER MUST be used for each Challenge.]
 *       challenge           OCTET STRING
 *       -- the encryption (under the public key for which the cert.
 *       -- request is being made) of Rand, where Rand is specified as
 *       --   Rand ::= SEQUENCE {
 *       --      int      INTEGER,
 *       --       - the randomly-generated INTEGER A (above)
 *       --      sender   GeneralName
 *       --       - the sender's name (as included in PKIHeader)
 *       --   }
 *   }
 */
typedef struct OSSL_cmp_challenge_st {
    X509_ALGOR *owf;
    ASN1_OCTET_STRING *witness;
    ASN1_OCTET_STRING *challenge;
} OSSL_CMP_CHALLENGE;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CHALLENGE)

/*-
 *  CAKeyUpdAnnContent ::= SEQUENCE {
 *     oldWithNew         Certificate,
 *     newWithOld         Certificate,
 *     newWithNew         Certificate
 *  }
 */
typedef struct OSSL_cmp_cakeyupdanncontent_st {
    X509 *oldWithNew;
    X509 *newWithOld;
    X509 *newWithNew;
} OSSL_CMP_CAKEYUPDANNCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CAKEYUPDANNCONTENT)

/*-
 * declared already here as it will be used in OSSL_CMP_MSG (nested) and
 * infotype and * value
 */
typedef STACK_OF(OSSL_CMP_MSG) OSSL_CMP_MSGS;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_MSGS)

/*-
 *   InfoTypeAndValue ::= SEQUENCE {
 *       infoType               OBJECT IDENTIFIER,
 *       infoValue              ANY DEFINED BY infoType  OPTIONAL
 *   }
 */
struct OSSL_cmp_itav_st {
    ASN1_OBJECT *infoType;
    union {
        char *ptr;
        /* NID_id_it_caProtEncCert - CA Protocol Encryption Certificate  */
        X509 *caProtEncCert;
        /* NID_id_it_signKeyPairTypes - Signing Key Pair Types  */
        STACK_OF(X509_ALGOR) *signKeyPairTypes;
        /* NID_id_it_encKeyPairTypes - Encryption/Key Agreement Key Pair Types*/
        STACK_OF(X509_ALGOR) *encKeyPairTypes;
        /* NID_id_it_preferredSymmAlg - Preferred Symmetric Algorithm  */
        X509_ALGOR *preferredSymmAlg;
        /* NID_id_it_caKeyUpdateInfo - Updated CA Key Pair */
        OSSL_CMP_CAKEYUPDANNCONTENT *caKeyUpdateInfo;
        /* NID_id_it_currentCRL - CRL  */
        X509_CRL *currentCRL;
        /* NID_id_it_unsupportedOIDs - Unsupported Object Identifiers */
        STACK_OF(ASN1_OBJECT) *unsupportedOIDs;
        /* NID_id_it_keyPairParamReq - Key Pair Parameters Request */
        ASN1_OBJECT *keyPairParamReq;
        /* NID_id_it_keyPairParamRep - Key Pair Parameters Response  */
        X509_ALGOR *keyPairParamRep;
        /* NID_id_it_revPassphrase - Revocation Passphrase */
        OSSL_CRMF_ENCRYPTEDVALUE *revPassphrase;
        /* NID_id_it_implicitConfirm - ImplicitConfirm  */
        ASN1_NULL *implicitConfirm;
        /* NID_id_it_confirmWaitTime - ConfirmWaitTime  */
        ASN1_GENERALIZEDTIME *confirmWaitTime;
        /* NID_id_it_origPKIMessage - origPKIMessage  */
        OSSL_CMP_MSGS *origPKIMessage;
        /* NID_id_it_suppLangTags - Supported Language Tags */
        STACK_OF(ASN1_UTF8STRING) *suppLangTagsValue;
        /* this is to be used for so far undeclared objects */
        ASN1_TYPE *other;
    } infoValue;
} /* OSSL_CMP_ITAV */;
OSSL_CMP_ITAV *OSSL_CMP_ITAV_dup(OSSL_CMP_ITAV *itav);
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_ITAV)


typedef struct OSSL_cmp_certorenccert_st {
    int type;
    union {
        X509 *certificate;
        OSSL_CRMF_ENCRYPTEDVALUE *encryptedCert;
    } value;
} OSSL_CMP_CERTORENCCERT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CERTORENCCERT)

/*-
 *   CertifiedKeyPair ::= SEQUENCE {
 *       certOrEncCert       CertOrEncCert,
 *       privateKey      [0] EncryptedValue      OPTIONAL,
 *       -- see [CRMF] for comment on encoding
 *       publicationInfo [1] PKIPublicationInfo  OPTIONAL
 *   }
 */
typedef struct OSSL_cmp_certifiedkeypair_st {
    OSSL_CMP_CERTORENCCERT *certOrEncCert;
    OSSL_CRMF_ENCRYPTEDVALUE *privateKey;
    OSSL_CRMF_PKIPUBLICATIONINFO *failInfo;
} OSSL_CMP_CERTIFIEDKEYPAIR;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CERTIFIEDKEYPAIR)

/*-
 *   PKIStatusInfo ::= SEQUENCE {
 *       status        PKIStatus,
 *       statusString  PKIFreeText     OPTIONAL,
 *       failInfo      PKIFailureInfo  OPTIONAL
 *   }
 */
struct OSSL_cmp_pkisi_st {
    OSSL_CMP_PKISTATUS *status;
    OSSL_CMP_PKIFREETEXT *statusString;
    OSSL_CMP_PKIFAILUREINFO *failInfo;
} /* OSSL_CMP_PKISI */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_PKISI)
OSSL_CMP_PKISI *OSSL_CMP_PKISI_dup(OSSL_CMP_PKISI *itav);

/*-
 *  RevReqContent ::= SEQUENCE OF RevDetails
 *
 *  RevDetails ::= SEQUENCE {
 *      certDetails         CertTemplate,
 *      crlEntryDetails     Extensions       OPTIONAL
 *  }
 */
typedef struct OSSL_cmp_revdetails_st {
    OSSL_CRMF_CERTTEMPLATE *certDetails;
    X509_EXTENSIONS *crlEntryDetails;
} OSSL_CMP_REVDETAILS;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_REVDETAILS)
DEFINE_STACK_OF(OSSL_CMP_REVDETAILS)

/*-
 *   RevRepContent ::= SEQUENCE {
 *       status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
 *       -- in same order as was sent in RevReqContent
 *       revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
 *                                           OPTIONAL,
 *       -- IDs for which revocation was requested
 *       -- (same order as status)
 *       crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList
 *                                           OPTIONAL
 *       -- the resulting CRLs (there may be more than one)
 *   }
 */
struct OSSL_cmp_revrepcontent_st {
    STACK_OF(OSSL_CMP_PKISI) *status;
    STACK_OF(OSSL_CRMF_CERTID) *certId;
    STACK_OF(X509) *crls;
} /* OSSL_CMP_REVREPCONTENT */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_REVREPCONTENT)

/*-
 *  KeyRecRepContent ::= SEQUENCE {
 *      status          PKIStatusInfo,
 *      newSigCert  [0] Certificate                   OPTIONAL,
 *      caCerts     [1] SEQUENCE SIZE (1..MAX) OF
 *                                   Certificate      OPTIONAL,
 *      keyPairHist [2] SEQUENCE SIZE (1..MAX) OF
 *                                   CertifiedKeyPair OPTIONAL
 *   }
 */
typedef struct OSSL_cmp_keyrecrepcontent_st {
    OSSL_CMP_PKISI *status;
    X509 *newSigCert;
    STACK_OF(X509) *caCerts;
    STACK_OF(OSSL_CMP_CERTIFIEDKEYPAIR) *keyPairHist;
} OSSL_CMP_KEYRECREPCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_KEYRECREPCONTENT)
/*-
 *   ErrorMsgContent ::= SEQUENCE {
 *       pKIStatusInfo          PKIStatusInfo,
 *       errorCode              INTEGER           OPTIONAL,
 *       -- implementation-specific error codes
 *       errorDetails           PKIFreeText       OPTIONAL
 *       -- implementation-specific error details
 *   }
 */
typedef struct OSSL_cmp_errormsgcontent_st {
    OSSL_CMP_PKISI *pKIStatusInfo;
    ASN1_INTEGER *errorCode;
    OSSL_CMP_PKIFREETEXT *errorDetails;
} OSSL_CMP_ERRORMSGCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_ERRORMSGCONTENT)

/*-
 *   CertConfirmContent ::= SEQUENCE OF CertStatus
 *
 *   CertStatus ::= SEQUENCE {
 *      certHash    OCTET STRING,
 *      -- the hash of the certificate, using the same hash algorithm
 *      -- as is used to create and verify the certificate signature
 *      certReqId   INTEGER,
 *      -- to match this confirmation with the corresponding req/rep
 *      statusInfo  PKIStatusInfo OPTIONAL
 *   }
 */
struct OSSL_cmp_certstatus_st {
    ASN1_OCTET_STRING *certHash;
    ASN1_INTEGER *certReqId;
    OSSL_CMP_PKISI *statusInfo;
} /* OSSL_CMP_CERTSTATUS */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CERTSTATUS)

typedef STACK_OF(OSSL_CMP_CERTSTATUS) OSSL_CMP_CERTCONFIRMCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CERTCONFIRMCONTENT)

/*-
 *   CertResponse ::= SEQUENCE {
 *       certReqId           INTEGER,
 *       -- to match this response with corresponding request (a value
 *       -- of -1 is to be used if certReqId is not specified in the
 *       -- corresponding request)
 *       status              PKIStatusInfo,
 *       certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
 *       rspInfo             OCTET STRING        OPTIONAL
 *       -- analogous to the id-regInfo-utf8Pairs string defined
 *       -- for regInfo in CertReqMsg [CRMF]
 *   }
 */
struct OSSL_cmp_certresponse_st {
    ASN1_INTEGER *certReqId;
    OSSL_CMP_PKISI *status;
    OSSL_CMP_CERTIFIEDKEYPAIR *certifiedKeyPair;
    ASN1_OCTET_STRING *rspInfo;
} /* OSSL_CMP_CERTRESPONSE */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CERTRESPONSE)

/*-
 *   CertRepMessage ::= SEQUENCE {
 *       caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
 *                        OPTIONAL,
 *       response         SEQUENCE OF CertResponse
 *   }
 */
struct OSSL_cmp_certrepmessage_st {
    STACK_OF(X509) *caPubs;
    STACK_OF(OSSL_CMP_CERTRESPONSE) *response;
} /* OSSL_CMP_CERTREPMESSAGE */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CERTREPMESSAGE)

/*-
 *   PollReqContent ::= SEQUENCE OF SEQUENCE {
 *         certReqId                              INTEGER
 *   }
 */
typedef struct OSSL_cmp_pollreq_st {
    ASN1_INTEGER *certReqId;
} OSSL_CMP_POLLREQ;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_POLLREQ)
DEFINE_STACK_OF(OSSL_CMP_POLLREQ)
typedef STACK_OF(OSSL_CMP_POLLREQ) OSSL_CMP_POLLREQCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_POLLREQCONTENT)

/*-
 * PollRepContent ::= SEQUENCE OF SEQUENCE {
 *         certReqId                              INTEGER,
 *         checkAfter                             INTEGER,  -- time in seconds
 *         reason                                 PKIFreeText OPTIONAL
 * }
 */
struct OSSL_cmp_pollrep_st {
    ASN1_INTEGER *certReqId;
    ASN1_INTEGER *checkAfter;
    OSSL_CMP_PKIFREETEXT *reason;
} /* OSSL_CMP_POLLREP */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_POLLREP)
DEFINE_STACK_OF(OSSL_CMP_POLLREP)
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_POLLREPCONTENT)

/*-
 * PKIHeader ::= SEQUENCE {
 *     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
 *     sender              GeneralName,
 *     -- identifies the sender
 *     recipient           GeneralName,
 *     -- identifies the intended recipient
 *     messageTime     [0] GeneralizedTime         OPTIONAL,
 *     -- time of production of this message (used when sender
 *     -- believes that the transport will be "suitable"; i.e.,
 *     -- that the time will still be meaningful upon receipt)
 *     protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
 *     -- algorithm used for calculation of protection bits
 *     senderKID       [2] KeyIdentifier           OPTIONAL,
 *     recipKID        [3] KeyIdentifier           OPTIONAL,
 *     -- to identify specific keys used for protection
 *     transactionID   [4] OCTET STRING            OPTIONAL,
 *     -- identifies the transaction; i.e., this will be the same in
 *     -- corresponding request, response, certConf, and PKIConf
 *     -- messages
 *     senderNonce     [5] OCTET STRING            OPTIONAL,
 *     recipNonce      [6] OCTET STRING            OPTIONAL,
 *     -- nonces used to provide replay protection, senderNonce
 *     -- is inserted by the creator of this message; recipNonce
 *     -- is a nonce previously inserted in a related message by
 *     -- the intended recipient of this message
 *     freeText        [7] PKIFreeText             OPTIONAL,
 *     -- this may be used to indicate context-specific instructions
 *     -- (this field is intended for human consumption)
 *     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
 *                            InfoTypeAndValue     OPTIONAL
 *     -- this may be used to convey context-specific information
 *     -- (this field not primarily intended for human consumption)
 *   }
 */
struct OSSL_cmp_pkiheader_st {
    ASN1_INTEGER *pvno;
    GENERAL_NAME *sender;
    GENERAL_NAME *recipient;
    ASN1_GENERALIZEDTIME *messageTime; /* 0 */
    X509_ALGOR *protectionAlg; /* 1 */
    ASN1_OCTET_STRING *senderKID; /* 2 */
    ASN1_OCTET_STRING *recipKID; /* 3 */
    ASN1_OCTET_STRING *transactionID; /* 4 */
    ASN1_OCTET_STRING *senderNonce; /* 5 */
    ASN1_OCTET_STRING *recipNonce; /* 6 */
    OSSL_CMP_PKIFREETEXT *freeText; /* 7 */
    STACK_OF(OSSL_CMP_ITAV) *generalInfo; /* 8 */
} /* OSSL_CMP_HDR */;

typedef STACK_OF(OSSL_CMP_CHALLENGE) OSSL_CMP_POPODECKEYCHALLCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_POPODECKEYCHALLCONTENT)
typedef STACK_OF(ASN1_INTEGER) OSSL_CMP_POPODECKEYRESPCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_POPODECKEYRESPCONTENT)
typedef STACK_OF(OSSL_CMP_REVDETAILS) OSSL_CMP_REVREQCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_REVREQCONTENT)
typedef STACK_OF(X509_CRL) OSSL_CMP_CRLANNCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_CRLANNCONTENT)
typedef STACK_OF(OSSL_CMP_ITAV) OSSL_CMP_GENMSGCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_GENMSGCONTENT)
typedef STACK_OF(OSSL_CMP_ITAV) OSSL_CMP_GENREPCONTENT;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_GENREPCONTENT)

/*-
 *   PKIBody ::= CHOICE {           -- message-specific body elements
 *           ir       [0]  CertReqMessages,            --Initialization Request
 *           ip       [1]  CertRepMessage,             --Initialization Response
 *           cr       [2]  CertReqMessages,            --Certification Request
 *           cp       [3]  CertRepMessage,             --Certification Response
 *           p10cr    [4]  CertificationRequest,       --imported from [PKCS10]
 *           popdecc  [5]  POPODecKeyChallContent,     --pop Challenge
 *           popdecr  [6]  POPODecKeyRespContent,      --pop Response
 *           kur      [7]  CertReqMessages,            --Key Update Request
 *           kup      [8]  CertRepMessage,             --Key Update Response
 *           krr      [9]  CertReqMessages,            --Key Recovery Request
 *           krp      [10] KeyRecRepContent,           --Key Recovery Response
 *           rr       [11] RevReqContent,              --Revocation Request
 *           rp       [12] RevRepContent,              --Revocation Response
 *           ccr      [13] CertReqMessages,            --Cross-Cert. Request
 *           ccp      [14] CertRepMessage,             --Cross-Cert. Response
 *           ckuann   [15] CAKeyUpdAnnContent,         --CA Key Update Ann.
 *           cann     [16] CertAnnContent,             --Certificate Ann.
 *           rann     [17] RevAnnContent,              --Revocation Ann.
 *           crlann   [18] CRLAnnContent,              --CRL Announcement
 *           pkiconf  [19] PKIConfirmContent,          --Confirmation
 *           nested   [20] NestedMessageContent,       --Nested Message
 *           genm     [21] GenMsgContent,              --General Message
 *           genp     [22] GenRepContent,              --General Response
 *           error    [23] ErrorMsgContent,            --Error Message
 *           certConf [24] CertConfirmContent,         --Certificate confirm
 *           pollReq  [25] PollReqContent,             --Polling request
 *           pollRep  [26] PollRepContent              --Polling response
 */
typedef struct OSSL_cmp_pkibody_st {
    int type;
    union {
        OSSL_CRMF_MSGS *ir; /* 0 */
        OSSL_CMP_CERTREPMESSAGE *ip; /* 1 */
        OSSL_CRMF_MSGS *cr; /* 2 */
        OSSL_CMP_CERTREPMESSAGE *cp; /* 3 */
        /* p10cr      [4]  CertificationRequest,     --imported from [PKCS10] */
        /* PKCS10_CERTIFICATIONREQUEST is effectively X509_REQ
           so it is used directly */
        X509_REQ *p10cr; /* 4 */
        /* popdecc    [5]  POPODecKeyChallContent, --pop Challenge */
        /* POPODecKeyChallContent ::= SEQUENCE OF Challenge */
        OSSL_CMP_POPODECKEYCHALLCONTENT *popdecc; /* 5 */
        /* popdecr    [6]  POPODecKeyRespContent,  --pop Response */
        /* POPODecKeyRespContent ::= SEQUENCE OF INTEGER */
        OSSL_CMP_POPODECKEYRESPCONTENT *popdecr; /* 6 */
        OSSL_CRMF_MSGS *kur; /* 7 */
        OSSL_CMP_CERTREPMESSAGE *kup; /* 8 */
        OSSL_CRMF_MSGS *krr; /* 9 */

        /* krp        [10] KeyRecRepContent,         --Key Recovery Response */
        OSSL_CMP_KEYRECREPCONTENT *krp; /* 10 */
        /* rr         [11] RevReqContent,            --Revocation Request */
        OSSL_CMP_REVREQCONTENT *rr; /* 11 */
        /* rp         [12] RevRepContent,            --Revocation Response */
        OSSL_CMP_REVREPCONTENT *rp; /* 12 */
        /* ccr        [13] CertReqMessages,          --Cross-Cert. Request */
        OSSL_CRMF_MSGS *ccr; /* 13 */
        /* ccp        [14] CertRepMessage,           --Cross-Cert. Response */
        OSSL_CMP_CERTREPMESSAGE *ccp; /* 14 */
        /* ckuann     [15] CAKeyUpdAnnContent,       --CA Key Update Ann. */
        OSSL_CMP_CAKEYUPDANNCONTENT *ckuann; /* 15 */
        /* cann       [16] CertAnnContent,           --Certificate Ann. */
        /* OSSL_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
        X509 *cann;         /* 16 */
        /* rann       [17] RevAnnContent,            --Revocation Ann. */
        OSSL_CMP_REVANNCONTENT *rann; /* 17 */
        /* crlann     [18] CRLAnnContent,            --CRL Announcement */
        /* CRLAnnContent ::= SEQUENCE OF CertificateList */
        OSSL_CMP_CRLANNCONTENT *crlann;
        /* PKIConfirmContent ::= NULL */
        /* pkiconf    [19] PKIConfirmContent,        --Confirmation */
        /* OSSL_CMP_PKICONFIRMCONTENT would be only a typedef of ASN1_NULL */
        /* OSSL_CMP_CONFIRMCONTENT *pkiconf; */
        /* NOTE: this should ASN1_NULL according to the RFC
           but there might be a struct in it when sent from faulty servers... */
        ASN1_TYPE *pkiconf; /* 19 */
        /* nested     [20] NestedMessageContent,     --Nested Message */
        /* NestedMessageContent ::= PKIMessages */
        OSSL_CMP_MSGS *nested; /* 20 */
        /* genm       [21] GenMsgContent,            --General Message */
        /* GenMsgContent ::= SEQUENCE OF InfoTypeAndValue */
        OSSL_CMP_GENMSGCONTENT *genm; /* 21 */
        /* genp       [22] GenRepContent,            --General Response */
        /* GenRepContent ::= SEQUENCE OF InfoTypeAndValue */
        OSSL_CMP_GENREPCONTENT *genp; /* 22 */
        /* error      [23] ErrorMsgContent,          --Error Message */
        OSSL_CMP_ERRORMSGCONTENT *error; /* 23 */
        /* certConf [24] CertConfirmContent,     --Certificate confirm */
        OSSL_CMP_CERTCONFIRMCONTENT *certConf; /* 24 */
        /* pollReq    [25] PollReqContent,           --Polling request */
        OSSL_CMP_POLLREQCONTENT *pollReq;
        /* pollRep    [26] PollRepContent            --Polling response */
        OSSL_CMP_POLLREPCONTENT *pollRep;
    } value;
} OSSL_CMP_PKIBODY;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_PKIBODY)

/*-
 *   PKIProtection ::= BIT STRING
 *
 *   PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
 *
 *    PKIMessage ::= SEQUENCE {
 *           header           PKIHeader,
 *           body             PKIBody,
 *           protection   [0] PKIProtection OPTIONAL,
 *           extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
 *                                            OPTIONAL
 *   }
 */
struct OSSL_cmp_msg_st {
    OSSL_CMP_HDR *header;
    OSSL_CMP_PKIBODY *body;
    ASN1_BIT_STRING *protection; /* 0 */
    /* OSSL_CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    STACK_OF(X509) *extraCerts; /* 1 */
} /* OSSL_CMP_MSG */;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_MSG)

/*-
 * ProtectedPart ::= SEQUENCE {
 * header    PKIHeader,
 * body      PKIBody
 * }
 */
typedef struct cmp_protectedpart_st {
    OSSL_CMP_HDR *header;
    OSSL_CMP_PKIBODY *body;
} CMP_PROTECTEDPART;
DECLARE_ASN1_FUNCTIONS(CMP_PROTECTEDPART)

/*-
 *  this is not defined here as it is already in CRMF:
 *   id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
 *   PBMParameter ::= SEQUENCE {
 *           salt                OCTET STRING,
 *           -- note:  implementations MAY wish to limit acceptable sizes
 *           -- of this string to values appropriate for their environment
 *           -- in order to reduce the risk of denial-of-service attacks
 *           owf                 AlgorithmIdentifier,
 *           -- AlgId for a One-Way Function (SHA-1 recommended)
 *           iterationCount      INTEGER,
 *           -- number of times the OWF is applied
 *           -- note:  implementations MAY wish to limit acceptable sizes
 *           -- of this integer to values appropriate for their environment
 *           -- in order to reduce the risk of denial-of-service attacks
 *           mac                 AlgorithmIdentifier
 *           -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
 *   }       -- or HMAC [RFC2104, RFC2202])
 */
/*-
 *  TODO: this is not yet defined here - but DH is anyway not used yet
 *
 *   id-DHBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 30}
 *   DHBMParameter ::= SEQUENCE {
 *           owf                 AlgorithmIdentifier,
 *           -- AlgId for a One-Way Function (SHA-1 recommended)
 *           mac                 AlgorithmIdentifier
 *           -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
 *   }       -- or HMAC [RFC2104, RFC2202])
 */
/*-
 * The following is not cared for, because it is described in section 5.2.5
 * that this is beyond the scope of CMP
 *   OOBCert ::= CMPCertificate
 *
 *   OOBCertHash ::= SEQUENCE {
 *           hashAlg         [0] AlgorithmIdentifier         OPTIONAL,
 *           certId          [1] CertId                      OPTIONAL,
 *           hashVal             BIT STRING
 *           -- hashVal is calculated over the DER encoding of the
 *           -- self-signed certificate with the identifier certID.
 *   }
 */

/*
 * constants
 */

/* certReqId for the first - and so far only - certificate request */
# define OSSL_CMP_CERTREQID 0L
/* sequence id for the first - and so far only - revocation request */
# define OSSL_CMP_REVREQSID 0L

/*
 * functions
 */

/* from cmp_msg.c */
X509_EXTENSIONS *CMP_exts_dup(X509_EXTENSIONS *extin);

/* from cmp_lib.c */
/*
OSSL_CMP_PKIFREETEXT_push_str() pushes the given text string (unless it is NULL)
to the given PKIFREETEXT ft or to a newly allocated freeText if ft is NULL.
It returns the new/updated freeText. On error it frees ft and returns NULL.
*/
OSSL_CMP_PKIFREETEXT *CMP_PKIFREETEXT_push_str(OSSL_CMP_PKIFREETEXT *ft,
                                               const char *text);

/*
OSSL_CMP_REVREPCONTENT_PKIStatusInfo_get() returns the status field of the
RevRepContent with the given request/sequence id inside a revocation response
(matching the sequence id as sent in the RevReqContent), or NULL on error.
*/
OSSL_CMP_PKISI *CMP_REVREPCONTENT_PKIStatusInfo_get(OSSL_CMP_REVREPCONTENT *rrep,
                                                    long reqId);
/*
OSSL_CMP_CERTSTATUS_set_certHash() calculates a hash of the certificate,
using the same hash algorithm as is used to create and verify the
certificate signature, and places the hash into the certHash field of a
OSSL_CMP_CERTSTATUS structure. This is used in the certConf message, for
example, to confirm that the certificate was received successfully.
*/
int CMP_CERTSTATUS_set_certHash(OSSL_CMP_CERTSTATUS *certStatus,
                                const X509 *cert);
int CMP_ITAV_stack_item_push0(STACK_OF(OSSL_CMP_ITAV) **
                              itav_sk_p, const OSSL_CMP_ITAV *itav);

/*
OSSL_CMP_CERTRESPONSE_get_certificate() attempts to retrieve the returned
certificate from the given certResponse B<crep>.
Takes the newKey in case of indirect POP from B<ctx>.
Returns a pointer to a copy of the found certificate, or NULL if not found.
*/
X509 *CMP_CERTRESPONSE_get_certificate(OSSL_CMP_CTX *ctx,
                                       OSSL_CMP_CERTRESPONSE *crep);
/*
OSSL_CMP_POLLREPCONTENT_pollRep_get0() returns a pointer to the PollRep
with the given certReqId (or the first one in case -1) inside a PollRepContent.
If no suitable PollRep is available or if there is an error, it returns NULL.
*/
OSSL_CMP_POLLREP *CMP_POLLREPCONTENT_pollRep_get0(OSSL_CMP_POLLREPCONTENT *prc,
                                                  long rid);
/*
OSSL_CMP_CERTREPMESSAGE_certResponse_get0() returns a pointer to the
CertResponse
with the given certReqId (or the first one in case -1 inside a CertRepMessage.
If no suitable CertResponse is available or there is an error, it returns NULL.
*/
OSSL_CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0(
                                    OSSL_CMP_CERTREPMESSAGE *crepmsg, long rid);
/*
OSSL_CMP_calc_protection()
calculates the protection for given PKImessage utilizing the given credentials
and the algorithm parameters set inside the message header's protectionAlg.
Does PBMAC in case B<secret> is non-NULL and signature using B<pkey> otherwise.
*/
ASN1_BIT_STRING *CMP_calc_protection(const OSSL_CMP_MSG *msg,
                                     const ASN1_OCTET_STRING *secret,
                                     const EVP_PKEY *pkey);

/* from cmp_ctx.c */
#ifdef CMP_POOR_LOG
#define CMP_LOG(x)  CMP_log_printf x /* poor man's variadic macro for C90;
   calls need argument(s) in doubly nested parentheses: LOG((args)) */
/* C99 would allow  #define LOG(...) log_print(__VA_ARGS__)  where
   the argument(s) could be given in normal parentheses: LOG(args) */
/* See also, e.g., https://en.wikipedia.org/wiki/Variadic_macro */
int CMP_log_printf(const char *file, int line, OSSL_CMP_severity level,
                   const char *fmt,...);
#endif

/* from cmp_vfy.c */
void put_cert_verify_err(int func);

/* from cmp_ses.c */

# ifdef  __cplusplus
}
# endif
#endif /* !defined OSSL_HEADER_CMP_INT_H */
