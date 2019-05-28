/*-
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP (RFC 4210) implementation by M. Peylo, M. Viljanen, and D. von Oheimb.
 */

#ifndef OSSL_HEADER_CMP_H
# define OSSL_HEADER_CMP_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMP
#  include <openssl/crmf.h>
#  include <openssl/cmperr.h>

/* explicit #includes not strictly needed since implied by the above: */
#  include <openssl/ossl_typ.h>
#  include <openssl/safestack.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>

#  define OSSL_CMP_PVNO 2

#  ifdef  __cplusplus
extern "C" {
#  endif

/*-
 *   PKIFailureInfo ::= BIT STRING {
 *   -- since we can fail in more than one way!
 *   -- More codes may be added in the future if/when required.
 *       badAlg              (0),
 *       -- unrecognized or unsupported Algorithm Identifier
 *       badMessageCheck     (1),
 *       -- integrity check failed (e.g., signature did not verify)
 *       badRequest          (2),
 *       -- transaction not permitted or supported
 *       badTime             (3),
 *       -- messageTime was not sufficiently close to the system time,
 *       -- as defined by local policy
 *       badCertId           (4),
 *       -- no certificate could be found matching the provided criteria
 *       badDataFormat       (5),
 *       -- the data submitted has the wrong format
 *       wrongAuthority      (6),
 *       -- the authority indicated in the request is different from the
 *       -- one creating the response token
 *       incorrectData       (7),
 *       -- the requester's data is incorrect (for notary services)
 *       missingTimeStamp    (8),
 *       -- when the timestamp is missing but should be there
 *       -- (by policy)
 *       badPOP              (9),
 *       -- the proof-of-possession failed
 *       certRevoked         (10),
 *          -- the certificate has already been revoked
 *       certConfirmed       (11),
 *          -- the certificate has already been confirmed
 *       wrongIntegrity      (12),
 *          -- invalid integrity, password based instead of signature or
 *          -- vice versa
 *       badRecipientNonce   (13),
 *          -- invalid recipient nonce, either missing or wrong value
 *       timeNotAvailable    (14),
 *          -- the TSA's time source is not available
 *       unacceptedPolicy    (15),
 *          -- the requested TSA policy is not supported by the TSA.
 *       unacceptedExtension (16),
 *          -- the requested extension is not supported by the TSA.
 *       addInfoNotAvailable (17),
 *          -- the additional information requested could not be
 *          -- understood or is not available
 *       badSenderNonce      (18),
 *          -- invalid sender nonce, either missing or wrong size
 *       badCertTemplate     (19),
 *          -- invalid cert. template or missing mandatory information
 *       signerNotTrusted    (20),
 *          -- signer of the message unknown or not trusted
 *       transactionIdInUse  (21),
 *          -- the transaction identifier is already in use
 *       unsupportedVersion  (22),
 *          -- the version of the message is not supported
 *       notAuthorized       (23),
 *          -- the sender was not authorized to make the preceding
 *          -- request or perform the preceding action
 *       systemUnavail       (24),
 *       -- the request cannot be handled due to system unavailability
 *       systemFailure       (25),
 *       -- the request cannot be handled due to system failure
 *       duplicateCertReq    (26)
 *       -- certificate cannot be issued because a duplicate
 *       -- certificate already exists
 *   }
 */
#  define OSSL_CMP_PKIFAILUREINFO_badAlg 0
#  define OSSL_CMP_PKIFAILUREINFO_badMessageCheck 1
#  define OSSL_CMP_PKIFAILUREINFO_badRequest 2
#  define OSSL_CMP_PKIFAILUREINFO_badTime 3
#  define OSSL_CMP_PKIFAILUREINFO_badCertId 4
#  define OSSL_CMP_PKIFAILUREINFO_badDataFormat 5
#  define OSSL_CMP_PKIFAILUREINFO_wrongAuthority 6
#  define OSSL_CMP_PKIFAILUREINFO_incorrectData 7
#  define OSSL_CMP_PKIFAILUREINFO_missingTimeStamp 8
#  define OSSL_CMP_PKIFAILUREINFO_badPOP 9
#  define OSSL_CMP_PKIFAILUREINFO_certRevoked 10
#  define OSSL_CMP_PKIFAILUREINFO_certConfirmed 11
#  define OSSL_CMP_PKIFAILUREINFO_wrongIntegrity 12
#  define OSSL_CMP_PKIFAILUREINFO_badRecipientNonce 13
#  define OSSL_CMP_PKIFAILUREINFO_timeNotAvailable 14
#  define OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy 15
#  define OSSL_CMP_PKIFAILUREINFO_unacceptedExtension 16
#  define OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable 17
#  define OSSL_CMP_PKIFAILUREINFO_badSenderNonce 18
#  define OSSL_CMP_PKIFAILUREINFO_badCertTemplate 19
#  define OSSL_CMP_PKIFAILUREINFO_signerNotTrusted 20
#  define OSSL_CMP_PKIFAILUREINFO_transactionIdInUse 21
#  define OSSL_CMP_PKIFAILUREINFO_unsupportedVersion 22
#  define OSSL_CMP_PKIFAILUREINFO_notAuthorized 23
#  define OSSL_CMP_PKIFAILUREINFO_systemUnavail 24
#  define OSSL_CMP_PKIFAILUREINFO_systemFailure 25
#  define OSSL_CMP_PKIFAILUREINFO_duplicateCertReq 26
#  define OSSL_CMP_PKIFAILUREINFO_MAX 26
#  define OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN \
    ( (1<<(OSSL_CMP_PKIFAILUREINFO_MAX+1)) - 1)
#  if OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN > INT_MAX
#   error  CMP_PKIFAILUREINFO_MAX bit pattern does not fit in type int
#  endif

typedef ASN1_BIT_STRING OSSL_CMP_PKIFAILUREINFO;

#  define OSSL_CMP_CTX_FAILINFO_badAlg (1 << 0)
#  define OSSL_CMP_CTX_FAILINFO_badMessageCheck (1 << 1)
#  define OSSL_CMP_CTX_FAILINFO_badRequest (1 << 2)
#  define OSSL_CMP_CTX_FAILINFO_badTime (1 << 3)
#  define OSSL_CMP_CTX_FAILINFO_badCertId (1 << 4)
#  define OSSL_CMP_CTX_FAILINFO_badDataFormat (1 << 5)
#  define OSSL_CMP_CTX_FAILINFO_wrongAuthority (1 << 6)
#  define OSSL_CMP_CTX_FAILINFO_incorrectData (1 << 7)
#  define OSSL_CMP_CTX_FAILINFO_missingTimeStamp (1 << 8)
#  define OSSL_CMP_CTX_FAILINFO_badPOP (1 << 9)
#  define OSSL_CMP_CTX_FAILINFO_certRevoked (1 << 10)
#  define OSSL_CMP_CTX_FAILINFO_certConfirmed (1 << 11)
#  define OSSL_CMP_CTX_FAILINFO_wrongIntegrity (1 << 12)
#  define OSSL_CMP_CTX_FAILINFO_badRecipientNonce (1 << 13)
#  define OSSL_CMP_CTX_FAILINFO_timeNotAvailable (1 << 14)
#  define OSSL_CMP_CTX_FAILINFO_unacceptedPolicy (1 << 15)
#  define OSSL_CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)
#  define OSSL_CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)
#  define OSSL_CMP_CTX_FAILINFO_badSenderNonce (1 << 18)
#  define OSSL_CMP_CTX_FAILINFO_badCertTemplate (1 << 19)
#  define OSSL_CMP_CTX_FAILINFO_signerNotTrusted (1 << 20)
#  define OSSL_CMP_CTX_FAILINFO_transactionIdInUse (1 << 21)
#  define OSSL_CMP_CTX_FAILINFO_unsupportedVersion (1 << 22)
#  define OSSL_CMP_CTX_FAILINFO_notAuthorized (1 << 23)
#  define OSSL_CMP_CTX_FAILINFO_systemUnavail (1 << 24)
#  define OSSL_CMP_CTX_FAILINFO_systemFailure (1 << 25)
#  define OSSL_CMP_CTX_FAILINFO_duplicateCertReq (1 << 26)

/*-
 *   PKIStatus ::= INTEGER {
 *       accepted                (0),
 *       -- you got exactly what you asked for
 *       grantedWithMods        (1),
 *       -- you got something like what you asked for; the
 *       -- requester is responsible for ascertaining the differences
 *       rejection              (2),
 *       -- you don't get it, more information elsewhere in the message
 *       waiting                (3),
 *       -- the request body part has not yet been processed; expect to
 *       -- hear more later (note: proper handling of this status
 *       -- response MAY use the polling req/rep PKIMessages specified
 *       -- in Section 5.3.22; alternatively, polling in the underlying
 *       -- transport layer MAY have some utility in this regard)
 *       revocationWarning      (4),
 *       -- this message contains a warning that a revocation is
 *       -- imminent
 *       revocationNotification (5),
 *       -- notification that a revocation has occurred
 *       keyUpdateWarning       (6)
 *       -- update already done for the oldCertId specified in
 *       -- CertReqMsg
 *   }
 */
#  define OSSL_CMP_PKISTATUS_accepted 0
#  define OSSL_CMP_PKISTATUS_grantedWithMods 1
#  define OSSL_CMP_PKISTATUS_rejection 2
#  define OSSL_CMP_PKISTATUS_waiting 3
#  define OSSL_CMP_PKISTATUS_revocationWarning 4
#  define OSSL_CMP_PKISTATUS_revocationNotification 5
#  define OSSL_CMP_PKISTATUS_keyUpdateWarning 6

typedef ASN1_INTEGER OSSL_CMP_PKISTATUS;
DECLARE_ASN1_ITEM(OSSL_CMP_PKISTATUS)

#  define OSSL_CMP_CERTORENCCERT_CERTIFICATE 0
#  define OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT 1

/* data type declarations */
typedef struct OSSL_cmp_ctx_st OSSL_CMP_CTX;
typedef struct OSSL_cmp_pkiheader_st OSSL_CMP_PKIHEADER;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_PKIHEADER)
typedef struct OSSL_cmp_msg_st OSSL_CMP_MSG;
DECLARE_ASN1_ENCODE_FUNCTIONS(OSSL_CMP_MSG, OSSL_CMP_MSG, OSSL_CMP_MSG)
typedef struct OSSL_cmp_certstatus_st OSSL_CMP_CERTSTATUS;
DEFINE_STACK_OF(OSSL_CMP_CERTSTATUS)
typedef struct OSSL_cmp_itav_st OSSL_CMP_ITAV;
DEFINE_STACK_OF(OSSL_CMP_ITAV)
typedef struct OSSL_cmp_revrepcontent_st OSSL_CMP_REVREPCONTENT;
typedef struct OSSL_cmp_pkisi_st OSSL_CMP_PKISI;
DEFINE_STACK_OF(OSSL_CMP_PKISI)
typedef struct OSSL_cmp_certrepmessage_st OSSL_CMP_CERTREPMESSAGE;
DEFINE_STACK_OF(OSSL_CMP_CERTREPMESSAGE)
typedef struct OSSL_cmp_pollrep_st OSSL_CMP_POLLREP;
typedef STACK_OF(OSSL_CMP_POLLREP) OSSL_CMP_POLLREPCONTENT;
typedef struct OSSL_cmp_certresponse_st OSSL_CMP_CERTRESPONSE;
DEFINE_STACK_OF(OSSL_CMP_CERTRESPONSE)
typedef STACK_OF(ASN1_UTF8STRING) OSSL_CMP_PKIFREETEXT;

/* from cmp_asn.c */
void OSSL_CMP_ITAV_set0(OSSL_CMP_ITAV *itav, ASN1_OBJECT *type,
                        ASN1_TYPE *value);
ASN1_OBJECT *OSSL_CMP_ITAV_get0_type(const OSSL_CMP_ITAV *itav);
ASN1_TYPE *OSSL_CMP_ITAV_get0_value(const OSSL_CMP_ITAV *itav);
int OSSL_CMP_ITAV_stack_item_push0(STACK_OF(OSSL_CMP_ITAV) **itav_sk_p,
                                   OSSL_CMP_ITAV *itav);
void OSSL_CMP_ITAV_free(OSSL_CMP_ITAV *itav);
void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg);
void OSSL_CMP_PKISI_free(OSSL_CMP_PKISI *si);
DECLARE_ASN1_DUP_FUNCTION(OSSL_CMP_MSG)

#   ifdef  __cplusplus
}
#   endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OSSL_HEADER_CMP_H */
