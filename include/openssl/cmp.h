/*
 * Copyright 2007-2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_CMP_H
# define OPENtls_CMP_H

# include <opentls/opentlsconf.h>
# ifndef OPENtls_NO_CMP

#  include <opentls/crmf.h>
#  include <opentls/cmperr.h>
#  include <opentls/cmp_util.h>

/* explicit #includes not strictly needed since implied by the above: */
#  include <opentls/types.h>
#  include <opentls/safestack.h>
#  include <opentls/x509.h>
#  include <opentls/x509v3.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

#  define Otls_CMP_PVNO 2

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
#  define Otls_CMP_PKIFAILUREINFO_badAlg 0
#  define Otls_CMP_PKIFAILUREINFO_badMessageCheck 1
#  define Otls_CMP_PKIFAILUREINFO_badRequest 2
#  define Otls_CMP_PKIFAILUREINFO_badTime 3
#  define Otls_CMP_PKIFAILUREINFO_badCertId 4
#  define Otls_CMP_PKIFAILUREINFO_badDataFormat 5
#  define Otls_CMP_PKIFAILUREINFO_wrongAuthority 6
#  define Otls_CMP_PKIFAILUREINFO_incorrectData 7
#  define Otls_CMP_PKIFAILUREINFO_missingTimeStamp 8
#  define Otls_CMP_PKIFAILUREINFO_badPOP 9
#  define Otls_CMP_PKIFAILUREINFO_certRevoked 10
#  define Otls_CMP_PKIFAILUREINFO_certConfirmed 11
#  define Otls_CMP_PKIFAILUREINFO_wrongIntegrity 12
#  define Otls_CMP_PKIFAILUREINFO_badRecipientNonce 13
#  define Otls_CMP_PKIFAILUREINFO_timeNotAvailable 14
#  define Otls_CMP_PKIFAILUREINFO_unacceptedPolicy 15
#  define Otls_CMP_PKIFAILUREINFO_unacceptedExtension 16
#  define Otls_CMP_PKIFAILUREINFO_addInfoNotAvailable 17
#  define Otls_CMP_PKIFAILUREINFO_badSenderNonce 18
#  define Otls_CMP_PKIFAILUREINFO_badCertTemplate 19
#  define Otls_CMP_PKIFAILUREINFO_signerNotTrusted 20
#  define Otls_CMP_PKIFAILUREINFO_transactionIdInUse 21
#  define Otls_CMP_PKIFAILUREINFO_unsupportedVersion 22
#  define Otls_CMP_PKIFAILUREINFO_notAuthorized 23
#  define Otls_CMP_PKIFAILUREINFO_systemUnavail 24
#  define Otls_CMP_PKIFAILUREINFO_systemFailure 25
#  define Otls_CMP_PKIFAILUREINFO_duplicateCertReq 26
#  define Otls_CMP_PKIFAILUREINFO_MAX 26
#  define Otls_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN \
    ( (1<<(Otls_CMP_PKIFAILUREINFO_MAX+1)) - 1)
#  if Otls_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN > INT_MAX
#   error  CMP_PKIFAILUREINFO_MAX bit pattern does not fit in type int
#  endif

typedef ASN1_BIT_STRING Otls_CMP_PKIFAILUREINFO;

#  define Otls_CMP_CTX_FAILINFO_badAlg (1 << 0)
#  define Otls_CMP_CTX_FAILINFO_badMessageCheck (1 << 1)
#  define Otls_CMP_CTX_FAILINFO_badRequest (1 << 2)
#  define Otls_CMP_CTX_FAILINFO_badTime (1 << 3)
#  define Otls_CMP_CTX_FAILINFO_badCertId (1 << 4)
#  define Otls_CMP_CTX_FAILINFO_badDataFormat (1 << 5)
#  define Otls_CMP_CTX_FAILINFO_wrongAuthority (1 << 6)
#  define Otls_CMP_CTX_FAILINFO_incorrectData (1 << 7)
#  define Otls_CMP_CTX_FAILINFO_missingTimeStamp (1 << 8)
#  define Otls_CMP_CTX_FAILINFO_badPOP (1 << 9)
#  define Otls_CMP_CTX_FAILINFO_certRevoked (1 << 10)
#  define Otls_CMP_CTX_FAILINFO_certConfirmed (1 << 11)
#  define Otls_CMP_CTX_FAILINFO_wrongIntegrity (1 << 12)
#  define Otls_CMP_CTX_FAILINFO_badRecipientNonce (1 << 13)
#  define Otls_CMP_CTX_FAILINFO_timeNotAvailable (1 << 14)
#  define Otls_CMP_CTX_FAILINFO_unacceptedPolicy (1 << 15)
#  define Otls_CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)
#  define Otls_CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)
#  define Otls_CMP_CTX_FAILINFO_badSenderNonce (1 << 18)
#  define Otls_CMP_CTX_FAILINFO_badCertTemplate (1 << 19)
#  define Otls_CMP_CTX_FAILINFO_signerNotTrusted (1 << 20)
#  define Otls_CMP_CTX_FAILINFO_transactionIdInUse (1 << 21)
#  define Otls_CMP_CTX_FAILINFO_unsupportedVersion (1 << 22)
#  define Otls_CMP_CTX_FAILINFO_notAuthorized (1 << 23)
#  define Otls_CMP_CTX_FAILINFO_systemUnavail (1 << 24)
#  define Otls_CMP_CTX_FAILINFO_systemFailure (1 << 25)
#  define Otls_CMP_CTX_FAILINFO_duplicateCertReq (1 << 26)

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
#  define Otls_CMP_PKISTATUS_accepted 0
#  define Otls_CMP_PKISTATUS_grantedWithMods 1
#  define Otls_CMP_PKISTATUS_rejection 2
#  define Otls_CMP_PKISTATUS_waiting 3
#  define Otls_CMP_PKISTATUS_revocationWarning 4
#  define Otls_CMP_PKISTATUS_revocationNotification 5
#  define Otls_CMP_PKISTATUS_keyUpdateWarning 6

typedef ASN1_INTEGER Otls_CMP_PKISTATUS;
DECLARE_ASN1_ITEM(Otls_CMP_PKISTATUS)

#  define Otls_CMP_CERTORENCCERT_CERTIFICATE 0
#  define Otls_CMP_CERTORENCCERT_ENCRYPTEDCERT 1

/* data type declarations */
typedef struct otls_cmp_ctx_st Otls_CMP_CTX;
typedef struct otls_cmp_pkiheader_st Otls_CMP_PKIHEADER;
DECLARE_ASN1_FUNCTIONS(Otls_CMP_PKIHEADER)
typedef struct otls_cmp_msg_st Otls_CMP_MSG;
DECLARE_ASN1_ENCODE_FUNCTIONS(Otls_CMP_MSG, Otls_CMP_MSG, Otls_CMP_MSG)
typedef struct otls_cmp_certstatus_st Otls_CMP_CERTSTATUS;
DEFINE_STACK_OF(Otls_CMP_CERTSTATUS)
typedef struct otls_cmp_itav_st Otls_CMP_ITAV;
DEFINE_STACK_OF(Otls_CMP_ITAV)
typedef struct otls_cmp_revrepcontent_st Otls_CMP_REVREPCONTENT;
typedef struct otls_cmp_pkisi_st Otls_CMP_PKISI;
DEFINE_STACK_OF(Otls_CMP_PKISI)
typedef struct otls_cmp_certrepmessage_st Otls_CMP_CERTREPMESSAGE;
DEFINE_STACK_OF(Otls_CMP_CERTREPMESSAGE)
typedef struct otls_cmp_pollrep_st Otls_CMP_POLLREP;
typedef STACK_OF(Otls_CMP_POLLREP) Otls_CMP_POLLREPCONTENT;
typedef struct otls_cmp_certresponse_st Otls_CMP_CERTRESPONSE;
DEFINE_STACK_OF(Otls_CMP_CERTRESPONSE)
typedef STACK_OF(ASN1_UTF8STRING) Otls_CMP_PKIFREETEXT;

/*
 * function DECLARATIONS
 */

/* from cmp_asn.c */
Otls_CMP_ITAV *Otls_CMP_ITAV_create(ASN1_OBJECT *type, ASN1_TYPE *value);
void Otls_CMP_ITAV_set0(Otls_CMP_ITAV *itav, ASN1_OBJECT *type,
                        ASN1_TYPE *value);
ASN1_OBJECT *Otls_CMP_ITAV_get0_type(const Otls_CMP_ITAV *itav);
ASN1_TYPE *Otls_CMP_ITAV_get0_value(const Otls_CMP_ITAV *itav);
int Otls_CMP_ITAV_push0_stack_item(STACK_OF(Otls_CMP_ITAV) **itav_sk_p,
                                   Otls_CMP_ITAV *itav);
void Otls_CMP_ITAV_free(Otls_CMP_ITAV *itav);
void Otls_CMP_MSG_free(Otls_CMP_MSG *msg);

/* from cmp_ctx.c */
Otls_CMP_CTX *Otls_CMP_CTX_new(void);
void Otls_CMP_CTX_free(Otls_CMP_CTX *ctx);
int Otls_CMP_CTX_reinit(Otls_CMP_CTX *ctx);
/* various CMP options: */
#  define Otls_CMP_OPT_LOG_VERBOSITY 0
#  define Otls_CMP_OPT_MSGTIMEOUT 1
#  define Otls_CMP_OPT_TOTALTIMEOUT 2
#  define Otls_CMP_OPT_VALIDITYDAYS 3
#  define Otls_CMP_OPT_SUBJECTALTNAME_NODEFAULT 4
#  define Otls_CMP_OPT_SUBJECTALTNAME_CRITICAL 5
#  define Otls_CMP_OPT_POLICIES_CRITICAL 6
#  define Otls_CMP_OPT_POPOMETHOD 7
#  define Otls_CMP_OPT_DIGEST_ALGNID 8
#  define Otls_CMP_OPT_OWF_ALGNID 9
#  define Otls_CMP_OPT_MAC_ALGNID 10
#  define Otls_CMP_OPT_REVOCATION_REASON 11
#  define Otls_CMP_OPT_IMPLICITCONFIRM 12
#  define Otls_CMP_OPT_DISABLECONFIRM 13
#  define Otls_CMP_OPT_UNPROTECTED_SEND 14
#  define Otls_CMP_OPT_UNPROTECTED_ERRORS 15
#  define Otls_CMP_OPT_IGNORE_KEYUSAGE 16
#  define Otls_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR 17
int Otls_CMP_CTX_set_option(Otls_CMP_CTX *ctx, int opt, int val);
int Otls_CMP_CTX_get_option(const Otls_CMP_CTX *ctx, int opt);
/* CMP-specific callback for logging and outputting the error queue: */
int Otls_CMP_CTX_set_log_cb(Otls_CMP_CTX *ctx, Otls_cmp_log_cb_t cb);
#  define Otls_CMP_CTX_set_log_verbosity(ctx, level) \
    Otls_CMP_CTX_set_option(ctx, Otls_CMP_OPT_LOG_VERBOSITY, level)
void Otls_CMP_CTX_print_errors(Otls_CMP_CTX *ctx);
/* message transfer: */
int Otls_CMP_CTX_set1_serverPath(Otls_CMP_CTX *ctx, const char *path);
int Otls_CMP_CTX_set1_serverName(Otls_CMP_CTX *ctx, const char *name);
int Otls_CMP_CTX_set_serverPort(Otls_CMP_CTX *ctx, int port);
int Otls_CMP_CTX_set1_proxyName(Otls_CMP_CTX *ctx, const char *name);
int Otls_CMP_CTX_set_proxyPort(Otls_CMP_CTX *ctx, int port);
#  define Otls_CMP_DEFAULT_PORT 80
typedef BIO *(*Otls_cmp_http_cb_t) (Otls_CMP_CTX *ctx, BIO *hbio,
                                    unsigned long detail);
int Otls_CMP_CTX_set_http_cb(Otls_CMP_CTX *ctx, Otls_cmp_http_cb_t cb);
int Otls_CMP_CTX_set_http_cb_arg(Otls_CMP_CTX *ctx, void *arg);
void *Otls_CMP_CTX_get_http_cb_arg(const Otls_CMP_CTX *ctx);
typedef int (*Otls_cmp_transfer_cb_t) (Otls_CMP_CTX *ctx,
                                       const Otls_CMP_MSG *req,
                                       Otls_CMP_MSG **res);
int Otls_CMP_CTX_set_transfer_cb(Otls_CMP_CTX *ctx, Otls_cmp_transfer_cb_t cb);
int Otls_CMP_CTX_set_transfer_cb_arg(Otls_CMP_CTX *ctx, void *arg);
void *Otls_CMP_CTX_get_transfer_cb_arg(const Otls_CMP_CTX *ctx);
/* server authentication: */
int Otls_CMP_CTX_set1_srvCert(Otls_CMP_CTX *ctx, X509 *cert);
int Otls_CMP_CTX_set1_expected_sender(Otls_CMP_CTX *ctx, const X509_NAME *name);
int Otls_CMP_CTX_set0_trustedStore(Otls_CMP_CTX *ctx, X509_STORE *store);
X509_STORE *Otls_CMP_CTX_get0_trustedStore(const Otls_CMP_CTX *ctx);
int Otls_CMP_CTX_set1_untrusted_certs(Otls_CMP_CTX *ctx, STACK_OF(X509) *certs);
STACK_OF(X509) *Otls_CMP_CTX_get0_untrusted_certs(const Otls_CMP_CTX *ctx);
/* client authentication: */
int Otls_CMP_CTX_set1_clCert(Otls_CMP_CTX *ctx, X509 *cert);
int Otls_CMP_CTX_set1_pkey(Otls_CMP_CTX *ctx, EVP_PKEY *pkey);
int Otls_CMP_CTX_set1_referenceValue(Otls_CMP_CTX *ctx,
                                     const unsigned char *ref, int len);
int Otls_CMP_CTX_set1_secretValue(Otls_CMP_CTX *ctx, const unsigned char *sec,
                                  const int len);
/* CMP message header and extra certificates: */
int Otls_CMP_CTX_set1_recipient(Otls_CMP_CTX *ctx, const X509_NAME *name);
int Otls_CMP_CTX_push0_geninfo_ITAV(Otls_CMP_CTX *ctx, Otls_CMP_ITAV *itav);
int Otls_CMP_CTX_set1_extraCertsOut(Otls_CMP_CTX *ctx,
                                    STACK_OF(X509) *extraCertsOut);
/* certificate template: */
int Otls_CMP_CTX_set0_newPkey(Otls_CMP_CTX *ctx, int priv, EVP_PKEY *pkey);
EVP_PKEY *Otls_CMP_CTX_get0_newPkey(const Otls_CMP_CTX *ctx, int priv);
int Otls_CMP_CTX_set1_issuer(Otls_CMP_CTX *ctx, const X509_NAME *name);
int Otls_CMP_CTX_set1_subjectName(Otls_CMP_CTX *ctx, const X509_NAME *name);
int Otls_CMP_CTX_push1_subjectAltName(Otls_CMP_CTX *ctx, const GENERAL_NAME *name);
int Otls_CMP_CTX_set0_reqExtensions(Otls_CMP_CTX *ctx, X509_EXTENSIONS *exts);
int Otls_CMP_CTX_reqExtensions_have_SAN(Otls_CMP_CTX *ctx);
int Otls_CMP_CTX_push0_policy(Otls_CMP_CTX *ctx, POLICYINFO *pinfo);
int Otls_CMP_CTX_set1_oldCert(Otls_CMP_CTX *ctx, X509 *cert);
int Otls_CMP_CTX_set1_p10CSR(Otls_CMP_CTX *ctx, const X509_REQ *csr);
/* misc body contents: */
int Otls_CMP_CTX_push0_genm_ITAV(Otls_CMP_CTX *ctx, Otls_CMP_ITAV *itav);
/* certificate confirmation: */
typedef int (*Otls_cmp_certConf_cb_t) (Otls_CMP_CTX *ctx, X509 *cert,
                                       int fail_info, const char **txt);
int Otls_CMP_CTX_set_certConf_cb(Otls_CMP_CTX *ctx, Otls_cmp_certConf_cb_t cb);
int Otls_CMP_CTX_set_certConf_cb_arg(Otls_CMP_CTX *ctx, void *arg);
void *Otls_CMP_CTX_get_certConf_cb_arg(const Otls_CMP_CTX *ctx);
/* result fetching: */
int Otls_CMP_CTX_get_status(const Otls_CMP_CTX *ctx);
Otls_CMP_PKIFREETEXT *Otls_CMP_CTX_get0_statusString(const Otls_CMP_CTX *ctx);
int Otls_CMP_CTX_get_failInfoCode(const Otls_CMP_CTX *ctx);
#  define Otls_CMP_PKISI_BUFLEN 1024
X509 *Otls_CMP_CTX_get0_newCert(const Otls_CMP_CTX *ctx);
STACK_OF(X509) *Otls_CMP_CTX_get1_caPubs(const Otls_CMP_CTX *ctx);
STACK_OF(X509) *Otls_CMP_CTX_get1_extraCertsIn(const Otls_CMP_CTX *ctx);
/* support application-level CMP debugging in cmp.c: */
int Otls_CMP_CTX_set1_transactionID(Otls_CMP_CTX *ctx,
                                    const ASN1_OCTET_STRING *id);
int Otls_CMP_CTX_set1_senderNonce(Otls_CMP_CTX *ctx,
                                  const ASN1_OCTET_STRING *nonce);

/* from cmp_status.c */
char *Otls_CMP_CTX_snprint_PKIStatus(Otls_CMP_CTX *ctx, char *buf,
                                     size_t bufsize);

/* from cmp_hdr.c */
/* support application-level CMP debugging in cmp.c: */
ASN1_OCTET_STRING *Otls_CMP_HDR_get0_transactionID(const Otls_CMP_PKIHEADER *hdr);
ASN1_OCTET_STRING *Otls_CMP_HDR_get0_recipNonce(const Otls_CMP_PKIHEADER *hdr);

/* from cmp_msg.c */
/* support application-level CMP debugging in cmp.c: */
Otls_CMP_PKIHEADER *Otls_CMP_MSG_get0_header(const Otls_CMP_MSG *msg);

#  ifdef  __cplusplus
}
#  endif
# endif /* !defined OPENtls_NO_CMP */
#endif /* !defined OPENtls_CMP_H */
