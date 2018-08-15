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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "apps.h"
#include "progs.h"
#include "s_apps.h"

/* tweaks needed due to missing unistd.h on Windows */
#ifdef _WIN32
#define access _access
#endif
#ifndef F_OK
# define F_OK 0
#endif

#ifndef OPENSSL_NO_CMP

#include <openssl/opensslconf.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

static char *opt_config = NULL;
#define CMP_SECTION "cmp"
#define SECTION_NAME_MAX 40 /* max length of section name */
#define DEFAULT_SECTION "default"
static char *opt_section = CMP_SECTION;
#define HTTP_HDR "http://"

#undef PROG
#define PROG cmp_main
char *prog = "cmp";

#include <openssl/crypto.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

static int read_config(void);
static int opt_nat(void);

static CONF *conf = NULL;       /* OpenSSL config file context structure */
static OSSL_CMP_CTX *cmp_ctx = NULL;

/*
 * a copy from apps.c just for visibility reasons,
 * TODO DvO remove when setup_engine_no_default() is integrated (PR #4277)
 */
#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");

    if (e != NULL) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0) ||
            !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}

static UI_METHOD *ui_method = NULL;
#endif

/*
 * an adapted copy of setup_engine() from apps.c, TODO DvO replace this by
 * setup_engine_flags() when merged upstream in apps.c (PR #4277)
 */
static ENGINE *setup_engine_no_default(const char *engine, int debug)
{
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (engine != NULL) {
        if (strcmp(engine, "auto") == 0) {
            BIO_printf(bio_err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL &&
            (e = try_load_engine(engine)) == NULL) {
            BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug && !ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0))
            return NULL;
        if (!ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1))
            return NULL;
# if 0
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            BIO_printf(bio_err, "can't use that engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }
# endif

        BIO_printf(bio_err, "engine \"%s\" set\n", ENGINE_get_id(e));
    }
#endif
    return e;
}

/*
 * the type of cmp command we want to send
 */
typedef enum {
    CMP_IR,
    CMP_KUR,
    CMP_CR,
    CMP_P10CR,
    CMP_RR,
    CMP_GENM
} cmp_cmd_t;

static char *opt_server = NULL;
static int server_port = 8080;

static char *opt_proxy = NULL;
static int proxy_port = 8080;

static char *opt_path = "/";
static int opt_msgtimeout = -1;
static int opt_totaltimeout = -1;

static int opt_tls_used = 0;
static char *opt_tls_cert = NULL;
static char *opt_tls_key = NULL;
static char *opt_tls_keypass = NULL;
static char *opt_tls_extra = NULL;
static char *opt_tls_trusted = NULL;
static char *opt_tls_host = NULL;

static char *opt_ref = NULL;
static char *opt_secret = NULL;
static char *opt_cert = NULL;
static char *opt_key = NULL;
static char *opt_keypass = NULL;
static int opt_unprotectedRequests = 0;
static char *opt_digest = NULL;
static char *opt_extracerts = NULL;

static char *opt_trusted = NULL;
static char *opt_untrusted = NULL;
static char *opt_srvcert = NULL;
static char *opt_recipient = NULL;
static char *opt_expect_sender = NULL;
static int opt_ignore_keyusage = 0;
static int opt_unprotectedErrors = 0;
static char *opt_extracertsout = NULL;
static char *opt_cacertsout = NULL;

static int opt_batch = 0;
static char *opt_reqin = NULL;
static char *opt_reqout = NULL;
static char *opt_rspin = NULL;
static char *opt_rspout = NULL;

#ifndef NDEBUG
static int opt_mock_srv = 0;

static char *opt_srv_ref = NULL;
static char *opt_srv_secret = NULL;
static char *opt_srv_cert = NULL;
static char *opt_srv_key = NULL;
static char *opt_srv_keypass = NULL;

static char *opt_srv_trusted = NULL;
static char *opt_srv_untrusted = NULL;
static char *opt_rsp_cert = NULL;
static char *opt_rsp_extracerts = NULL;
static char *opt_rsp_capubs = NULL;
static int opt_poll_count = 0;
static int opt_checkafter = 1;
static int opt_grant_implicitconf = 0;

static int opt_pkistatus = OSSL_CMP_PKISTATUS_accepted;
static int opt_failure = -1;
static unsigned long opt_failurebits = 0;
static char *opt_statusstring = NULL;
static int opt_send_error = 0;
static int opt_send_unprotected = 0;
static int opt_send_unprot_err = 0;
static int opt_accept_unprotected = 0;
static int opt_accept_unprot_err = 0;

static OSSL_CMP_SRV_CTX *srv_ctx = NULL;
#endif /* NDEBUG */

static int opt_crl_download = 0;
static char *opt_crls = NULL;
static int opt_crl_timeout = 10;

static X509_VERIFY_PARAM *vpm = NULL;

#ifndef OPENSSL_NO_OCSP
# include <openssl/ocsp.h>
static int opt_ocsp_check_all = 0;
static int opt_ocsp_use_aia = 0;
static char *opt_ocsp_url = NULL;
static int opt_ocsp_timeout = 10;
# define X509_V_FLAG_OCSP_STAPLING  0x20000 /* Use OCSP stapling (for TLS) */
# define X509_V_FLAG_OCSP_CHECK     0x40000 /* Check certificate with OCSP */
# define X509_V_FLAG_OCSP_CHECK_ALL 0x80000 /* Check whole chain with OCSP */
X509_STORE_CTX_check_revocation_fn check_revocation = NULL;
static int opt_ocsp_status = 0;
#endif

static char *opt_ownform_s = "PEM";
static int opt_ownform = FORMAT_PEM;
static char *opt_keyform_s = "PEM";
static int opt_keyform = FORMAT_PEM;
static char *opt_crlform_s = "PEM";
static int opt_crlform = FORMAT_PEM;
static char *opt_otherform_s = "PEM";
static int opt_otherform = FORMAT_PEM;
static char *opt_otherpass = NULL;
static char *opt_engine = NULL;

static char *opt_newkey = NULL;
static char *opt_newkeypass = NULL;
static char *opt_subject = NULL;
static char *opt_issuer = NULL;
static int opt_days = 0;
static char *opt_reqexts = NULL;
static char *opt_sans = NULL;
static int opt_san_nodefault = 0;
static char *opt_policies = NULL;
static int opt_policies_critical = 0;
static int opt_popo = OSSL_CRMF_POPO_NONE - 1;
static char *opt_csr = NULL;
static char *opt_out_trusted = NULL;
static int opt_implicitConfirm = 0;
static int opt_disableConfirm = 0;
static char *opt_certout = NULL;

static char *opt_oldcert = NULL;
static int opt_revreason = CRL_REASON_NONE;

static char *opt_cmd_s = NULL;
static int opt_cmd = -1;
static char *opt_infotype_s = NULL;
static int opt_infotype = NID_undef;
static char *opt_geninfo = NULL;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_CONFIG, OPT_SECTION,

    OPT_SERVER, OPT_PROXY, OPT_PATH,
    OPT_MSGTIMEOUT, OPT_TOTALTIMEOUT,

    OPT_TRUSTED, OPT_UNTRUSTED, OPT_SRVCERT,
    OPT_RECIPIENT, OPT_EXPECT_SENDER,
    OPT_IGNORE_KEYUSAGE, OPT_UNPROTECTEDERRORS,
    OPT_EXTRACERTSOUT, OPT_CACERTSOUT,

    OPT_REF, OPT_SECRET, OPT_CERT, OPT_KEY, OPT_KEYPASS,
    OPT_UNPROTECTEDREQUESTS, OPT_DIGEST, OPT_EXTRACERTS,

    OPT_CMD, OPT_INFOTYPE, OPT_GENINFO,

    OPT_NEWKEY, OPT_NEWKEYPASS, OPT_SUBJECT, OPT_ISSUER, OPT_DAYS, OPT_REQEXTS,
    OPT_SANS, OPT_SAN_NODEFAULT,
    OPT_POLICIES, OPT_POLICIES_CRITICAL,
    OPT_POPO, OPT_CSR,
    OPT_OUT_TRUSTED, OPT_IMPLICITCONFIRM, OPT_DISABLECONFIRM,
    OPT_CERTOUT,

    OPT_OLDCERT, OPT_REVREASON,

    OPT_OWNFORM, OPT_KEYFORM, OPT_CRLFORM, OPT_OTHERFORM, OPT_OTHERPASS,
#ifndef OPENSSL_NO_ENGINE
    OPT_ENGINE,
#endif

    OPT_TLS_USED, OPT_TLS_CERT, OPT_TLS_KEY, OPT_TLS_KEYPASS, OPT_TLS_EXTRA,
    OPT_TLS_TRUSTED, OPT_TLS_HOST,

    OPT_BATCH,
    OPT_REQIN, OPT_REQOUT, OPT_RSPOUT, OPT_RSPIN,

#ifndef NDEBUG
    OPT_MOCK_SRV,
    OPT_SRV_REF, OPT_SRV_SECRET,
    OPT_SRV_CERT, OPT_SRV_KEY, OPT_SRV_KEYPASS,
    OPT_SRV_TRUSTED, OPT_SRV_UNTRUSTED,
    OPT_RSP_CERT, OPT_RSP_EXTRACERTS, OPT_RSP_CAPUBS,
    OPT_POLL_COUNT, OPT_CHECKAFTER, OPT_GRANT_IMPLICITCONF,
    OPT_PKISTATUS, OPT_FAILURE, OPT_FAILUREBITS, OPT_STATUSSTRING,
    OPT_SEND_ERROR,
    OPT_SEND_UNPROTECTED, OPT_SEND_UNPROT_ERR,
    OPT_ACCEPT_UNPROTECTED, OPT_ACCEPT_UNPROT_ERR,
#endif

    OPT_CRL_DOWNLOAD, OPT_CRLS, OPT_CRL_TIMEOUT,
#ifndef OPENSSL_NO_OCSP
    OPT_OCSP_CHECK_ALL,
    OPT_OCSP_USE_AIA,
    OPT_OCSP_URL,
    OPT_OCSP_TIMEOUT,
    OPT_OCSP_STATUS,
#endif
    OPT_V_ENUM                  /* OPT_CRLALL etc. */
} OPTION_CHOICE;

const
OPTIONS cmp_options[] = {
    /* OPTION_CHOICE values must be in the same order as enumerated above!! */
    {"help", OPT_HELP, '-', "Display this summary"},
    {"config", OPT_CONFIG, 's',
     "Configuration file to use. \"\" = none. Default from env variable OPENSSL_CONF"},
    {"section", OPT_SECTION, 's',
     "Section(s) in config file defining CMP options. \"\" = 'default'. Default 'cmp'"},

    {OPT_MORE_STR, 0, 0, "\nMessage transfer options:"},
    {"server", OPT_SERVER, 's',
     "address[:port] of CMP server. Default port 8080"},
    {"proxy", OPT_PROXY, 's',
     "address[:port] of optional HTTP proxy. Default 8080. TLS not supported here."},
    {OPT_MORE_STR, 0, 0,
     "The env variable 'no_proxy' (or else NO_PROXY) is respected"},
    {"path", OPT_PATH, 's',
     "HTTP path location inside the server (aka CMP alias). Default '/'"},
    {"msgtimeout", OPT_MSGTIMEOUT, 'n',
     "Timeout per CMP message round trip (or 0 for none). Default 120 seconds"},
    {"totaltimeout", OPT_TOTALTIMEOUT, 'n',
     "Overall time an enrollment incl. polling may take. Default 0 = infinite"},

    {OPT_MORE_STR, 0, 0, "\nServer authentication options:"},
    {"trusted", OPT_TRUSTED, 's',
     "Trusted CA certs used for CMP server authentication when verifying responses"},
    {OPT_MORE_STR, 0, 0, "unless -srvcert is given"},
    {"untrusted", OPT_UNTRUSTED, 's',
     "Intermediate certs for chain construction verifying CMP/TLS/enrolled certs"},
    {"srvcert", OPT_SRVCERT, 's',
     "Specific CMP server cert to use and trust directly when verifying responses"},
    {"recipient", OPT_RECIPIENT, 's',
     "Distinguished Name (DN) of the recipient to use unless -srvcert is given"},
    {"expect_sender", OPT_EXPECT_SENDER, 's',
     "DN of expected response sender. Defaults to DN of -srvcert, if provided"},
    {"ignore_keyusage", OPT_IGNORE_KEYUSAGE, '-',
     "Ignore CMP signer cert key usage, else 'digitalSignature' must be allowed"},
    {"unprotectederrors", OPT_UNPROTECTEDERRORS, '-',
     "Accept unprotected error responses: regular error messages as well as"},
    {OPT_MORE_STR, 0, 0,
     "negative certificate responses (ip/cp/kup) and revocation responses (rp)."},
    {OPT_MORE_STR, 0, 0,
     "WARNING: This setting leads to behaviour allowing violation of RFC 4210"},
    {"extracertsout", OPT_EXTRACERTSOUT, 's',
     "File to save received extra certificates"},
    {"cacertsout", OPT_CACERTSOUT, 's',
     "File to save received CA certificates"},

    {OPT_MORE_STR, 0, 0, "\nClient authentication options:"},
    {"ref", OPT_REF, 's',
     "Reference value to use as senderKID in case no -cert is given"},
    {"secret", OPT_SECRET, 's',
     "Password source for client authentication with a pre-shared key (secret)"},
    {"cert", OPT_CERT, 's',
     "Client's current certificate (needed unless using -secret for PBM);"},
    {OPT_MORE_STR, 0, 0,
     "any further certs included are appended in extraCerts field"},
    {"key", OPT_KEY, 's', "Private key for the client's current certificate"},
    {"keypass", OPT_KEYPASS, 's',
     "Client private key (and cert and old cert file) pass phrase source"},
    {"unprotectedrequests", OPT_UNPROTECTEDREQUESTS, '-',
     "Send messages without CMP-level protection"},
    {"digest", OPT_DIGEST, 's',
     "Digest to use in message protection and POPO signatures. Default 'sha256'"},
    {"extracerts", OPT_EXTRACERTS, 's',
     "Certificates to append in extraCerts field when sending messages"},

    {OPT_MORE_STR, 0, 0, "\nGeneric message options:"},
    {"cmd", OPT_CMD, 's', "CMP request to send: ir/cr/kur/p10cr/rr/genm"},
    {"infotype", OPT_INFOTYPE, 's',
     "InfoType name for requesting specific info in genm, e.g. 'signKeyPairTypes'"},
    {"geninfo", OPT_GENINFO, 's',
     "Set generalInfo in request PKIHeader with type and integer value"},
    {OPT_MORE_STR, 0, 0,
     "given in the form <OID>:int:<n>, e.g. '1.2.3:int:987'"},

    {OPT_MORE_STR, 0, 0, "\nCertificate enrollment options:"},
    {"newkey", OPT_NEWKEY, 's',
     "Private key for the requested certificate. Default is current client's key"},
    {"newkeypass", OPT_NEWKEYPASS, 's', "New private key pass phrase source"},
    {"subject", OPT_SUBJECT, 's',
     "Distinguished Name (DN) of subject to use in the requested cert template"},
    {OPT_MORE_STR, 0, 0,
     "For KUR, default is the subject DN of the reference cert (see -oldcert);"},
    {OPT_MORE_STR, 0, 0,
     "this default is used for IR and CR only if no Subject Alt Names are set"},
    {"issuer", OPT_ISSUER, 's',
     "DN of the issuer, to be put in the requested certificate template;"},
    {OPT_MORE_STR, 0, 0,
     "also used as recipient if neither -recipient nor -srvcert are given"},
    {"days", OPT_DAYS, 'n',
     "Number of days the new certificate is asked to be valid for"},
    {"reqexts", OPT_REQEXTS, 's',
     "Name of section in config file defining certificate request extensions"},
    {"sans", OPT_SANS, 's',
     "Subject Alternative Name(s) (DNS/IPADDR) to add as cert request extension"},
    {"san_nodefault", OPT_SAN_NODEFAULT, '-',
     "Do not take default SANs from reference certificate (see -oldcert)"},
    {"policies", OPT_POLICIES, 's',
     "Policy OID(s) to add as certificate policies request extension"},
    {"policies_critical", OPT_POLICIES_CRITICAL, '-',
     "Flag the policies given with -policies as critical"},
    {"popo", OPT_POPO, 'n', "Set Proof-of-Possession (POPO) method where"},
    {OPT_MORE_STR, 0, 0,
     "-1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC"},
    {"csr", OPT_CSR, 's',
     "CSR in PKCS#10 format to use in p10cr for legacy support"},
    {"out_trusted", OPT_OUT_TRUSTED, 's',
     "Trusted certificates to use for verifying the newly enrolled certificate"},
    {"implicitconfirm", OPT_IMPLICITCONFIRM, '-',
     "Request implicit confirmation of newly enrolled certificate"},
    {"disableconfirm", OPT_DISABLECONFIRM, '-',
     "Do not confirm newly enrolled certificate."},
    {OPT_MORE_STR, 0, 0,
     "WARNING: This setting leads to behavior violating RFC 4210"},
    {"certout", OPT_CERTOUT, 's',
     "File to save the newly enrolled certificate"},

    {OPT_MORE_STR, 0, 0, "\nCertificate enrollment and revocation options:"},

    {"oldcert", OPT_OLDCERT, 's',
     "Certificate to be updated (defaulting to -cert) or to be revoked in rr;"},
    {OPT_MORE_STR, 0, 0,
     "also used as reference (defaulting to -cert) for subject DN and SANs."},
    {OPT_MORE_STR, 0, 0,
     "Its issuer is used as recipient unless -srvcert, -recipient or -issuer given"},
    {"revreason", OPT_REVREASON, 'n',
     "Set reason code to be included in revocation request (rr); possible values:"},
    {OPT_MORE_STR, 0, 0,
     "0..10 (see RFC5280, 5.3.1) or -1 for none. Default -1 = none"},

    {OPT_MORE_STR, 0, 0, "\nCredentials format options:"},
    {"ownform", OPT_OWNFORM, 's',
     "Format (PEM/DER/P12) to try first for client-side cert files. Default PEM"},
    {OPT_MORE_STR, 0, 0,
     "This also determines format to use for writing (not supported for P12)"},
    {"keyform", OPT_KEYFORM, 's',
     "Format (PEM/DER/P12) to try first when reading key files. Default PEM"},
    {"crlform", OPT_CRLFORM, 's',
     "Format (PEM/DER) to try first when reading CRL files. Default PEM"},
    {"otherform", OPT_OTHERFORM, 's',
     "Format (PEM/DER/P12) to try first reading cert files of others. Default PEM"},
    {"otherpass", OPT_OTHERPASS, 's',
    "Pass phrase source potentially needed for loading certificates of others"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's',
     "Use crypto engine with given identifier, possibly a hardware device."},
    {OPT_MORE_STR, 0, 0,
     "Engines may be defined in OpenSSL config file engine section."},
    {OPT_MORE_STR, 0, 0,
     "Options like -key specifying keys held in the engine can give key IDs"},
    {OPT_MORE_STR, 0, 0,
     "prefixed by 'engine:', e.g. '-key engine:pkcs11:object=mykey;pin-value=1234'"},
#endif

    {OPT_MORE_STR, 0, 0, "\nTLS options:"},
    {"tls_used", OPT_TLS_USED, '-',
     "Force using TLS (also when other TLS options are not set"},
    {"tls_cert", OPT_TLS_CERT, 's',
     "Client's TLS certificate. May include chain to be provided to TLS server"},
    {"tls_key", OPT_TLS_KEY, 's',
     "Private key for the client's TLS certificate"},
    {"tls_keypass", OPT_TLS_KEYPASS, 's',
     "Pass phrase source for the client's private TLS key (and TLS cert file)"},
    {"tls_extra", OPT_TLS_EXTRA, 's',
     "Extra certificates to provide to TLS server during TLS handshake"},
    {"tls_trusted", OPT_TLS_TRUSTED, 's',
     "Trusted certificates to use for verifying the TLS server certificate;"},
    {OPT_MORE_STR, 0, 0, "this implies host name validation"},
    {"tls_host", OPT_TLS_HOST, 's',
     "Address to be checked (rather than -server) during TLS host name validation"},

    {OPT_MORE_STR, 0, 0, "\nTesting and debugging options:"},
    {"batch", OPT_BATCH, '-',
     "Do not interactively prompt for input when a password is required etc."},
    {"reqin", OPT_REQIN, 's', "Take sequence of CMP requests from file(s)"},
    {"reqout", OPT_REQOUT, 's', "Save sequence of CMP requests to file(s)"},
    {"rspin", OPT_RSPIN, 's',
     "Process sequence of CMP responses provided in file(s), skipping server"},
    {"rspout", OPT_RSPOUT, 's', "Save sequence of CMP responses to file(s)"},

#ifndef NDEBUG
    {"mock_srv", OPT_MOCK_SRV, '-', "Mock the server"},
    {"srv_ref", OPT_SRV_REF, 's',
     "Reference value to use as senderKID of server in case no -cert is given"},
    {"srv_secret", OPT_SRV_SECRET, 's',
     "Password source for server authentication with a pre-shared key (secret)"},
    {"srv_cert", OPT_SRV_CERT, 's', "Certificate used by the server"},
    {"srv_key", OPT_SRV_KEY, 's',
     "Private key of the server used for signing messages"},
    {"srv_keypass", OPT_SRV_KEYPASS, 's',
     "Server private key (and cert file) pass phrase source"},
    {"srv_trusted", OPT_SRV_TRUSTED, 's',
     "Trusted certificates for client authentication"},
    {"srv_untrusted", OPT_SRV_UNTRUSTED, 's',
     "Intermediate certs for constructing chains for CMP protection by client"},
    {"rsp_cert", OPT_RSP_CERT, 's',
     "Certificate to be returned as mock enrollment result"},
    {"rsp_extracerts", OPT_RSP_EXTRACERTS, 's',
     "Extra certificates to be included in mock certification responses"},
    {"rsp_capubs", OPT_RSP_CAPUBS, 's',
     "CA certifiates to be included in mock ip response"},
    {"poll_count", OPT_POLL_COUNT, 'n',
     "How many times the client must poll before receiving a certificate"},
    {"checkafter", OPT_CHECKAFTER, 'n',
     "checkAfter value (time to wait) to included in poll response"},
    {"grant_implicitconf", OPT_GRANT_IMPLICITCONF, '-',
     "Grant implicit confirmation of newly enrolled certificate"},
    {"pkistatus", OPT_PKISTATUS, 'n',
     "PKIStatus to be included in server response"},
    {"failure", OPT_FAILURE, 'n',
     "A single failure info code to be included in server response"},
    {"failurebits", OPT_FAILUREBITS, 'n',
     "Unsigned number representing failure bits to be included in server response"},
    {"statusstring", OPT_STATUSSTRING, 's',
     "Status string to be included in server response"},
    {"send_error", OPT_SEND_ERROR, '-',
     "Force server to reply with error message"},
    {"send_unprotected", OPT_SEND_UNPROTECTED, '-',
     "Send response messages without CMP-level protection"},
    {"send_unprot_err", OPT_SEND_UNPROT_ERR, '-',
     "In case of negative responses, server shall send unprotected error messages,"},
    {OPT_MORE_STR, 0, 0,
     "certificate responses (ip/cp/kup), and revocation responses (rp)."},
    {OPT_MORE_STR, 0, 0,
     "WARNING: This setting leads to behaviour violating RFC 4210"},
    {"accept_unprotected", OPT_ACCEPT_UNPROTECTED, '-',
     "Accept unprotected requests"},
    {"accept_unprot_err", OPT_ACCEPT_UNPROT_ERR, '-',
     "Accept unprotected error messages from client"},
#endif

    {OPT_MORE_STR, 0, 0,
     "\nSpecific certificate verification options, for both CMP and TLS:"},
    {"crl_download", OPT_CRL_DOWNLOAD, '-',
     "Retrieve CRLs from distribution points given in certs as primary source"},
    {"crls", OPT_CRLS, 's',
     "Use given CRL(s) as secondary (fallback) source when verifying certs."},
    {OPT_MORE_STR, 0, 0,
     "URL may start with 'http:' or name a local file (can be prefixed by 'file:')"},
    {OPT_MORE_STR, 0, 0,
     "Note: -crl_download, -crls, and -crl_check require cert status checking"},
    {OPT_MORE_STR, 0, 0,
     "for at least the leaf cert using CRLs unless OCSP is enabled and succeeds."},
    {OPT_MORE_STR, 0, 0,
     "-crl_check_all requires revocation checks using CRLs for full cert chain."},
    {"crl_timeout", OPT_CRL_TIMEOUT, 'n',
     "Request timeout for online CRL retrieval (or 0 for none). Default 10 seconds"},
#ifndef OPENSSL_NO_OCSP
    {"ocsp_check_all", OPT_OCSP_CHECK_ALL, '-',
     "Require revocation checks (via OCSP) for full certificate chain"},
    {"ocsp_use_aia", OPT_OCSP_USE_AIA, '-',
     "Use OCSP with AIA entries in certificates as primary URL of OCSP responder"},
    {"ocsp_url", OPT_OCSP_URL, 's',
     "Use OCSP with given URL as secondary (fallback) URL of OCSP responder."},
    {OPT_MORE_STR, 0, 0,
     "Note: -ocsp_use_aia and -ocsp_url require certificate status checking"},
    {OPT_MORE_STR, 0, 0,
     "for at least the leaf cert using OCSP, with CRLs as fallback if enabled"},
    {"ocsp_timeout", OPT_OCSP_TIMEOUT, 'n',
     "Timeout for retrieving OCSP responses (or 0 for none). Default 10 seconds"},
    {"ocsp_status", OPT_OCSP_STATUS, '-',
     "Enable certificate status from TLS server via OCSP (not multi-)stapling"},
#endif

    {OPT_MORE_STR, 0, 0, "\nStandard certificate verification options:"},
 /*
  * subsumes:
  * {"crl_check_all", OPT_CRLALL, '-',
  *  "Check CRLs not only for leaf certificate but for full certificate chain"},
  */
    OPT_V_OPTIONS,

    {NULL}
};

typedef union {
    char **txt;
    int *num;
    long *num_long;
} varref;
static varref cmp_vars[] = {/* must be in the same order as enumerated above! */
    {&opt_config}, {&opt_section},

    {&opt_server}, {&opt_proxy}, {&opt_path},
    {(char **)&opt_msgtimeout}, {(char **)&opt_totaltimeout},

    {&opt_trusted}, {&opt_untrusted}, {&opt_srvcert},
    {&opt_recipient}, {&opt_expect_sender},
    {(char **)&opt_ignore_keyusage}, {(char **)&opt_unprotectedErrors},
    {&opt_extracertsout}, {&opt_cacertsout},

    {&opt_ref}, {&opt_secret}, {&opt_cert}, {&opt_key}, {&opt_keypass},
    {(char **)&opt_unprotectedRequests}, {&opt_digest}, {&opt_extracerts},

    {&opt_cmd_s}, {&opt_infotype_s}, {&opt_geninfo},

    {&opt_newkey}, {&opt_newkeypass}, {&opt_subject}, {&opt_issuer},
    {(char **)&opt_days}, {&opt_reqexts},
    {&opt_sans}, {(char **)&opt_san_nodefault},
    {&opt_policies}, {(char **)&opt_policies_critical},
    {(char **)&opt_popo}, {&opt_csr},
    {&opt_out_trusted},
    {(char **)&opt_implicitConfirm}, {(char **)&opt_disableConfirm},
    {&opt_certout},

    {&opt_oldcert}, {(char **)&opt_revreason},

    {&opt_ownform_s}, {&opt_keyform_s}, {&opt_crlform_s}, {&opt_otherform_s},
    {&opt_otherpass},
#ifndef OPENSSL_NO_ENGINE
    {&opt_engine},
#endif

    {(char **)&opt_tls_used}, {&opt_tls_cert}, {&opt_tls_key},
    {&opt_tls_keypass}, {&opt_tls_extra}, {&opt_tls_trusted}, {&opt_tls_host},

    {(char **)&opt_batch},
    {&opt_reqin}, {&opt_reqout}, {&opt_rspin}, {&opt_rspout},

#ifndef NDEBUG
    {(char **)&opt_mock_srv},
    {&opt_srv_ref}, {&opt_srv_secret},
    {&opt_srv_cert}, {&opt_srv_key}, {&opt_srv_keypass},
    {&opt_srv_trusted}, {&opt_srv_untrusted},
    {&opt_rsp_cert}, {&opt_rsp_extracerts}, {&opt_rsp_capubs},
    {(char **)&opt_poll_count}, {(char **)&opt_checkafter},
    {(char **)&opt_grant_implicitconf},
    {(char **)&opt_pkistatus}, {(char **)&opt_failure},
    {(char **)&opt_failurebits}, {&opt_statusstring},
    {(char **)&opt_send_error},
    {(char **)&opt_send_unprotected},
    {(char **)&opt_send_unprot_err},
    {(char **)&opt_accept_unprotected},
    {(char **)&opt_accept_unprot_err},
#endif

    {(char **)&opt_crl_download}, {&opt_crls}, {(char **)&opt_crl_timeout},
#ifndef OPENSSL_NO_OCSP
    {(char **)&opt_ocsp_check_all}, {(char **)&opt_ocsp_use_aia},
    {&opt_ocsp_url}, {(char **)&opt_ocsp_timeout},
    {(char **)&opt_ocsp_status},
#endif
    /* virtually at this point: OPT_CRLALL etc. */
    {NULL}
};

/* TODO DvO push this and related functions upstream (PR #multifile) */
static char *next_item(char *opt) /* in list separated by comma and/or space */
{
    /* advance to separator (comma or whitespace), if any */
    while (*opt != ',' && !isspace(*opt) && *opt != '\0') {
        if (*opt++ == '\\' && *opt != '\0') {
            opt++;
        }
    }
    if (*opt != '\0') {
        /* terminate current item */
        *opt++ = '\0';
        /* skip over any whitespace after separator */
        while (isspace(*opt))
            opt++;
    }
    return *opt == '\0' ? NULL : opt; /* NULL indicates end of input */
}

/*
 * code for loading certs, keys, and CRLs
 * TODO DvO the whole Cert, Key and CRL loading logic should be given upstream
 * to be included in apps.c, and then used from here (PR #4930, PR #4940,
 * #autofmt, #crls_timeout_local)
 */

/*
 * TODO DvO when load_cert_pass() from apps.c is merged upstream (PR #4930
 * and #crls_timeout_local), remove this declaration of load_pkcs12(),
 * which has been copied from apps.c just for visibility reasons
 */
static int load_pkcs12(BIO *in, const char *desc,
                       pem_password_cb *pem_cb, void *cb_data,
                       EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char tpass[PEM_BUFSIZE];
    int len;
    int ret = 0;
    PKCS12 *p12 = d2i_PKCS12_bio(in, NULL);

    if (p12 == NULL) {
        BIO_printf(bio_err, "error loading PKCS12 file for %s\n", desc);
        goto die;
    }
    /* See if an empty password will do */
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
        pass = "";
    else {
        if (pem_cb == NULL)
            pem_cb = (pem_password_cb *)password_callback;
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if (len < 0) {
            BIO_printf(bio_err, "passphrase callback error for %s\n", desc);
            goto die;
        }
        if (len < PEM_BUFSIZE)
            tpass[len] = 0;
        if (!PKCS12_verify_mac(p12, tpass, len)) {
            BIO_printf(bio_err,
                   "mac verify error (wrong password?) in PKCS12 file for %s\n",
                       desc);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
    if (ret && *ca != NULL) {
        int i; /* other certs are for some reason in reverted order */
        STACK_OF(X509) *certs = sk_X509_new_null();
        for (i = 0; i < sk_X509_num(*ca); i++)
            if (certs == NULL ||
                !sk_X509_insert(certs, sk_X509_value(*ca, i), 0)) {
                sk_X509_pop_free(certs, X509_free);
                sk_X509_pop_free(*ca, X509_free);
                X509_free(*cert);
                EVP_PKEY_free(*pkey);
                ret = 0;
                goto die;
            }
        sk_X509_free(*ca);
        *ca = certs;
    }
 die:
    PKCS12_free(p12);
    return ret;
}

/*
 * TODO DvO remove when load_cert_pass() is merged upstream in apps.c (PR #4930)
 * and after generalizing it w.r.t. timeout (PR #crls_timeout_local)
 */
static X509 *load_cert_pass(const char *file, int format, const char *pass,
                            const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format == FORMAT_HTTP) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        OSSL_CMP_load_cert_crl_http_timeout(file, opt_crl_timeout,
                                            &x, NULL, bio_err);
#endif
        goto end;
    }
    if (file == NULL) {
        unbuffer(stdin);
        cert = dup_bio_in(format);
    } else
        cert = bio_open_default(file, 'r', format);
    if (cert == NULL)
        goto end;
    if (format == FORMAT_ASN1)
        x = d2i_X509_bio(cert, NULL);
    else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_AUX(cert, NULL,
                                  (pem_password_cb *)password_callback,
                                  &cb_data);
    else if (format == FORMAT_PKCS12) {
        EVP_PKEY *pkey = NULL;  /* &pkey is required for matching cert */

        load_pkcs12(cert, cert_descrip, (pem_password_cb *)password_callback,
                    &cb_data, &pkey, &x, NULL);
        EVP_PKEY_free(pkey);
    } else {
        BIO_printf(bio_err, "bad input format specified for %s\n",
                   cert_descrip);
        goto end;
    }
 end:
    if (x == NULL) {
        BIO_printf(bio_err, "unable to load certificate\n");
        ERR_print_errors(bio_err);
    }
    BIO_free(cert);
    return (x);
}

/* TODO DvO remove when load_csr() is merged upstream in apps.c (PR #4940) */
static X509_REQ *load_csr(const char *file, int format, const char *desc)
{
    X509_REQ *req = NULL;
    BIO *in;

    in = bio_open_default(file, 'r', format);
    if (in == NULL)
        goto end;

    if (format == FORMAT_ASN1)
        req = d2i_X509_REQ_bio(in, NULL);
    else if (format == FORMAT_PEM)
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    else if (desc != NULL)
        BIO_printf(bio_err, "unsupported format for CSR loading\n");

 end:
    if (req == NULL && desc != NULL)
        BIO_printf(bio_err, "unable to load X509 request\n");
    BIO_free(in);
    return req;
}

/* TODO DvO push this and related functions upstream (PR #autofmt) */
static int adjust_format(const char **infile, int format, int engine_ok)
{
    if (!strncmp(*infile, "http://", 7) || !strncmp(*infile, "https://", 8))
        format = FORMAT_HTTP;
    else if (engine_ok && strncmp(*infile, "engine:", 7) == 0) {
        *infile += 7;
        format = FORMAT_ENGINE;
    } else {
        if (strncmp(*infile, "file:", 5) == 0)
            *infile += 5;
        /*
         * the following is a heuristic whether first to try PEM or DER
         * or PKCS12 as the input format for files
         */
        if (strlen(*infile) >= 4) {
            char *extension = (char *)(*infile + strlen(*infile) - 4);

            if (strncmp(extension, ".crt", 4) == 0 ||
                strncmp(extension, ".pem", 4) == 0)
                /* weak recognition of PEM format */
                format = FORMAT_PEM;
            else if (strncmp(extension, ".cer", 4) == 0 ||
                     strncmp(extension, ".der", 4) == 0 ||
                     strncmp(extension, ".crl", 4) == 0)
                /* weak recognition of DER format */
                format = FORMAT_ASN1;
            else if (strncmp(extension, ".p12", 4) == 0)
                /* weak recognition of PKCS#12 format */
                format = FORMAT_PKCS12;
            /* else retain given format */
        }
    }
    return format;
}

/* TODO DvO extend app_get_pass() from apps.c this way (PR #app_get_pass) */
static char *get_passwd(const char *pass, const char *desc)
{
    char *result = NULL;

    if (!app_passwd((char *)pass, NULL, &result, NULL)) {
        BIO_printf(bio_err, "error getting password for %s\n", desc);
    }
    if (pass != NULL && result == NULL) {
        BIO_printf(bio_err,
                   "for compatibility, trying plain input string (better precede with 'pass:')\n");
        result = OPENSSL_strdup(pass);
    }
    return result;
}

static void cleanse(char *str) {
    if (str != NULL) {
        OPENSSL_cleanse((void *)str, strlen(str));
    }
}

/* TODO DvO: push this and related functions upstream (PR #autofmt) */
static EVP_PKEY *load_key_autofmt(const char *infile, int format,
                                  const char *pass, ENGINE *e, const char *desc)
{
    EVP_PKEY *pkey;
    /* BIO_printf(bio_c_out, "loading %s from '%s'\n", desc, infile); */
    char *pass_string = get_passwd(pass, desc);
    BIO *bio_bak = bio_err;

    bio_err = NULL;
    format = adjust_format(&infile, format, 1);
    pkey = load_key(infile, format, 0, pass_string, e, desc);
    if (pkey == NULL && format != FORMAT_HTTP && format != FORMAT_ENGINE) {
        ERR_clear_error();
        pkey =
            load_key(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, 0,
                     pass_string, NULL, desc);
    }
    bio_err = bio_bak;
    if (pkey == NULL) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc,
                   infile);
    }
    if (pass_string != NULL)
        OPENSSL_clear_free(pass_string, strlen(pass_string));
    return pkey;
}

/* TODO DvO: push this and related functions upstream (PR #autofmt) */
static X509 *load_cert_autofmt(const char *infile, int format,
                               const char *pass, const char *desc)
{
    X509 *cert;
    /* BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile); */
    char *pass_string = get_passwd(pass, desc);
    BIO *bio_bak = bio_err;

    bio_err = NULL;
    format = adjust_format(&infile, format, 0);
    cert = load_cert_pass(infile, format, pass_string, desc);
    if (cert == NULL && format != FORMAT_HTTP) {
        ERR_clear_error();
        format = (format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
        cert = load_cert_pass(infile, format, pass_string, desc);
    }
    bio_err = bio_bak;
    if (cert == NULL) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc,
                   infile);
    }
    if (pass_string != NULL)
        OPENSSL_clear_free(pass_string, strlen(pass_string));
    return cert;
}

/* TODO DvO: push this and related functions upstream (PR #autofmt) */
static X509_REQ *load_csr_autofmt(const char *infile, int format,
                                  const char *desc)
{
    X509_REQ *csr;
    /* BIO_printf(bio_c_out, "loading %s from file '%s'\n", desc, infile); */
    BIO *bio_bak = bio_err;

    bio_err = NULL;
    format = adjust_format(&infile, format, 0);
    csr = load_csr(infile, format, desc);
    if (csr == NULL && (format == FORMAT_PEM || format == FORMAT_ASN1)) {
        ERR_clear_error();
        format = (format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
        csr = load_csr(infile, format, desc);
    }
    bio_err = bio_bak;
    if (csr == NULL) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc,
                   infile);
    }
    return csr;
}

/*
 * Initialize or extend, if *certs != NULL, a certificate stack.
 *
 * TODO DvO replace by generalized load_certs() when merged upstream (PR #4930)
 */
static int load_certs_also_pkcs12(const char *file, STACK_OF(X509) **certs,
                                  int format, const char *pass,
                                  const char *desc)
{
    X509 *cert = NULL;
    int ret = 0;
    int i;

    if (format == FORMAT_PKCS12) {
        BIO *bio = bio_open_default(file, 'r', format);
        if (bio != NULL) {
            EVP_PKEY *pkey = NULL;  /* &pkey is required for matching cert */
            PW_CB_DATA cb_data;

            cb_data.password = pass;
            cb_data.prompt_info = file;
            ret = load_pkcs12(bio, desc, (pem_password_cb *)password_callback,
                              &cb_data, &pkey, &cert, certs);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
        }
    } else if (format == FORMAT_ASN1) {/* load only one cert in this case */
        cert = load_cert_pass(file, format, pass, desc);
    }
    if (format == FORMAT_PKCS12 || format == FORMAT_ASN1) {
        if (cert) {
            if ((*certs) == NULL)
                *certs = sk_X509_new_null();
            if (*certs)
                ret = sk_X509_insert(*certs, cert, 0);
            else
                X509_free(cert);
        }
    } else {
        ret = load_certs(file, certs, format, pass, desc);
    }

    for (i = 0; ret && i < sk_X509_num(*certs); i++) {
        cert = sk_X509_value(*certs, i);
        if (OSSL_CMP_expired(X509_get0_notAfter(cert), vpm)) {
            char *s = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            BIO_printf(bio_err,
                     "warning: certificate with subject '%s' has expired\n", s);
            OPENSSL_free(s);
#if 0
            sk_X509_pop_free(*certs, X509_free);
            ret = 0;
#endif
        }
    }
    return ret;
}

/* TODO DvO push this and related functions upstream (PR #autofmt) */
static int load_certs_autofmt(const char *infile, STACK_OF(X509) **certs,
                              int format, int exclude_http, const char *pass,
                              const char *desc)
{
    int ret = 0;
    char *pass_string;
    BIO *bio_bak = bio_err;

    /* BIO_printf(bio_c_out, "loading %s from file '%s'\n", desc, infile); */
    format = adjust_format(&infile, format, 0);
    if (exclude_http && format == FORMAT_HTTP) {
        BIO_printf(bio_err, "error: HTTP retrieval not allowed for %s\n", desc);
        return ret;
    }
    pass_string = get_passwd(pass, desc);
    bio_err = NULL;
    ret = load_certs_also_pkcs12(infile, certs, format, pass_string, desc);
    if (!ret) {
        int format2 = format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM;

        ERR_clear_error();
        ret = load_certs_also_pkcs12(infile, certs, format2, pass_string, desc);
    }
    bio_err = bio_bak;
    if (!ret) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc,
                   infile);
    }
    if (pass_string != NULL)
        OPENSSL_clear_free(pass_string, strlen(pass_string));
    return ret;
}

/* TODO DvO push this and related functions upstream (PR #autofmt) */
/* this funtion is used by load_crls_fmt and LOCAL_load_crl_crldp */
static X509_CRL *load_crl_autofmt(const char *infile, int format,
                                  const char *desc)
{
    X509_CRL *crl = NULL;
    BIO *bio_bak = bio_err;

    bio_err = NULL;
    /* BIO_printf(bio_c_out, "loading %s from '%s'\n", desc, infile); */
    format = adjust_format(&infile, format, 0);
    if (format == FORMAT_HTTP) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        OSSL_CMP_load_cert_crl_http_timeout(infile, opt_crl_timeout, NULL,
                                            &crl, bio_err);
#endif
        goto end;
    }
    crl = load_crl(infile, format);
    if (crl == NULL) {
        ERR_clear_error();
        crl = load_crl(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
    }
 end:
    bio_err = bio_bak;
    if (crl == NULL) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc,
                   infile);
    }
    return crl;
}

/* TODO DvO push this and related functions upstream (PR #autofmt) */
/* this function is exclusively used by load_crls_autofmt */
static STACK_OF(X509_CRL) *load_crls_fmt(const char *infile, int format,
                                         const char *desc)
{
    X509_CRL *crl;

    if (format == FORMAT_PEM) {
        STACK_OF(X509_CRL) *crls = NULL;
        /* BIO_printf(bio_c_out, "loading %s from '%s'\n", desc, infile); */
        if (!load_crls(infile, &crls, format, NULL, desc))
            return NULL;
        return crls;
    } else {
        STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();
        if (crls == NULL)
            return NULL;
        crl = load_crl_autofmt(infile, format, desc);
     /* using load_crl_autofmt because of http capabilities including timeout */
        if (crl == NULL) {
            sk_X509_CRL_free(crls);
            return NULL;
        }
        sk_X509_CRL_push(crls, crl);
        return crls;
    }
}

/* TODO DvO push this and related functions upstream (PR #autofmt) */
static STACK_OF(X509_CRL) *load_crls_autofmt(const char *infile, int format,
                                             const char *desc)
{
    STACK_OF(X509_CRL) *crls;
    BIO *bio_bak = bio_err;

    bio_err = NULL;
    format = adjust_format(&infile, format, 0);
    crls = load_crls_fmt(infile, format, desc);
    if (crls == NULL && format != FORMAT_HTTP) {
        ERR_clear_error();
        crls = load_crls_fmt(infile,
                             format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM,
                             desc);
    }
    bio_err = bio_bak;
    if (crls == NULL) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc,
                   infile);
    }
    return crls;
}

static void DEBUG_print(const char *msg, const char *s1, const char *s2)
{
#if 1 && !defined NDEBUG
    BIO_printf(bio_err, "DEBUG: %s %s %s\n", msg,
               s1 != NULL ? s1 : "", s2 != NULL ? s2 : "");
#endif
}

/*
 * set the expected host name/IP addr and clears the email addr in the given ts.
 * The string must not be freed as long as cert_verify_cb() may use it.
 * returns 1 on success, 0 on error.
 */
#define X509_STORE_EX_DATA_HOST 0
#define X509_STORE_EX_DATA_SBIO 1
static int truststore_set_host_etc(X509_STORE *ts, const char *host)
{
    X509_VERIFY_PARAM *ts_vpm = X509_STORE_get0_param(ts);

    /* first clear any host names, IP, and email addresses */
    if (!X509_VERIFY_PARAM_set1_host(ts_vpm, NULL, 0) ||
        !X509_VERIFY_PARAM_set1_ip(ts_vpm, NULL, 0) ||
        !X509_VERIFY_PARAM_set1_email(ts_vpm, NULL, 0)) {
        return 0;
    }
    X509_VERIFY_PARAM_set_hostflags(ts_vpm,
                                    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    /*
     * Unfortunately there is no OpenSSL API function for retrieving the hosts/
     * ip entries in X509_VERIFY_PARAM. So we store the host value in ex_data
     * for use in cert_verify_cb() below.
     */
    if (!X509_STORE_set_ex_data(ts, X509_STORE_EX_DATA_HOST, (void *)host))
        return 0;
    return (host && X509_VERIFY_PARAM_set1_ip_asc(ts_vpm, host)) ||
           X509_VERIFY_PARAM_set1_host(ts_vpm, host, 0);
}

static X509_STORE *sk_X509_to_store(X509_STORE *store /* may be NULL */ ,
                                  const STACK_OF(X509) *certs /* may be NULL */)
{
    int i;

    if (store == NULL)
        store = X509_STORE_new();
    if (store == NULL)
        return NULL;
    for (i = 0; i < sk_X509_num(certs); i++) {
        if (!X509_STORE_add_cert(store, sk_X509_value(certs, i))) {
            X509_STORE_free(store);
            return NULL;
        }
    }
    return store;
}

/*
 * TODO DvO push this and related functions upstream (PR #crls_timeout_local)
 *
 * code for loading CRL via HTTP or from file, slightly adapted from apps/apps.c
 *
 * This is exclusively used in load_crl_crldp()
 */

static const char *LOCAL_get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i;
    int gtype;
    ASN1_STRING *uri;

    if (dp->distpoint == NULL || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            char *uptr = (char *)ASN1_STRING_get0_data(uri);
            if (strncmp(uptr, "http://", 7) == 0
                || strncmp(uptr, "file:", 5) == 0)
                return uptr;
        }
    }
    return NULL;
}

/*
 * TODO DvO push this and related functions upstream (PR #crls_timeout_local)
 *
 * THIS IS an extension of load_crl_crldp() FROM AND LOCAL TO apps.c,
 * with support for loading local CRL files,
 * logging of URL use, and use of *_autofmt
 */

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *LOCAL_load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;

    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = LOCAL_get_dp_url(dp);
        if (urlptr != NULL) {
            DEBUG_print("load_crl_crldp:", "using CDP URL:", urlptr);
            return load_crl_autofmt(urlptr, FORMAT_HTTP,
                                    "CRL via CDP entry in certificate");
        }
    }
    return NULL;
}

/*
 * TODO DvO push this and related functions upstream (PR #crls_timeout_local)
 *
 * THIS IS crls_http_cb() FROM AND LOCAL TO apps.c,
 * but using LOCAL_load_crl_crldp instead of the one from apps.c
 * This variant does support non-blocking I/O using a timeout, yet note
 * that if opt_crl_timeout > opt_msgtimeout the latter is overridden.
 *
 * Example of downloading CRLs from CRLDP: not usable for real world as it
 * always downloads and doesn't cache anything.
 */

static STACK_OF(X509_CRL) *LOCAL_crls_http_cb(X509_STORE_CTX *ctx,
                                              X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;

    crls = sk_X509_CRL_new_null();
    if (crls == NULL)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = LOCAL_load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl == NULL) {
        sk_X509_CRL_free(crls);
        return NULL;
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = LOCAL_load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl != NULL)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

/*
 * TODO DvO push this and related functions upstream (PR #crls_timeout_local)
 *
 * This allows for local CRLs and remote lookup through the callback.
 * In upstream openssl, X509_STORE_CTX_init() sets up the STORE_CTX
 * so that CRLs already loaded to the store get ignored if a callback is set.
 *
 * First try downloading CRLs from any CDP entries, then local CRLs from store.
 */

static STACK_OF(X509_CRL) *get_crls_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    STACK_OF(X509_CRL) *crls;
    crls = LOCAL_crls_http_cb(ctx, nm);
    if (crls == NULL) {
        crls = X509_STORE_CTX_get1_crls(ctx, nm);
    }
    return crls;
}

#ifndef OPENSSL_NO_OCSP
static void DEBUG_print_cert(const char *msg, const X509 *cert)
{
    char *s = X509_NAME_oneline(X509_get_subject_name((X509 *)cert), NULL, 0);
    DEBUG_print(msg, "for cert with subject =", s);
    OPENSSL_free(s);
}

/*
 * code implementing OCSP support
 */

/* TODO DvO push this function upstream & use in ocsp.c (PR #check_ocsp_resp) */

/* Maximum leeway in validity period: default 5 minutes */
# define MAX_OCSP_VALIDITY_PERIOD (5 * 60)

/* adapted from ocsp_main() of ocsp.c */
/*
 * Verify an OCSP response resp obtained via an OCSP request or OCSP stapling.
 * Returns 1 on success, 0 on rejection (i.e., cert revoked), -1 on error
 */
static int check_ocsp_resp(X509_STORE *ts, STACK_OF(X509) *untrusted,
                           X509 *cert, X509 *issuer, OCSP_RESPONSE *resp)
{
    X509_VERIFY_PARAM *bak_vpm = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_CERTID *id = NULL;
    int res = -1, status, reason;
    ASN1_GENERALIZEDTIME *rev;
    ASN1_GENERALIZEDTIME *thisupd;
    ASN1_GENERALIZEDTIME *nextupd;

    if (resp == NULL)
        return -1;

# if 0 && !defined NDEBUG
    BIO_puts(bio_c_out, "debug: OCSP response:\n");
    BIO_puts(bio_c_out, "======================================\n");
    OCSP_RESPONSE_print(bio_c_out, resp, 0);
    BIO_puts(bio_c_out, "======================================\n");
# endif

    status = OCSP_response_status(resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(bio_err, "OCSP responder error: %s (code %d)\n",
                   OCSP_response_status_str(status), status);
        return -1;
    }

    if ((br = OCSP_response_get1_basic(resp)) == NULL) {
        BIO_printf(bio_err, "error getting OCSP basic response\n");
        return -1;
    }

    {
        /* must not do revocation checking on OCSP responder cert chain */
        const X509_STORE_CTX_check_revocation_fn bak_fn =
            X509_STORE_get_check_revocation(ts);
        (void)X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(ts),
                                            X509_V_FLAG_CRL_CHECK);
        X509_STORE_set_check_revocation(ts, NULL);

        /* must not do host/ip/email checking on OCSP responder cert chain */
        if ((bak_vpm = X509_VERIFY_PARAM_new()) == NULL || /* copy vpm: */
            !X509_VERIFY_PARAM_inherit(bak_vpm, X509_STORE_get0_param(ts)) ||
            !truststore_set_host_etc(ts, NULL))
            goto end;

        res = OCSP_basic_verify(br, untrusted, ts, OCSP_TRUSTOTHER);

        X509_STORE_set_check_revocation(ts, bak_fn);
        if (!X509_STORE_set1_param(ts, bak_vpm))
            goto end;
    }
    if (res <= 0) {
        BIO_printf(bio_err, "OCSP response verify failure\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if ((id = OCSP_cert_to_id(NULL, cert, issuer)) == NULL) {
        BIO_puts(bio_err, "cannot obtain cert ID for OCSP\n");
        goto end;
    }
    if (!OCSP_resp_find_status(br, id,
                               &status, &reason, &rev, &thisupd, &nextupd)) {
        BIO_puts(bio_err, "OCSP status not found\n");
        goto end;
    }

    /* TODO: OCSP_check_validity() should respect -attime: vpm->check_time */
    if (!OCSP_check_validity(thisupd, nextupd, MAX_OCSP_VALIDITY_PERIOD, -1)) {
        BIO_puts(bio_err, "OCSP status times invalid\n");
        ERR_print_errors(bio_err);
        goto end;
    } else {
        switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            DEBUG_print_cert("OCSP status good", cert);
            res = 1;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            BIO_printf(bio_err, "OCSP status: revoked, reason=%s\n",
                       reason != -1 ? OCSP_crl_reason_str(reason) : "");
            res = 0;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
        default:
            BIO_printf(bio_err, "OCSP status unknown (value %d)\n", status);
            break;
        }
    }

 end:
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(br);
    X509_VERIFY_PARAM_free(bak_vpm);
    return res;
}

/* TODO DvO push this funct upstream & use in s_server.c (PR #get_ocsp_resp) */

/* adapted from get_ocsp_resp_from_responder() of s_server.c */
/*
 * Get an OCSP_RESPONSE from a responder for the given cert and trust store.
 * This is a simplified version. It examines certificates each time and makes
 * one OCSP responder query for each request. A full version would store details
 * such as the OCSP certificate IDs and minimise the number of OCSP responses
 * by caching them until they were considered "expired".
 */
static OCSP_RESPONSE *get_ocsp_resp(const X509 *cert, const X509 *issuer,
                                    char *url, int use_aia, int timeout)
{
    char *host = NULL;
    char *path = NULL;
    char *port = NULL;
    int use_ssl;
    STACK_OF(OPENSSL_STRING) *aia = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_CERTID *id_copy, *id = NULL;
    int res;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *br = NULL;

    aia = X509_get1_ocsp((X509 *)cert);
    if (aia != NULL && use_aia)
        url = sk_OPENSSL_STRING_value(aia, 0);
    if (url == NULL) {
        BIO_puts(bio_err,
                 "cert_status: no AIA in cert and no default responder URL\n");
        return NULL;
    }
    DEBUG_print_cert("certstatus query", cert);
    DEBUG_print("cert_status:", "using AIA URL:", url);
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl)) {
        BIO_printf(bio_err, "cert_status: cannot parse AIA URL: %s\n", url);
        goto end;
    }

    if ((req = OCSP_REQUEST_new()) == NULL)
        goto end;
    if ((id = OCSP_cert_to_id(NULL, (X509 *)cert, (X509 *)issuer)) == NULL)
        goto end;
    if (!OCSP_request_add0_id(req, (id_copy = id)))
        goto end;
    id = NULL;
    if (!OCSP_request_add1_nonce(req, NULL, -1))
        goto end;
# if 0
    STACK_OF(X509_EXTENSION) *exts;
    int i;

    /* Add any extensions to the request */
    SSL_get_tlsext_status_exts(s, &exts);
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        if (!OCSP_REQUEST_add_ext(req, ext, -1))
            goto end;
    }
# endif
    /* process_responder is defined ocsp.c */
    resp = process_responder(
                             req, host, path, port, use_ssl, NULL, timeout);
    if (resp == NULL) {
        BIO_puts(bio_err, "cert_status: error querying OCSP responder\n");
        goto end;
    }

    if ((br = OCSP_response_get1_basic(resp)) == NULL) {
        BIO_printf(bio_err, "error getting OCSP basic response\n");
        goto end;
    }
    if ((res = OCSP_check_nonce(req, br)) <= 0) {
        if (res == -1)
            BIO_printf(bio_err, "error: no nonce in OCSP response\n");
        else
            BIO_printf(bio_err, "nonce verification error\n");
        goto end;
    }
    if (!OCSP_resp_find_status(br, id_copy, NULL, NULL, NULL, NULL, NULL)) {
        BIO_puts(bio_err, "No OCSP status found matching cert ID in request\n");
        goto end;
    }

 end:
    if (url != NULL) {
        OPENSSL_free(host);
        OPENSSL_free(path);
        OPENSSL_free(port);
    }
    if (aia != NULL)
        X509_email_free(aia);
    OCSP_CERTID_free(id);
    OCSP_REQUEST_free(req);
    OCSP_BASICRESP_free(br);
    return resp;
}

/* TODO DvO (begin) push OCSP-related code upstream (PR #ocsp_stapling_crls) */

/* TODO DvO remove this function when the ones using it are merged upstream */
/*
 * check revocation status of cert at current error depth in ctx using CRLs.
 * Emulates the internal check_cert() function from crypto/x509/x509_vfy.c
 */
static int check_cert(X509_STORE_CTX *ctx)
{
    int i;
    int ok;
    X509 *cert, *cert_copy = NULL;
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int cnum = X509_STORE_CTX_get_error_depth(ctx);

    for (i = 0; i < sk_X509_num(chain); i++) {
        cert = sk_X509_value(chain, i);
        if (i == cnum)
            cert_copy = cert;
        /* do not check revocation of this cert:
           else
               X509_set_proxy_flag(cert); */
    }
    /* call internal check_cert() effectively only for the (cnum)-th cert: */
    ok = (*check_revocation)(ctx);
    if (ok)
        DEBUG_print_cert("CRL check good  ", cert_copy);
    /* well, better should restore original chain */
    return ok;
}

/* TODO DvO remove this function when the ones using it are merged upstream */
/*
 * emulate the internal verify_cb_cert() of crypto/cmp/x509_vfy.c;
 * depth already set
 */
static int verify_cb_cert(X509_STORE_CTX *ctx, const X509 *cert, int err)
{
    X509_STORE_CTX_verify_cb verify_cb = X509_STORE_CTX_get_verify_cb(ctx);

    X509_STORE_CTX_set_error(ctx, err);
    X509_STORE_CTX_set_current_cert(ctx, (X509 *)cert);
    return verify_cb && (*verify_cb) (0, ctx);
}

/*
 * Check the revocation status of the certificate as specified in given ctx
 * using any stapled OCSP response resp, else OCSP or CRLs as far as required.
 * Returns 1 on success, 0 on rejection or error
 */
# define OCSP_err(ok) \
    (ok == -2 ? X509_V_ERR_OCSP_VERIFY_NEEDED/* no OCSP response available*/ : \
     ok !=  0 ? X509_V_ERR_OCSP_VERIFY_FAILED : X509_V_ERR_CERT_REVOKED)
static int check_cert_revocation(X509_STORE_CTX *ctx, OCSP_RESPONSE *resp)
{
    X509_STORE *ts = X509_STORE_CTX_get0_store(ctx);
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(ctx);
    int i = X509_STORE_CTX_get_error_depth(ctx);
    int num = sk_X509_num(chain);
    X509 *cert = sk_X509_value(chain, i);
    X509 *issuer = sk_X509_value(chain, i < num - 1 ? i + 1 : num - 1);

    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
    int ocsp_stapling = flags & X509_V_FLAG_OCSP_STAPLING;
    int ocsp_check = flags & X509_V_FLAG_OCSP_CHECK;
    int crl_check = flags & X509_V_FLAG_CRL_CHECK;
    int ok = 0;

    if (ocsp_stapling) {
        if (resp != NULL) /* (stapled) response is available */
            ok = check_ocsp_resp(ts, chain, cert, issuer, resp);
        else
            ok = -2; /* inconclusive */
        if (ok == 1) /* cert status ok */
            return 1;
        if (ok == 0  /* cert revoked, thus clear failure or */ ||
            /* OCSP stapling was inconclusive: ok < 0 and is the only check */
            (ok < 0 && !ocsp_check && !crl_check))
            return verify_cb_cert(ctx, cert, OCSP_err(ok));
    }
    /* OCSP stapling is disabled or inconclusive */

    if (ocsp_check) {
        resp = get_ocsp_resp(cert, issuer, opt_ocsp_url, opt_ocsp_use_aia,
                             opt_ocsp_timeout == 0 ? -1 : opt_ocsp_timeout);
        /* TODO remove these direct references to OCSP options: opt_ocsp_... */
        ok = check_ocsp_resp(ts, untrusted, cert, issuer, resp);
        OCSP_RESPONSE_free(resp);

        if (ok == 1)        /* cert status ok */
            return 1;
        if (ok == 0 ||      /* cert revoked, thus clear failure */
            /* OCSP is the only check and it was inconclusive: ok < 0 */
            (ok < 0 && !crl_check)) {
            return verify_cb_cert(ctx, cert, OCSP_err(ok));
        }
    }
    /* OCSP (including stapling) is disabled or inconclusive */

    if (crl_check)
        return check_cert(ctx);
    return 1;
}

/*
 * callback function for verifying stapled OCSP responses
 * Returns 1 on success, 0 on rejection (i.e., cert revoked), -1 on error
 */
static int ocsp_stapling_cb(SSL *ssl, STACK_OF(X509) *untrusted)
{
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    const unsigned char *resp;
    OCSP_RESPONSE *rsp = NULL;
    X509_STORE_CTX *ctx = NULL;
    int ret = -1; /* tls_process_initial_server_flight reports
                     return code < 0 as internal error: malloc failure */
    int len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);

    if (resp == NULL) {
        BIO_puts(bio_err, "no OCSP response has been stapled\n");
    } else {
        DEBUG_print_cert("OCSP rsp stapled", sk_X509_value(chain, 0));
        rsp = d2i_OCSP_RESPONSE(NULL, &resp, len);
        if (rsp == NULL) {
            BIO_puts(bio_err, "error parsing stapled OCSP response\n");
            BIO_dump_indent(bio_err, (char *)resp, len, 4);
            /* well, this is likely not an internal error (malloc failure) */
            goto end;
        }
    }

    ctx = X509_STORE_CTX_new();/* ctx needed for CRL checking and diagnostics */
    if (ctx == NULL)
        goto end;
    if (!X509_STORE_CTX_init(ctx,
                             SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl)),
                             NULL/* cert */, untrusted))
        goto end;
    X509_STORE_CTX_set0_verified_chain(ctx, X509_chain_up_ref(chain));
    X509_STORE_CTX_set_error_depth(ctx, 0);
    ret = check_cert_revocation(ctx, rsp);

 end:
    /* must not: sk_X509_free(untrusted); */
    X509_STORE_CTX_free(ctx);
    OCSP_RESPONSE_free(rsp);
    return ret;
}

/*
 * Check revocation status on each cert in ctx->chain. As a generalization of
 * check_revocation() in crypto/x509/x509_vfy.c, do not only consider CRLs:
 * use any stapled OCSP response resp, else OCSP or CRLs as far as required.
 */
static int check_revocation_ocsp_crls(X509_STORE_CTX *ctx)
{
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int i;
    int last = 0;
    int num = sk_X509_num(chain);
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
    int ocsp_stapling = flags & X509_V_FLAG_OCSP_STAPLING;
    int ocsp_check = flags & X509_V_FLAG_OCSP_CHECK;
    int ocsp_check_all = flags & X509_V_FLAG_OCSP_CHECK_ALL;
    int crl_check = flags & X509_V_FLAG_CRL_CHECK;
    int crl_check_all = flags & X509_V_FLAG_CRL_CHECK_ALL;
    /* when set, usually CRL_CHECK is set as well, e.g., via opt_verify() */
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());

    if (!(ssl && ocsp_stapling) && !ocsp_check && !crl_check)
        return 1;

    if (ocsp_check_all || crl_check_all)
        last = num - 1;
    else {
        /* If checking CRL paths this is not the EE certificate */
        if (X509_STORE_CTX_get0_parent_ctx(ctx))
            return 1;
        last = 0;
    }
    for (i = 0; i <= last; i++) {
        X509 *cert = sk_X509_value(chain, i);

        X509_STORE_CTX_set_error_depth(ctx, i);
        if (i == last && X509_check_issued(cert, cert) == X509_V_OK)
            break; /* revocation does not work for self-signed, okay if last */
        /*
         * on current cert i in chain, first consider OCSP stapling if i == 0,
         * then OCSP, then CRLs
         */

        if (ssl != NULL &&
            i == 0 && ocsp_stapling) { /* OCSP (not multi-)stapling */
        /* We were called from ssl_verify_cert_chain() at state TLS_ST_CR_CERT.
           Stapled OCSP response becomes available only at TLS_ST_CR_CERT_STATUS
           and ocsp_stapling_cb() is called even later, at TLS_ST_CR_SRVR_DONE.
           What we can do here is to defer status checking of the first cert.
           This will then be performed by ocsp_stapling_cb(). */
                continue;
        }
        if (!check_cert_revocation(ctx, NULL))
            return 0;
        chain = X509_STORE_CTX_get0_chain(ctx); /* for some reason need again */

    }
    return 1;
}
/* TODO DvO (end) push OCSP-related code upstream (PR #ocsp_stapling_crls) */
#endif  /* !defined OPENSSL_NO_OCSP */

/*-
 * Writes OSSL_CMP_MSG DER-encoded to the file specified with outfile
 *
 * returns 1 on success, 0 on error
 */
static int write_PKIMESSAGE(OSSL_CMP_CTX *ctx,
                            const OSSL_CMP_MSG *msg, char **filenames)
{
    char *file;
    FILE *f;
    int res = 0;

    if (msg == NULL || filenames == NULL) {
        OSSL_CMP_err(ctx, "NULL arg to write_PKIMESSAGE");
        return 0;
    }
    if (*filenames == NULL) {
        OSSL_CMP_err(ctx,
                     "not enough file names have been provided for writing message");
        return 0;
    }

    file = *filenames;
    *filenames = next_item(file);
    f = fopen(file, "wb");
    if (f == NULL)
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                        "cannot open file '%s' for writing", file);
    else {
        unsigned char *out = NULL;
        int len = i2d_OSSL_CMP_MSG((OSSL_CMP_MSG *)msg, &out);

        if (len >= 0) {
            if ((size_t)len == fwrite(out, sizeof(*out), len, f))
                res = 1;
            else
                OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR, "cannot write file '%s'",
                                file);
            OPENSSL_free(out);
        }
        fclose(f);
    }
    return res;
}

/*-
 * Reads a DER-encoded OSSL_CMP_MSG from the file specified in infile
 * The OSS_CMP_MSG must be freed by the caller
 *
 * returns a pointer to the parsed OSSL_CMP_MSG, null on error
 */
static OSSL_CMP_MSG *read_PKIMESSAGE(OSSL_CMP_CTX *ctx, char **filenames)
{
    char *file;
    FILE *f;
    long fsize;
    unsigned char *in;
    OSSL_CMP_MSG *ret = NULL;

    if (filenames == NULL) {
        OSSL_CMP_err(ctx, "NULL arg to read_PKIMESSAGE");
        return 0;
    }
    if (*filenames == NULL) {
        OSSL_CMP_err(ctx,
                     "Not enough file names have been provided for reading message");
        return 0;
    }

    file = *filenames;
    *filenames = next_item(file);
    f = fopen(file, "rb");
    if (f == NULL)
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                        "cannot open file '%s' for reading", file);
    else {
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (fsize < 0) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                            "cannot get size of file '%s'", file);
        } else {
            in = OPENSSL_malloc(fsize);
            if (in == NULL)
                OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                                "Out of memory reading '%s'", file);
            else {
                if ((size_t)fsize != fread(in, 1, fsize, f))
                    OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                                    "cannot read file '%s'", file);
                else {
                    const unsigned char *p = in;
                    ret = d2i_OSSL_CMP_MSG(NULL, &p, fsize);
                    if (ret == NULL)
                        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                                        "cannot parse PKIMessage in file '%s'",
                                        file);
                }
                OPENSSL_free(in);
            }
        }
        fclose(f);
    }
    return ret;
}

/*-
 * Sends the PKIMessage req and on success place the response in *res
 * basically like OSSL_CMP_MSG_http_perform(), but in addition allows
 * to dump the sequence of requests and responses to files and/or
 * to take the sequence of requests and responses from files.
 */
static int read_write_req_resp(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                               OSSL_CMP_MSG **res)
{
    OSSL_CMP_MSG *req_new = NULL;
    OSSL_CMP_HDR *hdr;
    int ret = CMP_R_ERROR_TRANSFERRING_OUT;

    if (req != NULL && opt_reqout != NULL &&
        !write_PKIMESSAGE(ctx, req, &opt_reqout))
        goto err;

    if (opt_reqin != NULL) {
        if (opt_rspin != NULL) {
            OSSL_CMP_warn(ctx, "-reqin is ignored since -rspin is present");
        } else {
            ret = CMP_R_ERROR_TRANSFERRING_IN;
            if ((req_new = read_PKIMESSAGE(ctx, &opt_reqin)) == NULL)
                goto err;
# if 0
          /*
           * The transaction ID in req_new may not be fresh. In this case the
           * Insta Demo CA correctly complains: "Transaction id already in use."
           * The following workaround unfortunately requires re-protection.
           * --> GitHub issue#8
           */
            OSSL_CMP_HDR_set1_transactionID(OSSL_CMP_MSG_get0_header
                                            (req_new), NULL);
            OSSL_CMP_MSG_protect((OSSL_CMP_CTX *)ctx, req_new);
# endif
        }
    }

    ret = CMP_R_ERROR_TRANSFERRING_IN;
    if (opt_rspin != NULL) {
        if ((*res = read_PKIMESSAGE(ctx, &opt_rspin)))
            ret = 0;
    } else {
        const OSSL_CMP_MSG *actual_req = opt_reqin != NULL ? req_new : req;
# ifndef NDEBUG
        if (opt_mock_srv) {
            OSSL_CMP_CTX_set_transfer_cb_arg(ctx, srv_ctx);
            ret = OSSL_CMP_mock_server_perform(ctx, actual_req, res);
        } else {
# endif
# if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
            ret = OSSL_CMP_MSG_http_perform(ctx, actual_req, res);
# endif
# ifndef NDEBUG
        }
# endif
    }

    if (ret != 0 || (*res) == NULL)
        goto err;
    ret = ERR_R_MALLOC_FAILURE;
    hdr = OSSL_CMP_MSG_get0_header(*res);
    if ((opt_reqin != NULL || opt_rspin != NULL) &&
        /* need to satisfy nonce and transactionID checks */
        (!OSSL_CMP_CTX_set1_last_senderNonce(ctx,
                                             OSSL_CMP_HDR_get0_recipNonce(hdr))
         || !OSSL_CMP_CTX_set1_transactionID(ctx,
                                             OSSL_CMP_HDR_get0_transactionID(hdr))
        ))
        goto err;

    if (opt_rspout != NULL && !write_PKIMESSAGE(ctx, *res, &opt_rspout)) {
        ret = CMP_R_ERROR_TRANSFERRING_OUT;
        OSSL_CMP_MSG_free(*res);
        goto err;
    }

    ret = 0;
 err:
    OSSL_CMP_MSG_free(req_new);
    return ret;
}

static const char *tls_error_hint(unsigned long err)
{
    switch(ERR_GET_REASON(err)) {
/*  case 0x1408F10B: */ /* xSL_F_SSL3_GET_RECORD */
    case SSL_R_WRONG_VERSION_NUMBER:
/*  case 0x140770FC: */ /* xSL_F_SSL23_GET_SERVER_HELLO */
    case SSL_R_UNKNOWN_PROTOCOL:
         return "The server does not support (a recent version of) TLS";
/*  case 0x1407E086: */ /* xSL_F_SSL3_GET_SERVER_HELLO */
/*  case 0x1409F086: */ /* xSL_F_SSL3_WRITE_PENDING */
/*  case 0x14090086: */ /* xSL_F_SSL3_GET_SERVER_CERTIFICATE */
/*  case 0x1416F086: */ /* xSL_F_TLS_PROCESS_SERVER_CERTIFICATE */
    case SSL_R_CERTIFICATE_VERIFY_FAILED:
        return "Cannot authenticate server via its TLS certificate, likely due to mismatch with our trusted TLS certs or missing revocation status";
/*  case 0x14094418: */ /* xSL_F_SSL3_READ_BYTES */
    case SSL_AD_REASON_OFFSET+TLS1_AD_UNKNOWN_CA:
        return "Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor or missing revocation status";
    case SSL_AD_REASON_OFFSET+SSL3_AD_HANDSHAKE_FAILURE:
        return "Server requires our TLS certificate but did not receive one";
    default: /* no error or no hint available for error */
        return NULL;
    }
}

static BIO *tls_http_cb(OSSL_CMP_CTX *ctx, BIO *hbio, unsigned long detail)
{
    SSL_CTX *ssl_ctx = OSSL_CMP_CTX_get_http_cb_arg(ctx);
    BIO *sbio = NULL;
    if (detail == 1) { /* connecting */
        sbio = BIO_new_ssl(OSSL_CMP_CTX_get_http_cb_arg(ctx), 1/* client */);
        hbio = sbio != NULL ? BIO_push(sbio, hbio): NULL;
    } else { /* disconnecting */
        const char *hint = tls_error_hint(detail);
        if (hint != NULL)
            OSSL_CMP_add_error_data(hint);
        /* as a workaround for OpenSSL double free, do not pop the sbio, but
           rely on BIO_free_all() done by OSSL_CMP_MSG_http_perform() */
    }
    if (ssl_ctx != NULL) {
        X509_STORE *ts = SSL_CTX_get_cert_store(ssl_ctx);
        if (ts != NULL) {
            /* indicate if OSSL_CMP_MSG_http_perform() with TLS is active */
            (void)X509_STORE_set_ex_data(ts, X509_STORE_EX_DATA_SBIO, sbio);
        }
    }
    return hbio;
}

/*
 * This function is a callback used by OpenSSL's verify_cert function.
 * It is called at the end of a cert verification to allow an opportunity
 * to gather and output information regarding a failing cert verification,
 * and to possibly change the result of the verification (here maybe for OCSP).
 * This callback is also activated when constructing our own TLS chain:
 * tls_construct_client_certificate() -> ssl3_output_cert_chain() ->
 * ssl_add_cert_chain() -> X509_verify_cert() where errors are ignored.
 * returns 0 if and only if the cert verification is considered failed.
 */
static int cert_verify_cb (int ok, X509_STORE_CTX *ctx)
{
    if (ok == 0 && ctx != NULL) {
        int cert_error = X509_STORE_CTX_get_error(ctx);
        X509_STORE *ts = X509_STORE_CTX_get0_store(ctx);
        BIO *sbio = X509_STORE_get_ex_data(ts, X509_STORE_EX_DATA_SBIO);
        SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());
        const char *expected = NULL;

        if (sbio != 0 /* OSSL_CMP_MSG_http_perform() with TLS is active */
            && !ssl) /* ssl_add_cert_chain() is active */
            return ok; /* avoid printing spurious errors */

        switch (cert_error) {
        case X509_V_ERR_HOSTNAME_MISMATCH:
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            /*
             * Unfortunately there is no OpenSSL API function for retrieving the
             * hosts/ip entries in X509_VERIFY_PARAM. So we use ts->ex_data.
             * This works for names we set ourselves but not verify_hostname
             * used for OSSL_CMP_certConf_cb.
             */
            expected = X509_STORE_get_ex_data(ts, X509_STORE_EX_DATA_HOST);
            if (expected != NULL)
                OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_INFO,
                                "TLS connection expected host = %s", expected);
            break;
        default:
            break;
        }
    }
    return OSSL_CMP_print_cert_verify_cb(ok, ctx); /* print diagnostics */
}

/*!*****************************************************************************
* @brief parse string as integer value, not allowing trailing garbage
*
* @note see also https://www.gnu.org/software/libc/manual/html_node/Parsing-of-Integers.html
* @param str input string
* @return integer value, or INT_MIN on error
*******************************************************************************/
static int atoint(const char *str)
{
    char *tailptr;
    long res = strtol(str, &tailptr, 10);
    if  ((*tailptr != '\0') || (res < INT_MIN) || (res > INT_MAX)) {
        return INT_MIN;
    } else {
        return (int)res;
    }
}

static int parse_addr(OSSL_CMP_CTX *ctx,
                      char **opt_string, int port, const char *name)
{
    char *port_string;

    if (strncmp(*opt_string, HTTP_HDR, strlen(HTTP_HDR)) == 0) {
        (*opt_string) += strlen(HTTP_HDR);
    }
    if ((port_string = strrchr(*opt_string, ':')) == NULL) {
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_INFO,
                        "using default port %d for %s", port, name);
        return port;
    }
    *(port_string++) = '\0';
    port = atoint(port_string);
    if ((port <= 0) || (port > 65535)) {
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                        "invalid %s port '%s' given, sane range 1-65535",
                        name, port_string);
        return 0;
    }
    return port;
}

/*
 * verbatim from apps/s_cb.c
 * does not consume the crls
 */
static int add_crls_store(X509_STORE *st, STACK_OF(X509_CRL) *crls)
{
    X509_CRL *crl;
    int i;

    for (i = 0; i < sk_X509_CRL_num(crls); i++) {
        crl = sk_X509_CRL_value(crls, i);
        if (!X509_STORE_add_crl(st, crl))
            return 0;
    }
    return 1;
}

static int set1_store_parameters_crls(X509_STORE *ts, STACK_OF(X509_CRL) *crls)
{
    if (ts == NULL|| vpm == NULL)
        return 0;

    /* copy vpm to store */
    if (!X509_STORE_set1_param(ts, (X509_VERIFY_PARAM *)vpm)) {
        BIO_printf(bio_err, "error setting verification parameters\n");
        ERR_print_errors(bio_err);
        return 0;
    }

    X509_STORE_set_verify_cb(ts, cert_verify_cb);

    if (crls != NULL &&
        !add_crls_store(ts, crls)) /* ups the references to crls */
        return 0;

    if (opt_crl_download)
        X509_STORE_set_lookup_crls(ts, get_crls_cb);
    /*
     * TODO DvO: to be replaced with "store_setup_crl_download(ts)" from apps.h,
     * after extended version of crls_http_cb()
     * has been merged upstream (PR #crls_timeout_local)
     */

#ifndef OPENSSL_NO_OCSP
    if (check_revocation) {
        /* this implies opt_ocsp_use_aia || opt_ocsp_url || opt_ocsp_status */
        X509_STORE_set_check_revocation(ts, &check_revocation_ocsp_crls);
    }
#endif

    return 1;
}

static int set_name(const char *str,
                    int (*set_fn) (OSSL_CMP_CTX *ctx, const X509_NAME *name),
                    OSSL_CMP_CTX *ctx, const char *desc)
{
    if (str != NULL) {
        X509_NAME *n = parse_name((char *)str, MBSTRING_ASC, 0);

        if (n == NULL) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                            "cannot parse %s DN '%s'", desc, str);
            return 0;
        }
        if (!(*set_fn) (ctx, n)) {
            X509_NAME_free(n);
            OSSL_CMP_err(ctx, "out of memory");
            return 0;
        }
        X509_NAME_free(n);
    }
    return 1;
}

static int set_gennames(char *names, int type,
                       int (*set_fn) (OSSL_CMP_CTX *ctx, const GENERAL_NAME *name),
                       OSSL_CMP_CTX *ctx, const char *desc)
{
    char *next;
    for (; names != NULL; names = next) {
        GENERAL_NAME *n;
        next = next_item(names);

        if (type == GEN_DNS && strcmp(names, "critical") == 0) {
            (void)OSSL_CMP_CTX_set_option(ctx,
                      OSSL_CMP_CTX_OPT_SUBJECTALTNAME_CRITICAL, 1);
            continue;
        }
        if (type != GEN_DNS || isdigit(names[0])) {
            n = a2i_GENERAL_NAME(NULL, NULL, NULL,
                                 type != GEN_DNS ? type : GEN_IPADD, names, 0);
        } else { /* try IP address first, then domain name */
            (void)ERR_set_mark();
            n = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_IPADD, names, 0);
            (void)ERR_pop_to_mark();
            if (n == NULL) {
                n = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_DNS, names, 0);
            }
        }

        if (n == NULL) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                            "bad syntax of %s '%s'", desc, names);
            return 0;
        }
        if (!(*set_fn) (ctx, n)) {
            GENERAL_NAME_free(n);
            OSSL_CMP_err(ctx, "out of memory\n");
            return 0;
        }
        GENERAL_NAME_free(n);
    }
    return 1;
}

/* TODO DvO push this and related functions upstream (PR #multifile) */
/*
 * create cert store structure with certificates read from given file(s)
 * returns pointer to created X509_STORE on success, NULL on error
 */
static X509_STORE *load_certstore(char *input, const char *desc)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *certs = NULL;

    if (input == NULL)
        goto err;

    /* BIO_printf(bio_c_out, "loading %s from file '%s'\n", desc, input); */
    while (input != NULL) {
        char *next = next_item(input);           \

        if (!load_certs_autofmt(input, &certs, opt_otherform, 1,
                                opt_otherpass, desc) ||
            !(store = sk_X509_to_store(store, certs))) {
            /* BIO_puts(bio_err, "error: out of memory\n"); */
            X509_STORE_free(store);
            store = NULL;
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
        certs = NULL;
        input = next;
    }
 err:
    sk_X509_pop_free(certs, X509_free);
    return store;
}

/* TODO DvO push this and related functions upstream (PR #multifile) */
static STACK_OF(X509) *load_certs_multifile(char *files, int format,
                                            const char *pass, const char *desc)
{
    STACK_OF(X509) *certs = NULL;
    STACK_OF(X509) *result = sk_X509_new_null();

    if (files == NULL) {
        goto err;
    }
    if (result == NULL) {
        goto oom;
    }

    while (files != NULL) {
        char *next = next_item(files);

        if (!load_certs_autofmt(files, &certs, format, 0, pass, desc)) {
            goto err;
        }
        if (!OSSL_CMP_sk_X509_add1_certs(result, certs, 0, 1 /* no dups */)) {
            goto oom;
        }
        sk_X509_pop_free(certs, X509_free);
        certs = NULL;
        files = next;
    }
    return result;

 oom:
    BIO_printf(bio_err, "out of memory\n");
 err:
    sk_X509_pop_free(certs, X509_free);
    sk_X509_pop_free(result, X509_free);
    return NULL;
}

typedef int (*add_X509_stack_fn_t)(void *ctx, const STACK_OF(X509) *certs);
typedef int (*add_X509_fn_t      )(void *ctx, const X509 *cert);
static int setup_certs(char *files, const char *desc, void *ctx,
                       add_X509_stack_fn_t addn_fn, add_X509_fn_t add1_fn)
{
    int ret = 1;

    if (files != NULL) {
        STACK_OF(X509) *certs = load_certs_multifile(files, opt_otherform,
                                                     opt_otherpass, desc);
        if (certs == NULL) {
            ret = 0;
        } else {
            if (addn_fn != NULL) {
                ret = (*addn_fn)(ctx, certs);
            } else {
                int i;
                for (i = 0; i < sk_X509_num(certs /* may be NULL */); i++) {
                    ret &= (*add1_fn)(ctx, sk_X509_value(certs, i));
                }
            }
            sk_X509_pop_free(certs, X509_free);
        }
    }
    return ret;
}


/*
 * parse and tranform some options, checking their syntax.
 * Returns 1 on success, 0 on error
 */
static int transform_opts(OSSL_CMP_CTX *ctx) {
    if (opt_cmd_s != NULL) {
        if (!strcmp(opt_cmd_s, "ir"))
            opt_cmd = CMP_IR;
        else if (!strcmp(opt_cmd_s, "kur"))
            opt_cmd = CMP_KUR;
        else if (!strcmp(opt_cmd_s, "cr"))
            opt_cmd = CMP_CR;
        else if (!strcmp(opt_cmd_s, "p10cr"))
            opt_cmd = CMP_P10CR;
        else if (!strcmp(opt_cmd_s, "rr"))
            opt_cmd = CMP_RR;
        else if (!strcmp(opt_cmd_s, "genm"))
            opt_cmd = CMP_GENM;
        else {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                            "unknown cmp command '%s'", opt_cmd_s);
            return 0;
        }
    } else {
        OSSL_CMP_err(ctx, "no cmp command to execute");
        return 0;
    }

    if (opt_keyform_s != NULL &&
        !opt_format(opt_keyform_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12
# ifndef OPENSSL_NO_ENGINE
                                    | OPT_FMT_ENGINE
# endif
        , &opt_keyform)) {
        OSSL_CMP_err(ctx, "unknown option given for key format");
        return 0;
    }

    if (opt_ownform_s != NULL &&
        !opt_format(opt_ownform_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12,
                    &opt_ownform)) {
        OSSL_CMP_err(ctx, "unknown option given for own certificate format");
        return 0;
    }

    if (opt_otherform_s != NULL &&
        !opt_format(opt_otherform_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12,
                    &opt_otherform)) {
        OSSL_CMP_err(ctx, "unknown option given for certificate store format");
        return 0;
    }

    if (opt_crlform_s != NULL &&
        !opt_format(opt_crlform_s, OPT_FMT_PEMDER, &opt_crlform)) {
        OSSL_CMP_err(ctx, "unknown option given for CRL format");
        return 0;
    }

    return 1;
}

#ifndef NDEBUG
static int setup_srv_ctx(ENGINE *e)
{
    OSSL_CMP_CTX *ctx = NULL;
    srv_ctx = OSSL_CMP_SRV_CTX_create();

    if (srv_ctx == NULL)
        return 0;
    ctx = OSSL_CMP_SRV_CTX_get0_ctx(srv_ctx);

    if (opt_srv_ref == NULL && opt_srv_cert == NULL) {
        /* srv_cert should determine the sender */
        OSSL_CMP_err(ctx, "must give -srv_ref if no -srv_cert given");
        goto err;
    }
    if (opt_srv_secret != NULL) {
        int res;
        char *pass_string;
        if ((pass_string = get_passwd(opt_srv_secret,
                                      "PBMAC secret of server"))) {
            cleanse(opt_srv_secret);
            res = OSSL_CMP_CTX_set1_referenceValue(ctx,
                                                   (unsigned char *)opt_srv_ref,
                                                   strlen(opt_srv_ref)) &&
                  OSSL_CMP_CTX_set1_secretValue(ctx,
                                                (unsigned char *)pass_string,
                                                strlen(pass_string));
            OPENSSL_clear_free(pass_string, strlen(pass_string));
            if (res == 0)
                goto err;
        }
    } else if (opt_srv_cert == NULL && opt_srv_key == NULL) {
        OSSL_CMP_err(ctx,
                     "server credentials must be set if -mock_srv is used");
        goto err;
    }

    if (opt_srv_secret == NULL &&
        ((opt_srv_cert == NULL) != (opt_srv_key == NULL))) {
        OSSL_CMP_err(ctx,
                     "must give both -srv_cert and -srv_key options or neither");
            goto err;
    }
    if (opt_srv_cert != NULL) {
        X509 *srv_cert = load_cert_autofmt(opt_srv_cert, opt_ownform,
                              opt_srv_keypass, "CMP certificate of the server");
        /* from server perspective the server is the client */
        if (srv_cert == NULL || !OSSL_CMP_CTX_set1_clCert(ctx, srv_cert)) {
            X509_free(srv_cert);
            goto err;
        }
        X509_free(srv_cert);
    }
    if (opt_srv_key != NULL) {
        EVP_PKEY *pkey = load_key_autofmt(opt_srv_key, opt_keyform,
                  opt_srv_keypass, e, "private key for server CMP certificate");
        if (pkey == NULL || !OSSL_CMP_CTX_set0_pkey(ctx, pkey)) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    }
    cleanse(opt_srv_keypass);

    if (opt_srv_trusted != NULL) {
        X509_STORE *ts =
            load_certstore(opt_srv_trusted, "server trusted certificates");
        if (!set1_store_parameters_crls(ts/* may be NULL */, NULL/*no CRLs*/) ||
            !truststore_set_host_etc(ts, NULL/* for CMP level, no host etc*/) ||
            !OSSL_CMP_CTX_set0_trustedStore(ctx, ts)) {
            X509_STORE_free(ts);
            goto err;
        }
    }
    if (!setup_certs(opt_srv_untrusted, "untrusted certificates", ctx,
                     (add_X509_stack_fn_t)OSSL_CMP_CTX_set1_untrusted_certs,
                     NULL))
        goto err;

    if (opt_rsp_cert != NULL) {
        X509 *cert =
            load_cert_autofmt(opt_rsp_cert, opt_ownform, opt_keypass,
                              "certificate to be returned by the mock server");
       if (cert == NULL)
           goto err;
       /* from server-sight the server is the client */
       if (!OSSL_CMP_SRV_CTX_set1_certOut(srv_ctx, cert)) {
           X509_free(cert);
           goto err;
       }
       X509_free(cert);
    }
    /* TODO TPa: find a cleaner solution than this hack with typecasts */
    if (!setup_certs(opt_rsp_extracerts,
                     "CMP extra certificates for mock server", srv_ctx,
                     (add_X509_stack_fn_t)OSSL_CMP_SRV_CTX_set1_chainOut, NULL))
        goto err;
    if (!setup_certs(opt_rsp_capubs, "caPubs for mock server", srv_ctx,
             (add_X509_stack_fn_t)OSSL_CMP_SRV_CTX_set1_caPubsOut, NULL))
        goto err;
    (void)OSSL_CMP_SRV_CTX_set_pollCount(srv_ctx, opt_poll_count);
    (void)OSSL_CMP_SRV_CTX_set_checkAfterTime(srv_ctx, opt_checkafter);
    if (opt_grant_implicitconf)
        (void)OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv_ctx, 1);

    if (opt_failure >= 0) {
        if (opt_failurebits != 0)
            OSSL_CMP_warn(ctx, "-failurebits overrides -failure");
        else
            opt_failurebits = 1 << opt_failure;
    }
    if (!OSSL_CMP_SRV_CTX_set_statusInfo(srv_ctx, opt_pkistatus,
                                         opt_failurebits, opt_statusstring))
        goto err;

    if (opt_send_error)
        (void)OSSL_CMP_SRV_CTX_set_send_error(srv_ctx, 1);

    if (opt_send_unprotected)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 1);
    if (opt_send_unprot_err)
        (void)OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv_ctx, 1);
    if (opt_accept_unprotected)
        (void)OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx, 1);
    if (opt_accept_unprot_err)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);

    return 1;

 err:
    OSSL_CMP_SRV_CTX_delete(srv_ctx);
    srv_ctx = NULL;
    return 0;
}
#endif /* !defined(NDEBUG) */

/*
 * set up verification aspects of OSSL_CMP_CTX w.r.t. opts from config file/CLI.
 * Returns pointer on success, NULL on error
 */
static int setup_verification_ctx(OSSL_CMP_CTX *ctx, STACK_OF(X509_CRL) **all_crls) {
    *all_crls = NULL;
    if (opt_ocsp_status)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_OCSP_STAPLING);
    if (opt_ocsp_use_aia || opt_ocsp_url != NULL || opt_ocsp_check_all)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_OCSP_CHECK);
    if (opt_ocsp_check_all)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_OCSP_CHECK_ALL);
    if (opt_crls != NULL || opt_crl_download)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK);
    else if (X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_CRL_CHECK) {
        OSSL_CMP_err(ctx,
                     "must use -crl_download or -crls when -crl_check is given");
#if 0
        X509_VERIFY_PARAM_clear_flags(vpm, X509_V_FLAG_CRL_CHECK);
#else
        goto err;
#endif
    }
    {  /* just as a precaution in case CRL_CHECK_ALL is set without CRL_CHECK */
        unsigned long flags = X509_VERIFY_PARAM_get_flags(vpm);
        if ((flags & X509_V_FLAG_CRL_CHECK_ALL) &&
            !(flags & X509_V_FLAG_CRL_CHECK))
            OSSL_CMP_warn(ctx,
                          "-crl_check_all has no effect without -crls, -crl_download, or -crl_check");
    }
    if (opt_crl_timeout == 0)
        opt_crl_timeout = -1;
    if (opt_crls != NULL) {
/* TODO DvO extract load_multiple_crls() and push upstream (PR #multifile) */
        X509_CRL *crl;
        STACK_OF(X509_CRL) *crls;

        if ((*all_crls = sk_X509_CRL_new_null()) == NULL) {
            goto oom;
        }
        while (opt_crls != NULL) {
            char *next = next_item(opt_crls);

            crls =
                load_crls_autofmt(opt_crls, opt_crlform,
                                  "CRL(s) for checking certificate revocation");
            if (crls == NULL)
                goto err;
            while ((crl = sk_X509_CRL_shift(crls)) != NULL) {
                if (!sk_X509_CRL_push(*all_crls, crl)) {
                    sk_X509_CRL_pop_free(crls, X509_CRL_free);
                    goto oom;
                }
                if (OSSL_CMP_expired(X509_CRL_get0_nextUpdate(crl), vpm)) {
              /* well, should ignore expiry of base CRL if delta CRL is valid */
                    char *issuer =
                        X509_NAME_oneline(X509_CRL_get_issuer(crl), NULL, 0);
                    OSSL_CMP_printf(ctx, OSSL_CMP_FL_WARN,
                                    "CRL from '%s' issued by '%s' has expired",
                                    opt_crls, issuer);
                    OPENSSL_free(issuer);
#if 0
                    sk_X509_CRL_pop_free(crls, X509_CRL_free);
                    goto err;
#endif
                }
            }
            sk_X509_CRL_free(crls);
            opt_crls = next;
        }
    }
    if (!setup_certs(opt_untrusted, "untrusted certificates", ctx,
                     (add_X509_stack_fn_t)OSSL_CMP_CTX_set1_untrusted_certs,
                     NULL))
        goto err;

#ifndef OPENSSL_NO_OCSP
    if (opt_ocsp_use_aia || opt_ocsp_url != NULL || opt_ocsp_status) {
        X509_STORE_CTX *tmp_ctx = X509_STORE_CTX_new();

# if 0 && !defined NDEBUG
        OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_INFO,
                        "Will try %s%s for certificate status checking",
                        (opt_ocsp_use_aia || opt_ocsp_url != NULL) &&
                        opt_ocsp_status ? "OCSP stapling then OCSP" :
                        opt_ocsp_status ? "OCSP stapling" : "OCSP",
                        (opt_crl_download || opt_crls != NULL) ?
                        " then CRLs" : "");
# endif

        /*
         * Unfortunately, check_cert() in crypto/x509/x509_vfy.c is static, yet
         * we can access it indirectly via check_revocation() with a trick.
         */
        if (tmp_ctx != NULL && X509_STORE_CTX_init(tmp_ctx, NULL, NULL, NULL))
            check_revocation = X509_STORE_CTX_get_check_revocation(tmp_ctx);
        X509_STORE_CTX_free(tmp_ctx);
        if (!check_revocation) {
            OSSL_CMP_err(ctx, "internal issue: cannot get check_revocation");
            goto err;
        }
    } else if (opt_ocsp_check_all) {
        OSSL_CMP_err(ctx,
                     "must use -ocsp_use_aia or -ocsp_url if -ocsp_check_all is given");
        goto err;
    }
#endif

    if (opt_srvcert != NULL || opt_trusted != NULL) {
        X509_STORE *ts = NULL;

        if (opt_srvcert != NULL) {
            X509 *srvcert;
            if (opt_trusted != NULL) {
                OSSL_CMP_warn(ctx,
                              "-trusted option is ignored since -srvcert option is present");
                opt_trusted = NULL;
            }
            if (opt_recipient != NULL) {
                OSSL_CMP_warn(ctx,
                              "-recipient option is ignored since -srvcert option is present");
                opt_recipient = NULL;
            }
            srvcert = load_cert_autofmt(opt_srvcert, opt_otherform,
                                        opt_otherpass,
                                        "trusted CMP server certificate");
            if (srvcert == NULL)
  /* opt_otherpass is needed in case opt_srvcert is an encrypted PKCS#12 file */
                goto err;
            if (!OSSL_CMP_CTX_set1_srvCert(ctx, srvcert)) {
                X509_free(srvcert);
                goto oom;
            }
            X509_free(srvcert);
            if ((ts = X509_STORE_new()) == NULL)
                goto oom;
        }
        if (opt_trusted != NULL &&
            (ts = load_certstore(opt_trusted, "trusted certificates")) == NULL)
            goto err;
        if (!set1_store_parameters_crls(ts, *all_crls) ||
            !truststore_set_host_etc(ts, NULL/* for CMP level, no host etc*/) ||
            !OSSL_CMP_CTX_set0_trustedStore(ctx, ts)) {
            X509_STORE_free(ts);
            goto oom;
        }
    }

    if (opt_ignore_keyusage)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_IGNORE_KEYUSAGE, 1);

    if (opt_unprotectedErrors)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);

    if (opt_out_trusted != NULL) { /* for use in OSSL_CMP_certConf_cb() */
        X509_STORE *out_trusted =
            load_certstore(opt_out_trusted,
                           "trusted certs for verifying newly enrolled cert");
        if (out_trusted == NULL)
            goto err;
        /* any -verify_hostname, -verify_ip, and -verify_email apply here */
        if (!set1_store_parameters_crls(out_trusted, *all_crls))
            goto oom;
        (void)OSSL_CMP_CTX_set_certConf_cb_arg(ctx, out_trusted);

    }

    if (opt_disableConfirm)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_DISABLECONFIRM, 1);

    if (opt_implicitConfirm)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_IMPLICITCONFIRM, 1);

    (void)OSSL_CMP_CTX_set_certConf_cb(ctx, OSSL_CMP_certConf_cb);

    return 1;

 oom:
    OSSL_CMP_err(ctx, "out of memory");
 err:
    sk_X509_CRL_pop_free(*all_crls, X509_CRL_free);
    *all_crls = NULL;
    return 0;
}


static int SSL_CTX_add_extra_chain_free(SSL_CTX *ssl_ctx, STACK_OF(X509) *certs)
{
    int i;
    int res = 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        if (res != 0)
            res = SSL_CTX_add_extra_chain_cert(ssl_ctx,
                                               sk_X509_value(certs, i));
    }
    sk_X509_free(certs); /* must not free the stack elements */
    if (res == 0)
        BIO_printf(bio_err, "error: unable to use TLS extra certs\n");
    return res;
}

/*
 * set up ssl_ctx for the OSSL_CMP_CTX based on options from config file/CLI.
 * Returns pointer on success, NULL on error
 */
static SSL_CTX *setup_ssl_ctx(ENGINE *e, STACK_OF(X509) *untrusted_certs,
                              STACK_OF(X509_CRL) *all_crls)
{
    EVP_PKEY *pkey = NULL;
    X509_STORE *store = NULL;
    SSL_CTX *ssl_ctx;

    /* initialize OpenSSL's SSL lib */
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL) {
        goto oom;
    }
    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_TLSv1);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

#ifndef OPENSSL_NO_OCSP
    if (opt_ocsp_status) {
        SSL_CTX_set_tlsext_status_type(ssl_ctx, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ssl_ctx, ocsp_stapling_cb);
/*
 * help cert chain building with untrusted certs when list of certs is
 * insufficient from SSL_get0_verified_chain(ssl) and OCSP_resp_get0_certs(br):
 */
        SSL_CTX_set_tlsext_status_arg(ssl_ctx, untrusted_certs);
    }
#endif /* OPENSSL_NO_OCSP */

    if (opt_tls_trusted != NULL) {
        if ((store = load_certstore(opt_tls_trusted,
                                    "trusted TLS certificates")) == NULL) {
            goto err;
        }
        /* do immediately for automatic cleanup in case of errors: */
        SSL_CTX_set_cert_store(ssl_ctx, store);
        if (!set1_store_parameters_crls(store, all_crls))
            goto oom;
        /* enable and parameterize server hostname/IP address check */
        if (!truststore_set_host_etc(store, opt_tls_host != NULL ?
                                            opt_tls_host : opt_server))
            /* TODO: is the server host name correct for TLS via proxy? */
            goto oom;
        SSL_CTX_set_verify(ssl_ctx,
                           SSL_VERIFY_PEER |
                           SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    {
        X509_STORE *untrusted_store = sk_X509_to_store(NULL, untrusted_certs);

        /* do immediately for automatic cleanup in case of errors: */
        if (!SSL_CTX_set0_chain_cert_store(ssl_ctx,
                                           untrusted_store /* may be 0 */))
            goto oom;
    }

    if (opt_tls_cert != NULL && opt_tls_key != NULL) {
        X509 *cert = NULL;
        STACK_OF(X509) *certs = NULL;

        if (!load_certs_autofmt(opt_tls_cert, &certs, opt_ownform, 1,
                                opt_tls_keypass,
                                "TLS client certificate (optionally with chain)"))
/* opt_tls_keypass is needed in case opt_tls_cert is an encrypted PKCS#12 file*/
            goto err;

        cert = sk_X509_delete(certs, 0);
        if (cert == NULL || SSL_CTX_use_certificate(ssl_ctx, cert) <= 0) {
            BIO_printf(bio_err,
                       "error: unable to use client TLS certificate file '%s'\n",
                       opt_tls_cert);
            X509_free(cert);
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        X509_free(cert); /* we do not need the handle any more */

        /*
         * When the list of extra certificates in certs in non-empty,
         * well send them (instead of a chain built from opt_untrusted)
         * along with the TLS end entity certificate.
         */
        if (!SSL_CTX_add_extra_chain_free(ssl_ctx, certs))
            goto err;
        /* If present we append to the list also the certs from opt_tls_extra */
        if (opt_tls_extra != NULL) {
            STACK_OF(X509) *tls_extra =
                load_certs_multifile(opt_tls_extra, opt_ownform, opt_otherpass,
                                     "extra certificates for TLS");
            if (tls_extra == NULL ||
                !SSL_CTX_add_extra_chain_free(ssl_ctx, tls_extra))
                goto err;
        }

        pkey = load_key_autofmt(opt_tls_key, opt_keyform, opt_tls_keypass,
                                e, "TLS client private key");
        cleanse(opt_tls_keypass);
        if (pkey == NULL)
            goto err;
        /*
         * verify the key matches the cert,
         * not using SSL_CTX_check_private_key(ssl_ctx)
         * because it gives poor and sometimes misleading diagnostics
         */
        if (!X509_check_private_key(SSL_CTX_get0_certificate(ssl_ctx),
                                    pkey)) {
            BIO_printf(bio_err,
                       "error: TLS private key '%s' does not match the TLS certificate '%s'\n",
                       opt_tls_key, opt_tls_cert);
            EVP_PKEY_free(pkey);
            pkey = NULL;    /* otherwise, for some reason double free! */
            goto err;
        }
        if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) <= 0) {
            BIO_printf(bio_err,
                       "error: unable to use TLS client private key '%s'\n",
                       opt_tls_key);
            EVP_PKEY_free(pkey);
            pkey = NULL; /* otherwise, for some reason double free! */
            goto err;
        }
        EVP_PKEY_free(pkey); /* we do not need the handle any more */
    }
    return ssl_ctx;

 oom:
    BIO_printf(bio_err, "out of memory\n");
 err:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}

/*
 * set up protection aspects of OSSL_CMP_CTX based on options from config file/CLI
 * while parsing options and checking their consistency.
 * Returns 1 on success, 0 on error
 */
static int setup_protection_ctx(OSSL_CMP_CTX *ctx, ENGINE *e) {
    if (!opt_unprotectedRequests && !opt_secret && !(opt_cert && opt_key)) {
        OSSL_CMP_err(ctx,
                     "must give client credentials unless -unprotectedrequests is set");
        goto err;
    }

    if (opt_ref == NULL && opt_cert == NULL && opt_subject == NULL) {
        /* cert or subject should determine the sender */
        OSSL_CMP_err(ctx, "must give -ref if no -cert and no -subject given");
        goto err;
    }
    if (!opt_secret && ((opt_cert == NULL) != (opt_key == NULL))) {
        OSSL_CMP_err(ctx, "must give both -cert and -key options or neither");
        goto err;
    }
    if (opt_secret != NULL) {
        char *pass_string = NULL;
        int res;

        if ((pass_string = get_passwd(opt_secret, "PBMAC")) != NULL) {
            cleanse(opt_secret);
            res = OSSL_CMP_CTX_set1_secretValue(ctx,
                                                (unsigned char *)pass_string,
                                                strlen(pass_string));
            OPENSSL_clear_free(pass_string, strlen(pass_string));
            if (res == 0)
                goto err;
        }
        if (opt_cert != NULL || opt_key != NULL)
            OSSL_CMP_warn(ctx,
                          "no signature-based protection used since -secret is given");
    }
    if (opt_ref != NULL &&
        !OSSL_CMP_CTX_set1_referenceValue(ctx, (unsigned char *)opt_ref,
                                          strlen(opt_ref)))
        goto err;

    if (opt_key != NULL) {
        EVP_PKEY *pkey =
            load_key_autofmt(opt_key, opt_keyform, opt_keypass, e,
                             "private key for CMP client certificate");

        if (pkey == NULL || !OSSL_CMP_CTX_set0_pkey(ctx, pkey)) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    }
    if ((opt_cert != NULL || opt_unprotectedRequests) &&
        !(opt_srvcert != NULL || opt_trusted != NULL)) {
        OSSL_CMP_err(ctx, "no server certificate or trusted certificates set");
        goto err;
    }

    if (opt_cert != NULL) {
        X509 *clcert;
        STACK_OF(X509) *certs = NULL;
        int ok;

        if (!load_certs_autofmt(opt_cert, &certs, opt_ownform, 1,
            opt_keypass, "CMP client certificate (and optionally extra certs)"))
       /* opt_keypass is needed in case opt_cert is an encrypted PKCS#12 file */
            goto err;

        clcert = sk_X509_delete(certs, 0);
        if (clcert == NULL) {
            OSSL_CMP_err(ctx, "no client certificate found");
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        ok = OSSL_CMP_CTX_set1_clCert(ctx, clcert);
        X509_free(clcert);

        if (ok) {
            /* add any remaining certs to the list of untrusted certs */
            STACK_OF(X509) *untrusted = OSSL_CMP_CTX_get0_untrusted_certs(ctx);
            ok = untrusted != NULL ?
                OSSL_CMP_sk_X509_add1_certs(untrusted, certs,
                                            0/* allow self-signed */,
                                            1/* no dups */) :
                OSSL_CMP_CTX_set1_untrusted_certs(ctx, certs);
        }
        sk_X509_pop_free(certs, X509_free);
        if (!ok)
            goto oom;
    }

    if (!setup_certs(opt_extracerts, "extra certificates for CMP", ctx,
                     (add_X509_stack_fn_t)OSSL_CMP_CTX_set1_extraCertsOut, NULL))
        goto err;
    cleanse(opt_otherpass);

    if (opt_unprotectedRequests)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 1);

    if (opt_digest != NULL) {
        int digest = OBJ_ln2nid(opt_digest);
        if (digest == NID_undef) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                            "digest algorithm name not recognized: '%s'", opt_digest);
            goto err;
        }
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_DIGEST_ALGNID, digest);
    }
    return 1;

 oom:
    OSSL_CMP_err(ctx, "out of memory");
 err:
    return 0;
}

/*
 * set up IR/CR/KUR/CertConf/RR specific parts of the OSSL_CMP_CTX
 * based on options from config file/CLI.
 * Returns pointer on success, NULL on error
 */
static int setup_request_ctx(OSSL_CMP_CTX *ctx, ENGINE *e) {
    if (!set_name(opt_subject, OSSL_CMP_CTX_set1_subjectName, ctx, "subject") ||
        !set_name(opt_issuer, OSSL_CMP_CTX_set1_issuer, ctx, "issuer"))
        goto err;

    if (opt_newkey != NULL) {
        EVP_PKEY *pkey =
            load_key_autofmt(opt_newkey, opt_keyform, opt_newkeypass, e,
                             "new private key for certificate to be enrolled");

        cleanse(opt_newkeypass);
        if (pkey == NULL || !OSSL_CMP_CTX_set0_newPkey(ctx, pkey)) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    }

    if (opt_days > 0)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_VALIDITYDAYS, opt_days);

    if (opt_reqexts != NULL) {
        X509V3_CTX ext_ctx;
        X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();

        X509V3_set_ctx(&ext_ctx, NULL, NULL, NULL, NULL, 0);
        X509V3_set_nconf(&ext_ctx, conf);
        if (!X509V3_EXT_add_nconf_sk(conf, &ext_ctx, opt_reqexts, &exts)) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR, "cannot load extension section '%s'",
                       opt_reqexts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            goto err;
        }
        OSSL_CMP_CTX_set0_reqExtensions(ctx, exts);
    }
    if (OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) && opt_sans != NULL) {
        OSSL_CMP_err(ctx,
                     "cannot have Subject Alternative Names both via -reqexts and via -sans");
            goto err;
    }

    if (!set_gennames(opt_sans, GEN_DNS,
                      OSSL_CMP_CTX_subjectAltName_push1, ctx,
                      "Subject Alternative Name"))
        goto err;

    if (opt_san_nodefault) {
        if (opt_sans != NULL)
            OSSL_CMP_warn(ctx,
                          "-opt_san_nodefault has no effect when -sans is used");
        (void)OSSL_CMP_CTX_set_option(ctx,
                                      OSSL_CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT,
                                      1);
    }

    while (opt_policies != NULL) {
        char *next = next_item(opt_policies);
        int res = OSSL_CMP_CTX_policyOID_push1(ctx, opt_policies);

        if (res <= 0) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR, "cannot %s policy OID '%s'",
                            res == -1 ? "parse" : "add", opt_policies);
            goto err;
        }
        opt_policies = next;
    }

    if (opt_policies_critical) {
        if (opt_policies == NULL)
            OSSL_CMP_warn(ctx,
                          "-opt_policies_critical has no effect unless -policies is given");
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_POLICIES_CRITICAL, 1);
    }

    if (opt_popo < OSSL_CRMF_POPO_NONE - 1 || opt_popo > OSSL_CRMF_POPO_KEYENC) {
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                        "invalid value '%d' for popo method (must be between -1 and 2)",
                        opt_popo);
        goto err;
    }
    if (opt_popo >= OSSL_CRMF_POPO_NONE)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_POPOMETHOD,
                                      opt_popo);

    if (opt_csr != NULL) {
        if (opt_cmd != CMP_P10CR)
            OSSL_CMP_warn(ctx,
                          "-csr option is ignored for command other than p10cr");
        else {
            X509_REQ *csr =
                load_csr_autofmt(opt_csr, opt_ownform, "PKCS#10 CSR for p10cr");
            if (csr == NULL)
                goto err;
            if (!OSSL_CMP_CTX_set1_p10CSR(ctx, csr)) {
                X509_REQ_free(csr);
                goto oom;
            }
            X509_REQ_free(csr);
        }
    }

    if (opt_oldcert != NULL) {
        X509 *oldcert = load_cert_autofmt(opt_oldcert, opt_ownform, opt_keypass,
                                          "certificate to be updated/revoked");
    /* opt_keypass is needed in case opt_oldcert is an encrypted PKCS#12 file */
        if (oldcert == NULL)
            goto err;
        if (!OSSL_CMP_CTX_set1_oldClCert(ctx, oldcert)) {
            X509_free(oldcert);
            goto oom;
        }
        X509_free(oldcert);
    }
    cleanse(opt_keypass);
    if (opt_revreason > CRL_REASON_NONE)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_REVOCATION_REASON,
                                      opt_revreason);

    return 1;

 oom:
    OSSL_CMP_err(ctx, "out of memory");
 err:
    return 0;
}

/*
 * set up the OSSL_CMP_CTX structure based on options from config file/CLI
 * while parsing options and checking their consistency.
 * Prints reason for error to bio_err.
 * Returns 1 on success, 0 on error
 */
static int setup_ctx(OSSL_CMP_CTX *ctx, ENGINE *e)
{
    STACK_OF(X509_CRL) *all_crls = NULL;
    int ret = 0;

    if (opt_server == NULL) {
        OSSL_CMP_err(ctx, "missing server address[:port]");
        goto err;
    } else if ((server_port =
                parse_addr(ctx, &opt_server, server_port, "server")) == 0) {
        goto err;
    }
    if (!OSSL_CMP_CTX_set1_serverName(ctx, opt_server) ||
        !OSSL_CMP_CTX_set_serverPort(ctx, server_port) ||
        !OSSL_CMP_CTX_set1_serverPath(ctx, opt_path))
        goto oom;

    if (opt_proxy != NULL) {
        const char *no_proxy = getenv("no_proxy");
        if (no_proxy == NULL)
            no_proxy =  getenv("NO_PROXY");
        if ((proxy_port =
             parse_addr(ctx, &opt_proxy, proxy_port, "proxy")) == 0) {
            goto err;
        }
        if ((no_proxy == NULL || strstr(no_proxy, opt_server) == NULL) &&
            !(OSSL_CMP_CTX_set1_proxyName(ctx, opt_proxy) &&
              OSSL_CMP_CTX_set_proxyPort(ctx, proxy_port)))
            goto oom;
    }

    if (!transform_opts(ctx))
        goto err;

    if (opt_cmd == CMP_IR || opt_cmd == CMP_CR || opt_cmd == CMP_KUR) {
        if (opt_newkey == NULL && opt_key == NULL) {
            OSSL_CMP_err(ctx, "missing -key or -newkey to be certified");
            goto err;
        }
        if (opt_certout == NULL) {
            OSSL_CMP_err(ctx,
                         "-certout not given, nowhere to save certificate");
            goto err;
        }
    }
    if (opt_cmd == CMP_KUR) {
        char *ref_cert = opt_oldcert != NULL ? opt_oldcert : opt_cert;
        if (ref_cert == NULL) {
            OSSL_CMP_err(ctx, "missing certificate to be updated");
            goto err;
        }
        if (opt_subject != NULL)
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_WARN,
                            "-subject '%s' given, which overrides the subject of '%s' in KUR",
                            opt_subject, ref_cert);
    }
    if (opt_cmd == CMP_RR && opt_oldcert == NULL) {
        OSSL_CMP_err(ctx, "missing certificate to be revoked");
        goto err;
    }
    if (opt_cmd == CMP_P10CR && opt_csr == NULL) {
        OSSL_CMP_err(ctx, "missing PKCS#10 CSR for p10cr");
        goto err;
    }

    if (opt_recipient == NULL && opt_srvcert == NULL && opt_issuer == NULL &&
        opt_oldcert == NULL && opt_cert == NULL) {
        OSSL_CMP_warn(ctx,
                      "missing -recipient, -srvcert, -issuer, -oldcert or -cert; recipient will be set to \"NULL-DN\"");
    }

    if (opt_infotype_s) {
        char id_buf[87] = "id-it-";
        strncat(id_buf, opt_infotype_s, 80);
        if ((opt_infotype = OBJ_sn2nid(id_buf)) == NID_undef) {
            OSSL_CMP_err(ctx, "unknown OID name in -infotype option");
            goto err;
        }
    }


    if (!setup_verification_ctx(ctx, &all_crls))
        goto err;


    if (opt_tls_trusted != NULL || opt_tls_host != NULL) {
        opt_tls_used = 1;
    }
    if (opt_tls_cert != NULL || opt_tls_key != NULL || opt_tls_keypass != NULL) {
        opt_tls_used = 1;
        if (opt_tls_key == NULL) {
            OSSL_CMP_err(ctx, "missing -tls_key option");
            goto err;
        } else if (opt_tls_cert == NULL) {
            OSSL_CMP_err(ctx, "missing -tls_cert option");
        }
    }

    if (opt_tls_used) {
        SSL_CTX *ssl_ctx;

        if (opt_proxy != NULL) {
            OSSL_CMP_err(ctx, "sorry, TLS not yet supported via proxy");
            goto err;
        }
        ssl_ctx =
            setup_ssl_ctx(e, OSSL_CMP_CTX_get0_untrusted_certs(ctx), all_crls);
        if (ssl_ctx == NULL)
            goto err;

        (void)OSSL_CMP_CTX_set_http_cb(ctx, tls_http_cb);
        (void)OSSL_CMP_CTX_set_http_cb_arg(ctx, ssl_ctx);
    } else {
#ifndef OPENSSL_NO_OCSP
        if (opt_ocsp_status)
            OSSL_CMP_warn(ctx, "-ocsp_status has no effect without TLS");
#endif
    }


    if (!setup_protection_ctx(ctx, e))
        goto err;

    if (!setup_request_ctx(ctx, e))
        goto err;


    if (!set_name(opt_recipient, OSSL_CMP_CTX_set1_recipient, ctx, "recipient") ||
        !set_name(opt_expect_sender, OSSL_CMP_CTX_set1_expected_sender, ctx,
                  "expected sender"))
        goto oom;

    if (opt_geninfo != NULL) {
        long value;
        ASN1_OBJECT *type;
        ASN1_INTEGER *aint;
        ASN1_TYPE *val;
        OSSL_CMP_ITAV *itav;
        char *endstr;
        char *valptr = strchr(opt_geninfo, ':');

        if (valptr == NULL) {
            OSSL_CMP_err(ctx, "missing ':' in -geninfo option");
            goto err;
        }
        valptr[0] = '\0';
        valptr++;

        if (strncmp(valptr, "int:", 4) != 0) {
            OSSL_CMP_err(ctx, "missing 'int:' in -geninfo option");
            goto err;
        }
        valptr += 4;

        value = strtol(valptr, &endstr, 10);
        if (endstr == valptr || *endstr != '\0') {
            OSSL_CMP_err(ctx, "cannot parse int in -geninfo option");
            goto err;
        }

        type = OBJ_txt2obj(opt_geninfo, 1);
        if (type == NULL) {
            OSSL_CMP_err(ctx, "cannot parse OID in -geninfo option");
            goto err;
        }

        aint = ASN1_INTEGER_new();
        if (aint == NULL || !ASN1_INTEGER_set(aint, value)) {
            goto oom;
        }

        val = ASN1_TYPE_new();
        if (val == NULL) {
            ASN1_INTEGER_free(aint);
            goto oom;
        }
        ASN1_TYPE_set(val, V_ASN1_INTEGER, aint);
        itav = OSSL_CMP_ITAV_gen(type, val);
        if (itav == NULL) {
            ASN1_TYPE_free(val);
            goto oom;
        }

        if (!OSSL_CMP_CTX_geninfo_itav_push0(ctx, itav)) {
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }

    if (opt_msgtimeout >= 0)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_MSGTIMEOUT,
                                      opt_msgtimeout);
    if (opt_totaltimeout >= 0)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_TOTALTIMEOUT,
                                      opt_totaltimeout);

    if (opt_reqin != NULL || opt_reqout != NULL ||
        opt_rspin != NULL || opt_rspout != NULL
#ifndef NDEBUG
        || opt_mock_srv
#endif
        )
        (void)OSSL_CMP_CTX_set_transfer_cb(ctx, read_write_req_resp);
#ifndef NDEBUG
    if (opt_mock_srv && !setup_srv_ctx(e))
        goto err;
#endif

    ret = 1;

 err:
    sk_X509_CRL_pop_free(all_crls, X509_CRL_free);
    return ret;
 oom:
    OSSL_CMP_err(ctx, "out of memory");
    goto err;
}

/*
 * write out the given certificate to the output specified by bio.
 * Depending on options use either PEM or DER format.
 * Returns 1 on success, 0 on error
 */
static int write_cert(BIO *bio, X509 *cert)
{
    if ((opt_ownform == FORMAT_PEM && PEM_write_bio_X509(bio, cert))
        || (opt_ownform == FORMAT_ASN1 && i2d_X509_bio(bio, cert)))
        return 1;
    if (opt_ownform != FORMAT_PEM && opt_ownform != FORMAT_ASN1)
        BIO_printf(bio_err,
                   "error: unsupported type '%s' for writing certificates\n",
                   opt_ownform_s);
    return 0;
}

/*
 * writes out a stack of certs to the given file.
 * Depending on options use either PEM or DER format,
 * where DER does not make much sense for writing more than one cert!
 * Returns number of written certificates on success, 0 on error.
 */
static int save_certs(OSSL_CMP_CTX *ctx,
                      STACK_OF(X509) *certs, char *destFile, char *desc)
{
    BIO *bio = NULL;
    int i;
    int n = sk_X509_num(certs);

    OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_INFO,
                    "received %d %s certificate%s, saving to file '%s'",
                    n, desc, n == 1 ? "" : "s", destFile);
    if (n > 1 && opt_ownform != FORMAT_PEM)
        OSSL_CMP_warn(cmp_ctx,
                      "saving more than one certificate in non-PEM format");

    if (destFile == NULL || (bio = BIO_new(BIO_s_file())) == NULL ||
        !BIO_write_filename(bio, (char *)destFile)) {
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                        "could not open file '%s' for writing", destFile);
        n = -1;
        goto err;
    }

    for (i = 0; i < n; i++) {
        if (!write_cert(bio, sk_X509_value(certs, i))) {
            OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
                            "cannot write certificate to file '%s'", destFile);
            n = -1;
            goto err;
        }
    }

 err:
    BIO_free(bio);
    return n;
}

static void print_itavs(STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    OSSL_CMP_ITAV *itav = NULL;
    int i;
    int n = sk_OSSL_CMP_ITAV_num(itavs); /* itavs == NULL leads to 0 */

    if (n == 0) {
        OSSL_CMP_info(cmp_ctx, "genp contains no ITAV");
        return;
    }

    for (i = 0; i < n; i++) {
        char buf[128];
        itav = sk_OSSL_CMP_ITAV_value(itavs, i);
        OBJ_obj2txt(buf, 128, OSSL_CMP_ITAV_get0_type(itav), 0);
        OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_INFO,
                        "genp contains ITAV of type: %s", buf);
    }
}

static char opt_item[SECTION_NAME_MAX+1];
/* get previous name from a comma-separated list of names */
static char *prev_item(const char *opt, const char *end)
{
    const char *beg;
    int len;

    if (end == opt)
        return NULL;
    beg = end;
    while (beg != opt && beg[-1] != ',' && !isspace(beg[-1]))
        beg--;
    len = (int)(end - beg);
    if (len > SECTION_NAME_MAX)
        len = SECTION_NAME_MAX;
    strncpy(opt_item, beg, len);
    opt_item[len] = '\0';
    if (end - beg > SECTION_NAME_MAX) {
        BIO_printf(bio_err,
                   "warning: using only first %d characters of section name starting with \"%s\"\n",
                   SECTION_NAME_MAX, opt_item);
    }
    while (beg != opt && (beg[-1] == ',' || isspace(beg[-1])))
        beg--;
    return (char *)beg;
}

/* get str value for name from a comma-separated hierarchy of config sections */
static char *conf_get_string(const CONF *conf_, const char *groups,
                            const char *name)
{
    char *res = NULL;
    char *end = (char *)groups + strlen(groups);

    while ((end = prev_item(groups, end)) != NULL) {
        if ((res = NCONF_get_string(conf_, opt_item, name)) != NULL)
            return res;
    }
    return res;
}

/* get long val for name from a comma-separated hierarchy of config sections */
static int conf_get_number_e(const CONF *conf_, const char *groups,
                             const char *name, long *result)
{
    char *str = conf_get_string(conf_, groups, name);

    if (str == NULL || result == NULL)
        return 0;

    for (*result = 0; conf_->meth->is_number(conf_, *str);) {
        *result = (*result) * 10 + conf_->meth->to_int(conf_, *str);
        str++;
    }

    return 1;
}

/*
 * use the command line option table to read values from the CMP section
 * of openssl.cnf.  Defaults are taken from the config file, they can be
 * overwritten on the command line.
 */
static int read_config(void)
{
    unsigned int i;
    long num = 0;
    char *txt = NULL;
    const OPTIONS *opt;
    int verification_option;

    /*
     * starting with offset OPT_SECTION because OPT_CONFIG and OPT_SECTION would
     * not make sense within the config file. They have already been handled.
     */
    for (i = OPT_SECTION - OPT_HELP, opt = &cmp_options[OPT_SECTION];
         opt->name; i++, opt++) {
        if (!strcmp(opt->name, OPT_HELP_STR) ||
            !strcmp(opt->name, OPT_MORE_STR)) {
            i--;
            continue;
        }
        /* OPT_CRLALL etc. */
        verification_option = (OPT_V__FIRST <= opt->retval &&
                               opt->retval < OPT_V__LAST);
        if (verification_option)
            i--;
        if (cmp_vars[i].txt == NULL) {
            BIO_printf(bio_err,
                       "internal error: cmp_vars array too short, i=%d\n", i);
            return 0;
        }
        switch (opt->valtype) {
        case '-':
        case 'n':
        case 'l':
            if (!conf_get_number_e(conf, opt_section, opt->name, &num)) {
                ERR_clear_error();
                continue; /* option not provided */
            }
            break;
        /*
         * do not use '<' in cmp_options. Incorrect treatment
         * somewhere in args_verify() can wrongly set badarg = 1
         */
        case '<':
        case 's':
        case 'M':
            txt = conf_get_string(conf, opt_section, opt->name);
            if (txt == NULL) {
                ERR_clear_error();
                continue; /* option not provided */
            }
            break;
        default:
            BIO_printf(bio_err,
                      "internal error: unsupported type '%c' for option '%s'\n",
                       opt->valtype, opt->name);
            return 0;
            break;
        }
        if (verification_option) {
            int conf_argc = 1;
            char *conf_argv[3];
            char arg1[82];

            BIO_snprintf(arg1, 81, "-%s", (char *)opt->name);
            conf_argv[0] = ""; /* dummy prog name */
            conf_argv[1] = arg1;
            if (opt->valtype == '-') {
                if (num != 0)
                    conf_argc = 2;
            } else {
                conf_argc = 3;
                conf_argv[2] = conf_get_string(conf, opt_section, opt->name);
                /* not NULL */
            }
            if (conf_argc > 1) {
                (void)opt_init(conf_argc, conf_argv, cmp_options);
                if (!opt_verify(opt_next(), vpm))
                {
                    BIO_printf(bio_err,
                          "error for option '%s' in config file section '%s'\n",
                               opt->name, opt_section);
                    return 0;
                }
            }
        } else {
            switch (opt->valtype) {
            case '-':
            case 'n':
                if (num < INT_MIN || INT_MAX < num) {
                    BIO_printf(bio_err,
                               "integer value out of range for option '%s'\n",
                               opt->name);
                    return 0;
                }
                *cmp_vars[i].num = (int)num;
                break;
            case 'l':
                *cmp_vars[i].num_long = num;
                break;
            default:
                if (txt != NULL && txt[0] == '\0')
                    txt = NULL; /* reset option on empty string input */
                *cmp_vars[i].txt = txt;
                break;
            }
        }
    }

    return 1;
}

static char *opt_str(char *opt)
{
    char *arg = opt_arg();
    if (arg[0] == '\0') {
        BIO_printf(bio_err,
          "warning: argument of -%s option is empty string, resetting option\n",
                   opt);
        arg = NULL;
    } else if (arg[0] == '-') {
        BIO_printf(bio_err,
                   "warning: argument of -%s option starts with hyphen\n", opt);
    }
    return arg;
}

static int opt_nat(void)
{
    int result = -1;

    if (opt_int(opt_arg(), &result) && result < 0)
        BIO_printf(bio_err, "error: argument '%s' must be positive\n",
                   opt_arg());
    return result;
}

/* returns 0 on success, 1 on error, -1 on -help (i.e., stop with success) */
static int get_opts(int argc, char **argv)
{
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, cmp_options);

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            goto opt_err;
        case OPT_HELP:
            opt_help(cmp_options);
            return -1;
        case OPT_CONFIG: /* has already been handled */
            break;
        case OPT_SECTION: /* has already been handled */
            break;

        case OPT_SERVER:
            opt_server = opt_str("server");
            break;
        case OPT_PROXY:
            opt_proxy = opt_str("proxy");
            break;
        case OPT_PATH:
            opt_path = opt_str("path");
            break;
        case OPT_MSGTIMEOUT:
            if ((opt_msgtimeout = opt_nat()) < 0)
                goto opt_err;
            break;
        case OPT_TOTALTIMEOUT:
            if ((opt_totaltimeout = opt_nat()) < 0)
                goto opt_err;
            break;

        case OPT_TLS_USED:
            opt_tls_used = 1;
            break;
        case OPT_TLS_CERT:
            opt_tls_cert = opt_str("tls_cert");
            break;
        case OPT_TLS_KEY:
            opt_tls_key = opt_str("tls_key");
            break;
        case OPT_TLS_KEYPASS:
            opt_tls_keypass = opt_str("tls_keypass");
            break;
        case OPT_TLS_EXTRA:
            opt_tls_extra = opt_str("tls_extra");
            break;
        case OPT_TLS_TRUSTED:
            opt_tls_trusted = opt_str("tls_trusted");
            break;
        case OPT_TLS_HOST:
            opt_tls_host = opt_str("tls_host");
            break;

        case OPT_REF:
            opt_ref = opt_str("ref");
            break;
        case OPT_SECRET:
            opt_secret = opt_str("secret");
            break;
        case OPT_CERT:
            opt_cert = opt_str("cert");
            break;
        case OPT_KEY:
            opt_key = opt_str("key");
            break;
        case OPT_KEYPASS:
            opt_keypass = opt_str("keypass");
            break;
        case OPT_UNPROTECTEDREQUESTS:
            opt_unprotectedRequests = 1;
            break;
        case OPT_DIGEST:
            opt_digest = opt_str("digest");
            break;
        case OPT_EXTRACERTS:
            opt_extracerts = opt_str("extracerts");
            break;

        case OPT_TRUSTED:
            opt_trusted = opt_str("trusted");
            break;
        case OPT_UNTRUSTED:
            opt_untrusted = opt_str("untrusted");
            break;
        case OPT_SRVCERT:
            opt_srvcert = opt_str("srvcert");
            break;
        case OPT_RECIPIENT:
            opt_recipient = opt_str("recipient");
            break;
        case OPT_EXPECT_SENDER:
            opt_expect_sender = opt_str("expect_sender");
            break;
        case OPT_IGNORE_KEYUSAGE:
            opt_ignore_keyusage = 1;
            break;
        case OPT_UNPROTECTEDERRORS:
            opt_unprotectedErrors = 1;
            break;
        case OPT_EXTRACERTSOUT:
            opt_extracertsout = opt_str("extracertsout");
            break;
        case OPT_CACERTSOUT:
            opt_cacertsout = opt_str("cacertsout");
            break;

        case OPT_CRL_DOWNLOAD:
            opt_crl_download = 1;
            break;
        case OPT_CRLS:
            opt_crls = opt_str("crls");
            break;
        case OPT_CRL_TIMEOUT:
            if ((opt_crl_timeout = opt_nat()) < 0)
                goto opt_err;
            break;
# ifndef OPENSSL_NO_OCSP
        case OPT_OCSP_CHECK_ALL:
            opt_ocsp_check_all = 1;
            break;
        case OPT_OCSP_USE_AIA:
            opt_ocsp_use_aia = 1;
            break;
        case OPT_OCSP_URL:
            opt_ocsp_url = opt_str("ocsp_url");;
            break;
        case OPT_OCSP_TIMEOUT:
            if ((opt_ocsp_timeout = opt_nat()) < 0)
                goto opt_err;
            break;
        case OPT_OCSP_STATUS:
            opt_ocsp_status = 1;
            break;
# endif
        case OPT_V_CASES /* OPT_CRLALL etc. */ :
            if (!opt_verify(o, vpm))
                goto opt_err;
            break;

        case OPT_CMD:
            opt_cmd_s = opt_str("cmd");
            break;
        case OPT_INFOTYPE:
            opt_infotype_s = opt_str("infotype");
            break;
        case OPT_GENINFO:
            opt_geninfo = opt_str("geninfo");
            break;

        case OPT_NEWKEY:
            opt_newkey = opt_str("newkey");
            break;
        case OPT_NEWKEYPASS:
            opt_newkeypass = opt_str("newkeypass");
            break;
        case OPT_SUBJECT:
            opt_subject = opt_str("subject");
            break;
        case OPT_ISSUER:
            opt_issuer = opt_str("issuer");
            break;
        case OPT_DAYS:
            if (!opt_int(opt_arg(), &opt_days) || opt_days < 0) {
                BIO_printf(bio_err,
                           "error: days must be a non-negative integer\n");
                goto opt_err;
            }
            break;
        case OPT_REQEXTS:
            opt_reqexts = opt_str("reqexts");
            break;
        case OPT_SANS:
            opt_sans = opt_str("sans");
            break;
        case OPT_SAN_NODEFAULT:
            opt_san_nodefault = 1;
            break;
        case OPT_POLICIES:
            opt_policies = opt_str("policies");
            break;
        case OPT_POLICIES_CRITICAL:
            opt_policies_critical = 1;
            break;
        case OPT_POPO:
            if (opt_int(opt_arg(), &opt_popo) && opt_popo < OSSL_CRMF_POPO_NONE)
                goto opt_err;
            break;
        case OPT_CSR:
            opt_csr = opt_arg();
            break;
        case OPT_OUT_TRUSTED:
            opt_out_trusted = opt_str("out_trusted");
            break;
        case OPT_IMPLICITCONFIRM:
            opt_implicitConfirm = 1;
            break;
        case OPT_DISABLECONFIRM:
            opt_disableConfirm = 1;
            break;
        case OPT_CERTOUT:
            opt_certout = opt_str("certout");
            break;

        case OPT_OLDCERT:
            opt_oldcert = opt_str("oldcert");
            break;
        case OPT_REVREASON:
            if (!opt_int(opt_arg(), &opt_revreason) ||
                    opt_revreason < CRL_REASON_NONE ||
                    opt_revreason > CRL_REASON_AA_COMPROMISE ||
                    opt_revreason == 7) {
                BIO_printf(bio_err,
                           "error: invalid revreason. Valid values are -1..6, 8..10.");
                goto opt_err;
            }
            break;

        case OPT_OWNFORM:
            opt_ownform_s = opt_str("ownform");
            break;
        case OPT_KEYFORM:
            opt_keyform_s = opt_str("keyform");
            break;
        case OPT_CRLFORM:
            opt_crlform_s = opt_str("crlform");
            break;
        case OPT_OTHERFORM:
            opt_otherform_s = opt_str("otherform");
            break;
        case OPT_OTHERPASS:
            opt_otherpass = opt_str("otherpass");
            break;
# ifndef OPENSSL_NO_ENGINE
        case OPT_ENGINE:
            opt_engine = opt_str("engine");
            break;
# endif

        case OPT_BATCH:
            opt_batch = 1;
            break;
        case OPT_REQIN:
            opt_reqin = opt_str("reqin");
            break;
        case OPT_REQOUT:
            opt_reqout = opt_str("reqout");
            break;
        case OPT_RSPIN:
            opt_rspin = opt_str("rspin");
            break;
        case OPT_RSPOUT:
            opt_rspout = opt_str("rspout");
            break;
# ifndef NDEBUG
        case OPT_MOCK_SRV:
            opt_mock_srv = 1;
            break;
        case OPT_SRV_REF:
            opt_srv_ref = opt_str("srv_ref");
            break;
        case OPT_SRV_SECRET:
            opt_srv_secret = opt_str("srv_secret");
            break;
        case OPT_SRV_CERT:
            opt_srv_cert = opt_str("srv_cert");
            break;
        case OPT_SRV_KEY:
            opt_srv_key = opt_str("srv_key");
            break;
        case OPT_SRV_KEYPASS:
            opt_srv_keypass = opt_str("srv_keypass");
            break;
        case OPT_SRV_TRUSTED:
            opt_srv_trusted = opt_str("srv_trusted");
            break;
        case OPT_SRV_UNTRUSTED:
            opt_srv_untrusted = opt_str("srv_untrusted");
            break;
        case OPT_RSP_CERT:
            opt_rsp_cert = opt_str("rsp_cert");
            break;
        case OPT_RSP_EXTRACERTS:
            opt_rsp_extracerts = opt_str("rsp_extracerts");
            break;
        case OPT_RSP_CAPUBS:
            opt_rsp_capubs = opt_str("rsp_capubs");
            break;
        case OPT_POLL_COUNT:
            opt_poll_count = opt_nat();
            break;
        case OPT_CHECKAFTER:
            opt_checkafter = opt_nat();
            break;
        case OPT_GRANT_IMPLICITCONF:
            opt_grant_implicitconf = 1;
            break;
        case OPT_PKISTATUS:
            opt_pkistatus = opt_nat();
            break;
        case OPT_FAILURE:
            opt_failure = opt_nat();
            break;
        case OPT_FAILUREBITS:
            if (!opt_ulong(opt_arg(), &opt_failurebits)) {
                BIO_printf(bio_err,
                           "invalid unsigned number '%s' representing failure bits\n",
                           opt_arg());
                goto opt_err;
            }
            break;
        case OPT_STATUSSTRING:
            opt_statusstring = opt_str("statusstring");
            break;
        case OPT_SEND_ERROR:
            opt_send_error = 1;
            break;
        case OPT_SEND_UNPROTECTED:
            opt_send_unprotected = 1;
            break;
        case OPT_SEND_UNPROT_ERR:
            opt_send_unprot_err = 1;
            break;
        case OPT_ACCEPT_UNPROTECTED:
            opt_accept_unprotected = 1;
            break;
        case OPT_ACCEPT_UNPROT_ERR:
            opt_accept_unprot_err = 1;
            break;
# endif
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_printf(bio_err, "%s: unknown parameter %s\n", prog, argv[0]);
        goto opt_err;
    }
    return 0;

 opt_err:
    BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
    return 1;
}

/*
 *
 */
int cmp_main(int argc, char **argv)
{
    char *configfile = NULL;
    int i;
    int ret = 1; /* default: failure */
    X509 *newcert = NULL;
    ENGINE *e = NULL;

    if (argc <= 1) {
        opt_help(cmp_options);
        goto err;
    }

    /* handle OPT_CONFIG and OPT_SECTION upfront to take effect for other opts */
    for (i = 1; i < argc - 1; i++)
        if (*argv[i] == '-') {
            if (!strcmp(argv[i] + 1, cmp_options[OPT_CONFIG - OPT_HELP].name))
                opt_config = argv[i + 1];
            else if (!strcmp(argv[i] + 1,
                             cmp_options[OPT_SECTION - OPT_HELP].name))
                opt_section = argv[i + 1];
        }
    if (opt_section[0] == '\0') /* empty string */
        opt_section = DEFAULT_SECTION;

    if (!OSSL_CMP_log_init()) {
        BIO_printf(bio_err, "%s: cannot initialize logging\n", prog);
        goto err;
    }

    cmp_ctx = OSSL_CMP_CTX_create();
    vpm = X509_VERIFY_PARAM_new();
    if (cmp_ctx == NULL || vpm == NULL) {
        BIO_printf(bio_err, "%s: out of memory\n", prog);
        goto err;
    }

    /*
     * read default values for options from config file
     */
    configfile = opt_config != NULL ? opt_config : default_config_file;
    if (configfile && configfile[0] != '\0' /* non-empty string */ &&
        (configfile != default_config_file || access(configfile, F_OK) != -1)) {
        OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_INFO,
                        "using OpenSSL configuration file '%s'", configfile);
        conf = app_load_config(configfile);
        if (conf == NULL) {
            goto err;
        } else {
            if (strcmp(opt_section, CMP_SECTION) == 0) { /* default */
                if (!NCONF_get_section(conf, opt_section)) {
                    OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_INFO,
                                    "no [%s] section found in config file '%s';"
                                    " will thus use just [default] and unnamed section if present",
                                    opt_section, configfile);
                }
            } else {
                char *end = opt_section + strlen(opt_section);
                while ((end = prev_item(opt_section, end)) != NULL) {
                    if (!NCONF_get_section(conf, opt_item)) {
                        OSSL_CMP_printf(cmp_ctx, OSSL_CMP_FL_ERR,
                                        "no [%s] section found in config file '%s'",
                                        opt_item, configfile);
                        goto err;
                    }
                }
            }
            if (!read_config())
                goto err;
        }
    }
    (void)BIO_flush(bio_err); /* prevent interference with opt_help() */

    ret = get_opts(argc, argv);
    if (ret != 0)
        goto err;
    ret = 1;

    if (opt_batch) {
#ifndef OPENSSL_NO_ENGINE
        UI_METHOD *ui_fallback_method;
# ifndef OPENSSL_NO_UI_CONSOLE
        ui_fallback_method = UI_OpenSSL();
# else
        ui_fallback_method = (UI_METHOD *)UI_null();
# endif
        UI_method_set_reader(ui_fallback_method, NULL);
#endif
    }

    if (opt_engine != NULL)
        e = setup_engine_no_default(opt_engine, 0);
    if (!setup_ctx(cmp_ctx, e)) {
        OSSL_CMP_err(cmp_ctx, "cannot set up CMP context");
        goto err;
    }

    /*
     * everything is ready, now connect and perform the command!
     */
    switch (opt_cmd) {
    case CMP_IR:
        newcert = OSSL_CMP_exec_IR_ses(cmp_ctx);
        if (newcert == NULL)
            goto err;
        break;
    case CMP_KUR:
        newcert = OSSL_CMP_exec_KUR_ses(cmp_ctx);
        if (newcert == NULL)
            goto err;
        break;
    case CMP_CR:
        newcert = OSSL_CMP_exec_CR_ses(cmp_ctx);
        if (newcert == NULL)
            goto err;
        break;
    case CMP_P10CR:
        newcert = OSSL_CMP_exec_P10CR_ses(cmp_ctx);
        if (newcert == NULL)
            goto err;
        break;
    case CMP_RR:
        if (!OSSL_CMP_exec_RR_ses(cmp_ctx))
            goto err;
        break;
    case CMP_GENM:
        {
            STACK_OF(OSSL_CMP_ITAV) *itavs;

            if (opt_infotype != NID_undef) {
                OSSL_CMP_ITAV *itav =
                    OSSL_CMP_ITAV_gen(OBJ_nid2obj(opt_infotype), NULL);
                if (itav == NULL)
                    goto err;
                OSSL_CMP_CTX_genm_itav_push0(cmp_ctx, itav);
            }

            if ((itavs = OSSL_CMP_exec_GENM_ses(cmp_ctx)) == NULL)
                goto err;
            print_itavs(itavs);
            sk_OSSL_CMP_ITAV_pop_free(itavs, OSSL_CMP_ITAV_free);
            break;
        }
    default:
        break;
    }

    if (opt_cacertsout != NULL) {
        STACK_OF(X509) *certs = OSSL_CMP_CTX_caPubs_get1(cmp_ctx);
        if (sk_X509_num(certs) > 0 &&
            save_certs(cmp_ctx, certs, opt_cacertsout, "CA") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (opt_extracertsout != NULL) {
        STACK_OF(X509) *certs = OSSL_CMP_CTX_extraCertsIn_get1(cmp_ctx);
        if (sk_X509_num(certs) > 0 &&
            save_certs(cmp_ctx, certs, opt_extracertsout, "extra") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (opt_certout != NULL && newcert != NULL) {
        STACK_OF(X509) *certs = sk_X509_new_null();
        if (certs == NULL || !sk_X509_push(certs, X509_dup(newcert)) ||
            save_certs(cmp_ctx, certs, opt_certout, "enrolled") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    ret = 0;
 err:
    /*  in case we ended up here on error without proper cleaning */
    cleanse(opt_keypass);
    cleanse(opt_newkeypass);
    cleanse(opt_otherpass);
    cleanse(opt_tls_keypass);
    cleanse(opt_secret);
#ifndef NDEBUG
    cleanse(opt_srv_keypass);
    cleanse(opt_srv_secret);
    OSSL_CMP_SRV_CTX_delete(srv_ctx);
#endif
    if (ret > 0)
        ERR_print_errors_fp(stderr);

    SSL_CTX_free(OSSL_CMP_CTX_get_http_cb_arg(cmp_ctx));
    X509_STORE_free(OSSL_CMP_CTX_get_certConf_cb_arg(cmp_ctx));
    OSSL_CMP_CTX_delete(cmp_ctx);
    X509_VERIFY_PARAM_free(vpm);
    release_engine(e);

    NCONF_free(conf); /* must not do as long as opt_... variables are used */
    OSSL_CMP_log_close();

    return ret > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

#endif
