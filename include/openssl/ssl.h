/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_tls_H
# define OPENtls_tls_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_tls_H
# endif

# include <opentls/e_os2.h>
# include <opentls/opentlsconf.h>
# include <opentls/comp.h>
# include <opentls/bio.h>
# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  include <opentls/x509.h>
#  include <opentls/crypto.h>
#  include <opentls/buffer.h>
# endif
# include <opentls/lhash.h>
# include <opentls/pem.h>
# include <opentls/hmac.h>
# include <opentls/async.h>

# include <opentls/safestack.h>
# include <opentls/symhacks.h>
# include <opentls/ct.h>
# include <opentls/tlserr.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Opentls version number for ASN.1 encoding of the session information */
/*-
 * Version 0 - initial version
 * Version 1 - added the optional peer certificate
 */
# define tls_SESSION_ASN1_VERSION 0x0001

# define tls_MAX_tls_SESSION_ID_LENGTH           32
# define tls_MAX_SID_CTX_LENGTH                  32

# define tls_MIN_RSA_MODULUS_LENGTH_IN_BYTES     (512/8)
# define tls_MAX_KEY_ARG_LENGTH                  8
# define tls_MAX_MASTER_KEY_LENGTH               48

/* The maximum number of encrypt/decrypt pipelines we can support */
# define tls_MAX_PIPELINES  32

/* text strings for the ciphers */

/* These are used to specify which ciphers to use and not to use */

# define tls_TXT_LOW             "LOW"
# define tls_TXT_MEDIUM          "MEDIUM"
# define tls_TXT_HIGH            "HIGH"
# define tls_TXT_FIPS            "FIPS"

# define tls_TXT_aNULL           "aNULL"
# define tls_TXT_eNULL           "eNULL"
# define tls_TXT_NULL            "NULL"

# define tls_TXT_kRSA            "kRSA"
# define tls_TXT_kDHr            "kDHr"/* this cipher class has been removed */
# define tls_TXT_kDHd            "kDHd"/* this cipher class has been removed */
# define tls_TXT_kDH             "kDH"/* this cipher class has been removed */
# define tls_TXT_kEDH            "kEDH"/* alias for kDHE */
# define tls_TXT_kDHE            "kDHE"
# define tls_TXT_kECDHr          "kECDHr"/* this cipher class has been removed */
# define tls_TXT_kECDHe          "kECDHe"/* this cipher class has been removed */
# define tls_TXT_kECDH           "kECDH"/* this cipher class has been removed */
# define tls_TXT_kEECDH          "kEECDH"/* alias for kECDHE */
# define tls_TXT_kECDHE          "kECDHE"
# define tls_TXT_kPSK            "kPSK"
# define tls_TXT_kRSAPSK         "kRSAPSK"
# define tls_TXT_kECDHEPSK       "kECDHEPSK"
# define tls_TXT_kDHEPSK         "kDHEPSK"
# define tls_TXT_kGOST           "kGOST"
# define tls_TXT_kSRP            "kSRP"

# define tls_TXT_aRSA            "aRSA"
# define tls_TXT_aDSS            "aDSS"
# define tls_TXT_aDH             "aDH"/* this cipher class has been removed */
# define tls_TXT_aECDH           "aECDH"/* this cipher class has been removed */
# define tls_TXT_aECDSA          "aECDSA"
# define tls_TXT_aPSK            "aPSK"
# define tls_TXT_aGOST94         "aGOST94"
# define tls_TXT_aGOST01         "aGOST01"
# define tls_TXT_aGOST12         "aGOST12"
# define tls_TXT_aGOST           "aGOST"
# define tls_TXT_aSRP            "aSRP"

# define tls_TXT_DSS             "DSS"
# define tls_TXT_DH              "DH"
# define tls_TXT_DHE             "DHE"/* same as "kDHE:-ADH" */
# define tls_TXT_EDH             "EDH"/* alias for DHE */
# define tls_TXT_ADH             "ADH"
# define tls_TXT_RSA             "RSA"
# define tls_TXT_ECDH            "ECDH"
# define tls_TXT_EECDH           "EECDH"/* alias for ECDHE" */
# define tls_TXT_ECDHE           "ECDHE"/* same as "kECDHE:-AECDH" */
# define tls_TXT_AECDH           "AECDH"
# define tls_TXT_ECDSA           "ECDSA"
# define tls_TXT_PSK             "PSK"
# define tls_TXT_SRP             "SRP"

# define tls_TXT_DES             "DES"
# define tls_TXT_3DES            "3DES"
# define tls_TXT_RC4             "RC4"
# define tls_TXT_RC2             "RC2"
# define tls_TXT_IDEA            "IDEA"
# define tls_TXT_SEED            "SEED"
# define tls_TXT_AES128          "AES128"
# define tls_TXT_AES256          "AES256"
# define tls_TXT_AES             "AES"
# define tls_TXT_AES_GCM         "AESGCM"
# define tls_TXT_AES_CCM         "AESCCM"
# define tls_TXT_AES_CCM_8       "AESCCM8"
# define tls_TXT_CAMELLIA128     "CAMELLIA128"
# define tls_TXT_CAMELLIA256     "CAMELLIA256"
# define tls_TXT_CAMELLIA        "CAMELLIA"
# define tls_TXT_CHACHA20        "CHACHA20"
# define tls_TXT_GOST            "GOST89"
# define tls_TXT_ARIA            "ARIA"
# define tls_TXT_ARIA_GCM        "ARIAGCM"
# define tls_TXT_ARIA128         "ARIA128"
# define tls_TXT_ARIA256         "ARIA256"

# define tls_TXT_MD5             "MD5"
# define tls_TXT_SHA1            "SHA1"
# define tls_TXT_SHA             "SHA"/* same as "SHA1" */
# define tls_TXT_GOST94          "GOST94"
# define tls_TXT_GOST89MAC       "GOST89MAC"
# define tls_TXT_GOST12          "GOST12"
# define tls_TXT_GOST89MAC12     "GOST89MAC12"
# define tls_TXT_SHA256          "SHA256"
# define tls_TXT_SHA384          "SHA384"

# define tls_TXT_tlsV3           "tlsv3"
# define tls_TXT_TLSV1           "TLSv1"
# define tls_TXT_TLSV1_1         "TLSv1.1"
# define tls_TXT_TLSV1_2         "TLSv1.2"

# define tls_TXT_ALL             "ALL"

/*-
 * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
 * ciphers normally not being used.
 * Example: "RC4" will activate all ciphers using RC4 including ciphers
 * without authentication, which would normally disabled by DEFAULT (due
 * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
 * will make sure that it is also disabled in the specific selection.
 * COMPLEMENTOF* identifiers are portable between version, as adjustments
 * to the default cipher setup will also be included here.
 *
 * COMPLEMENTOFDEFAULT does not experience the same special treatment that
 * DEFAULT gets, as only selection is being done and no sorting as needed
 * for DEFAULT.
 */
# define tls_TXT_CMPALL          "COMPLEMENTOFALL"
# define tls_TXT_CMPDEF          "COMPLEMENTOFDEFAULT"

/*
 * The following cipher list is used by default. It also is substituted when
 * an application-defined cipher list string starts with 'DEFAULT'.
 * This applies to ciphersuites for TLSv1.2 and below.
 * DEPRECATED IN 3.0.0, in favor of Otls_default_cipher_list()
 * Update both macro and function simultaneously
 */
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define tls_DEFAULT_CIPHER_LIST "ALL:!COMPLEMENTOFDEFAULT:!eNULL"
/*
 * This is the default set of TLSv1.3 ciphersuites
 * DEPRECATED IN 3.0.0, in favor of Otls_default_ciphersuites()
 * Update both macro and function simultaneously
 */
#  if !defined(OPENtls_NO_CHACHA) && !defined(OPENtls_NO_POLY1305)
#   define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                    "TLS_CHACHA20_POLY1305_SHA256:" \
                                    "TLS_AES_128_GCM_SHA256"
#  else
#   define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                   "TLS_AES_128_GCM_SHA256"
#  endif
# endif
/*
 * As of Opentls 1.0.0, tls_create_cipher_list() in tls/tls_ciph.c always
 * starts with a reasonable order, and all we have to do for DEFAULT is
 * throwing out anonymous and unencrypted ciphersuites! (The latter are not
 * actually enabled by ALL, but "ALL:RSA" would enable some of them.)
 */

/* Used in tls_set_shutdown()/tls_get_shutdown(); */
# define tls_SENT_SHUTDOWN       1
# define tls_RECEIVED_SHUTDOWN   2

#ifdef __cplusplus
}
#endif

#ifdef  __cplusplus
extern "C" {
#endif

# define tls_FILETYPE_ASN1       X509_FILETYPE_ASN1
# define tls_FILETYPE_PEM        X509_FILETYPE_PEM

/*
 * This is needed to stop compilers complaining about the 'struct tls_st *'
 * function parameters used to prototype callbacks in tls_CTX.
 */
typedef struct tls_st *tls_crock_st;
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;
typedef struct tls_method_st tls_METHOD;
typedef struct tls_cipher_st tls_CIPHER;
typedef struct tls_session_st tls_SESSION;
typedef struct tls_sigalgs_st TLS_SIGALGS;
typedef struct tls_conf_ctx_st tls_CONF_CTX;
typedef struct tls_comp_st tls_COMP;

STACK_OF(tls_CIPHER);
STACK_OF(tls_COMP);

/* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
typedef struct srtp_protection_profile_st {
    const char *name;
    unsigned long id;
} SRTP_PROTECTION_PROFILE;

DEFINE_STACK_OF(SRTP_PROTECTION_PROFILE)

typedef int (*tls_session_ticket_ext_cb_fn)(tls *s, const unsigned char *data,
                                            int len, void *arg);
typedef int (*tls_session_secret_cb_fn)(tls *s, void *secret, int *secret_len,
                                        STACK_OF(tls_CIPHER) *peer_ciphers,
                                        const tls_CIPHER **cipher, void *arg);

/* Extension context codes */
/* This extension is only allowed in TLS */
#define tls_EXT_TLS_ONLY                        0x0001
/* This extension is only allowed in DTLS */
#define tls_EXT_DTLS_ONLY                       0x0002
/* Some extensions may be allowed in DTLS but we don't implement them for it */
#define tls_EXT_TLS_IMPLEMENTATION_ONLY         0x0004
/* Most extensions are not defined for tlsv3 but EXT_TYPE_renegotiate is */
#define tls_EXT_tls3_ALLOWED                    0x0008
/* Extension is only defined for TLS1.2 and below */
#define tls_EXT_TLS1_2_AND_BELOW_ONLY           0x0010
/* Extension is only defined for TLS1.3 and above */
#define tls_EXT_TLS1_3_ONLY                     0x0020
/* Ignore this extension during parsing if we are resuming */
#define tls_EXT_IGNORE_ON_RESUMPTION            0x0040
#define tls_EXT_CLIENT_HELLO                    0x0080
/* Really means TLS1.2 or below */
#define tls_EXT_TLS1_2_SERVER_HELLO             0x0100
#define tls_EXT_TLS1_3_SERVER_HELLO             0x0200
#define tls_EXT_TLS1_3_ENCRYPTED_EXTENSIONS     0x0400
#define tls_EXT_TLS1_3_HELLO_RETRY_REQUEST      0x0800
#define tls_EXT_TLS1_3_CERTIFICATE              0x1000
#define tls_EXT_TLS1_3_NEW_SESSION_TICKET       0x2000
#define tls_EXT_TLS1_3_CERTIFICATE_REQUEST      0x4000

/* Typedefs for handling custom extensions */

typedef int (*custom_ext_add_cb)(tls *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 int *al, void *add_arg);

typedef void (*custom_ext_free_cb)(tls *s, unsigned int ext_type,
                                   const unsigned char *out, void *add_arg);

typedef int (*custom_ext_parse_cb)(tls *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *parse_arg);


typedef int (*tls_custom_ext_add_cb_ex)(tls *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx,
                                        int *al, void *add_arg);

typedef void (*tls_custom_ext_free_cb_ex)(tls *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);

typedef int (*tls_custom_ext_parse_cb_ex)(tls *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx,
                                          int *al, void *parse_arg);

/* Typedef for verification callback */
typedef int (*tls_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);

/* Typedef for tls async callback */
typedef int (*tls_async_callback_fn)(tls *s, void *arg);

/*
 * Some values are reserved until Opentls 3.0.0 because they were previously
 * included in tls_OP_ALL in a 1.1.x release.
 */

/* Disable Extended master secret */
# define tls_OP_NO_EXTENDED_MASTER_SECRET                0x00000001U

/* Reserved value (until Opentls 3.0.0)                  0x00000002U */

/* Allow initial connection to servers that don't support RI */
# define tls_OP_LEGACY_SERVER_CONNECT                    0x00000004U

/* Reserved value (until Opentls 3.0.0)                  0x00000008U */
# define tls_OP_TLSEXT_PADDING                           0x00000010U
/* Reserved value (until Opentls 3.0.0)                  0x00000020U */
# define tls_OP_SAFARI_ECDHE_ECDSA_BUG                   0x00000040U
/*
 * Reserved value (until Opentls 3.0.0)                  0x00000080U
 * Reserved value (until Opentls 3.0.0)                  0x00000100U
 * Reserved value (until Opentls 3.0.0)                  0x00000200U
 */

/* In TLSv1.3 allow a non-(ec)dhe based kex_mode */
# define tls_OP_ALLOW_NO_DHE_KEX                         0x00000400U

/*
 * Disable tls 3.0/TLS 1.0 CBC vulnerability workaround that was added in
 * Opentls 0.9.6d.  Usually (depending on the application protocol) the
 * workaround is not needed.  Unfortunately some broken tls/TLS
 * implementations cannot handle it at all, which is why we include it in
 * tls_OP_ALL. Added in 0.9.6e
 */
# define tls_OP_DONT_INSERT_EMPTY_FRAGMENTS              0x00000800U

/* DTLS options */
# define tls_OP_NO_QUERY_MTU                             0x00001000U
/* Turn on Cookie Exchange (on relevant for servers) */
# define tls_OP_COOKIE_EXCHANGE                          0x00002000U
/* Don't use RFC4507 ticket extension */
# define tls_OP_NO_TICKET                                0x00004000U
# ifndef OPENtls_NO_DTLS1_METHOD
/* Use Cisco's "speshul" version of DTLS_BAD_VER
 * (only with deprecated DTLSv1_client_method())  */
#  define tls_OP_CISCO_ANYCONNECT                        0x00008000U
# endif

/* As server, disallow session resumption on renegotiation */
# define tls_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   0x00010000U
/* Don't use compression even if supported */
# define tls_OP_NO_COMPRESSION                           0x00020000U
/* Permit unsafe legacy renegotiation */
# define tls_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        0x00040000U
/* Disable encrypt-then-mac */
# define tls_OP_NO_ENCRYPT_THEN_MAC                      0x00080000U

/*
 * Enable TLSv1.3 Compatibility mode. This is on by default. A future version
 * of Opentls may have this disabled by default.
 */
# define tls_OP_ENABLE_MIDDLEBOX_COMPAT                  0x00100000U

/* Prioritize Chacha20Poly1305 when client does.
 * Modifies tls_OP_CIPHER_SERVER_PREFERENCE */
# define tls_OP_PRIORITIZE_CHACHA                        0x00200000U

/*
 * Set on servers to choose the cipher according to the server's preferences
 */
# define tls_OP_CIPHER_SERVER_PREFERENCE                 0x00400000U
/*
 * If set, a server will allow a client to issue a tlsv3.0 version number as
 * latest version supported in the premaster secret, even when TLSv1.0
 * (version 3.1) was announced in the client hello. Normally this is
 * forbidden to prevent version rollback attacks.
 */
# define tls_OP_TLS_ROLLBACK_BUG                         0x00800000U

/*
 * Switches off automatic TLSv1.3 anti-replay protection for early data. This
 * is a server-side option only (no effect on the client).
 */
# define tls_OP_NO_ANTI_REPLAY                           0x01000000U

# define tls_OP_NO_tlsv3                                 0x02000000U
# define tls_OP_NO_TLSv1                                 0x04000000U
# define tls_OP_NO_TLSv1_2                               0x08000000U
# define tls_OP_NO_TLSv1_1                               0x10000000U
# define tls_OP_NO_TLSv1_3                               0x20000000U

# define tls_OP_NO_DTLSv1                                0x04000000U
# define tls_OP_NO_DTLSv1_2                              0x08000000U

# define tls_OP_NO_tls_MASK (tls_OP_NO_tlsv3|\
        tls_OP_NO_TLSv1|tls_OP_NO_TLSv1_1|tls_OP_NO_TLSv1_2|tls_OP_NO_TLSv1_3)
# define tls_OP_NO_DTLS_MASK (tls_OP_NO_DTLSv1|tls_OP_NO_DTLSv1_2)

/* Disallow all renegotiation */
# define tls_OP_NO_RENEGOTIATION                         0x40000000U

/*
 * Make server add server-hello extension from early version of cryptopro
 * draft, when GOST ciphersuite is negotiated. Required for interoperability
 * with CryptoPro CSP 3.x
 */
# define tls_OP_CRYPTOPRO_TLSEXT_BUG                     0x80000000U

/*
 * tls_OP_ALL: various bug workarounds that should be rather harmless.
 * This used to be 0x000FFFFFL before 0.9.7.
 * This used to be 0x80000BFFU before 1.1.1.
 */
# define tls_OP_ALL        (tls_OP_CRYPTOPRO_TLSEXT_BUG|\
                            tls_OP_DONT_INSERT_EMPTY_FRAGMENTS|\
                            tls_OP_LEGACY_SERVER_CONNECT|\
                            tls_OP_TLSEXT_PADDING|\
                            tls_OP_SAFARI_ECDHE_ECDSA_BUG)

/* OBSOLETE OPTIONS: retained for compatibility */

/* Removed from Opentls 1.1.0. Was 0x00000001L */
/* Related to removed tlsv2. */
# define tls_OP_MICROSOFT_SESS_ID_BUG                    0x0
/* Removed from Opentls 1.1.0. Was 0x00000002L */
/* Related to removed tlsv2. */
# define tls_OP_NETSCAPE_CHALLENGE_BUG                   0x0
/* Removed from Opentls 0.9.8q and 1.0.0c. Was 0x00000008L */
/* Dead forever, see CVE-2010-4180 */
# define tls_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         0x0
/* Removed from Opentls 1.0.1h and 1.0.2. Was 0x00000010L */
/* Refers to ancient tlsREF and tlsv2. */
# define tls_OP_tlsREF2_REUSE_CERT_TYPE_BUG              0x0
/* Removed from Opentls 1.1.0. Was 0x00000020 */
# define tls_OP_MICROSOFT_BIG_tlsV3_BUFFER               0x0
/* Removed from Opentls 0.9.7h and 0.9.8b. Was 0x00000040L */
# define tls_OP_MSIE_tlsV2_RSA_PADDING                   0x0
/* Removed from Opentls 1.1.0. Was 0x00000080 */
/* Ancient tlseay version. */
# define tls_OP_tlsEAY_080_CLIENT_DH_BUG                 0x0
/* Removed from Opentls 1.1.0. Was 0x00000100L */
# define tls_OP_TLS_D5_BUG                               0x0
/* Removed from Opentls 1.1.0. Was 0x00000200L */
# define tls_OP_TLS_BLOCK_PADDING_BUG                    0x0
/* Removed from Opentls 1.1.0. Was 0x00080000L */
# define tls_OP_SINGLE_ECDH_USE                          0x0
/* Removed from Opentls 1.1.0. Was 0x00100000L */
# define tls_OP_SINGLE_DH_USE                            0x0
/* Removed from Opentls 1.0.1k and 1.0.2. Was 0x00200000L */
# define tls_OP_EPHEMERAL_RSA                            0x0
/* Removed from Opentls 1.1.0. Was 0x01000000L */
# define tls_OP_NO_tlsv2                                 0x0
/* Removed from Opentls 1.0.1. Was 0x08000000L */
# define tls_OP_PKCS1_CHECK_1                            0x0
/* Removed from Opentls 1.0.1. Was 0x10000000L */
# define tls_OP_PKCS1_CHECK_2                            0x0
/* Removed from Opentls 1.1.0. Was 0x20000000L */
# define tls_OP_NETSCAPE_CA_DN_BUG                       0x0
/* Removed from Opentls 1.1.0. Was 0x40000000L */
# define tls_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          0x0

/*
 * Allow tls_write(..., n) to return r with 0 < r < n (i.e. report success
 * when just a single record has been written):
 */
# define tls_MODE_ENABLE_PARTIAL_WRITE       0x00000001U
/*
 * Make it possible to retry tls_write() with changed buffer location (buffer
 * contents must stay the same!); this is not the default to avoid the
 * misconception that non-blocking tls_write() behaves like non-blocking
 * write():
 */
# define tls_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002U
/*
 * Never bother the application with retries if the transport is blocking:
 */
# define tls_MODE_AUTO_RETRY 0x00000004U
/* Don't attempt to automatically build certificate chain */
# define tls_MODE_NO_AUTO_CHAIN 0x00000008U
/*
 * Save RAM by releasing read and write buffers when they're empty. (tls3 and
 * TLS only.) Released buffers are freed.
 */
# define tls_MODE_RELEASE_BUFFERS 0x00000010U
/*
 * Send the current time in the Random fields of the ClientHello and
 * ServerHello records for compatibility with hypothetical implementations
 * that require it.
 */
# define tls_MODE_SEND_CLIENTHELLO_TIME 0x00000020U
# define tls_MODE_SEND_SERVERHELLO_TIME 0x00000040U
/*
 * Send TLS_FALLBACK_SCSV in the ClientHello. To be set only by applications
 * that reconnect with a downgraded protocol version; see
 * draft-ietf-tls-downgrade-scsv-00 for details. DO NOT ENABLE THIS if your
 * application attempts a normal handshake. Only use this in explicit
 * fallback retries, following the guidance in
 * draft-ietf-tls-downgrade-scsv-00.
 */
# define tls_MODE_SEND_FALLBACK_SCSV 0x00000080U
/*
 * Support Asynchronous operation
 */
# define tls_MODE_ASYNC 0x00000100U
/*
 * Don't use the kernel TLS data-path for sending.
 */
# define tls_MODE_NO_KTLS_TX 0x00000200U
/*
 * When using DTLS/SCTP, include the terminating zero in the label
 * used for computing the endpoint-pair shared secret. Required for
 * interoperability with implementations having this bug like these
 * older version of Opentls:
 * - Opentls 1.0.0 series
 * - Opentls 1.0.1 series
 * - Opentls 1.0.2 series
 * - Opentls 1.1.0 series
 * - Opentls 1.1.1 and 1.1.1a
 */
# define tls_MODE_DTLS_SCTP_LABEL_LENGTH_BUG 0x00000400U
/*
 * Don't use the kernel TLS data-path for receiving.
 */
# define tls_MODE_NO_KTLS_RX 0x00000800U

/* Cert related flags */
/*
 * Many implementations ignore some aspects of the TLS standards such as
 * enforcing certificate chain algorithms. When this is set we enforce them.
 */
# define tls_CERT_FLAG_TLS_STRICT                0x00000001U

/* Suite B modes, takes same values as certificate verify flags */
# define tls_CERT_FLAG_SUITEB_128_LOS_ONLY       0x10000
/* Suite B 192 bit only mode */
# define tls_CERT_FLAG_SUITEB_192_LOS            0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
# define tls_CERT_FLAG_SUITEB_128_LOS            0x30000

/* Perform all sorts of protocol violations for testing purposes */
# define tls_CERT_FLAG_BROKEN_PROTOCOL           0x10000000

/* Flags for building certificate chains */
/* Treat any existing certificates as untrusted CAs */
# define tls_BUILD_CHAIN_FLAG_UNTRUSTED          0x1
/* Don't include root CA in chain */
# define tls_BUILD_CHAIN_FLAG_NO_ROOT            0x2
/* Just check certificates already there */
# define tls_BUILD_CHAIN_FLAG_CHECK              0x4
/* Ignore verification errors */
# define tls_BUILD_CHAIN_FLAG_IGNORE_ERROR       0x8
/* Clear verification errors from queue */
# define tls_BUILD_CHAIN_FLAG_CLEAR_ERROR        0x10

/* Flags returned by tls_check_chain */
/* Certificate can be used with this session */
# define CERT_PKEY_VALID         0x1
/* Certificate can also be used for signing */
# define CERT_PKEY_SIGN          0x2
/* EE certificate signing algorithm OK */
# define CERT_PKEY_EE_SIGNATURE  0x10
/* CA signature algorithms OK */
# define CERT_PKEY_CA_SIGNATURE  0x20
/* EE certificate parameters OK */
# define CERT_PKEY_EE_PARAM      0x40
/* CA certificate parameters OK */
# define CERT_PKEY_CA_PARAM      0x80
/* Signing explicitly allowed as opposed to SHA1 fallback */
# define CERT_PKEY_EXPLICIT_SIGN 0x100
/* Client CA issuer names match (always set for server cert) */
# define CERT_PKEY_ISSUER_NAME   0x200
/* Cert type matches client types (always set for server cert) */
# define CERT_PKEY_CERT_TYPE     0x400
/* Cert chain suitable to Suite B */
# define CERT_PKEY_SUITEB        0x800

# define tls_CONF_FLAG_CMDLINE           0x1
# define tls_CONF_FLAG_FILE              0x2
# define tls_CONF_FLAG_CLIENT            0x4
# define tls_CONF_FLAG_SERVER            0x8
# define tls_CONF_FLAG_SHOW_ERRORS       0x10
# define tls_CONF_FLAG_CERTIFICATE       0x20
# define tls_CONF_FLAG_REQUIRE_PRIVATE   0x40
/* Configuration value types */
# define tls_CONF_TYPE_UNKNOWN           0x0
# define tls_CONF_TYPE_STRING            0x1
# define tls_CONF_TYPE_FILE              0x2
# define tls_CONF_TYPE_DIR               0x3
# define tls_CONF_TYPE_NONE              0x4
# define tls_CONF_TYPE_STORE             0x5

/* Maximum length of the application-controlled segment of a a TLSv1.3 cookie */
# define tls_COOKIE_LENGTH                       4096

/*
 * Note: tls[_CTX]_set_{options,mode} use |= op on the previous value, they
 * cannot be used to clear bits.
 */

unsigned long tls_CTX_get_options(const tls_CTX *ctx);
unsigned long tls_get_options(const tls *s);
unsigned long tls_CTX_clear_options(tls_CTX *ctx, unsigned long op);
unsigned long tls_clear_options(tls *s, unsigned long op);
unsigned long tls_CTX_set_options(tls_CTX *ctx, unsigned long op);
unsigned long tls_set_options(tls *s, unsigned long op);

# define tls_CTX_set_mode(ctx,op) \
        tls_CTX_ctrl((ctx),tls_CTRL_MODE,(op),NULL)
# define tls_CTX_clear_mode(ctx,op) \
        tls_CTX_ctrl((ctx),tls_CTRL_CLEAR_MODE,(op),NULL)
# define tls_CTX_get_mode(ctx) \
        tls_CTX_ctrl((ctx),tls_CTRL_MODE,0,NULL)
# define tls_clear_mode(tls,op) \
        tls_ctrl((tls),tls_CTRL_CLEAR_MODE,(op),NULL)
# define tls_set_mode(tls,op) \
        tls_ctrl((tls),tls_CTRL_MODE,(op),NULL)
# define tls_get_mode(tls) \
        tls_ctrl((tls),tls_CTRL_MODE,0,NULL)
# define tls_set_mtu(tls, mtu) \
        tls_ctrl((tls),tls_CTRL_SET_MTU,(mtu),NULL)
# define DTLS_set_link_mtu(tls, mtu) \
        tls_ctrl((tls),DTLS_CTRL_SET_LINK_MTU,(mtu),NULL)
# define DTLS_get_link_min_mtu(tls) \
        tls_ctrl((tls),DTLS_CTRL_GET_LINK_MIN_MTU,0,NULL)

# define tls_get_secure_renegotiation_support(tls) \
        tls_ctrl((tls), tls_CTRL_GET_RI_SUPPORT, 0, NULL)

# define tls_CTX_set_cert_flags(ctx,op) \
        tls_CTX_ctrl((ctx),tls_CTRL_CERT_FLAGS,(op),NULL)
# define tls_set_cert_flags(s,op) \
        tls_ctrl((s),tls_CTRL_CERT_FLAGS,(op),NULL)
# define tls_CTX_clear_cert_flags(ctx,op) \
        tls_CTX_ctrl((ctx),tls_CTRL_CLEAR_CERT_FLAGS,(op),NULL)
# define tls_clear_cert_flags(s,op) \
        tls_ctrl((s),tls_CTRL_CLEAR_CERT_FLAGS,(op),NULL)

void tls_CTX_set_msg_callback(tls_CTX *ctx,
                              void (*cb) (int write_p, int version,
                                          int content_type, const void *buf,
                                          size_t len, tls *tls, void *arg));
void tls_set_msg_callback(tls *tls,
                          void (*cb) (int write_p, int version,
                                      int content_type, const void *buf,
                                      size_t len, tls *tls, void *arg));
# define tls_CTX_set_msg_callback_arg(ctx, arg) tls_CTX_ctrl((ctx), tls_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
# define tls_set_msg_callback_arg(tls, arg) tls_ctrl((tls), tls_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))

# define tls_get_extms_support(s) \
        tls_ctrl((s),tls_CTRL_GET_EXTMS_SUPPORT,0,NULL)

# ifndef OPENtls_NO_SRP

/* see tls_srp.c */
__owur int tls_SRP_CTX_init(tls *s);
__owur int tls_CTX_SRP_CTX_init(tls_CTX *ctx);
int tls_SRP_CTX_free(tls *ctx);
int tls_CTX_SRP_CTX_free(tls_CTX *ctx);
__owur int tls_srp_server_param_with_username(tls *s, int *ad);
__owur int SRP_Calc_A_param(tls *s);

# endif

/* 100k max cert list */
# define tls_MAX_CERT_LIST_DEFAULT 1024*100

# define tls_SESSION_CACHE_MAX_SIZE_DEFAULT      (1024*20)

/*
 * This callback type is used inside tls_CTX, tls, and in the functions that
 * set them. It is used to override the generation of tls/TLS session IDs in
 * a server. Return value should be zero on an error, non-zero to proceed.
 * Also, callbacks should themselves check if the id they generate is unique
 * otherwise the tls handshake will fail with an error - callbacks can do
 * this using the 'tls' value they're passed by;
 * tls_has_matching_session_id(tls, id, *id_len) The length value passed in
 * is set at the maximum size the session ID can be. In tlsv3/TLSv1 it is 32
 * bytes. The callback can alter this length to be less if desired. It is
 * also an error for the callback to set the size to zero.
 */
typedef int (*GEN_SESSION_CB) (tls *tls, unsigned char *id,
                               unsigned int *id_len);

# define tls_SESS_CACHE_OFF                      0x0000
# define tls_SESS_CACHE_CLIENT                   0x0001
# define tls_SESS_CACHE_SERVER                   0x0002
# define tls_SESS_CACHE_BOTH     (tls_SESS_CACHE_CLIENT|tls_SESS_CACHE_SERVER)
# define tls_SESS_CACHE_NO_AUTO_CLEAR            0x0080
/* enough comments already ... see tls_CTX_set_session_cache_mode(3) */
# define tls_SESS_CACHE_NO_INTERNAL_LOOKUP       0x0100
# define tls_SESS_CACHE_NO_INTERNAL_STORE        0x0200
# define tls_SESS_CACHE_NO_INTERNAL \
        (tls_SESS_CACHE_NO_INTERNAL_LOOKUP|tls_SESS_CACHE_NO_INTERNAL_STORE)

LHASH_OF(tls_SESSION) *tls_CTX_sessions(tls_CTX *ctx);
# define tls_CTX_sess_number(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_NUMBER,0,NULL)
# define tls_CTX_sess_connect(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_CONNECT,0,NULL)
# define tls_CTX_sess_connect_good(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_CONNECT_GOOD,0,NULL)
# define tls_CTX_sess_connect_renegotiate(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_CONNECT_RENEGOTIATE,0,NULL)
# define tls_CTX_sess_accept(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_ACCEPT,0,NULL)
# define tls_CTX_sess_accept_renegotiate(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_ACCEPT_RENEGOTIATE,0,NULL)
# define tls_CTX_sess_accept_good(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_ACCEPT_GOOD,0,NULL)
# define tls_CTX_sess_hits(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_HIT,0,NULL)
# define tls_CTX_sess_cb_hits(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_CB_HIT,0,NULL)
# define tls_CTX_sess_misses(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_MISSES,0,NULL)
# define tls_CTX_sess_timeouts(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_TIMEOUTS,0,NULL)
# define tls_CTX_sess_cache_full(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_SESS_CACHE_FULL,0,NULL)

void tls_CTX_sess_set_new_cb(tls_CTX *ctx,
                             int (*new_session_cb) (struct tls_st *tls,
                                                    tls_SESSION *sess));
int (*tls_CTX_sess_get_new_cb(tls_CTX *ctx)) (struct tls_st *tls,
                                              tls_SESSION *sess);
void tls_CTX_sess_set_remove_cb(tls_CTX *ctx,
                                void (*remove_session_cb) (struct tls_ctx_st
                                                           *ctx,
                                                           tls_SESSION *sess));
void (*tls_CTX_sess_get_remove_cb(tls_CTX *ctx)) (struct tls_ctx_st *ctx,
                                                  tls_SESSION *sess);
void tls_CTX_sess_set_get_cb(tls_CTX *ctx,
                             tls_SESSION *(*get_session_cb) (struct tls_st
                                                             *tls,
                                                             const unsigned char
                                                             *data, int len,
                                                             int *copy));
tls_SESSION *(*tls_CTX_sess_get_get_cb(tls_CTX *ctx)) (struct tls_st *tls,
                                                       const unsigned char *data,
                                                       int len, int *copy);
void tls_CTX_set_info_callback(tls_CTX *ctx,
                               void (*cb) (const tls *tls, int type, int val));
void (*tls_CTX_get_info_callback(tls_CTX *ctx)) (const tls *tls, int type,
                                                 int val);
void tls_CTX_set_client_cert_cb(tls_CTX *ctx,
                                int (*client_cert_cb) (tls *tls, X509 **x509,
                                                       EVP_PKEY **pkey));
int (*tls_CTX_get_client_cert_cb(tls_CTX *ctx)) (tls *tls, X509 **x509,
                                                 EVP_PKEY **pkey);
# ifndef OPENtls_NO_ENGINE
__owur int tls_CTX_set_client_cert_engine(tls_CTX *ctx, ENGINE *e);
# endif
void tls_CTX_set_cookie_generate_cb(tls_CTX *ctx,
                                    int (*app_gen_cookie_cb) (tls *tls,
                                                              unsigned char
                                                              *cookie,
                                                              unsigned int
                                                              *cookie_len));
void tls_CTX_set_cookie_verify_cb(tls_CTX *ctx,
                                  int (*app_verify_cookie_cb) (tls *tls,
                                                               const unsigned
                                                               char *cookie,
                                                               unsigned int
                                                               cookie_len));

void tls_CTX_set_stateless_cookie_generate_cb(
    tls_CTX *ctx,
    int (*gen_stateless_cookie_cb) (tls *tls,
                                    unsigned char *cookie,
                                    size_t *cookie_len));
void tls_CTX_set_stateless_cookie_verify_cb(
    tls_CTX *ctx,
    int (*verify_stateless_cookie_cb) (tls *tls,
                                       const unsigned char *cookie,
                                       size_t cookie_len));
# ifndef OPENtls_NO_NEXTPROTONEG

typedef int (*tls_CTX_npn_advertised_cb_func)(tls *tls,
                                              const unsigned char **out,
                                              unsigned int *outlen,
                                              void *arg);
void tls_CTX_set_next_protos_advertised_cb(tls_CTX *s,
                                           tls_CTX_npn_advertised_cb_func cb,
                                           void *arg);
#  define tls_CTX_set_npn_advertised_cb tls_CTX_set_next_protos_advertised_cb

typedef int (*tls_CTX_npn_select_cb_func)(tls *s,
                                          unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *in,
                                          unsigned int inlen,
                                          void *arg);
void tls_CTX_set_next_proto_select_cb(tls_CTX *s,
                                      tls_CTX_npn_select_cb_func cb,
                                      void *arg);
#  define tls_CTX_set_npn_select_cb tls_CTX_set_next_proto_select_cb

void tls_get0_next_proto_negotiated(const tls *s, const unsigned char **data,
                                    unsigned *len);
#  define tls_get0_npn_negotiated tls_get0_next_proto_negotiated
# endif

__owur int tls_select_next_proto(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen,
                                 const unsigned char *client,
                                 unsigned int client_len);

# define OPENtls_NPN_UNSUPPORTED 0
# define OPENtls_NPN_NEGOTIATED  1
# define OPENtls_NPN_NO_OVERLAP  2

__owur int tls_CTX_set_alpn_protos(tls_CTX *ctx, const unsigned char *protos,
                                   unsigned int protos_len);
__owur int tls_set_alpn_protos(tls *tls, const unsigned char *protos,
                               unsigned int protos_len);
typedef int (*tls_CTX_alpn_select_cb_func)(tls *tls,
                                           const unsigned char **out,
                                           unsigned char *outlen,
                                           const unsigned char *in,
                                           unsigned int inlen,
                                           void *arg);
void tls_CTX_set_alpn_select_cb(tls_CTX *ctx,
                                tls_CTX_alpn_select_cb_func cb,
                                void *arg);
void tls_get0_alpn_selected(const tls *tls, const unsigned char **data,
                            unsigned int *len);

# ifndef OPENtls_NO_PSK
/*
 * the maximum length of the buffer given to callbacks containing the
 * resulting identity/psk
 */
#  define PSK_MAX_IDENTITY_LEN 128
#  define PSK_MAX_PSK_LEN 256
typedef unsigned int (*tls_psk_client_cb_func)(tls *tls,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);
void tls_CTX_set_psk_client_callback(tls_CTX *ctx, tls_psk_client_cb_func cb);
void tls_set_psk_client_callback(tls *tls, tls_psk_client_cb_func cb);

typedef unsigned int (*tls_psk_server_cb_func)(tls *tls,
                                               const char *identity,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);
void tls_CTX_set_psk_server_callback(tls_CTX *ctx, tls_psk_server_cb_func cb);
void tls_set_psk_server_callback(tls *tls, tls_psk_server_cb_func cb);

__owur int tls_CTX_use_psk_identity_hint(tls_CTX *ctx, const char *identity_hint);
__owur int tls_use_psk_identity_hint(tls *s, const char *identity_hint);
const char *tls_get_psk_identity_hint(const tls *s);
const char *tls_get_psk_identity(const tls *s);
# endif

typedef int (*tls_psk_find_session_cb_func)(tls *tls,
                                            const unsigned char *identity,
                                            size_t identity_len,
                                            tls_SESSION **sess);
typedef int (*tls_psk_use_session_cb_func)(tls *tls, const EVP_MD *md,
                                           const unsigned char **id,
                                           size_t *idlen,
                                           tls_SESSION **sess);

void tls_set_psk_find_session_callback(tls *s, tls_psk_find_session_cb_func cb);
void tls_CTX_set_psk_find_session_callback(tls_CTX *ctx,
                                           tls_psk_find_session_cb_func cb);
void tls_set_psk_use_session_callback(tls *s, tls_psk_use_session_cb_func cb);
void tls_CTX_set_psk_use_session_callback(tls_CTX *ctx,
                                          tls_psk_use_session_cb_func cb);

/* Register callbacks to handle custom TLS Extensions for client or server. */

__owur int tls_CTX_has_client_custom_ext(const tls_CTX *ctx,
                                         unsigned int ext_type);

__owur int tls_CTX_add_client_custom_ext(tls_CTX *ctx,
                                         unsigned int ext_type,
                                         custom_ext_add_cb add_cb,
                                         custom_ext_free_cb free_cb,
                                         void *add_arg,
                                         custom_ext_parse_cb parse_cb,
                                         void *parse_arg);

__owur int tls_CTX_add_server_custom_ext(tls_CTX *ctx,
                                         unsigned int ext_type,
                                         custom_ext_add_cb add_cb,
                                         custom_ext_free_cb free_cb,
                                         void *add_arg,
                                         custom_ext_parse_cb parse_cb,
                                         void *parse_arg);

__owur int tls_CTX_add_custom_ext(tls_CTX *ctx, unsigned int ext_type,
                                  unsigned int context,
                                  tls_custom_ext_add_cb_ex add_cb,
                                  tls_custom_ext_free_cb_ex free_cb,
                                  void *add_arg,
                                  tls_custom_ext_parse_cb_ex parse_cb,
                                  void *parse_arg);

__owur int tls_extension_supported(unsigned int ext_type);

# define tls_NOTHING            1
# define tls_WRITING            2
# define tls_READING            3
# define tls_X509_LOOKUP        4
# define tls_ASYNC_PAUSED       5
# define tls_ASYNC_NO_JOBS      6
# define tls_CLIENT_HELLO_CB    7

/* These will only be used when doing non-blocking IO */
# define tls_want_nothing(s)         (tls_want(s) == tls_NOTHING)
# define tls_want_read(s)            (tls_want(s) == tls_READING)
# define tls_want_write(s)           (tls_want(s) == tls_WRITING)
# define tls_want_x509_lookup(s)     (tls_want(s) == tls_X509_LOOKUP)
# define tls_want_async(s)           (tls_want(s) == tls_ASYNC_PAUSED)
# define tls_want_async_job(s)       (tls_want(s) == tls_ASYNC_NO_JOBS)
# define tls_want_client_hello_cb(s) (tls_want(s) == tls_CLIENT_HELLO_CB)

# define tls_MAC_FLAG_READ_MAC_STREAM 1
# define tls_MAC_FLAG_WRITE_MAC_STREAM 2

/*
 * A callback for logging out TLS key material. This callback should log out
 * |line| followed by a newline.
 */
typedef void (*tls_CTX_keylog_cb_func)(const tls *tls, const char *line);

/*
 * tls_CTX_set_keylog_callback configures a callback to log key material. This
 * is intended for debugging use with tools like Wireshark. The cb function
 * should log line followed by a newline.
 */
void tls_CTX_set_keylog_callback(tls_CTX *ctx, tls_CTX_keylog_cb_func cb);

/*
 * tls_CTX_get_keylog_callback returns the callback configured by
 * tls_CTX_set_keylog_callback.
 */
tls_CTX_keylog_cb_func tls_CTX_get_keylog_callback(const tls_CTX *ctx);

int tls_CTX_set_max_early_data(tls_CTX *ctx, uint32_t max_early_data);
uint32_t tls_CTX_get_max_early_data(const tls_CTX *ctx);
int tls_set_max_early_data(tls *s, uint32_t max_early_data);
uint32_t tls_get_max_early_data(const tls *s);
int tls_CTX_set_recv_max_early_data(tls_CTX *ctx, uint32_t recv_max_early_data);
uint32_t tls_CTX_get_recv_max_early_data(const tls_CTX *ctx);
int tls_set_recv_max_early_data(tls *s, uint32_t recv_max_early_data);
uint32_t tls_get_recv_max_early_data(const tls *s);

#ifdef __cplusplus
}
#endif

# include <opentls/tls2.h>
# include <opentls/tls3.h>
# include <opentls/tls1.h>      /* This is mostly tlsv3 with a few tweaks */
# include <opentls/dtls1.h>     /* Datagram TLS */
# include <opentls/srtp.h>      /* Support for the use_srtp extension */

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * These need to be after the above set of includes due to a compiler bug
 * in VisualStudio 2015
 */
DEFINE_STACK_OF_CONST(tls_CIPHER)
DEFINE_STACK_OF(tls_COMP)

/* compatibility */
# define tls_set_app_data(s,arg)         (tls_set_ex_data(s,0,(char *)(arg)))
# define tls_get_app_data(s)             (tls_get_ex_data(s,0))
# define tls_SESSION_set_app_data(s,a)   (tls_SESSION_set_ex_data(s,0, \
                                                                  (char *)(a)))
# define tls_SESSION_get_app_data(s)     (tls_SESSION_get_ex_data(s,0))
# define tls_CTX_get_app_data(ctx)       (tls_CTX_get_ex_data(ctx,0))
# define tls_CTX_set_app_data(ctx,arg)   (tls_CTX_set_ex_data(ctx,0, \
                                                              (char *)(arg)))
DEPRECATEDIN_1_1_0(void tls_set_debug(tls *s, int debug))

/* TLSv1.3 KeyUpdate message types */
/* -1 used so that this is an invalid value for the on-the-wire protocol */
#define tls_KEY_UPDATE_NONE             -1
/* Values as defined for the on-the-wire protocol */
#define tls_KEY_UPDATE_NOT_REQUESTED     0
#define tls_KEY_UPDATE_REQUESTED         1

/*
 * The valid handshake states (one for each type message sent and one for each
 * type of message received). There are also two "special" states:
 * TLS = TLS or DTLS state
 * DTLS = DTLS specific state
 * CR/SR = Client Read/Server Read
 * CW/SW = Client Write/Server Write
 *
 * The "special" states are:
 * TLS_ST_BEFORE = No handshake has been initiated yet
 * TLS_ST_OK = A handshake has been successfully completed
 */
typedef enum {
    TLS_ST_BEFORE,
    TLS_ST_OK,
    DTLS_ST_CR_HELLO_VERIFY_REQUEST,
    TLS_ST_CR_SRVR_HELLO,
    TLS_ST_CR_CERT,
    TLS_ST_CR_CERT_STATUS,
    TLS_ST_CR_KEY_EXCH,
    TLS_ST_CR_CERT_REQ,
    TLS_ST_CR_SRVR_DONE,
    TLS_ST_CR_SESSION_TICKET,
    TLS_ST_CR_CHANGE,
    TLS_ST_CR_FINISHED,
    TLS_ST_CW_CLNT_HELLO,
    TLS_ST_CW_CERT,
    TLS_ST_CW_KEY_EXCH,
    TLS_ST_CW_CERT_VRFY,
    TLS_ST_CW_CHANGE,
    TLS_ST_CW_NEXT_PROTO,
    TLS_ST_CW_FINISHED,
    TLS_ST_SW_HELLO_REQ,
    TLS_ST_SR_CLNT_HELLO,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST,
    TLS_ST_SW_SRVR_HELLO,
    TLS_ST_SW_CERT,
    TLS_ST_SW_KEY_EXCH,
    TLS_ST_SW_CERT_REQ,
    TLS_ST_SW_SRVR_DONE,
    TLS_ST_SR_CERT,
    TLS_ST_SR_KEY_EXCH,
    TLS_ST_SR_CERT_VRFY,
    TLS_ST_SR_NEXT_PROTO,
    TLS_ST_SR_CHANGE,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SESSION_TICKET,
    TLS_ST_SW_CERT_STATUS,
    TLS_ST_SW_CHANGE,
    TLS_ST_SW_FINISHED,
    TLS_ST_SW_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_CERT_VRFY,
    TLS_ST_SW_CERT_VRFY,
    TLS_ST_CR_HELLO_REQ,
    TLS_ST_SW_KEY_UPDATE,
    TLS_ST_CW_KEY_UPDATE,
    TLS_ST_SR_KEY_UPDATE,
    TLS_ST_CR_KEY_UPDATE,
    TLS_ST_EARLY_DATA,
    TLS_ST_PENDING_EARLY_DATA_END,
    TLS_ST_CW_END_OF_EARLY_DATA,
    TLS_ST_SR_END_OF_EARLY_DATA
} Otls_HANDSHAKE_STATE;

/*
 * Most of the following state values are no longer used and are defined to be
 * the closest equivalent value in the current state machine code. Not all
 * defines have an equivalent and are set to a dummy value (-1). tls_ST_CONNECT
 * and tls_ST_ACCEPT are still in use in the definition of tls_CB_ACCEPT_LOOP,
 * tls_CB_ACCEPT_EXIT, tls_CB_CONNECT_LOOP and tls_CB_CONNECT_EXIT.
 */

# define tls_ST_CONNECT                  0x1000
# define tls_ST_ACCEPT                   0x2000

# define tls_ST_MASK                     0x0FFF

# define tls_CB_LOOP                     0x01
# define tls_CB_EXIT                     0x02
# define tls_CB_READ                     0x04
# define tls_CB_WRITE                    0x08
# define tls_CB_ALERT                    0x4000/* used in callback */
# define tls_CB_READ_ALERT               (tls_CB_ALERT|tls_CB_READ)
# define tls_CB_WRITE_ALERT              (tls_CB_ALERT|tls_CB_WRITE)
# define tls_CB_ACCEPT_LOOP              (tls_ST_ACCEPT|tls_CB_LOOP)
# define tls_CB_ACCEPT_EXIT              (tls_ST_ACCEPT|tls_CB_EXIT)
# define tls_CB_CONNECT_LOOP             (tls_ST_CONNECT|tls_CB_LOOP)
# define tls_CB_CONNECT_EXIT             (tls_ST_CONNECT|tls_CB_EXIT)
# define tls_CB_HANDSHAKE_START          0x10
# define tls_CB_HANDSHAKE_DONE           0x20

/* Is the tls_connection established? */
# define tls_in_connect_init(a)          (tls_in_init(a) && !tls_is_server(a))
# define tls_in_accept_init(a)           (tls_in_init(a) && tls_is_server(a))
int tls_in_init(const tls *s);
int tls_in_before(const tls *s);
int tls_is_init_finished(const tls *s);

/*
 * The following 3 states are kept in tls->rlayer.rstate when reads fail, you
 * should not need these
 */
# define tls_ST_READ_HEADER                      0xF0
# define tls_ST_READ_BODY                        0xF1
# define tls_ST_READ_DONE                        0xF2

/*-
 * Obtain latest Finished message
 *   -- that we sent (tls_get_finished)
 *   -- that we expected from peer (tls_get_peer_finished).
 * Returns length (0 == no Finished so far), copies up to 'count' bytes.
 */
size_t tls_get_finished(const tls *s, void *buf, size_t count);
size_t tls_get_peer_finished(const tls *s, void *buf, size_t count);

/*
 * use either tls_VERIFY_NONE or tls_VERIFY_PEER, the last 3 options are
 * 'ored' with tls_VERIFY_PEER if they are desired
 */
# define tls_VERIFY_NONE                 0x00
# define tls_VERIFY_PEER                 0x01
# define tls_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
# define tls_VERIFY_CLIENT_ONCE          0x04
# define tls_VERIFY_POST_HANDSHAKE       0x08

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define Opentls_add_tls_algorithms()   tls_library_init()
#  define tlseay_add_tls_algorithms()    tls_library_init()
# endif

/* More backward compatibility */
# define tls_get_cipher(s) \
                tls_CIPHER_get_name(tls_get_current_cipher(s))
# define tls_get_cipher_bits(s,np) \
                tls_CIPHER_get_bits(tls_get_current_cipher(s),np)
# define tls_get_cipher_version(s) \
                tls_CIPHER_get_version(tls_get_current_cipher(s))
# define tls_get_cipher_name(s) \
                tls_CIPHER_get_name(tls_get_current_cipher(s))
# define tls_get_time(a)         tls_SESSION_get_time(a)
# define tls_set_time(a,b)       tls_SESSION_set_time((a),(b))
# define tls_get_timeout(a)      tls_SESSION_get_timeout(a)
# define tls_set_timeout(a,b)    tls_SESSION_set_timeout((a),(b))

# define d2i_tls_SESSION_bio(bp,s_id) ASN1_d2i_bio_of(tls_SESSION,tls_SESSION_new,d2i_tls_SESSION,bp,s_id)
# define i2d_tls_SESSION_bio(bp,s_id) ASN1_i2d_bio_of(tls_SESSION,i2d_tls_SESSION,bp,s_id)

DECLARE_PEM_rw(tls_SESSION, tls_SESSION)
# define tls_AD_REASON_OFFSET            1000/* offset to get tls_R_... value
                                              * from tls_AD_... */
/* These alert types are for tlsv3 and TLSv1 */
# define tls_AD_CLOSE_NOTIFY             tls3_AD_CLOSE_NOTIFY
/* fatal */
# define tls_AD_UNEXPECTED_MESSAGE       tls3_AD_UNEXPECTED_MESSAGE
/* fatal */
# define tls_AD_BAD_RECORD_MAC           tls3_AD_BAD_RECORD_MAC
# define tls_AD_DECRYPTION_FAILED        TLS1_AD_DECRYPTION_FAILED
# define tls_AD_RECORD_OVERFLOW          TLS1_AD_RECORD_OVERFLOW
/* fatal */
# define tls_AD_DECOMPRESSION_FAILURE    tls3_AD_DECOMPRESSION_FAILURE
/* fatal */
# define tls_AD_HANDSHAKE_FAILURE        tls3_AD_HANDSHAKE_FAILURE
/* Not for TLS */
# define tls_AD_NO_CERTIFICATE           tls3_AD_NO_CERTIFICATE
# define tls_AD_BAD_CERTIFICATE          tls3_AD_BAD_CERTIFICATE
# define tls_AD_UNSUPPORTED_CERTIFICATE  tls3_AD_UNSUPPORTED_CERTIFICATE
# define tls_AD_CERTIFICATE_REVOKED      tls3_AD_CERTIFICATE_REVOKED
# define tls_AD_CERTIFICATE_EXPIRED      tls3_AD_CERTIFICATE_EXPIRED
# define tls_AD_CERTIFICATE_UNKNOWN      tls3_AD_CERTIFICATE_UNKNOWN
/* fatal */
# define tls_AD_ILLEGAL_PARAMETER        tls3_AD_ILLEGAL_PARAMETER
/* fatal */
# define tls_AD_UNKNOWN_CA               TLS1_AD_UNKNOWN_CA
/* fatal */
# define tls_AD_ACCESS_DENIED            TLS1_AD_ACCESS_DENIED
/* fatal */
# define tls_AD_DECODE_ERROR             TLS1_AD_DECODE_ERROR
# define tls_AD_DECRYPT_ERROR            TLS1_AD_DECRYPT_ERROR
/* fatal */
# define tls_AD_EXPORT_RESTRICTION       TLS1_AD_EXPORT_RESTRICTION
/* fatal */
# define tls_AD_PROTOCOL_VERSION         TLS1_AD_PROTOCOL_VERSION
/* fatal */
# define tls_AD_INSUFFICIENT_SECURITY    TLS1_AD_INSUFFICIENT_SECURITY
/* fatal */
# define tls_AD_INTERNAL_ERROR           TLS1_AD_INTERNAL_ERROR
# define tls_AD_USER_CANCELLED           TLS1_AD_USER_CANCELLED
# define tls_AD_NO_RENEGOTIATION         TLS1_AD_NO_RENEGOTIATION
# define tls_AD_MISSING_EXTENSION        TLS13_AD_MISSING_EXTENSION
# define tls_AD_CERTIFICATE_REQUIRED     TLS13_AD_CERTIFICATE_REQUIRED
# define tls_AD_UNSUPPORTED_EXTENSION    TLS1_AD_UNSUPPORTED_EXTENSION
# define tls_AD_CERTIFICATE_UNOBTAINABLE TLS1_AD_CERTIFICATE_UNOBTAINABLE
# define tls_AD_UNRECOGNIZED_NAME        TLS1_AD_UNRECOGNIZED_NAME
# define tls_AD_BAD_CERTIFICATE_STATUS_RESPONSE TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE
# define tls_AD_BAD_CERTIFICATE_HASH_VALUE TLS1_AD_BAD_CERTIFICATE_HASH_VALUE
/* fatal */
# define tls_AD_UNKNOWN_PSK_IDENTITY     TLS1_AD_UNKNOWN_PSK_IDENTITY
/* fatal */
# define tls_AD_INAPPROPRIATE_FALLBACK   TLS1_AD_INAPPROPRIATE_FALLBACK
# define tls_AD_NO_APPLICATION_PROTOCOL  TLS1_AD_NO_APPLICATION_PROTOCOL
# define tls_ERROR_NONE                  0
# define tls_ERROR_tls                   1
# define tls_ERROR_WANT_READ             2
# define tls_ERROR_WANT_WRITE            3
# define tls_ERROR_WANT_X509_LOOKUP      4
# define tls_ERROR_SYSCALL               5/* look at error stack/return
                                           * value/errno */
# define tls_ERROR_ZERO_RETURN           6
# define tls_ERROR_WANT_CONNECT          7
# define tls_ERROR_WANT_ACCEPT           8
# define tls_ERROR_WANT_ASYNC            9
# define tls_ERROR_WANT_ASYNC_JOB       10
# define tls_ERROR_WANT_CLIENT_HELLO_CB 11
# define tls_CTRL_SET_TMP_DH                     3
# define tls_CTRL_SET_TMP_ECDH                   4
# define tls_CTRL_SET_TMP_DH_CB                  6
# define tls_CTRL_GET_CLIENT_CERT_REQUEST        9
# define tls_CTRL_GET_NUM_RENEGOTIATIONS         10
# define tls_CTRL_CLEAR_NUM_RENEGOTIATIONS       11
# define tls_CTRL_GET_TOTAL_RENEGOTIATIONS       12
# define tls_CTRL_GET_FLAGS                      13
# define tls_CTRL_EXTRA_CHAIN_CERT               14
# define tls_CTRL_SET_MSG_CALLBACK               15
# define tls_CTRL_SET_MSG_CALLBACK_ARG           16
/* only applies to datagram connections */
# define tls_CTRL_SET_MTU                17
/* Stats */
# define tls_CTRL_SESS_NUMBER                    20
# define tls_CTRL_SESS_CONNECT                   21
# define tls_CTRL_SESS_CONNECT_GOOD              22
# define tls_CTRL_SESS_CONNECT_RENEGOTIATE       23
# define tls_CTRL_SESS_ACCEPT                    24
# define tls_CTRL_SESS_ACCEPT_GOOD               25
# define tls_CTRL_SESS_ACCEPT_RENEGOTIATE        26
# define tls_CTRL_SESS_HIT                       27
# define tls_CTRL_SESS_CB_HIT                    28
# define tls_CTRL_SESS_MISSES                    29
# define tls_CTRL_SESS_TIMEOUTS                  30
# define tls_CTRL_SESS_CACHE_FULL                31
# define tls_CTRL_MODE                           33
# define tls_CTRL_GET_READ_AHEAD                 40
# define tls_CTRL_SET_READ_AHEAD                 41
# define tls_CTRL_SET_SESS_CACHE_SIZE            42
# define tls_CTRL_GET_SESS_CACHE_SIZE            43
# define tls_CTRL_SET_SESS_CACHE_MODE            44
# define tls_CTRL_GET_SESS_CACHE_MODE            45
# define tls_CTRL_GET_MAX_CERT_LIST              50
# define tls_CTRL_SET_MAX_CERT_LIST              51
# define tls_CTRL_SET_MAX_SEND_FRAGMENT          52
/* see tls1.h for macros based on these */
# define tls_CTRL_SET_TLSEXT_SERVERNAME_CB       53
# define tls_CTRL_SET_TLSEXT_SERVERNAME_ARG      54
# define tls_CTRL_SET_TLSEXT_HOSTNAME            55
# define tls_CTRL_SET_TLSEXT_DEBUG_CB            56
# define tls_CTRL_SET_TLSEXT_DEBUG_ARG           57
# define tls_CTRL_GET_TLSEXT_TICKET_KEYS         58
# define tls_CTRL_SET_TLSEXT_TICKET_KEYS         59
/*# define tls_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT    60 */
/*# define tls_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB 61 */
/*# define tls_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB_ARG 62 */
# define tls_CTRL_SET_TLSEXT_STATUS_REQ_CB       63
# define tls_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG   64
# define tls_CTRL_SET_TLSEXT_STATUS_REQ_TYPE     65
# define tls_CTRL_GET_TLSEXT_STATUS_REQ_EXTS     66
# define tls_CTRL_SET_TLSEXT_STATUS_REQ_EXTS     67
# define tls_CTRL_GET_TLSEXT_STATUS_REQ_IDS      68
# define tls_CTRL_SET_TLSEXT_STATUS_REQ_IDS      69
# define tls_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP        70
# define tls_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP        71
# define tls_CTRL_SET_TLSEXT_TICKET_KEY_CB       72
# define tls_CTRL_SET_TLS_EXT_SRP_USERNAME_CB    75
# define tls_CTRL_SET_SRP_VERIFY_PARAM_CB                76
# define tls_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB             77
# define tls_CTRL_SET_SRP_ARG            78
# define tls_CTRL_SET_TLS_EXT_SRP_USERNAME               79
# define tls_CTRL_SET_TLS_EXT_SRP_STRENGTH               80
# define tls_CTRL_SET_TLS_EXT_SRP_PASSWORD               81
# define DTLS_CTRL_GET_TIMEOUT           73
# define DTLS_CTRL_HANDLE_TIMEOUT        74
# define tls_CTRL_GET_RI_SUPPORT                 76
# define tls_CTRL_CLEAR_MODE                     78
# define tls_CTRL_SET_NOT_RESUMABLE_SESS_CB      79
# define tls_CTRL_GET_EXTRA_CHAIN_CERTS          82
# define tls_CTRL_CLEAR_EXTRA_CHAIN_CERTS        83
# define tls_CTRL_CHAIN                          88
# define tls_CTRL_CHAIN_CERT                     89
# define tls_CTRL_GET_GROUPS                     90
# define tls_CTRL_SET_GROUPS                     91
# define tls_CTRL_SET_GROUPS_LIST                92
# define tls_CTRL_GET_SHARED_GROUP               93
# define tls_CTRL_SET_SIGALGS                    97
# define tls_CTRL_SET_SIGALGS_LIST               98
# define tls_CTRL_CERT_FLAGS                     99
# define tls_CTRL_CLEAR_CERT_FLAGS               100
# define tls_CTRL_SET_CLIENT_SIGALGS             101
# define tls_CTRL_SET_CLIENT_SIGALGS_LIST        102
# define tls_CTRL_GET_CLIENT_CERT_TYPES          103
# define tls_CTRL_SET_CLIENT_CERT_TYPES          104
# define tls_CTRL_BUILD_CERT_CHAIN               105
# define tls_CTRL_SET_VERIFY_CERT_STORE          106
# define tls_CTRL_SET_CHAIN_CERT_STORE           107
# define tls_CTRL_GET_PEER_SIGNATURE_NID         108
# define tls_CTRL_GET_PEER_TMP_KEY               109
# define tls_CTRL_GET_RAW_CIPHERLIST             110
# define tls_CTRL_GET_EC_POINT_FORMATS           111
# define tls_CTRL_GET_CHAIN_CERTS                115
# define tls_CTRL_SELECT_CURRENT_CERT            116
# define tls_CTRL_SET_CURRENT_CERT               117
# define tls_CTRL_SET_DH_AUTO                    118
# define DTLS_CTRL_SET_LINK_MTU                  120
# define DTLS_CTRL_GET_LINK_MIN_MTU              121
# define tls_CTRL_GET_EXTMS_SUPPORT              122
# define tls_CTRL_SET_MIN_PROTO_VERSION          123
# define tls_CTRL_SET_MAX_PROTO_VERSION          124
# define tls_CTRL_SET_SPLIT_SEND_FRAGMENT        125
# define tls_CTRL_SET_MAX_PIPELINES              126
# define tls_CTRL_GET_TLSEXT_STATUS_REQ_TYPE     127
# define tls_CTRL_GET_TLSEXT_STATUS_REQ_CB       128
# define tls_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG   129
# define tls_CTRL_GET_MIN_PROTO_VERSION          130
# define tls_CTRL_GET_MAX_PROTO_VERSION          131
# define tls_CTRL_GET_SIGNATURE_NID              132
# define tls_CTRL_GET_TMP_KEY                    133
# define tls_CTRL_GET_NEGOTIATED_GROUP           134
# define tls_CERT_SET_FIRST                      1
# define tls_CERT_SET_NEXT                       2
# define tls_CERT_SET_SERVER                     3
# define DTLSv1_get_timeout(tls, arg) \
        tls_ctrl(tls,DTLS_CTRL_GET_TIMEOUT,0, (void *)(arg))
# define DTLSv1_handle_timeout(tls) \
        tls_ctrl(tls,DTLS_CTRL_HANDLE_TIMEOUT,0, NULL)
# define tls_num_renegotiations(tls) \
        tls_ctrl((tls),tls_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)
# define tls_clear_num_renegotiations(tls) \
        tls_ctrl((tls),tls_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)
# define tls_total_renegotiations(tls) \
        tls_ctrl((tls),tls_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)
# define tls_CTX_set_tmp_dh(ctx,dh) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_TMP_DH,0,(char *)(dh))
# define tls_CTX_set_dh_auto(ctx, onoff) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_DH_AUTO,onoff,NULL)
# define tls_set_dh_auto(s, onoff) \
        tls_ctrl(s,tls_CTRL_SET_DH_AUTO,onoff,NULL)
# define tls_set_tmp_dh(tls,dh) \
        tls_ctrl(tls,tls_CTRL_SET_TMP_DH,0,(char *)(dh))
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define tls_CTX_set_tmp_ecdh(ctx,ecdh) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))
#  define tls_set_tmp_ecdh(tls,ecdh) \
        tls_ctrl(tls,tls_CTRL_SET_TMP_ECDH,0,(char *)(ecdh))
# endif
# define tls_CTX_add_extra_chain_cert(ctx,x509) \
        tls_CTX_ctrl(ctx,tls_CTRL_EXTRA_CHAIN_CERT,0,(char *)(x509))
# define tls_CTX_get_extra_chain_certs(ctx,px509) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)
# define tls_CTX_get_extra_chain_certs_only(ctx,px509) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)
# define tls_CTX_clear_extra_chain_certs(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)
# define tls_CTX_set0_chain(ctx,sk) \
        tls_CTX_ctrl(ctx,tls_CTRL_CHAIN,0,(char *)(sk))
# define tls_CTX_set1_chain(ctx,sk) \
        tls_CTX_ctrl(ctx,tls_CTRL_CHAIN,1,(char *)(sk))
# define tls_CTX_add0_chain_cert(ctx,x509) \
        tls_CTX_ctrl(ctx,tls_CTRL_CHAIN_CERT,0,(char *)(x509))
# define tls_CTX_add1_chain_cert(ctx,x509) \
        tls_CTX_ctrl(ctx,tls_CTRL_CHAIN_CERT,1,(char *)(x509))
# define tls_CTX_get0_chain_certs(ctx,px509) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_CHAIN_CERTS,0,px509)
# define tls_CTX_clear_chain_certs(ctx) \
        tls_CTX_set0_chain(ctx,NULL)
# define tls_CTX_build_cert_chain(ctx, flags) \
        tls_CTX_ctrl(ctx,tls_CTRL_BUILD_CERT_CHAIN, flags, NULL)
# define tls_CTX_select_current_cert(ctx,x509) \
        tls_CTX_ctrl(ctx,tls_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))
# define tls_CTX_set_current_cert(ctx, op) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_CURRENT_CERT, op, NULL)
# define tls_CTX_set0_verify_cert_store(ctx,st) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))
# define tls_CTX_set1_verify_cert_store(ctx,st) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))
# define tls_CTX_set0_chain_cert_store(ctx,st) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))
# define tls_CTX_set1_chain_cert_store(ctx,st) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))
# define tls_set0_chain(s,sk) \
        tls_ctrl(s,tls_CTRL_CHAIN,0,(char *)(sk))
# define tls_set1_chain(s,sk) \
        tls_ctrl(s,tls_CTRL_CHAIN,1,(char *)(sk))
# define tls_add0_chain_cert(s,x509) \
        tls_ctrl(s,tls_CTRL_CHAIN_CERT,0,(char *)(x509))
# define tls_add1_chain_cert(s,x509) \
        tls_ctrl(s,tls_CTRL_CHAIN_CERT,1,(char *)(x509))
# define tls_get0_chain_certs(s,px509) \
        tls_ctrl(s,tls_CTRL_GET_CHAIN_CERTS,0,px509)
# define tls_clear_chain_certs(s) \
        tls_set0_chain(s,NULL)
# define tls_build_cert_chain(s, flags) \
        tls_ctrl(s,tls_CTRL_BUILD_CERT_CHAIN, flags, NULL)
# define tls_select_current_cert(s,x509) \
        tls_ctrl(s,tls_CTRL_SELECT_CURRENT_CERT,0,(char *)(x509))
# define tls_set_current_cert(s,op) \
        tls_ctrl(s,tls_CTRL_SET_CURRENT_CERT, op, NULL)
# define tls_set0_verify_cert_store(s,st) \
        tls_ctrl(s,tls_CTRL_SET_VERIFY_CERT_STORE,0,(char *)(st))
# define tls_set1_verify_cert_store(s,st) \
        tls_ctrl(s,tls_CTRL_SET_VERIFY_CERT_STORE,1,(char *)(st))
# define tls_set0_chain_cert_store(s,st) \
        tls_ctrl(s,tls_CTRL_SET_CHAIN_CERT_STORE,0,(char *)(st))
# define tls_set1_chain_cert_store(s,st) \
        tls_ctrl(s,tls_CTRL_SET_CHAIN_CERT_STORE,1,(char *)(st))
# define tls_get1_groups(s, glist) \
        tls_ctrl(s,tls_CTRL_GET_GROUPS,0,(int*)(glist))
# define tls_CTX_set1_groups(ctx, glist, glistlen) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_GROUPS,glistlen,(char *)(glist))
# define tls_CTX_set1_groups_list(ctx, s) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_GROUPS_LIST,0,(char *)(s))
# define tls_set1_groups(s, glist, glistlen) \
        tls_ctrl(s,tls_CTRL_SET_GROUPS,glistlen,(char *)(glist))
# define tls_set1_groups_list(s, str) \
        tls_ctrl(s,tls_CTRL_SET_GROUPS_LIST,0,(char *)(str))
# define tls_get_shared_group(s, n) \
        tls_ctrl(s,tls_CTRL_GET_SHARED_GROUP,n,NULL)
# define tls_get_negotiated_group(s) \
        tls_ctrl(s,tls_CTRL_GET_NEGOTIATED_GROUP,0,NULL)
# define tls_CTX_set1_sigalgs(ctx, slist, slistlen) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_SIGALGS,slistlen,(int *)(slist))
# define tls_CTX_set1_sigalgs_list(ctx, s) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_SIGALGS_LIST,0,(char *)(s))
# define tls_set1_sigalgs(s, slist, slistlen) \
        tls_ctrl(s,tls_CTRL_SET_SIGALGS,slistlen,(int *)(slist))
# define tls_set1_sigalgs_list(s, str) \
        tls_ctrl(s,tls_CTRL_SET_SIGALGS_LIST,0,(char *)(str))
# define tls_CTX_set1_client_sigalgs(ctx, slist, slistlen) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_CLIENT_SIGALGS,slistlen,(int *)(slist))
# define tls_CTX_set1_client_sigalgs_list(ctx, s) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(s))
# define tls_set1_client_sigalgs(s, slist, slistlen) \
        tls_ctrl(s,tls_CTRL_SET_CLIENT_SIGALGS,slistlen,(int *)(slist))
# define tls_set1_client_sigalgs_list(s, str) \
        tls_ctrl(s,tls_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)(str))
# define tls_get0_certificate_types(s, clist) \
        tls_ctrl(s, tls_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)(clist))
# define tls_CTX_set1_client_certificate_types(ctx, clist, clistlen) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_CLIENT_CERT_TYPES,clistlen, \
                     (char *)(clist))
# define tls_set1_client_certificate_types(s, clist, clistlen) \
        tls_ctrl(s,tls_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)(clist))
# define tls_get_signature_nid(s, pn) \
        tls_ctrl(s,tls_CTRL_GET_SIGNATURE_NID,0,pn)
# define tls_get_peer_signature_nid(s, pn) \
        tls_ctrl(s,tls_CTRL_GET_PEER_SIGNATURE_NID,0,pn)
# define tls_get_peer_tmp_key(s, pk) \
        tls_ctrl(s,tls_CTRL_GET_PEER_TMP_KEY,0,pk)
# define tls_get_tmp_key(s, pk) \
        tls_ctrl(s,tls_CTRL_GET_TMP_KEY,0,pk)
# define tls_get0_raw_cipherlist(s, plst) \
        tls_ctrl(s,tls_CTRL_GET_RAW_CIPHERLIST,0,plst)
# define tls_get0_ec_point_formats(s, plst) \
        tls_ctrl(s,tls_CTRL_GET_EC_POINT_FORMATS,0,plst)
# define tls_CTX_set_min_proto_version(ctx, version) \
        tls_CTX_ctrl(ctx, tls_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
# define tls_CTX_set_max_proto_version(ctx, version) \
        tls_CTX_ctrl(ctx, tls_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
# define tls_CTX_get_min_proto_version(ctx) \
        tls_CTX_ctrl(ctx, tls_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)
# define tls_CTX_get_max_proto_version(ctx) \
        tls_CTX_ctrl(ctx, tls_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)
# define tls_set_min_proto_version(s, version) \
        tls_ctrl(s, tls_CTRL_SET_MIN_PROTO_VERSION, version, NULL)
# define tls_set_max_proto_version(s, version) \
        tls_ctrl(s, tls_CTRL_SET_MAX_PROTO_VERSION, version, NULL)
# define tls_get_min_proto_version(s) \
        tls_ctrl(s, tls_CTRL_GET_MIN_PROTO_VERSION, 0, NULL)
# define tls_get_max_proto_version(s) \
        tls_ctrl(s, tls_CTRL_GET_MAX_PROTO_VERSION, 0, NULL)

/* Backwards compatibility, original 1.1.0 names */
# define tls_CTRL_GET_SERVER_TMP_KEY \
         tls_CTRL_GET_PEER_TMP_KEY
# define tls_get_server_tmp_key(s, pk) \
         tls_get_peer_tmp_key(s, pk)

/*
 * The following symbol names are old and obsolete. They are kept
 * for compatibility reasons only and should not be used anymore.
 */
# define tls_CTRL_GET_CURVES           tls_CTRL_GET_GROUPS
# define tls_CTRL_SET_CURVES           tls_CTRL_SET_GROUPS
# define tls_CTRL_SET_CURVES_LIST      tls_CTRL_SET_GROUPS_LIST
# define tls_CTRL_GET_SHARED_CURVE     tls_CTRL_GET_SHARED_GROUP

# define tls_get1_curves               tls_get1_groups
# define tls_CTX_set1_curves           tls_CTX_set1_groups
# define tls_CTX_set1_curves_list      tls_CTX_set1_groups_list
# define tls_set1_curves               tls_set1_groups
# define tls_set1_curves_list          tls_set1_groups_list
# define tls_get_shared_curve          tls_get_shared_group


# ifndef OPENtls_NO_DEPRECATED_1_1_0
/* Provide some compatibility macros for removed functionality. */
#  define tls_CTX_need_tmp_RSA(ctx)                0
#  define tls_CTX_set_tmp_rsa(ctx,rsa)             1
#  define tls_need_tmp_RSA(tls)                    0
#  define tls_set_tmp_rsa(tls,rsa)                 1
#  define tls_CTX_set_ecdh_auto(dummy, onoff)      ((onoff) != 0)
#  define tls_set_ecdh_auto(dummy, onoff)          ((onoff) != 0)
/*
 * We "pretend" to call the callback to avoid warnings about unused static
 * functions.
 */
#  define tls_CTX_set_tmp_rsa_callback(ctx, cb)    while(0) (cb)(NULL, 0, 0)
#  define tls_set_tmp_rsa_callback(tls, cb)        while(0) (cb)(NULL, 0, 0)
# endif
__owur const BIO_METHOD *BIO_f_tls(void);
__owur BIO *BIO_new_tls(tls_CTX *ctx, int client);
__owur BIO *BIO_new_tls_connect(tls_CTX *ctx);
__owur BIO *BIO_new_buffer_tls_connect(tls_CTX *ctx);
__owur int BIO_tls_copy_session_id(BIO *to, BIO *from);
void BIO_tls_shutdown(BIO *tls_bio);

__owur int tls_CTX_set_cipher_list(tls_CTX *, const char *str);
__owur tls_CTX *tls_CTX_new(const tls_METHOD *meth);
int tls_CTX_up_ref(tls_CTX *ctx);
void tls_CTX_free(tls_CTX *);
__owur long tls_CTX_set_timeout(tls_CTX *ctx, long t);
__owur long tls_CTX_get_timeout(const tls_CTX *ctx);
__owur X509_STORE *tls_CTX_get_cert_store(const tls_CTX *);
void tls_CTX_set_cert_store(tls_CTX *, X509_STORE *);
void tls_CTX_set1_cert_store(tls_CTX *, X509_STORE *);
__owur int tls_want(const tls *s);
__owur int tls_clear(tls *s);

void tls_CTX_flush_sessions(tls_CTX *ctx, long tm);

__owur const tls_CIPHER *tls_get_current_cipher(const tls *s);
__owur const tls_CIPHER *tls_get_pending_cipher(const tls *s);
__owur int tls_CIPHER_get_bits(const tls_CIPHER *c, int *alg_bits);
__owur const char *tls_CIPHER_get_version(const tls_CIPHER *c);
__owur const char *tls_CIPHER_get_name(const tls_CIPHER *c);
__owur const char *tls_CIPHER_standard_name(const tls_CIPHER *c);
__owur const char *OPENtls_cipher_name(const char *rfc_name);
__owur uint32_t tls_CIPHER_get_id(const tls_CIPHER *c);
__owur uint16_t tls_CIPHER_get_protocol_id(const tls_CIPHER *c);
__owur int tls_CIPHER_get_kx_nid(const tls_CIPHER *c);
__owur int tls_CIPHER_get_auth_nid(const tls_CIPHER *c);
__owur const EVP_MD *tls_CIPHER_get_handshake_digest(const tls_CIPHER *c);
__owur int tls_CIPHER_is_aead(const tls_CIPHER *c);

__owur int tls_get_fd(const tls *s);
__owur int tls_get_rfd(const tls *s);
__owur int tls_get_wfd(const tls *s);
__owur const char *tls_get_cipher_list(const tls *s, int n);
__owur char *tls_get_shared_ciphers(const tls *s, char *buf, int size);
__owur int tls_get_read_ahead(const tls *s);
__owur int tls_pending(const tls *s);
__owur int tls_has_pending(const tls *s);
# ifndef OPENtls_NO_SOCK
__owur int tls_set_fd(tls *s, int fd);
__owur int tls_set_rfd(tls *s, int fd);
__owur int tls_set_wfd(tls *s, int fd);
# endif
void tls_set0_rbio(tls *s, BIO *rbio);
void tls_set0_wbio(tls *s, BIO *wbio);
void tls_set_bio(tls *s, BIO *rbio, BIO *wbio);
__owur BIO *tls_get_rbio(const tls *s);
__owur BIO *tls_get_wbio(const tls *s);
__owur int tls_set_cipher_list(tls *s, const char *str);
__owur int tls_CTX_set_ciphersuites(tls_CTX *ctx, const char *str);
__owur int tls_set_ciphersuites(tls *s, const char *str);
void tls_set_read_ahead(tls *s, int yes);
__owur int tls_get_verify_mode(const tls *s);
__owur int tls_get_verify_depth(const tls *s);
__owur tls_verify_cb tls_get_verify_callback(const tls *s);
void tls_set_verify(tls *s, int mode, tls_verify_cb callback);
void tls_set_verify_depth(tls *s, int depth);
void tls_set_cert_cb(tls *s, int (*cb) (tls *tls, void *arg), void *arg);
# ifndef OPENtls_NO_RSA
__owur int tls_use_RSAPrivateKey(tls *tls, RSA *rsa);
__owur int tls_use_RSAPrivateKey_ASN1(tls *tls, const unsigned char *d,
                                      long len);
# endif
__owur int tls_use_PrivateKey(tls *tls, EVP_PKEY *pkey);
__owur int tls_use_PrivateKey_ASN1(int pk, tls *tls, const unsigned char *d,
                                   long len);
__owur int tls_use_certificate(tls *tls, X509 *x);
__owur int tls_use_certificate_ASN1(tls *tls, const unsigned char *d, int len);
__owur int tls_use_cert_and_key(tls *tls, X509 *x509, EVP_PKEY *privatekey,
                                STACK_OF(X509) *chain, int override);


/* serverinfo file format versions */
# define tls_SERVERINFOV1   1
# define tls_SERVERINFOV2   2

/* Set serverinfo data for the current active cert. */
__owur int tls_CTX_use_serverinfo(tls_CTX *ctx, const unsigned char *serverinfo,
                                  size_t serverinfo_length);
__owur int tls_CTX_use_serverinfo_ex(tls_CTX *ctx, unsigned int version,
                                     const unsigned char *serverinfo,
                                     size_t serverinfo_length);
__owur int tls_CTX_use_serverinfo_file(tls_CTX *ctx, const char *file);

#ifndef OPENtls_NO_RSA
__owur int tls_use_RSAPrivateKey_file(tls *tls, const char *file, int type);
#endif

__owur int tls_use_PrivateKey_file(tls *tls, const char *file, int type);
__owur int tls_use_certificate_file(tls *tls, const char *file, int type);

#ifndef OPENtls_NO_RSA
__owur int tls_CTX_use_RSAPrivateKey_file(tls_CTX *ctx, const char *file,
                                          int type);
#endif
__owur int tls_CTX_use_PrivateKey_file(tls_CTX *ctx, const char *file,
                                       int type);
__owur int tls_CTX_use_certificate_file(tls_CTX *ctx, const char *file,
                                        int type);
/* PEM type */
__owur int tls_CTX_use_certificate_chain_file(tls_CTX *ctx, const char *file);
__owur int tls_use_certificate_chain_file(tls *tls, const char *file);
__owur STACK_OF(X509_NAME) *tls_load_client_CA_file(const char *file);
__owur int tls_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
                                               const char *file);
int tls_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
                                       const char *dir);
int tls_add_store_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
                                       const char *uri);

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define tls_load_error_strings() \
    OPENtls_init_tls(OPENtls_INIT_LOAD_tls_STRINGS \
                     | OPENtls_INIT_LOAD_CRYPTO_STRINGS, NULL)
# endif

__owur const char *tls_state_string(const tls *s);
__owur const char *tls_rstate_string(const tls *s);
__owur const char *tls_state_string_long(const tls *s);
__owur const char *tls_rstate_string_long(const tls *s);
__owur long tls_SESSION_get_time(const tls_SESSION *s);
__owur long tls_SESSION_set_time(tls_SESSION *s, long t);
__owur long tls_SESSION_get_timeout(const tls_SESSION *s);
__owur long tls_SESSION_set_timeout(tls_SESSION *s, long t);
__owur int tls_SESSION_get_protocol_version(const tls_SESSION *s);
__owur int tls_SESSION_set_protocol_version(tls_SESSION *s, int version);

__owur const char *tls_SESSION_get0_hostname(const tls_SESSION *s);
__owur int tls_SESSION_set1_hostname(tls_SESSION *s, const char *hostname);
void tls_SESSION_get0_alpn_selected(const tls_SESSION *s,
                                    const unsigned char **alpn,
                                    size_t *len);
__owur int tls_SESSION_set1_alpn_selected(tls_SESSION *s,
                                          const unsigned char *alpn,
                                          size_t len);
__owur const tls_CIPHER *tls_SESSION_get0_cipher(const tls_SESSION *s);
__owur int tls_SESSION_set_cipher(tls_SESSION *s, const tls_CIPHER *cipher);
__owur int tls_SESSION_has_ticket(const tls_SESSION *s);
__owur unsigned long tls_SESSION_get_ticket_lifetime_hint(const tls_SESSION *s);
void tls_SESSION_get0_ticket(const tls_SESSION *s, const unsigned char **tick,
                             size_t *len);
__owur uint32_t tls_SESSION_get_max_early_data(const tls_SESSION *s);
__owur int tls_SESSION_set_max_early_data(tls_SESSION *s,
                                          uint32_t max_early_data);
__owur int tls_copy_session_id(tls *to, const tls *from);
__owur X509 *tls_SESSION_get0_peer(tls_SESSION *s);
__owur int tls_SESSION_set1_id_context(tls_SESSION *s,
                                       const unsigned char *sid_ctx,
                                       unsigned int sid_ctx_len);
__owur int tls_SESSION_set1_id(tls_SESSION *s, const unsigned char *sid,
                               unsigned int sid_len);
__owur int tls_SESSION_is_resumable(const tls_SESSION *s);

__owur tls_SESSION *tls_SESSION_new(void);
__owur tls_SESSION *tls_SESSION_dup(const tls_SESSION *src);
const unsigned char *tls_SESSION_get_id(const tls_SESSION *s,
                                        unsigned int *len);
const unsigned char *tls_SESSION_get0_id_context(const tls_SESSION *s,
                                                 unsigned int *len);
__owur unsigned int tls_SESSION_get_compress_id(const tls_SESSION *s);
# ifndef OPENtls_NO_STDIO
int tls_SESSION_print_fp(FILE *fp, const tls_SESSION *ses);
# endif
int tls_SESSION_print(BIO *fp, const tls_SESSION *ses);
int tls_SESSION_print_keylog(BIO *bp, const tls_SESSION *x);
int tls_SESSION_up_ref(tls_SESSION *ses);
void tls_SESSION_free(tls_SESSION *ses);
__owur int i2d_tls_SESSION(const tls_SESSION *in, unsigned char **pp);
__owur int tls_set_session(tls *to, tls_SESSION *session);
int tls_CTX_add_session(tls_CTX *ctx, tls_SESSION *session);
int tls_CTX_remove_session(tls_CTX *ctx, tls_SESSION *session);
__owur int tls_CTX_set_generate_session_id(tls_CTX *ctx, GEN_SESSION_CB cb);
__owur int tls_set_generate_session_id(tls *s, GEN_SESSION_CB cb);
__owur int tls_has_matching_session_id(const tls *s,
                                       const unsigned char *id,
                                       unsigned int id_len);
tls_SESSION *d2i_tls_SESSION(tls_SESSION **a, const unsigned char **pp,
                             long length);

# ifdef OPENtls_X509_H
__owur X509 *tls_get_peer_certificate(const tls *s);
# endif

__owur STACK_OF(X509) *tls_get_peer_cert_chain(const tls *s);

__owur int tls_CTX_get_verify_mode(const tls_CTX *ctx);
__owur int tls_CTX_get_verify_depth(const tls_CTX *ctx);
__owur tls_verify_cb tls_CTX_get_verify_callback(const tls_CTX *ctx);
void tls_CTX_set_verify(tls_CTX *ctx, int mode, tls_verify_cb callback);
void tls_CTX_set_verify_depth(tls_CTX *ctx, int depth);
void tls_CTX_set_cert_verify_callback(tls_CTX *ctx,
                                      int (*cb) (X509_STORE_CTX *, void *),
                                      void *arg);
void tls_CTX_set_cert_cb(tls_CTX *c, int (*cb) (tls *tls, void *arg),
                         void *arg);
# ifndef OPENtls_NO_RSA
__owur int tls_CTX_use_RSAPrivateKey(tls_CTX *ctx, RSA *rsa);
__owur int tls_CTX_use_RSAPrivateKey_ASN1(tls_CTX *ctx, const unsigned char *d,
                                          long len);
# endif
__owur int tls_CTX_use_PrivateKey(tls_CTX *ctx, EVP_PKEY *pkey);
__owur int tls_CTX_use_PrivateKey_ASN1(int pk, tls_CTX *ctx,
                                       const unsigned char *d, long len);
__owur int tls_CTX_use_certificate(tls_CTX *ctx, X509 *x);
__owur int tls_CTX_use_certificate_ASN1(tls_CTX *ctx, int len,
                                        const unsigned char *d);
__owur int tls_CTX_use_cert_and_key(tls_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                                    STACK_OF(X509) *chain, int override);

void tls_CTX_set_default_passwd_cb(tls_CTX *ctx, pem_password_cb *cb);
void tls_CTX_set_default_passwd_cb_userdata(tls_CTX *ctx, void *u);
pem_password_cb *tls_CTX_get_default_passwd_cb(tls_CTX *ctx);
void *tls_CTX_get_default_passwd_cb_userdata(tls_CTX *ctx);
void tls_set_default_passwd_cb(tls *s, pem_password_cb *cb);
void tls_set_default_passwd_cb_userdata(tls *s, void *u);
pem_password_cb *tls_get_default_passwd_cb(tls *s);
void *tls_get_default_passwd_cb_userdata(tls *s);

__owur int tls_CTX_check_private_key(const tls_CTX *ctx);
__owur int tls_check_private_key(const tls *ctx);

__owur int tls_CTX_set_session_id_context(tls_CTX *ctx,
                                          const unsigned char *sid_ctx,
                                          unsigned int sid_ctx_len);

tls *tls_new(tls_CTX *ctx);
int tls_up_ref(tls *s);
int tls_is_dtls(const tls *s);
__owur int tls_set_session_id_context(tls *tls, const unsigned char *sid_ctx,
                                      unsigned int sid_ctx_len);

__owur int tls_CTX_set_purpose(tls_CTX *ctx, int purpose);
__owur int tls_set_purpose(tls *tls, int purpose);
__owur int tls_CTX_set_trust(tls_CTX *ctx, int trust);
__owur int tls_set_trust(tls *tls, int trust);

__owur int tls_set1_host(tls *s, const char *hostname);
__owur int tls_add1_host(tls *s, const char *hostname);
__owur const char *tls_get0_peername(tls *s);
void tls_set_hostflags(tls *s, unsigned int flags);

__owur int tls_CTX_dane_enable(tls_CTX *ctx);
__owur int tls_CTX_dane_mtype_set(tls_CTX *ctx, const EVP_MD *md,
                                  uint8_t mtype, uint8_t ord);
__owur int tls_dane_enable(tls *s, const char *basedomain);
__owur int tls_dane_tlsa_add(tls *s, uint8_t usage, uint8_t selector,
                             uint8_t mtype, unsigned const char *data, size_t dlen);
__owur int tls_get0_dane_authority(tls *s, X509 **mcert, EVP_PKEY **mspki);
__owur int tls_get0_dane_tlsa(tls *s, uint8_t *usage, uint8_t *selector,
                              uint8_t *mtype, unsigned const char **data,
                              size_t *dlen);
/*
 * Bridge opacity barrier between libcrypt and libtls, also needed to support
 * offline testing in test/danetest.c
 */
tls_DANE *tls_get0_dane(tls *tls);
/*
 * DANE flags
 */
unsigned long tls_CTX_dane_set_flags(tls_CTX *ctx, unsigned long flags);
unsigned long tls_CTX_dane_clear_flags(tls_CTX *ctx, unsigned long flags);
unsigned long tls_dane_set_flags(tls *tls, unsigned long flags);
unsigned long tls_dane_clear_flags(tls *tls, unsigned long flags);

__owur int tls_CTX_set1_param(tls_CTX *ctx, X509_VERIFY_PARAM *vpm);
__owur int tls_set1_param(tls *tls, X509_VERIFY_PARAM *vpm);

__owur X509_VERIFY_PARAM *tls_CTX_get0_param(tls_CTX *ctx);
__owur X509_VERIFY_PARAM *tls_get0_param(tls *tls);

# ifndef OPENtls_NO_SRP
int tls_CTX_set_srp_username(tls_CTX *ctx, char *name);
int tls_CTX_set_srp_password(tls_CTX *ctx, char *password);
int tls_CTX_set_srp_strength(tls_CTX *ctx, int strength);
int tls_CTX_set_srp_client_pwd_callback(tls_CTX *ctx,
                                        char *(*cb) (tls *, void *));
int tls_CTX_set_srp_verify_param_callback(tls_CTX *ctx,
                                          int (*cb) (tls *, void *));
int tls_CTX_set_srp_username_callback(tls_CTX *ctx,
                                      int (*cb) (tls *, int *, void *));
int tls_CTX_set_srp_cb_arg(tls_CTX *ctx, void *arg);

int tls_set_srp_server_param(tls *s, const BIGNUM *N, const BIGNUM *g,
                             BIGNUM *sa, BIGNUM *v, char *info);
int tls_set_srp_server_param_pw(tls *s, const char *user, const char *pass,
                                const char *grp);

__owur BIGNUM *tls_get_srp_g(tls *s);
__owur BIGNUM *tls_get_srp_N(tls *s);

__owur char *tls_get_srp_username(tls *s);
__owur char *tls_get_srp_userinfo(tls *s);
# endif

/*
 * ClientHello callback and helpers.
 */

# define tls_CLIENT_HELLO_SUCCESS 1
# define tls_CLIENT_HELLO_ERROR   0
# define tls_CLIENT_HELLO_RETRY   (-1)

typedef int (*tls_client_hello_cb_fn) (tls *s, int *al, void *arg);
void tls_CTX_set_client_hello_cb(tls_CTX *c, tls_client_hello_cb_fn cb,
                                 void *arg);
int tls_client_hello_isv2(tls *s);
unsigned int tls_client_hello_get0_legacy_version(tls *s);
size_t tls_client_hello_get0_random(tls *s, const unsigned char **out);
size_t tls_client_hello_get0_session_id(tls *s, const unsigned char **out);
size_t tls_client_hello_get0_ciphers(tls *s, const unsigned char **out);
size_t tls_client_hello_get0_compression_methods(tls *s,
                                                 const unsigned char **out);
int tls_client_hello_get1_extensions_present(tls *s, int **out, size_t *outlen);
int tls_client_hello_get0_ext(tls *s, unsigned int type,
                              const unsigned char **out, size_t *outlen);

void tls_certs_clear(tls *s);
void tls_free(tls *tls);
# ifdef Otls_ASYNC_FD
/*
 * Windows application developer has to include windows.h to use these.
 */
__owur int tls_waiting_for_async(tls *s);
__owur int tls_get_all_async_fds(tls *s, Otls_ASYNC_FD *fds, size_t *numfds);
__owur int tls_get_changed_async_fds(tls *s, Otls_ASYNC_FD *addfd,
                                     size_t *numaddfds, Otls_ASYNC_FD *delfd,
                                     size_t *numdelfds);
__owur int tls_CTX_set_async_callback(tls_CTX *ctx, tls_async_callback_fn callback);
__owur int tls_CTX_set_async_callback_arg(tls_CTX *ctx, void *arg);
__owur int tls_set_async_callback(tls *s, tls_async_callback_fn callback);
__owur int tls_set_async_callback_arg(tls *s, void *arg);
__owur int tls_get_async_status(tls *s, int *status);

# endif
__owur int tls_accept(tls *tls);
__owur int tls_stateless(tls *s);
__owur int tls_connect(tls *tls);
__owur int tls_read(tls *tls, void *buf, int num);
__owur int tls_read_ex(tls *tls, void *buf, size_t num, size_t *readbytes);

# define tls_READ_EARLY_DATA_ERROR   0
# define tls_READ_EARLY_DATA_SUCCESS 1
# define tls_READ_EARLY_DATA_FINISH  2

__owur int tls_read_early_data(tls *s, void *buf, size_t num,
                               size_t *readbytes);
__owur int tls_peek(tls *tls, void *buf, int num);
__owur int tls_peek_ex(tls *tls, void *buf, size_t num, size_t *readbytes);
__owur otls_ssize_t tls_sendfile(tls *s, int fd, off_t offset, size_t size,
                                 int flags);
__owur int tls_write(tls *tls, const void *buf, int num);
__owur int tls_write_ex(tls *s, const void *buf, size_t num, size_t *written);
__owur int tls_write_early_data(tls *s, const void *buf, size_t num,
                                size_t *written);
long tls_ctrl(tls *tls, int cmd, long larg, void *parg);
long tls_callback_ctrl(tls *, int, void (*)(void));
long tls_CTX_ctrl(tls_CTX *ctx, int cmd, long larg, void *parg);
long tls_CTX_callback_ctrl(tls_CTX *, int, void (*)(void));

# define tls_EARLY_DATA_NOT_SENT    0
# define tls_EARLY_DATA_REJECTED    1
# define tls_EARLY_DATA_ACCEPTED    2

__owur int tls_get_early_data_status(const tls *s);

__owur int tls_get_error(const tls *s, int ret_code);
__owur const char *tls_get_version(const tls *s);

/* This sets the 'default' tls version that tls_new() will create */
__owur int tls_CTX_set_tls_version(tls_CTX *ctx, const tls_METHOD *meth);

# ifndef OPENtls_NO_tls3_METHOD
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *tlsv3_method(void)) /* tlsv3 */
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *tlsv3_server_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *tlsv3_client_method(void))
# endif

#define tlsv23_method           TLS_method
#define tlsv23_server_method    TLS_server_method
#define tlsv23_client_method    TLS_client_method

/* Negotiate highest available tls/TLS version */
__owur const tls_METHOD *TLS_method(void);
__owur const tls_METHOD *TLS_server_method(void);
__owur const tls_METHOD *TLS_client_method(void);

# ifndef OPENtls_NO_TLS1_METHOD
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_method(void)) /* TLSv1.0 */
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_server_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_client_method(void))
# endif

# ifndef OPENtls_NO_TLS1_1_METHOD
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_1_method(void)) /* TLSv1.1 */
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_1_server_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_1_client_method(void))
# endif

# ifndef OPENtls_NO_TLS1_2_METHOD
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_2_method(void)) /* TLSv1.2 */
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_2_server_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *TLSv1_2_client_method(void))
# endif

# ifndef OPENtls_NO_DTLS1_METHOD
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *DTLSv1_method(void)) /* DTLSv1.0 */
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *DTLSv1_server_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *DTLSv1_client_method(void))
# endif

# ifndef OPENtls_NO_DTLS1_2_METHOD
/* DTLSv1.2 */
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *DTLSv1_2_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *DTLSv1_2_server_method(void))
DEPRECATEDIN_1_1_0(__owur const tls_METHOD *DTLSv1_2_client_method(void))
# endif

__owur const tls_METHOD *DTLS_method(void); /* DTLS 1.0 and 1.2 */
__owur const tls_METHOD *DTLS_server_method(void); /* DTLS 1.0 and 1.2 */
__owur const tls_METHOD *DTLS_client_method(void); /* DTLS 1.0 and 1.2 */

__owur size_t DTLS_get_data_mtu(const tls *s);

__owur STACK_OF(tls_CIPHER) *tls_get_ciphers(const tls *s);
__owur STACK_OF(tls_CIPHER) *tls_CTX_get_ciphers(const tls_CTX *ctx);
__owur STACK_OF(tls_CIPHER) *tls_get_client_ciphers(const tls *s);
__owur STACK_OF(tls_CIPHER) *tls_get1_supported_ciphers(tls *s);

__owur int tls_do_handshake(tls *s);
int tls_key_update(tls *s, int updatetype);
int tls_get_key_update_type(const tls *s);
int tls_renegotiate(tls *s);
int tls_renegotiate_abbreviated(tls *s);
__owur int tls_renegotiate_pending(const tls *s);
int tls_shutdown(tls *s);
__owur int tls_verify_client_post_handshake(tls *s);
void tls_CTX_set_post_handshake_auth(tls_CTX *ctx, int val);
void tls_set_post_handshake_auth(tls *s, int val);

__owur const tls_METHOD *tls_CTX_get_tls_method(const tls_CTX *ctx);
__owur const tls_METHOD *tls_get_tls_method(const tls *s);
__owur int tls_set_tls_method(tls *s, const tls_METHOD *method);
__owur const char *tls_alert_type_string_long(int value);
__owur const char *tls_alert_type_string(int value);
__owur const char *tls_alert_desc_string_long(int value);
__owur const char *tls_alert_desc_string(int value);

void tls_set0_CA_list(tls *s, STACK_OF(X509_NAME) *name_list);
void tls_CTX_set0_CA_list(tls_CTX *ctx, STACK_OF(X509_NAME) *name_list);
__owur const STACK_OF(X509_NAME) *tls_get0_CA_list(const tls *s);
__owur const STACK_OF(X509_NAME) *tls_CTX_get0_CA_list(const tls_CTX *ctx);
__owur int tls_add1_to_CA_list(tls *tls, const X509 *x);
__owur int tls_CTX_add1_to_CA_list(tls_CTX *ctx, const X509 *x);
__owur const STACK_OF(X509_NAME) *tls_get0_peer_CA_list(const tls *s);

void tls_set_client_CA_list(tls *s, STACK_OF(X509_NAME) *name_list);
void tls_CTX_set_client_CA_list(tls_CTX *ctx, STACK_OF(X509_NAME) *name_list);
__owur STACK_OF(X509_NAME) *tls_get_client_CA_list(const tls *s);
__owur STACK_OF(X509_NAME) *tls_CTX_get_client_CA_list(const tls_CTX *s);
__owur int tls_add_client_CA(tls *tls, X509 *x);
__owur int tls_CTX_add_client_CA(tls_CTX *ctx, X509 *x);

void tls_set_connect_state(tls *s);
void tls_set_accept_state(tls *s);

__owur long tls_get_default_timeout(const tls *s);

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define tls_library_init() OPENtls_init_tls(0, NULL)
# endif

__owur char *tls_CIPHER_description(const tls_CIPHER *, char *buf, int size);
__owur STACK_OF(X509_NAME) *tls_dup_CA_list(const STACK_OF(X509_NAME) *sk);

__owur tls *tls_dup(tls *tls);

__owur X509 *tls_get_certificate(const tls *tls);
/*
 * EVP_PKEY
 */
struct evp_pkey_st *tls_get_privatekey(const tls *tls);

__owur X509 *tls_CTX_get0_certificate(const tls_CTX *ctx);
__owur EVP_PKEY *tls_CTX_get0_privatekey(const tls_CTX *ctx);

void tls_CTX_set_quiet_shutdown(tls_CTX *ctx, int mode);
__owur int tls_CTX_get_quiet_shutdown(const tls_CTX *ctx);
void tls_set_quiet_shutdown(tls *tls, int mode);
__owur int tls_get_quiet_shutdown(const tls *tls);
void tls_set_shutdown(tls *tls, int mode);
__owur int tls_get_shutdown(const tls *tls);
__owur int tls_version(const tls *tls);
__owur int tls_client_version(const tls *s);
__owur int tls_CTX_set_default_verify_paths(tls_CTX *ctx);
__owur int tls_CTX_set_default_verify_dir(tls_CTX *ctx);
__owur int tls_CTX_set_default_verify_file(tls_CTX *ctx);
__owur int tls_CTX_set_default_verify_store(tls_CTX *ctx);
__owur int tls_CTX_load_verify_file(tls_CTX *ctx, const char *CAfile);
__owur int tls_CTX_load_verify_dir(tls_CTX *ctx, const char *CApath);
__owur int tls_CTX_load_verify_store(tls_CTX *ctx, const char *CAstore);
DEPRECATEDIN_3_0(__owur int tls_CTX_load_verify_locations(tls_CTX *ctx,
                                                        const char *CAfile,
                                                        const char *CApath))
# define tls_get0_session tls_get_session/* just peek at pointer */
__owur tls_SESSION *tls_get_session(const tls *tls);
__owur tls_SESSION *tls_get1_session(tls *tls); /* obtain a reference count */
__owur tls_CTX *tls_get_tls_CTX(const tls *tls);
tls_CTX *tls_set_tls_CTX(tls *tls, tls_CTX *ctx);
void tls_set_info_callback(tls *tls,
                           void (*cb) (const tls *tls, int type, int val));
void (*tls_get_info_callback(const tls *tls)) (const tls *tls, int type,
                                               int val);
__owur Otls_HANDSHAKE_STATE tls_get_state(const tls *tls);

void tls_set_verify_result(tls *tls, long v);
__owur long tls_get_verify_result(const tls *tls);
__owur STACK_OF(X509) *tls_get0_verified_chain(const tls *s);

__owur size_t tls_get_client_random(const tls *tls, unsigned char *out,
                                    size_t outlen);
__owur size_t tls_get_server_random(const tls *tls, unsigned char *out,
                                    size_t outlen);
__owur size_t tls_SESSION_get_master_key(const tls_SESSION *sess,
                                         unsigned char *out, size_t outlen);
__owur int tls_SESSION_set1_master_key(tls_SESSION *sess,
                                       const unsigned char *in, size_t len);
uint8_t tls_SESSION_get_max_fragment_length(const tls_SESSION *sess);

#define tls_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_tls, l, p, newf, dupf, freef)
__owur int tls_set_ex_data(tls *tls, int idx, void *data);
void *tls_get_ex_data(const tls *tls, int idx);
#define tls_SESSION_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_tls_SESSION, l, p, newf, dupf, freef)
__owur int tls_SESSION_set_ex_data(tls_SESSION *ss, int idx, void *data);
void *tls_SESSION_get_ex_data(const tls_SESSION *ss, int idx);
#define tls_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_tls_CTX, l, p, newf, dupf, freef)
__owur int tls_CTX_set_ex_data(tls_CTX *tls, int idx, void *data);
void *tls_CTX_get_ex_data(const tls_CTX *tls, int idx);

__owur int tls_get_ex_data_X509_STORE_CTX_idx(void);

# define tls_CTX_sess_set_cache_size(ctx,t) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_SESS_CACHE_SIZE,t,NULL)
# define tls_CTX_sess_get_cache_size(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_SESS_CACHE_SIZE,0,NULL)
# define tls_CTX_set_session_cache_mode(ctx,m) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_SESS_CACHE_MODE,m,NULL)
# define tls_CTX_get_session_cache_mode(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_SESS_CACHE_MODE,0,NULL)

# define tls_CTX_get_default_read_ahead(ctx) tls_CTX_get_read_ahead(ctx)
# define tls_CTX_set_default_read_ahead(ctx,m) tls_CTX_set_read_ahead(ctx,m)
# define tls_CTX_get_read_ahead(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_READ_AHEAD,0,NULL)
# define tls_CTX_set_read_ahead(ctx,m) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_READ_AHEAD,m,NULL)
# define tls_CTX_get_max_cert_list(ctx) \
        tls_CTX_ctrl(ctx,tls_CTRL_GET_MAX_CERT_LIST,0,NULL)
# define tls_CTX_set_max_cert_list(ctx,m) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_MAX_CERT_LIST,m,NULL)
# define tls_get_max_cert_list(tls) \
        tls_ctrl(tls,tls_CTRL_GET_MAX_CERT_LIST,0,NULL)
# define tls_set_max_cert_list(tls,m) \
        tls_ctrl(tls,tls_CTRL_SET_MAX_CERT_LIST,m,NULL)

# define tls_CTX_set_max_send_fragment(ctx,m) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)
# define tls_set_max_send_fragment(tls,m) \
        tls_ctrl(tls,tls_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)
# define tls_CTX_set_split_send_fragment(ctx,m) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_SPLIT_SEND_FRAGMENT,m,NULL)
# define tls_set_split_send_fragment(tls,m) \
        tls_ctrl(tls,tls_CTRL_SET_SPLIT_SEND_FRAGMENT,m,NULL)
# define tls_CTX_set_max_pipelines(ctx,m) \
        tls_CTX_ctrl(ctx,tls_CTRL_SET_MAX_PIPELINES,m,NULL)
# define tls_set_max_pipelines(tls,m) \
        tls_ctrl(tls,tls_CTRL_SET_MAX_PIPELINES,m,NULL)

void tls_CTX_set_default_read_buffer_len(tls_CTX *ctx, size_t len);
void tls_set_default_read_buffer_len(tls *s, size_t len);

# ifndef OPENtls_NO_DH
/* NB: the |keylength| is only applicable when is_export is true */
void tls_CTX_set_tmp_dh_callback(tls_CTX *ctx,
                                 DH *(*dh) (tls *tls, int is_export,
                                            int keylength));
void tls_set_tmp_dh_callback(tls *tls,
                             DH *(*dh) (tls *tls, int is_export,
                                        int keylength));
# endif

__owur const COMP_METHOD *tls_get_current_compression(const tls *s);
__owur const COMP_METHOD *tls_get_current_expansion(const tls *s);
__owur const char *tls_COMP_get_name(const COMP_METHOD *comp);
__owur const char *tls_COMP_get0_name(const tls_COMP *comp);
__owur int tls_COMP_get_id(const tls_COMP *comp);
STACK_OF(tls_COMP) *tls_COMP_get_compression_methods(void);
__owur STACK_OF(tls_COMP) *tls_COMP_set0_compression_methods(STACK_OF(tls_COMP)
                                                             *meths);
# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define tls_COMP_free_compression_methods() while(0) continue
# endif
__owur int tls_COMP_add_compression_method(int id, COMP_METHOD *cm);

const tls_CIPHER *tls_CIPHER_find(tls *tls, const unsigned char *ptr);
int tls_CIPHER_get_cipher_nid(const tls_CIPHER *c);
int tls_CIPHER_get_digest_nid(const tls_CIPHER *c);
int tls_bytes_to_cipher_list(tls *s, const unsigned char *bytes, size_t len,
                             int isv2format, STACK_OF(tls_CIPHER) **sk,
                             STACK_OF(tls_CIPHER) **scsvs);

/* TLS extensions functions */
__owur int tls_set_session_ticket_ext(tls *s, void *ext_data, int ext_len);

__owur int tls_set_session_ticket_ext_cb(tls *s,
                                         tls_session_ticket_ext_cb_fn cb,
                                         void *arg);

/* Pre-shared secret session resumption functions */
__owur int tls_set_session_secret_cb(tls *s,
                                     tls_session_secret_cb_fn session_secret_cb,
                                     void *arg);

void tls_CTX_set_not_resumable_session_callback(tls_CTX *ctx,
                                                int (*cb) (tls *tls,
                                                           int
                                                           is_forward_secure));

void tls_set_not_resumable_session_callback(tls *tls,
                                            int (*cb) (tls *tls,
                                                       int is_forward_secure));

void tls_CTX_set_record_padding_callback(tls_CTX *ctx,
                                         size_t (*cb) (tls *tls, int type,
                                                       size_t len, void *arg));
void tls_CTX_set_record_padding_callback_arg(tls_CTX *ctx, void *arg);
void *tls_CTX_get_record_padding_callback_arg(const tls_CTX *ctx);
int tls_CTX_set_block_padding(tls_CTX *ctx, size_t block_size);

void tls_set_record_padding_callback(tls *tls,
                                    size_t (*cb) (tls *tls, int type,
                                                  size_t len, void *arg));
void tls_set_record_padding_callback_arg(tls *tls, void *arg);
void *tls_get_record_padding_callback_arg(const tls *tls);
int tls_set_block_padding(tls *tls, size_t block_size);

int tls_set_num_tickets(tls *s, size_t num_tickets);
size_t tls_get_num_tickets(const tls *s);
int tls_CTX_set_num_tickets(tls_CTX *ctx, size_t num_tickets);
size_t tls_CTX_get_num_tickets(const tls_CTX *ctx);

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define tls_cache_hit(s) tls_session_reused(s)
# endif

__owur int tls_session_reused(const tls *s);
__owur int tls_is_server(const tls *s);

__owur __owur tls_CONF_CTX *tls_CONF_CTX_new(void);
int tls_CONF_CTX_finish(tls_CONF_CTX *cctx);
void tls_CONF_CTX_free(tls_CONF_CTX *cctx);
unsigned int tls_CONF_CTX_set_flags(tls_CONF_CTX *cctx, unsigned int flags);
__owur unsigned int tls_CONF_CTX_clear_flags(tls_CONF_CTX *cctx,
                                             unsigned int flags);
__owur int tls_CONF_CTX_set1_prefix(tls_CONF_CTX *cctx, const char *pre);

void tls_CONF_CTX_set_tls(tls_CONF_CTX *cctx, tls *tls);
void tls_CONF_CTX_set_tls_ctx(tls_CONF_CTX *cctx, tls_CTX *ctx);

__owur int tls_CONF_cmd(tls_CONF_CTX *cctx, const char *cmd, const char *value);
__owur int tls_CONF_cmd_argv(tls_CONF_CTX *cctx, int *pargc, char ***pargv);
__owur int tls_CONF_cmd_value_type(tls_CONF_CTX *cctx, const char *cmd);

void tls_add_tls_module(void);
int tls_config(tls *s, const char *name);
int tls_CTX_config(tls_CTX *ctx, const char *name);

# ifndef OPENtls_NO_tls_TRACE
void tls_trace(int write_p, int version, int content_type,
               const void *buf, size_t len, tls *tls, void *arg);
# endif

# ifndef OPENtls_NO_SOCK
int DTLSv1_listen(tls *s, BIO_ADDR *client);
# endif

# ifndef OPENtls_NO_CT

/*
 * A callback for verifying that the received SCTs are sufficient.
 * Expected to return 1 if they are sufficient, otherwise 0.
 * May return a negative integer if an error occurs.
 * A connection should be aborted if the SCTs are deemed insufficient.
 */
typedef int (*tls_ct_validation_cb)(const CT_POLICY_EVAL_CTX *ctx,
                                    const STACK_OF(SCT) *scts, void *arg);

/*
 * Sets a |callback| that is invoked upon receipt of ServerHelloDone to validate
 * the received SCTs.
 * If the callback returns a non-positive result, the connection is terminated.
 * Call this function before beginning a handshake.
 * If a NULL |callback| is provided, SCT validation is disabled.
 * |arg| is arbitrary userdata that will be passed to the callback whenever it
 * is invoked. Ownership of |arg| remains with the caller.
 *
 * NOTE: A side-effect of setting a CT callback is that an OCSP stapled response
 *       will be requested.
 */
int tls_set_ct_validation_callback(tls *s, tls_ct_validation_cb callback,
                                   void *arg);
int tls_CTX_set_ct_validation_callback(tls_CTX *ctx,
                                       tls_ct_validation_cb callback,
                                       void *arg);
#define tls_disable_ct(s) \
        ((void) tls_set_validation_callback((s), NULL, NULL))
#define tls_CTX_disable_ct(ctx) \
        ((void) tls_CTX_set_validation_callback((ctx), NULL, NULL))

/*
 * The validation type enumerates the available behaviours of the built-in tls
 * CT validation callback selected via tls_enable_ct() and tls_CTX_enable_ct().
 * The underlying callback is a static function in libtls.
 */
enum {
    tls_CT_VALIDATION_PERMISSIVE = 0,
    tls_CT_VALIDATION_STRICT
};

/*
 * Enable CT by setting up a callback that implements one of the built-in
 * validation variants.  The tls_CT_VALIDATION_PERMISSIVE variant always
 * continues the handshake, the application can make appropriate decisions at
 * handshake completion.  The tls_CT_VALIDATION_STRICT variant requires at
 * least one valid SCT, or else handshake termination will be requested.  The
 * handshake may continue anyway if tls_VERIFY_NONE is in effect.
 */
int tls_enable_ct(tls *s, int validation_mode);
int tls_CTX_enable_ct(tls_CTX *ctx, int validation_mode);

/*
 * Report whether a non-NULL callback is enabled.
 */
int tls_ct_is_enabled(const tls *s);
int tls_CTX_ct_is_enabled(const tls_CTX *ctx);

/* Gets the SCTs received from a connection */
const STACK_OF(SCT) *tls_get0_peer_scts(tls *s);

/*
 * Loads the CT log list from the default location.
 * If a CTLOG_STORE has previously been set using tls_CTX_set_ctlog_store,
 * the log information loaded from this file will be appended to the
 * CTLOG_STORE.
 * Returns 1 on success, 0 otherwise.
 */
int tls_CTX_set_default_ctlog_list_file(tls_CTX *ctx);

/*
 * Loads the CT log list from the specified file path.
 * If a CTLOG_STORE has previously been set using tls_CTX_set_ctlog_store,
 * the log information loaded from this file will be appended to the
 * CTLOG_STORE.
 * Returns 1 on success, 0 otherwise.
 */
int tls_CTX_set_ctlog_list_file(tls_CTX *ctx, const char *path);

/*
 * Sets the CT log list used by all tls connections created from this tls_CTX.
 * Ownership of the CTLOG_STORE is transferred to the tls_CTX.
 */
void tls_CTX_set0_ctlog_store(tls_CTX *ctx, CTLOG_STORE *logs);

/*
 * Gets the CT log list used by all tls connections created from this tls_CTX.
 * This will be NULL unless one of the following functions has been called:
 * - tls_CTX_set_default_ctlog_list_file
 * - tls_CTX_set_ctlog_list_file
 * - tls_CTX_set_ctlog_store
 */
const CTLOG_STORE *tls_CTX_get0_ctlog_store(const tls_CTX *ctx);

# endif /* OPENtls_NO_CT */

/* What the "other" parameter contains in security callback */
/* Mask for type */
# define tls_SECOP_OTHER_TYPE    0xffff0000
# define tls_SECOP_OTHER_NONE    0
# define tls_SECOP_OTHER_CIPHER  (1 << 16)
# define tls_SECOP_OTHER_CURVE   (2 << 16)
# define tls_SECOP_OTHER_DH      (3 << 16)
# define tls_SECOP_OTHER_PKEY    (4 << 16)
# define tls_SECOP_OTHER_SIGALG  (5 << 16)
# define tls_SECOP_OTHER_CERT    (6 << 16)

/* Indicated operation refers to peer key or certificate */
# define tls_SECOP_PEER          0x1000

/* Values for "op" parameter in security callback */

/* Called to filter ciphers */
/* Ciphers client supports */
# define tls_SECOP_CIPHER_SUPPORTED      (1 | tls_SECOP_OTHER_CIPHER)
/* Cipher shared by client/server */
# define tls_SECOP_CIPHER_SHARED         (2 | tls_SECOP_OTHER_CIPHER)
/* Sanity check of cipher server selects */
# define tls_SECOP_CIPHER_CHECK          (3 | tls_SECOP_OTHER_CIPHER)
/* Curves supported by client */
# define tls_SECOP_CURVE_SUPPORTED       (4 | tls_SECOP_OTHER_CURVE)
/* Curves shared by client/server */
# define tls_SECOP_CURVE_SHARED          (5 | tls_SECOP_OTHER_CURVE)
/* Sanity check of curve server selects */
# define tls_SECOP_CURVE_CHECK           (6 | tls_SECOP_OTHER_CURVE)
/* Temporary DH key */
# define tls_SECOP_TMP_DH                (7 | tls_SECOP_OTHER_PKEY)
/* tls/TLS version */
# define tls_SECOP_VERSION               (9 | tls_SECOP_OTHER_NONE)
/* Session tickets */
# define tls_SECOP_TICKET                (10 | tls_SECOP_OTHER_NONE)
/* Supported signature algorithms sent to peer */
# define tls_SECOP_SIGALG_SUPPORTED      (11 | tls_SECOP_OTHER_SIGALG)
/* Shared signature algorithm */
# define tls_SECOP_SIGALG_SHARED         (12 | tls_SECOP_OTHER_SIGALG)
/* Sanity check signature algorithm allowed */
# define tls_SECOP_SIGALG_CHECK          (13 | tls_SECOP_OTHER_SIGALG)
/* Used to get mask of supported public key signature algorithms */
# define tls_SECOP_SIGALG_MASK           (14 | tls_SECOP_OTHER_SIGALG)
/* Use to see if compression is allowed */
# define tls_SECOP_COMPRESSION           (15 | tls_SECOP_OTHER_NONE)
/* EE key in certificate */
# define tls_SECOP_EE_KEY                (16 | tls_SECOP_OTHER_CERT)
/* CA key in certificate */
# define tls_SECOP_CA_KEY                (17 | tls_SECOP_OTHER_CERT)
/* CA digest algorithm in certificate */
# define tls_SECOP_CA_MD                 (18 | tls_SECOP_OTHER_CERT)
/* Peer EE key in certificate */
# define tls_SECOP_PEER_EE_KEY           (tls_SECOP_EE_KEY | tls_SECOP_PEER)
/* Peer CA key in certificate */
# define tls_SECOP_PEER_CA_KEY           (tls_SECOP_CA_KEY | tls_SECOP_PEER)
/* Peer CA digest algorithm in certificate */
# define tls_SECOP_PEER_CA_MD            (tls_SECOP_CA_MD | tls_SECOP_PEER)

void tls_set_security_level(tls *s, int level);
__owur int tls_get_security_level(const tls *s);
void tls_set_security_callback(tls *s,
                               int (*cb) (const tls *s, const tls_CTX *ctx,
                                          int op, int bits, int nid,
                                          void *other, void *ex));
int (*tls_get_security_callback(const tls *s)) (const tls *s,
                                                const tls_CTX *ctx, int op,
                                                int bits, int nid, void *other,
                                                void *ex);
void tls_set0_security_ex_data(tls *s, void *ex);
__owur void *tls_get0_security_ex_data(const tls *s);

void tls_CTX_set_security_level(tls_CTX *ctx, int level);
__owur int tls_CTX_get_security_level(const tls_CTX *ctx);
void tls_CTX_set_security_callback(tls_CTX *ctx,
                                   int (*cb) (const tls *s, const tls_CTX *ctx,
                                              int op, int bits, int nid,
                                              void *other, void *ex));
int (*tls_CTX_get_security_callback(const tls_CTX *ctx)) (const tls *s,
                                                          const tls_CTX *ctx,
                                                          int op, int bits,
                                                          int nid,
                                                          void *other,
                                                          void *ex);
void tls_CTX_set0_security_ex_data(tls_CTX *ctx, void *ex);
__owur void *tls_CTX_get0_security_ex_data(const tls_CTX *ctx);

/* OPENtls_INIT flag 0x010000 reserved for internal use */
# define OPENtls_INIT_NO_LOAD_tls_STRINGS    0x00100000L
# define OPENtls_INIT_LOAD_tls_STRINGS       0x00200000L

# define OPENtls_INIT_tls_DEFAULT \
        (OPENtls_INIT_LOAD_tls_STRINGS | OPENtls_INIT_LOAD_CRYPTO_STRINGS)

int OPENtls_init_tls(uint64_t opts, const OPENtls_INIT_SETTINGS *settings);

# ifndef OPENtls_NO_UNIT_TEST
__owur const struct opentls_tls_test_functions *tls_test_functions(void);
# endif

__owur int tls_free_buffers(tls *tls);
__owur int tls_alloc_buffers(tls *tls);

/* Status codes passed to the decrypt session ticket callback. Some of these
 * are for internal use only and are never passed to the callback. */
typedef int tls_TICKET_STATUS;

/* Support for ticket appdata */
/* fatal error, malloc failure */
# define tls_TICKET_FATAL_ERR_MALLOC 0
/* fatal error, either from parsing or decrypting the ticket */
# define tls_TICKET_FATAL_ERR_OTHER  1
/* No ticket present */
# define tls_TICKET_NONE             2
/* Empty ticket present */
# define tls_TICKET_EMPTY            3
/* the ticket couldn't be decrypted */
# define tls_TICKET_NO_DECRYPT       4
/* a ticket was successfully decrypted */
# define tls_TICKET_SUCCESS          5
/* same as above but the ticket needs to be renewed */
# define tls_TICKET_SUCCESS_RENEW    6

/* Return codes for the decrypt session ticket callback */
typedef int tls_TICKET_RETURN;

/* An error occurred */
#define tls_TICKET_RETURN_ABORT             0
/* Do not use the ticket, do not send a renewed ticket to the client */
#define tls_TICKET_RETURN_IGNORE            1
/* Do not use the ticket, send a renewed ticket to the client */
#define tls_TICKET_RETURN_IGNORE_RENEW      2
/* Use the ticket, do not send a renewed ticket to the client */
#define tls_TICKET_RETURN_USE               3
/* Use the ticket, send a renewed ticket to the client */
#define tls_TICKET_RETURN_USE_RENEW         4

typedef int (*tls_CTX_generate_session_ticket_fn)(tls *s, void *arg);
typedef tls_TICKET_RETURN (*tls_CTX_decrypt_session_ticket_fn)(tls *s, tls_SESSION *ss,
                                                               const unsigned char *keyname,
                                                               size_t keyname_length,
                                                               tls_TICKET_STATUS status,
                                                               void *arg);
int tls_CTX_set_session_ticket_cb(tls_CTX *ctx,
                                  tls_CTX_generate_session_ticket_fn gen_cb,
                                  tls_CTX_decrypt_session_ticket_fn dec_cb,
                                  void *arg);
int tls_SESSION_set1_ticket_appdata(tls_SESSION *ss, const void *data, size_t len);
int tls_SESSION_get0_ticket_appdata(tls_SESSION *ss, void **data, size_t *len);

typedef unsigned int (*DTLS_timer_cb)(tls *s, unsigned int timer_us);

void DTLS_set_timer_cb(tls *s, DTLS_timer_cb cb);


typedef int (*tls_allow_early_data_cb_fn)(tls *s, void *arg);
void tls_CTX_set_allow_early_data_cb(tls_CTX *ctx,
                                     tls_allow_early_data_cb_fn cb,
                                     void *arg);
void tls_set_allow_early_data_cb(tls *s,
                                 tls_allow_early_data_cb_fn cb,
                                 void *arg);

/* store the default cipher strings inside the library */
const char *Otls_default_cipher_list(void);
const char *Otls_default_ciphersuites(void);

# ifdef  __cplusplus
}
# endif
#endif
