/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_tls3_H
# define OPENtls_tls3_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_tls3_H
# endif

# include <opentls/comp.h>
# include <opentls/buffer.h>
# include <opentls/evp.h>
# include <opentls/tls.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Signalling cipher suite value from RFC 5746
 * (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
 */
# define tls3_CK_SCSV                            0x030000FF

/*
 * Signalling cipher suite value from draft-ietf-tls-downgrade-scsv-00
 * (TLS_FALLBACK_SCSV)
 */
# define tls3_CK_FALLBACK_SCSV                   0x03005600

# define tls3_CK_RSA_NULL_MD5                    0x03000001
# define tls3_CK_RSA_NULL_SHA                    0x03000002
# define tls3_CK_RSA_RC4_40_MD5                  0x03000003
# define tls3_CK_RSA_RC4_128_MD5                 0x03000004
# define tls3_CK_RSA_RC4_128_SHA                 0x03000005
# define tls3_CK_RSA_RC2_40_MD5                  0x03000006
# define tls3_CK_RSA_IDEA_128_SHA                0x03000007
# define tls3_CK_RSA_DES_40_CBC_SHA              0x03000008
# define tls3_CK_RSA_DES_64_CBC_SHA              0x03000009
# define tls3_CK_RSA_DES_192_CBC3_SHA            0x0300000A

# define tls3_CK_DH_DSS_DES_40_CBC_SHA           0x0300000B
# define tls3_CK_DH_DSS_DES_64_CBC_SHA           0x0300000C
# define tls3_CK_DH_DSS_DES_192_CBC3_SHA         0x0300000D
# define tls3_CK_DH_RSA_DES_40_CBC_SHA           0x0300000E
# define tls3_CK_DH_RSA_DES_64_CBC_SHA           0x0300000F
# define tls3_CK_DH_RSA_DES_192_CBC3_SHA         0x03000010

# define tls3_CK_DHE_DSS_DES_40_CBC_SHA          0x03000011
# define tls3_CK_EDH_DSS_DES_40_CBC_SHA          tls3_CK_DHE_DSS_DES_40_CBC_SHA
# define tls3_CK_DHE_DSS_DES_64_CBC_SHA          0x03000012
# define tls3_CK_EDH_DSS_DES_64_CBC_SHA          tls3_CK_DHE_DSS_DES_64_CBC_SHA
# define tls3_CK_DHE_DSS_DES_192_CBC3_SHA        0x03000013
# define tls3_CK_EDH_DSS_DES_192_CBC3_SHA        tls3_CK_DHE_DSS_DES_192_CBC3_SHA
# define tls3_CK_DHE_RSA_DES_40_CBC_SHA          0x03000014
# define tls3_CK_EDH_RSA_DES_40_CBC_SHA          tls3_CK_DHE_RSA_DES_40_CBC_SHA
# define tls3_CK_DHE_RSA_DES_64_CBC_SHA          0x03000015
# define tls3_CK_EDH_RSA_DES_64_CBC_SHA          tls3_CK_DHE_RSA_DES_64_CBC_SHA
# define tls3_CK_DHE_RSA_DES_192_CBC3_SHA        0x03000016
# define tls3_CK_EDH_RSA_DES_192_CBC3_SHA        tls3_CK_DHE_RSA_DES_192_CBC3_SHA

# define tls3_CK_ADH_RC4_40_MD5                  0x03000017
# define tls3_CK_ADH_RC4_128_MD5                 0x03000018
# define tls3_CK_ADH_DES_40_CBC_SHA              0x03000019
# define tls3_CK_ADH_DES_64_CBC_SHA              0x0300001A
# define tls3_CK_ADH_DES_192_CBC_SHA             0x0300001B

/* a bundle of RFC standard cipher names, generated from tls3_ciphers[] */
# define tls3_RFC_RSA_NULL_MD5                   "TLS_RSA_WITH_NULL_MD5"
# define tls3_RFC_RSA_NULL_SHA                   "TLS_RSA_WITH_NULL_SHA"
# define tls3_RFC_RSA_DES_192_CBC3_SHA           "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# define tls3_RFC_DHE_DSS_DES_192_CBC3_SHA       "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
# define tls3_RFC_DHE_RSA_DES_192_CBC3_SHA       "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
# define tls3_RFC_ADH_DES_192_CBC_SHA            "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
# define tls3_RFC_RSA_IDEA_128_SHA               "TLS_RSA_WITH_IDEA_CBC_SHA"
# define tls3_RFC_RSA_RC4_128_MD5                "TLS_RSA_WITH_RC4_128_MD5"
# define tls3_RFC_RSA_RC4_128_SHA                "TLS_RSA_WITH_RC4_128_SHA"
# define tls3_RFC_ADH_RC4_128_MD5                "TLS_DH_anon_WITH_RC4_128_MD5"

# define tls3_TXT_RSA_NULL_MD5                   "NULL-MD5"
# define tls3_TXT_RSA_NULL_SHA                   "NULL-SHA"
# define tls3_TXT_RSA_RC4_40_MD5                 "EXP-RC4-MD5"
# define tls3_TXT_RSA_RC4_128_MD5                "RC4-MD5"
# define tls3_TXT_RSA_RC4_128_SHA                "RC4-SHA"
# define tls3_TXT_RSA_RC2_40_MD5                 "EXP-RC2-CBC-MD5"
# define tls3_TXT_RSA_IDEA_128_SHA               "IDEA-CBC-SHA"
# define tls3_TXT_RSA_DES_40_CBC_SHA             "EXP-DES-CBC-SHA"
# define tls3_TXT_RSA_DES_64_CBC_SHA             "DES-CBC-SHA"
# define tls3_TXT_RSA_DES_192_CBC3_SHA           "DES-CBC3-SHA"

# define tls3_TXT_DH_DSS_DES_40_CBC_SHA          "EXP-DH-DSS-DES-CBC-SHA"
# define tls3_TXT_DH_DSS_DES_64_CBC_SHA          "DH-DSS-DES-CBC-SHA"
# define tls3_TXT_DH_DSS_DES_192_CBC3_SHA        "DH-DSS-DES-CBC3-SHA"
# define tls3_TXT_DH_RSA_DES_40_CBC_SHA          "EXP-DH-RSA-DES-CBC-SHA"
# define tls3_TXT_DH_RSA_DES_64_CBC_SHA          "DH-RSA-DES-CBC-SHA"
# define tls3_TXT_DH_RSA_DES_192_CBC3_SHA        "DH-RSA-DES-CBC3-SHA"

# define tls3_TXT_DHE_DSS_DES_40_CBC_SHA         "EXP-DHE-DSS-DES-CBC-SHA"
# define tls3_TXT_DHE_DSS_DES_64_CBC_SHA         "DHE-DSS-DES-CBC-SHA"
# define tls3_TXT_DHE_DSS_DES_192_CBC3_SHA       "DHE-DSS-DES-CBC3-SHA"
# define tls3_TXT_DHE_RSA_DES_40_CBC_SHA         "EXP-DHE-RSA-DES-CBC-SHA"
# define tls3_TXT_DHE_RSA_DES_64_CBC_SHA         "DHE-RSA-DES-CBC-SHA"
# define tls3_TXT_DHE_RSA_DES_192_CBC3_SHA       "DHE-RSA-DES-CBC3-SHA"

/*
 * This next block of six "EDH" labels is for backward compatibility with
 * older versions of Opentls.  New code should use the six "DHE" labels above
 * instead:
 */
# define tls3_TXT_EDH_DSS_DES_40_CBC_SHA         "EXP-EDH-DSS-DES-CBC-SHA"
# define tls3_TXT_EDH_DSS_DES_64_CBC_SHA         "EDH-DSS-DES-CBC-SHA"
# define tls3_TXT_EDH_DSS_DES_192_CBC3_SHA       "EDH-DSS-DES-CBC3-SHA"
# define tls3_TXT_EDH_RSA_DES_40_CBC_SHA         "EXP-EDH-RSA-DES-CBC-SHA"
# define tls3_TXT_EDH_RSA_DES_64_CBC_SHA         "EDH-RSA-DES-CBC-SHA"
# define tls3_TXT_EDH_RSA_DES_192_CBC3_SHA       "EDH-RSA-DES-CBC3-SHA"

# define tls3_TXT_ADH_RC4_40_MD5                 "EXP-ADH-RC4-MD5"
# define tls3_TXT_ADH_RC4_128_MD5                "ADH-RC4-MD5"
# define tls3_TXT_ADH_DES_40_CBC_SHA             "EXP-ADH-DES-CBC-SHA"
# define tls3_TXT_ADH_DES_64_CBC_SHA             "ADH-DES-CBC-SHA"
# define tls3_TXT_ADH_DES_192_CBC_SHA            "ADH-DES-CBC3-SHA"

# define tls3_tls_SESSION_ID_LENGTH              32
# define tls3_MAX_tls_SESSION_ID_LENGTH          32

# define tls3_MASTER_SECRET_SIZE                 48
# define tls3_RANDOM_SIZE                        32
# define tls3_SESSION_ID_SIZE                    32
# define tls3_RT_HEADER_LENGTH                   5

# define tls3_HM_HEADER_LENGTH                  4

# ifndef tls3_ALIGN_PAYLOAD
 /*
  * Some will argue that this increases memory footprint, but it's not
  * actually true. Point is that malloc has to return at least 64-bit aligned
  * pointers, meaning that allocating 5 bytes wastes 3 bytes in either case.
  * Suggested pre-gaping simply moves these wasted bytes from the end of
  * allocated region to its front, but makes data payload aligned, which
  * improves performance:-)
  */
#  define tls3_ALIGN_PAYLOAD                     8
# else
#  if (tls3_ALIGN_PAYLOAD&(tls3_ALIGN_PAYLOAD-1))!=0
#   error "insane tls3_ALIGN_PAYLOAD"
#   undef tls3_ALIGN_PAYLOAD
#  endif
# endif

/*
 * This is the maximum MAC (digest) size used by the tls library. Currently
 * maximum of 20 is used by SHA1, but we reserve for future extension for
 * 512-bit hashes.
 */

# define tls3_RT_MAX_MD_SIZE                     64

/*
 * Maximum block size used in all ciphersuites. Currently 16 for AES.
 */

# define tls_RT_MAX_CIPHER_BLOCK_SIZE            16

# define tls3_RT_MAX_EXTRA                       (16384)

/* Maximum plaintext length: defined by tls/TLS standards */
# define tls3_RT_MAX_PLAIN_LENGTH                16384
/* Maximum compression overhead: defined by tls/TLS standards */
# define tls3_RT_MAX_COMPRESSED_OVERHEAD         1024

/*
 * The standards give a maximum encryption overhead of 1024 bytes. In
 * practice the value is lower than this. The overhead is the maximum number
 * of padding bytes (256) plus the mac size.
 */
# define tls3_RT_MAX_ENCRYPTED_OVERHEAD        (256 + tls3_RT_MAX_MD_SIZE)
# define tls3_RT_MAX_TLS13_ENCRYPTED_OVERHEAD  256

/*
 * Opentls currently only uses a padding length of at most one block so the
 * send overhead is smaller.
 */

# define tls3_RT_SEND_MAX_ENCRYPTED_OVERHEAD \
                        (tls_RT_MAX_CIPHER_BLOCK_SIZE + tls3_RT_MAX_MD_SIZE)

/* If compression isn't used don't include the compression overhead */

# ifdef OPENtls_NO_COMP
#  define tls3_RT_MAX_COMPRESSED_LENGTH           tls3_RT_MAX_PLAIN_LENGTH
# else
#  define tls3_RT_MAX_COMPRESSED_LENGTH   \
            (tls3_RT_MAX_PLAIN_LENGTH+tls3_RT_MAX_COMPRESSED_OVERHEAD)
# endif
# define tls3_RT_MAX_ENCRYPTED_LENGTH    \
            (tls3_RT_MAX_ENCRYPTED_OVERHEAD+tls3_RT_MAX_COMPRESSED_LENGTH)
# define tls3_RT_MAX_TLS13_ENCRYPTED_LENGTH \
            (tls3_RT_MAX_PLAIN_LENGTH + tls3_RT_MAX_TLS13_ENCRYPTED_OVERHEAD)
# define tls3_RT_MAX_PACKET_SIZE         \
            (tls3_RT_MAX_ENCRYPTED_LENGTH+tls3_RT_HEADER_LENGTH)

# define tls3_MD_CLIENT_FINISHED_CONST   "\x43\x4C\x4E\x54"
# define tls3_MD_SERVER_FINISHED_CONST   "\x53\x52\x56\x52"

# define tls3_VERSION                    0x0300
# define tls3_VERSION_MAJOR              0x03
# define tls3_VERSION_MINOR              0x00

# define tls3_RT_CHANGE_CIPHER_SPEC      20
# define tls3_RT_ALERT                   21
# define tls3_RT_HANDSHAKE               22
# define tls3_RT_APPLICATION_DATA        23

/* Pseudo content types to indicate additional parameters */
# define TLS1_RT_CRYPTO                  0x1000
# define TLS1_RT_CRYPTO_PREMASTER        (TLS1_RT_CRYPTO | 0x1)
# define TLS1_RT_CRYPTO_CLIENT_RANDOM    (TLS1_RT_CRYPTO | 0x2)
# define TLS1_RT_CRYPTO_SERVER_RANDOM    (TLS1_RT_CRYPTO | 0x3)
# define TLS1_RT_CRYPTO_MASTER           (TLS1_RT_CRYPTO | 0x4)

# define TLS1_RT_CRYPTO_READ             0x0000
# define TLS1_RT_CRYPTO_WRITE            0x0100
# define TLS1_RT_CRYPTO_MAC              (TLS1_RT_CRYPTO | 0x5)
# define TLS1_RT_CRYPTO_KEY              (TLS1_RT_CRYPTO | 0x6)
# define TLS1_RT_CRYPTO_IV               (TLS1_RT_CRYPTO | 0x7)
# define TLS1_RT_CRYPTO_FIXED_IV         (TLS1_RT_CRYPTO | 0x8)

/* Pseudo content types for tls/TLS header info */
# define tls3_RT_HEADER                  0x100
# define tls3_RT_INNER_CONTENT_TYPE      0x101

# define tls3_AL_WARNING                 1
# define tls3_AL_FATAL                   2

# define tls3_AD_CLOSE_NOTIFY             0
# define tls3_AD_UNEXPECTED_MESSAGE      10/* fatal */
# define tls3_AD_BAD_RECORD_MAC          20/* fatal */
# define tls3_AD_DECOMPRESSION_FAILURE   30/* fatal */
# define tls3_AD_HANDSHAKE_FAILURE       40/* fatal */
# define tls3_AD_NO_CERTIFICATE          41
# define tls3_AD_BAD_CERTIFICATE         42
# define tls3_AD_UNSUPPORTED_CERTIFICATE 43
# define tls3_AD_CERTIFICATE_REVOKED     44
# define tls3_AD_CERTIFICATE_EXPIRED     45
# define tls3_AD_CERTIFICATE_UNKNOWN     46
# define tls3_AD_ILLEGAL_PARAMETER       47/* fatal */

# define TLS1_HB_REQUEST         1
# define TLS1_HB_RESPONSE        2


# define tls3_CT_RSA_SIGN                        1
# define tls3_CT_DSS_SIGN                        2
# define tls3_CT_RSA_FIXED_DH                    3
# define tls3_CT_DSS_FIXED_DH                    4
# define tls3_CT_RSA_EPHEMERAL_DH                5
# define tls3_CT_DSS_EPHEMERAL_DH                6
# define tls3_CT_FORTEZZA_DMS                    20
/*
 * tls3_CT_NUMBER is used to size arrays and it must be large enough to
 * contain all of the cert types defined for *either* tlsv3 and TLSv1.
 */
# define tls3_CT_NUMBER                  10

# if defined(TLS_CT_NUMBER)
#  if TLS_CT_NUMBER != tls3_CT_NUMBER
#    error "tls/TLS CT_NUMBER values do not match"
#  endif
# endif

/* No longer used as of Opentls 1.1.1 */
# define tls3_FLAGS_NO_RENEGOTIATE_CIPHERS       0x0001

/* Removed from Opentls 1.1.0 */
# define TLS1_FLAGS_TLS_PADDING_BUG              0x0

# define TLS1_FLAGS_SKIP_CERT_VERIFY             0x0010

/* Set if we encrypt then mac instead of usual mac then encrypt */
# define TLS1_FLAGS_ENCRYPT_THEN_MAC_READ        0x0100
# define TLS1_FLAGS_ENCRYPT_THEN_MAC             TLS1_FLAGS_ENCRYPT_THEN_MAC_READ

/* Set if extended master secret extension received from peer */
# define TLS1_FLAGS_RECEIVED_EXTMS               0x0200

# define TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE       0x0400

# define TLS1_FLAGS_STATELESS                    0x0800

# define tls3_MT_HELLO_REQUEST                   0
# define tls3_MT_CLIENT_HELLO                    1
# define tls3_MT_SERVER_HELLO                    2
# define tls3_MT_NEWSESSION_TICKET               4
# define tls3_MT_END_OF_EARLY_DATA               5
# define tls3_MT_ENCRYPTED_EXTENSIONS            8
# define tls3_MT_CERTIFICATE                     11
# define tls3_MT_SERVER_KEY_EXCHANGE             12
# define tls3_MT_CERTIFICATE_REQUEST             13
# define tls3_MT_SERVER_DONE                     14
# define tls3_MT_CERTIFICATE_VERIFY              15
# define tls3_MT_CLIENT_KEY_EXCHANGE             16
# define tls3_MT_FINISHED                        20
# define tls3_MT_CERTIFICATE_URL                 21
# define tls3_MT_CERTIFICATE_STATUS              22
# define tls3_MT_SUPPLEMENTAL_DATA               23
# define tls3_MT_KEY_UPDATE                      24
# ifndef OPENtls_NO_NEXTPROTONEG
#  define tls3_MT_NEXT_PROTO                     67
# endif
# define tls3_MT_MESSAGE_HASH                    254
# define DTLS1_MT_HELLO_VERIFY_REQUEST           3

/* Dummy message type for handling CCS like a normal handshake message */
# define tls3_MT_CHANGE_CIPHER_SPEC              0x0101

# define tls3_MT_CCS                             1

/* These are used when changing over to a new cipher */
# define tls3_CC_READ            0x001
# define tls3_CC_WRITE           0x002
# define tls3_CC_CLIENT          0x010
# define tls3_CC_SERVER          0x020
# define tls3_CC_EARLY           0x040
# define tls3_CC_HANDSHAKE       0x080
# define tls3_CC_APPLICATION     0x100
# define tls3_CHANGE_CIPHER_CLIENT_WRITE (tls3_CC_CLIENT|tls3_CC_WRITE)
# define tls3_CHANGE_CIPHER_SERVER_READ  (tls3_CC_SERVER|tls3_CC_READ)
# define tls3_CHANGE_CIPHER_CLIENT_READ  (tls3_CC_CLIENT|tls3_CC_READ)
# define tls3_CHANGE_CIPHER_SERVER_WRITE (tls3_CC_SERVER|tls3_CC_WRITE)

#ifdef  __cplusplus
}
#endif
#endif
