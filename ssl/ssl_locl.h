/* ssl/ssl_locl.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#ifndef HEADER_SSL_LOCL_H
# define HEADER_SSL_LOCL_H
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <errno.h>

# include "e_os.h"

# include <openssl/buffer.h>
# ifndef OPENSSL_NO_COMP
#  include <openssl/comp.h>
# endif
# include <openssl/bio.h>
# include <openssl/stack.h>
# ifndef OPENSSL_NO_RSA
#  include <openssl/rsa.h>
# endif
# ifndef OPENSSL_NO_DSA
#  include <openssl/dsa.h>
# endif
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/async.h>
# include <openssl/symhacks.h>

#include "record/record.h"
#include "statem/statem.h"
#include "packet_locl.h"

# ifdef OPENSSL_BUILD_SHLIBSSL
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

# undef PKCS1_CHECK

# define c2l(c,l)        (l = ((unsigned long)(*((c)++)))     , \
                         l|=(((unsigned long)(*((c)++)))<< 8), \
                         l|=(((unsigned long)(*((c)++)))<<16), \
                         l|=(((unsigned long)(*((c)++)))<<24))

/* NOTE - c is not incremented as per c2l */
# define c2ln(c,l1,l2,n) { \
                        c+=n; \
                        l1=l2=0; \
                        switch (n) { \
                        case 8: l2 =((unsigned long)(*(--(c))))<<24; \
                        case 7: l2|=((unsigned long)(*(--(c))))<<16; \
                        case 6: l2|=((unsigned long)(*(--(c))))<< 8; \
                        case 5: l2|=((unsigned long)(*(--(c))));     \
                        case 4: l1 =((unsigned long)(*(--(c))))<<24; \
                        case 3: l1|=((unsigned long)(*(--(c))))<<16; \
                        case 2: l1|=((unsigned long)(*(--(c))))<< 8; \
                        case 1: l1|=((unsigned long)(*(--(c))));     \
                                } \
                        }

# define l2c(l,c)        (*((c)++)=(unsigned char)(((l)    )&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff))

# define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24, \
                         l|=((unsigned long)(*((c)++)))<<16, \
                         l|=((unsigned long)(*((c)++)))<< 8, \
                         l|=((unsigned long)(*((c)++))))

# define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))

# define l2n6(l,c)       (*((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))

# define l2n8(l,c)       (*((c)++)=(unsigned char)(((l)>>56)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>48)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))

# define n2l6(c,l)       (l =((BN_ULLONG)(*((c)++)))<<40, \
                         l|=((BN_ULLONG)(*((c)++)))<<32, \
                         l|=((BN_ULLONG)(*((c)++)))<<24, \
                         l|=((BN_ULLONG)(*((c)++)))<<16, \
                         l|=((BN_ULLONG)(*((c)++)))<< 8, \
                         l|=((BN_ULLONG)(*((c)++))))

/* NOTE - c is not incremented as per l2c */
# define l2cn(l1,l2,c,n) { \
                        c+=n; \
                        switch (n) { \
                        case 8: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
                        case 7: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
                        case 6: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
                        case 5: *(--(c))=(unsigned char)(((l2)    )&0xff); \
                        case 4: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
                        case 3: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
                        case 2: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
                        case 1: *(--(c))=(unsigned char)(((l1)    )&0xff); \
                                } \
                        }

# define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)
# define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

# define n2l3(c,l)       ((l =(((unsigned long)(c[0]))<<16)| \
                             (((unsigned long)(c[1]))<< 8)| \
                             (((unsigned long)(c[2]))    )),c+=3)

# define l2n3(l,c)       ((c[0]=(unsigned char)(((l)>>16)&0xff), \
                          c[1]=(unsigned char)(((l)>> 8)&0xff), \
                          c[2]=(unsigned char)(((l)    )&0xff)),c+=3)

/* LOCAL STUFF */

# define SSL_DECRYPT     0
# define SSL_ENCRYPT     1

# define TWO_BYTE_BIT    0x80
# define SEC_ESC_BIT     0x40
# define TWO_BYTE_MASK   0x7fff
# define THREE_BYTE_MASK 0x3fff

# define INC32(a)        ((a)=((a)+1)&0xffffffffL)
# define DEC32(a)        ((a)=((a)-1)&0xffffffffL)
# define MAX_MAC_SIZE    20     /* up from 16 for SSLv3 */

/*
 * Define the Bitmasks for SSL_CIPHER.algorithms.
 * This bits are used packed as dense as possible. If new methods/ciphers
 * etc will be added, the bits a likely to change, so this information
 * is for internal library use only, even though SSL_CIPHER.algorithms
 * can be publicly accessed.
 * Use the according functions for cipher management instead.
 *
 * The bit mask handling in the selection and sorting scheme in
 * ssl_create_cipher_list() has only limited capabilities, reflecting
 * that the different entities within are mutually exclusive:
 * ONLY ONE BIT PER MASK CAN BE SET AT A TIME.
 */

/* Bits for algorithm_mkey (key exchange algorithm) */
/* RSA key exchange */
# define SSL_kRSA                0x00000001U
/* DH cert, RSA CA cert */
# define SSL_kDHr                0x00000002U
/* DH cert, DSA CA cert */
# define SSL_kDHd                0x00000004U
/* tmp DH key no DH cert */
# define SSL_kDHE                0x00000008U
/* synonym */
# define SSL_kEDH                SSL_kDHE
/* ECDH cert, RSA CA cert */
# define SSL_kECDHr              0x00000020U
/* ECDH cert, ECDSA CA cert */
# define SSL_kECDHe              0x00000040U
/* ephemeral ECDH */
# define SSL_kECDHE              0x00000080U
/* synonym */
# define SSL_kEECDH              SSL_kECDHE
/* PSK */
# define SSL_kPSK                0x00000100U
/* GOST key exchange */
# define SSL_kGOST       0x00000200U
/* SRP */
# define SSL_kSRP        0x00000400U

# define SSL_kRSAPSK             0x00000800U
# define SSL_kECDHEPSK           0x00001000U
# define SSL_kDHEPSK             0x00002000U

/* all PSK */

#define SSL_PSK     (SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK)

/* Bits for algorithm_auth (server authentication) */
/* RSA auth */
# define SSL_aRSA                0x00000001U
/* DSS auth */
# define SSL_aDSS                0x00000002U
/* no auth (i.e. use ADH or AECDH) */
# define SSL_aNULL               0x00000004U
/* Fixed DH auth (kDHd or kDHr) */
# define SSL_aDH                 0x00000008U
/* Fixed ECDH auth (kECDHe or kECDHr) */
# define SSL_aECDH               0x00000010U
/* ECDSA auth*/
# define SSL_aECDSA              0x00000040U
/* PSK auth */
# define SSL_aPSK                0x00000080U
/* GOST R 34.10-2001 signature auth */
# define SSL_aGOST01                     0x00000200U
/* SRP auth */
# define SSL_aSRP                0x00000400U
/* GOST R 34.10-2012 signature auth */
# define SSL_aGOST12             0x00000800U

/* Bits for algorithm_enc (symmetric encryption) */
# define SSL_DES                 0x00000001U
# define SSL_3DES                0x00000002U
# define SSL_RC4                 0x00000004U
# define SSL_RC2                 0x00000008U
# define SSL_IDEA                0x00000010U
# define SSL_eNULL               0x00000020U
# define SSL_AES128              0x00000040U
# define SSL_AES256              0x00000080U
# define SSL_CAMELLIA128         0x00000100U
# define SSL_CAMELLIA256         0x00000200U
# define SSL_eGOST2814789CNT     0x00000400U
# define SSL_SEED                0x00000800U
# define SSL_AES128GCM           0x00001000U
# define SSL_AES256GCM           0x00002000U
# define SSL_AES128CCM           0x00004000U
# define SSL_AES256CCM           0x00008000U
# define SSL_AES128CCM8          0x00010000U
# define SSL_AES256CCM8          0x00020000U
# define SSL_eGOST2814789CNT12   0x00040000U

# define SSL_AES                 (SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM|SSL_AES128CCM|SSL_AES256CCM|SSL_AES128CCM8|SSL_AES256CCM8)
# define SSL_CAMELLIA            (SSL_CAMELLIA128|SSL_CAMELLIA256)

/* Bits for algorithm_mac (symmetric authentication) */

# define SSL_MD5                 0x00000001U
# define SSL_SHA1                0x00000002U
# define SSL_GOST94      0x00000004U
# define SSL_GOST89MAC   0x00000008U
# define SSL_SHA256              0x00000010U
# define SSL_SHA384              0x00000020U
/* Not a real MAC, just an indication it is part of cipher */
# define SSL_AEAD                0x00000040U
# define SSL_GOST12_256          0x00000080U
# define SSL_GOST89MAC12         0x00000100U
# define SSL_GOST12_512          0x00000200U

/* Bits for algorithm_ssl (protocol version) */
# define SSL_SSLV3               0x00000002U
# define SSL_TLSV1               0x00000004U
# define SSL_TLSV1_2             0x00000008U

/*
 * When adding new digest in the ssl_ciph.c and increment SSL_MD_NUM_IDX make
 * sure to update this constant too
 */

# define SSL_MD_MD5_IDX  0
# define SSL_MD_SHA1_IDX 1
# define SSL_MD_GOST94_IDX 2
# define SSL_MD_GOST89MAC_IDX 3
# define SSL_MD_SHA256_IDX 4
# define SSL_MD_SHA384_IDX 5
# define SSL_MD_GOST12_256_IDX  6
# define SSL_MD_GOST89MAC12_IDX 7
# define SSL_MD_GOST12_512_IDX  8
# define SSL_MD_MD5_SHA1_IDX 9
# define SSL_MD_SHA224_IDX 10
# define SSL_MD_SHA512_IDX 11
# define SSL_MAX_DIGEST 12

/* Bits for algorithm2 (handshake digests and other extra flags) */

/* Bits 0-7 are handshake MAC */
# define SSL_HANDSHAKE_MAC_MASK  0xFF
# define SSL_HANDSHAKE_MAC_MD5_SHA1 SSL_MD_MD5_SHA1_IDX
# define SSL_HANDSHAKE_MAC_SHA256   SSL_MD_SHA256_IDX
# define SSL_HANDSHAKE_MAC_SHA384   SSL_MD_SHA384_IDX
# define SSL_HANDSHAKE_MAC_GOST94 SSL_MD_GOST94_IDX
# define SSL_HANDSHAKE_MAC_GOST12_256 SSL_MD_GOST12_256_IDX
# define SSL_HANDSHAKE_MAC_GOST12_512 SSL_MD_GOST12_512_IDX
# define SSL_HANDSHAKE_MAC_DEFAULT  SSL_HANDSHAKE_MAC_MD5_SHA1

/* Bits 8-15 bits are PRF */
# define TLS1_PRF_DGST_SHIFT 8
# define TLS1_PRF_SHA1_MD5 (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256 (SSL_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384 (SSL_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST94 (SSL_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_256 (SSL_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_GOST12_512 (SSL_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF            (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)

/*
 * Stream MAC for GOST ciphersuites from cryptopro draft (currently this also
 * goes into algorithm2)
 */
# define TLS1_STREAM_MAC 0x10000

/*
 * Export and cipher strength information. For each cipher we have to decide
 * whether it is exportable or not. This information is likely to change
 * over time, since the export control rules are no static technical issue.
 *
 * Independent of the export flag the cipher strength is sorted into classes.
 * SSL_EXP40 was denoting the 40bit US export limit of past times, which now
 * is at 56bit (SSL_EXP56). If the exportable cipher class is going to change
 * again (eg. to 64bit) the use of "SSL_EXP*" becomes blurred even more,
 * since SSL_EXP64 could be similar to SSL_LOW.
 * For this reason SSL_MICRO and SSL_MINI macros are included to widen the
 * namespace of SSL_LOW-SSL_HIGH to lower values. As development of speed
 * and ciphers goes, another extension to SSL_SUPER and/or SSL_ULTRA would
 * be possible.
 */
# define SSL_EXP_MASK            0x00000003U
# define SSL_STRONG_MASK         0x000001fcU
# define SSL_DEFAULT_MASK        0X00000200U

# define SSL_NOT_EXP             0x00000001U
# define SSL_EXPORT              0x00000002U

# define SSL_STRONG_NONE         0x00000004U
# define SSL_EXP40               0x00000008U
# define SSL_MICRO               (SSL_EXP40)
# define SSL_EXP56               0x00000010U
# define SSL_MINI                (SSL_EXP56)
# define SSL_LOW                 0x00000020U
# define SSL_MEDIUM              0x00000040U
# define SSL_HIGH                0x00000080U
# define SSL_FIPS                0x00000100U

# define SSL_NOT_DEFAULT         0x00000200U

/* we have used 000003ff - 22 bits left to go */

/*-
 * Macros to check the export status and cipher strength for export ciphers.
 * Even though the macros for EXPORT and EXPORT40/56 have similar names,
 * their meaning is different:
 * *_EXPORT macros check the 'exportable' status.
 * *_EXPORT40/56 macros are used to check whether a certain cipher strength
 *          is given.
 * Since the SSL_IS_EXPORT* and SSL_EXPORT* macros depend on the correct
 * algorithm structure element to be passed (algorithms, algo_strength) and no
 * typechecking can be done as they are all of type unsigned long, their
 * direct usage is discouraged.
 * Use the SSL_C_* macros instead.
 */
# define SSL_IS_EXPORT(a)        ((a)&SSL_EXPORT)
# define SSL_IS_EXPORT56(a)      ((a)&SSL_EXP56)
# define SSL_IS_EXPORT40(a)      ((a)&SSL_EXP40)
# define SSL_C_IS_EXPORT(c)      SSL_IS_EXPORT((c)->algo_strength)
# define SSL_C_IS_EXPORT56(c)    SSL_IS_EXPORT56((c)->algo_strength)
# define SSL_C_IS_EXPORT40(c)    SSL_IS_EXPORT40((c)->algo_strength)

# define SSL_EXPORT_KEYLENGTH(a,s)       (SSL_IS_EXPORT40(s) ? 5 : \
                                 (a) == SSL_DES ? 8 : 7)
# define SSL_EXPORT_PKEYLENGTH(a) (SSL_IS_EXPORT40(a) ? 512 : 1024)
# define SSL_C_EXPORT_KEYLENGTH(c)       SSL_EXPORT_KEYLENGTH((c)->algorithm_enc, \
                                (c)->algo_strength)
# define SSL_C_EXPORT_PKEYLENGTH(c)      SSL_EXPORT_PKEYLENGTH((c)->algo_strength)

/* Check if an SSL structure is using DTLS */
# define SSL_IS_DTLS(s)  (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)
/* See if we need explicit IV */
# define SSL_USE_EXPLICIT_IV(s)  \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)
/*
 * See if we use signature algorithms extension and signature algorithm
 * before signatures.
 */
# define SSL_USE_SIGALGS(s)      \
                        (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS)
/*
 * Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2: may
 * apply to others in future.
 */
# define SSL_USE_TLS1_2_CIPHERS(s)       \
                (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
/*
 * Determine if a client can use TLS 1.2 ciphersuites: can't rely on method
 * flags because it may not be set to correct version yet.
 */
# define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)        \
                ((SSL_IS_DTLS(s) && s->client_version <= DTLS1_2_VERSION) || \
                (!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION))

# ifdef TLSEXT_TYPE_encrypt_then_mac
#  define SSL_USE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC)
# else
#  define SSL_USE_ETM(s) (0)
# endif

/* Mostly for SSLv3 */
# define SSL_PKEY_RSA_ENC        0
# define SSL_PKEY_RSA_SIGN       1
# define SSL_PKEY_DSA_SIGN       2
# define SSL_PKEY_DH_RSA         3
# define SSL_PKEY_DH_DSA         4
# define SSL_PKEY_ECC            5
# define SSL_PKEY_GOST01         7
# define SSL_PKEY_GOST12_256     8
# define SSL_PKEY_GOST12_512     9
# define SSL_PKEY_NUM            10
/*
 * Pseudo-constant. GOST cipher suites can use different certs for 1
 * SSL_CIPHER. So let's see which one we have in fact.
 */
# define SSL_PKEY_GOST_EC SSL_PKEY_NUM+1

/*-
 * SSL_kRSA <- RSA_ENC | (RSA_TMP & RSA_SIGN) |
 *          <- (EXPORT & (RSA_ENC | RSA_TMP) & RSA_SIGN)
 * SSL_kDH  <- DH_ENC & (RSA_ENC | RSA_SIGN | DSA_SIGN)
 * SSL_kDHE <- RSA_ENC | RSA_SIGN | DSA_SIGN
 * SSL_aRSA <- RSA_ENC | RSA_SIGN
 * SSL_aDSS <- DSA_SIGN
 */

/*-
#define CERT_INVALID            0
#define CERT_PUBLIC_KEY         1
#define CERT_PRIVATE_KEY        2
*/


/* CipherSuite length. SSLv3 and all TLS versions. */
#define TLS_CIPHER_LEN 2
/* used to hold info on the particular ciphers used */
struct ssl_cipher_st {
    uint32_t valid;
    const char *name;        /* text name */
    uint32_t id;             /* id, 4 bytes, first is version */
    /*
     * changed in 1.0.0: these four used to be portions of a single value
     * 'algorithms'
     */
    uint32_t algorithm_mkey; /* key exchange algorithm */
    uint32_t algorithm_auth; /* server authentication */
    uint32_t algorithm_enc;  /* symmetric encryption */
    uint32_t algorithm_mac;  /* symmetric authentication */
    uint32_t algorithm_ssl;  /* (major) protocol version */
    uint32_t algo_strength;  /* strength and export flags */
    uint32_t algorithm2;     /* Extra flags */
    int32_t strength_bits;   /* Number of bits really used */
    uint32_t alg_bits;       /* Number of bits for algorithm */
};

/* Used to hold SSL/TLS functions */
struct ssl_method_st {
    int version;
    int (*ssl_new) (SSL *s);
    void (*ssl_clear) (SSL *s);
    void (*ssl_free) (SSL *s);
    int (*ssl_accept) (SSL *s);
    int (*ssl_connect) (SSL *s);
    int (*ssl_read) (SSL *s, void *buf, int len);
    int (*ssl_peek) (SSL *s, void *buf, int len);
    int (*ssl_write) (SSL *s, const void *buf, int len);
    int (*ssl_shutdown) (SSL *s);
    int (*ssl_renegotiate) (SSL *s);
    int (*ssl_renegotiate_check) (SSL *s);
    int (*ssl_read_bytes) (SSL *s, int type, int *recvd_type,
                           unsigned char *buf, int len, int peek);
    int (*ssl_write_bytes) (SSL *s, int type, const void *buf_, int len);
    int (*ssl_dispatch_alert) (SSL *s);
    long (*ssl_ctrl) (SSL *s, int cmd, long larg, void *parg);
    long (*ssl_ctx_ctrl) (SSL_CTX *ctx, int cmd, long larg, void *parg);
    const SSL_CIPHER *(*get_cipher_by_char) (const unsigned char *ptr);
    int (*put_cipher_by_char) (const SSL_CIPHER *cipher, unsigned char *ptr);
    int (*ssl_pending) (const SSL *s);
    int (*num_ciphers) (void);
    const SSL_CIPHER *(*get_cipher) (unsigned ncipher);
    const struct ssl_method_st *(*get_ssl_method) (int version);
    long (*get_timeout) (void);
    const struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
    int (*ssl_version) (void);
    long (*ssl_callback_ctrl) (SSL *s, int cb_id, void (*fp) (void));
    long (*ssl_ctx_callback_ctrl) (SSL_CTX *s, int cb_id, void (*fp) (void));
};

/*-
 * Lets make this into an ASN.1 type structure as follows
 * SSL_SESSION_ID ::= SEQUENCE {
 *      version                 INTEGER,        -- structure version number
 *      SSLversion              INTEGER,        -- SSL version number
 *      Cipher                  OCTET STRING,   -- the 3 byte cipher ID
 *      Session_ID              OCTET STRING,   -- the Session ID
 *      Master_key              OCTET STRING,   -- the master key
 *      Key_Arg [ 0 ] IMPLICIT  OCTET STRING,   -- the optional Key argument
 *      Time [ 1 ] EXPLICIT     INTEGER,        -- optional Start Time
 *      Timeout [ 2 ] EXPLICIT  INTEGER,        -- optional Timeout ins seconds
 *      Peer [ 3 ] EXPLICIT     X509,           -- optional Peer Certificate
 *      Session_ID_context [ 4 ] EXPLICIT OCTET STRING,   -- the Session ID context
 *      Verify_result [ 5 ] EXPLICIT INTEGER,   -- X509_V_... code for `Peer'
 *      HostName [ 6 ] EXPLICIT OCTET STRING,   -- optional HostName from servername TLS extension
 *      PSK_identity_hint [ 7 ] EXPLICIT OCTET STRING, -- optional PSK identity hint
 *      PSK_identity [ 8 ] EXPLICIT OCTET STRING,  -- optional PSK identity
 *      Ticket_lifetime_hint [9] EXPLICIT INTEGER, -- server's lifetime hint for session ticket
 *      Ticket [10]             EXPLICIT OCTET STRING, -- session ticket (clients only)
 *      Compression_meth [11]   EXPLICIT OCTET STRING, -- optional compression method
 *      SRP_username [ 12 ] EXPLICIT OCTET STRING -- optional SRP username
 *      flags [ 13 ] EXPLICIT INTEGER -- optional flags
 *      }
 * Look in ssl/ssl_asn1.c for more details
 * I'm using EXPLICIT tags so I can read the damn things using asn1parse :-).
 */
struct ssl_session_st {
    int ssl_version;            /* what ssl version session info is being
                                 * kept in here? */
    int master_key_length;
    unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
    /* session_id - valid? */
    unsigned int session_id_length;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    /*
     * this is used to determine whether the session is being reused in the
     * appropriate context. It is up to the application to set this, via
     * SSL_new
     */
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
# ifndef OPENSSL_NO_PSK
    char *psk_identity_hint;
    char *psk_identity;
# endif
    /*
     * Used to indicate that session resumption is not allowed. Applications
     * can also set this bit for a new session via not_resumable_session_cb
     * to disable session caching and tickets.
     */
    int not_resumable;
    /* This is the cert and type for the other end. */
    X509 *peer;
    int peer_type;
    /* Certificate chain of peer */
    STACK_OF(X509) *peer_chain;
    /*
     * when app_verify_callback accepts a session where the peer's
     * certificate is not ok, we must remember the error for session reuse:
     */
    long verify_result;         /* only for servers */
    int references;
    long timeout;
    long time;
    unsigned int compress_meth; /* Need to lookup the method */
    const SSL_CIPHER *cipher;
    unsigned long cipher_id;    /* when ASN.1 loaded, this needs to be used
                                 * to load the 'cipher' structure */
    STACK_OF(SSL_CIPHER) *ciphers; /* shared ciphers? */
    CRYPTO_EX_DATA ex_data;     /* application specific data */
    /*
     * These are used to make removal of session-ids more efficient and to
     * implement a maximum cache size.
     */
    struct ssl_session_st *prev, *next;
    char *tlsext_hostname;
# ifndef OPENSSL_NO_EC
    size_t tlsext_ecpointformatlist_length;
    unsigned char *tlsext_ecpointformatlist; /* peer's list */
    size_t tlsext_ellipticcurvelist_length;
    unsigned char *tlsext_ellipticcurvelist; /* peer's list */
# endif                       /* OPENSSL_NO_EC */
    /* RFC4507 info */
    unsigned char *tlsext_tick; /* Session ticket */
    size_t tlsext_ticklen;      /* Session ticket length */
    unsigned long tlsext_tick_lifetime_hint; /* Session lifetime hint in seconds */
# ifndef OPENSSL_NO_SRP
    char *srp_username;
# endif
    uint32_t flags;
};

/* Extended master secret support */
#  define SSL_SESS_FLAG_EXTMS             0x1


# ifndef OPENSSL_NO_SRP

typedef struct srp_ctx_st {
    /* param for all the callbacks */
    void *SRP_cb_arg;
    /* set client Hello login callback */
    int (*TLS_ext_srp_username_callback) (SSL *, int *, void *);
    /* set SRP N/g param callback for verification */
    int (*SRP_verify_param_callback) (SSL *, void *);
    /* set SRP client passwd callback */
    char *(*SRP_give_srp_client_pwd_callback) (SSL *, void *);
    char *login;
    BIGNUM *N, *g, *s, *B, *A;
    BIGNUM *a, *b, *v;
    char *info;
    int strength;
    unsigned long srp_Mask;
} SRP_CTX;

# endif

typedef struct ssl_comp_st SSL_COMP;

struct ssl_comp_st {
    int id;
    const char *name;
    COMP_METHOD *method;
};

DECLARE_STACK_OF(SSL_COMP)
DECLARE_LHASH_OF(SSL_SESSION);


struct ssl_ctx_st {
    const SSL_METHOD *method;
    STACK_OF(SSL_CIPHER) *cipher_list;
    /* same as above but sorted for lookup */
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    struct x509_store_st /* X509_STORE */ *cert_store;
    LHASH_OF(SSL_SESSION) *sessions;
    /*
     * Most session-ids that will be cached, default is
     * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
     */
    unsigned long session_cache_size;
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    /*
     * This can have one of 2 values, ored together, SSL_SESS_CACHE_CLIENT,
     * SSL_SESS_CACHE_SERVER, Default is SSL_SESSION_CACHE_SERVER, which
     * means only SSL_accept which cache SSL_SESSIONS.
     */
    uint32_t session_cache_mode;
    /*
     * If timeout is not 0, it is the default timeout value set when
     * SSL_new() is called.  This has been put in to make life easier to set
     * things up
     */
    long session_timeout;
    /*
     * If this callback is not null, it will be called each time a session id
     * is added to the cache.  If this function returns 1, it means that the
     * callback will do a SSL_SESSION_free() when it has finished using it.
     * Otherwise, on 0, it means the callback has finished with it. If
     * remove_session_cb is not null, it will be called when a session-id is
     * removed from the cache.  After the call, OpenSSL will
     * SSL_SESSION_free() it.
     */
    int (*new_session_cb) (struct ssl_st *ssl, SSL_SESSION *sess);
    void (*remove_session_cb) (struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    SSL_SESSION *(*get_session_cb) (struct ssl_st *ssl,
                                    unsigned char *data, int len, int *copy);
    struct {
        int sess_connect;       /* SSL new conn - started */
        int sess_connect_renegotiate; /* SSL reneg - requested */
        int sess_connect_good;  /* SSL new conne/reneg - finished */
        int sess_accept;        /* SSL new accept - started */
        int sess_accept_renegotiate; /* SSL reneg - requested */
        int sess_accept_good;   /* SSL accept/reneg - finished */
        int sess_miss;          /* session lookup misses */
        int sess_timeout;       /* reuse attempt on timeouted session */
        int sess_cache_full;    /* session removed due to full cache */
        int sess_hit;           /* session reuse actually done */
        int sess_cb_hit;        /* session-id that was not in the cache was
                                 * passed back via the callback.  This
                                 * indicates that the application is
                                 * supplying session-id's from other
                                 * processes - spooky :-) */
    } stats;

    int references;

    /* if defined, these override the X509_verify_cert() calls */
    int (*app_verify_callback) (X509_STORE_CTX *, void *);
    void *app_verify_arg;
    /*
     * before OpenSSL 0.9.7, 'app_verify_arg' was ignored
     * ('app_verify_callback' was called with just one argument)
     */

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* get client cert callback */
    int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);

    /* cookie generate callback */
    int (*app_gen_cookie_cb) (SSL *ssl, unsigned char *cookie,
                              unsigned int *cookie_len);

    /* verify cookie callback */
    int (*app_verify_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                 unsigned int cookie_len);

    CRYPTO_EX_DATA ex_data;

    const EVP_MD *md5;          /* For SSLv3/TLSv1 'ssl3-md5' */
    const EVP_MD *sha1;         /* For SSLv3/TLSv1 'ssl3->sha1' */

    STACK_OF(X509) *extra_certs;
    STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */

    /* Default values used when no per-SSL value is defined follow */

    /* used if SSL's info_callback is NULL */
    void (*info_callback) (const SSL *ssl, int type, int val);

    /* what we put in client cert requests */
    STACK_OF(X509_NAME) *client_CA;

    /*
     * Default values to use in SSL structures follow (these are copied by
     * SSL_new)
     */

    uint32_t options;
    uint32_t mode;
    long max_cert_list;

    struct cert_st /* CERT */ *cert;
    int read_ahead;

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;

    uint32_t verify_mode;
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* called 'verify_callback' in the SSL */
    int (*default_verify_callback) (int ok, X509_STORE_CTX *ctx);

    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;

    X509_VERIFY_PARAM *param;

    int quiet_shutdown;

    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    unsigned int max_send_fragment;

#  ifndef OPENSSL_NO_ENGINE
    /*
     * Engine to pass requests for client certs to
     */
    ENGINE *client_cert_engine;
#  endif

    /* TLS extensions servername callback */
    int (*tlsext_servername_callback) (SSL *, int *, void *);
    void *tlsext_servername_arg;
    /* RFC 4507 session ticket keys */
    unsigned char tlsext_tick_key_name[16];
    unsigned char tlsext_tick_hmac_key[16];
    unsigned char tlsext_tick_aes_key[16];
    /* Callback to support customisation of ticket key setting */
    int (*tlsext_ticket_key_cb) (SSL *ssl,
                                 unsigned char *name, unsigned char *iv,
                                 EVP_CIPHER_CTX *ectx,
                                 HMAC_CTX *hctx, int enc);

    /* certificate status request info */
    /* Callback for status request */
    int (*tlsext_status_cb) (SSL *ssl, void *arg);
    void *tlsext_status_arg;

#  ifndef OPENSSL_NO_PSK
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
#  endif

#  ifndef OPENSSL_NO_SRP
    SRP_CTX srp_ctx;            /* ctx for SRP authentication */
#  endif

#  ifndef OPENSSL_NO_NEXTPROTONEG
    /* Next protocol negotiation information */
    /* (for experimental NPN extension). */

    /*
     * For a server, this contains a callback function by which the set of
     * advertised protocols can be provided.
     */
    int (*next_protos_advertised_cb) (SSL *s, const unsigned char **buf,
                                      unsigned int *len, void *arg);
    void *next_protos_advertised_cb_arg;
    /*
     * For a client, this contains a callback function that selects the next
     * protocol from the list provided by the server.
     */
    int (*next_proto_select_cb) (SSL *s, unsigned char **out,
                                 unsigned char *outlen,
                                 const unsigned char *in,
                                 unsigned int inlen, void *arg);
    void *next_proto_select_cb_arg;
#  endif

    /*
     * ALPN information (we are in the process of transitioning from NPN to
     * ALPN.)
     */

        /*-
         * For a server, this contains a callback function that allows the
         * server to select the protocol for the connection.
         *   out: on successful return, this must point to the raw protocol
         *        name (without the length prefix).
         *   outlen: on successful return, this contains the length of |*out|.
         *   in: points to the client's list of supported protocols in
         *       wire-format.
         *   inlen: the length of |in|.
         */
    int (*alpn_select_cb) (SSL *s,
                           const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in,
                           unsigned int inlen, void *arg);
    void *alpn_select_cb_arg;

    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;

    /* SRTP profiles we are willing to do from RFC 5764 */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);
#  ifndef OPENSSL_NO_EC
    /* EC extension values inherited by SSL structure */
    size_t tlsext_ecpointformatlist_length;
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    unsigned char *tlsext_ellipticcurvelist;
#  endif                        /* OPENSSL_NO_EC */
};


struct ssl_st {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;

    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;

    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* where we are */
    OSSL_STATEM statem;

    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * ssl3_get_message() */
    int init_num;               /* amount read/written */
    int init_off;               /* amount read/written */

    struct ssl3_state_st *s3;   /* SSLv3 variables */
    struct dtls1_state_st *d1;  /* DTLSv1 variables */

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
    /* crypto */
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    uint32_t mac_flags;
    EVP_CIPHER_CTX *enc_read_ctx; /* cryptographic state */
    EVP_MD_CTX *read_hash;      /* used for mac generation */
    COMP_CTX *compress;         /* compression */
    COMP_CTX *expand;           /* uncompress */
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;
    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;
    /* Used in SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    uint32_t verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
#  ifndef OPENSSL_NO_PSK
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
#  endif
    SSL_CTX *ctx;
    /*
     * set this flag to 1 and a sleep(1) is put into all SSL_read() and
     * SSL_write() calls, good for nbio debuging :-)
     */
    int debug;
    /* extra application data */
    long verify_result;
    CRYPTO_EX_DATA ex_data;
    /* for server side, keep the list of CA_dn we can use */
    STACK_OF(X509_NAME) *client_CA;
    int references;
    /* protocol behaviour */
    uint32_t options;
    /* API behaviour */
    uint32_t mode;
    long max_cert_list;
    int first_packet;
    /* what was passed, used for SSLv3/TLS rollback check */
    int client_version;
    unsigned int max_send_fragment;

    /* TLS extension debug callback */
    void (*tlsext_debug_cb) (SSL *s, int client_server, int type,
                             unsigned char *data, int len, void *arg);
    void *tlsext_debug_arg;
    char *tlsext_hostname;
    /*-
     * no further mod of servername
     * 0 : call the servername extension callback.
     * 1 : prepare 2, allow last ack just after in server callback.
     * 2 : don't call servername callback, no ack in server hello
     */
    int servername_done;
    /* certificate status request info */
    /* Status type or -1 if no status type */
    int tlsext_status_type;
    /* Expect OCSP CertificateStatus message */
    int tlsext_status_expected;
    /* OCSP status request only */
    STACK_OF(OCSP_RESPID) *tlsext_ocsp_ids;
    X509_EXTENSIONS *tlsext_ocsp_exts;
    /* OCSP response received or to be sent */
    unsigned char *tlsext_ocsp_resp;
    int tlsext_ocsp_resplen;
    /* RFC4507 session ticket expected to be received or sent */
    int tlsext_ticket_expected;
#  ifndef OPENSSL_NO_EC
    size_t tlsext_ecpointformatlist_length;
    /* our list */
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    /* our list */
    unsigned char *tlsext_ellipticcurvelist;
#  endif                       /* OPENSSL_NO_EC */
    /* TLS Session Ticket extension override */
    TLS_SESSION_TICKET_EXT *tlsext_session_ticket;
    /* TLS Session Ticket extension callback */
    tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
    void *tls_session_ticket_ext_cb_arg;
    /* TLS pre-shared secret session resumption */
    tls_session_secret_cb_fn tls_session_secret_cb;
    void *tls_session_secret_cb_arg;
    SSL_CTX *initial_ctx;       /* initial ctx, used to store sessions */
#  ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * Next protocol negotiation. For the client, this is the protocol that
     * we sent in NextProtocol and is set when handling ServerHello
     * extensions. For a server, this is the client's selected_protocol from
     * NextProtocol and is set when handling the NextProtocol message, before
     * the Finished message.
     */
    unsigned char *next_proto_negotiated;
    unsigned char next_proto_negotiated_len;
#  endif
#  define session_ctx initial_ctx
    /* What we'll do */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /* What's been chosen */
    SRTP_PROTECTION_PROFILE *srtp_profile;
        /*-
         * Is use of the Heartbeat extension negotiated?
         *  0: disabled
         *  1: enabled
         *  2: enabled, but not allowed to send Requests
         */
    unsigned int tlsext_heartbeat;
    /* Indicates if a HeartbeatRequest is in flight */
    unsigned int tlsext_hb_pending;
    /* HeartbeatRequest sequence number */
    unsigned int tlsext_hb_seq;
    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;

    /*-
     * 1 if we are renegotiating.
     * 2 if we are a server and are inside a handshake
     * (i.e. not just sending a HelloRequest)
     */
    int renegotiate;
#  ifndef OPENSSL_NO_SRP
    /* ctx for SRP authentication */
    SRP_CTX srp_ctx;
#  endif
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);
    
    RECORD_LAYER rlayer;

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* Async Job info */
    ASYNC_JOB *job;
};


typedef struct ssl3_state_st {
    long flags;
    int read_mac_secret_size;
    unsigned char read_mac_secret[EVP_MAX_MD_SIZE];
    int write_mac_secret_size;
    unsigned char write_mac_secret[EVP_MAX_MD_SIZE];
    unsigned char server_random[SSL3_RANDOM_SIZE];
    unsigned char client_random[SSL3_RANDOM_SIZE];
    /* flags for countermeasure against known-IV weakness */
    int need_empty_fragments;
    int empty_fragment_done;
    /* The value of 'extra' when the buffers were initialized */
    int init_extra;
    /* used during startup, digest all incoming/outgoing packets */
    BIO *handshake_buffer;
    /*
     * When handshake digest is determined, buffer is hashed and
     * freed and MD_CTX for the required digest is stored here.
     */
    EVP_MD_CTX *handshake_dgst;
    /*
     * Set whenever an expected ChangeCipherSpec message is processed.
     * Unset when the peer's Finished message is received.
     * Unexpected ChangeCipherSpec messages trigger a fatal alert.
     */
    int change_cipher_spec;
    int warn_alert;
    int fatal_alert;
    /*
     * we allow one fatal and one warning alert to be outstanding, send close
     * alert via the warning alert
     */
    int alert_dispatch;
    unsigned char send_alert[2];
    /*
     * This flag is set when we should renegotiate ASAP, basically when there
     * is no more data in the read or write buffers
     */
    int renegotiate;
    int total_renegotiations;
    int num_renegotiations;
    int in_read_app_data;
    struct {
        /* actually only need to be 16+20 for SSLv3 and 12 for TLS */
        unsigned char finish_md[EVP_MAX_MD_SIZE * 2];
        int finish_md_len;
        unsigned char peer_finish_md[EVP_MAX_MD_SIZE * 2];
        int peer_finish_md_len;
        unsigned long message_size;
        int message_type;
        /* used to hold the new cipher we are going to use */
        const SSL_CIPHER *new_cipher;
#  ifndef OPENSSL_NO_DH
        DH *dh;
#  endif
#  ifndef OPENSSL_NO_EC
        EC_KEY *ecdh;           /* holds short lived ECDH key */
#  endif
        /* used for certificate requests */
        int cert_req;
        int ctype_num;
        char ctype[SSL3_CT_NUMBER];
        STACK_OF(X509_NAME) *ca_names;
        int use_rsa_tmp;
        int key_block_length;
        unsigned char *key_block;
        const EVP_CIPHER *new_sym_enc;
        const EVP_MD *new_hash;
        int new_mac_pkey_type;
        int new_mac_secret_size;
#  ifndef OPENSSL_NO_COMP
        const SSL_COMP *new_compression;
#  else
        char *new_compression;
#  endif
        int cert_request;
        /* Raw values of the cipher list from a client */
        unsigned char *ciphers_raw;
        size_t ciphers_rawlen;
        /* Temporary storage for premaster secret */
        unsigned char *pms;
        size_t pmslen;
#ifndef OPENSSL_NO_PSK
        /* Temporary storage for PSK key */
        unsigned char *psk;
        size_t psklen;
#endif
        /*
         * signature algorithms peer reports: e.g. supported signature
         * algorithms extension for server or as part of a certificate
         * request for client.
         */
        unsigned char *peer_sigalgs;
        /* Size of above array */
        size_t peer_sigalgslen;
        /* Digest peer uses for signing */
        const EVP_MD *peer_md;
        /* Array of digests used for signing */
        const EVP_MD *md[SSL_PKEY_NUM];
        /*
         * Set if corresponding CERT_PKEY can be used with current
         * SSL session: e.g. appropriate curve, signature algorithms etc.
         * If zero it can't be used at all.
         */
        uint32_t valid_flags[SSL_PKEY_NUM];
        /*
         * For servers the following masks are for the key and auth algorithms
         * that are supported by the certs below. For clients they are masks of
         * *disabled* algorithms based on the current session.
         */
        uint32_t mask_k;
        uint32_t mask_a;
        uint32_t export_mask_k;
        uint32_t export_mask_a;
        /* Client only */
        uint32_t mask_ssl;
    } tmp;

    /* Connection binding to prevent renegotiation attacks */
    unsigned char previous_client_finished[EVP_MAX_MD_SIZE];
    unsigned char previous_client_finished_len;
    unsigned char previous_server_finished[EVP_MAX_MD_SIZE];
    unsigned char previous_server_finished_len;
    int send_connection_binding; /* TODOEKR */

#  ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * Set if we saw the Next Protocol Negotiation extension from our peer.
     */
    int next_proto_neg_seen;
#  endif

    /*
     * ALPN information (we are in the process of transitioning from NPN to
     * ALPN.)
     */

    /*
     * In a server these point to the selected ALPN protocol after the
     * ClientHello has been processed. In a client these contain the protocol
     * that the server selected once the ServerHello has been processed.
     */
    unsigned char *alpn_selected;
    unsigned alpn_selected_len;

#   ifndef OPENSSL_NO_EC
    /*
     * This is set to true if we believe that this is a version of Safari
     * running on OS X 10.6 or newer. We wish to know this because Safari on
     * 10.8 .. 10.8.3 has broken ECDHE-ECDSA support.
     */
    char is_probably_safari;
#   endif                       /* !OPENSSL_NO_EC */

    /* For clients: peer temporary key */
# ifndef OPENSSL_NO_RSA
    RSA *peer_rsa_tmp;
# endif
# ifndef OPENSSL_NO_DH
    DH *peer_dh_tmp;
# endif
# ifndef OPENSSL_NO_EC
    EC_KEY *peer_ecdh_tmp;
# endif

} SSL3_STATE;


/* DTLS structures */

#  ifndef OPENSSL_NO_SCTP
#   define DTLS1_SCTP_AUTH_LABEL   "EXPORTER_DTLS_OVER_SCTP"
#  endif

/* Max MTU overhead we know about so far is 40 for IPv6 + 8 for UDP */
#  define DTLS1_MAX_MTU_OVERHEAD                   48

/*
 * Flag used in message reuse to indicate the buffer contains the record
 * header as well as the the handshake message header.
 */
#  define DTLS1_SKIP_RECORD_HEADER                 2

struct dtls1_retransmit_state {
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
    COMP_CTX *compress;         /* compression */
    SSL_SESSION *session;
    unsigned short epoch;
};

struct hm_header_st {
    unsigned char type;
    unsigned long msg_len;
    unsigned short seq;
    unsigned long frag_off;
    unsigned long frag_len;
    unsigned int is_ccs;
    struct dtls1_retransmit_state saved_retransmit_state;
};

struct dtls1_timeout_st {
    /* Number of read timeouts so far */
    unsigned int read_timeouts;
    /* Number of write timeouts so far */
    unsigned int write_timeouts;
    /* Number of alerts received so far */
    unsigned int num_alerts;
};

typedef struct hm_fragment_st {
    struct hm_header_st msg_header;
    unsigned char *fragment;
    unsigned char *reassembly;
} hm_fragment;

typedef struct dtls1_state_st {
    unsigned char cookie[DTLS1_COOKIE_LENGTH];
    unsigned int cookie_len;
    unsigned int cookie_verified;

    /* handshake message numbers */
    unsigned short handshake_write_seq;
    unsigned short next_handshake_write_seq;
    unsigned short handshake_read_seq;

    /* Buffered handshake messages */
    pqueue buffered_messages;
    /* Buffered (sent) handshake records */
    pqueue sent_messages;

    unsigned int link_mtu;      /* max on-the-wire DTLS packet size */
    unsigned int mtu;           /* max DTLS packet size */
    struct hm_header_st w_msg_hdr;
    struct hm_header_st r_msg_hdr;
    struct dtls1_timeout_st timeout;
    /*
     * Indicates when the last handshake msg or heartbeat sent will timeout
     */
    struct timeval next_timeout;
    /* Timeout duration */
    unsigned short timeout_duration;

    unsigned int retransmitting;
#  ifndef OPENSSL_NO_SCTP
    int shutdown_received;
#  endif
} DTLS1_STATE;



# ifndef OPENSSL_NO_EC
/*
 * From ECC-TLS draft, used in encoding the curve type in ECParameters
 */
#  define EXPLICIT_PRIME_CURVE_TYPE  1
#  define EXPLICIT_CHAR2_CURVE_TYPE  2
#  define NAMED_CURVE_TYPE           3
# endif                         /* OPENSSL_NO_EC */

typedef struct cert_pkey_st {
    X509 *x509;
    EVP_PKEY *privatekey;
    /* Chain for this certificate */
    STACK_OF(X509) *chain;

    /*-
     * serverinfo data for this certificate.  The data is in TLS Extension
     * wire format, specifically it's a series of records like:
     *   uint16_t extension_type; // (RFC 5246, 7.4.1.4, Extension)
     *   uint16_t length;
     *   uint8_t data[length];
     */
    unsigned char *serverinfo;
    size_t serverinfo_length;
} CERT_PKEY;
/* Retrieve Suite B flags */
# define tls1_suiteb(s)  (s->cert->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS)
/* Uses to check strict mode: suite B modes are always strict */
# define SSL_CERT_FLAGS_CHECK_TLS_STRICT \
        (SSL_CERT_FLAG_SUITEB_128_LOS|SSL_CERT_FLAG_TLS_STRICT)

typedef struct {
    unsigned short ext_type;
    /*
     * Per-connection flags relating to this extension type: not used if
     * part of an SSL_CTX structure.
     */
    uint32_t ext_flags;
    custom_ext_add_cb add_cb;
    custom_ext_free_cb free_cb;
    void *add_arg;
    custom_ext_parse_cb parse_cb;
    void *parse_arg;
} custom_ext_method;

/* ext_flags values */

/*
 * Indicates an extension has been received. Used to check for unsolicited or
 * duplicate extensions.
 */
# define SSL_EXT_FLAG_RECEIVED   0x1
/*
 * Indicates an extension has been sent: used to enable sending of
 * corresponding ServerHello extension.
 */
# define SSL_EXT_FLAG_SENT       0x2

typedef struct {
    custom_ext_method *meths;
    size_t meths_count;
} custom_ext_methods;

typedef struct cert_st {
    /* Current active set */
    /*
     * ALWAYS points to an element of the pkeys array
     * Probably it would make more sense to store
     * an index, not a pointer.
     */
    CERT_PKEY *key;
# ifndef OPENSSL_NO_RSA
    RSA *rsa_tmp;
    RSA *(*rsa_tmp_cb) (SSL *ssl, int is_export, int keysize);
# endif
# ifndef OPENSSL_NO_DH
    DH *dh_tmp;
    DH *(*dh_tmp_cb) (SSL *ssl, int is_export, int keysize);
    int dh_tmp_auto;
# endif
# ifndef OPENSSL_NO_EC
    EC_KEY *ecdh_tmp;
    /* Callback for generating ephemeral ECDH keys */
    EC_KEY *(*ecdh_tmp_cb) (SSL *ssl, int is_export, int keysize);
    /* Select ECDH parameters automatically */
    int ecdh_tmp_auto;
# endif
    /* Flags related to certificates */
    uint32_t cert_flags;
    CERT_PKEY pkeys[SSL_PKEY_NUM];
    /*
     * Certificate types (received or sent) in certificate request message.
     * On receive this is only set if number of certificate types exceeds
     * SSL3_CT_NUMBER.
     */
    unsigned char *ctypes;
    size_t ctype_num;
    /*
     * suppported signature algorithms. When set on a client this is sent in
     * the client hello as the supported signature algorithms extension. For
     * servers it represents the signature algorithms we are willing to use.
     */
    unsigned char *conf_sigalgs;
    /* Size of above array */
    size_t conf_sigalgslen;
    /*
     * Client authentication signature algorithms, if not set then uses
     * conf_sigalgs. On servers these will be the signature algorithms sent
     * to the client in a cerificate request for TLS 1.2. On a client this
     * represents the signature algortithms we are willing to use for client
     * authentication.
     */
    unsigned char *client_sigalgs;
    /* Size of above array */
    size_t client_sigalgslen;
    /*
     * Signature algorithms shared by client and server: cached because these
     * are used most often.
     */
    TLS_SIGALGS *shared_sigalgs;
    size_t shared_sigalgslen;
    /*
     * Certificate setup callback: if set is called whenever a certificate
     * may be required (client or server). the callback can then examine any
     * appropriate parameters and setup any certificates required. This
     * allows advanced applications to select certificates on the fly: for
     * example based on supported signature algorithms or curves.
     */
    int (*cert_cb) (SSL *ssl, void *arg);
    void *cert_cb_arg;
    /*
     * Optional X509_STORE for chain building or certificate validation If
     * NULL the parent SSL_CTX store is used instead.
     */
    X509_STORE *chain_store;
    X509_STORE *verify_store;
    /* Custom extension methods for server and client */
    custom_ext_methods cli_ext;
    custom_ext_methods srv_ext;
    /* Security callback */
    int (*sec_cb) (SSL *s, SSL_CTX *ctx, int op, int bits, int nid,
                   void *other, void *ex);
    /* Security level */
    int sec_level;
    void *sec_ex;
#ifndef OPENSSL_NO_PSK
    /* If not NULL psk identity hint to use for servers */
    char *psk_identity_hint;
#endif
    int references;             /* >1 only if SSL_copy_session_id is used */
} CERT;

/* Structure containing decoded values of signature algorithms extension */
struct tls_sigalgs_st {
    /* NID of hash algorithm */
    int hash_nid;
    /* NID of signature algorithm */
    int sign_nid;
    /* Combined hash and signature NID */
    int signandhash_nid;
    /* Raw values used in extension */
    unsigned char rsign;
    unsigned char rhash;
};

/*
 * #define MAC_DEBUG
 */

/*
 * #define ERR_DEBUG
 */
/*
 * #define ABORT_DEBUG
 */
/*
 * #define PKT_DEBUG 1
 */
/*
 * #define DES_DEBUG
 */
/*
 * #define DES_OFB_DEBUG
 */
/*
 * #define SSL_DEBUG
 */
/*
 * #define RSA_DEBUG
 */
/*
 * #define IDEA_DEBUG
 */

# define FP_ICC  (int (*)(const void *,const void *))

/*
 * This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff It is a bit
 * of a mess of functions, but hell, think of it as an opaque structure :-)
 */
typedef struct ssl3_enc_method {
    int (*enc) (SSL *, int);
    int (*mac) (SSL *, unsigned char *, int);
    int (*setup_key_block) (SSL *);
    int (*generate_master_secret) (SSL *, unsigned char *, unsigned char *,
                                   int);
    int (*change_cipher_state) (SSL *, int);
    int (*final_finish_mac) (SSL *, const char *, int, unsigned char *);
    int finish_mac_length;
    const char *client_finished_label;
    int client_finished_label_len;
    const char *server_finished_label;
    int server_finished_label_len;
    int (*alert_value) (int);
    int (*export_keying_material) (SSL *, unsigned char *, size_t,
                                   const char *, size_t,
                                   const unsigned char *, size_t,
                                   int use_context);
    /* Various flags indicating protocol version requirements */
    uint32_t enc_flags;
    /* Handshake header length */
    unsigned int hhlen;
    /* Set the handshake header */
    int (*set_handshake_header) (SSL *s, int type, unsigned long len);
    /* Write out handshake message */
    int (*do_write) (SSL *s);
} SSL3_ENC_METHOD;

# define SSL_HM_HEADER_LENGTH(s) s->method->ssl3_enc->hhlen
# define ssl_handshake_start(s) \
        (((unsigned char *)s->init_buf->data) + s->method->ssl3_enc->hhlen)
# define ssl_set_handshake_header(s, htype, len) \
        s->method->ssl3_enc->set_handshake_header(s, htype, len)
# define ssl_do_write(s)  s->method->ssl3_enc->do_write(s)

/* Values for enc_flags */

/* Uses explicit IV for CBC mode */
# define SSL_ENC_FLAG_EXPLICIT_IV        0x1
/* Uses signature algorithms extension */
# define SSL_ENC_FLAG_SIGALGS            0x2
/* Uses SHA256 default PRF */
# define SSL_ENC_FLAG_SHA256_PRF         0x4
/* Is DTLS */
# define SSL_ENC_FLAG_DTLS               0x8
/*
 * Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2: may
 * apply to others in future.
 */
# define SSL_ENC_FLAG_TLS1_2_CIPHERS     0x10

# ifndef OPENSSL_NO_COMP
/* Used for holding the relevant compression methods loaded into SSL_CTX */
typedef struct ssl3_comp_st {
    int comp_id;                /* The identifier byte for this compression
                                 * type */
    char *name;                 /* Text name used for the compression type */
    COMP_METHOD *method;        /* The method :-) */
} SSL3_COMP;
# endif

extern SSL3_ENC_METHOD ssl3_undef_enc_method;
OPENSSL_EXTERN const SSL_CIPHER ssl3_ciphers[];

SSL_METHOD *ssl_bad_method(int ver);

extern const SSL3_ENC_METHOD TLSv1_enc_data;
extern const SSL3_ENC_METHOD TLSv1_1_enc_data;
extern const SSL3_ENC_METHOD TLSv1_2_enc_data;
extern const SSL3_ENC_METHOD SSLv3_enc_data;
extern const SSL3_ENC_METHOD DTLSv1_enc_data;
extern const SSL3_ENC_METHOD DTLSv1_2_enc_data;

# define IMPLEMENT_tls_meth_func(version, func_name, s_accept, s_connect, \
                                s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                tls1_new, \
                tls1_clear, \
                tls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_read_bytes, \
                ssl3_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                s_get_meth, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

# define IMPLEMENT_ssl3_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                SSL3_VERSION, \
                ssl3_new, \
                ssl3_clear, \
                ssl3_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_read_bytes, \
                ssl3_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                s_get_meth, \
                ssl3_default_timeout, \
                &SSLv3_enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

# define IMPLEMENT_dtls1_meth_func(version, func_name, s_accept, s_connect, \
                                        s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                dtls1_new, \
                dtls1_clear, \
                dtls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                dtls1_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                dtls1_read_bytes, \
                dtls1_write_app_data_bytes, \
                dtls1_dispatch_alert, \
                dtls1_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                dtls1_get_cipher, \
                s_get_meth, \
                dtls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

struct openssl_ssl_test_functions {
    int (*p_ssl_init_wbio_buffer) (SSL *s, int push);
    int (*p_ssl3_setup_buffers) (SSL *s);
    int (*p_tls1_process_heartbeat) (SSL *s,
        unsigned char *p, unsigned int length);
    int (*p_dtls1_process_heartbeat) (SSL *s,
        unsigned char *p, unsigned int length);
};

# ifndef OPENSSL_UNIT_TEST

void ssl_clear_cipher_ctx(SSL *s);
int ssl_clear_bad_session(SSL *s);
__owur CERT *ssl_cert_new(void);
__owur CERT *ssl_cert_dup(CERT *cert);
void ssl_cert_clear_certs(CERT *c);
void ssl_cert_free(CERT *c);
__owur int ssl_get_new_session(SSL *s, int session);
__owur int ssl_get_prev_session(SSL *s, const PACKET *ext,
                                const PACKET *session_id);
__owur SSL_SESSION *ssl_session_dup(SSL_SESSION *src, int ticket);
__owur int ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b);
DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
__owur int ssl_cipher_ptr_id_cmp(const SSL_CIPHER *const *ap,
                          const SSL_CIPHER *const *bp);
__owur STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *meth,
                                             STACK_OF(SSL_CIPHER) **pref,
                                             STACK_OF(SSL_CIPHER) **sorted,
                                             const char *rule_str, CERT *c);
void ssl_update_cache(SSL *s, int mode);
__owur int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
                       const EVP_MD **md, int *mac_pkey_type,
                       int *mac_secret_size, SSL_COMP **comp, int use_etm);
__owur int ssl_cipher_get_cert_index(const SSL_CIPHER *c);
__owur const SSL_CIPHER *ssl_get_cipher_by_char(SSL *ssl, const unsigned char *ptr);
__owur int ssl_cert_set0_chain(SSL *s, SSL_CTX *ctx, STACK_OF(X509) *chain);
__owur int ssl_cert_set1_chain(SSL *s, SSL_CTX *ctx, STACK_OF(X509) *chain);
__owur int ssl_cert_add0_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x);
__owur int ssl_cert_add1_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x);
__owur int ssl_cert_select_current(CERT *c, X509 *x);
__owur int ssl_cert_set_current(CERT *c, long arg);
__owur X509 *ssl_cert_get0_next_certificate(CERT *c, int first);
void ssl_cert_set_cert_cb(CERT *c, int (*cb) (SSL *ssl, void *arg),
                          void *arg);

__owur int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk);
__owur int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l);
__owur int ssl_build_cert_chain(SSL *s, SSL_CTX *ctx, int flags);
__owur int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref);

__owur int ssl_security(SSL *s, int op, int bits, int nid, void *other);
__owur int ssl_ctx_security(SSL_CTX *ctx, int op, int bits, int nid, void *other);

int ssl_undefined_function(SSL *s);
__owur int ssl_undefined_void_function(void);
__owur int ssl_undefined_const_function(const SSL *s);
__owur CERT_PKEY *ssl_get_server_send_pkey(SSL *s);
__owur int ssl_get_server_cert_serverinfo(SSL *s, const unsigned char **serverinfo,
                                   size_t *serverinfo_length);
__owur EVP_PKEY *ssl_get_sign_pkey(SSL *s, const SSL_CIPHER *c, const EVP_MD **pmd);
__owur int ssl_cert_type(X509 *x, EVP_PKEY *pkey);
void ssl_set_masks(SSL *s, const SSL_CIPHER *cipher);
__owur STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *s);
__owur int ssl_verify_alarm_type(long type);
void ssl_load_ciphers(void);
__owur int ssl_fill_hello_random(SSL *s, int server, unsigned char *field, int len);
__owur int ssl_generate_master_secret(SSL *s, unsigned char *pms, size_t pmslen,
                                      int free_pms);

__owur const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p);
__owur int ssl3_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p);
void ssl3_init_finished_mac(SSL *s);
__owur int ssl3_setup_key_block(SSL *s);
__owur int ssl3_change_cipher_state(SSL *s, int which);
void ssl3_cleanup_key_block(SSL *s);
__owur int ssl3_do_write(SSL *s, int type);
int ssl3_send_alert(SSL *s, int level, int desc);
__owur int ssl3_generate_master_secret(SSL *s, unsigned char *out,
                                unsigned char *p, int len);
__owur int ssl3_get_req_cert_type(SSL *s, unsigned char *p);
__owur int ssl3_num_ciphers(void);
__owur const SSL_CIPHER *ssl3_get_cipher(unsigned int u);
int ssl3_renegotiate(SSL *ssl);
int ssl3_renegotiate_check(SSL *ssl);
__owur int ssl3_dispatch_alert(SSL *s);
__owur int ssl3_final_finish_mac(SSL *s, const char *sender, int slen,
                          unsigned char *p);
void ssl3_finish_mac(SSL *s, const unsigned char *buf, int len);
void ssl3_free_digest_list(SSL *s);
__owur unsigned long ssl3_output_cert_chain(SSL *s, CERT_PKEY *cpk);
__owur SSL_CIPHER *ssl3_choose_cipher(SSL *ssl, STACK_OF(SSL_CIPHER) *clnt,
                               STACK_OF(SSL_CIPHER) *srvr);
__owur int ssl3_digest_cached_records(SSL *s, int keep);
__owur int ssl3_new(SSL *s);
void ssl3_free(SSL *s);
__owur int ssl3_read(SSL *s, void *buf, int len);
__owur int ssl3_peek(SSL *s, void *buf, int len);
__owur int ssl3_write(SSL *s, const void *buf, int len);
__owur int ssl3_shutdown(SSL *s);
void ssl3_clear(SSL *s);
__owur long ssl3_ctrl(SSL *s, int cmd, long larg, void *parg);
__owur long ssl3_ctx_ctrl(SSL_CTX *s, int cmd, long larg, void *parg);
__owur long ssl3_callback_ctrl(SSL *s, int cmd, void (*fp) (void));
__owur long ssl3_ctx_callback_ctrl(SSL_CTX *s, int cmd, void (*fp) (void));

__owur int ssl3_do_change_cipher_spec(SSL *ssl);
__owur long ssl3_default_timeout(void);

__owur int ssl3_set_handshake_header(SSL *s, int htype, unsigned long len);
__owur int ssl3_handshake_write(SSL *s);

__owur int ssl_allow_compression(SSL *s);

__owur long tls1_default_timeout(void);
__owur int dtls1_do_write(SSL *s, int type);
void dtls1_set_message_header(SSL *s,
                              unsigned char *p, unsigned char mt,
                              unsigned long len,
                              unsigned long frag_off,
                              unsigned long frag_len);

__owur int dtls1_write_app_data_bytes(SSL *s, int type, const void *buf, int len);

__owur int dtls1_read_failed(SSL *s, int code);
__owur int dtls1_buffer_message(SSL *s, int ccs);
__owur int dtls1_retransmit_message(SSL *s, unsigned short seq,
                             unsigned long frag_off, int *found);
__owur int dtls1_get_queue_priority(unsigned short seq, int is_ccs);
int dtls1_retransmit_buffered_messages(SSL *s);
void dtls1_clear_record_buffer(SSL *s);
void dtls1_get_message_header(unsigned char *data,
                              struct hm_header_st *msg_hdr);
__owur long dtls1_default_timeout(void);
__owur struct timeval *dtls1_get_timeout(SSL *s, struct timeval *timeleft);
__owur int dtls1_check_timeout_num(SSL *s);
__owur int dtls1_handle_timeout(SSL *s);
__owur const SSL_CIPHER *dtls1_get_cipher(unsigned int u);
void dtls1_start_timer(SSL *s);
void dtls1_stop_timer(SSL *s);
__owur int dtls1_is_timer_expired(SSL *s);
void dtls1_double_timeout(SSL *s);
__owur unsigned int dtls_raw_hello_verify_request(unsigned char *buf,
                                                  unsigned char *cookie,
                                                  unsigned char cookie_len);
__owur int dtls1_send_newsession_ticket(SSL *s);
__owur unsigned int dtls1_min_mtu(SSL *s);
void dtls1_hm_fragment_free(hm_fragment *frag);
__owur int dtls1_query_mtu(SSL *s);

__owur int tls1_new(SSL *s);
void tls1_free(SSL *s);
void tls1_clear(SSL *s);
long tls1_ctrl(SSL *s, int cmd, long larg, void *parg);
long tls1_callback_ctrl(SSL *s, int cmd, void (*fp) (void));

__owur int dtls1_new(SSL *s);
void dtls1_free(SSL *s);
void dtls1_clear(SSL *s);
long dtls1_ctrl(SSL *s, int cmd, long larg, void *parg);
__owur int dtls1_shutdown(SSL *s);

__owur int dtls1_dispatch_alert(SSL *s);

__owur int ssl_init_wbio_buffer(SSL *s, int push);
void ssl_free_wbio_buffer(SSL *s);

__owur int tls1_change_cipher_state(SSL *s, int which);
__owur int tls1_setup_key_block(SSL *s);
__owur int tls1_final_finish_mac(SSL *s,
                          const char *str, int slen, unsigned char *p);
__owur int tls1_generate_master_secret(SSL *s, unsigned char *out,
                                unsigned char *p, int len);
__owur int tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                                const char *label, size_t llen,
                                const unsigned char *p, size_t plen,
                                int use_context);
__owur int tls1_alert_code(int code);
__owur int ssl3_alert_code(int code);
__owur int ssl_ok(SSL *s);

#  ifndef OPENSSL_NO_EC
__owur int ssl_check_srvr_ecc_cert_and_alg(X509 *x, SSL *s);
#  endif

SSL_COMP *ssl3_comp_find(STACK_OF(SSL_COMP) *sk, int n);

#  ifndef OPENSSL_NO_EC
__owur int tls1_ec_curve_id2nid(int curve_id);
__owur int tls1_ec_nid2curve_id(int nid);
__owur int tls1_check_curve(SSL *s, const unsigned char *p, size_t len);
__owur int tls1_shared_curve(SSL *s, int nmatch);
__owur int tls1_set_curves(unsigned char **pext, size_t *pextlen,
                    int *curves, size_t ncurves);
__owur int tls1_set_curves_list(unsigned char **pext, size_t *pextlen,
                         const char *str);
__owur int tls1_check_ec_tmp_key(SSL *s, unsigned long id);
#  endif                        /* OPENSSL_NO_EC */

__owur int tls1_shared_list(SSL *s,
                     const unsigned char *l1, size_t l1len,
                     const unsigned char *l2, size_t l2len, int nmatch);
__owur unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *buf,
                                          unsigned char *limit, int *al);
__owur unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *buf,
                                          unsigned char *limit, int *al);
__owur int ssl_parse_clienthello_tlsext(SSL *s, PACKET *pkt);
void ssl_set_default_md(SSL *s);
__owur int tls1_set_server_sigalgs(SSL *s);
__owur int ssl_check_clienthello_tlsext_late(SSL *s);
__owur int ssl_parse_serverhello_tlsext(SSL *s, PACKET *pkt);
__owur int ssl_prepare_clienthello_tlsext(SSL *s);
__owur int ssl_prepare_serverhello_tlsext(SSL *s);

#  ifndef OPENSSL_NO_HEARTBEATS
__owur int tls1_heartbeat(SSL *s);
__owur int dtls1_heartbeat(SSL *s);
__owur int tls1_process_heartbeat(SSL *s, unsigned char *p, unsigned int length);
__owur int dtls1_process_heartbeat(SSL *s, unsigned char *p, unsigned int length);
#  endif

__owur int tls1_process_ticket(SSL *s, const PACKET *ext,
                               const PACKET *session_id, SSL_SESSION **ret);

__owur int tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk,
                         const EVP_MD *md);
__owur int tls12_get_sigid(const EVP_PKEY *pk);
__owur const EVP_MD *tls12_get_hash(unsigned char hash_alg);
void ssl_set_sig_mask(uint32_t *pmask_a, SSL *s, int op);

__owur int tls1_set_sigalgs_list(CERT *c, const char *str, int client);
__owur int tls1_set_sigalgs(CERT *c, const int *salg, size_t salglen, int client);
int tls1_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain,
                     int idx);
void tls1_set_cert_validity(SSL *s);

#  ifndef OPENSSL_NO_DH
__owur DH *ssl_get_auto_dh(SSL *s);
#  endif

__owur int ssl_security_cert(SSL *s, SSL_CTX *ctx, X509 *x, int vfy, int is_ee);
__owur int ssl_security_cert_chain(SSL *s, STACK_OF(X509) *sk, X509 *ex, int vfy);

__owur EVP_MD_CTX *ssl_replace_hash(EVP_MD_CTX **hash, const EVP_MD *md);
void ssl_clear_hash_ctx(EVP_MD_CTX **hash);
__owur int ssl_add_serverhello_renegotiate_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen);
__owur int ssl_parse_serverhello_renegotiate_ext(SSL *s, PACKET *pkt,
                                          int *al);
__owur int ssl_add_clienthello_renegotiate_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen);
__owur int ssl_parse_clienthello_renegotiate_ext(SSL *s, PACKET *pkt, int *al);
__owur long ssl_get_algorithm2(SSL *s);
__owur size_t tls12_copy_sigalgs(SSL *s, unsigned char *out,
                          const unsigned char *psig, size_t psiglen);
__owur int tls1_save_sigalgs(SSL *s, const unsigned char *data, int dsize);
__owur int tls1_process_sigalgs(SSL *s);
__owur size_t tls12_get_psigalgs(SSL *s, const unsigned char **psigs);
__owur int tls12_check_peer_sigalg(const EVP_MD **pmd, SSL *s,
                            const unsigned char *sig, EVP_PKEY *pkey);
void ssl_set_client_disabled(SSL *s);
__owur int ssl_cipher_disabled(SSL *s, const SSL_CIPHER *c, int op);

__owur int ssl_add_clienthello_use_srtp_ext(SSL *s, unsigned char *p, int *len,
                                     int maxlen);
__owur int ssl_parse_clienthello_use_srtp_ext(SSL *s, PACKET *pkt, int *al);
__owur int ssl_add_serverhello_use_srtp_ext(SSL *s, unsigned char *p, int *len,
                                     int maxlen);
__owur int ssl_parse_serverhello_use_srtp_ext(SSL *s, PACKET *pkt, int *al);

__owur int ssl_handshake_hash(SSL *s, unsigned char *out, int outlen);
__owur const EVP_MD *ssl_md(int idx);
__owur const EVP_MD *ssl_handshake_md(SSL *s);
__owur const EVP_MD *ssl_prf_md(SSL *s);

/* s3_cbc.c */
__owur char ssl3_cbc_record_digest_supported(const EVP_MD_CTX *ctx);
__owur int ssl3_cbc_digest_record(const EVP_MD_CTX *ctx,
                                  unsigned char *md_out,
                                  size_t *md_out_size,
                                  const unsigned char header[13],
                                  const unsigned char *data,
                                  size_t data_plus_mac_size,
                                  size_t data_plus_mac_plus_padding_size,
                                  const unsigned char *mac_secret,
                                  unsigned mac_secret_length, char is_sslv3);

void tls_fips_digest_extra(const EVP_CIPHER_CTX *cipher_ctx,
                           EVP_MD_CTX *mac_ctx, const unsigned char *data,
                           size_t data_len, size_t orig_len);

__owur int srp_generate_server_master_secret(SSL *s);
__owur int srp_generate_client_master_secret(SSL *s);
__owur int srp_verify_server_param(SSL *s, int *al);

/* t1_ext.c */

void custom_ext_init(custom_ext_methods *meths);

__owur int custom_ext_parse(SSL *s, int server,
                     unsigned int ext_type,
                     const unsigned char *ext_data, size_t ext_size, int *al);
__owur int custom_ext_add(SSL *s, int server,
                   unsigned char **pret, unsigned char *limit, int *al);

__owur int custom_exts_copy(custom_ext_methods *dst, const custom_ext_methods *src);
void custom_exts_free(custom_ext_methods *exts);

# else

#  define ssl_init_wbio_buffer SSL_test_functions()->p_ssl_init_wbio_buffer
#  define ssl3_setup_buffers SSL_test_functions()->p_ssl3_setup_buffers
#  define tls1_process_heartbeat SSL_test_functions()->p_tls1_process_heartbeat
#  define dtls1_process_heartbeat SSL_test_functions()->p_dtls1_process_heartbeat

# endif
#endif
