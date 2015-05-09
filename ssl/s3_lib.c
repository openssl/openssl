/* $OpenBSD: s3_lib.c,v 1.68 2014/07/10 08:51:14 tedu Exp $ */
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
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
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

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"
#include "../crypto/ec/ec_lcl.h"
#include <openssl/md5.h>
#include <openssl/dh.h>

#define SSL3_NUM_CIPHERS	(sizeof(ssl3_ciphers) / sizeof(SSL_CIPHER))

/*
 * FIXED_NONCE_LEN is a macro that provides in the correct value to set the
 * fixed nonce length in algorithms2. It is the inverse of the
 * SSL_CIPHER_AEAD_FIXED_NONCE_LEN macro.
 */
#define FIXED_NONCE_LEN(x) (((x / 2) & 0xf) << 24)

/* list of available SSLv3 ciphers (sorted by id) */
SSL_CIPHER ssl3_ciphers[] = {

	/* The RSA ciphers */
	/* Cipher 01 */
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_NULL_MD5,
		.id = SSL3_CK_RSA_NULL_MD5,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher 02 */
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_NULL_SHA,
		.id = SSL3_CK_RSA_NULL_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher 03 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_RSA_RC4_40_MD5,
		.id = SSL3_CK_RSA_RC4_40_MD5,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 128,
	},

	/* Cipher 04 */
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_RC4_128_MD5,
		.id = SSL3_CK_RSA_RC4_128_MD5,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 05 */
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_RC4_128_SHA,
		.id = SSL3_CK_RSA_RC4_128_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 06 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_RSA_RC2_40_MD5,
		.id = SSL3_CK_RSA_RC2_40_MD5,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_RC2,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 128,
	},

	/* Cipher 07 */
#ifndef OPENSSL_NO_IDEA
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_IDEA_128_SHA,
		.id = SSL3_CK_RSA_IDEA_128_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_IDEA,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
#endif

	/* Cipher 08 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_RSA_DES_40_CBC_SHA,
		.id = SSL3_CK_RSA_DES_40_CBC_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 56,
	},

	/* Cipher 09 */
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_DES_64_CBC_SHA,
		.id = SSL3_CK_RSA_DES_64_CBC_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_LOW,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 56,
		.alg_bits = 56,
	},

	/* Cipher 0A */
	{
		.valid = 1,
		.name = SSL3_TXT_RSA_DES_192_CBC3_SHA,
		.id = SSL3_CK_RSA_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* The DH ciphers */
	/* Cipher 0B */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_DH_DSS_DES_40_CBC_SHA,
		.id = SSL3_CK_DH_DSS_DES_40_CBC_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 56,
	},

	/* Cipher 0C */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = SSL3_TXT_DH_DSS_DES_64_CBC_SHA,
		.id = SSL3_CK_DH_DSS_DES_64_CBC_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_LOW,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 56,
		.alg_bits = 56,
	},

	/* Cipher 0D */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = SSL3_TXT_DH_DSS_DES_192_CBC3_SHA,
		.id = SSL3_CK_DH_DSS_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher 0E */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = SSL3_TXT_DH_RSA_DES_40_CBC_SHA,
		.id = SSL3_CK_DH_RSA_DES_40_CBC_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 56,
	},

	/* Cipher 0F */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = SSL3_TXT_DH_RSA_DES_64_CBC_SHA,
		.id = SSL3_CK_DH_RSA_DES_64_CBC_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_LOW,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 56,
		.alg_bits = 56,
	},

	/* Cipher 10 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = SSL3_TXT_DH_RSA_DES_192_CBC3_SHA,
		.id = SSL3_CK_DH_RSA_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* The Ephemeral DH ciphers */
	/* Cipher 11 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_EDH_DSS_DES_40_CBC_SHA,
		.id = SSL3_CK_EDH_DSS_DES_40_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 56,
	},

	/* Cipher 12 */
	{
		.valid = 1,
		.name = SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
		.id = SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_LOW,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 56,
		.alg_bits = 56,
	},

	/* Cipher 13 */
	{
		.valid = 1,
		.name = SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
		.id = SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher 14 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_EDH_RSA_DES_40_CBC_SHA,
		.id = SSL3_CK_EDH_RSA_DES_40_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 56,
	},

	/* Cipher 15 */
	{
		.valid = 1,
		.name = SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
		.id = SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_LOW,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 56,
		.alg_bits = 56,
	},

	/* Cipher 16 */
	{
		.valid = 1,
		.name = SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
		.id = SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher 17 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_ADH_RC4_40_MD5,
		.id = SSL3_CK_ADH_RC4_40_MD5,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 128,
	},

	/* Cipher 18 */
	{
		.valid = 1,
		.name = SSL3_TXT_ADH_RC4_128_MD5,
		.id = SSL3_CK_ADH_RC4_128_MD5,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 19 */
	{
		.valid = 0,	/* Weakened 40-bit export cipher. */
		.name = SSL3_TXT_ADH_DES_40_CBC_SHA,
		.id = SSL3_CK_ADH_DES_40_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = 0,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 40,
		.alg_bits = 128,
	},

	/* Cipher 1A */
	{
		.valid = 1,
		.name = SSL3_TXT_ADH_DES_64_CBC_SHA,
		.id = SSL3_CK_ADH_DES_64_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_LOW,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 56,
		.alg_bits = 56,
	},

	/* Cipher 1B */
	{
		.valid = 1,
		.name = SSL3_TXT_ADH_DES_192_CBC_SHA,
		.id = SSL3_CK_ADH_DES_192_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_SSLV3,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* New AES ciphersuites */
	/* Cipher 2F */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_AES_128_SHA,
		.id = TLS1_CK_RSA_WITH_AES_128_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
	/* Cipher 30 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_DSS_WITH_AES_128_SHA,
		.id = TLS1_CK_DH_DSS_WITH_AES_128_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
	/* Cipher 31 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_RSA_WITH_AES_128_SHA,
		.id = TLS1_CK_DH_RSA_WITH_AES_128_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
	/* Cipher 32 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
		.id = TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
	/* Cipher 33 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
		.id = TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
	/* Cipher 34 */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_AES_128_SHA,
		.id = TLS1_CK_ADH_WITH_AES_128_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 35 */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_AES_256_SHA,
		.id = TLS1_CK_RSA_WITH_AES_256_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},
	/* Cipher 36 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_DSS_WITH_AES_256_SHA,
		.id = TLS1_CK_DH_DSS_WITH_AES_256_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 37 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_RSA_WITH_AES_256_SHA,
		.id = TLS1_CK_DH_RSA_WITH_AES_256_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 38 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
		.id = TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 39 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
		.id = TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 3A */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_AES_256_SHA,
		.id = TLS1_CK_ADH_WITH_AES_256_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* TLS v1.2 ciphersuites */
	/* Cipher 3B */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_NULL_SHA256,
		.id = TLS1_CK_RSA_WITH_NULL_SHA256,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher 3C */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_RSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 3D */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_AES_256_SHA256,
		.id = TLS1_CK_RSA_WITH_AES_256_SHA256,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 3E */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_DSS_WITH_AES_128_SHA256,
		.id = TLS1_CK_DH_DSS_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 3F */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_RSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_DH_RSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 40 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
		.id = TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

#ifndef OPENSSL_NO_CAMELLIA
	/* Camellia ciphersuites from RFC4132 (128-bit portion) */

	/* Cipher 41 */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
		.id = TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_CAMELLIA128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 42 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
		.id = TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_CAMELLIA128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 43 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
		.id = TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_CAMELLIA128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 44 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
		.id = TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_CAMELLIA128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 45 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		.id = TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_CAMELLIA128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 46 */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
		.id = TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_CAMELLIA128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},
#endif /* OPENSSL_NO_CAMELLIA */

	/* TLS v1.2 ciphersuites */
	/* Cipher 67 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 68 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_DSS_WITH_AES_256_SHA256,
		.id = TLS1_CK_DH_DSS_WITH_AES_256_SHA256,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 69 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_RSA_WITH_AES_256_SHA256,
		.id = TLS1_CK_DH_RSA_WITH_AES_256_SHA256,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 6A */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
		.id = TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 6B */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
		.id = TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 6C */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_AES_128_SHA256,
		.id = TLS1_CK_ADH_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 6D */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_AES_256_SHA256,
		.id = TLS1_CK_ADH_WITH_AES_256_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* GOST Ciphersuites */

	{
		.valid = 1,
		.name = "GOST94-GOST89-GOST89",
		.id = 0x3000080,
		.algorithm_mkey = SSL_kGOST,
		.algorithm_auth = SSL_aGOST94,
		.algorithm_enc = SSL_eGOST2814789CNT,
		.algorithm_mac = SSL_GOST89MAC,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_GOST94|TLS1_PRF_GOST94|
		    TLS1_STREAM_MAC,
		.strength_bits = 256,
		.alg_bits = 256
	},
	{
		.valid = 1,
		.name = "GOST2001-GOST89-GOST89",
		.id = 0x3000081,
		.algorithm_mkey = SSL_kGOST,
		.algorithm_auth = SSL_aGOST01,
		.algorithm_enc = SSL_eGOST2814789CNT,
		.algorithm_mac = SSL_GOST89MAC,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_GOST94|TLS1_PRF_GOST94|
		    TLS1_STREAM_MAC,
		.strength_bits = 256,
		.alg_bits = 256
	},
	{
		.valid = 1,
		.name = "GOST94-NULL-GOST94",
		.id = 0x3000082,
		.algorithm_mkey = SSL_kGOST,
		.algorithm_auth = SSL_aGOST94,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_GOST94,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_GOST94|TLS1_PRF_GOST94,
		.strength_bits = 0,
		.alg_bits = 0
	},
	{
		.valid = 1,
		.name = "GOST2001-NULL-GOST94",
		.id = 0x3000083,
		.algorithm_mkey = SSL_kGOST,
		.algorithm_auth = SSL_aGOST01,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_GOST94,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_GOST94|TLS1_PRF_GOST94,
		.strength_bits = 0,
		.alg_bits = 0
	},

#ifndef OPENSSL_NO_CAMELLIA
	/* Camellia ciphersuites from RFC4132 (256-bit portion) */

	/* Cipher 84 */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
		.id = TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_CAMELLIA256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 85 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
		.id = TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_CAMELLIA256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 86 */
	{
		.valid = 0, /* not implemented (non-ephemeral DH) */
		.name = TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
		.id = TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_CAMELLIA256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 87 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
		.id = TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_CAMELLIA256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 88 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		.id = TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_CAMELLIA256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 89 */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
		.id = TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_CAMELLIA256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},
#endif /* OPENSSL_NO_CAMELLIA */


	/* GCM ciphersuites from RFC5288 */

	/* Cipher 9C */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 9D */
	{
		.valid = 1,
		.name = TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher 9E */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher 9F */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher A0 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher A1 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kDHr,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher A2 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher A3 */
	{
		.valid = 1,
		.name = TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aDSS,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher A4 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher A5 */
	{
		.valid = 0,
		.name = TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kDHd,
		.algorithm_auth = SSL_aDH,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher A6 */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher A7 */
	{
		.valid = 1,
		.name = TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C001 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA,
		.id = TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher C002 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA,
		.id = TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C003 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
		.id = TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher C004 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		.id = TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C005 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		.id = TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C006 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher C007 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C008 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher C009 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C00A */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C00B */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_NULL_SHA,
		.id = TLS1_CK_ECDH_RSA_WITH_NULL_SHA,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher C00C */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA,
		.id = TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C00D */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA,
		.id = TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher C00E */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA,
		.id = TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C00F */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA,
		.id = TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C010 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
		.id = TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher C011 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
		.id = TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C012 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
		.id = TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher C013 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		.id = TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C014 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		.id = TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C015 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
		.id = TLS1_CK_ECDH_anon_WITH_NULL_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_eNULL,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_STRONG_NONE,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 0,
		.alg_bits = 0,
	},

	/* Cipher C016 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
		.id = TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_RC4,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_MEDIUM,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C017 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
		.id = TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_3DES,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 112,
		.alg_bits = 168,
	},

	/* Cipher C018 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
		.id = TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C019 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
		.id = TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aNULL,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA1,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},


	/* HMAC based TLS v1.2 ciphersuites from RFC5289 */

	/* Cipher C023 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C024 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA384,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C025 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C026 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384,
		.id = TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA384,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C027 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C028 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
		.id = TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA384,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C029 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256,
		.id = TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES128,
		.algorithm_mac = SSL_SHA256,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C02A */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384,
		.id = TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES256,
		.algorithm_mac = SSL_SHA384,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* GCM based TLS v1.2 ciphersuites from RFC5289 */

	/* Cipher C02B */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C02C */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C02D */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C02E */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kECDHe,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C02F */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C030 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

	/* Cipher C031 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		.id = TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES128GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 128,
		.alg_bits = 128,
	},

	/* Cipher C032 */
	{
		.valid = 1,
		.name = TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		.id = TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		.algorithm_mkey = SSL_kECDHr,
		.algorithm_auth = SSL_aECDH,
		.algorithm_enc = SSL_AES256GCM,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(4)|
		    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
		.strength_bits = 256,
		.alg_bits = 256,
	},

#ifdef TEMP_GOST_TLS
	/* Cipher FF00 */
	{
		.valid = 1,
		.name = "GOST-MD5",
		.id = 0x0300ff00,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eGOST2814789CNT,
		.algorithm_mac = SSL_MD5,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256,
	},
	{
		.valid = 1,
		.name = "GOST-GOST94",
		.id = 0x0300ff01,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eGOST2814789CNT,
		.algorithm_mac = SSL_GOST94,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256
	},
	{
		.valid = 1,
		.name = "GOST-GOST89MAC",
		.id = 0x0300ff02,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eGOST2814789CNT,
		.algorithm_mac = SSL_GOST89MAC,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF,
		.strength_bits = 256,
		.alg_bits = 256
	},
	{
		.valid = 1,
		.name = "GOST-GOST89STREAM",
		.id = 0x0300ff03,
		.algorithm_mkey = SSL_kRSA,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_eGOST2814789CNT,
		.algorithm_mac = SSL_GOST89MAC,
		.algorithm_ssl = SSL_TLSV1,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF|
		    TLS1_STREAM_MAC,
		.strength_bits = 256,
		.alg_bits = 256
	},
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		.id = TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_CHACHA20POLY1305,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(0),
		.strength_bits = 256,
		.alg_bits = 0,
	},

	{
		.valid = 1,
		.name = TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		.id = TLS1_CK_ECDHE_ECDSA_CHACHA20_POLY1305,
		.algorithm_mkey = SSL_kEECDH,
		.algorithm_auth = SSL_aECDSA,
		.algorithm_enc = SSL_CHACHA20POLY1305,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(0),
		.strength_bits = 256,
		.alg_bits = 0,
	},

	{
		.valid = 1,
		.name = TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
		.id = TLS1_CK_DHE_RSA_CHACHA20_POLY1305,
		.algorithm_mkey = SSL_kEDH,
		.algorithm_auth = SSL_aRSA,
		.algorithm_enc = SSL_CHACHA20POLY1305,
		.algorithm_mac = SSL_AEAD,
		.algorithm_ssl = SSL_TLSV1_2,
		.algo_strength = SSL_HIGH,
		.algorithm2 = SSL_HANDSHAKE_MAC_SHA256|TLS1_PRF_SHA256|
		    SSL_CIPHER_ALGORITHM2_AEAD|FIXED_NONCE_LEN(0),
		.strength_bits = 256,
		.alg_bits = 0,
	},
#endif

	/* end of list */
};

SSL3_ENC_METHOD SSLv3_enc_data = {
	.enc = ssl3_enc,
	.mac = n_ssl3_mac,
	.setup_key_block = ssl3_setup_key_block,
	.generate_master_secret = ssl3_generate_master_secret,
	.change_cipher_state = ssl3_change_cipher_state,
	.final_finish_mac = ssl3_final_finish_mac,
	.finish_mac_length = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
	.cert_verify_mac = ssl3_cert_verify_mac,
	.client_finished_label = SSL3_MD_CLIENT_FINISHED_CONST,
	.client_finished_label_len = 4,
	.server_finished_label = SSL3_MD_SERVER_FINISHED_CONST,
	.server_finished_label_len = 4,
	.alert_value = ssl3_alert_code,
	.export_keying_material = (int (*)(SSL *, unsigned char *, size_t,
	    const char *, size_t, const unsigned char *, size_t,
	    int use_context))ssl_undefined_function,
	.enc_flags = 0,
};

long
ssl3_default_timeout(void)
{
	/*
	 * 2 hours, the 24 hours mentioned in the SSLv3 spec
	 * is way too long for http, the cache would over fill
	 */
	return (60 * 60 * 2);
}

int
ssl3_num_ciphers(void)
{
	return (SSL3_NUM_CIPHERS);
}

const SSL_CIPHER *
ssl3_get_cipher(unsigned int u)
{
	if (u < SSL3_NUM_CIPHERS)
		return (&(ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - u]));
	else
		return (NULL);
}

int
ssl3_pending(const SSL *s)
{
	if (s->rstate == SSL_ST_READ_BODY)
		return 0;

	return (s->s3->rrec.type == SSL3_RT_APPLICATION_DATA) ?
	    s->s3->rrec.length : 0;
}

int
ssl3_new(SSL *s)
{
	SSL3_STATE	*s3;

	if ((s3 = calloc(1, sizeof *s3)) == NULL)
		goto err;
	memset(s3->rrec.seq_num, 0, sizeof(s3->rrec.seq_num));
	memset(s3->wrec.seq_num, 0, sizeof(s3->wrec.seq_num));

	s->s3 = s3;

	s->method->ssl_clear(s);
	return (1);
err:
	return (0);
}

void
ssl3_free(SSL *s)
{
	if (s == NULL)
		return;

	ssl3_cleanup_key_block(s);
	ssl3_release_read_buffer(s);
	ssl3_release_write_buffer(s);

	DH_free(s->s3->tmp.dh);
	EC_KEY_free(s->s3->tmp.ecdh);

	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
	BIO_free(s->s3->handshake_buffer);
	ssl3_free_digest_list(s);
	OPENSSL_cleanse(s->s3, sizeof *s->s3);
	free(s->s3);
	s->s3 = NULL;
}

void
ssl3_clear(SSL *s)
{
	unsigned char	*rp, *wp;
	size_t		 rlen, wlen;
	int		 init_extra;

	ssl3_cleanup_key_block(s);
	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);

	DH_free(s->s3->tmp.dh);
	s->s3->tmp.dh = NULL;
	EC_KEY_free(s->s3->tmp.ecdh);
	s->s3->tmp.ecdh = NULL;

	s->s3->is_probably_safari = 0;

	rp = s->s3->rbuf.buf;
	wp = s->s3->wbuf.buf;
	rlen = s->s3->rbuf.len;
	wlen = s->s3->wbuf.len;
	init_extra = s->s3->init_extra;

	BIO_free(s->s3->handshake_buffer);
	s->s3->handshake_buffer = NULL;

	ssl3_free_digest_list(s);

	memset(s->s3, 0, sizeof *s->s3);
	s->s3->rbuf.buf = rp;
	s->s3->wbuf.buf = wp;
	s->s3->rbuf.len = rlen;
	s->s3->wbuf.len = wlen;
	s->s3->init_extra = init_extra;

	ssl_free_wbio_buffer(s);

	s->packet_length = 0;
	s->s3->renegotiate = 0;
	s->s3->total_renegotiations = 0;
	s->s3->num_renegotiations = 0;
	s->s3->in_read_app_data = 0;
	s->version = SSL3_VERSION;

#ifndef OPENSSL_NO_NEXTPROTONEG
	free(s->next_proto_negotiated);
	s->next_proto_negotiated = NULL;
	s->next_proto_negotiated_len = 0;
#endif
}


long
ssl3_ctrl(SSL *s, int cmd, long larg, void *parg)
{
	int ret = 0;

	if (cmd == SSL_CTRL_SET_TMP_RSA || cmd == SSL_CTRL_SET_TMP_RSA_CB ||
	    cmd == SSL_CTRL_SET_TMP_DH || cmd == SSL_CTRL_SET_TMP_DH_CB) {
		if (!ssl_cert_inst(&s->cert)) {
			SSLerr(SSL_F_SSL3_CTRL,
			    ERR_R_MALLOC_FAILURE);
			return (0);
		}
	}

	switch (cmd) {
	case SSL_CTRL_GET_SESSION_REUSED:
		ret = s->hit;
		break;
	case SSL_CTRL_GET_CLIENT_CERT_REQUEST:
		break;
	case SSL_CTRL_GET_NUM_RENEGOTIATIONS:
		ret = s->s3->num_renegotiations;
		break;
	case SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS:
		ret = s->s3->num_renegotiations;
		s->s3->num_renegotiations = 0;
		break;
	case SSL_CTRL_GET_TOTAL_RENEGOTIATIONS:
		ret = s->s3->total_renegotiations;
		break;
	case SSL_CTRL_GET_FLAGS:
		ret = (int)(s->s3->flags);
		break;
	case SSL_CTRL_NEED_TMP_RSA:
		if ((s->cert != NULL) && (s->cert->rsa_tmp == NULL) &&
		    ((s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) ||
		    (EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey)
		    > (512 / 8))))
			ret = 1;
		break;
	case SSL_CTRL_SET_TMP_RSA:
		{
			RSA *rsa = (RSA *)parg;
			if (rsa == NULL) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_PASSED_NULL_PARAMETER);
				return (ret);
			}
			if ((rsa = RSAPrivateKey_dup(rsa)) == NULL) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_RSA_LIB);
				return (ret);
			}
			RSA_free(s->cert->rsa_tmp);
			s->cert->rsa_tmp = rsa;
			ret = 1;
		}
		break;
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
			SSLerr(SSL_F_SSL3_CTRL,
			    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
			return (ret);
		}
		break;
	case SSL_CTRL_SET_TMP_DH:
		{
			DH *dh = (DH *)parg;
			if (dh == NULL) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_PASSED_NULL_PARAMETER);
				return (ret);
			}
			if ((dh = DHparams_dup(dh)) == NULL) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_DH_LIB);
				return (ret);
			}
			if (!(s->options & SSL_OP_SINGLE_DH_USE)) {
				if (!DH_generate_key(dh)) {
					DH_free(dh);
					SSLerr(SSL_F_SSL3_CTRL,
					    ERR_R_DH_LIB);
					return (ret);
				}
			}
			DH_free(s->cert->dh_tmp);
			s->cert->dh_tmp = dh;
			ret = 1;
		}
		break;
	case SSL_CTRL_SET_TMP_DH_CB:
		{
			SSLerr(SSL_F_SSL3_CTRL,
			    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
			return (ret);
		}
		break;
	case SSL_CTRL_SET_TMP_ECDH:
		{
			EC_KEY *ecdh = NULL;

			if (parg == NULL) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_PASSED_NULL_PARAMETER);
				return (ret);
			}
			if (!EC_KEY_up_ref((EC_KEY *)parg)) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_ECDH_LIB);
				return (ret);
			}
			ecdh = (EC_KEY *)parg;
			if (!(s->options & SSL_OP_SINGLE_ECDH_USE)) {
				if (!EC_KEY_generate_key(ecdh)) {
					EC_KEY_free(ecdh);
					SSLerr(SSL_F_SSL3_CTRL,
					    ERR_R_ECDH_LIB);
					return (ret);
				}
			}
			EC_KEY_free(s->cert->ecdh_tmp);
			s->cert->ecdh_tmp = ecdh;
			ret = 1;
		}
		break;
	case SSL_CTRL_SET_TMP_ECDH_CB:
		{
			SSLerr(SSL_F_SSL3_CTRL,
			    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
			return (ret);
		}
		break;
	case SSL_CTRL_SET_TLSEXT_HOSTNAME:
		if (larg == TLSEXT_NAMETYPE_host_name) {
			free(s->tlsext_hostname);
			s->tlsext_hostname = NULL;

			ret = 1;
			if (parg == NULL)
				break;
			if (strlen((char *)parg) > TLSEXT_MAXLEN_host_name) {
				SSLerr(SSL_F_SSL3_CTRL,
				    SSL_R_SSL3_EXT_INVALID_SERVERNAME);
				return 0;
			}
			if ((s->tlsext_hostname = BUF_strdup((char *)parg))
			    == NULL) {
				SSLerr(SSL_F_SSL3_CTRL,
				    ERR_R_INTERNAL_ERROR);
				return 0;
			}
		} else {
			SSLerr(SSL_F_SSL3_CTRL,
			    SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE);
			return 0;
		}
		break;
	case SSL_CTRL_SET_TLSEXT_DEBUG_ARG:
		s->tlsext_debug_arg = parg;
		ret = 1;
		break;

	case SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
		s->tlsext_status_type = larg;
		ret = 1;
		break;

	case SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS:
		*(STACK_OF(X509_EXTENSION) **)parg = s->tlsext_ocsp_exts;
		ret = 1;
		break;

	case SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS:
		s->tlsext_ocsp_exts = parg;
		ret = 1;
		break;

	case SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS:
		*(STACK_OF(OCSP_RESPID) **)parg = s->tlsext_ocsp_ids;
		ret = 1;
		break;

	case SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS:
		s->tlsext_ocsp_ids = parg;
		ret = 1;
		break;

	case SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP:
		*(unsigned char **)parg = s->tlsext_ocsp_resp;
		return s->tlsext_ocsp_resplen;

	case SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP:
		free(s->tlsext_ocsp_resp);
		s->tlsext_ocsp_resp = parg;
		s->tlsext_ocsp_resplen = larg;
		ret = 1;
		break;

	default:
		break;
	}
	return (ret);
}

long
ssl3_callback_ctrl(SSL *s, int cmd, void (*fp)(void))
{
	int	ret = 0;

	if (cmd == SSL_CTRL_SET_TMP_RSA_CB || cmd == SSL_CTRL_SET_TMP_DH_CB) {
		if (!ssl_cert_inst(&s->cert)) {
			SSLerr(SSL_F_SSL3_CALLBACK_CTRL,
			    ERR_R_MALLOC_FAILURE);
			return (0);
		}
	}

	switch (cmd) {
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
			s->cert->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
		}
		break;
	case SSL_CTRL_SET_TMP_DH_CB:
		{
			s->cert->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
		}
		break;
	case SSL_CTRL_SET_TMP_ECDH_CB:
		{
			s->cert->ecdh_tmp_cb =
			    (EC_KEY *(*)(SSL *, int, int))fp;
		}
		break;
	case SSL_CTRL_SET_TLSEXT_DEBUG_CB:
		s->tlsext_debug_cb = (void (*)(SSL *, int , int,
		    unsigned char *, int, void *))fp;
		break;
	default:
		break;
	}
	return (ret);
}

long
ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
	CERT	*cert;

	cert = ctx->cert;

	switch (cmd) {
	case SSL_CTRL_NEED_TMP_RSA:
		if ((cert->rsa_tmp == NULL) &&
		    ((cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) ||
		    (EVP_PKEY_size(cert->pkeys[SSL_PKEY_RSA_ENC].privatekey) >
		    (512 / 8))))
			return (1);
		else
			return (0);
		/* break; */
	case SSL_CTRL_SET_TMP_RSA:
		{
			RSA *rsa;
			int i;

			rsa = (RSA *)parg;
			i = 1;
			if (rsa == NULL)
				i = 0;
			else {
				if ((rsa = RSAPrivateKey_dup(rsa)) == NULL)
					i = 0;
			}
			if (!i) {
				SSLerr(SSL_F_SSL3_CTX_CTRL,
				    ERR_R_RSA_LIB);
				return (0);
			} else {
				RSA_free(cert->rsa_tmp);
				cert->rsa_tmp = rsa;
				return (1);
			}
		}
		/* break; */
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
			SSLerr(SSL_F_SSL3_CTX_CTRL,
			    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
			return (0);
		}
		break;
	case SSL_CTRL_SET_TMP_DH:
		{
			DH *new = NULL, *dh;

			dh = (DH *)parg;
			if ((new = DHparams_dup(dh)) == NULL) {
				SSLerr(SSL_F_SSL3_CTX_CTRL,
				    ERR_R_DH_LIB);
				return 0;
			}
			if (!(ctx->options & SSL_OP_SINGLE_DH_USE)) {
				if (!DH_generate_key(new)) {
					SSLerr(SSL_F_SSL3_CTX_CTRL,
					    ERR_R_DH_LIB);
					DH_free(new);
					return 0;
				}
			}
			DH_free(cert->dh_tmp);
			cert->dh_tmp = new;
			return 1;
		}
		/*break; */
	case SSL_CTRL_SET_TMP_DH_CB:
		{
			SSLerr(SSL_F_SSL3_CTX_CTRL,
			    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
			return (0);
		}
		break;
	case SSL_CTRL_SET_TMP_ECDH:
		{
			EC_KEY *ecdh = NULL;

			if (parg == NULL) {
				SSLerr(SSL_F_SSL3_CTX_CTRL,
				    ERR_R_ECDH_LIB);
				return 0;
			}
			ecdh = EC_KEY_dup((EC_KEY *)parg);
			if (ecdh == NULL) {
				SSLerr(SSL_F_SSL3_CTX_CTRL,
				    ERR_R_EC_LIB);
				return 0;
			}
			if (!(ctx->options & SSL_OP_SINGLE_ECDH_USE)) {
				if (!EC_KEY_generate_key(ecdh)) {
					EC_KEY_free(ecdh);
					SSLerr(SSL_F_SSL3_CTX_CTRL,
					    ERR_R_ECDH_LIB);
					return 0;
				}
			}

			EC_KEY_free(cert->ecdh_tmp);
			cert->ecdh_tmp = ecdh;
			return 1;
		}
		/* break; */
	case SSL_CTRL_SET_TMP_ECDH_CB:
		{
			SSLerr(SSL_F_SSL3_CTX_CTRL,
			    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
			return (0);
		}
		break;
	case SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG:
		ctx->tlsext_servername_arg = parg;
		break;
	case SSL_CTRL_SET_TLSEXT_TICKET_KEYS:
	case SSL_CTRL_GET_TLSEXT_TICKET_KEYS:
		{
			unsigned char *keys = parg;
			if (!keys)
				return 48;
			if (larg != 48) {
				SSLerr(SSL_F_SSL3_CTX_CTRL,
				    SSL_R_INVALID_TICKET_KEYS_LENGTH);
				return 0;
			}
			if (cmd == SSL_CTRL_SET_TLSEXT_TICKET_KEYS) {
				memcpy(ctx->tlsext_tick_key_name, keys, 16);
				memcpy(ctx->tlsext_tick_hmac_key,
				    keys + 16, 16);
				memcpy(ctx->tlsext_tick_aes_key, keys + 32, 16);
			} else {
				memcpy(keys, ctx->tlsext_tick_key_name, 16);
				memcpy(keys + 16,
				    ctx->tlsext_tick_hmac_key, 16);
				memcpy(keys + 32,
				    ctx->tlsext_tick_aes_key, 16);
			}
			return 1;
		}

	case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG:
		ctx->tlsext_status_arg = parg;
		return 1;
		break;


		/* A Thawte special :-) */
	case SSL_CTRL_EXTRA_CHAIN_CERT:
		if (ctx->extra_certs == NULL) {
			if ((ctx->extra_certs = sk_X509_new_null()) == NULL)
				return (0);
		}
		sk_X509_push(ctx->extra_certs,(X509 *)parg);
		break;

	case SSL_CTRL_GET_EXTRA_CHAIN_CERTS:
		*(STACK_OF(X509) **)parg = ctx->extra_certs;
		break;

	case SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS:
		if (ctx->extra_certs) {
			sk_X509_pop_free(ctx->extra_certs, X509_free);
			ctx->extra_certs = NULL;
		}
		break;

	default:
		return (0);
	}
	return (1);
}

long
ssl3_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void))
{
	CERT	*cert;

	cert = ctx->cert;

	switch (cmd) {
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
			cert->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
		}
		break;
	case SSL_CTRL_SET_TMP_DH_CB:
		{
			cert->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
		}
		break;
	case SSL_CTRL_SET_TMP_ECDH_CB:
		{
			cert->ecdh_tmp_cb = (EC_KEY *(*)(SSL *, int, int))fp;
		}
		break;
	case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
		ctx->tlsext_servername_callback =
		    (int (*)(SSL *, int *, void *))fp;
		break;

	case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB:
		ctx->tlsext_status_cb = (int (*)(SSL *, void *))fp;
		break;

	case SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB:
		ctx->tlsext_ticket_key_cb = (int (*)(SSL *, unsigned char  *,
		    unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int))fp;
		break;

	default:
		return (0);
	}
	return (1);
}

/* This function needs to check if the ciphers required are actually
 * available */
const SSL_CIPHER *
ssl3_get_cipher_by_char(const unsigned char *p)
{
	SSL_CIPHER		 c;
	const SSL_CIPHER	*cp;
	unsigned long		 id;

	id = 0x03000000L | ((unsigned long)p[0] << 8L) | (unsigned long)p[1];
	c.id = id;
	cp = OBJ_bsearch_ssl_cipher_id(&c, ssl3_ciphers, SSL3_NUM_CIPHERS);
#ifdef DEBUG_PRINT_UNKNOWN_CIPHERSUITES
	if (cp == NULL)
		fprintf(stderr, "Unknown cipher ID %x\n", (p[0] << 8) | p[1]);
#endif
	if (cp == NULL || cp->valid == 0)
		return NULL;
	else
		return cp;
}

int
ssl3_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p)
{
	long	l;

	if (p != NULL) {
		l = c->id;
		if ((l & 0xff000000) != 0x03000000)
			return (0);
		p[0] = ((unsigned char)(l >> 8L)) & 0xFF;
		p[1] = ((unsigned char)(l)) & 0xFF;
	}
	return (2);
}

SSL_CIPHER *ssl3_choose_cipher(SSL *s, STACK_OF(SSL_CIPHER) *clnt,
    STACK_OF(SSL_CIPHER) *srvr)
{
	SSL_CIPHER		*c, *ret = NULL;
	STACK_OF(SSL_CIPHER)	*prio, *allow;
	int			 i, ii, ok;
	unsigned int j;
	int ec_ok, ec_nid;
	unsigned char ec_search1 = 0, ec_search2 = 0;
	CERT *cert;
	unsigned long alg_k, alg_a, mask_k, mask_a;

	/* Let's see which ciphers we can support */
	cert = s->cert;

	/*
	 * Do not set the compare functions, because this may lead to a
	 * reordering by "id". We want to keep the original ordering.
	 * We may pay a price in performance during sk_SSL_CIPHER_find(),
	 * but would have to pay with the price of sk_SSL_CIPHER_dup().
	 */

	if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
		prio = srvr;
		allow = clnt;
	} else {
		prio = clnt;
		allow = srvr;
	}

	for (i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
		c = sk_SSL_CIPHER_value(prio, i);

		/* Skip TLS v1.2 only ciphersuites if not supported. */
		if ((c->algorithm_ssl & SSL_TLSV1_2) &&
		    !SSL_USE_TLS1_2_CIPHERS(s))
			continue;

		ssl_set_cert_masks(cert, c);
		mask_k = cert->mask_k;
		mask_a = cert->mask_a;

		alg_k = c->algorithm_mkey;
		alg_a = c->algorithm_auth;


		ok = (alg_k & mask_k) && (alg_a & mask_a);

		if (
		/*
		 * if we are considering an ECC cipher suite that uses our
		 * certificate
		 */
		(alg_a & SSL_aECDSA || alg_a & SSL_aECDH)
		/* and we have an ECC certificate */
		&& (s->cert->pkeys[SSL_PKEY_ECC].x509 != NULL)
		/*
		 * and the client specified a Supported Point Formats
		 * extension
		 */
		&& ((s->session->tlsext_ecpointformatlist_length > 0) &&
		(s->session->tlsext_ecpointformatlist != NULL))
		/* and our certificate's point is compressed */
		&& (
		(s->cert->pkeys[SSL_PKEY_ECC].x509->cert_info != NULL)
		&& (s->cert->pkeys[SSL_PKEY_ECC].x509->cert_info->key != NULL)
		&& (s->cert->pkeys[SSL_PKEY_ECC].x509->cert_info->key->public_key != NULL)
		&& (s->cert->pkeys[SSL_PKEY_ECC].x509->cert_info->key->public_key->data != NULL)
		&& (
		(*(s->cert->pkeys[SSL_PKEY_ECC].x509->cert_info->key->public_key->data) == POINT_CONVERSION_COMPRESSED)
		|| (*(s->cert->pkeys[SSL_PKEY_ECC].x509->cert_info->key->public_key->data) == POINT_CONVERSION_COMPRESSED + 1)
		)
		)
		) {
			ec_ok = 0;
			/*
			 * If our certificate's curve is over a field type
			 * that the client does not support then do not allow
			 * this cipher suite to be negotiated
			 */
			if (
			(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec != NULL)
			&& (s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group != NULL)
			&& (s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group->meth != NULL)
			&& (EC_METHOD_get_field_type(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group->meth) == NID_X9_62_prime_field)
			) {
				for (j = 0; j < s->session->tlsext_ecpointformatlist_length; j++) {
					if (s->session->tlsext_ecpointformatlist[j] == TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime) {
						ec_ok = 1;
						break;
					}
				}
			} else if (EC_METHOD_get_field_type(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group->meth) == NID_X9_62_characteristic_two_field) {
				for (j = 0; j < s->session->tlsext_ecpointformatlist_length; j++) {
					if (s->session->tlsext_ecpointformatlist[j] == TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2) {
						ec_ok = 1;
						break;
					}
				}
			}
			ok = ok && ec_ok;
		}
		if (
		/*
		 * If we are considering an ECC cipher suite that uses our
		 * certificate
		 */
		(alg_a & SSL_aECDSA || alg_a & SSL_aECDH)
		/* and we have an ECC certificate */
		&& (s->cert->pkeys[SSL_PKEY_ECC].x509 != NULL)
		/* and the client specified an EllipticCurves extension */
		&& ((s->session->tlsext_ellipticcurvelist_length > 0) && (s->session->tlsext_ellipticcurvelist != NULL))
		) {
			ec_ok = 0;
			if (
			(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec != NULL)
			&& (s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group != NULL)
			) {
				ec_nid = EC_GROUP_get_curve_name(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group);
				if ((ec_nid == 0)
				&& (s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group->meth != NULL)
				) {
					if (EC_METHOD_get_field_type(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group->meth) == NID_X9_62_prime_field) {
						ec_search1 = 0xFF;
						ec_search2 = 0x01;
					} else if (EC_METHOD_get_field_type(s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec->group->meth) == NID_X9_62_characteristic_two_field) {
						ec_search1 = 0xFF;
						ec_search2 = 0x02;
					}
				} else {
					ec_search1 = 0x00;
					ec_search2 = tls1_ec_nid2curve_id(ec_nid);
				}
				if ((ec_search1 != 0) || (ec_search2 != 0)) {
					for (j = 0; j < s->session->tlsext_ellipticcurvelist_length / 2; j++) {
						if ((s->session->tlsext_ellipticcurvelist[2*j] == ec_search1) && (s->session->tlsext_ellipticcurvelist[2*j + 1] == ec_search2)) {
							ec_ok = 1;
							break;
						}
					}
				}
			}
			ok = ok && ec_ok;
		}
		if (
		/*
		 * if we are considering an ECC cipher suite that uses an
		 * ephemeral EC key
		 */
		(alg_k & SSL_kEECDH)
		/* and we have an ephemeral EC key */
		&& (s->cert->ecdh_tmp != NULL)
		/* and the client specified an EllipticCurves extension */
		&& ((s->session->tlsext_ellipticcurvelist_length > 0) && (s->session->tlsext_ellipticcurvelist != NULL))
		) {
			ec_ok = 0;
			if (s->cert->ecdh_tmp->group != NULL) {
				ec_nid = EC_GROUP_get_curve_name(s->cert->ecdh_tmp->group);
				if ((ec_nid == 0)
				&& (s->cert->ecdh_tmp->group->meth != NULL)
				) {
					if (EC_METHOD_get_field_type(s->cert->ecdh_tmp->group->meth) == NID_X9_62_prime_field) {
						ec_search1 = 0xFF;
						ec_search2 = 0x01;
					} else if (EC_METHOD_get_field_type(s->cert->ecdh_tmp->group->meth) == NID_X9_62_characteristic_two_field) {
						ec_search1 = 0xFF;
						ec_search2 = 0x02;
					}
				} else {
					ec_search1 = 0x00;
					ec_search2 = tls1_ec_nid2curve_id(ec_nid);
				}
				if ((ec_search1 != 0) || (ec_search2 != 0)) {
					for (j = 0; j < s->session->tlsext_ellipticcurvelist_length / 2; j++) {
						if ((s->session->tlsext_ellipticcurvelist[2*j] == ec_search1) && (s->session->tlsext_ellipticcurvelist[2*j + 1] == ec_search2)) {
							ec_ok = 1;
							break;
						}
					}
				}
			}
			ok = ok && ec_ok;
		}

		if (!ok)
			continue;
		ii = sk_SSL_CIPHER_find(allow, c);
		if (ii >= 0) {
			if ((alg_k & SSL_kEECDH) &&
			    (alg_a & SSL_aECDSA) && s->s3->is_probably_safari) {
				if (!ret)
					ret = sk_SSL_CIPHER_value(allow, ii);
				continue;
			}
			ret = sk_SSL_CIPHER_value(allow, ii);
			break;
		}
	}
	return (ret);
}

int
ssl3_get_req_cert_type(SSL *s, unsigned char *p)
{
	int		ret = 0;
	unsigned long	alg_k;

	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

#ifndef OPENSSL_NO_GOST
	if (s->version >= TLS1_VERSION) {
		if (alg_k & SSL_kGOST) {
			p[ret++] = TLS_CT_GOST94_SIGN;
			p[ret++] = TLS_CT_GOST01_SIGN;
			return (ret);
		}
	}
#endif

	if (alg_k & (SSL_kDHr|SSL_kEDH)) {
		p[ret++] = SSL3_CT_RSA_FIXED_DH;
		p[ret++] = SSL3_CT_DSS_FIXED_DH;
	}
	if ((s->version == SSL3_VERSION) &&
		(alg_k & (SSL_kEDH|SSL_kDHd|SSL_kDHr))) {
		p[ret++] = SSL3_CT_RSA_EPHEMERAL_DH;
		p[ret++] = SSL3_CT_DSS_EPHEMERAL_DH;
	}
	p[ret++] = SSL3_CT_RSA_SIGN;
	p[ret++] = SSL3_CT_DSS_SIGN;
	if ((alg_k & (SSL_kECDHr|SSL_kECDHe)) && (s->version >= TLS1_VERSION)) {
		p[ret++] = TLS_CT_RSA_FIXED_ECDH;
		p[ret++] = TLS_CT_ECDSA_FIXED_ECDH;
	}

	/*
	 * ECDSA certs can be used with RSA cipher suites as well 
	 * so we don't need to check for SSL_kECDH or SSL_kEECDH
	 */
	if (s->version >= TLS1_VERSION) {
		p[ret++] = TLS_CT_ECDSA_SIGN;
	}
	return (ret);
}

int
ssl3_shutdown(SSL *s)
{
	int	ret;

	/*
	 * Don't do anything much if we have not done the handshake or
	 * we don't want to send messages :-)
	 */
	if ((s->quiet_shutdown) || (s->state == SSL_ST_BEFORE)) {
		s->shutdown = (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
		return (1);
	}

	if (!(s->shutdown & SSL_SENT_SHUTDOWN)) {
		s->shutdown|=SSL_SENT_SHUTDOWN;
		ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY);
		/*
		 * Our shutdown alert has been sent now, and if it still needs
	 	 * to be written, s->s3->alert_dispatch will be true
		 */
		if (s->s3->alert_dispatch)
			return(-1);	/* return WANT_WRITE */
	} else if (s->s3->alert_dispatch) {
		/* resend it if not sent */
		ret = s->method->ssl_dispatch_alert(s);
		if (ret == -1) {
			/*
			 * We only get to return -1 here the 2nd/Nth
			 * invocation, we must  have already signalled
			 * return 0 upon a previous invoation,
			 * return WANT_WRITE
			 */
			return (ret);
		}
	} else if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
		/* If we are waiting for a close from our peer, we are closed */
		s->method->ssl_read_bytes(s, 0, NULL, 0, 0);
		if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
			return(-1);	/* return WANT_READ */
		}
	}

	if ((s->shutdown == (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) &&
	    !s->s3->alert_dispatch)
		return (1);
	else
		return (0);
}

int
ssl3_write(SSL *s, const void *buf, int len)
{
	int	ret, n;

#if 0
	if (s->shutdown & SSL_SEND_SHUTDOWN) {
		s->rwstate = SSL_NOTHING;
		return (0);
	}
#endif
	errno = 0;
	if (s->s3->renegotiate)
		ssl3_renegotiate_check(s);

	/*
	 * This is an experimental flag that sends the
	 * last handshake message in the same packet as the first
	 * use data - used to see if it helps the TCP protocol during
	 * session-id reuse
	 */
	/* The second test is because the buffer may have been removed */
	if ((s->s3->flags & SSL3_FLAGS_POP_BUFFER) && (s->wbio == s->bbio)) {
		/* First time through, we write into the buffer */
		if (s->s3->delay_buf_pop_ret == 0) {
			ret = ssl3_write_bytes(s, SSL3_RT_APPLICATION_DATA,
			    buf, len);
			if (ret <= 0)
				return (ret);

			s->s3->delay_buf_pop_ret = ret;
		}

		s->rwstate = SSL_WRITING;
		n = BIO_flush(s->wbio);
		if (n <= 0)
			return (n);
		s->rwstate = SSL_NOTHING;

		/* We have flushed the buffer, so remove it */
		ssl_free_wbio_buffer(s);
		s->s3->flags&= ~SSL3_FLAGS_POP_BUFFER;

		ret = s->s3->delay_buf_pop_ret;
		s->s3->delay_buf_pop_ret = 0;
	} else {
		ret = s->method->ssl_write_bytes(s, SSL3_RT_APPLICATION_DATA,
		    buf, len);
		if (ret <= 0)
			return (ret);
	}

	return (ret);
}

static int
ssl3_read_internal(SSL *s, void *buf, int len, int peek)
{
	int	ret;

	errno = 0;
	if (s->s3->renegotiate)
		ssl3_renegotiate_check(s);
	s->s3->in_read_app_data = 1;
	ret = s->method->ssl_read_bytes(s,
	    SSL3_RT_APPLICATION_DATA, buf, len, peek);
	if ((ret == -1) && (s->s3->in_read_app_data == 2)) {
		/*
		 * ssl3_read_bytes decided to call s->handshake_func, which
		 * called ssl3_read_bytes to read handshake data.
		 * However, ssl3_read_bytes actually found application data
		 * and thinks that application data makes sense here; so disable
		 * handshake processing and try to read application data again.
		 */
		s->in_handshake++;
		ret = s->method->ssl_read_bytes(s,
		    SSL3_RT_APPLICATION_DATA, buf, len, peek);
		s->in_handshake--;
	} else
		s->s3->in_read_app_data = 0;

	return (ret);
}

int
ssl3_read(SSL *s, void *buf, int len)
{
	return ssl3_read_internal(s, buf, len, 0);
}

int
ssl3_peek(SSL *s, void *buf, int len)
{
	return ssl3_read_internal(s, buf, len, 1);
}

int
ssl3_renegotiate(SSL *s)
{
	if (s->handshake_func == NULL)
		return (1);

	if (s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
		return (0);

	s->s3->renegotiate = 1;
	return (1);
}

int
ssl3_renegotiate_check(SSL *s)
{
	int	ret = 0;

	if (s->s3->renegotiate) {
		if ((s->s3->rbuf.left == 0) && (s->s3->wbuf.left == 0) &&
		    !SSL_in_init(s)) {
			/*
			 * If we are the server, and we have sent
			 * a 'RENEGOTIATE' message, we need to go
			 * to SSL_ST_ACCEPT.
			 */
			/* SSL_ST_ACCEPT */
			s->state = SSL_ST_RENEGOTIATE;
			s->s3->renegotiate = 0;
			s->s3->num_renegotiations++;
			s->s3->total_renegotiations++;
			ret = 1;
		}
	}
	return (ret);
}
/*
 * If we are using TLS v1.2 or later and default SHA1+MD5 algorithms switch
 * to new SHA256 PRF and handshake macs
 */
long
ssl_get_algorithm2(SSL *s)
{
	long	alg2 = s->s3->tmp.new_cipher->algorithm2;

	if (s->method->version == TLS1_2_VERSION &&
	    alg2 == (SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF))
		return SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256;
	return alg2;
}
