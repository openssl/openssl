/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_SYMHACKS_H
#define HEADER_SYMHACKS_H

/* Hacks to solve the problem with linkers incapable of handling very long
   symbol names.  In the case of VMS, the limit is 31 characters on VMS for
   VAX. */
#ifdef VMS

/* Hack a long name in crypto/asn1/a_mbstr.c */
#undef ASN1_STRING_set_default_mask_asc
#define ASN1_STRING_set_default_mask_asc	ASN1_STRING_set_def_mask_asc

/* Hack the names created with DECLARE_ASN1_SET_OF(PKCS7_SIGNER_INFO) */
#undef i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO
#define i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO	i2d_ASN1_SET_OF_PKCS7_SIGINF
#undef d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO
#define d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO	d2i_ASN1_SET_OF_PKCS7_SIGINF

/* Hack the names created with DECLARE_ASN1_SET_OF(PKCS7_RECIP_INFO) */
#undef i2d_ASN1_SET_OF_PKCS7_RECIP_INFO
#define i2d_ASN1_SET_OF_PKCS7_RECIP_INFO	i2d_ASN1_SET_OF_PKCS7_RECGINF
#undef d2i_ASN1_SET_OF_PKCS7_RECIP_INFO
#define d2i_ASN1_SET_OF_PKCS7_RECIP_INFO	d2i_ASN1_SET_OF_PKCS7_RECGINF

/* Hack the names created with DECLARE_ASN1_SET_OF(ACCESS_DESCRIPTION) */
#undef i2d_ASN1_SET_OF_ACCESS_DESCRIPTION
#define i2d_ASN1_SET_OF_ACCESS_DESCRIPTION	i2d_ASN1_SET_OF_ACC_DESC
#undef d2i_ASN1_SET_OF_ACCESS_DESCRIPTION
#define d2i_ASN1_SET_OF_ACCESS_DESCRIPTION	d2i_ASN1_SET_OF_ACC_DESC

/* Hack the names created with DECLARE_PEM_rw(NETSCAPE_CERT_SEQUENCE) */
#undef PEM_read_NETSCAPE_CERT_SEQUENCE
#define PEM_read_NETSCAPE_CERT_SEQUENCE		PEM_read_NS_CERT_SEQ
#undef PEM_write_NETSCAPE_CERT_SEQUENCE
#define PEM_write_NETSCAPE_CERT_SEQUENCE	PEM_write_NS_CERT_SEQ
#undef PEM_read_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_read_bio_NETSCAPE_CERT_SEQUENCE	PEM_read_bio_NS_CERT_SEQ
#undef PEM_write_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_write_bio_NETSCAPE_CERT_SEQUENCE	PEM_write_bio_NS_CERT_SEQ
#undef PEM_write_cb_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_write_cb_bio_NETSCAPE_CERT_SEQUENCE	PEM_write_cb_bio_NS_CERT_SEQ

/* Hack the names created with DECLARE_PEM_rw(PKCS8_PRIV_KEY_INFO) */
#undef PEM_read_PKCS8_PRIV_KEY_INFO
#define PEM_read_PKCS8_PRIV_KEY_INFO		PEM_read_P8_PRIV_KEY_INFO
#undef PEM_write_PKCS8_PRIV_KEY_INFO
#define PEM_write_PKCS8_PRIV_KEY_INFO		PEM_write_P8_PRIV_KEY_INFO
#undef PEM_read_bio_PKCS8_PRIV_KEY_INFO
#define PEM_read_bio_PKCS8_PRIV_KEY_INFO	PEM_read_bio_P8_PRIV_KEY_INFO
#undef PEM_write_bio_PKCS8_PRIV_KEY_INFO
#define PEM_write_bio_PKCS8_PRIV_KEY_INFO	PEM_write_bio_P8_PRIV_KEY_INFO
#undef PEM_write_cb_bio_PKCS8_PRIV_KEY_INFO
#define PEM_write_cb_bio_PKCS8_PRIV_KEY_INFO	PEM_wrt_cb_bio_P8_PRIV_KEY_INFO

/* Hack other PEM names */
#undef PEM_write_bio_PKCS8PrivateKey_nid
#define PEM_write_bio_PKCS8PrivateKey_nid	PEM_write_bio_PKCS8PrivKey_nid

/* Hack some long X509 names */
#undef X509_REVOKED_get_ext_by_critical
#define X509_REVOKED_get_ext_by_critical	X509_REVOKED_get_ext_by_critic

#endif /* defined VMS */


/* Case insensiteve linking causes problems.... */
#if defined(WIN16) || defined(VMS)
#undef ERR_load_CRYPTO_strings
#define ERR_load_CRYPTO_strings			ERR_load_CRYPTOlib_strings
#endif


#endif /* ! defined HEADER_VMS_IDHACKS_H */
