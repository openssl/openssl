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

#ifndef HEADER_VMS_IDHACKS_H
#define HEADER_VMS_IDHACKS_H

#ifdef VMS

/* Hack a long name in crypto/asn1/a_mbstr.c */
#define ASN1_STRING_set_default_mask_asc ASN1_STRING_set_def_mask_asc
/* Hack the names created with DECLARE_STACK_OF(PKCS7_SIGNER_INFO) */
#define sk_PKCS7_SIGNER_INFO_new		sk_PKCS7_SIGINF_new
#define sk_PKCS7_SIGNER_INFO_new_null		sk_PKCS7_SIGINF_new_null
#define sk_PKCS7_SIGNER_INFO_free		sk_PKCS7_SIGINF_free
#define sk_PKCS7_SIGNER_INFO_num		sk_PKCS7_SIGINF_num
#define sk_PKCS7_SIGNER_INFO_value		sk_PKCS7_SIGINF_value
#define sk_PKCS7_SIGNER_INFO_set		sk_PKCS7_SIGINF_set
#define sk_PKCS7_SIGNER_INFO_zero		sk_PKCS7_SIGINF_zero
#define sk_PKCS7_SIGNER_INFO_push		sk_PKCS7_SIGINF_push
#define sk_PKCS7_SIGNER_INFO_unshift		sk_PKCS7_SIGINF_unshift
#define sk_PKCS7_SIGNER_INFO_find		sk_PKCS7_SIGINF_find
#define sk_PKCS7_SIGNER_INFO_delete		sk_PKCS7_SIGINF_delete
#define sk_PKCS7_SIGNER_INFO_delete_ptr		sk_PKCS7_SIGINF_delete_ptr
#define sk_PKCS7_SIGNER_INFO_insert		sk_PKCS7_SIGINF_insert
#define sk_PKCS7_SIGNER_INFO_set_cmp_func	sk_PKCS7_SIGINF_set_cmp_func
#define sk_PKCS7_SIGNER_INFO_dup		sk_PKCS7_SIGINF_dup
#define sk_PKCS7_SIGNER_INFO_pop_free		sk_PKCS7_SIGINF_pop_free
#define sk_PKCS7_SIGNER_INFO_shift		sk_PKCS7_SIGINF_shift
#define sk_PKCS7_SIGNER_INFO_pop		sk_PKCS7_SIGINF_pop
#define sk_PKCS7_SIGNER_INFO_sort		sk_PKCS7_SIGINF_sort

/* Hack the names created with DECLARE_STACK_OF(PKCS7_RECIP_INFO) */
#define sk_PKCS7_RECIP_INFO_new			sk_PKCS7_RECINF_new
#define sk_PKCS7_RECIP_INFO_new_null		sk_PKCS7_RECINF_new_null
#define sk_PKCS7_RECIP_INFO_free		sk_PKCS7_RECINF_free
#define sk_PKCS7_RECIP_INFO_num			sk_PKCS7_RECINF_num
#define sk_PKCS7_RECIP_INFO_value		sk_PKCS7_RECINF_value
#define sk_PKCS7_RECIP_INFO_set			sk_PKCS7_RECINF_set
#define sk_PKCS7_RECIP_INFO_zero		sk_PKCS7_RECINF_zero
#define sk_PKCS7_RECIP_INFO_push		sk_PKCS7_RECINF_push
#define sk_PKCS7_RECIP_INFO_unshift		sk_PKCS7_RECINF_unshift
#define sk_PKCS7_RECIP_INFO_find		sk_PKCS7_RECINF_find
#define sk_PKCS7_RECIP_INFO_delete		sk_PKCS7_RECINF_delete
#define sk_PKCS7_RECIP_INFO_delete_ptr		sk_PKCS7_RECINF_delete_ptr
#define sk_PKCS7_RECIP_INFO_insert		sk_PKCS7_RECINF_insert
#define sk_PKCS7_RECIP_INFO_set_cmp_func	sk_PKCS7_RECINF_set_cmp_func
#define sk_PKCS7_RECIP_INFO_dup			sk_PKCS7_RECINF_dup
#define sk_PKCS7_RECIP_INFO_pop_free		sk_PKCS7_RECINF_pop_free
#define sk_PKCS7_RECIP_INFO_shift		sk_PKCS7_RECINF_shift
#define sk_PKCS7_RECIP_INFO_pop			sk_PKCS7_RECINF_pop
#define sk_PKCS7_RECIP_INFO_sort		sk_PKCS7_RECINF_sort

/* Hack the names created with DECLARE_STACK_OF(ASN1_STRING_TABLE) */
#define sk_ASN1_STRING_TABLE_new		sk_ASN1_STRTAB_new
#define sk_ASN1_STRING_TABLE_new_null		sk_ASN1_STRTAB_new_null
#define sk_ASN1_STRING_TABLE_free		sk_ASN1_STRTAB_free
#define sk_ASN1_STRING_TABLE_num		sk_ASN1_STRTAB_num
#define sk_ASN1_STRING_TABLE_value		sk_ASN1_STRTAB_value
#define sk_ASN1_STRING_TABLE_set		sk_ASN1_STRTAB_set
#define sk_ASN1_STRING_TABLE_zero		sk_ASN1_STRTAB_zero
#define sk_ASN1_STRING_TABLE_push		sk_ASN1_STRTAB_push
#define sk_ASN1_STRING_TABLE_unshift		sk_ASN1_STRTAB_unshift
#define sk_ASN1_STRING_TABLE_find		sk_ASN1_STRTAB_find
#define sk_ASN1_STRING_TABLE_delete		sk_ASN1_STRTAB_delete
#define sk_ASN1_STRING_TABLE_delete_ptr		sk_ASN1_STRTAB_delete_ptr
#define sk_ASN1_STRING_TABLE_insert		sk_ASN1_STRTAB_insert
#define sk_ASN1_STRING_TABLE_set_cmp_func	sk_ASN1_STRTAB_set_cmp_func
#define sk_ASN1_STRING_TABLE_dup		sk_ASN1_STRTAB_dup
#define sk_ASN1_STRING_TABLE_pop_free		sk_ASN1_STRTAB_pop_free
#define sk_ASN1_STRING_TABLE_shift		sk_ASN1_STRTAB_shift
#define sk_ASN1_STRING_TABLE_pop		sk_ASN1_STRTAB_pop
#define sk_ASN1_STRING_TABLE_sort		sk_ASN1_STRTAB_sort

/* Hack the names created with DECLARE_STACK_OF(ACCESS_DESCRIPTION) */
#define sk_ACCESS_DESCRIPTION_new		sk_ACC_DESC_new
#define sk_ACCESS_DESCRIPTION_new_null		sk_ACC_DESC_new_null
#define sk_ACCESS_DESCRIPTION_free		sk_ACC_DESC_free
#define sk_ACCESS_DESCRIPTION_num		sk_ACC_DESC_num
#define sk_ACCESS_DESCRIPTION_value		sk_ACC_DESC_value
#define sk_ACCESS_DESCRIPTION_set		sk_ACC_DESC_set
#define sk_ACCESS_DESCRIPTION_zero		sk_ACC_DESC_zero
#define sk_ACCESS_DESCRIPTION_push		sk_ACC_DESC_push
#define sk_ACCESS_DESCRIPTION_unshift		sk_ACC_DESC_unshift
#define sk_ACCESS_DESCRIPTION_find		sk_ACC_DESC_find
#define sk_ACCESS_DESCRIPTION_delete		sk_ACC_DESC_delete
#define sk_ACCESS_DESCRIPTION_delete_ptr	sk_ACC_DESC_delete_ptr
#define sk_ACCESS_DESCRIPTION_insert		sk_ACC_DESC_insert
#define sk_ACCESS_DESCRIPTION_set_cmp_func	sk_ACC_DESC_set_cmp_func
#define sk_ACCESS_DESCRIPTION_dup		sk_ACC_DESC_dup
#define sk_ACCESS_DESCRIPTION_pop_free		sk_ACC_DESC_pop_free
#define sk_ACCESS_DESCRIPTION_shift		sk_ACC_DESC_shift
#define sk_ACCESS_DESCRIPTION_pop		sk_ACC_DESC_pop
#define sk_ACCESS_DESCRIPTION_sort		sk_ACC_DESC_sort

/* Hack the names created with DECLARE_STACK_OF(CRYPTO_EX_DATA_FUNCS) */
#define sk_CRYPTO_EX_DATA_FUNCS_new		sk_CRYPT_EX_DATFNS_new
#define sk_CRYPTO_EX_DATA_FUNCS_new_null	sk_CRYPT_EX_DATFNS_new_null
#define sk_CRYPTO_EX_DATA_FUNCS_free		sk_CRYPT_EX_DATFNS_free
#define sk_CRYPTO_EX_DATA_FUNCS_num		sk_CRYPT_EX_DATFNS_num
#define sk_CRYPTO_EX_DATA_FUNCS_value		sk_CRYPT_EX_DATFNS_value
#define sk_CRYPTO_EX_DATA_FUNCS_set		sk_CRYPT_EX_DATFNS_set
#define sk_CRYPTO_EX_DATA_FUNCS_zero		sk_CRYPT_EX_DATFNS_zero
#define sk_CRYPTO_EX_DATA_FUNCS_push		sk_CRYPT_EX_DATFNS_push
#define sk_CRYPTO_EX_DATA_FUNCS_unshift		sk_CRYPT_EX_DATFNS_unshift
#define sk_CRYPTO_EX_DATA_FUNCS_find		sk_CRYPT_EX_DATFNS_find
#define sk_CRYPTO_EX_DATA_FUNCS_delete		sk_CRYPT_EX_DATFNS_delete
#define sk_CRYPTO_EX_DATA_FUNCS_delete_ptr	sk_CRYPT_EX_DATFNS_delete_ptr
#define sk_CRYPTO_EX_DATA_FUNCS_insert		sk_CRYPT_EX_DATFNS_insert
#define sk_CRYPTO_EX_DATA_FUNCS_set_cmp_func	sk_CRYPT_EX_DATFNS_set_cmp_func
#define sk_CRYPTO_EX_DATA_FUNCS_dup		sk_CRYPT_EX_DATFNS_dup
#define sk_CRYPTO_EX_DATA_FUNCS_pop_free	sk_CRYPT_EX_DATFNS_pop_free
#define sk_CRYPTO_EX_DATA_FUNCS_shift		sk_CRYPT_EX_DATFNS_shift
#define sk_CRYPTO_EX_DATA_FUNCS_pop		sk_CRYPT_EX_DATFNS_pop
#define sk_CRYPTO_EX_DATA_FUNCS_sort		sk_CRYPT_EX_DATFNS_sort

/* Hack the names created with DECLARE_ASN1_SET_OF(PKCS7_SIGNER_INFO) */
#define i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO	i2d_ASN1_SET_OF_PKCS7_SIGINF
#define d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO	d2i_ASN1_SET_OF_PKCS7_SIGINF

/* Hack the names created with DECLARE_ASN1_SET_OF(PKCS7_RECIP_INFO) */
#define i2d_ASN1_SET_OF_PKCS7_RECIP_INFO	i2d_ASN1_SET_OF_PKCS7_RECGINF
#define d2i_ASN1_SET_OF_PKCS7_RECIP_INFO	d2i_ASN1_SET_OF_PKCS7_RECGINF

/* Hack the names created with DECLARE_ASN1_SET_OF(ACCESS_DESCRIPTION) */
#define i2d_ASN1_SET_OF_ACCESS_DESCRIPTION	i2d_ASN1_SET_OF_ACC_DESC
#define d2i_ASN1_SET_OF_ACCESS_DESCRIPTION	d2i_ASN1_SET_OF_ACC_DESC

/* Hack the names created with DECLARE_PEM_rw(NETSCAPE_CERT_SEQUENCE) */
#define PEM_read_NETSCAPE_CERT_SEQUENCE		PEM_read_NS_CERT_SEQUENCE
#define PEM_write_NETSCAPE_CERT_SEQUENCE	PEM_write_NS_CERT_SEQUENCE
#define PEM_read_bio_NETSCAPE_CERT_SEQUENCE	PEM_read_bio_NS_CERT_SEQUENCE
#define PEM_write_bio_NETSCAPE_CERT_SEQUENCE	PEM_write_bio_NS_CERT_SEQUENCE
#define PEM_write_cb_bio_NETSCAPE_CERT_SEQUENCE	PEM_write_cb_bio_NS_CERT_SEQUENCE

/* Hack the names created with DECLARE_PEM_rw(PKCS8_PRIV_KEY_INFO) */
#define PEM_read_PKCS8_PRIV_KEY_INFO		PEM_read_P8_PRIV_KEY_INFO
#define PEM_write_PKCS8_PRIV_KEY_INFO		PEM_write_P8_PRIV_KEY_INFO
#define PEM_read_bio_PKCS8_PRIV_KEY_INFO	PEM_read_bio_P8_PRIV_KEY_INFO
#define PEM_write_bio_PKCS8_PRIV_KEY_INFO	PEM_write_bio_P8_PRIV_KEY_INFO
#define PEM_write_cb_bio_PKCS8_PRIV_KEY_INFO	PEM_wrt_cb_bio_P8_PRIV_KEY_INFO

/* Hack other PEM names */
#define PEM_write_bio_PKCS8PrivateKey_nid	PEM_write_bio_PKCS8PrivKey_nid

#endif /* defined VMS */

#endif /* ! defined HEADER_VMS_IDHACKS_H */
