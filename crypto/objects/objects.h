/* crypto/objects/objects.h */
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

#ifndef HEADER_OBJECTS_H
#define HEADER_OBJECTS_H

#ifdef  __cplusplus
extern "C" {
#endif

#define SN_undef			"UNDEF"
#define LN_undef			"undefined"
#define NID_undef			0

#define SN_Algorithm			"Algorithm"
#define LN_algorithm			"algorithm"
#define NID_algorithm			38
#define OBJ_algorithm			1L,3L,14L,3L,2L

#define LN_rsadsi			"rsadsi"
#define NID_rsadsi			1
#define OBJ_rsadsi			1L,2L,840L,113549L

#define LN_pkcs				"pkcs"
#define NID_pkcs			2
#define OBJ_pkcs			OBJ_rsadsi,1L

#define SN_md2				"MD2"
#define LN_md2				"md2"
#define NID_md2				3
#define OBJ_md2				OBJ_rsadsi,2L,2L

#define SN_md5				"MD5"
#define LN_md5				"md5"
#define NID_md5				4
#define OBJ_md5				OBJ_rsadsi,2L,5L

#define SN_rc4				"RC4"
#define LN_rc4				"rc4"
#define NID_rc4				5
#define OBJ_rc4				OBJ_rsadsi,3L,4L

#define LN_rsaEncryption		"rsaEncryption"
#define NID_rsaEncryption		6
#define OBJ_rsaEncryption		OBJ_pkcs,1L,1L

#define SN_md2WithRSAEncryption		"RSA-MD2"
#define LN_md2WithRSAEncryption		"md2WithRSAEncryption"
#define NID_md2WithRSAEncryption	7
#define OBJ_md2WithRSAEncryption	OBJ_pkcs,1L,2L

#define SN_md5WithRSAEncryption		"RSA-MD5"
#define LN_md5WithRSAEncryption		"md5WithRSAEncryption"
#define NID_md5WithRSAEncryption	8
#define OBJ_md5WithRSAEncryption	OBJ_pkcs,1L,4L

#define LN_pbeWithMD2AndDES_CBC		"pbeWithMD2AndDES-CBC"
#define NID_pbeWithMD2AndDES_CBC	9
#define OBJ_pbeWithMD2AndDES_CBC	OBJ_pkcs,5L,1L

#define LN_pbeWithMD5AndDES_CBC		"pbeWithMD5AndDES-CBC"
#define NID_pbeWithMD5AndDES_CBC	10
#define OBJ_pbeWithMD5AndDES_CBC	OBJ_pkcs,5L,3L

#define LN_X500				"X500"
#define NID_X500			11
#define OBJ_X500			2L,5L

#define LN_X509				"X509"
#define NID_X509			12
#define OBJ_X509			OBJ_X500,4L

#define SN_commonName			"CN"
#define LN_commonName			"commonName"
#define NID_commonName			13
#define OBJ_commonName			OBJ_X509,3L

#define SN_countryName			"C"
#define LN_countryName			"countryName"
#define NID_countryName			14
#define OBJ_countryName			OBJ_X509,6L

#define SN_localityName			"L"
#define LN_localityName			"localityName"
#define NID_localityName		15
#define OBJ_localityName		OBJ_X509,7L

/* Postal Address? PA */

/* should be "ST" (rfc1327) but MS uses 'S' */
#define SN_stateOrProvinceName		"ST"
#define LN_stateOrProvinceName		"stateOrProvinceName"
#define NID_stateOrProvinceName		16
#define OBJ_stateOrProvinceName		OBJ_X509,8L

#define SN_organizationName		"O"
#define LN_organizationName		"organizationName"
#define NID_organizationName		17
#define OBJ_organizationName		OBJ_X509,10L

#define SN_organizationalUnitName	"OU"
#define LN_organizationalUnitName	"organizationalUnitName"
#define NID_organizationalUnitName	18
#define OBJ_organizationalUnitName	OBJ_X509,11L

#define SN_rsa				"RSA"
#define LN_rsa				"rsa"
#define NID_rsa				19
#define OBJ_rsa				OBJ_X500,8L,1L,1L

#define LN_pkcs7			"pkcs7"
#define NID_pkcs7			20
#define OBJ_pkcs7			OBJ_pkcs,7L

#define LN_pkcs7_data			"pkcs7-data"
#define NID_pkcs7_data			21
#define OBJ_pkcs7_data			OBJ_pkcs7,1L

#define LN_pkcs7_signed			"pkcs7-signedData"
#define NID_pkcs7_signed		22
#define OBJ_pkcs7_signed		OBJ_pkcs7,2L

#define LN_pkcs7_enveloped		"pkcs7-envelopedData"
#define NID_pkcs7_enveloped		23
#define OBJ_pkcs7_enveloped		OBJ_pkcs7,3L

#define LN_pkcs7_signedAndEnveloped	"pkcs7-signedAndEnvelopedData"
#define NID_pkcs7_signedAndEnveloped	24
#define OBJ_pkcs7_signedAndEnveloped	OBJ_pkcs7,4L

#define LN_pkcs7_digest			"pkcs7-digestData"
#define NID_pkcs7_digest		25
#define OBJ_pkcs7_digest		OBJ_pkcs7,5L

#define LN_pkcs7_encrypted		"pkcs7-encryptedData"
#define NID_pkcs7_encrypted		26
#define OBJ_pkcs7_encrypted		OBJ_pkcs7,6L

#define LN_pkcs3			"pkcs3"
#define NID_pkcs3			27
#define OBJ_pkcs3			OBJ_pkcs,3L

#define LN_dhKeyAgreement		"dhKeyAgreement"
#define NID_dhKeyAgreement		28
#define OBJ_dhKeyAgreement		OBJ_pkcs3,1L

#define SN_des_ecb			"DES-ECB"
#define LN_des_ecb			"des-ecb"
#define NID_des_ecb			29
#define OBJ_des_ecb			OBJ_algorithm,6L

#define SN_des_cfb64			"DES-CFB"
#define LN_des_cfb64			"des-cfb"
#define NID_des_cfb64			30
/* IV + num */
#define OBJ_des_cfb64			OBJ_algorithm,9L

#define SN_des_cbc			"DES-CBC"
#define LN_des_cbc			"des-cbc"
#define NID_des_cbc			31
/* IV */
#define OBJ_des_cbc			OBJ_algorithm,7L

#define SN_des_ede			"DES-EDE"
#define LN_des_ede			"des-ede"
#define NID_des_ede			32
/* ?? */
#define OBJ_des_ede			OBJ_algorithm,17L

#define SN_des_ede3			"DES-EDE3"
#define LN_des_ede3			"des-ede3"
#define NID_des_ede3			33

#define SN_idea_cbc			"IDEA-CBC"
#define LN_idea_cbc			"idea-cbc"
#define NID_idea_cbc			34

#define SN_idea_cfb64			"IDEA-CFB"
#define LN_idea_cfb64			"idea-cfb"
#define NID_idea_cfb64			35

#define SN_idea_ecb			"IDEA-ECB"
#define LN_idea_ecb			"idea-ecb"
#define NID_idea_ecb			36

#define SN_rc2_cbc			"RC2-CBC"
#define LN_rc2_cbc			"rc2-cbc"
#define NID_rc2_cbc			37
#define OBJ_rc2_cbc			OBJ_rsadsi,3L,2L

#define SN_rc2_ecb			"RC2-ECB"
#define LN_rc2_ecb			"rc2-ecb"
#define NID_rc2_ecb			38

#define SN_rc2_cfb64			"RC2-CFB"
#define LN_rc2_cfb64			"rc2-cfb"
#define NID_rc2_cfb64			39

#define SN_rc2_ofb64			"RC2-OFB"
#define LN_rc2_ofb64			"rc2-ofb"
#define NID_rc2_ofb64			40

#define SN_sha				"SHA"
#define LN_sha				"sha"
#define NID_sha				41
#define OBJ_sha				OBJ_algorithm,18L

#define SN_shaWithRSAEncryption		"RSA-SHA"
#define LN_shaWithRSAEncryption		"shaWithRSAEncryption"
#define NID_shaWithRSAEncryption	42
#define OBJ_shaWithRSAEncryption	OBJ_algorithm,15L

#define SN_des_ede_cbc			"DES-EDE-CBC"
#define LN_des_ede_cbc			"des-ede-cbc"
#define NID_des_ede_cbc			43

#define SN_des_ede3_cbc			"DES-EDE3-CBC"
#define LN_des_ede3_cbc			"des-ede3-cbc"
#define NID_des_ede3_cbc		44
#define OBJ_des_ede3_cbc		OBJ_rsadsi,3L,7L

#define SN_des_ofb64			"DES-OFB"
#define LN_des_ofb64			"des-ofb"
#define NID_des_ofb64			45
#define OBJ_des_ofb64			OBJ_algorithm,8L

#define SN_idea_ofb64			"IDEA-OFB"
#define LN_idea_ofb64			"idea-ofb"
#define NID_idea_ofb64			46

#define LN_pkcs9			"pkcs9"
#define NID_pkcs9			47
#define OBJ_pkcs9			OBJ_pkcs,9L

#define SN_pkcs9_emailAddress		"Email"
#define LN_pkcs9_emailAddress		"emailAddress"
#define NID_pkcs9_emailAddress		48
#define OBJ_pkcs9_emailAddress		OBJ_pkcs9,1L

#define LN_pkcs9_unstructuredName	"unstructuredName"
#define NID_pkcs9_unstructuredName	49
#define OBJ_pkcs9_unstructuredName	OBJ_pkcs9,2L

#define LN_pkcs9_contentType		"contentType"
#define NID_pkcs9_contentType		50
#define OBJ_pkcs9_contentType		OBJ_pkcs9,3L

#define LN_pkcs9_messageDigest		"messageDigest"
#define NID_pkcs9_messageDigest		51
#define OBJ_pkcs9_messageDigest		OBJ_pkcs9,4L

#define LN_pkcs9_signingTime		"signingTime"
#define NID_pkcs9_signingTime		52
#define OBJ_pkcs9_signingTime		OBJ_pkcs9,5L

#define LN_pkcs9_countersignature	"countersignature"
#define NID_pkcs9_countersignature	53
#define OBJ_pkcs9_countersignature	OBJ_pkcs9,6L

#define LN_pkcs9_challengePassword	"challengePassword"
#define NID_pkcs9_challengePassword	54
#define OBJ_pkcs9_challengePassword	OBJ_pkcs9,7L

#define LN_pkcs9_unstructuredAddress	"unstructuredAddress"
#define NID_pkcs9_unstructuredAddress	55
#define OBJ_pkcs9_unstructuredAddress	OBJ_pkcs9,8L

#define LN_pkcs9_extCertAttributes	"extendedCertificateAttributes"
#define NID_pkcs9_extCertAttributes	56
#define OBJ_pkcs9_extCertAttributes	OBJ_pkcs9,9L

#define SN_netscape			"Netscape"
#define LN_netscape			"Netscape Communications Corp."
#define NID_netscape			57
#define OBJ_netscape			2L,16L,840L,1L,113730L

#define SN_netscape_cert_extension	"nsCertExt"
#define LN_netscape_cert_extension	"Netscape Certificate Extension"
#define NID_netscape_cert_extension	58
#define OBJ_netscape_cert_extension	OBJ_netscape,1L

#define SN_netscape_data_type		"nsDataType"
#define LN_netscape_data_type		"Netscape Data Type"
#define NID_netscape_data_type		59
#define OBJ_netscape_data_type		OBJ_netscape,2L

#define SN_des_ede_cfb64		"DES-EDE-CFB"
#define LN_des_ede_cfb64		"des-ede-cfb"
#define NID_des_ede_cfb64		60

#define SN_des_ede3_cfb64		"DES-EDE3-CFB"
#define LN_des_ede3_cfb64		"des-ede3-cfb"
#define NID_des_ede3_cfb64		61

#define SN_des_ede_ofb64		"DES-EDE-OFB"
#define LN_des_ede_ofb64		"des-ede-ofb"
#define NID_des_ede_ofb64		62

#define SN_des_ede3_ofb64		"DES-EDE3-OFB"
#define LN_des_ede3_ofb64		"des-ede3-ofb"
#define NID_des_ede3_ofb64		63

/* I'm not sure about the object ID */
#define SN_sha1				"SHA1"
#define LN_sha1				"sha1"
#define NID_sha1			64
#define OBJ_sha1			OBJ_algorithm,26L
/* 28 Jun 1996 - eay */
/* #define OBJ_sha1			1L,3L,14L,2L,26L,05L <- wrong */

#define SN_sha1WithRSAEncryption	"RSA-SHA1"
#define LN_sha1WithRSAEncryption	"sha1WithRSAEncryption"
#define NID_sha1WithRSAEncryption	65
#define OBJ_sha1WithRSAEncryption	OBJ_pkcs,1L,5L

#define SN_dsaWithSHA			"DSA-SHA"
#define LN_dsaWithSHA			"dsaWithSHA"
#define NID_dsaWithSHA			66
#define OBJ_dsaWithSHA			OBJ_algorithm,13L

#define SN_dsa_2			"DSA-old"
#define LN_dsa_2			"dsaEncryption-old"
#define NID_dsa_2			67
#define OBJ_dsa_2			OBJ_algorithm,12L

/* proposed by microsoft to RSA */
#define LN_pbeWithSHA1AndRC2_CBC	"pbeWithSHA1AndRC2-CBC"
#define NID_pbeWithSHA1AndRC2_CBC	68
#define OBJ_pbeWithSHA1AndRC2_CBC	OBJ_pkcs,5L,11L 

/* proposed by microsoft to RSA */
#define LN_pbeWithSHA1AndRC4		"pbeWithSHA1AndRC4"
#define NID_pbeWithSHA1AndRC4		69
#define OBJ_pbeWithSHA1AndRC4		OBJ_pkcs,5L,12L 

#define SN_dsaWithSHA1_2		"DSA-SHA1-old"
#define LN_dsaWithSHA1_2		"dsaWithSHA1"
#define NID_dsaWithSHA1_2		70
/* Got this one from 'sdn706r20.pdf' which is actually an NSA document :-) */
#define OBJ_dsaWithSHA1_2		OBJ_algorithm,27L

#define SN_netscape_cert_type		"nsCertType"
#define LN_netscape_cert_type		"Netscape Cert Type"
#define NID_netscape_cert_type		71
#define OBJ_netscape_cert_type		OBJ_netscape_cert_extension,1L

#define SN_netscape_base_url		"nsBaseUrl"
#define LN_netscape_base_url		"Netscape Base Url"
#define NID_netscape_base_url		72
#define OBJ_netscape_base_url		OBJ_netscape_cert_extension,2L

#define SN_netscape_revocation_url	"nsRevocationUrl"
#define LN_netscape_revocation_url	"Netscape Revocation Url"
#define NID_netscape_revocation_url	73
#define OBJ_netscape_revocation_url	OBJ_netscape_cert_extension,3L

#define SN_netscape_ca_revocation_url	"nsCaRevocationUrl"
#define LN_netscape_ca_revocation_url	"Netscape CA Revocation Url"
#define NID_netscape_ca_revocation_url	74
#define OBJ_netscape_ca_revocation_url	OBJ_netscape_cert_extension,4L

#define SN_netscape_renewal_url		"nsRenewalUrl"
#define LN_netscape_renewal_url		"Netscape Renewal Url"
#define NID_netscape_renewal_url	75
#define OBJ_netscape_renewal_url	OBJ_netscape_cert_extension,7L

#define SN_netscape_ca_policy_url	"nsCaPolicyUrl"
#define LN_netscape_ca_policy_url	"Netscape CA Policy Url"
#define NID_netscape_ca_policy_url	76
#define OBJ_netscape_ca_policy_url	OBJ_netscape_cert_extension,8L

#define SN_netscape_ssl_server_name	"nsSslServerName"
#define LN_netscape_ssl_server_name	"Netscape SSL Server Name"
#define NID_netscape_ssl_server_name	77
#define OBJ_netscape_ssl_server_name	OBJ_netscape_cert_extension,12L

#define SN_netscape_comment		"nsComment"
#define LN_netscape_comment		"Netscape Comment"
#define NID_netscape_comment		78
#define OBJ_netscape_comment		OBJ_netscape_cert_extension,13L

#define SN_netscape_cert_sequence	"nsCertSequence"
#define LN_netscape_cert_sequence	"Netscape Certificate Sequence"
#define NID_netscape_cert_sequence	79
#define OBJ_netscape_cert_sequence	OBJ_netscape_data_type,5L

#define SN_desx_cbc			"DESX-CBC"
#define LN_desx_cbc			"desx-cbc"
#define NID_desx_cbc			80

#define SN_ld_ce			"ld-ce"
#define NID_ld_ce			81
#define OBJ_ld_ce			2L,5L,29L

#define SN_subject_key_identifier	"subjectKeyIdentifier"
#define LN_subject_key_identifier	"X509v3 Subject Key Identifier"
#define NID_subject_key_identifier	82
#define OBJ_subject_key_identifier	OBJ_ld_ce,14L

#define SN_key_usage			"keyUsage"
#define LN_key_usage			"X509v3 Key Usage"
#define NID_key_usage			83
#define OBJ_key_usage			OBJ_ld_ce,15L

#define SN_private_key_usage_period	"privateKeyUsagePeriod"
#define LN_private_key_usage_period	"X509v3 Private Key Usage Period"
#define NID_private_key_usage_period	84
#define OBJ_private_key_usage_period	OBJ_ld_ce,16L

#define SN_subject_alt_name		"subjectAltName"
#define LN_subject_alt_name		"X509v3 Subject Alternative Name"
#define NID_subject_alt_name		85
#define OBJ_subject_alt_name		OBJ_ld_ce,17L

#define SN_issuer_alt_name		"issuerAltName"
#define LN_issuer_alt_name		"X509v3 Issuer Alternative Name"
#define NID_issuer_alt_name		86
#define OBJ_issuer_alt_name		OBJ_ld_ce,18L

#define SN_basic_constraints		"basicConstraints"
#define LN_basic_constraints		"X509v3 Basic Constraints"
#define NID_basic_constraints		87
#define OBJ_basic_constraints		OBJ_ld_ce,19L

#define SN_crl_number			"crlNumber"
#define LN_crl_number			"X509v3 CRL Number"
#define NID_crl_number			88
#define OBJ_crl_number			OBJ_ld_ce,20L

#define SN_certificate_policies		"certificatePolicies"
#define LN_certificate_policies		"X509v3 Certificate Policies"
#define NID_certificate_policies	89
#define OBJ_certificate_policies	OBJ_ld_ce,32L

#define SN_authority_key_identifier	"authorityKeyIdentifier"
#define LN_authority_key_identifier	"X509v3 Authority Key Identifier"
#define NID_authority_key_identifier	90
#define OBJ_authority_key_identifier	OBJ_ld_ce,35L

#define SN_bf_cbc			"BF-CBC"
#define LN_bf_cbc			"bf-cbc"
#define NID_bf_cbc			91

#define SN_bf_ecb			"BF-ECB"
#define LN_bf_ecb			"bf-ecb"
#define NID_bf_ecb			92

#define SN_bf_cfb64			"BF-CFB"
#define LN_bf_cfb64			"bf-cfb"
#define NID_bf_cfb64			93

#define SN_bf_ofb64			"BF-OFB"
#define LN_bf_ofb64			"bf-ofb"
#define NID_bf_ofb64			94

#define SN_mdc2				"MDC2"
#define LN_mdc2				"mdc2"
#define NID_mdc2			95
#define OBJ_mdc2			2L,5L,8L,3L,101L
/* An alternative?			1L,3L,14L,3L,2L,19L */

#define SN_mdc2WithRSA			"RSA-MDC2"
#define LN_mdc2WithRSA			"mdc2withRSA"
#define NID_mdc2WithRSA			96
#define OBJ_mdc2WithRSA			2L,5L,8L,3L,100L

#define SN_rc4_40			"RC4-40"
#define LN_rc4_40			"rc4-40"
#define NID_rc4_40			97

#define SN_rc2_40_cbc			"RC2-40-CBC"
#define LN_rc2_40_cbc			"rc2-40-cbc"
#define NID_rc2_40_cbc			98

#define SN_givenName			"G"
#define LN_givenName			"givenName"
#define NID_givenName			99
#define OBJ_givenName			OBJ_X509,42L

#define SN_surname			"S"
#define LN_surname			"surname"
#define NID_surname			100
#define OBJ_surname			OBJ_X509,4L

#define SN_initials			"I"
#define LN_initials			"initials"
#define NID_initials			101
#define OBJ_initials			OBJ_X509,43L

#define SN_uniqueIdentifier		"UID"
#define LN_uniqueIdentifier		"uniqueIdentifier"
#define NID_uniqueIdentifier		102
#define OBJ_uniqueIdentifier		OBJ_X509,45L

#define SN_crl_distribution_points	"crlDistributionPoints"
#define LN_crl_distribution_points	"X509v3 CRL Distribution Points"
#define NID_crl_distribution_points	103
#define OBJ_crl_distribution_points	OBJ_ld_ce,31L

#define SN_md5WithRSA			"RSA-NP-MD5"
#define LN_md5WithRSA			"md5WithRSA"
#define NID_md5WithRSA			104
#define OBJ_md5WithRSA			OBJ_algorithm,3L

#define SN_serialNumber			"SN"
#define LN_serialNumber			"serialNumber"
#define NID_serialNumber		105
#define OBJ_serialNumber		OBJ_X509,5L

#define SN_title			"T"
#define LN_title			"title"
#define NID_title			106
#define OBJ_title			OBJ_X509,12L

#define SN_description			"D"
#define LN_description			"description"
#define NID_description			107
#define OBJ_description			OBJ_X509,13L

/* CAST5 is CAST-128, I'm just sticking with the documentation */
#define SN_cast5_cbc			"CAST5-CBC"
#define LN_cast5_cbc			"cast5-cbc"
#define NID_cast5_cbc			108
#define OBJ_cast5_cbc			1L,2L,840L,113533L,7L,66L,10L

#define SN_cast5_ecb			"CAST5-ECB"
#define LN_cast5_ecb			"cast5-ecb"
#define NID_cast5_ecb			109

#define SN_cast5_cfb64			"CAST5-CFB"
#define LN_cast5_cfb64			"cast5-cfb"
#define NID_cast5_cfb64			110

#define SN_cast5_ofb64			"CAST5-OFB"
#define LN_cast5_ofb64			"cast5-ofb"
#define NID_cast5_ofb64			111

#define LN_pbeWithMD5AndCast5_CBC	"pbeWithMD5AndCast5CBC"
#define NID_pbeWithMD5AndCast5_CBC	112
#define OBJ_pbeWithMD5AndCast5_CBC	1L,2L,840L,113533L,7L,66L,12L

/* This is one sun will soon be using :-(
 * id-dsa-with-sha1 ID  ::= {
 *   iso(1) member-body(2) us(840) x9-57 (10040) x9cm(4) 3 }
 */
#define SN_dsaWithSHA1			"DSA-SHA1"
#define LN_dsaWithSHA1			"dsaWithSHA1"
#define NID_dsaWithSHA1			113
#define OBJ_dsaWithSHA1			1L,2L,840L,10040L,4L,3L

#define NID_md5_sha1			114
#define SN_md5_sha1			"MD5-SHA1"
#define LN_md5_sha1			"md5-sha1"

#define SN_sha1WithRSA			"RSA-SHA1-2"
#define LN_sha1WithRSA			"sha1WithRSA"
#define NID_sha1WithRSA			115
#define OBJ_sha1WithRSA			OBJ_algorithm,29L

#define SN_dsa				"DSA"
#define LN_dsa				"dsaEncryption"
#define NID_dsa				116
#define OBJ_dsa				1L,2L,840L,10040L,4L,1L

#define SN_ripemd160			"RIPEMD160"
#define LN_ripemd160			"ripemd160"
#define NID_ripemd160			117
#define OBJ_ripemd160			1L,3L,36L,3L,2L,1L

/* The name should actually be rsaSignatureWithripemd160, but I'm going
 * to contiune using the convention I'm using with the other ciphers */
#define SN_ripemd160WithRSA		"RSA-RIPEMD160"
#define LN_ripemd160WithRSA		"ripemd160WithRSA"
#define NID_ripemd160WithRSA		119
#define OBJ_ripemd160WithRSA		1L,3L,36L,3L,3L,1L,2L

/* Taken from rfc2040
 *  RC5_CBC_Parameters ::= SEQUENCE {
 *	version           INTEGER (v1_0(16)),
 *	rounds            INTEGER (8..127),
 *	blockSizeInBits   INTEGER (64, 128),
 *	iv                OCTET STRING OPTIONAL
 *	}
 */
#define SN_rc5_cbc			"RC5-CBC"
#define LN_rc5_cbc			"rc5-cbc"
#define NID_rc5_cbc			120
#define OBJ_rc5_cbc			OBJ_rsadsi,3L,8L

#define SN_rc5_ecb			"RC5-ECB"
#define LN_rc5_ecb			"rc5-ecb"
#define NID_rc5_ecb			121

#define SN_rc5_cfb64			"RC5-CFB"
#define LN_rc5_cfb64			"rc5-cfb"
#define NID_rc5_cfb64			122

#define SN_rc5_ofb64			"RC5-OFB"
#define LN_rc5_ofb64			"rc5-ofb"
#define NID_rc5_ofb64			123

#include "bio.h"
#include "asn1.h"

#define		OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)

#ifndef NOPROTO

ASN1_OBJECT *	OBJ_dup(ASN1_OBJECT *o);
ASN1_OBJECT *	OBJ_nid2obj(int n);
char *		OBJ_nid2ln(int n);
char *		OBJ_nid2sn(int n);
int		OBJ_obj2nid(ASN1_OBJECT *o);
int		OBJ_txt2nid(char *s);
int		OBJ_ln2nid(char *s);
int		OBJ_sn2nid(char *s);
int		OBJ_cmp(ASN1_OBJECT *a,ASN1_OBJECT *b);
char *		OBJ_bsearch(char *key,char *base,int num,int size,int (*cmp)());

void		ERR_load_OBJ_strings(void );

int		OBJ_new_nid(int num);
int		OBJ_add_object(ASN1_OBJECT *obj);
int		OBJ_create(char *oid,char *sn,char *ln);
void		OBJ_cleanup(void );
int		OBJ_create_objects(BIO *in);

#else

ASN1_OBJECT *	OBJ_dup();
ASN1_OBJECT *	OBJ_nid2obj();
char *		OBJ_nid2ln();
char *		OBJ_nid2sn();
int		OBJ_obj2nid();
int		OBJ_txt2nid();
int		OBJ_ln2nid();
int		OBJ_sn2nid();
int		OBJ_cmp();
char *		OBJ_bsearch();

void		ERR_load_OBJ_strings();

int		OBJ_new_nid();
int		OBJ_add_object();
int		OBJ_create();
void		OBJ_cleanup();
int		OBJ_create_objects();

#endif

/* BEGIN ERROR CODES */
/* Error codes for the OBJ functions. */

/* Function codes. */
#define OBJ_F_OBJ_CREATE				 100
#define OBJ_F_OBJ_DUP					 101
#define OBJ_F_OBJ_NID2LN				 102
#define OBJ_F_OBJ_NID2OBJ				 103
#define OBJ_F_OBJ_NID2SN				 104

/* Reason codes. */
#define OBJ_R_MALLOC_FAILURE				 100
#define OBJ_R_UNKNOWN_NID				 101
 
#ifdef  __cplusplus
}
#endif
#endif

