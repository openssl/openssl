/* crypto/objects/obj_mac.h */

/* THIS FILE IS GENERATED FROM objects.txt by objects.pl via the
 * following command:
 * perl objects.pl objects.txt obj_mac.num obj_mac.h
 */

/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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

#define SN_undef			"UNDEF"
#define LN_undef			"undefined"
#define NID_undef			0
#define OBJ_undef			0L

#define SN_iso		"ISO"
#define LN_iso		"iso"
#define NID_iso		181
#define OBJ_iso		1L

#define SN_joint_iso_ccitt		"JOINT-ISO-CCITT"
#define LN_joint_iso_ccitt		"joint-iso-ccitt"
#define NID_joint_iso_ccitt		393
#define OBJ_joint_iso_ccitt		2L

#define SN_member_body		"member-body"
#define LN_member_body		"ISO Member Body"
#define NID_member_body		182
#define OBJ_member_body		OBJ_iso,2L

#define SN_selected_attribute_types		"selected-attribute-types"
#define LN_selected_attribute_types		"Selected Attribute Types"
#define NID_selected_attribute_types		394
#define OBJ_selected_attribute_types		OBJ_joint_iso_ccitt,5L,1L,5L

#define SN_clearance		"clearance"
#define NID_clearance		395
#define OBJ_clearance		OBJ_selected_attribute_types,55L

#define SN_ISO_US		"ISO-US"
#define LN_ISO_US		"ISO US Member Body"
#define NID_ISO_US		183
#define OBJ_ISO_US		OBJ_member_body,840L

#define SN_X9_57		"X9-57"
#define LN_X9_57		"X9.57"
#define NID_X9_57		184
#define OBJ_X9_57		OBJ_ISO_US,10040L

#define SN_X9cm		"X9cm"
#define LN_X9cm		"X9.57 CM ?"
#define NID_X9cm		185
#define OBJ_X9cm		OBJ_X9_57,4L

#define SN_dsa		"DSA"
#define LN_dsa		"dsaEncryption"
#define NID_dsa		116
#define OBJ_dsa		OBJ_X9cm,1L

#define SN_dsaWithSHA1		"DSA-SHA1"
#define LN_dsaWithSHA1		"dsaWithSHA1"
#define NID_dsaWithSHA1		113
#define OBJ_dsaWithSHA1		OBJ_X9cm,3L

#define SN_cast5_cbc		"CAST5-CBC"
#define LN_cast5_cbc		"cast5-cbc"
#define NID_cast5_cbc		108
#define OBJ_cast5_cbc		OBJ_ISO_US,113533L,7L,66L,10L

#define SN_cast5_ecb		"CAST5-ECB"
#define LN_cast5_ecb		"cast5-ecb"
#define NID_cast5_ecb		109

#define SN_cast5_cfb64		"CAST5-CFB"
#define LN_cast5_cfb64		"cast5-cfb"
#define NID_cast5_cfb64		110

#define SN_cast5_ofb64		"CAST5-OFB"
#define LN_cast5_ofb64		"cast5-ofb"
#define NID_cast5_ofb64		111

#define LN_pbeWithMD5AndCast5_CBC		"pbeWithMD5AndCast5CBC"
#define NID_pbeWithMD5AndCast5_CBC		112
#define OBJ_pbeWithMD5AndCast5_CBC		OBJ_ISO_US,113533L,7L,66L,12L

#define SN_rsadsi		"rsadsi"
#define LN_rsadsi		"RSA Data Security, Inc."
#define NID_rsadsi		1
#define OBJ_rsadsi		OBJ_ISO_US,113549L

#define SN_pkcs		"pkcs"
#define LN_pkcs		"RSA Data Security, Inc. PKCS"
#define NID_pkcs		2
#define OBJ_pkcs		OBJ_rsadsi,1L

#define SN_pkcs1		"pkcs1"
#define NID_pkcs1		186
#define OBJ_pkcs1		OBJ_pkcs,1L

#define LN_rsaEncryption		"rsaEncryption"
#define NID_rsaEncryption		6
#define OBJ_rsaEncryption		OBJ_pkcs1,1L

#define SN_md2WithRSAEncryption		"RSA-MD2"
#define LN_md2WithRSAEncryption		"md2WithRSAEncryption"
#define NID_md2WithRSAEncryption		7
#define OBJ_md2WithRSAEncryption		OBJ_pkcs1,2L

#define SN_md4WithRSAEncryption		"RSA-MD4"
#define LN_md4WithRSAEncryption		"md4WithRSAEncryption"
#define NID_md4WithRSAEncryption		396
#define OBJ_md4WithRSAEncryption		OBJ_pkcs1,3L

#define SN_md5WithRSAEncryption		"RSA-MD5"
#define LN_md5WithRSAEncryption		"md5WithRSAEncryption"
#define NID_md5WithRSAEncryption		8
#define OBJ_md5WithRSAEncryption		OBJ_pkcs1,4L

#define SN_sha1WithRSAEncryption		"RSA-SHA1"
#define LN_sha1WithRSAEncryption		"sha1WithRSAEncryption"
#define NID_sha1WithRSAEncryption		65
#define OBJ_sha1WithRSAEncryption		OBJ_pkcs1,5L

#define SN_pkcs3		"pkcs3"
#define NID_pkcs3		27
#define OBJ_pkcs3		OBJ_pkcs,3L

#define LN_dhKeyAgreement		"dhKeyAgreement"
#define NID_dhKeyAgreement		28
#define OBJ_dhKeyAgreement		OBJ_pkcs3,1L

#define SN_pkcs5		"pkcs5"
#define NID_pkcs5		187
#define OBJ_pkcs5		OBJ_pkcs,5L

#define SN_pbeWithMD2AndDES_CBC		"PBE-MD2-DES"
#define LN_pbeWithMD2AndDES_CBC		"pbeWithMD2AndDES-CBC"
#define NID_pbeWithMD2AndDES_CBC		9
#define OBJ_pbeWithMD2AndDES_CBC		OBJ_pkcs5,1L

#define SN_pbeWithMD5AndDES_CBC		"PBE-MD5-DES"
#define LN_pbeWithMD5AndDES_CBC		"pbeWithMD5AndDES-CBC"
#define NID_pbeWithMD5AndDES_CBC		10
#define OBJ_pbeWithMD5AndDES_CBC		OBJ_pkcs5,3L

#define SN_pbeWithMD2AndRC2_CBC		"PBE-MD2-RC2-64"
#define LN_pbeWithMD2AndRC2_CBC		"pbeWithMD2AndRC2-CBC"
#define NID_pbeWithMD2AndRC2_CBC		168
#define OBJ_pbeWithMD2AndRC2_CBC		OBJ_pkcs5,4L

#define SN_pbeWithMD5AndRC2_CBC		"PBE-MD5-RC2-64"
#define LN_pbeWithMD5AndRC2_CBC		"pbeWithMD5AndRC2-CBC"
#define NID_pbeWithMD5AndRC2_CBC		169
#define OBJ_pbeWithMD5AndRC2_CBC		OBJ_pkcs5,6L

#define SN_pbeWithSHA1AndDES_CBC		"PBE-SHA1-DES"
#define LN_pbeWithSHA1AndDES_CBC		"pbeWithSHA1AndDES-CBC"
#define NID_pbeWithSHA1AndDES_CBC		170
#define OBJ_pbeWithSHA1AndDES_CBC		OBJ_pkcs5,10L

#define SN_pbeWithSHA1AndRC2_CBC		"PBE-SHA1-RC2-64"
#define LN_pbeWithSHA1AndRC2_CBC		"pbeWithSHA1AndRC2-CBC"
#define NID_pbeWithSHA1AndRC2_CBC		68
#define OBJ_pbeWithSHA1AndRC2_CBC		OBJ_pkcs5,11L

#define LN_id_pbkdf2		"PBKDF2"
#define NID_id_pbkdf2		69
#define OBJ_id_pbkdf2		OBJ_pkcs5,12L

#define LN_pbes2		"PBES2"
#define NID_pbes2		161
#define OBJ_pbes2		OBJ_pkcs5,13L

#define LN_pbmac1		"PBMAC1"
#define NID_pbmac1		162
#define OBJ_pbmac1		OBJ_pkcs5,14L

#define SN_pkcs7		"pkcs7"
#define NID_pkcs7		20
#define OBJ_pkcs7		OBJ_pkcs,7L

#define LN_pkcs7_data		"pkcs7-data"
#define NID_pkcs7_data		21
#define OBJ_pkcs7_data		OBJ_pkcs7,1L

#define LN_pkcs7_signed		"pkcs7-signedData"
#define NID_pkcs7_signed		22
#define OBJ_pkcs7_signed		OBJ_pkcs7,2L

#define LN_pkcs7_enveloped		"pkcs7-envelopedData"
#define NID_pkcs7_enveloped		23
#define OBJ_pkcs7_enveloped		OBJ_pkcs7,3L

#define LN_pkcs7_signedAndEnveloped		"pkcs7-signedAndEnvelopedData"
#define NID_pkcs7_signedAndEnveloped		24
#define OBJ_pkcs7_signedAndEnveloped		OBJ_pkcs7,4L

#define LN_pkcs7_digest		"pkcs7-digestData"
#define NID_pkcs7_digest		25
#define OBJ_pkcs7_digest		OBJ_pkcs7,5L

#define LN_pkcs7_encrypted		"pkcs7-encryptedData"
#define NID_pkcs7_encrypted		26
#define OBJ_pkcs7_encrypted		OBJ_pkcs7,6L

#define SN_pkcs9		"pkcs9"
#define NID_pkcs9		47
#define OBJ_pkcs9		OBJ_pkcs,9L

#define SN_pkcs9_emailAddress		"Email"
#define LN_pkcs9_emailAddress		"emailAddress"
#define NID_pkcs9_emailAddress		48
#define OBJ_pkcs9_emailAddress		OBJ_pkcs9,1L

#define LN_pkcs9_unstructuredName		"unstructuredName"
#define NID_pkcs9_unstructuredName		49
#define OBJ_pkcs9_unstructuredName		OBJ_pkcs9,2L

#define LN_pkcs9_contentType		"contentType"
#define NID_pkcs9_contentType		50
#define OBJ_pkcs9_contentType		OBJ_pkcs9,3L

#define LN_pkcs9_messageDigest		"messageDigest"
#define NID_pkcs9_messageDigest		51
#define OBJ_pkcs9_messageDigest		OBJ_pkcs9,4L

#define LN_pkcs9_signingTime		"signingTime"
#define NID_pkcs9_signingTime		52
#define OBJ_pkcs9_signingTime		OBJ_pkcs9,5L

#define LN_pkcs9_countersignature		"countersignature"
#define NID_pkcs9_countersignature		53
#define OBJ_pkcs9_countersignature		OBJ_pkcs9,6L

#define LN_pkcs9_challengePassword		"challengePassword"
#define NID_pkcs9_challengePassword		54
#define OBJ_pkcs9_challengePassword		OBJ_pkcs9,7L

#define LN_pkcs9_unstructuredAddress		"unstructuredAddress"
#define NID_pkcs9_unstructuredAddress		55
#define OBJ_pkcs9_unstructuredAddress		OBJ_pkcs9,8L

#define LN_pkcs9_extCertAttributes		"extendedCertificateAttributes"
#define NID_pkcs9_extCertAttributes		56
#define OBJ_pkcs9_extCertAttributes		OBJ_pkcs9,9L

#define SN_ext_req		"extReq"
#define LN_ext_req		"Extension Request"
#define NID_ext_req		172
#define OBJ_ext_req		OBJ_pkcs9,14L

#define SN_SMIMECapabilities		"SMIME-CAPS"
#define LN_SMIMECapabilities		"S/MIME Capabilities"
#define NID_SMIMECapabilities		167
#define OBJ_SMIMECapabilities		OBJ_pkcs9,15L

#define SN_SMIME		"SMIME"
#define LN_SMIME		"S/MIME"
#define NID_SMIME		188
#define OBJ_SMIME		OBJ_pkcs9,16L

#define SN_id_smime_mod		"id-smime-mod"
#define NID_id_smime_mod		189
#define OBJ_id_smime_mod		OBJ_SMIME,0L

#define SN_id_smime_ct		"id-smime-ct"
#define NID_id_smime_ct		190
#define OBJ_id_smime_ct		OBJ_SMIME,1L

#define SN_id_smime_aa		"id-smime-aa"
#define NID_id_smime_aa		191
#define OBJ_id_smime_aa		OBJ_SMIME,2L

#define SN_id_smime_alg		"id-smime-alg"
#define NID_id_smime_alg		192
#define OBJ_id_smime_alg		OBJ_SMIME,3L

#define SN_id_smime_cd		"id-smime-cd"
#define NID_id_smime_cd		193
#define OBJ_id_smime_cd		OBJ_SMIME,4L

#define SN_id_smime_spq		"id-smime-spq"
#define NID_id_smime_spq		194
#define OBJ_id_smime_spq		OBJ_SMIME,5L

#define SN_id_smime_cti		"id-smime-cti"
#define NID_id_smime_cti		195
#define OBJ_id_smime_cti		OBJ_SMIME,6L

#define SN_id_smime_mod_cms		"id-smime-mod-cms"
#define NID_id_smime_mod_cms		196
#define OBJ_id_smime_mod_cms		OBJ_id_smime_mod,1L

#define SN_id_smime_mod_ess		"id-smime-mod-ess"
#define NID_id_smime_mod_ess		197
#define OBJ_id_smime_mod_ess		OBJ_id_smime_mod,2L

#define SN_id_smime_mod_oid		"id-smime-mod-oid"
#define NID_id_smime_mod_oid		198
#define OBJ_id_smime_mod_oid		OBJ_id_smime_mod,3L

#define SN_id_smime_mod_msg_v3		"id-smime-mod-msg-v3"
#define NID_id_smime_mod_msg_v3		199
#define OBJ_id_smime_mod_msg_v3		OBJ_id_smime_mod,4L

#define SN_id_smime_mod_ets_eSignature_88		"id-smime-mod-ets-eSignature-88"
#define NID_id_smime_mod_ets_eSignature_88		200
#define OBJ_id_smime_mod_ets_eSignature_88		OBJ_id_smime_mod,5L

#define SN_id_smime_mod_ets_eSignature_97		"id-smime-mod-ets-eSignature-97"
#define NID_id_smime_mod_ets_eSignature_97		201
#define OBJ_id_smime_mod_ets_eSignature_97		OBJ_id_smime_mod,6L

#define SN_id_smime_mod_ets_eSigPolicy_88		"id-smime-mod-ets-eSigPolicy-88"
#define NID_id_smime_mod_ets_eSigPolicy_88		202
#define OBJ_id_smime_mod_ets_eSigPolicy_88		OBJ_id_smime_mod,7L

#define SN_id_smime_mod_ets_eSigPolicy_97		"id-smime-mod-ets-eSigPolicy-97"
#define NID_id_smime_mod_ets_eSigPolicy_97		203
#define OBJ_id_smime_mod_ets_eSigPolicy_97		OBJ_id_smime_mod,8L

#define SN_id_smime_ct_receipt		"id-smime-ct-receipt"
#define NID_id_smime_ct_receipt		204
#define OBJ_id_smime_ct_receipt		OBJ_id_smime_ct,1L

#define SN_id_smime_ct_authData		"id-smime-ct-authData"
#define NID_id_smime_ct_authData		205
#define OBJ_id_smime_ct_authData		OBJ_id_smime_ct,2L

#define SN_id_smime_ct_publishCert		"id-smime-ct-publishCert"
#define NID_id_smime_ct_publishCert		206
#define OBJ_id_smime_ct_publishCert		OBJ_id_smime_ct,3L

#define SN_id_smime_ct_TSTInfo		"id-smime-ct-TSTInfo"
#define NID_id_smime_ct_TSTInfo		207
#define OBJ_id_smime_ct_TSTInfo		OBJ_id_smime_ct,4L

#define SN_id_smime_ct_TDTInfo		"id-smime-ct-TDTInfo"
#define NID_id_smime_ct_TDTInfo		208
#define OBJ_id_smime_ct_TDTInfo		OBJ_id_smime_ct,5L

#define SN_id_smime_ct_contentInfo		"id-smime-ct-contentInfo"
#define NID_id_smime_ct_contentInfo		209
#define OBJ_id_smime_ct_contentInfo		OBJ_id_smime_ct,6L

#define SN_id_smime_ct_DVCSRequestData		"id-smime-ct-DVCSRequestData"
#define NID_id_smime_ct_DVCSRequestData		210
#define OBJ_id_smime_ct_DVCSRequestData		OBJ_id_smime_ct,7L

#define SN_id_smime_ct_DVCSResponseData		"id-smime-ct-DVCSResponseData"
#define NID_id_smime_ct_DVCSResponseData		211
#define OBJ_id_smime_ct_DVCSResponseData		OBJ_id_smime_ct,8L

#define SN_id_smime_aa_receiptRequest		"id-smime-aa-receiptRequest"
#define NID_id_smime_aa_receiptRequest		212
#define OBJ_id_smime_aa_receiptRequest		OBJ_id_smime_aa,1L

#define SN_id_smime_aa_securityLabel		"id-smime-aa-securityLabel"
#define NID_id_smime_aa_securityLabel		213
#define OBJ_id_smime_aa_securityLabel		OBJ_id_smime_aa,2L

#define SN_id_smime_aa_mlExpandHistory		"id-smime-aa-mlExpandHistory"
#define NID_id_smime_aa_mlExpandHistory		214
#define OBJ_id_smime_aa_mlExpandHistory		OBJ_id_smime_aa,3L

#define SN_id_smime_aa_contentHint		"id-smime-aa-contentHint"
#define NID_id_smime_aa_contentHint		215
#define OBJ_id_smime_aa_contentHint		OBJ_id_smime_aa,4L

#define SN_id_smime_aa_msgSigDigest		"id-smime-aa-msgSigDigest"
#define NID_id_smime_aa_msgSigDigest		216
#define OBJ_id_smime_aa_msgSigDigest		OBJ_id_smime_aa,5L

#define SN_id_smime_aa_encapContentType		"id-smime-aa-encapContentType"
#define NID_id_smime_aa_encapContentType		217
#define OBJ_id_smime_aa_encapContentType		OBJ_id_smime_aa,6L

#define SN_id_smime_aa_contentIdentifier		"id-smime-aa-contentIdentifier"
#define NID_id_smime_aa_contentIdentifier		218
#define OBJ_id_smime_aa_contentIdentifier		OBJ_id_smime_aa,7L

#define SN_id_smime_aa_macValue		"id-smime-aa-macValue"
#define NID_id_smime_aa_macValue		219
#define OBJ_id_smime_aa_macValue		OBJ_id_smime_aa,8L

#define SN_id_smime_aa_equivalentLabels		"id-smime-aa-equivalentLabels"
#define NID_id_smime_aa_equivalentLabels		220
#define OBJ_id_smime_aa_equivalentLabels		OBJ_id_smime_aa,9L

#define SN_id_smime_aa_contentReference		"id-smime-aa-contentReference"
#define NID_id_smime_aa_contentReference		221
#define OBJ_id_smime_aa_contentReference		OBJ_id_smime_aa,10L

#define SN_id_smime_aa_encrypKeyPref		"id-smime-aa-encrypKeyPref"
#define NID_id_smime_aa_encrypKeyPref		222
#define OBJ_id_smime_aa_encrypKeyPref		OBJ_id_smime_aa,11L

#define SN_id_smime_aa_signingCertificate		"id-smime-aa-signingCertificate"
#define NID_id_smime_aa_signingCertificate		223
#define OBJ_id_smime_aa_signingCertificate		OBJ_id_smime_aa,12L

#define SN_id_smime_aa_smimeEncryptCerts		"id-smime-aa-smimeEncryptCerts"
#define NID_id_smime_aa_smimeEncryptCerts		224
#define OBJ_id_smime_aa_smimeEncryptCerts		OBJ_id_smime_aa,13L

#define SN_id_smime_aa_timeStampToken		"id-smime-aa-timeStampToken"
#define NID_id_smime_aa_timeStampToken		225
#define OBJ_id_smime_aa_timeStampToken		OBJ_id_smime_aa,14L

#define SN_id_smime_aa_ets_sigPolicyId		"id-smime-aa-ets-sigPolicyId"
#define NID_id_smime_aa_ets_sigPolicyId		226
#define OBJ_id_smime_aa_ets_sigPolicyId		OBJ_id_smime_aa,15L

#define SN_id_smime_aa_ets_commitmentType		"id-smime-aa-ets-commitmentType"
#define NID_id_smime_aa_ets_commitmentType		227
#define OBJ_id_smime_aa_ets_commitmentType		OBJ_id_smime_aa,16L

#define SN_id_smime_aa_ets_signerLocation		"id-smime-aa-ets-signerLocation"
#define NID_id_smime_aa_ets_signerLocation		228
#define OBJ_id_smime_aa_ets_signerLocation		OBJ_id_smime_aa,17L

#define SN_id_smime_aa_ets_signerAttr		"id-smime-aa-ets-signerAttr"
#define NID_id_smime_aa_ets_signerAttr		229
#define OBJ_id_smime_aa_ets_signerAttr		OBJ_id_smime_aa,18L

#define SN_id_smime_aa_ets_otherSigCert		"id-smime-aa-ets-otherSigCert"
#define NID_id_smime_aa_ets_otherSigCert		230
#define OBJ_id_smime_aa_ets_otherSigCert		OBJ_id_smime_aa,19L

#define SN_id_smime_aa_ets_contentTimestamp		"id-smime-aa-ets-contentTimestamp"
#define NID_id_smime_aa_ets_contentTimestamp		231
#define OBJ_id_smime_aa_ets_contentTimestamp		OBJ_id_smime_aa,20L

#define SN_id_smime_aa_ets_CertificateRefs		"id-smime-aa-ets-CertificateRefs"
#define NID_id_smime_aa_ets_CertificateRefs		232
#define OBJ_id_smime_aa_ets_CertificateRefs		OBJ_id_smime_aa,21L

#define SN_id_smime_aa_ets_RevocationRefs		"id-smime-aa-ets-RevocationRefs"
#define NID_id_smime_aa_ets_RevocationRefs		233
#define OBJ_id_smime_aa_ets_RevocationRefs		OBJ_id_smime_aa,22L

#define SN_id_smime_aa_ets_certValues		"id-smime-aa-ets-certValues"
#define NID_id_smime_aa_ets_certValues		234
#define OBJ_id_smime_aa_ets_certValues		OBJ_id_smime_aa,23L

#define SN_id_smime_aa_ets_revocationValues		"id-smime-aa-ets-revocationValues"
#define NID_id_smime_aa_ets_revocationValues		235
#define OBJ_id_smime_aa_ets_revocationValues		OBJ_id_smime_aa,24L

#define SN_id_smime_aa_ets_escTimeStamp		"id-smime-aa-ets-escTimeStamp"
#define NID_id_smime_aa_ets_escTimeStamp		236
#define OBJ_id_smime_aa_ets_escTimeStamp		OBJ_id_smime_aa,25L

#define SN_id_smime_aa_ets_certCRLTimestamp		"id-smime-aa-ets-certCRLTimestamp"
#define NID_id_smime_aa_ets_certCRLTimestamp		237
#define OBJ_id_smime_aa_ets_certCRLTimestamp		OBJ_id_smime_aa,26L

#define SN_id_smime_aa_ets_archiveTimeStamp		"id-smime-aa-ets-archiveTimeStamp"
#define NID_id_smime_aa_ets_archiveTimeStamp		238
#define OBJ_id_smime_aa_ets_archiveTimeStamp		OBJ_id_smime_aa,27L

#define SN_id_smime_aa_signatureType		"id-smime-aa-signatureType"
#define NID_id_smime_aa_signatureType		239
#define OBJ_id_smime_aa_signatureType		OBJ_id_smime_aa,28L

#define SN_id_smime_aa_dvcs_dvc		"id-smime-aa-dvcs-dvc"
#define NID_id_smime_aa_dvcs_dvc		240
#define OBJ_id_smime_aa_dvcs_dvc		OBJ_id_smime_aa,29L

#define SN_id_smime_alg_ESDHwith3DES		"id-smime-alg-ESDHwith3DES"
#define NID_id_smime_alg_ESDHwith3DES		241
#define OBJ_id_smime_alg_ESDHwith3DES		OBJ_id_smime_alg,1L

#define SN_id_smime_alg_ESDHwithRC2		"id-smime-alg-ESDHwithRC2"
#define NID_id_smime_alg_ESDHwithRC2		242
#define OBJ_id_smime_alg_ESDHwithRC2		OBJ_id_smime_alg,2L

#define SN_id_smime_alg_3DESwrap		"id-smime-alg-3DESwrap"
#define NID_id_smime_alg_3DESwrap		243
#define OBJ_id_smime_alg_3DESwrap		OBJ_id_smime_alg,3L

#define SN_id_smime_alg_RC2wrap		"id-smime-alg-RC2wrap"
#define NID_id_smime_alg_RC2wrap		244
#define OBJ_id_smime_alg_RC2wrap		OBJ_id_smime_alg,4L

#define SN_id_smime_alg_ESDH		"id-smime-alg-ESDH"
#define NID_id_smime_alg_ESDH		245
#define OBJ_id_smime_alg_ESDH		OBJ_id_smime_alg,5L

#define SN_id_smime_alg_CMS3DESwrap		"id-smime-alg-CMS3DESwrap"
#define NID_id_smime_alg_CMS3DESwrap		246
#define OBJ_id_smime_alg_CMS3DESwrap		OBJ_id_smime_alg,6L

#define SN_id_smime_alg_CMSRC2wrap		"id-smime-alg-CMSRC2wrap"
#define NID_id_smime_alg_CMSRC2wrap		247
#define OBJ_id_smime_alg_CMSRC2wrap		OBJ_id_smime_alg,7L

#define SN_id_smime_cd_ldap		"id-smime-cd-ldap"
#define NID_id_smime_cd_ldap		248
#define OBJ_id_smime_cd_ldap		OBJ_id_smime_cd,1L

#define SN_id_smime_spq_ets_sqt_uri		"id-smime-spq-ets-sqt-uri"
#define NID_id_smime_spq_ets_sqt_uri		249
#define OBJ_id_smime_spq_ets_sqt_uri		OBJ_id_smime_spq,1L

#define SN_id_smime_spq_ets_sqt_unotice		"id-smime-spq-ets-sqt-unotice"
#define NID_id_smime_spq_ets_sqt_unotice		250
#define OBJ_id_smime_spq_ets_sqt_unotice		OBJ_id_smime_spq,2L

#define SN_id_smime_cti_ets_proofOfOrigin		"id-smime-cti-ets-proofOfOrigin"
#define NID_id_smime_cti_ets_proofOfOrigin		251
#define OBJ_id_smime_cti_ets_proofOfOrigin		OBJ_id_smime_cti,1L

#define SN_id_smime_cti_ets_proofOfReceipt		"id-smime-cti-ets-proofOfReceipt"
#define NID_id_smime_cti_ets_proofOfReceipt		252
#define OBJ_id_smime_cti_ets_proofOfReceipt		OBJ_id_smime_cti,2L

#define SN_id_smime_cti_ets_proofOfDelivery		"id-smime-cti-ets-proofOfDelivery"
#define NID_id_smime_cti_ets_proofOfDelivery		253
#define OBJ_id_smime_cti_ets_proofOfDelivery		OBJ_id_smime_cti,3L

#define SN_id_smime_cti_ets_proofOfSender		"id-smime-cti-ets-proofOfSender"
#define NID_id_smime_cti_ets_proofOfSender		254
#define OBJ_id_smime_cti_ets_proofOfSender		OBJ_id_smime_cti,4L

#define SN_id_smime_cti_ets_proofOfApproval		"id-smime-cti-ets-proofOfApproval"
#define NID_id_smime_cti_ets_proofOfApproval		255
#define OBJ_id_smime_cti_ets_proofOfApproval		OBJ_id_smime_cti,5L

#define SN_id_smime_cti_ets_proofOfCreation		"id-smime-cti-ets-proofOfCreation"
#define NID_id_smime_cti_ets_proofOfCreation		256
#define OBJ_id_smime_cti_ets_proofOfCreation		OBJ_id_smime_cti,6L

#define LN_friendlyName		"friendlyName"
#define NID_friendlyName		156
#define OBJ_friendlyName		OBJ_pkcs9,20L

#define LN_localKeyID		"localKeyID"
#define NID_localKeyID		157
#define OBJ_localKeyID		OBJ_pkcs9,21L

#define OBJ_certTypes		OBJ_pkcs9,22L

#define LN_x509Certificate		"x509Certificate"
#define NID_x509Certificate		158
#define OBJ_x509Certificate		OBJ_certTypes,1L

#define LN_sdsiCertificate		"sdsiCertificate"
#define NID_sdsiCertificate		159
#define OBJ_sdsiCertificate		OBJ_certTypes,2L

#define OBJ_crlTypes		OBJ_pkcs9,23L

#define LN_x509Crl		"x509Crl"
#define NID_x509Crl		160
#define OBJ_x509Crl		OBJ_crlTypes,1L

#define OBJ_pkcs12		OBJ_pkcs,12L

#define OBJ_pkcs12_pbeids		OBJ_pkcs12,1L

#define SN_pbe_WithSHA1And128BitRC4		"PBE-SHA1-RC4-128"
#define LN_pbe_WithSHA1And128BitRC4		"pbeWithSHA1And128BitRC4"
#define NID_pbe_WithSHA1And128BitRC4		144
#define OBJ_pbe_WithSHA1And128BitRC4		OBJ_pkcs12_pbeids,1L

#define SN_pbe_WithSHA1And40BitRC4		"PBE-SHA1-RC4-40"
#define LN_pbe_WithSHA1And40BitRC4		"pbeWithSHA1And40BitRC4"
#define NID_pbe_WithSHA1And40BitRC4		145
#define OBJ_pbe_WithSHA1And40BitRC4		OBJ_pkcs12_pbeids,2L

#define SN_pbe_WithSHA1And3_Key_TripleDES_CBC		"PBE-SHA1-3DES"
#define LN_pbe_WithSHA1And3_Key_TripleDES_CBC		"pbeWithSHA1And3-KeyTripleDES-CBC"
#define NID_pbe_WithSHA1And3_Key_TripleDES_CBC		146
#define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC		OBJ_pkcs12_pbeids,3L

#define SN_pbe_WithSHA1And2_Key_TripleDES_CBC		"PBE-SHA1-2DES"
#define LN_pbe_WithSHA1And2_Key_TripleDES_CBC		"pbeWithSHA1And2-KeyTripleDES-CBC"
#define NID_pbe_WithSHA1And2_Key_TripleDES_CBC		147
#define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC		OBJ_pkcs12_pbeids,4L

#define SN_pbe_WithSHA1And128BitRC2_CBC		"PBE-SHA1-RC2-128"
#define LN_pbe_WithSHA1And128BitRC2_CBC		"pbeWithSHA1And128BitRC2-CBC"
#define NID_pbe_WithSHA1And128BitRC2_CBC		148
#define OBJ_pbe_WithSHA1And128BitRC2_CBC		OBJ_pkcs12_pbeids,5L

#define SN_pbe_WithSHA1And40BitRC2_CBC		"PBE-SHA1-RC2-40"
#define LN_pbe_WithSHA1And40BitRC2_CBC		"pbeWithSHA1And40BitRC2-CBC"
#define NID_pbe_WithSHA1And40BitRC2_CBC		149
#define OBJ_pbe_WithSHA1And40BitRC2_CBC		OBJ_pkcs12_pbeids,6L

#define OBJ_pkcs12_Version1		OBJ_pkcs12,10L

#define OBJ_pkcs12_BagIds		OBJ_pkcs12_Version1,1L

#define LN_keyBag		"keyBag"
#define NID_keyBag		150
#define OBJ_keyBag		OBJ_pkcs12_BagIds,1L

#define LN_pkcs8ShroudedKeyBag		"pkcs8ShroudedKeyBag"
#define NID_pkcs8ShroudedKeyBag		151
#define OBJ_pkcs8ShroudedKeyBag		OBJ_pkcs12_BagIds,2L

#define LN_certBag		"certBag"
#define NID_certBag		152
#define OBJ_certBag		OBJ_pkcs12_BagIds,3L

#define LN_crlBag		"crlBag"
#define NID_crlBag		153
#define OBJ_crlBag		OBJ_pkcs12_BagIds,4L

#define LN_secretBag		"secretBag"
#define NID_secretBag		154
#define OBJ_secretBag		OBJ_pkcs12_BagIds,5L

#define LN_safeContentsBag		"safeContentsBag"
#define NID_safeContentsBag		155
#define OBJ_safeContentsBag		OBJ_pkcs12_BagIds,6L

#define SN_md2		"MD2"
#define LN_md2		"md2"
#define NID_md2		3
#define OBJ_md2		OBJ_rsadsi,2L,2L

#define SN_md4		"MD4"
#define LN_md4		"md4"
#define NID_md4		257
#define OBJ_md4		OBJ_rsadsi,2L,4L

#define SN_md5		"MD5"
#define LN_md5		"md5"
#define NID_md5		4
#define OBJ_md5		OBJ_rsadsi,2L,5L

#define SN_md5_sha1		"MD5-SHA1"
#define LN_md5_sha1		"md5-sha1"
#define NID_md5_sha1		114

#define LN_hmacWithSHA1		"hmacWithSHA1"
#define NID_hmacWithSHA1		163
#define OBJ_hmacWithSHA1		OBJ_rsadsi,2L,7L

#define SN_rc2_cbc		"RC2-CBC"
#define LN_rc2_cbc		"rc2-cbc"
#define NID_rc2_cbc		37
#define OBJ_rc2_cbc		OBJ_rsadsi,3L,2L

#define SN_rc2_ecb		"RC2-ECB"
#define LN_rc2_ecb		"rc2-ecb"
#define NID_rc2_ecb		38

#define SN_rc2_cfb64		"RC2-CFB"
#define LN_rc2_cfb64		"rc2-cfb"
#define NID_rc2_cfb64		39

#define SN_rc2_ofb64		"RC2-OFB"
#define LN_rc2_ofb64		"rc2-ofb"
#define NID_rc2_ofb64		40

#define SN_rc2_40_cbc		"RC2-40-CBC"
#define LN_rc2_40_cbc		"rc2-40-cbc"
#define NID_rc2_40_cbc		98

#define SN_rc2_64_cbc		"RC2-64-CBC"
#define LN_rc2_64_cbc		"rc2-64-cbc"
#define NID_rc2_64_cbc		166

#define SN_rc4		"RC4"
#define LN_rc4		"rc4"
#define NID_rc4		5
#define OBJ_rc4		OBJ_rsadsi,3L,4L

#define SN_rc4_40		"RC4-40"
#define LN_rc4_40		"rc4-40"
#define NID_rc4_40		97

#define SN_des_ede3_cbc		"DES-EDE3-CBC"
#define LN_des_ede3_cbc		"des-ede3-cbc"
#define NID_des_ede3_cbc		44
#define OBJ_des_ede3_cbc		OBJ_rsadsi,3L,7L

#define SN_rc5_cbc		"RC5-CBC"
#define LN_rc5_cbc		"rc5-cbc"
#define NID_rc5_cbc		120
#define OBJ_rc5_cbc		OBJ_rsadsi,3L,8L

#define SN_rc5_ecb		"RC5-ECB"
#define LN_rc5_ecb		"rc5-ecb"
#define NID_rc5_ecb		121

#define SN_rc5_cfb64		"RC5-CFB"
#define LN_rc5_cfb64		"rc5-cfb"
#define NID_rc5_cfb64		122

#define SN_rc5_ofb64		"RC5-OFB"
#define LN_rc5_ofb64		"rc5-ofb"
#define NID_rc5_ofb64		123

#define SN_ms_ext_req		"msExtReq"
#define LN_ms_ext_req		"Microsoft Extension Request"
#define NID_ms_ext_req		171
#define OBJ_ms_ext_req		1L,3L,6L,1L,4L,1L,311L,2L,1L,14L

#define SN_ms_code_ind		"msCodeInd"
#define LN_ms_code_ind		"Microsoft Individual Code Signing"
#define NID_ms_code_ind		134
#define OBJ_ms_code_ind		1L,3L,6L,1L,4L,1L,311L,2L,1L,21L

#define SN_ms_code_com		"msCodeCom"
#define LN_ms_code_com		"Microsoft Commercial Code Signing"
#define NID_ms_code_com		135
#define OBJ_ms_code_com		1L,3L,6L,1L,4L,1L,311L,2L,1L,22L

#define SN_ms_ctl_sign		"msCTLSign"
#define LN_ms_ctl_sign		"Microsoft Trust List Signing"
#define NID_ms_ctl_sign		136
#define OBJ_ms_ctl_sign		1L,3L,6L,1L,4L,1L,311L,10L,3L,1L

#define SN_ms_sgc		"msSGC"
#define LN_ms_sgc		"Microsoft Server Gated Crypto"
#define NID_ms_sgc		137
#define OBJ_ms_sgc		1L,3L,6L,1L,4L,1L,311L,10L,3L,3L

#define SN_ms_efs		"msEFS"
#define LN_ms_efs		"Microsoft Encrypted File System"
#define NID_ms_efs		138
#define OBJ_ms_efs		1L,3L,6L,1L,4L,1L,311L,10L,3L,4L

#define SN_idea_cbc		"IDEA-CBC"
#define LN_idea_cbc		"idea-cbc"
#define NID_idea_cbc		34
#define OBJ_idea_cbc		1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

#define SN_idea_ecb		"IDEA-ECB"
#define LN_idea_ecb		"idea-ecb"
#define NID_idea_ecb		36

#define SN_idea_cfb64		"IDEA-CFB"
#define LN_idea_cfb64		"idea-cfb"
#define NID_idea_cfb64		35

#define SN_idea_ofb64		"IDEA-OFB"
#define LN_idea_ofb64		"idea-ofb"
#define NID_idea_ofb64		46

#define SN_bf_cbc		"BF-CBC"
#define LN_bf_cbc		"bf-cbc"
#define NID_bf_cbc		91
#define OBJ_bf_cbc		1L,3L,6L,1L,4L,1L,3029L,1L,2L

#define SN_bf_ecb		"BF-ECB"
#define LN_bf_ecb		"bf-ecb"
#define NID_bf_ecb		92

#define SN_bf_cfb64		"BF-CFB"
#define LN_bf_cfb64		"bf-cfb"
#define NID_bf_cfb64		93

#define SN_bf_ofb64		"BF-OFB"
#define LN_bf_ofb64		"bf-ofb"
#define NID_bf_ofb64		94

#define SN_id_pkix		"PKIX"
#define NID_id_pkix		127
#define OBJ_id_pkix		1L,3L,6L,1L,5L,5L,7L

#define SN_id_pkix_mod		"id-pkix-mod"
#define NID_id_pkix_mod		258
#define OBJ_id_pkix_mod		OBJ_id_pkix,0L

#define SN_id_pe		"id-pe"
#define NID_id_pe		175
#define OBJ_id_pe		OBJ_id_pkix,1L

#define SN_id_qt		"id-qt"
#define NID_id_qt		259
#define OBJ_id_qt		OBJ_id_pkix,2L

#define SN_id_kp		"id-kp"
#define NID_id_kp		128
#define OBJ_id_kp		OBJ_id_pkix,3L

#define SN_id_it		"id-it"
#define NID_id_it		260
#define OBJ_id_it		OBJ_id_pkix,4L

#define SN_id_pkip		"id-pkip"
#define NID_id_pkip		261
#define OBJ_id_pkip		OBJ_id_pkix,5L

#define SN_id_alg		"id-alg"
#define NID_id_alg		262
#define OBJ_id_alg		OBJ_id_pkix,6L

#define SN_id_cmc		"id-cmc"
#define NID_id_cmc		263
#define OBJ_id_cmc		OBJ_id_pkix,7L

#define SN_id_on		"id-on"
#define NID_id_on		264
#define OBJ_id_on		OBJ_id_pkix,8L

#define SN_id_pda		"id-pda"
#define NID_id_pda		265
#define OBJ_id_pda		OBJ_id_pkix,9L

#define SN_id_aca		"id-aca"
#define NID_id_aca		266
#define OBJ_id_aca		OBJ_id_pkix,10L

#define SN_id_qcs		"id-qcs"
#define NID_id_qcs		267
#define OBJ_id_qcs		OBJ_id_pkix,11L

#define SN_id_cct		"id-cct"
#define NID_id_cct		268
#define OBJ_id_cct		OBJ_id_pkix,12L

#define SN_id_ad		"id-ad"
#define NID_id_ad		176
#define OBJ_id_ad		OBJ_id_pkix,48L

#define SN_id_pkix1_explicit_88		"id-pkix1-explicit-88"
#define NID_id_pkix1_explicit_88		269
#define OBJ_id_pkix1_explicit_88		OBJ_id_pkix_mod,1L

#define SN_id_pkix1_implicit_88		"id-pkix1-implicit-88"
#define NID_id_pkix1_implicit_88		270
#define OBJ_id_pkix1_implicit_88		OBJ_id_pkix_mod,2L

#define SN_id_pkix1_explicit_93		"id-pkix1-explicit-93"
#define NID_id_pkix1_explicit_93		271
#define OBJ_id_pkix1_explicit_93		OBJ_id_pkix_mod,3L

#define SN_id_pkix1_implicit_93		"id-pkix1-implicit-93"
#define NID_id_pkix1_implicit_93		272
#define OBJ_id_pkix1_implicit_93		OBJ_id_pkix_mod,4L

#define SN_id_mod_crmf		"id-mod-crmf"
#define NID_id_mod_crmf		273
#define OBJ_id_mod_crmf		OBJ_id_pkix_mod,5L

#define SN_id_mod_cmc		"id-mod-cmc"
#define NID_id_mod_cmc		274
#define OBJ_id_mod_cmc		OBJ_id_pkix_mod,6L

#define SN_id_mod_kea_profile_88		"id-mod-kea-profile-88"
#define NID_id_mod_kea_profile_88		275
#define OBJ_id_mod_kea_profile_88		OBJ_id_pkix_mod,7L

#define SN_id_mod_kea_profile_93		"id-mod-kea-profile-93"
#define NID_id_mod_kea_profile_93		276
#define OBJ_id_mod_kea_profile_93		OBJ_id_pkix_mod,8L

#define SN_id_mod_cmp		"id-mod-cmp"
#define NID_id_mod_cmp		277
#define OBJ_id_mod_cmp		OBJ_id_pkix_mod,9L

#define SN_id_mod_qualified_cert_88		"id-mod-qualified-cert-88"
#define NID_id_mod_qualified_cert_88		278
#define OBJ_id_mod_qualified_cert_88		OBJ_id_pkix_mod,10L

#define SN_id_mod_qualified_cert_93		"id-mod-qualified-cert-93"
#define NID_id_mod_qualified_cert_93		279
#define OBJ_id_mod_qualified_cert_93		OBJ_id_pkix_mod,11L

#define SN_id_mod_attribute_cert		"id-mod-attribute-cert"
#define NID_id_mod_attribute_cert		280
#define OBJ_id_mod_attribute_cert		OBJ_id_pkix_mod,12L

#define SN_id_mod_timestamp_protocol		"id-mod-timestamp-protocol"
#define NID_id_mod_timestamp_protocol		281
#define OBJ_id_mod_timestamp_protocol		OBJ_id_pkix_mod,13L

#define SN_id_mod_ocsp		"id-mod-ocsp"
#define NID_id_mod_ocsp		282
#define OBJ_id_mod_ocsp		OBJ_id_pkix_mod,14L

#define SN_id_mod_dvcs		"id-mod-dvcs"
#define NID_id_mod_dvcs		283
#define OBJ_id_mod_dvcs		OBJ_id_pkix_mod,15L

#define SN_id_mod_cmp2000		"id-mod-cmp2000"
#define NID_id_mod_cmp2000		284
#define OBJ_id_mod_cmp2000		OBJ_id_pkix_mod,16L

#define SN_info_access		"authorityInfoAccess"
#define LN_info_access		"Authority Information Access"
#define NID_info_access		177
#define OBJ_info_access		OBJ_id_pe,1L

#define SN_biometricInfo		"biometricInfo"
#define LN_biometricInfo		"Biometric Info"
#define NID_biometricInfo		285
#define OBJ_biometricInfo		OBJ_id_pe,2L

#define SN_qcStatements		"qcStatements"
#define NID_qcStatements		286
#define OBJ_qcStatements		OBJ_id_pe,3L

#define SN_ac_auditEntity		"ac-auditEntity"
#define NID_ac_auditEntity		287
#define OBJ_ac_auditEntity		OBJ_id_pe,4L

#define SN_ac_targeting		"ac-targeting"
#define NID_ac_targeting		288
#define OBJ_ac_targeting		OBJ_id_pe,5L

#define SN_aaControls		"aaControls"
#define NID_aaControls		289
#define OBJ_aaControls		OBJ_id_pe,6L

#define SN_sbqp_ipAddrBlock		"sbqp-ipAddrBlock"
#define NID_sbqp_ipAddrBlock		290
#define OBJ_sbqp_ipAddrBlock		OBJ_id_pe,7L

#define SN_sbqp_autonomousSysNum		"sbqp-autonomousSysNum"
#define NID_sbqp_autonomousSysNum		291
#define OBJ_sbqp_autonomousSysNum		OBJ_id_pe,8L

#define SN_sbqp_routerIdentifier		"sbqp-routerIdentifier"
#define NID_sbqp_routerIdentifier		292
#define OBJ_sbqp_routerIdentifier		OBJ_id_pe,9L

#define SN_ac_proxying		"ac-proxying"
#define NID_ac_proxying		397
#define OBJ_ac_proxying		OBJ_id_pe,10L

#define SN_sinfo_access		"subjectInfoAccess"
#define LN_sinfo_access		"Subject Information Access"
#define NID_sinfo_access		398
#define OBJ_sinfo_access		OBJ_id_pe,11L

#define SN_id_qt_cps		"id-qt-cps"
#define LN_id_qt_cps		"Policy Qualifier CPS"
#define NID_id_qt_cps		164
#define OBJ_id_qt_cps		OBJ_id_qt,1L

#define SN_id_qt_unotice		"id-qt-unotice"
#define LN_id_qt_unotice		"Policy Qualifier User Notice"
#define NID_id_qt_unotice		165
#define OBJ_id_qt_unotice		OBJ_id_qt,2L

#define SN_textNotice		"textNotice"
#define NID_textNotice		293
#define OBJ_textNotice		OBJ_id_qt,3L

#define SN_server_auth		"serverAuth"
#define LN_server_auth		"TLS Web Server Authentication"
#define NID_server_auth		129
#define OBJ_server_auth		OBJ_id_kp,1L

#define SN_client_auth		"clientAuth"
#define LN_client_auth		"TLS Web Client Authentication"
#define NID_client_auth		130
#define OBJ_client_auth		OBJ_id_kp,2L

#define SN_code_sign		"codeSigning"
#define LN_code_sign		"Code Signing"
#define NID_code_sign		131
#define OBJ_code_sign		OBJ_id_kp,3L

#define SN_email_protect		"emailProtection"
#define LN_email_protect		"E-mail Protection"
#define NID_email_protect		132
#define OBJ_email_protect		OBJ_id_kp,4L

#define SN_ipsecEndSystem		"ipsecEndSystem"
#define LN_ipsecEndSystem		"IPSec End System"
#define NID_ipsecEndSystem		294
#define OBJ_ipsecEndSystem		OBJ_id_kp,5L

#define SN_ipsecTunnel		"ipsecTunnel"
#define LN_ipsecTunnel		"IPSec Tunnel"
#define NID_ipsecTunnel		295
#define OBJ_ipsecTunnel		OBJ_id_kp,6L

#define SN_ipsecUser		"ipsecUser"
#define LN_ipsecUser		"IPSec User"
#define NID_ipsecUser		296
#define OBJ_ipsecUser		OBJ_id_kp,7L

#define SN_time_stamp		"timeStamping"
#define LN_time_stamp		"Time Stamping"
#define NID_time_stamp		133
#define OBJ_time_stamp		OBJ_id_kp,8L

#define SN_OCSP_sign		"OCSPSigning"
#define LN_OCSP_sign		"OCSP Signing"
#define NID_OCSP_sign		180
#define OBJ_OCSP_sign		OBJ_id_kp,9L

#define SN_dvcs		"DVCS"
#define LN_dvcs		"dvcs"
#define NID_dvcs		297
#define OBJ_dvcs		OBJ_id_kp,10L

#define SN_id_it_caProtEncCert		"id-it-caProtEncCert"
#define NID_id_it_caProtEncCert		298
#define OBJ_id_it_caProtEncCert		OBJ_id_it,1L

#define SN_id_it_signKeyPairTypes		"id-it-signKeyPairTypes"
#define NID_id_it_signKeyPairTypes		299
#define OBJ_id_it_signKeyPairTypes		OBJ_id_it,2L

#define SN_id_it_encKeyPairTypes		"id-it-encKeyPairTypes"
#define NID_id_it_encKeyPairTypes		300
#define OBJ_id_it_encKeyPairTypes		OBJ_id_it,3L

#define SN_id_it_preferredSymmAlg		"id-it-preferredSymmAlg"
#define NID_id_it_preferredSymmAlg		301
#define OBJ_id_it_preferredSymmAlg		OBJ_id_it,4L

#define SN_id_it_caKeyUpdateInfo		"id-it-caKeyUpdateInfo"
#define NID_id_it_caKeyUpdateInfo		302
#define OBJ_id_it_caKeyUpdateInfo		OBJ_id_it,5L

#define SN_id_it_currentCRL		"id-it-currentCRL"
#define NID_id_it_currentCRL		303
#define OBJ_id_it_currentCRL		OBJ_id_it,6L

#define SN_id_it_unsupportedOIDs		"id-it-unsupportedOIDs"
#define NID_id_it_unsupportedOIDs		304
#define OBJ_id_it_unsupportedOIDs		OBJ_id_it,7L

#define SN_id_it_subscriptionRequest		"id-it-subscriptionRequest"
#define NID_id_it_subscriptionRequest		305
#define OBJ_id_it_subscriptionRequest		OBJ_id_it,8L

#define SN_id_it_subscriptionResponse		"id-it-subscriptionResponse"
#define NID_id_it_subscriptionResponse		306
#define OBJ_id_it_subscriptionResponse		OBJ_id_it,9L

#define SN_id_it_keyPairParamReq		"id-it-keyPairParamReq"
#define NID_id_it_keyPairParamReq		307
#define OBJ_id_it_keyPairParamReq		OBJ_id_it,10L

#define SN_id_it_keyPairParamRep		"id-it-keyPairParamRep"
#define NID_id_it_keyPairParamRep		308
#define OBJ_id_it_keyPairParamRep		OBJ_id_it,11L

#define SN_id_it_revPassphrase		"id-it-revPassphrase"
#define NID_id_it_revPassphrase		309
#define OBJ_id_it_revPassphrase		OBJ_id_it,12L

#define SN_id_it_implicitConfirm		"id-it-implicitConfirm"
#define NID_id_it_implicitConfirm		310
#define OBJ_id_it_implicitConfirm		OBJ_id_it,13L

#define SN_id_it_confirmWaitTime		"id-it-confirmWaitTime"
#define NID_id_it_confirmWaitTime		311
#define OBJ_id_it_confirmWaitTime		OBJ_id_it,14L

#define SN_id_it_origPKIMessage		"id-it-origPKIMessage"
#define NID_id_it_origPKIMessage		312
#define OBJ_id_it_origPKIMessage		OBJ_id_it,15L

#define SN_id_regCtrl		"id-regCtrl"
#define NID_id_regCtrl		313
#define OBJ_id_regCtrl		OBJ_id_pkip,1L

#define SN_id_regInfo		"id-regInfo"
#define NID_id_regInfo		314
#define OBJ_id_regInfo		OBJ_id_pkip,2L

#define SN_id_regCtrl_regToken		"id-regCtrl-regToken"
#define NID_id_regCtrl_regToken		315
#define OBJ_id_regCtrl_regToken		OBJ_id_regCtrl,1L

#define SN_id_regCtrl_authenticator		"id-regCtrl-authenticator"
#define NID_id_regCtrl_authenticator		316
#define OBJ_id_regCtrl_authenticator		OBJ_id_regCtrl,2L

#define SN_id_regCtrl_pkiPublicationInfo		"id-regCtrl-pkiPublicationInfo"
#define NID_id_regCtrl_pkiPublicationInfo		317
#define OBJ_id_regCtrl_pkiPublicationInfo		OBJ_id_regCtrl,3L

#define SN_id_regCtrl_pkiArchiveOptions		"id-regCtrl-pkiArchiveOptions"
#define NID_id_regCtrl_pkiArchiveOptions		318
#define OBJ_id_regCtrl_pkiArchiveOptions		OBJ_id_regCtrl,4L

#define SN_id_regCtrl_oldCertID		"id-regCtrl-oldCertID"
#define NID_id_regCtrl_oldCertID		319
#define OBJ_id_regCtrl_oldCertID		OBJ_id_regCtrl,5L

#define SN_id_regCtrl_protocolEncrKey		"id-regCtrl-protocolEncrKey"
#define NID_id_regCtrl_protocolEncrKey		320
#define OBJ_id_regCtrl_protocolEncrKey		OBJ_id_regCtrl,6L

#define SN_id_regInfo_utf8Pairs		"id-regInfo-utf8Pairs"
#define NID_id_regInfo_utf8Pairs		321
#define OBJ_id_regInfo_utf8Pairs		OBJ_id_regInfo,1L

#define SN_id_regInfo_certReq		"id-regInfo-certReq"
#define NID_id_regInfo_certReq		322
#define OBJ_id_regInfo_certReq		OBJ_id_regInfo,2L

#define SN_id_alg_des40		"id-alg-des40"
#define NID_id_alg_des40		323
#define OBJ_id_alg_des40		OBJ_id_alg,1L

#define SN_id_alg_noSignature		"id-alg-noSignature"
#define NID_id_alg_noSignature		324
#define OBJ_id_alg_noSignature		OBJ_id_alg,2L

#define SN_id_alg_dh_sig_hmac_sha1		"id-alg-dh-sig-hmac-sha1"
#define NID_id_alg_dh_sig_hmac_sha1		325
#define OBJ_id_alg_dh_sig_hmac_sha1		OBJ_id_alg,3L

#define SN_id_alg_dh_pop		"id-alg-dh-pop"
#define NID_id_alg_dh_pop		326
#define OBJ_id_alg_dh_pop		OBJ_id_alg,4L

#define SN_id_cmc_statusInfo		"id-cmc-statusInfo"
#define NID_id_cmc_statusInfo		327
#define OBJ_id_cmc_statusInfo		OBJ_id_cmc,1L

#define SN_id_cmc_identification		"id-cmc-identification"
#define NID_id_cmc_identification		328
#define OBJ_id_cmc_identification		OBJ_id_cmc,2L

#define SN_id_cmc_identityProof		"id-cmc-identityProof"
#define NID_id_cmc_identityProof		329
#define OBJ_id_cmc_identityProof		OBJ_id_cmc,3L

#define SN_id_cmc_dataReturn		"id-cmc-dataReturn"
#define NID_id_cmc_dataReturn		330
#define OBJ_id_cmc_dataReturn		OBJ_id_cmc,4L

#define SN_id_cmc_transactionId		"id-cmc-transactionId"
#define NID_id_cmc_transactionId		331
#define OBJ_id_cmc_transactionId		OBJ_id_cmc,5L

#define SN_id_cmc_senderNonce		"id-cmc-senderNonce"
#define NID_id_cmc_senderNonce		332
#define OBJ_id_cmc_senderNonce		OBJ_id_cmc,6L

#define SN_id_cmc_recipientNonce		"id-cmc-recipientNonce"
#define NID_id_cmc_recipientNonce		333
#define OBJ_id_cmc_recipientNonce		OBJ_id_cmc,7L

#define SN_id_cmc_addExtensions		"id-cmc-addExtensions"
#define NID_id_cmc_addExtensions		334
#define OBJ_id_cmc_addExtensions		OBJ_id_cmc,8L

#define SN_id_cmc_encryptedPOP		"id-cmc-encryptedPOP"
#define NID_id_cmc_encryptedPOP		335
#define OBJ_id_cmc_encryptedPOP		OBJ_id_cmc,9L

#define SN_id_cmc_decryptedPOP		"id-cmc-decryptedPOP"
#define NID_id_cmc_decryptedPOP		336
#define OBJ_id_cmc_decryptedPOP		OBJ_id_cmc,10L

#define SN_id_cmc_lraPOPWitness		"id-cmc-lraPOPWitness"
#define NID_id_cmc_lraPOPWitness		337
#define OBJ_id_cmc_lraPOPWitness		OBJ_id_cmc,11L

#define SN_id_cmc_getCert		"id-cmc-getCert"
#define NID_id_cmc_getCert		338
#define OBJ_id_cmc_getCert		OBJ_id_cmc,15L

#define SN_id_cmc_getCRL		"id-cmc-getCRL"
#define NID_id_cmc_getCRL		339
#define OBJ_id_cmc_getCRL		OBJ_id_cmc,16L

#define SN_id_cmc_revokeRequest		"id-cmc-revokeRequest"
#define NID_id_cmc_revokeRequest		340
#define OBJ_id_cmc_revokeRequest		OBJ_id_cmc,17L

#define SN_id_cmc_regInfo		"id-cmc-regInfo"
#define NID_id_cmc_regInfo		341
#define OBJ_id_cmc_regInfo		OBJ_id_cmc,18L

#define SN_id_cmc_responseInfo		"id-cmc-responseInfo"
#define NID_id_cmc_responseInfo		342
#define OBJ_id_cmc_responseInfo		OBJ_id_cmc,19L

#define SN_id_cmc_queryPending		"id-cmc-queryPending"
#define NID_id_cmc_queryPending		343
#define OBJ_id_cmc_queryPending		OBJ_id_cmc,21L

#define SN_id_cmc_popLinkRandom		"id-cmc-popLinkRandom"
#define NID_id_cmc_popLinkRandom		344
#define OBJ_id_cmc_popLinkRandom		OBJ_id_cmc,22L

#define SN_id_cmc_popLinkWitness		"id-cmc-popLinkWitness"
#define NID_id_cmc_popLinkWitness		345
#define OBJ_id_cmc_popLinkWitness		OBJ_id_cmc,23L

#define SN_id_cmc_confirmCertAcceptance		"id-cmc-confirmCertAcceptance"
#define NID_id_cmc_confirmCertAcceptance		346
#define OBJ_id_cmc_confirmCertAcceptance		OBJ_id_cmc,24L

#define SN_id_on_personalData		"id-on-personalData"
#define NID_id_on_personalData		347
#define OBJ_id_on_personalData		OBJ_id_on,1L

#define SN_id_pda_dateOfBirth		"id-pda-dateOfBirth"
#define NID_id_pda_dateOfBirth		348
#define OBJ_id_pda_dateOfBirth		OBJ_id_pda,1L

#define SN_id_pda_placeOfBirth		"id-pda-placeOfBirth"
#define NID_id_pda_placeOfBirth		349
#define OBJ_id_pda_placeOfBirth		OBJ_id_pda,2L

#define SN_id_pda_gender		"id-pda-gender"
#define NID_id_pda_gender		351
#define OBJ_id_pda_gender		OBJ_id_pda,3L

#define SN_id_pda_countryOfCitizenship		"id-pda-countryOfCitizenship"
#define NID_id_pda_countryOfCitizenship		352
#define OBJ_id_pda_countryOfCitizenship		OBJ_id_pda,4L

#define SN_id_pda_countryOfResidence		"id-pda-countryOfResidence"
#define NID_id_pda_countryOfResidence		353
#define OBJ_id_pda_countryOfResidence		OBJ_id_pda,5L

#define SN_id_aca_authenticationInfo		"id-aca-authenticationInfo"
#define NID_id_aca_authenticationInfo		354
#define OBJ_id_aca_authenticationInfo		OBJ_id_aca,1L

#define SN_id_aca_accessIdentity		"id-aca-accessIdentity"
#define NID_id_aca_accessIdentity		355
#define OBJ_id_aca_accessIdentity		OBJ_id_aca,2L

#define SN_id_aca_chargingIdentity		"id-aca-chargingIdentity"
#define NID_id_aca_chargingIdentity		356
#define OBJ_id_aca_chargingIdentity		OBJ_id_aca,3L

#define SN_id_aca_group		"id-aca-group"
#define NID_id_aca_group		357
#define OBJ_id_aca_group		OBJ_id_aca,4L

#define SN_id_aca_role		"id-aca-role"
#define NID_id_aca_role		358
#define OBJ_id_aca_role		OBJ_id_aca,5L

#define SN_id_aca_encAttrs		"id-aca-encAttrs"
#define NID_id_aca_encAttrs		399
#define OBJ_id_aca_encAttrs		OBJ_id_aca,6L

#define SN_id_qcs_pkixQCSyntax_v1		"id-qcs-pkixQCSyntax-v1"
#define NID_id_qcs_pkixQCSyntax_v1		359
#define OBJ_id_qcs_pkixQCSyntax_v1		OBJ_id_qcs,1L

#define SN_id_cct_crs		"id-cct-crs"
#define NID_id_cct_crs		360
#define OBJ_id_cct_crs		OBJ_id_cct,1L

#define SN_id_cct_PKIData		"id-cct-PKIData"
#define NID_id_cct_PKIData		361
#define OBJ_id_cct_PKIData		OBJ_id_cct,2L

#define SN_id_cct_PKIResponse		"id-cct-PKIResponse"
#define NID_id_cct_PKIResponse		362
#define OBJ_id_cct_PKIResponse		OBJ_id_cct,3L

#define SN_ad_OCSP		"OCSP"
#define LN_ad_OCSP		"OCSP"
#define NID_ad_OCSP		178
#define OBJ_ad_OCSP		OBJ_id_ad,1L

#define SN_ad_ca_issuers		"caIssuers"
#define LN_ad_ca_issuers		"CA Issuers"
#define NID_ad_ca_issuers		179
#define OBJ_ad_ca_issuers		OBJ_id_ad,2L

#define SN_ad_timeStamping		"ad_timestamping"
#define LN_ad_timeStamping		"AD Time Stamping"
#define NID_ad_timeStamping		363
#define OBJ_ad_timeStamping		OBJ_id_ad,3L

#define SN_ad_dvcs		"AD_DVCS"
#define LN_ad_dvcs		"ad dvcs"
#define NID_ad_dvcs		364
#define OBJ_ad_dvcs		OBJ_id_ad,4L

#define OBJ_id_pkix_OCSP		OBJ_ad_OCSP

#define SN_id_pkix_OCSP_basic		"basicOCSPResponse"
#define LN_id_pkix_OCSP_basic		"Basic OCSP Response"
#define NID_id_pkix_OCSP_basic		365
#define OBJ_id_pkix_OCSP_basic		OBJ_id_pkix_OCSP,1L

#define SN_id_pkix_OCSP_Nonce		"Nonce"
#define LN_id_pkix_OCSP_Nonce		"OCSP Nonce"
#define NID_id_pkix_OCSP_Nonce		366
#define OBJ_id_pkix_OCSP_Nonce		OBJ_id_pkix_OCSP,2L

#define SN_id_pkix_OCSP_CrlID		"CrlID"
#define LN_id_pkix_OCSP_CrlID		"OCSP CRL ID"
#define NID_id_pkix_OCSP_CrlID		367
#define OBJ_id_pkix_OCSP_CrlID		OBJ_id_pkix_OCSP,3L

#define SN_id_pkix_OCSP_acceptableResponses		"acceptableResponses"
#define LN_id_pkix_OCSP_acceptableResponses		"Acceptable OCSP Responses"
#define NID_id_pkix_OCSP_acceptableResponses		368
#define OBJ_id_pkix_OCSP_acceptableResponses		OBJ_id_pkix_OCSP,4L

#define SN_id_pkix_OCSP_noCheck		"noCheck"
#define NID_id_pkix_OCSP_noCheck		369
#define OBJ_id_pkix_OCSP_noCheck		OBJ_id_pkix_OCSP,5L

#define SN_id_pkix_OCSP_archiveCutoff		"archiveCutoff"
#define LN_id_pkix_OCSP_archiveCutoff		"OCSP Archive Cutoff"
#define NID_id_pkix_OCSP_archiveCutoff		370
#define OBJ_id_pkix_OCSP_archiveCutoff		OBJ_id_pkix_OCSP,6L

#define SN_id_pkix_OCSP_serviceLocator		"serviceLocator"
#define LN_id_pkix_OCSP_serviceLocator		"OCSP Service Locator"
#define NID_id_pkix_OCSP_serviceLocator		371
#define OBJ_id_pkix_OCSP_serviceLocator		OBJ_id_pkix_OCSP,7L

#define SN_id_pkix_OCSP_extendedStatus		"extendedStatus"
#define LN_id_pkix_OCSP_extendedStatus		"Extended OCSP Status"
#define NID_id_pkix_OCSP_extendedStatus		372
#define OBJ_id_pkix_OCSP_extendedStatus		OBJ_id_pkix_OCSP,8L

#define SN_id_pkix_OCSP_valid		"valid"
#define NID_id_pkix_OCSP_valid		373
#define OBJ_id_pkix_OCSP_valid		OBJ_id_pkix_OCSP,9L

#define SN_id_pkix_OCSP_path		"path"
#define NID_id_pkix_OCSP_path		374
#define OBJ_id_pkix_OCSP_path		OBJ_id_pkix_OCSP,10L

#define SN_id_pkix_OCSP_trustRoot		"trustRoot"
#define LN_id_pkix_OCSP_trustRoot		"Trust Root"
#define NID_id_pkix_OCSP_trustRoot		375
#define OBJ_id_pkix_OCSP_trustRoot		OBJ_id_pkix_OCSP,11L

#define SN_algorithm		"algorithm"
#define LN_algorithm		"algorithm"
#define NID_algorithm		376
#define OBJ_algorithm		1L,3L,14L,3L,2L

#define SN_md5WithRSA		"RSA-NP-MD5"
#define LN_md5WithRSA		"md5WithRSA"
#define NID_md5WithRSA		104
#define OBJ_md5WithRSA		OBJ_algorithm,3L

#define SN_des_ecb		"DES-ECB"
#define LN_des_ecb		"des-ecb"
#define NID_des_ecb		29
#define OBJ_des_ecb		OBJ_algorithm,6L

#define SN_des_cbc		"DES-CBC"
#define LN_des_cbc		"des-cbc"
#define NID_des_cbc		31
#define OBJ_des_cbc		OBJ_algorithm,7L

#define SN_des_ofb64		"DES-OFB"
#define LN_des_ofb64		"des-ofb"
#define NID_des_ofb64		45
#define OBJ_des_ofb64		OBJ_algorithm,8L

#define SN_des_cfb64		"DES-CFB"
#define LN_des_cfb64		"des-cfb"
#define NID_des_cfb64		30
#define OBJ_des_cfb64		OBJ_algorithm,9L

#define SN_rsaSignature		"rsaSignature"
#define NID_rsaSignature		377
#define OBJ_rsaSignature		OBJ_algorithm,11L

#define SN_dsa_2		"DSA-old"
#define LN_dsa_2		"dsaEncryption-old"
#define NID_dsa_2		67
#define OBJ_dsa_2		OBJ_algorithm,12L

#define SN_dsaWithSHA		"DSA-SHA"
#define LN_dsaWithSHA		"dsaWithSHA"
#define NID_dsaWithSHA		66
#define OBJ_dsaWithSHA		OBJ_algorithm,13L

#define SN_shaWithRSAEncryption		"RSA-SHA"
#define LN_shaWithRSAEncryption		"shaWithRSAEncryption"
#define NID_shaWithRSAEncryption		42
#define OBJ_shaWithRSAEncryption		OBJ_algorithm,15L

#define SN_des_ede		"DES-EDE"
#define LN_des_ede		"des-ede"
#define NID_des_ede		32
#define OBJ_des_ede		OBJ_algorithm,17L

#define SN_des_ede3		"DES-EDE3"
#define LN_des_ede3		"des-ede3"
#define NID_des_ede3		33

#define SN_des_ede_cbc		"DES-EDE-CBC"
#define LN_des_ede_cbc		"des-ede-cbc"
#define NID_des_ede_cbc		43

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

#define SN_desx_cbc		"DESX-CBC"
#define LN_desx_cbc		"desx-cbc"
#define NID_desx_cbc		80

#define SN_sha		"SHA"
#define LN_sha		"sha"
#define NID_sha		41
#define OBJ_sha		OBJ_algorithm,18L

#define SN_sha1		"SHA1"
#define LN_sha1		"sha1"
#define NID_sha1		64
#define OBJ_sha1		OBJ_algorithm,26L

#define SN_dsaWithSHA1_2		"DSA-SHA1-old"
#define LN_dsaWithSHA1_2		"dsaWithSHA1-old"
#define NID_dsaWithSHA1_2		70
#define OBJ_dsaWithSHA1_2		OBJ_algorithm,27L

#define SN_sha1WithRSA		"RSA-SHA1-2"
#define LN_sha1WithRSA		"sha1WithRSA"
#define NID_sha1WithRSA		115
#define OBJ_sha1WithRSA		OBJ_algorithm,29L

#define SN_ripemd160		"RIPEMD160"
#define LN_ripemd160		"ripemd160"
#define NID_ripemd160		117
#define OBJ_ripemd160		1L,3L,36L,3L,2L,1L

#define SN_ripemd160WithRSA		"RSA-RIPEMD160"
#define LN_ripemd160WithRSA		"ripemd160WithRSA"
#define NID_ripemd160WithRSA		119
#define OBJ_ripemd160WithRSA		1L,3L,36L,3L,3L,1L,2L

#define SN_sxnet		"SXNetID"
#define LN_sxnet		"Strong Extranet ID"
#define NID_sxnet		143
#define OBJ_sxnet		1L,3L,101L,1L,4L,1L

#define SN_X500		"X500"
#define LN_X500		"directory services (X.500)"
#define NID_X500		11
#define OBJ_X500		2L,5L

#define SN_X509		"X509"
#define NID_X509		12
#define OBJ_X509		OBJ_X500,4L

#define SN_commonName		"CN"
#define LN_commonName		"commonName"
#define NID_commonName		13
#define OBJ_commonName		OBJ_X509,3L

#define SN_surname		"S"
#define LN_surname		"surname"
#define NID_surname		100
#define OBJ_surname		OBJ_X509,4L

#define SN_serialNumber		"SN"
#define LN_serialNumber		"serialNumber"
#define NID_serialNumber		105
#define OBJ_serialNumber		OBJ_X509,5L

#define SN_countryName		"C"
#define LN_countryName		"countryName"
#define NID_countryName		14
#define OBJ_countryName		OBJ_X509,6L

#define SN_localityName		"L"
#define LN_localityName		"localityName"
#define NID_localityName		15
#define OBJ_localityName		OBJ_X509,7L

#define SN_stateOrProvinceName		"ST"
#define LN_stateOrProvinceName		"stateOrProvinceName"
#define NID_stateOrProvinceName		16
#define OBJ_stateOrProvinceName		OBJ_X509,8L

#define SN_organizationName		"O"
#define LN_organizationName		"organizationName"
#define NID_organizationName		17
#define OBJ_organizationName		OBJ_X509,10L

#define SN_organizationalUnitName		"OU"
#define LN_organizationalUnitName		"organizationalUnitName"
#define NID_organizationalUnitName		18
#define OBJ_organizationalUnitName		OBJ_X509,11L

#define SN_title		"T"
#define LN_title		"title"
#define NID_title		106
#define OBJ_title		OBJ_X509,12L

#define SN_description		"D"
#define LN_description		"description"
#define NID_description		107
#define OBJ_description		OBJ_X509,13L

#define SN_name		"name"
#define LN_name		"name"
#define NID_name		173
#define OBJ_name		OBJ_X509,41L

#define SN_givenName		"G"
#define LN_givenName		"givenName"
#define NID_givenName		99
#define OBJ_givenName		OBJ_X509,42L

#define SN_initials		"I"
#define LN_initials		"initials"
#define NID_initials		101
#define OBJ_initials		OBJ_X509,43L

#define LN_uniqueIdentifier		"uniqueIdentifier"
#define NID_uniqueIdentifier		102
#define OBJ_uniqueIdentifier		OBJ_X509,45L

#define SN_dnQualifier		"dnQualifier"
#define LN_dnQualifier		"dnQualifier"
#define NID_dnQualifier		174
#define OBJ_dnQualifier		OBJ_X509,46L

#define SN_role		"role"
#define LN_role		"role"
#define NID_role		400
#define OBJ_role		OBJ_X509,72L

#define SN_X500algorithms		"X500algorithms"
#define LN_X500algorithms		"directory services - algorithms"
#define NID_X500algorithms		378
#define OBJ_X500algorithms		OBJ_X500,8L

#define SN_rsa		"RSA"
#define LN_rsa		"rsa"
#define NID_rsa		19
#define OBJ_rsa		OBJ_X500algorithms,1L,1L

#define SN_mdc2WithRSA		"RSA-MDC2"
#define LN_mdc2WithRSA		"mdc2WithRSA"
#define NID_mdc2WithRSA		96
#define OBJ_mdc2WithRSA		OBJ_X500algorithms,3L,100L

#define SN_mdc2		"MDC2"
#define LN_mdc2		"mdc2"
#define NID_mdc2		95
#define OBJ_mdc2		OBJ_X500algorithms,3L,101L

#define SN_id_ce		"id-ce"
#define NID_id_ce		81
#define OBJ_id_ce		OBJ_X500,29L

#define SN_subject_key_identifier		"subjectKeyIdentifier"
#define LN_subject_key_identifier		"X509v3 Subject Key Identifier"
#define NID_subject_key_identifier		82
#define OBJ_subject_key_identifier		OBJ_id_ce,14L

#define SN_key_usage		"keyUsage"
#define LN_key_usage		"X509v3 Key Usage"
#define NID_key_usage		83
#define OBJ_key_usage		OBJ_id_ce,15L

#define SN_private_key_usage_period		"privateKeyUsagePeriod"
#define LN_private_key_usage_period		"X509v3 Private Key Usage Period"
#define NID_private_key_usage_period		84
#define OBJ_private_key_usage_period		OBJ_id_ce,16L

#define SN_subject_alt_name		"subjectAltName"
#define LN_subject_alt_name		"X509v3 Subject Alternative Name"
#define NID_subject_alt_name		85
#define OBJ_subject_alt_name		OBJ_id_ce,17L

#define SN_issuer_alt_name		"issuerAltName"
#define LN_issuer_alt_name		"X509v3 Issuer Alternative Name"
#define NID_issuer_alt_name		86
#define OBJ_issuer_alt_name		OBJ_id_ce,18L

#define SN_basic_constraints		"basicConstraints"
#define LN_basic_constraints		"X509v3 Basic Constraints"
#define NID_basic_constraints		87
#define OBJ_basic_constraints		OBJ_id_ce,19L

#define SN_crl_number		"crlNumber"
#define LN_crl_number		"X509v3 CRL Number"
#define NID_crl_number		88
#define OBJ_crl_number		OBJ_id_ce,20L

#define SN_crl_reason		"CRLReason"
#define LN_crl_reason		"X509v3 CRL Reason Code"
#define NID_crl_reason		141
#define OBJ_crl_reason		OBJ_id_ce,21L

#define SN_invalidity_date		"invalidityDate"
#define LN_invalidity_date		"Invalidity Date"
#define NID_invalidity_date		142
#define OBJ_invalidity_date		OBJ_id_ce,24L

#define SN_delta_crl		"deltaCRL"
#define LN_delta_crl		"X509v3 Delta CRL Indicator"
#define NID_delta_crl		140
#define OBJ_delta_crl		OBJ_id_ce,27L

#define SN_crl_distribution_points		"crlDistributionPoints"
#define LN_crl_distribution_points		"X509v3 CRL Distribution Points"
#define NID_crl_distribution_points		103
#define OBJ_crl_distribution_points		OBJ_id_ce,31L

#define SN_certificate_policies		"certificatePolicies"
#define LN_certificate_policies		"X509v3 Certificate Policies"
#define NID_certificate_policies		89
#define OBJ_certificate_policies		OBJ_id_ce,32L

#define SN_authority_key_identifier		"authorityKeyIdentifier"
#define LN_authority_key_identifier		"X509v3 Authority Key Identifier"
#define NID_authority_key_identifier		90
#define OBJ_authority_key_identifier		OBJ_id_ce,35L

#define SN_policy_constraints		"policyConstraints"
#define LN_policy_constraints		"X509v3 Policy Constraints"
#define NID_policy_constraints		401
#define OBJ_policy_constraints		OBJ_id_ce,36L

#define SN_ext_key_usage		"extendedKeyUsage"
#define LN_ext_key_usage		"X509v3 Extended Key Usage"
#define NID_ext_key_usage		126
#define OBJ_ext_key_usage		OBJ_id_ce,37L

#define SN_target_information		"targetInformation"
#define LN_target_information		"X509v3 AC Targeting"
#define NID_target_information		402
#define OBJ_target_information		OBJ_id_ce,55L

#define SN_no_rev_avail		"noRevAvail"
#define LN_no_rev_avail		"X509v3 No Revocation Available"
#define NID_no_rev_avail		403
#define OBJ_no_rev_avail		OBJ_id_ce,56L

#define SN_netscape		"Netscape"
#define LN_netscape		"Netscape Communications Corp."
#define NID_netscape		57
#define OBJ_netscape		2L,16L,840L,1L,113730L

#define SN_netscape_cert_extension		"nsCertExt"
#define LN_netscape_cert_extension		"Netscape Certificate Extension"
#define NID_netscape_cert_extension		58
#define OBJ_netscape_cert_extension		OBJ_netscape,1L

#define SN_netscape_data_type		"nsDataType"
#define LN_netscape_data_type		"Netscape Data Type"
#define NID_netscape_data_type		59
#define OBJ_netscape_data_type		OBJ_netscape,2L

#define SN_netscape_cert_type		"nsCertType"
#define LN_netscape_cert_type		"Netscape Cert Type"
#define NID_netscape_cert_type		71
#define OBJ_netscape_cert_type		OBJ_netscape_cert_extension,1L

#define SN_netscape_base_url		"nsBaseUrl"
#define LN_netscape_base_url		"Netscape Base Url"
#define NID_netscape_base_url		72
#define OBJ_netscape_base_url		OBJ_netscape_cert_extension,2L

#define SN_netscape_revocation_url		"nsRevocationUrl"
#define LN_netscape_revocation_url		"Netscape Revocation Url"
#define NID_netscape_revocation_url		73
#define OBJ_netscape_revocation_url		OBJ_netscape_cert_extension,3L

#define SN_netscape_ca_revocation_url		"nsCaRevocationUrl"
#define LN_netscape_ca_revocation_url		"Netscape CA Revocation Url"
#define NID_netscape_ca_revocation_url		74
#define OBJ_netscape_ca_revocation_url		OBJ_netscape_cert_extension,4L

#define SN_netscape_renewal_url		"nsRenewalUrl"
#define LN_netscape_renewal_url		"Netscape Renewal Url"
#define NID_netscape_renewal_url		75
#define OBJ_netscape_renewal_url		OBJ_netscape_cert_extension,7L

#define SN_netscape_ca_policy_url		"nsCaPolicyUrl"
#define LN_netscape_ca_policy_url		"Netscape CA Policy Url"
#define NID_netscape_ca_policy_url		76
#define OBJ_netscape_ca_policy_url		OBJ_netscape_cert_extension,8L

#define SN_netscape_ssl_server_name		"nsSslServerName"
#define LN_netscape_ssl_server_name		"Netscape SSL Server Name"
#define NID_netscape_ssl_server_name		77
#define OBJ_netscape_ssl_server_name		OBJ_netscape_cert_extension,12L

#define SN_netscape_comment		"nsComment"
#define LN_netscape_comment		"Netscape Comment"
#define NID_netscape_comment		78
#define OBJ_netscape_comment		OBJ_netscape_cert_extension,13L

#define SN_netscape_cert_sequence		"nsCertSequence"
#define LN_netscape_cert_sequence		"Netscape Certificate Sequence"
#define NID_netscape_cert_sequence		79
#define OBJ_netscape_cert_sequence		OBJ_netscape_data_type,5L

#define SN_ns_sgc		"nsSGC"
#define LN_ns_sgc		"Netscape Server Gated Crypto"
#define NID_ns_sgc		139
#define OBJ_ns_sgc		OBJ_netscape,4L,1L

#define SN_org		"ORG"
#define LN_org		"org"
#define NID_org		379
#define OBJ_org		OBJ_iso,3L

#define SN_dod		"DOD"
#define LN_dod		"dod"
#define NID_dod		380
#define OBJ_dod		OBJ_org,6L

#define SN_iana		"IANA"
#define LN_iana		"iana"
#define NID_iana		381
#define OBJ_iana		OBJ_dod,1L

#define OBJ_internet		OBJ_iana

#define SN_Directory		"directory"
#define LN_Directory		"Directory"
#define NID_Directory		382
#define OBJ_Directory		OBJ_internet,1L

#define SN_Management		"mgmt"
#define LN_Management		"Management"
#define NID_Management		383
#define OBJ_Management		OBJ_internet,2L

#define SN_Experimental		"experimental"
#define LN_Experimental		"Experimental"
#define NID_Experimental		384
#define OBJ_Experimental		OBJ_internet,3L

#define SN_Private		"private"
#define LN_Private		"Private"
#define NID_Private		385
#define OBJ_Private		OBJ_internet,4L

#define SN_Security		"security"
#define LN_Security		"Security"
#define NID_Security		386
#define OBJ_Security		OBJ_internet,5L

#define SN_SNMPv2		"snmpv2"
#define LN_SNMPv2		"SNMPv2"
#define NID_SNMPv2		387
#define OBJ_SNMPv2		OBJ_internet,6L

#define SN_Mail		"mail"
#define LN_Mail		"Mail"
#define NID_Mail		388
#define OBJ_Mail		OBJ_internet,7L

#define SN_Enterprises		"enterprises"
#define LN_Enterprises		"Enterprises"
#define NID_Enterprises		389
#define OBJ_Enterprises		OBJ_private,1L

#define SN_dcObject		"dcobject"
#define LN_dcObject		"dcObject"
#define NID_dcObject		390
#define OBJ_dcObject		OBJ_enterprises,1466L,344L

#define SN_domainComponent		"DC"
#define LN_domainComponent		"domainComponent"
#define NID_domainComponent		391
#define OBJ_domainComponent		0L,9L,2342L,19200300L,100L,1L,25L

#define SN_Domain		"domain"
#define LN_Domain		"Domain"
#define NID_Domain		392
#define OBJ_Domain		0L,9L,2342L,19200300L,100L,4L,13L

#define SN_rle_compression		"RLE"
#define LN_rle_compression		"run length compression"
#define NID_rle_compression		124
#define OBJ_rle_compression		1L,1L,1L,1L,666L,1L

#define SN_zlib_compression		"ZLIB"
#define LN_zlib_compression		"zlib compression"
#define NID_zlib_compression		125
#define OBJ_zlib_compression		1L,1L,1L,1L,666L,2L

