/* lib/obj/obj_dat.h */
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

/* THIS FILE IS GENERATED FROM Objects.h by obj_dat.pl via the
 * following command:
 * perl obj_dat.pl < objects.h > obj_dat.h
 */

#define NUM_NID 97
#define NUM_SN 70
#define NUM_LN 96
#define NUM_OBJ 78

static unsigned char lvalues[515]={
0x2A,0x86,0x48,0x86,0xF7,0x0D,               /* [  0] OBJ_rsadsi */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,          /* [  6] OBJ_pkcs */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x02,     /* [ 13] OBJ_md2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,     /* [ 21] OBJ_md5 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x04,     /* [ 29] OBJ_rc4 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,/* [ 37] OBJ_rsaEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x02,/* [ 46] OBJ_md2WithRSAEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x04,/* [ 55] OBJ_md5WithRSAEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x01,/* [ 64] OBJ_pbeWithMD2AndDES_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x03,/* [ 73] OBJ_pbeWithMD5AndDES_CBC */
0x55,                                        /* [ 82] OBJ_X500 */
0x55,0x04,                                   /* [ 83] OBJ_X509 */
0x55,0x04,0x03,                              /* [ 85] OBJ_commonName */
0x55,0x04,0x06,                              /* [ 88] OBJ_countryName */
0x55,0x04,0x07,                              /* [ 91] OBJ_localityName */
0x55,0x04,0x08,                              /* [ 94] OBJ_stateOrProvinceName */
0x55,0x04,0x0A,                              /* [ 97] OBJ_organizationName */
0x55,0x04,0x0B,                              /* [100] OBJ_organizationalUnitName */
0x55,0x08,0x01,0x01,                         /* [103] OBJ_rsa */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,     /* [107] OBJ_pkcs7 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01,/* [115] OBJ_pkcs7_data */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02,/* [124] OBJ_pkcs7_signed */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x03,/* [133] OBJ_pkcs7_enveloped */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x04,/* [142] OBJ_pkcs7_signedAndEnveloped */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x05,/* [151] OBJ_pkcs7_digest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x06,/* [160] OBJ_pkcs7_encrypted */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x03,     /* [169] OBJ_pkcs3 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x03,0x01,/* [177] OBJ_dhKeyAgreement */
0x2B,0x0E,0x03,0x02,0x06,                    /* [186] OBJ_des_ecb */
0x2B,0x0E,0x03,0x02,0x09,                    /* [191] OBJ_des_cfb64 */
0x2B,0x0E,0x03,0x02,0x07,                    /* [196] OBJ_des_cbc */
0x2B,0x0E,0x03,0x02,0x11,                    /* [201] OBJ_des_ede */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x02,     /* [206] OBJ_rc2_cbc */
0x2B,0x0E,0x03,0x02,0x12,                    /* [214] OBJ_sha */
0x2B,0x0E,0x03,0x02,0x0F,                    /* [219] OBJ_shaWithRSAEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x07,     /* [224] OBJ_des_ede3_cbc */
0x2B,0x0E,0x03,0x02,0x08,                    /* [232] OBJ_des_ofb64 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,     /* [237] OBJ_pkcs9 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x01,/* [245] OBJ_pkcs9_emailAddress */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x02,/* [254] OBJ_pkcs9_unstructuredName */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03,/* [263] OBJ_pkcs9_contentType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04,/* [272] OBJ_pkcs9_messageDigest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x05,/* [281] OBJ_pkcs9_signingTime */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x06,/* [290] OBJ_pkcs9_countersignature */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x07,/* [299] OBJ_pkcs9_challengePassword */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x08,/* [308] OBJ_pkcs9_unstructuredAddress */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x09,/* [317] OBJ_pkcs9_extCertAttributes */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,          /* [326] OBJ_netscape */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,     /* [333] OBJ_netscape_cert_extension */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x02,     /* [341] OBJ_netscape_data_type */
0x2B,0x0E,0x03,0x02,0x1A,                    /* [349] OBJ_sha1 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05,/* [354] OBJ_sha1WithRSAEncryption */
0x2B,0x0E,0x03,0x02,0x0D,                    /* [363] OBJ_dsaWithSHA */
0x2B,0x0E,0x03,0x02,0x0C,                    /* [368] OBJ_dsa */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0B,/* [373] OBJ_pbeWithSHA1AndRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C,/* [382] OBJ_pbeWithSHA1AndRC4 */
0x2B,0x0E,0x03,0x02,0x1B,                    /* [391] OBJ_dsaWithSHA1 */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x01,/* [396] OBJ_netscape_cert_type */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x02,/* [405] OBJ_netscape_base_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x03,/* [414] OBJ_netscape_revocation_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x04,/* [423] OBJ_netscape_ca_revocation_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x07,/* [432] OBJ_netscape_renewal_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x08,/* [441] OBJ_netscape_ca_policy_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x0C,/* [450] OBJ_netscape_ssl_server_name */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x0D,/* [459] OBJ_netscape_comment */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x02,0x05,/* [468] OBJ_netscape_cert_sequence */
0x55,0x1D,                                   /* [477] OBJ_ld_ce */
0x55,0x1D,0x0E,                              /* [479] OBJ_subject_key_identifier */
0x55,0x1D,0x0F,                              /* [482] OBJ_key_usage */
0x55,0x1D,0x10,                              /* [485] OBJ_private_key_usage_period */
0x55,0x1D,0x11,                              /* [488] OBJ_subject_alt_name */
0x55,0x1D,0x12,                              /* [491] OBJ_issuer_alt_name */
0x55,0x1D,0x13,                              /* [494] OBJ_basic_constraints */
0x55,0x1D,0x14,                              /* [497] OBJ_crl_number */
0x55,0x1D,0x20,                              /* [500] OBJ_certificate_policies */
0x55,0x1D,0x23,                              /* [503] OBJ_authority_key_identifier */
0x55,0x08,0x03,0x65,                         /* [506] OBJ_mdc2 */
0x55,0x08,0x03,0x64,                         /* [510] OBJ_mdc2WithRSA */
};

static ASN1_OBJECT nid_objs[NUM_NID]={
{"UNDEF","undefined",NID_undef,0,NULL},
{"rsadsi","rsadsi",NID_rsadsi,6,&(lvalues[0]),0},
{"pkcs","pkcs",NID_pkcs,7,&(lvalues[6]),0},
{"MD2","md2",NID_md2,8,&(lvalues[13]),0},
{"MD5","md5",NID_md5,8,&(lvalues[21]),0},
{"RC4","rc4",NID_rc4,8,&(lvalues[29]),0},
{"rsaEncryption","rsaEncryption",NID_rsaEncryption,9,&(lvalues[37]),0},
{"RSA-MD2","md2WithRSAEncryption",NID_md2WithRSAEncryption,9,
	&(lvalues[46]),0},
{"RSA-MD5","md5WithRSAEncryption",NID_md5WithRSAEncryption,9,
	&(lvalues[55]),0},
{"pbeWithMD2AndDES-CBC","pbeWithMD2AndDES-CBC",
	NID_pbeWithMD2AndDES_CBC,9,&(lvalues[64]),0},
{"pbeWithMD5AndDES-CBC","pbeWithMD5AndDES-CBC",
	NID_pbeWithMD5AndDES_CBC,9,&(lvalues[73]),0},
{"X500","X500",NID_X500,1,&(lvalues[82]),0},
{"X509","X509",NID_X509,2,&(lvalues[83]),0},
{"CN","commonName",NID_commonName,3,&(lvalues[85]),0},
{"C","countryName",NID_countryName,3,&(lvalues[88]),0},
{"L","localityName",NID_localityName,3,&(lvalues[91]),0},
{"ST","stateOrProvinceName",NID_stateOrProvinceName,3,&(lvalues[94]),0},
{"O","organizationName",NID_organizationName,3,&(lvalues[97]),0},
{"OU","organizationalUnitName",NID_organizationalUnitName,3,
	&(lvalues[100]),0},
{"RSA","rsa",NID_rsa,4,&(lvalues[103]),0},
{"pkcs7","pkcs7",NID_pkcs7,8,&(lvalues[107]),0},
{"pkcs7-data","pkcs7-data",NID_pkcs7_data,9,&(lvalues[115]),0},
{"pkcs7-signedData","pkcs7-signedData",NID_pkcs7_signed,9,
	&(lvalues[124]),0},
{"pkcs7-envelopedData","pkcs7-envelopedData",NID_pkcs7_enveloped,9,
	&(lvalues[133]),0},
{"pkcs7-signedAndEnvelopedData","pkcs7-signedAndEnvelopedData",
	NID_pkcs7_signedAndEnveloped,9,&(lvalues[142]),0},
{"pkcs7-digestData","pkcs7-digestData",NID_pkcs7_digest,9,
	&(lvalues[151]),0},
{"pkcs7-encryptedData","pkcs7-encryptedData",NID_pkcs7_encrypted,9,
	&(lvalues[160]),0},
{"pkcs3","pkcs3",NID_pkcs3,8,&(lvalues[169]),0},
{"dhKeyAgreement","dhKeyAgreement",NID_dhKeyAgreement,9,
	&(lvalues[177]),0},
{"DES-ECB","des-ecb",NID_des_ecb,5,&(lvalues[186]),0},
{"DES-CFB","des-cfb",NID_des_cfb64,5,&(lvalues[191]),0},
{"DES-CBC","des-cbc",NID_des_cbc,5,&(lvalues[196]),0},
{"DES-EDE","des-ede",NID_des_ede,5,&(lvalues[201]),0},
{"DES-EDE3","des-ede3",NID_des_ede3,0,NULL},
{"IDEA-CBC","idea-cbc",NID_idea_cbc,0,NULL},
{"IDEA-CFB","idea-cfb",NID_idea_cfb64,0,NULL},
{"IDEA-ECB","idea-ecb",NID_idea_ecb,0,NULL},
{"RC2-CBC","rc2-cbc",NID_rc2_cbc,8,&(lvalues[206]),0},
{"RC2-ECB","rc2-ecb",NID_rc2_ecb,0,NULL},
{"RC2-CFB","rc2-cfb",NID_rc2_cfb64,0,NULL},
{"RC2-OFB","rc2-ofb",NID_rc2_ofb64,0,NULL},
{"SHA","sha",NID_sha,5,&(lvalues[214]),0},
{"RSA-SHA","shaWithRSAEncryption",NID_shaWithRSAEncryption,5,
	&(lvalues[219]),0},
{"DES-EDE-CBC","des-ede-cbc",NID_des_ede_cbc,0,NULL},
{"DES-EDE3-CBC","des-ede3-cbc",NID_des_ede3_cbc,8,&(lvalues[224]),0},
{"DES-OFB","des-ofb",NID_des_ofb64,5,&(lvalues[232]),0},
{"IDEA-OFB","idea-ofb",NID_idea_ofb64,0,NULL},
{"pkcs9","pkcs9",NID_pkcs9,8,&(lvalues[237]),0},
{"Email","emailAddress",NID_pkcs9_emailAddress,9,&(lvalues[245]),0},
{"unstructuredName","unstructuredName",NID_pkcs9_unstructuredName,9,
	&(lvalues[254]),0},
{"contentType","contentType",NID_pkcs9_contentType,9,&(lvalues[263]),0},
{"messageDigest","messageDigest",NID_pkcs9_messageDigest,9,
	&(lvalues[272]),0},
{"signingTime","signingTime",NID_pkcs9_signingTime,9,&(lvalues[281]),0},
{"countersignature","countersignature",NID_pkcs9_countersignature,9,
	&(lvalues[290]),0},
{"challengePassword","challengePassword",NID_pkcs9_challengePassword,
	9,&(lvalues[299]),0},
{"unstructuredAddress","unstructuredAddress",
	NID_pkcs9_unstructuredAddress,9,&(lvalues[308]),0},
{"extendedCertificateAttributes","extendedCertificateAttributes",
	NID_pkcs9_extCertAttributes,9,&(lvalues[317]),0},
{"Netscape","Netscape Communications Corp.",NID_netscape,7,
	&(lvalues[326]),0},
{"nsCertExt","Netscape Certificate Extension",
	NID_netscape_cert_extension,8,&(lvalues[333]),0},
{"nsDataType","Netscape Data Type",NID_netscape_data_type,8,
	&(lvalues[341]),0},
{"DES-EDE-CFB","des-ede-cfb",NID_des_ede_cfb64,0,NULL},
{"DES-EDE3-CFB","des-ede3-cfb",NID_des_ede3_cfb64,0,NULL},
{"DES-EDE-OFB","des-ede-ofb",NID_des_ede_ofb64,0,NULL},
{"DES-EDE3-OFB","des-ede3-ofb",NID_des_ede3_ofb64,0,NULL},
{"SHA1","sha1",NID_sha1,5,&(lvalues[349]),0},
{"RSA-SHA1","sha1WithRSAEncryption",NID_sha1WithRSAEncryption,9,
	&(lvalues[354]),0},
{"DSA-SHA","dsaWithSHA",NID_dsaWithSHA,5,&(lvalues[363]),0},
{"DSA","dsaEncryption",NID_dsa,5,&(lvalues[368]),0},
{"pbeWithSHA1AndRC2-CBC","pbeWithSHA1AndRC2-CBC",
	NID_pbeWithSHA1AndRC2_CBC,9,&(lvalues[373]),0},
{"pbeWithSHA1AndRC4","pbeWithSHA1AndRC4",NID_pbeWithSHA1AndRC4,9,
	&(lvalues[382]),0},
{"DSA-SHA1","dsaWithSHA1",NID_dsaWithSHA1,5,&(lvalues[391]),0},
{"nsCertType","Netscape Cert Type",NID_netscape_cert_type,9,
	&(lvalues[396]),0},
{"nsBaseUrl","Netscape Base Url",NID_netscape_base_url,9,
	&(lvalues[405]),0},
{"nsRevocationUrl","Netscape Revocation Url",
	NID_netscape_revocation_url,9,&(lvalues[414]),0},
{"nsCaRevocationUrl","Netscape CA Revocation Url",
	NID_netscape_ca_revocation_url,9,&(lvalues[423]),0},
{"nsRenewalUrl","Netscape Renewal Url",NID_netscape_renewal_url,9,
	&(lvalues[432]),0},
{"nsCaPolicyUrl","Netscape CA Policy Url",NID_netscape_ca_policy_url,
	9,&(lvalues[441]),0},
{"nsSslServerName","Netscape SSL Server Name",
	NID_netscape_ssl_server_name,9,&(lvalues[450]),0},
{"nsComment","Netscape Comment",NID_netscape_comment,9,&(lvalues[459]),0},
{"nsCertSequence","Netscape Certificate Sequence",
	NID_netscape_cert_sequence,9,&(lvalues[468]),0},
{"DESX-CBC","desx-cbc",NID_desx_cbc,0,NULL},
{"ld-ce","ld-ce",NID_ld_ce,2,&(lvalues[477]),0},
{"subjectKeyIdentifier","X509v3 Subject Key Identifier",
	NID_subject_key_identifier,3,&(lvalues[479]),0},
{"keyUsage","X509v3 Key Usage",NID_key_usage,3,&(lvalues[482]),0},
{"privateKeyUsagePeriod","X509v3 Private Key Usage Period",
	NID_private_key_usage_period,3,&(lvalues[485]),0},
{"subjectAltName","X509v3 Subject Alternative Name",
	NID_subject_alt_name,3,&(lvalues[488]),0},
{"issuerAltName","X509v3 Issuer Alternative Name",NID_issuer_alt_name,
	3,&(lvalues[491]),0},
{"basicConstraints","X509v3 Basic Constraints",NID_basic_constraints,
	3,&(lvalues[494]),0},
{"crlNumber","X509v3 CRL Number",NID_crl_number,3,&(lvalues[497]),0},
{"certificatePolicies","X509v3 Certificate Policies",
	NID_certificate_policies,3,&(lvalues[500]),0},
{"authorityKeyIdentifier","X509v3 Authority Key Identifier",
	NID_authority_key_identifier,3,&(lvalues[503]),0},
{"BF-CBC","bf-cbc",NID_bf_cbc,0,NULL},
{"BF-ECB","bf-ecb",NID_bf_ecb,0,NULL},
{"BF-CFB","bf-cfb",NID_bf_cfb64,0,NULL},
{"BF-OFB","bf-ofb",NID_bf_ofb64,0,NULL},
{"MDC2","mdc2",NID_mdc2,4,&(lvalues[506]),0},
{"RSA-MDC2","mdc2withRSA",NID_mdc2WithRSA,4,&(lvalues[510]),0},
};

static ASN1_OBJECT *sn_objs[NUM_SN]={
&(nid_objs[91]),/* "BF-CBC" */
&(nid_objs[93]),/* "BF-CFB" */
&(nid_objs[92]),/* "BF-ECB" */
&(nid_objs[94]),/* "BF-OFB" */
&(nid_objs[14]),/* "C" */
&(nid_objs[13]),/* "CN" */
&(nid_objs[31]),/* "DES-CBC" */
&(nid_objs[30]),/* "DES-CFB" */
&(nid_objs[29]),/* "DES-ECB" */
&(nid_objs[32]),/* "DES-EDE" */
&(nid_objs[43]),/* "DES-EDE-CBC" */
&(nid_objs[60]),/* "DES-EDE-CFB" */
&(nid_objs[62]),/* "DES-EDE-OFB" */
&(nid_objs[33]),/* "DES-EDE3" */
&(nid_objs[44]),/* "DES-EDE3-CBC" */
&(nid_objs[61]),/* "DES-EDE3-CFB" */
&(nid_objs[63]),/* "DES-EDE3-OFB" */
&(nid_objs[45]),/* "DES-OFB" */
&(nid_objs[80]),/* "DESX-CBC" */
&(nid_objs[67]),/* "DSA" */
&(nid_objs[66]),/* "DSA-SHA" */
&(nid_objs[70]),/* "DSA-SHA1" */
&(nid_objs[48]),/* "Email" */
&(nid_objs[34]),/* "IDEA-CBC" */
&(nid_objs[35]),/* "IDEA-CFB" */
&(nid_objs[36]),/* "IDEA-ECB" */
&(nid_objs[46]),/* "IDEA-OFB" */
&(nid_objs[15]),/* "L" */
&(nid_objs[ 3]),/* "MD2" */
&(nid_objs[ 4]),/* "MD5" */
&(nid_objs[95]),/* "MDC2" */
&(nid_objs[57]),/* "Netscape" */
&(nid_objs[17]),/* "O" */
&(nid_objs[18]),/* "OU" */
&(nid_objs[37]),/* "RC2-CBC" */
&(nid_objs[39]),/* "RC2-CFB" */
&(nid_objs[38]),/* "RC2-ECB" */
&(nid_objs[40]),/* "RC2-OFB" */
&(nid_objs[ 5]),/* "RC4" */
&(nid_objs[19]),/* "RSA" */
&(nid_objs[ 7]),/* "RSA-MD2" */
&(nid_objs[ 8]),/* "RSA-MD5" */
&(nid_objs[96]),/* "RSA-MDC2" */
&(nid_objs[42]),/* "RSA-SHA" */
&(nid_objs[65]),/* "RSA-SHA1" */
&(nid_objs[41]),/* "SHA" */
&(nid_objs[64]),/* "SHA1" */
&(nid_objs[16]),/* "ST" */
&(nid_objs[ 0]),/* "UNDEF" */
&(nid_objs[90]),/* "authorityKeyIdentifier" */
&(nid_objs[87]),/* "basicConstraints" */
&(nid_objs[89]),/* "certificatePolicies" */
&(nid_objs[88]),/* "crlNumber" */
&(nid_objs[86]),/* "issuerAltName" */
&(nid_objs[83]),/* "keyUsage" */
&(nid_objs[81]),/* "ld-ce" */
&(nid_objs[72]),/* "nsBaseUrl" */
&(nid_objs[76]),/* "nsCaPolicyUrl" */
&(nid_objs[74]),/* "nsCaRevocationUrl" */
&(nid_objs[58]),/* "nsCertExt" */
&(nid_objs[79]),/* "nsCertSequence" */
&(nid_objs[71]),/* "nsCertType" */
&(nid_objs[78]),/* "nsComment" */
&(nid_objs[59]),/* "nsDataType" */
&(nid_objs[75]),/* "nsRenewalUrl" */
&(nid_objs[73]),/* "nsRevocationUrl" */
&(nid_objs[77]),/* "nsSslServerName" */
&(nid_objs[84]),/* "privateKeyUsagePeriod" */
&(nid_objs[85]),/* "subjectAltName" */
&(nid_objs[82]),/* "subjectKeyIdentifier" */
};

static ASN1_OBJECT *ln_objs[NUM_LN]={
&(nid_objs[72]),/* "Netscape Base Url" */
&(nid_objs[76]),/* "Netscape CA Policy Url" */
&(nid_objs[74]),/* "Netscape CA Revocation Url" */
&(nid_objs[71]),/* "Netscape Cert Type" */
&(nid_objs[58]),/* "Netscape Certificate Extension" */
&(nid_objs[79]),/* "Netscape Certificate Sequence" */
&(nid_objs[78]),/* "Netscape Comment" */
&(nid_objs[57]),/* "Netscape Communications Corp." */
&(nid_objs[59]),/* "Netscape Data Type" */
&(nid_objs[75]),/* "Netscape Renewal Url" */
&(nid_objs[73]),/* "Netscape Revocation Url" */
&(nid_objs[77]),/* "Netscape SSL Server Name" */
&(nid_objs[11]),/* "X500" */
&(nid_objs[12]),/* "X509" */
&(nid_objs[90]),/* "X509v3 Authority Key Identifier" */
&(nid_objs[87]),/* "X509v3 Basic Constraints" */
&(nid_objs[88]),/* "X509v3 CRL Number" */
&(nid_objs[89]),/* "X509v3 Certificate Policies" */
&(nid_objs[86]),/* "X509v3 Issuer Alternative Name" */
&(nid_objs[83]),/* "X509v3 Key Usage" */
&(nid_objs[84]),/* "X509v3 Private Key Usage Period" */
&(nid_objs[85]),/* "X509v3 Subject Alternative Name" */
&(nid_objs[82]),/* "X509v3 Subject Key Identifier" */
&(nid_objs[91]),/* "bf-cbc" */
&(nid_objs[93]),/* "bf-cfb" */
&(nid_objs[92]),/* "bf-ecb" */
&(nid_objs[94]),/* "bf-ofb" */
&(nid_objs[54]),/* "challengePassword" */
&(nid_objs[13]),/* "commonName" */
&(nid_objs[50]),/* "contentType" */
&(nid_objs[53]),/* "countersignature" */
&(nid_objs[14]),/* "countryName" */
&(nid_objs[31]),/* "des-cbc" */
&(nid_objs[30]),/* "des-cfb" */
&(nid_objs[29]),/* "des-ecb" */
&(nid_objs[32]),/* "des-ede" */
&(nid_objs[43]),/* "des-ede-cbc" */
&(nid_objs[60]),/* "des-ede-cfb" */
&(nid_objs[62]),/* "des-ede-ofb" */
&(nid_objs[33]),/* "des-ede3" */
&(nid_objs[44]),/* "des-ede3-cbc" */
&(nid_objs[61]),/* "des-ede3-cfb" */
&(nid_objs[63]),/* "des-ede3-ofb" */
&(nid_objs[45]),/* "des-ofb" */
&(nid_objs[80]),/* "desx-cbc" */
&(nid_objs[28]),/* "dhKeyAgreement" */
&(nid_objs[67]),/* "dsaEncryption" */
&(nid_objs[66]),/* "dsaWithSHA" */
&(nid_objs[70]),/* "dsaWithSHA1" */
&(nid_objs[48]),/* "emailAddress" */
&(nid_objs[56]),/* "extendedCertificateAttributes" */
&(nid_objs[34]),/* "idea-cbc" */
&(nid_objs[35]),/* "idea-cfb" */
&(nid_objs[36]),/* "idea-ecb" */
&(nid_objs[46]),/* "idea-ofb" */
&(nid_objs[15]),/* "localityName" */
&(nid_objs[ 3]),/* "md2" */
&(nid_objs[ 7]),/* "md2WithRSAEncryption" */
&(nid_objs[ 4]),/* "md5" */
&(nid_objs[ 8]),/* "md5WithRSAEncryption" */
&(nid_objs[95]),/* "mdc2" */
&(nid_objs[96]),/* "mdc2withRSA" */
&(nid_objs[51]),/* "messageDigest" */
&(nid_objs[17]),/* "organizationName" */
&(nid_objs[18]),/* "organizationalUnitName" */
&(nid_objs[ 9]),/* "pbeWithMD2AndDES-CBC" */
&(nid_objs[10]),/* "pbeWithMD5AndDES-CBC" */
&(nid_objs[68]),/* "pbeWithSHA1AndRC2-CBC" */
&(nid_objs[69]),/* "pbeWithSHA1AndRC4" */
&(nid_objs[ 2]),/* "pkcs" */
&(nid_objs[27]),/* "pkcs3" */
&(nid_objs[20]),/* "pkcs7" */
&(nid_objs[21]),/* "pkcs7-data" */
&(nid_objs[25]),/* "pkcs7-digestData" */
&(nid_objs[26]),/* "pkcs7-encryptedData" */
&(nid_objs[23]),/* "pkcs7-envelopedData" */
&(nid_objs[24]),/* "pkcs7-signedAndEnvelopedData" */
&(nid_objs[22]),/* "pkcs7-signedData" */
&(nid_objs[47]),/* "pkcs9" */
&(nid_objs[37]),/* "rc2-cbc" */
&(nid_objs[39]),/* "rc2-cfb" */
&(nid_objs[38]),/* "rc2-ecb" */
&(nid_objs[40]),/* "rc2-ofb" */
&(nid_objs[ 5]),/* "rc4" */
&(nid_objs[19]),/* "rsa" */
&(nid_objs[ 6]),/* "rsaEncryption" */
&(nid_objs[ 1]),/* "rsadsi" */
&(nid_objs[41]),/* "sha" */
&(nid_objs[64]),/* "sha1" */
&(nid_objs[65]),/* "sha1WithRSAEncryption" */
&(nid_objs[42]),/* "shaWithRSAEncryption" */
&(nid_objs[52]),/* "signingTime" */
&(nid_objs[16]),/* "stateOrProvinceName" */
&(nid_objs[ 0]),/* "undefined" */
&(nid_objs[55]),/* "unstructuredAddress" */
&(nid_objs[49]),/* "unstructuredName" */
};

static ASN1_OBJECT *obj_objs[NUM_OBJ]={
&(nid_objs[11]),/* OBJ_X500                         2 5 */
&(nid_objs[12]),/* OBJ_X509                         2 5 4 */
&(nid_objs[81]),/* OBJ_ld_ce                        2 5 29 */
&(nid_objs[13]),/* OBJ_commonName                   2 5 4 3 */
&(nid_objs[14]),/* OBJ_countryName                  2 5 4 6 */
&(nid_objs[15]),/* OBJ_localityName                 2 5 4 7 */
&(nid_objs[16]),/* OBJ_stateOrProvinceName          2 5 4 8 */
&(nid_objs[17]),/* OBJ_organizationName             2 5 4 10 */
&(nid_objs[18]),/* OBJ_organizationalUnitName       2 5 4 11 */
&(nid_objs[82]),/* OBJ_subject_key_identifier       2 5 29 14 */
&(nid_objs[83]),/* OBJ_key_usage                    2 5 29 15 */
&(nid_objs[84]),/* OBJ_private_key_usage_period     2 5 29 16 */
&(nid_objs[85]),/* OBJ_subject_alt_name             2 5 29 17 */
&(nid_objs[86]),/* OBJ_issuer_alt_name              2 5 29 18 */
&(nid_objs[87]),/* OBJ_basic_constraints            2 5 29 19 */
&(nid_objs[88]),/* OBJ_crl_number                   2 5 29 20 */
&(nid_objs[89]),/* OBJ_certificate_policies         2 5 29 32 */
&(nid_objs[90]),/* OBJ_authority_key_identifier     2 5 29 35 */
&(nid_objs[19]),/* OBJ_rsa                          2 5 8 1 1 */
&(nid_objs[96]),/* OBJ_mdc2WithRSA                  2 5 8 3 100 */
&(nid_objs[95]),/* OBJ_mdc2                         2 5 8 3 101 */
&(nid_objs[29]),/* OBJ_des_ecb                      1 3 14 3 2 6 */
&(nid_objs[31]),/* OBJ_des_cbc                      1 3 14 3 2 7 */
&(nid_objs[45]),/* OBJ_des_ofb64                    1 3 14 3 2 8 */
&(nid_objs[30]),/* OBJ_des_cfb64                    1 3 14 3 2 9 */
&(nid_objs[67]),/* OBJ_dsa                          1 3 14 3 2 12 */
&(nid_objs[66]),/* OBJ_dsaWithSHA                   1 3 14 3 2 13 */
&(nid_objs[42]),/* OBJ_shaWithRSAEncryption         1 3 14 3 2 15 */
&(nid_objs[32]),/* OBJ_des_ede                      1 3 14 3 2 17 */
&(nid_objs[41]),/* OBJ_sha                          1 3 14 3 2 18 */
&(nid_objs[64]),/* OBJ_sha1                         1 3 14 3 2 26 */
&(nid_objs[70]),/* OBJ_dsaWithSHA1                  1 3 14 3 2 27 */
&(nid_objs[ 1]),/* OBJ_rsadsi                       1 2 840 113549 */
&(nid_objs[ 2]),/* OBJ_pkcs                         1 2 840 113549 1 */
&(nid_objs[57]),/* OBJ_netscape                     2 16 840 1 113730 */
&(nid_objs[27]),/* OBJ_pkcs3                        1 2 840 113549 1 3 */
&(nid_objs[20]),/* OBJ_pkcs7                        1 2 840 113549 1 7 */
&(nid_objs[47]),/* OBJ_pkcs9                        1 2 840 113549 1 9 */
&(nid_objs[ 3]),/* OBJ_md2                          1 2 840 113549 2 2 */
&(nid_objs[ 4]),/* OBJ_md5                          1 2 840 113549 2 5 */
&(nid_objs[37]),/* OBJ_rc2_cbc                      1 2 840 113549 3 2 */
&(nid_objs[ 5]),/* OBJ_rc4                          1 2 840 113549 3 4 */
&(nid_objs[44]),/* OBJ_des_ede3_cbc                 1 2 840 113549 3 7 */
&(nid_objs[58]),/* OBJ_netscape_cert_extension      2 16 840 1 113730 1 */
&(nid_objs[59]),/* OBJ_netscape_data_type           2 16 840 1 113730 2 */
&(nid_objs[ 6]),/* OBJ_rsaEncryption                1 2 840 113549 1 1 1 */
&(nid_objs[ 7]),/* OBJ_md2WithRSAEncryption         1 2 840 113549 1 1 2 */
&(nid_objs[ 8]),/* OBJ_md5WithRSAEncryption         1 2 840 113549 1 1 4 */
&(nid_objs[65]),/* OBJ_sha1WithRSAEncryption        1 2 840 113549 1 1 5 */
&(nid_objs[28]),/* OBJ_dhKeyAgreement               1 2 840 113549 1 3 1 */
&(nid_objs[ 9]),/* OBJ_pbeWithMD2AndDES_CBC         1 2 840 113549 1 5 1 */
&(nid_objs[10]),/* OBJ_pbeWithMD5AndDES_CBC         1 2 840 113549 1 5 3 */
&(nid_objs[68]),/* OBJ_pbeWithSHA1AndRC2_CBC        1 2 840 113549 1 5 11  */
&(nid_objs[69]),/* OBJ_pbeWithSHA1AndRC4            1 2 840 113549 1 5 12  */
&(nid_objs[21]),/* OBJ_pkcs7_data                   1 2 840 113549 1 7 1 */
&(nid_objs[22]),/* OBJ_pkcs7_signed                 1 2 840 113549 1 7 2 */
&(nid_objs[23]),/* OBJ_pkcs7_enveloped              1 2 840 113549 1 7 3 */
&(nid_objs[24]),/* OBJ_pkcs7_signedAndEnveloped     1 2 840 113549 1 7 4 */
&(nid_objs[25]),/* OBJ_pkcs7_digest                 1 2 840 113549 1 7 5 */
&(nid_objs[26]),/* OBJ_pkcs7_encrypted              1 2 840 113549 1 7 6 */
&(nid_objs[48]),/* OBJ_pkcs9_emailAddress           1 2 840 113549 1 9 1 */
&(nid_objs[49]),/* OBJ_pkcs9_unstructuredName       1 2 840 113549 1 9 2 */
&(nid_objs[50]),/* OBJ_pkcs9_contentType            1 2 840 113549 1 9 3 */
&(nid_objs[51]),/* OBJ_pkcs9_messageDigest          1 2 840 113549 1 9 4 */
&(nid_objs[52]),/* OBJ_pkcs9_signingTime            1 2 840 113549 1 9 5 */
&(nid_objs[53]),/* OBJ_pkcs9_countersignature       1 2 840 113549 1 9 6 */
&(nid_objs[54]),/* OBJ_pkcs9_challengePassword      1 2 840 113549 1 9 7 */
&(nid_objs[55]),/* OBJ_pkcs9_unstructuredAddress    1 2 840 113549 1 9 8 */
&(nid_objs[56]),/* OBJ_pkcs9_extCertAttributes      1 2 840 113549 1 9 9 */
&(nid_objs[71]),/* OBJ_netscape_cert_type           2 16 840 1 113730 1 1 */
&(nid_objs[72]),/* OBJ_netscape_base_url            2 16 840 1 113730 1 2 */
&(nid_objs[73]),/* OBJ_netscape_revocation_url      2 16 840 1 113730 1 3 */
&(nid_objs[74]),/* OBJ_netscape_ca_revocation_url   2 16 840 1 113730 1 4 */
&(nid_objs[75]),/* OBJ_netscape_renewal_url         2 16 840 1 113730 1 7 */
&(nid_objs[76]),/* OBJ_netscape_ca_policy_url       2 16 840 1 113730 1 8 */
&(nid_objs[77]),/* OBJ_netscape_ssl_server_name     2 16 840 1 113730 1 12 */
&(nid_objs[78]),/* OBJ_netscape_comment             2 16 840 1 113730 1 13 */
&(nid_objs[79]),/* OBJ_netscape_cert_sequence       2 16 840 1 113730 2 5 */
};

