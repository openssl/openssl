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
 * perl obj_dat.pl objects.h obj_dat.h
 */

#define NUM_NID 181
#define NUM_SN 141
#define NUM_LN 175
#define NUM_OBJ 154

static unsigned char lvalues[1085]={
0x00,                                        /* [  0] OBJ_undef */
0x2A,0x86,0x48,0x86,0xF7,0x0D,               /* [  1] OBJ_rsadsi */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,          /* [  7] OBJ_pkcs */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x02,     /* [ 14] OBJ_md2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,     /* [ 22] OBJ_md5 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x04,     /* [ 30] OBJ_rc4 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,/* [ 38] OBJ_rsaEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x02,/* [ 47] OBJ_md2WithRSAEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x04,/* [ 56] OBJ_md5WithRSAEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x01,/* [ 65] OBJ_pbeWithMD2AndDES_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x03,/* [ 74] OBJ_pbeWithMD5AndDES_CBC */
0x55,                                        /* [ 83] OBJ_X500 */
0x55,0x04,                                   /* [ 84] OBJ_X509 */
0x55,0x04,0x03,                              /* [ 86] OBJ_commonName */
0x55,0x04,0x06,                              /* [ 89] OBJ_countryName */
0x55,0x04,0x07,                              /* [ 92] OBJ_localityName */
0x55,0x04,0x08,                              /* [ 95] OBJ_stateOrProvinceName */
0x55,0x04,0x0A,                              /* [ 98] OBJ_organizationName */
0x55,0x04,0x0B,                              /* [101] OBJ_organizationalUnitName */
0x55,0x08,0x01,0x01,                         /* [104] OBJ_rsa */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,     /* [108] OBJ_pkcs7 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01,/* [116] OBJ_pkcs7_data */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02,/* [125] OBJ_pkcs7_signed */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x03,/* [134] OBJ_pkcs7_enveloped */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x04,/* [143] OBJ_pkcs7_signedAndEnveloped */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x05,/* [152] OBJ_pkcs7_digest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x06,/* [161] OBJ_pkcs7_encrypted */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x03,     /* [170] OBJ_pkcs3 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x03,0x01,/* [178] OBJ_dhKeyAgreement */
0x2B,0x0E,0x03,0x02,0x06,                    /* [187] OBJ_des_ecb */
0x2B,0x0E,0x03,0x02,0x09,                    /* [192] OBJ_des_cfb64 */
0x2B,0x0E,0x03,0x02,0x07,                    /* [197] OBJ_des_cbc */
0x2B,0x0E,0x03,0x02,0x11,                    /* [202] OBJ_des_ede */
0x2B,0x06,0x01,0x04,0x01,0x81,0x3C,0x07,0x01,0x01,0x02,/* [207] OBJ_idea_cbc */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x02,     /* [218] OBJ_rc2_cbc */
0x2B,0x0E,0x03,0x02,0x12,                    /* [226] OBJ_sha */
0x2B,0x0E,0x03,0x02,0x0F,                    /* [231] OBJ_shaWithRSAEncryption */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x07,     /* [236] OBJ_des_ede3_cbc */
0x2B,0x0E,0x03,0x02,0x08,                    /* [244] OBJ_des_ofb64 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,     /* [249] OBJ_pkcs9 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x01,/* [257] OBJ_pkcs9_emailAddress */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x02,/* [266] OBJ_pkcs9_unstructuredName */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03,/* [275] OBJ_pkcs9_contentType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04,/* [284] OBJ_pkcs9_messageDigest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x05,/* [293] OBJ_pkcs9_signingTime */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x06,/* [302] OBJ_pkcs9_countersignature */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x07,/* [311] OBJ_pkcs9_challengePassword */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x08,/* [320] OBJ_pkcs9_unstructuredAddress */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x09,/* [329] OBJ_pkcs9_extCertAttributes */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,          /* [338] OBJ_netscape */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,     /* [345] OBJ_netscape_cert_extension */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x02,     /* [353] OBJ_netscape_data_type */
0x2B,0x0E,0x03,0x02,0x1A,                    /* [361] OBJ_sha1 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05,/* [366] OBJ_sha1WithRSAEncryption */
0x2B,0x0E,0x03,0x02,0x0D,                    /* [375] OBJ_dsaWithSHA */
0x2B,0x0E,0x03,0x02,0x0C,                    /* [380] OBJ_dsa_2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0B,/* [385] OBJ_pbeWithSHA1AndRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C,/* [394] OBJ_id_pbkdf2 */
0x2B,0x0E,0x03,0x02,0x1B,                    /* [403] OBJ_dsaWithSHA1_2 */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x01,/* [408] OBJ_netscape_cert_type */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x02,/* [417] OBJ_netscape_base_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x03,/* [426] OBJ_netscape_revocation_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x04,/* [435] OBJ_netscape_ca_revocation_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x07,/* [444] OBJ_netscape_renewal_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x08,/* [453] OBJ_netscape_ca_policy_url */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x0C,/* [462] OBJ_netscape_ssl_server_name */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x01,0x0D,/* [471] OBJ_netscape_comment */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x02,0x05,/* [480] OBJ_netscape_cert_sequence */
0x55,0x1D,                                   /* [489] OBJ_ld_ce */
0x55,0x1D,0x0E,                              /* [491] OBJ_subject_key_identifier */
0x55,0x1D,0x0F,                              /* [494] OBJ_key_usage */
0x55,0x1D,0x10,                              /* [497] OBJ_private_key_usage_period */
0x55,0x1D,0x11,                              /* [500] OBJ_subject_alt_name */
0x55,0x1D,0x12,                              /* [503] OBJ_issuer_alt_name */
0x55,0x1D,0x13,                              /* [506] OBJ_basic_constraints */
0x55,0x1D,0x14,                              /* [509] OBJ_crl_number */
0x55,0x1D,0x20,                              /* [512] OBJ_certificate_policies */
0x55,0x1D,0x23,                              /* [515] OBJ_authority_key_identifier */
0x2B,0x06,0x01,0x04,0x01,0x97,0x55,0x01,0x02,/* [518] OBJ_bf_cbc */
0x55,0x08,0x03,0x65,                         /* [527] OBJ_mdc2 */
0x55,0x08,0x03,0x64,                         /* [531] OBJ_mdc2WithRSA */
0x55,0x04,0x2A,                              /* [535] OBJ_givenName */
0x55,0x04,0x04,                              /* [538] OBJ_surname */
0x55,0x04,0x2B,                              /* [541] OBJ_initials */
0x55,0x04,0x2D,                              /* [544] OBJ_uniqueIdentifier */
0x55,0x1D,0x1F,                              /* [547] OBJ_crl_distribution_points */
0x2B,0x0E,0x03,0x02,0x03,                    /* [550] OBJ_md5WithRSA */
0x55,0x04,0x05,                              /* [555] OBJ_serialNumber */
0x55,0x04,0x0C,                              /* [558] OBJ_title */
0x55,0x04,0x0D,                              /* [561] OBJ_description */
0x2A,0x86,0x48,0x86,0xF6,0x7D,0x07,0x42,0x0A,/* [564] OBJ_cast5_cbc */
0x2A,0x86,0x48,0x86,0xF6,0x7D,0x07,0x42,0x0C,/* [573] OBJ_pbeWithMD5AndCast5_CBC */
0x2A,0x86,0x48,0xCE,0x38,0x04,0x03,          /* [582] OBJ_dsaWithSHA1 */
0x2B,0x0E,0x03,0x02,0x1D,                    /* [589] OBJ_sha1WithRSA */
0x2A,0x86,0x48,0xCE,0x38,0x04,0x01,          /* [594] OBJ_dsa */
0x2B,0x24,0x03,0x02,0x01,                    /* [601] OBJ_ripemd160 */
0x2B,0x24,0x03,0x03,0x01,0x02,               /* [606] OBJ_ripemd160WithRSA */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x08,     /* [612] OBJ_rc5_cbc */
0x29,0x01,0x01,0x85,0x1A,0x01,               /* [620] OBJ_rle_compression */
0x29,0x01,0x01,0x85,0x1A,0x02,               /* [626] OBJ_zlib_compression */
0x55,0x1D,0x25,                              /* [632] OBJ_ext_key_usage */
0x2B,0x06,0x01,0x05,0x05,0x07,               /* [635] OBJ_id_pkix */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,          /* [641] OBJ_id_kp */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01,     /* [648] OBJ_server_auth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02,     /* [656] OBJ_client_auth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x03,     /* [664] OBJ_code_sign */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x04,     /* [672] OBJ_email_protect */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x08,     /* [680] OBJ_time_stamp */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x15,/* [688] OBJ_ms_code_ind */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x16,/* [698] OBJ_ms_code_com */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x01,/* [708] OBJ_ms_ctl_sign */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x03,/* [718] OBJ_ms_sgc */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x04,/* [728] OBJ_ms_efs */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x04,0x01,/* [738] OBJ_ns_sgc */
0x55,0x1D,0x1B,                              /* [747] OBJ_delta_crl */
0x55,0x1D,0x15,                              /* [750] OBJ_crl_reason */
0x55,0x1D,0x18,                              /* [753] OBJ_invalidity_date */
0x2B,0x65,0x01,0x04,0x01,                    /* [756] OBJ_sxnet */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x01,/* [761] OBJ_pbe_WithSHA1And128BitRC4 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x02,/* [771] OBJ_pbe_WithSHA1And40BitRC4 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x03,/* [781] OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x04,/* [791] OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x05,/* [801] OBJ_pbe_WithSHA1And128BitRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x06,/* [811] OBJ_pbe_WithSHA1And40BitRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x01,/* [821] OBJ_keyBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x02,/* [832] OBJ_pkcs8ShroudedKeyBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x03,/* [843] OBJ_certBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x04,/* [854] OBJ_crlBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x05,/* [865] OBJ_secretBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x06,/* [876] OBJ_safeContentsBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x14,/* [887] OBJ_friendlyName */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x15,/* [896] OBJ_localKeyID */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x16,0x01,/* [905] OBJ_x509Certificate */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x16,0x02,/* [915] OBJ_sdsiCertificate */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x17,0x01,/* [925] OBJ_x509Crl */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0D,/* [935] OBJ_pbes2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0E,/* [944] OBJ_pbmac1 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x07,     /* [953] OBJ_hmacWithSHA1 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x01,     /* [961] OBJ_id_qt_cps */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x02,     /* [969] OBJ_id_qt_unotice */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0F,/* [977] OBJ_SMIMECapabilities */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x04,/* [986] OBJ_pbeWithMD2AndRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x06,/* [995] OBJ_pbeWithMD5AndRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0A,/* [1004] OBJ_pbeWithSHA1AndDES_CBC */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x0E,/* [1013] OBJ_ms_ext_req */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0E,/* [1023] OBJ_ext_req */
0x55,0x04,0x29,                              /* [1032] OBJ_name */
0x55,0x04,0x2E,                              /* [1035] OBJ_dnQualifier */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,          /* [1038] OBJ_id_pe */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,          /* [1045] OBJ_id_ad */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x01,     /* [1052] OBJ_info_access */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,     /* [1060] OBJ_ad_OCSP */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,     /* [1068] OBJ_ad_ca_issuers */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x09,     /* [1076] OBJ_OCSP_sign */
};

static ASN1_OBJECT nid_objs[NUM_NID]={
{"UNDEF","undefined",NID_undef,1,&(lvalues[0]),0},
{"rsadsi","rsadsi",NID_rsadsi,6,&(lvalues[1]),0},
{"pkcs","pkcs",NID_pkcs,7,&(lvalues[7]),0},
{"MD2","md2",NID_md2,8,&(lvalues[14]),0},
{"MD5","md5",NID_md5,8,&(lvalues[22]),0},
{"RC4","rc4",NID_rc4,8,&(lvalues[30]),0},
{"rsaEncryption","rsaEncryption",NID_rsaEncryption,9,&(lvalues[38]),0},
{"RSA-MD2","md2WithRSAEncryption",NID_md2WithRSAEncryption,9,
	&(lvalues[47]),0},
{"RSA-MD5","md5WithRSAEncryption",NID_md5WithRSAEncryption,9,
	&(lvalues[56]),0},
{"PBE-MD2-DES","pbeWithMD2AndDES-CBC",NID_pbeWithMD2AndDES_CBC,9,
	&(lvalues[65]),0},
{"PBE-MD5-DES","pbeWithMD5AndDES-CBC",NID_pbeWithMD5AndDES_CBC,9,
	&(lvalues[74]),0},
{"X500","X500",NID_X500,1,&(lvalues[83]),0},
{"X509","X509",NID_X509,2,&(lvalues[84]),0},
{"CN","commonName",NID_commonName,3,&(lvalues[86]),0},
{"C","countryName",NID_countryName,3,&(lvalues[89]),0},
{"L","localityName",NID_localityName,3,&(lvalues[92]),0},
{"ST","stateOrProvinceName",NID_stateOrProvinceName,3,&(lvalues[95]),0},
{"O","organizationName",NID_organizationName,3,&(lvalues[98]),0},
{"OU","organizationalUnitName",NID_organizationalUnitName,3,
	&(lvalues[101]),0},
{"RSA","rsa",NID_rsa,4,&(lvalues[104]),0},
{"pkcs7","pkcs7",NID_pkcs7,8,&(lvalues[108]),0},
{"pkcs7-data","pkcs7-data",NID_pkcs7_data,9,&(lvalues[116]),0},
{"pkcs7-signedData","pkcs7-signedData",NID_pkcs7_signed,9,
	&(lvalues[125]),0},
{"pkcs7-envelopedData","pkcs7-envelopedData",NID_pkcs7_enveloped,9,
	&(lvalues[134]),0},
{"pkcs7-signedAndEnvelopedData","pkcs7-signedAndEnvelopedData",
	NID_pkcs7_signedAndEnveloped,9,&(lvalues[143]),0},
{"pkcs7-digestData","pkcs7-digestData",NID_pkcs7_digest,9,
	&(lvalues[152]),0},
{"pkcs7-encryptedData","pkcs7-encryptedData",NID_pkcs7_encrypted,9,
	&(lvalues[161]),0},
{"pkcs3","pkcs3",NID_pkcs3,8,&(lvalues[170]),0},
{"dhKeyAgreement","dhKeyAgreement",NID_dhKeyAgreement,9,
	&(lvalues[178]),0},
{"DES-ECB","des-ecb",NID_des_ecb,5,&(lvalues[187]),0},
{"DES-CFB","des-cfb",NID_des_cfb64,5,&(lvalues[192]),0},
{"DES-CBC","des-cbc",NID_des_cbc,5,&(lvalues[197]),0},
{"DES-EDE","des-ede",NID_des_ede,5,&(lvalues[202]),0},
{"DES-EDE3","des-ede3",NID_des_ede3,0,NULL},
{"IDEA-CBC","idea-cbc",NID_idea_cbc,11,&(lvalues[207]),0},
{"IDEA-CFB","idea-cfb",NID_idea_cfb64,0,NULL},
{"IDEA-ECB","idea-ecb",NID_idea_ecb,0,NULL},
{"RC2-CBC","rc2-cbc",NID_rc2_cbc,8,&(lvalues[218]),0},
{"RC2-ECB","rc2-ecb",NID_rc2_ecb,0,NULL},
{"RC2-CFB","rc2-cfb",NID_rc2_cfb64,0,NULL},
{"RC2-OFB","rc2-ofb",NID_rc2_ofb64,0,NULL},
{"SHA","sha",NID_sha,5,&(lvalues[226]),0},
{"RSA-SHA","shaWithRSAEncryption",NID_shaWithRSAEncryption,5,
	&(lvalues[231]),0},
{"DES-EDE-CBC","des-ede-cbc",NID_des_ede_cbc,0,NULL},
{"DES-EDE3-CBC","des-ede3-cbc",NID_des_ede3_cbc,8,&(lvalues[236]),0},
{"DES-OFB","des-ofb",NID_des_ofb64,5,&(lvalues[244]),0},
{"IDEA-OFB","idea-ofb",NID_idea_ofb64,0,NULL},
{"pkcs9","pkcs9",NID_pkcs9,8,&(lvalues[249]),0},
{"Email","emailAddress",NID_pkcs9_emailAddress,9,&(lvalues[257]),0},
{"unstructuredName","unstructuredName",NID_pkcs9_unstructuredName,9,
	&(lvalues[266]),0},
{"contentType","contentType",NID_pkcs9_contentType,9,&(lvalues[275]),0},
{"messageDigest","messageDigest",NID_pkcs9_messageDigest,9,
	&(lvalues[284]),0},
{"signingTime","signingTime",NID_pkcs9_signingTime,9,&(lvalues[293]),0},
{"countersignature","countersignature",NID_pkcs9_countersignature,9,
	&(lvalues[302]),0},
{"challengePassword","challengePassword",NID_pkcs9_challengePassword,
	9,&(lvalues[311]),0},
{"unstructuredAddress","unstructuredAddress",
	NID_pkcs9_unstructuredAddress,9,&(lvalues[320]),0},
{"extendedCertificateAttributes","extendedCertificateAttributes",
	NID_pkcs9_extCertAttributes,9,&(lvalues[329]),0},
{"Netscape","Netscape Communications Corp.",NID_netscape,7,
	&(lvalues[338]),0},
{"nsCertExt","Netscape Certificate Extension",
	NID_netscape_cert_extension,8,&(lvalues[345]),0},
{"nsDataType","Netscape Data Type",NID_netscape_data_type,8,
	&(lvalues[353]),0},
{"DES-EDE-CFB","des-ede-cfb",NID_des_ede_cfb64,0,NULL},
{"DES-EDE3-CFB","des-ede3-cfb",NID_des_ede3_cfb64,0,NULL},
{"DES-EDE-OFB","des-ede-ofb",NID_des_ede_ofb64,0,NULL},
{"DES-EDE3-OFB","des-ede3-ofb",NID_des_ede3_ofb64,0,NULL},
{"SHA1","sha1",NID_sha1,5,&(lvalues[361]),0},
{"RSA-SHA1","sha1WithRSAEncryption",NID_sha1WithRSAEncryption,9,
	&(lvalues[366]),0},
{"DSA-SHA","dsaWithSHA",NID_dsaWithSHA,5,&(lvalues[375]),0},
{"DSA-old","dsaEncryption-old",NID_dsa_2,5,&(lvalues[380]),0},
{"PBE-SHA1-RC2-64","pbeWithSHA1AndRC2-CBC",NID_pbeWithSHA1AndRC2_CBC,
	9,&(lvalues[385]),0},
{"PBKDF2","PBKDF2",NID_id_pbkdf2,9,&(lvalues[394]),0},
{"DSA-SHA1-old","dsaWithSHA1-old",NID_dsaWithSHA1_2,5,&(lvalues[403]),0},
{"nsCertType","Netscape Cert Type",NID_netscape_cert_type,9,
	&(lvalues[408]),0},
{"nsBaseUrl","Netscape Base Url",NID_netscape_base_url,9,
	&(lvalues[417]),0},
{"nsRevocationUrl","Netscape Revocation Url",
	NID_netscape_revocation_url,9,&(lvalues[426]),0},
{"nsCaRevocationUrl","Netscape CA Revocation Url",
	NID_netscape_ca_revocation_url,9,&(lvalues[435]),0},
{"nsRenewalUrl","Netscape Renewal Url",NID_netscape_renewal_url,9,
	&(lvalues[444]),0},
{"nsCaPolicyUrl","Netscape CA Policy Url",NID_netscape_ca_policy_url,
	9,&(lvalues[453]),0},
{"nsSslServerName","Netscape SSL Server Name",
	NID_netscape_ssl_server_name,9,&(lvalues[462]),0},
{"nsComment","Netscape Comment",NID_netscape_comment,9,&(lvalues[471]),0},
{"nsCertSequence","Netscape Certificate Sequence",
	NID_netscape_cert_sequence,9,&(lvalues[480]),0},
{"DESX-CBC","desx-cbc",NID_desx_cbc,0,NULL},
{"ld-ce","ld-ce",NID_ld_ce,2,&(lvalues[489]),0},
{"subjectKeyIdentifier","X509v3 Subject Key Identifier",
	NID_subject_key_identifier,3,&(lvalues[491]),0},
{"keyUsage","X509v3 Key Usage",NID_key_usage,3,&(lvalues[494]),0},
{"privateKeyUsagePeriod","X509v3 Private Key Usage Period",
	NID_private_key_usage_period,3,&(lvalues[497]),0},
{"subjectAltName","X509v3 Subject Alternative Name",
	NID_subject_alt_name,3,&(lvalues[500]),0},
{"issuerAltName","X509v3 Issuer Alternative Name",NID_issuer_alt_name,
	3,&(lvalues[503]),0},
{"basicConstraints","X509v3 Basic Constraints",NID_basic_constraints,
	3,&(lvalues[506]),0},
{"crlNumber","X509v3 CRL Number",NID_crl_number,3,&(lvalues[509]),0},
{"certificatePolicies","X509v3 Certificate Policies",
	NID_certificate_policies,3,&(lvalues[512]),0},
{"authorityKeyIdentifier","X509v3 Authority Key Identifier",
	NID_authority_key_identifier,3,&(lvalues[515]),0},
{"BF-CBC","bf-cbc",NID_bf_cbc,9,&(lvalues[518]),0},
{"BF-ECB","bf-ecb",NID_bf_ecb,0,NULL},
{"BF-CFB","bf-cfb",NID_bf_cfb64,0,NULL},
{"BF-OFB","bf-ofb",NID_bf_ofb64,0,NULL},
{"MDC2","mdc2",NID_mdc2,4,&(lvalues[527]),0},
{"RSA-MDC2","mdc2withRSA",NID_mdc2WithRSA,4,&(lvalues[531]),0},
{"RC4-40","rc4-40",NID_rc4_40,0,NULL},
{"RC2-40-CBC","rc2-40-cbc",NID_rc2_40_cbc,0,NULL},
{"G","givenName",NID_givenName,3,&(lvalues[535]),0},
{"S","surname",NID_surname,3,&(lvalues[538]),0},
{"I","initials",NID_initials,3,&(lvalues[541]),0},
{"UID","uniqueIdentifier",NID_uniqueIdentifier,3,&(lvalues[544]),0},
{"crlDistributionPoints","X509v3 CRL Distribution Points",
	NID_crl_distribution_points,3,&(lvalues[547]),0},
{"RSA-NP-MD5","md5WithRSA",NID_md5WithRSA,5,&(lvalues[550]),0},
{"SN","serialNumber",NID_serialNumber,3,&(lvalues[555]),0},
{"T","title",NID_title,3,&(lvalues[558]),0},
{"D","description",NID_description,3,&(lvalues[561]),0},
{"CAST5-CBC","cast5-cbc",NID_cast5_cbc,9,&(lvalues[564]),0},
{"CAST5-ECB","cast5-ecb",NID_cast5_ecb,0,NULL},
{"CAST5-CFB","cast5-cfb",NID_cast5_cfb64,0,NULL},
{"CAST5-OFB","cast5-ofb",NID_cast5_ofb64,0,NULL},
{"pbeWithMD5AndCast5CBC","pbeWithMD5AndCast5CBC",
	NID_pbeWithMD5AndCast5_CBC,9,&(lvalues[573]),0},
{"DSA-SHA1","dsaWithSHA1",NID_dsaWithSHA1,7,&(lvalues[582]),0},
{"MD5-SHA1","md5-sha1",NID_md5_sha1,0,NULL},
{"RSA-SHA1-2","sha1WithRSA",NID_sha1WithRSA,5,&(lvalues[589]),0},
{"DSA","dsaEncryption",NID_dsa,7,&(lvalues[594]),0},
{"RIPEMD160","ripemd160",NID_ripemd160,5,&(lvalues[601]),0},
{NULL,NULL,NID_undef,0,NULL},
{"RSA-RIPEMD160","ripemd160WithRSA",NID_ripemd160WithRSA,6,
	&(lvalues[606]),0},
{"RC5-CBC","rc5-cbc",NID_rc5_cbc,8,&(lvalues[612]),0},
{"RC5-ECB","rc5-ecb",NID_rc5_ecb,0,NULL},
{"RC5-CFB","rc5-cfb",NID_rc5_cfb64,0,NULL},
{"RC5-OFB","rc5-ofb",NID_rc5_ofb64,0,NULL},
{"RLE","run length compression",NID_rle_compression,6,&(lvalues[620]),0},
{"ZLIB","zlib compression",NID_zlib_compression,6,&(lvalues[626]),0},
{"extendedKeyUsage","X509v3 Extended Key Usage",NID_ext_key_usage,3,
	&(lvalues[632]),0},
{"PKIX","PKIX",NID_id_pkix,6,&(lvalues[635]),0},
{"id-kp","id-kp",NID_id_kp,7,&(lvalues[641]),0},
{"serverAuth","TLS Web Server Authentication",NID_server_auth,8,
	&(lvalues[648]),0},
{"clientAuth","TLS Web Client Authentication",NID_client_auth,8,
	&(lvalues[656]),0},
{"codeSigning","Code Signing",NID_code_sign,8,&(lvalues[664]),0},
{"emailProtection","E-mail Protection",NID_email_protect,8,
	&(lvalues[672]),0},
{"timeStamping","Time Stamping",NID_time_stamp,8,&(lvalues[680]),0},
{"msCodeInd","Microsoft Individual Code Signing",NID_ms_code_ind,10,
	&(lvalues[688]),0},
{"msCodeCom","Microsoft Commercial Code Signing",NID_ms_code_com,10,
	&(lvalues[698]),0},
{"msCTLSign","Microsoft Trust List Signing",NID_ms_ctl_sign,10,
	&(lvalues[708]),0},
{"msSGC","Microsoft Server Gated Crypto",NID_ms_sgc,10,&(lvalues[718]),0},
{"msEFS","Microsoft Encrypted File System",NID_ms_efs,10,
	&(lvalues[728]),0},
{"nsSGC","Netscape Server Gated Crypto",NID_ns_sgc,9,&(lvalues[738]),0},
{"deltaCRL","X509v3 Delta CRL Indicator",NID_delta_crl,3,
	&(lvalues[747]),0},
{"CRLReason","CRL Reason Code",NID_crl_reason,3,&(lvalues[750]),0},
{"invalidityDate","Invalidity Date",NID_invalidity_date,3,
	&(lvalues[753]),0},
{"SXNetID","Strong Extranet ID",NID_sxnet,5,&(lvalues[756]),0},
{"PBE-SHA1-RC4-128","pbeWithSHA1And128BitRC4",
	NID_pbe_WithSHA1And128BitRC4,10,&(lvalues[761]),0},
{"PBE-SHA1-RC4-40","pbeWithSHA1And40BitRC4",
	NID_pbe_WithSHA1And40BitRC4,10,&(lvalues[771]),0},
{"PBE-SHA1-3DES","pbeWithSHA1And3-KeyTripleDES-CBC",
	NID_pbe_WithSHA1And3_Key_TripleDES_CBC,10,&(lvalues[781]),0},
{"PBE-SHA1-2DES","pbeWithSHA1And2-KeyTripleDES-CBC",
	NID_pbe_WithSHA1And2_Key_TripleDES_CBC,10,&(lvalues[791]),0},
{"PBE-SHA1-RC2-128","pbeWithSHA1And128BitRC2-CBC",
	NID_pbe_WithSHA1And128BitRC2_CBC,10,&(lvalues[801]),0},
{"PBE-SHA1-RC2-40","pbeWithSHA1And40BitRC2-CBC",
	NID_pbe_WithSHA1And40BitRC2_CBC,10,&(lvalues[811]),0},
{"keyBag","keyBag",NID_keyBag,11,&(lvalues[821]),0},
{"pkcs8ShroudedKeyBag","pkcs8ShroudedKeyBag",NID_pkcs8ShroudedKeyBag,
	11,&(lvalues[832]),0},
{"certBag","certBag",NID_certBag,11,&(lvalues[843]),0},
{"crlBag","crlBag",NID_crlBag,11,&(lvalues[854]),0},
{"secretBag","secretBag",NID_secretBag,11,&(lvalues[865]),0},
{"safeContentsBag","safeContentsBag",NID_safeContentsBag,11,
	&(lvalues[876]),0},
{"friendlyName","friendlyName",NID_friendlyName,9,&(lvalues[887]),0},
{"localKeyID","localKeyID",NID_localKeyID,9,&(lvalues[896]),0},
{"x509Certificate","x509Certificate",NID_x509Certificate,10,
	&(lvalues[905]),0},
{"sdsiCertificate","sdsiCertificate",NID_sdsiCertificate,10,
	&(lvalues[915]),0},
{"x509Crl","x509Crl",NID_x509Crl,10,&(lvalues[925]),0},
{"PBES2","PBES2",NID_pbes2,9,&(lvalues[935]),0},
{"PBMAC1","PBMAC1",NID_pbmac1,9,&(lvalues[944]),0},
{"hmacWithSHA1","hmacWithSHA1",NID_hmacWithSHA1,8,&(lvalues[953]),0},
{"id-qt-cps","Policy Qualifier CPS",NID_id_qt_cps,8,&(lvalues[961]),0},
{"id-qt-unotice","Policy Qualifier User Notice",NID_id_qt_unotice,8,
	&(lvalues[969]),0},
{"RC2-64-CBC","rc2-64-cbc",NID_rc2_64_cbc,0,NULL},
{"SMIME-CAPS","S/MIME Capabilities",NID_SMIMECapabilities,9,
	&(lvalues[977]),0},
{"PBE-MD2-RC2-64","pbeWithMD2AndRC2-CBC",NID_pbeWithMD2AndRC2_CBC,9,
	&(lvalues[986]),0},
{"PBE-MD5-RC2-64","pbeWithMD5AndRC2-CBC",NID_pbeWithMD5AndRC2_CBC,9,
	&(lvalues[995]),0},
{"PBE-SHA1-DES","pbeWithSHA1AndDES-CBC",NID_pbeWithSHA1AndDES_CBC,9,
	&(lvalues[1004]),0},
{"msExtReq","Microsoft Extension Request",NID_ms_ext_req,10,
	&(lvalues[1013]),0},
{"extReq","Extension Request",NID_ext_req,9,&(lvalues[1023]),0},
{"name","name",NID_name,3,&(lvalues[1032]),0},
{"dnQualifier","dnQualifier",NID_dnQualifier,3,&(lvalues[1035]),0},
{"id-pe","id-pe",NID_id_pe,7,&(lvalues[1038]),0},
{"id-ad","id-ad",NID_id_ad,7,&(lvalues[1045]),0},
{"authorityInfoAccess","Authority Information Access",NID_info_access,
	8,&(lvalues[1052]),0},
{"OCSP","OCSP",NID_ad_OCSP,8,&(lvalues[1060]),0},
{"caIssuers","CA Issuers",NID_ad_ca_issuers,8,&(lvalues[1068]),0},
{"OCSPSigning","OCSP Signing",NID_OCSP_sign,8,&(lvalues[1076]),0},
};

static ASN1_OBJECT *sn_objs[NUM_SN]={
&(nid_objs[91]),/* "BF-CBC" */
&(nid_objs[93]),/* "BF-CFB" */
&(nid_objs[92]),/* "BF-ECB" */
&(nid_objs[94]),/* "BF-OFB" */
&(nid_objs[14]),/* "C" */
&(nid_objs[108]),/* "CAST5-CBC" */
&(nid_objs[110]),/* "CAST5-CFB" */
&(nid_objs[109]),/* "CAST5-ECB" */
&(nid_objs[111]),/* "CAST5-OFB" */
&(nid_objs[13]),/* "CN" */
&(nid_objs[141]),/* "CRLReason" */
&(nid_objs[107]),/* "D" */
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
&(nid_objs[116]),/* "DSA" */
&(nid_objs[66]),/* "DSA-SHA" */
&(nid_objs[113]),/* "DSA-SHA1" */
&(nid_objs[70]),/* "DSA-SHA1-old" */
&(nid_objs[67]),/* "DSA-old" */
&(nid_objs[48]),/* "Email" */
&(nid_objs[99]),/* "G" */
&(nid_objs[101]),/* "I" */
&(nid_objs[34]),/* "IDEA-CBC" */
&(nid_objs[35]),/* "IDEA-CFB" */
&(nid_objs[36]),/* "IDEA-ECB" */
&(nid_objs[46]),/* "IDEA-OFB" */
&(nid_objs[15]),/* "L" */
&(nid_objs[ 3]),/* "MD2" */
&(nid_objs[ 4]),/* "MD5" */
&(nid_objs[114]),/* "MD5-SHA1" */
&(nid_objs[95]),/* "MDC2" */
&(nid_objs[57]),/* "Netscape" */
&(nid_objs[17]),/* "O" */
&(nid_objs[178]),/* "OCSP" */
&(nid_objs[180]),/* "OCSPSigning" */
&(nid_objs[18]),/* "OU" */
&(nid_objs[ 9]),/* "PBE-MD2-DES" */
&(nid_objs[168]),/* "PBE-MD2-RC2-64" */
&(nid_objs[10]),/* "PBE-MD5-DES" */
&(nid_objs[169]),/* "PBE-MD5-RC2-64" */
&(nid_objs[147]),/* "PBE-SHA1-2DES" */
&(nid_objs[146]),/* "PBE-SHA1-3DES" */
&(nid_objs[170]),/* "PBE-SHA1-DES" */
&(nid_objs[148]),/* "PBE-SHA1-RC2-128" */
&(nid_objs[149]),/* "PBE-SHA1-RC2-40" */
&(nid_objs[68]),/* "PBE-SHA1-RC2-64" */
&(nid_objs[144]),/* "PBE-SHA1-RC4-128" */
&(nid_objs[145]),/* "PBE-SHA1-RC4-40" */
&(nid_objs[127]),/* "PKIX" */
&(nid_objs[98]),/* "RC2-40-CBC" */
&(nid_objs[166]),/* "RC2-64-CBC" */
&(nid_objs[37]),/* "RC2-CBC" */
&(nid_objs[39]),/* "RC2-CFB" */
&(nid_objs[38]),/* "RC2-ECB" */
&(nid_objs[40]),/* "RC2-OFB" */
&(nid_objs[ 5]),/* "RC4" */
&(nid_objs[97]),/* "RC4-40" */
&(nid_objs[120]),/* "RC5-CBC" */
&(nid_objs[122]),/* "RC5-CFB" */
&(nid_objs[121]),/* "RC5-ECB" */
&(nid_objs[123]),/* "RC5-OFB" */
&(nid_objs[117]),/* "RIPEMD160" */
&(nid_objs[124]),/* "RLE" */
&(nid_objs[19]),/* "RSA" */
&(nid_objs[ 7]),/* "RSA-MD2" */
&(nid_objs[ 8]),/* "RSA-MD5" */
&(nid_objs[96]),/* "RSA-MDC2" */
&(nid_objs[104]),/* "RSA-NP-MD5" */
&(nid_objs[119]),/* "RSA-RIPEMD160" */
&(nid_objs[42]),/* "RSA-SHA" */
&(nid_objs[65]),/* "RSA-SHA1" */
&(nid_objs[115]),/* "RSA-SHA1-2" */
&(nid_objs[100]),/* "S" */
&(nid_objs[41]),/* "SHA" */
&(nid_objs[64]),/* "SHA1" */
&(nid_objs[167]),/* "SMIME-CAPS" */
&(nid_objs[105]),/* "SN" */
&(nid_objs[16]),/* "ST" */
&(nid_objs[143]),/* "SXNetID" */
&(nid_objs[106]),/* "T" */
&(nid_objs[102]),/* "UID" */
&(nid_objs[ 0]),/* "UNDEF" */
&(nid_objs[125]),/* "ZLIB" */
&(nid_objs[177]),/* "authorityInfoAccess" */
&(nid_objs[90]),/* "authorityKeyIdentifier" */
&(nid_objs[87]),/* "basicConstraints" */
&(nid_objs[179]),/* "caIssuers" */
&(nid_objs[89]),/* "certificatePolicies" */
&(nid_objs[130]),/* "clientAuth" */
&(nid_objs[131]),/* "codeSigning" */
&(nid_objs[103]),/* "crlDistributionPoints" */
&(nid_objs[88]),/* "crlNumber" */
&(nid_objs[140]),/* "deltaCRL" */
&(nid_objs[174]),/* "dnQualifier" */
&(nid_objs[132]),/* "emailProtection" */
&(nid_objs[172]),/* "extReq" */
&(nid_objs[126]),/* "extendedKeyUsage" */
&(nid_objs[176]),/* "id-ad" */
&(nid_objs[128]),/* "id-kp" */
&(nid_objs[175]),/* "id-pe" */
&(nid_objs[164]),/* "id-qt-cps" */
&(nid_objs[165]),/* "id-qt-unotice" */
&(nid_objs[142]),/* "invalidityDate" */
&(nid_objs[86]),/* "issuerAltName" */
&(nid_objs[83]),/* "keyUsage" */
&(nid_objs[81]),/* "ld-ce" */
&(nid_objs[136]),/* "msCTLSign" */
&(nid_objs[135]),/* "msCodeCom" */
&(nid_objs[134]),/* "msCodeInd" */
&(nid_objs[138]),/* "msEFS" */
&(nid_objs[171]),/* "msExtReq" */
&(nid_objs[137]),/* "msSGC" */
&(nid_objs[173]),/* "name" */
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
&(nid_objs[139]),/* "nsSGC" */
&(nid_objs[77]),/* "nsSslServerName" */
&(nid_objs[84]),/* "privateKeyUsagePeriod" */
&(nid_objs[129]),/* "serverAuth" */
&(nid_objs[85]),/* "subjectAltName" */
&(nid_objs[82]),/* "subjectKeyIdentifier" */
&(nid_objs[133]),/* "timeStamping" */
};

static ASN1_OBJECT *ln_objs[NUM_LN]={
&(nid_objs[177]),/* "Authority Information Access" */
&(nid_objs[179]),/* "CA Issuers" */
&(nid_objs[141]),/* "CRL Reason Code" */
&(nid_objs[131]),/* "Code Signing" */
&(nid_objs[132]),/* "E-mail Protection" */
&(nid_objs[172]),/* "Extension Request" */
&(nid_objs[142]),/* "Invalidity Date" */
&(nid_objs[135]),/* "Microsoft Commercial Code Signing" */
&(nid_objs[138]),/* "Microsoft Encrypted File System" */
&(nid_objs[171]),/* "Microsoft Extension Request" */
&(nid_objs[134]),/* "Microsoft Individual Code Signing" */
&(nid_objs[137]),/* "Microsoft Server Gated Crypto" */
&(nid_objs[136]),/* "Microsoft Trust List Signing" */
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
&(nid_objs[139]),/* "Netscape Server Gated Crypto" */
&(nid_objs[180]),/* "OCSP Signing" */
&(nid_objs[178]),/* "OCSP" */
&(nid_objs[161]),/* "PBES2" */
&(nid_objs[69]),/* "PBKDF2" */
&(nid_objs[162]),/* "PBMAC1" */
&(nid_objs[164]),/* "Policy Qualifier CPS" */
&(nid_objs[165]),/* "Policy Qualifier User Notice" */
&(nid_objs[167]),/* "S/MIME Capabilities" */
&(nid_objs[143]),/* "Strong Extranet ID" */
&(nid_objs[130]),/* "TLS Web Client Authentication" */
&(nid_objs[129]),/* "TLS Web Server Authentication" */
&(nid_objs[133]),/* "Time Stamping" */
&(nid_objs[11]),/* "X500" */
&(nid_objs[12]),/* "X509" */
&(nid_objs[90]),/* "X509v3 Authority Key Identifier" */
&(nid_objs[87]),/* "X509v3 Basic Constraints" */
&(nid_objs[103]),/* "X509v3 CRL Distribution Points" */
&(nid_objs[88]),/* "X509v3 CRL Number" */
&(nid_objs[89]),/* "X509v3 Certificate Policies" */
&(nid_objs[140]),/* "X509v3 Delta CRL Indicator" */
&(nid_objs[126]),/* "X509v3 Extended Key Usage" */
&(nid_objs[86]),/* "X509v3 Issuer Alternative Name" */
&(nid_objs[83]),/* "X509v3 Key Usage" */
&(nid_objs[84]),/* "X509v3 Private Key Usage Period" */
&(nid_objs[85]),/* "X509v3 Subject Alternative Name" */
&(nid_objs[82]),/* "X509v3 Subject Key Identifier" */
&(nid_objs[91]),/* "bf-cbc" */
&(nid_objs[93]),/* "bf-cfb" */
&(nid_objs[92]),/* "bf-ecb" */
&(nid_objs[94]),/* "bf-ofb" */
&(nid_objs[108]),/* "cast5-cbc" */
&(nid_objs[110]),/* "cast5-cfb" */
&(nid_objs[109]),/* "cast5-ecb" */
&(nid_objs[111]),/* "cast5-ofb" */
&(nid_objs[152]),/* "certBag" */
&(nid_objs[54]),/* "challengePassword" */
&(nid_objs[13]),/* "commonName" */
&(nid_objs[50]),/* "contentType" */
&(nid_objs[53]),/* "countersignature" */
&(nid_objs[14]),/* "countryName" */
&(nid_objs[153]),/* "crlBag" */
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
&(nid_objs[107]),/* "description" */
&(nid_objs[80]),/* "desx-cbc" */
&(nid_objs[28]),/* "dhKeyAgreement" */
&(nid_objs[174]),/* "dnQualifier" */
&(nid_objs[116]),/* "dsaEncryption" */
&(nid_objs[67]),/* "dsaEncryption-old" */
&(nid_objs[66]),/* "dsaWithSHA" */
&(nid_objs[113]),/* "dsaWithSHA1" */
&(nid_objs[70]),/* "dsaWithSHA1-old" */
&(nid_objs[48]),/* "emailAddress" */
&(nid_objs[56]),/* "extendedCertificateAttributes" */
&(nid_objs[156]),/* "friendlyName" */
&(nid_objs[99]),/* "givenName" */
&(nid_objs[163]),/* "hmacWithSHA1" */
&(nid_objs[34]),/* "idea-cbc" */
&(nid_objs[35]),/* "idea-cfb" */
&(nid_objs[36]),/* "idea-ecb" */
&(nid_objs[46]),/* "idea-ofb" */
&(nid_objs[101]),/* "initials" */
&(nid_objs[150]),/* "keyBag" */
&(nid_objs[157]),/* "localKeyID" */
&(nid_objs[15]),/* "localityName" */
&(nid_objs[ 3]),/* "md2" */
&(nid_objs[ 7]),/* "md2WithRSAEncryption" */
&(nid_objs[ 4]),/* "md5" */
&(nid_objs[114]),/* "md5-sha1" */
&(nid_objs[104]),/* "md5WithRSA" */
&(nid_objs[ 8]),/* "md5WithRSAEncryption" */
&(nid_objs[95]),/* "mdc2" */
&(nid_objs[96]),/* "mdc2withRSA" */
&(nid_objs[51]),/* "messageDigest" */
&(nid_objs[173]),/* "name" */
&(nid_objs[17]),/* "organizationName" */
&(nid_objs[18]),/* "organizationalUnitName" */
&(nid_objs[ 9]),/* "pbeWithMD2AndDES-CBC" */
&(nid_objs[168]),/* "pbeWithMD2AndRC2-CBC" */
&(nid_objs[112]),/* "pbeWithMD5AndCast5CBC" */
&(nid_objs[10]),/* "pbeWithMD5AndDES-CBC" */
&(nid_objs[169]),/* "pbeWithMD5AndRC2-CBC" */
&(nid_objs[148]),/* "pbeWithSHA1And128BitRC2-CBC" */
&(nid_objs[144]),/* "pbeWithSHA1And128BitRC4" */
&(nid_objs[147]),/* "pbeWithSHA1And2-KeyTripleDES-CBC" */
&(nid_objs[146]),/* "pbeWithSHA1And3-KeyTripleDES-CBC" */
&(nid_objs[149]),/* "pbeWithSHA1And40BitRC2-CBC" */
&(nid_objs[145]),/* "pbeWithSHA1And40BitRC4" */
&(nid_objs[170]),/* "pbeWithSHA1AndDES-CBC" */
&(nid_objs[68]),/* "pbeWithSHA1AndRC2-CBC" */
&(nid_objs[ 2]),/* "pkcs" */
&(nid_objs[27]),/* "pkcs3" */
&(nid_objs[20]),/* "pkcs7" */
&(nid_objs[21]),/* "pkcs7-data" */
&(nid_objs[25]),/* "pkcs7-digestData" */
&(nid_objs[26]),/* "pkcs7-encryptedData" */
&(nid_objs[23]),/* "pkcs7-envelopedData" */
&(nid_objs[24]),/* "pkcs7-signedAndEnvelopedData" */
&(nid_objs[22]),/* "pkcs7-signedData" */
&(nid_objs[151]),/* "pkcs8ShroudedKeyBag" */
&(nid_objs[47]),/* "pkcs9" */
&(nid_objs[98]),/* "rc2-40-cbc" */
&(nid_objs[166]),/* "rc2-64-cbc" */
&(nid_objs[37]),/* "rc2-cbc" */
&(nid_objs[39]),/* "rc2-cfb" */
&(nid_objs[38]),/* "rc2-ecb" */
&(nid_objs[40]),/* "rc2-ofb" */
&(nid_objs[ 5]),/* "rc4" */
&(nid_objs[97]),/* "rc4-40" */
&(nid_objs[120]),/* "rc5-cbc" */
&(nid_objs[122]),/* "rc5-cfb" */
&(nid_objs[121]),/* "rc5-ecb" */
&(nid_objs[123]),/* "rc5-ofb" */
&(nid_objs[117]),/* "ripemd160" */
&(nid_objs[119]),/* "ripemd160WithRSA" */
&(nid_objs[19]),/* "rsa" */
&(nid_objs[ 6]),/* "rsaEncryption" */
&(nid_objs[ 1]),/* "rsadsi" */
&(nid_objs[124]),/* "run length compression" */
&(nid_objs[155]),/* "safeContentsBag" */
&(nid_objs[159]),/* "sdsiCertificate" */
&(nid_objs[154]),/* "secretBag" */
&(nid_objs[105]),/* "serialNumber" */
&(nid_objs[41]),/* "sha" */
&(nid_objs[64]),/* "sha1" */
&(nid_objs[115]),/* "sha1WithRSA" */
&(nid_objs[65]),/* "sha1WithRSAEncryption" */
&(nid_objs[42]),/* "shaWithRSAEncryption" */
&(nid_objs[52]),/* "signingTime" */
&(nid_objs[16]),/* "stateOrProvinceName" */
&(nid_objs[100]),/* "surname" */
&(nid_objs[106]),/* "title" */
&(nid_objs[ 0]),/* "undefined" */
&(nid_objs[102]),/* "uniqueIdentifier" */
&(nid_objs[55]),/* "unstructuredAddress" */
&(nid_objs[49]),/* "unstructuredName" */
&(nid_objs[158]),/* "x509Certificate" */
&(nid_objs[160]),/* "x509Crl" */
&(nid_objs[125]),/* "zlib compression" */
};

static ASN1_OBJECT *obj_objs[NUM_OBJ]={
&(nid_objs[ 0]),/* OBJ_undef                        0 */
&(nid_objs[11]),/* OBJ_X500                         2 5 */
&(nid_objs[12]),/* OBJ_X509                         2 5 4 */
&(nid_objs[81]),/* OBJ_ld_ce                        2 5 29 */
&(nid_objs[13]),/* OBJ_commonName                   2 5 4 3 */
&(nid_objs[100]),/* OBJ_surname                      2 5 4 4 */
&(nid_objs[105]),/* OBJ_serialNumber                 2 5 4 5 */
&(nid_objs[14]),/* OBJ_countryName                  2 5 4 6 */
&(nid_objs[15]),/* OBJ_localityName                 2 5 4 7 */
&(nid_objs[16]),/* OBJ_stateOrProvinceName          2 5 4 8 */
&(nid_objs[17]),/* OBJ_organizationName             2 5 4 10 */
&(nid_objs[18]),/* OBJ_organizationalUnitName       2 5 4 11 */
&(nid_objs[106]),/* OBJ_title                        2 5 4 12 */
&(nid_objs[107]),/* OBJ_description                  2 5 4 13 */
&(nid_objs[173]),/* OBJ_name                         2 5 4 41 */
&(nid_objs[99]),/* OBJ_givenName                    2 5 4 42 */
&(nid_objs[101]),/* OBJ_initials                     2 5 4 43 */
&(nid_objs[102]),/* OBJ_uniqueIdentifier             2 5 4 45 */
&(nid_objs[174]),/* OBJ_dnQualifier                  2 5 4 46 */
&(nid_objs[82]),/* OBJ_subject_key_identifier       2 5 29 14 */
&(nid_objs[83]),/* OBJ_key_usage                    2 5 29 15 */
&(nid_objs[84]),/* OBJ_private_key_usage_period     2 5 29 16 */
&(nid_objs[85]),/* OBJ_subject_alt_name             2 5 29 17 */
&(nid_objs[86]),/* OBJ_issuer_alt_name              2 5 29 18 */
&(nid_objs[87]),/* OBJ_basic_constraints            2 5 29 19 */
&(nid_objs[88]),/* OBJ_crl_number                   2 5 29 20 */
&(nid_objs[141]),/* OBJ_crl_reason                   2 5 29 21 */
&(nid_objs[142]),/* OBJ_invalidity_date              2 5 29 24 */
&(nid_objs[140]),/* OBJ_delta_crl                    2 5 29 27 */
&(nid_objs[103]),/* OBJ_crl_distribution_points      2 5 29 31 */
&(nid_objs[89]),/* OBJ_certificate_policies         2 5 29 32 */
&(nid_objs[90]),/* OBJ_authority_key_identifier     2 5 29 35 */
&(nid_objs[126]),/* OBJ_ext_key_usage                2 5 29 37 */
&(nid_objs[19]),/* OBJ_rsa                          2 5 8 1 1 */
&(nid_objs[96]),/* OBJ_mdc2WithRSA                  2 5 8 3 100 */
&(nid_objs[95]),/* OBJ_mdc2                         2 5 8 3 101 */
&(nid_objs[104]),/* OBJ_md5WithRSA                   1 3 14 3 2 3 */
&(nid_objs[29]),/* OBJ_des_ecb                      1 3 14 3 2 6 */
&(nid_objs[31]),/* OBJ_des_cbc                      1 3 14 3 2 7 */
&(nid_objs[45]),/* OBJ_des_ofb64                    1 3 14 3 2 8 */
&(nid_objs[30]),/* OBJ_des_cfb64                    1 3 14 3 2 9 */
&(nid_objs[67]),/* OBJ_dsa_2                        1 3 14 3 2 12 */
&(nid_objs[66]),/* OBJ_dsaWithSHA                   1 3 14 3 2 13 */
&(nid_objs[42]),/* OBJ_shaWithRSAEncryption         1 3 14 3 2 15 */
&(nid_objs[32]),/* OBJ_des_ede                      1 3 14 3 2 17 */
&(nid_objs[41]),/* OBJ_sha                          1 3 14 3 2 18 */
&(nid_objs[64]),/* OBJ_sha1                         1 3 14 3 2 26 */
&(nid_objs[70]),/* OBJ_dsaWithSHA1_2                1 3 14 3 2 27 */
&(nid_objs[115]),/* OBJ_sha1WithRSA                  1 3 14 3 2 29 */
&(nid_objs[117]),/* OBJ_ripemd160                    1 3 36 3 2 1 */
&(nid_objs[143]),/* OBJ_sxnet                        1 3 101 1 4 1 */
&(nid_objs[124]),/* OBJ_rle_compression              1 1 1 1 666 1 */
&(nid_objs[125]),/* OBJ_zlib_compression             1 1 1 1 666 2 */
&(nid_objs[ 1]),/* OBJ_rsadsi                       1 2 840 113549 */
&(nid_objs[127]),/* OBJ_id_pkix                      1 3 6 1 5 5 7 */
&(nid_objs[119]),/* OBJ_ripemd160WithRSA             1 3 36 3 3 1 2 */
&(nid_objs[ 2]),/* OBJ_pkcs                         1 2 840 113549 1 */
&(nid_objs[116]),/* OBJ_dsa                          1 2 840 10040 4 1 */
&(nid_objs[113]),/* OBJ_dsaWithSHA1                  1 2 840 10040 4 3 */
&(nid_objs[175]),/* OBJ_id_pe                        1 3 6 1 5 5 7 1 */
&(nid_objs[128]),/* OBJ_id_kp                        1 3 6 1 5 5 7 3 */
&(nid_objs[176]),/* OBJ_id_ad                        1 3 6 1 5 5 7 48 */
&(nid_objs[57]),/* OBJ_netscape                     2 16 840 1 113730 */
&(nid_objs[27]),/* OBJ_pkcs3                        1 2 840 113549 1 3 */
&(nid_objs[20]),/* OBJ_pkcs7                        1 2 840 113549 1 7 */
&(nid_objs[47]),/* OBJ_pkcs9                        1 2 840 113549 1 9 */
&(nid_objs[ 3]),/* OBJ_md2                          1 2 840 113549 2 2 */
&(nid_objs[ 4]),/* OBJ_md5                          1 2 840 113549 2 5 */
&(nid_objs[163]),/* OBJ_hmacWithSHA1                 1 2 840 113549 2 7 */
&(nid_objs[37]),/* OBJ_rc2_cbc                      1 2 840 113549 3 2 */
&(nid_objs[ 5]),/* OBJ_rc4                          1 2 840 113549 3 4 */
&(nid_objs[44]),/* OBJ_des_ede3_cbc                 1 2 840 113549 3 7 */
&(nid_objs[120]),/* OBJ_rc5_cbc                      1 2 840 113549 3 8 */
&(nid_objs[177]),/* OBJ_info_access                  1 3 6 1 5 5 7 1 1 */
&(nid_objs[164]),/* OBJ_id_qt_cps                    1 3 6 1 5 5 7 2 1 */
&(nid_objs[165]),/* OBJ_id_qt_unotice                1 3 6 1 5 5 7 2 2 */
&(nid_objs[129]),/* OBJ_server_auth                  1 3 6 1 5 5 7 3 1 */
&(nid_objs[130]),/* OBJ_client_auth                  1 3 6 1 5 5 7 3 2 */
&(nid_objs[131]),/* OBJ_code_sign                    1 3 6 1 5 5 7 3 3 */
&(nid_objs[132]),/* OBJ_email_protect                1 3 6 1 5 5 7 3 4 */
&(nid_objs[133]),/* OBJ_time_stamp                   1 3 6 1 5 5 7 3 8 */
&(nid_objs[180]),/* OBJ_OCSP_sign                    1 3 6 1 5 5 7 3 9 */
&(nid_objs[178]),/* OBJ_ad_OCSP                      1 3 6 1 5 5 7 48 1 */
&(nid_objs[179]),/* OBJ_ad_ca_issuers                1 3 6 1 5 5 7 48 2 */
&(nid_objs[58]),/* OBJ_netscape_cert_extension      2 16 840 1 113730 1 */
&(nid_objs[59]),/* OBJ_netscape_data_type           2 16 840 1 113730 2 */
&(nid_objs[108]),/* OBJ_cast5_cbc                    1 2 840 113533 7 66 10 */
&(nid_objs[112]),/* OBJ_pbeWithMD5AndCast5_CBC       1 2 840 113533 7 66 12 */
&(nid_objs[ 6]),/* OBJ_rsaEncryption                1 2 840 113549 1 1 1 */
&(nid_objs[ 7]),/* OBJ_md2WithRSAEncryption         1 2 840 113549 1 1 2 */
&(nid_objs[ 8]),/* OBJ_md5WithRSAEncryption         1 2 840 113549 1 1 4 */
&(nid_objs[65]),/* OBJ_sha1WithRSAEncryption        1 2 840 113549 1 1 5 */
&(nid_objs[28]),/* OBJ_dhKeyAgreement               1 2 840 113549 1 3 1 */
&(nid_objs[ 9]),/* OBJ_pbeWithMD2AndDES_CBC         1 2 840 113549 1 5 1 */
&(nid_objs[10]),/* OBJ_pbeWithMD5AndDES_CBC         1 2 840 113549 1 5 3 */
&(nid_objs[168]),/* OBJ_pbeWithMD2AndRC2_CBC         1 2 840 113549 1 5 4 */
&(nid_objs[169]),/* OBJ_pbeWithMD5AndRC2_CBC         1 2 840 113549 1 5 6 */
&(nid_objs[170]),/* OBJ_pbeWithSHA1AndDES_CBC        1 2 840 113549 1 5 10 */
&(nid_objs[68]),/* OBJ_pbeWithSHA1AndRC2_CBC        1 2 840 113549 1 5 11  */
&(nid_objs[69]),/* OBJ_id_pbkdf2                    1 2 840 113549 1 5 12  */
&(nid_objs[161]),/* OBJ_pbes2                        1 2 840 113549 1 5 13 */
&(nid_objs[162]),/* OBJ_pbmac1                       1 2 840 113549 1 5 14 */
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
&(nid_objs[172]),/* OBJ_ext_req                      1 2 840 113549 1 9 14 */
&(nid_objs[167]),/* OBJ_SMIMECapabilities            1 2 840 113549 1 9 15 */
&(nid_objs[156]),/* OBJ_friendlyName                 1 2 840 113549 1 9  20 */
&(nid_objs[157]),/* OBJ_localKeyID                   1 2 840 113549 1 9  21 */
&(nid_objs[91]),/* OBJ_bf_cbc                       1 3 6 1 4 1 3029 1 2 */
&(nid_objs[71]),/* OBJ_netscape_cert_type           2 16 840 1 113730 1 1 */
&(nid_objs[72]),/* OBJ_netscape_base_url            2 16 840 1 113730 1 2 */
&(nid_objs[73]),/* OBJ_netscape_revocation_url      2 16 840 1 113730 1 3 */
&(nid_objs[74]),/* OBJ_netscape_ca_revocation_url   2 16 840 1 113730 1 4 */
&(nid_objs[75]),/* OBJ_netscape_renewal_url         2 16 840 1 113730 1 7 */
&(nid_objs[76]),/* OBJ_netscape_ca_policy_url       2 16 840 1 113730 1 8 */
&(nid_objs[77]),/* OBJ_netscape_ssl_server_name     2 16 840 1 113730 1 12 */
&(nid_objs[78]),/* OBJ_netscape_comment             2 16 840 1 113730 1 13 */
&(nid_objs[79]),/* OBJ_netscape_cert_sequence       2 16 840 1 113730 2 5 */
&(nid_objs[139]),/* OBJ_ns_sgc                       2 16 840 1 113730 4 1 */
&(nid_objs[158]),/* OBJ_x509Certificate              1 2 840 113549 1 9  22  1 */
&(nid_objs[159]),/* OBJ_sdsiCertificate              1 2 840 113549 1 9  22  2 */
&(nid_objs[160]),/* OBJ_x509Crl                      1 2 840 113549 1 9  23  1 */
&(nid_objs[144]),/* OBJ_pbe_WithSHA1And128BitRC4     1 2 840 113549 1 12  1  1 */
&(nid_objs[145]),/* OBJ_pbe_WithSHA1And40BitRC4      1 2 840 113549 1 12  1  2 */
&(nid_objs[146]),/* OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC 1 2 840 113549 1 12  1  3 */
&(nid_objs[147]),/* OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC 1 2 840 113549 1 12  1  4 */
&(nid_objs[148]),/* OBJ_pbe_WithSHA1And128BitRC2_CBC 1 2 840 113549 1 12  1  5 */
&(nid_objs[149]),/* OBJ_pbe_WithSHA1And40BitRC2_CBC  1 2 840 113549 1 12  1  6 */
&(nid_objs[171]),/* OBJ_ms_ext_req                   1 3 6 1 4 1 311 2 1 14 */
&(nid_objs[134]),/* OBJ_ms_code_ind                  1 3 6 1 4 1 311 2 1 21 */
&(nid_objs[135]),/* OBJ_ms_code_com                  1 3 6 1 4 1 311 2 1 22 */
&(nid_objs[136]),/* OBJ_ms_ctl_sign                  1 3 6 1 4 1 311 10 3 1 */
&(nid_objs[137]),/* OBJ_ms_sgc                       1 3 6 1 4 1 311 10 3 3 */
&(nid_objs[138]),/* OBJ_ms_efs                       1 3 6 1 4 1 311 10 3 4 */
&(nid_objs[150]),/* OBJ_keyBag                       1 2 840 113549 1 12  10  1  1 */
&(nid_objs[151]),/* OBJ_pkcs8ShroudedKeyBag          1 2 840 113549 1 12  10  1  2 */
&(nid_objs[152]),/* OBJ_certBag                      1 2 840 113549 1 12  10  1  3 */
&(nid_objs[153]),/* OBJ_crlBag                       1 2 840 113549 1 12  10  1  4 */
&(nid_objs[154]),/* OBJ_secretBag                    1 2 840 113549 1 12  10  1  5 */
&(nid_objs[155]),/* OBJ_safeContentsBag              1 2 840 113549 1 12  10  1  6 */
&(nid_objs[34]),/* OBJ_idea_cbc                     1 3 6 1 4 1 188 7 1 1 2 */
};

