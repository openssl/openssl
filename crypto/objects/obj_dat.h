/* crypto/objects/obj_dat.h */

/* THIS FILE IS GENERATED FROM objects.h by obj_dat.pl via the
 * following command:
 * perl obj_dat.pl objects.h obj_dat.h
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

#define NUM_NID 404
#define NUM_SN 402
#define NUM_LN 402
#define NUM_OBJ 376

static unsigned char lvalues[2941]={
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
0x55,0x1D,                                   /* [489] OBJ_id_ce */
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
0x28,                                        /* [1084] OBJ_iso */
0x2A,                                        /* [1085] OBJ_member_body */
0x2A,0x86,0x48,                              /* [1086] OBJ_ISO_US */
0x2A,0x86,0x48,0xCE,0x38,                    /* [1089] OBJ_X9_57 */
0x2A,0x86,0x48,0xCE,0x38,0x04,               /* [1094] OBJ_X9cm */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,     /* [1100] OBJ_pkcs1 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,     /* [1108] OBJ_pkcs5 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,/* [1116] OBJ_SMIME */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,/* [1125] OBJ_id_smime_mod */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,/* [1135] OBJ_id_smime_ct */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,/* [1145] OBJ_id_smime_aa */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,/* [1155] OBJ_id_smime_alg */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x04,/* [1165] OBJ_id_smime_cd */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x05,/* [1175] OBJ_id_smime_spq */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,/* [1185] OBJ_id_smime_cti */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x01,/* [1195] OBJ_id_smime_mod_cms */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x02,/* [1206] OBJ_id_smime_mod_ess */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x03,/* [1217] OBJ_id_smime_mod_oid */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x04,/* [1228] OBJ_id_smime_mod_msg_v3 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x05,/* [1239] OBJ_id_smime_mod_ets_eSignature_88 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x06,/* [1250] OBJ_id_smime_mod_ets_eSignature_97 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x07,/* [1261] OBJ_id_smime_mod_ets_eSigPolicy_88 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x08,/* [1272] OBJ_id_smime_mod_ets_eSigPolicy_97 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x01,/* [1283] OBJ_id_smime_ct_receipt */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x02,/* [1294] OBJ_id_smime_ct_authData */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x03,/* [1305] OBJ_id_smime_ct_publishCert */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x04,/* [1316] OBJ_id_smime_ct_TSTInfo */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x05,/* [1327] OBJ_id_smime_ct_TDTInfo */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x06,/* [1338] OBJ_id_smime_ct_contentInfo */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x07,/* [1349] OBJ_id_smime_ct_DVCSRequestData */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x08,/* [1360] OBJ_id_smime_ct_DVCSResponseData */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x01,/* [1371] OBJ_id_smime_aa_receiptRequest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x02,/* [1382] OBJ_id_smime_aa_securityLabel */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x03,/* [1393] OBJ_id_smime_aa_mlExpandHistory */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x04,/* [1404] OBJ_id_smime_aa_contentHint */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x05,/* [1415] OBJ_id_smime_aa_msgSigDigest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x06,/* [1426] OBJ_id_smime_aa_encapContentType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x07,/* [1437] OBJ_id_smime_aa_contentIdentifier */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x08,/* [1448] OBJ_id_smime_aa_macValue */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x09,/* [1459] OBJ_id_smime_aa_equivalentLabels */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0A,/* [1470] OBJ_id_smime_aa_contentReference */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0B,/* [1481] OBJ_id_smime_aa_encrypKeyPref */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0C,/* [1492] OBJ_id_smime_aa_signingCertificate */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0D,/* [1503] OBJ_id_smime_aa_smimeEncryptCerts */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0E,/* [1514] OBJ_id_smime_aa_timeStampToken */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0F,/* [1525] OBJ_id_smime_aa_ets_sigPolicyId */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x10,/* [1536] OBJ_id_smime_aa_ets_commitmentType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x11,/* [1547] OBJ_id_smime_aa_ets_signerLocation */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x12,/* [1558] OBJ_id_smime_aa_ets_signerAttr */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x13,/* [1569] OBJ_id_smime_aa_ets_otherSigCert */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x14,/* [1580] OBJ_id_smime_aa_ets_contentTimestamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x15,/* [1591] OBJ_id_smime_aa_ets_CertificateRefs */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x16,/* [1602] OBJ_id_smime_aa_ets_RevocationRefs */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x17,/* [1613] OBJ_id_smime_aa_ets_certValues */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x18,/* [1624] OBJ_id_smime_aa_ets_revocationValues */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x19,/* [1635] OBJ_id_smime_aa_ets_escTimeStamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1A,/* [1646] OBJ_id_smime_aa_ets_certCRLTimestamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1B,/* [1657] OBJ_id_smime_aa_ets_archiveTimeStamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1C,/* [1668] OBJ_id_smime_aa_signatureType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1D,/* [1679] OBJ_id_smime_aa_dvcs_dvc */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x01,/* [1690] OBJ_id_smime_alg_ESDHwith3DES */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x02,/* [1701] OBJ_id_smime_alg_ESDHwithRC2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x03,/* [1712] OBJ_id_smime_alg_3DESwrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x04,/* [1723] OBJ_id_smime_alg_RC2wrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x05,/* [1734] OBJ_id_smime_alg_ESDH */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x06,/* [1745] OBJ_id_smime_alg_CMS3DESwrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x07,/* [1756] OBJ_id_smime_alg_CMSRC2wrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x04,0x01,/* [1767] OBJ_id_smime_cd_ldap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x05,0x01,/* [1778] OBJ_id_smime_spq_ets_sqt_uri */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x05,0x02,/* [1789] OBJ_id_smime_spq_ets_sqt_unotice */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x01,/* [1800] OBJ_id_smime_cti_ets_proofOfOrigin */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x02,/* [1811] OBJ_id_smime_cti_ets_proofOfReceipt */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x03,/* [1822] OBJ_id_smime_cti_ets_proofOfDelivery */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x04,/* [1833] OBJ_id_smime_cti_ets_proofOfSender */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x05,/* [1844] OBJ_id_smime_cti_ets_proofOfApproval */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x06,/* [1855] OBJ_id_smime_cti_ets_proofOfCreation */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x04,     /* [1866] OBJ_md4 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,          /* [1874] OBJ_id_pkix_mod */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,          /* [1881] OBJ_id_qt */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,          /* [1888] OBJ_id_it */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,          /* [1895] OBJ_id_pkip */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,          /* [1902] OBJ_id_alg */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,          /* [1909] OBJ_id_cmc */
0x2B,0x06,0x01,0x05,0x05,0x07,0x08,          /* [1916] OBJ_id_on */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,          /* [1923] OBJ_id_pda */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,          /* [1930] OBJ_id_aca */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0B,          /* [1937] OBJ_id_qcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,          /* [1944] OBJ_id_cct */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x01,     /* [1951] OBJ_id_pkix1_explicit_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x02,     /* [1959] OBJ_id_pkix1_implicit_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x03,     /* [1967] OBJ_id_pkix1_explicit_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x04,     /* [1975] OBJ_id_pkix1_implicit_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x05,     /* [1983] OBJ_id_mod_crmf */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x06,     /* [1991] OBJ_id_mod_cmc */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x07,     /* [1999] OBJ_id_mod_kea_profile_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x08,     /* [2007] OBJ_id_mod_kea_profile_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x09,     /* [2015] OBJ_id_mod_cmp */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0A,     /* [2023] OBJ_id_mod_qualified_cert_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0B,     /* [2031] OBJ_id_mod_qualified_cert_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0C,     /* [2039] OBJ_id_mod_attribute_cert */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0D,     /* [2047] OBJ_id_mod_timestamp_protocol */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0E,     /* [2055] OBJ_id_mod_ocsp */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0F,     /* [2063] OBJ_id_mod_dvcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x10,     /* [2071] OBJ_id_mod_cmp2000 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x02,     /* [2079] OBJ_biometricInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x03,     /* [2087] OBJ_qcStatements */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x04,     /* [2095] OBJ_ac_auditEntity */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x05,     /* [2103] OBJ_ac_targeting */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x06,     /* [2111] OBJ_aaControls */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x07,     /* [2119] OBJ_sbqp_ipAddrBlock */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x08,     /* [2127] OBJ_sbqp_autonomousSysNum */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x09,     /* [2135] OBJ_sbqp_routerIdentifier */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x03,     /* [2143] OBJ_textNotice */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x05,     /* [2151] OBJ_ipsecEndSystem */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x06,     /* [2159] OBJ_ipsecTunnel */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x07,     /* [2167] OBJ_ipsecUser */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x0A,     /* [2175] OBJ_dvcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x01,     /* [2183] OBJ_id_it_caProtEncCert */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x02,     /* [2191] OBJ_id_it_signKeyPairTypes */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x03,     /* [2199] OBJ_id_it_encKeyPairTypes */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x04,     /* [2207] OBJ_id_it_preferredSymmAlg */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x05,     /* [2215] OBJ_id_it_caKeyUpdateInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x06,     /* [2223] OBJ_id_it_currentCRL */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x07,     /* [2231] OBJ_id_it_unsupportedOIDs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x08,     /* [2239] OBJ_id_it_subscriptionRequest */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x09,     /* [2247] OBJ_id_it_subscriptionResponse */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0A,     /* [2255] OBJ_id_it_keyPairParamReq */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0B,     /* [2263] OBJ_id_it_keyPairParamRep */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0C,     /* [2271] OBJ_id_it_revPassphrase */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0D,     /* [2279] OBJ_id_it_implicitConfirm */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0E,     /* [2287] OBJ_id_it_confirmWaitTime */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0F,     /* [2295] OBJ_id_it_origPKIMessage */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,     /* [2303] OBJ_id_regCtrl */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x02,     /* [2311] OBJ_id_regInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x01,/* [2319] OBJ_id_regCtrl_regToken */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x02,/* [2328] OBJ_id_regCtrl_authenticator */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x03,/* [2337] OBJ_id_regCtrl_pkiPublicationInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x04,/* [2346] OBJ_id_regCtrl_pkiArchiveOptions */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x05,/* [2355] OBJ_id_regCtrl_oldCertID */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x06,/* [2364] OBJ_id_regCtrl_protocolEncrKey */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x02,0x01,/* [2373] OBJ_id_regInfo_utf8Pairs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x02,0x02,/* [2382] OBJ_id_regInfo_certReq */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x01,     /* [2391] OBJ_id_alg_des40 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x02,     /* [2399] OBJ_id_alg_noSignature */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x03,     /* [2407] OBJ_id_alg_dh_sig_hmac_sha1 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x04,     /* [2415] OBJ_id_alg_dh_pop */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x01,     /* [2423] OBJ_id_cmc_statusInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x02,     /* [2431] OBJ_id_cmc_identification */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x03,     /* [2439] OBJ_id_cmc_identityProof */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x04,     /* [2447] OBJ_id_cmc_dataReturn */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x05,     /* [2455] OBJ_id_cmc_transactionId */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x06,     /* [2463] OBJ_id_cmc_senderNonce */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x07,     /* [2471] OBJ_id_cmc_recipientNonce */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x08,     /* [2479] OBJ_id_cmc_addExtensions */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x09,     /* [2487] OBJ_id_cmc_encryptedPOP */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x0A,     /* [2495] OBJ_id_cmc_decryptedPOP */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x0B,     /* [2503] OBJ_id_cmc_lraPOPWitness */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x0F,     /* [2511] OBJ_id_cmc_getCert */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x10,     /* [2519] OBJ_id_cmc_getCRL */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x11,     /* [2527] OBJ_id_cmc_revokeRequest */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x12,     /* [2535] OBJ_id_cmc_regInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x13,     /* [2543] OBJ_id_cmc_responseInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x15,     /* [2551] OBJ_id_cmc_queryPending */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x16,     /* [2559] OBJ_id_cmc_popLinkRandom */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x17,     /* [2567] OBJ_id_cmc_popLinkWitness */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x18,     /* [2575] OBJ_id_cmc_confirmCertAcceptance */
0x2B,0x06,0x01,0x05,0x05,0x07,0x08,0x01,     /* [2583] OBJ_id_on_personalData */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x01,     /* [2591] OBJ_id_pda_dateOfBirth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x02,     /* [2599] OBJ_id_pda_placeOfBirth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x03,     /* [2607] OBJ_id_pda_gender */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x04,     /* [2615] OBJ_id_pda_countryOfCitizenship */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x05,     /* [2623] OBJ_id_pda_countryOfResidence */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x01,     /* [2631] OBJ_id_aca_authenticationInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x02,     /* [2639] OBJ_id_aca_accessIdentity */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x03,     /* [2647] OBJ_id_aca_chargingIdentity */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x04,     /* [2655] OBJ_id_aca_group */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x05,     /* [2663] OBJ_id_aca_role */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0B,0x01,     /* [2671] OBJ_id_qcs_pkixQCSyntax_v1 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,0x01,     /* [2679] OBJ_id_cct_crs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,0x02,     /* [2687] OBJ_id_cct_PKIData */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,0x03,     /* [2695] OBJ_id_cct_PKIResponse */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x03,     /* [2703] OBJ_ad_timeStamping */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x04,     /* [2711] OBJ_ad_dvcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x01,/* [2719] OBJ_id_pkix_OCSP_basic */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x02,/* [2728] OBJ_id_pkix_OCSP_Nonce */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x03,/* [2737] OBJ_id_pkix_OCSP_CrlID */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x04,/* [2746] OBJ_id_pkix_OCSP_acceptableResponses */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x05,/* [2755] OBJ_id_pkix_OCSP_noCheck */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x06,/* [2764] OBJ_id_pkix_OCSP_archiveCutoff */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x07,/* [2773] OBJ_id_pkix_OCSP_serviceLocator */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x08,/* [2782] OBJ_id_pkix_OCSP_extendedStatus */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x09,/* [2791] OBJ_id_pkix_OCSP_valid */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x0A,/* [2800] OBJ_id_pkix_OCSP_path */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x0B,/* [2809] OBJ_id_pkix_OCSP_trustRoot */
0x2B,0x0E,0x03,0x02,                         /* [2818] OBJ_algorithm */
0x2B,0x0E,0x03,0x02,0x0B,                    /* [2822] OBJ_rsaSignature */
0x55,0x08,                                   /* [2827] OBJ_X500algorithms */
0x2B,                                        /* [2829] OBJ_org */
0x2B,0x06,                                   /* [2830] OBJ_dod */
0x2B,0x06,0x01,                              /* [2832] OBJ_iana */
0x2B,0x06,0x01,0x01,                         /* [2835] OBJ_Directory */
0x2B,0x06,0x01,0x02,                         /* [2839] OBJ_Management */
0x2B,0x06,0x01,0x03,                         /* [2843] OBJ_Experimental */
0x2B,0x06,0x01,0x04,                         /* [2847] OBJ_Private */
0x2B,0x06,0x01,0x05,                         /* [2851] OBJ_Security */
0x2B,0x06,0x01,0x06,                         /* [2855] OBJ_SNMPv2 */
0x2B,0x06,0x01,0x07,                         /* [2859] OBJ_Mail */
0x01,                                        /* [2863] OBJ_Enterprises */
0xBA,0x82,0x58,                              /* [2864] OBJ_dcObject */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x19,/* [2867] OBJ_domainComponent */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x0D,/* [2877] OBJ_Domain */
0x50,                                        /* [2887] OBJ_joint_iso_ccitt */
0x55,0x01,0x05,                              /* [2888] OBJ_selected_attribute_types */
0x55,0x01,0x05,0x37,                         /* [2891] OBJ_clearance */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x03,/* [2895] OBJ_md4WithRSAEncryption */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x0A,     /* [2904] OBJ_ac_proxying */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x0B,     /* [2912] OBJ_sinfo_access */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x06,     /* [2920] OBJ_id_aca_encAttrs */
0x55,0x04,0x48,                              /* [2928] OBJ_role */
0x55,0x1D,0x24,                              /* [2931] OBJ_policy_constraints */
0x55,0x1D,0x37,                              /* [2934] OBJ_target_information */
0x55,0x1D,0x38,                              /* [2937] OBJ_no_rev_avail */
};

static ASN1_OBJECT nid_objs[NUM_NID]={
{"UNDEF","undefined",NID_undef,1,&(lvalues[0]),0},
{"rsadsi","RSA Data Security, Inc.",NID_rsadsi,6,&(lvalues[1]),0},
{"pkcs","RSA Data Security, Inc. PKCS",NID_pkcs,7,&(lvalues[7]),0},
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
{"X500","directory services (X.500)",NID_X500,1,&(lvalues[83]),0},
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
{"id-ce","id-ce",NID_id_ce,2,&(lvalues[489]),0},
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
{"RSA-MDC2","mdc2WithRSA",NID_mdc2WithRSA,4,&(lvalues[531]),0},
{"RC4-40","rc4-40",NID_rc4_40,0,NULL},
{"RC2-40-CBC","rc2-40-cbc",NID_rc2_40_cbc,0,NULL},
{"G","givenName",NID_givenName,3,&(lvalues[535]),0},
{"S","surname",NID_surname,3,&(lvalues[538]),0},
{"I","initials",NID_initials,3,&(lvalues[541]),0},
{"uniqueIdentifier","uniqueIdentifier",NID_uniqueIdentifier,3,
	&(lvalues[544]),0},
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
{"CRLReason","X509v3 CRL Reason Code",NID_crl_reason,3,&(lvalues[750]),0},
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
{"ISO","iso",NID_iso,1,&(lvalues[1084]),0},
{"member-body","ISO Member Body",NID_member_body,1,&(lvalues[1085]),0},
{"ISO-US","ISO US Member Body",NID_ISO_US,3,&(lvalues[1086]),0},
{"X9-57","X9.57",NID_X9_57,5,&(lvalues[1089]),0},
{"X9cm","X9.57 CM ?",NID_X9cm,6,&(lvalues[1094]),0},
{"pkcs1","pkcs1",NID_pkcs1,8,&(lvalues[1100]),0},
{"pkcs5","pkcs5",NID_pkcs5,8,&(lvalues[1108]),0},
{"SMIME","S/MIME",NID_SMIME,9,&(lvalues[1116]),0},
{"id-smime-mod","id-smime-mod",NID_id_smime_mod,10,&(lvalues[1125]),0},
{"id-smime-ct","id-smime-ct",NID_id_smime_ct,10,&(lvalues[1135]),0},
{"id-smime-aa","id-smime-aa",NID_id_smime_aa,10,&(lvalues[1145]),0},
{"id-smime-alg","id-smime-alg",NID_id_smime_alg,10,&(lvalues[1155]),0},
{"id-smime-cd","id-smime-cd",NID_id_smime_cd,10,&(lvalues[1165]),0},
{"id-smime-spq","id-smime-spq",NID_id_smime_spq,10,&(lvalues[1175]),0},
{"id-smime-cti","id-smime-cti",NID_id_smime_cti,10,&(lvalues[1185]),0},
{"id-smime-mod-cms","id-smime-mod-cms",NID_id_smime_mod_cms,11,
	&(lvalues[1195]),0},
{"id-smime-mod-ess","id-smime-mod-ess",NID_id_smime_mod_ess,11,
	&(lvalues[1206]),0},
{"id-smime-mod-oid","id-smime-mod-oid",NID_id_smime_mod_oid,11,
	&(lvalues[1217]),0},
{"id-smime-mod-msg-v3","id-smime-mod-msg-v3",NID_id_smime_mod_msg_v3,
	11,&(lvalues[1228]),0},
{"id-smime-mod-ets-eSignature-88","id-smime-mod-ets-eSignature-88",
	NID_id_smime_mod_ets_eSignature_88,11,&(lvalues[1239]),0},
{"id-smime-mod-ets-eSignature-97","id-smime-mod-ets-eSignature-97",
	NID_id_smime_mod_ets_eSignature_97,11,&(lvalues[1250]),0},
{"id-smime-mod-ets-eSigPolicy-88","id-smime-mod-ets-eSigPolicy-88",
	NID_id_smime_mod_ets_eSigPolicy_88,11,&(lvalues[1261]),0},
{"id-smime-mod-ets-eSigPolicy-97","id-smime-mod-ets-eSigPolicy-97",
	NID_id_smime_mod_ets_eSigPolicy_97,11,&(lvalues[1272]),0},
{"id-smime-ct-receipt","id-smime-ct-receipt",NID_id_smime_ct_receipt,
	11,&(lvalues[1283]),0},
{"id-smime-ct-authData","id-smime-ct-authData",
	NID_id_smime_ct_authData,11,&(lvalues[1294]),0},
{"id-smime-ct-publishCert","id-smime-ct-publishCert",
	NID_id_smime_ct_publishCert,11,&(lvalues[1305]),0},
{"id-smime-ct-TSTInfo","id-smime-ct-TSTInfo",NID_id_smime_ct_TSTInfo,
	11,&(lvalues[1316]),0},
{"id-smime-ct-TDTInfo","id-smime-ct-TDTInfo",NID_id_smime_ct_TDTInfo,
	11,&(lvalues[1327]),0},
{"id-smime-ct-contentInfo","id-smime-ct-contentInfo",
	NID_id_smime_ct_contentInfo,11,&(lvalues[1338]),0},
{"id-smime-ct-DVCSRequestData","id-smime-ct-DVCSRequestData",
	NID_id_smime_ct_DVCSRequestData,11,&(lvalues[1349]),0},
{"id-smime-ct-DVCSResponseData","id-smime-ct-DVCSResponseData",
	NID_id_smime_ct_DVCSResponseData,11,&(lvalues[1360]),0},
{"id-smime-aa-receiptRequest","id-smime-aa-receiptRequest",
	NID_id_smime_aa_receiptRequest,11,&(lvalues[1371]),0},
{"id-smime-aa-securityLabel","id-smime-aa-securityLabel",
	NID_id_smime_aa_securityLabel,11,&(lvalues[1382]),0},
{"id-smime-aa-mlExpandHistory","id-smime-aa-mlExpandHistory",
	NID_id_smime_aa_mlExpandHistory,11,&(lvalues[1393]),0},
{"id-smime-aa-contentHint","id-smime-aa-contentHint",
	NID_id_smime_aa_contentHint,11,&(lvalues[1404]),0},
{"id-smime-aa-msgSigDigest","id-smime-aa-msgSigDigest",
	NID_id_smime_aa_msgSigDigest,11,&(lvalues[1415]),0},
{"id-smime-aa-encapContentType","id-smime-aa-encapContentType",
	NID_id_smime_aa_encapContentType,11,&(lvalues[1426]),0},
{"id-smime-aa-contentIdentifier","id-smime-aa-contentIdentifier",
	NID_id_smime_aa_contentIdentifier,11,&(lvalues[1437]),0},
{"id-smime-aa-macValue","id-smime-aa-macValue",
	NID_id_smime_aa_macValue,11,&(lvalues[1448]),0},
{"id-smime-aa-equivalentLabels","id-smime-aa-equivalentLabels",
	NID_id_smime_aa_equivalentLabels,11,&(lvalues[1459]),0},
{"id-smime-aa-contentReference","id-smime-aa-contentReference",
	NID_id_smime_aa_contentReference,11,&(lvalues[1470]),0},
{"id-smime-aa-encrypKeyPref","id-smime-aa-encrypKeyPref",
	NID_id_smime_aa_encrypKeyPref,11,&(lvalues[1481]),0},
{"id-smime-aa-signingCertificate","id-smime-aa-signingCertificate",
	NID_id_smime_aa_signingCertificate,11,&(lvalues[1492]),0},
{"id-smime-aa-smimeEncryptCerts","id-smime-aa-smimeEncryptCerts",
	NID_id_smime_aa_smimeEncryptCerts,11,&(lvalues[1503]),0},
{"id-smime-aa-timeStampToken","id-smime-aa-timeStampToken",
	NID_id_smime_aa_timeStampToken,11,&(lvalues[1514]),0},
{"id-smime-aa-ets-sigPolicyId","id-smime-aa-ets-sigPolicyId",
	NID_id_smime_aa_ets_sigPolicyId,11,&(lvalues[1525]),0},
{"id-smime-aa-ets-commitmentType","id-smime-aa-ets-commitmentType",
	NID_id_smime_aa_ets_commitmentType,11,&(lvalues[1536]),0},
{"id-smime-aa-ets-signerLocation","id-smime-aa-ets-signerLocation",
	NID_id_smime_aa_ets_signerLocation,11,&(lvalues[1547]),0},
{"id-smime-aa-ets-signerAttr","id-smime-aa-ets-signerAttr",
	NID_id_smime_aa_ets_signerAttr,11,&(lvalues[1558]),0},
{"id-smime-aa-ets-otherSigCert","id-smime-aa-ets-otherSigCert",
	NID_id_smime_aa_ets_otherSigCert,11,&(lvalues[1569]),0},
{"id-smime-aa-ets-contentTimestamp",
	"id-smime-aa-ets-contentTimestamp",
	NID_id_smime_aa_ets_contentTimestamp,11,&(lvalues[1580]),0},
{"id-smime-aa-ets-CertificateRefs","id-smime-aa-ets-CertificateRefs",
	NID_id_smime_aa_ets_CertificateRefs,11,&(lvalues[1591]),0},
{"id-smime-aa-ets-RevocationRefs","id-smime-aa-ets-RevocationRefs",
	NID_id_smime_aa_ets_RevocationRefs,11,&(lvalues[1602]),0},
{"id-smime-aa-ets-certValues","id-smime-aa-ets-certValues",
	NID_id_smime_aa_ets_certValues,11,&(lvalues[1613]),0},
{"id-smime-aa-ets-revocationValues",
	"id-smime-aa-ets-revocationValues",
	NID_id_smime_aa_ets_revocationValues,11,&(lvalues[1624]),0},
{"id-smime-aa-ets-escTimeStamp","id-smime-aa-ets-escTimeStamp",
	NID_id_smime_aa_ets_escTimeStamp,11,&(lvalues[1635]),0},
{"id-smime-aa-ets-certCRLTimestamp",
	"id-smime-aa-ets-certCRLTimestamp",
	NID_id_smime_aa_ets_certCRLTimestamp,11,&(lvalues[1646]),0},
{"id-smime-aa-ets-archiveTimeStamp",
	"id-smime-aa-ets-archiveTimeStamp",
	NID_id_smime_aa_ets_archiveTimeStamp,11,&(lvalues[1657]),0},
{"id-smime-aa-signatureType","id-smime-aa-signatureType",
	NID_id_smime_aa_signatureType,11,&(lvalues[1668]),0},
{"id-smime-aa-dvcs-dvc","id-smime-aa-dvcs-dvc",
	NID_id_smime_aa_dvcs_dvc,11,&(lvalues[1679]),0},
{"id-smime-alg-ESDHwith3DES","id-smime-alg-ESDHwith3DES",
	NID_id_smime_alg_ESDHwith3DES,11,&(lvalues[1690]),0},
{"id-smime-alg-ESDHwithRC2","id-smime-alg-ESDHwithRC2",
	NID_id_smime_alg_ESDHwithRC2,11,&(lvalues[1701]),0},
{"id-smime-alg-3DESwrap","id-smime-alg-3DESwrap",
	NID_id_smime_alg_3DESwrap,11,&(lvalues[1712]),0},
{"id-smime-alg-RC2wrap","id-smime-alg-RC2wrap",
	NID_id_smime_alg_RC2wrap,11,&(lvalues[1723]),0},
{"id-smime-alg-ESDH","id-smime-alg-ESDH",NID_id_smime_alg_ESDH,11,
	&(lvalues[1734]),0},
{"id-smime-alg-CMS3DESwrap","id-smime-alg-CMS3DESwrap",
	NID_id_smime_alg_CMS3DESwrap,11,&(lvalues[1745]),0},
{"id-smime-alg-CMSRC2wrap","id-smime-alg-CMSRC2wrap",
	NID_id_smime_alg_CMSRC2wrap,11,&(lvalues[1756]),0},
{"id-smime-cd-ldap","id-smime-cd-ldap",NID_id_smime_cd_ldap,11,
	&(lvalues[1767]),0},
{"id-smime-spq-ets-sqt-uri","id-smime-spq-ets-sqt-uri",
	NID_id_smime_spq_ets_sqt_uri,11,&(lvalues[1778]),0},
{"id-smime-spq-ets-sqt-unotice","id-smime-spq-ets-sqt-unotice",
	NID_id_smime_spq_ets_sqt_unotice,11,&(lvalues[1789]),0},
{"id-smime-cti-ets-proofOfOrigin","id-smime-cti-ets-proofOfOrigin",
	NID_id_smime_cti_ets_proofOfOrigin,11,&(lvalues[1800]),0},
{"id-smime-cti-ets-proofOfReceipt","id-smime-cti-ets-proofOfReceipt",
	NID_id_smime_cti_ets_proofOfReceipt,11,&(lvalues[1811]),0},
{"id-smime-cti-ets-proofOfDelivery",
	"id-smime-cti-ets-proofOfDelivery",
	NID_id_smime_cti_ets_proofOfDelivery,11,&(lvalues[1822]),0},
{"id-smime-cti-ets-proofOfSender","id-smime-cti-ets-proofOfSender",
	NID_id_smime_cti_ets_proofOfSender,11,&(lvalues[1833]),0},
{"id-smime-cti-ets-proofOfApproval",
	"id-smime-cti-ets-proofOfApproval",
	NID_id_smime_cti_ets_proofOfApproval,11,&(lvalues[1844]),0},
{"id-smime-cti-ets-proofOfCreation",
	"id-smime-cti-ets-proofOfCreation",
	NID_id_smime_cti_ets_proofOfCreation,11,&(lvalues[1855]),0},
{"MD4","md4",NID_md4,8,&(lvalues[1866]),0},
{"id-pkix-mod","id-pkix-mod",NID_id_pkix_mod,7,&(lvalues[1874]),0},
{"id-qt","id-qt",NID_id_qt,7,&(lvalues[1881]),0},
{"id-it","id-it",NID_id_it,7,&(lvalues[1888]),0},
{"id-pkip","id-pkip",NID_id_pkip,7,&(lvalues[1895]),0},
{"id-alg","id-alg",NID_id_alg,7,&(lvalues[1902]),0},
{"id-cmc","id-cmc",NID_id_cmc,7,&(lvalues[1909]),0},
{"id-on","id-on",NID_id_on,7,&(lvalues[1916]),0},
{"id-pda","id-pda",NID_id_pda,7,&(lvalues[1923]),0},
{"id-aca","id-aca",NID_id_aca,7,&(lvalues[1930]),0},
{"id-qcs","id-qcs",NID_id_qcs,7,&(lvalues[1937]),0},
{"id-cct","id-cct",NID_id_cct,7,&(lvalues[1944]),0},
{"id-pkix1-explicit-88","id-pkix1-explicit-88",
	NID_id_pkix1_explicit_88,8,&(lvalues[1951]),0},
{"id-pkix1-implicit-88","id-pkix1-implicit-88",
	NID_id_pkix1_implicit_88,8,&(lvalues[1959]),0},
{"id-pkix1-explicit-93","id-pkix1-explicit-93",
	NID_id_pkix1_explicit_93,8,&(lvalues[1967]),0},
{"id-pkix1-implicit-93","id-pkix1-implicit-93",
	NID_id_pkix1_implicit_93,8,&(lvalues[1975]),0},
{"id-mod-crmf","id-mod-crmf",NID_id_mod_crmf,8,&(lvalues[1983]),0},
{"id-mod-cmc","id-mod-cmc",NID_id_mod_cmc,8,&(lvalues[1991]),0},
{"id-mod-kea-profile-88","id-mod-kea-profile-88",
	NID_id_mod_kea_profile_88,8,&(lvalues[1999]),0},
{"id-mod-kea-profile-93","id-mod-kea-profile-93",
	NID_id_mod_kea_profile_93,8,&(lvalues[2007]),0},
{"id-mod-cmp","id-mod-cmp",NID_id_mod_cmp,8,&(lvalues[2015]),0},
{"id-mod-qualified-cert-88","id-mod-qualified-cert-88",
	NID_id_mod_qualified_cert_88,8,&(lvalues[2023]),0},
{"id-mod-qualified-cert-93","id-mod-qualified-cert-93",
	NID_id_mod_qualified_cert_93,8,&(lvalues[2031]),0},
{"id-mod-attribute-cert","id-mod-attribute-cert",
	NID_id_mod_attribute_cert,8,&(lvalues[2039]),0},
{"id-mod-timestamp-protocol","id-mod-timestamp-protocol",
	NID_id_mod_timestamp_protocol,8,&(lvalues[2047]),0},
{"id-mod-ocsp","id-mod-ocsp",NID_id_mod_ocsp,8,&(lvalues[2055]),0},
{"id-mod-dvcs","id-mod-dvcs",NID_id_mod_dvcs,8,&(lvalues[2063]),0},
{"id-mod-cmp2000","id-mod-cmp2000",NID_id_mod_cmp2000,8,
	&(lvalues[2071]),0},
{"biometricInfo","Biometric Info",NID_biometricInfo,8,&(lvalues[2079]),0},
{"qcStatements","qcStatements",NID_qcStatements,8,&(lvalues[2087]),0},
{"ac-auditEntity","ac-auditEntity",NID_ac_auditEntity,8,
	&(lvalues[2095]),0},
{"ac-targeting","ac-targeting",NID_ac_targeting,8,&(lvalues[2103]),0},
{"aaControls","aaControls",NID_aaControls,8,&(lvalues[2111]),0},
{"sbqp-ipAddrBlock","sbqp-ipAddrBlock",NID_sbqp_ipAddrBlock,8,
	&(lvalues[2119]),0},
{"sbqp-autonomousSysNum","sbqp-autonomousSysNum",
	NID_sbqp_autonomousSysNum,8,&(lvalues[2127]),0},
{"sbqp-routerIdentifier","sbqp-routerIdentifier",
	NID_sbqp_routerIdentifier,8,&(lvalues[2135]),0},
{"textNotice","textNotice",NID_textNotice,8,&(lvalues[2143]),0},
{"ipsecEndSystem","IPSec End System",NID_ipsecEndSystem,8,
	&(lvalues[2151]),0},
{"ipsecTunnel","IPSec Tunnel",NID_ipsecTunnel,8,&(lvalues[2159]),0},
{"ipsecUser","IPSec User",NID_ipsecUser,8,&(lvalues[2167]),0},
{"DVCS","dvcs",NID_dvcs,8,&(lvalues[2175]),0},
{"id-it-caProtEncCert","id-it-caProtEncCert",NID_id_it_caProtEncCert,
	8,&(lvalues[2183]),0},
{"id-it-signKeyPairTypes","id-it-signKeyPairTypes",
	NID_id_it_signKeyPairTypes,8,&(lvalues[2191]),0},
{"id-it-encKeyPairTypes","id-it-encKeyPairTypes",
	NID_id_it_encKeyPairTypes,8,&(lvalues[2199]),0},
{"id-it-preferredSymmAlg","id-it-preferredSymmAlg",
	NID_id_it_preferredSymmAlg,8,&(lvalues[2207]),0},
{"id-it-caKeyUpdateInfo","id-it-caKeyUpdateInfo",
	NID_id_it_caKeyUpdateInfo,8,&(lvalues[2215]),0},
{"id-it-currentCRL","id-it-currentCRL",NID_id_it_currentCRL,8,
	&(lvalues[2223]),0},
{"id-it-unsupportedOIDs","id-it-unsupportedOIDs",
	NID_id_it_unsupportedOIDs,8,&(lvalues[2231]),0},
{"id-it-subscriptionRequest","id-it-subscriptionRequest",
	NID_id_it_subscriptionRequest,8,&(lvalues[2239]),0},
{"id-it-subscriptionResponse","id-it-subscriptionResponse",
	NID_id_it_subscriptionResponse,8,&(lvalues[2247]),0},
{"id-it-keyPairParamReq","id-it-keyPairParamReq",
	NID_id_it_keyPairParamReq,8,&(lvalues[2255]),0},
{"id-it-keyPairParamRep","id-it-keyPairParamRep",
	NID_id_it_keyPairParamRep,8,&(lvalues[2263]),0},
{"id-it-revPassphrase","id-it-revPassphrase",NID_id_it_revPassphrase,
	8,&(lvalues[2271]),0},
{"id-it-implicitConfirm","id-it-implicitConfirm",
	NID_id_it_implicitConfirm,8,&(lvalues[2279]),0},
{"id-it-confirmWaitTime","id-it-confirmWaitTime",
	NID_id_it_confirmWaitTime,8,&(lvalues[2287]),0},
{"id-it-origPKIMessage","id-it-origPKIMessage",
	NID_id_it_origPKIMessage,8,&(lvalues[2295]),0},
{"id-regCtrl","id-regCtrl",NID_id_regCtrl,8,&(lvalues[2303]),0},
{"id-regInfo","id-regInfo",NID_id_regInfo,8,&(lvalues[2311]),0},
{"id-regCtrl-regToken","id-regCtrl-regToken",NID_id_regCtrl_regToken,
	9,&(lvalues[2319]),0},
{"id-regCtrl-authenticator","id-regCtrl-authenticator",
	NID_id_regCtrl_authenticator,9,&(lvalues[2328]),0},
{"id-regCtrl-pkiPublicationInfo","id-regCtrl-pkiPublicationInfo",
	NID_id_regCtrl_pkiPublicationInfo,9,&(lvalues[2337]),0},
{"id-regCtrl-pkiArchiveOptions","id-regCtrl-pkiArchiveOptions",
	NID_id_regCtrl_pkiArchiveOptions,9,&(lvalues[2346]),0},
{"id-regCtrl-oldCertID","id-regCtrl-oldCertID",
	NID_id_regCtrl_oldCertID,9,&(lvalues[2355]),0},
{"id-regCtrl-protocolEncrKey","id-regCtrl-protocolEncrKey",
	NID_id_regCtrl_protocolEncrKey,9,&(lvalues[2364]),0},
{"id-regInfo-utf8Pairs","id-regInfo-utf8Pairs",
	NID_id_regInfo_utf8Pairs,9,&(lvalues[2373]),0},
{"id-regInfo-certReq","id-regInfo-certReq",NID_id_regInfo_certReq,9,
	&(lvalues[2382]),0},
{"id-alg-des40","id-alg-des40",NID_id_alg_des40,8,&(lvalues[2391]),0},
{"id-alg-noSignature","id-alg-noSignature",NID_id_alg_noSignature,8,
	&(lvalues[2399]),0},
{"id-alg-dh-sig-hmac-sha1","id-alg-dh-sig-hmac-sha1",
	NID_id_alg_dh_sig_hmac_sha1,8,&(lvalues[2407]),0},
{"id-alg-dh-pop","id-alg-dh-pop",NID_id_alg_dh_pop,8,&(lvalues[2415]),0},
{"id-cmc-statusInfo","id-cmc-statusInfo",NID_id_cmc_statusInfo,8,
	&(lvalues[2423]),0},
{"id-cmc-identification","id-cmc-identification",
	NID_id_cmc_identification,8,&(lvalues[2431]),0},
{"id-cmc-identityProof","id-cmc-identityProof",
	NID_id_cmc_identityProof,8,&(lvalues[2439]),0},
{"id-cmc-dataReturn","id-cmc-dataReturn",NID_id_cmc_dataReturn,8,
	&(lvalues[2447]),0},
{"id-cmc-transactionId","id-cmc-transactionId",
	NID_id_cmc_transactionId,8,&(lvalues[2455]),0},
{"id-cmc-senderNonce","id-cmc-senderNonce",NID_id_cmc_senderNonce,8,
	&(lvalues[2463]),0},
{"id-cmc-recipientNonce","id-cmc-recipientNonce",
	NID_id_cmc_recipientNonce,8,&(lvalues[2471]),0},
{"id-cmc-addExtensions","id-cmc-addExtensions",
	NID_id_cmc_addExtensions,8,&(lvalues[2479]),0},
{"id-cmc-encryptedPOP","id-cmc-encryptedPOP",NID_id_cmc_encryptedPOP,
	8,&(lvalues[2487]),0},
{"id-cmc-decryptedPOP","id-cmc-decryptedPOP",NID_id_cmc_decryptedPOP,
	8,&(lvalues[2495]),0},
{"id-cmc-lraPOPWitness","id-cmc-lraPOPWitness",
	NID_id_cmc_lraPOPWitness,8,&(lvalues[2503]),0},
{"id-cmc-getCert","id-cmc-getCert",NID_id_cmc_getCert,8,
	&(lvalues[2511]),0},
{"id-cmc-getCRL","id-cmc-getCRL",NID_id_cmc_getCRL,8,&(lvalues[2519]),0},
{"id-cmc-revokeRequest","id-cmc-revokeRequest",
	NID_id_cmc_revokeRequest,8,&(lvalues[2527]),0},
{"id-cmc-regInfo","id-cmc-regInfo",NID_id_cmc_regInfo,8,
	&(lvalues[2535]),0},
{"id-cmc-responseInfo","id-cmc-responseInfo",NID_id_cmc_responseInfo,
	8,&(lvalues[2543]),0},
{"id-cmc-queryPending","id-cmc-queryPending",NID_id_cmc_queryPending,
	8,&(lvalues[2551]),0},
{"id-cmc-popLinkRandom","id-cmc-popLinkRandom",
	NID_id_cmc_popLinkRandom,8,&(lvalues[2559]),0},
{"id-cmc-popLinkWitness","id-cmc-popLinkWitness",
	NID_id_cmc_popLinkWitness,8,&(lvalues[2567]),0},
{"id-cmc-confirmCertAcceptance","id-cmc-confirmCertAcceptance",
	NID_id_cmc_confirmCertAcceptance,8,&(lvalues[2575]),0},
{"id-on-personalData","id-on-personalData",NID_id_on_personalData,8,
	&(lvalues[2583]),0},
{"id-pda-dateOfBirth","id-pda-dateOfBirth",NID_id_pda_dateOfBirth,8,
	&(lvalues[2591]),0},
{"id-pda-placeOfBirth","id-pda-placeOfBirth",NID_id_pda_placeOfBirth,
	8,&(lvalues[2599]),0},
{NULL,NULL,NID_undef,0,NULL},
{"id-pda-gender","id-pda-gender",NID_id_pda_gender,8,&(lvalues[2607]),0},
{"id-pda-countryOfCitizenship","id-pda-countryOfCitizenship",
	NID_id_pda_countryOfCitizenship,8,&(lvalues[2615]),0},
{"id-pda-countryOfResidence","id-pda-countryOfResidence",
	NID_id_pda_countryOfResidence,8,&(lvalues[2623]),0},
{"id-aca-authenticationInfo","id-aca-authenticationInfo",
	NID_id_aca_authenticationInfo,8,&(lvalues[2631]),0},
{"id-aca-accessIdentity","id-aca-accessIdentity",
	NID_id_aca_accessIdentity,8,&(lvalues[2639]),0},
{"id-aca-chargingIdentity","id-aca-chargingIdentity",
	NID_id_aca_chargingIdentity,8,&(lvalues[2647]),0},
{"id-aca-group","id-aca-group",NID_id_aca_group,8,&(lvalues[2655]),0},
{"id-aca-role","id-aca-role",NID_id_aca_role,8,&(lvalues[2663]),0},
{"id-qcs-pkixQCSyntax-v1","id-qcs-pkixQCSyntax-v1",
	NID_id_qcs_pkixQCSyntax_v1,8,&(lvalues[2671]),0},
{"id-cct-crs","id-cct-crs",NID_id_cct_crs,8,&(lvalues[2679]),0},
{"id-cct-PKIData","id-cct-PKIData",NID_id_cct_PKIData,8,
	&(lvalues[2687]),0},
{"id-cct-PKIResponse","id-cct-PKIResponse",NID_id_cct_PKIResponse,8,
	&(lvalues[2695]),0},
{"ad_timestamping","AD Time Stamping",NID_ad_timeStamping,8,
	&(lvalues[2703]),0},
{"AD_DVCS","ad dvcs",NID_ad_dvcs,8,&(lvalues[2711]),0},
{"basicOCSPResponse","Basic OCSP Response",NID_id_pkix_OCSP_basic,9,
	&(lvalues[2719]),0},
{"Nonce","OCSP Nonce",NID_id_pkix_OCSP_Nonce,9,&(lvalues[2728]),0},
{"CrlID","OCSP CRL ID",NID_id_pkix_OCSP_CrlID,9,&(lvalues[2737]),0},
{"acceptableResponses","Acceptable OCSP Responses",
	NID_id_pkix_OCSP_acceptableResponses,9,&(lvalues[2746]),0},
{"noCheck","noCheck",NID_id_pkix_OCSP_noCheck,9,&(lvalues[2755]),0},
{"archiveCutoff","OCSP Archive Cutoff",NID_id_pkix_OCSP_archiveCutoff,
	9,&(lvalues[2764]),0},
{"serviceLocator","OCSP Service Locator",
	NID_id_pkix_OCSP_serviceLocator,9,&(lvalues[2773]),0},
{"extendedStatus","Extended OCSP Status",
	NID_id_pkix_OCSP_extendedStatus,9,&(lvalues[2782]),0},
{"valid","valid",NID_id_pkix_OCSP_valid,9,&(lvalues[2791]),0},
{"path","path",NID_id_pkix_OCSP_path,9,&(lvalues[2800]),0},
{"trustRoot","Trust Root",NID_id_pkix_OCSP_trustRoot,9,
	&(lvalues[2809]),0},
{"algorithm","algorithm",NID_algorithm,4,&(lvalues[2818]),0},
{"rsaSignature","rsaSignature",NID_rsaSignature,5,&(lvalues[2822]),0},
{"X500algorithms","directory services - algorithms",
	NID_X500algorithms,2,&(lvalues[2827]),0},
{"ORG","org",NID_org,1,&(lvalues[2829]),0},
{"DOD","dod",NID_dod,2,&(lvalues[2830]),0},
{"IANA","iana",NID_iana,3,&(lvalues[2832]),0},
{"directory","Directory",NID_Directory,4,&(lvalues[2835]),0},
{"mgmt","Management",NID_Management,4,&(lvalues[2839]),0},
{"experimental","Experimental",NID_Experimental,4,&(lvalues[2843]),0},
{"private","Private",NID_Private,4,&(lvalues[2847]),0},
{"security","Security",NID_Security,4,&(lvalues[2851]),0},
{"snmpv2","SNMPv2",NID_SNMPv2,4,&(lvalues[2855]),0},
{"mail","Mail",NID_Mail,4,&(lvalues[2859]),0},
{"enterprises","Enterprises",NID_Enterprises,1,&(lvalues[2863]),0},
{"dcobject","dcObject",NID_dcObject,3,&(lvalues[2864]),0},
{"DC","domainComponent",NID_domainComponent,10,&(lvalues[2867]),0},
{"domain","Domain",NID_Domain,10,&(lvalues[2877]),0},
{"JOINT-ISO-CCITT","joint-iso-ccitt",NID_joint_iso_ccitt,1,
	&(lvalues[2887]),0},
{"selected-attribute-types","Selected Attribute Types",
	NID_selected_attribute_types,3,&(lvalues[2888]),0},
{"clearance","clearance",NID_clearance,4,&(lvalues[2891]),0},
{"RSA-MD4","md4WithRSAEncryption",NID_md4WithRSAEncryption,9,
	&(lvalues[2895]),0},
{"ac-proxying","ac-proxying",NID_ac_proxying,8,&(lvalues[2904]),0},
{"subjectInfoAccess","Subject Information Access",NID_sinfo_access,8,
	&(lvalues[2912]),0},
{"id-aca-encAttrs","id-aca-encAttrs",NID_id_aca_encAttrs,8,
	&(lvalues[2920]),0},
{"role","role",NID_role,3,&(lvalues[2928]),0},
{"policyConstraints","X509v3 Policy Constraints",
	NID_policy_constraints,3,&(lvalues[2931]),0},
{"targetInformation","X509v3 AC Targeting",NID_target_information,3,
	&(lvalues[2934]),0},
{"noRevAvail","X509v3 No Revocation Available",NID_no_rev_avail,3,
	&(lvalues[2937]),0},
};

static ASN1_OBJECT *sn_objs[NUM_SN]={
&(nid_objs[364]),/* "AD_DVCS" */
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
&(nid_objs[367]),/* "CrlID" */
&(nid_objs[107]),/* "D" */
&(nid_objs[391]),/* "DC" */
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
&(nid_objs[380]),/* "DOD" */
&(nid_objs[116]),/* "DSA" */
&(nid_objs[66]),/* "DSA-SHA" */
&(nid_objs[113]),/* "DSA-SHA1" */
&(nid_objs[70]),/* "DSA-SHA1-old" */
&(nid_objs[67]),/* "DSA-old" */
&(nid_objs[297]),/* "DVCS" */
&(nid_objs[48]),/* "Email" */
&(nid_objs[99]),/* "G" */
&(nid_objs[101]),/* "I" */
&(nid_objs[381]),/* "IANA" */
&(nid_objs[34]),/* "IDEA-CBC" */
&(nid_objs[35]),/* "IDEA-CFB" */
&(nid_objs[36]),/* "IDEA-ECB" */
&(nid_objs[46]),/* "IDEA-OFB" */
&(nid_objs[181]),/* "ISO" */
&(nid_objs[183]),/* "ISO-US" */
&(nid_objs[393]),/* "JOINT-ISO-CCITT" */
&(nid_objs[15]),/* "L" */
&(nid_objs[ 3]),/* "MD2" */
&(nid_objs[257]),/* "MD4" */
&(nid_objs[ 4]),/* "MD5" */
&(nid_objs[114]),/* "MD5-SHA1" */
&(nid_objs[95]),/* "MDC2" */
&(nid_objs[57]),/* "Netscape" */
&(nid_objs[366]),/* "Nonce" */
&(nid_objs[17]),/* "O" */
&(nid_objs[178]),/* "OCSP" */
&(nid_objs[180]),/* "OCSPSigning" */
&(nid_objs[379]),/* "ORG" */
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
&(nid_objs[161]),/* "PBES2" */
&(nid_objs[69]),/* "PBKDF2" */
&(nid_objs[162]),/* "PBMAC1" */
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
&(nid_objs[396]),/* "RSA-MD4" */
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
&(nid_objs[188]),/* "SMIME" */
&(nid_objs[167]),/* "SMIME-CAPS" */
&(nid_objs[105]),/* "SN" */
&(nid_objs[16]),/* "ST" */
&(nid_objs[143]),/* "SXNetID" */
&(nid_objs[106]),/* "T" */
&(nid_objs[ 0]),/* "UNDEF" */
&(nid_objs[11]),/* "X500" */
&(nid_objs[378]),/* "X500algorithms" */
&(nid_objs[12]),/* "X509" */
&(nid_objs[184]),/* "X9-57" */
&(nid_objs[185]),/* "X9cm" */
&(nid_objs[125]),/* "ZLIB" */
&(nid_objs[289]),/* "aaControls" */
&(nid_objs[287]),/* "ac-auditEntity" */
&(nid_objs[397]),/* "ac-proxying" */
&(nid_objs[288]),/* "ac-targeting" */
&(nid_objs[368]),/* "acceptableResponses" */
&(nid_objs[363]),/* "ad_timestamping" */
&(nid_objs[376]),/* "algorithm" */
&(nid_objs[370]),/* "archiveCutoff" */
&(nid_objs[177]),/* "authorityInfoAccess" */
&(nid_objs[90]),/* "authorityKeyIdentifier" */
&(nid_objs[87]),/* "basicConstraints" */
&(nid_objs[365]),/* "basicOCSPResponse" */
&(nid_objs[285]),/* "biometricInfo" */
&(nid_objs[179]),/* "caIssuers" */
&(nid_objs[152]),/* "certBag" */
&(nid_objs[89]),/* "certificatePolicies" */
&(nid_objs[54]),/* "challengePassword" */
&(nid_objs[395]),/* "clearance" */
&(nid_objs[130]),/* "clientAuth" */
&(nid_objs[131]),/* "codeSigning" */
&(nid_objs[50]),/* "contentType" */
&(nid_objs[53]),/* "countersignature" */
&(nid_objs[153]),/* "crlBag" */
&(nid_objs[103]),/* "crlDistributionPoints" */
&(nid_objs[88]),/* "crlNumber" */
&(nid_objs[390]),/* "dcobject" */
&(nid_objs[140]),/* "deltaCRL" */
&(nid_objs[28]),/* "dhKeyAgreement" */
&(nid_objs[382]),/* "directory" */
&(nid_objs[174]),/* "dnQualifier" */
&(nid_objs[392]),/* "domain" */
&(nid_objs[132]),/* "emailProtection" */
&(nid_objs[389]),/* "enterprises" */
&(nid_objs[384]),/* "experimental" */
&(nid_objs[172]),/* "extReq" */
&(nid_objs[56]),/* "extendedCertificateAttributes" */
&(nid_objs[126]),/* "extendedKeyUsage" */
&(nid_objs[372]),/* "extendedStatus" */
&(nid_objs[156]),/* "friendlyName" */
&(nid_objs[163]),/* "hmacWithSHA1" */
&(nid_objs[266]),/* "id-aca" */
&(nid_objs[355]),/* "id-aca-accessIdentity" */
&(nid_objs[354]),/* "id-aca-authenticationInfo" */
&(nid_objs[356]),/* "id-aca-chargingIdentity" */
&(nid_objs[399]),/* "id-aca-encAttrs" */
&(nid_objs[357]),/* "id-aca-group" */
&(nid_objs[358]),/* "id-aca-role" */
&(nid_objs[176]),/* "id-ad" */
&(nid_objs[262]),/* "id-alg" */
&(nid_objs[323]),/* "id-alg-des40" */
&(nid_objs[326]),/* "id-alg-dh-pop" */
&(nid_objs[325]),/* "id-alg-dh-sig-hmac-sha1" */
&(nid_objs[324]),/* "id-alg-noSignature" */
&(nid_objs[268]),/* "id-cct" */
&(nid_objs[361]),/* "id-cct-PKIData" */
&(nid_objs[362]),/* "id-cct-PKIResponse" */
&(nid_objs[360]),/* "id-cct-crs" */
&(nid_objs[81]),/* "id-ce" */
&(nid_objs[263]),/* "id-cmc" */
&(nid_objs[334]),/* "id-cmc-addExtensions" */
&(nid_objs[346]),/* "id-cmc-confirmCertAcceptance" */
&(nid_objs[330]),/* "id-cmc-dataReturn" */
&(nid_objs[336]),/* "id-cmc-decryptedPOP" */
&(nid_objs[335]),/* "id-cmc-encryptedPOP" */
&(nid_objs[339]),/* "id-cmc-getCRL" */
&(nid_objs[338]),/* "id-cmc-getCert" */
&(nid_objs[328]),/* "id-cmc-identification" */
&(nid_objs[329]),/* "id-cmc-identityProof" */
&(nid_objs[337]),/* "id-cmc-lraPOPWitness" */
&(nid_objs[344]),/* "id-cmc-popLinkRandom" */
&(nid_objs[345]),/* "id-cmc-popLinkWitness" */
&(nid_objs[343]),/* "id-cmc-queryPending" */
&(nid_objs[333]),/* "id-cmc-recipientNonce" */
&(nid_objs[341]),/* "id-cmc-regInfo" */
&(nid_objs[342]),/* "id-cmc-responseInfo" */
&(nid_objs[340]),/* "id-cmc-revokeRequest" */
&(nid_objs[332]),/* "id-cmc-senderNonce" */
&(nid_objs[327]),/* "id-cmc-statusInfo" */
&(nid_objs[331]),/* "id-cmc-transactionId" */
&(nid_objs[260]),/* "id-it" */
&(nid_objs[302]),/* "id-it-caKeyUpdateInfo" */
&(nid_objs[298]),/* "id-it-caProtEncCert" */
&(nid_objs[311]),/* "id-it-confirmWaitTime" */
&(nid_objs[303]),/* "id-it-currentCRL" */
&(nid_objs[300]),/* "id-it-encKeyPairTypes" */
&(nid_objs[310]),/* "id-it-implicitConfirm" */
&(nid_objs[308]),/* "id-it-keyPairParamRep" */
&(nid_objs[307]),/* "id-it-keyPairParamReq" */
&(nid_objs[312]),/* "id-it-origPKIMessage" */
&(nid_objs[301]),/* "id-it-preferredSymmAlg" */
&(nid_objs[309]),/* "id-it-revPassphrase" */
&(nid_objs[299]),/* "id-it-signKeyPairTypes" */
&(nid_objs[305]),/* "id-it-subscriptionRequest" */
&(nid_objs[306]),/* "id-it-subscriptionResponse" */
&(nid_objs[304]),/* "id-it-unsupportedOIDs" */
&(nid_objs[128]),/* "id-kp" */
&(nid_objs[280]),/* "id-mod-attribute-cert" */
&(nid_objs[274]),/* "id-mod-cmc" */
&(nid_objs[277]),/* "id-mod-cmp" */
&(nid_objs[284]),/* "id-mod-cmp2000" */
&(nid_objs[273]),/* "id-mod-crmf" */
&(nid_objs[283]),/* "id-mod-dvcs" */
&(nid_objs[275]),/* "id-mod-kea-profile-88" */
&(nid_objs[276]),/* "id-mod-kea-profile-93" */
&(nid_objs[282]),/* "id-mod-ocsp" */
&(nid_objs[278]),/* "id-mod-qualified-cert-88" */
&(nid_objs[279]),/* "id-mod-qualified-cert-93" */
&(nid_objs[281]),/* "id-mod-timestamp-protocol" */
&(nid_objs[264]),/* "id-on" */
&(nid_objs[347]),/* "id-on-personalData" */
&(nid_objs[265]),/* "id-pda" */
&(nid_objs[352]),/* "id-pda-countryOfCitizenship" */
&(nid_objs[353]),/* "id-pda-countryOfResidence" */
&(nid_objs[348]),/* "id-pda-dateOfBirth" */
&(nid_objs[351]),/* "id-pda-gender" */
&(nid_objs[349]),/* "id-pda-placeOfBirth" */
&(nid_objs[175]),/* "id-pe" */
&(nid_objs[261]),/* "id-pkip" */
&(nid_objs[258]),/* "id-pkix-mod" */
&(nid_objs[269]),/* "id-pkix1-explicit-88" */
&(nid_objs[271]),/* "id-pkix1-explicit-93" */
&(nid_objs[270]),/* "id-pkix1-implicit-88" */
&(nid_objs[272]),/* "id-pkix1-implicit-93" */
&(nid_objs[267]),/* "id-qcs" */
&(nid_objs[359]),/* "id-qcs-pkixQCSyntax-v1" */
&(nid_objs[259]),/* "id-qt" */
&(nid_objs[164]),/* "id-qt-cps" */
&(nid_objs[165]),/* "id-qt-unotice" */
&(nid_objs[313]),/* "id-regCtrl" */
&(nid_objs[316]),/* "id-regCtrl-authenticator" */
&(nid_objs[319]),/* "id-regCtrl-oldCertID" */
&(nid_objs[318]),/* "id-regCtrl-pkiArchiveOptions" */
&(nid_objs[317]),/* "id-regCtrl-pkiPublicationInfo" */
&(nid_objs[320]),/* "id-regCtrl-protocolEncrKey" */
&(nid_objs[315]),/* "id-regCtrl-regToken" */
&(nid_objs[314]),/* "id-regInfo" */
&(nid_objs[322]),/* "id-regInfo-certReq" */
&(nid_objs[321]),/* "id-regInfo-utf8Pairs" */
&(nid_objs[191]),/* "id-smime-aa" */
&(nid_objs[215]),/* "id-smime-aa-contentHint" */
&(nid_objs[218]),/* "id-smime-aa-contentIdentifier" */
&(nid_objs[221]),/* "id-smime-aa-contentReference" */
&(nid_objs[240]),/* "id-smime-aa-dvcs-dvc" */
&(nid_objs[217]),/* "id-smime-aa-encapContentType" */
&(nid_objs[222]),/* "id-smime-aa-encrypKeyPref" */
&(nid_objs[220]),/* "id-smime-aa-equivalentLabels" */
&(nid_objs[232]),/* "id-smime-aa-ets-CertificateRefs" */
&(nid_objs[233]),/* "id-smime-aa-ets-RevocationRefs" */
&(nid_objs[238]),/* "id-smime-aa-ets-archiveTimeStamp" */
&(nid_objs[237]),/* "id-smime-aa-ets-certCRLTimestamp" */
&(nid_objs[234]),/* "id-smime-aa-ets-certValues" */
&(nid_objs[227]),/* "id-smime-aa-ets-commitmentType" */
&(nid_objs[231]),/* "id-smime-aa-ets-contentTimestamp" */
&(nid_objs[236]),/* "id-smime-aa-ets-escTimeStamp" */
&(nid_objs[230]),/* "id-smime-aa-ets-otherSigCert" */
&(nid_objs[235]),/* "id-smime-aa-ets-revocationValues" */
&(nid_objs[226]),/* "id-smime-aa-ets-sigPolicyId" */
&(nid_objs[229]),/* "id-smime-aa-ets-signerAttr" */
&(nid_objs[228]),/* "id-smime-aa-ets-signerLocation" */
&(nid_objs[219]),/* "id-smime-aa-macValue" */
&(nid_objs[214]),/* "id-smime-aa-mlExpandHistory" */
&(nid_objs[216]),/* "id-smime-aa-msgSigDigest" */
&(nid_objs[212]),/* "id-smime-aa-receiptRequest" */
&(nid_objs[213]),/* "id-smime-aa-securityLabel" */
&(nid_objs[239]),/* "id-smime-aa-signatureType" */
&(nid_objs[223]),/* "id-smime-aa-signingCertificate" */
&(nid_objs[224]),/* "id-smime-aa-smimeEncryptCerts" */
&(nid_objs[225]),/* "id-smime-aa-timeStampToken" */
&(nid_objs[192]),/* "id-smime-alg" */
&(nid_objs[243]),/* "id-smime-alg-3DESwrap" */
&(nid_objs[246]),/* "id-smime-alg-CMS3DESwrap" */
&(nid_objs[247]),/* "id-smime-alg-CMSRC2wrap" */
&(nid_objs[245]),/* "id-smime-alg-ESDH" */
&(nid_objs[241]),/* "id-smime-alg-ESDHwith3DES" */
&(nid_objs[242]),/* "id-smime-alg-ESDHwithRC2" */
&(nid_objs[244]),/* "id-smime-alg-RC2wrap" */
&(nid_objs[193]),/* "id-smime-cd" */
&(nid_objs[248]),/* "id-smime-cd-ldap" */
&(nid_objs[190]),/* "id-smime-ct" */
&(nid_objs[210]),/* "id-smime-ct-DVCSRequestData" */
&(nid_objs[211]),/* "id-smime-ct-DVCSResponseData" */
&(nid_objs[208]),/* "id-smime-ct-TDTInfo" */
&(nid_objs[207]),/* "id-smime-ct-TSTInfo" */
&(nid_objs[205]),/* "id-smime-ct-authData" */
&(nid_objs[209]),/* "id-smime-ct-contentInfo" */
&(nid_objs[206]),/* "id-smime-ct-publishCert" */
&(nid_objs[204]),/* "id-smime-ct-receipt" */
&(nid_objs[195]),/* "id-smime-cti" */
&(nid_objs[255]),/* "id-smime-cti-ets-proofOfApproval" */
&(nid_objs[256]),/* "id-smime-cti-ets-proofOfCreation" */
&(nid_objs[253]),/* "id-smime-cti-ets-proofOfDelivery" */
&(nid_objs[251]),/* "id-smime-cti-ets-proofOfOrigin" */
&(nid_objs[252]),/* "id-smime-cti-ets-proofOfReceipt" */
&(nid_objs[254]),/* "id-smime-cti-ets-proofOfSender" */
&(nid_objs[189]),/* "id-smime-mod" */
&(nid_objs[196]),/* "id-smime-mod-cms" */
&(nid_objs[197]),/* "id-smime-mod-ess" */
&(nid_objs[202]),/* "id-smime-mod-ets-eSigPolicy-88" */
&(nid_objs[203]),/* "id-smime-mod-ets-eSigPolicy-97" */
&(nid_objs[200]),/* "id-smime-mod-ets-eSignature-88" */
&(nid_objs[201]),/* "id-smime-mod-ets-eSignature-97" */
&(nid_objs[199]),/* "id-smime-mod-msg-v3" */
&(nid_objs[198]),/* "id-smime-mod-oid" */
&(nid_objs[194]),/* "id-smime-spq" */
&(nid_objs[250]),/* "id-smime-spq-ets-sqt-unotice" */
&(nid_objs[249]),/* "id-smime-spq-ets-sqt-uri" */
&(nid_objs[142]),/* "invalidityDate" */
&(nid_objs[294]),/* "ipsecEndSystem" */
&(nid_objs[295]),/* "ipsecTunnel" */
&(nid_objs[296]),/* "ipsecUser" */
&(nid_objs[86]),/* "issuerAltName" */
&(nid_objs[150]),/* "keyBag" */
&(nid_objs[83]),/* "keyUsage" */
&(nid_objs[157]),/* "localKeyID" */
&(nid_objs[388]),/* "mail" */
&(nid_objs[182]),/* "member-body" */
&(nid_objs[51]),/* "messageDigest" */
&(nid_objs[383]),/* "mgmt" */
&(nid_objs[136]),/* "msCTLSign" */
&(nid_objs[135]),/* "msCodeCom" */
&(nid_objs[134]),/* "msCodeInd" */
&(nid_objs[138]),/* "msEFS" */
&(nid_objs[171]),/* "msExtReq" */
&(nid_objs[137]),/* "msSGC" */
&(nid_objs[173]),/* "name" */
&(nid_objs[369]),/* "noCheck" */
&(nid_objs[403]),/* "noRevAvail" */
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
&(nid_objs[374]),/* "path" */
&(nid_objs[112]),/* "pbeWithMD5AndCast5CBC" */
&(nid_objs[ 2]),/* "pkcs" */
&(nid_objs[186]),/* "pkcs1" */
&(nid_objs[27]),/* "pkcs3" */
&(nid_objs[187]),/* "pkcs5" */
&(nid_objs[20]),/* "pkcs7" */
&(nid_objs[21]),/* "pkcs7-data" */
&(nid_objs[25]),/* "pkcs7-digestData" */
&(nid_objs[26]),/* "pkcs7-encryptedData" */
&(nid_objs[23]),/* "pkcs7-envelopedData" */
&(nid_objs[24]),/* "pkcs7-signedAndEnvelopedData" */
&(nid_objs[22]),/* "pkcs7-signedData" */
&(nid_objs[151]),/* "pkcs8ShroudedKeyBag" */
&(nid_objs[47]),/* "pkcs9" */
&(nid_objs[401]),/* "policyConstraints" */
&(nid_objs[385]),/* "private" */
&(nid_objs[84]),/* "privateKeyUsagePeriod" */
&(nid_objs[286]),/* "qcStatements" */
&(nid_objs[400]),/* "role" */
&(nid_objs[ 6]),/* "rsaEncryption" */
&(nid_objs[377]),/* "rsaSignature" */
&(nid_objs[ 1]),/* "rsadsi" */
&(nid_objs[155]),/* "safeContentsBag" */
&(nid_objs[291]),/* "sbqp-autonomousSysNum" */
&(nid_objs[290]),/* "sbqp-ipAddrBlock" */
&(nid_objs[292]),/* "sbqp-routerIdentifier" */
&(nid_objs[159]),/* "sdsiCertificate" */
&(nid_objs[154]),/* "secretBag" */
&(nid_objs[386]),/* "security" */
&(nid_objs[394]),/* "selected-attribute-types" */
&(nid_objs[129]),/* "serverAuth" */
&(nid_objs[371]),/* "serviceLocator" */
&(nid_objs[52]),/* "signingTime" */
&(nid_objs[387]),/* "snmpv2" */
&(nid_objs[85]),/* "subjectAltName" */
&(nid_objs[398]),/* "subjectInfoAccess" */
&(nid_objs[82]),/* "subjectKeyIdentifier" */
&(nid_objs[402]),/* "targetInformation" */
&(nid_objs[293]),/* "textNotice" */
&(nid_objs[133]),/* "timeStamping" */
&(nid_objs[375]),/* "trustRoot" */
&(nid_objs[102]),/* "uniqueIdentifier" */
&(nid_objs[55]),/* "unstructuredAddress" */
&(nid_objs[49]),/* "unstructuredName" */
&(nid_objs[373]),/* "valid" */
&(nid_objs[158]),/* "x509Certificate" */
&(nid_objs[160]),/* "x509Crl" */
};

static ASN1_OBJECT *ln_objs[NUM_LN]={
&(nid_objs[363]),/* "AD Time Stamping" */
&(nid_objs[368]),/* "Acceptable OCSP Responses" */
&(nid_objs[177]),/* "Authority Information Access" */
&(nid_objs[365]),/* "Basic OCSP Response" */
&(nid_objs[285]),/* "Biometric Info" */
&(nid_objs[179]),/* "CA Issuers" */
&(nid_objs[131]),/* "Code Signing" */
&(nid_objs[382]),/* "Directory" */
&(nid_objs[392]),/* "Domain" */
&(nid_objs[132]),/* "E-mail Protection" */
&(nid_objs[389]),/* "Enterprises" */
&(nid_objs[384]),/* "Experimental" */
&(nid_objs[372]),/* "Extended OCSP Status" */
&(nid_objs[172]),/* "Extension Request" */
&(nid_objs[294]),/* "IPSec End System" */
&(nid_objs[295]),/* "IPSec Tunnel" */
&(nid_objs[296]),/* "IPSec User" */
&(nid_objs[182]),/* "ISO Member Body" */
&(nid_objs[183]),/* "ISO US Member Body" */
&(nid_objs[142]),/* "Invalidity Date" */
&(nid_objs[388]),/* "Mail" */
&(nid_objs[383]),/* "Management" */
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
&(nid_objs[178]),/* "OCSP" */
&(nid_objs[370]),/* "OCSP Archive Cutoff" */
&(nid_objs[367]),/* "OCSP CRL ID" */
&(nid_objs[366]),/* "OCSP Nonce" */
&(nid_objs[371]),/* "OCSP Service Locator" */
&(nid_objs[180]),/* "OCSP Signing" */
&(nid_objs[161]),/* "PBES2" */
&(nid_objs[69]),/* "PBKDF2" */
&(nid_objs[162]),/* "PBMAC1" */
&(nid_objs[127]),/* "PKIX" */
&(nid_objs[164]),/* "Policy Qualifier CPS" */
&(nid_objs[165]),/* "Policy Qualifier User Notice" */
&(nid_objs[385]),/* "Private" */
&(nid_objs[ 1]),/* "RSA Data Security, Inc." */
&(nid_objs[ 2]),/* "RSA Data Security, Inc. PKCS" */
&(nid_objs[188]),/* "S/MIME" */
&(nid_objs[167]),/* "S/MIME Capabilities" */
&(nid_objs[387]),/* "SNMPv2" */
&(nid_objs[386]),/* "Security" */
&(nid_objs[394]),/* "Selected Attribute Types" */
&(nid_objs[143]),/* "Strong Extranet ID" */
&(nid_objs[398]),/* "Subject Information Access" */
&(nid_objs[130]),/* "TLS Web Client Authentication" */
&(nid_objs[129]),/* "TLS Web Server Authentication" */
&(nid_objs[133]),/* "Time Stamping" */
&(nid_objs[375]),/* "Trust Root" */
&(nid_objs[12]),/* "X509" */
&(nid_objs[402]),/* "X509v3 AC Targeting" */
&(nid_objs[90]),/* "X509v3 Authority Key Identifier" */
&(nid_objs[87]),/* "X509v3 Basic Constraints" */
&(nid_objs[103]),/* "X509v3 CRL Distribution Points" */
&(nid_objs[88]),/* "X509v3 CRL Number" */
&(nid_objs[141]),/* "X509v3 CRL Reason Code" */
&(nid_objs[89]),/* "X509v3 Certificate Policies" */
&(nid_objs[140]),/* "X509v3 Delta CRL Indicator" */
&(nid_objs[126]),/* "X509v3 Extended Key Usage" */
&(nid_objs[86]),/* "X509v3 Issuer Alternative Name" */
&(nid_objs[83]),/* "X509v3 Key Usage" */
&(nid_objs[403]),/* "X509v3 No Revocation Available" */
&(nid_objs[401]),/* "X509v3 Policy Constraints" */
&(nid_objs[84]),/* "X509v3 Private Key Usage Period" */
&(nid_objs[85]),/* "X509v3 Subject Alternative Name" */
&(nid_objs[82]),/* "X509v3 Subject Key Identifier" */
&(nid_objs[184]),/* "X9.57" */
&(nid_objs[185]),/* "X9.57 CM ?" */
&(nid_objs[289]),/* "aaControls" */
&(nid_objs[287]),/* "ac-auditEntity" */
&(nid_objs[397]),/* "ac-proxying" */
&(nid_objs[288]),/* "ac-targeting" */
&(nid_objs[364]),/* "ad dvcs" */
&(nid_objs[376]),/* "algorithm" */
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
&(nid_objs[395]),/* "clearance" */
&(nid_objs[13]),/* "commonName" */
&(nid_objs[50]),/* "contentType" */
&(nid_objs[53]),/* "countersignature" */
&(nid_objs[14]),/* "countryName" */
&(nid_objs[153]),/* "crlBag" */
&(nid_objs[390]),/* "dcObject" */
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
&(nid_objs[11]),/* "directory services (X.500)" */
&(nid_objs[378]),/* "directory services - algorithms" */
&(nid_objs[174]),/* "dnQualifier" */
&(nid_objs[380]),/* "dod" */
&(nid_objs[391]),/* "domainComponent" */
&(nid_objs[116]),/* "dsaEncryption" */
&(nid_objs[67]),/* "dsaEncryption-old" */
&(nid_objs[66]),/* "dsaWithSHA" */
&(nid_objs[113]),/* "dsaWithSHA1" */
&(nid_objs[70]),/* "dsaWithSHA1-old" */
&(nid_objs[297]),/* "dvcs" */
&(nid_objs[48]),/* "emailAddress" */
&(nid_objs[56]),/* "extendedCertificateAttributes" */
&(nid_objs[156]),/* "friendlyName" */
&(nid_objs[99]),/* "givenName" */
&(nid_objs[163]),/* "hmacWithSHA1" */
&(nid_objs[381]),/* "iana" */
&(nid_objs[266]),/* "id-aca" */
&(nid_objs[355]),/* "id-aca-accessIdentity" */
&(nid_objs[354]),/* "id-aca-authenticationInfo" */
&(nid_objs[356]),/* "id-aca-chargingIdentity" */
&(nid_objs[399]),/* "id-aca-encAttrs" */
&(nid_objs[357]),/* "id-aca-group" */
&(nid_objs[358]),/* "id-aca-role" */
&(nid_objs[176]),/* "id-ad" */
&(nid_objs[262]),/* "id-alg" */
&(nid_objs[323]),/* "id-alg-des40" */
&(nid_objs[326]),/* "id-alg-dh-pop" */
&(nid_objs[325]),/* "id-alg-dh-sig-hmac-sha1" */
&(nid_objs[324]),/* "id-alg-noSignature" */
&(nid_objs[268]),/* "id-cct" */
&(nid_objs[361]),/* "id-cct-PKIData" */
&(nid_objs[362]),/* "id-cct-PKIResponse" */
&(nid_objs[360]),/* "id-cct-crs" */
&(nid_objs[81]),/* "id-ce" */
&(nid_objs[263]),/* "id-cmc" */
&(nid_objs[334]),/* "id-cmc-addExtensions" */
&(nid_objs[346]),/* "id-cmc-confirmCertAcceptance" */
&(nid_objs[330]),/* "id-cmc-dataReturn" */
&(nid_objs[336]),/* "id-cmc-decryptedPOP" */
&(nid_objs[335]),/* "id-cmc-encryptedPOP" */
&(nid_objs[339]),/* "id-cmc-getCRL" */
&(nid_objs[338]),/* "id-cmc-getCert" */
&(nid_objs[328]),/* "id-cmc-identification" */
&(nid_objs[329]),/* "id-cmc-identityProof" */
&(nid_objs[337]),/* "id-cmc-lraPOPWitness" */
&(nid_objs[344]),/* "id-cmc-popLinkRandom" */
&(nid_objs[345]),/* "id-cmc-popLinkWitness" */
&(nid_objs[343]),/* "id-cmc-queryPending" */
&(nid_objs[333]),/* "id-cmc-recipientNonce" */
&(nid_objs[341]),/* "id-cmc-regInfo" */
&(nid_objs[342]),/* "id-cmc-responseInfo" */
&(nid_objs[340]),/* "id-cmc-revokeRequest" */
&(nid_objs[332]),/* "id-cmc-senderNonce" */
&(nid_objs[327]),/* "id-cmc-statusInfo" */
&(nid_objs[331]),/* "id-cmc-transactionId" */
&(nid_objs[260]),/* "id-it" */
&(nid_objs[302]),/* "id-it-caKeyUpdateInfo" */
&(nid_objs[298]),/* "id-it-caProtEncCert" */
&(nid_objs[311]),/* "id-it-confirmWaitTime" */
&(nid_objs[303]),/* "id-it-currentCRL" */
&(nid_objs[300]),/* "id-it-encKeyPairTypes" */
&(nid_objs[310]),/* "id-it-implicitConfirm" */
&(nid_objs[308]),/* "id-it-keyPairParamRep" */
&(nid_objs[307]),/* "id-it-keyPairParamReq" */
&(nid_objs[312]),/* "id-it-origPKIMessage" */
&(nid_objs[301]),/* "id-it-preferredSymmAlg" */
&(nid_objs[309]),/* "id-it-revPassphrase" */
&(nid_objs[299]),/* "id-it-signKeyPairTypes" */
&(nid_objs[305]),/* "id-it-subscriptionRequest" */
&(nid_objs[306]),/* "id-it-subscriptionResponse" */
&(nid_objs[304]),/* "id-it-unsupportedOIDs" */
&(nid_objs[128]),/* "id-kp" */
&(nid_objs[280]),/* "id-mod-attribute-cert" */
&(nid_objs[274]),/* "id-mod-cmc" */
&(nid_objs[277]),/* "id-mod-cmp" */
&(nid_objs[284]),/* "id-mod-cmp2000" */
&(nid_objs[273]),/* "id-mod-crmf" */
&(nid_objs[283]),/* "id-mod-dvcs" */
&(nid_objs[275]),/* "id-mod-kea-profile-88" */
&(nid_objs[276]),/* "id-mod-kea-profile-93" */
&(nid_objs[282]),/* "id-mod-ocsp" */
&(nid_objs[278]),/* "id-mod-qualified-cert-88" */
&(nid_objs[279]),/* "id-mod-qualified-cert-93" */
&(nid_objs[281]),/* "id-mod-timestamp-protocol" */
&(nid_objs[264]),/* "id-on" */
&(nid_objs[347]),/* "id-on-personalData" */
&(nid_objs[265]),/* "id-pda" */
&(nid_objs[352]),/* "id-pda-countryOfCitizenship" */
&(nid_objs[353]),/* "id-pda-countryOfResidence" */
&(nid_objs[348]),/* "id-pda-dateOfBirth" */
&(nid_objs[351]),/* "id-pda-gender" */
&(nid_objs[349]),/* "id-pda-placeOfBirth" */
&(nid_objs[175]),/* "id-pe" */
&(nid_objs[261]),/* "id-pkip" */
&(nid_objs[258]),/* "id-pkix-mod" */
&(nid_objs[269]),/* "id-pkix1-explicit-88" */
&(nid_objs[271]),/* "id-pkix1-explicit-93" */
&(nid_objs[270]),/* "id-pkix1-implicit-88" */
&(nid_objs[272]),/* "id-pkix1-implicit-93" */
&(nid_objs[267]),/* "id-qcs" */
&(nid_objs[359]),/* "id-qcs-pkixQCSyntax-v1" */
&(nid_objs[259]),/* "id-qt" */
&(nid_objs[313]),/* "id-regCtrl" */
&(nid_objs[316]),/* "id-regCtrl-authenticator" */
&(nid_objs[319]),/* "id-regCtrl-oldCertID" */
&(nid_objs[318]),/* "id-regCtrl-pkiArchiveOptions" */
&(nid_objs[317]),/* "id-regCtrl-pkiPublicationInfo" */
&(nid_objs[320]),/* "id-regCtrl-protocolEncrKey" */
&(nid_objs[315]),/* "id-regCtrl-regToken" */
&(nid_objs[314]),/* "id-regInfo" */
&(nid_objs[322]),/* "id-regInfo-certReq" */
&(nid_objs[321]),/* "id-regInfo-utf8Pairs" */
&(nid_objs[191]),/* "id-smime-aa" */
&(nid_objs[215]),/* "id-smime-aa-contentHint" */
&(nid_objs[218]),/* "id-smime-aa-contentIdentifier" */
&(nid_objs[221]),/* "id-smime-aa-contentReference" */
&(nid_objs[240]),/* "id-smime-aa-dvcs-dvc" */
&(nid_objs[217]),/* "id-smime-aa-encapContentType" */
&(nid_objs[222]),/* "id-smime-aa-encrypKeyPref" */
&(nid_objs[220]),/* "id-smime-aa-equivalentLabels" */
&(nid_objs[232]),/* "id-smime-aa-ets-CertificateRefs" */
&(nid_objs[233]),/* "id-smime-aa-ets-RevocationRefs" */
&(nid_objs[238]),/* "id-smime-aa-ets-archiveTimeStamp" */
&(nid_objs[237]),/* "id-smime-aa-ets-certCRLTimestamp" */
&(nid_objs[234]),/* "id-smime-aa-ets-certValues" */
&(nid_objs[227]),/* "id-smime-aa-ets-commitmentType" */
&(nid_objs[231]),/* "id-smime-aa-ets-contentTimestamp" */
&(nid_objs[236]),/* "id-smime-aa-ets-escTimeStamp" */
&(nid_objs[230]),/* "id-smime-aa-ets-otherSigCert" */
&(nid_objs[235]),/* "id-smime-aa-ets-revocationValues" */
&(nid_objs[226]),/* "id-smime-aa-ets-sigPolicyId" */
&(nid_objs[229]),/* "id-smime-aa-ets-signerAttr" */
&(nid_objs[228]),/* "id-smime-aa-ets-signerLocation" */
&(nid_objs[219]),/* "id-smime-aa-macValue" */
&(nid_objs[214]),/* "id-smime-aa-mlExpandHistory" */
&(nid_objs[216]),/* "id-smime-aa-msgSigDigest" */
&(nid_objs[212]),/* "id-smime-aa-receiptRequest" */
&(nid_objs[213]),/* "id-smime-aa-securityLabel" */
&(nid_objs[239]),/* "id-smime-aa-signatureType" */
&(nid_objs[223]),/* "id-smime-aa-signingCertificate" */
&(nid_objs[224]),/* "id-smime-aa-smimeEncryptCerts" */
&(nid_objs[225]),/* "id-smime-aa-timeStampToken" */
&(nid_objs[192]),/* "id-smime-alg" */
&(nid_objs[243]),/* "id-smime-alg-3DESwrap" */
&(nid_objs[246]),/* "id-smime-alg-CMS3DESwrap" */
&(nid_objs[247]),/* "id-smime-alg-CMSRC2wrap" */
&(nid_objs[245]),/* "id-smime-alg-ESDH" */
&(nid_objs[241]),/* "id-smime-alg-ESDHwith3DES" */
&(nid_objs[242]),/* "id-smime-alg-ESDHwithRC2" */
&(nid_objs[244]),/* "id-smime-alg-RC2wrap" */
&(nid_objs[193]),/* "id-smime-cd" */
&(nid_objs[248]),/* "id-smime-cd-ldap" */
&(nid_objs[190]),/* "id-smime-ct" */
&(nid_objs[210]),/* "id-smime-ct-DVCSRequestData" */
&(nid_objs[211]),/* "id-smime-ct-DVCSResponseData" */
&(nid_objs[208]),/* "id-smime-ct-TDTInfo" */
&(nid_objs[207]),/* "id-smime-ct-TSTInfo" */
&(nid_objs[205]),/* "id-smime-ct-authData" */
&(nid_objs[209]),/* "id-smime-ct-contentInfo" */
&(nid_objs[206]),/* "id-smime-ct-publishCert" */
&(nid_objs[204]),/* "id-smime-ct-receipt" */
&(nid_objs[195]),/* "id-smime-cti" */
&(nid_objs[255]),/* "id-smime-cti-ets-proofOfApproval" */
&(nid_objs[256]),/* "id-smime-cti-ets-proofOfCreation" */
&(nid_objs[253]),/* "id-smime-cti-ets-proofOfDelivery" */
&(nid_objs[251]),/* "id-smime-cti-ets-proofOfOrigin" */
&(nid_objs[252]),/* "id-smime-cti-ets-proofOfReceipt" */
&(nid_objs[254]),/* "id-smime-cti-ets-proofOfSender" */
&(nid_objs[189]),/* "id-smime-mod" */
&(nid_objs[196]),/* "id-smime-mod-cms" */
&(nid_objs[197]),/* "id-smime-mod-ess" */
&(nid_objs[202]),/* "id-smime-mod-ets-eSigPolicy-88" */
&(nid_objs[203]),/* "id-smime-mod-ets-eSigPolicy-97" */
&(nid_objs[200]),/* "id-smime-mod-ets-eSignature-88" */
&(nid_objs[201]),/* "id-smime-mod-ets-eSignature-97" */
&(nid_objs[199]),/* "id-smime-mod-msg-v3" */
&(nid_objs[198]),/* "id-smime-mod-oid" */
&(nid_objs[194]),/* "id-smime-spq" */
&(nid_objs[250]),/* "id-smime-spq-ets-sqt-unotice" */
&(nid_objs[249]),/* "id-smime-spq-ets-sqt-uri" */
&(nid_objs[34]),/* "idea-cbc" */
&(nid_objs[35]),/* "idea-cfb" */
&(nid_objs[36]),/* "idea-ecb" */
&(nid_objs[46]),/* "idea-ofb" */
&(nid_objs[101]),/* "initials" */
&(nid_objs[181]),/* "iso" */
&(nid_objs[393]),/* "joint-iso-ccitt" */
&(nid_objs[150]),/* "keyBag" */
&(nid_objs[157]),/* "localKeyID" */
&(nid_objs[15]),/* "localityName" */
&(nid_objs[ 3]),/* "md2" */
&(nid_objs[ 7]),/* "md2WithRSAEncryption" */
&(nid_objs[257]),/* "md4" */
&(nid_objs[396]),/* "md4WithRSAEncryption" */
&(nid_objs[ 4]),/* "md5" */
&(nid_objs[114]),/* "md5-sha1" */
&(nid_objs[104]),/* "md5WithRSA" */
&(nid_objs[ 8]),/* "md5WithRSAEncryption" */
&(nid_objs[95]),/* "mdc2" */
&(nid_objs[96]),/* "mdc2WithRSA" */
&(nid_objs[51]),/* "messageDigest" */
&(nid_objs[173]),/* "name" */
&(nid_objs[369]),/* "noCheck" */
&(nid_objs[379]),/* "org" */
&(nid_objs[17]),/* "organizationName" */
&(nid_objs[18]),/* "organizationalUnitName" */
&(nid_objs[374]),/* "path" */
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
&(nid_objs[186]),/* "pkcs1" */
&(nid_objs[27]),/* "pkcs3" */
&(nid_objs[187]),/* "pkcs5" */
&(nid_objs[20]),/* "pkcs7" */
&(nid_objs[21]),/* "pkcs7-data" */
&(nid_objs[25]),/* "pkcs7-digestData" */
&(nid_objs[26]),/* "pkcs7-encryptedData" */
&(nid_objs[23]),/* "pkcs7-envelopedData" */
&(nid_objs[24]),/* "pkcs7-signedAndEnvelopedData" */
&(nid_objs[22]),/* "pkcs7-signedData" */
&(nid_objs[151]),/* "pkcs8ShroudedKeyBag" */
&(nid_objs[47]),/* "pkcs9" */
&(nid_objs[286]),/* "qcStatements" */
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
&(nid_objs[400]),/* "role" */
&(nid_objs[19]),/* "rsa" */
&(nid_objs[ 6]),/* "rsaEncryption" */
&(nid_objs[377]),/* "rsaSignature" */
&(nid_objs[124]),/* "run length compression" */
&(nid_objs[155]),/* "safeContentsBag" */
&(nid_objs[291]),/* "sbqp-autonomousSysNum" */
&(nid_objs[290]),/* "sbqp-ipAddrBlock" */
&(nid_objs[292]),/* "sbqp-routerIdentifier" */
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
&(nid_objs[293]),/* "textNotice" */
&(nid_objs[106]),/* "title" */
&(nid_objs[ 0]),/* "undefined" */
&(nid_objs[102]),/* "uniqueIdentifier" */
&(nid_objs[55]),/* "unstructuredAddress" */
&(nid_objs[49]),/* "unstructuredName" */
&(nid_objs[373]),/* "valid" */
&(nid_objs[158]),/* "x509Certificate" */
&(nid_objs[160]),/* "x509Crl" */
&(nid_objs[125]),/* "zlib compression" */
};

static ASN1_OBJECT *obj_objs[NUM_OBJ]={
&(nid_objs[ 0]),/* OBJ_undef                        0 */
&(nid_objs[389]),/* OBJ_Enterprises                   1 */
&(nid_objs[181]),/* OBJ_iso                          1 */
&(nid_objs[182]),/* OBJ_member_body                  1 2 */
&(nid_objs[379]),/* OBJ_org                          1 3 */
&(nid_objs[393]),/* OBJ_joint_iso_ccitt              2 */
&(nid_objs[11]),/* OBJ_X500                         2 5 */
&(nid_objs[380]),/* OBJ_dod                          1 3 6 */
&(nid_objs[12]),/* OBJ_X509                         2 5 4 */
&(nid_objs[378]),/* OBJ_X500algorithms               2 5 8 */
&(nid_objs[81]),/* OBJ_id_ce                        2 5 29 */
&(nid_objs[183]),/* OBJ_ISO_US                       1 2 840 */
&(nid_objs[381]),/* OBJ_iana                         1 3 6 1 */
&(nid_objs[394]),/* OBJ_selected_attribute_types     2 5 1 5 */
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
&(nid_objs[400]),/* OBJ_role                         2 5 4 72 */
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
&(nid_objs[401]),/* OBJ_policy_constraints           2 5 29 36 */
&(nid_objs[126]),/* OBJ_ext_key_usage                2 5 29 37 */
&(nid_objs[402]),/* OBJ_target_information           2 5 29 55 */
&(nid_objs[403]),/* OBJ_no_rev_avail                 2 5 29 56 */
&(nid_objs[390]),/* OBJ_dcObject                      1466 344 */
&(nid_objs[382]),/* OBJ_Directory                    1 3 6 1 1 */
&(nid_objs[383]),/* OBJ_Management                   1 3 6 1 2 */
&(nid_objs[384]),/* OBJ_Experimental                 1 3 6 1 3 */
&(nid_objs[385]),/* OBJ_Private                      1 3 6 1 4 */
&(nid_objs[386]),/* OBJ_Security                     1 3 6 1 5 */
&(nid_objs[387]),/* OBJ_SNMPv2                       1 3 6 1 6 */
&(nid_objs[388]),/* OBJ_Mail                         1 3 6 1 7 */
&(nid_objs[376]),/* OBJ_algorithm                    1 3 14 3 2 */
&(nid_objs[395]),/* OBJ_clearance                    2 5 1 5 55 */
&(nid_objs[19]),/* OBJ_rsa                          2 5 8 1 1 */
&(nid_objs[96]),/* OBJ_mdc2WithRSA                  2 5 8 3 100 */
&(nid_objs[95]),/* OBJ_mdc2                         2 5 8 3 101 */
&(nid_objs[184]),/* OBJ_X9_57                        1 2 840 10040 */
&(nid_objs[104]),/* OBJ_md5WithRSA                   1 3 14 3 2 3 */
&(nid_objs[29]),/* OBJ_des_ecb                      1 3 14 3 2 6 */
&(nid_objs[31]),/* OBJ_des_cbc                      1 3 14 3 2 7 */
&(nid_objs[45]),/* OBJ_des_ofb64                    1 3 14 3 2 8 */
&(nid_objs[30]),/* OBJ_des_cfb64                    1 3 14 3 2 9 */
&(nid_objs[377]),/* OBJ_rsaSignature                 1 3 14 3 2 11 */
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
&(nid_objs[185]),/* OBJ_X9cm                         1 2 840 10040 4 */
&(nid_objs[127]),/* OBJ_id_pkix                      1 3 6 1 5 5 7 */
&(nid_objs[119]),/* OBJ_ripemd160WithRSA             1 3 36 3 3 1 2 */
&(nid_objs[ 2]),/* OBJ_pkcs                         1 2 840 113549 1 */
&(nid_objs[116]),/* OBJ_dsa                          1 2 840 10040 4 1 */
&(nid_objs[113]),/* OBJ_dsaWithSHA1                  1 2 840 10040 4 3 */
&(nid_objs[258]),/* OBJ_id_pkix_mod                  1 3 6 1 5 5 7 0 */
&(nid_objs[175]),/* OBJ_id_pe                        1 3 6 1 5 5 7 1 */
&(nid_objs[259]),/* OBJ_id_qt                        1 3 6 1 5 5 7 2 */
&(nid_objs[128]),/* OBJ_id_kp                        1 3 6 1 5 5 7 3 */
&(nid_objs[260]),/* OBJ_id_it                        1 3 6 1 5 5 7 4 */
&(nid_objs[261]),/* OBJ_id_pkip                      1 3 6 1 5 5 7 5 */
&(nid_objs[262]),/* OBJ_id_alg                       1 3 6 1 5 5 7 6 */
&(nid_objs[263]),/* OBJ_id_cmc                       1 3 6 1 5 5 7 7 */
&(nid_objs[264]),/* OBJ_id_on                        1 3 6 1 5 5 7 8 */
&(nid_objs[265]),/* OBJ_id_pda                       1 3 6 1 5 5 7 9 */
&(nid_objs[266]),/* OBJ_id_aca                       1 3 6 1 5 5 7 10 */
&(nid_objs[267]),/* OBJ_id_qcs                       1 3 6 1 5 5 7 11 */
&(nid_objs[268]),/* OBJ_id_cct                       1 3 6 1 5 5 7 12 */
&(nid_objs[176]),/* OBJ_id_ad                        1 3 6 1 5 5 7 48 */
&(nid_objs[57]),/* OBJ_netscape                     2 16 840 1 113730 */
&(nid_objs[186]),/* OBJ_pkcs1                        1 2 840 113549 1 1 */
&(nid_objs[27]),/* OBJ_pkcs3                        1 2 840 113549 1 3 */
&(nid_objs[187]),/* OBJ_pkcs5                        1 2 840 113549 1 5 */
&(nid_objs[20]),/* OBJ_pkcs7                        1 2 840 113549 1 7 */
&(nid_objs[47]),/* OBJ_pkcs9                        1 2 840 113549 1 9 */
&(nid_objs[ 3]),/* OBJ_md2                          1 2 840 113549 2 2 */
&(nid_objs[257]),/* OBJ_md4                          1 2 840 113549 2 4 */
&(nid_objs[ 4]),/* OBJ_md5                          1 2 840 113549 2 5 */
&(nid_objs[163]),/* OBJ_hmacWithSHA1                 1 2 840 113549 2 7 */
&(nid_objs[37]),/* OBJ_rc2_cbc                      1 2 840 113549 3 2 */
&(nid_objs[ 5]),/* OBJ_rc4                          1 2 840 113549 3 4 */
&(nid_objs[44]),/* OBJ_des_ede3_cbc                 1 2 840 113549 3 7 */
&(nid_objs[120]),/* OBJ_rc5_cbc                      1 2 840 113549 3 8 */
&(nid_objs[269]),/* OBJ_id_pkix1_explicit_88         1 3 6 1 5 5 7 0 1 */
&(nid_objs[270]),/* OBJ_id_pkix1_implicit_88         1 3 6 1 5 5 7 0 2 */
&(nid_objs[271]),/* OBJ_id_pkix1_explicit_93         1 3 6 1 5 5 7 0 3 */
&(nid_objs[272]),/* OBJ_id_pkix1_implicit_93         1 3 6 1 5 5 7 0 4 */
&(nid_objs[273]),/* OBJ_id_mod_crmf                  1 3 6 1 5 5 7 0 5 */
&(nid_objs[274]),/* OBJ_id_mod_cmc                   1 3 6 1 5 5 7 0 6 */
&(nid_objs[275]),/* OBJ_id_mod_kea_profile_88        1 3 6 1 5 5 7 0 7 */
&(nid_objs[276]),/* OBJ_id_mod_kea_profile_93        1 3 6 1 5 5 7 0 8 */
&(nid_objs[277]),/* OBJ_id_mod_cmp                   1 3 6 1 5 5 7 0 9 */
&(nid_objs[278]),/* OBJ_id_mod_qualified_cert_88     1 3 6 1 5 5 7 0 10 */
&(nid_objs[279]),/* OBJ_id_mod_qualified_cert_93     1 3 6 1 5 5 7 0 11 */
&(nid_objs[280]),/* OBJ_id_mod_attribute_cert        1 3 6 1 5 5 7 0 12 */
&(nid_objs[281]),/* OBJ_id_mod_timestamp_protocol    1 3 6 1 5 5 7 0 13 */
&(nid_objs[282]),/* OBJ_id_mod_ocsp                  1 3 6 1 5 5 7 0 14 */
&(nid_objs[283]),/* OBJ_id_mod_dvcs                  1 3 6 1 5 5 7 0 15 */
&(nid_objs[284]),/* OBJ_id_mod_cmp2000               1 3 6 1 5 5 7 0 16 */
&(nid_objs[177]),/* OBJ_info_access                  1 3 6 1 5 5 7 1 1 */
&(nid_objs[285]),/* OBJ_biometricInfo                1 3 6 1 5 5 7 1 2 */
&(nid_objs[286]),/* OBJ_qcStatements                 1 3 6 1 5 5 7 1 3 */
&(nid_objs[287]),/* OBJ_ac_auditEntity               1 3 6 1 5 5 7 1 4 */
&(nid_objs[288]),/* OBJ_ac_targeting                 1 3 6 1 5 5 7 1 5 */
&(nid_objs[289]),/* OBJ_aaControls                   1 3 6 1 5 5 7 1 6 */
&(nid_objs[290]),/* OBJ_sbqp_ipAddrBlock             1 3 6 1 5 5 7 1 7 */
&(nid_objs[291]),/* OBJ_sbqp_autonomousSysNum        1 3 6 1 5 5 7 1 8 */
&(nid_objs[292]),/* OBJ_sbqp_routerIdentifier        1 3 6 1 5 5 7 1 9 */
&(nid_objs[397]),/* OBJ_ac_proxying                  1 3 6 1 5 5 7 1 10 */
&(nid_objs[398]),/* OBJ_sinfo_access                 1 3 6 1 5 5 7 1 11 */
&(nid_objs[164]),/* OBJ_id_qt_cps                    1 3 6 1 5 5 7 2 1 */
&(nid_objs[165]),/* OBJ_id_qt_unotice                1 3 6 1 5 5 7 2 2 */
&(nid_objs[293]),/* OBJ_textNotice                   1 3 6 1 5 5 7 2 3 */
&(nid_objs[129]),/* OBJ_server_auth                  1 3 6 1 5 5 7 3 1 */
&(nid_objs[130]),/* OBJ_client_auth                  1 3 6 1 5 5 7 3 2 */
&(nid_objs[131]),/* OBJ_code_sign                    1 3 6 1 5 5 7 3 3 */
&(nid_objs[132]),/* OBJ_email_protect                1 3 6 1 5 5 7 3 4 */
&(nid_objs[294]),/* OBJ_ipsecEndSystem               1 3 6 1 5 5 7 3 5 */
&(nid_objs[295]),/* OBJ_ipsecTunnel                  1 3 6 1 5 5 7 3 6 */
&(nid_objs[296]),/* OBJ_ipsecUser                    1 3 6 1 5 5 7 3 7 */
&(nid_objs[133]),/* OBJ_time_stamp                   1 3 6 1 5 5 7 3 8 */
&(nid_objs[180]),/* OBJ_OCSP_sign                    1 3 6 1 5 5 7 3 9 */
&(nid_objs[297]),/* OBJ_dvcs                         1 3 6 1 5 5 7 3 10 */
&(nid_objs[298]),/* OBJ_id_it_caProtEncCert          1 3 6 1 5 5 7 4 1 */
&(nid_objs[299]),/* OBJ_id_it_signKeyPairTypes       1 3 6 1 5 5 7 4 2 */
&(nid_objs[300]),/* OBJ_id_it_encKeyPairTypes        1 3 6 1 5 5 7 4 3 */
&(nid_objs[301]),/* OBJ_id_it_preferredSymmAlg       1 3 6 1 5 5 7 4 4 */
&(nid_objs[302]),/* OBJ_id_it_caKeyUpdateInfo        1 3 6 1 5 5 7 4 5 */
&(nid_objs[303]),/* OBJ_id_it_currentCRL             1 3 6 1 5 5 7 4 6 */
&(nid_objs[304]),/* OBJ_id_it_unsupportedOIDs        1 3 6 1 5 5 7 4 7 */
&(nid_objs[305]),/* OBJ_id_it_subscriptionRequest    1 3 6 1 5 5 7 4 8 */
&(nid_objs[306]),/* OBJ_id_it_subscriptionResponse   1 3 6 1 5 5 7 4 9 */
&(nid_objs[307]),/* OBJ_id_it_keyPairParamReq        1 3 6 1 5 5 7 4 10 */
&(nid_objs[308]),/* OBJ_id_it_keyPairParamRep        1 3 6 1 5 5 7 4 11 */
&(nid_objs[309]),/* OBJ_id_it_revPassphrase          1 3 6 1 5 5 7 4 12 */
&(nid_objs[310]),/* OBJ_id_it_implicitConfirm        1 3 6 1 5 5 7 4 13 */
&(nid_objs[311]),/* OBJ_id_it_confirmWaitTime        1 3 6 1 5 5 7 4 14 */
&(nid_objs[312]),/* OBJ_id_it_origPKIMessage         1 3 6 1 5 5 7 4 15 */
&(nid_objs[313]),/* OBJ_id_regCtrl                   1 3 6 1 5 5 7 5 1 */
&(nid_objs[314]),/* OBJ_id_regInfo                   1 3 6 1 5 5 7 5 2 */
&(nid_objs[323]),/* OBJ_id_alg_des40                 1 3 6 1 5 5 7 6 1 */
&(nid_objs[324]),/* OBJ_id_alg_noSignature           1 3 6 1 5 5 7 6 2 */
&(nid_objs[325]),/* OBJ_id_alg_dh_sig_hmac_sha1      1 3 6 1 5 5 7 6 3 */
&(nid_objs[326]),/* OBJ_id_alg_dh_pop                1 3 6 1 5 5 7 6 4 */
&(nid_objs[327]),/* OBJ_id_cmc_statusInfo            1 3 6 1 5 5 7 7 1 */
&(nid_objs[328]),/* OBJ_id_cmc_identification        1 3 6 1 5 5 7 7 2 */
&(nid_objs[329]),/* OBJ_id_cmc_identityProof         1 3 6 1 5 5 7 7 3 */
&(nid_objs[330]),/* OBJ_id_cmc_dataReturn            1 3 6 1 5 5 7 7 4 */
&(nid_objs[331]),/* OBJ_id_cmc_transactionId         1 3 6 1 5 5 7 7 5 */
&(nid_objs[332]),/* OBJ_id_cmc_senderNonce           1 3 6 1 5 5 7 7 6 */
&(nid_objs[333]),/* OBJ_id_cmc_recipientNonce        1 3 6 1 5 5 7 7 7 */
&(nid_objs[334]),/* OBJ_id_cmc_addExtensions         1 3 6 1 5 5 7 7 8 */
&(nid_objs[335]),/* OBJ_id_cmc_encryptedPOP          1 3 6 1 5 5 7 7 9 */
&(nid_objs[336]),/* OBJ_id_cmc_decryptedPOP          1 3 6 1 5 5 7 7 10 */
&(nid_objs[337]),/* OBJ_id_cmc_lraPOPWitness         1 3 6 1 5 5 7 7 11 */
&(nid_objs[338]),/* OBJ_id_cmc_getCert               1 3 6 1 5 5 7 7 15 */
&(nid_objs[339]),/* OBJ_id_cmc_getCRL                1 3 6 1 5 5 7 7 16 */
&(nid_objs[340]),/* OBJ_id_cmc_revokeRequest         1 3 6 1 5 5 7 7 17 */
&(nid_objs[341]),/* OBJ_id_cmc_regInfo               1 3 6 1 5 5 7 7 18 */
&(nid_objs[342]),/* OBJ_id_cmc_responseInfo          1 3 6 1 5 5 7 7 19 */
&(nid_objs[343]),/* OBJ_id_cmc_queryPending          1 3 6 1 5 5 7 7 21 */
&(nid_objs[344]),/* OBJ_id_cmc_popLinkRandom         1 3 6 1 5 5 7 7 22 */
&(nid_objs[345]),/* OBJ_id_cmc_popLinkWitness        1 3 6 1 5 5 7 7 23 */
&(nid_objs[346]),/* OBJ_id_cmc_confirmCertAcceptance 1 3 6 1 5 5 7 7 24 */
&(nid_objs[347]),/* OBJ_id_on_personalData           1 3 6 1 5 5 7 8 1 */
&(nid_objs[348]),/* OBJ_id_pda_dateOfBirth           1 3 6 1 5 5 7 9 1 */
&(nid_objs[349]),/* OBJ_id_pda_placeOfBirth          1 3 6 1 5 5 7 9 2 */
&(nid_objs[351]),/* OBJ_id_pda_gender                1 3 6 1 5 5 7 9 3 */
&(nid_objs[352]),/* OBJ_id_pda_countryOfCitizenship  1 3 6 1 5 5 7 9 4 */
&(nid_objs[353]),/* OBJ_id_pda_countryOfResidence    1 3 6 1 5 5 7 9 5 */
&(nid_objs[354]),/* OBJ_id_aca_authenticationInfo    1 3 6 1 5 5 7 10 1 */
&(nid_objs[355]),/* OBJ_id_aca_accessIdentity        1 3 6 1 5 5 7 10 2 */
&(nid_objs[356]),/* OBJ_id_aca_chargingIdentity      1 3 6 1 5 5 7 10 3 */
&(nid_objs[357]),/* OBJ_id_aca_group                 1 3 6 1 5 5 7 10 4 */
&(nid_objs[358]),/* OBJ_id_aca_role                  1 3 6 1 5 5 7 10 5 */
&(nid_objs[399]),/* OBJ_id_aca_encAttrs              1 3 6 1 5 5 7 10 6 */
&(nid_objs[359]),/* OBJ_id_qcs_pkixQCSyntax_v1       1 3 6 1 5 5 7 11 1 */
&(nid_objs[360]),/* OBJ_id_cct_crs                   1 3 6 1 5 5 7 12 1 */
&(nid_objs[361]),/* OBJ_id_cct_PKIData               1 3 6 1 5 5 7 12 2 */
&(nid_objs[362]),/* OBJ_id_cct_PKIResponse           1 3 6 1 5 5 7 12 3 */
&(nid_objs[178]),/* OBJ_ad_OCSP                      1 3 6 1 5 5 7 48 1 */
&(nid_objs[179]),/* OBJ_ad_ca_issuers                1 3 6 1 5 5 7 48 2 */
&(nid_objs[363]),/* OBJ_ad_timeStamping              1 3 6 1 5 5 7 48 3 */
&(nid_objs[364]),/* OBJ_ad_dvcs                      1 3 6 1 5 5 7 48 4 */
&(nid_objs[58]),/* OBJ_netscape_cert_extension      2 16 840 1 113730 1 */
&(nid_objs[59]),/* OBJ_netscape_data_type           2 16 840 1 113730 2 */
&(nid_objs[108]),/* OBJ_cast5_cbc                    1 2 840 113533 7 66 10 */
&(nid_objs[112]),/* OBJ_pbeWithMD5AndCast5_CBC       1 2 840 113533 7 66 12 */
&(nid_objs[ 6]),/* OBJ_rsaEncryption                1 2 840 113549 1 1 1 */
&(nid_objs[ 7]),/* OBJ_md2WithRSAEncryption         1 2 840 113549 1 1 2 */
&(nid_objs[396]),/* OBJ_md4WithRSAEncryption         1 2 840 113549 1 1 3 */
&(nid_objs[ 8]),/* OBJ_md5WithRSAEncryption         1 2 840 113549 1 1 4 */
&(nid_objs[65]),/* OBJ_sha1WithRSAEncryption        1 2 840 113549 1 1 5 */
&(nid_objs[28]),/* OBJ_dhKeyAgreement               1 2 840 113549 1 3 1 */
&(nid_objs[ 9]),/* OBJ_pbeWithMD2AndDES_CBC         1 2 840 113549 1 5 1 */
&(nid_objs[10]),/* OBJ_pbeWithMD5AndDES_CBC         1 2 840 113549 1 5 3 */
&(nid_objs[168]),/* OBJ_pbeWithMD2AndRC2_CBC         1 2 840 113549 1 5 4 */
&(nid_objs[169]),/* OBJ_pbeWithMD5AndRC2_CBC         1 2 840 113549 1 5 6 */
&(nid_objs[170]),/* OBJ_pbeWithSHA1AndDES_CBC        1 2 840 113549 1 5 10 */
&(nid_objs[68]),/* OBJ_pbeWithSHA1AndRC2_CBC        1 2 840 113549 1 5 11 */
&(nid_objs[69]),/* OBJ_id_pbkdf2                    1 2 840 113549 1 5 12 */
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
&(nid_objs[188]),/* OBJ_SMIME                        1 2 840 113549 1 9 16 */
&(nid_objs[156]),/* OBJ_friendlyName                 1 2 840 113549 1 9 20 */
&(nid_objs[157]),/* OBJ_localKeyID                   1 2 840 113549 1 9 21 */
&(nid_objs[91]),/* OBJ_bf_cbc                       1 3 6 1 4 1 3029 1 2 */
&(nid_objs[315]),/* OBJ_id_regCtrl_regToken          1 3 6 1 5 5 7 5 1 1 */
&(nid_objs[316]),/* OBJ_id_regCtrl_authenticator     1 3 6 1 5 5 7 5 1 2 */
&(nid_objs[317]),/* OBJ_id_regCtrl_pkiPublicationInfo 1 3 6 1 5 5 7 5 1 3 */
&(nid_objs[318]),/* OBJ_id_regCtrl_pkiArchiveOptions 1 3 6 1 5 5 7 5 1 4 */
&(nid_objs[319]),/* OBJ_id_regCtrl_oldCertID         1 3 6 1 5 5 7 5 1 5 */
&(nid_objs[320]),/* OBJ_id_regCtrl_protocolEncrKey   1 3 6 1 5 5 7 5 1 6 */
&(nid_objs[321]),/* OBJ_id_regInfo_utf8Pairs         1 3 6 1 5 5 7 5 2 1 */
&(nid_objs[322]),/* OBJ_id_regInfo_certReq           1 3 6 1 5 5 7 5 2 2 */
&(nid_objs[365]),/* OBJ_id_pkix_OCSP_basic           1 3 6 1 5 5 7 48 1 1 */
&(nid_objs[366]),/* OBJ_id_pkix_OCSP_Nonce           1 3 6 1 5 5 7 48 1 2 */
&(nid_objs[367]),/* OBJ_id_pkix_OCSP_CrlID           1 3 6 1 5 5 7 48 1 3 */
&(nid_objs[368]),/* OBJ_id_pkix_OCSP_acceptableResponses 1 3 6 1 5 5 7 48 1 4 */
&(nid_objs[369]),/* OBJ_id_pkix_OCSP_noCheck         1 3 6 1 5 5 7 48 1 5 */
&(nid_objs[370]),/* OBJ_id_pkix_OCSP_archiveCutoff   1 3 6 1 5 5 7 48 1 6 */
&(nid_objs[371]),/* OBJ_id_pkix_OCSP_serviceLocator  1 3 6 1 5 5 7 48 1 7 */
&(nid_objs[372]),/* OBJ_id_pkix_OCSP_extendedStatus  1 3 6 1 5 5 7 48 1 8 */
&(nid_objs[373]),/* OBJ_id_pkix_OCSP_valid           1 3 6 1 5 5 7 48 1 9 */
&(nid_objs[374]),/* OBJ_id_pkix_OCSP_path            1 3 6 1 5 5 7 48 1 10 */
&(nid_objs[375]),/* OBJ_id_pkix_OCSP_trustRoot       1 3 6 1 5 5 7 48 1 11 */
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
&(nid_objs[391]),/* OBJ_domainComponent              0 9 2342 19200300 100 1 25 */
&(nid_objs[392]),/* OBJ_Domain                       0 9 2342 19200300 100 4 13 */
&(nid_objs[189]),/* OBJ_id_smime_mod                 1 2 840 113549 1 9 16 0 */
&(nid_objs[190]),/* OBJ_id_smime_ct                  1 2 840 113549 1 9 16 1 */
&(nid_objs[191]),/* OBJ_id_smime_aa                  1 2 840 113549 1 9 16 2 */
&(nid_objs[192]),/* OBJ_id_smime_alg                 1 2 840 113549 1 9 16 3 */
&(nid_objs[193]),/* OBJ_id_smime_cd                  1 2 840 113549 1 9 16 4 */
&(nid_objs[194]),/* OBJ_id_smime_spq                 1 2 840 113549 1 9 16 5 */
&(nid_objs[195]),/* OBJ_id_smime_cti                 1 2 840 113549 1 9 16 6 */
&(nid_objs[158]),/* OBJ_x509Certificate              1 2 840 113549 1 9 22 1 */
&(nid_objs[159]),/* OBJ_sdsiCertificate              1 2 840 113549 1 9 22 2 */
&(nid_objs[160]),/* OBJ_x509Crl                      1 2 840 113549 1 9 23 1 */
&(nid_objs[144]),/* OBJ_pbe_WithSHA1And128BitRC4     1 2 840 113549 1 12 1 1 */
&(nid_objs[145]),/* OBJ_pbe_WithSHA1And40BitRC4      1 2 840 113549 1 12 1 2 */
&(nid_objs[146]),/* OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC 1 2 840 113549 1 12 1 3 */
&(nid_objs[147]),/* OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC 1 2 840 113549 1 12 1 4 */
&(nid_objs[148]),/* OBJ_pbe_WithSHA1And128BitRC2_CBC 1 2 840 113549 1 12 1 5 */
&(nid_objs[149]),/* OBJ_pbe_WithSHA1And40BitRC2_CBC  1 2 840 113549 1 12 1 6 */
&(nid_objs[171]),/* OBJ_ms_ext_req                   1 3 6 1 4 1 311 2 1 14 */
&(nid_objs[134]),/* OBJ_ms_code_ind                  1 3 6 1 4 1 311 2 1 21 */
&(nid_objs[135]),/* OBJ_ms_code_com                  1 3 6 1 4 1 311 2 1 22 */
&(nid_objs[136]),/* OBJ_ms_ctl_sign                  1 3 6 1 4 1 311 10 3 1 */
&(nid_objs[137]),/* OBJ_ms_sgc                       1 3 6 1 4 1 311 10 3 3 */
&(nid_objs[138]),/* OBJ_ms_efs                       1 3 6 1 4 1 311 10 3 4 */
&(nid_objs[196]),/* OBJ_id_smime_mod_cms             1 2 840 113549 1 9 16 0 1 */
&(nid_objs[197]),/* OBJ_id_smime_mod_ess             1 2 840 113549 1 9 16 0 2 */
&(nid_objs[198]),/* OBJ_id_smime_mod_oid             1 2 840 113549 1 9 16 0 3 */
&(nid_objs[199]),/* OBJ_id_smime_mod_msg_v3          1 2 840 113549 1 9 16 0 4 */
&(nid_objs[200]),/* OBJ_id_smime_mod_ets_eSignature_88 1 2 840 113549 1 9 16 0 5 */
&(nid_objs[201]),/* OBJ_id_smime_mod_ets_eSignature_97 1 2 840 113549 1 9 16 0 6 */
&(nid_objs[202]),/* OBJ_id_smime_mod_ets_eSigPolicy_88 1 2 840 113549 1 9 16 0 7 */
&(nid_objs[203]),/* OBJ_id_smime_mod_ets_eSigPolicy_97 1 2 840 113549 1 9 16 0 8 */
&(nid_objs[204]),/* OBJ_id_smime_ct_receipt          1 2 840 113549 1 9 16 1 1 */
&(nid_objs[205]),/* OBJ_id_smime_ct_authData         1 2 840 113549 1 9 16 1 2 */
&(nid_objs[206]),/* OBJ_id_smime_ct_publishCert      1 2 840 113549 1 9 16 1 3 */
&(nid_objs[207]),/* OBJ_id_smime_ct_TSTInfo          1 2 840 113549 1 9 16 1 4 */
&(nid_objs[208]),/* OBJ_id_smime_ct_TDTInfo          1 2 840 113549 1 9 16 1 5 */
&(nid_objs[209]),/* OBJ_id_smime_ct_contentInfo      1 2 840 113549 1 9 16 1 6 */
&(nid_objs[210]),/* OBJ_id_smime_ct_DVCSRequestData  1 2 840 113549 1 9 16 1 7 */
&(nid_objs[211]),/* OBJ_id_smime_ct_DVCSResponseData 1 2 840 113549 1 9 16 1 8 */
&(nid_objs[212]),/* OBJ_id_smime_aa_receiptRequest   1 2 840 113549 1 9 16 2 1 */
&(nid_objs[213]),/* OBJ_id_smime_aa_securityLabel    1 2 840 113549 1 9 16 2 2 */
&(nid_objs[214]),/* OBJ_id_smime_aa_mlExpandHistory  1 2 840 113549 1 9 16 2 3 */
&(nid_objs[215]),/* OBJ_id_smime_aa_contentHint      1 2 840 113549 1 9 16 2 4 */
&(nid_objs[216]),/* OBJ_id_smime_aa_msgSigDigest     1 2 840 113549 1 9 16 2 5 */
&(nid_objs[217]),/* OBJ_id_smime_aa_encapContentType 1 2 840 113549 1 9 16 2 6 */
&(nid_objs[218]),/* OBJ_id_smime_aa_contentIdentifier 1 2 840 113549 1 9 16 2 7 */
&(nid_objs[219]),/* OBJ_id_smime_aa_macValue         1 2 840 113549 1 9 16 2 8 */
&(nid_objs[220]),/* OBJ_id_smime_aa_equivalentLabels 1 2 840 113549 1 9 16 2 9 */
&(nid_objs[221]),/* OBJ_id_smime_aa_contentReference 1 2 840 113549 1 9 16 2 10 */
&(nid_objs[222]),/* OBJ_id_smime_aa_encrypKeyPref    1 2 840 113549 1 9 16 2 11 */
&(nid_objs[223]),/* OBJ_id_smime_aa_signingCertificate 1 2 840 113549 1 9 16 2 12 */
&(nid_objs[224]),/* OBJ_id_smime_aa_smimeEncryptCerts 1 2 840 113549 1 9 16 2 13 */
&(nid_objs[225]),/* OBJ_id_smime_aa_timeStampToken   1 2 840 113549 1 9 16 2 14 */
&(nid_objs[226]),/* OBJ_id_smime_aa_ets_sigPolicyId  1 2 840 113549 1 9 16 2 15 */
&(nid_objs[227]),/* OBJ_id_smime_aa_ets_commitmentType 1 2 840 113549 1 9 16 2 16 */
&(nid_objs[228]),/* OBJ_id_smime_aa_ets_signerLocation 1 2 840 113549 1 9 16 2 17 */
&(nid_objs[229]),/* OBJ_id_smime_aa_ets_signerAttr   1 2 840 113549 1 9 16 2 18 */
&(nid_objs[230]),/* OBJ_id_smime_aa_ets_otherSigCert 1 2 840 113549 1 9 16 2 19 */
&(nid_objs[231]),/* OBJ_id_smime_aa_ets_contentTimestamp 1 2 840 113549 1 9 16 2 20 */
&(nid_objs[232]),/* OBJ_id_smime_aa_ets_CertificateRefs 1 2 840 113549 1 9 16 2 21 */
&(nid_objs[233]),/* OBJ_id_smime_aa_ets_RevocationRefs 1 2 840 113549 1 9 16 2 22 */
&(nid_objs[234]),/* OBJ_id_smime_aa_ets_certValues   1 2 840 113549 1 9 16 2 23 */
&(nid_objs[235]),/* OBJ_id_smime_aa_ets_revocationValues 1 2 840 113549 1 9 16 2 24 */
&(nid_objs[236]),/* OBJ_id_smime_aa_ets_escTimeStamp 1 2 840 113549 1 9 16 2 25 */
&(nid_objs[237]),/* OBJ_id_smime_aa_ets_certCRLTimestamp 1 2 840 113549 1 9 16 2 26 */
&(nid_objs[238]),/* OBJ_id_smime_aa_ets_archiveTimeStamp 1 2 840 113549 1 9 16 2 27 */
&(nid_objs[239]),/* OBJ_id_smime_aa_signatureType    1 2 840 113549 1 9 16 2 28 */
&(nid_objs[240]),/* OBJ_id_smime_aa_dvcs_dvc         1 2 840 113549 1 9 16 2 29 */
&(nid_objs[241]),/* OBJ_id_smime_alg_ESDHwith3DES    1 2 840 113549 1 9 16 3 1 */
&(nid_objs[242]),/* OBJ_id_smime_alg_ESDHwithRC2     1 2 840 113549 1 9 16 3 2 */
&(nid_objs[243]),/* OBJ_id_smime_alg_3DESwrap        1 2 840 113549 1 9 16 3 3 */
&(nid_objs[244]),/* OBJ_id_smime_alg_RC2wrap         1 2 840 113549 1 9 16 3 4 */
&(nid_objs[245]),/* OBJ_id_smime_alg_ESDH            1 2 840 113549 1 9 16 3 5 */
&(nid_objs[246]),/* OBJ_id_smime_alg_CMS3DESwrap     1 2 840 113549 1 9 16 3 6 */
&(nid_objs[247]),/* OBJ_id_smime_alg_CMSRC2wrap      1 2 840 113549 1 9 16 3 7 */
&(nid_objs[248]),/* OBJ_id_smime_cd_ldap             1 2 840 113549 1 9 16 4 1 */
&(nid_objs[249]),/* OBJ_id_smime_spq_ets_sqt_uri     1 2 840 113549 1 9 16 5 1 */
&(nid_objs[250]),/* OBJ_id_smime_spq_ets_sqt_unotice 1 2 840 113549 1 9 16 5 2 */
&(nid_objs[251]),/* OBJ_id_smime_cti_ets_proofOfOrigin 1 2 840 113549 1 9 16 6 1 */
&(nid_objs[252]),/* OBJ_id_smime_cti_ets_proofOfReceipt 1 2 840 113549 1 9 16 6 2 */
&(nid_objs[253]),/* OBJ_id_smime_cti_ets_proofOfDelivery 1 2 840 113549 1 9 16 6 3 */
&(nid_objs[254]),/* OBJ_id_smime_cti_ets_proofOfSender 1 2 840 113549 1 9 16 6 4 */
&(nid_objs[255]),/* OBJ_id_smime_cti_ets_proofOfApproval 1 2 840 113549 1 9 16 6 5 */
&(nid_objs[256]),/* OBJ_id_smime_cti_ets_proofOfCreation 1 2 840 113549 1 9 16 6 6 */
&(nid_objs[150]),/* OBJ_keyBag                       1 2 840 113549 1 12 10 1 1 */
&(nid_objs[151]),/* OBJ_pkcs8ShroudedKeyBag          1 2 840 113549 1 12 10 1 2 */
&(nid_objs[152]),/* OBJ_certBag                      1 2 840 113549 1 12 10 1 3 */
&(nid_objs[153]),/* OBJ_crlBag                       1 2 840 113549 1 12 10 1 4 */
&(nid_objs[154]),/* OBJ_secretBag                    1 2 840 113549 1 12 10 1 5 */
&(nid_objs[155]),/* OBJ_safeContentsBag              1 2 840 113549 1 12 10 1 6 */
&(nid_objs[34]),/* OBJ_idea_cbc                     1 3 6 1 4 1 188 7 1 1 2 */
};

