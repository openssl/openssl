/* crypto/objects/obj_dat.h */

/* THIS FILE IS GENERATED FROM objects.h by obj_dat.pl via the
 * following command:
 * perl obj_dat.pl obj_mac.h obj_dat.h
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

#define NUM_NID 510
#define NUM_SN 507
#define NUM_LN 507
#define NUM_OBJ 481

static unsigned char lvalues[3881]={
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
0x2B,0x0E,0x03,0x02,0x11,                    /* [202] OBJ_des_ede_ecb */
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
0x55,0x1D,0x1F,                              /* [544] OBJ_crl_distribution_points */
0x2B,0x0E,0x03,0x02,0x03,                    /* [547] OBJ_md5WithRSA */
0x55,0x04,0x05,                              /* [552] OBJ_serialNumber */
0x55,0x04,0x0C,                              /* [555] OBJ_title */
0x55,0x04,0x0D,                              /* [558] OBJ_description */
0x2A,0x86,0x48,0x86,0xF6,0x7D,0x07,0x42,0x0A,/* [561] OBJ_cast5_cbc */
0x2A,0x86,0x48,0x86,0xF6,0x7D,0x07,0x42,0x0C,/* [570] OBJ_pbeWithMD5AndCast5_CBC */
0x2A,0x86,0x48,0xCE,0x38,0x04,0x03,          /* [579] OBJ_dsaWithSHA1 */
0x2B,0x0E,0x03,0x02,0x1D,                    /* [586] OBJ_sha1WithRSA */
0x2A,0x86,0x48,0xCE,0x38,0x04,0x01,          /* [591] OBJ_dsa */
0x2B,0x24,0x03,0x02,0x01,                    /* [598] OBJ_ripemd160 */
0x2B,0x24,0x03,0x03,0x01,0x02,               /* [603] OBJ_ripemd160WithRSA */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x03,0x08,     /* [609] OBJ_rc5_cbc */
0x29,0x01,0x01,0x85,0x1A,0x01,               /* [617] OBJ_rle_compression */
0x29,0x01,0x01,0x85,0x1A,0x02,               /* [623] OBJ_zlib_compression */
0x55,0x1D,0x25,                              /* [629] OBJ_ext_key_usage */
0x2B,0x06,0x01,0x05,0x05,0x07,               /* [632] OBJ_id_pkix */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,          /* [638] OBJ_id_kp */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01,     /* [645] OBJ_server_auth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02,     /* [653] OBJ_client_auth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x03,     /* [661] OBJ_code_sign */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x04,     /* [669] OBJ_email_protect */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x08,     /* [677] OBJ_time_stamp */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x15,/* [685] OBJ_ms_code_ind */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x16,/* [695] OBJ_ms_code_com */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x01,/* [705] OBJ_ms_ctl_sign */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x03,/* [715] OBJ_ms_sgc */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x03,0x04,/* [725] OBJ_ms_efs */
0x60,0x86,0x48,0x01,0x86,0xF8,0x42,0x04,0x01,/* [735] OBJ_ns_sgc */
0x55,0x1D,0x1B,                              /* [744] OBJ_delta_crl */
0x55,0x1D,0x15,                              /* [747] OBJ_crl_reason */
0x55,0x1D,0x18,                              /* [750] OBJ_invalidity_date */
0x2B,0x65,0x01,0x04,0x01,                    /* [753] OBJ_sxnet */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x01,/* [758] OBJ_pbe_WithSHA1And128BitRC4 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x02,/* [768] OBJ_pbe_WithSHA1And40BitRC4 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x03,/* [778] OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x04,/* [788] OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x05,/* [798] OBJ_pbe_WithSHA1And128BitRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x01,0x06,/* [808] OBJ_pbe_WithSHA1And40BitRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x01,/* [818] OBJ_keyBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x02,/* [829] OBJ_pkcs8ShroudedKeyBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x03,/* [840] OBJ_certBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x04,/* [851] OBJ_crlBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x05,/* [862] OBJ_secretBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x06,/* [873] OBJ_safeContentsBag */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x14,/* [884] OBJ_friendlyName */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x15,/* [893] OBJ_localKeyID */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x16,0x01,/* [902] OBJ_x509Certificate */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x16,0x02,/* [912] OBJ_sdsiCertificate */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x17,0x01,/* [922] OBJ_x509Crl */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0D,/* [932] OBJ_pbes2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0E,/* [941] OBJ_pbmac1 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x07,     /* [950] OBJ_hmacWithSHA1 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x01,     /* [958] OBJ_id_qt_cps */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x02,     /* [966] OBJ_id_qt_unotice */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0F,/* [974] OBJ_SMIMECapabilities */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x04,/* [983] OBJ_pbeWithMD2AndRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x06,/* [992] OBJ_pbeWithMD5AndRC2_CBC */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0A,/* [1001] OBJ_pbeWithSHA1AndDES_CBC */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x0E,/* [1010] OBJ_ms_ext_req */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0E,/* [1020] OBJ_ext_req */
0x55,0x04,0x29,                              /* [1029] OBJ_name */
0x55,0x04,0x2E,                              /* [1032] OBJ_dnQualifier */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,          /* [1035] OBJ_id_pe */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,          /* [1042] OBJ_id_ad */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x01,     /* [1049] OBJ_info_access */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,     /* [1057] OBJ_ad_OCSP */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,     /* [1065] OBJ_ad_ca_issuers */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x09,     /* [1073] OBJ_OCSP_sign */
0x28,                                        /* [1081] OBJ_iso */
0x2A,                                        /* [1082] OBJ_member_body */
0x2A,0x86,0x48,                              /* [1083] OBJ_ISO_US */
0x2A,0x86,0x48,0xCE,0x38,                    /* [1086] OBJ_X9_57 */
0x2A,0x86,0x48,0xCE,0x38,0x04,               /* [1091] OBJ_X9cm */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,     /* [1097] OBJ_pkcs1 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,     /* [1105] OBJ_pkcs5 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,/* [1113] OBJ_SMIME */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,/* [1122] OBJ_id_smime_mod */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,/* [1132] OBJ_id_smime_ct */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,/* [1142] OBJ_id_smime_aa */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,/* [1152] OBJ_id_smime_alg */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x04,/* [1162] OBJ_id_smime_cd */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x05,/* [1172] OBJ_id_smime_spq */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,/* [1182] OBJ_id_smime_cti */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x01,/* [1192] OBJ_id_smime_mod_cms */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x02,/* [1203] OBJ_id_smime_mod_ess */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x03,/* [1214] OBJ_id_smime_mod_oid */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x04,/* [1225] OBJ_id_smime_mod_msg_v3 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x05,/* [1236] OBJ_id_smime_mod_ets_eSignature_88 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x06,/* [1247] OBJ_id_smime_mod_ets_eSignature_97 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x07,/* [1258] OBJ_id_smime_mod_ets_eSigPolicy_88 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x00,0x08,/* [1269] OBJ_id_smime_mod_ets_eSigPolicy_97 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x01,/* [1280] OBJ_id_smime_ct_receipt */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x02,/* [1291] OBJ_id_smime_ct_authData */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x03,/* [1302] OBJ_id_smime_ct_publishCert */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x04,/* [1313] OBJ_id_smime_ct_TSTInfo */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x05,/* [1324] OBJ_id_smime_ct_TDTInfo */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x06,/* [1335] OBJ_id_smime_ct_contentInfo */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x07,/* [1346] OBJ_id_smime_ct_DVCSRequestData */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x08,/* [1357] OBJ_id_smime_ct_DVCSResponseData */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x01,/* [1368] OBJ_id_smime_aa_receiptRequest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x02,/* [1379] OBJ_id_smime_aa_securityLabel */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x03,/* [1390] OBJ_id_smime_aa_mlExpandHistory */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x04,/* [1401] OBJ_id_smime_aa_contentHint */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x05,/* [1412] OBJ_id_smime_aa_msgSigDigest */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x06,/* [1423] OBJ_id_smime_aa_encapContentType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x07,/* [1434] OBJ_id_smime_aa_contentIdentifier */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x08,/* [1445] OBJ_id_smime_aa_macValue */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x09,/* [1456] OBJ_id_smime_aa_equivalentLabels */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0A,/* [1467] OBJ_id_smime_aa_contentReference */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0B,/* [1478] OBJ_id_smime_aa_encrypKeyPref */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0C,/* [1489] OBJ_id_smime_aa_signingCertificate */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0D,/* [1500] OBJ_id_smime_aa_smimeEncryptCerts */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0E,/* [1511] OBJ_id_smime_aa_timeStampToken */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x0F,/* [1522] OBJ_id_smime_aa_ets_sigPolicyId */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x10,/* [1533] OBJ_id_smime_aa_ets_commitmentType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x11,/* [1544] OBJ_id_smime_aa_ets_signerLocation */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x12,/* [1555] OBJ_id_smime_aa_ets_signerAttr */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x13,/* [1566] OBJ_id_smime_aa_ets_otherSigCert */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x14,/* [1577] OBJ_id_smime_aa_ets_contentTimestamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x15,/* [1588] OBJ_id_smime_aa_ets_CertificateRefs */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x16,/* [1599] OBJ_id_smime_aa_ets_RevocationRefs */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x17,/* [1610] OBJ_id_smime_aa_ets_certValues */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x18,/* [1621] OBJ_id_smime_aa_ets_revocationValues */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x19,/* [1632] OBJ_id_smime_aa_ets_escTimeStamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1A,/* [1643] OBJ_id_smime_aa_ets_certCRLTimestamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1B,/* [1654] OBJ_id_smime_aa_ets_archiveTimeStamp */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1C,/* [1665] OBJ_id_smime_aa_signatureType */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x02,0x1D,/* [1676] OBJ_id_smime_aa_dvcs_dvc */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x01,/* [1687] OBJ_id_smime_alg_ESDHwith3DES */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x02,/* [1698] OBJ_id_smime_alg_ESDHwithRC2 */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x03,/* [1709] OBJ_id_smime_alg_3DESwrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x04,/* [1720] OBJ_id_smime_alg_RC2wrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x05,/* [1731] OBJ_id_smime_alg_ESDH */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x06,/* [1742] OBJ_id_smime_alg_CMS3DESwrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x03,0x07,/* [1753] OBJ_id_smime_alg_CMSRC2wrap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x04,0x01,/* [1764] OBJ_id_smime_cd_ldap */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x05,0x01,/* [1775] OBJ_id_smime_spq_ets_sqt_uri */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x05,0x02,/* [1786] OBJ_id_smime_spq_ets_sqt_unotice */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x01,/* [1797] OBJ_id_smime_cti_ets_proofOfOrigin */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x02,/* [1808] OBJ_id_smime_cti_ets_proofOfReceipt */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x03,/* [1819] OBJ_id_smime_cti_ets_proofOfDelivery */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x04,/* [1830] OBJ_id_smime_cti_ets_proofOfSender */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x05,/* [1841] OBJ_id_smime_cti_ets_proofOfApproval */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x06,0x06,/* [1852] OBJ_id_smime_cti_ets_proofOfCreation */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x04,     /* [1863] OBJ_md4 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,          /* [1871] OBJ_id_pkix_mod */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,          /* [1878] OBJ_id_qt */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,          /* [1885] OBJ_id_it */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,          /* [1892] OBJ_id_pkip */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,          /* [1899] OBJ_id_alg */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,          /* [1906] OBJ_id_cmc */
0x2B,0x06,0x01,0x05,0x05,0x07,0x08,          /* [1913] OBJ_id_on */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,          /* [1920] OBJ_id_pda */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,          /* [1927] OBJ_id_aca */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0B,          /* [1934] OBJ_id_qcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,          /* [1941] OBJ_id_cct */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x01,     /* [1948] OBJ_id_pkix1_explicit_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x02,     /* [1956] OBJ_id_pkix1_implicit_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x03,     /* [1964] OBJ_id_pkix1_explicit_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x04,     /* [1972] OBJ_id_pkix1_implicit_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x05,     /* [1980] OBJ_id_mod_crmf */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x06,     /* [1988] OBJ_id_mod_cmc */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x07,     /* [1996] OBJ_id_mod_kea_profile_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x08,     /* [2004] OBJ_id_mod_kea_profile_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x09,     /* [2012] OBJ_id_mod_cmp */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0A,     /* [2020] OBJ_id_mod_qualified_cert_88 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0B,     /* [2028] OBJ_id_mod_qualified_cert_93 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0C,     /* [2036] OBJ_id_mod_attribute_cert */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0D,     /* [2044] OBJ_id_mod_timestamp_protocol */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0E,     /* [2052] OBJ_id_mod_ocsp */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x0F,     /* [2060] OBJ_id_mod_dvcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x00,0x10,     /* [2068] OBJ_id_mod_cmp2000 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x02,     /* [2076] OBJ_biometricInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x03,     /* [2084] OBJ_qcStatements */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x04,     /* [2092] OBJ_ac_auditEntity */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x05,     /* [2100] OBJ_ac_targeting */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x06,     /* [2108] OBJ_aaControls */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x07,     /* [2116] OBJ_sbqp_ipAddrBlock */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x08,     /* [2124] OBJ_sbqp_autonomousSysNum */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x09,     /* [2132] OBJ_sbqp_routerIdentifier */
0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x03,     /* [2140] OBJ_textNotice */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x05,     /* [2148] OBJ_ipsecEndSystem */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x06,     /* [2156] OBJ_ipsecTunnel */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x07,     /* [2164] OBJ_ipsecUser */
0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x0A,     /* [2172] OBJ_dvcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x01,     /* [2180] OBJ_id_it_caProtEncCert */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x02,     /* [2188] OBJ_id_it_signKeyPairTypes */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x03,     /* [2196] OBJ_id_it_encKeyPairTypes */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x04,     /* [2204] OBJ_id_it_preferredSymmAlg */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x05,     /* [2212] OBJ_id_it_caKeyUpdateInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x06,     /* [2220] OBJ_id_it_currentCRL */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x07,     /* [2228] OBJ_id_it_unsupportedOIDs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x08,     /* [2236] OBJ_id_it_subscriptionRequest */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x09,     /* [2244] OBJ_id_it_subscriptionResponse */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0A,     /* [2252] OBJ_id_it_keyPairParamReq */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0B,     /* [2260] OBJ_id_it_keyPairParamRep */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0C,     /* [2268] OBJ_id_it_revPassphrase */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0D,     /* [2276] OBJ_id_it_implicitConfirm */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0E,     /* [2284] OBJ_id_it_confirmWaitTime */
0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0F,     /* [2292] OBJ_id_it_origPKIMessage */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,     /* [2300] OBJ_id_regCtrl */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x02,     /* [2308] OBJ_id_regInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x01,/* [2316] OBJ_id_regCtrl_regToken */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x02,/* [2325] OBJ_id_regCtrl_authenticator */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x03,/* [2334] OBJ_id_regCtrl_pkiPublicationInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x04,/* [2343] OBJ_id_regCtrl_pkiArchiveOptions */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x05,/* [2352] OBJ_id_regCtrl_oldCertID */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x01,0x06,/* [2361] OBJ_id_regCtrl_protocolEncrKey */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x02,0x01,/* [2370] OBJ_id_regInfo_utf8Pairs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x05,0x02,0x02,/* [2379] OBJ_id_regInfo_certReq */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x01,     /* [2388] OBJ_id_alg_des40 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x02,     /* [2396] OBJ_id_alg_noSignature */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x03,     /* [2404] OBJ_id_alg_dh_sig_hmac_sha1 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x06,0x04,     /* [2412] OBJ_id_alg_dh_pop */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x01,     /* [2420] OBJ_id_cmc_statusInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x02,     /* [2428] OBJ_id_cmc_identification */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x03,     /* [2436] OBJ_id_cmc_identityProof */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x04,     /* [2444] OBJ_id_cmc_dataReturn */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x05,     /* [2452] OBJ_id_cmc_transactionId */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x06,     /* [2460] OBJ_id_cmc_senderNonce */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x07,     /* [2468] OBJ_id_cmc_recipientNonce */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x08,     /* [2476] OBJ_id_cmc_addExtensions */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x09,     /* [2484] OBJ_id_cmc_encryptedPOP */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x0A,     /* [2492] OBJ_id_cmc_decryptedPOP */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x0B,     /* [2500] OBJ_id_cmc_lraPOPWitness */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x0F,     /* [2508] OBJ_id_cmc_getCert */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x10,     /* [2516] OBJ_id_cmc_getCRL */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x11,     /* [2524] OBJ_id_cmc_revokeRequest */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x12,     /* [2532] OBJ_id_cmc_regInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x13,     /* [2540] OBJ_id_cmc_responseInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x15,     /* [2548] OBJ_id_cmc_queryPending */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x16,     /* [2556] OBJ_id_cmc_popLinkRandom */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x17,     /* [2564] OBJ_id_cmc_popLinkWitness */
0x2B,0x06,0x01,0x05,0x05,0x07,0x07,0x18,     /* [2572] OBJ_id_cmc_confirmCertAcceptance */
0x2B,0x06,0x01,0x05,0x05,0x07,0x08,0x01,     /* [2580] OBJ_id_on_personalData */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x01,     /* [2588] OBJ_id_pda_dateOfBirth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x02,     /* [2596] OBJ_id_pda_placeOfBirth */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x03,     /* [2604] OBJ_id_pda_gender */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x04,     /* [2612] OBJ_id_pda_countryOfCitizenship */
0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x05,     /* [2620] OBJ_id_pda_countryOfResidence */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x01,     /* [2628] OBJ_id_aca_authenticationInfo */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x02,     /* [2636] OBJ_id_aca_accessIdentity */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x03,     /* [2644] OBJ_id_aca_chargingIdentity */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x04,     /* [2652] OBJ_id_aca_group */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x05,     /* [2660] OBJ_id_aca_role */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0B,0x01,     /* [2668] OBJ_id_qcs_pkixQCSyntax_v1 */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,0x01,     /* [2676] OBJ_id_cct_crs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,0x02,     /* [2684] OBJ_id_cct_PKIData */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0C,0x03,     /* [2692] OBJ_id_cct_PKIResponse */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x03,     /* [2700] OBJ_ad_timeStamping */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x04,     /* [2708] OBJ_ad_dvcs */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x01,/* [2716] OBJ_id_pkix_OCSP_basic */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x02,/* [2725] OBJ_id_pkix_OCSP_Nonce */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x03,/* [2734] OBJ_id_pkix_OCSP_CrlID */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x04,/* [2743] OBJ_id_pkix_OCSP_acceptableResponses */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x05,/* [2752] OBJ_id_pkix_OCSP_noCheck */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x06,/* [2761] OBJ_id_pkix_OCSP_archiveCutoff */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x07,/* [2770] OBJ_id_pkix_OCSP_serviceLocator */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x08,/* [2779] OBJ_id_pkix_OCSP_extendedStatus */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x09,/* [2788] OBJ_id_pkix_OCSP_valid */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x0A,/* [2797] OBJ_id_pkix_OCSP_path */
0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x0B,/* [2806] OBJ_id_pkix_OCSP_trustRoot */
0x2B,0x0E,0x03,0x02,                         /* [2815] OBJ_algorithm */
0x2B,0x0E,0x03,0x02,0x0B,                    /* [2819] OBJ_rsaSignature */
0x55,0x08,                                   /* [2824] OBJ_X500algorithms */
0x2B,                                        /* [2826] OBJ_org */
0x2B,0x06,                                   /* [2827] OBJ_dod */
0x2B,0x06,0x01,                              /* [2829] OBJ_iana */
0x2B,0x06,0x01,0x01,                         /* [2832] OBJ_Directory */
0x2B,0x06,0x01,0x02,                         /* [2836] OBJ_Management */
0x2B,0x06,0x01,0x03,                         /* [2840] OBJ_Experimental */
0x2B,0x06,0x01,0x04,                         /* [2844] OBJ_Private */
0x2B,0x06,0x01,0x05,                         /* [2848] OBJ_Security */
0x2B,0x06,0x01,0x06,                         /* [2852] OBJ_SNMPv2 */
0x2B,0x06,0x01,0x07,                         /* [2856] OBJ_Mail */
0x2B,0x06,0x01,0x04,0x01,                    /* [2860] OBJ_Enterprises */
0x2B,0x06,0x01,0x04,0x01,0x8B,0x3A,0x82,0x58,/* [2865] OBJ_dcObject */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x19,/* [2874] OBJ_domainComponent */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x0D,/* [2884] OBJ_Domain */
0x50,                                        /* [2894] OBJ_joint_iso_ccitt */
0x55,0x01,0x05,                              /* [2895] OBJ_selected_attribute_types */
0x55,0x01,0x05,0x37,                         /* [2898] OBJ_clearance */
0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x03,/* [2902] OBJ_md4WithRSAEncryption */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x0A,     /* [2911] OBJ_ac_proxying */
0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x0B,     /* [2919] OBJ_sinfo_access */
0x2B,0x06,0x01,0x05,0x05,0x07,0x0A,0x06,     /* [2927] OBJ_id_aca_encAttrs */
0x55,0x04,0x48,                              /* [2935] OBJ_role */
0x55,0x1D,0x24,                              /* [2938] OBJ_policy_constraints */
0x55,0x1D,0x37,                              /* [2941] OBJ_target_information */
0x55,0x1D,0x38,                              /* [2944] OBJ_no_rev_avail */
0x00,                                        /* [2947] OBJ_ccitt */
0x2A,0x86,0x48,0xCE,0x3D,                    /* [2948] OBJ_ansi_X9_62 */
0x2A,0x86,0x48,0xCE,0x3D,0x01,0x01,          /* [2953] OBJ_X9_62_prime_field */
0x2A,0x86,0x48,0xCE,0x3D,0x01,0x02,          /* [2960] OBJ_X9_62_characteristic_two_field */
0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,          /* [2967] OBJ_X9_62_id_ecPublicKey */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x01,     /* [2974] OBJ_X9_62_prime192v1 */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x02,     /* [2982] OBJ_X9_62_prime192v2 */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x03,     /* [2990] OBJ_X9_62_prime192v3 */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x04,     /* [2998] OBJ_X9_62_prime239v1 */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x05,     /* [3006] OBJ_X9_62_prime239v2 */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x06,     /* [3014] OBJ_X9_62_prime239v3 */
0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,     /* [3022] OBJ_X9_62_prime256v1 */
0x2A,0x86,0x48,0xCE,0x3D,0x04,0x01,          /* [3030] OBJ_ecdsa_with_SHA1 */
0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x11,0x01,/* [3037] OBJ_ms_csp_name */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x01,/* [3046] OBJ_aes_128_ecb */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02,/* [3055] OBJ_aes_128_cbc */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x03,/* [3064] OBJ_aes_128_ofb128 */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x04,/* [3073] OBJ_aes_128_cfb128 */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x15,/* [3082] OBJ_aes_192_ecb */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x16,/* [3091] OBJ_aes_192_cbc */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x17,/* [3100] OBJ_aes_192_ofb128 */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x18,/* [3109] OBJ_aes_192_cfb128 */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x29,/* [3118] OBJ_aes_256_ecb */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2A,/* [3127] OBJ_aes_256_cbc */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2B,/* [3136] OBJ_aes_256_ofb128 */
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2C,/* [3145] OBJ_aes_256_cfb128 */
0x55,0x1D,0x17,                              /* [3154] OBJ_hold_instruction_code */
0x2A,0x86,0x48,0xCE,0x38,0x02,0x01,          /* [3157] OBJ_hold_instruction_none */
0x2A,0x86,0x48,0xCE,0x38,0x02,0x02,          /* [3164] OBJ_hold_instruction_call_issuer */
0x2A,0x86,0x48,0xCE,0x38,0x02,0x03,          /* [3171] OBJ_hold_instruction_reject */
0x09,                                        /* [3178] OBJ_data */
0x09,0x92,0x26,                              /* [3179] OBJ_pss */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,          /* [3182] OBJ_ucl */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,     /* [3189] OBJ_pilot */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,/* [3197] OBJ_pilotAttributeType */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x03,/* [3206] OBJ_pilotAttributeSyntax */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,/* [3215] OBJ_pilotObjectClass */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x0A,/* [3224] OBJ_pilotGroups */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x03,0x04,/* [3233] OBJ_iA5StringSyntax */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x03,0x05,/* [3243] OBJ_caseIgnoreIA5StringSyntax */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x03,/* [3253] OBJ_pilotObject */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x04,/* [3263] OBJ_pilotPerson */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x05,/* [3273] OBJ_account */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x06,/* [3283] OBJ_document */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x07,/* [3293] OBJ_room */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x09,/* [3303] OBJ_documentSeries */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x0E,/* [3313] OBJ_rFC822localPart */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x0F,/* [3323] OBJ_dNSDomain */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x11,/* [3333] OBJ_domainRelatedObject */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x12,/* [3343] OBJ_friendlyCountry */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x13,/* [3353] OBJ_simpleSecurityObject */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x14,/* [3363] OBJ_pilotOrganization */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x15,/* [3373] OBJ_pilotDSA */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x04,0x16,/* [3383] OBJ_qualityLabelledData */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x01,/* [3393] OBJ_userId */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x02,/* [3403] OBJ_textEncodedORAddress */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x03,/* [3413] OBJ_rfc822Mailbox */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x04,/* [3423] OBJ_info */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x05,/* [3433] OBJ_favouriteDrink */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x06,/* [3443] OBJ_roomNumber */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x07,/* [3453] OBJ_photo */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x08,/* [3463] OBJ_userClass */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x09,/* [3473] OBJ_host */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x0A,/* [3483] OBJ_manager */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x0B,/* [3493] OBJ_documentIdentifier */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x0C,/* [3503] OBJ_documentTitle */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x0D,/* [3513] OBJ_documentVersion */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x0E,/* [3523] OBJ_documentAuthor */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x0F,/* [3533] OBJ_documentLocation */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x14,/* [3543] OBJ_homeTelephoneNumber */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x15,/* [3553] OBJ_secretary */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x16,/* [3563] OBJ_otherMailbox */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x17,/* [3573] OBJ_lastModifiedTime */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x18,/* [3583] OBJ_lastModifiedBy */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x1A,/* [3593] OBJ_aRecord */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x1B,/* [3603] OBJ_pilotAttributeType27 */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x1C,/* [3613] OBJ_mXRecord */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x1D,/* [3623] OBJ_nSRecord */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x1E,/* [3633] OBJ_sOARecord */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x1F,/* [3643] OBJ_cNAMERecord */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x25,/* [3653] OBJ_associatedDomain */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x26,/* [3663] OBJ_associatedName */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x27,/* [3673] OBJ_homePostalAddress */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x28,/* [3683] OBJ_personalTitle */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x29,/* [3693] OBJ_mobileTelephoneNumber */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x2A,/* [3703] OBJ_pagerTelephoneNumber */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x2B,/* [3713] OBJ_friendlyCountryName */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x2D,/* [3723] OBJ_organizationalStatus */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x2E,/* [3733] OBJ_janetMailbox */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x2F,/* [3743] OBJ_mailPreferenceOption */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x30,/* [3753] OBJ_buildingName */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x31,/* [3763] OBJ_dSAQuality */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x32,/* [3773] OBJ_singleLevelQuality */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x33,/* [3783] OBJ_subtreeMinimumQuality */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x34,/* [3793] OBJ_subtreeMaximumQuality */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x35,/* [3803] OBJ_personalSignature */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x36,/* [3813] OBJ_dITRedirect */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x37,/* [3823] OBJ_audio */
0x09,0x92,0x26,0x89,0x93,0xF2,0x2C,0x64,0x01,0x38,/* [3833] OBJ_documentPublisher */
0x55,0x04,0x2D,                              /* [3843] OBJ_x500UniqueIdentifier */
0x2B,0x06,0x01,0x07,0x01,                    /* [3846] OBJ_mime_mhs */
0x2B,0x06,0x01,0x07,0x01,0x01,               /* [3851] OBJ_mime_mhs_headings */
0x2B,0x06,0x01,0x07,0x01,0x02,               /* [3857] OBJ_mime_mhs_bodies */
0x2B,0x06,0x01,0x07,0x01,0x01,0x01,          /* [3863] OBJ_id_hex_partial_message */
0x2B,0x06,0x01,0x07,0x01,0x01,0x02,          /* [3870] OBJ_id_hex_multipart_message */
0x55,0x04,0x2C,                              /* [3877] OBJ_generationQualifier */
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
{"DES-EDE","des-ede",NID_des_ede_ecb,5,&(lvalues[202]),0},
{"DES-EDE3","des-ede3",NID_des_ede3_ecb,0,NULL},
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
{"emailAddress","emailAddress",NID_pkcs9_emailAddress,9,
	&(lvalues[257]),0},
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
{"gn","givenName",NID_givenName,3,&(lvalues[535]),0},
{"SN","surname",NID_surname,3,&(lvalues[538]),0},
{"initials","initials",NID_initials,3,&(lvalues[541]),0},
{NULL,NULL,NID_undef,0,NULL},
{"crlDistributionPoints","X509v3 CRL Distribution Points",
	NID_crl_distribution_points,3,&(lvalues[544]),0},
{"RSA-NP-MD5","md5WithRSA",NID_md5WithRSA,5,&(lvalues[547]),0},
{"serialNumber","serialNumber",NID_serialNumber,3,&(lvalues[552]),0},
{"title","title",NID_title,3,&(lvalues[555]),0},
{"description","description",NID_description,3,&(lvalues[558]),0},
{"CAST5-CBC","cast5-cbc",NID_cast5_cbc,9,&(lvalues[561]),0},
{"CAST5-ECB","cast5-ecb",NID_cast5_ecb,0,NULL},
{"CAST5-CFB","cast5-cfb",NID_cast5_cfb64,0,NULL},
{"CAST5-OFB","cast5-ofb",NID_cast5_ofb64,0,NULL},
{"pbeWithMD5AndCast5CBC","pbeWithMD5AndCast5CBC",
	NID_pbeWithMD5AndCast5_CBC,9,&(lvalues[570]),0},
{"DSA-SHA1","dsaWithSHA1",NID_dsaWithSHA1,7,&(lvalues[579]),0},
{"MD5-SHA1","md5-sha1",NID_md5_sha1,0,NULL},
{"RSA-SHA1-2","sha1WithRSA",NID_sha1WithRSA,5,&(lvalues[586]),0},
{"DSA","dsaEncryption",NID_dsa,7,&(lvalues[591]),0},
{"RIPEMD160","ripemd160",NID_ripemd160,5,&(lvalues[598]),0},
{NULL,NULL,NID_undef,0,NULL},
{"RSA-RIPEMD160","ripemd160WithRSA",NID_ripemd160WithRSA,6,
	&(lvalues[603]),0},
{"RC5-CBC","rc5-cbc",NID_rc5_cbc,8,&(lvalues[609]),0},
{"RC5-ECB","rc5-ecb",NID_rc5_ecb,0,NULL},
{"RC5-CFB","rc5-cfb",NID_rc5_cfb64,0,NULL},
{"RC5-OFB","rc5-ofb",NID_rc5_ofb64,0,NULL},
{"RLE","run length compression",NID_rle_compression,6,&(lvalues[617]),0},
{"ZLIB","zlib compression",NID_zlib_compression,6,&(lvalues[623]),0},
{"extendedKeyUsage","X509v3 Extended Key Usage",NID_ext_key_usage,3,
	&(lvalues[629]),0},
{"PKIX","PKIX",NID_id_pkix,6,&(lvalues[632]),0},
{"id-kp","id-kp",NID_id_kp,7,&(lvalues[638]),0},
{"serverAuth","TLS Web Server Authentication",NID_server_auth,8,
	&(lvalues[645]),0},
{"clientAuth","TLS Web Client Authentication",NID_client_auth,8,
	&(lvalues[653]),0},
{"codeSigning","Code Signing",NID_code_sign,8,&(lvalues[661]),0},
{"emailProtection","E-mail Protection",NID_email_protect,8,
	&(lvalues[669]),0},
{"timeStamping","Time Stamping",NID_time_stamp,8,&(lvalues[677]),0},
{"msCodeInd","Microsoft Individual Code Signing",NID_ms_code_ind,10,
	&(lvalues[685]),0},
{"msCodeCom","Microsoft Commercial Code Signing",NID_ms_code_com,10,
	&(lvalues[695]),0},
{"msCTLSign","Microsoft Trust List Signing",NID_ms_ctl_sign,10,
	&(lvalues[705]),0},
{"msSGC","Microsoft Server Gated Crypto",NID_ms_sgc,10,&(lvalues[715]),0},
{"msEFS","Microsoft Encrypted File System",NID_ms_efs,10,
	&(lvalues[725]),0},
{"nsSGC","Netscape Server Gated Crypto",NID_ns_sgc,9,&(lvalues[735]),0},
{"deltaCRL","X509v3 Delta CRL Indicator",NID_delta_crl,3,
	&(lvalues[744]),0},
{"CRLReason","X509v3 CRL Reason Code",NID_crl_reason,3,&(lvalues[747]),0},
{"invalidityDate","Invalidity Date",NID_invalidity_date,3,
	&(lvalues[750]),0},
{"SXNetID","Strong Extranet ID",NID_sxnet,5,&(lvalues[753]),0},
{"PBE-SHA1-RC4-128","pbeWithSHA1And128BitRC4",
	NID_pbe_WithSHA1And128BitRC4,10,&(lvalues[758]),0},
{"PBE-SHA1-RC4-40","pbeWithSHA1And40BitRC4",
	NID_pbe_WithSHA1And40BitRC4,10,&(lvalues[768]),0},
{"PBE-SHA1-3DES","pbeWithSHA1And3-KeyTripleDES-CBC",
	NID_pbe_WithSHA1And3_Key_TripleDES_CBC,10,&(lvalues[778]),0},
{"PBE-SHA1-2DES","pbeWithSHA1And2-KeyTripleDES-CBC",
	NID_pbe_WithSHA1And2_Key_TripleDES_CBC,10,&(lvalues[788]),0},
{"PBE-SHA1-RC2-128","pbeWithSHA1And128BitRC2-CBC",
	NID_pbe_WithSHA1And128BitRC2_CBC,10,&(lvalues[798]),0},
{"PBE-SHA1-RC2-40","pbeWithSHA1And40BitRC2-CBC",
	NID_pbe_WithSHA1And40BitRC2_CBC,10,&(lvalues[808]),0},
{"keyBag","keyBag",NID_keyBag,11,&(lvalues[818]),0},
{"pkcs8ShroudedKeyBag","pkcs8ShroudedKeyBag",NID_pkcs8ShroudedKeyBag,
	11,&(lvalues[829]),0},
{"certBag","certBag",NID_certBag,11,&(lvalues[840]),0},
{"crlBag","crlBag",NID_crlBag,11,&(lvalues[851]),0},
{"secretBag","secretBag",NID_secretBag,11,&(lvalues[862]),0},
{"safeContentsBag","safeContentsBag",NID_safeContentsBag,11,
	&(lvalues[873]),0},
{"friendlyName","friendlyName",NID_friendlyName,9,&(lvalues[884]),0},
{"localKeyID","localKeyID",NID_localKeyID,9,&(lvalues[893]),0},
{"x509Certificate","x509Certificate",NID_x509Certificate,10,
	&(lvalues[902]),0},
{"sdsiCertificate","sdsiCertificate",NID_sdsiCertificate,10,
	&(lvalues[912]),0},
{"x509Crl","x509Crl",NID_x509Crl,10,&(lvalues[922]),0},
{"PBES2","PBES2",NID_pbes2,9,&(lvalues[932]),0},
{"PBMAC1","PBMAC1",NID_pbmac1,9,&(lvalues[941]),0},
{"hmacWithSHA1","hmacWithSHA1",NID_hmacWithSHA1,8,&(lvalues[950]),0},
{"id-qt-cps","Policy Qualifier CPS",NID_id_qt_cps,8,&(lvalues[958]),0},
{"id-qt-unotice","Policy Qualifier User Notice",NID_id_qt_unotice,8,
	&(lvalues[966]),0},
{"RC2-64-CBC","rc2-64-cbc",NID_rc2_64_cbc,0,NULL},
{"SMIME-CAPS","S/MIME Capabilities",NID_SMIMECapabilities,9,
	&(lvalues[974]),0},
{"PBE-MD2-RC2-64","pbeWithMD2AndRC2-CBC",NID_pbeWithMD2AndRC2_CBC,9,
	&(lvalues[983]),0},
{"PBE-MD5-RC2-64","pbeWithMD5AndRC2-CBC",NID_pbeWithMD5AndRC2_CBC,9,
	&(lvalues[992]),0},
{"PBE-SHA1-DES","pbeWithSHA1AndDES-CBC",NID_pbeWithSHA1AndDES_CBC,9,
	&(lvalues[1001]),0},
{"msExtReq","Microsoft Extension Request",NID_ms_ext_req,10,
	&(lvalues[1010]),0},
{"extReq","Extension Request",NID_ext_req,9,&(lvalues[1020]),0},
{"name","name",NID_name,3,&(lvalues[1029]),0},
{"dnQualifier","dnQualifier",NID_dnQualifier,3,&(lvalues[1032]),0},
{"id-pe","id-pe",NID_id_pe,7,&(lvalues[1035]),0},
{"id-ad","id-ad",NID_id_ad,7,&(lvalues[1042]),0},
{"authorityInfoAccess","Authority Information Access",NID_info_access,
	8,&(lvalues[1049]),0},
{"OCSP","OCSP",NID_ad_OCSP,8,&(lvalues[1057]),0},
{"caIssuers","CA Issuers",NID_ad_ca_issuers,8,&(lvalues[1065]),0},
{"OCSPSigning","OCSP Signing",NID_OCSP_sign,8,&(lvalues[1073]),0},
{"ISO","iso",NID_iso,1,&(lvalues[1081]),0},
{"member-body","ISO Member Body",NID_member_body,1,&(lvalues[1082]),0},
{"ISO-US","ISO US Member Body",NID_ISO_US,3,&(lvalues[1083]),0},
{"X9-57","X9.57",NID_X9_57,5,&(lvalues[1086]),0},
{"X9cm","X9.57 CM ?",NID_X9cm,6,&(lvalues[1091]),0},
{"pkcs1","pkcs1",NID_pkcs1,8,&(lvalues[1097]),0},
{"pkcs5","pkcs5",NID_pkcs5,8,&(lvalues[1105]),0},
{"SMIME","S/MIME",NID_SMIME,9,&(lvalues[1113]),0},
{"id-smime-mod","id-smime-mod",NID_id_smime_mod,10,&(lvalues[1122]),0},
{"id-smime-ct","id-smime-ct",NID_id_smime_ct,10,&(lvalues[1132]),0},
{"id-smime-aa","id-smime-aa",NID_id_smime_aa,10,&(lvalues[1142]),0},
{"id-smime-alg","id-smime-alg",NID_id_smime_alg,10,&(lvalues[1152]),0},
{"id-smime-cd","id-smime-cd",NID_id_smime_cd,10,&(lvalues[1162]),0},
{"id-smime-spq","id-smime-spq",NID_id_smime_spq,10,&(lvalues[1172]),0},
{"id-smime-cti","id-smime-cti",NID_id_smime_cti,10,&(lvalues[1182]),0},
{"id-smime-mod-cms","id-smime-mod-cms",NID_id_smime_mod_cms,11,
	&(lvalues[1192]),0},
{"id-smime-mod-ess","id-smime-mod-ess",NID_id_smime_mod_ess,11,
	&(lvalues[1203]),0},
{"id-smime-mod-oid","id-smime-mod-oid",NID_id_smime_mod_oid,11,
	&(lvalues[1214]),0},
{"id-smime-mod-msg-v3","id-smime-mod-msg-v3",NID_id_smime_mod_msg_v3,
	11,&(lvalues[1225]),0},
{"id-smime-mod-ets-eSignature-88","id-smime-mod-ets-eSignature-88",
	NID_id_smime_mod_ets_eSignature_88,11,&(lvalues[1236]),0},
{"id-smime-mod-ets-eSignature-97","id-smime-mod-ets-eSignature-97",
	NID_id_smime_mod_ets_eSignature_97,11,&(lvalues[1247]),0},
{"id-smime-mod-ets-eSigPolicy-88","id-smime-mod-ets-eSigPolicy-88",
	NID_id_smime_mod_ets_eSigPolicy_88,11,&(lvalues[1258]),0},
{"id-smime-mod-ets-eSigPolicy-97","id-smime-mod-ets-eSigPolicy-97",
	NID_id_smime_mod_ets_eSigPolicy_97,11,&(lvalues[1269]),0},
{"id-smime-ct-receipt","id-smime-ct-receipt",NID_id_smime_ct_receipt,
	11,&(lvalues[1280]),0},
{"id-smime-ct-authData","id-smime-ct-authData",
	NID_id_smime_ct_authData,11,&(lvalues[1291]),0},
{"id-smime-ct-publishCert","id-smime-ct-publishCert",
	NID_id_smime_ct_publishCert,11,&(lvalues[1302]),0},
{"id-smime-ct-TSTInfo","id-smime-ct-TSTInfo",NID_id_smime_ct_TSTInfo,
	11,&(lvalues[1313]),0},
{"id-smime-ct-TDTInfo","id-smime-ct-TDTInfo",NID_id_smime_ct_TDTInfo,
	11,&(lvalues[1324]),0},
{"id-smime-ct-contentInfo","id-smime-ct-contentInfo",
	NID_id_smime_ct_contentInfo,11,&(lvalues[1335]),0},
{"id-smime-ct-DVCSRequestData","id-smime-ct-DVCSRequestData",
	NID_id_smime_ct_DVCSRequestData,11,&(lvalues[1346]),0},
{"id-smime-ct-DVCSResponseData","id-smime-ct-DVCSResponseData",
	NID_id_smime_ct_DVCSResponseData,11,&(lvalues[1357]),0},
{"id-smime-aa-receiptRequest","id-smime-aa-receiptRequest",
	NID_id_smime_aa_receiptRequest,11,&(lvalues[1368]),0},
{"id-smime-aa-securityLabel","id-smime-aa-securityLabel",
	NID_id_smime_aa_securityLabel,11,&(lvalues[1379]),0},
{"id-smime-aa-mlExpandHistory","id-smime-aa-mlExpandHistory",
	NID_id_smime_aa_mlExpandHistory,11,&(lvalues[1390]),0},
{"id-smime-aa-contentHint","id-smime-aa-contentHint",
	NID_id_smime_aa_contentHint,11,&(lvalues[1401]),0},
{"id-smime-aa-msgSigDigest","id-smime-aa-msgSigDigest",
	NID_id_smime_aa_msgSigDigest,11,&(lvalues[1412]),0},
{"id-smime-aa-encapContentType","id-smime-aa-encapContentType",
	NID_id_smime_aa_encapContentType,11,&(lvalues[1423]),0},
{"id-smime-aa-contentIdentifier","id-smime-aa-contentIdentifier",
	NID_id_smime_aa_contentIdentifier,11,&(lvalues[1434]),0},
{"id-smime-aa-macValue","id-smime-aa-macValue",
	NID_id_smime_aa_macValue,11,&(lvalues[1445]),0},
{"id-smime-aa-equivalentLabels","id-smime-aa-equivalentLabels",
	NID_id_smime_aa_equivalentLabels,11,&(lvalues[1456]),0},
{"id-smime-aa-contentReference","id-smime-aa-contentReference",
	NID_id_smime_aa_contentReference,11,&(lvalues[1467]),0},
{"id-smime-aa-encrypKeyPref","id-smime-aa-encrypKeyPref",
	NID_id_smime_aa_encrypKeyPref,11,&(lvalues[1478]),0},
{"id-smime-aa-signingCertificate","id-smime-aa-signingCertificate",
	NID_id_smime_aa_signingCertificate,11,&(lvalues[1489]),0},
{"id-smime-aa-smimeEncryptCerts","id-smime-aa-smimeEncryptCerts",
	NID_id_smime_aa_smimeEncryptCerts,11,&(lvalues[1500]),0},
{"id-smime-aa-timeStampToken","id-smime-aa-timeStampToken",
	NID_id_smime_aa_timeStampToken,11,&(lvalues[1511]),0},
{"id-smime-aa-ets-sigPolicyId","id-smime-aa-ets-sigPolicyId",
	NID_id_smime_aa_ets_sigPolicyId,11,&(lvalues[1522]),0},
{"id-smime-aa-ets-commitmentType","id-smime-aa-ets-commitmentType",
	NID_id_smime_aa_ets_commitmentType,11,&(lvalues[1533]),0},
{"id-smime-aa-ets-signerLocation","id-smime-aa-ets-signerLocation",
	NID_id_smime_aa_ets_signerLocation,11,&(lvalues[1544]),0},
{"id-smime-aa-ets-signerAttr","id-smime-aa-ets-signerAttr",
	NID_id_smime_aa_ets_signerAttr,11,&(lvalues[1555]),0},
{"id-smime-aa-ets-otherSigCert","id-smime-aa-ets-otherSigCert",
	NID_id_smime_aa_ets_otherSigCert,11,&(lvalues[1566]),0},
{"id-smime-aa-ets-contentTimestamp",
	"id-smime-aa-ets-contentTimestamp",
	NID_id_smime_aa_ets_contentTimestamp,11,&(lvalues[1577]),0},
{"id-smime-aa-ets-CertificateRefs","id-smime-aa-ets-CertificateRefs",
	NID_id_smime_aa_ets_CertificateRefs,11,&(lvalues[1588]),0},
{"id-smime-aa-ets-RevocationRefs","id-smime-aa-ets-RevocationRefs",
	NID_id_smime_aa_ets_RevocationRefs,11,&(lvalues[1599]),0},
{"id-smime-aa-ets-certValues","id-smime-aa-ets-certValues",
	NID_id_smime_aa_ets_certValues,11,&(lvalues[1610]),0},
{"id-smime-aa-ets-revocationValues",
	"id-smime-aa-ets-revocationValues",
	NID_id_smime_aa_ets_revocationValues,11,&(lvalues[1621]),0},
{"id-smime-aa-ets-escTimeStamp","id-smime-aa-ets-escTimeStamp",
	NID_id_smime_aa_ets_escTimeStamp,11,&(lvalues[1632]),0},
{"id-smime-aa-ets-certCRLTimestamp",
	"id-smime-aa-ets-certCRLTimestamp",
	NID_id_smime_aa_ets_certCRLTimestamp,11,&(lvalues[1643]),0},
{"id-smime-aa-ets-archiveTimeStamp",
	"id-smime-aa-ets-archiveTimeStamp",
	NID_id_smime_aa_ets_archiveTimeStamp,11,&(lvalues[1654]),0},
{"id-smime-aa-signatureType","id-smime-aa-signatureType",
	NID_id_smime_aa_signatureType,11,&(lvalues[1665]),0},
{"id-smime-aa-dvcs-dvc","id-smime-aa-dvcs-dvc",
	NID_id_smime_aa_dvcs_dvc,11,&(lvalues[1676]),0},
{"id-smime-alg-ESDHwith3DES","id-smime-alg-ESDHwith3DES",
	NID_id_smime_alg_ESDHwith3DES,11,&(lvalues[1687]),0},
{"id-smime-alg-ESDHwithRC2","id-smime-alg-ESDHwithRC2",
	NID_id_smime_alg_ESDHwithRC2,11,&(lvalues[1698]),0},
{"id-smime-alg-3DESwrap","id-smime-alg-3DESwrap",
	NID_id_smime_alg_3DESwrap,11,&(lvalues[1709]),0},
{"id-smime-alg-RC2wrap","id-smime-alg-RC2wrap",
	NID_id_smime_alg_RC2wrap,11,&(lvalues[1720]),0},
{"id-smime-alg-ESDH","id-smime-alg-ESDH",NID_id_smime_alg_ESDH,11,
	&(lvalues[1731]),0},
{"id-smime-alg-CMS3DESwrap","id-smime-alg-CMS3DESwrap",
	NID_id_smime_alg_CMS3DESwrap,11,&(lvalues[1742]),0},
{"id-smime-alg-CMSRC2wrap","id-smime-alg-CMSRC2wrap",
	NID_id_smime_alg_CMSRC2wrap,11,&(lvalues[1753]),0},
{"id-smime-cd-ldap","id-smime-cd-ldap",NID_id_smime_cd_ldap,11,
	&(lvalues[1764]),0},
{"id-smime-spq-ets-sqt-uri","id-smime-spq-ets-sqt-uri",
	NID_id_smime_spq_ets_sqt_uri,11,&(lvalues[1775]),0},
{"id-smime-spq-ets-sqt-unotice","id-smime-spq-ets-sqt-unotice",
	NID_id_smime_spq_ets_sqt_unotice,11,&(lvalues[1786]),0},
{"id-smime-cti-ets-proofOfOrigin","id-smime-cti-ets-proofOfOrigin",
	NID_id_smime_cti_ets_proofOfOrigin,11,&(lvalues[1797]),0},
{"id-smime-cti-ets-proofOfReceipt","id-smime-cti-ets-proofOfReceipt",
	NID_id_smime_cti_ets_proofOfReceipt,11,&(lvalues[1808]),0},
{"id-smime-cti-ets-proofOfDelivery",
	"id-smime-cti-ets-proofOfDelivery",
	NID_id_smime_cti_ets_proofOfDelivery,11,&(lvalues[1819]),0},
{"id-smime-cti-ets-proofOfSender","id-smime-cti-ets-proofOfSender",
	NID_id_smime_cti_ets_proofOfSender,11,&(lvalues[1830]),0},
{"id-smime-cti-ets-proofOfApproval",
	"id-smime-cti-ets-proofOfApproval",
	NID_id_smime_cti_ets_proofOfApproval,11,&(lvalues[1841]),0},
{"id-smime-cti-ets-proofOfCreation",
	"id-smime-cti-ets-proofOfCreation",
	NID_id_smime_cti_ets_proofOfCreation,11,&(lvalues[1852]),0},
{"MD4","md4",NID_md4,8,&(lvalues[1863]),0},
{"id-pkix-mod","id-pkix-mod",NID_id_pkix_mod,7,&(lvalues[1871]),0},
{"id-qt","id-qt",NID_id_qt,7,&(lvalues[1878]),0},
{"id-it","id-it",NID_id_it,7,&(lvalues[1885]),0},
{"id-pkip","id-pkip",NID_id_pkip,7,&(lvalues[1892]),0},
{"id-alg","id-alg",NID_id_alg,7,&(lvalues[1899]),0},
{"id-cmc","id-cmc",NID_id_cmc,7,&(lvalues[1906]),0},
{"id-on","id-on",NID_id_on,7,&(lvalues[1913]),0},
{"id-pda","id-pda",NID_id_pda,7,&(lvalues[1920]),0},
{"id-aca","id-aca",NID_id_aca,7,&(lvalues[1927]),0},
{"id-qcs","id-qcs",NID_id_qcs,7,&(lvalues[1934]),0},
{"id-cct","id-cct",NID_id_cct,7,&(lvalues[1941]),0},
{"id-pkix1-explicit-88","id-pkix1-explicit-88",
	NID_id_pkix1_explicit_88,8,&(lvalues[1948]),0},
{"id-pkix1-implicit-88","id-pkix1-implicit-88",
	NID_id_pkix1_implicit_88,8,&(lvalues[1956]),0},
{"id-pkix1-explicit-93","id-pkix1-explicit-93",
	NID_id_pkix1_explicit_93,8,&(lvalues[1964]),0},
{"id-pkix1-implicit-93","id-pkix1-implicit-93",
	NID_id_pkix1_implicit_93,8,&(lvalues[1972]),0},
{"id-mod-crmf","id-mod-crmf",NID_id_mod_crmf,8,&(lvalues[1980]),0},
{"id-mod-cmc","id-mod-cmc",NID_id_mod_cmc,8,&(lvalues[1988]),0},
{"id-mod-kea-profile-88","id-mod-kea-profile-88",
	NID_id_mod_kea_profile_88,8,&(lvalues[1996]),0},
{"id-mod-kea-profile-93","id-mod-kea-profile-93",
	NID_id_mod_kea_profile_93,8,&(lvalues[2004]),0},
{"id-mod-cmp","id-mod-cmp",NID_id_mod_cmp,8,&(lvalues[2012]),0},
{"id-mod-qualified-cert-88","id-mod-qualified-cert-88",
	NID_id_mod_qualified_cert_88,8,&(lvalues[2020]),0},
{"id-mod-qualified-cert-93","id-mod-qualified-cert-93",
	NID_id_mod_qualified_cert_93,8,&(lvalues[2028]),0},
{"id-mod-attribute-cert","id-mod-attribute-cert",
	NID_id_mod_attribute_cert,8,&(lvalues[2036]),0},
{"id-mod-timestamp-protocol","id-mod-timestamp-protocol",
	NID_id_mod_timestamp_protocol,8,&(lvalues[2044]),0},
{"id-mod-ocsp","id-mod-ocsp",NID_id_mod_ocsp,8,&(lvalues[2052]),0},
{"id-mod-dvcs","id-mod-dvcs",NID_id_mod_dvcs,8,&(lvalues[2060]),0},
{"id-mod-cmp2000","id-mod-cmp2000",NID_id_mod_cmp2000,8,
	&(lvalues[2068]),0},
{"biometricInfo","Biometric Info",NID_biometricInfo,8,&(lvalues[2076]),0},
{"qcStatements","qcStatements",NID_qcStatements,8,&(lvalues[2084]),0},
{"ac-auditEntity","ac-auditEntity",NID_ac_auditEntity,8,
	&(lvalues[2092]),0},
{"ac-targeting","ac-targeting",NID_ac_targeting,8,&(lvalues[2100]),0},
{"aaControls","aaControls",NID_aaControls,8,&(lvalues[2108]),0},
{"sbqp-ipAddrBlock","sbqp-ipAddrBlock",NID_sbqp_ipAddrBlock,8,
	&(lvalues[2116]),0},
{"sbqp-autonomousSysNum","sbqp-autonomousSysNum",
	NID_sbqp_autonomousSysNum,8,&(lvalues[2124]),0},
{"sbqp-routerIdentifier","sbqp-routerIdentifier",
	NID_sbqp_routerIdentifier,8,&(lvalues[2132]),0},
{"textNotice","textNotice",NID_textNotice,8,&(lvalues[2140]),0},
{"ipsecEndSystem","IPSec End System",NID_ipsecEndSystem,8,
	&(lvalues[2148]),0},
{"ipsecTunnel","IPSec Tunnel",NID_ipsecTunnel,8,&(lvalues[2156]),0},
{"ipsecUser","IPSec User",NID_ipsecUser,8,&(lvalues[2164]),0},
{"DVCS","dvcs",NID_dvcs,8,&(lvalues[2172]),0},
{"id-it-caProtEncCert","id-it-caProtEncCert",NID_id_it_caProtEncCert,
	8,&(lvalues[2180]),0},
{"id-it-signKeyPairTypes","id-it-signKeyPairTypes",
	NID_id_it_signKeyPairTypes,8,&(lvalues[2188]),0},
{"id-it-encKeyPairTypes","id-it-encKeyPairTypes",
	NID_id_it_encKeyPairTypes,8,&(lvalues[2196]),0},
{"id-it-preferredSymmAlg","id-it-preferredSymmAlg",
	NID_id_it_preferredSymmAlg,8,&(lvalues[2204]),0},
{"id-it-caKeyUpdateInfo","id-it-caKeyUpdateInfo",
	NID_id_it_caKeyUpdateInfo,8,&(lvalues[2212]),0},
{"id-it-currentCRL","id-it-currentCRL",NID_id_it_currentCRL,8,
	&(lvalues[2220]),0},
{"id-it-unsupportedOIDs","id-it-unsupportedOIDs",
	NID_id_it_unsupportedOIDs,8,&(lvalues[2228]),0},
{"id-it-subscriptionRequest","id-it-subscriptionRequest",
	NID_id_it_subscriptionRequest,8,&(lvalues[2236]),0},
{"id-it-subscriptionResponse","id-it-subscriptionResponse",
	NID_id_it_subscriptionResponse,8,&(lvalues[2244]),0},
{"id-it-keyPairParamReq","id-it-keyPairParamReq",
	NID_id_it_keyPairParamReq,8,&(lvalues[2252]),0},
{"id-it-keyPairParamRep","id-it-keyPairParamRep",
	NID_id_it_keyPairParamRep,8,&(lvalues[2260]),0},
{"id-it-revPassphrase","id-it-revPassphrase",NID_id_it_revPassphrase,
	8,&(lvalues[2268]),0},
{"id-it-implicitConfirm","id-it-implicitConfirm",
	NID_id_it_implicitConfirm,8,&(lvalues[2276]),0},
{"id-it-confirmWaitTime","id-it-confirmWaitTime",
	NID_id_it_confirmWaitTime,8,&(lvalues[2284]),0},
{"id-it-origPKIMessage","id-it-origPKIMessage",
	NID_id_it_origPKIMessage,8,&(lvalues[2292]),0},
{"id-regCtrl","id-regCtrl",NID_id_regCtrl,8,&(lvalues[2300]),0},
{"id-regInfo","id-regInfo",NID_id_regInfo,8,&(lvalues[2308]),0},
{"id-regCtrl-regToken","id-regCtrl-regToken",NID_id_regCtrl_regToken,
	9,&(lvalues[2316]),0},
{"id-regCtrl-authenticator","id-regCtrl-authenticator",
	NID_id_regCtrl_authenticator,9,&(lvalues[2325]),0},
{"id-regCtrl-pkiPublicationInfo","id-regCtrl-pkiPublicationInfo",
	NID_id_regCtrl_pkiPublicationInfo,9,&(lvalues[2334]),0},
{"id-regCtrl-pkiArchiveOptions","id-regCtrl-pkiArchiveOptions",
	NID_id_regCtrl_pkiArchiveOptions,9,&(lvalues[2343]),0},
{"id-regCtrl-oldCertID","id-regCtrl-oldCertID",
	NID_id_regCtrl_oldCertID,9,&(lvalues[2352]),0},
{"id-regCtrl-protocolEncrKey","id-regCtrl-protocolEncrKey",
	NID_id_regCtrl_protocolEncrKey,9,&(lvalues[2361]),0},
{"id-regInfo-utf8Pairs","id-regInfo-utf8Pairs",
	NID_id_regInfo_utf8Pairs,9,&(lvalues[2370]),0},
{"id-regInfo-certReq","id-regInfo-certReq",NID_id_regInfo_certReq,9,
	&(lvalues[2379]),0},
{"id-alg-des40","id-alg-des40",NID_id_alg_des40,8,&(lvalues[2388]),0},
{"id-alg-noSignature","id-alg-noSignature",NID_id_alg_noSignature,8,
	&(lvalues[2396]),0},
{"id-alg-dh-sig-hmac-sha1","id-alg-dh-sig-hmac-sha1",
	NID_id_alg_dh_sig_hmac_sha1,8,&(lvalues[2404]),0},
{"id-alg-dh-pop","id-alg-dh-pop",NID_id_alg_dh_pop,8,&(lvalues[2412]),0},
{"id-cmc-statusInfo","id-cmc-statusInfo",NID_id_cmc_statusInfo,8,
	&(lvalues[2420]),0},
{"id-cmc-identification","id-cmc-identification",
	NID_id_cmc_identification,8,&(lvalues[2428]),0},
{"id-cmc-identityProof","id-cmc-identityProof",
	NID_id_cmc_identityProof,8,&(lvalues[2436]),0},
{"id-cmc-dataReturn","id-cmc-dataReturn",NID_id_cmc_dataReturn,8,
	&(lvalues[2444]),0},
{"id-cmc-transactionId","id-cmc-transactionId",
	NID_id_cmc_transactionId,8,&(lvalues[2452]),0},
{"id-cmc-senderNonce","id-cmc-senderNonce",NID_id_cmc_senderNonce,8,
	&(lvalues[2460]),0},
{"id-cmc-recipientNonce","id-cmc-recipientNonce",
	NID_id_cmc_recipientNonce,8,&(lvalues[2468]),0},
{"id-cmc-addExtensions","id-cmc-addExtensions",
	NID_id_cmc_addExtensions,8,&(lvalues[2476]),0},
{"id-cmc-encryptedPOP","id-cmc-encryptedPOP",NID_id_cmc_encryptedPOP,
	8,&(lvalues[2484]),0},
{"id-cmc-decryptedPOP","id-cmc-decryptedPOP",NID_id_cmc_decryptedPOP,
	8,&(lvalues[2492]),0},
{"id-cmc-lraPOPWitness","id-cmc-lraPOPWitness",
	NID_id_cmc_lraPOPWitness,8,&(lvalues[2500]),0},
{"id-cmc-getCert","id-cmc-getCert",NID_id_cmc_getCert,8,
	&(lvalues[2508]),0},
{"id-cmc-getCRL","id-cmc-getCRL",NID_id_cmc_getCRL,8,&(lvalues[2516]),0},
{"id-cmc-revokeRequest","id-cmc-revokeRequest",
	NID_id_cmc_revokeRequest,8,&(lvalues[2524]),0},
{"id-cmc-regInfo","id-cmc-regInfo",NID_id_cmc_regInfo,8,
	&(lvalues[2532]),0},
{"id-cmc-responseInfo","id-cmc-responseInfo",NID_id_cmc_responseInfo,
	8,&(lvalues[2540]),0},
{"id-cmc-queryPending","id-cmc-queryPending",NID_id_cmc_queryPending,
	8,&(lvalues[2548]),0},
{"id-cmc-popLinkRandom","id-cmc-popLinkRandom",
	NID_id_cmc_popLinkRandom,8,&(lvalues[2556]),0},
{"id-cmc-popLinkWitness","id-cmc-popLinkWitness",
	NID_id_cmc_popLinkWitness,8,&(lvalues[2564]),0},
{"id-cmc-confirmCertAcceptance","id-cmc-confirmCertAcceptance",
	NID_id_cmc_confirmCertAcceptance,8,&(lvalues[2572]),0},
{"id-on-personalData","id-on-personalData",NID_id_on_personalData,8,
	&(lvalues[2580]),0},
{"id-pda-dateOfBirth","id-pda-dateOfBirth",NID_id_pda_dateOfBirth,8,
	&(lvalues[2588]),0},
{"id-pda-placeOfBirth","id-pda-placeOfBirth",NID_id_pda_placeOfBirth,
	8,&(lvalues[2596]),0},
{NULL,NULL,NID_undef,0,NULL},
{"id-pda-gender","id-pda-gender",NID_id_pda_gender,8,&(lvalues[2604]),0},
{"id-pda-countryOfCitizenship","id-pda-countryOfCitizenship",
	NID_id_pda_countryOfCitizenship,8,&(lvalues[2612]),0},
{"id-pda-countryOfResidence","id-pda-countryOfResidence",
	NID_id_pda_countryOfResidence,8,&(lvalues[2620]),0},
{"id-aca-authenticationInfo","id-aca-authenticationInfo",
	NID_id_aca_authenticationInfo,8,&(lvalues[2628]),0},
{"id-aca-accessIdentity","id-aca-accessIdentity",
	NID_id_aca_accessIdentity,8,&(lvalues[2636]),0},
{"id-aca-chargingIdentity","id-aca-chargingIdentity",
	NID_id_aca_chargingIdentity,8,&(lvalues[2644]),0},
{"id-aca-group","id-aca-group",NID_id_aca_group,8,&(lvalues[2652]),0},
{"id-aca-role","id-aca-role",NID_id_aca_role,8,&(lvalues[2660]),0},
{"id-qcs-pkixQCSyntax-v1","id-qcs-pkixQCSyntax-v1",
	NID_id_qcs_pkixQCSyntax_v1,8,&(lvalues[2668]),0},
{"id-cct-crs","id-cct-crs",NID_id_cct_crs,8,&(lvalues[2676]),0},
{"id-cct-PKIData","id-cct-PKIData",NID_id_cct_PKIData,8,
	&(lvalues[2684]),0},
{"id-cct-PKIResponse","id-cct-PKIResponse",NID_id_cct_PKIResponse,8,
	&(lvalues[2692]),0},
{"ad_timestamping","AD Time Stamping",NID_ad_timeStamping,8,
	&(lvalues[2700]),0},
{"AD_DVCS","ad dvcs",NID_ad_dvcs,8,&(lvalues[2708]),0},
{"basicOCSPResponse","Basic OCSP Response",NID_id_pkix_OCSP_basic,9,
	&(lvalues[2716]),0},
{"Nonce","OCSP Nonce",NID_id_pkix_OCSP_Nonce,9,&(lvalues[2725]),0},
{"CrlID","OCSP CRL ID",NID_id_pkix_OCSP_CrlID,9,&(lvalues[2734]),0},
{"acceptableResponses","Acceptable OCSP Responses",
	NID_id_pkix_OCSP_acceptableResponses,9,&(lvalues[2743]),0},
{"noCheck","OCSP No Check",NID_id_pkix_OCSP_noCheck,9,&(lvalues[2752]),0},
{"archiveCutoff","OCSP Archive Cutoff",NID_id_pkix_OCSP_archiveCutoff,
	9,&(lvalues[2761]),0},
{"serviceLocator","OCSP Service Locator",
	NID_id_pkix_OCSP_serviceLocator,9,&(lvalues[2770]),0},
{"extendedStatus","Extended OCSP Status",
	NID_id_pkix_OCSP_extendedStatus,9,&(lvalues[2779]),0},
{"valid","valid",NID_id_pkix_OCSP_valid,9,&(lvalues[2788]),0},
{"path","path",NID_id_pkix_OCSP_path,9,&(lvalues[2797]),0},
{"trustRoot","Trust Root",NID_id_pkix_OCSP_trustRoot,9,
	&(lvalues[2806]),0},
{"algorithm","algorithm",NID_algorithm,4,&(lvalues[2815]),0},
{"rsaSignature","rsaSignature",NID_rsaSignature,5,&(lvalues[2819]),0},
{"X500algorithms","directory services - algorithms",
	NID_X500algorithms,2,&(lvalues[2824]),0},
{"ORG","org",NID_org,1,&(lvalues[2826]),0},
{"DOD","dod",NID_dod,2,&(lvalues[2827]),0},
{"IANA","iana",NID_iana,3,&(lvalues[2829]),0},
{"directory","Directory",NID_Directory,4,&(lvalues[2832]),0},
{"mgmt","Management",NID_Management,4,&(lvalues[2836]),0},
{"experimental","Experimental",NID_Experimental,4,&(lvalues[2840]),0},
{"private","Private",NID_Private,4,&(lvalues[2844]),0},
{"security","Security",NID_Security,4,&(lvalues[2848]),0},
{"snmpv2","SNMPv2",NID_SNMPv2,4,&(lvalues[2852]),0},
{"Mail","Mail",NID_Mail,4,&(lvalues[2856]),0},
{"enterprises","Enterprises",NID_Enterprises,5,&(lvalues[2860]),0},
{"dcobject","dcObject",NID_dcObject,9,&(lvalues[2865]),0},
{"DC","domainComponent",NID_domainComponent,10,&(lvalues[2874]),0},
{"domain","Domain",NID_Domain,10,&(lvalues[2884]),0},
{"JOINT-ISO-CCITT","joint-iso-ccitt",NID_joint_iso_ccitt,1,
	&(lvalues[2894]),0},
{"selected-attribute-types","Selected Attribute Types",
	NID_selected_attribute_types,3,&(lvalues[2895]),0},
{"clearance","clearance",NID_clearance,4,&(lvalues[2898]),0},
{"RSA-MD4","md4WithRSAEncryption",NID_md4WithRSAEncryption,9,
	&(lvalues[2902]),0},
{"ac-proxying","ac-proxying",NID_ac_proxying,8,&(lvalues[2911]),0},
{"subjectInfoAccess","Subject Information Access",NID_sinfo_access,8,
	&(lvalues[2919]),0},
{"id-aca-encAttrs","id-aca-encAttrs",NID_id_aca_encAttrs,8,
	&(lvalues[2927]),0},
{"role","role",NID_role,3,&(lvalues[2935]),0},
{"policyConstraints","X509v3 Policy Constraints",
	NID_policy_constraints,3,&(lvalues[2938]),0},
{"targetInformation","X509v3 AC Targeting",NID_target_information,3,
	&(lvalues[2941]),0},
{"noRevAvail","X509v3 No Revocation Available",NID_no_rev_avail,3,
	&(lvalues[2944]),0},
{"CCITT","ccitt",NID_ccitt,1,&(lvalues[2947]),0},
{"ansi-X9-62","ANSI X9.62",NID_ansi_X9_62,5,&(lvalues[2948]),0},
{"prime-field","prime-field",NID_X9_62_prime_field,7,&(lvalues[2953]),0},
{"characteristic-two-field","characteristic-two-field",
	NID_X9_62_characteristic_two_field,7,&(lvalues[2960]),0},
{"id-ecPublicKey","id-ecPublicKey",NID_X9_62_id_ecPublicKey,7,
	&(lvalues[2967]),0},
{"prime192v1","prime192v1",NID_X9_62_prime192v1,8,&(lvalues[2974]),0},
{"prime192v2","prime192v2",NID_X9_62_prime192v2,8,&(lvalues[2982]),0},
{"prime192v3","prime192v3",NID_X9_62_prime192v3,8,&(lvalues[2990]),0},
{"prime239v1","prime239v1",NID_X9_62_prime239v1,8,&(lvalues[2998]),0},
{"prime239v2","prime239v2",NID_X9_62_prime239v2,8,&(lvalues[3006]),0},
{"prime239v3","prime239v3",NID_X9_62_prime239v3,8,&(lvalues[3014]),0},
{"prime256v1","prime256v1",NID_X9_62_prime256v1,8,&(lvalues[3022]),0},
{"ecdsa-with-SHA1","ecdsa-with-SHA1",NID_ecdsa_with_SHA1,7,
	&(lvalues[3030]),0},
{"CSPName","Microsoft CSP Name",NID_ms_csp_name,9,&(lvalues[3037]),0},
{"AES-128-ECB","aes-128-ecb",NID_aes_128_ecb,9,&(lvalues[3046]),0},
{"AES-128-CBC","aes-128-cbc",NID_aes_128_cbc,9,&(lvalues[3055]),0},
{"AES-128-OFB","aes-128-ofb",NID_aes_128_ofb128,9,&(lvalues[3064]),0},
{"AES-128-CFB","aes-128-cfb",NID_aes_128_cfb128,9,&(lvalues[3073]),0},
{"AES-192-ECB","aes-192-ecb",NID_aes_192_ecb,9,&(lvalues[3082]),0},
{"AES-192-CBC","aes-192-cbc",NID_aes_192_cbc,9,&(lvalues[3091]),0},
{"AES-192-OFB","aes-192-ofb",NID_aes_192_ofb128,9,&(lvalues[3100]),0},
{"AES-192-CFB","aes-192-cfb",NID_aes_192_cfb128,9,&(lvalues[3109]),0},
{"AES-256-ECB","aes-256-ecb",NID_aes_256_ecb,9,&(lvalues[3118]),0},
{"AES-256-CBC","aes-256-cbc",NID_aes_256_cbc,9,&(lvalues[3127]),0},
{"AES-256-OFB","aes-256-ofb",NID_aes_256_ofb128,9,&(lvalues[3136]),0},
{"AES-256-CFB","aes-256-cfb",NID_aes_256_cfb128,9,&(lvalues[3145]),0},
{"holdInstructionCode","Hold Instruction Code",
	NID_hold_instruction_code,3,&(lvalues[3154]),0},
{"holdInstructionNone","Hold Instruction None",
	NID_hold_instruction_none,7,&(lvalues[3157]),0},
{"holdInstructionCallIssuer","Hold Instruction Call Issuer",
	NID_hold_instruction_call_issuer,7,&(lvalues[3164]),0},
{"holdInstructionReject","Hold Instruction Reject",
	NID_hold_instruction_reject,7,&(lvalues[3171]),0},
{"data","data",NID_data,1,&(lvalues[3178]),0},
{"pss","pss",NID_pss,3,&(lvalues[3179]),0},
{"ucl","ucl",NID_ucl,7,&(lvalues[3182]),0},
{"pilot","pilot",NID_pilot,8,&(lvalues[3189]),0},
{"pilotAttributeType","pilotAttributeType",NID_pilotAttributeType,9,
	&(lvalues[3197]),0},
{"pilotAttributeSyntax","pilotAttributeSyntax",
	NID_pilotAttributeSyntax,9,&(lvalues[3206]),0},
{"pilotObjectClass","pilotObjectClass",NID_pilotObjectClass,9,
	&(lvalues[3215]),0},
{"pilotGroups","pilotGroups",NID_pilotGroups,9,&(lvalues[3224]),0},
{"iA5StringSyntax","iA5StringSyntax",NID_iA5StringSyntax,10,
	&(lvalues[3233]),0},
{"caseIgnoreIA5StringSyntax","caseIgnoreIA5StringSyntax",
	NID_caseIgnoreIA5StringSyntax,10,&(lvalues[3243]),0},
{"pilotObject","pilotObject",NID_pilotObject,10,&(lvalues[3253]),0},
{"pilotPerson","pilotPerson",NID_pilotPerson,10,&(lvalues[3263]),0},
{"account","account",NID_account,10,&(lvalues[3273]),0},
{"document","document",NID_document,10,&(lvalues[3283]),0},
{"room","room",NID_room,10,&(lvalues[3293]),0},
{"documentSeries","documentSeries",NID_documentSeries,10,
	&(lvalues[3303]),0},
{"rFC822localPart","rFC822localPart",NID_rFC822localPart,10,
	&(lvalues[3313]),0},
{"dNSDomain","dNSDomain",NID_dNSDomain,10,&(lvalues[3323]),0},
{"domainRelatedObject","domainRelatedObject",NID_domainRelatedObject,
	10,&(lvalues[3333]),0},
{"friendlyCountry","friendlyCountry",NID_friendlyCountry,10,
	&(lvalues[3343]),0},
{"simpleSecurityObject","simpleSecurityObject",
	NID_simpleSecurityObject,10,&(lvalues[3353]),0},
{"pilotOrganization","pilotOrganization",NID_pilotOrganization,10,
	&(lvalues[3363]),0},
{"pilotDSA","pilotDSA",NID_pilotDSA,10,&(lvalues[3373]),0},
{"qualityLabelledData","qualityLabelledData",NID_qualityLabelledData,
	10,&(lvalues[3383]),0},
{"UID","userId",NID_userId,10,&(lvalues[3393]),0},
{"textEncodedORAddress","textEncodedORAddress",
	NID_textEncodedORAddress,10,&(lvalues[3403]),0},
{"mail","rfc822Mailbox",NID_rfc822Mailbox,10,&(lvalues[3413]),0},
{"info","info",NID_info,10,&(lvalues[3423]),0},
{"favouriteDrink","favouriteDrink",NID_favouriteDrink,10,
	&(lvalues[3433]),0},
{"roomNumber","roomNumber",NID_roomNumber,10,&(lvalues[3443]),0},
{"photo","photo",NID_photo,10,&(lvalues[3453]),0},
{"userClass","userClass",NID_userClass,10,&(lvalues[3463]),0},
{"host","host",NID_host,10,&(lvalues[3473]),0},
{"manager","manager",NID_manager,10,&(lvalues[3483]),0},
{"documentIdentifier","documentIdentifier",NID_documentIdentifier,10,
	&(lvalues[3493]),0},
{"documentTitle","documentTitle",NID_documentTitle,10,&(lvalues[3503]),0},
{"documentVersion","documentVersion",NID_documentVersion,10,
	&(lvalues[3513]),0},
{"documentAuthor","documentAuthor",NID_documentAuthor,10,
	&(lvalues[3523]),0},
{"documentLocation","documentLocation",NID_documentLocation,10,
	&(lvalues[3533]),0},
{"homeTelephoneNumber","homeTelephoneNumber",NID_homeTelephoneNumber,
	10,&(lvalues[3543]),0},
{"secretary","secretary",NID_secretary,10,&(lvalues[3553]),0},
{"otherMailbox","otherMailbox",NID_otherMailbox,10,&(lvalues[3563]),0},
{"lastModifiedTime","lastModifiedTime",NID_lastModifiedTime,10,
	&(lvalues[3573]),0},
{"lastModifiedBy","lastModifiedBy",NID_lastModifiedBy,10,
	&(lvalues[3583]),0},
{"aRecord","aRecord",NID_aRecord,10,&(lvalues[3593]),0},
{"pilotAttributeType27","pilotAttributeType27",
	NID_pilotAttributeType27,10,&(lvalues[3603]),0},
{"mXRecord","mXRecord",NID_mXRecord,10,&(lvalues[3613]),0},
{"nSRecord","nSRecord",NID_nSRecord,10,&(lvalues[3623]),0},
{"sOARecord","sOARecord",NID_sOARecord,10,&(lvalues[3633]),0},
{"cNAMERecord","cNAMERecord",NID_cNAMERecord,10,&(lvalues[3643]),0},
{"associatedDomain","associatedDomain",NID_associatedDomain,10,
	&(lvalues[3653]),0},
{"associatedName","associatedName",NID_associatedName,10,
	&(lvalues[3663]),0},
{"homePostalAddress","homePostalAddress",NID_homePostalAddress,10,
	&(lvalues[3673]),0},
{"personalTitle","personalTitle",NID_personalTitle,10,&(lvalues[3683]),0},
{"mobileTelephoneNumber","mobileTelephoneNumber",
	NID_mobileTelephoneNumber,10,&(lvalues[3693]),0},
{"pagerTelephoneNumber","pagerTelephoneNumber",
	NID_pagerTelephoneNumber,10,&(lvalues[3703]),0},
{"friendlyCountryName","friendlyCountryName",NID_friendlyCountryName,
	10,&(lvalues[3713]),0},
{"organizationalStatus","organizationalStatus",
	NID_organizationalStatus,10,&(lvalues[3723]),0},
{"janetMailbox","janetMailbox",NID_janetMailbox,10,&(lvalues[3733]),0},
{"mailPreferenceOption","mailPreferenceOption",
	NID_mailPreferenceOption,10,&(lvalues[3743]),0},
{"buildingName","buildingName",NID_buildingName,10,&(lvalues[3753]),0},
{"dSAQuality","dSAQuality",NID_dSAQuality,10,&(lvalues[3763]),0},
{"singleLevelQuality","singleLevelQuality",NID_singleLevelQuality,10,
	&(lvalues[3773]),0},
{"subtreeMinimumQuality","subtreeMinimumQuality",
	NID_subtreeMinimumQuality,10,&(lvalues[3783]),0},
{"subtreeMaximumQuality","subtreeMaximumQuality",
	NID_subtreeMaximumQuality,10,&(lvalues[3793]),0},
{"personalSignature","personalSignature",NID_personalSignature,10,
	&(lvalues[3803]),0},
{"dITRedirect","dITRedirect",NID_dITRedirect,10,&(lvalues[3813]),0},
{"audio","audio",NID_audio,10,&(lvalues[3823]),0},
{"documentPublisher","documentPublisher",NID_documentPublisher,10,
	&(lvalues[3833]),0},
{"x500UniqueIdentifier","x500UniqueIdentifier",
	NID_x500UniqueIdentifier,3,&(lvalues[3843]),0},
{"mime-mhs","MIME MHS",NID_mime_mhs,5,&(lvalues[3846]),0},
{"mime-mhs-headings","mime-mhs-headings",NID_mime_mhs_headings,6,
	&(lvalues[3851]),0},
{"mime-mhs-bodies","mime-mhs-bodies",NID_mime_mhs_bodies,6,
	&(lvalues[3857]),0},
{"id-hex-partial-message","id-hex-partial-message",
	NID_id_hex_partial_message,7,&(lvalues[3863]),0},
{"id-hex-multipart-message","id-hex-multipart-message",
	NID_id_hex_multipart_message,7,&(lvalues[3870]),0},
{"generationQualifier","generationQualifier",NID_generationQualifier,
	3,&(lvalues[3877]),0},
};

static ASN1_OBJECT *sn_objs[NUM_SN]={
&(nid_objs[364]),/* "AD_DVCS" */
&(nid_objs[419]),/* "AES-128-CBC" */
&(nid_objs[421]),/* "AES-128-CFB" */
&(nid_objs[418]),/* "AES-128-ECB" */
&(nid_objs[420]),/* "AES-128-OFB" */
&(nid_objs[423]),/* "AES-192-CBC" */
&(nid_objs[425]),/* "AES-192-CFB" */
&(nid_objs[422]),/* "AES-192-ECB" */
&(nid_objs[424]),/* "AES-192-OFB" */
&(nid_objs[427]),/* "AES-256-CBC" */
&(nid_objs[429]),/* "AES-256-CFB" */
&(nid_objs[426]),/* "AES-256-ECB" */
&(nid_objs[428]),/* "AES-256-OFB" */
&(nid_objs[91]),/* "BF-CBC" */
&(nid_objs[93]),/* "BF-CFB" */
&(nid_objs[92]),/* "BF-ECB" */
&(nid_objs[94]),/* "BF-OFB" */
&(nid_objs[14]),/* "C" */
&(nid_objs[108]),/* "CAST5-CBC" */
&(nid_objs[110]),/* "CAST5-CFB" */
&(nid_objs[109]),/* "CAST5-ECB" */
&(nid_objs[111]),/* "CAST5-OFB" */
&(nid_objs[404]),/* "CCITT" */
&(nid_objs[13]),/* "CN" */
&(nid_objs[141]),/* "CRLReason" */
&(nid_objs[417]),/* "CSPName" */
&(nid_objs[367]),/* "CrlID" */
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
&(nid_objs[388]),/* "Mail" */
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
&(nid_objs[41]),/* "SHA" */
&(nid_objs[64]),/* "SHA1" */
&(nid_objs[188]),/* "SMIME" */
&(nid_objs[167]),/* "SMIME-CAPS" */
&(nid_objs[100]),/* "SN" */
&(nid_objs[16]),/* "ST" */
&(nid_objs[143]),/* "SXNetID" */
&(nid_objs[458]),/* "UID" */
&(nid_objs[ 0]),/* "UNDEF" */
&(nid_objs[11]),/* "X500" */
&(nid_objs[378]),/* "X500algorithms" */
&(nid_objs[12]),/* "X509" */
&(nid_objs[184]),/* "X9-57" */
&(nid_objs[185]),/* "X9cm" */
&(nid_objs[125]),/* "ZLIB" */
&(nid_objs[478]),/* "aRecord" */
&(nid_objs[289]),/* "aaControls" */
&(nid_objs[287]),/* "ac-auditEntity" */
&(nid_objs[397]),/* "ac-proxying" */
&(nid_objs[288]),/* "ac-targeting" */
&(nid_objs[368]),/* "acceptableResponses" */
&(nid_objs[446]),/* "account" */
&(nid_objs[363]),/* "ad_timestamping" */
&(nid_objs[376]),/* "algorithm" */
&(nid_objs[405]),/* "ansi-X9-62" */
&(nid_objs[370]),/* "archiveCutoff" */
&(nid_objs[484]),/* "associatedDomain" */
&(nid_objs[485]),/* "associatedName" */
&(nid_objs[501]),/* "audio" */
&(nid_objs[177]),/* "authorityInfoAccess" */
&(nid_objs[90]),/* "authorityKeyIdentifier" */
&(nid_objs[87]),/* "basicConstraints" */
&(nid_objs[365]),/* "basicOCSPResponse" */
&(nid_objs[285]),/* "biometricInfo" */
&(nid_objs[494]),/* "buildingName" */
&(nid_objs[483]),/* "cNAMERecord" */
&(nid_objs[179]),/* "caIssuers" */
&(nid_objs[443]),/* "caseIgnoreIA5StringSyntax" */
&(nid_objs[152]),/* "certBag" */
&(nid_objs[89]),/* "certificatePolicies" */
&(nid_objs[54]),/* "challengePassword" */
&(nid_objs[407]),/* "characteristic-two-field" */
&(nid_objs[395]),/* "clearance" */
&(nid_objs[130]),/* "clientAuth" */
&(nid_objs[131]),/* "codeSigning" */
&(nid_objs[50]),/* "contentType" */
&(nid_objs[53]),/* "countersignature" */
&(nid_objs[153]),/* "crlBag" */
&(nid_objs[103]),/* "crlDistributionPoints" */
&(nid_objs[88]),/* "crlNumber" */
&(nid_objs[500]),/* "dITRedirect" */
&(nid_objs[451]),/* "dNSDomain" */
&(nid_objs[495]),/* "dSAQuality" */
&(nid_objs[434]),/* "data" */
&(nid_objs[390]),/* "dcobject" */
&(nid_objs[140]),/* "deltaCRL" */
&(nid_objs[107]),/* "description" */
&(nid_objs[28]),/* "dhKeyAgreement" */
&(nid_objs[382]),/* "directory" */
&(nid_objs[174]),/* "dnQualifier" */
&(nid_objs[447]),/* "document" */
&(nid_objs[471]),/* "documentAuthor" */
&(nid_objs[468]),/* "documentIdentifier" */
&(nid_objs[472]),/* "documentLocation" */
&(nid_objs[502]),/* "documentPublisher" */
&(nid_objs[449]),/* "documentSeries" */
&(nid_objs[469]),/* "documentTitle" */
&(nid_objs[470]),/* "documentVersion" */
&(nid_objs[392]),/* "domain" */
&(nid_objs[452]),/* "domainRelatedObject" */
&(nid_objs[416]),/* "ecdsa-with-SHA1" */
&(nid_objs[48]),/* "emailAddress" */
&(nid_objs[132]),/* "emailProtection" */
&(nid_objs[389]),/* "enterprises" */
&(nid_objs[384]),/* "experimental" */
&(nid_objs[172]),/* "extReq" */
&(nid_objs[56]),/* "extendedCertificateAttributes" */
&(nid_objs[126]),/* "extendedKeyUsage" */
&(nid_objs[372]),/* "extendedStatus" */
&(nid_objs[462]),/* "favouriteDrink" */
&(nid_objs[453]),/* "friendlyCountry" */
&(nid_objs[490]),/* "friendlyCountryName" */
&(nid_objs[156]),/* "friendlyName" */
&(nid_objs[509]),/* "generationQualifier" */
&(nid_objs[99]),/* "gn" */
&(nid_objs[163]),/* "hmacWithSHA1" */
&(nid_objs[432]),/* "holdInstructionCallIssuer" */
&(nid_objs[430]),/* "holdInstructionCode" */
&(nid_objs[431]),/* "holdInstructionNone" */
&(nid_objs[433]),/* "holdInstructionReject" */
&(nid_objs[486]),/* "homePostalAddress" */
&(nid_objs[473]),/* "homeTelephoneNumber" */
&(nid_objs[466]),/* "host" */
&(nid_objs[442]),/* "iA5StringSyntax" */
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
&(nid_objs[408]),/* "id-ecPublicKey" */
&(nid_objs[508]),/* "id-hex-multipart-message" */
&(nid_objs[507]),/* "id-hex-partial-message" */
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
&(nid_objs[461]),/* "info" */
&(nid_objs[101]),/* "initials" */
&(nid_objs[142]),/* "invalidityDate" */
&(nid_objs[294]),/* "ipsecEndSystem" */
&(nid_objs[295]),/* "ipsecTunnel" */
&(nid_objs[296]),/* "ipsecUser" */
&(nid_objs[86]),/* "issuerAltName" */
&(nid_objs[492]),/* "janetMailbox" */
&(nid_objs[150]),/* "keyBag" */
&(nid_objs[83]),/* "keyUsage" */
&(nid_objs[477]),/* "lastModifiedBy" */
&(nid_objs[476]),/* "lastModifiedTime" */
&(nid_objs[157]),/* "localKeyID" */
&(nid_objs[480]),/* "mXRecord" */
&(nid_objs[460]),/* "mail" */
&(nid_objs[493]),/* "mailPreferenceOption" */
&(nid_objs[467]),/* "manager" */
&(nid_objs[182]),/* "member-body" */
&(nid_objs[51]),/* "messageDigest" */
&(nid_objs[383]),/* "mgmt" */
&(nid_objs[504]),/* "mime-mhs" */
&(nid_objs[506]),/* "mime-mhs-bodies" */
&(nid_objs[505]),/* "mime-mhs-headings" */
&(nid_objs[488]),/* "mobileTelephoneNumber" */
&(nid_objs[136]),/* "msCTLSign" */
&(nid_objs[135]),/* "msCodeCom" */
&(nid_objs[134]),/* "msCodeInd" */
&(nid_objs[138]),/* "msEFS" */
&(nid_objs[171]),/* "msExtReq" */
&(nid_objs[137]),/* "msSGC" */
&(nid_objs[481]),/* "nSRecord" */
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
&(nid_objs[491]),/* "organizationalStatus" */
&(nid_objs[475]),/* "otherMailbox" */
&(nid_objs[489]),/* "pagerTelephoneNumber" */
&(nid_objs[374]),/* "path" */
&(nid_objs[112]),/* "pbeWithMD5AndCast5CBC" */
&(nid_objs[499]),/* "personalSignature" */
&(nid_objs[487]),/* "personalTitle" */
&(nid_objs[464]),/* "photo" */
&(nid_objs[437]),/* "pilot" */
&(nid_objs[439]),/* "pilotAttributeSyntax" */
&(nid_objs[438]),/* "pilotAttributeType" */
&(nid_objs[479]),/* "pilotAttributeType27" */
&(nid_objs[456]),/* "pilotDSA" */
&(nid_objs[441]),/* "pilotGroups" */
&(nid_objs[444]),/* "pilotObject" */
&(nid_objs[440]),/* "pilotObjectClass" */
&(nid_objs[455]),/* "pilotOrganization" */
&(nid_objs[445]),/* "pilotPerson" */
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
&(nid_objs[406]),/* "prime-field" */
&(nid_objs[409]),/* "prime192v1" */
&(nid_objs[410]),/* "prime192v2" */
&(nid_objs[411]),/* "prime192v3" */
&(nid_objs[412]),/* "prime239v1" */
&(nid_objs[413]),/* "prime239v2" */
&(nid_objs[414]),/* "prime239v3" */
&(nid_objs[415]),/* "prime256v1" */
&(nid_objs[385]),/* "private" */
&(nid_objs[84]),/* "privateKeyUsagePeriod" */
&(nid_objs[435]),/* "pss" */
&(nid_objs[286]),/* "qcStatements" */
&(nid_objs[457]),/* "qualityLabelledData" */
&(nid_objs[450]),/* "rFC822localPart" */
&(nid_objs[400]),/* "role" */
&(nid_objs[448]),/* "room" */
&(nid_objs[463]),/* "roomNumber" */
&(nid_objs[ 6]),/* "rsaEncryption" */
&(nid_objs[377]),/* "rsaSignature" */
&(nid_objs[ 1]),/* "rsadsi" */
&(nid_objs[482]),/* "sOARecord" */
&(nid_objs[155]),/* "safeContentsBag" */
&(nid_objs[291]),/* "sbqp-autonomousSysNum" */
&(nid_objs[290]),/* "sbqp-ipAddrBlock" */
&(nid_objs[292]),/* "sbqp-routerIdentifier" */
&(nid_objs[159]),/* "sdsiCertificate" */
&(nid_objs[154]),/* "secretBag" */
&(nid_objs[474]),/* "secretary" */
&(nid_objs[386]),/* "security" */
&(nid_objs[394]),/* "selected-attribute-types" */
&(nid_objs[105]),/* "serialNumber" */
&(nid_objs[129]),/* "serverAuth" */
&(nid_objs[371]),/* "serviceLocator" */
&(nid_objs[52]),/* "signingTime" */
&(nid_objs[454]),/* "simpleSecurityObject" */
&(nid_objs[496]),/* "singleLevelQuality" */
&(nid_objs[387]),/* "snmpv2" */
&(nid_objs[85]),/* "subjectAltName" */
&(nid_objs[398]),/* "subjectInfoAccess" */
&(nid_objs[82]),/* "subjectKeyIdentifier" */
&(nid_objs[498]),/* "subtreeMaximumQuality" */
&(nid_objs[497]),/* "subtreeMinimumQuality" */
&(nid_objs[402]),/* "targetInformation" */
&(nid_objs[459]),/* "textEncodedORAddress" */
&(nid_objs[293]),/* "textNotice" */
&(nid_objs[133]),/* "timeStamping" */
&(nid_objs[106]),/* "title" */
&(nid_objs[375]),/* "trustRoot" */
&(nid_objs[436]),/* "ucl" */
&(nid_objs[55]),/* "unstructuredAddress" */
&(nid_objs[49]),/* "unstructuredName" */
&(nid_objs[465]),/* "userClass" */
&(nid_objs[373]),/* "valid" */
&(nid_objs[503]),/* "x500UniqueIdentifier" */
&(nid_objs[158]),/* "x509Certificate" */
&(nid_objs[160]),/* "x509Crl" */
};

static ASN1_OBJECT *ln_objs[NUM_LN]={
&(nid_objs[363]),/* "AD Time Stamping" */
&(nid_objs[405]),/* "ANSI X9.62" */
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
&(nid_objs[432]),/* "Hold Instruction Call Issuer" */
&(nid_objs[430]),/* "Hold Instruction Code" */
&(nid_objs[431]),/* "Hold Instruction None" */
&(nid_objs[433]),/* "Hold Instruction Reject" */
&(nid_objs[294]),/* "IPSec End System" */
&(nid_objs[295]),/* "IPSec Tunnel" */
&(nid_objs[296]),/* "IPSec User" */
&(nid_objs[182]),/* "ISO Member Body" */
&(nid_objs[183]),/* "ISO US Member Body" */
&(nid_objs[142]),/* "Invalidity Date" */
&(nid_objs[504]),/* "MIME MHS" */
&(nid_objs[388]),/* "Mail" */
&(nid_objs[383]),/* "Management" */
&(nid_objs[417]),/* "Microsoft CSP Name" */
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
&(nid_objs[369]),/* "OCSP No Check" */
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
&(nid_objs[478]),/* "aRecord" */
&(nid_objs[289]),/* "aaControls" */
&(nid_objs[287]),/* "ac-auditEntity" */
&(nid_objs[397]),/* "ac-proxying" */
&(nid_objs[288]),/* "ac-targeting" */
&(nid_objs[446]),/* "account" */
&(nid_objs[364]),/* "ad dvcs" */
&(nid_objs[419]),/* "aes-128-cbc" */
&(nid_objs[421]),/* "aes-128-cfb" */
&(nid_objs[418]),/* "aes-128-ecb" */
&(nid_objs[420]),/* "aes-128-ofb" */
&(nid_objs[423]),/* "aes-192-cbc" */
&(nid_objs[425]),/* "aes-192-cfb" */
&(nid_objs[422]),/* "aes-192-ecb" */
&(nid_objs[424]),/* "aes-192-ofb" */
&(nid_objs[427]),/* "aes-256-cbc" */
&(nid_objs[429]),/* "aes-256-cfb" */
&(nid_objs[426]),/* "aes-256-ecb" */
&(nid_objs[428]),/* "aes-256-ofb" */
&(nid_objs[376]),/* "algorithm" */
&(nid_objs[484]),/* "associatedDomain" */
&(nid_objs[485]),/* "associatedName" */
&(nid_objs[501]),/* "audio" */
&(nid_objs[91]),/* "bf-cbc" */
&(nid_objs[93]),/* "bf-cfb" */
&(nid_objs[92]),/* "bf-ecb" */
&(nid_objs[94]),/* "bf-ofb" */
&(nid_objs[494]),/* "buildingName" */
&(nid_objs[483]),/* "cNAMERecord" */
&(nid_objs[443]),/* "caseIgnoreIA5StringSyntax" */
&(nid_objs[108]),/* "cast5-cbc" */
&(nid_objs[110]),/* "cast5-cfb" */
&(nid_objs[109]),/* "cast5-ecb" */
&(nid_objs[111]),/* "cast5-ofb" */
&(nid_objs[404]),/* "ccitt" */
&(nid_objs[152]),/* "certBag" */
&(nid_objs[54]),/* "challengePassword" */
&(nid_objs[407]),/* "characteristic-two-field" */
&(nid_objs[395]),/* "clearance" */
&(nid_objs[13]),/* "commonName" */
&(nid_objs[50]),/* "contentType" */
&(nid_objs[53]),/* "countersignature" */
&(nid_objs[14]),/* "countryName" */
&(nid_objs[153]),/* "crlBag" */
&(nid_objs[500]),/* "dITRedirect" */
&(nid_objs[451]),/* "dNSDomain" */
&(nid_objs[495]),/* "dSAQuality" */
&(nid_objs[434]),/* "data" */
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
&(nid_objs[447]),/* "document" */
&(nid_objs[471]),/* "documentAuthor" */
&(nid_objs[468]),/* "documentIdentifier" */
&(nid_objs[472]),/* "documentLocation" */
&(nid_objs[502]),/* "documentPublisher" */
&(nid_objs[449]),/* "documentSeries" */
&(nid_objs[469]),/* "documentTitle" */
&(nid_objs[470]),/* "documentVersion" */
&(nid_objs[380]),/* "dod" */
&(nid_objs[391]),/* "domainComponent" */
&(nid_objs[452]),/* "domainRelatedObject" */
&(nid_objs[116]),/* "dsaEncryption" */
&(nid_objs[67]),/* "dsaEncryption-old" */
&(nid_objs[66]),/* "dsaWithSHA" */
&(nid_objs[113]),/* "dsaWithSHA1" */
&(nid_objs[70]),/* "dsaWithSHA1-old" */
&(nid_objs[297]),/* "dvcs" */
&(nid_objs[416]),/* "ecdsa-with-SHA1" */
&(nid_objs[48]),/* "emailAddress" */
&(nid_objs[56]),/* "extendedCertificateAttributes" */
&(nid_objs[462]),/* "favouriteDrink" */
&(nid_objs[453]),/* "friendlyCountry" */
&(nid_objs[490]),/* "friendlyCountryName" */
&(nid_objs[156]),/* "friendlyName" */
&(nid_objs[509]),/* "generationQualifier" */
&(nid_objs[99]),/* "givenName" */
&(nid_objs[163]),/* "hmacWithSHA1" */
&(nid_objs[486]),/* "homePostalAddress" */
&(nid_objs[473]),/* "homeTelephoneNumber" */
&(nid_objs[466]),/* "host" */
&(nid_objs[442]),/* "iA5StringSyntax" */
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
&(nid_objs[408]),/* "id-ecPublicKey" */
&(nid_objs[508]),/* "id-hex-multipart-message" */
&(nid_objs[507]),/* "id-hex-partial-message" */
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
&(nid_objs[461]),/* "info" */
&(nid_objs[101]),/* "initials" */
&(nid_objs[181]),/* "iso" */
&(nid_objs[492]),/* "janetMailbox" */
&(nid_objs[393]),/* "joint-iso-ccitt" */
&(nid_objs[150]),/* "keyBag" */
&(nid_objs[477]),/* "lastModifiedBy" */
&(nid_objs[476]),/* "lastModifiedTime" */
&(nid_objs[157]),/* "localKeyID" */
&(nid_objs[15]),/* "localityName" */
&(nid_objs[480]),/* "mXRecord" */
&(nid_objs[493]),/* "mailPreferenceOption" */
&(nid_objs[467]),/* "manager" */
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
&(nid_objs[506]),/* "mime-mhs-bodies" */
&(nid_objs[505]),/* "mime-mhs-headings" */
&(nid_objs[488]),/* "mobileTelephoneNumber" */
&(nid_objs[481]),/* "nSRecord" */
&(nid_objs[173]),/* "name" */
&(nid_objs[379]),/* "org" */
&(nid_objs[17]),/* "organizationName" */
&(nid_objs[491]),/* "organizationalStatus" */
&(nid_objs[18]),/* "organizationalUnitName" */
&(nid_objs[475]),/* "otherMailbox" */
&(nid_objs[489]),/* "pagerTelephoneNumber" */
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
&(nid_objs[499]),/* "personalSignature" */
&(nid_objs[487]),/* "personalTitle" */
&(nid_objs[464]),/* "photo" */
&(nid_objs[437]),/* "pilot" */
&(nid_objs[439]),/* "pilotAttributeSyntax" */
&(nid_objs[438]),/* "pilotAttributeType" */
&(nid_objs[479]),/* "pilotAttributeType27" */
&(nid_objs[456]),/* "pilotDSA" */
&(nid_objs[441]),/* "pilotGroups" */
&(nid_objs[444]),/* "pilotObject" */
&(nid_objs[440]),/* "pilotObjectClass" */
&(nid_objs[455]),/* "pilotOrganization" */
&(nid_objs[445]),/* "pilotPerson" */
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
&(nid_objs[406]),/* "prime-field" */
&(nid_objs[409]),/* "prime192v1" */
&(nid_objs[410]),/* "prime192v2" */
&(nid_objs[411]),/* "prime192v3" */
&(nid_objs[412]),/* "prime239v1" */
&(nid_objs[413]),/* "prime239v2" */
&(nid_objs[414]),/* "prime239v3" */
&(nid_objs[415]),/* "prime256v1" */
&(nid_objs[435]),/* "pss" */
&(nid_objs[286]),/* "qcStatements" */
&(nid_objs[457]),/* "qualityLabelledData" */
&(nid_objs[450]),/* "rFC822localPart" */
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
&(nid_objs[460]),/* "rfc822Mailbox" */
&(nid_objs[117]),/* "ripemd160" */
&(nid_objs[119]),/* "ripemd160WithRSA" */
&(nid_objs[400]),/* "role" */
&(nid_objs[448]),/* "room" */
&(nid_objs[463]),/* "roomNumber" */
&(nid_objs[19]),/* "rsa" */
&(nid_objs[ 6]),/* "rsaEncryption" */
&(nid_objs[377]),/* "rsaSignature" */
&(nid_objs[124]),/* "run length compression" */
&(nid_objs[482]),/* "sOARecord" */
&(nid_objs[155]),/* "safeContentsBag" */
&(nid_objs[291]),/* "sbqp-autonomousSysNum" */
&(nid_objs[290]),/* "sbqp-ipAddrBlock" */
&(nid_objs[292]),/* "sbqp-routerIdentifier" */
&(nid_objs[159]),/* "sdsiCertificate" */
&(nid_objs[154]),/* "secretBag" */
&(nid_objs[474]),/* "secretary" */
&(nid_objs[105]),/* "serialNumber" */
&(nid_objs[41]),/* "sha" */
&(nid_objs[64]),/* "sha1" */
&(nid_objs[115]),/* "sha1WithRSA" */
&(nid_objs[65]),/* "sha1WithRSAEncryption" */
&(nid_objs[42]),/* "shaWithRSAEncryption" */
&(nid_objs[52]),/* "signingTime" */
&(nid_objs[454]),/* "simpleSecurityObject" */
&(nid_objs[496]),/* "singleLevelQuality" */
&(nid_objs[16]),/* "stateOrProvinceName" */
&(nid_objs[498]),/* "subtreeMaximumQuality" */
&(nid_objs[497]),/* "subtreeMinimumQuality" */
&(nid_objs[100]),/* "surname" */
&(nid_objs[459]),/* "textEncodedORAddress" */
&(nid_objs[293]),/* "textNotice" */
&(nid_objs[106]),/* "title" */
&(nid_objs[436]),/* "ucl" */
&(nid_objs[ 0]),/* "undefined" */
&(nid_objs[55]),/* "unstructuredAddress" */
&(nid_objs[49]),/* "unstructuredName" */
&(nid_objs[465]),/* "userClass" */
&(nid_objs[458]),/* "userId" */
&(nid_objs[373]),/* "valid" */
&(nid_objs[503]),/* "x500UniqueIdentifier" */
&(nid_objs[158]),/* "x509Certificate" */
&(nid_objs[160]),/* "x509Crl" */
&(nid_objs[125]),/* "zlib compression" */
};

static ASN1_OBJECT *obj_objs[NUM_OBJ]={
&(nid_objs[ 0]),/* OBJ_undef                        0 */
&(nid_objs[404]),/* OBJ_ccitt                        0 */
&(nid_objs[434]),/* OBJ_data                         0 9 */
&(nid_objs[181]),/* OBJ_iso                          1 */
&(nid_objs[182]),/* OBJ_member_body                  1 2 */
&(nid_objs[379]),/* OBJ_org                          1 3 */
&(nid_objs[393]),/* OBJ_joint_iso_ccitt              2 */
&(nid_objs[11]),/* OBJ_X500                         2 5 */
&(nid_objs[380]),/* OBJ_dod                          1 3 6 */
&(nid_objs[12]),/* OBJ_X509                         2 5 4 */
&(nid_objs[378]),/* OBJ_X500algorithms               2 5 8 */
&(nid_objs[81]),/* OBJ_id_ce                        2 5 29 */
&(nid_objs[435]),/* OBJ_pss                          0 9 2342 */
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
&(nid_objs[509]),/* OBJ_generationQualifier          2 5 4 44 */
&(nid_objs[503]),/* OBJ_x500UniqueIdentifier         2 5 4 45 */
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
&(nid_objs[430]),/* OBJ_hold_instruction_code        2 5 29 23 */
&(nid_objs[142]),/* OBJ_invalidity_date              2 5 29 24 */
&(nid_objs[140]),/* OBJ_delta_crl                    2 5 29 27 */
&(nid_objs[103]),/* OBJ_crl_distribution_points      2 5 29 31 */
&(nid_objs[89]),/* OBJ_certificate_policies         2 5 29 32 */
&(nid_objs[90]),/* OBJ_authority_key_identifier     2 5 29 35 */
&(nid_objs[401]),/* OBJ_policy_constraints           2 5 29 36 */
&(nid_objs[126]),/* OBJ_ext_key_usage                2 5 29 37 */
&(nid_objs[402]),/* OBJ_target_information           2 5 29 55 */
&(nid_objs[403]),/* OBJ_no_rev_avail                 2 5 29 56 */
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
&(nid_objs[405]),/* OBJ_ansi_X9_62                   1 2 840 10045 */
&(nid_objs[389]),/* OBJ_Enterprises                  1 3 6 1 4 1 */
&(nid_objs[504]),/* OBJ_mime_mhs                     1 3 6 1 7 1 */
&(nid_objs[104]),/* OBJ_md5WithRSA                   1 3 14 3 2 3 */
&(nid_objs[29]),/* OBJ_des_ecb                      1 3 14 3 2 6 */
&(nid_objs[31]),/* OBJ_des_cbc                      1 3 14 3 2 7 */
&(nid_objs[45]),/* OBJ_des_ofb64                    1 3 14 3 2 8 */
&(nid_objs[30]),/* OBJ_des_cfb64                    1 3 14 3 2 9 */
&(nid_objs[377]),/* OBJ_rsaSignature                 1 3 14 3 2 11 */
&(nid_objs[67]),/* OBJ_dsa_2                        1 3 14 3 2 12 */
&(nid_objs[66]),/* OBJ_dsaWithSHA                   1 3 14 3 2 13 */
&(nid_objs[42]),/* OBJ_shaWithRSAEncryption         1 3 14 3 2 15 */
&(nid_objs[32]),/* OBJ_des_ede_ecb                  1 3 14 3 2 17 */
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
&(nid_objs[505]),/* OBJ_mime_mhs_headings            1 3 6 1 7 1 1 */
&(nid_objs[506]),/* OBJ_mime_mhs_bodies              1 3 6 1 7 1 2 */
&(nid_objs[119]),/* OBJ_ripemd160WithRSA             1 3 36 3 3 1 2 */
&(nid_objs[436]),/* OBJ_ucl                          0 9 2342 19200300 */
&(nid_objs[ 2]),/* OBJ_pkcs                         1 2 840 113549 1 */
&(nid_objs[431]),/* OBJ_hold_instruction_none        1 2 840 10040 2 1 */
&(nid_objs[432]),/* OBJ_hold_instruction_call_issuer 1 2 840 10040 2 2 */
&(nid_objs[433]),/* OBJ_hold_instruction_reject      1 2 840 10040 2 3 */
&(nid_objs[116]),/* OBJ_dsa                          1 2 840 10040 4 1 */
&(nid_objs[113]),/* OBJ_dsaWithSHA1                  1 2 840 10040 4 3 */
&(nid_objs[406]),/* OBJ_X9_62_prime_field            1 2 840 10045 1 1 */
&(nid_objs[407]),/* OBJ_X9_62_characteristic_two_field 1 2 840 10045 1 2 */
&(nid_objs[408]),/* OBJ_X9_62_id_ecPublicKey         1 2 840 10045 2 1 */
&(nid_objs[416]),/* OBJ_ecdsa_with_SHA1              1 2 840 10045 4 1 */
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
&(nid_objs[507]),/* OBJ_id_hex_partial_message       1 3 6 1 7 1 1 1 */
&(nid_objs[508]),/* OBJ_id_hex_multipart_message     1 3 6 1 7 1 1 2 */
&(nid_objs[57]),/* OBJ_netscape                     2 16 840 1 113730 */
&(nid_objs[437]),/* OBJ_pilot                        0 9 2342 19200300 100 */
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
&(nid_objs[409]),/* OBJ_X9_62_prime192v1             1 2 840 10045 3 1 1 */
&(nid_objs[410]),/* OBJ_X9_62_prime192v2             1 2 840 10045 3 1 2 */
&(nid_objs[411]),/* OBJ_X9_62_prime192v3             1 2 840 10045 3 1 3 */
&(nid_objs[412]),/* OBJ_X9_62_prime239v1             1 2 840 10045 3 1 4 */
&(nid_objs[413]),/* OBJ_X9_62_prime239v2             1 2 840 10045 3 1 5 */
&(nid_objs[414]),/* OBJ_X9_62_prime239v3             1 2 840 10045 3 1 6 */
&(nid_objs[415]),/* OBJ_X9_62_prime256v1             1 2 840 10045 3 1 7 */
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
&(nid_objs[438]),/* OBJ_pilotAttributeType           0 9 2342 19200300 100 1 */
&(nid_objs[439]),/* OBJ_pilotAttributeSyntax         0 9 2342 19200300 100 3 */
&(nid_objs[440]),/* OBJ_pilotObjectClass             0 9 2342 19200300 100 4 */
&(nid_objs[441]),/* OBJ_pilotGroups                  0 9 2342 19200300 100 10 */
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
&(nid_objs[417]),/* OBJ_ms_csp_name                  1 3 6 1 4 1 311 17 1 */
&(nid_objs[390]),/* OBJ_dcObject                     1 3 6 1 4 1 1466 344 */
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
&(nid_objs[418]),/* OBJ_aes_128_ecb                  2 16 840 1 101 3 4 1 1 */
&(nid_objs[419]),/* OBJ_aes_128_cbc                  2 16 840 1 101 3 4 1 2 */
&(nid_objs[420]),/* OBJ_aes_128_ofb128               2 16 840 1 101 3 4 1 3 */
&(nid_objs[421]),/* OBJ_aes_128_cfb128               2 16 840 1 101 3 4 1 4 */
&(nid_objs[422]),/* OBJ_aes_192_ecb                  2 16 840 1 101 3 4 1 21 */
&(nid_objs[423]),/* OBJ_aes_192_cbc                  2 16 840 1 101 3 4 1 22 */
&(nid_objs[424]),/* OBJ_aes_192_ofb128               2 16 840 1 101 3 4 1 23 */
&(nid_objs[425]),/* OBJ_aes_192_cfb128               2 16 840 1 101 3 4 1 24 */
&(nid_objs[426]),/* OBJ_aes_256_ecb                  2 16 840 1 101 3 4 1 41 */
&(nid_objs[427]),/* OBJ_aes_256_cbc                  2 16 840 1 101 3 4 1 42 */
&(nid_objs[428]),/* OBJ_aes_256_ofb128               2 16 840 1 101 3 4 1 43 */
&(nid_objs[429]),/* OBJ_aes_256_cfb128               2 16 840 1 101 3 4 1 44 */
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
&(nid_objs[458]),/* OBJ_userId                       0 9 2342 19200300 100 1 1 */
&(nid_objs[459]),/* OBJ_textEncodedORAddress         0 9 2342 19200300 100 1 2 */
&(nid_objs[460]),/* OBJ_rfc822Mailbox                0 9 2342 19200300 100 1 3 */
&(nid_objs[461]),/* OBJ_info                         0 9 2342 19200300 100 1 4 */
&(nid_objs[462]),/* OBJ_favouriteDrink               0 9 2342 19200300 100 1 5 */
&(nid_objs[463]),/* OBJ_roomNumber                   0 9 2342 19200300 100 1 6 */
&(nid_objs[464]),/* OBJ_photo                        0 9 2342 19200300 100 1 7 */
&(nid_objs[465]),/* OBJ_userClass                    0 9 2342 19200300 100 1 8 */
&(nid_objs[466]),/* OBJ_host                         0 9 2342 19200300 100 1 9 */
&(nid_objs[467]),/* OBJ_manager                      0 9 2342 19200300 100 1 10 */
&(nid_objs[468]),/* OBJ_documentIdentifier           0 9 2342 19200300 100 1 11 */
&(nid_objs[469]),/* OBJ_documentTitle                0 9 2342 19200300 100 1 12 */
&(nid_objs[470]),/* OBJ_documentVersion              0 9 2342 19200300 100 1 13 */
&(nid_objs[471]),/* OBJ_documentAuthor               0 9 2342 19200300 100 1 14 */
&(nid_objs[472]),/* OBJ_documentLocation             0 9 2342 19200300 100 1 15 */
&(nid_objs[473]),/* OBJ_homeTelephoneNumber          0 9 2342 19200300 100 1 20 */
&(nid_objs[474]),/* OBJ_secretary                    0 9 2342 19200300 100 1 21 */
&(nid_objs[475]),/* OBJ_otherMailbox                 0 9 2342 19200300 100 1 22 */
&(nid_objs[476]),/* OBJ_lastModifiedTime             0 9 2342 19200300 100 1 23 */
&(nid_objs[477]),/* OBJ_lastModifiedBy               0 9 2342 19200300 100 1 24 */
&(nid_objs[391]),/* OBJ_domainComponent              0 9 2342 19200300 100 1 25 */
&(nid_objs[478]),/* OBJ_aRecord                      0 9 2342 19200300 100 1 26 */
&(nid_objs[479]),/* OBJ_pilotAttributeType27         0 9 2342 19200300 100 1 27 */
&(nid_objs[480]),/* OBJ_mXRecord                     0 9 2342 19200300 100 1 28 */
&(nid_objs[481]),/* OBJ_nSRecord                     0 9 2342 19200300 100 1 29 */
&(nid_objs[482]),/* OBJ_sOARecord                    0 9 2342 19200300 100 1 30 */
&(nid_objs[483]),/* OBJ_cNAMERecord                  0 9 2342 19200300 100 1 31 */
&(nid_objs[484]),/* OBJ_associatedDomain             0 9 2342 19200300 100 1 37 */
&(nid_objs[485]),/* OBJ_associatedName               0 9 2342 19200300 100 1 38 */
&(nid_objs[486]),/* OBJ_homePostalAddress            0 9 2342 19200300 100 1 39 */
&(nid_objs[487]),/* OBJ_personalTitle                0 9 2342 19200300 100 1 40 */
&(nid_objs[488]),/* OBJ_mobileTelephoneNumber        0 9 2342 19200300 100 1 41 */
&(nid_objs[489]),/* OBJ_pagerTelephoneNumber         0 9 2342 19200300 100 1 42 */
&(nid_objs[490]),/* OBJ_friendlyCountryName          0 9 2342 19200300 100 1 43 */
&(nid_objs[491]),/* OBJ_organizationalStatus         0 9 2342 19200300 100 1 45 */
&(nid_objs[492]),/* OBJ_janetMailbox                 0 9 2342 19200300 100 1 46 */
&(nid_objs[493]),/* OBJ_mailPreferenceOption         0 9 2342 19200300 100 1 47 */
&(nid_objs[494]),/* OBJ_buildingName                 0 9 2342 19200300 100 1 48 */
&(nid_objs[495]),/* OBJ_dSAQuality                   0 9 2342 19200300 100 1 49 */
&(nid_objs[496]),/* OBJ_singleLevelQuality           0 9 2342 19200300 100 1 50 */
&(nid_objs[497]),/* OBJ_subtreeMinimumQuality        0 9 2342 19200300 100 1 51 */
&(nid_objs[498]),/* OBJ_subtreeMaximumQuality        0 9 2342 19200300 100 1 52 */
&(nid_objs[499]),/* OBJ_personalSignature            0 9 2342 19200300 100 1 53 */
&(nid_objs[500]),/* OBJ_dITRedirect                  0 9 2342 19200300 100 1 54 */
&(nid_objs[501]),/* OBJ_audio                        0 9 2342 19200300 100 1 55 */
&(nid_objs[502]),/* OBJ_documentPublisher            0 9 2342 19200300 100 1 56 */
&(nid_objs[442]),/* OBJ_iA5StringSyntax              0 9 2342 19200300 100 3 4 */
&(nid_objs[443]),/* OBJ_caseIgnoreIA5StringSyntax    0 9 2342 19200300 100 3 5 */
&(nid_objs[444]),/* OBJ_pilotObject                  0 9 2342 19200300 100 4 3 */
&(nid_objs[445]),/* OBJ_pilotPerson                  0 9 2342 19200300 100 4 4 */
&(nid_objs[446]),/* OBJ_account                      0 9 2342 19200300 100 4 5 */
&(nid_objs[447]),/* OBJ_document                     0 9 2342 19200300 100 4 6 */
&(nid_objs[448]),/* OBJ_room                         0 9 2342 19200300 100 4 7 */
&(nid_objs[449]),/* OBJ_documentSeries               0 9 2342 19200300 100 4 9 */
&(nid_objs[392]),/* OBJ_Domain                       0 9 2342 19200300 100 4 13 */
&(nid_objs[450]),/* OBJ_rFC822localPart              0 9 2342 19200300 100 4 14 */
&(nid_objs[451]),/* OBJ_dNSDomain                    0 9 2342 19200300 100 4 15 */
&(nid_objs[452]),/* OBJ_domainRelatedObject          0 9 2342 19200300 100 4 17 */
&(nid_objs[453]),/* OBJ_friendlyCountry              0 9 2342 19200300 100 4 18 */
&(nid_objs[454]),/* OBJ_simpleSecurityObject         0 9 2342 19200300 100 4 19 */
&(nid_objs[455]),/* OBJ_pilotOrganization            0 9 2342 19200300 100 4 20 */
&(nid_objs[456]),/* OBJ_pilotDSA                     0 9 2342 19200300 100 4 21 */
&(nid_objs[457]),/* OBJ_qualityLabelledData          0 9 2342 19200300 100 4 22 */
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

