/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ONLY included by evp_fetch.c */

#include <openssl/obj_mac.h>

/* Stuff from c_allc.c */
static const char * const des_cfb_names[] =
    { SN_des_cfb64, LN_des_cfb64, NULL };
static const char * const des_cfb1_names[] =
    { SN_des_cfb1, LN_des_cfb1, NULL };
static const char * const des_cfb8_names[] =
    { SN_des_cfb8, LN_des_cfb8, NULL };
static const char * const des_ede_cfb_names[] =
    { SN_des_ede_cfb64, LN_des_ede_cfb64, NULL };
static const char * const des_ede3_cfb_names[] =
    { SN_des_ede3_cfb64, LN_des_ede3_cfb64, NULL };
static const char * const des_ede3_cfb1_names[] =
    { SN_des_ede3_cfb1, LN_des_ede3_cfb1, NULL };
static const char * const des_ede3_cfb8_names[] =
    { SN_des_ede3_cfb8, LN_des_ede3_cfb8, NULL };

static const char * const des_ofb_names[] =
    { SN_des_ofb64, LN_des_ofb64, NULL };
static const char * const des_ede_ofb_names[] =
    { SN_des_ede_ofb64, LN_des_ede_ofb64, NULL };
static const char * const des_ede3_ofb_names[] =
    { SN_des_ede3_ofb64, LN_des_ede3_ofb64, NULL };

static const char * const desx_cbc_names[] =
    { SN_desx_cbc, LN_desx_cbc, "DESX", NULL };

static const char * const des_cbc_names[] =
    { SN_des_cbc, LN_des_cbc, "DES", NULL };
static const char * const des_ede_cbc_names[] =
    { SN_des_ede_cbc, LN_des_ede_cbc, NULL };
static const char * const des_ede3_cbc_names[] =
    { SN_des_ede3_cbc, LN_des_ede3_cbc, "DES3", NULL };

static const char * const des_ecb_names[] =
    { SN_des_ecb, LN_des_ecb, NULL };
static const char * const des_ede_names[] =
    { SN_des_ede_ecb, LN_des_ede_ecb, "DES-EDE-ECB", NULL };
static const char * const des_ede3_names[] =
    { SN_des_ede3_ecb, LN_des_ede3_ecb, "DES-EDE3-ECB",
      NULL };

static const char * const des_ede3_wrap_names[] =
    { SN_id_smime_alg_CMS3DESwrap, "des3-wrap", NULL };


static const char * const rc4_names[] =
    { SN_rc4, LN_rc4, NULL };
static const char * const rc4_40_names[] =
    { SN_rc4_40, LN_rc4_40, NULL };
static const char * const rc4_hmac_md5_names[] =
    { SN_rc4_hmac_md5, LN_rc4_hmac_md5, NULL };


static const char * const idea_ecb_names[] =
    { SN_idea_ecb, LN_idea_ecb, NULL };
static const char * const idea_cfb_names[] =
    { SN_idea_cfb64, LN_idea_cfb64, NULL };
static const char * const idea_ofb_names[] =
    { SN_idea_ofb64, LN_idea_ofb64, NULL };
static const char * const idea_cbc_names[] =
    { SN_idea_cbc, LN_idea_cbc, "IDEA", NULL };


static const char * const seed_ecb_names[] =
    { SN_seed_ecb, LN_seed_ecb, NULL };
static const char * const seed_cfb_names[] =
    { SN_seed_cfb128, LN_seed_cfb128, NULL };
static const char * const seed_ofb_names[] =
    { SN_seed_ofb128, LN_seed_ofb128, NULL };
static const char * const seed_cbc_names[] =
    { SN_seed_cbc, LN_seed_cbc, "SEED", NULL };


static const char * const sm4_ecb_names[] =
    { SN_sm4_ecb, LN_sm4_ecb, NULL };
static const char * const sm4_cbc_names[] =
    { SN_sm4_cbc, LN_sm4_cbc, "SM4", NULL };
static const char * const sm4_cfb_names[] =
    { SN_sm4_cfb128, LN_sm4_cfb128, NULL };
#if 0                /* Curiously, these aren't present in c_allc.c */
static const char * const sm4_cfb1_names[] =
    { SN_sm4_cfb1, LN_sm4_cfb1, NULL };
static const char * const sm4_cfb8_names[] =
    { SN_sm4_cfb8, LN_sm4_cfb8, NULL };
#endif
static const char * const sm4_ofb_names[] =
    { SN_sm4_ofb128, LN_sm4_ofb128, NULL };
static const char * const sm4_ctr_names[] =
    { SN_sm4_ctr, LN_sm4_ctr, NULL };


static const char * const rc2_ecb_names[] =
    { SN_rc2_ecb, LN_rc2_ecb, NULL };
static const char * const rc2_cfb_names[] =
    { SN_rc2_cfb64, LN_rc2_cfb64, NULL };
static const char * const rc2_ofb_names[] =
    { SN_rc2_ofb64, LN_rc2_ofb64, NULL };
static const char * const rc2_cbc_names[] =
    { SN_rc2_cbc, LN_rc2_cbc, "RC2", "rc2-128", NULL };
static const char * const rc2_64_cbc_names[] =
    { SN_rc2_64_cbc, LN_rc2_64_cbc, "rc2-64", NULL };
static const char * const rc2_40_cbc_names[] =
    { SN_rc2_40_cbc, LN_rc2_40_cbc, "rc2-40", NULL };


static const char * const bf_ecb_names[] =
    { SN_bf_ecb, LN_bf_ecb, NULL };
static const char * const bf_cfb_names[] =
    { SN_bf_cfb64, LN_bf_cfb64, NULL };
static const char * const bf_ofb_names[] =
    { SN_bf_ofb64, LN_bf_ofb64, NULL };
static const char * const bf_cbc_names[] =
    { SN_bf_cbc, LN_bf_cbc, "BF", "blowfish", NULL };


static const char * const cast5_ecb_names[] =
    { SN_cast5_ecb, LN_cast5_ecb, NULL };
static const char * const cast5_cfb_names[] =
    { SN_cast5_cfb64, LN_cast5_cfb64, NULL };
static const char * const cast5_ofb_names[] =
    { SN_cast5_ofb64, LN_cast5_ofb64, NULL };
static const char * const cast5_cbc_names[] =
    { SN_cast5_cbc, LN_cast5_cbc, "CAST", "CAST-CBC",
      NULL };


static const char * const rc5_32_12_16_ecb_names[] =
    { SN_rc5_ecb, LN_rc5_ecb, NULL };
static const char * const rc5_32_12_16_cfb_names[] =
    { SN_rc5_cfb64, LN_rc5_cfb64, NULL };
static const char * const rc5_32_12_16_ofb_names[] =
    { SN_rc5_ofb64, LN_rc5_ofb64, NULL };
static const char * const rc5_32_12_16_cbc_names[] =
    { SN_rc5_cbc, LN_rc5_cbc, "RC5", NULL };


static const char * const aes_128_ecb_names[] =
    { SN_aes_128_ecb, LN_aes_128_ecb, NULL };
static const char * const aes_128_cbc_names[] =
    { SN_aes_128_cbc, LN_aes_128_cbc, "AES128", NULL };
static const char * const aes_128_cfb_names[] =
    { SN_aes_128_cfb128, LN_aes_128_cfb128, NULL };
static const char * const aes_128_cfb1_names[] =
    { SN_aes_128_cfb1, LN_aes_128_cfb1, NULL };
static const char * const aes_128_cfb8_names[] =
    { SN_aes_128_cfb8, LN_aes_128_cfb8, NULL };
static const char * const aes_128_ofb_names[] =
    { SN_aes_128_ofb128, LN_aes_128_ofb128, NULL };
static const char * const aes_128_ctr_names[] =
    { SN_aes_128_ctr, LN_aes_128_ctr, NULL };
static const char * const aes_128_gcm_names[] =
    { SN_aes_128_gcm, LN_aes_128_gcm, NULL };
static const char * const aes_128_ocb_names[] =
    { SN_aes_128_ocb, LN_aes_128_ocb, NULL };
static const char * const aes_128_xts_names[] =
    { SN_aes_128_xts, LN_aes_128_xts, NULL };
static const char * const aes_128_ccm_names[] =
    { SN_aes_128_ccm, LN_aes_128_ccm, NULL };
static const char * const id_aes128_wrap_names[] =
    { SN_id_aes128_wrap, "aes128-wrap", NULL };
static const char * const id_aes128_wrap_pad_names[] =
    { SN_id_aes128_wrap_pad, NULL };

static const char * const aes_192_ecb_names[] =
    { SN_aes_192_ecb, LN_aes_192_ecb, NULL };
static const char * const aes_192_cbc_names[] =
    { SN_aes_192_cbc, LN_aes_192_cbc, "AES192", NULL };
static const char * const aes_192_cfb_names[] =
    { SN_aes_192_cfb128, LN_aes_192_cfb128, NULL };
static const char * const aes_192_cfb1_names[] =
    { SN_aes_192_cfb1, LN_aes_192_cfb1, NULL };
static const char * const aes_192_cfb8_names[] =
    { SN_aes_192_cfb8, LN_aes_192_cfb8, NULL };
static const char * const aes_192_ofb_names[] =
    { SN_aes_192_ofb128, LN_aes_192_ofb128, NULL };
static const char * const aes_192_ctr_names[] =
    { SN_aes_192_ctr, LN_aes_192_ctr, NULL };
static const char * const aes_192_gcm_names[] =
    { SN_aes_192_gcm, LN_aes_192_gcm, NULL };
static const char * const aes_192_ocb_names[] =
    { SN_aes_192_ocb, LN_aes_192_ocb, NULL };
static const char * const aes_192_ccm_names[] =
    { SN_aes_192_ccm, LN_aes_192_ccm, NULL };
static const char * const id_aes192_wrap_names[] =
    { SN_id_aes192_wrap, "aes192-wrap", NULL };
static const char * const id_aes192_wrap_pad_names[] =
    { SN_id_aes192_wrap_pad, NULL };

static const char * const aes_256_ecb_names[] =
    { SN_aes_256_ecb, LN_aes_256_ecb, NULL };
static const char * const aes_256_cbc_names[] =
    { SN_aes_256_cbc, LN_aes_256_cbc, "AES256", NULL };
static const char * const aes_256_cfb_names[] =
    { SN_aes_256_cfb128, LN_aes_256_cfb128, NULL };
static const char * const aes_256_cfb1_names[] =
    { SN_aes_256_cfb1, LN_aes_256_cfb1, NULL };
static const char * const aes_256_cfb8_names[] =
    { SN_aes_256_cfb8, LN_aes_256_cfb8, NULL };
static const char * const aes_256_ofb_names[] =
    { SN_aes_256_ofb128, LN_aes_256_ofb128, NULL };
static const char * const aes_256_ctr_names[] =
    { SN_aes_256_ctr, LN_aes_256_ctr, NULL };
static const char * const aes_256_gcm_names[] =
    { SN_aes_256_gcm, LN_aes_256_gcm, NULL };
static const char * const aes_256_ocb_names[] =
    { SN_aes_256_ocb, LN_aes_256_ocb, NULL };
static const char * const aes_256_xts_names[] =
    { SN_aes_256_xts, LN_aes_256_xts, NULL };
static const char * const aes_256_ccm_names[] =
    { SN_aes_256_ccm, LN_aes_256_ccm, NULL };
static const char * const id_aes256_wrap_names[] =
    { SN_id_aes256_wrap, "aes256-wrap", NULL };
static const char * const id_aes256_wrap_pad_names[] =
    { SN_id_aes256_wrap_pad, NULL };

static const char * const aes_128_cbc_hmac_sha1_names[] =
    { SN_aes_128_cbc_hmac_sha1, LN_aes_128_cbc_hmac_sha1, NULL };
#if 0                  /* Curiously, this isn't present in c_allc.c */
static const char * const aes_192_cbc_hmac_sha1_names[] =
    { SN_aes_192_cbc_hmac_sha1, LN_aes_192_cbc_hmac_sha1, NULL };
#endif
static const char * const aes_256_cbc_hmac_sha1_names[] =
    { SN_aes_256_cbc_hmac_sha1, LN_aes_256_cbc_hmac_sha1, NULL };
static const char * const aes_128_cbc_hmac_sha256_names[] =
    { SN_aes_128_cbc_hmac_sha256, LN_aes_128_cbc_hmac_sha256, NULL };
#if 0                  /* Curiously, this isn't present in c_allc.c */
static const char * const aes_192_cbc_hmac_sha256_names[] =
    { SN_aes_192_cbc_hmac_sha256, LN_aes_192_cbc_hmac_sha256, NULL };
#endif
static const char * const aes_256_cbc_hmac_sha256_names[] =
    { SN_aes_256_cbc_hmac_sha256, LN_aes_256_cbc_hmac_sha256, NULL };

static const char * const aes_128_siv_names[] =
    { SN_aes_128_siv, LN_aes_128_siv, NULL };
static const char * const aes_192_siv_names[] =
    { SN_aes_192_siv, LN_aes_192_siv, NULL };
static const char * const aes_256_siv_names[] =
    { SN_aes_256_siv, LN_aes_256_siv, NULL };


static const char * const aria_128_ecb_names[] =
    { SN_aria_128_ecb, LN_aria_128_ecb, NULL };
static const char * const aria_128_cbc_names[] =
    { SN_aria_128_cbc, LN_aria_128_cbc, "ARIA128", NULL };
static const char * const aria_128_cfb_names[] =
    { SN_aria_128_cfb128, LN_aria_128_cfb128, NULL };
static const char * const aria_128_cfb1_names[] =
    { SN_aria_128_cfb1, LN_aria_128_cfb1, NULL };
static const char * const aria_128_cfb8_names[] =
    { SN_aria_128_cfb8, LN_aria_128_cfb8, NULL };
static const char * const aria_128_ctr_names[] =
    { SN_aria_128_ctr, LN_aria_128_ctr, NULL };
static const char * const aria_128_ofb_names[] =
    { SN_aria_128_ofb128, LN_aria_128_ofb128, NULL };
static const char * const aria_128_gcm_names[] =
    { SN_aria_128_gcm, LN_aria_128_gcm, NULL };
static const char * const aria_128_ccm_names[] =
    { SN_aria_128_ccm, LN_aria_128_ccm, NULL };

static const char * const aria_192_ecb_names[] =
    { SN_aria_192_ecb, LN_aria_192_ecb, NULL };
static const char * const aria_192_cbc_names[] =
    { SN_aria_192_cbc, LN_aria_192_cbc, "ARIA192", NULL };
static const char * const aria_192_cfb_names[] =
    { SN_aria_192_cfb128, LN_aria_192_cfb128, NULL };
static const char * const aria_192_cfb1_names[] =
    { SN_aria_192_cfb1, LN_aria_192_cfb1, NULL };
static const char * const aria_192_cfb8_names[] =
    { SN_aria_192_cfb8, LN_aria_192_cfb8, NULL };
static const char * const aria_192_ctr_names[] =
    { SN_aria_192_ctr, LN_aria_192_ctr, NULL };
static const char * const aria_192_ofb_names[] =
    { SN_aria_192_ofb128, LN_aria_192_ofb128, NULL };
static const char * const aria_192_gcm_names[] =
    { SN_aria_192_gcm, LN_aria_192_gcm, NULL };
static const char * const aria_192_ccm_names[] =
    { SN_aria_192_ccm, LN_aria_192_ccm, NULL };

static const char * const aria_256_ecb_names[] =
    { SN_aria_256_ecb, LN_aria_256_ecb, NULL };
static const char * const aria_256_cbc_names[] =
    { SN_aria_256_cbc, LN_aria_256_cbc, "ARIA256", NULL };
static const char * const aria_256_cfb_names[] =
    { SN_aria_256_cfb128, LN_aria_256_cfb128, NULL };
static const char * const aria_256_cfb1_names[] =
    { SN_aria_256_cfb1, LN_aria_256_cfb1, NULL };
static const char * const aria_256_cfb8_names[] =
    { SN_aria_256_cfb8, LN_aria_256_cfb8, NULL };
static const char * const aria_256_ctr_names[] =
    { SN_aria_256_ctr, LN_aria_256_ctr, NULL };
static const char * const aria_256_ofb_names[] =
    { SN_aria_256_ofb128, LN_aria_256_ofb128, NULL };
static const char * const aria_256_gcm_names[] =
    { SN_aria_256_gcm, LN_aria_256_gcm, NULL };
static const char * const aria_256_ccm_names[] =
    { SN_aria_256_ccm, LN_aria_256_ccm, NULL };


static const char * const camellia_128_ecb_names[] =
    { SN_camellia_128_ecb, LN_camellia_128_ecb, NULL };
static const char * const camellia_128_cbc_names[] =
    { SN_camellia_128_cbc, LN_camellia_128_cbc, "CAMELLIA128", NULL };
static const char * const camellia_128_cfb_names[] =
    { SN_camellia_128_cfb128, LN_camellia_128_cfb128, NULL };
static const char * const camellia_128_cfb1_names[] =
    { SN_camellia_128_cfb1, LN_camellia_128_cfb1, NULL };
static const char * const camellia_128_cfb8_names[] =
    { SN_camellia_128_cfb8, LN_camellia_128_cfb8, NULL };
static const char * const camellia_128_ofb_names[] =
    { SN_camellia_128_ofb128, LN_camellia_128_ofb128, NULL };
#if 0                /* Curiously, these aren't present in c_allc.c */
static const char * const camellia_128_gcm_names[] =
    { SN_camellia_128_gcm, LN_camellia_128_gcm, NULL };
static const char * const camellia_128_ccm_names[] =
    { SN_camellia_128_ccm, LN_camellia_128_ccm, NULL };
static const char * const camellia_128_cmac_names[] =
    { SN_camellia_128_cmac, LN_camellia_128_cmac, NULL };
#endif

static const char * const camellia_192_ecb_names[] =
    { SN_camellia_192_ecb, LN_camellia_192_ecb, NULL };
static const char * const camellia_192_cbc_names[] =
    { SN_camellia_192_cbc, LN_camellia_192_cbc, "CAMELLIA192", NULL };
static const char * const camellia_192_cfb_names[] =
    { SN_camellia_192_cfb128, LN_camellia_192_cfb128, NULL };
static const char * const camellia_192_cfb1_names[] =
    { SN_camellia_192_cfb1, LN_camellia_192_cfb1, NULL };
static const char * const camellia_192_cfb8_names[] =
    { SN_camellia_192_cfb8, LN_camellia_192_cfb8, NULL };
static const char * const camellia_192_ofb_names[] =
    { SN_camellia_192_ofb128, LN_camellia_192_ofb128, NULL };
#if 0                /* Curiously, these aren't present in c_allc.c */
static const char * const camellia_192_gcm_names[] =
    { SN_camellia_192_gcm, LN_camellia_192_gcm, NULL };
static const char * const camellia_192_ccm_names[] =
    { SN_camellia_192_ccm, LN_camellia_192_ccm, NULL };
static const char * const camellia_192_cmac_names[] =
    { SN_camellia_192_cmac, LN_camellia_192_cmac, NULL };
#endif

static const char * const camellia_256_ecb_names[] =
    { SN_camellia_256_ecb, LN_camellia_256_ecb, NULL };
static const char * const camellia_256_cbc_names[] =
    { SN_camellia_256_cbc, LN_camellia_256_cbc, "CAMELLIA256", NULL };
static const char * const camellia_256_cfb_names[] =
    { SN_camellia_256_cfb128, LN_camellia_256_cfb128, NULL };
static const char * const camellia_256_cfb1_names[] =
    { SN_camellia_256_cfb1, LN_camellia_256_cfb1, NULL };
static const char * const camellia_256_cfb8_names[] =
    { SN_camellia_256_cfb8, LN_camellia_256_cfb8, NULL };
static const char * const camellia_256_ofb_names[] =
    { SN_camellia_256_ofb128, LN_camellia_256_ofb128, NULL };
#if 0                /* Curiously, these aren't present in c_allc.c */
static const char * const camellia_256_gcm_names[] =
    { SN_camellia_256_gcm, LN_camellia_256_gcm, NULL };
static const char * const camellia_256_ccm_names[] =
    { SN_camellia_256_ccm, LN_camellia_256_ccm, NULL };
static const char * const camellia_256_cmac_names[] =
    { SN_camellia_256_cmac, LN_camellia_256_cmac, NULL };
#endif

static const char * const camellia_128_ctr_names[] =
    { SN_camellia_128_ctr, LN_camellia_128_ctr, NULL };
static const char * const camellia_192_ctr_names[] =
    { SN_camellia_192_ctr, LN_camellia_192_ctr, NULL };
static const char * const camellia_256_ctr_names[] =
    { SN_camellia_256_ctr, LN_camellia_256_ctr, NULL };


static const char * const chacha20_names[] =
    { SN_chacha20, LN_chacha20, NULL };
static const char * const chacha20_poly1305_names[] =
    { SN_chacha20_poly1305, LN_chacha20_poly1305, NULL };


static const char * const * const all_cipher_names[] = {
    des_cfb_names,
    des_cfb1_names,
    des_cfb8_names,
    des_ede_cfb_names,
    des_ede3_cfb_names,
    des_ede3_cfb1_names,
    des_ede3_cfb8_names,
    des_ofb_names,
    des_ede_ofb_names,
    des_ede3_ofb_names,
    desx_cbc_names,
    des_cbc_names,
    des_ede_cbc_names,
    des_ede3_cbc_names,
    des_ecb_names,
    des_ede_names,
    des_ede3_names,
    des_ede3_wrap_names,
    rc4_names,
    rc4_40_names,
    rc4_hmac_md5_names,
    idea_ecb_names,
    idea_cfb_names,
    idea_ofb_names,
    idea_cbc_names,
    seed_ecb_names,
    seed_cfb_names,
    seed_ofb_names,
    seed_cbc_names,
    sm4_ecb_names,
    sm4_cbc_names,
    sm4_cfb_names,
#if 0                /* Curiously, these aren't present in c_allc.c */
    sm4_cfb1_names,
    sm4_cfb8_names,
#endif
    sm4_ofb_names,
    sm4_ctr_names,
    rc2_ecb_names,
    rc2_cfb_names,
    rc2_ofb_names,
    rc2_cbc_names,
    rc2_64_cbc_names,
    rc2_40_cbc_names,
    bf_ecb_names,
    bf_cfb_names,
    bf_ofb_names,
    bf_cbc_names,
    cast5_ecb_names,
    cast5_cfb_names,
    cast5_ofb_names,
    cast5_cbc_names,
    rc5_32_12_16_ecb_names,
    rc5_32_12_16_cfb_names,
    rc5_32_12_16_ofb_names,
    rc5_32_12_16_cbc_names,
    aes_128_ecb_names,
    aes_128_cbc_names,
    aes_128_cfb_names,
    aes_128_cfb1_names,
    aes_128_cfb8_names,
    aes_128_ofb_names,
    aes_128_ctr_names,
    aes_128_gcm_names,
    aes_128_ocb_names,
    aes_128_xts_names,
    aes_128_ccm_names,
    id_aes128_wrap_names,
    id_aes128_wrap_pad_names,
    aes_192_ecb_names,
    aes_192_cbc_names,
    aes_192_cfb_names,
    aes_192_cfb1_names,
    aes_192_cfb8_names,
    aes_192_ofb_names,
    aes_192_ctr_names,
    aes_192_gcm_names,
    aes_192_ocb_names,
    aes_192_ccm_names,
    id_aes192_wrap_names,
    id_aes192_wrap_pad_names,
    aes_256_ecb_names,
    aes_256_cbc_names,
    aes_256_cfb_names,
    aes_256_cfb1_names,
    aes_256_cfb8_names,
    aes_256_ofb_names,
    aes_256_ctr_names,
    aes_256_gcm_names,
    aes_256_ocb_names,
    aes_256_xts_names,
    aes_256_ccm_names,
    id_aes256_wrap_names,
    id_aes256_wrap_pad_names,
    aes_128_cbc_hmac_sha1_names,
#if 0                  /* Curiously, this isn't present in c_allc.c */
    aes_192_cbc_hmac_sha1_names,
#endif
    aes_256_cbc_hmac_sha1_names,
    aes_128_cbc_hmac_sha256_names,
#if 0                  /* Curiously, this isn't present in c_allc.c */
    aes_192_cbc_hmac_sha256_names,
#endif
    aes_256_cbc_hmac_sha256_names,
    aes_128_siv_names,
    aes_192_siv_names,
    aes_256_siv_names,
    aria_128_ecb_names,
    aria_128_cbc_names,
    aria_128_cfb_names,
    aria_128_cfb1_names,
    aria_128_cfb8_names,
    aria_128_ctr_names,
    aria_128_ofb_names,
    aria_128_gcm_names,
    aria_128_ccm_names,
    aria_192_ecb_names,
    aria_192_cbc_names,
    aria_192_cfb_names,
    aria_192_cfb1_names,
    aria_192_cfb8_names,
    aria_192_ctr_names,
    aria_192_ofb_names,
    aria_192_gcm_names,
    aria_192_ccm_names,
    aria_256_ecb_names,
    aria_256_cbc_names,
    aria_256_cfb_names,
    aria_256_cfb1_names,
    aria_256_cfb8_names,
    aria_256_ctr_names,
    aria_256_ofb_names,
    aria_256_gcm_names,
    aria_256_ccm_names,
    camellia_128_ecb_names,
    camellia_128_cbc_names,
    camellia_128_cfb_names,
    camellia_128_cfb1_names,
    camellia_128_cfb8_names,
    camellia_128_ofb_names,
#if 0                /* Curiously, these aren't present in c_allc.c */
    camellia_128_gcm_names,
    camellia_128_ccm_names,
    camellia_128_cmac_names,
#endif
    camellia_192_ecb_names,
    camellia_192_cbc_names,
    camellia_192_cfb_names,
    camellia_192_cfb1_names,
    camellia_192_cfb8_names,
    camellia_192_ofb_names,
#if 0                /* Curiously, these aren't present in c_allc.c */
    camellia_192_gcm_names,
    camellia_192_ccm_names,
    camellia_192_cmac_names,
#endif
    camellia_256_ecb_names,
    camellia_256_cbc_names,
    camellia_256_cfb_names,
    camellia_256_cfb1_names,
    camellia_256_cfb8_names,
    camellia_256_ofb_names,
#if 0                /* Curiously, these aren't present in c_allc.c */
    camellia_256_gcm_names,
    camellia_256_ccm_names,
    camellia_256_cmac_names,
#endif
    camellia_128_ctr_names,
    camellia_192_ctr_names,
    camellia_256_ctr_names,
    chacha20_names,
    chacha20_poly1305_names,
    NULL
};
