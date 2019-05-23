/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Digests */
extern const char *sha1_names[];
extern const OSSL_DISPATCH sha1_functions[];
extern const char *sha224_names[];
extern const OSSL_DISPATCH sha224_functions[];
extern const char *sha256_names[];
extern const OSSL_DISPATCH sha256_functions[];
extern const char *sha384_names[];
extern const OSSL_DISPATCH sha384_functions[];
extern const char *sha512_names[];
extern const OSSL_DISPATCH sha512_functions[];
extern const char *sha512_224_names[];
extern const OSSL_DISPATCH sha512_224_functions[];
extern const char *sha512_256_names[];
extern const OSSL_DISPATCH sha512_256_functions[];
extern const char *sha3_224_names[];
extern const OSSL_DISPATCH sha3_224_functions[];
extern const char *sha3_256_names[];
extern const OSSL_DISPATCH sha3_256_functions[];
extern const char *sha3_384_names[];
extern const OSSL_DISPATCH sha3_384_functions[];
extern const char *sha3_512_names[];
extern const OSSL_DISPATCH sha3_512_functions[];
extern const char *keccak_kmac_128_names[];
extern const OSSL_DISPATCH keccak_kmac_128_functions[];
extern const char *keccak_kmac_256_names[];
extern const OSSL_DISPATCH keccak_kmac_256_functions[];
extern const char *shake_128_names[];
extern const OSSL_DISPATCH shake_128_functions[];
extern const char *shake_256_names[];
extern const OSSL_DISPATCH shake_256_functions[];
extern const char *blake2s256_names[];
extern const OSSL_DISPATCH blake2s256_functions[];
extern const char *blake2b512_names[];
extern const OSSL_DISPATCH blake2b512_functions[];
extern const char *md5_names[];
extern const OSSL_DISPATCH md5_functions[];
extern const char *md5_sha1_names[];
extern const OSSL_DISPATCH md5_sha1_functions[];
extern const char *sm3_names[];
extern const OSSL_DISPATCH sm3_functions[];
extern const char *md2_names[];
extern const OSSL_DISPATCH md2_functions[];
extern const char *md4_names[];
extern const OSSL_DISPATCH md4_functions[];
extern const char *mdc2_names[];
extern const OSSL_DISPATCH mdc2_functions[];
extern const char *wp_names[];
extern const OSSL_DISPATCH wp_functions[];
extern const char *ripemd160_names[];
extern const OSSL_DISPATCH ripemd160_functions[];

/* Ciphers */
extern const char *aes256ecb_names[];
extern const OSSL_DISPATCH aes256ecb_functions[];
extern const char *aes192ecb_names[];
extern const OSSL_DISPATCH aes192ecb_functions[];
extern const char *aes128ecb_names[];
extern const OSSL_DISPATCH aes128ecb_functions[];
extern const char *aes256cbc_names[];
extern const OSSL_DISPATCH aes256cbc_functions[];
extern const char *aes192cbc_names[];
extern const OSSL_DISPATCH aes192cbc_functions[];
extern const char *aes128cbc_names[];
extern const OSSL_DISPATCH aes128cbc_functions[];
extern const char *aes256ofb_names[];
extern const OSSL_DISPATCH aes256ofb_functions[];
extern const char *aes192ofb_names[];
extern const OSSL_DISPATCH aes192ofb_functions[];
extern const char *aes128ofb_names[];
extern const OSSL_DISPATCH aes128ofb_functions[];
extern const char *aes256cfb_names[];
extern const OSSL_DISPATCH aes256cfb_functions[];
extern const char *aes192cfb_names[];
extern const OSSL_DISPATCH aes192cfb_functions[];
extern const char *aes128cfb_names[];
extern const OSSL_DISPATCH aes128cfb_functions[];
extern const char *aes256cfb1_names[];
extern const OSSL_DISPATCH aes256cfb1_functions[];
extern const char *aes192cfb1_names[];
extern const OSSL_DISPATCH aes192cfb1_functions[];
extern const char *aes128cfb1_names[];
extern const OSSL_DISPATCH aes128cfb1_functions[];
extern const char *aes256cfb8_names[];
extern const OSSL_DISPATCH aes256cfb8_functions[];
extern const char *aes192cfb8_names[];
extern const OSSL_DISPATCH aes192cfb8_functions[];
extern const char *aes128cfb8_names[];
extern const OSSL_DISPATCH aes128cfb8_functions[];
extern const char *aes256ctr_names[];
extern const OSSL_DISPATCH aes256ctr_functions[];
extern const char *aes192ctr_names[];
extern const OSSL_DISPATCH aes192ctr_functions[];
extern const char *aes128ctr_names[];
extern const OSSL_DISPATCH aes128ctr_functions[];
extern const char *aes256xts_names[];
extern const OSSL_DISPATCH aes256xts_functions[];
extern const char *aes128xts_names[];
extern const OSSL_DISPATCH aes128xts_functions[];
#ifndef OPENSSL_NO_OCB
extern const char *aes256ocb_names[];
extern const OSSL_DISPATCH aes256ocb_functions[];
extern const char *aes192ocb_names[];
extern const OSSL_DISPATCH aes192ocb_functions[];
extern const char *aes128ocb_names[];
extern const OSSL_DISPATCH aes128ocb_functions[];
#endif /* OPENSSL_NO_OCB */
extern const char *aes256gcm_names[];
extern const OSSL_DISPATCH aes256gcm_functions[];
extern const char *aes192gcm_names[];
extern const OSSL_DISPATCH aes192gcm_functions[];
extern const char *aes128gcm_names[];
extern const OSSL_DISPATCH aes128gcm_functions[];
extern const char *aes256ccm_names[];
extern const OSSL_DISPATCH aes256ccm_functions[];
extern const char *aes192ccm_names[];
extern const OSSL_DISPATCH aes192ccm_functions[];
extern const char *aes128ccm_names[];
extern const OSSL_DISPATCH aes128ccm_functions[];
extern const char *aes256wrap_names[];
extern const OSSL_DISPATCH aes256wrap_functions[];
extern const char *aes192wrap_names[];
extern const OSSL_DISPATCH aes192wrap_functions[];
extern const char *aes128wrap_names[];
extern const OSSL_DISPATCH aes128wrap_functions[];
extern const char *aes256wrappad_names[];
extern const OSSL_DISPATCH aes256wrappad_functions[];
extern const char *aes192wrappad_names[];
extern const OSSL_DISPATCH aes192wrappad_functions[];
extern const char *aes128wrappad_names[];
extern const OSSL_DISPATCH aes128wrappad_functions[];

#ifndef OPENSSL_NO_ARIA
extern const char *aria256gcm_names[];
extern const OSSL_DISPATCH aria256gcm_functions[];
extern const char *aria192gcm_names[];
extern const OSSL_DISPATCH aria192gcm_functions[];
extern const char *aria128gcm_names[];
extern const OSSL_DISPATCH aria128gcm_functions[];
extern const char *aria256ccm_names[];
extern const OSSL_DISPATCH aria256ccm_functions[];
extern const char *aria192ccm_names[];
extern const OSSL_DISPATCH aria192ccm_functions[];
extern const char *aria128ccm_names[];
extern const OSSL_DISPATCH aria128ccm_functions[];
extern const char *aria256ecb_names[];
extern const OSSL_DISPATCH aria256ecb_functions[];
extern const char *aria192ecb_names[];
extern const OSSL_DISPATCH aria192ecb_functions[];
extern const char *aria128ecb_names[];
extern const OSSL_DISPATCH aria128ecb_functions[];
extern const char *aria256cbc_names[];
extern const OSSL_DISPATCH aria256cbc_functions[];
extern const char *aria192cbc_names[];
extern const OSSL_DISPATCH aria192cbc_functions[];
extern const char *aria128cbc_names[];
extern const OSSL_DISPATCH aria128cbc_functions[];
extern const char *aria256ofb_names[];
extern const OSSL_DISPATCH aria256ofb_functions[];
extern const char *aria192ofb_names[];
extern const OSSL_DISPATCH aria192ofb_functions[];
extern const char *aria128ofb_names[];
extern const OSSL_DISPATCH aria128ofb_functions[];
extern const char *aria256cfb_names[];
extern const OSSL_DISPATCH aria256cfb_functions[];
extern const char *aria192cfb_names[];
extern const OSSL_DISPATCH aria192cfb_functions[];
extern const char *aria128cfb_names[];
extern const OSSL_DISPATCH aria128cfb_functions[];
extern const char *aria256cfb1_names[];
extern const OSSL_DISPATCH aria256cfb1_functions[];
extern const char *aria192cfb1_names[];
extern const OSSL_DISPATCH aria192cfb1_functions[];
extern const char *aria128cfb1_names[];
extern const OSSL_DISPATCH aria128cfb1_functions[];
extern const char *aria256cfb8_names[];
extern const OSSL_DISPATCH aria256cfb8_functions[];
extern const char *aria192cfb8_names[];
extern const OSSL_DISPATCH aria192cfb8_functions[];
extern const char *aria128cfb8_names[];
extern const OSSL_DISPATCH aria128cfb8_functions[];
extern const char *aria256ctr_names[];
extern const OSSL_DISPATCH aria256ctr_functions[];
extern const char *aria192ctr_names[];
extern const OSSL_DISPATCH aria192ctr_functions[];
extern const char *aria128ctr_names[];
extern const OSSL_DISPATCH aria128ctr_functions[];
#endif /* OPENSSL_NO_ARIA */
#ifndef OPENSSL_NO_CAMELLIA
extern const char *camellia256ecb_names[];
extern const OSSL_DISPATCH camellia256ecb_functions[];
extern const char *camellia192ecb_names[];
extern const OSSL_DISPATCH camellia192ecb_functions[];
extern const char *camellia128ecb_names[];
extern const OSSL_DISPATCH camellia128ecb_functions[];
extern const char *camellia256cbc_names[];
extern const OSSL_DISPATCH camellia256cbc_functions[];
extern const char *camellia192cbc_names[];
extern const OSSL_DISPATCH camellia192cbc_functions[];
extern const char *camellia128cbc_names[];
extern const OSSL_DISPATCH camellia128cbc_functions[];
extern const char *camellia256ofb_names[];
extern const OSSL_DISPATCH camellia256ofb_functions[];
extern const char *camellia192ofb_names[];
extern const OSSL_DISPATCH camellia192ofb_functions[];
extern const char *camellia128ofb_names[];
extern const OSSL_DISPATCH camellia128ofb_functions[];
extern const char *camellia256cfb_names[];
extern const OSSL_DISPATCH camellia256cfb_functions[];
extern const char *camellia192cfb_names[];
extern const OSSL_DISPATCH camellia192cfb_functions[];
extern const char *camellia128cfb_names[];
extern const OSSL_DISPATCH camellia128cfb_functions[];
extern const char *camellia256cfb1_names[];
extern const OSSL_DISPATCH camellia256cfb1_functions[];
extern const char *camellia192cfb1_names[];
extern const OSSL_DISPATCH camellia192cfb1_functions[];
extern const char *camellia128cfb1_names[];
extern const OSSL_DISPATCH camellia128cfb1_functions[];
extern const char *camellia256cfb8_names[];
extern const OSSL_DISPATCH camellia256cfb8_functions[];
extern const char *camellia192cfb8_names[];
extern const OSSL_DISPATCH camellia192cfb8_functions[];
extern const char *camellia128cfb8_names[];
extern const OSSL_DISPATCH camellia128cfb8_functions[];
extern const char *camellia256ctr_names[];
extern const OSSL_DISPATCH camellia256ctr_functions[];
extern const char *camellia192ctr_names[];
extern const OSSL_DISPATCH camellia192ctr_functions[];
extern const char *camellia128ctr_names[];
extern const OSSL_DISPATCH camellia128ctr_functions[];
#endif /* OPENSSL_NO_CAMELLIA */
#ifndef OPENSSL_NO_BF
extern const char *blowfish128ecb_names[];
extern const OSSL_DISPATCH blowfish128ecb_functions[];
extern const char *blowfish128cbc_names[];
extern const OSSL_DISPATCH blowfish128cbc_functions[];
extern const char *blowfish64ofb64_names[];
extern const OSSL_DISPATCH blowfish64ofb64_functions[];
extern const char *blowfish64cfb64_names[];
extern const OSSL_DISPATCH blowfish64cfb64_functions[];
#endif /* OPENSSL_NO_BF */
#ifndef OPENSSL_NO_IDEA
extern const char *idea128ecb_names[];
extern const OSSL_DISPATCH idea128ecb_functions[];
extern const char *idea128cbc_names[];
extern const OSSL_DISPATCH idea128cbc_functions[];
extern const char *idea128ofb64_names[];
extern const OSSL_DISPATCH idea128ofb64_functions[];
extern const char *idea128cfb64_names[];
extern const OSSL_DISPATCH idea128cfb64_functions[];
#endif /* OPENSSL_NO_IDEA */
#ifndef OPENSSL_NO_CAST
extern const char *cast5128ecb_names[];
extern const OSSL_DISPATCH cast5128ecb_functions[];
extern const char *cast5128cbc_names[];
extern const OSSL_DISPATCH cast5128cbc_functions[];
extern const char *cast564ofb64_names[];
extern const OSSL_DISPATCH cast564ofb64_functions[];
extern const char *cast564cfb64_names[];
extern const OSSL_DISPATCH cast564cfb64_functions[];
#endif /* OPENSSL_NO_CAST */
#ifndef OPENSSL_NO_SEED
extern const char *seed128ecb_names[];
extern const OSSL_DISPATCH seed128ecb_functions[];
extern const char *seed128cbc_names[];
extern const OSSL_DISPATCH seed128cbc_functions[];
extern const char *seed128ofb128_names[];
extern const OSSL_DISPATCH seed128ofb128_functions[];
extern const char *seed128cfb128_names[];
extern const OSSL_DISPATCH seed128cfb128_functions[];
#endif /* OPENSSL_NO_SEED */
#ifndef OPENSSL_NO_SM4
extern const char *sm4128ecb_names[];
extern const OSSL_DISPATCH sm4128ecb_functions[];
extern const char *sm4128cbc_names[];
extern const OSSL_DISPATCH sm4128cbc_functions[];
extern const char *sm4128ctr_names[];
extern const OSSL_DISPATCH sm4128ctr_functions[];
extern const char *sm4128ofb128_names[];
extern const OSSL_DISPATCH sm4128ofb128_functions[];
extern const char *sm4128cfb128_names[];
extern const OSSL_DISPATCH sm4128cfb128_functions[];
#endif /* OPENSSL_NO_SM4 */

#ifndef OPENSSL_NO_DES
extern const char *tdes_ede3_ecb_names[];
extern const OSSL_DISPATCH tdes_ede3_ecb_functions[];
extern const char *tdes_ede3_cbc_names[];
extern const OSSL_DISPATCH tdes_ede3_cbc_functions[];
# ifndef FIPS_MODE
extern const char *tdes_ede3_ofb_names[];
extern const OSSL_DISPATCH tdes_ede3_ofb_functions[];
extern const char *tdes_ede3_cfb_names[];
extern const OSSL_DISPATCH tdes_ede3_cfb_functions[];
extern const char *tdes_ede3_cfb8_names[];
extern const OSSL_DISPATCH tdes_ede3_cfb8_functions[];
extern const char *tdes_ede3_cfb1_names[];
extern const OSSL_DISPATCH tdes_ede3_cfb1_functions[];

extern const char *tdes_ede2_ecb_names[];
extern const OSSL_DISPATCH tdes_ede2_ecb_functions[];
extern const char *tdes_ede2_cbc_names[];
extern const OSSL_DISPATCH tdes_ede2_cbc_functions[];
extern const char *tdes_ede2_ofb_names[];
extern const OSSL_DISPATCH tdes_ede2_ofb_functions[];
extern const char *tdes_ede2_cfb_names[];
extern const OSSL_DISPATCH tdes_ede2_cfb_functions[];

extern const char *tdes_desx_cbc_names[];
extern const OSSL_DISPATCH tdes_desx_cbc_functions[];
extern const char *tdes_wrap_cbc_names[];
extern const OSSL_DISPATCH tdes_wrap_cbc_functions[];

extern const char *des_ecb_names[];
extern const OSSL_DISPATCH des_ecb_functions[];
extern const char *des_cbc_names[];
extern const OSSL_DISPATCH des_cbc_functions[];
extern const char *des_ofb64_names[];
extern const OSSL_DISPATCH des_ofb64_functions[];
extern const char *des_cfb64_names[];
extern const OSSL_DISPATCH des_cfb64_functions[];
extern const char *des_cfb1_names[];
extern const OSSL_DISPATCH des_cfb1_functions[];
extern const char *des_cfb8_names[];
extern const OSSL_DISPATCH des_cfb8_functions[];
# endif /* FIPS_MODE */
#endif /* OPENSSL_NO_DES */

#ifndef OPENSSL_NO_RC4
extern const OSSL_DISPATCH rc440_functions[];
extern const OSSL_DISPATCH rc4128_functions[];
#endif /* OPENSSL_NO_RC4 */

/* MACs */
extern const char *blake2bmac_names[];
extern const OSSL_DISPATCH blake2bmac_functions[];
extern const char *blake2smac_names[];
extern const OSSL_DISPATCH blake2smac_functions[];
extern const char *cmac_names[];
extern const OSSL_DISPATCH cmac_functions[];
extern const char *gmac_names[];
extern const OSSL_DISPATCH gmac_functions[];
extern const char *hmac_names[];
extern const OSSL_DISPATCH hmac_functions[];
extern const char *kmac128_names[];
extern const OSSL_DISPATCH kmac128_functions[];
extern const char *kmac256_names[];
extern const OSSL_DISPATCH kmac256_functions[];
extern const char *siphash_names[];
extern const OSSL_DISPATCH siphash_functions[];
extern const char *poly1305_names[];
extern const OSSL_DISPATCH poly1305_functions[];

/* KDFs / PRFs */
extern const char *kdf_pbkdf2_names[];
extern const OSSL_DISPATCH kdf_pbkdf2_functions[];
#ifndef OPENSSL_NO_SCRYPT
extern const char *kdf_scrypt_names[];
extern const OSSL_DISPATCH kdf_scrypt_functions[];
#endif
extern const char *kdf_tls1_prf_names[];
extern const OSSL_DISPATCH kdf_tls1_prf_functions[];
extern const char *kdf_hkdf_names[];
extern const OSSL_DISPATCH kdf_hkdf_functions[];
extern const char *kdf_sshkdf_names[];
extern const OSSL_DISPATCH kdf_sshkdf_functions[];
extern const char *kdf_sskdf_names[];
extern const OSSL_DISPATCH kdf_sskdf_functions[];
extern const char *kdf_x963_kdf_names[];
extern const OSSL_DISPATCH kdf_x963_kdf_functions[];
extern const OSSL_DISPATCH kdf_kbkdf_functions[];
#ifndef OPENSSL_NO_CMS
extern const char *kdf_x942_kdf_names[];
extern const OSSL_DISPATCH kdf_x942_kdf_functions[];
#endif


/* Names that are common for diverse public key operations */
extern const char *dh_names[];
extern const char *dsa_names[];

/* Key management */
extern const char *dh_keymgmt_names[];
extern const OSSL_DISPATCH dh_keymgmt_functions[];
extern const char *dsa_keymgmt_names[];
extern const OSSL_DISPATCH dsa_keymgmt_functions[];

/* Key Exchange */
extern const char *dh_keyexch_names[];
extern const OSSL_DISPATCH dh_keyexch_functions[];

/* Signature */
extern const char *dsa_signature_names[];
extern const OSSL_DISPATCH dsa_signature_functions[];
