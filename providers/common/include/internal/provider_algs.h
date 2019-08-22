/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Digests */
extern const OSSL_DISPATCH sha1_functions[];
extern const OSSL_DISPATCH sha224_functions[];
extern const OSSL_DISPATCH sha256_functions[];
extern const OSSL_DISPATCH sha384_functions[];
extern const OSSL_DISPATCH sha512_functions[];
extern const OSSL_DISPATCH sha512_224_functions[];
extern const OSSL_DISPATCH sha512_256_functions[];
extern const OSSL_DISPATCH sha3_224_functions[];
extern const OSSL_DISPATCH sha3_256_functions[];
extern const OSSL_DISPATCH sha3_384_functions[];
extern const OSSL_DISPATCH sha3_512_functions[];
extern const OSSL_DISPATCH keccak_kmac_128_functions[];
extern const OSSL_DISPATCH keccak_kmac_256_functions[];
extern const OSSL_DISPATCH shake_128_functions[];
extern const OSSL_DISPATCH shake_256_functions[];
extern const OSSL_DISPATCH blake2s256_functions[];
extern const OSSL_DISPATCH blake2b512_functions[];
extern const OSSL_DISPATCH md5_functions[];
extern const OSSL_DISPATCH md5_sha1_functions[];
extern const OSSL_DISPATCH sm3_functions[];
extern const OSSL_DISPATCH md2_functions[];
extern const OSSL_DISPATCH md4_functions[];
extern const OSSL_DISPATCH mdc2_functions[];
extern const OSSL_DISPATCH wp_functions[];
extern const OSSL_DISPATCH ripemd160_functions[];

/* Ciphers */
extern const OSSL_DISPATCH aes256ecb_functions[];
extern const OSSL_DISPATCH aes192ecb_functions[];
extern const OSSL_DISPATCH aes128ecb_functions[];
extern const OSSL_DISPATCH aes256cbc_functions[];
extern const OSSL_DISPATCH aes192cbc_functions[];
extern const OSSL_DISPATCH aes128cbc_functions[];
extern const OSSL_DISPATCH aes256ofb_functions[];
extern const OSSL_DISPATCH aes192ofb_functions[];
extern const OSSL_DISPATCH aes128ofb_functions[];
extern const OSSL_DISPATCH aes256cfb_functions[];
extern const OSSL_DISPATCH aes192cfb_functions[];
extern const OSSL_DISPATCH aes128cfb_functions[];
extern const OSSL_DISPATCH aes256cfb1_functions[];
extern const OSSL_DISPATCH aes192cfb1_functions[];
extern const OSSL_DISPATCH aes128cfb1_functions[];
extern const OSSL_DISPATCH aes256cfb8_functions[];
extern const OSSL_DISPATCH aes192cfb8_functions[];
extern const OSSL_DISPATCH aes128cfb8_functions[];
extern const OSSL_DISPATCH aes256ctr_functions[];
extern const OSSL_DISPATCH aes192ctr_functions[];
extern const OSSL_DISPATCH aes128ctr_functions[];
extern const OSSL_DISPATCH aes256gcm_functions[];
extern const OSSL_DISPATCH aes192gcm_functions[];
extern const OSSL_DISPATCH aes128gcm_functions[];
extern const OSSL_DISPATCH aes256ccm_functions[];
extern const OSSL_DISPATCH aes192ccm_functions[];
extern const OSSL_DISPATCH aes128ccm_functions[];
#ifndef OPENSSL_NO_ARIA
extern const OSSL_DISPATCH aria256gcm_functions[];
extern const OSSL_DISPATCH aria192gcm_functions[];
extern const OSSL_DISPATCH aria128gcm_functions[];
extern const OSSL_DISPATCH aria256ccm_functions[];
extern const OSSL_DISPATCH aria192ccm_functions[];
extern const OSSL_DISPATCH aria128ccm_functions[];
extern const OSSL_DISPATCH aria256ecb_functions[];
extern const OSSL_DISPATCH aria192ecb_functions[];
extern const OSSL_DISPATCH aria128ecb_functions[];
extern const OSSL_DISPATCH aria256cbc_functions[];
extern const OSSL_DISPATCH aria192cbc_functions[];
extern const OSSL_DISPATCH aria128cbc_functions[];
extern const OSSL_DISPATCH aria256ofb_functions[];
extern const OSSL_DISPATCH aria192ofb_functions[];
extern const OSSL_DISPATCH aria128ofb_functions[];
extern const OSSL_DISPATCH aria256cfb_functions[];
extern const OSSL_DISPATCH aria192cfb_functions[];
extern const OSSL_DISPATCH aria128cfb_functions[];
extern const OSSL_DISPATCH aria256cfb1_functions[];
extern const OSSL_DISPATCH aria192cfb1_functions[];
extern const OSSL_DISPATCH aria128cfb1_functions[];
extern const OSSL_DISPATCH aria256cfb8_functions[];
extern const OSSL_DISPATCH aria192cfb8_functions[];
extern const OSSL_DISPATCH aria128cfb8_functions[];
extern const OSSL_DISPATCH aria256ctr_functions[];
extern const OSSL_DISPATCH aria192ctr_functions[];
extern const OSSL_DISPATCH aria128ctr_functions[];
#endif /* OPENSSL_NO_ARIA */
#ifndef OPENSSL_NO_CAMELLIA
extern const OSSL_DISPATCH camellia256ecb_functions[];
extern const OSSL_DISPATCH camellia192ecb_functions[];
extern const OSSL_DISPATCH camellia128ecb_functions[];
extern const OSSL_DISPATCH camellia256cbc_functions[];
extern const OSSL_DISPATCH camellia192cbc_functions[];
extern const OSSL_DISPATCH camellia128cbc_functions[];
extern const OSSL_DISPATCH camellia256ofb_functions[];
extern const OSSL_DISPATCH camellia192ofb_functions[];
extern const OSSL_DISPATCH camellia128ofb_functions[];
extern const OSSL_DISPATCH camellia256cfb_functions[];
extern const OSSL_DISPATCH camellia192cfb_functions[];
extern const OSSL_DISPATCH camellia128cfb_functions[];
extern const OSSL_DISPATCH camellia256cfb1_functions[];
extern const OSSL_DISPATCH camellia192cfb1_functions[];
extern const OSSL_DISPATCH camellia128cfb1_functions[];
extern const OSSL_DISPATCH camellia256cfb8_functions[];
extern const OSSL_DISPATCH camellia192cfb8_functions[];
extern const OSSL_DISPATCH camellia128cfb8_functions[];
extern const OSSL_DISPATCH camellia256ctr_functions[];
extern const OSSL_DISPATCH camellia192ctr_functions[];
extern const OSSL_DISPATCH camellia128ctr_functions[];
#endif /* OPENSSL_NO_CAMELLIA */

/* MACs */
extern const OSSL_DISPATCH blake2bmac_functions[];
extern const OSSL_DISPATCH blake2smac_functions[];
extern const OSSL_DISPATCH cmac_functions[];
extern const OSSL_DISPATCH gmac_functions[];
extern const OSSL_DISPATCH hmac_functions[];
extern const OSSL_DISPATCH kmac128_functions[];
extern const OSSL_DISPATCH kmac256_functions[];
extern const OSSL_DISPATCH siphash_functions[];
extern const OSSL_DISPATCH poly1305_functions[];

/* Key management */
extern const OSSL_DISPATCH dh_keymgmt_functions[];

/* Key Exchange */
extern const OSSL_DISPATCH dh_keyexch_functions[];
