/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_MLKEM_H
# define OSSL_INTERNAL_MLKEM_H
# pragma once

# include <stdint.h>

# define MLKEM512_SECRETKEYBYTES 1632
# define MLKEM512_PUBLICKEYBYTES 800
# define MLKEM512_CIPHERTEXTBYTES 768
# define MLKEM512_KEYPAIRCOINBYTES 64
# define MLKEM512_ENCCOINBYTES 32
# define MLKEM512_BYTES 32

# define MLKEM512_REF_SECRETKEYBYTES MLKEM512_SECRETKEYBYTES
# define MLKEM512_REF_PUBLICKEYBYTES MLKEM512_PUBLICKEYBYTES
# define MLKEM512_REF_CIPHERTEXTBYTES MLKEM512_CIPHERTEXTBYTES
# define MLKEM512_REF_KEYPAIRCOINBYTES MLKEM512_KEYPAIRCOINBYTES
# define MLKEM512_REF_ENCCOINBYTES MLKEM512_ENCCOINBYTES
# define MLKEM512_REF_BYTES MLKEM512_BYTES

int mlkem512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int mlkem512_ref_keypair(uint8_t *pk, uint8_t *sk);
int mlkem512_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int mlkem512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

# define MLKEM768_SECRETKEYBYTES 2400
# define MLKEM768_PUBLICKEYBYTES 1184
# define MLKEM768_CIPHERTEXTBYTES 1088
# define MLKEM768_KEYPAIRCOINBYTES 64
# define MLKEM768_ENCCOINBYTES 32
# define MLKEM768_BYTES 32
# define MLKEM768_SECURITY_BITS 192 /* TODO(ML-KEM): CHECK ME */

# define MLKEM768_REF_SECRETKEYBYTES MLKEM768_SECRETKEYBYTES
# define MLKEM768_REF_PUBLICKEYBYTES MLKEM768_PUBLICKEYBYTES
# define MLKEM768_REF_CIPHERTEXTBYTES MLKEM768_CIPHERTEXTBYTES
# define MLKEM768_REF_KEYPAIRCOINBYTES MLKEM768_KEYPAIRCOINBYTES
# define MLKEM768_REF_ENCCOINBYTES MLKEM768_ENCCOINBYTES
# define MLKEM768_REF_BYTES MLKEM768_BYTES

int mlkem768_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int mlkem768_ref_keypair(uint8_t *pk, uint8_t *sk);
int mlkem768_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int mlkem768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

# define MLKEM1024_SECRETKEYBYTES 3168
# define MLKEM1024_PUBLICKEYBYTES 1568
# define MLKEM1024_CIPHERTEXTBYTES 1568
# define MLKEM1024_KEYPAIRCOINBYTES 64
# define MLKEM1024_ENCCOINBYTES 32
# define MLKEM1024_BYTES 32

# define MLKEM1024_REF_SECRETKEYBYTES MLKEM1024_SECRETKEYBYTES
# define MLKEM1024_REF_PUBLICKEYBYTES MLKEM1024_PUBLICKEYBYTES
# define MLKEM1024_REF_CIPHERTEXTBYTES MLKEM1024_CIPHERTEXTBYTES
# define MLKEM1024_REF_KEYPAIRCOINBYTES MLKEM1024_KEYPAIRCOINBYTES
# define MLKEM1024_REF_ENCCOINBYTES MLKEM1024_ENCCOINBYTES
# define MLKEM1024_REF_BYTES MLKEM1024_BYTES

int mlkem1024_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int mlkem1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int mlkem1024_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int mlkem1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

# define MLKEM_KEY_TYPE_512     0
# define MLKEM_KEY_TYPE_768     1
# define MLKEY_KEY_TYPE_1024    2

typedef struct mlkem_key_st {
    int keytype;
    uint8_t *seckey;
    uint8_t *pubkey;
} MLKEM_KEY;

#endif /* OSSL_INTERNAL_MLKEM_H */
