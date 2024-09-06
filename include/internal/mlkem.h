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

# define mlkem512_SECRETKEYBYTES 1632
# define mlkem512_PUBLICKEYBYTES 800
# define mlkem512_CIPHERTEXTBYTES 768
# define mlkem512_KEYPAIRCOINBYTES 64
# define mlkem512_ENCCOINBYTES 32
# define mlkem512_BYTES 32

# define MLKEM512_REF_SECRETKEYBYTES mlkem512_SECRETKEYBYTES
# define MLKEM512_REF_PUBLICKEYBYTES mlkem512_PUBLICKEYBYTES
# define MLKEM512_REF_CIPHERTEXTBYTES mlkem512_CIPHERTEXTBYTES
# define MLKEM512_REF_KEYPAIRCOINBYTES mlkem512_KEYPAIRCOINBYTES
# define MLKEM512_REF_ENCCOINBYTES mlkem512_ENCCOINBYTES
# define MLKEM512_REF_BYTES mlkem512_BYTES

int mlkem512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int mlkem512_ref_keypair(uint8_t *pk, uint8_t *sk);
int mlkem512_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int mlkem512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

# define mlkem768_SECRETKEYBYTES 2400
# define mlkem768_PUBLICKEYBYTES 1184
# define mlkem768_CIPHERTEXTBYTES 1088
# define mlkem768_KEYPAIRCOINBYTES 64
# define mlkem768_ENCCOINBYTES 32
# define mlkem768_BYTES 32

# define MLKEM768_REF_SECRETKEYBYTES mlkem768_SECRETKEYBYTES
# define MLKEM768_REF_PUBLICKEYBYTES mlkem768_PUBLICKEYBYTES
# define MLKEM768_REF_CIPHERTEXTBYTES mlkem768_CIPHERTEXTBYTES
# define MLKEM768_REF_KEYPAIRCOINBYTES mlkem768_KEYPAIRCOINBYTES
# define MLKEM768_REF_ENCCOINBYTES mlkem768_ENCCOINBYTES
# define MLKEM768_REF_BYTES mlkem768_BYTES

int mlkem768_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int mlkem768_ref_keypair(uint8_t *pk, uint8_t *sk);
int mlkem768_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int mlkem768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

# define mlkem1024_SECRETKEYBYTES 3168
# define mlkem1024_PUBLICKEYBYTES 1568
# define mlkem1024_CIPHERTEXTBYTES 1568
# define mlkem1024_KEYPAIRCOINBYTES 64
# define mlkem1024_ENCCOINBYTES 32
# define mlkem1024_BYTES 32

# define MLKEM1024_REF_SECRETKEYBYTES mlkem1024_SECRETKEYBYTES
# define MLKEM1024_REF_PUBLICKEYBYTES mlkem1024_PUBLICKEYBYTES
# define MLKEM1024_REF_CIPHERTEXTBYTES mlkem1024_CIPHERTEXTBYTES
# define MLKEM1024_REF_KEYPAIRCOINBYTES mlkem1024_KEYPAIRCOINBYTES
# define MLKEM1024_REF_ENCCOINBYTES mlkem1024_ENCCOINBYTES
# define MLKEM1024_REF_BYTES mlkem1024_BYTES

int mlkem1024_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int mlkem1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int mlkem1024_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int mlkem1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* OSSL_INTERNAL_MLKEM_H */
