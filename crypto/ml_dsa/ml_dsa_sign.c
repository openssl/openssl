/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"
#include "ml_dsa_params.h"
#include "ml_dsa_matrix.h"


/*
 * FIPS 204, Algorithm 7, ML-DSA.Sign_internal()
 * @returns 1 on success and 0 on failure.
 */
template <int K, int L>
static int ossl_ml_dsa_sign_internal(
    uint8_t out_encoded_signature[signature_bytes<K>()],
    const struct private_key<K, L> *priv, const uint8_t *msg, size_t msg_len,
    const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len,
    const uint8_t randomizer[MLDSA_SIGNATURE_RANDOMIZER_BYTES]) {
  uint8_t mu[kMuBytes];
  struct BORINGSSL_keccak_st keccak_ctx;
  BORINGSSL_keccak_init(&keccak_ctx, boringssl_shake256);
  BORINGSSL_keccak_absorb(&keccak_ctx, priv->public_key_hash,
                          sizeof(priv->public_key_hash));
  BORINGSSL_keccak_absorb(&keccak_ctx, context_prefix, context_prefix_len);
  BORINGSSL_keccak_absorb(&keccak_ctx, context, context_len);
  BORINGSSL_keccak_absorb(&keccak_ctx, msg, msg_len);
  BORINGSSL_keccak_squeeze(&keccak_ctx, mu, kMuBytes);

  uint8_t rho_prime[kRhoPrimeBytes];
  BORINGSSL_keccak_init(&keccak_ctx, boringssl_shake256);
  BORINGSSL_keccak_absorb(&keccak_ctx, priv->k, sizeof(priv->k));
  BORINGSSL_keccak_absorb(&keccak_ctx, randomizer,
                          MLDSA_SIGNATURE_RANDOMIZER_BYTES);
  BORINGSSL_keccak_absorb(&keccak_ctx, mu, kMuBytes);
  BORINGSSL_keccak_squeeze(&keccak_ctx, rho_prime, kRhoPrimeBytes);

  // Intermediate values, allocated on the heap to allow use when there is a
  // limited amount of stack.
  struct values_st {
    struct signature<K, L> sign;
    vector<L> s1_ntt;
    vector<K> s2_ntt;
    vector<K> t0_ntt;
    matrix<K, L> a_ntt;
    vector<L> y;
    vector<K> w;
    vector<K> w1;
    vector<L> cs1;
    vector<K> cs2;
  };
  std::unique_ptr<values_st, DeleterFree<values_st>> values(
      reinterpret_cast<struct values_st *>(OPENSSL_malloc(sizeof(values_st))));
  if (values == NULL) {
    return 0;
  }
  OPENSSL_memcpy(&values->s1_ntt, &priv->s1, sizeof(values->s1_ntt));
  vector_ntt(&values->s1_ntt);

  OPENSSL_memcpy(&values->s2_ntt, &priv->s2, sizeof(values->s2_ntt));
  vector_ntt(&values->s2_ntt);

  OPENSSL_memcpy(&values->t0_ntt, &priv->t0, sizeof(values->t0_ntt));
  vector_ntt(&values->t0_ntt);

  matrix_expand(&values->a_ntt, priv->rho);

  // kappa must not exceed 2**16/L = 13107. But the probability of it
  // exceeding even 1000 iterations is vanishingly small.
  for (size_t kappa = 0;; kappa += L) {
    vector_expand_mask(&values->y, rho_prime, kappa);

    vector<L> *y_ntt = &values->cs1;
    OPENSSL_memcpy(y_ntt, &values->y, sizeof(*y_ntt));
    vector_ntt(y_ntt);

    matrix_mult(&values->w, &values->a_ntt, y_ntt);
    vector_inverse_ntt(&values->w);

    vector_high_bits(&values->w1, &values->w);
    uint8_t w1_encoded[128 * K];
    w1_encode(w1_encoded, &values->w1);

    BORINGSSL_keccak_init(&keccak_ctx, boringssl_shake256);
    BORINGSSL_keccak_absorb(&keccak_ctx, mu, kMuBytes);
    BORINGSSL_keccak_absorb(&keccak_ctx, w1_encoded, 128 * K);
    BORINGSSL_keccak_squeeze(&keccak_ctx, values->sign.c_tilde,
                             2 * lambda_bytes<K>());

    scalar c_ntt;
    scalar_sample_in_ball_vartime(&c_ntt, values->sign.c_tilde,
                                  sizeof(values->sign.c_tilde), tau<K>());
    scalar_ntt(&c_ntt);

    vector_mult_scalar(&values->cs1, &values->s1_ntt, &c_ntt);
    vector_inverse_ntt(&values->cs1);
    vector_mult_scalar(&values->cs2, &values->s2_ntt, &c_ntt);
    vector_inverse_ntt(&values->cs2);

    vector_add(&values->sign.z, &values->y, &values->cs1);

    vector<K> *r0 = &values->w1;
    vector_sub(r0, &values->w, &values->cs2);
    vector_low_bits(r0, r0);

    // Leaking the fact that a signature was rejected is fine as the next
    // attempt at a signature will be (indistinguishable from) independent of
    // this one. Note, however, that we additionally leak which of the two
    // branches rejected the signature. Section 5.5 of
    // https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf
    // describes this leak as OK. Note we leak less than what is described by
    // the paper; we do not reveal which coefficient violated the bound, and
    // we hide which of the |z_max| or |r0_max| bound failed. See also
    // https://boringssl-review.googlesource.com/c/boringssl/+/67747/comment/2bbab0fa_d241d35a/
    uint32_t z_max = vector_max(&values->sign.z);
    uint32_t r0_max = vector_max_signed(r0);
    if (constant_time_declassify_w(
            constant_time_ge_w(z_max, gamma1<K>() - beta<K>()) |
            constant_time_ge_w(r0_max, kGamma2 - beta<K>()))) {
      continue;
    }

    vector<K> *ct0 = &values->w1;
    vector_mult_scalar(ct0, &values->t0_ntt, &c_ntt);
    vector_inverse_ntt(ct0);
    vector_make_hint(&values->sign.h, ct0, &values->cs2, &values->w);

    // See above.
    uint32_t ct0_max = vector_max(ct0);
    size_t h_ones = vector_count_ones(&values->sign.h);
    if (constant_time_declassify_w(constant_time_ge_w(ct0_max, kGamma2) |
                                   constant_time_lt_w(omega<K>(), h_ones))) {
      continue;
    }

    // Although computed with the private key, the signature is public.
    CONSTTIME_DECLASSIFY(values->sign.c_tilde, sizeof(values->sign.c_tilde));
    CONSTTIME_DECLASSIFY(&values->sign.z, sizeof(values->sign.z));
    CONSTTIME_DECLASSIFY(&values->sign.h, sizeof(values->sign.h));

    CBB cbb;
    CBB_init_fixed(&cbb, out_encoded_signature, signature_bytes<K>());
    if (!mldsa_marshal_signature(&cbb, &values->sign)) {
      return 0;
    }

    BSSL_CHECK(CBB_len(&cbb) == signature_bytes<K>());
    return 1;
  }
}



