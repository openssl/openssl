#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;

#define polyvecl_uniform_eta DILITHIUM_NAMESPACE(_polyvecl_uniform_eta)
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[SEEDBYTES], uint16_t nonce);

#define polyvecl_uniform_gamma1 DILITHIUM_NAMESPACE(_polyvecl_uniform_gamma1)
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[SEEDBYTES], uint16_t nonce);

#define polyvecl_reduce DILITHIUM_NAMESPACE(_polyvecl_reduce)
void polyvecl_reduce(polyvecl *v);

#define polyvecl_freeze DILITHIUM_NAMESPACE(_polyvecl_freeze)
void polyvecl_freeze(polyvecl *v);

#define polyvecl_add DILITHIUM_NAMESPACE(_polyvecl_add)
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

#define polyvecl_ntt DILITHIUM_NAMESPACE(_polyvecl_ntt)
void polyvecl_ntt(polyvecl *v);
#define polyvecl_invntt_tomont DILITHIUM_NAMESPACE(_polyvecl_invntt_tomont)
void polyvecl_invntt_tomont(polyvecl *v);
#define polyvecl_pointwise_poly_montgomery DILITHIUM_NAMESPACE(_polyvecl_pointwise_poly_montgomery)
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
#define polyvecl_pointwise_acc_montgomery \
        DILITHIUM_NAMESPACE(_polyvecl_pointwise_acc_montgomery)
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);


#define polyvecl_chknorm DILITHIUM_NAMESPACE(_polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, int32_t B);



/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;

#define polyveck_uniform_eta DILITHIUM_NAMESPACE(_polyveck_uniform_eta)
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[SEEDBYTES], uint16_t nonce);

#define polyveck_reduce DILITHIUM_NAMESPACE(_polyveck_reduce)
void polyveck_reduce(polyveck *v);
#define polyveck_caddq DILITHIUM_NAMESPACE(_polyveck_caddq)
void polyveck_caddq(polyveck *v);
#define polyveck_freeze DILITHIUM_NAMESPACE(_polyveck_freeze)
void polyveck_freeze(polyveck *v);

#define polyveck_add DILITHIUM_NAMESPACE(_polyveck_add)
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_sub DILITHIUM_NAMESPACE(_polyveck_sub)
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_shiftl DILITHIUM_NAMESPACE(_polyveck_shiftl)
void polyveck_shiftl(polyveck *v);

#define polyveck_ntt DILITHIUM_NAMESPACE(_polyveck_ntt)
void polyveck_ntt(polyveck *v);
#define polyveck_invntt_tomont DILITHIUM_NAMESPACE(_polyveck_invntt_tomont)
void polyveck_invntt_tomont(polyveck *v);
#define polyveck_pointwise_poly_montgomery DILITHIUM_NAMESPACE(_polyveck_pointwise_poly_montgomery)
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);

#define polyveck_chknorm DILITHIUM_NAMESPACE(_polyveck_chknorm)
int polyveck_chknorm(const polyveck *v, int32_t B);

#define polyveck_power2round DILITHIUM_NAMESPACE(_polyveck_power2round)
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_decompose DILITHIUM_NAMESPACE(_polyveck_decompose)
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_make_hint DILITHIUM_NAMESPACE(_polyveck_make_hint)
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
#define polyveck_use_hint DILITHIUM_NAMESPACE(_polyveck_use_hint)
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

#define polyveck_pack_w1 DILITHIUM_NAMESPACE(_polyveck_pack_w1)
void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1);

#define polyvec_matrix_expand DILITHIUM_NAMESPACE(_polyvec_matrix_expand)
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);

#define polyvec_matrix_pointwise_montgomery DILITHIUM_NAMESPACE(_polyvec_matrix_pointwise_montgomery)
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);

#endif
