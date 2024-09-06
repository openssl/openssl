#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include <immintrin.h>

#define ntt_avx KYBER_NAMESPACE(ntt_avx)
void ntt_avx(__m256i *r, const __m256i *qdata);
#define invntt_avx KYBER_NAMESPACE(invntt_avx)
void invntt_avx(__m256i *r, const __m256i *qdata);

#define nttpack_avx KYBER_NAMESPACE(nttpack_avx)
void nttpack_avx(__m256i *r, const __m256i *qdata);
#define nttunpack_avx KYBER_NAMESPACE(nttunpack_avx)
void nttunpack_avx(__m256i *r, const __m256i *qdata);

#define basemul_avx KYBER_NAMESPACE(basemul_avx)
void basemul_avx(__m256i *r,
                 const __m256i *a,
                 const __m256i *b,
                 const __m256i *qdata);

#define ntttobytes_avx KYBER_NAMESPACE(ntttobytes_avx)
void ntttobytes_avx(uint8_t *r, const __m256i *a, const __m256i *qdata);
#define nttfrombytes_avx KYBER_NAMESPACE(nttfrombytes_avx)
void nttfrombytes_avx(__m256i *r, const uint8_t *a, const __m256i *qdata);

#endif
