#include "params.h"
#include <oqs/rand.h>
#include <oqs/sha3.h>

static void pack_pk(unsigned char *r, const polyvec *pk, const unsigned char *seed) {
	int i;
	polyvec_compress(r, pk);
	for (i = 0; i < KYBER_SEEDBYTES; i++)
		r[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
}

static void unpack_pk(polyvec *pk, unsigned char *seed, const unsigned char *packedpk) {
	int i;
	polyvec_decompress(pk, packedpk);

	for (i = 0; i < KYBER_SEEDBYTES; i++)
		seed[i] = packedpk[i + KYBER_POLYVECCOMPRESSEDBYTES];
}

static void pack_ciphertext(unsigned char *r, const polyvec *b, const poly *v) {
	polyvec_compress(r, b);
	poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const unsigned char *c) {
	polyvec_decompress(b, c);
	poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static void pack_sk(unsigned char *r, const polyvec *sk) {
	polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const unsigned char *packedsk) {
	polyvec_frombytes(sk, packedsk);
}

#define gen_a(A, B) gen_matrix(A, B, 0)
#define gen_at(A, B) gen_matrix(A, B, 1)

/* Generate entry a_{i,j} of matrix A as Parse(SHAKE128(seed|i|j)) */
static void gen_matrix(polyvec *a, const unsigned char *seed, int transposed) //XXX: Not static for benchmarking
{
	unsigned int pos = 0, ctr;
	uint16_t val;
	unsigned int nblocks = 4;
	uint8_t buf[OQS_SHA3_SHAKE128_RATE * 4]; // was * nblocks, but VS doesn't like this buf init
	int i, j;
	uint16_t dsep;
	uint64_t state[25]; // CSHAKE state

	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_D; j++) {
			ctr = pos = 0;
			if (transposed)
				dsep = j + (i << 8);
			else
				dsep = i + (j << 8);

			OQS_SHA3_cshake128_simple_absorb(state, dsep, seed, KYBER_SEEDBYTES);
			OQS_SHA3_cshake128_simple_squeezeblocks(buf, nblocks, state);

			while (ctr < KYBER_N) {
				val = (buf[pos] | ((uint16_t) buf[pos + 1] << 8)) & 0x1fff;
				if (val < KYBER_Q) {
					a[i].vec[j].coeffs[ctr++] = val;
				}
				pos += 2;

				if (pos > OQS_SHA3_SHAKE128_RATE * nblocks - 2) {
					nblocks = 1;
					OQS_SHA3_cshake128_simple_squeezeblocks(buf, nblocks, state);
					pos = 0;
				}
			}
		}
	}
}

static void indcpa_keypair(unsigned char *pk,
                           unsigned char *sk, OQS_RAND *rand) {
	polyvec a[KYBER_D], e, pkpv, skpv;
	unsigned char seed[KYBER_SEEDBYTES];
	unsigned char noiseseed[KYBER_COINBYTES];
	int i;
	unsigned char nonce = 0;

	rand->rand_n(rand, seed, KYBER_SEEDBYTES);
	OQS_SHA3_shake128(seed, KYBER_SEEDBYTES, seed, KYBER_SEEDBYTES); /* Don't send output of system RNG */
	rand->rand_n(rand, noiseseed, KYBER_COINBYTES);

	gen_a(a, seed);

	for (i = 0; i < KYBER_D; i++)
		poly_getnoise(skpv.vec + i, noiseseed, nonce++);

	polyvec_ntt(&skpv);

	for (i = 0; i < KYBER_D; i++)
		poly_getnoise(e.vec + i, noiseseed, nonce++);

	// matrix-vector multiplication
	for (i = 0; i < KYBER_D; i++)
		polyvec_pointwise_acc(&pkpv.vec[i], &skpv, a + i);

	polyvec_invntt(&pkpv);
	polyvec_add(&pkpv, &pkpv, &e);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, seed);
}

static void indcpa_enc(unsigned char *c,
                       const unsigned char *m,
                       const unsigned char *pk,
                       const unsigned char *coins) {
	polyvec sp, pkpv, ep, at[KYBER_D], bp;
	poly v, k, epp;
	unsigned char seed[KYBER_SEEDBYTES];
	int i;
	unsigned char nonce = 0;

	unpack_pk(&pkpv, seed, pk);

	poly_frommsg(&k, m);

	for (i = 0; i < KYBER_D; i++)
		bitrev_vector(pkpv.vec[i].coeffs);
	polyvec_ntt(&pkpv);

	gen_at(at, seed);

	for (i = 0; i < KYBER_D; i++)
		poly_getnoise(sp.vec + i, coins, nonce++);

	polyvec_ntt(&sp);

	for (i = 0; i < KYBER_D; i++)
		poly_getnoise(ep.vec + i, coins, nonce++);

	// matrix-vector multiplication
	for (i = 0; i < KYBER_D; i++)
		polyvec_pointwise_acc(&bp.vec[i], &sp, at + i);

	polyvec_invntt(&bp);
	polyvec_add(&bp, &bp, &ep);

	polyvec_pointwise_acc(&v, &pkpv, &sp);
	poly_invntt(&v);

	poly_getnoise(&epp, coins, nonce++);

	poly_add(&v, &v, &epp);
	poly_add(&v, &v, &k);

	pack_ciphertext(c, &bp, &v);
}

static void indcpa_dec(unsigned char *m,
                       const unsigned char *c,
                       const unsigned char *sk) {
	polyvec bp, skpv;
	poly v, mp;
	size_t i;

	unpack_ciphertext(&bp, &v, c);
	unpack_sk(&skpv, sk);

	for (i = 0; i < KYBER_D; i++)
		bitrev_vector(bp.vec[i].coeffs);
	polyvec_ntt(&bp);

	polyvec_pointwise_acc(&mp, &skpv, &bp);
	poly_invntt(&mp);

	poly_sub(&mp, &mp, &v);

	poly_tomsg(m, &mp);
}
