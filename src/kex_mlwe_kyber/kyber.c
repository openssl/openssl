#include <stdint.h>

#include <oqs/sha3.h>
#include <oqs/rand.h>

// clang-format off
// (order of include matters)
#include "precomp.c"
#include "reduce.c"
#include "verify.c"
#include "ntt.c"
#include "poly.c"
#include "polyvec.c"
#include "indcpa.c"
// clang-format on

// API FUNCTIONS

/* Build a CCA-secure KEM from an IND-CPA-secure encryption scheme */

static void keygen(unsigned char *pk, unsigned char *sk, OQS_RAND *rand) {
	size_t i;
	indcpa_keypair(pk, sk, rand);
	for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
		sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	OQS_SHA3_shake128(sk + KYBER_SECRETKEYBYTES - 64, 32, pk, KYBER_PUBLICKEYBYTES);
	rand->rand_n(rand, sk + KYBER_SECRETKEYBYTES - KYBER_SHAREDKEYBYTES, KYBER_SHAREDKEYBYTES); /* Value z for pseudo-random output on reject */
}

static void sharedb(unsigned char *sharedkey, unsigned char *send,
                    const unsigned char *received, OQS_RAND *rand) {
	unsigned char krq[96]; /* Will contain key, coins, qrom-hash */
	unsigned char buf[64];
	int i;

	rand->rand_n(rand, buf, 32);
	OQS_SHA3_shake128(buf, 32, buf, 32); /* Don't release system RNG output */

	OQS_SHA3_shake128(buf + 32, 32, received, KYBER_PUBLICKEYBYTES); /* Multitarget countermeasure for coins + contributory KEM */
	OQS_SHA3_shake128(krq, 96, buf, 64);

	indcpa_enc(send, buf, received, krq + 32); /* coins are in krq+32 */

	for (i = 0; i < 32; i++)
		send[i + KYBER_INDCPA_BYTES] = krq[i + 64];

	OQS_SHA3_shake128(krq + 32, 32, send, KYBER_BYTES); /* overwrite coins in krq with h(c) */
	OQS_SHA3_shake128(sharedkey, 32, krq, 64);          /* hash concatenation of pre-k and h(c) to k */

#ifndef STATISTICAL_TEST
	OQS_SHA3_sha3256(sharedkey, sharedkey, 32);
#endif
}

static void shareda(unsigned char *sharedkey, const unsigned char *sk,
                    const unsigned char *received) {
	int i, fail;
	unsigned char cmp[KYBER_BYTES];
	unsigned char buf[64];
	unsigned char krq[96]; /* Will contain key, coins, qrom-hash */
	const unsigned char *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	indcpa_dec(buf, received, sk);

	// shake128(buf+32, 32, pk, KYBER_PUBLICKEYBYTES); /* Multitarget countermeasure for coins + contributory KEM */
	for (i = 0; i < 32; i++) /* Save hash by storing h(pk) in sk */
		buf[32 + i] = sk[KYBER_SECRETKEYBYTES - 64 + i];
	OQS_SHA3_shake128(krq, 96, buf, 64);

	indcpa_enc(cmp, buf, pk, krq + 32); /* coins are in krq+32 */

	for (i = 0; i < 32; i++)
		cmp[i + KYBER_INDCPA_BYTES] = krq[i + 64];

	fail = verify(received, cmp, KYBER_BYTES);

	OQS_SHA3_shake128(krq + 32, 32, received, KYBER_BYTES); /* overwrite coins in krq with h(c)  */

	cmov(krq, sk + KYBER_SECRETKEYBYTES - KYBER_SHAREDKEYBYTES, KYBER_SHAREDKEYBYTES, fail); /* Overwrite pre-k with z on re-encryption failure */

	OQS_SHA3_shake128(sharedkey, 32, krq, 64); /* hash concatenation of pre-k and h(c) to k */

#ifndef STATISTICAL_TEST
	OQS_SHA3_sha3256(sharedkey, sharedkey, 32);
#endif
}
