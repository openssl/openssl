/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/

#include <string.h>
#include "sha3/fips202.h"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, OQS_RAND *rand) { // SIKE's key generation
	                                                                           // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
	                                                                           //          public key pk (CRYPTO_PUBLICKEYBYTES bytes)

	// Generate lower portion of secret key sk <- s||SK
	OQS_RAND_n(rand, sk, MSG_BYTES);
	random_mod_order_B(sk + MSG_BYTES, rand);

	// Generate public key pk
	EphemeralKeyGeneration_B(sk + MSG_BYTES, pk, rand);

	// Append public key pk to secret key sk
	memcpy(&sk[MSG_BYTES + SECRETKEY_B_BYTES], pk, OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES);

	return 0;
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk, OQS_RAND *rand) { // SIKE's encapsulation
	                                                                                                // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
	                                                                                                // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
	                                                                                                //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
	const uint16_t G = 0;
	const uint16_t H = 1;
	const uint16_t P = 2;
	unsigned char ephemeralsk[SECRETKEY_A_BYTES];
	unsigned char jinvariant[FP2_ENCODED_BYTES];
	unsigned char h[MSG_BYTES];
	unsigned char temp[OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES + MSG_BYTES];
	unsigned int i;

	// Generate ephemeralsk <- G(m||pk) mod oA
	OQS_RAND_n(rand, temp, MSG_BYTES);
	memcpy(&temp[MSG_BYTES], pk, OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES);
	cshake256_simple(ephemeralsk, SECRETKEY_A_BYTES, G, temp, OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES + MSG_BYTES);
	ephemeralsk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

	// Encrypt
	EphemeralKeyGeneration_A(ephemeralsk, ct, rand);
	EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);
	cshake256_simple(h, MSG_BYTES, P, jinvariant, FP2_ENCODED_BYTES);
	for (i = 0; i < MSG_BYTES; i++)
		ct[i + OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];

	// Generate shared secret ss <- H(m||ct)
	memcpy(&temp[MSG_BYTES], ct, OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES);
	cshake256_simple(ss, OQS_SIDH_MSR_CRYPTO_BYTES, H, temp, OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);

	return 0;
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk, OQS_RAND *rand) { // SIKE's decapsulation
	                                                                                                      // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
	                                                                                                      //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
	                                                                                                      // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
	const uint16_t G = 0;
	const uint16_t H = 1;
	const uint16_t P = 2;
	unsigned char ephemeralsk_[SECRETKEY_A_BYTES];
	unsigned char jinvariant_[FP2_ENCODED_BYTES];
	unsigned char h_[MSG_BYTES];
	unsigned char c0_[OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES];
	unsigned char temp[OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES + MSG_BYTES];
	unsigned int i;

	// Decrypt
	EphemeralSecretAgreement_B(sk + MSG_BYTES, ct, jinvariant_);
	cshake256_simple(h_, MSG_BYTES, P, jinvariant_, FP2_ENCODED_BYTES);
	for (i = 0; i < MSG_BYTES; i++)
		temp[i] = ct[i + OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES] ^ h_[i];

	// Generate ephemeralsk_ <- G(m||pk) mod oA
	memcpy(&temp[MSG_BYTES], &sk[MSG_BYTES + SECRETKEY_B_BYTES], OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES);
	cshake256_simple(ephemeralsk_, SECRETKEY_A_BYTES, G, temp, OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES + MSG_BYTES);
	ephemeralsk_[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

	// Generate shared secret ss <- H(m||ct) or output ss <- H(s||ct)
	EphemeralKeyGeneration_A(ephemeralsk_, c0_, rand);
	if (memcmp(c0_, ct, OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES) != 0) {
		memcpy(temp, sk, MSG_BYTES);
	}
	memcpy(&temp[MSG_BYTES], ct, OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES);
	cshake256_simple(ss, OQS_SIDH_MSR_CRYPTO_BYTES, H, temp, OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);

	return 0;
}
