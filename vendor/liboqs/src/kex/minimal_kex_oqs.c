/*
 * minimal_kex_oqs.c
 *
 * Minimal example of a Diffie-Hellman post-quantum key exchange method
 * implemented in liboqs.
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

/* Cleaning up memory etc */
void cleanup(uint8_t *alice_msg, size_t alice_msg_len, uint8_t *alice_key,
             size_t alice_key_len, uint8_t *bob_msg, size_t bob_msg_len,
             uint8_t *bob_key, size_t bob_key_len, void *alice_priv,
             OQS_KEX *kex, OQS_RAND *rnd);

#ifdef ENABLE_KEX_LWE_FRODO
int main(void) {
	/* Key exchange parameters */
	void *alice_priv = NULL;   // Alice's private key
	uint8_t *alice_msg = NULL; // Alice's message
	size_t alice_msg_len = 0;  // Alice's message length
	uint8_t *alice_key = NULL; // Alice's final key
	size_t alice_key_len = 0;  // Alice's final key length

	uint8_t *bob_msg = NULL; // Bob's message
	size_t bob_msg_len = 0;  // Bob's message length
	uint8_t *bob_key = NULL; // Bob's final key
	size_t bob_key_len = 0;  // Bob's final key length

	/* Setup the key exchange protocol */
	enum OQS_KEX_alg_name alg_name = OQS_KEX_alg_lwe_frodo;      // Alg. name
	const uint8_t *seed = (unsigned char *) "01234567890123456"; // Rand. seed
	const size_t seed_len = 16;                                  // Seed length
	const char *named_parameters = "recommended";                // Named params.
	OQS_RAND *rnd = NULL;                                        // Source of randomness
	OQS_KEX *kex = NULL;                                         // OQS_KEX structure

	/* Setup the source of randomness */
	rnd = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
	if (rnd == NULL) {
		eprintf("ERROR: Setting up the randomness source!\n");
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	/* Populate the OQS_KEX structure, here's where liboqs sets up
     * the specific details of the selected KEX implementation */
	kex = OQS_KEX_new(rnd, alg_name, seed, seed_len, named_parameters);
	if (kex == NULL) {
		eprintf("ERROR: OQS_KEX_new failed!\n");
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	/* Proceed with the Diffie-Hellman key exchange mechanism */
	printf("===============================================================\n");
	printf("Diffie-Hellman post-quantum key exchange: %s\n", kex->method_name);
	printf("===============================================================\n");

	/* Alice's initial message */
	int success = OQS_KEX_alice_0(kex, &alice_priv, &alice_msg, &alice_msg_len);
	if (success != OQS_SUCCESS) {
		eprintf("ERROR: OQS_KEX_alice_0 failed!\n");
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	OQS_print_part_hex_string("Alice message", alice_msg, alice_msg_len, 20);

	/* Bob's response */
	success = OQS_KEX_bob(kex, alice_msg, alice_msg_len, &bob_msg, &bob_msg_len,
	                      &bob_key, &bob_key_len);
	if (success != OQS_SUCCESS) {
		eprintf("ERROR: OQS_KEX_bob failed!\n");
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	OQS_print_part_hex_string("Bob message", bob_msg, bob_msg_len, 20);
	OQS_print_hex_string("Bob session key", bob_key, bob_key_len);

	/* Alice processes Bob's response */
	success = OQS_KEX_alice_1(kex, alice_priv, bob_msg, bob_msg_len, &alice_key,
	                          &alice_key_len);
	if (success != OQS_SUCCESS) {
		eprintf("ERROR: OQS_KEX_alice_1 failed!\n");
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	OQS_print_hex_string("Alice session key", alice_key, alice_key_len);

	/* Compare key lengths */
	if (alice_key_len != bob_key_len) {
		eprintf("ERROR: Alice's session key and Bob's session keys "
		        "have different lengths (%zu vs %zu)!\n",
		        alice_key_len, bob_key_len);
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	/* Compare key values */
	success = memcmp(alice_key, bob_key, alice_key_len);
	if (success != 0) {
		eprintf("ERROR: Alice's session key and Bob's session "
		        "key are not equal!\n");
		OQS_print_hex_string("Alice session key", alice_key, alice_key_len);
		OQS_print_hex_string("Bob session key", bob_key, bob_key_len);
		cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
		        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

		return EXIT_FAILURE;
	}

	/* Success and clean-up */
	printf("Alice and Bob's session keys match.\n");
	cleanup(alice_msg, alice_msg_len, alice_key, alice_key_len, bob_msg,
	        bob_msg_len, bob_key, bob_key_len, alice_priv, kex, rnd);

	return EXIT_SUCCESS;
}
#else // !ENABLE_KEX_LWE_FRODO
int main(void) {
	printf("KEX algorithm not available. Make sure configure was run properly; see Readme.md.\n");
	return EXIT_FAILURE;
}
#endif

void cleanup(uint8_t *alice_msg, size_t alice_msg_len, uint8_t *alice_key,
             size_t alice_key_len, uint8_t *bob_msg, size_t bob_msg_len,
             uint8_t *bob_key, size_t bob_key_len, void *alice_priv,
             OQS_KEX *kex, OQS_RAND *rnd) {
	/* Secure cleaning */
	OQS_MEM_secure_free(alice_msg, alice_msg_len);
	OQS_MEM_secure_free(alice_key, alice_key_len);
	OQS_MEM_secure_free(bob_msg, bob_msg_len);
	OQS_MEM_secure_free(bob_key, bob_key_len);
	OQS_KEX_alice_priv_free(kex, alice_priv);
	OQS_KEX_free(kex);
	OQS_RAND_free(rnd);
}
