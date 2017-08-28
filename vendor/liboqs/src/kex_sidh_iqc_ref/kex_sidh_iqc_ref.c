#if defined(WINDOWS)
#define UNUSED
#else
#define UNUSED __attribute__((unused))
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sidh_elliptic_curve.h"
#include "sidh_public_param.h"
#include "sidh_isogeny.h"
#include "sidh_private_key.h"
#include "sidh_public_key.h"
#include "sidh_shared_key.h"
#include "kex_sidh_iqc_ref.h"

OQS_KEX *OQS_KEX_sidh_iqc_ref_new(OQS_RAND *rand) {

	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		return NULL;
	}

	// initialize
	//	char *input_params = "sample_params/public_params_771";
	public_params_t *params =
	    (public_params_t *) malloc(2 * sizeof(public_params_t));
	oqs_sidh_iqc_ref_public_params_init(params[0]);
	oqs_sidh_iqc_ref_public_params_init(params[1]);

	if (!oqs_sidh_iqc_ref_public_params_read(params[0], params[1], "sample_params/public_params_771"))
		return NULL;

	oqs_sidh_iqc_ref_fp_init_chararacteristic(params[0]->characteristic);

	k->rand = rand;
	k->method_name = strdup("SIDH IQC REFERENCE");
	k->estimated_classical_security = 192;
	k->estimated_quantum_security = 128;
	k->seed = NULL;
	k->seed_len = 0;
	k->named_parameters = strdup("sample_params/public_params_771");
	k->params = params;
	k->ctx = NULL;
	k->alice_0 = &OQS_KEX_sidh_iqc_ref_alice_0;
	k->bob = &OQS_KEX_sidh_iqc_ref_bob;
	k->alice_1 = &OQS_KEX_sidh_iqc_ref_alice_1;
	k->alice_priv_free = &OQS_KEX_sidh_iqc_ref_alice_priv_free;
	k->free = &OQS_KEX_sidh_iqc_ref_free;

	return k;
}

int OQS_KEX_sidh_iqc_ref_alice_0(OQS_KEX *k, void **alice_priv,
                                 uint8_t **alice_msg, size_t *alice_msg_len) {

	public_params_t *params = (public_params_t *) k->params;
	private_key_t Alice_private_key;
	oqs_sidh_iqc_ref_private_key_init(Alice_private_key);
	oqs_sidh_iqc_ref_private_key_generate(Alice_private_key, params[0]);

	public_key_t Alice_public_key;
	oqs_sidh_iqc_ref_public_key_init(Alice_public_key);
	point_t kernel_gen;
	oqs_sidh_iqc_ref_point_init(kernel_gen);
	oqs_sidh_iqc_ref_private_key_compute_kernel_gen(kernel_gen, Alice_private_key,
	                                                params[0]->P, params[0]->Q,
	                                                params[0]->le, params[0]->E);
	oqs_sidh_iqc_ref_public_key_generate(Alice_public_key, kernel_gen, params[0],
	                                     params[1]);

	// sizes in bytes
	uint32_t prime_size = (mpz_sizeinbase(characteristic, 2) + 7) / 8;
	uint32_t private_key_size = 2 * prime_size;
	uint32_t public_key_size = 12 * prime_size;

	*alice_priv = NULL;
	*alice_msg = NULL;
	*alice_priv = malloc(private_key_size);
	*alice_msg = malloc(public_key_size);
	*alice_msg_len = public_key_size;

	oqs_sidh_iqc_ref_private_key_to_bytes((uint8_t *) *alice_priv,
	                                      Alice_private_key, prime_size);
	oqs_sidh_iqc_ref_public_key_to_bytes((uint8_t *) *alice_msg, Alice_public_key,
	                                     prime_size);

	oqs_sidh_iqc_ref_private_key_clear(Alice_private_key);
	oqs_sidh_iqc_ref_public_key_clear(Alice_public_key);
	oqs_sidh_iqc_ref_point_clear(kernel_gen);

	return 1;
}

int OQS_KEX_sidh_iqc_ref_bob(OQS_KEX *k, const uint8_t *alice_msg,
                             UNUSED const size_t alice_msg_len,
                             uint8_t **bob_msg, size_t *bob_msg_len,
                             uint8_t **key, size_t *key_len) {

	public_params_t *params = (public_params_t *) k->params;

	private_key_t Bob_private_key;
	oqs_sidh_iqc_ref_private_key_init(Bob_private_key);
	oqs_sidh_iqc_ref_private_key_generate(Bob_private_key, params[1]);

	public_key_t Bob_public_key;
	oqs_sidh_iqc_ref_public_key_init(Bob_public_key);
	point_t kernel_gen;
	oqs_sidh_iqc_ref_point_init(kernel_gen);
	oqs_sidh_iqc_ref_private_key_compute_kernel_gen(kernel_gen, Bob_private_key,
	                                                params[1]->P, params[1]->Q,
	                                                params[1]->le, params[1]->E);
	oqs_sidh_iqc_ref_public_key_generate(Bob_public_key, kernel_gen, params[1],
	                                     params[0]);

	// sizes in bytes
	uint32_t prime_size = (mpz_sizeinbase(characteristic, 2) + 7) / 8;
	uint32_t public_key_size = 12 * prime_size;
	uint32_t shared_key_size = 2 * prime_size;

	*bob_msg = NULL;
	*key = NULL;
	*bob_msg = malloc(public_key_size);
	*key = malloc(shared_key_size);
	*bob_msg_len = public_key_size;
	*key_len = shared_key_size;

	oqs_sidh_iqc_ref_public_key_to_bytes((uint8_t *) *bob_msg, Bob_public_key,
	                                     prime_size);

	public_key_t Alice_public_key;
	oqs_sidh_iqc_ref_public_key_init(Alice_public_key);
	oqs_sidh_iqc_ref_bytes_to_public_key(Alice_public_key, alice_msg, prime_size);

	fp2_element_t Bob_shared_key;
	oqs_sidh_iqc_ref_fp2_init(Bob_shared_key);
	oqs_sidh_iqc_ref_shared_key_generate(Bob_shared_key, Alice_public_key,
	                                     Bob_private_key, params[1]);

	oqs_sidh_iqc_ref_fp2_to_bytes((uint8_t *) *key, Bob_shared_key, prime_size);

	oqs_sidh_iqc_ref_public_key_clear(Alice_public_key);
	oqs_sidh_iqc_ref_private_key_clear(Bob_private_key);
	oqs_sidh_iqc_ref_public_key_clear(Bob_public_key);
	oqs_sidh_iqc_ref_point_clear(kernel_gen);
	oqs_sidh_iqc_ref_fp2_clear(Bob_shared_key);

	return 1;
}

int OQS_KEX_sidh_iqc_ref_alice_1(OQS_KEX *k, const void *alice_priv,
                                 const uint8_t *bob_msg,
                                 UNUSED const size_t bob_msg_len, uint8_t **key,
                                 size_t *key_len) {

	public_params_t *params = (public_params_t *) k->params;

	// sizes in bytes
	uint32_t prime_size = (mpz_sizeinbase(characteristic, 2) + 7) / 8;
	uint32_t shared_key_size = 2 * prime_size;

	*key = NULL;
	*key_len = shared_key_size;
	*key = malloc(shared_key_size);

	private_key_t Alice_private_key;
	oqs_sidh_iqc_ref_private_key_init(Alice_private_key);
	oqs_sidh_iqc_ref_bytes_to_private_key(Alice_private_key, alice_priv,
	                                      prime_size);

	public_key_t Bob_public_key;
	oqs_sidh_iqc_ref_public_key_init(Bob_public_key);
	oqs_sidh_iqc_ref_bytes_to_public_key(Bob_public_key, bob_msg, prime_size);

	fp2_element_t Alice_shared_key;
	oqs_sidh_iqc_ref_fp2_init(Alice_shared_key);
	oqs_sidh_iqc_ref_shared_key_generate(Alice_shared_key, Bob_public_key,
	                                     Alice_private_key, params[0]);

	oqs_sidh_iqc_ref_fp2_to_bytes((uint8_t *) *key, Alice_shared_key, prime_size);

	oqs_sidh_iqc_ref_private_key_clear(Alice_private_key);
	oqs_sidh_iqc_ref_public_key_clear(Bob_public_key);
	oqs_sidh_iqc_ref_fp2_clear(Alice_shared_key);

	return 1;
}

void OQS_KEX_sidh_iqc_ref_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		free(alice_priv);
	}
}

void OQS_KEX_sidh_iqc_ref_free(OQS_KEX *k) {
	if (!k) {
		return;
	}

	oqs_sidh_iqc_ref_public_params_clear(((public_params_t *) (k->params))[0]);
	oqs_sidh_iqc_ref_public_params_clear(((public_params_t *) (k->params))[1]);
	free(k->params);
	k->ctx = NULL;
	free(k->method_name);
	k->method_name = NULL;
	free(k);
}
