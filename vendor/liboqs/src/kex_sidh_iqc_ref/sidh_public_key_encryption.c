#include "sidh_public_key_encryption.h"
#include "sidh_public_key.h"
#include "sidh_util.h"
#include "sidh_shared_key.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void oqs_sidh_iqc_ref_public_key_ciphertext_init(ciphertext_t ciphertext) {
	oqs_sidh_iqc_ref_elliptic_curve_init(ciphertext->E);
	oqs_sidh_iqc_ref_point_init(ciphertext->P);
	oqs_sidh_iqc_ref_point_init(ciphertext->Q);
	ciphertext->size = 0;
}

void oqs_sidh_iqc_ref_public_key_ciphertext_clear(ciphertext_t ciphertext) {
	oqs_sidh_iqc_ref_elliptic_curve_clear(ciphertext->E);
	oqs_sidh_iqc_ref_point_clear(ciphertext->P);
	oqs_sidh_iqc_ref_point_clear(ciphertext->Q);
	free(ciphertext->content);
	ciphertext->size = 0;
}

void oqs_sidh_iqc_ref_public_key_plaintext_init(plaintext_t plaintext) {
	plaintext->size = 0;
}

void oqs_sidh_iqc_ref_public_key_plaintext_clear(plaintext_t plaintext) {
	plaintext->size = 0;
}

int oqs_sidh_iqc_ref_public_key_pad_plaintext(plaintext_t result,
                                              const plaintext_t raw) {
	long key_size = oqs_sidh_iqc_ref_public_key_get_key_size();
	long max_msg_size = key_size - 1;

	if (raw->size > key_size) {
		printf("\nMessage too large. It should be less than %ld bytes.\n",
		       max_msg_size);
		return -1;
	}

	// pad the message
	char *new_content = (char *) malloc(max_msg_size);
	memset(new_content, 0, max_msg_size);
	memcpy(new_content, raw->content, raw->size);

	result->content = new_content;
	result->size = max_msg_size;

	return 1;
}

void oqs_sidh_iqc_ref_public_key_encrypt(ciphertext_t ciphertext,
                                         const plaintext_t plaintext,
                                         const public_key_t public_keyA,
                                         const public_params_t paramsA,
                                         const public_params_t paramsB) {

	private_key_t private_key_temp;
	oqs_sidh_iqc_ref_private_key_init(private_key_temp);
	oqs_sidh_iqc_ref_private_key_generate(private_key_temp, paramsB);

	point_t kernel_gen;
	oqs_sidh_iqc_ref_point_init(kernel_gen);
	oqs_sidh_iqc_ref_private_key_compute_kernel_gen(kernel_gen,
	                                                private_key_temp,
	                                                paramsB->P,
	                                                paramsB->Q,
	                                                paramsB->le,
	                                                paramsB->E);

	public_key_t public_key_temp;
	oqs_sidh_iqc_ref_public_key_init(public_key_temp);
	oqs_sidh_iqc_ref_public_key_generate(public_key_temp, kernel_gen, paramsB, paramsA);

	fp2_element_t shared_key;
	oqs_sidh_iqc_ref_fp2_init(shared_key);
	oqs_sidh_iqc_ref_shared_key_generate(shared_key, public_keyA, private_key_temp, paramsB);
	char *hash = oqs_sidh_iqc_ref_public_key_encryption_hash(shared_key, plaintext->size);

	ciphertext->content = oqs_sidh_iqc_ref_array_xor(plaintext->content,
	                                                 hash, plaintext->size);
	ciphertext->size = plaintext->size;
	oqs_sidh_iqc_ref_elliptic_curve_set(ciphertext->E, public_key_temp->E);
	oqs_sidh_iqc_ref_point_set(ciphertext->P, public_key_temp->P);
	oqs_sidh_iqc_ref_point_set(ciphertext->Q, public_key_temp->Q);

	oqs_sidh_iqc_ref_private_key_clear(private_key_temp);
	oqs_sidh_iqc_ref_point_clear(kernel_gen);
	oqs_sidh_iqc_ref_public_key_clear(public_key_temp);
	oqs_sidh_iqc_ref_fp2_clear(shared_key);
	free(hash);
}

void oqs_sidh_iqc_ref_public_key_decrypt(plaintext_t plaintext,
                                         const ciphertext_t ciphertext,
                                         const private_key_t private_keyA,
                                         const public_params_t paramsA) {

	public_key_t public_key_temp;
	oqs_sidh_iqc_ref_public_key_init(public_key_temp);
	oqs_sidh_iqc_ref_elliptic_curve_set(public_key_temp->E, ciphertext->E);
	oqs_sidh_iqc_ref_point_set(public_key_temp->P, ciphertext->P);
	oqs_sidh_iqc_ref_point_set(public_key_temp->Q, ciphertext->Q);

	fp2_element_t shared_key;
	oqs_sidh_iqc_ref_fp2_init(shared_key);
	oqs_sidh_iqc_ref_shared_key_generate(shared_key, public_key_temp, private_keyA, paramsA);
	char *hash = oqs_sidh_iqc_ref_public_key_encryption_hash(shared_key, ciphertext->size);

	plaintext->content = oqs_sidh_iqc_ref_array_xor(ciphertext->content, hash,
	                                                ciphertext->size);
	plaintext->size = ciphertext->size;

	oqs_sidh_iqc_ref_public_key_clear(public_key_temp);
	oqs_sidh_iqc_ref_fp2_clear(shared_key);
	free(hash);
}

const mp_limb_t *mpz_limbs_read(const mpz_t x);

char *oqs_sidh_iqc_ref_public_key_encryption_hash(const fp2_element_t value,
                                                  long size) {
	// compute the size of value in chars
	long size_a = mpz_size(value->a) * sizeof(mp_limb_t);
	long size_b = mpz_size(value->b) * sizeof(mp_limb_t);

	char *hash = (char *) malloc(size);

	memcpy(hash, (char *) mpz_limbs_read(value->a), size_a);
	memcpy(hash + size_a, (char *) mpz_limbs_read(value->b), size_b);

	return hash;
}

long oqs_sidh_iqc_ref_public_key_get_key_size() {
	// the key size is twice as large as the base prime.
	long key_size = 2 * mpz_size(characteristic) * sizeof(mp_limb_t);
	return key_size;
}
