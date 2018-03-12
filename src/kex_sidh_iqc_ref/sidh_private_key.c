#include "sidh_private_key.h"
#include "sidh_util.h"
#include "sidh_public_param.h"
#include <stdio.h>

void oqs_sidh_iqc_ref_private_key_init(private_key_t private_key) {
	mpz_inits(private_key->m, private_key->n, NULL);
}

void oqs_sidh_iqc_ref_private_key_clear(private_key_t private_key) {
	mpz_clears(private_key->m, private_key->n, NULL);
}

void oqs_sidh_iqc_ref_private_key_generate(private_key_t private_key,
                                           const public_params_t params) {
	gmp_randstate_t randstate;
	gmp_randinit_default(randstate);
	mpz_t seed;
	mpz_init(seed);
	oqs_sidh_iqc_ref_get_random_mpz(seed);
	gmp_randseed(randstate, seed);

	while (1) {
		mpz_urandomm(private_key->m, randstate, params->le);
		mpz_urandomm(private_key->n, randstate, params->le);

		if (!mpz_divisible_ui_p(private_key->m, params->l))
			break;

		if (!mpz_divisible_ui_p(private_key->n, params->l)) {
			mpz_swap(private_key->m, private_key->n);
			break;
		}
	}

	gmp_randclear(randstate);
	mpz_clear(seed);
}

void oqs_sidh_iqc_ref_private_key_compute_kernel_gen(
    point_t gen, const private_key_t private_key, const point_t P,
    const point_t Q, const mpz_t le, const elliptic_curve_t E) {
	mpz_t temp_m;
	mpz_t temp_n;
	mpz_init_set(temp_m, private_key->m);
	mpz_init_set(temp_n, private_key->n);

	point_t result;
	oqs_sidh_iqc_ref_point_init(result);

	mpz_invert(temp_m, temp_m, le);
	mpz_mul(temp_n, temp_m, temp_n);
	mpz_mod(temp_n, temp_n, le);

	oqs_sidh_iqc_ref_point_mul_scaler(result, Q, temp_n, E);
	oqs_sidh_iqc_ref_point_add(result, result, P, E);
	oqs_sidh_iqc_ref_point_set(gen, result);

	mpz_clears(temp_m, temp_n, NULL);
	oqs_sidh_iqc_ref_point_clear(result);
}

void oqs_sidh_iqc_ref_private_key_print(const private_key_t private_key) {
	printf("m: %s\n", mpz_get_str(NULL, 10, private_key->m));
	printf("n: %s\n", mpz_get_str(NULL, 10, private_key->n));
}

void oqs_sidh_iqc_ref_private_key_to_bytes(uint8_t *bytes,
                                           const private_key_t private_key,
                                           long prime_size) {
	for (long i = 0; i < 2 * prime_size; i++)
		bytes[i] = 0;

	mpz_export(bytes, NULL, -1, 1, 0, 0, private_key->m);
	mpz_export(bytes + prime_size, NULL, -1, 1, 0, 0, private_key->n);
}

void oqs_sidh_iqc_ref_bytes_to_private_key(private_key_t private_key,
                                           const uint8_t *bytes,
                                           long prime_size) {
	mpz_set_ui(private_key->m, 0);
	mpz_set_ui(private_key->n, 0);
	mpz_import(private_key->m, prime_size, -1, 1, 0, 0, bytes);
	mpz_import(private_key->n, prime_size, -1, 1, 0, 0, bytes + prime_size);
}
