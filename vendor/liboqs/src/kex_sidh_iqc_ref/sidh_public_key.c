#include "sidh_public_key.h"
#include "sidh_isogeny.h"
#include "sidh_private_key.h"
#include <stdio.h>
#include <math.h>

void oqs_sidh_iqc_ref_public_key_init(public_key_t public_key) {
	oqs_sidh_iqc_ref_elliptic_curve_init(public_key->E);
	oqs_sidh_iqc_ref_point_init(public_key->P);
	oqs_sidh_iqc_ref_point_init(public_key->Q);
}

void oqs_sidh_iqc_ref_public_key_clear(public_key_t public_key) {
	oqs_sidh_iqc_ref_elliptic_curve_clear(public_key->E);
	oqs_sidh_iqc_ref_point_clear(public_key->P);
	oqs_sidh_iqc_ref_point_clear(public_key->Q);
}

void oqs_sidh_iqc_ref_public_key_generate(public_key_t public_key,
                                          const point_t kernel_gen,
                                          const public_params_t paramsA,
                                          const public_params_t paramsB) {

	point_t points[2];
	oqs_sidh_iqc_ref_point_init(points[0]);
	oqs_sidh_iqc_ref_point_init(points[1]);

	oqs_sidh_iqc_ref_elliptic_curve_set(public_key->E, paramsA->E);
	oqs_sidh_iqc_ref_point_set(points[0], paramsB->P);
	oqs_sidh_iqc_ref_point_set(points[1], paramsB->Q);

	oqs_sidh_iqc_ref_isogeny_evaluate_strategy(public_key->E,
	                                           points,
	                                           2,
	                                           kernel_gen,
	                                           paramsA->l,
	                                           paramsA->e,
	                                           0.5);

	//        oqs_sidh_iqc_ref_isogeny_evaluate_naive(public_key->E,
	//                               points,
	//                               2,
	//                               kernel_gen,
	//                               paramsA->l,
	//                               paramsA->e,
	//                               10);

	oqs_sidh_iqc_ref_point_set(public_key->P, points[0]);
	oqs_sidh_iqc_ref_point_set(public_key->Q, points[1]);

	oqs_sidh_iqc_ref_point_clear(points[0]);
	oqs_sidh_iqc_ref_point_clear(points[1]);
}

void oqs_sidh_iqc_ref_public_key_print(const public_key_t public_key) {
	printf("E: %s\n", oqs_sidh_iqc_ref_elliptic_curve_get_str(public_key->E));
	printf("P: %s\n", oqs_sidh_iqc_ref_point_get_str(public_key->P));
	printf("Q: %s\n", oqs_sidh_iqc_ref_point_get_str(public_key->Q));
}

void oqs_sidh_iqc_ref_public_key_to_bytes(uint8_t *bytes,
                                          const public_key_t public_key,
                                          long prime_size) {
	long index = 0;
	oqs_sidh_iqc_ref_fp2_to_bytes(bytes + index, public_key->E->a, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_fp2_to_bytes(bytes + index, public_key->E->b, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_fp2_to_bytes(bytes + index, public_key->P->x, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_fp2_to_bytes(bytes + index, public_key->P->y, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_fp2_to_bytes(bytes + index, public_key->Q->x, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_fp2_to_bytes(bytes + index, public_key->Q->y, prime_size);
}

void oqs_sidh_iqc_ref_bytes_to_public_key(public_key_t public_key,
                                          const uint8_t *bytes,
                                          long prime_size) {
	long index = 0;
	oqs_sidh_iqc_ref_bytes_to_fp2(public_key->E->a, bytes + index, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_bytes_to_fp2(public_key->E->b, bytes + index, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_bytes_to_fp2(public_key->P->x, bytes + index, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_bytes_to_fp2(public_key->P->y, bytes + index, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_bytes_to_fp2(public_key->Q->x, bytes + index, prime_size);
	index += 2 * prime_size;
	oqs_sidh_iqc_ref_bytes_to_fp2(public_key->Q->y, bytes + index, prime_size);

	public_key->P->z = 1;
	public_key->Q->z = 1;
}
