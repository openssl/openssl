#include "sidh_elliptic_curve_dlp.h"
#include <stdio.h>

void oqs_sidh_iqc_ref_elliptic_curve_prime_power_dlp(mpz_t x,
                                                     const point_t P,
                                                     const point_t Q,
                                                     const elliptic_curve_t E,
                                                     long l,
                                                     long e) {
	mpz_t exponent1;
	mpz_t exponent2;
	point_t temp_P;
	point_t temp_Q;
	point_t temp_R;
	point_t PP;

	mpz_init(exponent1);
	mpz_init(exponent2);
	oqs_sidh_iqc_ref_point_init(temp_P);
	oqs_sidh_iqc_ref_point_init(temp_Q);
	oqs_sidh_iqc_ref_point_init(temp_R);
	oqs_sidh_iqc_ref_point_init(PP);

	int ladic_rep[e];
	mpz_ui_pow_ui(exponent1, l, e - 1);

	// PP = l^(e - 1) * P once and for all
	oqs_sidh_iqc_ref_point_mul_scaler(PP, P, exponent1, E);

	// compute the first ladic coefficient
	oqs_sidh_iqc_ref_point_mul_scaler(temp_Q, Q, exponent1, E);
	long ladic_coeff = oqs_sidh_iqc_ref_elliptic_curve_prime_dlp(PP, temp_Q, E, l);

	for (int j = 1; j < e; j++) {
		if (ladic_coeff >= 0) {
			ladic_rep[j - 1] = ladic_coeff;
		} else {
			break;
		}

		mpz_ui_pow_ui(exponent2, l, j - 1);
		mpz_mul_ui(exponent2, exponent2, ladic_rep[j - 1]);
		mpz_divexact_ui(exponent1, exponent1, l);
		oqs_sidh_iqc_ref_point_mul_scaler(temp_P, P, exponent2, E);
		oqs_sidh_iqc_ref_point_add(temp_R, temp_R, temp_P, E);
		oqs_sidh_iqc_ref_point_sub(temp_Q, Q, temp_R, E);
		oqs_sidh_iqc_ref_point_mul_scaler(temp_Q, temp_Q, exponent1, E);
		ladic_coeff = oqs_sidh_iqc_ref_elliptic_curve_prime_dlp(PP, temp_Q, E, l);
	}

	if (ladic_coeff >= 0) {
		ladic_rep[e - 1] = ladic_coeff;

		// set x = l_{e - 1}l^{e - 1} + ... + l_1l + l_0
		mpz_set_ui(x, ladic_rep[e - 1]);
		for (long i = e - 2; i >= 0; i--) {
			mpz_mul_ui(x, x, l);
			mpz_add_ui(x, x, ladic_rep[i]);
		}
	} else {
		mpz_set_si(x, -1);
	}

	mpz_clear(exponent1);
	mpz_clear(exponent2);
	oqs_sidh_iqc_ref_point_clear(temp_P);
	oqs_sidh_iqc_ref_point_clear(temp_Q);
	oqs_sidh_iqc_ref_point_clear(temp_R);
	oqs_sidh_iqc_ref_point_clear(PP);
}

long oqs_sidh_iqc_ref_elliptic_curve_prime_dlp(const point_t P,
                                               const point_t Q,
                                               const elliptic_curve_t E,
                                               long l) {
	if (oqs_sidh_iqc_ref_point_is_zero(Q))
		return 0;

	if (oqs_sidh_iqc_ref_point_equals(P, Q))
		return 1;

	point_t temp;
	oqs_sidh_iqc_ref_point_init(temp);
	oqs_sidh_iqc_ref_point_set(temp, P);

	long result = -1;
	for (long i = 2; i < l; i++) {
		oqs_sidh_iqc_ref_point_add(temp, temp, P, E);
		if (oqs_sidh_iqc_ref_point_equals(temp, Q)) {
			result = i;
			break;
		}
	}

	oqs_sidh_iqc_ref_point_clear(temp);
	return result;
}
