#include "sidh_public_key_validation.h"
#include "sidh_elliptic_curve_dlp.h"
#include <stdio.h>

int oqs_sidh_iqc_ref_public_key_is_valid(const public_key_t public_key,
                                         const public_params_t params) {
	if (!oqs_sidh_iqc_ref_public_key_check_order(public_key->P, public_key->E, params))
		return 0;

	if (!oqs_sidh_iqc_ref_public_key_check_order(public_key->Q, public_key->E, params))
		return 0;

	if (!oqs_sidh_iqc_ref_public_key_check_dependency(public_key, params))
		return 0;

	if (!oqs_sidh_iqc_ref_public_key_check_curve(public_key->E))
		return 0;

	return 1;
}

int oqs_sidh_iqc_ref_public_key_check_order(const point_t P,
                                            const elliptic_curve_t E,
                                            const public_params_t params) {
	mpz_t order;
	point_t temp;

	mpz_init_set(order, params->le);
	oqs_sidh_iqc_ref_point_init(temp);

	int result = 0;
	mpz_divexact_ui(order, order, params->l);
	oqs_sidh_iqc_ref_point_mul_scaler(temp, P, order, E);
	if (!oqs_sidh_iqc_ref_point_is_zero(temp)) {
		oqs_sidh_iqc_ref_point_mul_scaler_si(temp, temp, params->l, E);
		if (oqs_sidh_iqc_ref_point_is_zero(temp))
			result = 1;
	}

	mpz_clear(order);
	oqs_sidh_iqc_ref_point_clear(temp);
	return result;
}

int oqs_sidh_iqc_ref_public_key_check_dependency(const public_key_t public_key,
                                                 const public_params_t params) {
	mpz_t x;
	mpz_init(x);

	int result = 0;
	oqs_sidh_iqc_ref_elliptic_curve_prime_power_dlp(x,
	                                                public_key->P,
	                                                public_key->Q,
	                                                public_key->E,
	                                                params->l,
	                                                params->e);

	if (mpz_cmp_si(x, -1) == 0) {
		oqs_sidh_iqc_ref_elliptic_curve_prime_power_dlp(x,
		                                                public_key->Q,
		                                                public_key->P,
		                                                public_key->E,
		                                                params->l,
		                                                params->e);
		if (mpz_cmp_si(x, -1) == 0)
			result = 1;
	}

	mpz_clear(x);
	return result;
}

int oqs_sidh_iqc_ref_public_key_check_curve(const elliptic_curve_t E) {
	point_t temp;
	mpz_t exponent;

	oqs_sidh_iqc_ref_point_init(temp);
	mpz_init_set(exponent, characteristic);
	mpz_add_ui(exponent, exponent, 1);

	oqs_sidh_iqc_ref_elliptic_curve_random_point(temp, E);
	oqs_sidh_iqc_ref_point_mul_scaler(temp, temp, exponent, E);
	int result = oqs_sidh_iqc_ref_point_is_zero(temp);

	oqs_sidh_iqc_ref_point_clear(temp);
	mpz_clear(exponent);

	return result;
}
