#include <stdlib.h>

#include "sidh_elliptic_curve.h"
#include "sidh_util.h"
#include <string.h>

void oqs_sidh_iqc_ref_elliptic_curve_init(elliptic_curve_t E) {
	oqs_sidh_iqc_ref_fp2_init_set_si(E->a, 0, 1);
	oqs_sidh_iqc_ref_fp2_init_set_si(E->b, 0, 1);
}

void oqs_sidh_iqc_ref_elliptic_curve_set(elliptic_curve_t E,
                                         const elliptic_curve_t T) {
	oqs_sidh_iqc_ref_fp2_set(E->a, T->a);
	oqs_sidh_iqc_ref_fp2_set(E->b, T->b);
}

void oqs_sidh_iqc_ref_elliptic_curve_set_coeffs(elliptic_curve_t E,
                                                const fp2_element_t a,
                                                const fp2_element_t b) {
	oqs_sidh_iqc_ref_fp2_set(E->a, a);
	oqs_sidh_iqc_ref_fp2_set(E->b, b);
}

void oqs_sidh_iqc_ref_point_init(point_t P) {
	oqs_sidh_iqc_ref_fp2_init(P->x);
	oqs_sidh_iqc_ref_fp2_init(P->y);
	oqs_sidh_iqc_ref_point_zero(P);
}

void oqs_sidh_iqc_ref_point_set_coordinates(point_t P,
                                            const fp2_element_t x,
                                            const fp2_element_t y,
                                            int z) {
	oqs_sidh_iqc_ref_fp2_set(P->x, x);
	oqs_sidh_iqc_ref_fp2_set(P->y, y);
	P->z = z;
}

void oqs_sidh_iqc_ref_point_set(point_t P,
                                const point_t Q) {
	oqs_sidh_iqc_ref_point_set_coordinates(P, Q->x, Q->y, Q->z);
}

void oqs_sidh_iqc_ref_point_zero(point_t P) {
	oqs_sidh_iqc_ref_fp2_zero(P->x);
	oqs_sidh_iqc_ref_fp2_one(P->y);
	P->z = 0;
}

int oqs_sidh_iqc_ref_point_is_zero(const point_t P) {
	return P->z == 0;
}

void oqs_sidh_iqc_ref_point_negate(point_t P,
                                   const point_t Q) {
	oqs_sidh_iqc_ref_point_set(P, Q);
	oqs_sidh_iqc_ref_fp2_negate(P->y, P->y);
}

int oqs_sidh_iqc_ref_point_has_order_2(const point_t P) {
	return oqs_sidh_iqc_ref_fp2_is_zero(P->y);
}

void oqs_sidh_iqc_ref_elliptic_curve_clear(elliptic_curve_t E) {
	oqs_sidh_iqc_ref_fp2_clear(E->a);
	oqs_sidh_iqc_ref_fp2_clear(E->b);
}

void oqs_sidh_iqc_ref_point_clear(point_t P) {
	oqs_sidh_iqc_ref_fp2_clear(P->x);
	oqs_sidh_iqc_ref_fp2_clear(P->y);
}

int oqs_sidh_iqc_ref_point_equals(const point_t P,
                                  const point_t Q) {
	return oqs_sidh_iqc_ref_fp2_equals(P->x, Q->x) &&
	       oqs_sidh_iqc_ref_fp2_equals(P->y, Q->y) &&
	       (P->z == Q->z);
}

char *oqs_sidh_iqc_ref_elliptic_curve_get_str(const elliptic_curve_t E) {
	char *result = "";
	result = oqs_sidh_iqc_ref_concat(result, "y^2 = x^3");
	if (!oqs_sidh_iqc_ref_fp2_is_zero(E->a)) {
		result = oqs_sidh_iqc_ref_concat(result, " + (");
		result = oqs_sidh_iqc_ref_concat(result, oqs_sidh_iqc_ref_fp2_get_str(E->a));
		result = oqs_sidh_iqc_ref_concat(result, ")");
		result = oqs_sidh_iqc_ref_concat(result, " * x");
	}

	if (!oqs_sidh_iqc_ref_fp2_is_zero(E->b)) {
		result = oqs_sidh_iqc_ref_concat(result, " + (");
		result = oqs_sidh_iqc_ref_concat(result, oqs_sidh_iqc_ref_fp2_get_str(E->b));
		result = oqs_sidh_iqc_ref_concat(result, ")");
	}

	return result;
}

char *oqs_sidh_iqc_ref_point_get_str(const point_t P) {
	char *result = "";
	result = oqs_sidh_iqc_ref_concat(result, "(");
	result = oqs_sidh_iqc_ref_concat(result, oqs_sidh_iqc_ref_fp2_get_str(P->x));
	result = oqs_sidh_iqc_ref_concat(result, " : ");
	result = oqs_sidh_iqc_ref_concat(result, oqs_sidh_iqc_ref_fp2_get_str(P->y));
	result = oqs_sidh_iqc_ref_concat(result, " : ");
	result = oqs_sidh_iqc_ref_concat(result, (P->z == 1 ? "1" : "0"));
	result = oqs_sidh_iqc_ref_concat(result, ")");

	return result;
}

void oqs_sidh_iqc_ref_point_add_with_lambda(point_t R,
                                            const point_t P,
                                            const point_t Q,
                                            const fp2_element_t lambda) {
	point_t result;
	oqs_sidh_iqc_ref_point_init(result);
	result->z = 1;

	// x_R = lambda^2 - x_P - x_Q
	oqs_sidh_iqc_ref_fp2_square(result->x, lambda);
	oqs_sidh_iqc_ref_fp2_sub(result->x, result->x, P->x);
	oqs_sidh_iqc_ref_fp2_sub(result->x, result->x, Q->x);

	// y_R = lambda * (x_P - x_R) - y_P
	oqs_sidh_iqc_ref_fp2_sub(result->y, P->x, result->x);
	oqs_sidh_iqc_ref_fp2_mul(result->y, result->y, lambda);
	oqs_sidh_iqc_ref_fp2_sub(result->y, result->y, P->y);
	oqs_sidh_iqc_ref_point_set(R, result);

	oqs_sidh_iqc_ref_point_clear(result);
}

void oqs_sidh_iqc_ref_point_double(point_t R,
                                   const point_t P,
                                   const elliptic_curve_t E) {
	if (oqs_sidh_iqc_ref_point_is_zero(P)) {
		oqs_sidh_iqc_ref_point_zero(R);
		return;
	}

	// check if the point is of order 2
	if (oqs_sidh_iqc_ref_point_has_order_2(P)) {
		oqs_sidh_iqc_ref_point_zero(R);
		return;
	}

	fp2_element_t temp;
	fp2_element_t lambda;

	oqs_sidh_iqc_ref_fp2_init(temp);
	oqs_sidh_iqc_ref_fp2_init(lambda);

	// lambda = (3(x_P)^2 + a) / (2y_p)
	oqs_sidh_iqc_ref_fp2_square(lambda, P->x);
	oqs_sidh_iqc_ref_fp2_mul_scaler_si(lambda, lambda, 3);
	oqs_sidh_iqc_ref_fp2_add(lambda, lambda, E->a);
	oqs_sidh_iqc_ref_fp2_mul_scaler_si(temp, P->y, 2);
	oqs_sidh_iqc_ref_fp2_div(lambda, lambda, temp);

	oqs_sidh_iqc_ref_point_add_with_lambda(R, P, P, lambda);

	oqs_sidh_iqc_ref_fp2_clear(temp);
	oqs_sidh_iqc_ref_fp2_clear(lambda);
}

void oqs_sidh_iqc_ref_point_add(point_t R,
                                const point_t P,
                                const point_t Q,
                                const elliptic_curve_t E) {
	if (oqs_sidh_iqc_ref_point_is_zero(P)) {
		oqs_sidh_iqc_ref_point_set(R, Q);
		return;
	}

	if (oqs_sidh_iqc_ref_point_is_zero(Q)) {
		oqs_sidh_iqc_ref_point_set(R, P);
		return;
	}

	if (oqs_sidh_iqc_ref_fp2_equals(P->x, Q->x)) {
		if (oqs_sidh_iqc_ref_fp2_equals(P->y, Q->y)) {
			oqs_sidh_iqc_ref_point_double(R, P, E);
			return;
		}

		oqs_sidh_iqc_ref_point_zero(R);
		return;
	}

	fp2_element_t temp;
	fp2_element_t lambda;

	oqs_sidh_iqc_ref_fp2_init(temp);
	oqs_sidh_iqc_ref_fp2_init(lambda);

	// lambda = (y_Q - y_P) / (x_Q - x_P)
	oqs_sidh_iqc_ref_fp2_sub(lambda, Q->y, P->y);
	oqs_sidh_iqc_ref_fp2_sub(temp, Q->x, P->x);
	oqs_sidh_iqc_ref_fp2_div(lambda, lambda, temp);

	oqs_sidh_iqc_ref_point_add_with_lambda(R, P, Q, lambda);

	oqs_sidh_iqc_ref_fp2_clear(temp);
	oqs_sidh_iqc_ref_fp2_clear(lambda);
}

void oqs_sidh_iqc_ref_point_sub(point_t R,
                                const point_t P,
                                const point_t Q,
                                const elliptic_curve_t E) {
	point_t temp;
	oqs_sidh_iqc_ref_point_init(temp);
	oqs_sidh_iqc_ref_point_negate(temp, Q);
	oqs_sidh_iqc_ref_point_add(R, P, temp, E);
	oqs_sidh_iqc_ref_point_clear(temp);
}

void oqs_sidh_iqc_ref_point_mul_scaler(point_t R,
                                       const point_t P,
                                       const mpz_t scaler,
                                       const elliptic_curve_t E) {
	if (mpz_cmp_ui(scaler, 0) == 0) {
		oqs_sidh_iqc_ref_point_zero(R);
		return;
	}

	if (mpz_cmp_ui(scaler, 1) == 0) {
		oqs_sidh_iqc_ref_point_set(R, P);
		return;
	}

	point_t R0;
	point_t R1;

	oqs_sidh_iqc_ref_point_init(R0);
	oqs_sidh_iqc_ref_point_init(R1);
	oqs_sidh_iqc_ref_point_set(R1, P);

	long num_bits = mpz_sizeinbase(scaler, 2);
	for (long i = 0; i < num_bits; i++) {
		if (mpz_tstbit(scaler, i) == 1)
			oqs_sidh_iqc_ref_point_add(R0, R0, R1, E);
		oqs_sidh_iqc_ref_point_double(R1, R1, E);
	}

	if (mpz_sgn(scaler) < 0)
		oqs_sidh_iqc_ref_point_negate(R0, R0);

	oqs_sidh_iqc_ref_point_set(R, R0);
	oqs_sidh_iqc_ref_point_clear(R0);
	oqs_sidh_iqc_ref_point_clear(R1);
}

void oqs_sidh_iqc_ref_point_mul_scaler_si(point_t R,
                                          const point_t P,
                                          long scaler,
                                          const elliptic_curve_t E) {
	mpz_t temp;
	mpz_init_set_si(temp, scaler);
	oqs_sidh_iqc_ref_point_mul_scaler(R, P, temp, E);
	mpz_clear(temp);
}

void oqs_sidh_iqc_ref_elliptic_curve_compute_j_inv(fp2_element_t j_inv,
                                                   const elliptic_curve_t E) {
	fp2_element_t result;
	fp2_element_t temp;
	oqs_sidh_iqc_ref_fp2_init(result);
	oqs_sidh_iqc_ref_fp2_init(temp);

	oqs_sidh_iqc_ref_fp2_pow_ui(temp, E->a, 3);
	oqs_sidh_iqc_ref_fp2_mul_scaler_si(temp, temp, 4);
	oqs_sidh_iqc_ref_fp2_square(result, E->b);
	oqs_sidh_iqc_ref_fp2_mul_scaler_si(result, result, 27);
	oqs_sidh_iqc_ref_fp2_add(result, result, temp);
	oqs_sidh_iqc_ref_fp2_inv(result, result);
	oqs_sidh_iqc_ref_fp2_mul(result, result, temp);
	oqs_sidh_iqc_ref_fp2_mul_scaler_si(result, result, 1728);
	oqs_sidh_iqc_ref_fp2_set(j_inv, result);

	oqs_sidh_iqc_ref_fp2_clear(result);
	oqs_sidh_iqc_ref_fp2_clear(temp);
}

int oqs_sidh_iqc_ref_point_is_on_curve(const point_t P,
                                       const elliptic_curve_t E) {

	if (oqs_sidh_iqc_ref_point_is_zero(P))
		return 1;

	fp2_element_t temp_x;
	oqs_sidh_iqc_ref_fp2_init(temp_x);

	// compute x^3 + a * x + b = x * (x^2 + a) + b
	oqs_sidh_iqc_ref_fp2_square(temp_x, P->x);
	oqs_sidh_iqc_ref_fp2_add(temp_x, temp_x, E->a);
	oqs_sidh_iqc_ref_fp2_mul(temp_x, temp_x, P->x);
	oqs_sidh_iqc_ref_fp2_add(temp_x, temp_x, E->b);

	fp2_element_t temp_y;
	oqs_sidh_iqc_ref_fp2_init(temp_y);
	oqs_sidh_iqc_ref_fp2_square(temp_y, P->y);

	int result = oqs_sidh_iqc_ref_fp2_equals(temp_y, temp_x);

	oqs_sidh_iqc_ref_fp2_clear(temp_x);
	oqs_sidh_iqc_ref_fp2_clear(temp_y);

	return result;
}

void oqs_sidh_iqc_ref_elliptic_curve_random_point(point_t P,
                                                  const elliptic_curve_t E) {
	point_t result;
	oqs_sidh_iqc_ref_point_init(result);
	result->z = 1;

	fp2_element_t temp_x;
	oqs_sidh_iqc_ref_fp2_init(temp_x);

	fp2_element_t temp_y;
	oqs_sidh_iqc_ref_fp2_init(temp_y);

	gmp_randstate_t randstate;
	gmp_randinit_default(randstate);

	while (1) {
		oqs_sidh_iqc_ref_fp2_random(result->x, randstate);

		// compute x^3 + a * x + b = x * (x^2 + a) + b
		oqs_sidh_iqc_ref_fp2_square(temp_x, result->x);
		oqs_sidh_iqc_ref_fp2_add(temp_x, temp_x, E->a);
		oqs_sidh_iqc_ref_fp2_mul(temp_x, temp_x, result->x);
		oqs_sidh_iqc_ref_fp2_add(temp_x, temp_x, E->b);

		if (oqs_sidh_iqc_ref_fp2_is_square(temp_x)) {
			oqs_sidh_iqc_ref_fp2_sqrt(result->y, temp_x);
			break;
		}
	}

	oqs_sidh_iqc_ref_point_set(P, result);

	oqs_sidh_iqc_ref_point_clear(result);
	oqs_sidh_iqc_ref_fp2_clear(temp_x);
	oqs_sidh_iqc_ref_fp2_clear(temp_y);
	gmp_randclear(randstate);
}
