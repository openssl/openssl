#include <stdlib.h>
#include <stdio.h>
#include "sidh_isogeny.h"
#include <math.h>

void oqs_sidh_iqc_ref_isogeny_init(isogeny_t isogeny,
                                   long kernel_size) {
	isogeny->kernel_size = 0;
	isogeny->partition_size = 0;
	oqs_sidh_iqc_ref_isogeny_set_kernel_size(isogeny, kernel_size);
	long size = isogeny->partition_size;
	isogeny->partition = (point_t *) malloc(size * sizeof(point_t));
	isogeny->gx = (fp2_element_t *) malloc(size * sizeof(fp2_element_t));
	isogeny->gy = (fp2_element_t *) malloc(size * sizeof(fp2_element_t));
	isogeny->u = (fp2_element_t *) malloc(size * sizeof(fp2_element_t));
	isogeny->v = (fp2_element_t *) malloc(size * sizeof(fp2_element_t));

	oqs_sidh_iqc_ref_elliptic_curve_init(isogeny->domain);
	oqs_sidh_iqc_ref_elliptic_curve_init(isogeny->codomain);

	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_point_init(isogeny->partition[i]);
		oqs_sidh_iqc_ref_fp2_init(isogeny->gx[i]);
		oqs_sidh_iqc_ref_fp2_init(isogeny->gy[i]);
		oqs_sidh_iqc_ref_fp2_init(isogeny->u[i]);
		oqs_sidh_iqc_ref_fp2_init(isogeny->v[i]);
	}
}

void oqs_sidh_iqc_ref_isogeny_clear(isogeny_t isogeny) {
	oqs_sidh_iqc_ref_elliptic_curve_clear(isogeny->domain);
	oqs_sidh_iqc_ref_elliptic_curve_clear(isogeny->codomain);

	for (long i = 0; i < isogeny->partition_size; i++) {
		oqs_sidh_iqc_ref_point_clear(isogeny->partition[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->gx[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->gy[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->u[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->v[i]);
	}

	free(isogeny->partition);
	free(isogeny->gx);
	free(isogeny->gy);
	free(isogeny->u);
	free(isogeny->v);
}

void oqs_sidh_iqc_ref_isogeny_compute(isogeny_t isogeny,
                                      const point_t kernel_gen) {
	oqs_sidh_iqc_ref_isogeny_partition_kernel(isogeny->partition,
	                                          isogeny->partition_size,
	                                          kernel_gen,
	                                          isogeny->domain);
	long size = isogeny->partition_size;

	// compute gx_P = 3 * x_P^2 + a
	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_fp2_square(isogeny->gx[i], isogeny->partition[i]->x);
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(isogeny->gx[i], isogeny->gx[i], 3);
		oqs_sidh_iqc_ref_fp2_add(isogeny->gx[i], isogeny->gx[i], isogeny->domain->a);
	}

	// compute gy_P = -2y_P
	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(isogeny->gy[i], isogeny->partition[i]->y, -2);
	}

	// compute v_P = gx_P or 2gx_P
	for (long i = 0; i < size; i++) {
		if (oqs_sidh_iqc_ref_point_has_order_2(isogeny->partition[i]))
			oqs_sidh_iqc_ref_fp2_set(isogeny->v[i], isogeny->gx[i]);
		else
			oqs_sidh_iqc_ref_fp2_mul_scaler_si(isogeny->v[i], isogeny->gx[i], 2);
	}

	// compute u_P = gy_P^2
	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_fp2_square(isogeny->u[i], isogeny->gy[i]);
	}

	// compute the codomain curve
	fp2_element_t v;
	fp2_element_t w;
	fp2_element_t temp;
	oqs_sidh_iqc_ref_fp2_init(v);
	oqs_sidh_iqc_ref_fp2_init(w);
	oqs_sidh_iqc_ref_fp2_init(temp);

	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_fp2_add(v, v, isogeny->v[i]);
		oqs_sidh_iqc_ref_fp2_mul(temp, isogeny->v[i], isogeny->partition[i]->x);
		oqs_sidh_iqc_ref_fp2_add(temp, isogeny->u[i], temp);
		oqs_sidh_iqc_ref_fp2_add(w, w, temp);
	}

	oqs_sidh_iqc_ref_fp2_mul_scaler_si(v, v, 5);
	oqs_sidh_iqc_ref_fp2_sub(v, isogeny->domain->a, v);
	oqs_sidh_iqc_ref_fp2_mul_scaler_si(w, w, 7);
	oqs_sidh_iqc_ref_fp2_sub(w, isogeny->domain->b, w);
	oqs_sidh_iqc_ref_elliptic_curve_set_coeffs(isogeny->codomain, v, w);

	oqs_sidh_iqc_ref_fp2_clear(v);
	oqs_sidh_iqc_ref_fp2_clear(w);
	oqs_sidh_iqc_ref_fp2_clear(temp);
}

void oqs_sidh_iqc_ref_isogeny_partition_kernel(point_t *partition,
                                               long partition_size,
                                               const point_t kernel_gen,
                                               const elliptic_curve_t E) {
	oqs_sidh_iqc_ref_point_set(partition[0], kernel_gen);
	for (long i = 1; i < partition_size; i++) {
		oqs_sidh_iqc_ref_point_add(partition[i], partition[i - 1], kernel_gen, E);
	}
}

void oqs_sidh_iqc_ref_isogeny_set_kernel_size(isogeny_t isogeny,
                                              long kernel_size) {
	long current_size = isogeny->kernel_size;
	if (current_size != 0 && current_size <= kernel_size)
		return;

	current_size = isogeny->partition_size;
	isogeny->kernel_size = kernel_size;

	if (kernel_size % 2 == 0)
		isogeny->partition_size = kernel_size / 2;
	else
		isogeny->partition_size = (kernel_size - 1) / 2;

	// clear the the unused memory after shrinking
	for (long i = isogeny->partition_size; i < current_size; i++) {
		oqs_sidh_iqc_ref_point_clear(isogeny->partition[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->gx[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->gy[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->u[i]);
		oqs_sidh_iqc_ref_fp2_clear(isogeny->v[i]);
	}
}

void oqs_sidh_iqc_ref_isogeny_evaluate_velu(point_t Q,
                                            const isogeny_t isogeny,
                                            const point_t P) {

	if (oqs_sidh_iqc_ref_point_is_zero(P)) {
		oqs_sidh_iqc_ref_point_zero(Q);
		return;
	}

	long size = isogeny->partition_size;

	fp2_element_t temp1;
	fp2_element_t temp2;
	fp2_element_t temp3;
	oqs_sidh_iqc_ref_fp2_init(temp1);
	oqs_sidh_iqc_ref_fp2_init(temp2);
	oqs_sidh_iqc_ref_fp2_init(temp3);

	point_t result;
	oqs_sidh_iqc_ref_point_init(result);
	oqs_sidh_iqc_ref_point_set(result, P);

	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_fp2_sub(temp1, P->x, isogeny->partition[i]->x);

		// check if the point is in the kernel
		if (oqs_sidh_iqc_ref_fp2_is_zero(temp1)) {
			oqs_sidh_iqc_ref_point_zero(result);
			break;
		}

		// 1 / (x - x_P)
		oqs_sidh_iqc_ref_fp2_inv(temp1, temp1);

		// add 1 / (x - x_P) * (v_P + u_P / (x - x_P)) to x
		oqs_sidh_iqc_ref_fp2_mul(temp2, isogeny->u[i], temp1);
		oqs_sidh_iqc_ref_fp2_add(temp2, temp2, isogeny->v[i]);
		oqs_sidh_iqc_ref_fp2_mul(temp2, temp2, temp1);
		oqs_sidh_iqc_ref_fp2_add(result->x, result->x, temp2);

		// v_P * (y - y_P) - gx_P * gy_P
		oqs_sidh_iqc_ref_fp2_sub(temp2, P->y, isogeny->partition[i]->y);
		oqs_sidh_iqc_ref_fp2_mul(temp2, temp2, isogeny->v[i]);
		oqs_sidh_iqc_ref_fp2_mul(temp3, isogeny->gx[i], isogeny->gy[i]);
		oqs_sidh_iqc_ref_fp2_sub(temp2, temp2, temp3);

		// 2 * u_P * y / (x - x_P)
		oqs_sidh_iqc_ref_fp2_mul(temp3, isogeny->u[i], P->y);
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(temp3, temp3, 2);
		oqs_sidh_iqc_ref_fp2_mul(temp3, temp3, temp1);

		oqs_sidh_iqc_ref_fp2_add(temp3, temp3, temp2);
		oqs_sidh_iqc_ref_fp2_square(temp1, temp1);
		oqs_sidh_iqc_ref_fp2_mul(temp3, temp3, temp1);
		oqs_sidh_iqc_ref_fp2_sub(result->y, result->y, temp3);
	}

	oqs_sidh_iqc_ref_point_set(Q, result);

	oqs_sidh_iqc_ref_point_clear(result);
	oqs_sidh_iqc_ref_fp2_clear(temp1);
	oqs_sidh_iqc_ref_fp2_clear(temp2);
	oqs_sidh_iqc_ref_fp2_clear(temp3);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_kohel(point_t Q,
                                             const isogeny_t isogeny,
                                             const point_t P) {
	fp2_element_t ix1;
	fp2_element_t ix2;
	fp2_element_t ix3;
	fp2_element_t temp1;
	fp2_element_t temp2;
	fp2_element_t temp3;
	fp2_element_t sigma1;

	oqs_sidh_iqc_ref_fp2_init(ix1);
	oqs_sidh_iqc_ref_fp2_init(ix2);
	oqs_sidh_iqc_ref_fp2_init(ix3);
	oqs_sidh_iqc_ref_fp2_init(temp1);
	oqs_sidh_iqc_ref_fp2_init(temp2);
	oqs_sidh_iqc_ref_fp2_init(temp3);
	oqs_sidh_iqc_ref_fp2_init(sigma1);

	point_t result;
	oqs_sidh_iqc_ref_point_init(result);
	oqs_sidh_iqc_ref_point_set(result, P);

	long size = isogeny->partition_size;

	for (long i = 0; i < size; i++) {
		oqs_sidh_iqc_ref_fp2_add(sigma1, sigma1, isogeny->partition[i]->x);
		oqs_sidh_iqc_ref_fp2_sub(temp1, P->x, isogeny->partition[i]->x);

		// check if the point is in the kernel
		if (oqs_sidh_iqc_ref_fp2_is_zero(temp1)) {
			oqs_sidh_iqc_ref_point_zero(result);
			break;
		}

		// 1 / (x - x_P)
		oqs_sidh_iqc_ref_fp2_inv(temp1, temp1);

		// 1 / (x - x_P)^2
		oqs_sidh_iqc_ref_fp2_square(temp2, temp1);

		// 1 / (x - x_P)^3
		oqs_sidh_iqc_ref_fp2_mul(temp3, temp2, temp1);

		if (!oqs_sidh_iqc_ref_point_has_order_2(isogeny->partition[i])) {
			oqs_sidh_iqc_ref_fp2_add(temp1, temp1, temp1);
			oqs_sidh_iqc_ref_fp2_add(temp2, temp2, temp2);
			oqs_sidh_iqc_ref_fp2_add(temp3, temp3, temp3);
			oqs_sidh_iqc_ref_fp2_add(sigma1, sigma1, isogeny->partition[i]->x);
		}

		oqs_sidh_iqc_ref_fp2_add(ix1, ix1, temp1);
		oqs_sidh_iqc_ref_fp2_add(ix2, ix2, temp2);
		oqs_sidh_iqc_ref_fp2_add(ix3, ix3, temp3);
	}

	if (!oqs_sidh_iqc_ref_point_is_zero(result)) {
		fp2_element_t u1;
		fp2_element_t u2;

		oqs_sidh_iqc_ref_fp2_init(u1);
		oqs_sidh_iqc_ref_fp2_init(u2);

		// 3 * x^2 + a
		oqs_sidh_iqc_ref_fp2_square(u1, P->x);
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(u1, u1, 3);
		oqs_sidh_iqc_ref_fp2_add(u1, u1, isogeny->domain->a);

		// 2 * y^2
		oqs_sidh_iqc_ref_fp2_square(u2, P->y);
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(u2, u2, 2);

		// compute the first coordinate
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(result->x, P->x, isogeny->kernel_size);
		oqs_sidh_iqc_ref_fp2_sub(result->x, result->x, sigma1);
		oqs_sidh_iqc_ref_fp2_mul(temp1, u1, ix1);
		oqs_sidh_iqc_ref_fp2_sub(result->x, result->x, temp1);
		oqs_sidh_iqc_ref_fp2_mul(temp1, u2, ix2);
		oqs_sidh_iqc_ref_fp2_add(result->x, result->x, temp1);

		// compute the second coordinate
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(temp1, P->x, -6);
		oqs_sidh_iqc_ref_fp2_mul(result->y, temp1, ix1);
		oqs_sidh_iqc_ref_fp2_add_ui(result->y, result->y, isogeny->kernel_size);
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(temp1, u1, 3);
		oqs_sidh_iqc_ref_fp2_mul(temp1, temp1, ix2);
		oqs_sidh_iqc_ref_fp2_add(result->y, result->y, temp1);
		oqs_sidh_iqc_ref_fp2_mul_scaler_si(temp1, u2, -2);
		oqs_sidh_iqc_ref_fp2_mul(temp1, temp1, ix3);
		oqs_sidh_iqc_ref_fp2_add(result->y, result->y, temp1);
		oqs_sidh_iqc_ref_fp2_mul(result->y, result->y, P->y);

		oqs_sidh_iqc_ref_fp2_clear(u1);
		oqs_sidh_iqc_ref_fp2_clear(u2);
	}

	oqs_sidh_iqc_ref_point_set(Q, result);

	oqs_sidh_iqc_ref_point_clear(result);
	oqs_sidh_iqc_ref_fp2_clear(ix1);
	oqs_sidh_iqc_ref_fp2_clear(ix2);
	oqs_sidh_iqc_ref_fp2_clear(ix3);
	oqs_sidh_iqc_ref_fp2_clear(temp1);
	oqs_sidh_iqc_ref_fp2_clear(temp2);
	oqs_sidh_iqc_ref_fp2_clear(temp3);
	oqs_sidh_iqc_ref_fp2_clear(sigma1);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_naive(elliptic_curve_t E,
                                             point_t *points,
                                             long num_points,
                                             const point_t kernel_gen,
                                             long l,
                                             long e,
                                             long isogeny_jump) {

	point_t temp_gen;
	oqs_sidh_iqc_ref_point_init(temp_gen);
	oqs_sidh_iqc_ref_point_set(temp_gen, kernel_gen);

	mpz_t le;
	mpz_init(le);
	mpz_ui_pow_ui(le, l, e);

	long kernel_size = 0;
	if (e <= isogeny_jump)
		kernel_size = mpz_get_si(le);
	else
		kernel_size = (long) pow(l, isogeny_jump);

	isogeny_t isogeny;
	oqs_sidh_iqc_ref_isogeny_init(isogeny, kernel_size);
	oqs_sidh_iqc_ref_elliptic_curve_set(isogeny->domain, E);

	long i = 0;
	while (i < e) {
		mpz_divexact_ui(le, le, kernel_size);
		oqs_sidh_iqc_ref_isogeny_evaluate_naive_helper(isogeny,
		                                               E,
		                                               points,
		                                               num_points,
		                                               temp_gen,
		                                               le);
		i += isogeny_jump;

		if ((e - i > 0) && (e - i) < isogeny_jump) {
			kernel_size = (long) pow(l, e - i);
			oqs_sidh_iqc_ref_isogeny_set_kernel_size(isogeny, kernel_size);
		}
	}

	oqs_sidh_iqc_ref_point_clear(temp_gen);
	mpz_clear(le);
	oqs_sidh_iqc_ref_isogeny_clear(isogeny);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_naive_curve(elliptic_curve_t E,
                                                   const point_t kernel_gen,
                                                   long l,
                                                   long e,
                                                   long isogeny_jump) {
	oqs_sidh_iqc_ref_isogeny_evaluate_naive(E, NULL, 0, kernel_gen, l, e, isogeny_jump);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_naive_helper(isogeny_t isogeny,
                                                    elliptic_curve_t E,
                                                    point_t *points,
                                                    long num_points,
                                                    point_t kernel_gen,
                                                    const mpz_t le) {
	point_t K;
	oqs_sidh_iqc_ref_point_init(K);

	oqs_sidh_iqc_ref_point_mul_scaler(K, kernel_gen, le, E);
	oqs_sidh_iqc_ref_isogeny_compute(isogeny, K);
	oqs_sidh_iqc_ref_isogeny_evaluate_kohel(kernel_gen, isogeny, kernel_gen);

	for (long i = 0; i < num_points; i++) {
		oqs_sidh_iqc_ref_isogeny_evaluate_kohel(points[i], isogeny, points[i]);
	}

	oqs_sidh_iqc_ref_elliptic_curve_set(E, isogeny->codomain);
	oqs_sidh_iqc_ref_elliptic_curve_set(isogeny->domain, isogeny->codomain);

	oqs_sidh_iqc_ref_point_clear(K);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_strategy_rec(elliptic_curve_t E,
                                                    point_t *points,
                                                    long num_points,
                                                    point_t *kernel_gens,
                                                    long num_gens,
                                                    long l,
                                                    long e,
                                                    float ratio) {

	if (e == 1) {
		isogeny_t isogeny;

		long kernel_size = (long) pow(l, e);
		oqs_sidh_iqc_ref_isogeny_init(isogeny, kernel_size);
		oqs_sidh_iqc_ref_elliptic_curve_set(isogeny->domain, E);
		oqs_sidh_iqc_ref_isogeny_compute(isogeny, kernel_gens[num_gens - 1]);
		oqs_sidh_iqc_ref_elliptic_curve_set(E, isogeny->codomain);

		for (long i = 0; i < num_points; i++) {
			oqs_sidh_iqc_ref_isogeny_evaluate_velu(points[i], isogeny, points[i]);
		}

		for (long i = 0; i < num_gens - 1; i++) {
			oqs_sidh_iqc_ref_isogeny_evaluate_velu(kernel_gens[i],
			                                       isogeny,
			                                       kernel_gens[i]);
		}

		oqs_sidh_iqc_ref_isogeny_clear(isogeny);
		return;
	}

	long r = (long) (ratio * e);

	mpz_t exponent;
	mpz_init(exponent);
	mpz_ui_pow_ui(exponent, l, r);

	oqs_sidh_iqc_ref_point_mul_scaler(kernel_gens[num_gens],
	                                  kernel_gens[num_gens - 1],
	                                  exponent, E);

	oqs_sidh_iqc_ref_isogeny_evaluate_strategy_rec(E, points, num_points, kernel_gens,
	                                               num_gens + 1, l, e - r, ratio);
	oqs_sidh_iqc_ref_isogeny_evaluate_strategy_rec(E, points, num_points, kernel_gens,
	                                               num_gens, l, r, ratio);
	mpz_clear(exponent);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_strategy(elliptic_curve_t E,
                                                point_t *points,
                                                long num_points,
                                                const point_t kernel_gen,
                                                long l,
                                                long e,
                                                float ratio) {

	point_t *kernel_gens = (point_t *) malloc(e * sizeof(point_t));
	for (long i = 0; i < e; i++)
		oqs_sidh_iqc_ref_point_init(kernel_gens[i]);
	oqs_sidh_iqc_ref_point_set(kernel_gens[0], kernel_gen);

	oqs_sidh_iqc_ref_isogeny_evaluate_strategy_rec(E, points, num_points,
	                                               kernel_gens, 1, l, e, ratio);

	for (long i = 0; i < e; i++)
		oqs_sidh_iqc_ref_point_clear(kernel_gens[i]);
	free(kernel_gens);
}

void oqs_sidh_iqc_ref_isogeny_evaluate_strategy_curve(elliptic_curve_t E,
                                                      const point_t kernel_gen,
                                                      long l,
                                                      long e,
                                                      float ratio) {
	oqs_sidh_iqc_ref_isogeny_evaluate_strategy(E, NULL, 0, kernel_gen, l, e, ratio);
}
