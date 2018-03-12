#include "sidh_quadratic_ext.h"
#include "sidh_util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void oqs_sidh_iqc_ref_fp_init_chararacteristic_ui(long p) {
	mpz_init_set_ui(characteristic, p);
}

void oqs_sidh_iqc_ref_fp_init_chararacteristic_str(const char *value) {
	mpz_init_set_str(characteristic, value, 10);
}

void oqs_sidh_iqc_ref_fp_init_chararacteristic(const mpz_t p) {
	mpz_init_set(characteristic, p);
}

void oqs_sidh_iqc_ref_fp_set(mpz_t x, const mpz_t a) {
	mpz_mod(x, a, characteristic);
}

void oqs_sidh_iqc_ref_fp_add(mpz_t x, const mpz_t a, const mpz_t b) {
	mpz_add(x, a, b);
	mpz_mod(x, x, characteristic);
}

void oqs_sidh_iqc_ref_fp_add_ui(mpz_t x, const mpz_t a, unsigned long b) {
	mpz_add_ui(x, a, b);
	mpz_mod(x, x, characteristic);
}

void oqs_sidh_iqc_ref_fp_sub(mpz_t x, const mpz_t a, const mpz_t b) {
	mpz_sub(x, a, b);
	mpz_mod(x, x, characteristic);
}

void oqs_sidh_iqc_ref_fp_sub_ui(mpz_t x, const mpz_t a, unsigned long b) {
	mpz_sub_ui(x, a, b);
	mpz_mod(x, x, characteristic);
}

void oqs_sidh_iqc_ref_fp_mul(mpz_t x, const mpz_t a, const mpz_t b) {
	mpz_mul(x, a, b);
	mpz_mod(x, x, characteristic);
}

void oqs_sidh_iqc_ref_fp_mul_si(mpz_t x, const mpz_t a, long b) {
	mpz_mul_si(x, a, b);
	mpz_mod(x, x, characteristic);
}

void oqs_sidh_iqc_ref_fp_inv(mpz_t x, const mpz_t a) {
	mpz_invert(x, a, characteristic);
}

void oqs_sidh_iqc_ref_fp_div(mpz_t x, const mpz_t a, const mpz_t b) {
	oqs_sidh_iqc_ref_fp_inv(x, b);
	oqs_sidh_iqc_ref_fp_mul(x, a, x);
}

void oqs_sidh_iqc_ref_fp_neg(mpz_t x, const mpz_t a) {
	oqs_sidh_iqc_ref_fp_sub(x, characteristic, a);
}

void oqs_sidh_iqc_ref_fp_sqrt(mpz_t x, const mpz_t a) {
	mpz_t exponent;
	mpz_init(exponent);

	// compute (p + 1) / 4
	mpz_add_ui(exponent, characteristic, 1);
	mpz_divexact_ui(exponent, exponent, 4);

	mpz_powm(x, a, exponent, characteristic);
	mpz_clear(exponent);
}

//////////////// fp2 methods //////////////////////////

void oqs_sidh_iqc_ref_fp2_init(fp2_element_t x) { mpz_inits(x->a, x->b, NULL); }

void oqs_sidh_iqc_ref_fp2_init_set_si(fp2_element_t x, long a, long b) {
	mpz_init_set_si(x->a, a);
	mpz_init_set_si(x->b, b);
}

void oqs_sidh_iqc_ref_fp2_init_set_str(fp2_element_t x, const char *a,
                                       const char *b) {
	mpz_init_set_str(x->a, a, 10);
	mpz_init_set_str(x->b, b, 10);
}

void oqs_sidh_iqc_ref_fp2_init_set(fp2_element_t x, const fp2_element_t a) {
	mpz_init_set(x->a, a->a);
	mpz_init_set(x->b, a->b);
}

void oqs_sidh_iqc_ref_fp2_clear(fp2_element_t x) {
	mpz_clears(x->a, x->b, NULL);
}

void oqs_sidh_iqc_ref_fp2_set(fp2_element_t x, const fp2_element_t b) {
	mpz_set(x->a, b->a);
	mpz_set(x->b, b->b);
}

void oqs_sidh_iqc_ref_fp2_zero(fp2_element_t x) {
	mpz_set_si(x->a, 0);
	mpz_set_si(x->b, 0);
}

void oqs_sidh_iqc_ref_fp2_one(fp2_element_t x) {
	mpz_set_si(x->a, 0);
	mpz_set_si(x->b, 1);
}

char *oqs_sidh_iqc_ref_fp2_get_str(const fp2_element_t a) {

	if (mpz_cmp_si(a->a, 0) == 0 && mpz_cmp_si(a->b, 0) == 0) {
		return "0";
	}

	if (mpz_cmp_si(a->a, 0) == 0) {
		return mpz_get_str(NULL, 10, a->b);
	}

	char *result = "";

	if (mpz_cmp_si(a->b, 0) == 0) {
		result = oqs_sidh_iqc_ref_concat(result, mpz_get_str(NULL, 10, a->a));
		result = oqs_sidh_iqc_ref_concat(result, " * i");
		return result;
	}

	result = oqs_sidh_iqc_ref_concat(result, mpz_get_str(NULL, 10, a->a));
	result = oqs_sidh_iqc_ref_concat(result, " * i + ");
	result = oqs_sidh_iqc_ref_concat(result, mpz_get_str(NULL, 10, a->b));

	return result;
}

void oqs_sidh_iqc_ref_fp2_add(fp2_element_t x, const fp2_element_t a,
                              const fp2_element_t b) {
	oqs_sidh_iqc_ref_fp_add(x->a, a->a, b->a);
	oqs_sidh_iqc_ref_fp_add(x->b, a->b, b->b);
}

void oqs_sidh_iqc_ref_fp2_add_ui(fp2_element_t x, const fp2_element_t a,
                                 unsigned long b) {
	oqs_sidh_iqc_ref_fp_add_ui(x->b, a->b, b);
	oqs_sidh_iqc_ref_fp_set(x->a, a->a);
}

void oqs_sidh_iqc_ref_fp2_sub(fp2_element_t x, const fp2_element_t a,
                              const fp2_element_t b) {
	oqs_sidh_iqc_ref_fp_sub(x->a, a->a, b->a);
	oqs_sidh_iqc_ref_fp_sub(x->b, a->b, b->b);
}

void oqs_sidh_iqc_ref_fp2_sub_ui(fp2_element_t x, const fp2_element_t a,
                                 unsigned long b) {
	oqs_sidh_iqc_ref_fp_sub_ui(x->b, a->b, b);
	oqs_sidh_iqc_ref_fp_set(x->a, a->a);
}

void oqs_sidh_iqc_ref_fp2_mul(fp2_element_t x, const fp2_element_t a,
                              const fp2_element_t b) {
	mpz_t temp1;
	mpz_t temp2;

	mpz_init(temp1);
	mpz_init(temp2);

	fp2_element_t result;
	oqs_sidh_iqc_ref_fp2_init(result);

	// (a + b) * (c + d)
	oqs_sidh_iqc_ref_fp_add(temp1, a->a, a->b);
	oqs_sidh_iqc_ref_fp_add(temp2, b->a, b->b);
	oqs_sidh_iqc_ref_fp_mul(result->a, temp1, temp2);

	// a * c
	oqs_sidh_iqc_ref_fp_mul(temp1, a->a, b->a);
	// b * d
	oqs_sidh_iqc_ref_fp_mul(temp2, a->b, b->b);

	oqs_sidh_iqc_ref_fp_sub(result->a, result->a, temp1);
	oqs_sidh_iqc_ref_fp_sub(result->a, result->a, temp2);
	oqs_sidh_iqc_ref_fp_sub(result->b, temp2, temp1);
	oqs_sidh_iqc_ref_fp2_set(x, result);

	mpz_clear(temp1);
	mpz_clear(temp2);
	oqs_sidh_iqc_ref_fp2_clear(result);
}

void oqs_sidh_iqc_ref_fp2_square(fp2_element_t x, const fp2_element_t a) {
	mpz_t temp1;
	mpz_t temp2;

	mpz_init(temp1);
	mpz_init(temp2);

	fp2_element_t result;
	oqs_sidh_iqc_ref_fp2_init(result);

	// (b + a) * (b - a)
	oqs_sidh_iqc_ref_fp_add(temp1, a->a, a->b);
	oqs_sidh_iqc_ref_fp_sub(temp2, a->b, a->a);
	oqs_sidh_iqc_ref_fp_mul(result->b, temp1, temp2);

	// 2 * a * b
	oqs_sidh_iqc_ref_fp_mul(result->a, a->a, a->b);
	oqs_sidh_iqc_ref_fp_mul_si(result->a, result->a, 2);

	oqs_sidh_iqc_ref_fp2_set(x, result);

	mpz_clear(temp1);
	mpz_clear(temp2);
	oqs_sidh_iqc_ref_fp2_clear(result);
}

void oqs_sidh_iqc_ref_fp2_pow_ui(fp2_element_t x, const fp2_element_t a,
                                 unsigned long n) {
	mpz_t temp_n;
	mpz_init_set_ui(temp_n, n);
	oqs_sidh_iqc_ref_fp2_pow(x, a, temp_n);
	mpz_clear(temp_n);
}

void oqs_sidh_iqc_ref_fp2_pow(fp2_element_t x, const fp2_element_t a,
                              const mpz_t n) {
	if (mpz_cmp_ui(n, 0) == 0) {
		oqs_sidh_iqc_ref_fp2_one(x);
		return;
	}

	fp2_element_t temp1;
	fp2_element_t temp2;
	oqs_sidh_iqc_ref_fp2_init_set_si(temp1, 0, 1);
	oqs_sidh_iqc_ref_fp2_init_set(temp2, a);

	long num_bits = mpz_sizeinbase(n, 2);
	for (long i = 0; i < num_bits; i++) {
		if (mpz_tstbit(n, i) == 1)
			oqs_sidh_iqc_ref_fp2_mul(temp1, temp1, temp2);
		oqs_sidh_iqc_ref_fp2_square(temp2, temp2);
	}

	oqs_sidh_iqc_ref_fp2_set(x, temp1);

	oqs_sidh_iqc_ref_fp2_clear(temp1);
	oqs_sidh_iqc_ref_fp2_clear(temp2);
}

void oqs_sidh_iqc_ref_fp2_conjugate(fp2_element_t x, const fp2_element_t a) {
	oqs_sidh_iqc_ref_fp2_set(x, a);
	oqs_sidh_iqc_ref_fp_neg(x->a, x->a);
}

void oqs_sidh_iqc_ref_fp2_negate(fp2_element_t x, const fp2_element_t a) {
	oqs_sidh_iqc_ref_fp2_set(x, a);
	oqs_sidh_iqc_ref_fp_neg(x->a, x->a);
	oqs_sidh_iqc_ref_fp_neg(x->b, x->b);
}

void oqs_sidh_iqc_ref_fp2_mul_scaler(fp2_element_t x, const fp2_element_t a,
                                     const mpz_t scaler) {
	oqs_sidh_iqc_ref_fp_mul(x->a, a->a, scaler);
	oqs_sidh_iqc_ref_fp_mul(x->b, a->b, scaler);
}

void oqs_sidh_iqc_ref_fp2_mul_scaler_si(fp2_element_t x, const fp2_element_t a,
                                        long scaler) {
	oqs_sidh_iqc_ref_fp_mul_si(x->a, a->a, scaler);
	oqs_sidh_iqc_ref_fp_mul_si(x->b, a->b, scaler);
}

void oqs_sidh_iqc_ref_fp2_inv(fp2_element_t x, const fp2_element_t a) {
	mpz_t temp;
	fp2_element_t result;

	mpz_init(temp);
	oqs_sidh_iqc_ref_fp2_init(result);

	oqs_sidh_iqc_ref_fp2_conjugate(result, a);
	oqs_sidh_iqc_ref_fp2_norm(temp, a);
	oqs_sidh_iqc_ref_fp_inv(temp, temp);
	oqs_sidh_iqc_ref_fp2_mul_scaler(result, result, temp);
	oqs_sidh_iqc_ref_fp2_set(x, result);

	mpz_clear(temp);
	oqs_sidh_iqc_ref_fp2_clear(result);
}

void oqs_sidh_iqc_ref_fp2_div(fp2_element_t x, const fp2_element_t a,
                              const fp2_element_t b) {
	fp2_element_t result;
	oqs_sidh_iqc_ref_fp2_init(result);

	oqs_sidh_iqc_ref_fp2_inv(result, b);
	oqs_sidh_iqc_ref_fp2_mul(result, a, result);
	oqs_sidh_iqc_ref_fp2_set(x, result);

	oqs_sidh_iqc_ref_fp2_clear(result);
}

int oqs_sidh_iqc_ref_fp2_is_zero(const fp2_element_t a) {
	return !mpz_cmp_si(a->a, 0) && !mpz_cmp_si(a->b, 0);
}

int oqs_sidh_iqc_ref_fp2_is_one(const fp2_element_t a) {
	return !mpz_cmp_si(a->a, 0) && !mpz_cmp_si(a->b, 1);
}

int oqs_sidh_iqc_ref_fp2_equals(const fp2_element_t a, const fp2_element_t b) {
	return (mpz_cmp(a->a, b->a) == 0) && (mpz_cmp(a->b, b->b) == 0);
}

void oqs_sidh_iqc_ref_fp2_random(fp2_element_t x, gmp_randstate_t randstate) {
	mpz_urandomm(x->a, randstate, characteristic);
	mpz_urandomm(x->b, randstate, characteristic);
}

void oqs_sidh_iqc_ref_fp2_sqrt(fp2_element_t x, const fp2_element_t a) {
	mpz_t exponent;
	fp2_element_t temp_a;
	fp2_element_t b;
	fp2_element_t c;
	fp2_element_t beta;
	mpz_t base_root;
	gmp_randstate_t randstate;

	mpz_init(exponent);
	oqs_sidh_iqc_ref_fp2_init(temp_a);
	oqs_sidh_iqc_ref_fp2_init(b);
	oqs_sidh_iqc_ref_fp2_init(c);
	oqs_sidh_iqc_ref_fp2_init(beta);
	mpz_init(base_root);
	gmp_randinit_default(randstate);

	// compute (p - 1) / 2
	mpz_sub_ui(exponent, characteristic, 1);
	mpz_divexact_ui(exponent, exponent, 2);

	while (oqs_sidh_iqc_ref_fp2_is_zero(b)) {
		oqs_sidh_iqc_ref_fp2_random(c, randstate);
		oqs_sidh_iqc_ref_fp2_square(temp_a, c);
		oqs_sidh_iqc_ref_fp2_mul(temp_a, temp_a, a);

		// compute 1 + temp_a^((p - 1) / 2)
		oqs_sidh_iqc_ref_fp2_pow(b, temp_a, exponent);
		oqs_sidh_iqc_ref_fp2_add_ui(b, b, 1);
	}

	// compute temp_a * b^2
	oqs_sidh_iqc_ref_fp2_square(beta, b);
	oqs_sidh_iqc_ref_fp2_mul(beta, beta, temp_a);

	// beta is now in the prime field
	oqs_sidh_iqc_ref_fp_sqrt(base_root, beta->b);
	oqs_sidh_iqc_ref_fp2_inv(b, b);
	oqs_sidh_iqc_ref_fp2_mul_scaler(b, b, base_root);
	oqs_sidh_iqc_ref_fp2_div(x, b, c);

	mpz_clear(exponent);
	oqs_sidh_iqc_ref_fp2_clear(temp_a);
	oqs_sidh_iqc_ref_fp2_clear(b);
	oqs_sidh_iqc_ref_fp2_clear(c);
	oqs_sidh_iqc_ref_fp2_clear(beta);
	mpz_clear(base_root);
	gmp_randclear(randstate);
}

int oqs_sidh_iqc_ref_fp2_is_square(const fp2_element_t a) {
	mpz_t exponent;
	mpz_t norm;
	fp2_element_t temp;

	mpz_init(exponent);
	mpz_init(norm);
	oqs_sidh_iqc_ref_fp2_init(temp);

	// a^((p - 1) / 2)
	mpz_sub_ui(exponent, characteristic, 1);
	mpz_divexact_ui(exponent, exponent, 2);
	oqs_sidh_iqc_ref_fp2_pow(temp, a, exponent);

	oqs_sidh_iqc_ref_fp2_norm(norm, temp);
	int result = (mpz_cmp_si(norm, 1) == 0);

	mpz_clear(exponent);
	mpz_clear(norm);
	oqs_sidh_iqc_ref_fp2_clear(temp);

	return result;
}

void oqs_sidh_iqc_ref_fp2_norm(mpz_t x, const fp2_element_t a) {
	mpz_t temp1;
	mpz_t temp2;
	mpz_inits(temp1, temp2, NULL);

	oqs_sidh_iqc_ref_fp_mul(temp1, a->a, a->a);
	oqs_sidh_iqc_ref_fp_mul(temp2, a->b, a->b);
	oqs_sidh_iqc_ref_fp_add(temp1, temp1, temp2);

	mpz_set(x, temp1);
	mpz_clears(temp1, temp2, NULL);
}

void oqs_sidh_iqc_ref_fp2_to_bytes(uint8_t *bytes, const fp2_element_t a,
                                   long prime_size) {
	for (long i = 0; i < 2 * prime_size; i++)
		bytes[i] = 0;

	mpz_export(bytes, NULL, -1, 1, 0, 0, a->a);
	mpz_export(bytes + prime_size, NULL, -1, 1, 0, 0, a->b);
}

void oqs_sidh_iqc_ref_bytes_to_fp2(fp2_element_t a, const uint8_t *bytes,
                                   long prime_size) {
	oqs_sidh_iqc_ref_fp2_zero(a);
	mpz_import(a->a, prime_size, -1, 1, 0, 0, bytes);
	mpz_import(a->b, prime_size, -1, 1, 0, 0, bytes + prime_size);
}
