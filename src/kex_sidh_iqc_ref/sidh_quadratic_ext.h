#ifndef FP2_H
#define FP2_H

#include <gmp.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

mpz_t characteristic;

/**
 * Representation of elements of the quadratic extension F_(p^2)
 * of F_p. We assume F_(p^2) is represented by the quotient
 * F_p[X] / (X^2 + 1) which requires X^2 + 1 to be irreducible over F_p.
 * The elements are therefore of the form a * i + b where i^2 = -1.
 */
typedef struct {
	mpz_t a;
	mpz_t b;
} fp2_element_struct;

typedef fp2_element_struct fp2_element_t[1];

//////////////// fp methods //////////////////////////

/**
 * {@link oqs_sidh_iqc_ref_init_chararacteristic}
 * @param p
 */
void oqs_sidh_iqc_ref_fp_init_chararacteristic_ui(long p);

/**
 * {@link oqs_sidh_iqc_ref_init_chararacteristic}
 * @param value
 */
void oqs_sidh_iqc_ref_fp_init_chararacteristic_str(const char *value);

/**
 * Initializes the characteristic to {@code p}.
 * @param p
 */
void oqs_sidh_iqc_ref_fp_init_chararacteristic(const mpz_t p);

/**
 * Sets {@code x = a}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp_set(mpz_t x, const mpz_t a);

/**
 * Sets {@code x = a + b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_add(mpz_t x,
                             const mpz_t a,
                             const mpz_t b);

/**
 * {@link oqs_sidh_iqc_ref_fp_add}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_add_ui(mpz_t x,
                                const mpz_t a,
                                unsigned long b);

/**
 * Sets {@code x = a - b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_sub(mpz_t x,
                             const mpz_t a,
                             const mpz_t b);

/**
 * {@link oqs_sidh_iqc_ref_fp_sub}
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_sub_ui(mpz_t x,
                                const mpz_t a,
                                unsigned long b);

/**
 * Sets {@code x = a * b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_mul(mpz_t x,
                             const mpz_t a,
                             const mpz_t b);

/**
 * {@link oqs_sidh_iqc_ref_fp_mul}
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_mul_si(mpz_t x,
                                const mpz_t a,
                                long b);

/**
 * Sets {@code x = 1 / a}. This is possible only if {@code a} is
 * prime to the characteristic.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp_inv(mpz_t x,
                             const mpz_t a);

/**
 * Sets {x = a / b}. @see fp_inv.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp_div(mpz_t x,
                             const mpz_t a,
                             const mpz_t b);

/**
 * Sets {@code x = -a}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp_neg(mpz_t x,
                             const mpz_t a);

/**
 * Computes the square root of {@code a}.
 * This method works only for p = 3 mod 4.
 * @param x the square root
 * @param a
 */
void oqs_sidh_iqc_ref_fp_sqrt(mpz_t x,
                              const mpz_t a);

//////////////// fp2 methods //////////////////////////

/**
 * Initializes {@code x} to zero.
 * @param x
 */
void oqs_sidh_iqc_ref_fp2_init(fp2_element_t x);

/**
 * Initializes {@code x} to {@code a * i + b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_init_set_si(fp2_element_t x,
                                      long a,
                                      long b);

/**
 * {@link oqs_sidh_iqc_ref_fp2_init_set_si}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_init_set_str(fp2_element_t x,
                                       const char *a,
                                       const char *b);

/**
 * Initializes {@code x} to {@code a}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_init_set(fp2_element_t x,
                                   const fp2_element_t a);

/**
 * Frees the memory allocated to {@code x}.
 * @param x
 */
void oqs_sidh_iqc_ref_fp2_clear(fp2_element_t x);

/**
 * Copies {@code a} into {@code x}.
 * @param x
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_set(fp2_element_t x,
                              const fp2_element_t b);

/**
 * Sets {@code a = 0}
 * @param x
 */
void oqs_sidh_iqc_ref_fp2_zero(fp2_element_t x);

/**
 * Sets {@code x = 1}.
 * @param x
 */
void oqs_sidh_iqc_ref_fp2_one(fp2_element_t x);

/**
 * @param a
 * @return the string representation of {@code a}
 */
char *oqs_sidh_iqc_ref_fp2_get_str(const fp2_element_t a);

/**
 * Sets {@code x = a + b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_add(fp2_element_t x,
                              const fp2_element_t a,
                              const fp2_element_t b);

/**
 * {@link oqs_sidh_iqc_ref_fp2_add}
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_add_ui(fp2_element_t x,
                                 const fp2_element_t a,
                                 unsigned long b);

/**
 * Sets {@code x = a - b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_sub(fp2_element_t x,
                              const fp2_element_t a,
                              const fp2_element_t b);

/**
 * {@link oqs_sidh_iqc_ref_fp2_sub}
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_sub_ui(fp2_element_t x,
                                 const fp2_element_t a,
                                 unsigned long b);

/**
 * Sets {@code x = a * b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_mul(fp2_element_t x,
                              const fp2_element_t a,
                              const fp2_element_t b);

/**
 * Sets {@code x = a^2}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_square(fp2_element_t x,
                                 const fp2_element_t a);

/**
 * {@link oqs_sidh_iqc_ref_fp2_pow}
 */
void oqs_sidh_iqc_ref_fp2_pow_ui(fp2_element_t x,
                                 const fp2_element_t a,
                                 unsigned long n);

/**
 * Sets {@code x = a^n}.
 * @param x
 * @param a
 * @param n
 */
void oqs_sidh_iqc_ref_fp2_pow(fp2_element_t x,
                              const fp2_element_t a,
                              const mpz_t n);

/**
 * Sets {@code x = 1 / a}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_inv(fp2_element_t x,
                              const fp2_element_t a);

/**
 * Sets {@code x = a / b}.
 * @param x
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_fp2_div(fp2_element_t x,
                              const fp2_element_t a,
                              const fp2_element_t b);

/**
 * Sets {@code x = -u * i + v} where {@code a = u * i + v}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_conjugate(fp2_element_t x,
                                    const fp2_element_t a);

/**
 * Sets {@code x = -a}.
 * @param x
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_negate(fp2_element_t x,
                                 const fp2_element_t a);

/**
 * Sets {@code x = a * scaler}.
 * @param x
 * @param a
 * @param scaler
 */
void oqs_sidh_iqc_ref_fp2_mul_scaler(fp2_element_t x,
                                     const fp2_element_t a,
                                     const mpz_t scaler);

/**
 * {@link oqs_sidh_iqc_ref_fp2_mul_scaler}
 * @param x
 * @param a
 * @param scaler
 */
void oqs_sidh_iqc_ref_fp2_mul_scaler_si(fp2_element_t x,
                                        const fp2_element_t a,
                                        long scaler);

/**
 * Checks if {@code a} is zero.
 * @param a
 * @return 1 if {@code a == 0}, and 0 otherwise
 */
int oqs_sidh_iqc_ref_fp2_is_zero(const fp2_element_t a);

/**
 * Checks if {@code a} is one.
 * @param a
 * @return 1 if {@code a == 1}, and 0 otherwise
 */
int oqs_sidh_iqc_ref_fp2_is_one(const fp2_element_t a);

/**
 * Checks if {@code a == b}.
 * @param a
 * @param b
 * @return 1 if {@code a == b}, and 0 otherwise.
 */
int oqs_sidh_iqc_ref_fp2_equals(const fp2_element_t a,
                                const fp2_element_t b);

/**
 * Generates a random element in the quadratic extension.
 * @param x the generated random element
 * @param randstate
 */
void oqs_sidh_iqc_ref_fp2_random(fp2_element_t x,
                                 gmp_randstate_t randstate);

/**
 * Computes the square root of {@code a}.
 * The algorithm is based on
 * Doliskani & Schost, Taking Roots over High Extensions of Finite Fields, 2011.
 * It works for any characteristic, but since it uses {@link oqs_sidh_iqc_ref_fp_sqrt} for
 * base-case square root, it is limited to p = 3 mod 4.
 * @param x the square root
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_sqrt(fp2_element_t x,
                               const fp2_element_t a);

/**
 * Checks if {@code a} is a square.
 * @param a
 * @return 1 if {@code a} is a square, 0 otherwise
 */
int oqs_sidh_iqc_ref_fp2_is_square(const fp2_element_t a);

/**
 * Computes the norm of {@code x = b * i + c} which is b^2 + c^2.
 * @param x the computed norm
 * @param a
 */
void oqs_sidh_iqc_ref_fp2_norm(mpz_t x,
                               const fp2_element_t a);

/**
 * Converts bytes an fp2 element to a byte array.
 * @param bytes
 * @param a
 * @param prime_size
 */
void oqs_sidh_iqc_ref_fp2_to_bytes(uint8_t *bytes,
                                   const fp2_element_t a,
                                   long prime_size);

/**
 * Converts a byte array to an fp2 element.
 * @param a
 * @param bytes
 * @param prime_size
 */
void oqs_sidh_iqc_ref_bytes_to_fp2(fp2_element_t a,
                                   const uint8_t *bytes,
                                   long prime_size);

#ifdef __cplusplus
}
#endif

#endif /* FP2_H */
