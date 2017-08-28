#ifndef CURVE_H
#define CURVE_H

#include "sidh_quadratic_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Representation of the elliptic curve y^2 = x^3 + a * x^2 + b * x
 */
typedef struct {
	fp2_element_t a;
	fp2_element_t b;
} elliptic_curve_struct;

typedef elliptic_curve_struct elliptic_curve_t[1];

/**
 * Representation of a point in the standard affine D+(z) of the
 * plain projective projective space
 */
typedef struct {
	fp2_element_t x;
	fp2_element_t y;
	int z;
} point_struct;

typedef point_struct point_t[1];

/**
 * Initializes the input curve to y^2 = x^3 + x + 1.
 * @param E
 */
void oqs_sidh_iqc_ref_elliptic_curve_init(elliptic_curve_t E);

/**
 * Copies T into E
 * @param E
 * @param T
 */
void oqs_sidh_iqc_ref_elliptic_curve_set(elliptic_curve_t E,
                                         const elliptic_curve_t T);

/**
 * Sets the coefficients of E: y^2 = x^3 + a * x^2 + b * x.
 * @param E
 * @param a
 * @param b
 */
void oqs_sidh_iqc_ref_elliptic_curve_set_coeffs(elliptic_curve_t E,
                                                const fp2_element_t a,
                                                const fp2_element_t b);

/**
 * Initializes the point {@code P} to the zero point (0 : 1 : 0).
 * @param P
 */
void oqs_sidh_iqc_ref_point_init(point_t P);

/**
 * Sets the coordinates of the point {@code P}.
 * @param P
 * @param x
 * @param y
 * @param z
 */
void oqs_sidh_iqc_ref_point_set_coordinates(point_t P,
                                            const fp2_element_t x,
                                            const fp2_element_t y,
                                            int z);

/**
 * Copies {@code Q} into {@code P}
 * @param P
 * @param Q
 */
void oqs_sidh_iqc_ref_point_set(point_t P,
                                const point_t Q);

/**
 * Sets the given point to zero.
 * @param P
 */
void oqs_sidh_iqc_ref_point_zero(point_t P);

/**
 * Checks if a given point is zero.
 * @param P
 * @return
 */
int oqs_sidh_iqc_ref_point_is_zero(const point_t P);

/**
 * Sets {@code P} to {@code -Q} as a group element.
 * @param P
 * @param Q
 */
void oqs_sidh_iqc_ref_point_negate(point_t P,
                                   const point_t Q);

/**
 * Checks if 2 * {@code P} = 0.
 * @param P
 * @return
 */
int oqs_sidh_iqc_ref_point_has_order_2(const point_t P);

/**
 * Frees the memory allocated to {@code E}.
 * @param E
 */
void oqs_sidh_iqc_ref_elliptic_curve_clear(elliptic_curve_t E);

/**
 * Frees the memory allocated to {@code P}.
 * @param P
 */
void oqs_sidh_iqc_ref_point_clear(point_t P);

/**
 * Checks if {@code P = Q}.
 * @param P
 * @param Q
 * @return 1 if the points are equal, 0 otherwise
 */
int oqs_sidh_iqc_ref_point_equals(const point_t P,
                                  const point_t Q);

/**
 * @param E
 * @return A string representation of {@code E}
 */
char *oqs_sidh_iqc_ref_elliptic_curve_get_str(const elliptic_curve_t E);

/**
 * @param P
 * @return A string representation of {@code P}
 */
char *oqs_sidh_iqc_ref_point_get_str(const point_t P);

/**
 * Sets {@code R = P + Q} on {@code E}.
 * @param R
 * @param P
 * @param Q
 * @param E
 */
void oqs_sidh_iqc_ref_point_add(point_t R,
                                const point_t P,
                                const point_t Q,
                                const elliptic_curve_t E);

/**
 * Sets {@code R = P - Q}.
 * @param R
 * @param P
 * @param Q
 * @param E
 */
void oqs_sidh_iqc_ref_point_sub(point_t R,
                                const point_t P,
                                const point_t Q,
                                const elliptic_curve_t E);

/**
 * Sets {@code R = P + Q} on {@code E}.
 * @param R
 * @param P
 * @param Q
 * @param lambda The slope of the line passing through {@code P, Q}
 */
void oqs_sidh_iqc_ref_point_add_with_lambda(point_t R,
                                            const point_t P,
                                            const point_t Q,
                                            const fp2_element_t lambda);

/**
 * Sets {@code R = 2 * P} on {@code E}.
 * @param R
 * @param P
 * @param E
 */
void oqs_sidh_iqc_ref_point_double(point_t R,
                                   const point_t P,
                                   const elliptic_curve_t E);

/**
 * Sets {@code R = scaler * P} on {@code E}.
 * @param R
 * @param P
 * @param scaler
 * @param E
 */
void oqs_sidh_iqc_ref_point_mul_scaler(point_t R,
                                       const point_t P,
                                       const mpz_t scaler,
                                       const elliptic_curve_t E);

/**
 * {@link oqs_sidh_iqc_ref_point_mul_scaler}
 * @param R
 * @param P
 * @param scaler
 * @param E
 */
void oqs_sidh_iqc_ref_point_mul_scaler_si(point_t R,
                                          const point_t P,
                                          long scaler,
                                          const elliptic_curve_t E);

/**
 * Computes the j-invariant of {@code E}.
 * @param j_inv
 * @param E
 */
void oqs_sidh_iqc_ref_elliptic_curve_compute_j_inv(fp2_element_t j_inv,
                                                   const elliptic_curve_t E);

/**
 * Checks if the point {@code P} is on the curve {@code E}.
 * @param P
 * @param E
 * @return 1 if the point is on the curve, 0 otherwise
 */
int oqs_sidh_iqc_ref_point_is_on_curve(const point_t P,
                                       const elliptic_curve_t E);

/**
 * Generates a random point on the curve {@code E}.
 * @param P the generated random point.
 * @param E
 */
void oqs_sidh_iqc_ref_elliptic_curve_random_point(point_t P,
                                                  const elliptic_curve_t E);

#ifdef __cplusplus
}
#endif

#endif /* CURVE_H */
