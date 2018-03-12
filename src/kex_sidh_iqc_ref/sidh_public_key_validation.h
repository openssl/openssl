#ifndef PUBLIC_KEY_VALIDATION_H
#define PUBLIC_KEY_VALIDATION_H

#include "sidh_elliptic_curve.h"
#include "sidh_public_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if a given public-key is valid.
 * @param public_key
 * @param params the other party's public parameters from which
 * the public-key is generated.
 * @return 1 if the public-key is valid, 0 otherwise
 */
int oqs_sidh_iqc_ref_public_key_is_valid(const public_key_t public_key,
                                         const public_params_t params);

/**
 * Checks if {@code P} has the exact order l^e where l, e are given in
 * {@code params}.
 * @param P
 * @param E
 * @param params
 * @return 1 if {@code P} has order l^e, 0 otherwise
 */
int oqs_sidh_iqc_ref_public_key_check_order(const point_t P,
                                            const elliptic_curve_t E,
                                            const public_params_t params);

/**
 * Checks if the two point in {@code public-key} are linearly independent.
 * @param public_key
 * @param params
 * @return 1 if the points are linearly independent, 0 otherwise
 */
int oqs_sidh_iqc_ref_public_key_check_dependency(const public_key_t public_key,
                                                 const public_params_t params);

/**
 * Checks if a given is valid supersingular curve. A curve is considered
 * valid if it has order (p + 1)^2 where p is the characteristic. The test
 * is done probabilistically.
 * @param E
 * @return 1 if the curve is valid, 0 otherwise.
 */
int oqs_sidh_iqc_ref_public_key_check_curve(const elliptic_curve_t E);

#ifdef __cplusplus
}
#endif

#endif /* PUBLIC_KEY_VALIDATION_H */
