#ifndef PUBLIC_PARAM_H
#define PUBLIC_PARAM_H

#include "sidh_elliptic_curve.h"
#include "sidh_quadratic_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Representation of the public parameters in oqs_sidh_iqc_ref
 */
typedef struct {
	// the characteristic
	mpz_t characteristic;

	elliptic_curve_t E;
	unsigned long l;
	unsigned long e;

	// a generator for the l^e torsion subgroup of E
	point_t P;
	point_t Q;

	// l^e, precomputed
	mpz_t le;

} public_params_struct;

typedef public_params_struct public_params_t[1];

/**
 * Initializes the public parameters.
 * @param params
 */
void oqs_sidh_iqc_ref_public_params_init(public_params_t params);

/**
 * Reads the public parameters from array pointed by {@code input}.
 * @param paramsA
 * @param paramsB
 * @param input
 * @return 1 if the parameters are read successfully, and 0 otherwise.
 */
int oqs_sidh_iqc_ref_public_params_read(public_params_t paramsA,
                                        public_params_t paramsB,
                                        const char **input);

/**
 * Prints the public parameters to the standard output.
 * @param params
 * @param torsion if it is 1 only the torsion parameters are printed
 */
void oqs_sidh_iqc_ref_public_params_print(const public_params_t params,
                                          int print_torsion);

/**
 * Frees the memory allocated to {@code params}.
 * @param params
 */
void oqs_sidh_iqc_ref_public_params_clear(public_params_t params);

#ifdef __cplusplus
}
#endif

#endif /* PUBLIC_PARAM_H */
