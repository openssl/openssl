#include <stdio.h>
#include "sidh_public_param.h"

void oqs_sidh_iqc_ref_public_params_init(public_params_t params) {
	mpz_init(params->characteristic);
	oqs_sidh_iqc_ref_elliptic_curve_init(params->E);
	oqs_sidh_iqc_ref_point_init(params->P);
	oqs_sidh_iqc_ref_point_init(params->Q);
	mpz_init(params->le);
}

int oqs_sidh_iqc_ref_public_params_read(public_params_t paramsA,
                                        public_params_t paramsB,
                                        const char **input) {
	fp2_element_t a;
	fp2_element_t b;
	oqs_sidh_iqc_ref_fp2_init(a);
	oqs_sidh_iqc_ref_fp2_init(b);

	gmp_sscanf(input[0], "p : %Zd \n", paramsA->characteristic);
	mpz_set(paramsB->characteristic, paramsA->characteristic);
	gmp_sscanf(input[1],
	           "E : y^2 = x^3 + (%Zd * i + %Zd) * x + (%Zd * i + %Zd) \n",
	           a->a, a->b, b->a, b->b);
	oqs_sidh_iqc_ref_elliptic_curve_set_coeffs(paramsA->E, a, b);
	oqs_sidh_iqc_ref_elliptic_curve_set(paramsB->E, paramsA->E);
	gmp_sscanf(input[2], "lA: %ld \n", &paramsA->l);
	gmp_sscanf(input[3], "eA: %ld \n", &paramsA->e);
	mpz_ui_pow_ui(paramsA->le, paramsA->l, paramsA->e);
	gmp_sscanf(input[4],
	           "PA: (%Zd * i + %Zd, %Zd * i + %Zd) \n",
	           a->a, a->b, b->a, b->b);
	oqs_sidh_iqc_ref_point_set_coordinates(paramsA->P, a, b, 1);
	gmp_sscanf(input[5],
	           "QA: (%Zd * i + %Zd, %Zd * i + %Zd) \n",
	           a->a, a->b, b->a, b->b);
	oqs_sidh_iqc_ref_point_set_coordinates(paramsA->Q, a, b, 1);
	gmp_sscanf(input[6], "lB: %ld \n", &paramsB->l);
	gmp_sscanf(input[7], "eB: %ld \n", &paramsB->e);
	mpz_ui_pow_ui(paramsB->le, paramsB->l, paramsB->e);
	gmp_sscanf(input[8],
	           "PB: (%Zd * i + %Zd, %Zd * i + %Zd) \n",
	           a->a, a->b, b->a, b->b);
	oqs_sidh_iqc_ref_point_set_coordinates(paramsB->P, a, b, 1);
	gmp_sscanf(input[9],
	           "QB: (%Zd * i + %Zd, %Zd * i + %Zd) \n",
	           a->a, a->b, b->a, b->b);
	oqs_sidh_iqc_ref_point_set_coordinates(paramsB->Q, a, b, 1);

	oqs_sidh_iqc_ref_fp2_clear(a);
	oqs_sidh_iqc_ref_fp2_clear(b);

	return 1;
}

void oqs_sidh_iqc_ref_public_params_print(const public_params_t params,
                                          int print_torsion) {
	if (print_torsion != 1) {
		printf("p : %s\n", mpz_get_str(NULL, 10, params->characteristic));
		printf("E : %s\n", oqs_sidh_iqc_ref_elliptic_curve_get_str(params->E));
	}

	printf("lA: %ld\n", params->l);
	printf("eA: %ld\n", params->e);
	printf("PA: %s\n", oqs_sidh_iqc_ref_point_get_str(params->P));
	printf("QA: %s\n", oqs_sidh_iqc_ref_point_get_str(params->Q));
}

void oqs_sidh_iqc_ref_public_params_clear(public_params_t params) {
	mpz_clear(params->characteristic);
	oqs_sidh_iqc_ref_elliptic_curve_clear(params->E);
	oqs_sidh_iqc_ref_point_clear(params->P);
	oqs_sidh_iqc_ref_point_clear(params->Q);
	mpz_clear(params->le);
}
