#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <oqs/rand.h>

#include "sidh_util.h"

char *oqs_sidh_iqc_ref_concat(char *str1, const char *str2) {
	char *temp = (char *) malloc(strlen(str1) + strlen(str2) + 1);
	strcpy(temp, str1);
	strcat(temp, str2);
	return temp;
}

char *oqs_sidh_iqc_ref_get_random_str(int num_bytes) {
	char *rand_value = (char *) malloc(num_bytes);
	OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
	OQS_RAND_n(rand, (uint8_t *) rand_value, num_bytes);

	return rand_value;
}

void oqs_sidh_iqc_ref_get_random_mpz(mpz_t x) {
	int num_bytes = 20;
	char *a = oqs_sidh_iqc_ref_get_random_str(num_bytes);
	mpz_import(x, num_bytes, 1, sizeof(char), 0, 0, a);
}

char *oqs_sidh_iqc_ref_array_xor(const char *array1, const char *array2,
                                 long lenght) {
	char *result = (char *) malloc(lenght);
	for (long i = 0; i < lenght; i++)
		result[i] = array1[i] ^ array2[i];

	return result;
}
