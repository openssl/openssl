#ifndef UTIL_H
#define UTIL_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Concatenates two strings.
 * @param str1
 * @param str2
 * @return the concatenation of {@code str1, str2}
 */
char *oqs_sidh_iqc_ref_concat(char *str1,
                              const char *str2);

/**
 * Generates a random char array of length {@code num_bytes}.
 * @param num_bytes
 * @return a random char array of length {@code num_bytes}
 */
char *oqs_sidh_iqc_ref_get_random_str(int num_bytes);

/**
 * @param x a randomly generated 160bit integer
 */
void oqs_sidh_iqc_ref_get_random_mpz(mpz_t x);

/**
 * @param array1
 * @param array2
 * @param lenght
 * @return the bitwise xor of the two arrays
 */
char *oqs_sidh_iqc_ref_array_xor(const char *array1,
                                 const char *array2,
                                 long lenght);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_H */
