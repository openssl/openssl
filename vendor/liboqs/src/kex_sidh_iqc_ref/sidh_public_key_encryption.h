#ifndef PUBLIC_KEY_ENCRYPTION_H
#define PUBLIC_KEY_ENCRYPTION_H

#include "sidh_elliptic_curve.h"
#include "sidh_public_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Representation of ciphertext in oqs_sidh_iqc_ref
 */
typedef struct {
	elliptic_curve_t E;
	point_t P;
	point_t Q;
	char *content;

	// size of the content field
	long size;
} ciphertext_struct;

/**
 * Representation of plaintext in oqs_sidh_iqc_ref
 */
typedef struct {
	char *content;

	// size of the content field
	long size;
} plaintext_struct;

typedef ciphertext_struct ciphertext_t[1];
typedef plaintext_struct plaintext_t[1];

/**
 * Initializes the ciphertext.
 * @param ciphertext
 */
void oqs_sidh_iqc_ref_public_key_ciphertext_init(ciphertext_t ciphertext);

/**
 * Frees the memory allocated to {@code ciphertext}.
 * @param ciphertext
 */
void oqs_sidh_iqc_ref_public_key_ciphertext_clear(ciphertext_t ciphertext);

/**
 * Initializes the plaintext.
 * @param plaintext
 */
void oqs_sidh_iqc_ref_public_key_plaintext_init(plaintext_t plaintext);

/**
 * Frees the memory allocated to {@code plaintext}.
 * @param plaintext
 */
void oqs_sidh_iqc_ref_public_key_plaintext_clear(plaintext_t plaintext);

/**
 * Pads a given plain text for encryption.
 * @param result the prepared plaintext
 * @param raw the given plaintext
 * @return 1 if successful, and -1 otherwise
 */
int oqs_sidh_iqc_ref_public_key_pad_plaintext(plaintext_t result,
                                              const plaintext_t raw);

/**
 * Encrypts the {@code plaintext} using {@code public_key}.
 * @param ciphertext the generated cipher
 * @param plaintext
 * @param public_keyA other's public-key
 * @param paramsA other's public params
 * @param paramsB own pubic params
 */
void oqs_sidh_iqc_ref_public_key_encrypt(ciphertext_t ciphertext,
                                         const plaintext_t plaintext,
                                         const public_key_t public_keyA,
                                         const public_params_t paramsA,
                                         const public_params_t paramsB);

/**
 * Decrypts the {@code ciphertext} using {@code private_key}.
 * @param plaintext the result
 * @param ciphertext the given ciphertext
 * @param private_keyA
 * @param paramsA the public parameters associated to the owner of
 * the private-key
 */
void oqs_sidh_iqc_ref_public_key_decrypt(plaintext_t plaintext,
                                         const ciphertext_t ciphertext,
                                         const private_key_t private_keyA,
                                         const public_params_t paramsA);

/**
 * Computes the hash of {@code value}
 * @param value
 * @param size size of the output hash
 * @return the hash
 */
char *oqs_sidh_iqc_ref_public_key_encryption_hash(const fp2_element_t value,
                                                  long size);

/**
 * @return the key-size in bytes
 */
long oqs_sidh_iqc_ref_public_key_get_key_size();

#ifdef __cplusplus
}
#endif

#endif /* PUBLIC_KEY_ENCRYPTION_H */
