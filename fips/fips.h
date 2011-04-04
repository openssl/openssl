/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#error FIPS is disabled.
#endif

#ifdef OPENSSL_FIPS

#ifdef  __cplusplus
extern "C" {
#endif

struct dsa_st;
struct rsa_st;
struct evp_pkey_st;
struct env_md_st;
struct evp_cipher_st;
struct evp_cipher_ctx_st;

int FIPS_mode_set(int onoff);
int FIPS_mode(void);
const void *FIPS_rand_check(void);
int FIPS_selftest(void);
int FIPS_selftest_failed(void);
void FIPS_selftest_check(void);
void FIPS_corrupt_sha1(void);
int FIPS_selftest_sha1(void);
void FIPS_corrupt_aes(void);
int FIPS_selftest_aes_gcm(void);
void FIPS_corrupt_aes_gcm(void);
int FIPS_selftest_aes(void);
void FIPS_corrupt_des(void);
int FIPS_selftest_des(void);
void FIPS_corrupt_rsa(void);
void FIPS_corrupt_rsa_keygen(void);
int FIPS_selftest_rsa(void);
void FIPS_corrupt_dsa(void);
void FIPS_corrupt_dsa_keygen(void);
int FIPS_selftest_dsa(void);
int FIPS_selftest_ecdsa(void);
void FIPS_corrupt_ecdsa(void);
void FIPS_corrupt_ec_keygen(void);
void FIPS_corrupt_rng(void);
void FIPS_corrupt_drbg(void);
void FIPS_rng_stick(void);
void FIPS_drbg_stick(void);
int FIPS_selftest_rng(void);
int FIPS_selftest_hmac(void);
int FIPS_selftest_drbg(void);
int FIPS_selftest_cmac(void);

unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len);
int FIPS_check_incore_fingerprint(void);

int fips_pkey_signature_test(struct evp_pkey_st *pkey,
			const unsigned char *tbs, int tbslen,
			const unsigned char *kat, unsigned int katlen,
			const struct env_md_st *digest, int pad_mode,
			const char *fail_str);

int fips_cipher_test(struct evp_cipher_ctx_st *ctx,
			const struct evp_cipher_st *cipher,
			const unsigned char *key,
			const unsigned char *iv,
			const unsigned char *plaintext,
			const unsigned char *ciphertext,
			int len);

void fips_set_selftest_fail(void);
int fips_check_rsa(struct rsa_st *rsa);

void FIPS_set_locking_callbacks(void (*func)(int mode, int type,
				const char *file,int line),
				int (*add_cb)(int *pointer, int amount,
					int type, const char *file, int line));

void FIPS_set_malloc_callbacks(
		void *(*malloc_cb)(int num, const char *file, int line),
		void (*free_cb)(void *));

#define FIPS_ERROR_IGNORED(alg) OpenSSLDie(__FILE__, __LINE__, \
		alg " previous FIPS forbidden algorithm error ignored");

/* Where necessary redirect standard OpenSSL APIs to FIPS versions */

#if defined(OPENSSL_FIPSCANISTER) && defined(OPENSSL_FIPSAPI)

#define CRYPTO_lock FIPS_lock
#define CRYPTO_add_lock FIPS_add_lock
#define CRYPTO_malloc FIPS_malloc
#define CRYPTO_free FIPS_free

#define ERR_put_error FIPS_put_error
#define ERR_add_error_data FIPS_add_error_data

#define EVP_MD_CTX_init FIPS_md_ctx_init
#define EVP_MD_CTX_cleanup FIPS_md_ctx_cleanup
#define EVP_MD_CTX_create FIPS_md_ctx_create
#define EVP_MD_CTX_destroy FIPS_md_ctx_destroy
#define EVP_DigestInit_ex(ctx, type, impl) FIPS_digestinit(ctx, type)
#define EVP_DigestInit FIPS_digestinit
#define EVP_DigestUpdate FIPS_digestupdate
#define EVP_Digest(data, count, md, size, type, impl) \
			FIPS_digest(data, count, md, size, type)
#define EVP_DigestFinal_ex FIPS_digestfinal
#define EVP_MD_CTX_copy_ex FIPS_md_ctx_copy

#define EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc) \
				FIPS_cipherinit(ctx, cipher, key, iv, enc)

#define EVP_CipherInit FIPS_cipherinit

#define EVP_CIPHER_CTX_init FIPS_cipher_ctx_init
#define EVP_CIPHER_CTX_cleanup FIPS_cipher_ctx_cleanup
#define EVP_Cipher FIPS_cipher
#define EVP_CIPHER_CTX_ctrl FIPS_cipher_ctx_ctrl
#define EVP_CIPHER_CTX_new FIPS_cipher_ctx_new
#define EVP_CIPHER_CTX_free FIPS_cipher_ctx_free
#define EVP_CIPHER_CTX_copy FIPS_cipher_ctx_copy
#define EVP_CIPHER_CTX_set_key_length FIPS_cipher_ctx_set_key_length

#define DSA_SIG_new FIPS_dsa_sig_new
#define DSA_SIG_free FIPS_dsa_sig_free

#define ECDSA_SIG_new FIPS_ecdsa_sig_new
#define ECDSA_SIG_free FIPS_ecdsa_sig_free

#define ecdsa_check fips_ecdsa_check
#define ecdh_check fips_ecdh_check

#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_FIPS_strings(void);

/* Error codes for the FIPS functions. */

/* Function codes. */
#define FIPS_F_DH_BUILTIN_GENPARAMS			 100
#define FIPS_F_DRBG_CPRNG_TEST				 141
#define FIPS_F_DSA_BUILTIN_PARAMGEN			 101
#define FIPS_F_DSA_BUILTIN_PARAMGEN2			 126
#define FIPS_F_DSA_DO_SIGN				 102
#define FIPS_F_DSA_DO_VERIFY				 103
#define FIPS_F_EVP_CIPHERINIT_EX			 124
#define FIPS_F_EVP_DIGESTINIT_EX			 125
#define FIPS_F_FIPS_CHECK_DSA				 104
#define FIPS_F_FIPS_CHECK_EC				 129
#define FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT		 105
#define FIPS_F_FIPS_CHECK_RSA				 106
#define FIPS_F_FIPS_CIPHERINIT				 128
#define FIPS_F_FIPS_DIGESTINIT				 127
#define FIPS_F_FIPS_DRBG_BYTES				 142
#define FIPS_F_FIPS_DRBG_GENERATE			 132
#define FIPS_F_FIPS_DRBG_GENERATE_INTERNAL		 138
#define FIPS_F_FIPS_DRBG_HEALTH_CHECK			 137
#define FIPS_F_FIPS_DRBG_INIT				 136
#define FIPS_F_FIPS_DRBG_INSTANTIATE			 133
#define FIPS_F_FIPS_DRBG_NEW				 134
#define FIPS_F_FIPS_DRBG_RESEED				 135
#define FIPS_F_FIPS_DRBG_SINGLE_KAT			 140
#define FIPS_F_FIPS_DSA_CHECK				 107
#define FIPS_F_FIPS_MODE_SET				 108
#define FIPS_F_FIPS_PKEY_SIGNATURE_TEST			 109
#define FIPS_F_FIPS_SELFTEST_AES			 110
#define FIPS_F_FIPS_SELFTEST_AES_GCM			 130
#define FIPS_F_FIPS_SELFTEST_CMAC			 139
#define FIPS_F_FIPS_SELFTEST_DES			 111
#define FIPS_F_FIPS_SELFTEST_DSA			 112
#define FIPS_F_FIPS_SELFTEST_ECDSA			 131
#define FIPS_F_FIPS_SELFTEST_HMAC			 113
#define FIPS_F_FIPS_SELFTEST_RNG			 114
#define FIPS_F_FIPS_SELFTEST_SHA1			 115
#define FIPS_F_HASH_FINAL				 123
#define FIPS_F_RSA_BUILTIN_KEYGEN			 116
#define FIPS_F_RSA_EAY_PRIVATE_DECRYPT			 117
#define FIPS_F_RSA_EAY_PRIVATE_ENCRYPT			 118
#define FIPS_F_RSA_EAY_PUBLIC_DECRYPT			 119
#define FIPS_F_RSA_EAY_PUBLIC_ENCRYPT			 120
#define FIPS_F_RSA_X931_GENERATE_KEY_EX			 121
#define FIPS_F_SSLEAY_RAND_BYTES			 122

/* Reason codes. */
#define FIPS_R_ADDITIONAL_INPUT_TOO_LONG		 118
#define FIPS_R_ALREADY_INSTANTIATED			 119
#define FIPS_R_CANNOT_READ_EXE				 103
#define FIPS_R_CANNOT_READ_EXE_DIGEST			 104
#define FIPS_R_CONTRADICTING_EVIDENCE			 114
#define FIPS_R_DRBG_STUCK				 142
#define FIPS_R_ENTROPY_ERROR_UNDETECTED			 133
#define FIPS_R_ENTROPY_NOT_REQUESTED_FOR_RESEED		 134
#define FIPS_R_ERROR_INITIALISING_DRBG			 120
#define FIPS_R_ERROR_INSTANTIATING_DRBG			 121
#define FIPS_R_ERROR_RETRIEVING_ADDITIONAL_INPUT	 144
#define FIPS_R_ERROR_RETRIEVING_ENTROPY			 122
#define FIPS_R_ERROR_RETRIEVING_NONCE			 123
#define FIPS_R_EXE_DIGEST_DOES_NOT_MATCH		 105
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH		 110
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH_NONPIC_RELOCATED 111
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH_SEGMENT_ALIASING 112
#define FIPS_R_FIPS_MODE_ALREADY_SET			 102
#define FIPS_R_FIPS_SELFTEST_FAILED			 106
#define FIPS_R_FUNCTION_ERROR				 135
#define FIPS_R_GENERATE_ERROR				 124
#define FIPS_R_GENERATE_ERROR_UNDETECTED		 136
#define FIPS_R_INSTANTIATE_ERROR			 125
#define FIPS_R_INSUFFICIENT_SECURITY_STRENGTH		 132
#define FIPS_R_INTERNAL_ERROR				 143
#define FIPS_R_INVALID_KEY_LENGTH			 109
#define FIPS_R_IN_ERROR_STATE				 126
#define FIPS_R_KEY_TOO_SHORT				 108
#define FIPS_R_NON_FIPS_METHOD				 100
#define FIPS_R_NOT_INSTANTIATED				 127
#define FIPS_R_PAIRWISE_TEST_FAILED			 107
#define FIPS_R_PERSONALISATION_ERROR_UNDETECTED		 137
#define FIPS_R_PERSONALISATION_STRING_TOO_LONG		 128
#define FIPS_R_REQUEST_LENGTH_ERROR_UNDETECTED		 138
#define FIPS_R_REQUEST_TOO_LARGE_FOR_DRBG		 129
#define FIPS_R_RESEED_COUNTER_ERROR			 139
#define FIPS_R_RESEED_ERROR				 130
#define FIPS_R_RSA_DECRYPT_ERROR			 115
#define FIPS_R_RSA_ENCRYPT_ERROR			 116
#define FIPS_R_SELFTEST_FAILED				 101
#define FIPS_R_STRENGTH_ERROR_UNDETECTED		 140
#define FIPS_R_TEST_FAILURE				 117
#define FIPS_R_UNINSTANTIATE_ZEROISE_ERROR		 141
#define FIPS_R_UNSUPPORTED_DRBG_TYPE			 131
#define FIPS_R_UNSUPPORTED_PLATFORM			 113

#ifdef  __cplusplus
}
#endif
#endif
