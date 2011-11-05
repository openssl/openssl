/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
#include <stdarg.h>

#ifndef OPENSSL_FIPS
#error FIPS is disabled.
#endif

#ifdef OPENSSL_FIPS

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef OPENSSL_FIPSCANISTER
#define OPENSSL_FIPSCAPABLE
#endif

struct dsa_st;
struct ec_key_st;
struct rsa_st;
struct evp_pkey_st;
struct env_md_st;
struct env_md_ctx_st;
struct evp_cipher_st;
struct evp_cipher_ctx_st;
struct ec_method_st;
struct ecdsa_method;
struct dh_method;
struct CMAC_CTX_st;
struct hmac_ctx_st;

unsigned long FIPS_module_version(void);
const char *FIPS_module_version_text(void);

int FIPS_module_mode_set(int onoff, const char *auth);
int FIPS_module_mode(void);
const void *FIPS_rand_check(void);
int FIPS_selftest(void);
int FIPS_selftest_failed(void);
void FIPS_selftest_check(void);
int FIPS_selftest_sha1(void);
int FIPS_selftest_aes_ccm(void);
int FIPS_selftest_aes_gcm(void);
int FIPS_selftest_aes_xts(void);
int FIPS_selftest_aes(void);
int FIPS_selftest_des(void);
int FIPS_selftest_rsa(void);
int FIPS_selftest_dsa(void);
int FIPS_selftest_ecdsa(void);
int FIPS_selftest_ecdh(void);
void FIPS_x931_stick(int onoff);
void FIPS_drbg_stick(int onoff);
int FIPS_selftest_x931(void);
int FIPS_selftest_hmac(void);
int FIPS_selftest_drbg(void);
int FIPS_selftest_drbg_all(void);
int FIPS_selftest_cmac(void);

unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len);
int FIPS_check_incore_fingerprint(void);

void fips_set_selftest_fail(void);
int fips_check_rsa(struct rsa_st *rsa);
int fips_check_rsa_prng(struct rsa_st *rsa, int bits);
int fips_check_dsa_prng(struct dsa_st *dsa, size_t L, size_t N);
int fips_check_ec_prng(struct ec_key_st *ec);

void FIPS_set_locking_callbacks(void (*func)(int mode, int type,
				const char *file,int line),
				int (*add_cb)(int *pointer, int amount,
					int type, const char *file, int line));

void FIPS_set_error_callbacks(
	void (*put_cb)(int lib, int func,int reason,const char *file,int line),
	void (*add_cb)(int num, va_list args) );

void FIPS_set_malloc_callbacks(
		void *(*malloc_cb)(int num, const char *file, int line),
		void (*free_cb)(void *));

void FIPS_get_timevec(unsigned char *buf, unsigned long *pctr);

/* POST callback operation value: */
/* All tests started */
#define	FIPS_POST_BEGIN		1
/* All tests end: result in id */
#define	FIPS_POST_END		2
/* One individual test started */
#define	FIPS_POST_STARTED	3
/* Individual test success */
#define	FIPS_POST_SUCCESS	4
/* Individual test failure */
#define	FIPS_POST_FAIL		5
/* Induce failure in test if zero return */
#define FIPS_POST_CORRUPT	6

/* Test IDs */
/* HMAC integrity test */
#define FIPS_TEST_INTEGRITY	1
/* Digest test */
#define FIPS_TEST_DIGEST	2
/* Symmetric cipher test */
#define FIPS_TEST_CIPHER	3
/* Public key signature test */
#define FIPS_TEST_SIGNATURE	4
/* HMAC test */
#define FIPS_TEST_HMAC		5
/* CMAC test */
#define FIPS_TEST_CMAC		6
/* GCM test */
#define FIPS_TEST_GCM		7
/* CCM test */
#define FIPS_TEST_CCM		8
/* XTS test */
#define FIPS_TEST_XTS		9
/* X9.31 PRNG */
#define FIPS_TEST_X931		10
/* DRNB */
#define FIPS_TEST_DRBG		11
/* Keygen pairwise consistency test */
#define FIPS_TEST_PAIRWISE	12
/* Continuous PRNG test */
#define FIPS_TEST_CONTINUOUS	13
/* ECDH test */
#define FIPS_TEST_ECDH		14

/* Minimum authorisation string length */
#define FIPS_AUTH_MIN_LEN	16

void FIPS_post_set_callback(
	int (*post_cb)(int op, int id, int subid, void *ex));

#define FIPS_ERROR_IGNORED(alg) OpenSSLDie(__FILE__, __LINE__, \
		alg " previous FIPS forbidden algorithm error ignored");

int fips_pkey_signature_test(int id, struct evp_pkey_st *pkey,
			const unsigned char *tbs, size_t tbslen,
			const unsigned char *kat, size_t katlen,
			const struct env_md_st *digest, int pad_mode,
			const char *fail_str);

int fips_cipher_test(int id, struct evp_cipher_ctx_st *ctx,
			const struct evp_cipher_st *cipher,
			const unsigned char *key,
			const unsigned char *iv,
			const unsigned char *plaintext,
			const unsigned char *ciphertext,
			int len);

const struct env_md_st *FIPS_get_digestbynid(int nid);

const struct evp_cipher_st *FIPS_get_cipherbynid(int nid);

struct rsa_st *FIPS_rsa_new(void);
void FIPS_rsa_free(struct rsa_st *r);
int FIPS_rsa_sign_ctx(struct rsa_st *rsa, struct env_md_ctx_st *ctx,
			int rsa_pad_mode, int saltlen,
			const struct env_md_st *mgf1Hash,
			unsigned char *sigret, unsigned int *siglen);
int FIPS_rsa_sign_digest(struct rsa_st *rsa,
			const unsigned char *md, int md_len,
			const struct env_md_st *mhash,
			int rsa_pad_mode, int saltlen,
			const struct env_md_st *mgf1Hash,
			unsigned char *sigret, unsigned int *siglen);
int FIPS_rsa_verify_ctx(struct rsa_st *rsa, struct env_md_ctx_st *ctx,
			int rsa_pad_mode, int saltlen,
			const struct env_md_st *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen);
int FIPS_rsa_verify_digest(struct rsa_st *rsa,
			const unsigned char *dig, int diglen,
			const struct env_md_st *mhash,
			int rsa_pad_mode, int saltlen,
			const struct env_md_st *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen);

int FIPS_rsa_sign(struct rsa_st *rsa, const unsigned char *msg, int msglen,
			const struct env_md_st *mhash, int rsa_pad_mode,
			int saltlen, const struct env_md_st *mgf1Hash,
			unsigned char *sigret, unsigned int *siglen);

int FIPS_rsa_verify(struct rsa_st *rsa, const unsigned char *msg, int msglen,
			const struct env_md_st *mhash, int rsa_pad_mode,
			int saltlen, const struct env_md_st *mgf1Hash,
			const unsigned char *sigbuf, unsigned int siglen);

#ifdef OPENSSL_FIPSCAPABLE

int FIPS_digestinit(EVP_MD_CTX *ctx, const EVP_MD *type);
int FIPS_digestupdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int FIPS_digestfinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size);
int FIPS_md_ctx_cleanup(EVP_MD_CTX *ctx);

int FIPS_cipherinit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
	     const unsigned char *key, const unsigned char *iv, int enc);
int FIPS_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			const unsigned char *in, unsigned int inl);
int FIPS_cipher_ctx_cleanup(EVP_CIPHER_CTX *c);

const EVP_CIPHER *FIPS_evp_aes_128_cbc(void);
const EVP_CIPHER *FIPS_evp_aes_128_ccm(void);
const EVP_CIPHER *FIPS_evp_aes_128_cfb1(void);
const EVP_CIPHER *FIPS_evp_aes_128_cfb128(void);
const EVP_CIPHER *FIPS_evp_aes_128_cfb8(void);
const EVP_CIPHER *FIPS_evp_aes_128_ctr(void);
const EVP_CIPHER *FIPS_evp_aes_128_ecb(void);
const EVP_CIPHER *FIPS_evp_aes_128_gcm(void);
const EVP_CIPHER *FIPS_evp_aes_128_ofb(void);
const EVP_CIPHER *FIPS_evp_aes_128_xts(void);
const EVP_CIPHER *FIPS_evp_aes_192_cbc(void);
const EVP_CIPHER *FIPS_evp_aes_192_ccm(void);
const EVP_CIPHER *FIPS_evp_aes_192_cfb1(void);
const EVP_CIPHER *FIPS_evp_aes_192_cfb128(void);
const EVP_CIPHER *FIPS_evp_aes_192_cfb8(void);
const EVP_CIPHER *FIPS_evp_aes_192_ctr(void);
const EVP_CIPHER *FIPS_evp_aes_192_ecb(void);
const EVP_CIPHER *FIPS_evp_aes_192_gcm(void);
const EVP_CIPHER *FIPS_evp_aes_192_ofb(void);
const EVP_CIPHER *FIPS_evp_aes_256_cbc(void);
const EVP_CIPHER *FIPS_evp_aes_256_ccm(void);
const EVP_CIPHER *FIPS_evp_aes_256_cfb1(void);
const EVP_CIPHER *FIPS_evp_aes_256_cfb128(void);
const EVP_CIPHER *FIPS_evp_aes_256_cfb8(void);
const EVP_CIPHER *FIPS_evp_aes_256_ctr(void);
const EVP_CIPHER *FIPS_evp_aes_256_ecb(void);
const EVP_CIPHER *FIPS_evp_aes_256_gcm(void);
const EVP_CIPHER *FIPS_evp_aes_256_ofb(void);
const EVP_CIPHER *FIPS_evp_aes_256_xts(void);
const EVP_CIPHER *FIPS_evp_des_ede(void);
const EVP_CIPHER *FIPS_evp_des_ede3(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cbc(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cfb1(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cfb64(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cfb8(void);
const EVP_CIPHER *FIPS_evp_des_ede3_ecb(void);
const EVP_CIPHER *FIPS_evp_des_ede3_ofb(void);
const EVP_CIPHER *FIPS_evp_des_ede_cbc(void);
const EVP_CIPHER *FIPS_evp_des_ede_cfb64(void);
const EVP_CIPHER *FIPS_evp_des_ede_ecb(void);
const EVP_CIPHER *FIPS_evp_des_ede_ofb(void);
const EVP_CIPHER *FIPS_evp_enc_null(void);
const EVP_MD *FIPS_evp_sha1(void);
const EVP_MD *FIPS_evp_sha224(void);
const EVP_MD *FIPS_evp_sha256(void);
const EVP_MD *FIPS_evp_sha384(void);
const EVP_MD *FIPS_evp_sha512(void);
const EVP_MD *FIPS_evp_dss1(void);
const EVP_MD *FIPS_evp_dss(void);
const EVP_MD *FIPS_evp_ecdsa(void);

const RSA_METHOD *FIPS_rsa_pkcs1_ssleay(void);
int FIPS_rsa_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

const struct dsa_method *FIPS_dsa_openssl(void);
int	FIPS_dsa_generate_key(DSA *dsa);
int	FIPS_dsa_generate_parameters_ex(DSA *dsa, int bits,
		const unsigned char *seed,int seed_len,
		int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);

int fips_dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);

const struct ec_method_st *fips_ec_gf2m_simple_method(void);
const struct ec_method_st *fips_ec_gfp_simple_method(void);
const struct ec_method_st *fips_ec_gfp_mont_method(void);
const struct ec_method_st *fips_ec_gfp_nist_method(void);

const struct ecdsa_method *FIPS_ecdsa_openssl(void);
const struct ecdh_method *FIPS_ecdh_openssl(void);

int FIPS_ec_key_generate_key(struct ec_key_st *key);

const struct dh_method *FIPS_dh_openssl(void);
int FIPS_dh_generate_parameters_ex(DH *dh, int prime_len,
						int generator, BN_GENCB *cb);

int FIPS_cmac_init(struct CMAC_CTX_st *ctx, const void *key, size_t keylen, 
			const EVP_CIPHER *cipher, ENGINE *impl);
int FIPS_cmac_update(struct CMAC_CTX_st *ctx, const void *in, size_t dlen);
int FIPS_cmac_final(struct CMAC_CTX_st *ctx, unsigned char *out,
							size_t *poutlen);
void FIPS_cmac_ctx_cleanup(struct CMAC_CTX_st *ctx);

void FIPS_hmac_ctx_cleanup(struct hmac_ctx_st *ctx);
int FIPS_hmac_init_ex(struct hmac_ctx_st *ctx, const void *key, int len,
		  const EVP_MD *md, ENGINE *impl);
int FIPS_hmac_update(struct hmac_ctx_st *ctx,
			const unsigned char *data, size_t len);
int FIPS_hmac_final(struct hmac_ctx_st *ctx,
			unsigned char *md, unsigned int *len);

#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_FIPS_strings(void);

/* Error codes for the FIPS functions. */

/* Function codes. */
#define FIPS_F_DH_BUILTIN_GENPARAMS			 100
#define FIPS_F_DH_INIT					 148
#define FIPS_F_DRBG_RESEED				 162
#define FIPS_F_DSA_BUILTIN_PARAMGEN			 101
#define FIPS_F_DSA_BUILTIN_PARAMGEN2			 102
#define FIPS_F_DSA_DO_SIGN				 103
#define FIPS_F_DSA_DO_VERIFY				 104
#define FIPS_F_ECDH_COMPUTE_KEY				 163
#define FIPS_F_ECDSA_DO_SIGN				 164
#define FIPS_F_ECDSA_DO_VERIFY				 165
#define FIPS_F_EC_KEY_GENERATE_KEY			 166
#define FIPS_F_FIPS_CHECK_DSA				 105
#define FIPS_F_FIPS_CHECK_DSA_PRNG			 151
#define FIPS_F_FIPS_CHECK_EC				 106
#define FIPS_F_FIPS_CHECK_EC_PRNG			 152
#define FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT		 107
#define FIPS_F_FIPS_CHECK_RSA				 108
#define FIPS_F_FIPS_CHECK_RSA_PRNG			 150
#define FIPS_F_FIPS_CIPHER				 160
#define FIPS_F_FIPS_CIPHERINIT				 109
#define FIPS_F_FIPS_CIPHER_CTX_CTRL			 161
#define FIPS_F_FIPS_DIGESTFINAL				 158
#define FIPS_F_FIPS_DIGESTINIT				 110
#define FIPS_F_FIPS_DIGESTUPDATE			 159
#define FIPS_F_FIPS_DRBG_BYTES				 111
#define FIPS_F_FIPS_DRBG_CHECK				 146
#define FIPS_F_FIPS_DRBG_CPRNG_TEST			 112
#define FIPS_F_FIPS_DRBG_ERROR_CHECK			 114
#define FIPS_F_FIPS_DRBG_GENERATE			 113
#define FIPS_F_FIPS_DRBG_INIT				 115
#define FIPS_F_FIPS_DRBG_INSTANTIATE			 116
#define FIPS_F_FIPS_DRBG_NEW				 117
#define FIPS_F_FIPS_DRBG_RESEED				 118
#define FIPS_F_FIPS_DRBG_SINGLE_KAT			 119
#define FIPS_F_FIPS_DSA_SIGN_DIGEST			 154
#define FIPS_F_FIPS_DSA_VERIFY_DIGEST			 155
#define FIPS_F_FIPS_GET_ENTROPY				 147
#define FIPS_F_FIPS_MODULE_MODE_SET			 120
#define FIPS_F_FIPS_PKEY_SIGNATURE_TEST			 121
#define FIPS_F_FIPS_RAND_ADD				 122
#define FIPS_F_FIPS_RAND_BYTES				 123
#define FIPS_F_FIPS_RAND_PSEUDO_BYTES			 124
#define FIPS_F_FIPS_RAND_SEED				 125
#define FIPS_F_FIPS_RAND_SET_METHOD			 126
#define FIPS_F_FIPS_RAND_STATUS				 127
#define FIPS_F_FIPS_RSA_SIGN_DIGEST			 156
#define FIPS_F_FIPS_RSA_VERIFY_DIGEST			 157
#define FIPS_F_FIPS_SELFTEST_AES			 128
#define FIPS_F_FIPS_SELFTEST_AES_CCM			 145
#define FIPS_F_FIPS_SELFTEST_AES_GCM			 129
#define FIPS_F_FIPS_SELFTEST_AES_XTS			 144
#define FIPS_F_FIPS_SELFTEST_CMAC			 130
#define FIPS_F_FIPS_SELFTEST_DES			 131
#define FIPS_F_FIPS_SELFTEST_DSA			 132
#define FIPS_F_FIPS_SELFTEST_ECDSA			 133
#define FIPS_F_FIPS_SELFTEST_HMAC			 134
#define FIPS_F_FIPS_SELFTEST_SHA1			 135
#define FIPS_F_FIPS_SELFTEST_X931			 136
#define FIPS_F_FIPS_SET_PRNG_KEY			 153
#define FIPS_F_HASH_FINAL				 137
#define FIPS_F_RSA_BUILTIN_KEYGEN			 138
#define FIPS_F_RSA_EAY_INIT				 149
#define FIPS_F_RSA_EAY_PRIVATE_DECRYPT			 139
#define FIPS_F_RSA_EAY_PRIVATE_ENCRYPT			 140
#define FIPS_F_RSA_EAY_PUBLIC_DECRYPT			 141
#define FIPS_F_RSA_EAY_PUBLIC_ENCRYPT			 142
#define FIPS_F_RSA_X931_GENERATE_KEY_EX			 143

/* Reason codes. */
#define FIPS_R_ADDITIONAL_INPUT_ERROR_UNDETECTED	 150
#define FIPS_R_ADDITIONAL_INPUT_TOO_LONG		 100
#define FIPS_R_ALREADY_INSTANTIATED			 101
#define FIPS_R_AUTHENTICATION_FAILURE			 151
#define FIPS_R_CONTRADICTING_EVIDENCE			 102
#define FIPS_R_DRBG_NOT_INITIALISED			 152
#define FIPS_R_DRBG_STUCK				 103
#define FIPS_R_ENTROPY_ERROR_UNDETECTED			 104
#define FIPS_R_ENTROPY_NOT_REQUESTED_FOR_RESEED		 105
#define FIPS_R_ENTROPY_SOURCE_STUCK			 142
#define FIPS_R_ERROR_INITIALISING_DRBG			 106
#define FIPS_R_ERROR_INSTANTIATING_DRBG			 107
#define FIPS_R_ERROR_RETRIEVING_ADDITIONAL_INPUT	 108
#define FIPS_R_ERROR_RETRIEVING_ENTROPY			 109
#define FIPS_R_ERROR_RETRIEVING_NONCE			 110
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH		 111
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH_NONPIC_RELOCATED 112
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH_SEGMENT_ALIASING 113
#define FIPS_R_FIPS_MODE_ALREADY_SET			 114
#define FIPS_R_FIPS_SELFTEST_FAILED			 115
#define FIPS_R_FUNCTION_ERROR				 116
#define FIPS_R_GENERATE_ERROR				 117
#define FIPS_R_GENERATE_ERROR_UNDETECTED		 118
#define FIPS_R_INSTANTIATE_ERROR			 119
#define FIPS_R_INSUFFICIENT_SECURITY_STRENGTH		 120
#define FIPS_R_INTERNAL_ERROR				 121
#define FIPS_R_INVALID_KEY_LENGTH			 122
#define FIPS_R_INVALID_PARAMETERS			 144
#define FIPS_R_IN_ERROR_STATE				 123
#define FIPS_R_KEY_TOO_SHORT				 124
#define FIPS_R_NONCE_ERROR_UNDETECTED			 149
#define FIPS_R_NON_FIPS_METHOD				 125
#define FIPS_R_NOPR_TEST1_FAILURE			 145
#define FIPS_R_NOPR_TEST2_FAILURE			 146
#define FIPS_R_NOT_INSTANTIATED				 126
#define FIPS_R_PAIRWISE_TEST_FAILED			 127
#define FIPS_R_PERSONALISATION_ERROR_UNDETECTED		 128
#define FIPS_R_PERSONALISATION_STRING_TOO_LONG		 129
#define FIPS_R_PRNG_STRENGTH_TOO_LOW			 143
#define FIPS_R_PR_TEST1_FAILURE				 147
#define FIPS_R_PR_TEST2_FAILURE				 148
#define FIPS_R_REQUEST_LENGTH_ERROR_UNDETECTED		 130
#define FIPS_R_REQUEST_TOO_LARGE_FOR_DRBG		 131
#define FIPS_R_RESEED_COUNTER_ERROR			 132
#define FIPS_R_RESEED_ERROR				 133
#define FIPS_R_SELFTEST_FAILED				 134
#define FIPS_R_SELFTEST_FAILURE				 135
#define FIPS_R_STRENGTH_ERROR_UNDETECTED		 136
#define FIPS_R_TEST_FAILURE				 137
#define FIPS_R_UNINSTANTIATE_ERROR			 141
#define FIPS_R_UNINSTANTIATE_ZEROISE_ERROR		 138
#define FIPS_R_UNSUPPORTED_DRBG_TYPE			 139
#define FIPS_R_UNSUPPORTED_PLATFORM			 140

#ifdef  __cplusplus
}
#endif
#endif
