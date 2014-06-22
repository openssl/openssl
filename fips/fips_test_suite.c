/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 *
 * This command is intended as a test driver for the FIPS-140 testing
 * lab performing FIPS-140 validation.  It demonstrates the use of the
 * OpenSSL library ito perform a variety of common cryptographic
 * functions.  A power-up self test is demonstrated by deliberately
 * pointing to an invalid executable hash
 *
 * Contributed by Steve Marquess.
 *
 */

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

#ifndef OPENSSL_FIPS
int main(int argc, char *argv[])
    {
    printf("No FIPS support\n");
    return(0);
    }
#else

#define ERR_clear_error() while(0)

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include "fips_utl.h"

/* AES: encrypt and decrypt known plaintext, verify result matches original plaintext
*/
static int FIPS_aes_test(void)
	{
	int ret = 0;
	unsigned char pltmp[16];
	unsigned char citmp[16];
	unsigned char key[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	unsigned char plaintext[16] = "etaonrishdlcu";
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	if (FIPS_cipherinit(&ctx, EVP_aes_128_ecb(), key, NULL, 1) <= 0)
		goto err;
	FIPS_cipher(&ctx, citmp, plaintext, 16);
	if (FIPS_cipherinit(&ctx, EVP_aes_128_ecb(), key, NULL, 0) <= 0)
		goto err;
	FIPS_cipher(&ctx, pltmp, citmp, 16);
	if (memcmp(pltmp, plaintext, 16))
		goto err;
	ret = 1;
	err:
	FIPS_cipher_ctx_cleanup(&ctx);
	return ret;
	}

static int FIPS_aes_gcm_test(void)
	{
	int ret = 0;
	unsigned char pltmp[16];
	unsigned char citmp[16];
	unsigned char tagtmp[16];
	unsigned char key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	unsigned char iv[16] = {21,22,23,24,25,26,27,28,29,30,31,32};
	unsigned char aad[] = "Some text AAD";
	unsigned char plaintext[16] = "etaonrishdlcu";
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	if (FIPS_cipherinit(&ctx, EVP_aes_128_gcm(), key, iv, 1) <= 0)
		goto err;
	FIPS_cipher(&ctx, NULL, aad, sizeof(aad));
	FIPS_cipher(&ctx, citmp, plaintext, 16);
	FIPS_cipher(&ctx, NULL, NULL, 0);
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, 16, tagtmp))
		goto err;

	if (FIPS_cipherinit(&ctx, EVP_aes_128_gcm(), key, iv, 0) <= 0)
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16, tagtmp))
		goto err;

	FIPS_cipher(&ctx, NULL, aad, sizeof(aad));

	FIPS_cipher(&ctx, pltmp, citmp, 16);

	if (FIPS_cipher(&ctx, NULL, NULL, 0) < 0)
		goto err;

	if (memcmp(pltmp, plaintext, 16))
		goto err;

	ret = 1;
	err:
	FIPS_cipher_ctx_cleanup(&ctx);
	return ret;
	}

static int FIPS_des3_test(void)
	{
	int ret = 0;
	unsigned char pltmp[8];
	unsigned char citmp[8];
    	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
		              19,20,21,22,23,24};
    	unsigned char plaintext[] = { 'e', 't', 'a', 'o', 'n', 'r', 'i', 's' };
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	if (FIPS_cipherinit(&ctx, EVP_des_ede3_ecb(), key, NULL, 1) <= 0)
		goto err;
	FIPS_cipher(&ctx, citmp, plaintext, 8);
	if (FIPS_cipherinit(&ctx, EVP_des_ede3_ecb(), key, NULL, 0) <= 0)
		goto err;
	FIPS_cipher(&ctx, pltmp, citmp, 8);
	if (memcmp(pltmp, plaintext, 8))
		goto err;
	ret = 1;
	err:
	FIPS_cipher_ctx_cleanup(&ctx);
	return ret;
	}

/*
 * DSA: generate keys and sign, verify input plaintext.
 */
static int FIPS_dsa_test(int bad)
    {
    DSA *dsa = NULL;
    unsigned char dgst[] = "etaonrishdlc";
    int r = 0;
    DSA_SIG *sig = NULL;

    ERR_clear_error();
    dsa = FIPS_dsa_new();
    if (!dsa)
	goto end;
    if (!DSA_generate_parameters_ex(dsa, 1024,NULL,0,NULL,NULL,NULL))
	goto end;
    if (!DSA_generate_key(dsa))
	goto end;
    if (bad)
	    BN_add_word(dsa->pub_key, 1);

    sig = FIPS_dsa_sign(dsa, dgst, sizeof(dgst) -1, EVP_sha256());
    if (!sig)
	goto end;

    r = FIPS_dsa_verify(dsa, dgst, sizeof(dgst) -1, EVP_sha256(), sig);
    end:
    if (sig)
	FIPS_dsa_sig_free(sig);
    if (dsa)
  	  FIPS_dsa_free(dsa);
    if (r != 1)
	return 0;
    return 1;
    }

/*
 * RSA: generate keys and sign, verify input plaintext.
 */
static int FIPS_rsa_test(int bad)
    {
    RSA *key;
    unsigned char input_ptext[] = "etaonrishdlc";
    unsigned char buf[256];
    unsigned int slen;
    BIGNUM *bn;
    int r = 0;

    ERR_clear_error();
    key = FIPS_rsa_new();
    bn = BN_new();
    if (!key || !bn)
	return 0;
    BN_set_word(bn, 65537);
    if (!RSA_generate_key_ex(key, 2048,bn,NULL))
	return 0;
    BN_free(bn);
    if (bad)
	    BN_add_word(key->n, 1);

    if (!FIPS_rsa_sign(key, input_ptext, sizeof(input_ptext) - 1, EVP_sha256(),
			RSA_PKCS1_PADDING, 0, NULL, buf, &slen))
	goto end;

    r = FIPS_rsa_verify(key, input_ptext, sizeof(input_ptext) - 1, EVP_sha256(),
			RSA_PKCS1_PADDING, 0, NULL, buf, slen);
    end:
    if (key)
  	  FIPS_rsa_free(key);
    if (r != 1)
	return 0;
    return 1;
    }

/* SHA1: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha1_test()
    {
    unsigned char digest[SHA_DIGEST_LENGTH] =
        { 0x11, 0xf1, 0x9a, 0x3a, 0xec, 0x1a, 0x1e, 0x8e, 0x65, 0xd4, 0x9a, 0x38, 0x0c, 0x8b, 0x1e, 0x2c, 0xe8, 0xb3, 0xc5, 0x18 };
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA_DIGEST_LENGTH];

    ERR_clear_error();
    if (!FIPS_digest(str,sizeof(str) - 1,md, NULL, EVP_sha1())) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* SHA256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha256_test()
    {
    unsigned char digest[SHA256_DIGEST_LENGTH] =
	{0xf5, 0x53, 0xcd, 0xb8, 0xcf, 0x1, 0xee, 0x17, 0x9b, 0x93, 0xc9, 0x68, 0xc0, 0xea, 0x40, 0x91,
	 0x6, 0xec, 0x8e, 0x11, 0x96, 0xc8, 0x5d, 0x1c, 0xaf, 0x64, 0x22, 0xe6, 0x50, 0x4f, 0x47, 0x57};
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA256_DIGEST_LENGTH];

    ERR_clear_error();
    if (!FIPS_digest(str,sizeof(str) - 1,md, NULL, EVP_sha256())) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* SHA512: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha512_test()
    {
    unsigned char digest[SHA512_DIGEST_LENGTH] =
	{0x99, 0xc9, 0xe9, 0x5b, 0x88, 0xd4, 0x78, 0x88, 0xdf, 0x88, 0x5f, 0x94, 0x71, 0x64, 0x28, 0xca,
	 0x16, 0x1f, 0x3d, 0xf4, 0x1f, 0xf3, 0x0f, 0xc5, 0x03, 0x99, 0xb2, 0xd0, 0xe7, 0x0b, 0x94, 0x4a,
	 0x45, 0xd2, 0x6c, 0x4f, 0x20, 0x06, 0xef, 0x71, 0xa9, 0x25, 0x7f, 0x24, 0xb1, 0xd9, 0x40, 0x22,
	 0x49, 0x54, 0x10, 0xc2, 0x22, 0x9d, 0x27, 0xfe, 0xbd, 0xd6, 0xd6, 0xeb, 0x2d, 0x42, 0x1d, 0xa3};
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA512_DIGEST_LENGTH];

    ERR_clear_error();
    if (!FIPS_digest(str,sizeof(str) - 1,md, NULL, EVP_sha512())) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* HMAC-SHA1: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha1_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0x73, 0xf7, 0xa0, 0x48, 0xf8, 0x94, 0xed, 0xdd, 0x0a, 0xea, 0xea, 0x56, 0x1b, 0x61, 0x2e, 0x70,
	 0xb2, 0xfb, 0xec, 0xc6};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha1(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA224: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha224_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0x75, 0x58, 0xd5, 0xbd, 0x55, 0x6d, 0x87, 0x0f, 0x75, 0xff, 0xbe, 0x1c, 0xb2, 0xf0, 0x20, 0x35,
	 0xe5, 0x62, 0x49, 0xb6, 0x94, 0xb9, 0xfc, 0x65, 0x34, 0x33, 0x3a, 0x19};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha224(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha256_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xe9, 0x17, 0xc1, 0x7b, 0x4c, 0x6b, 0x77, 0xda, 0xd2, 0x30, 0x36, 0x02, 0xf5, 0x72, 0x33, 0x87,
	 0x9f, 0xc6, 0x6e, 0x7b, 0x7e, 0xa8, 0xea, 0xaa, 0x9f, 0xba, 0xee, 0x51, 0xff, 0xda, 0x24, 0xf4};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha256(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA384: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha384_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xb2, 0x9d, 0x40, 0x58, 0x32, 0xc4, 0xe3, 0x31, 0xb6, 0x63, 0x08, 0x26, 0x99, 0xef, 0x3b, 0x10,
	 0xe2, 0xdf, 0xf8, 0xff, 0xc6, 0xe1, 0x03, 0x29, 0x81, 0x2a, 0x1b, 0xac, 0xb0, 0x07, 0x39, 0x08,
	 0xf3, 0x91, 0x35, 0x11, 0x76, 0xd6, 0x4c, 0x20, 0xfb, 0x4d, 0xc3, 0xf3, 0xb8, 0x9b, 0x88, 0x1c};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha384(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA512: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha512_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xcd, 0x3e, 0xb9, 0x51, 0xb8, 0xbc, 0x7f, 0x9a, 0x23, 0xaf, 0xf3, 0x77, 0x59, 0x85, 0xa9, 0xe6,
	 0xf7, 0xd1, 0x51, 0x96, 0x17, 0xe0, 0x92, 0xd8, 0xa6, 0x3b, 0xc1, 0xad, 0x7e, 0x24, 0xca, 0xb1,
	 0xd7, 0x79, 0x0a, 0xa5, 0xea, 0x2c, 0x02, 0x58, 0x0b, 0xa6, 0x52, 0x6b, 0x61, 0x7f, 0xeb, 0x9c,
	 0x47, 0x86, 0x5d, 0x74, 0x2b, 0x88, 0xdf, 0xee, 0x46, 0x69, 0x96, 0x3d, 0xa6, 0xd9, 0x2a, 0x53};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha512(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* CMAC-AES128: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_aes128_test()
    {
    unsigned char key[16] = { 0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
			      0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	    { 0x16,0x83,0xfe,0xac, 0x52,0x9b,0xae,0x23,
	      0xd7,0xd5,0x66,0xf5, 0xd2,0x8d,0xbd,0x2a, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_aes_128_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-AES128: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }

/* CMAC-AES192: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_aes192_test()
    {
    unsigned char key[] = { 0x8e,0x73,0xb0,0xf7, 0xda,0x0e,0x64,0x52,
			    0xc8,0x10,0xf3,0x2b, 0x80,0x90,0x79,0xe5,
			    0x62,0xf8,0xea,0xd2, 0x52,0x2c,0x6b,0x7b, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[] =
	    { 0xd6,0x99,0x19,0x25, 0xe5,0x1d,0x95,0x48,
	      0xb1,0x4a,0x0b,0xf2, 0xc6,0x3c,0x47,0x1f, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_aes_192_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-AES192: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }

/* CMAC-AES256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_aes256_test()
    {
    unsigned char key[] = { 0x60,0x3d,0xeb,0x10, 0x15,0xca,0x71,0xbe,
			    0x2b,0x73,0xae,0xf0, 0x85,0x7d,0x77,0x81,
			    0x1f,0x35,0x2c,0x07, 0x3b,0x61,0x08,0xd7,
			    0x2d,0x98,0x10,0xa3, 0x09,0x14,0xdf,0xf4, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[] =
	    { 0xec,0xc2,0xcf,0x63, 0xc7,0xce,0xfc,0xa4,
	      0xb0,0x86,0x37,0x5f, 0x15,0x60,0xba,0x1f, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_aes_256_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-AES256: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }

/* CMAC-TDEA3: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_tdea3_test()
    {
    unsigned char key[] = { 0x8a,0xa8,0x3b,0xf8, 0xcb,0xda,0x10,0x62,
			    0x0b,0xc1,0xbf,0x19, 0xfb,0xb6,0xcd,0x58,
			    0xbc,0x31,0x3d,0x4a, 0x37,0x1c,0xa8,0xb5, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	    { 0xb4,0x06,0x4e,0xbf, 0x59,0x89,0xba,0x68, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_des_ede3_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-TDEA3: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }


/* DH: generate shared parameters
*/
static int dh_test()
    {
    DH *dh;
    ERR_clear_error();
    dh = FIPS_dh_new();
    if (!dh)
	return 0;
    if (!DH_generate_parameters_ex(dh, 1024, 2, NULL))
	return 0;
    FIPS_dh_free(dh);
    return 1;
    }

/* Zeroize
*/
static int Zeroize()
    {
    RSA *key;
    BIGNUM *bn;
    unsigned char userkey[16] =
	{ 0x48, 0x50, 0xf0, 0xa3, 0x3a, 0xed, 0xd3, 0xaf, 0x6e, 0x47, 0x7f, 0x83, 0x02, 0xb1, 0x09, 0x68 };
    size_t i;
    int n;

    key = FIPS_rsa_new();
    bn = BN_new();
    if (!key || !bn)
	return 0;
    BN_set_word(bn, 65537);
    if (!RSA_generate_key_ex(key, 1024,bn,NULL))
	return 0;
    BN_free(bn);

    n = BN_num_bytes(key->d);
    printf(" Generated %d byte RSA private key\n", n);
    printf("\tBN key before overwriting:\n");
    do_bn_print(stdout, key->d);
    BN_rand(key->d,n*8,-1,0);
    printf("\tBN key after overwriting:\n");
    do_bn_print(stdout, key->d);

    printf("\tchar buffer key before overwriting: \n\t\t");
    for(i = 0; i < sizeof(userkey); i++) printf("%02x", userkey[i]);
        printf("\n");
    RAND_bytes(userkey, sizeof userkey);
    printf("\tchar buffer key after overwriting: \n\t\t");
    for(i = 0; i < sizeof(userkey); i++) printf("%02x", userkey[i]);
        printf("\n");

    FIPS_rsa_free(key);

    return 1;
    }

/* Dummy Entropy for DRBG tests. WARNING: THIS IS TOTALLY BOGUS
 * HAS ZERO SECURITY AND MUST NOT BE USED IN REAL APPLICATIONS.
 */

static unsigned char dummy_drbg_entropy[1024];

static size_t drbg_test_cb(DRBG_CTX *ctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	*pout = dummy_drbg_entropy;
	/* Round up to multiple of block size */
	return (min_len + 0xf) & ~0xf;
	}

/* Callback which returns 0 to indicate entropy source failure */
static size_t drbg_fail_cb(DRBG_CTX *ctx, unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
	{
	return 0;
	}

/* DRBG test: just generate lots of data and trigger health checks */

static int do_drbg_test(int type, int flags)
    {
    DRBG_CTX *dctx;
    int rv = 0;
    size_t i;
    unsigned char randout[1024];
    dctx = FIPS_drbg_new(type, flags);
    if (!dctx)
	return 0;
    FIPS_drbg_set_callbacks(dctx, drbg_test_cb, 0, 0x10, drbg_test_cb, 0);
    for (i = 0; i < sizeof(dummy_drbg_entropy); i++)
	{
	dummy_drbg_entropy[i] = i & 0xff;
	}
    if (!FIPS_drbg_instantiate(dctx, dummy_drbg_entropy, 10))
	goto err;
    FIPS_drbg_set_check_interval(dctx, 10);
    for (i = 0; i < 32; i++)
	{
	if (!FIPS_drbg_generate(dctx, randout, sizeof(randout), 0, NULL, 0))
		goto err;
	if (!FIPS_drbg_generate(dctx, randout, sizeof(randout), 0, dummy_drbg_entropy, 1))
		goto err;
	}
    rv = 1;
    err:
    FIPS_drbg_free(dctx);
    return rv;
    }

typedef struct
    {
    int type, flags;
    } DRBG_LIST;

static int do_drbg_all(void)
    {
    static DRBG_LIST drbg_types[] =
	{
		{NID_sha1, 0},
		{NID_sha224, 0},
		{NID_sha256, 0},
		{NID_sha384, 0},
		{NID_sha512, 0},
		{NID_hmacWithSHA1, 0},
		{NID_hmacWithSHA224, 0},
		{NID_hmacWithSHA256, 0},
		{NID_hmacWithSHA384, 0},
		{NID_hmacWithSHA512, 0},
		{NID_aes_128_ctr, 0},
		{NID_aes_192_ctr, 0},
		{NID_aes_256_ctr, 0},
		{NID_aes_128_ctr, DRBG_FLAG_CTR_USE_DF},
		{NID_aes_192_ctr, DRBG_FLAG_CTR_USE_DF},
		{NID_aes_256_ctr, DRBG_FLAG_CTR_USE_DF},
		{(NID_X9_62_prime256v1 << 16)|NID_sha1, 0},
		{(NID_X9_62_prime256v1 << 16)|NID_sha224, 0},
		{(NID_X9_62_prime256v1 << 16)|NID_sha256, 0},
		{(NID_X9_62_prime256v1 << 16)|NID_sha384, 0},
		{(NID_X9_62_prime256v1 << 16)|NID_sha512, 0},
		{(NID_secp384r1 << 16)|NID_sha224, 0},
		{(NID_secp384r1 << 16)|NID_sha256, 0},
		{(NID_secp384r1 << 16)|NID_sha384, 0},
		{(NID_secp384r1 << 16)|NID_sha512, 0},
		{(NID_secp521r1 << 16)|NID_sha256, 0},
		{(NID_secp521r1 << 16)|NID_sha384, 0},
		{(NID_secp521r1 << 16)|NID_sha512, 0},
		{0, 0}
	};
    DRBG_LIST *lst;
    int rv = 1;
    for (lst = drbg_types;; lst++)
	{
	if (lst->type == 0)
		break;
	if (!do_drbg_test(lst->type, lst->flags))
		rv = 0;
	}
    return rv;
    }

static int Error;
static const char * Fail(const char *msg)
    {
    Error++;
    return msg;
    }

static void test_msg(const char *msg, int result)
	{
	printf("%s...%s\n", msg, result ? "successful" : Fail("Failed!"));
	}

/* Table of IDs for POST translating between NIDs and names */

typedef struct
	{
	int id;
	const char *name;
	} POST_ID;

POST_ID id_list[] = {
	{NID_sha1, "SHA1"},
	{NID_sha224, "SHA224"},
	{NID_sha256, "SHA256"},
	{NID_sha384, "SHA384"},
	{NID_sha512, "SHA512"},
	{NID_hmacWithSHA1, "HMAC-SHA1"},
	{NID_hmacWithSHA224, "HMAC-SHA224"},
	{NID_hmacWithSHA256, "HMAC-SHA256"},
	{NID_hmacWithSHA384, "HMAC-SHA384"},
	{NID_hmacWithSHA512, "HMAC-SHA512"},
	{EVP_PKEY_RSA, "RSA"},
	{EVP_PKEY_DSA, "DSA"},
	{EVP_PKEY_EC, "ECDSA"},
	{NID_aes_128_cbc, "AES-128-CBC"},
	{NID_aes_192_cbc, "AES-192-CBC"},
	{NID_aes_256_cbc, "AES-256-CBC"},
	{NID_aes_128_ctr, "AES-128-CTR"},
	{NID_aes_192_ctr, "AES-192-CTR"},
	{NID_aes_256_ctr, "AES-256-CTR"},
	{NID_aes_128_ecb, "AES-128-ECB"},
	{NID_aes_128_xts, "AES-128-XTS"},
	{NID_aes_256_xts, "AES-256-XTS"},
	{NID_des_ede3_cbc, "DES-EDE3-CBC"},
	{NID_des_ede3_ecb, "DES-EDE3-ECB"},
	{NID_secp224r1, "P-224"},
	{NID_sect233r1, "B-233"},
	{NID_sect233k1, "K-233"},
	{NID_X9_62_prime256v1, "P-256"},
	{NID_secp384r1, "P-384"},
	{NID_secp521r1, "P-521"},
	{0, NULL}
};

static const char *lookup_id(int id)
	{
	POST_ID *n;
	static char out[40];
	for (n = id_list; n->name; n++)
		{
		if (n->id == id)
			return n->name;
		}
	sprintf(out, "ID=%d", id);
	return out;
	}

static int fail_id = -1;
static int fail_sub = -1;
static int fail_key = -1;

static int st_err, post_quiet = 0;

static int post_cb(int op, int id, int subid, void *ex)
	{
	const char *idstr, *exstr = "";
	char asctmp[20];
	int keytype = -1;
	int exp_fail = 0;
#ifdef FIPS_POST_TIME
	static struct timespec start, end, tstart, tend;
#endif
	switch(id)
		{
		case FIPS_TEST_INTEGRITY:
		idstr = "Integrity";
		break;

		case FIPS_TEST_DIGEST:
		idstr = "Digest";
		exstr = lookup_id(subid);
		break;

		case FIPS_TEST_CIPHER:
		exstr = lookup_id(subid);
		idstr = "Cipher";
		break;

		case FIPS_TEST_SIGNATURE:
		if (ex)
			{
			EVP_PKEY *pkey = ex;
			keytype = pkey->type;
			if (keytype == EVP_PKEY_EC)
				{
				const EC_GROUP *grp;
				int cnid;
				grp = EC_KEY_get0_group(pkey->pkey.ec);
				cnid = EC_GROUP_get_curve_name(grp);
				sprintf(asctmp, "ECDSA %s", lookup_id(cnid));
				exstr = asctmp;
				}
			else
				exstr = lookup_id(keytype);
			}
		idstr = "Signature";
		break;

		case FIPS_TEST_HMAC:
		exstr = lookup_id(subid);
		idstr = "HMAC";
		break;

		case FIPS_TEST_CMAC:
		idstr = "CMAC";
		exstr = lookup_id(subid);
		break;

		case FIPS_TEST_GCM:
		idstr = "GCM";
		break;

		case FIPS_TEST_XTS:
		idstr = "XTS";
		exstr = lookup_id(subid);
		break;

		case FIPS_TEST_CCM:
		idstr = "CCM";
		break;

		case FIPS_TEST_X931:
		idstr = "X9.31 PRNG";
		sprintf(asctmp, "keylen=%d", subid);
		exstr = asctmp;
		break;

		case FIPS_TEST_DRBG:
		idstr = "DRBG";
		if (*(int *)ex & DRBG_FLAG_CTR_USE_DF)
			{
			sprintf(asctmp, "%s DF", lookup_id(subid));
			exstr = asctmp;
			}
		else if (subid >> 16)
			{
			sprintf(asctmp, "%s %s",
					lookup_id(subid >> 16),
					lookup_id(subid & 0xFFFF));
			exstr = asctmp;
			}
		else
			exstr = lookup_id(subid);
		break;

		case FIPS_TEST_PAIRWISE:
		if (ex)
			{
			EVP_PKEY *pkey = ex;
			keytype = pkey->type;
			exstr = lookup_id(keytype);
			}
		idstr = "Pairwise Consistency";
		break;

		case FIPS_TEST_CONTINUOUS:
		idstr = "Continuous PRNG";
		break;

		case FIPS_TEST_ECDH:
		idstr = "ECDH";
		exstr = lookup_id(subid);
		break;

		default:
		idstr = "Unknown";
		break;

		}

	if (fail_id == id
		&& (fail_key == -1 || fail_key == keytype)
		&& (fail_sub == -1 || fail_sub == subid))
			exp_fail = 1;

	switch(op)
		{
		case FIPS_POST_BEGIN:
#ifdef FIPS_POST_TIME
		clock_getres(CLOCK_REALTIME, &tstart);
		printf("\tTimer resolution %ld s, %ld ns\n",
				(long)tstart.tv_sec, (long)tstart.tv_nsec);
		clock_gettime(CLOCK_REALTIME, &tstart);
#endif
		printf("\tPOST started\n");
		break;

		case FIPS_POST_END:
		printf("\tPOST %s\n", id ? "Success" : "Failed");
#ifdef FIPS_POST_TIME
		clock_gettime(CLOCK_REALTIME, &tend);
		printf("\t\tTook %f seconds\n",
			(double)((tend.tv_sec+tend.tv_nsec*1e-9)
                        - (tstart.tv_sec+tstart.tv_nsec*1e-9)));
#endif
		break;

		case FIPS_POST_STARTED:
		if (!post_quiet && !exp_fail)
			printf("\t\t%s %s test started\n", idstr, exstr);
#ifdef FIPS_POST_TIME
		clock_gettime(CLOCK_REALTIME, &start);
#endif
		break;

		case FIPS_POST_SUCCESS:
		if (exp_fail)
			{
			printf("\t\t%s %s test OK but should've failed\n",
								idstr, exstr);
			st_err++;
			}
		else if (!post_quiet)
			printf("\t\t%s %s test OK\n", idstr, exstr);
#ifdef FIPS_POST_TIME
		clock_gettime(CLOCK_REALTIME, &end);
		printf("\t\t\tTook %f seconds\n",
			(double)((end.tv_sec+end.tv_nsec*1e-9)
                        - (start.tv_sec+start.tv_nsec*1e-9)));
#endif
		break;

		case FIPS_POST_FAIL:
		if (exp_fail)
			{
			printf("\t\t%s %s test failed as expected\n",
							idstr, exstr);
			}
		else
			{
			printf("\t\t%s %s test Failed Incorrectly!!\n",
							idstr, exstr);
			st_err++;
			}
		break;

		case FIPS_POST_CORRUPT:
		if (exp_fail)
			{
			printf("\t\t%s %s test failure induced\n", idstr, exstr);
			return 0;
			}
		break;

		}
	return 1;
	}

/* Test POST induced failures */

typedef struct
	{
	const char *name;
	int id, subid, keyid;
	} fail_list;

static fail_list flist[] =
	{
	{"Integrity", FIPS_TEST_INTEGRITY, -1, -1},
	{"AES", FIPS_TEST_CIPHER, NID_aes_128_ecb, -1},
	{"DES3", FIPS_TEST_CIPHER, NID_des_ede3_ecb, -1},
	{"AES-GCM", FIPS_TEST_GCM, -1, -1},
	{"AES-CCM", FIPS_TEST_CCM, -1, -1},
	{"AES-XTS", FIPS_TEST_XTS, -1, -1},
	{"Digest", FIPS_TEST_DIGEST, -1, -1},
	{"HMAC", FIPS_TEST_HMAC, -1, -1},
	{"CMAC", FIPS_TEST_CMAC, -1, -1},
	{"DRBG", FIPS_TEST_DRBG, -1, -1},
	{"X9.31 PRNG", FIPS_TEST_X931, -1, -1},
	{"RSA", FIPS_TEST_SIGNATURE, -1, EVP_PKEY_RSA},
	{"DSA", FIPS_TEST_SIGNATURE, -1, EVP_PKEY_DSA},
	{"ECDSA", FIPS_TEST_SIGNATURE, -1, EVP_PKEY_EC},
	{"ECDH", FIPS_TEST_ECDH, -1, -1},
	{NULL, -1, -1, -1}
	};

static int do_fail_all(int fullpost, int fullerr)
	{
	fail_list *ftmp;
	int rv;
	size_t i;
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	DRBG_CTX *dctx = NULL, *defctx = NULL;
	EC_KEY *ec = NULL;
	BIGNUM *bn = NULL;
	unsigned char out[10];
	if (!fullpost)
		post_quiet = 1;
	if (!fullerr)
		no_err = 1;
	FIPS_module_mode_set(0, NULL);
	for (ftmp = flist; ftmp->name; ftmp++)
		{
		printf("    Testing induced failure of %s test\n", ftmp->name);
		fail_id = ftmp->id;
		fail_sub = ftmp->subid;
		fail_key = ftmp->keyid;
		rv = FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS);
		if (rv)
			{
			printf("\tFIPS mode incorrectly successful!!\n");
			st_err++;
			}
		}
	printf("    Testing induced failure of RSA keygen test\n");
	/* NB POST will succeed with a pairwise test failures as
	 * it is not used during POST.
	 */
	fail_id = FIPS_TEST_PAIRWISE;
	fail_key = EVP_PKEY_RSA;
	/* Now enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}

	rsa = FIPS_rsa_new();
	bn = BN_new();
 	if (!rsa || !bn)
		return 0;
	BN_set_word(bn, 65537);
	if (RSA_generate_key_ex(rsa, 2048,bn,NULL))
		{
		printf("\tRSA key generated OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tRSA key generation failed as expected.\n");

	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);

	printf("    Testing induced failure of DSA keygen test\n");
	fail_key = EVP_PKEY_DSA;
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}
	dsa = FIPS_dsa_new();
    	if (!dsa)
		return 0;
	if (!DSA_generate_parameters_ex(dsa, 1024,NULL,0,NULL,NULL,NULL))
		return 0;
    	if (DSA_generate_key(dsa))
		{
		printf("\tDSA key generated OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tDSA key generation failed as expected.\n");

	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}

	printf("    Testing induced failure of ECDSA keygen test\n");
	fail_key = EVP_PKEY_EC;

	ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ec)
		return 0;

    	if (EC_KEY_generate_key(ec))
		{
		printf("\tECDSA key generated OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tECDSA key generation failed as expected.\n");

	FIPS_ec_key_free(ec);
	ec = NULL;

	fail_id = -1;
	fail_sub = -1;
	fail_key = -1;
	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}
	/* Induce continuous PRNG failure for DRBG */
	printf("    Testing induced failure of DRBG CPRNG test\n");
	FIPS_drbg_stick(1);

	/* Initialise a DRBG context */
	dctx = FIPS_drbg_new(NID_sha1, 0);
	if (!dctx)
		return 0;
	for (i = 0; i < sizeof(dummy_drbg_entropy); i++)
		{
		dummy_drbg_entropy[i] = i & 0xff;
		}
	FIPS_drbg_set_callbacks(dctx, drbg_test_cb, 0, 0x10, drbg_test_cb, 0);
	if (!FIPS_drbg_instantiate(dctx, dummy_drbg_entropy, 10))
		{
		printf("\tDRBG instantiate error!!\n");
		st_err++;
		}
	if (FIPS_drbg_generate(dctx, out, sizeof(out), 0, NULL, 0))
		{
		printf("\tDRBG continuous PRNG OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tDRBG continuous PRNG failed as expected\n");
	FIPS_drbg_stick(0);

	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}

	FIPS_drbg_free(dctx);

	/* Induce continuous PRNG failure for DRBG entropy source*/
	printf("    Testing induced failure of DRBG entropy CPRNG test\n");

	/* Initialise a DRBG context */
	dctx = FIPS_drbg_new(NID_sha1, 0);
	if (!dctx)
		return 0;
	for (i = 0; i < sizeof(dummy_drbg_entropy); i++)
		{
		dummy_drbg_entropy[i] = i & 0xf;
		}
	FIPS_drbg_set_callbacks(dctx, drbg_test_cb, 0, 0x10, drbg_test_cb, 0);
	if (FIPS_drbg_instantiate(dctx, dummy_drbg_entropy, 10))
		{
		printf("\tDRBG continuous PRNG entropy OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tDRBG continuous PRNG entropy failed as expected\n");
	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}
	FIPS_drbg_free(dctx);

	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}

	printf("    Testing induced failure of X9.31 CPRNG test\n");
	FIPS_x931_stick(1);
	if (!FIPS_x931_set_key(dummy_drbg_entropy, 32))
		{
		printf("\tError initialiasing X9.31 PRNG\n");
		st_err++;
		}
	if (!FIPS_x931_seed(dummy_drbg_entropy + 32, 16))
		{
		printf("\tError seeding X9.31 PRNG\n");
		st_err++;
		}
	if (FIPS_x931_bytes(out, 10) > 0)
		{
		printf("\tX9.31 continuous PRNG failure OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tX9.31 continuous PRNG failed as expected\n");
	FIPS_x931_stick(0);

	/* Leave FIPS mode to clear error */
	FIPS_module_mode_set(0, NULL);
	/* Enter FIPS mode successfully */
	if (!FIPS_module_mode_set(1, FIPS_AUTH_USER_PASS))
		{
		printf("\tError entering FIPS mode\n");
		st_err++;
		}

	printf("    Testing operation failure with DRBG entropy failure\n");

	/* Generate DSA key for later use */
    	if (DSA_generate_key(dsa))
		printf("\tDSA key generated OK as expected.\n");
	else
		{
		printf("\tDSA key generation FAILED!!\n");
		st_err++;
		}

	/* Initialise default DRBG context */
	defctx = FIPS_get_default_drbg();
	if (!defctx)
		return 0;
	if (!FIPS_drbg_init(defctx, NID_sha512, 0))
		return 0;
	/* Set entropy failure callback */
	FIPS_drbg_set_callbacks(defctx, drbg_fail_cb, 0, 0x10, drbg_test_cb, 0);
	if (FIPS_drbg_instantiate(defctx, dummy_drbg_entropy, 10))
		{
		printf("\tDRBG entropy fail OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tDRBG entropy fail failed as expected\n");

	if (FIPS_dsa_sign(dsa, dummy_drbg_entropy, 5, EVP_sha256()))
		{
		printf("\tDSA signing OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tDSA signing failed as expected\n");

	ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ec)
		return 0;

    	if (EC_KEY_generate_key(ec))
		{
		printf("\tECDSA key generated OK incorrectly!!\n");
		st_err++;
		}
	else
		printf("\tECDSA key generation failed as expected.\n");

	printf("  Induced failure test completed with %d errors\n", st_err);
	post_quiet = 0;
	no_err = 0;
	BN_free(bn);
	FIPS_rsa_free(rsa);
	FIPS_dsa_free(dsa);
	FIPS_ec_key_free(ec);
	if (st_err)
		return 0;
	return 1;
	}

#ifdef FIPS_ALGVS
int fips_test_suite_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char **args = argv + 1;
    int bad_rsa = 0, bad_dsa = 0;
    int do_rng_stick = 0;
    int do_drbg_stick = 0;
    int no_exit = 0;
    int no_dh = 0, no_drbg = 0;
    char *pass = FIPS_AUTH_USER_PASS;
    int fullpost = 0, fullerr = 0;

    FIPS_post_set_callback(post_cb);

    printf("\tFIPS-mode test application\n");

    printf("\t%s\n\n", FIPS_module_version_text());

    while(*args) {
        /* Corrupted KAT tests */
        if (!strcmp(*args, "integrity")) {
	    fail_id = FIPS_TEST_INTEGRITY;
        } else if (!strcmp(*args, "aes")) {
	    fail_id = FIPS_TEST_CIPHER;
	    fail_sub = NID_aes_128_ecb;	
        } else if (!strcmp(*args, "aes-ccm")) {
	    fail_id = FIPS_TEST_CCM;
        } else if (!strcmp(*args, "aes-gcm")) {
	    fail_id = FIPS_TEST_GCM;
        } else if (!strcmp(*args, "aes-xts")) {
	    fail_id = FIPS_TEST_XTS;
        } else if (!strcmp(*args, "des")) {
	    fail_id = FIPS_TEST_CIPHER;
	    fail_sub = NID_des_ede3_ecb;	
        } else if (!strcmp(*args, "dsa")) {
	    fail_id = FIPS_TEST_SIGNATURE;
	    fail_key = EVP_PKEY_DSA;	
        } else if (!strcmp(argv[1], "ecdh")) {
	    fail_id = FIPS_TEST_ECDH;
        } else if (!strcmp(*args, "ecdsa")) {
	    fail_id = FIPS_TEST_SIGNATURE;
	    fail_key = EVP_PKEY_EC;	
        } else if (!strcmp(*args, "rsa")) {
	    fail_id = FIPS_TEST_SIGNATURE;
	    fail_key = EVP_PKEY_RSA;	
        } else if (!strcmp(*args, "rsakey")) {
            printf("RSA key generation and signature validation with corrupted key...\n");
	    bad_rsa = 1;
	    no_exit = 1;
        } else if (!strcmp(*args, "rsakeygen")) {
	    fail_id = FIPS_TEST_PAIRWISE;
	    fail_key = EVP_PKEY_RSA;
	    no_exit = 1;
        } else if (!strcmp(*args, "dsakey")) {
            printf("DSA key generation and signature validation with corrupted key...\n");
	    bad_dsa = 1;
	    no_exit = 1;
        } else if (!strcmp(*args, "dsakeygen")) {
	    fail_id = FIPS_TEST_PAIRWISE;
	    fail_key = EVP_PKEY_DSA;
	    no_exit = 1;
        } else if (!strcmp(*args, "sha1")) {
	    fail_id = FIPS_TEST_DIGEST;
        } else if (!strcmp(*args, "hmac")) {
	    fail_id = FIPS_TEST_HMAC;
        } else if (!strcmp(*args, "cmac")) {
	    fail_id = FIPS_TEST_CMAC;
	} else if (!strcmp(*args, "drbg")) {
	    fail_id = FIPS_TEST_DRBG;
	} else if (!strcmp(argv[1], "rng")) {
	    fail_id = FIPS_TEST_X931;
	} else if (!strcmp(*args, "nodrbg")) {
	    no_drbg = 1;
	    no_exit = 1;
	} else if (!strcmp(*args, "nodh")) {
	    no_dh = 1;
	    no_exit = 1;
	} else if (!strcmp(*args, "post")) {
	    fail_id = -1;
	} else if (!strcmp(*args, "rngstick")) {
	    do_rng_stick = 1;
	    no_exit = 1;
	    printf("RNG test with stuck continuous test...\n");
	} else if (!strcmp(*args, "drbgentstick")) {
		do_entropy_stick();
	} else if (!strcmp(*args, "drbgstick")) {
	    do_drbg_stick = 1;
	    no_exit = 1;
	    printf("DRBG test with stuck continuous test...\n");
	} else if (!strcmp(*args, "user")) {
		pass = FIPS_AUTH_USER_PASS;
	} else if (!strcmp(*args, "officer")) {
		pass = FIPS_AUTH_OFFICER_PASS;
	} else if (!strcmp(*args, "badpass")) {
		pass = "bad invalid password";
	} else if (!strcmp(*args, "nopass")) {
		pass = "";
	} else if (!strcmp(*args, "fullpost")) {
		fullpost = 1;
	    	no_exit = 1;
	} else if (!strcmp(*args, "fullerr")) {
		fullerr = 1;
	    	no_exit = 1;
        } else {
            printf("Bad argument \"%s\"\n", *args);
            return 1;
        }
    args++;
    }

    if ((argc != 1) && !no_exit) {
    		fips_algtest_init_nofips();
        	if (!FIPS_module_mode_set(1, pass)) {
        	    printf("Power-up self test failed\n");
		    return 1;
		}
        	printf("Power-up self test successful\n");
        	return 0;
    }

    fips_algtest_init_nofips();

    /* Non-Approved cryptographic operation
    */
    printf("1. Non-Approved cryptographic operation test...\n");
    if (no_dh)
	printf("\t D-H test skipped\n");
    else
    	test_msg("\ta. Included algorithm (D-H)...", dh_test());

    /* Power-up self test
    */
    ERR_clear_error();
    test_msg("2. Automatic power-up self test", FIPS_module_mode_set(1, pass));
    if (!FIPS_module_mode())
	return 1;
    if (do_drbg_stick)
            FIPS_drbg_stick(1);
    if (do_rng_stick)
            FIPS_x931_stick(1);

    /* AES encryption/decryption
    */
    test_msg("3a. AES encryption/decryption", FIPS_aes_test());
    /* AES GCM encryption/decryption
    */
    test_msg("3b. AES-GCM encryption/decryption", FIPS_aes_gcm_test());

    /* RSA key generation and encryption/decryption
    */
    test_msg("4. RSA key generation and encryption/decryption",
						FIPS_rsa_test(bad_rsa));

    /* DES-CBC encryption/decryption
    */
    test_msg("5. DES-ECB encryption/decryption", FIPS_des3_test());

    /* DSA key generation and signature validation
    */
    test_msg("6. DSA key generation and signature validation",
    						FIPS_dsa_test(bad_dsa));

    /* SHA-1 hash
    */
    test_msg("7a. SHA-1 hash", FIPS_sha1_test());

    /* SHA-256 hash
    */
    test_msg("7b. SHA-256 hash", FIPS_sha256_test());

    /* SHA-512 hash
    */
    test_msg("7c. SHA-512 hash", FIPS_sha512_test());

    /* HMAC-SHA-1 hash
    */
    test_msg("7d. HMAC-SHA-1 hash", FIPS_hmac_sha1_test());

    /* HMAC-SHA-224 hash
    */
    test_msg("7e. HMAC-SHA-224 hash", FIPS_hmac_sha224_test());

    /* HMAC-SHA-256 hash
    */
    test_msg("7f. HMAC-SHA-256 hash", FIPS_hmac_sha256_test());

    /* HMAC-SHA-384 hash
    */
    test_msg("7g. HMAC-SHA-384 hash", FIPS_hmac_sha384_test());

    /* HMAC-SHA-512 hash
    */
    test_msg("7h. HMAC-SHA-512 hash", FIPS_hmac_sha512_test());

    /* CMAC-AES-128 hash
    */
    test_msg("8a. CMAC-AES-128 hash", FIPS_cmac_aes128_test());

    /* CMAC-AES-192 hash
    */
    test_msg("8b. CMAC-AES-192 hash", FIPS_cmac_aes192_test());

    /* CMAC-AES-256 hash
    */
    test_msg("8c. CMAC-AES-256 hash", FIPS_cmac_aes256_test());

# if 0				/* Not a FIPS algorithm */
    /* CMAC-TDEA-2 hash
    */
    test_msg("8d. CMAC-TDEA-2 hash", FIPS_cmac_tdea2_test());
#endif

    /* CMAC-TDEA-3 hash
    */
    test_msg("8e. CMAC-TDEA-3 hash", FIPS_cmac_tdea3_test());

    /* Non-Approved cryptographic operation
    */
    printf("9. Non-Approved cryptographic operation test...\n");
    printf("\ta. Included algorithm (D-H)...%s\n",
		no_dh ? "skipped" :
    		dh_test() ? "successful as expected"
	    					: Fail("failed INCORRECTLY!") );

    /* Zeroization
    */
    printf("10. Zero-ization...\n\t%s\n",
    		Zeroize() ? "successful as expected"
					: Fail("failed INCORRECTLY!") );

    printf("11. Complete DRBG health check...\n");
    printf("\t%s\n", FIPS_selftest_drbg_all() ? "successful as expected"
					: Fail("failed INCORRECTLY!") );

    printf("12. DRBG generation check...\n");
    if (no_drbg)
	printf("\tskipped\n");
    else
    	printf("\t%s\n", do_drbg_all() ? "successful as expected"
					: Fail("failed INCORRECTLY!") );

    printf("13. Induced test failure check...\n");
    printf("\t%s\n", do_fail_all(fullpost, fullerr) ? "successful as expected"
					: Fail("failed INCORRECTLY!") );
    printf("\nAll tests completed with %d errors\n", Error);
    return Error ? 1 : 0;
    }

#endif
