/* crypto/ecdsa/ecdsatest.c */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by 
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CLOCKS_PER_SEC
	/* "To determine the time in seconds, the value returned
	 * by the clock function should be divided by the value
	 * of the macro CLOCKS_PER_SEC."
	 *                                       -- ISO/IEC 9899 */
#	define UNIT "s"
#else
	/* "`CLOCKS_PER_SEC' undeclared (first use this function)"
	 *                            -- cc on NeXTstep/OpenStep */
#	define UNIT "units"
#	define CLOCKS_PER_SEC 1
#endif

#ifdef OPENSSL_NO_ECDSA
int main(int argc, char * argv[]) { puts("Elliptic curves are disabled."); return 0; }
#else

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>

static BIO *bio_err=NULL;
static const char rnd_seed[] = "string to make the random number generator think it has entropy";

#define	ECDSA_NIST_TESTS	10
ECDSA_SIG*	signatures[ECDSA_NIST_TESTS];
unsigned char	digest[ECDSA_NIST_TESTS][20];

/* some declarations */
void clear_ecdsa(EC_KEY *);
int set_p192_param(EC_KEY *);
int set_p239_param(EC_KEY *);
int test_sig_vrf(EC_KEY *, const unsigned char *);
int test_x962_sig_vrf(EC_KEY *, const unsigned char *,
                           const char *, const char *, const char *);
int ecdsa_cmp(const EC_KEY *, const EC_KEY *);

void clear_ecdsa(EC_KEY *ecdsa)
{
	if (!ecdsa)
		return;
	if (ecdsa->group)
	{
		EC_GROUP_free(ecdsa->group);
		ecdsa->group = NULL;
	}
	if (ecdsa->pub_key)
	{
		EC_POINT_free(ecdsa->pub_key);
		ecdsa->pub_key = NULL;
	}
	if (ecdsa->priv_key)
	{
		BN_free(ecdsa->priv_key);
		ecdsa->priv_key = NULL;
	}
}

int set_p192_param(EC_KEY *ecdsa)
{
	BN_CTX	 *ctx=NULL;
	int 	 ret=0;

	if (!ecdsa)
		return 0;
	if ((ctx = BN_CTX_new()) == NULL) goto err;
	clear_ecdsa(ecdsa);
	
	if ((ecdsa->group = EC_GROUP_new_by_nid(NID_X9_62_prime192v1)) == NULL)
	{
		BIO_printf(bio_err,"ECDSA_SET_GROUP_P_192_V1() failed \n");
		goto err;
	}
	if ((ecdsa->pub_key = EC_POINT_new(ecdsa->group)) == NULL)
	{
		BIO_printf(bio_err,"EC_POINT_new failed \n");
		goto err;
	}

	if (!BN_dec2bn(&(ecdsa->priv_key), "651056770906015076056810763456358567190100156695615665659"))	goto err;
	if (!EC_POINT_mul(ecdsa->group,ecdsa->pub_key,ecdsa->priv_key,NULL,NULL,ctx))
	{
		BIO_printf(bio_err,"EC_POINT_mul() failed \n");
		goto err;
	}
	ret = 1;

err :	if (ctx)	BN_CTX_free(ctx);
	return ret;
}

int set_p239_param(EC_KEY *ecdsa)
{
	BN_CTX	 *ctx=NULL;
	int 	 ret=0;

	if (!ecdsa)
		return 0;
	if ((ctx = BN_CTX_new()) == NULL) goto err;
	clear_ecdsa(ecdsa);
	
	if ((ecdsa->group = EC_GROUP_new_by_nid(NID_X9_62_prime239v1)) == NULL)
	{
		BIO_printf(bio_err,"ECDSA_SET_GROUP_P_239_V1() failed \n");
		goto err;
	}
	if ((ecdsa->pub_key = EC_POINT_new(ecdsa->group)) == NULL)
	{
		BIO_printf(bio_err,"EC_POINT_new failed \n");
		goto err;
	}

	if (!BN_dec2bn(&(ecdsa->priv_key), "876300101507107567501066130761671078357010671067781776716671676178726717"))	goto err;
	if (!EC_POINT_mul(ecdsa->group,ecdsa->pub_key,ecdsa->priv_key,NULL,NULL,ctx))
	{
		BIO_printf(bio_err,"EC_POINT_mul() failed \n");
		goto err;
	}
	ret = 1;

err :	if (ctx)	BN_CTX_free(ctx);
	return ret;
}

int test_sig_vrf(EC_KEY *ecdsa, const unsigned char* dgst)
{
        int       ret=0,type=0;
        unsigned char *buffer=NULL;
        unsigned int  buf_len;
        clock_t  tim;
 
        if (!ecdsa || !ecdsa->group || !ecdsa->pub_key || !ecdsa->priv_key)
                return 0;
        if ((buf_len = ECDSA_size(ecdsa)) == 0)
        {
                BIO_printf(bio_err, "ECDSA_size() == 0 \n");
                goto err;
        }
        if ((buffer = OPENSSL_malloc(buf_len)) == NULL)
                goto err;
 
        tim = clock();
        if (!ECDSA_sign(type, dgst , 20, buffer, &buf_len, ecdsa))
        {
                BIO_printf(bio_err, "ECDSA_sign() FAILED \n");
                goto err;
        }
        tim = clock() - tim;
        BIO_printf(bio_err, " [ ECDSA_sign() %.2f"UNIT, (double)tim/(CLOCKS_PER_SEC));
 
        tim = clock();
        ret = ECDSA_verify(type, dgst, 20, buffer, buf_len, ecdsa);
        if (ret != 1)
        {
                BIO_printf(bio_err, "ECDSA_verify() FAILED \n");
                goto err;
        }
        tim = clock() - tim;
        BIO_printf(bio_err, " and ECDSA_verify() %.2f"UNIT" ] ", (double)tim/(CLOCKS_PER_SEC));
 
err:    OPENSSL_free(buffer);
        return(ret == 1);
}

int test_x962_sig_vrf(EC_KEY *eckey, const unsigned char *dgst,
                           const char *k_in, const char *r_in, const char *s_in)
{
        int       ret=0;
        ECDSA_SIG *sig=NULL;
        EC_POINT  *point=NULL;
        BIGNUM    *r=NULL,*s=NULL,*k=NULL,*x=NULL,*y=NULL,*m=NULL,*ord=NULL;
        BN_CTX    *ctx=NULL;
        char      *tmp_char=NULL;
	ECDSA_DATA *ecdsa = ecdsa_check(eckey);;
	
        if (!eckey || !eckey->group || !eckey->pub_key || !eckey->priv_key
		|| !ecdsa)
                return 0;
        if ((point = EC_POINT_new(eckey->group)) == NULL) goto err;
        if ((r = BN_new()) == NULL || (s = BN_new()) == NULL 
		|| (k = BN_new()) == NULL || (x = BN_new()) == NULL || 
		(y = BN_new()) == NULL || (m = BN_new()) == NULL ||
		(ord = BN_new()) == NULL) goto err;
        if ((ctx = BN_CTX_new()) == NULL) goto err;
        if (!BN_bin2bn(dgst, 20, m)) goto err;
        if (!BN_dec2bn(&k, k_in)) goto err;
        if (!EC_POINT_mul(eckey->group, point, k, NULL, NULL, ctx)) goto err;
        if (!EC_POINT_get_affine_coordinates_GFp(eckey->group, point, x, y,
		ctx)) goto err;
        if (!EC_GROUP_get_order(eckey->group, ord, ctx)) goto err;
        if ((ecdsa->r = BN_dup(x)) == NULL) goto err;
        if ((ecdsa->kinv = BN_mod_inverse(NULL, k, ord, ctx)) == NULL)
		goto err;
 
        if ((sig = ECDSA_do_sign(dgst, 20, eckey)) == NULL)
        {
                BIO_printf(bio_err,"ECDSA_do_sign() failed \n");
                goto err;
        }
 
        if (!BN_dec2bn(&r, r_in)) goto err;
        if (!BN_dec2bn(&s, s_in)) goto err;
        if (BN_cmp(sig->r,r) != 0 || BN_cmp(sig->s,s) != 0)
        {
                tmp_char = OPENSSL_malloc(128);
                if (tmp_char == NULL) goto err;
                tmp_char = BN_bn2dec(sig->r);
                BIO_printf(bio_err,"unexpected signature \n");
                BIO_printf(bio_err,"sig->r = %s\n",tmp_char);
                tmp_char = BN_bn2dec(sig->s);
                BIO_printf(bio_err,"sig->s = %s\n",tmp_char);
                goto err;
        }
	        ret = ECDSA_do_verify(dgst, 20, sig, eckey);
        if (ret != 1)
        {
                BIO_printf(bio_err,"ECDSA_do_verify : signature verification failed \n");
                goto err;
        }
 
        ret = 1;
err :   if (r)    BN_free(r);
        if (s)    BN_free(s);
        if (k)    BN_free(k);
        if (x)    BN_free(x);
        if (y)    BN_free(y);
	if (m)	  BN_free(m);
        if (ord)  BN_free(ord);
        if (sig)  ECDSA_SIG_free(sig);
        if (ctx)  BN_CTX_free(ctx);
        if (point) EC_POINT_free(point);
        if (tmp_char) OPENSSL_free(tmp_char);
        return(ret == 1);
}

int ecdsa_cmp(const EC_KEY *a, const EC_KEY *b)
{
	int 	ret=1;
	BN_CTX	*ctx=NULL;
	BIGNUM	*tmp_a1=NULL, *tmp_a2=NULL, *tmp_a3=NULL;
	BIGNUM	*tmp_b1=NULL, *tmp_b2=NULL, *tmp_b3=NULL;

	if ((ctx = BN_CTX_new()) == NULL) return 1;
	if ((tmp_a1 = BN_new()) == NULL || (tmp_a2 = BN_new()) == NULL || (tmp_a3 = BN_new()) == NULL) goto err;
	if ((tmp_b1 = BN_new()) == NULL || (tmp_b2 = BN_new()) == NULL || (tmp_b3 = BN_new()) == NULL) goto err;

	if (a->pub_key && b->pub_key)
		if (EC_POINT_cmp(a->group, a->pub_key, b->pub_key, ctx) != 0) goto err;
	if (a->priv_key && b->priv_key)
		if (BN_cmp(a->priv_key, b->priv_key) != 0) goto err;
	if (!EC_GROUP_get_curve_GFp(a->group, tmp_a1, tmp_a2, tmp_a3, ctx)) goto err;
	if (!EC_GROUP_get_curve_GFp(a->group, tmp_b1, tmp_b2, tmp_b3, ctx)) goto err;
	if (BN_cmp(tmp_a1, tmp_b1) != 0) goto err;
	if (BN_cmp(tmp_a2, tmp_b2) != 0) goto err;
	if (BN_cmp(tmp_a3, tmp_b3) != 0) goto err;

	ret = 0;
err:	if (tmp_a1) BN_free(tmp_a1);
	if (tmp_a2) BN_free(tmp_a2);
	if (tmp_a3) BN_free(tmp_a3);
	if (tmp_b1) BN_free(tmp_b1);
	if (tmp_b2) BN_free(tmp_b2);
	if (tmp_b3) BN_free(tmp_b3);
	if (ctx) BN_CTX_free(ctx);
	return(ret);
}

int main(void)
{
	EC_KEY	 	*ecdsa=NULL, *ret_ecdsa=NULL;
	BIGNUM	 	*d=NULL;
	X509_PUBKEY 	*x509_pubkey=NULL;
	PKCS8_PRIV_KEY_INFO *pkcs8=NULL;
	EVP_PKEY 	*pkey=NULL, *ret_pkey=NULL;
	int 	 	dgst_len=0;
	unsigned char 	*dgst=NULL;
	int 	 	ret = 0, i=0;
	clock_t		tim;
	unsigned char 	*buffer=NULL;
	unsigned char   *pp;
	long		buf_len=0;
	double		tim_d;
	EVP_MD_CTX	*md_ctx=NULL;
	
	/* enable memory leak checking unless explicitly disabled */
	if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) && (0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off"))))
		{
		CRYPTO_malloc_debug_init();
		CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
		}
	else
		{
		/* OPENSSL_DEBUG_MEMORY=off */
		CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
		}
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	ERR_load_crypto_strings();

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

	RAND_seed(rnd_seed, sizeof(rnd_seed));

	if ((ecdsa = EC_KEY_new()) == NULL)   goto err;

	set_p192_param(ecdsa);
	EC_KEY_print(bio_err, ecdsa, 0);

	/* en- decode tests */

	/* i2d_ - d2i_ECParameters() */
	BIO_printf(bio_err, "\nTesting i2d_ - d2i_ECDSAParameters \n");
	buf_len = i2d_ECParameters(ecdsa, NULL);
	if (!buf_len || (buffer = OPENSSL_malloc(buf_len)) == NULL) goto err;
	pp = buffer;
	if (!i2d_ECParameters(ecdsa, &pp)) goto err;
	pp = buffer;
	if ((ret_ecdsa = d2i_ECParameters(&ret_ecdsa, (const unsigned char **)&pp, 
			buf_len)) == NULL) goto err;
	ECParameters_print(bio_err, ret_ecdsa);
	if (ecdsa_cmp(ecdsa, ret_ecdsa)) goto err;
	OPENSSL_free(buffer);
	buffer = NULL;
	EC_KEY_free(ret_ecdsa);
	ret_ecdsa = NULL;

	/* i2d_ - d2i_ECPrivateKey() */
	BIO_printf(bio_err, "\nTesting i2d_ - d2i_ECDSAPrivateKey \n");
	buf_len = i2d_ECPrivateKey(ecdsa, NULL);
	if (!buf_len || (buffer = OPENSSL_malloc(buf_len)) == NULL) goto err;
	pp = buffer;
	if (!i2d_ECPrivateKey(ecdsa, &pp)) goto err;
	pp = buffer;
	if ((ret_ecdsa = d2i_ECPrivateKey(&ret_ecdsa, (const unsigned char**)&pp, 
			buf_len)) == NULL) goto err;
	EC_KEY_print(bio_err, ret_ecdsa, 0);
	if (ecdsa_cmp(ecdsa, ret_ecdsa)) goto err;
	EC_KEY_free(ret_ecdsa);
	ret_ecdsa = NULL;
	OPENSSL_free(buffer);
	buffer = NULL;

	/* X509_PUBKEY_set() &  X509_PUBKEY_get() */	

	BIO_printf(bio_err, "\nTesting X509_PUBKEY_{get,set}            : ");
	if ((pkey = EVP_PKEY_new()) == NULL) goto err;
	EVP_PKEY_assign_EC_KEY(pkey, ecdsa);
	if ((x509_pubkey = X509_PUBKEY_new()) == NULL) goto err;
	if (!X509_PUBKEY_set(&x509_pubkey, pkey)) goto err;

	if ((ret_pkey = X509_PUBKEY_get(x509_pubkey)) == NULL) goto err;
	ret_ecdsa = EVP_PKEY_get1_EC_KEY(ret_pkey);
	EVP_PKEY_free(ret_pkey);
	ret_pkey = NULL;

	if (ecdsa_cmp(ecdsa, ret_ecdsa)) 
	{
		BIO_printf(bio_err, "TEST FAILED \n");
		goto err;
	}
	else BIO_printf(bio_err, "TEST OK \n");
	X509_PUBKEY_free(x509_pubkey);
	x509_pubkey = NULL;
	EC_KEY_free(ret_ecdsa);
	ret_ecdsa = NULL;

	/* Testing PKCS8_PRIV_KEY_INFO <-> EVP_PKEY */
	BIO_printf(bio_err, "Testing PKCS8_PRIV_KEY_INFO <-> EVP_PKEY : \n");
	BIO_printf(bio_err, "PKCS8_OK              : ");
	if ((pkcs8 = EVP_PKEY2PKCS8_broken(pkey, PKCS8_OK)) == NULL) goto err;
	if ((ret_pkey = EVP_PKCS82PKEY(pkcs8)) == NULL) goto err;
	ret_ecdsa = EVP_PKEY_get1_EC_KEY(ret_pkey);
	if (ecdsa_cmp(ecdsa, ret_ecdsa))
	{
		BIO_printf(bio_err, "TEST FAILED \n");
		goto err;
	}
	else BIO_printf(bio_err, "TEST OK \n");
	EVP_PKEY_free(ret_pkey);
	ret_pkey = NULL;
	EC_KEY_free(ret_ecdsa);
	ret_ecdsa = NULL;
	PKCS8_PRIV_KEY_INFO_free(pkcs8);
	EVP_PKEY_free(pkey);
	pkey  = NULL;
	ecdsa = NULL;
	pkcs8 = NULL;

	/* sign and verify tests */
	if ((d = BN_new()) == NULL) goto err;
 
        if (!BN_dec2bn(&d, "968236873715988614170569073515315707566766479517")) goto err;
        dgst_len = BN_num_bytes(d);
	if ((dgst = OPENSSL_malloc(dgst_len)) == NULL) goto err;
        if (!BN_bn2bin(d, dgst)) goto err;

        BIO_printf(bio_err, "Performing tests based on examples H.3.1 and H.3.2 of X9.62 \n");
 
        BIO_printf(bio_err, "PRIME_192_V1 : ");
	if ((ecdsa = EC_KEY_new()) == NULL) goto err;
        if (!set_p192_param(ecdsa)) goto err;
        if (!test_x962_sig_vrf(ecdsa, dgst, "6140507067065001063065065565667405560006161556565665656654",
                               "3342403536405981729393488334694600415596881826869351677613",
                               "5735822328888155254683894997897571951568553642892029982342"))
                goto err;
        else
                BIO_printf(bio_err, "OK\n");
        BIO_printf(bio_err, "PRIME_239_V1 : ");
        if (!set_p239_param(ecdsa))
                goto err;
        if (!test_x962_sig_vrf(ecdsa, dgst, "700000017569056646655505781757157107570501575775705779575555657156756655",
                               "308636143175167811492622547300668018854959378758531778147462058306432176",
                               "323813553209797357708078776831250505931891051755007842781978505179448783"))
                goto err;
        else
                BIO_printf(bio_err, "OK\n");

	EC_KEY_free(ecdsa);
	ecdsa = NULL;
	OPENSSL_free(dgst);
	dgst = NULL;

	for (i=0; i<ECDSA_NIST_TESTS; i++)
		if (!RAND_bytes(digest[i], 20)) goto err;

 	BIO_printf(bio_err, "\n");

/* Macro for each test */
#define ECDSA_GROUP_TEST(text, curve) \
 	BIO_printf(bio_err, "Testing sign & verify with %s : \n", text); \
	EC_KEY_free(ecdsa); \
	if ((ecdsa = EC_KEY_new()) == NULL) goto err; \
	if ((ecdsa->group = EC_GROUP_new_by_nid(curve)) == NULL) goto err; \
	if (!EC_KEY_generate_key(ecdsa)) goto err; \
        tim = clock(); \
        for (i=0; i<ECDSA_NIST_TESTS; i++) \
                if ((signatures[i] = ECDSA_do_sign(digest[i], 20, ecdsa)) == NULL) goto err; \
        tim = clock() - tim; \
	tim_d = (double)tim / CLOCKS_PER_SEC; \
        BIO_printf(bio_err, "%d x ECDSA_do_sign()   in %.2f"UNIT" => average time for ECDSA_do_sign()   %.4f"UNIT"\n" \
		, ECDSA_NIST_TESTS, tim_d, tim_d / ECDSA_NIST_TESTS); \
	tim = clock(); \
	for (i=0; i<ECDSA_NIST_TESTS; i++) \
		if (!ECDSA_do_verify(digest[i], 20, signatures[i], ecdsa)) goto err; \
	tim = clock() - tim; \
	tim_d = (double)tim / CLOCKS_PER_SEC; \
	BIO_printf(bio_err, "%d x ECDSA_do_verify() in %.2f"UNIT" => average time for ECDSA_do_verify() %.4f"UNIT"\n" \
                , ECDSA_NIST_TESTS, tim_d, tim_d/ECDSA_NIST_TESTS); \
	for (i=0; i<ECDSA_NIST_TESTS; i++) \
	{ \
		ECDSA_SIG_free(signatures[i]); \
		signatures[i] = NULL; \
	}
	
	/* NIST PRIME CURVES TESTS */
	ECDSA_GROUP_TEST("NIST Prime-Curve P-192", NID_X9_62_prime192v1);
	ECDSA_GROUP_TEST("NIST Prime-Curve P-224", NID_secp224r1);
	ECDSA_GROUP_TEST("NIST Prime-Curve P-256", NID_X9_62_prime256v1);
	ECDSA_GROUP_TEST("NIST Prime-Curve P-384", NID_secp384r1);
	ECDSA_GROUP_TEST("NIST Prime-Curve P-521", NID_secp521r1);
	/* NIST BINARY CURVES TESTS */
	ECDSA_GROUP_TEST("NIST Binary-Curve K-163", NID_sect163k1);
	ECDSA_GROUP_TEST("NIST Binary-Curve B-163", NID_sect163r2);
	ECDSA_GROUP_TEST("NIST Binary-Curve K-233", NID_sect233k1);
	ECDSA_GROUP_TEST("NIST Binary-Curve B-233", NID_sect233r1);
	ECDSA_GROUP_TEST("NIST Binary-Curve K-283", NID_sect283k1);
	ECDSA_GROUP_TEST("NIST Binary-Curve B-283", NID_sect283r1);
	ECDSA_GROUP_TEST("NIST Binary-Curve K-409", NID_sect409k1);
	ECDSA_GROUP_TEST("NIST Binary-Curve B-409", NID_sect409r1);
	ECDSA_GROUP_TEST("NIST Binary-Curve K-571", NID_sect571k1);
	ECDSA_GROUP_TEST("NIST Binary-Curve B-571", NID_sect571r1);
#undef ECDSA_GROUP_TEST

	EC_KEY_free(ecdsa);
	ecdsa = NULL;
	OPENSSL_free(buffer);
	buffer = NULL;
	EVP_PKEY_free(pkey);
	pkey = NULL;
	
	ret = 1;
err:	if (!ret) 	
		BIO_printf(bio_err, "TEST FAILED \n");
	else 
		BIO_printf(bio_err, "TEST PASSED \n");
	if (!ret)
		ERR_print_errors(bio_err);
	if (ecdsa)	EC_KEY_free(ecdsa);
	if (d)		BN_free(d);
	if (dgst)	OPENSSL_free(dgst);
	if (md_ctx)	EVP_MD_CTX_destroy(md_ctx);
	if (pkey)	EVP_PKEY_free(pkey);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	CRYPTO_mem_leaks(bio_err);
	if (bio_err != NULL)
	{
		BIO_free(bio_err);
		bio_err = NULL;
	}
	return(0);
}	

#endif
