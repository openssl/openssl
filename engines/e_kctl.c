/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define _GNU_SOURCE

#include <keyutils.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/syscall.h>

#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "e_kctl_err.h"
#include "e_kctl_err.c"

#define KCTL_DESC_MAX_LEN 64

#define KEY_TAG_DH_PRIVATE "dh:private"
#define KEY_TAG_DH_PRIME "dh:prime"
#define KEY_TAG_DH_GENERATOR "dh:generator"
#define KEY_TAG_DH_PKEY "dh:public_key"
#define KEY_TAG_RSA_PKEY "rsa:pkey"

#define KEY_TYPE_PKEY "asymmetric"
#define KEY_TYPE_DH_PARAM "user"

#define INVALID_KEYCTL_ID -1

#define add_ref(ptr, member) \
	__atomic_add_fetch(&((ptr)->member), 1, __ATOMIC_RELAXED)

#define release_ref(ptr, member, deleter) \
	do { \
		if (!__atomic_sub_fetch(&((ptr)->member), 1, __ATOMIC_ACQ_REL)) { \
			deleter((ptr)); \
		} \
	} \
	while (false)

typedef struct PkeyExCtx {
	key_serial_t id;
	char desc[KCTL_DESC_MAX_LEN];
	int32_t ref;
} PkeyExCtx;

typedef struct DhExCtx {
	key_serial_t priv;
	key_serial_t p;
	key_serial_t g;
	int32_t ref;
} DhExCtx;

static bool kctl_pkey_error(PkeyExCtx *pkey_ctx)
{
	return pkey_ctx->id == INVALID_KEYCTL_ID;
}

static bool kctl_pkey_uninitialized(PkeyExCtx *pkey_ctx)
{
	return pkey_ctx->desc[0] == '\0';
}

static bool kctl_pkey_ready(PkeyExCtx *pkey_ctx)
{
	return !kctl_pkey_uninitialized(pkey_ctx) &&
	       !kctl_pkey_error(pkey_ctx);
}

static PkeyExCtx *kctl_create_pkey_ctx()
{
	return OPENSSL_zalloc(sizeof(PkeyExCtx));
}

#define kctl_unlink_key(key_id) \
	keyctl_unlink((key_id), KEY_SPEC_PROCESS_KEYRING)

#define kctl_free_pkey_ctx(pkey_ctx) \
	do { \
		if (!(pkey_ctx) || !kctl_pkey_ready((pkey_ctx))) { \
			break; \
		} \
		kctl_unlink_key((pkey_ctx)->id); \
	} \
	while (false)

static DhExCtx *kctl_create_dh_ctx()
{
	return OPENSSL_zalloc(sizeof(DhExCtx));
}

#define kctl_free_dh_ctx(dh_ctx) \
	do { \
		if ((dh_ctx)->priv > 0) { \
			kctl_unlink_key((dh_ctx)->priv); \
		} \
		if ((dh_ctx)->p > 0) { \
			kctl_unlink_key((dh_ctx)->p); \
		} \
		if ((dh_ctx)->g > 0) { \
			kctl_unlink_key((dh_ctx)->g); \
		} \
	} \
	while (false)

#ifndef gettid
#define gettid() syscall(SYS_gettid)
#endif

static char *kctl_build_desc(char *buffer, size_t len, const char *tag)
{
	static __thread uint64_t idx = 0;
	snprintf(buffer, len, "e_kctl-%s-%ld-%ld", tag, gettid(), idx++);
	return buffer;
}

static int kctl_pkey_add(PkeyExCtx *pkey_ctx,
                         const unsigned char *payload,
                         size_t payload_len,
                         int flag /*current not used*/) {
	/* currently only rsa supported */
	kctl_build_desc(pkey_ctx->desc, sizeof(pkey_ctx->desc), KEY_TAG_RSA_PKEY);
	pkey_ctx->id = add_key(KEY_TYPE_PKEY, pkey_ctx->desc, payload, payload_len, KEY_SPEC_PROCESS_KEYRING);
	if (pkey_ctx->id == INVALID_KEYCTL_ID)
		KCTLerr(KCTL_F_KCTL_PKEY_ADD, KCTL_R_KCTL_INVALID_PAYLOAD);

	return pkey_ctx->id == INVALID_KEYCTL_ID ? 0 : 1;
}

static int kctl_upload_dh_payload(const unsigned char *param, 
                                  size_t param_len, const char *tag)
{
	int ret;
	char desc[KCTL_DESC_MAX_LEN];
	kctl_build_desc(desc, sizeof(desc), tag);
	ret = add_key(KEY_TYPE_DH_PARAM, desc, (const char *)param, param_len, KEY_SPEC_PROCESS_KEYRING);
	if (ret < 0)
		KCTLerr(KCTL_F_KCTL_UPLOAD_DH_PAYLOAD,
		        KCTL_R_KEYCTL_ADD_FAILURE);

	return ret;
}

static int kctl_upload_dh_bn(const BIGNUM *param, const char *tag)
{
	int ret, len = BN_num_bytes(param);
	unsigned char *p = OPENSSL_malloc(len);
	BN_bn2binpad(param, p, len);
	ret = kctl_upload_dh_payload(p, len, tag);
	OPENSSL_free(p);
	return ret;
}

static int kctl_upload_rsa_privkey(PkeyExCtx *pkey_ctx,
                            RSA *rsa)
{
	int ret = 0, payload_len;
	unsigned char *payload = NULL;
	EVP_PKEY *pkey = NULL;
	PKCS8_PRIV_KEY_INFO *p8info = NULL;

	if (kctl_pkey_error(pkey_ctx) ||
	    !kctl_pkey_uninitialized(pkey_ctx)) {
		return ret;
	}
	if (!RSA_check_key(rsa)) {
		KCTLerr(KCTL_F_KCTL_UPLOAD_RSA_PRIVKEY,
		        KCTL_R_INVALID_RSA_KEY);
		return ret;
	}
	
	pkey = EVP_PKEY_new();
	if (!pkey || EVP_PKEY_set1_RSA(pkey, rsa) <= 0)
		goto clear;

	p8info = EVP_PKEY2PKCS8(pkey);
	if (!p8info ||
		(payload_len = i2d_PKCS8_PRIV_KEY_INFO(p8info, &payload)) <= 0)
		goto clear;

	ret = kctl_pkey_add(pkey_ctx, payload, payload_len, 0);

clear:
	OPENSSL_free(payload);
	PKCS8_PRIV_KEY_INFO_free(p8info);
	EVP_PKEY_free(pkey);
	return ret;
}

static int kctl_upload_dh_params(DhExCtx *dh_ctx, DH *dh)
{
	int ret = 0;
	const BIGNUM *p, *q, *g, *priv = DH_get0_priv_key(dh);
	DH_get0_pqg(dh, &p, &q, &g);
	if (!dh_ctx->priv && 
		(dh_ctx->priv = kctl_upload_dh_bn(priv, KEY_TAG_DH_PRIVATE)) <= 0) {
		dh_ctx->priv = 0;
		goto err;
	}
	if (!dh_ctx->p &&
		(dh_ctx->p = kctl_upload_dh_bn(p, KEY_TAG_DH_PRIME)) <= 0) {
		dh_ctx->p = 0;
		goto err;
	}
	if (!dh_ctx->g &&
	    (dh_ctx->g = kctl_upload_dh_bn(g, KEY_TAG_DH_GENERATOR)) <= 0) {
		dh_ctx->g = 0;
		goto err;
	}

	ret = 1;
	return ret;

err:
	if (dh_ctx->priv) {
		kctl_unlink_key(dh_ctx->priv);
	}
	if (dh_ctx->p) {
		kctl_unlink_key(dh_ctx->p);
	}
	if (dh_ctx->g) {
		kctl_unlink_key(dh_ctx->g);
	}
	return ret;
}

/************************ RSA override ************************/
static RSA_METHOD *kctl_rsa_meth = NULL;
static const RSA_METHOD *ossl_rsa_meth = NULL;
static int kctl_rsa_idx = 0;

/* kctl engine RSA methods declaration */
static int kctl_rsa_priv_enc(int flen, const unsigned char *from,
                             unsigned char *to, RSA *rsa, int padding);
static int kctl_rsa_priv_dec(int flen, const unsigned char *from,
                             unsigned char *to, RSA *rsa, int padding);
static int kctl_rsa_pub_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
static int kctl_rsa_pub_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);

static void kctl_pkey_ex_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
				             int idx, long argl, void *argp) 
{
	PkeyExCtx *pkey_ctx = kctl_create_pkey_ctx();
	add_ref(pkey_ctx, ref);
	CRYPTO_set_ex_data(ad, idx, pkey_ctx);
}

static int kctl_pkey_ex_cpy(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
				     void *from_d, int idx, long argl, void *argp) 
{
	void *s_pkey = CRYPTO_get_ex_data(from, idx);
	void *d_pkey = s_pkey;
	void **pptr = (void **)from_d;

	*pptr = d_pkey;
	CRYPTO_set_ex_data(to, idx, d_pkey);
	add_ref((PkeyExCtx *)s_pkey, ref);
	return 0;
}

static void kctl_pkey_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
				       int idx, long argl, void *argp)
{
	release_ref((PkeyExCtx *)ptr, ref, kctl_free_pkey_ctx);
}

RSA_METHOD *kctl_get_RSA_methods(void)
{
	int res = 1;
	if (kctl_rsa_meth) {
		return kctl_rsa_meth;
	}
	if (!ossl_rsa_meth) {
		ossl_rsa_meth = RSA_PKCS1_OpenSSL();
		if (!ossl_rsa_meth) {
			return NULL;
		}
	}

	if ((kctl_rsa_meth = RSA_meth_new("kctl RSA method", 0)) == NULL)
		return NULL;

	kctl_rsa_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, 0, NULL, 
	                                       kctl_pkey_ex_new, kctl_pkey_ex_cpy,
										   kctl_pkey_ex_free);

	res &= RSA_meth_set_pub_enc(kctl_rsa_meth, kctl_rsa_pub_enc);
	res &= RSA_meth_set_pub_dec(kctl_rsa_meth, kctl_rsa_pub_dec);
	res &= RSA_meth_set_priv_enc(kctl_rsa_meth, kctl_rsa_priv_enc);
	res &= RSA_meth_set_priv_dec(kctl_rsa_meth, kctl_rsa_priv_dec);
	res &= RSA_meth_set_mod_exp(kctl_rsa_meth,
		RSA_meth_get_mod_exp(ossl_rsa_meth));
	res &= RSA_meth_set_bn_mod_exp(kctl_rsa_meth,
		RSA_meth_get_bn_mod_exp(ossl_rsa_meth));
	res &= RSA_meth_set_init(kctl_rsa_meth,
		RSA_meth_get_init(ossl_rsa_meth));
	res &= RSA_meth_set_finish(kctl_rsa_meth,
		RSA_meth_get_finish(ossl_rsa_meth));

	if (kctl_rsa_idx < 0 || res == 0)
		return (RSA_METHOD *)RSA_get_default_method();

	return kctl_rsa_meth;
}

void kctl_free_RSA_methods(void)
{
	if (kctl_rsa_meth) {
		RSA_meth_free(kctl_rsa_meth);
		kctl_rsa_meth = NULL;
	}
	if (kctl_rsa_idx > 0)
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, kctl_rsa_idx);
}

static PkeyExCtx* kctl_get_pkey_ctx(RSA *rsa) {
	PkeyExCtx *pkey_ctx = (PkeyExCtx *) RSA_get_ex_data(rsa, kctl_rsa_idx);
	if (kctl_pkey_uninitialized(pkey_ctx)) {
		kctl_upload_rsa_privkey(pkey_ctx, rsa);
	}
	return kctl_pkey_ready(pkey_ctx) ? pkey_ctx : NULL;
}

static int kctl_hw_rsa_pub_func(PkeyExCtx *pkey_ctx,
	                            const unsigned char *from, int flen,
	                            unsigned char *to, int tlen)
{
	int ret = keyctl_pkey_encrypt(pkey_ctx->id, "enc=raw", from, flen, to, tlen);
	if (ret <= 0) {
		KCTLerr(KCTL_F_HW_RSA_PUB_FUNC, KCTL_R_HW_PUB_FUNC_FAILURE);
	}
	return ret;
}

static int kctl_hw_rsa_priv_func(PkeyExCtx *pkey_ctx,
	                             const unsigned char *from, int flen,
	                             unsigned char *to, int tlen)
{
	int ret = keyctl_pkey_decrypt(pkey_ctx->id, "enc=raw", from, flen, to, tlen);
	if (ret <= 0) {
		KCTLerr(KCTL_F_HW_RSA_PRIV_FUNC,
		        KCTL_R_HW_PRIV_FUNC_FAILURE);
	}
	return ret;
}

static int kctl_rsa_pub_enc(int flen, const unsigned char *from,
		    		        unsigned char *to, RSA *rsa, int padding)
{
	
	PkeyExCtx *pkey_ctx = kctl_get_pkey_ctx(rsa);
	int num, i, ret = -1;
	unsigned char* buf = NULL;
	if (!pkey_ctx) {
		return RSA_meth_get_pub_enc(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}

	num = RSA_size(rsa);
	buf = OPENSSL_malloc(num);
	switch (padding) {
	case RSA_PKCS1_PADDING:
		i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		break;

	case RSA_PKCS1_OAEP_PADDING:
		i = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		break;

	case RSA_SSLV23_PADDING:
		i = RSA_padding_add_SSLv23(buf, num, from, flen);
		break;

	case RSA_NO_PADDING:
		i = RSA_padding_add_none(buf, num, from, flen);
		break;

	default:
        KCTLerr(KCTL_F_KCTL_RSA_PUB_ENC,
		        KCTL_R_UNKNOWN_PADDING_TYPE);
		goto out;
	}

	if (i <= 0)
		goto out;

	ret = kctl_hw_rsa_pub_func(pkey_ctx, buf, num, to, num);
	goto out;

out:
	OPENSSL_clear_free(buf, num);
	return ret;
}

static int kctl_rsa_pub_dec(int flen, const unsigned char *from,
				            unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = kctl_get_pkey_ctx(rsa);
	int ret = -1, num = RSA_size(rsa);
	unsigned char *buf = NULL;
	BIGNUM *plaintext = NULL;

	if (!pkey_ctx) {
		return RSA_meth_get_pub_dec(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}
	buf = OPENSSL_malloc(num);
	ret = kctl_hw_rsa_pub_func(pkey_ctx, from, num, buf, num);
	if (ret <= 0)
		goto err;

	if ((padding == RSA_X931_PADDING)) {
		plaintext = BN_new();
		if (BN_bin2bn(buf, ret, plaintext) <= 0) {
			goto err;
		}
		if ((BN_get_word(plaintext) & 0xf) != 12 && 
		    !BN_sub(plaintext, RSA_get0_n(rsa), plaintext)) {
			goto err;
		}
		ret = BN_bn2binpad(plaintext, buf, num);
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_1(to, num, buf, ret, num);
		break;

	case RSA_X931_PADDING:
		ret = RSA_padding_check_X931(to, num, buf, ret, num);
		break;

	case RSA_NO_PADDING:
		memcpy(to, buf, ret);
		break;

	default:
        KCTLerr(KCTL_F_KCTL_RSA_PUB_DEC,
		        KCTL_R_UNKNOWN_PADDING_TYPE);
        goto err;
	}
	if (ret < 0) {
        KCTLerr(KCTL_F_KCTL_RSA_PUB_DEC,
		        KCTL_R_PADDING_CHECK_FAILED);
		goto err;
	}

err:
	BN_free(plaintext);
	OPENSSL_clear_free(buf, num);
	return ret;
}

static int kctl_rsa_priv_enc(int flen, const unsigned char *from,
				             unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = kctl_get_pkey_ctx(rsa);
	unsigned char *buf = NULL;
	BIGNUM *f = NULL, *r = NULL, *res;
	BN_CTX *bn_ctx = NULL;
	int ret = -1, num = RSA_size(rsa);
	if (!pkey_ctx) {
		return RSA_meth_get_priv_enc(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}
	buf = OPENSSL_malloc(num);
	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
		break;

	case RSA_NO_PADDING:
		ret = RSA_padding_add_none(buf, num, from, flen);
		break;

	case RSA_X931_PADDING:
		ret = RSA_padding_add_X931(buf, num, from, flen);
		break;

	case RSA_SSLV23_PADDING:
	default:
        KCTLerr(KCTL_F_KCTL_RSA_PRIV_ENC,
		        KCTL_R_UNKNOWN_PADDING_TYPE);
        goto err;
	}
	if (ret <= 0) {
		goto err;
	}
	ret = kctl_hw_rsa_priv_func(pkey_ctx, buf, num, to, num);
	if (ret <= 0) {
		goto err;
	}
	if (padding == RSA_X931_PADDING) {
		if ((bn_ctx = BN_CTX_new()) == NULL) {
			goto err;
		}
		BN_CTX_start(bn_ctx);
		f = BN_CTX_get(bn_ctx);
		r = BN_CTX_get(bn_ctx);
		if (BN_bin2bn(buf, ret, f) <= 0) {
			goto err;
		}
		if (BN_bin2bn(to, ret, r) <= 0) {
			goto err;
		}
		if (!BN_sub(f, RSA_get0_n(rsa), r)) {
			goto err;
		}
		if (BN_cmp(r, f) > 0) {
			res = f;
		} else {
			res = r;
		}
		ret = BN_bn2binpad(res, to, num);
	}

err:
	if (bn_ctx != NULL) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	OPENSSL_clear_free(buf, num);
	return ret;
}

static int kctl_rsa_priv_dec(int flen, const unsigned char *from,
				             unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = kctl_get_pkey_ctx(rsa);
	unsigned char *buf = NULL;
	int ret = -1, num = RSA_size(rsa);
	if (!pkey_ctx) {
		return RSA_meth_get_priv_dec(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}
	buf = OPENSSL_malloc(num);
	ret = kctl_hw_rsa_priv_func(pkey_ctx, from, num, buf, num); 
	if (ret <= 0) {
		goto err;
	}
	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_2(to, num, buf, ret, num);
		break;

	case  RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, ret, num, NULL, 0);
		break;

	case RSA_SSLV23_PADDING:
		ret = RSA_padding_check_SSLv23(to, num, buf, ret, num);
		break;

	case RSA_NO_PADDING:
		memcpy(to, buf, ret);
		break;

	default:
        KCTLerr(KCTL_F_KCTL_RSA_PRIV_DEC,
		        KCTL_R_UNKNOWN_PADDING_TYPE);
        goto err;
	}
	if (ret < 0) {
        KCTLerr(KCTL_F_KCTL_RSA_PRIV_DEC,
		        KCTL_R_PADDING_CHECK_FAILED);
	}

err:
    OPENSSL_clear_free(buf, num);
	return ret;
}

/************************ DH override ************************/
static int kctl_dh_idx = 0;
static DH_METHOD *kctl_dh_meth = NULL;
static const DH_METHOD *ossl_dh_meth = NULL;

static int kctl_dh_generate_key(DH *dh);
static int kctl_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

static void kctl_dh_ex_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	DhExCtx *dh_ctx = kctl_create_dh_ctx();
	add_ref(dh_ctx, ref);
	CRYPTO_set_ex_data(ad, idx, dh_ctx);
}

static int kctl_dh_ex_cpy(CRYPTO_EX_DATA *to, 
	                      const CRYPTO_EX_DATA *from, 
	                      void *from_d, 
	                      int idx, 
	                      long argl, 
	                      void *argp)
{
	void *d_dh = OPENSSL_malloc(sizeof(DhExCtx));
	void *s_dh = CRYPTO_get_ex_data(from, idx);
	void **pptr = (void**)from_d;

	*pptr = d_dh;
	CRYPTO_set_ex_data(to, idx, d_dh);
	add_ref((DhExCtx *)s_dh, ref);
	return 0;
}

static void kctl_dh_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	release_ref((DhExCtx *)ptr, ref, kctl_free_dh_ctx);
}

DH_METHOD *kctl_get_DH_methods(void)
{
	int res = 1;
	if (kctl_dh_meth) {
		return kctl_dh_meth;
	}

	if (!ossl_dh_meth) {
		ossl_dh_meth = DH_OpenSSL();
		if (!ossl_dh_meth) {
			return NULL;
		}
	}

	if (!(kctl_dh_meth = DH_meth_new("KCTL DH method", 0))) {
		KCTLerr(KCTL_F_KCTL_GET_DH_METHODS, KCTL_R_KCTL_ALLOC_DH_METH_FAILURE);
		return NULL;
	}

	kctl_dh_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, 0, 
		NULL, kctl_dh_ex_new, kctl_dh_ex_cpy, kctl_dh_ex_free);

    res &= DH_meth_set_generate_key(kctl_dh_meth, kctl_dh_generate_key);
    res &= DH_meth_set_compute_key(kctl_dh_meth, kctl_dh_compute_key);
    res &= DH_meth_set_bn_mod_exp(kctl_dh_meth,
		DH_meth_get_bn_mod_exp(ossl_dh_meth));
    res &= DH_meth_set_init(kctl_dh_meth, 
		DH_meth_get_init(ossl_dh_meth));
    res &= DH_meth_set_finish(kctl_dh_meth,
		DH_meth_get_finish(ossl_dh_meth));

    if (res == 0) {
        KCTLerr(KCTL_F_KCTL_GET_DH_METHODS,
		        KCTL_R_KCTL_SET_DH_METH_FAILURE);
		goto err;
    }
    return kctl_dh_meth;

err:
	DH_meth_free(kctl_dh_meth);
	return NULL;
}

void kctl_free_DH_methods(void)
{
	if (kctl_dh_meth) {
		DH_meth_free(kctl_dh_meth);
		kctl_dh_meth = NULL;
	}
	if (kctl_dh_idx > 0)
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_DH, kctl_dh_idx);
}

static int kctl_dh_generate_priv(DH *dh)
{
	int ok = 0;
	unsigned l;
	BIGNUM *priv_key = NULL;

	priv_key = BN_secure_new();
	if (priv_key == NULL)
		goto err;

	if (DH_get0_q(dh)) {
		do {
			if (!BN_priv_rand_range(priv_key, DH_get0_q(dh)))
				goto err;

		} while (BN_is_zero(priv_key) || BN_is_one(priv_key));
	} else {
		l = DH_get_length(dh) ? 
			DH_get_length(dh) : BN_num_bytes(DH_get0_p(dh));
		if (!BN_priv_rand(priv_key, l, BN_RAND_TOP_ONE,
		                  BN_RAND_BOTTOM_ANY))
			goto err;
	}
	ok = 1;
	DH_set0_key(dh, NULL, priv_key);

err:
	if (ok != 1)
		KCTLerr(KCTL_F_KCTL_DH_GENERATE_PRIV, KCTL_R_BN_LIB_ERR);

	if (DH_get0_priv_key(dh) != priv_key)
		BN_free(priv_key);

	return ok;
}

static int kctl_dh_generate_key(DH *dh)
{
	unsigned char *pkey_buf = NULL;
	int len, ok = 0;
	BIGNUM *pub_key;
	DhExCtx *dh_ctx = DH_get_ex_data(dh, kctl_dh_idx);
	if (!dh_ctx)
		return DH_meth_get_generate_key(ossl_dh_meth)(dh);

	len = DH_get_length(dh) ? DH_get_length(dh) : BN_num_bytes(DH_get0_p(dh));;

	if (!DH_get0_priv_key(dh) && !kctl_dh_generate_priv(dh))
		return 0;

	if (DH_get0_pub_key(dh))
		return 1;

	if (!kctl_upload_dh_params(dh_ctx, dh))
		return DH_meth_get_generate_key(ossl_dh_meth)(dh);

	pkey_buf = OPENSSL_malloc(len);
	len = keyctl_dh_compute(dh_ctx->priv, dh_ctx->p, 
	                        dh_ctx->g,  (char*)pkey_buf, len);
	if (len <= 0) {
		KCTLerr(KCTL_F_KCTL_DH_GENERATE_KEY, 
		        KCTL_R_DH_COMPUTE_FALUIRE);
		goto err;
	}
	pub_key = BN_bin2bn(pkey_buf, len, NULL);
	DH_set0_key(dh, pub_key, BN_dup(DH_get0_priv_key(dh)));
	ok = 1;

err:
	OPENSSL_free(pkey_buf);
	return ok;
}

static int kctl_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
	int ret = 0, pkey = 0, len;
	unsigned char *key_buff = NULL;
	DhExCtx *dh_ctx = DH_get_ex_data(dh, kctl_dh_idx);
	if (!dh_ctx)
		return DH_meth_get_compute_key(ossl_dh_meth)
			(key, pub_key, dh);

	if (!dh_ctx->priv || !dh_ctx->p || !dh_ctx->g)
		goto clear;

	pkey = kctl_upload_dh_bn(pub_key, KEY_TAG_DH_PKEY);
	if (!pkey)
		return DH_meth_get_compute_key(ossl_dh_meth)
			(key, pub_key, dh);

	len = DH_size(dh);
	key_buff = OPENSSL_malloc(len);
	ret = keyctl_dh_compute(dh_ctx->priv, dh_ctx->p, pkey,
	                        (char *)key_buff, len);
	if (ret < 0)
		goto clear;

	memcpy(key, key_buff, ret);

clear:
	kctl_unlink_key(pkey);
	OPENSSL_free(key_buff);
	return ret;
}

/************************ KCTL Engine ************************/
static const char *engine_id = "kctl-engine";
static const char *engine_name = "A keyctl-based asymmetric engine for cerification.";
static int kctl_engine_desctroy(ENGINE *e);

static int bind_kctl_engine(ENGINE *e, const char *id)
{
	int ret = 0;
	const char* _id = strrchr(id, '/');
	if (!_id) {
		_id = id;
	} else {
		_id++;
	}
	if (_id && strncmp(engine_id, _id, strlen(engine_id)))
		goto end;

	if (!ENGINE_set_id(e, engine_id))
		goto end;

	if (!ENGINE_set_name(e, engine_name))
		goto end;

	ERR_load_KCTL_strings();

	if (!ENGINE_set_RSA(e, kctl_get_RSA_methods()))
		goto end;

	if (!ENGINE_set_DH(e, kctl_get_DH_methods()))
		goto end;

	ret = 1;
	ret &= ENGINE_set_destroy_function(e, kctl_engine_desctroy);

end:
	return ret;
}

static int kctl_engine_desctroy(ENGINE *e)
{
	kctl_free_RSA_methods();	
	kctl_free_DH_methods();
	ERR_unload_KCTL_strings();
	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_kctl_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()
