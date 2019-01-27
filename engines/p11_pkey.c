/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2017 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2017-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "libp11-int.h"
#include <string.h>

static int (*orig_pkey_rsa_sign_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_rsa_sign) (EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
static int (*orig_pkey_rsa_decrypt_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_rsa_decrypt) (EVP_PKEY_CTX *ctx,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen);

#ifndef OPENSSL_NO_EC
static int (*orig_pkey_ec_sign_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_ec_sign) (EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
#endif /* OPENSSL_NO_EC */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
struct evp_pkey_method_st {
	int pkey_id;
	int flags;
	int (*init) (EVP_PKEY_CTX *ctx);
	int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
	void (*cleanup) (EVP_PKEY_CTX *ctx);
	int (*paramgen_init) (EVP_PKEY_CTX *ctx);
	int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
	int (*keygen_init) (EVP_PKEY_CTX *ctx);
	int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
	int (*sign_init) (EVP_PKEY_CTX *ctx);
	int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen);
	int (*verify_init) (EVP_PKEY_CTX *ctx);
	int (*verify) (EVP_PKEY_CTX *ctx,
		const unsigned char *sig, size_t siglen,
		const unsigned char *tbs, size_t tbslen);
	int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
	int (*verify_recover) (EVP_PKEY_CTX *ctx,
		unsigned char *rout, size_t *routlen,
		const unsigned char *sig, size_t siglen);
	int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
	int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		EVP_MD_CTX *mctx);
	int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
	int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
		EVP_MD_CTX *mctx);
	int (*encrypt_init) (EVP_PKEY_CTX *ctx);
	int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen);
	int (*decrypt_init) (EVP_PKEY_CTX *ctx);
	int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen);
	int (*derive_init) (EVP_PKEY_CTX *ctx);
	int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
	int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
	int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
} /* EVP_PKEY_METHOD */ ;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)

typedef struct {
	int nbits;
	BIGNUM *pub_exp;
	int gentmp[2];
	int pad_mode;
	const EVP_MD *md;
	const EVP_MD *mgf1md;
	int saltlen;
	unsigned char *tbuf;
} RSA_PKEY_CTX;

static int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*pmd = rctx->md;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*pmd = rctx->md;
	return 1;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L

static int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*pmd = rctx->mgf1md;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *padding)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*padding = rctx->pad_mode;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*saltlen = rctx->saltlen;
	return 1;
}

static void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src)
{
	memcpy((int *)dst + 2, (int *)src + 2, 25 * sizeof(void (*)()));
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x100020d0L || defined(LIBRESSL_VERSION_NUMBER)
static void EVP_PKEY_meth_get_sign(EVP_PKEY_METHOD *pmeth,
		int (**psign_init) (EVP_PKEY_CTX *ctx),
		int (**psign) (EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen))
{
	if (psign_init)
		*psign_init = pmeth->sign_init;
	if (psign)
		*psign = pmeth->sign;
}

static void EVP_PKEY_meth_get_decrypt(EVP_PKEY_METHOD *pmeth,
		int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
		int (**pdecrypt) (EVP_PKEY_CTX *ctx,
			unsigned char *out,
			size_t *outlen,
			const unsigned char *in,
			size_t inlen))
{
	if (pdecrypt_init)
		*pdecrypt_init = pmeth->decrypt_init;
	if (pdecrypt)
		*pdecrypt = pmeth->decrypt;
}
#endif

static CK_MECHANISM_TYPE pkcs11_md2ckm(const EVP_MD *md)
{
	switch (EVP_MD_type(md)) {
	case NID_sha1:
		return CKM_SHA_1;
	case NID_sha224:
		return CKM_SHA224;
	case NID_sha256:
		return CKM_SHA256;
	case NID_sha512:
		return CKM_SHA512;
	case NID_sha384:
		return CKM_SHA384;
	default:
		return 0;
	}
}

static CK_RSA_PKCS_MGF_TYPE pkcs11_md2ckg(const EVP_MD *md)
{
	switch (EVP_MD_type(md)) {
	case NID_sha1:
		return CKG_MGF1_SHA1;
	case NID_sha224:
		return CKG_MGF1_SHA224;
	case NID_sha256:
		return CKG_MGF1_SHA256;
	case NID_sha512:
		return CKG_MGF1_SHA512;
	case NID_sha384:
		return CKG_MGF1_SHA384;
	default:
		return 0;
	}
}

static int pkcs11_params_pss(CK_RSA_PKCS_PSS_PARAMS *pss,
		EVP_PKEY_CTX *ctx)
{
	const EVP_MD *sig_md, *mgf1_md;
	EVP_PKEY *evp_pkey;
	int salt_len;

	/* retrieve PSS parameters */
	if (EVP_PKEY_CTX_get_signature_md(ctx, &sig_md) <= 0)
		return -1;
	if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1_md) <= 0)
		return -1;
	if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &salt_len))
		return -1;
	switch (salt_len) {
	case -1:
		salt_len = EVP_MD_size(sig_md);
		break;
	case -2:
		evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
		if (evp_pkey == NULL)
			return -1;
		salt_len = EVP_PKEY_size(evp_pkey) - EVP_MD_size(sig_md) - 2;
		if (((EVP_PKEY_bits(evp_pkey) - 1) & 0x7) == 0)
			salt_len--;
		if (salt_len < 0) /* integer underflow detected */
			return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "salt_len=%d sig_md=%s mdf1_md=%s\n",
		salt_len, EVP_MD_name(sig_md), EVP_MD_name(mgf1_md));
#endif

	/* fill the CK_RSA_PKCS_PSS_PARAMS structure */
	memset(pss, 0, sizeof(CK_RSA_PKCS_PSS_PARAMS));
	pss->hashAlg = pkcs11_md2ckm(sig_md);
	pss->mgf = pkcs11_md2ckg(mgf1_md);
	if (!pss->hashAlg || !pss->mgf)
		return -1;
	pss->sLen = salt_len;
	return 0;
}

static int pkcs11_params_oaep(CK_RSA_PKCS_OAEP_PARAMS *oaep,
		EVP_PKEY_CTX *ctx)
{
	const EVP_MD *oaep_md, *mgf1_md;

	/* retrieve OAEP parameters */
	if (EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &oaep_md) <= 0)
		return -1;
	if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1_md) <= 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "oaep_md=%s mdf1_md=%s\n",
		EVP_MD_name(oaep_md), EVP_MD_name(mgf1_md));
#endif

	/* fill the CK_RSA_PKCS_OAEP_PARAMS structure */
	memset(oaep, 0, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
	oaep->hashAlg = pkcs11_md2ckm(oaep_md);
	oaep->mgf = pkcs11_md2ckg(mgf1_md);
	if (!oaep->hashAlg || !oaep->mgf)
		return -1;
	/* we do not support the OAEP "label" parameter yet... */
	oaep->source = 0UL; /* empty parameter (label) */
	oaep->pSourceData = NULL;
	oaep->ulSourceDataLen = 0;
	return 0;
}

static int pkcs11_try_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	PKCS11_KEY *key;
	int rv = 0;
	CK_ULONG size = *siglen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	PKCS11_CTX_private *cpriv;
	const EVP_MD *sig_md;

#ifdef DEBUG
	fprintf(stderr, "%s:%d pkcs11_try_pkey_rsa_sign() "
		"sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__, sig, *siglen, tbs, tbslen);
#endif
	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;
	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL)
		return -1;
	key = pkcs11_get_ex_data_rsa(rsa);
	if (check_key_fork(key) < 0)
		return -1;
	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);
	cpriv = PRIVCTX(ctx);

	if (evp_pkey_ctx == NULL)
		return -1;
	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;
	if (tbslen != (size_t)EVP_MD_size(sig_md))
		return -1;

	if (!cpriv->sign_initialized) {
		int padding;
		CK_MECHANISM mechanism;
		CK_RSA_PKCS_PSS_PARAMS pss_params;

		memset(&mechanism, 0, sizeof mechanism);
		EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding);
		switch (padding) {
		case RSA_PKCS1_PSS_PADDING:
#ifdef DEBUG
			fprintf(stderr, "%s:%d padding=RSA_PKCS1_PSS_PADDING\n",
				__FILE__, __LINE__);
#endif
			if (pkcs11_params_pss(&pss_params, evp_pkey_ctx) < 0)
				return -1;
			mechanism.mechanism = CKM_RSA_PKCS_PSS;
			mechanism.pParameter = &pss_params;
			mechanism.ulParameterLen = sizeof pss_params;
			break;
		default:
#ifdef DEBUG
			fprintf(stderr, "%s:%d unsupported padding: %d\n",
				__FILE__, __LINE__, padding);
#endif
			return -1;
		} /* end switch(padding) */

		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = CRYPTOKI_call(ctx,
			C_SignInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
	}
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE_PTR)tbs, tbslen, sig, &size));
	cpriv->sign_initialized = !rv && sig == NULL;
	if (!cpriv->sign_initialized)
		CRYPTO_THREAD_unlock(cpriv->rwlock);
#ifdef DEBUG
	fprintf(stderr, "%s:%d C_SignInit or C_Sign rv=%d\n",
		__FILE__, __LINE__, rv);
#endif

	if (rv != CKR_OK)
		return -1;
	*siglen = size;
	return 1;
}

static int pkcs11_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_try_pkey_rsa_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_rsa_sign)(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static int pkcs11_try_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	PKCS11_KEY *key;
	int rv = 0;
	CK_ULONG size = *outlen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	PKCS11_CTX_private *cpriv;

#ifdef DEBUG
	fprintf(stderr, "%s:%d pkcs11_try_pkey_rsa_decrypt() "
		"out=%p *outlen=%lu in=%p inlen=%lu\n",
		__FILE__, __LINE__, out, *outlen, in, inlen);
#endif
	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;
	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL)
		return -1;
	key = pkcs11_get_ex_data_rsa(rsa);
	if (check_key_fork(key) < 0)
		return -1;
	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);
	cpriv = PRIVCTX(ctx);

	if (evp_pkey_ctx == NULL)
		return -1;

	if (!cpriv->decrypt_initialized) {
		int padding;
		CK_MECHANISM mechanism;
		CK_RSA_PKCS_OAEP_PARAMS oaep_params;

		memset(&mechanism, 0, sizeof mechanism);
		EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding);
		switch (padding) {
		case RSA_PKCS1_OAEP_PADDING:
#ifdef DEBUG
			fprintf(stderr, "%s:%d padding=RSA_PKCS1_OAEP_PADDING\n",
				__FILE__, __LINE__);
#endif
			if (pkcs11_params_oaep(&oaep_params, evp_pkey_ctx) < 0)
				return -1;
			mechanism.mechanism = CKM_RSA_PKCS_OAEP;
			mechanism.pParameter = &oaep_params;
			mechanism.ulParameterLen = sizeof oaep_params;
			break;
		case CKM_RSA_PKCS:
#ifdef DEBUG
			fprintf(stderr, "%s:%d padding=CKM_RSA_PKCS\n",
				__FILE__, __LINE__);
#endif
			mechanism.pParameter = NULL;
			mechanism.ulParameterLen = 0;
			break;
		default:
#ifdef DEBUG
			fprintf(stderr, "%s:%d unsupported padding: %d\n",
				__FILE__, __LINE__, padding);
#endif
			return -1;
		} /* end switch(padding) */

		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = CRYPTOKI_call(ctx,
			C_DecryptInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
	}
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Decrypt(spriv->session, (CK_BYTE_PTR)in, inlen, out, &size));
	cpriv->decrypt_initialized = !rv && out == NULL;
	if (!cpriv->decrypt_initialized)
		CRYPTO_THREAD_unlock(cpriv->rwlock);
#ifdef DEBUG
	fprintf(stderr, "%s:%d C_DecryptInit or C_Decrypt rv=%d\n",
		__FILE__, __LINE__, rv);
#endif

	if (rv != CKR_OK)
		return -1;
	*outlen = size;
	return 1;
}

static int pkcs11_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	int ret;

	ret = pkcs11_try_pkey_rsa_decrypt(evp_pkey_ctx, out, outlen, in, inlen);
	if (ret < 0)
		ret = (*orig_pkey_rsa_decrypt)(evp_pkey_ctx, out, outlen, in, inlen);
	return ret;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_rsa()
{
	EVP_PKEY_METHOD *orig_meth, *new_meth;

	orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_RSA);
	EVP_PKEY_meth_get_sign(orig_meth,
		&orig_pkey_rsa_sign_init, &orig_pkey_rsa_sign);
	EVP_PKEY_meth_get_decrypt(orig_meth,
		&orig_pkey_rsa_decrypt_init,
		&orig_pkey_rsa_decrypt);

	new_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA,
		EVP_PKEY_FLAG_AUTOARGLEN);

	EVP_PKEY_meth_copy(new_meth, orig_meth);

	EVP_PKEY_meth_set_sign(new_meth,
		orig_pkey_rsa_sign_init, pkcs11_pkey_rsa_sign);
	EVP_PKEY_meth_set_decrypt(new_meth,
		orig_pkey_rsa_decrypt_init, pkcs11_pkey_rsa_decrypt);

	return new_meth;
}

#ifndef OPENSSL_NO_EC

static int pkcs11_try_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	PKCS11_KEY *key;
	int rv = 0;
	CK_ULONG size = *siglen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	PKCS11_CTX_private *cpriv;
	const EVP_MD *sig_md;
	ECDSA_SIG *ossl_sig;

#ifdef DEBUG
	fprintf(stderr, "%s:%d pkcs11_try_pkey_ec_sign() "
		"sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__, sig, *siglen, tbs, tbslen);
#endif

	ossl_sig = ECDSA_SIG_new();
	if (ossl_sig == NULL)
		return-1;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;

	eckey = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
	if (eckey == NULL)
		return -1;

	if (*siglen < (size_t)ECDSA_size(eckey))
		return -1;

	key = pkcs11_get_ex_data_ec(eckey);
	if (check_key_fork(key) < 0)
		return -1;

	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);
	cpriv = PRIVCTX(ctx);

	if (evp_pkey_ctx == NULL)
		return -1;

	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;

	if (tbslen < (size_t)EVP_MD_size(sig_md))
		return -1;

	if (!cpriv->sign_initialized) {
		CK_MECHANISM mechanism;
		memset(&mechanism, 0, sizeof mechanism);

		mechanism.mechanism = CKM_ECDSA;

		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = CRYPTOKI_call(ctx,
			C_SignInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
	}
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE_PTR)tbs, tbslen, sig, &size));

	cpriv->sign_initialized = !rv && sig == NULL;
	if (!cpriv->sign_initialized)
		CRYPTO_THREAD_unlock(cpriv->rwlock);
#ifdef DEBUG
	fprintf(stderr, "%s:%d C_SignInit or C_Sign rv=%d\n",
		__FILE__, __LINE__, rv);
#endif

	if (rv == CKR_OK) {
		BIGNUM *r = BN_bin2bn(sig, size/2, NULL);
		BIGNUM *s = BN_bin2bn(sig + size/2, size/2, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		ECDSA_SIG_set0(ossl_sig, r, s);
#else
		BN_free(ossl_sig->r);
		ossl_sig->r = r;
		BN_free(ossl_sig->s);
		ossl_sig->s = s;
#endif
		*siglen = i2d_ECDSA_SIG(ossl_sig, &sig);
	}

	ECDSA_SIG_free(ossl_sig);

	if (rv != CKR_OK)
		return -1;

	return 1;
}

static int pkcs11_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_try_pkey_ec_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_ec_sign)(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_ec()
{
	EVP_PKEY_METHOD *orig_meth, *new_meth;

	orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_sign(orig_meth,
		&orig_pkey_ec_sign_init, &orig_pkey_ec_sign);

	new_meth = EVP_PKEY_meth_new(EVP_PKEY_EC,
		EVP_PKEY_FLAG_AUTOARGLEN);

	EVP_PKEY_meth_copy(new_meth, orig_meth);

	EVP_PKEY_meth_set_sign(new_meth,
		orig_pkey_ec_sign_init, pkcs11_pkey_ec_sign);

	return new_meth;
}

#endif /* OPENSSL_NO_EC */

int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
		EVP_PKEY_EC,
		0
	};
	static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
	static EVP_PKEY_METHOD *pkey_method_ec = NULL;

	(void)e; /* squash the unused parameter warning */
	/* all PKCS#11 engines currently share the same pkey_meths */

	if (!pmeth) { /* get the list of supported nids */
		*nids = pkey_nids;
		return sizeof(pkey_nids) / sizeof(int) - 1;
	}

	/* get the EVP_PKEY_METHOD */
	switch (nid) {
	case EVP_PKEY_RSA:
		if (pkey_method_rsa == NULL)
			pkey_method_rsa = pkcs11_pkey_method_rsa();
		if (pkey_method_rsa == NULL)
			return 0;
		*pmeth = pkey_method_rsa;
		return 1; /* success */
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		if (pkey_method_ec == NULL)
			pkey_method_ec = pkcs11_pkey_method_ec();
		if (pkey_method_ec == NULL)
			return 0;
		*pmeth = pkey_method_ec;
		return 1; /* success */
#endif /* OPENSSL_NO_EC */
	}
	*pmeth = NULL;
	return 0;
}

/* vim: set noexpandtab: */
