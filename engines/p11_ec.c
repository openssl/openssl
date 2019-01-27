/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2011, 2013 Douglas E. Engert <deengert@anl.gov>
 * Copyright (C) 2014, 2016 Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

/*
 * This file implements the handling of EC keys stored on a
 * PKCS11 token
 */

#include "libp11-int.h"
#include <string.h>

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif

#ifndef OPENSSL_NO_EC

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
typedef int (*compute_key_fn)(unsigned char **, size_t *,
	const EC_POINT *, const EC_KEY *);
#else
typedef int (*compute_key_fn)(void *, size_t,
	const EC_POINT *, const EC_KEY *,
	void *(*)(const void *, size_t, void *, size_t *));
#endif
static compute_key_fn ossl_ecdh_compute_key;

static int ec_ex_index = 0;

/********** Missing ECDSA_METHOD functions for OpenSSL < 1.1.0 */

typedef ECDSA_SIG *(*sign_sig_fn)(const unsigned char *, int,
	const BIGNUM *, const BIGNUM *, EC_KEY *);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* ecdsa_method maintains unchanged layout between 0.9.8 and 1.0.2 */

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdsa_method {
	char *name;
	sign_sig_fn ecdsa_do_sign;
	void (*ecdsa_sign_setup)();
	void (*ecdsa_do_verify)();
	int flags;
	char *app_data;
};

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)

/* Define missing functions */

ECDSA_METHOD *ECDSA_METHOD_new(const ECDSA_METHOD *m)
{
	ECDSA_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDSA_METHOD));
	if (out == NULL)
		return NULL;
	if (m)
		memcpy(out, m, sizeof(ECDSA_METHOD));
	else
		memset(out, 0, sizeof(ECDSA_METHOD));
	return out;
}

void ECDSA_METHOD_free(ECDSA_METHOD *m)
{
	OPENSSL_free(m);
}

void ECDSA_METHOD_set_sign(ECDSA_METHOD *m, sign_sig_fn f)
{
	m->ecdsa_do_sign = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10002000L */

/********** Missing ECDH_METHOD functions for OpenSSL < 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

/* ecdh_method maintains unchanged layout between 0.9.8 and 1.0.2 */

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdh_method {
	char *name;
	compute_key_fn compute_key;
	int flags;
	char *data;
};

/* Define missing functions */

ECDH_METHOD *ECDH_METHOD_new(const ECDH_METHOD *m)
{
	ECDH_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDH_METHOD));
	if (out == NULL)
		return NULL;
	if (m)
		memcpy(out, m, sizeof(ECDH_METHOD));
	else
		memset(out, 0, sizeof(ECDH_METHOD));
	return out;
}

void ECDH_METHOD_free(ECDH_METHOD *m)
{
	OPENSSL_free(m);
}

void ECDH_METHOD_get_compute_key(ECDH_METHOD *m, compute_key_fn *f)
{
	*f = m->compute_key;
}

void ECDH_METHOD_set_compute_key(ECDH_METHOD *m, compute_key_fn f)
{
	m->compute_key = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/********** Manage EC ex_data */

/* NOTE: ECDH also uses ECDSA ex_data and *not* ECDH ex_data */
static void alloc_ec_ex_index()
{
	if (ec_ex_index == 0) {
		while (ec_ex_index == 0) /* Workaround for OpenSSL RT3710 */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L && !defined(LIBRESSL_VERSION_NUMBER)
			ec_ex_index = EC_KEY_get_ex_new_index(0, "libp11 ec_key",
				NULL, NULL, NULL);
#else
			ec_ex_index = ECDSA_get_ex_new_index(0, "libp11 ecdsa",
				NULL, NULL, NULL);
#endif
		if (ec_ex_index < 0)
			ec_ex_index = 0; /* Fallback to app_data */
	}
}

#if 0
/* TODO: Free the indexes on unload */
static void free_ec_ex_index()
{
	if (ec_ex_index > 0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
		/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, ec_ex_index);
#endif
		ec_ex_index = 0;
	}
}
#endif

/********** EVP_PKEY retrieval */

/* Retrieve EC parameters from key into ec
 * return nonzero on error */
static int pkcs11_get_params(EC_KEY *ec, PKCS11_KEY *key)
{
	CK_BYTE *params;
	size_t params_len = 0;
	const unsigned char *a;
	int rv;

	if (key_getattr_alloc(key, CKA_EC_PARAMS, &params, &params_len))
		return -1;

	a = params;
	rv = d2i_ECParameters(&ec, &a, (long)params_len) == NULL;
	OPENSSL_free(params);
	return rv;
}

/* Retrieve EC point from key into ec
 * return nonzero on error */
static int pkcs11_get_point(EC_KEY *ec, PKCS11_KEY *key)
{
	CK_BYTE *point;
	size_t point_len = 0;
	const unsigned char *a;
	ASN1_OCTET_STRING *os;
	int rv = -1;

	if (key == NULL ||
			key_getattr_alloc(key, CKA_EC_POINT, &point, &point_len))
		return -1;

	/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
	a = point;
	os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)point_len);
	if (os) {
		a = os->data;
		rv = o2i_ECPublicKey(&ec, &a, os->length) == NULL;
		ASN1_STRING_free(os);
	}
	if (rv) { /* Workaround for broken PKCS#11 modules */
		a = point;
		rv = o2i_ECPublicKey(&ec, &a, (long)point_len) == NULL;
	}
	OPENSSL_free(point);
	return rv;
}

static EC_KEY *pkcs11_get_ec(PKCS11_KEY *key)
{
	EC_KEY *ec;
	int no_params, no_point;

	ec = EC_KEY_new();
	if (ec == NULL)
		return NULL;

	/* For OpenSSL req we need at least the
	 * EC_KEY_get0_group(ec_key)) to return the group.
	 * Continue even if it fails, as the sign operation does not need
	 * it if the PKCS#11 module or the hardware can figure this out
	 */
	no_params = pkcs11_get_params(ec, key);
	no_point = pkcs11_get_point(ec, key);
	if (no_point && key->isPrivate) /* Retry with the public key */
		no_point = pkcs11_get_point(ec, pkcs11_find_key_from_key(key));

	if (key->isPrivate && EC_KEY_get0_private_key(ec) == NULL) {
		EC_KEY_set_private_key(ec, BN_new());
	}

	/* A public keys requires both the params and the point to be present */
	if (!key->isPrivate && (no_params || no_point)) {
		EC_KEY_free(ec);
		return NULL;
	}

	return ec;
}

PKCS11_KEY *pkcs11_get_ex_data_ec(const EC_KEY *ec)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	return EC_KEY_get_ex_data(ec, ec_ex_index);
#else
	return ECDSA_get_ex_data((EC_KEY *)ec, ec_ex_index);
#endif
}

static void pkcs11_set_ex_data_ec(EC_KEY *ec, PKCS11_KEY *key)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	EC_KEY_set_ex_data(ec, ec_ex_index, key);
#else
	ECDSA_set_ex_data(ec, ec_ex_index, key);
#endif
}

static void pkcs11_update_ex_data_ec(PKCS11_KEY *key)
{
	EVP_PKEY *evp = key->evp_key;
	EC_KEY *ec;
	if (evp == NULL)
		return;
	if (EVP_PKEY_base_id(evp) != EVP_PKEY_EC)
		return;

	ec = EVP_PKEY_get1_EC_KEY(evp);
	pkcs11_set_ex_data_ec(ec, key);
	EC_KEY_free(ec);
}

/*
 * Get EC key material and stash pointer in ex_data
 * Note we get called twice, once for private key, and once for public
 * We need to get the EC_PARAMS and EC_POINT into both,
 * as lib11 dates from RSA only where all the pub key components
 * were also part of the private key.  With EC the point
 * is not in the private key, and the params may or may not be.
 *
 */
static EVP_PKEY *pkcs11_get_evp_key_ec(PKCS11_KEY *key)
{
	EVP_PKEY *pk;
	EC_KEY *ec;

	ec = pkcs11_get_ec(key);
	if (ec == NULL)
		return NULL;
	pk = EVP_PKEY_new();
	if (pk == NULL) {
		EC_KEY_free(ec);
		return NULL;
	}
	EVP_PKEY_set1_EC_KEY(pk, ec); /* Also increments the ec ref count */

	if (key->isPrivate) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		EC_KEY_set_method(ec, PKCS11_get_ec_key_method());
#else
		ECDSA_set_method(ec, PKCS11_get_ecdsa_method());
		ECDH_set_method(ec, PKCS11_get_ecdh_method());
#endif
	}
	/* TODO: Retrieve the ECDSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

	pkcs11_set_ex_data_ec(ec, key);
	EC_KEY_free(ec); /* Drops our reference to it */
	return pk;
}

/********** ECDSA signing */

/* Signature size is the issue, will assume the caller has a big buffer! */
/* No padding or other stuff needed.  We can call PKCS11 from here */
static int pkcs11_ecdsa_sign(const unsigned char *msg, unsigned int msg_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *key)
{
	int rv;
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG ck_sigsize;

	ck_sigsize = *siglen;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	CRYPTO_THREAD_write_lock(PRIVCTX(ctx)->rwlock);
	rv = CRYPTOKI_call(ctx,
		C_SignInit(spriv->session, &mechanism, kpriv->object));
	if (!rv && kpriv->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *)msg, msg_len, sigret, &ck_sigsize));
	CRYPTO_THREAD_unlock(PRIVCTX(ctx)->rwlock);

	if (rv) {
		CKRerr(CKR_F_PKCS11_ECDSA_SIGN, rv);
		return -1;
	}
	*siglen = ck_sigsize;

	return ck_sigsize;
}

/**
 * ECDSA signing method (replaces ossl_ecdsa_sign_sig)
 *
 *  @param  dgst     hash value to sign
 *  @param  dlen     length of the hash value
 *  @param  kinv     precomputed inverse k (from the sign_setup method)
 *  @param  rp       precomputed rp (from the sign_setup method)
 *  @param  ec       private EC signing key
 *  @return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
static ECDSA_SIG *pkcs11_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
		const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *ec)
{
	unsigned char sigret[512]; /* HACK for now */
	ECDSA_SIG *sig;
	PKCS11_KEY *key;
	unsigned int siglen;
	BIGNUM *r, *s, *order;

	(void)kinv; /* Precomputed values are not used for PKCS#11 */
	(void)rp; /* Precomputed values are not used for PKCS#11 */

	key = pkcs11_get_ex_data_ec(ec);
	if (check_key_fork(key) < 0) {
		sign_sig_fn orig_sign_sig;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		const EC_KEY_METHOD *meth = EC_KEY_OpenSSL();
		EC_KEY_METHOD_get_sign((EC_KEY_METHOD *)meth,
			NULL, NULL, &orig_sign_sig);
#else
		const ECDSA_METHOD *meth = ECDSA_OpenSSL();
		orig_sign_sig = meth->ecdsa_do_sign;
#endif
		return orig_sign_sig(dgst, dlen, kinv, rp, ec);
	}

	/* Truncate digest if its byte size is longer than needed */
	order = BN_new();
	if (order) {
		const EC_GROUP *group = EC_KEY_get0_group(ec);
		if (group && EC_GROUP_get_order(group, order, NULL)) {
			int klen = BN_num_bits(order);
			if (klen < 8*dlen)
				dlen = (klen+7)/8;
		}
		BN_free(order);
	}

	siglen = sizeof sigret;
	if (pkcs11_ecdsa_sign(dgst, dlen, sigret, &siglen, key) <= 0)
		return NULL;

	r = BN_bin2bn(sigret, siglen/2, NULL);
	s = BN_bin2bn(sigret + siglen/2, siglen/2, NULL);
	sig = ECDSA_SIG_new();
	if (sig == NULL)
		return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	ECDSA_SIG_set0(sig, r, s);
#else
	BN_free(sig->r);
	sig->r = r;
	BN_free(sig->s);
	sig->s = s;
#endif
	return sig;
}

/********** ECDH key derivation */

static CK_ECDH1_DERIVE_PARAMS *pkcs11_ecdh_params_alloc(
		const EC_GROUP *group, const EC_POINT *point)
{
	CK_ECDH1_DERIVE_PARAMS *parms;
	size_t len;
	unsigned char *buf = NULL;

	if (group == NULL || point == NULL)
		return NULL;
	len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (len == 0)
		return NULL;
	buf = OPENSSL_malloc(len);
	if (buf == NULL)
		return NULL;
	len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, len, NULL);
	if (len == 0) {
		OPENSSL_free(buf);
		return NULL;
	}

	parms = OPENSSL_malloc(sizeof(CK_ECDH1_DERIVE_PARAMS));
	if (parms == NULL) {
		OPENSSL_free(buf);
		return NULL;
	}
	parms->kdf = CKD_NULL;
	parms->pSharedData = NULL;
	parms->ulSharedDataLen = 0;
	parms->pPublicData = buf;
	parms->ulPublicDataLen = len;
	return parms;
}

static void pkcs11_ecdh_params_free(CK_ECDH1_DERIVE_PARAMS *parms)
{
	OPENSSL_free(parms->pPublicData);
	OPENSSL_free(parms);
}

/* initial code will only support what is needed for pkcs11_ec_ckey
 * i.e. CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE
 * and CK_EC_KDF_TYPE  supported by token
 * The secret key object is deleted
 *
 * In future CKM_ECMQV_DERIVE with CK_ECMQV_DERIVE_PARAMS
 * could also be supported, and the secret key object could be returned.
 */
static int pkcs11_ecdh_derive(unsigned char **out, size_t *outlen,
		const unsigned long ecdh_mechanism,
		const void *ec_params,
		void *outnewkey,
		PKCS11_KEY *key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_TOKEN *token = KEY2TOKEN(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	int rv;

	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_OBJECT_HANDLE *tmpnewkey = (CK_OBJECT_HANDLE *)outnewkey;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)}
	};

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism  = ecdh_mechanism;
	mechanism.pParameter =  (void*)ec_params;
	switch (ecdh_mechanism) {
		case CKM_ECDH1_DERIVE:
		case CKM_ECDH1_COFACTOR_DERIVE:
			mechanism.ulParameterLen  = sizeof(CK_ECDH1_DERIVE_PARAMS);
			break;
#if 0
		/* TODO */
		case CK_ECMQV_DERIVE_PARAMS:
			mechanism.ulParameterLen  = sizeof(CK_ECMQV_DERIVE_PARAMS);
			break;
#endif
		default:
			P11err(P11_F_PKCS11_ECDH_DERIVE, P11_R_NOT_SUPPORTED);
			return -1;
	}

	rv = CRYPTOKI_call(ctx, C_DeriveKey(spriv->session, &mechanism, kpriv->object, newkey_template, 5, &newkey));
	CRYPTOKI_checkerr(CKR_F_PKCS11_ECDH_DERIVE, rv);

	/* Return the value of the secret key and/or the object handle of the secret key */
	if (out && outlen) { /* pkcs11_ec_ckey only asks for the value */
		if (pkcs11_getattr_alloc(token, newkey, CKA_VALUE, out, outlen)) {
			CKRerr(CKR_F_PKCS11_ECDH_DERIVE, CKR_ATTRIBUTE_VALUE_INVALID);
			CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, newkey));
			return -1;
		}
	}
	if (tmpnewkey) /* For future use (not used by pkcs11_ec_ckey) */
		*tmpnewkey = newkey;
	else /* Destroy the temporary key */
		CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, newkey));

	return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)

/**
 * ECDH key derivation method (replaces ossl_ecdh_compute_key)
 * Implementation for OpenSSL 1.1.0-pre4 and later
 *
 * @param  out        derived key
 * @param  outlen     derived key length
 * @param  peer_point public key point
 * @param  ecdh       private key
 * @return 1 on success or 0 on error
 */
static int pkcs11_ec_ckey(unsigned char **out, size_t *outlen,
		const EC_POINT *peer_point, const EC_KEY *ecdh)
{
	PKCS11_KEY *key;
	CK_ECDH1_DERIVE_PARAMS *parms;
	unsigned char *buf = NULL;
	size_t buflen;
	int rv;

	key = pkcs11_get_ex_data_ec(ecdh);
	if (check_key_fork(key) < 0)
		return ossl_ecdh_compute_key(out, outlen, peer_point, ecdh);

	/* both peer and ecdh use same group parameters */
	parms = pkcs11_ecdh_params_alloc(EC_KEY_get0_group(ecdh), peer_point);
	if (parms == NULL)
		return 0;
	rv = pkcs11_ecdh_derive(&buf, &buflen, CKM_ECDH1_DERIVE, parms, NULL, key);
	pkcs11_ecdh_params_free(parms);
	if (rv < 0)
		return 0;

	*out = buf;
	*outlen = buflen;
	return 1;
}

#else

/**
 * ECDH key derivation method (replaces ossl_ecdh_compute_key)
 * Implementation for OpenSSL 1.1.0-pre3 and earlier
 *
 * @param  out        derived key
 * @param  outlen     derived key length
 * @param  peer_point public key point
 * @param  ecdh       private key
 * @param  KCF        key derivation function
 * @return the length of the derived key or -1 if an error occurred
 */
static int pkcs11_ec_ckey(void *out, size_t outlen,
		const EC_POINT *peer_point, const EC_KEY *ecdh,
		void *(*KDF)(const void *, size_t, void *, size_t *))
{
	PKCS11_KEY *key;
	CK_ECDH1_DERIVE_PARAMS *parms;
	unsigned char *buf = NULL;
	size_t buflen;
	int rv;

	key = pkcs11_get_ex_data_ec(ecdh);
	if (check_key_fork(key) < 0)
		return ossl_ecdh_compute_key(out, outlen, peer_point, ecdh, KDF);

	/* both peer and ecdh use same group parameters */
	parms = pkcs11_ecdh_params_alloc(EC_KEY_get0_group(ecdh), peer_point);
	if (parms == NULL)
		return -1;
	rv = pkcs11_ecdh_derive(&buf, &buflen, CKM_ECDH1_DERIVE, parms, NULL, key);
	pkcs11_ecdh_params_free(parms);
	if (rv < 0)
		return -1;

	if (KDF) {
		if (KDF(buf, buflen, out, &outlen) == NULL) {
			OPENSSL_free(buf);
			return -1;
		}
	} else {
		if (outlen > buflen)
			outlen = buflen;
		memcpy(out, buf, outlen);
	}
	OPENSSL_free(buf);
	return outlen;
}

#endif

/********** Set OpenSSL EC methods */

/*
 * Overload the default OpenSSL methods for ECDSA
 * If OpenSSL supports ECDSA_METHOD_new we will use it.
 * First introduced in 1.0.2, changed in 1.1-pre
 */

/* New way to allocate an ECDSA_METOD object */
/* OpenSSL 1.1 has single method  EC_KEY_METHOD for ECDSA and ECDH */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)

EC_KEY_METHOD *PKCS11_get_ec_key_method(void)
{
	static EC_KEY_METHOD *ops = NULL;
	int (*orig_sign)(int, const unsigned char *, int, unsigned char *,
		unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *) = NULL;

	alloc_ec_ex_index();
	if (ops == NULL) {
		ops = EC_KEY_METHOD_new((EC_KEY_METHOD *)EC_KEY_OpenSSL());
		EC_KEY_METHOD_get_sign(ops, &orig_sign, NULL, NULL);
		EC_KEY_METHOD_set_sign(ops, orig_sign, NULL, pkcs11_ecdsa_sign_sig);
		EC_KEY_METHOD_get_compute_key(ops, &ossl_ecdh_compute_key);
		EC_KEY_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

/* define old way to keep old engines working without ECDSA */
void *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

void *PKCS11_get_ecdh_method(void)
{
	return NULL;
}

#else /* OPENSSL_VERSION_NUMBER */

/* define new way to keep new engines from crashing with older libp11 */
void *PKCS11_get_ec_key_method(void)
{
	return NULL;
}

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	static ECDSA_METHOD *ops = NULL;

	if (ops == NULL) {
		alloc_ec_ex_index();
		ops = ECDSA_METHOD_new((ECDSA_METHOD *)ECDSA_OpenSSL());
		ECDSA_METHOD_set_sign(ops, pkcs11_ecdsa_sign_sig);
	}
	return ops;
}

ECDH_METHOD *PKCS11_get_ecdh_method(void)
{
	static ECDH_METHOD *ops = NULL;

	if (ops == NULL) {
		alloc_ec_ex_index();
		ops = ECDH_METHOD_new((ECDH_METHOD *)ECDH_OpenSSL());
		ECDH_METHOD_get_compute_key(ops, &ossl_ecdh_compute_key);
		ECDH_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

#endif /* OPENSSL_VERSION_NUMBER */

PKCS11_KEY_ops pkcs11_ec_ops_s = {
	EVP_PKEY_EC,
	pkcs11_get_evp_key_ec,
	pkcs11_update_ex_data_ec,
};
PKCS11_KEY_ops *pkcs11_ec_ops = {&pkcs11_ec_ops_s};

#else /* OPENSSL_NO_EC */

PKCS11_KEY_ops *pkcs11_ec_ops = {NULL};

/* if not built with EC or OpenSSL does not support ECDSA
 * add these routines so engine_pkcs11 can be built now and not
 * require further changes */
#warning "ECDSA support not built with libp11"

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

#endif /* OPENSSL_NO_EC */

/* TODO: remove this function in libp11 0.5.0 */
void PKCS11_ecdsa_method_free(void)
{
	/* no op */
}

/* vim: set noexpandtab: */
