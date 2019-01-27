/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
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
 * p11_cert.c - Handle certificates residing on a PKCS11 token
 *
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
 */

#include "libp11-int.h"
#include <string.h>

static int pkcs11_find_certs(PKCS11_TOKEN *);
static int pkcs11_next_cert(PKCS11_CTX *, PKCS11_TOKEN *, CK_SESSION_HANDLE);
static int pkcs11_init_cert(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o, PKCS11_CERT **);

/*
 * Enumerate all certs on the card
 */
int pkcs11_enumerate_certs(PKCS11_TOKEN *token,
		PKCS11_CERT **certp, unsigned int *countp)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	int rv;

	/* Make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 0))
		return -1;

	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = pkcs11_find_certs(token);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	if (rv < 0) {
		pkcs11_destroy_certs(token);
		return -1;
	}

	if (certp)
		*certp = tpriv->certs;
	if (countp)
		*countp = tpriv->ncerts;
	return 0;
}

/**
 * Remove a certificate from the associated token
 */ 
int pkcs11_remove_certificate(PKCS11_CERT *cert){
	PKCS11_SLOT *slot = CERT2SLOT(cert);
	PKCS11_CTX *ctx = CERT2CTX(cert);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	CK_ATTRIBUTE search_parameters[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 1)){
		return -1;
	}
	
	pkcs11_addattr_int(search_parameters + n++, CKA_CLASS, CKO_CERTIFICATE);
	if (cert->id && cert->id_len){
		pkcs11_addattr(search_parameters + n++, CKA_ID, cert->id, cert->id_len);
	}
	if (cert->label){
	 	pkcs11_addattr_s(search_parameters + n++, CKA_LABEL, cert->label);
	}

	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, search_parameters, n));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_CERTIFICATE, rv);
	
	rv = CRYPTOKI_call(ctx, C_FindObjects(spriv->session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_CERTIFICATE, rv);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));
	if (count!=1){
		pkcs11_zap_attrs(search_parameters, n);
		return -1;
	}
	rv = CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, obj));
	if (rv != CKR_OK){
		pkcs11_zap_attrs(search_parameters, n);
		return -1;
	}
	pkcs11_zap_attrs(search_parameters, n);
	return 0;
}

/*
 * Find certificate matching a key
 */
PKCS11_CERT *pkcs11_find_certificate(PKCS11_KEY *key)
{
	PKCS11_KEY_private *kpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert;
	unsigned int n, count;

	kpriv = PRIVKEY(key);
	if (PKCS11_enumerate_certs(KEY2TOKEN(key), &cert, &count))
		return NULL;
	for (n = 0; n < count; n++, cert++) {
		cpriv = PRIVCERT(cert);
		if (cpriv->id_len == kpriv->id_len
				&& !memcmp(cpriv->id, kpriv->id, kpriv->id_len))
			return cert;
	}
	return NULL;
}

/*
 * Find all certs of a given type (public or private)
 */
static int pkcs11_find_certs(PKCS11_TOKEN *token)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_CLASS cert_search_class;
	CK_ATTRIBUTE cert_search_attrs[] = {
		{CKA_CLASS, &cert_search_class, sizeof(cert_search_class)},
	};
	int rv, res = -1;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	cert_search_class = CKO_CERTIFICATE;
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(spriv->session, cert_search_attrs, 1));
	CRYPTOKI_checkerr(CKR_F_PKCS11_FIND_CERTS, rv);

	do {
		res = pkcs11_next_cert(ctx, token, spriv->session);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_cert(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
		CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_NEXT_CERT, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_cert(ctx, token, session, obj, NULL))
		return -1;

	return 0;
}

static int pkcs11_init_cert(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, PKCS11_CERT ** ret)
{
	PKCS11_TOKEN_private *tpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert, *tmp;
	unsigned char *data;
	CK_CERTIFICATE_TYPE cert_type;
	size_t size;
	int i;

	(void)ctx;
	(void)session;

	/* Ignore unknown certificate types */
	size = sizeof(CK_CERTIFICATE_TYPE);
	if (pkcs11_getattr_var(token, obj, CKA_CERTIFICATE_TYPE, (CK_BYTE *)&cert_type, &size))
		return -1;
	if (cert_type != CKC_X_509)
		return 0;

	/* Prevent re-adding existing PKCS#11 object handles */
	/* TODO: Rewrite the O(n) algorithm as O(log n),
	 * or it may be too slow with a large number of certificates */
	for (i=0; i < PRIVTOKEN(token)->ncerts; ++i)
		if (PRIVCERT(PRIVTOKEN(token)->certs + i)->object == obj)
			return 0;

	/* Allocate memory */
	cpriv = OPENSSL_malloc(sizeof(PKCS11_CERT_private));
	if (cpriv == NULL)
		return -1;
	memset(cpriv, 0, sizeof(PKCS11_CERT_private));
	tpriv = PRIVTOKEN(token);
	tmp = OPENSSL_realloc(tpriv->certs,
		(tpriv->ncerts + 1) * sizeof(PKCS11_CERT));
	if (tmp == NULL)
		return -1;
	tpriv->certs = tmp;
	cert = tpriv->certs + tpriv->ncerts++;
	memset(cert, 0, sizeof(PKCS11_CERT));

	/* Fill public properties */
	pkcs11_getattr_alloc(token, obj, CKA_LABEL, (CK_BYTE **)&cert->label, NULL);
	size = 0;
	if (!pkcs11_getattr_alloc(token, obj, CKA_VALUE, &data, &size)) {
		const unsigned char *p = data;

		cert->x509 = d2i_X509(NULL, &p, (long)size);
		OPENSSL_free(data);
	}
	cert->id_len = 0;
	pkcs11_getattr_alloc(token, obj, CKA_ID, &cert->id, &cert->id_len);

	/* Fill private properties */
	cert->_private = cpriv;
	cpriv->object = obj;
	cpriv->parent = token;
	cpriv->id_len = sizeof cpriv->id;
	if (pkcs11_getattr_var(token, obj, CKA_ID, cpriv->id, &cpriv->id_len))
		cpriv->id_len = 0;

	if (ret)
		*ret = cert;
	return 0;
}

/*
 * Destroy all certs
 */
void pkcs11_destroy_certs(PKCS11_TOKEN *token)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);

	while (tpriv->ncerts > 0) {
		PKCS11_CERT *cert = &tpriv->certs[--(tpriv->ncerts)];

		if (cert->x509)
			X509_free(cert->x509);
		OPENSSL_free(cert->label);
		if (cert->id)
			OPENSSL_free(cert->id);
		if (cert->_private != NULL)
			OPENSSL_free(cert->_private);
	}
	if (tpriv->certs)
		OPENSSL_free(tpriv->certs);
	tpriv->certs = NULL;
	tpriv->ncerts = 0;
}

/*
 * Store certificate
 */
int pkcs11_store_certificate(PKCS11_TOKEN *token, X509 *x509, char *label,
		unsigned char *id, size_t id_len, PKCS11_CERT ** ret_cert)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;
	const EVP_MD* evp_md;
	CK_MECHANISM_TYPE ckm_md;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;

	/* Now build the template */
	pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_CERTIFICATE);
	pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
	pkcs11_addattr_int(attrs + n++, CKA_CERTIFICATE_TYPE, CKC_X_509);
	pkcs11_addattr_obj(attrs + n++, CKA_SUBJECT,
		(pkcs11_i2d_fn)i2d_X509_NAME, X509_get_subject_name(x509));
	pkcs11_addattr_obj(attrs + n++, CKA_ISSUER,
		(pkcs11_i2d_fn)i2d_X509_NAME, X509_get_issuer_name(x509));

	/* Get digest algorithm from x509 certificate */
	evp_md = EVP_get_digestbynid(X509_get_signature_nid(x509));
	switch (EVP_MD_type(evp_md)) {
	default:
	case NID_sha1:
		ckm_md = CKM_SHA_1;
		break;
	case NID_sha224:
		ckm_md = CKM_SHA224;
		break;
	case NID_sha256:
		ckm_md = CKM_SHA256;
		break;
	case NID_sha512:
		ckm_md = CKM_SHA512;
		break;
	case NID_sha384:
		ckm_md = CKM_SHA384;
		break;
	}

	/* Set hash algorithm; default is SHA-1 */
	pkcs11_addattr_int(attrs + n++, CKA_NAME_HASH_ALGORITHM, ckm_md);
	if(X509_pubkey_digest(x509,evp_md,md,&md_len))
		pkcs11_addattr(attrs + n++, CKA_HASH_OF_SUBJECT_PUBLIC_KEY,md,md_len);

	pkcs11_addattr_obj(attrs + n++, CKA_VALUE, (pkcs11_i2d_fn)i2d_X509, x509);
	if (label)
		pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(spriv->session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(CKR_F_PKCS11_STORE_CERTIFICATE, rv);

	/* Gobble the key object */
	return pkcs11_init_cert(ctx, token, spriv->session, object, ret_cert);
}

/* vim: set noexpandtab: */
