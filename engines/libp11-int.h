/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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

#ifndef _LIBP11_INT_H
#define _LIBP11_INT_H

#include "libp11.h"

#define CRYPTOKI_EXPORTS
#include "pkcs11.h"

#if OPENSSL_VERSION_NUMBER < 0x10100004L || defined(LIBRESSL_VERSION_NUMBER)
typedef int PKCS11_RWLOCK;
#else
typedef CRYPTO_RWLOCK *PKCS11_RWLOCK;
#endif

/* get private implementations of PKCS11 structures */

/*
 * PKCS11_CTX: context for a PKCS11 implementation
 */
typedef struct pkcs11_ctx_private {
	CK_FUNCTION_LIST_PTR method;
	void *handle;
	char *init_args;
	UI_METHOD *ui_method; /* UI_METHOD for CKU_CONTEXT_SPECIFIC PINs */
	void *ui_user_data;
	unsigned int forkid;
	PKCS11_RWLOCK rwlock;
	int sign_initialized;
	int decrypt_initialized;
} PKCS11_CTX_private;
#define PRIVCTX(ctx)		((PKCS11_CTX_private *) ((ctx)->_private))

typedef struct pkcs11_slot_private {
	PKCS11_CTX *parent;
	unsigned char haveSession, loggedIn;
	CK_SLOT_ID id;
	CK_SESSION_HANDLE session;
	unsigned int forkid;
	int prev_rw; /* the rw status the session was open */

	/* options used in last PKCS11_login */
	char *prev_pin;
	int prev_so;
} PKCS11_SLOT_private;
#define PRIVSLOT(slot)		((PKCS11_SLOT_private *) ((slot)->_private))
#define SLOT2CTX(slot)		(PRIVSLOT(slot)->parent)

typedef struct pkcs11_keys {
	int num;
	PKCS11_KEY *keys;
} PKCS11_keys;

typedef struct pkcs11_token_private {
	PKCS11_SLOT *parent;
	PKCS11_keys prv, pub;
	int ncerts;
	PKCS11_CERT *certs;
} PKCS11_TOKEN_private;
#define PRIVTOKEN(token)	((PKCS11_TOKEN_private *) ((token)->_private))
#define TOKEN2SLOT(token)	(PRIVTOKEN(token)->parent)
#define TOKEN2CTX(token)	SLOT2CTX(TOKEN2SLOT(token))

typedef struct pkcs11_key_ops {
	int type; /* EVP_PKEY_xxx */
	EVP_PKEY *(*get_evp_key) (PKCS11_KEY *);
	void (*update_ex_data) (PKCS11_KEY *);
} PKCS11_KEY_ops;

typedef struct pkcs11_key_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	CK_BBOOL always_authenticate;
	unsigned char id[255];
	size_t id_len;
	PKCS11_KEY_ops *ops;
	unsigned int forkid;
} PKCS11_KEY_private;
#define PRIVKEY(key)		((PKCS11_KEY_private *) (key)->_private)
#define KEY2SLOT(key)		TOKEN2SLOT(KEY2TOKEN(key))
#define KEY2TOKEN(key)		(PRIVKEY(key)->parent)
#define KEY2CTX(key)		TOKEN2CTX(KEY2TOKEN(key))

typedef struct pkcs11_cert_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	unsigned char id[255];
	size_t id_len;
} PKCS11_CERT_private;
#define PRIVCERT(cert)		((PKCS11_CERT_private *) (cert)->_private)
#define CERT2SLOT(cert)		TOKEN2SLOT(CERT2TOKEN(cert))
#define CERT2TOKEN(cert)	(PRIVCERT(cert)->parent)
#define CERT2CTX(cert)		TOKEN2CTX(CERT2TOKEN(cert))

extern PKCS11_KEY_ops pkcs11_rsa_ops;
extern PKCS11_KEY_ops *pkcs11_ec_ops;

/*
 * Internal functions
 */
#define CRYPTOKI_checkerr(f, rv) \
	do { \
		if (rv) { \
			CKRerr(f, rv); \
			return -1; \
		} \
		ERR_clear_error(); \
	} while (0)
#define CRYPTOKI_call(ctx, func_and_args) \
	PRIVCTX(ctx)->method->func_and_args
extern int ERR_load_CKR_strings(void);

/* Memory allocation */
#define PKCS11_DUP(s) \
	pkcs11_strdup((char *) s, sizeof(s))
extern char *pkcs11_strdup(char *, size_t);

/* Emulate the OpenSSL 1.1 locking API for older OpenSSL versions */
#if OPENSSL_VERSION_NUMBER < 0x10100004L || defined(LIBRESSL_VERSION_NUMBER)
int CRYPTO_THREAD_lock_new();
void CRYPTO_THREAD_lock_free(int);
#define CRYPTO_THREAD_write_lock(type) \
	if(type) CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_THREAD_unlock(type) \
	if(type) CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_THREAD_read_lock(type) \
	if(type) CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_THREAD_read_unlock(type) \
	if(type) CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#endif

/* Emulate the OpenSSL 1.1 getters */
#if OPENSSL_VERSION_NUMBER < 0x10100003L || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_PKEY_get0_RSA(key) ((key)->pkey.rsa)
#define EVP_PKEY_get0_EC_KEY(key) ((key)->pkey.ec)
#endif

/* Reinitializing the module afer fork (if detected) */
extern unsigned int get_forkid();
extern int check_fork(PKCS11_CTX *ctx);
extern int check_slot_fork(PKCS11_SLOT *slot);
extern int check_token_fork(PKCS11_TOKEN *token);
extern int check_key_fork(PKCS11_KEY *key);
extern int check_cert_fork(PKCS11_CERT *cert);

/* Other internal functions */
extern void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
extern CK_RV C_UnloadModule(void *module);
extern void pkcs11_destroy_keys(PKCS11_TOKEN *, unsigned int);
extern void pkcs11_destroy_certs(PKCS11_TOKEN *);
extern int pkcs11_reload_key(PKCS11_KEY *);
extern int pkcs11_reopen_session(PKCS11_SLOT * slot);
extern int pkcs11_relogin(PKCS11_SLOT * slot);

/* Managing object attributes */
extern int pkcs11_getattr_var(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
	unsigned int, CK_BYTE *, size_t *);
extern int pkcs11_getattr_val(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
	unsigned int, void *, size_t);
extern int pkcs11_getattr_alloc(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
	unsigned int, CK_BYTE **, size_t *);
/*
 * Caution: the BIGNUM ** shall reference either a NULL pointer or a
 * pointer to a valid BIGNUM.
 */
extern int pkcs11_getattr_bn(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
	unsigned int, BIGNUM **);

#define key_getattr_var(key, t, p, s) \
	pkcs11_getattr_var(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (p), (s))

#define key_getattr_val(key, t, p, s) \
	pkcs11_getattr_val(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (p), (s))

#define key_getattr_alloc(key, t, p, s) \
	pkcs11_getattr_alloc(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (p), (s))

/*
 * Caution: bn shall reference either a NULL pointer or a pointer to
 * a valid BIGNUM.
 */
#define key_getattr_bn(key, t, bn) \
	pkcs11_getattr_bn(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (bn))

typedef int (*pkcs11_i2d_fn) (void *, unsigned char **);
extern void pkcs11_addattr(CK_ATTRIBUTE_PTR, int, const void *, size_t);
extern void pkcs11_addattr_int(CK_ATTRIBUTE_PTR, int, unsigned long);
extern void pkcs11_addattr_bool(CK_ATTRIBUTE_PTR, int, int);
extern void pkcs11_addattr_s(CK_ATTRIBUTE_PTR, int, const char *);
extern void pkcs11_addattr_bn(CK_ATTRIBUTE_PTR, int, const BIGNUM *);
extern void pkcs11_addattr_obj(CK_ATTRIBUTE_PTR, int, pkcs11_i2d_fn, void *);
extern void pkcs11_zap_attrs(CK_ATTRIBUTE_PTR, unsigned int);

/* Internal implementation of current features */

/* Allocate the context */
extern PKCS11_CTX *pkcs11_CTX_new(void);

/* Specify any private PKCS#11 module initialization args, if necessary */
extern void pkcs11_CTX_init_args(PKCS11_CTX * ctx, const char * init_args);

/* Load a PKCS#11 module */
extern int pkcs11_CTX_load(PKCS11_CTX * ctx, const char * ident);

/* Reinitialize a PKCS#11 module (after a fork) */
extern int pkcs11_CTX_reload(PKCS11_CTX * ctx);

/* Unload a PKCS#11 module */
extern void pkcs11_CTX_unload(PKCS11_CTX * ctx);

/* Free a libp11 context */
extern void pkcs11_CTX_free(PKCS11_CTX * ctx);

/* Open a session in RO or RW mode */
extern int pkcs11_open_session(PKCS11_SLOT * slot, int rw, int relogin);

/* Get a list of all slots */
extern int pkcs11_enumerate_slots(PKCS11_CTX * ctx,
			PKCS11_SLOT **slotsp, unsigned int *nslotsp);

/* Get the slot_id from a slot as it is stored in private */
extern unsigned long pkcs11_get_slotid_from_slot(PKCS11_SLOT *slot);

/* Free the list of slots allocated by PKCS11_enumerate_slots() */
extern void pkcs11_release_all_slots(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots);

/* Find the first slot with a token */
extern PKCS11_SLOT *pkcs11_find_token(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots);

/* Find the next slot with a token */
extern PKCS11_SLOT *pkcs11_find_next_token(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots,
			PKCS11_SLOT *current);

/* Check if user is already authenticated to a card */
extern int pkcs11_is_logged_in(PKCS11_SLOT * slot, int so, int * res);

/* Authenticate to the card */
extern int pkcs11_login(PKCS11_SLOT * slot, int so, const char *pin, int relogin);

/* De-authenticate from the card */
extern int pkcs11_logout(PKCS11_SLOT * slot);

/* Authenticate a private the key operation if needed */
int pkcs11_authenticate(PKCS11_KEY *key);

/* Get a list of keys associated with this token */
extern int pkcs11_enumerate_keys(PKCS11_TOKEN *token, unsigned int type,
	PKCS11_KEY **keys, unsigned int *nkeys);

/* Remove a key from the token */
extern int pkcs11_remove_key(PKCS11_KEY *key);

/* Get the key type (as EVP_PKEY_XXX) */
extern int pkcs11_get_key_type(PKCS11_KEY *key);

/* Returns a EVP_PKEY object with the private or public key */
extern EVP_PKEY *pkcs11_get_key(PKCS11_KEY *key, int isPrivate);

/* Find the corresponding certificate (if any) */
extern PKCS11_CERT *pkcs11_find_certificate(PKCS11_KEY *key);

/* Find the corresponding key (if any) */
extern PKCS11_KEY *pkcs11_find_key(PKCS11_CERT *cert);

/* Find the corresponding key (if any)  pub <-> priv base on ID */
extern PKCS11_KEY *pkcs11_find_key_from_key(PKCS11_KEY *key);

/* Get a list of all certificates associated with this token */
extern int pkcs11_enumerate_certs(PKCS11_TOKEN *token,
	PKCS11_CERT **certs, unsigned int *ncerts);

/* Remove a certificate from the token */
extern int pkcs11_remove_certificate(PKCS11_CERT *key);

/* Set UI method to allow retrieving CKU_CONTEXT_SPECIFIC PINs interactively */
extern int pkcs11_set_ui_method(PKCS11_CTX *ctx,
	UI_METHOD *ui_method, void *ui_user_data);

/* Initialize a token */
extern int pkcs11_init_token(PKCS11_TOKEN * token, const char *pin,
	const char *label);

/* Initialize the user PIN on a token */
extern int pkcs11_init_pin(PKCS11_TOKEN * token, const char *pin);

/* Change the user PIN on a token */
extern int pkcs11_change_pin(PKCS11_SLOT * slot,
	const char *old_pin, const char *new_pin);

/* Store private key on a token */
extern int pkcs11_store_private_key(PKCS11_TOKEN * token,
	EVP_PKEY * pk, char *label, unsigned char *id, size_t id_len);

/* Store public key on a token */
extern int pkcs11_store_public_key(PKCS11_TOKEN * token,
	EVP_PKEY * pk, char *label, unsigned char *id, size_t id_len);

/* Store certificate on a token */
extern int pkcs11_store_certificate(PKCS11_TOKEN * token, X509 * x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert);

/* Access the random number generator */
extern int pkcs11_seed_random(PKCS11_SLOT *, const unsigned char *s, unsigned int s_len);
extern int pkcs11_generate_random(PKCS11_SLOT *, unsigned char *r, unsigned int r_len);

/* Internal implementation of deprecated features */

/* Generate and store a private key on the token */
extern int pkcs11_generate_key(PKCS11_TOKEN * token,
	int algorithm, unsigned int bits,
	char *label, unsigned char* id, size_t id_len);

/* Get the RSA key modulus size (in bytes) */
extern int pkcs11_get_key_size(PKCS11_KEY *);

/* Get the RSA key modules as BIGNUM */
extern int pkcs11_get_key_modulus(PKCS11_KEY *, BIGNUM **);

/* Get the RSA key public exponent as BIGNUM */
extern int pkcs11_get_key_exponent(PKCS11_KEY *, BIGNUM **);

/* Sign with the RSA private key */
extern int pkcs11_sign(int type,
	const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key);

/* This function has never been implemented */
extern int pkcs11_verify(int type,
	const unsigned char *m, unsigned int m_len,
	unsigned char *signature, unsigned int siglen, PKCS11_KEY * key);

/* Encrypts data using the private key */
extern int pkcs11_private_encrypt(
	int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY * rsa, int padding);

/* Decrypts data using the private key */
extern int pkcs11_private_decrypt(
	int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY * key, int padding);

/* Retrieve PKCS11_KEY from an RSA key */
extern PKCS11_KEY *pkcs11_get_ex_data_rsa(const RSA *rsa);

/* Retrieve PKCS11_KEY from an EC_KEY */
extern PKCS11_KEY *pkcs11_get_ex_data_ec(const EC_KEY *ec);

#endif

/* vim: set noexpandtab: */
