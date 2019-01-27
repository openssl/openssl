/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
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

/**
 * @file libp11.h
 * @brief libp11 header file
 */

#ifndef _LIB11_H
#define _LIB11_H

#include "p11_err.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

int ERR_load_CKR_strings(void);
void ERR_unload_CKR_strings(void);
void ERR_CKR_error(int function, int reason, char *file, int line);
# define CKRerr(f,r) ERR_CKR_error((f),(r),__FILE__,__LINE__)
int ERR_get_CKR_code(void);

/*
 * The purpose of this library is to provide a simple PKCS11
 * interface to OpenSSL application that wish to use a previously
 * initialized card (as opposed to initializing it, etc).
 *
 * I am therefore making some simplifying assumptions:
 *
 *  -	no support for any operations that alter the card,
 *  	i.e. readonly-login
 */

/** PKCS11 key object (public or private) */
typedef struct PKCS11_key_st {
	char *label;
	unsigned char *id;
	size_t id_len;
	unsigned char isPrivate;	/**< private key present? */
	unsigned char needLogin;	/**< login to read private key? */
	EVP_PKEY *evp_key;		/**< initially NULL, need to call PKCS11_load_key */
	void *_private;
} PKCS11_KEY;

/** PKCS11 certificate object */
typedef struct PKCS11_cert_st {
	char *label;
	unsigned char *id;
	size_t id_len;
	X509 *x509;
	void *_private;
} PKCS11_CERT;

/** PKCS11 token: smart card or USB key */
typedef struct PKCS11_token_st {
	char *label;
	char *manufacturer;
	char *model;
	char *serialnr;
	unsigned char initialized;
	unsigned char loginRequired;
	unsigned char secureLogin;
	unsigned char userPinSet;
	unsigned char readOnly;
	unsigned char hasRng;
	unsigned char userPinCountLow;
	unsigned char userPinFinalTry;
	unsigned char userPinLocked;
	unsigned char userPinToBeChanged;
	unsigned char soPinCountLow;
	unsigned char soPinFinalTry;
	unsigned char soPinLocked;
	unsigned char soPinToBeChanged;
	void *_private;
} PKCS11_TOKEN;

/** PKCS11 slot: card reader */
typedef struct PKCS11_slot_st {
	char *manufacturer;
	char *description;
	unsigned char removable;
	PKCS11_TOKEN *token;	/**< NULL if no token present */
	void *_private;
} PKCS11_SLOT;

/** PKCS11 context */
typedef struct PKCS11_ctx_st {
	char *manufacturer;
	char *description;
	void *_private;
} PKCS11_CTX;

/**
 * Create a new libp11 context
 *
 * This should be the first function called in the use of libp11
 * @return an allocated context
 */
extern PKCS11_CTX *PKCS11_CTX_new(void);

/**
 * Specify any private PKCS#11 module initialization args, if necessary
 *
 * @return none
 */
extern void PKCS11_CTX_init_args(PKCS11_CTX * ctx, const char * init_args);

/**
 * Load a PKCS#11 module
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param ident PKCS#11 library filename
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_CTX_load(PKCS11_CTX * ctx, const char * ident);

/**
 * Reinitialize a PKCS#11 module (after a fork)
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_CTX_reload(PKCS11_CTX * ctx);

/**
 * Unload a PKCS#11 module
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 */
extern void PKCS11_CTX_unload(PKCS11_CTX * ctx);

/**
 * Free a libp11 context
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 */
extern void PKCS11_CTX_free(PKCS11_CTX * ctx);

/** Open a session in RO or RW mode
 *
 * @param slot slot descriptor returned by PKCS11_find_token() or PKCS11_enumerate_slots()
 * @param rw open in read/write mode is mode != 0, otherwise in read only mode
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_open_session(PKCS11_SLOT * slot, int rw);

/**
 * Get a list of all slots
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slotsp pointer on a list of slots
 * @param nslotsp size of the allocated list
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_enumerate_slots(PKCS11_CTX * ctx,
			PKCS11_SLOT **slotsp, unsigned int *nslotsp);

/**
 * Get the slot_id from a slot as it is stored in private
 *
 * @param slotp pointer on a slot
 * @retval the slotid
 */
extern unsigned long PKCS11_get_slotid_from_slot(PKCS11_SLOT *slotp);

/**
 * Free the list of slots allocated by PKCS11_enumerate_slots()
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slots list of slots allocated by PKCS11_enumerate_slots()
 * @param nslots size of the list
 */
extern void PKCS11_release_all_slots(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots);

/**
 * Find the first slot with a token
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slots list of slots allocated by PKCS11_enumerate_slots()
 * @param nslots size of the list
 * @retval !=NULL pointer on a slot structure
 * @retval NULL error
 */
PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots);

/**
 * Find the next slot with a token
 *
 * @param ctx context allocated by PKCS11_CTX_new()
 * @param slots list of slots allocated by PKCS11_enumerate_slots()
 * @param nslots size of the list
 * @param slot current slot
 * @retval !=NULL pointer on a slot structure
 * @retval NULL error
 */
PKCS11_SLOT *PKCS11_find_next_token(PKCS11_CTX * ctx,
			PKCS11_SLOT *slots, unsigned int nslots,
		   	PKCS11_SLOT *slot);

/**
 * Check if user is already authenticated to a card
 *
 * @param slot slot returned by PKCS11_find_token()
 * @param so kind of login to check: CKU_SO if != 0, otherwise CKU_USER
 * @param res pointer to return value: 1 if logged in, 0 if not logged in
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_is_logged_in(PKCS11_SLOT * slot, int so, int * res);

/**
 * Authenticate to the card
 *
 * @param slot slot returned by PKCS11_find_token()
 * @param so login as CKU_SO if != 0, otherwise login as CKU_USER
 * @param pin PIN value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_login(PKCS11_SLOT * slot, int so, const char *pin);

/**
 * De-authenticate from the card
 *
 * @param slot slot returned by PKCS11_find_token()
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_logout(PKCS11_SLOT * slot);

/* Get a list of private keys associated with this token */
extern int PKCS11_enumerate_keys(PKCS11_TOKEN *,
	PKCS11_KEY **, unsigned int *);

/* Remove the key from this token */
extern int PKCS11_remove_key(PKCS11_KEY *);

/* Get a list of public keys associated with this token */
extern int PKCS11_enumerate_public_keys(PKCS11_TOKEN *,
	PKCS11_KEY **, unsigned int *);

/* Get the key type (as EVP_PKEY_XXX) */
extern int PKCS11_get_key_type(PKCS11_KEY *);

/**
 * Returns a EVP_PKEY object for the private key
 *
 * @param   key  PKCS11_KEY object
 * @retval !=NULL reference to the EVP_PKEY object
 * @retval NULL error
 */
extern EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *key);

/**
 * Returns a EVP_PKEY object with the public key
 *
 * @param  key  PKCS11_KEY object
 * @retval !=NULL reference to the EVP_PKEY object
 * @retval NULL error
 */
extern EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *key);

/* Find the corresponding certificate (if any) */
extern PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *);

/* Find the corresponding key (if any) */
extern PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *);

/* Get a list of all certificates associated with this token */
extern int PKCS11_enumerate_certs(PKCS11_TOKEN *, PKCS11_CERT **, unsigned int *);

/* Remove the certificate from this token */
extern int PKCS11_remove_certificate(PKCS11_CERT *);

/* Set UI method to allow retrieving CKU_CONTEXT_SPECIFIC PINs interactively */
extern int PKCS11_set_ui_method(PKCS11_CTX *ctx,
	UI_METHOD *ui_method, void *ui_user_data);

/**
 * Initialize a token
 *
 * @param token token descriptor (in general slot->token)
 * @param pin Security Officer PIN value
 * @param label new name of the token
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_init_token(PKCS11_TOKEN * token, const char *pin,
	const char *label);

/**
 * Initialize the user PIN on a token
 *
 * @param token token descriptor (in general slot->token)
 * @param pin new user PIN value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_init_pin(PKCS11_TOKEN * token, const char *pin);

/**
 * Change the currently used (either USER or SO) PIN on a token.
 *
 * @param slot slot returned by PKCS11_find_token()
 * @param old_pin old PIN value
 * @param new_pin new PIN value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_change_pin(PKCS11_SLOT * slot, const char *old_pin,
	const char *new_pin);

/**
 * Store private key on a token
 *
 * @param token token returned by PKCS11_find_token()
 * @param pk private key
 * @param label label for this key
 * @param id bytes to use as the id value
 * @param id_len length of the id value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label, unsigned char *id, size_t id_len);

/**
 * Store public key on a token
 *
 * @param token token returned by PKCS11_find_token()
 * @param pk private key
 * @param label label for this key
 * @param id bytes to use as the id value
 * @param id_len length of the id value
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label, unsigned char *id, size_t id_len);

/**
 * Store certificate on a token
 *
 * @param token token returned by PKCS11_find_token()
 * @param x509 x509 certificate object
 * @param label label for this certificate
 * @param id bytes to use as the id value
 * @param id_len length of the id value
 * @param ret_cert put new PKCS11_CERT object here
 * @retval 0 success
 * @retval -1 error
 */
extern int PKCS11_store_certificate(PKCS11_TOKEN * token, X509 * x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert);

/* Access the random number generator */
extern int PKCS11_seed_random(PKCS11_SLOT *slot, const unsigned char *s, unsigned int s_len);
extern int PKCS11_generate_random(PKCS11_SLOT *slot, unsigned char *r, unsigned int r_len);

/*
 * PKCS#11 implementation for OpenSSL methods
 */
RSA_METHOD *PKCS11_get_rsa_method(void);
/* Also define unsupported methods to retain backward compatibility */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L && !defined(LIBRESSL_VERSION_NUMBER)
EC_KEY_METHOD *PKCS11_get_ec_key_method(void);
void *PKCS11_get_ecdsa_method(void);
void *PKCS11_get_ecdh_method(void);
#else
void *PKCS11_get_ec_key_method(void);
ECDSA_METHOD *PKCS11_get_ecdsa_method(void);
ECDH_METHOD *PKCS11_get_ecdh_method(void);
#endif
int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid);

/**
 * Load PKCS11 error strings
 *
 * Call this function to be able to use ERR_reason_error_string(ERR_get_error())
 * to get an textual version of the latest error code
 */
extern void ERR_load_PKCS11_strings(void);

#if defined(_LIBP11_INT_H)
	/* Deprecated functions will no longer be exported in libp11 0.5.0 */
	/* They are, however, used internally in OpenSSL method definitions */
#define P11_DEPRECATED(msg)
#elif defined(_MSC_VER)
#define P11_DEPRECATED(msg) __declspec(deprecated(msg))
#elif defined(__GNUC__)
#if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= 40500
	/* GCC >= 4.5.0 supports printing a message */
#define P11_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
#else
#define P11_DEPRECATED(msg) __attribute__ ((deprecated))
#endif
#elif defined(__clang__)
#define P11_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
#else
#define P11_DEPRECATED(msg)
#endif

#define P11_DEPRECATED_FUNC \
	P11_DEPRECATED("This function will be removed in libp11 0.5.0")

/*
 * These functions will be removed from libp11, because they partially
 * duplicate the functionality OpenSSL provides for EVP_PKEY objects
 */

/**
 * Generate a private key on the token
 *
 * @param token token returned by PKCS11_find_token()
 * @param algorithm IGNORED (still here for backward compatibility)
 * @param bits size of the modulus in bits
 * @param label label for this key
 * @param id bytes to use as the id value
 * @param id_len length of the id value
 * @retval 0 success
 * @retval -1 error
 */
P11_DEPRECATED_FUNC extern int PKCS11_generate_key(PKCS11_TOKEN * token,
	int algorithm, unsigned int bits,
	char *label, unsigned char* id, size_t id_len);

/* Get the RSA key modulus size (in bytes) */
P11_DEPRECATED_FUNC extern int PKCS11_get_key_size(PKCS11_KEY *);

/* Get the RSA key modules as BIGNUM */
P11_DEPRECATED_FUNC extern int PKCS11_get_key_modulus(PKCS11_KEY *, BIGNUM **);

/* Get the RSA key public exponent as BIGNUM */
P11_DEPRECATED_FUNC extern int PKCS11_get_key_exponent(PKCS11_KEY *, BIGNUM **);

/* Sign with the EC private key */
P11_DEPRECATED_FUNC extern int PKCS11_ecdsa_sign(
	const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key);

/* Sign with the RSA private key */
P11_DEPRECATED_FUNC extern int PKCS11_sign(int type,
	const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, PKCS11_KEY * key);

/* This function has never been implemented */
P11_DEPRECATED_FUNC extern int PKCS11_verify(int type,
	const unsigned char *m, unsigned int m_len,
	unsigned char *signature, unsigned int siglen, PKCS11_KEY * key);

/* Encrypts data using the private key */
P11_DEPRECATED_FUNC extern int PKCS11_private_encrypt(
	int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY * rsa, int padding);

/**
 * Decrypts data using the private key
 *
 * @param  flen     length of the encrypted data
 * @param  from     encrypted data
 * @param  to       output buffer (MUST be a least flen bytes long)
 * @param  key      private key object
 * @param  padding  padding algorithm to be used
 * @return the length of the decrypted data or 0 if an error occurred
 */
P11_DEPRECATED_FUNC extern int PKCS11_private_decrypt(
	int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY * key, int padding);

/* Function codes */
# define CKR_F_PKCS11_CHANGE_PIN                          100
# define CKR_F_PKCS11_CHECK_TOKEN                         101
# define CKR_F_PKCS11_CTX_LOAD                            102
# define CKR_F_PKCS11_ECDH_DERIVE                         103
# define CKR_F_PKCS11_ECDSA_SIGN                          104
# define CKR_F_PKCS11_ENUMERATE_SLOTS                     105
# define CKR_F_PKCS11_FIND_CERTS                          106
# define CKR_F_PKCS11_FIND_KEYS                           107
# define CKR_F_PKCS11_GENERATE_RANDOM                     108
# define CKR_F_PKCS11_GETATTR_ALLOC                       109
# define CKR_F_PKCS11_GETATTR_BN                          110
# define CKR_F_PKCS11_GETATTR_INT                         111
# define CKR_F_PKCS11_INIT_PIN                            112
# define CKR_F_PKCS11_INIT_SLOT                           113
# define CKR_F_PKCS11_INIT_TOKEN                          114
# define CKR_F_PKCS11_IS_LOGGED_IN                        115
# define CKR_F_PKCS11_LOGIN                               116
# define CKR_F_PKCS11_LOGOUT                              117
# define CKR_F_PKCS11_NEXT_CERT                           118
# define CKR_F_PKCS11_NEXT_KEY                            119
# define CKR_F_PKCS11_OPEN_SESSION                        120
# define CKR_F_PKCS11_PRIVATE_DECRYPT                     121
# define CKR_F_PKCS11_PRIVATE_ENCRYPT                     122
# define CKR_F_PKCS11_RELOAD_KEY                          123
# define CKR_F_PKCS11_REOPEN_SESSION                      124
# define CKR_F_PKCS11_SEED_RANDOM                         125
# define CKR_F_PKCS11_STORE_CERTIFICATE                   126
# define CKR_F_PKCS11_STORE_KEY                           127
# define CKR_F_PKCS11_REMOVE_KEY                          128
# define CKR_F_PKCS11_REMOVE_CERTIFICATE                  129
# define CKR_F_PKCS11_GENERATE_KEY                        130

/* Backward compatibility of error function codes */
#define PKCS11_F_PKCS11_CHANGE_PIN CKR_F_PKCS11_CHANGE_PIN
#define PKCS11_F_PKCS11_CHECK_TOKEN CKR_F_PKCS11_CHECK_TOKEN
#define PKCS11_F_PKCS11_CTX_LOAD CKR_F_PKCS11_CTX_LOAD
#define PKCS11_F_PKCS11_ECDH_DERIVE CKR_F_PKCS11_ECDH_DERIVE
#define PKCS11_F_PKCS11_ECDSA_SIGN CKR_F_PKCS11_ECDSA_SIGN
#define PKCS11_F_PKCS11_ENUMERATE_SLOTS CKR_F_PKCS11_ENUMERATE_SLOTS
#define PKCS11_F_PKCS11_FIND_CERTS CKR_F_PKCS11_FIND_CERTS
#define PKCS11_F_PKCS11_FIND_KEYS CKR_F_PKCS11_FIND_KEYS
#define PKCS11_F_PKCS11_GENERATE_RANDOM CKR_F_PKCS11_GENERATE_RANDOM
#define PKCS11_F_PKCS11_GETATTR_ALLOC CKR_F_PKCS11_GETATTR_ALLOC
#define PKCS11_F_PKCS11_GETATTR_BN CKR_F_PKCS11_GETATTR_BN
#define PKCS11_F_PKCS11_GETATTR_INT CKR_F_PKCS11_GETATTR_INT
#define PKCS11_F_PKCS11_INIT_PIN CKR_F_PKCS11_INIT_PIN
#define PKCS11_F_PKCS11_INIT_SLOT CKR_F_PKCS11_INIT_SLOT
#define PKCS11_F_PKCS11_INIT_TOKEN CKR_F_PKCS11_INIT_TOKEN
#define PKCS11_F_PKCS11_IS_LOGGED_IN CKR_F_PKCS11_IS_LOGGED_IN
#define PKCS11_F_PKCS11_LOGIN CKR_F_PKCS11_LOGIN
#define PKCS11_F_PKCS11_LOGOUT CKR_F_PKCS11_LOGOUT
#define PKCS11_F_PKCS11_NEXT_CERT CKR_F_PKCS11_NEXT_CERT
#define PKCS11_F_PKCS11_NEXT_KEY CKR_F_PKCS11_NEXT_KEY
#define PKCS11_F_PKCS11_OPEN_SESSION CKR_F_PKCS11_OPEN_SESSION
#define PKCS11_F_PKCS11_PRIVATE_DECRYPT CKR_F_PKCS11_PRIVATE_DECRYPT
#define PKCS11_F_PKCS11_PRIVATE_ENCRYPT CKR_F_PKCS11_PRIVATE_ENCRYPT
#define PKCS11_F_PKCS11_RELOAD_KEY CKR_F_PKCS11_RELOAD_KEY
#define PKCS11_F_PKCS11_REOPEN_SESSION CKR_F_PKCS11_REOPEN_SESSION
#define PKCS11_F_PKCS11_SEED_RANDOM CKR_F_PKCS11_SEED_RANDOM
#define PKCS11_F_PKCS11_STORE_CERTIFICATE CKR_F_PKCS11_STORE_CERTIFICATE
#define PKCS11_F_PKCS11_STORE_KEY CKR_F_PKCS11_STORE_KEY
#define PKCS11_F_PKCS11_REMOVE_KEY CKR_F_PKCS11_REMOVE_KEY
#define PKCS11_F_PKCS11_REMOVE_CERTIFICATE CKR_F_PKCS11_REMOVE_CERTIFICATE
#define PKCS11_F_PKCS11_GENERATE_KEY CKR_F_PKCS11_GENERATE_KEY

/* Backward compatibility of error reason codes */
#define PKCS11_LOAD_MODULE_ERROR                          P11_R_LOAD_MODULE_ERROR
#define PKCS11_MODULE_LOADED_ERROR                        -1
#define PKCS11_SYMBOL_NOT_FOUND_ERROR                     -1
#define PKCS11_NOT_SUPPORTED                              P11_R_NOT_SUPPORTED
#define PKCS11_NO_SESSION                                 P11_R_NO_SESSION
#define PKCS11_KEYGEN_FAILED                              P11_R_KEYGEN_FAILED
#define PKCS11_UI_FAILED                                  P11_R_UI_FAILED

/* Backward compatibility emulation of the ERR_LIB_PKCS11 constant.
 * We currently use two separate variables for library error codes:
 * one for imported PKCS#11 module errors, and one for our own libp11 errors.
 * We return the value for PKCS#11, as it is more likely to be needed. */
#define ERR_LIB_PKCS11 (ERR_get_CKR_code())

#ifdef __cplusplus
}
#endif
#endif

/* vim: set noexpandtab: */
