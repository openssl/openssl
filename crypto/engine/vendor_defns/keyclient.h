#ifndef HEADER_KEYCLIENT_H
#define HEADER_KEYCLIENT_H

/* Stop name-munging before it begins */
#ifdef __cplusplus
extern "C" {
#endif

/* This header is consistent with the "libclient" header but has been modified
 * and pruned (esp. virtually all explanations and comments have gone) for
 * inclusion in openssl. */

#if 0 /* Not used in openssl */
/* The obligatory nonsense associated with porting shared libraries to win32 */
#if defined(KSCLIENT_BUILD)
#define KC_INTERFACE __declspec(dllexport)
#elif defined(KSCLIENT_USE)
#define KC_INTERFACE __declspec(dllimport)
#else
#define KC_INTERFACE
#endif
#else
#define KC_INTERFACE
#endif

/* 
 * TYPES
 */

typedef struct _keyclient_ctx	keyclient_ctx;

typedef struct _ctx_locking_table {
	/* These functions return zero for failure. */
	int (*ctx_lock)(const void *, unsigned int);
	int (*ctx_unlock)(const void *, unsigned int);
} ctx_locking_table;

typedef struct _global_locking_table {
	void (*lock)(void);
	void (*unlock)(void);
} global_locking_table;

#define KC_MAX_PUBKEY_ASN 512	/* If the key doesn't fit, don't try */
typedef struct _keyclient_key_t {
	enum {
		KC_KEY_RSA = 0,
		KC_KEY_DSA = 1
	} key_type;
	unsigned int der_len;
	unsigned char der[KC_MAX_PUBKEY_ASN];
} keyclient_key_t;

/*
 * ENUMS
 */

/* Different "operation" types */
typedef enum {
	KC_FIRST_OP_INDEX = 0,
	/* RSA operations */
	KC_RSA_FIRST_OP = KC_FIRST_OP_INDEX,
	KC_RSA_PUB_ENCRYPT = KC_RSA_FIRST_OP,
	KC_RSA_PUB_DECRYPT,
	KC_RSA_PRIV_ENCRYPT,
	KC_RSA_PRIV_DECRYPT,
	KC_RSA_SIGN,
	KC_RSA_VERIFY,
	KC_RSA_LAST_OP = KC_RSA_VERIFY,
	/* DSA operations */
	KC_DSA_FIRST_OP,
	KC_DSA_SIGN = KC_DSA_FIRST_OP,
	KC_DSA_VERIFY,
	KC_DSA_LAST_OP = KC_DSA_VERIFY,
	/* Round it out */
	KC_LAST_OP_INDEX = KC_DSA_LAST_OP
} keyclient_op_t;

/* Different "padding" types */
typedef enum {
	KC_FIRST_PAD_INDEX = 0,
	/* No padding (works for RSA and DSA) */
	KC_PADDING_NONE = KC_FIRST_PAD_INDEX,
	KC_PADDING_DSA = KC_PADDING_NONE,
	/* RSA padding schemes */
	KC_PADDING_RSA_PKCS1,
	KC_PADDING_RSA_SSLV23,
	KC_PADDING_RSA_PKCS1_OAEP,
	/* Round it out */
	KC_LAST_PAD_INDEX = KC_PADDING_RSA_PKCS1_OAEP
} keyclient_pad_t;

/* Different "return" types */
typedef enum {
	KC_RET_OK = 0,
	KC_RET_ERR_INTERNAL, /* Bug */
	KC_RET_ERR_BAD_ADDRESS, /* Bad address string */
	KC_RET_ERR_NO_CONNECT, /* Can not connect to the address */
	KC_RET_ERR_MEM, /* Memory error, insufficient space or some such */
	KC_RET_ERR_REF_MISUSE, /* Reference count corruption */
	KC_RET_ERR_INVALID_LOCKS, /* Caller provided inconsistent callbacks */
	KC_RET_ERR_REQUEST_ENCODING, /* Error encoding the request */
	KC_RET_ERR_RESPONSE_DECODING, /* Error decoding the response */
	KC_RET_ERR_SELECT, /* Error in underlying select() call */
	KC_RET_ERR_NETWORK_IO, /* Error in network I/O calls */
	KC_RET_ERR_CTX_LOCK, /* lock() callback returned failure! */
	KC_RET_ERR_CTX_UNLOCK, /* unlock() callback returned failure! */
	KC_RET_ERR_REQUEST_SPACE, /* The request can not fit in the provided space */
	KC_RET_ERR_RESULT_SPACE, /* The response can not fit in the provided space */
	KC_RET_ERR_RESPONSE_MISMATCH, /* We received someone else's response? */
	KC_RET_ERR_PRIVATE_EMBED, /* Cannot embed private keys in requests */
	KC_RET_ERR_FLAG_COMBO, /* A bad combination of bitwise flags was used */
	KC_RET_ERR_NULL1, /* Parameter 1 was NULL */
	KC_RET_ERR_NULL2, /* Parameter 2 was NULL */
	KC_RET_ERR_NULL3, /* Parameter 3 was NULL */
	KC_RET_ERR_NULL4, /* Parameter 4 was NULL */
	KC_RET_ERR_NULL5, /* Parameter 5 was NULL */
	KC_RET_ERR_NULL6, /* Parameter 6 was NULL */
	KC_RET_ERR_NULL7, /* Parameter 7 was NULL */
	KC_RET_ERR_NULL8, /* Parameter 8 was NULL */
	KC_RET_ERR_NON_NULL1, /* Parameter 1 was *not* NULL */
	KC_RET_ERR_NON_NULL2, /* Parameter 2 was *not* NULL */
	KC_RET_ERR_NON_NULL3, /* Parameter 3 was *not* NULL */
	KC_RET_ERR_NON_NULL4, /* Parameter 4 was *not* NULL */
	KC_RET_ERR_NON_NULL5, /* Parameter 5 was *not* NULL */
	KC_RET_ERR_NON_NULL6, /* Parameter 6 was *not* NULL */
	KC_RET_ERR_NON_NULL7, /* Parameter 7 was *not* NULL */
	KC_RET_ERR_NON_NULL8, /* Parameter 8 was *not* NULL */
	KC_RET_ERR_BAD_RANGE1, /* Parameter 1 was out of range */
	KC_RET_ERR_BAD_RANGE2, /* Parameter 2 was out of range */
	KC_RET_ERR_BAD_RANGE3, /* Parameter 3 was out of range */
	KC_RET_ERR_BAD_RANGE4, /* Parameter 4 was out of range */
	KC_RET_ERR_BAD_RANGE5, /* Parameter 5 was out of range */
	KC_RET_ERR_BAD_RANGE6, /* Parameter 6 was out of range */
	KC_RET_ERR_BAD_RANGE7, /* Parameter 7 was out of range */
	KC_RET_ERR_BAD_RANGE8, /* Parameter 8 was out of range */
	/* These errors are all "soft" - if keyclient_keyop() returns one of
	 * these values, then the operation completed successfully but the
	 * underlying payload of the response had its internal "error" value set
	 * to something other than KS_OP_ERR_OK. */
	KC_RET_SOFT_UNKNOWN_OPERATION = 200, /* The keyserver doesn't support that */
	KC_RET_SOFT_NO_SUCH_KEY, /* The keyserver doesn't have that key */
	KC_RET_SOFT_NO_DATA, /* Data was required but was not supplied */
	KC_RET_SOFT_OP_FAILED, /* The key operation on the server did not work */
	KC_RET_SOFT_MISC /* An error that is not currently aliased was received */
} KC_RET;


/* Context flags (used in keyclient_create) */

#define KC_FLAG_USE_LOCKING		0x01
#define KC_FLAG_NO_LOCKING		0x02
#define KC_FLAG_PERSISTENT_CONN		0x04
#define KC_FLAG_PID_CHECK		0x08
#define KC_FLAG_PERSISTENT_RETRY	0x10
#define KC_FLAG_PERSISTENT_LATE		0x20


/*
 * FUNCTIONS
 */

KC_INTERFACE KC_RET keyclient_set_global_locks(const global_locking_table *locking);
typedef KC_RET t_keyclient_set_global_locks(const global_locking_table *locking);

KC_INTERFACE KC_RET keyclient_create(keyclient_ctx **ctx, const char *target_string,
		unsigned int flags, const ctx_locking_table *locking);
typedef KC_RET t_keyclient_create(keyclient_ctx **ctx, const char *target_string,
		unsigned int flags, const ctx_locking_table *locking);

KC_INTERFACE KC_RET keyclient_release(keyclient_ctx *ctx);
typedef KC_RET t_keyclient_release(keyclient_ctx *ctx);

KC_INTERFACE KC_RET keyclient_dup(keyclient_ctx *ctx);
typedef KC_RET t_keyclient_dup(keyclient_ctx *ctx);

KC_INTERFACE KC_RET keyclient_get_uid(const keyclient_ctx *ctx, unsigned int *uid);
typedef KC_RET t_keyclient_get_uid(const keyclient_ctx *ctx, unsigned int *uid);

KC_INTERFACE KC_RET keyclient_keyop(keyclient_ctx *ctx, keyclient_op_t operation,
		const unsigned char *data, unsigned int data_len,
		unsigned char *result, unsigned int *result_len,
		keyclient_pad_t padding, const unsigned char *keyhash);
typedef KC_RET t_keyclient_keyop(keyclient_ctx *ctx, keyclient_op_t operation,
		const unsigned char *data, unsigned int data_len,
		unsigned char *result, unsigned int *result_len,
		keyclient_pad_t padding, const unsigned char *keyhash);

KC_INTERFACE KC_RET keyclient_pubkeyop(keyclient_ctx *ctx, keyclient_op_t operation,
		const unsigned char *data, unsigned int data_len,
		unsigned char *result, unsigned int *result_len,
		keyclient_pad_t padding, const keyclient_key_t *pubkey);
typedef KC_RET t_keyclient_pubkeyop(keyclient_ctx *ctx, keyclient_op_t operation,
		const unsigned char *data, unsigned int data_len,
		unsigned char *result, unsigned int *result_len,
		keyclient_pad_t padding, const keyclient_key_t *pubkey);

typedef struct _keyclient_symbol_table {
	t_keyclient_set_global_locks *keyclient_set_global_locks;
	t_keyclient_create *keyclient_create;
	t_keyclient_release *keyclient_release;
	t_keyclient_dup *keyclient_dup;
	t_keyclient_get_uid *keyclient_get_uid;
	t_keyclient_keyop *keyclient_keyop;
	t_keyclient_pubkeyop *keyclient_pubkeyop;
} keyclient_symbol_table;

KC_INTERFACE void keyclient_bind_symbols(keyclient_symbol_table *funcs);
typedef void t_keyclient_bind_symbols(keyclient_symbol_table *funcs);

#ifdef __cplusplus
}
#endif

#endif
