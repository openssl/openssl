/* crypto/engine/hw_keyclient.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2001.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include "engine_int.h"
#include <openssl/engine.h>

#ifndef NO_HW
#ifndef NO_HW_KEYCLIENT

#ifdef FLAT_INC
#include "keyclient.h"
#else
#include "vendor_defns/keyclient.h"
#endif


/********************************/
/* Static function declarations */
/********************************/

/* ENGINE level stuff */
static int keyclient_init(void);
static int keyclient_finish(void);
/* static int keyclient_ctrl(int cmd, long i, void *p, void (*f)()); */

/* RSA stuff */
static int keyclient_rsa_pub_enc(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
static int keyclient_rsa_pub_dec(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
static int keyclient_rsa_priv_enc(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
static int keyclient_rsa_priv_dec(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
static int keyclient_rsa_init(RSA *rsa);
static int keyclient_rsa_finish(RSA *rsa);

/* DSA stuff */
static DSA_SIG *keyclient_dsa_sign(const unsigned char *dgst, int dlen,
		DSA *dsa);
static int keyclient_dsa_verify(const unsigned char *dgst, int dgst_len,
		DSA_SIG *sig, DSA *dsa);
static int keyclient_dsa_init(DSA *dsa);
static int keyclient_dsa_finish(DSA *dsa);

/* DH stuff */
/* ... */

/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD keyclient_rsa =
	{
	"KeyClient RSA method",
	keyclient_rsa_pub_enc,
	keyclient_rsa_pub_dec,
	keyclient_rsa_priv_enc,
	keyclient_rsa_priv_dec,
	NULL,
	NULL,
	keyclient_rsa_init,
	keyclient_rsa_finish,
	0,
	NULL,
	NULL,
	NULL
	};

/* Our internal DSA_METHOD that we provide pointers to */
static DSA_METHOD keyclient_dsa =
	{
	"KeyClient DSA method",
	keyclient_dsa_sign,
	NULL,
	keyclient_dsa_verify,
	NULL,
	NULL,
	keyclient_dsa_init,
	keyclient_dsa_finish,
	0,
	NULL
	};

/* Our internal DH_METHOD that we provide pointers to */
/* ... */

/* Our ENGINE structure. */
static ENGINE engine_keyclient =
        {
	"keyclient",
	"CryptoApps distributed crypto client support",
	&keyclient_rsa,
	&keyclient_dsa,
	NULL,
	NULL,
	NULL,
	NULL,
	keyclient_init,
	keyclient_finish,
	NULL, /* no ctrl() */
	NULL, /* no load_privkey() */
	NULL, /* no load_pubkey() */
	RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY, /* flags */
	0, 0, /* no references */
	NULL, NULL /* unlinked */
        };

/* As this is only ever called once, there's no need for locking (indeed - the
 * lock will already be held by our caller!!!) */
ENGINE *ENGINE_keyclient()
	{
	return &engine_keyclient;
	}

static DSO *keyclient_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
t_keyclient_bind_symbols *p_keyclient_bind_symbols = NULL;
keyclient_symbol_table kc =
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL };

/* Used in the DSO operations. */
static const char *KEYCLIENT_LIBNAME = "ksclient";
static const char *KEYCLIENT_F1 = "keyclient_bind_symbols";

/* If a key isn't supported or there is a failure, we won't retry until at least
 * this many seconds later. */
static unsigned int keyclient_retry_period = 3;

/* When a key isn't supported or there is a failure, we work locally (or fail)
 * for the above retry period. If this value is non-zero, we will log a message
 * to stderr each time such a retry/hibernation takes place. */
static int display_warnings = 0;

/****************************/
/* Internal structure types */
/****************************/

typedef enum {
	/* Haven't determined yet if the keyclient_ctx we're using will support
	 * this key. */
	kc_discover,
	/* The keyclient_ctx supports this key. */
	kc_present,
	/* The keyserver does *not* have this key. Will check again in a few
	 * seconds. */
	kc_absent,
	/* Receiving errors of some kind, will rollback to software (or fail)
	 * for a few seconds and try again. */
	kc_error
} kc_exist_state;

/* This structure is embedded in each key */
typedef struct _kc_per_key_ctx {
	/* The keyclient_ctx as used by the keyclient API */
	keyclient_ctx *ctx;
	/* In the event of "local" operation, this is the engine to do it. */
	ENGINE *fallback;
	/* Initialise-on-first-use flag */
	int initialised;
	/* What state we are currently in. */
	kc_exist_state exist_state;
	/* When the "kc_absent" or "kc_err" state arrives, this time value is
	 * set. After "keyclient_retry_seconds", a retry will be attempted. */
	time_t retry_marker;
	/* If doing a private key operation and the keyclient_ctx does not
	 * support this key, do we act locally rather than failing? */
	int private;
	/* If doing a public key operation and the keyclient_ctx does not
	 * support this key, do we embed the key or act locally? */
	enum {
		kc_embed,
		kc_local
	} public;
	/* DER encoding of the public key */
	keyclient_key_t public_der;
	/* SHA1 hash of the public key modulus */
	unsigned char public_sha1[SHA_DIGEST_LENGTH];
} kc_per_key_ctx;

#define KC_MAX_ADDRESS_SIZE 100

/* This structure is kept globally */
typedef struct _kc_global_ctx {
	/* Has this been initialised yet? */
	int initialised;
	/* The current "context of choice" */
	keyclient_ctx *ctx;
	/* The address of the current "context of choice", must be
	 * null-terminated! */
	char address[KC_MAX_ADDRESS_SIZE];
} kc_global_ctx;

static kc_global_ctx kc_global =
	{
	0, /* not initialised */
	NULL, /* no context yet */
#ifdef WIN32
	"IP:127.0.0.1:9001" /* win32 uses this by default */
#else
	"UNIX:/tmp/kclient" /* default address string */
#endif
	};

/* In a no-threading environment where file-descriptor limits won't be a
 * problem, we might prefer;
 * 	KC_FLAG_PERSISTENT_CONN | KC_FLAG_PID_CHECK | \
 * 	KC_FLAG_PERSISTENT_RETRY | KC_FLAG_PERSISTENT_LATE
 * But in general we can't assume that. */
unsigned int kc_create_flags = KC_FLAG_NO_LOCKING;

/* Setup default global context */
static int keyclient_global_check()
	{
	if(kc_global.initialised)
		return 1;
	if(kc.keyclient_create(&kc_global.ctx, kc_global.address,
			kc_create_flags, NULL) != KC_RET_OK)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_CHECK_GLOBAL,ENGINE_R_UNIT_FAILURE);
		return 0;
		}
	kc_global.initialised = 1;
	return 1;
	}

/* Where in the CRYPTO_EX_DATA stack we stick our per-key contexts */
static int kc_rsa_ex_data_idx = -1;
static int kc_dsa_ex_data_idx = -1;

/* Convert OpenSSL padding enumerated type to keyclient enumerated type */
static int keyclient_padding(int padding)
	{
	switch(padding)
		{
	case RSA_PKCS1_PADDING:
		return KC_PADDING_RSA_PKCS1;
	case RSA_SSLV23_PADDING:
		return KC_PADDING_RSA_SSLV23;
	case RSA_NO_PADDING:
		return KC_PADDING_NONE;
	case RSA_PKCS1_OAEP_PADDING:
		return KC_PADDING_RSA_PKCS1_OAEP;
	default:
		break;
		}
	ENGINEerr(ENGINE_F_KEYCLIENT_PADDING,ENGINE_R_INVALID_PADDING);
	return -1;
	}

/* (de)initialisation functions. */
static int keyclient_init(void)
	{
	if(keyclient_dso != NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_INIT,ENGINE_R_ALREADY_LOADED);
		goto err;
		}
	/* First, ensure we have index numbers we can use for our RSA and DSA
	 * key contexts */
	if(kc_rsa_ex_data_idx == -1)
		kc_rsa_ex_data_idx = RSA_get_ex_new_index(
				0, NULL, NULL, NULL, NULL);
	if(kc_dsa_ex_data_idx == -1)
		kc_dsa_ex_data_idx = DSA_get_ex_new_index(
				0, NULL, NULL, NULL, NULL);
	if((kc_rsa_ex_data_idx == -1) || (kc_dsa_ex_data_idx == -1))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_INIT,ENGINE_R_NO_INDEX);
		goto err;
		}
	/* Attempt to load libksclient.so/ksclient.dll/whatever. */
	keyclient_dso = DSO_load(NULL, KEYCLIENT_LIBNAME, NULL,
		DSO_FLAG_NAME_TRANSLATION);
	if(keyclient_dso == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	if(!(p_keyclient_bind_symbols = (t_keyclient_bind_symbols *)
				DSO_bind_func(keyclient_dso, KEYCLIENT_F1)))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	p_keyclient_bind_symbols(&kc);
	if(!keyclient_global_check())
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_INIT,ENGINE_R_UNIT_FAILURE);
		goto err;
		}
	/* Everything should be fine. */
	return 1;
err:
	if(keyclient_dso)
		DSO_free(keyclient_dso);
	keyclient_dso = NULL;
	p_keyclient_bind_symbols = NULL;
	return 0;
	}

static int keyclient_finish(void)
	{
	if(keyclient_dso == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_FINISH,ENGINE_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(keyclient_dso))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_FINISH,ENGINE_R_DSO_FAILURE);
		return 0;
		}
	keyclient_dso = NULL;
	p_keyclient_bind_symbols = NULL;
	return 1;
	}

/* Space-saving functions. These two functions, although having odd prototypes,
 * save some code duplication in the "kc_int_[rsa|dsa]_[pub|priv]" functions. */

static void kc_should_retry_util(kc_exist_state *s, time_t retry)
	{
	if((*s == kc_error) || (*s == kc_absent))
		{
		time_t now = time(NULL);
		if((now - retry) >= (time_t)keyclient_retry_period)
			*s = kc_discover;
		}
	}

static int kc_post_op_util(KC_RET ret, kc_exist_state *s, time_t *retry)
	{
	if(ret == KC_RET_OK)
		{
		*s = kc_present;
		return 1;
		}
	if(ret == KC_RET_SOFT_NO_SUCH_KEY)
		{
		*s = kc_absent;
		*retry = time(NULL);
		}
	else
		{
		/* We'll set the state and retry_marker so that another genuine
		 * attempt at communication is attempted later on. */
		*s = kc_error;
		*retry = time(NULL);
		/* We could drill further into ret at this point to provide more
		 * meaningful errors - but we don't. */
		if(display_warnings)
			fprintf(stderr, "WARNING: Keyclient engine experiencing"
				" errors. Will try to continue.\n");
		}
	return 0;
	}

static int kc_post_embed_util(KC_RET ret, kc_exist_state *s, time_t *retry)
	{
	if(ret == KC_RET_OK)
		{
		*s = kc_absent;
		return 1;
		}
	/* We'll set the state and retry_marker so that another genuine attempt
	 * at communication is attempted later on. */
	*s = kc_error;
	*retry = time(NULL);
	/* We could drill further into ret at this point to provide more
	 * meaningful errors - but for now, just use something base-level. */
	if(display_warnings)
		fprintf(stderr, "WARNING: Keyclient engine experiencing"
			" errors. Will try to continue.\n");
	return 0;
	}

/*************/
/* RSA STUFF */
/*************/

/* Set a key's per-key context. */
static int keyclient_set_rsa_ctx(RSA *rsa, kc_per_key_ctx *ctx)
	{
	if(kc_rsa_ex_data_idx == -1)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_SET_RSA_CTX,
				ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	return CRYPTO_set_ex_data(&rsa->ex_data, kc_rsa_ex_data_idx,
			(void *)ctx);
	}

/* Retrieve the pointer to a key's per-key context. */
static kc_per_key_ctx *keyclient_get_rsa_ctx(RSA *rsa)
	{
	unsigned char *ptr, *bnbin = NULL;
	EVP_MD_CTX md_ctx;
	int bin_size;
	kc_per_key_ctx *ctx;


	if((kc_rsa_ex_data_idx == -1) || ((ctx =
			(kc_per_key_ctx *)CRYPTO_get_ex_data(&rsa->ex_data,
				kc_rsa_ex_data_idx)) == NULL))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,
				ENGINE_R_NOT_INITIALISED);
		return NULL;
		}
	if(ctx->initialised)
		return ctx;
	if((rsa->n == NULL) || (BN_num_bytes(rsa->n) < 32))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,
				ENGINE_R_NOT_INITIALISED);
		return NULL;
		}
	bin_size = BN_num_bytes(rsa->n);
	ctx->exist_state = kc_discover;
	/* Choose whether to fallback to software for failed private key
	 * operations. */
	if(rsa->dmp1)
		ctx->private = 1;
	else
		ctx->private = 0;
	/* If the public key is large enough, we will send it to the keyserver
	 * if it doesn't have it. Otherwise, the ASN workload isn't worth the
	 * hassle and we act locally. */
	if(RSA_size(rsa) > 128)
		ctx->public = kc_embed;
	else
		ctx->public = kc_local;
	/* We have no "retry" situation yet so set the retry_marker to 1970 or
	 * something. */
	ctx->retry_marker = (time_t)0;
	/* Produce the key embedding */
	ctx->public_der.key_type = KC_KEY_RSA;
	ctx->public_der.der_len = i2d_RSAPublicKey(rsa, NULL);
	if(ctx->public_der.der_len > KC_MAX_PUBKEY_ASN)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,ENGINE_R_KEY_TOO_LARGE);
		return NULL;
		}
	ptr = ctx->public_der.der;
	i2d_RSAPublicKey(rsa, &ptr);
	/* Now the keyhash */
	if((bnbin = OPENSSL_malloc(bin_size)) == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	BN_bn2bin(rsa->n, bnbin);
	EVP_DigestInit(&md_ctx, EVP_sha1());
	EVP_DigestUpdate(&md_ctx, bnbin, bin_size);
	EVP_DigestFinal(&md_ctx, ctx->public_sha1, NULL);
	OPENSSL_free(bnbin);
	/* Now setup the software fallback */
	if((ctx->fallback = ENGINE_by_id("openssl")) == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,ENGINE_R_NO_SUCH_ENGINE);
		return NULL;
		}
	/* And grab a functional reference (NB: We reuse bin_size as a temp) */
	bin_size = ENGINE_init(ctx->fallback);
	/* Release the original structural reference */
	ENGINE_free(ctx->fallback);
	if(!bin_size)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,ENGINE_R_INIT_FAILED);
		return NULL;
		}
	/* Finally, duplicate the global keyclient context */
	if(kc.keyclient_dup(kc_global.ctx) != KC_RET_OK)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_RSA_CTX,ENGINE_R_UNIT_FAILURE);
		return NULL;
		}
	ctx->ctx = kc_global.ctx;
	/* Success! */
	ctx->initialised = 1;
	keyclient_set_rsa_ctx(rsa, ctx);
	return ctx;
	}

static int keyclient_rsa_init(RSA *rsa)
	{
	kc_per_key_ctx *ctx = OPENSSL_malloc(sizeof(kc_per_key_ctx));
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_INIT,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	/* Success! */
	ctx->initialised = 0;
	keyclient_set_rsa_ctx(rsa, ctx);
	return 1;
	}

static int keyclient_rsa_finish(RSA *rsa)
	{
	kc_per_key_ctx *ctx = keyclient_get_rsa_ctx(rsa);
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_FINISH,
				ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	/* Destroy the "ctx"'s contents before destroying it */
	if(!ENGINE_finish(ctx->fallback))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_FINISH,ENGINE_R_FINISH_FAILED);
		return 0;
		}
	if(kc.keyclient_release(ctx->ctx) != KC_RET_OK)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_FINISH,ENGINE_R_UNIT_FAILURE);
		return 0;
		}
	/* Great, remove the context from ex_data, and free it */
	keyclient_set_rsa_ctx(rsa, NULL);
	OPENSSL_free(ctx);
	return 1;
	}

static int kc_int_rsa_pub(RSA *rsa, kc_per_key_ctx *ctx,
		unsigned char *from, int flen, unsigned char *to,
		int tolen, int padding, int is_dec)
	{
	KC_RET ret;
	const RSA_METHOD *rsa_meth;
	RSA rsa_copy;
	keyclient_op_t op;
	keyclient_pad_t pad;
	unsigned int len = tolen;
	/* If we're in a "down" moment and need to periodically try again, check
	 * the time. */
	kc_should_retry_util(&ctx->exist_state, ctx->retry_marker);
	op = (is_dec ? KC_RSA_PUB_DECRYPT : KC_RSA_PUB_ENCRYPT);
	pad = keyclient_padding(padding);
	/* The obvious preference is to use "keyhash"ing */
	if((ctx->exist_state == kc_discover) ||
			(ctx->exist_state == kc_present))
		{
		ret = kc.keyclient_keyop(ctx->ctx, op, from, flen, to, &len,
				pad, ctx->public_sha1);
		if(kc_post_op_util(ret, &ctx->exist_state, &ctx->retry_marker))
			return len;
		}
	/* Now we try "embedding" */
	if((ctx->exist_state != kc_error) && (ctx->public == kc_embed))
		{
		/* The above code branch may have modified "len" */
		len = tolen;
		ret = kc.keyclient_pubkeyop(ctx->ctx, op, from, flen, to, &len,
				pad, &ctx->public_der);
		if(kc_post_embed_util(ret, &ctx->exist_state, &ctx->retry_marker))
			return len;
		}
	/* This copying trickery is to prevent the fallback implementation
	 * actually using our bignum functions. */
	memcpy(&rsa_copy, rsa, sizeof(RSA));
	rsa_copy.engine = ctx->fallback;
	rsa_meth = ENGINE_get_RSA(ctx->fallback);
	if(!rsa_meth)
		{
		ENGINEerr(ENGINE_F_KC_INT_RSA_PUB,ENGINE_R_REQUEST_FALLBACK);
		return -1;
		}
	if(is_dec)
		return rsa_meth->rsa_pub_dec(flen, from, to, &rsa_copy, pad);
	return rsa_meth->rsa_pub_enc(flen, from, to, &rsa_copy, pad);
	}

static int kc_int_rsa_priv(RSA *rsa, kc_per_key_ctx *ctx,
		unsigned char *from, int flen, unsigned char *to,
		int tolen, int padding, int is_dec)
	{
	KC_RET ret;
	const RSA_METHOD *rsa_meth;
	RSA rsa_copy;
	keyclient_op_t op;
	keyclient_pad_t pad;
	unsigned int len = tolen;
	/* If we're in a "down" moment and need to periodically try again, check
	 * the time. */
	kc_should_retry_util(&ctx->exist_state, ctx->retry_marker);
	op = (is_dec ? KC_RSA_PRIV_DECRYPT : KC_RSA_PRIV_ENCRYPT);
	pad = keyclient_padding(padding);
	/* The obvious preference is to use "keyhash"ing */
	if((ctx->exist_state == kc_discover) ||
			(ctx->exist_state == kc_present))
		{
		ret = kc.keyclient_keyop(ctx->ctx, op, from, flen, to, &len,
				pad, ctx->public_sha1);
		if(kc_post_op_util(ret, &ctx->exist_state, &ctx->retry_marker))
			return len;
		}
	/* If we prohibit "local" operation, we fail */
	if(!ctx->private)
		{
		ENGINEerr(ENGINE_F_KC_INT_RSA_PRIV,ENGINE_R_UNIT_FAILURE);
		return -1;
		}
	/* This copying trickery is to prevent the fallback implementation
	 * actually using our bignum functions. */
	memcpy(&rsa_copy, rsa, sizeof(RSA));
	rsa_copy.engine = ctx->fallback;
	rsa_meth = ENGINE_get_RSA(ctx->fallback);
	if(!rsa_meth)
		{
		ENGINEerr(ENGINE_F_KC_INT_RSA_PRIV,ENGINE_R_REQUEST_FALLBACK);
		return -1;
		}
	if(is_dec)
		return rsa_meth->rsa_priv_dec(flen, from, to, &rsa_copy, pad);
	return rsa_meth->rsa_priv_enc(flen, from, to, &rsa_copy, pad);
	}

static int keyclient_rsa_pub_enc(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
	{
	kc_per_key_ctx *ctx = keyclient_get_rsa_ctx(rsa);
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_PUB_ENC,
				ENGINE_R_NOT_INITIALISED);
		return -1;
		}
	return kc_int_rsa_pub(rsa, ctx, from, flen, to,
			BN_num_bytes(rsa->n), padding, 0);
	}

static int keyclient_rsa_pub_dec(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
	{
	kc_per_key_ctx *ctx = keyclient_get_rsa_ctx(rsa);
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_PUB_DEC,
				ENGINE_R_NOT_INITIALISED);
		return -1;
		}
	return kc_int_rsa_pub(rsa, ctx, from, flen, to,
			BN_num_bytes(rsa->n), padding, 1);
	}

static int keyclient_rsa_priv_enc(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
	{
	kc_per_key_ctx *ctx = keyclient_get_rsa_ctx(rsa);
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_PRIV_ENC,
				ENGINE_R_NOT_INITIALISED);
		return -1;
		}
	return kc_int_rsa_priv(rsa, ctx, from, flen, to,
			BN_num_bytes(rsa->n), padding, 0);
	}

static int keyclient_rsa_priv_dec(int flen, unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
	{
	kc_per_key_ctx *ctx = keyclient_get_rsa_ctx(rsa);
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_RSA_PRIV_DEC,
				ENGINE_R_NOT_INITIALISED);
		return -1;
		}
	return kc_int_rsa_priv(rsa, ctx, from, flen, to,
			BN_num_bytes(rsa->n), padding, 1);
	}

/*************/
/* DSA STUFF */
/*************/

/* Set a key's per-key context. */
static int keyclient_set_dsa_ctx(DSA *dsa, kc_per_key_ctx *ctx)
	{
	if(kc_dsa_ex_data_idx == -1)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_SET_DSA_CTX,
				ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	return CRYPTO_set_ex_data(&dsa->ex_data, kc_dsa_ex_data_idx,
			(void *)ctx);
	}

/* Retrieve the pointer to a key's per-key context. */
static kc_per_key_ctx *keyclient_get_dsa_ctx(DSA *dsa)
	{
	unsigned char *ptr, *bnbin = NULL;
	EVP_MD_CTX md_ctx;
	int bin_size;
	kc_per_key_ctx *ctx;

	if((kc_dsa_ex_data_idx == -1) || ((ctx =
			(kc_per_key_ctx *)CRYPTO_get_ex_data(&dsa->ex_data,
				kc_dsa_ex_data_idx)) == NULL))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,
				ENGINE_R_NOT_INITIALISED);
		return NULL;
		}
	if(ctx->initialised)
		return ctx;
	if((dsa->pub_key == NULL) || (BN_num_bytes(dsa->pub_key) < 32))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,
				ENGINE_R_NOT_INITIALISED);
		return NULL;
		}
	bin_size = BN_num_bytes(dsa->pub_key);
	ctx->exist_state = kc_discover;
	/* Choose whether to fallback to software for failed private key
	 * operations. */
	if(dsa->priv_key)
		ctx->private = 1;
	else
		ctx->private = 0;
	/* If the public key is large enough, we will send it to the keyserver
	 * if it doesn't have it. Otherwise, the ASN workload isn't worth the
	 * hassle and we act locally. */
	if(BN_num_bytes(dsa->pub_key) >= 64)
		ctx->public = kc_embed;
	else
		ctx->public = kc_local;
	/* We have no "retry" situation yet so set the retry_marker to 1970 or
	 * something. */
	ctx->retry_marker = (time_t)0;
	/* Produce the key embedding */
	ctx->public_der.key_type = KC_KEY_DSA;
	ctx->public_der.der_len = i2d_DSAPublicKey(dsa, NULL);
	if(ctx->public_der.der_len > KC_MAX_PUBKEY_ASN)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,ENGINE_R_KEY_TOO_LARGE);
		return NULL;
		}
	ptr = ctx->public_der.der;
	i2d_DSAPublicKey(dsa, &ptr);
	/* Now the keyhash */
	if((bnbin = OPENSSL_malloc(bin_size)) == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	BN_bn2bin(dsa->pub_key, bnbin);
	EVP_DigestInit(&md_ctx, EVP_sha1());
	EVP_DigestUpdate(&md_ctx, bnbin, bin_size);
	EVP_DigestFinal(&md_ctx, ctx->public_sha1, NULL);
	OPENSSL_free(bnbin);
	/* Now setup the software fallback */
	if((ctx->fallback = ENGINE_by_id("openssl")) == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,ENGINE_R_NO_SUCH_ENGINE);
		return NULL;
		}
	/* And grab a functional reference (NB: We reuse bin_size as a temp) */
	bin_size = ENGINE_init(ctx->fallback);
	/* Release the original structural reference */
	ENGINE_free(ctx->fallback);
	if(!bin_size)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,ENGINE_R_INIT_FAILED);
		return NULL;
		}
	/* Finally duplicate the global keyclient context */
	if(kc.keyclient_dup(kc_global.ctx) != KC_RET_OK)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_GET_DSA_CTX,ENGINE_R_UNIT_FAILURE);
		return NULL;
		}
	ctx->ctx = kc_global.ctx;
	/* Success! */
	ctx->initialised = 1;
	keyclient_set_dsa_ctx(dsa, ctx);
	return ctx;
	}

static int keyclient_dsa_init(DSA *dsa)
	{
	kc_per_key_ctx *ctx = OPENSSL_malloc(sizeof(kc_per_key_ctx));
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_INIT,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	/* Success! */
	ctx->initialised = 0;
	keyclient_set_dsa_ctx(dsa, ctx);
	return 1;
	}

static int keyclient_dsa_finish(DSA *dsa)
	{
	kc_per_key_ctx *ctx = keyclient_get_dsa_ctx(dsa);
	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_FINISH,
				ENGINE_R_NOT_INITIALISED);
		return 0;
		}
	/* Destroy the "ctx"'s contents before destroying it */
	if(!ENGINE_finish(ctx->fallback))
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_FINISH,ENGINE_R_FINISH_FAILED);
		return 0;
		}
	if(kc.keyclient_release(ctx->ctx) != KC_RET_OK)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_FINISH,ENGINE_R_UNIT_FAILURE);
		return 0;
		}
	/* Great, remove the context from ex_data, and free it */
	keyclient_set_dsa_ctx(dsa, NULL);
	OPENSSL_free(ctx);
	return 1;
	}

static DSA_SIG *keyclient_dsa_sign(const unsigned char *dgst, int dlen,
		DSA *dsa)
	{
	KC_RET ret;
	const DSA_METHOD *dsa_meth;
	DSA dsa_copy;
	unsigned char result[256];
	unsigned int result_len = sizeof(result);
	unsigned char *cptr = NULL;
	DSA_SIG *to_return = NULL;
	keyclient_op_t op = KC_DSA_SIGN;
	keyclient_pad_t pad = KC_PADDING_DSA;
	kc_per_key_ctx *ctx = keyclient_get_dsa_ctx(dsa);

	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_SIGN,ENGINE_R_NOT_INITIALISED);
		return NULL;
		}
	/* If we're in a "down" moment and need to periodically try again, check
	 * the time. */
	kc_should_retry_util(&ctx->exist_state, ctx->retry_marker);
	/* The obvious preference is to use "keyhash"ing */
	if((ctx->exist_state == kc_discover) ||
			(ctx->exist_state == kc_present))
		{
		ret = kc.keyclient_keyop(ctx->ctx, op, dgst, dlen,
				result, &result_len, pad, ctx->public_sha1);
		if(kc_post_op_util(ret, &ctx->exist_state, &ctx->retry_marker))
			{
			/* We parse the result as an ASN-encoded signature */
			cptr = result;
			to_return = d2i_DSA_SIG(NULL, &cptr, result_len);
			return to_return;
			}
		}
	/* If we prohibit "local" operation, we fail */
	if(!ctx->private)
		{
		ENGINEerr(ENGINE_F_KC_INT_DSA_PRIV,ENGINE_R_UNIT_FAILURE);
		return NULL;
		}
	/* This copying trickery is to prevent the fallback implementation
	 * actually using our bignum functions. */
	memcpy(&dsa_copy, dsa, sizeof(DSA));
	dsa_copy.engine = ctx->fallback;
	dsa_meth = ENGINE_get_DSA(ctx->fallback);
	if(!dsa_meth)
		{
		ENGINEerr(ENGINE_F_KC_INT_DSA_PRIV,ENGINE_R_REQUEST_FALLBACK);
		return NULL;
		}
	return dsa_meth->dsa_do_sign(dgst, dlen, &dsa_copy);
	}

static int keyclient_dsa_verify(const unsigned char *dgst, int dgst_len,
		DSA_SIG *sig, DSA *dsa)
	{
	KC_RET ret;
	const DSA_METHOD *dsa_meth;
	DSA dsa_copy;
	unsigned char response;
	unsigned int response_len = 1;
	unsigned char *ptr;
	unsigned int flen;
	unsigned char *from = NULL;
	keyclient_op_t op = KC_DSA_VERIFY;
	keyclient_pad_t pad = KC_PADDING_DSA;
	kc_per_key_ctx *ctx = keyclient_get_dsa_ctx(dsa);

	if(!ctx)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_VERIFY,
				ENGINE_R_NOT_INITIALISED);
		return -1;
		}
	flen = i2d_DSA_SIG(sig, NULL);
	if((from = OPENSSL_malloc(flen + dgst_len + 1)) == NULL)
		{
		ENGINEerr(ENGINE_F_KEYCLIENT_DSA_VERIFY,ERR_R_MALLOC_FAILURE);
		return -1;
		}
	ptr = from;
	flen = i2d_DSA_SIG(sig, &ptr);
	/* Some versions of OpenSSL have a bug where 'ptr' is not incremented in
	 * this case. */
	if(ptr == from)
		ptr += flen;
	memcpy(ptr, dgst, dgst_len);
	flen += dgst_len;
	/* If we're in a "down" moment and need to periodically try again, check
	 * the time. */
	kc_should_retry_util(&ctx->exist_state, ctx->retry_marker);
	/* The obvious preference is to use "keyhash"ing */
	if((ctx->exist_state == kc_discover) ||
			(ctx->exist_state == kc_present))
		{
		ret = kc.keyclient_keyop(ctx->ctx, op, from, flen, &response,
				&response_len, pad, ctx->public_sha1);
		if(kc_post_op_util(ret, &ctx->exist_state, &ctx->retry_marker))
			{
			OPENSSL_free(from);
			return response_len;
			}
		}
	/* Now we try "embedding" */
	if((ctx->exist_state != kc_error) && (ctx->public == kc_embed))
		{
		/* The above code branch could change "response_len" */
		response_len = 1;
		ret = kc.keyclient_pubkeyop(ctx->ctx, op, from, flen, &response,
				&response_len, pad, &ctx->public_der);
		OPENSSL_free(from);
		if(kc_post_embed_util(ret, &ctx->exist_state, &ctx->retry_marker))
			return response_len;
		}
	/* This copying trickery is to prevent the fallback implementation
	 * actually using our bignum functions. */
	OPENSSL_free(from);
	memcpy(&dsa_copy, dsa, sizeof(DSA));
	dsa_copy.engine = ctx->fallback;
	dsa_meth = ENGINE_get_DSA(ctx->fallback);
	if(!dsa_meth)
		{
		ENGINEerr(ENGINE_F_KC_INT_DSA_VERIFY,ENGINE_R_REQUEST_FALLBACK);
		return -1;
		}
	return dsa_meth->dsa_do_verify(dgst, dgst_len, sig, &dsa_copy);
	}

#endif /* !NO_HW_KEYCLIENT */
#endif /* !NO_HW */
