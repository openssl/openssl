/* Demo of how to construct your own engine and using it.  The basis of this
   engine is RSAref, an old reference of the RSA algorithm which can still
   be found a little here and there. */

#include <stdio.h>
#include "./source/global.h"
#include "./source/rsaref.h"
#include "./source/rsa.h"
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

#define RSAREF_LIB_NAME "rsaref engine"
#include "rsaref_err.c"

/* Constants used when creating the ENGINE */
static const char *engine_rsaref_id = "rsaref";
static const char *engine_rsaref_name = "RSAref engine support";

static int rsaref_destroy(ENGINE *e);
static int rsaref_init(ENGINE *e);
static int rsaref_finish(ENGINE *e);
#if 0
static int rsaref_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)()); 
#endif

static int rsaref_private_decrypt(int len, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
static int rsaref_private_encrypt(int len, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
static int rsaref_public_encrypt(int len, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
static int rsaref_public_decrypt(int len, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);
static int bnref_mod_exp(BIGNUM *r,const BIGNUM *a,const BIGNUM *p,const BIGNUM *m,
			  BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int rsaref_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa);

static const ENGINE_CMD_DEFN rsaref_cmd_defns[] = {
	{0, NULL, NULL, 0}
	};

static RSA_METHOD rsaref_rsa =
{
  "RSAref PKCS#1 RSA",
  rsaref_public_encrypt,
  rsaref_public_decrypt,
  rsaref_private_encrypt,
  rsaref_private_decrypt,
  rsaref_mod_exp,
  bnref_mod_exp,
  NULL,
  NULL,
  0,
  NULL,
  NULL,
  NULL
};

/* Now, to our own code */

static int bind_rsaref(ENGINE *e)
	{
	const RSA_METHOD *meth1;
	if(!ENGINE_set_id(e, engine_rsaref_id)
		|| !ENGINE_set_name(e, engine_rsaref_name)
		|| !ENGINE_set_RSA(e, &rsaref_rsa)
		|| !ENGINE_set_destroy_function(e, rsaref_destroy)
		|| !ENGINE_set_init_function(e, rsaref_init)
		|| !ENGINE_set_finish_function(e, rsaref_finish)
		/* || !ENGINE_set_ctrl_function(e, rsaref_ctrl) */
		/* || !ENGINE_set_cmd_defns(e, rsaref_cmd_defns) */)
		return 0;

	/* Ensure the rsaref error handling is set up */
	ERR_load_RSAREF_strings();
	return 1;
	}

#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_helper(ENGINE *e, const char *id)
	{
	if(id && (strcmp(id, engine_rsaref_id) != 0))
		return 0;
	if(!bind_rsaref(e))
		return 0;
	return 1;
	}       
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
static ENGINE *engine_rsaref(void)
	{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_rsaref(ret))
		{
		ENGINE_free(ret);
		return NULL;
		}
	return ret;
	}

void ENGINE_load_rsaref(void)
	{
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_rsaref();
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
	}
#endif

/* Initiator which is only present to make sure this engine looks available */
static int rsaref_init(ENGINE *e)
	{
	return 1;
	}

/* Finisher which is only present to make sure this engine looks available */
static int rsaref_finish(ENGINE *e)
	{
	return 1;
	}

/* Destructor (complements the "ENGINE_ncipher()" constructor) */
static int rsaref_destroy(ENGINE *e)
	{
	ERR_unload_RSAREF_strings();
	return 1;
	}

static int rsaref_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa)
	{
	RSAREFerr(RSAREF_F_RSAREF_MOD_EXP,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return(0);
	}

static int bnref_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			  const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	RSAREFerr(RSAREF_F_BNREF_MOD_EXP,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return(0);
	}

/* unsigned char *to:  [max]    */
static int RSAref_bn2bin(BIGNUM *from, unsigned char *to, int max)
	{
	int i;

	i=BN_num_bytes(from);
	if (i > max)
		{
		RSAREFerr(RSAREF_F_RSAREF_BN2BIN,RSAREF_R_LEN);
		return(0);
		}

	memset(to,0,(unsigned int)max);
	if (!BN_bn2bin(from,&(to[max-i])))
		return(0);
	return(1);
	}

#ifdef undef
/* unsigned char *from:  [max]    */
static BIGNUM *RSAref_bin2bn(unsigned char *from, BIGNUM *to, int max)
	{
	int i;
	BIGNUM *ret;

	for (i=0; i<max; i++)
		if (from[i]) break;

	ret=BN_bin2bn(&(from[i]),max-i,to);
	return(ret);
	}

static int RSAref_Public_ref2eay(RSArefPublicKey *from, RSA *to)
	{
	to->n=RSAref_bin2bn(from->m,NULL,RSAref_MAX_LEN);
	to->e=RSAref_bin2bn(from->e,NULL,RSAref_MAX_LEN);
	if ((to->n == NULL) || (to->e == NULL)) return(0);
	return(1);
	}
#endif

static int RSAref_Public_eay2ref(RSA *from, R_RSA_PUBLIC_KEY *to)
	{
	to->bits=BN_num_bits(from->n);
	if (!RSAref_bn2bin(from->n,to->modulus,MAX_RSA_MODULUS_LEN)) return(0);
	if (!RSAref_bn2bin(from->e,to->exponent,MAX_RSA_MODULUS_LEN)) return(0);
	return(1);
	}

#ifdef undef
static int RSAref_Private_ref2eay(RSArefPrivateKey *from, RSA *to)
	{
	if ((to->n=RSAref_bin2bn(from->m,NULL,RSAref_MAX_LEN)) == NULL)
		return(0);
	if ((to->e=RSAref_bin2bn(from->e,NULL,RSAref_MAX_LEN)) == NULL)
		return(0);
	if ((to->d=RSAref_bin2bn(from->d,NULL,RSAref_MAX_LEN)) == NULL)
		return(0);
	if ((to->p=RSAref_bin2bn(from->prime[0],NULL,RSAref_MAX_PLEN)) == NULL)
		return(0);
	if ((to->q=RSAref_bin2bn(from->prime[1],NULL,RSAref_MAX_PLEN)) == NULL)
		return(0);
	if ((to->dmp1=RSAref_bin2bn(from->pexp[0],NULL,RSAref_MAX_PLEN))
		== NULL)
		return(0);
	if ((to->dmq1=RSAref_bin2bn(from->pexp[1],NULL,RSAref_MAX_PLEN))
		== NULL)
		return(0);
	if ((to->iqmp=RSAref_bin2bn(from->coef,NULL,RSAref_MAX_PLEN)) == NULL)
		return(0);
	return(1);
	}
#endif

static int RSAref_Private_eay2ref(RSA *from, R_RSA_PRIVATE_KEY *to)
	{
	to->bits=BN_num_bits(from->n);
	if (!RSAref_bn2bin(from->n,to->modulus,MAX_RSA_MODULUS_LEN)) return(0);
	if (!RSAref_bn2bin(from->e,to->publicExponent,MAX_RSA_MODULUS_LEN)) return(0);
	if (!RSAref_bn2bin(from->d,to->exponent,MAX_RSA_MODULUS_LEN)) return(0);
	if (!RSAref_bn2bin(from->p,to->prime[0],MAX_RSA_PRIME_LEN)) return(0);
	if (!RSAref_bn2bin(from->q,to->prime[1],MAX_RSA_PRIME_LEN)) return(0);
	if (!RSAref_bn2bin(from->dmp1,to->primeExponent[0],MAX_RSA_PRIME_LEN)) return(0);
	if (!RSAref_bn2bin(from->dmq1,to->primeExponent[1],MAX_RSA_PRIME_LEN)) return(0);
	if (!RSAref_bn2bin(from->iqmp,to->coefficient,MAX_RSA_PRIME_LEN)) return(0);
	return(1);
	}

static int rsaref_private_decrypt(int len, const unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int i,outlen= -1;
	R_RSA_PRIVATE_KEY RSAkey;

	if (!RSAref_Private_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPrivateDecrypt(to,&outlen,(unsigned char *)from,len,&RSAkey)) != 0)
		{
		RSAREFerr(RSAREF_F_RSAREF_PRIVATE_DECRYPT,i);
		outlen= -1;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	return(outlen);
	}

static int rsaref_private_encrypt(int len, const unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int i,outlen= -1;
	R_RSA_PRIVATE_KEY RSAkey;

	if (padding != RSA_PKCS1_PADDING)
		{
		RSAREFerr(RSAREF_F_RSAREF_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (!RSAref_Private_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPrivateEncrypt(to,&outlen,(unsigned char *)from,len,&RSAkey)) != 0)
		{
		RSAREFerr(RSAREF_F_RSAREF_PRIVATE_ENCRYPT,i);
		outlen= -1;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	return(outlen);
	}

static int rsaref_public_decrypt(int len, const unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int i,outlen= -1;
	R_RSA_PUBLIC_KEY RSAkey;

	if (!RSAref_Public_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPublicDecrypt(to,&outlen,(unsigned char *)from,len,&RSAkey)) != 0)
		{
		RSAREFerr(RSAREF_F_RSAREF_PUBLIC_DECRYPT,i);
		outlen= -1;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	return(outlen);
	}

static int rsaref_public_encrypt(int len, const unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
	{
	int outlen= -1;
	int i;
	R_RSA_PUBLIC_KEY RSAkey;
	R_RANDOM_STRUCT rnd;
	unsigned char buf[16];

	if (padding != RSA_PKCS1_PADDING && padding != RSA_SSLV23_PADDING) 
		{
		RSAREFerr(RSAREF_F_RSAREF_PUBLIC_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
		}
	
	R_RandomInit(&rnd);
	R_GetRandomBytesNeeded((unsigned int *)&i,&rnd);
	while (i > 0)
		{
		if (RAND_bytes(buf,16) <= 0)
			goto err;
		R_RandomUpdate(&rnd,buf,(unsigned int)((i>16)?16:i));
		i-=16;
		}

	if (!RSAref_Public_eay2ref(rsa,&RSAkey))
		goto err;
	if ((i=RSAPublicEncrypt(to,&outlen,(unsigned char *)from,len,&RSAkey,&rnd)) != 0)
		{
		RSAREFerr(RSAREF_F_RSAREF_PUBLIC_ENCRYPT,i);
		outlen= -1;
		goto err;
		}
err:
	memset(&RSAkey,0,sizeof(RSAkey));
	R_RandomFinal(&rnd);
	memset(&rnd,0,sizeof(rnd));
	return(outlen);
	}
