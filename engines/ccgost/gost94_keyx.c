/**********************************************************************
 *                             gost94_keyx.c                          *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *     Implements generation and parsing of GOST_KEY_TRANSPORT for    *
 *     			GOST R 34.10-94 algorithms                            *
 *																	  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "gost89.h"
#include "gosthash.h"
#include "e_gost_err.h"
#include "gost_keywrap.h"
#include "gost_lcl.h"
/* Common functions for both 94 and 2001 key exchange schemes */
int decrypt_cryptocom_key(unsigned char *sess_key,int max_key_len,
	const unsigned char *crypted_key,int crypted_key_len, gost_ctx *ctx)
	{
	int i;
	int j;
	int blocks = crypted_key_len >>3;
	unsigned char gamma[8];
	if (max_key_len <crypted_key_len)
		{
		GOSTerr(GOST_F_DECRYPT_CRYPTOCOM_KEY,GOST_R_NOT_ENOUGH_SPACE_FOR_KEY);
		return 0;
		}	
	if ((crypted_key_len & 7) !=0) 
		{
		GOSTerr(GOST_F_DECRYPT_CRYPTOCOM_KEY,GOST_R_INVALID_ENCRYPTED_KEY_SIZE);
		return 0;
		}	
	for (i=blocks-1;i>0;i--) 
		{
		gostcrypt(ctx,crypted_key+(i-1)*8,gamma);
		for(j=0;j<8;j++) 
			{
			sess_key[i*8+j]=gamma[j]^crypted_key[i*8+j];
			}
		}	
	gostcrypt(ctx,sess_key+crypted_key_len-8,gamma);	
	for(j=0;j<8;j++) 
		{
		sess_key[j]=gamma[j]^crypted_key[j];
		}
	return 1;
	}
int encrypt_cryptocom_key(const unsigned char *sess_key,int key_len,
	unsigned char *crypted_key, gost_ctx *ctx)
	{
	int i;
	int j;
	unsigned char gamma[8];
	memcpy(gamma,sess_key+key_len-8,8);
	for (i=0;i<key_len;i+=8)
		{
		gostcrypt(ctx,gamma,gamma);
		for (j=0;j<8;j++)
			gamma[j]=crypted_key[i+j]=sess_key[i+j]^gamma[j];
		}
	return 1;
	}
/* Implementation of the Diffi-Hellman key agreement scheme based on
 * GOST-94 keys */

/* Computes Diffie-Hellman key and stores it into buffer in
 * little-endian byte order as expected by both versions of GOST 94
 * algorigthm
 */
static int compute_pair_key_le(unsigned char *pair_key,BIGNUM *pub_key,DH *dh) 
	{
	unsigned char be_key[128];
	int i,key_size;
	key_size=DH_compute_key(be_key,pub_key,dh);
	if (!key_size) return 0;
	memset(pair_key,0,128);
	for (i=0;i<key_size;i++)
		{
		pair_key[i]=be_key[key_size-1-i];
		}
	return key_size;	
	}	
/*
 * Computes 256 bit key exchange key for CryptoCom variation of GOST 94
 * algorithm
 */
static int make_gost_shared_key(DH *dh,EVP_PKEY *pubk,unsigned char *shared_key) 
	{
	unsigned char dh_key [128];
	int i;
	/* Compute key */
	memset(dh_key,0,128);
	if (!compute_pair_key_le(dh_key,((DSA *)EVP_PKEY_get0(pubk))->pub_key,dh)) return 0;	
	/* Fold it down to 256 bit */
	/* According to GOST  either 2^1020<p<2^1024 or 
	 * 2^509<p<2^512, so DH_size can be exactly 128 or exactly 64 only
	 */
	
	if (DH_size(dh)==128)
		{
		for (i=0;i<64;i++)
			{
			dh_key[i]^=dh_key[64+i];
			}
		}
	for (i=0;i<32;i++)
		{
		shared_key[i]=dh_key[i]^dh_key[32+i];
		}
	return 1;
	}

static DH *make_ephemeral_key(EVP_PKEY *pubk,BIGNUM *ephemeral_key)
	{
	DH *dh = DH_new();
	dh->g = BN_dup(pubk->pkey.dsa->g);
	dh->p = BN_dup(pubk->pkey.dsa->p);
	dh->priv_key = BN_dup(ephemeral_key);
	/* Generate ephemeral key pair */
	if (!DH_generate_key(dh))
		{
		DH_free(dh);
		return NULL;
		}	
	return dh;
	}	
/*
 * Computes 256 bit Key exchange key as specified in RFC 4357 
 */
static int make_cp_exchange_key(DH *dh,EVP_PKEY *pubk, unsigned char *shared_key)
	{
	unsigned char dh_key [128];
	gost_hash_ctx hash_ctx;
	memset(dh_key,0,128);
	if (!compute_pair_key_le(dh_key,((DSA *)(EVP_PKEY_get0(pubk)))->pub_key,dh)) return 0;
	init_gost_hash_ctx(&hash_ctx,&GostR3411_94_CryptoProParamSet);
	start_hash(&hash_ctx);
	hash_block(&hash_ctx,dh_key,128);
	finish_hash(&hash_ctx,shared_key);
	done_gost_hash_ctx(&hash_ctx);
	return 1;
	}

/* EVP_PKEY_METHOD callback encrypt for
 * GOST R 34.10-94 cryptopro modification
 */

int pkey_GOST94cp_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char* key, size_t key_len ) 
	{
	GOST_KEY_TRANSPORT *gkt=NULL;
	DH *dh = NULL;
	unsigned char shared_key[32], ukm[8],crypted_key[44];
	const struct gost_cipher_info *param=get_encryption_params(NULL);
	EVP_PKEY *pubk = EVP_PKEY_CTX_get0_pkey(ctx);
	struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
	int size=-1;
	gost_ctx cctx;

	if (!(data->eph_seckey))
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_ENCRYPT,
			GOST_R_CTX_NOT_INITIALIZED_FOR_ENCRYPT);
		return -1;
		}	

	dh = make_ephemeral_key(pubk,gost_get_priv_key(data->eph_seckey));
	gost_init(&cctx,param->sblock);	
	make_cp_exchange_key(dh,pubk,shared_key);
	if (RAND_bytes(ukm,8)<=0)
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_ENCRYPT,
			GOST_R_RANDOM_GENERATOR_FAILURE);
		return -1;
		}	
	keyWrapCryptoPro(&cctx,shared_key,ukm,key,crypted_key);
	gkt = GOST_KEY_TRANSPORT_new();
	if (!gkt)
		{
		goto memerr;
		}	
	if(!ASN1_OCTET_STRING_set(gkt->key_agreement_info->eph_iv,
			ukm,8))
		{
		goto memerr;
		}	
	if (!ASN1_OCTET_STRING_set(gkt->key_info->imit,crypted_key+40,4))
		{
		goto memerr;
		}
	if (!ASN1_OCTET_STRING_set(gkt->key_info->encrypted_key,crypted_key+8,32))
		{
		goto memerr;
		}
	if (!X509_PUBKEY_set(&gkt->key_agreement_info->ephem_key,data->eph_seckey))
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_ENCRYPT,GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
		goto err;
		}	
	ASN1_OBJECT_free(gkt->key_agreement_info->cipher);
	gkt->key_agreement_info->cipher = OBJ_nid2obj(param->nid);
	*outlen = i2d_GOST_KEY_TRANSPORT(gkt,&out);
	if (!size)
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_ENCRYPT,GOST_R_ERROR_PACKING_KEY_TRANSPORT_INFO);
		size=-1;
		}
	GOST_KEY_TRANSPORT_free(gkt);
	DH_free(dh);
	return 1;	
	memerr:
	GOSTerr(GOST_F_PKEY_GOST94CP_ENCRYPT,
		GOST_R_MALLOC_FAILURE);
	err:		
	GOST_KEY_TRANSPORT_free(gkt);
	DH_free(dh);
	return -1;
	}

/* EVP_PKEY_METHOD callback encrypt for
 * GOST R 34.10-94 cryptocom modification
 */

int pkey_GOST94cc_encrypt (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,  const unsigned char *   key,size_t key_len) 
	{
	EVP_PKEY *pubk = EVP_PKEY_CTX_get0_pkey(ctx);
	struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
	/* create DH structure filling parameters from passed pub_key */
	DH *dh = NULL;
	GOST_KEY_TRANSPORT *gkt = NULL;
	gost_ctx cctx;
	EVP_PKEY *newkey=NULL;
	unsigned char shared_key[32],encrypted_key[32],hmac[4],
		iv[8]={0,0,0,0,0,0,0,0};

	if (! data->eph_seckey)
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_ENCRYPT,
			GOST_R_CTX_NOT_INITIALIZED_FOR_ENCRYPT);
		return -1;
		}	
	dh = make_ephemeral_key(pubk,gost_get_priv_key(data->eph_seckey));
	if (!dh) goto err;
	/* compute shared key */
	if (!make_gost_shared_key(dh,pubk,shared_key)) 
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_ERROR_COMPUTING_SHARED_KEY);
		goto err;
		}	
	/* encrypt session key */
	gost_init(&cctx, &GostR3411_94_CryptoProParamSet);
	gost_key(&cctx,shared_key);
	encrypt_cryptocom_key(key,key_len,encrypted_key,&cctx);
	/* compute hmac of session key */
	if (!gost_mac(&cctx,32,key,32,hmac)) 
		{
		DH_free(dh);
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_ERROR_COMPUTING_MAC);
		return -1;
		}
	gkt = GOST_KEY_TRANSPORT_new();
	if (!gkt) 
		{
		DH_free(dh);
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_NO_MEMORY);
		return -1;
		}	
	/* Store IV which is always zero in our case */
	if (!ASN1_OCTET_STRING_set(gkt->key_agreement_info->eph_iv,iv,8))
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_ERROR_STORING_IV);
		goto err;
		}	
	if (!ASN1_OCTET_STRING_set(gkt->key_info->imit,hmac,4)) 
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_ERROR_STORING_MAC);
		goto err;
		}	
	if (!ASN1_OCTET_STRING_set(gkt->key_info->encrypted_key,encrypted_key,32))
		{	
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_ERROR_STORING_ENCRYPTED_KEY);
		goto err;
		}
	if (!X509_PUBKEY_set(&gkt->key_agreement_info->ephem_key,data->eph_seckey))
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_ENCRYPT,GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
		goto err;
		}	
	ASN1_OBJECT_free(gkt->key_agreement_info->cipher);
	gkt->key_agreement_info->cipher = OBJ_nid2obj(NID_id_Gost28147_89_cc);
	*outlen = i2d_GOST_KEY_TRANSPORT(gkt,&out);
	err:
	if (gkt) GOST_KEY_TRANSPORT_free(gkt);
	if (dh) DH_free(dh);
	if (newkey) EVP_PKEY_free(newkey);
	return 1;
	}	
	
/* EVP_PLEY_METHOD callback decrypt for
 * GOST R 34.10-94 cryptopro modification
 */
int pkey_GOST94cp_decrypt (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *key_len,const unsigned char *in, size_t in_len) {
	DH *dh = DH_new();
	const unsigned char *p = in;
	GOST_KEY_TRANSPORT *gkt = NULL;
	unsigned char wrappedKey[44];
	unsigned char sharedKey[32];
	gost_ctx cctx;
	const struct gost_cipher_info *param=NULL;
	EVP_PKEY *eph_key=NULL;
	EVP_PKEY *priv= EVP_PKEY_CTX_get0_pkey(ctx); 
	
	if (!key)
		{
		*key_len = 32;
		return 1;
		}	
	
	dh->g = BN_dup(priv->pkey.dsa->g);
	dh->p = BN_dup(priv->pkey.dsa->p);
	dh->priv_key = BN_dup(priv->pkey.dsa->priv_key);
	gkt = d2i_GOST_KEY_TRANSPORT(NULL,(const unsigned char **)&p,
		in_len);
	if (!gkt)
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_DECRYPT,GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
		DH_free(dh);
		return 0;
		}	
	eph_key = X509_PUBKEY_get(gkt->key_agreement_info->ephem_key);
	param = get_encryption_params(gkt->key_agreement_info->cipher);
	gost_init(&cctx,param->sblock);	
	OPENSSL_assert(gkt->key_agreement_info->eph_iv->length==8);
	memcpy(wrappedKey,gkt->key_agreement_info->eph_iv->data,8);
	OPENSSL_assert(gkt->key_info->encrypted_key->length==32);
	memcpy(wrappedKey+8,gkt->key_info->encrypted_key->data,32);
	OPENSSL_assert(gkt->key_info->imit->length==4);
	memcpy(wrappedKey+40,gkt->key_info->imit->data,4);	
	make_cp_exchange_key(dh,eph_key,sharedKey);
	if (!keyUnwrapCryptoPro(&cctx,sharedKey,wrappedKey,key))
		{
		GOSTerr(GOST_F_PKEY_GOST94CP_DECRYPT,
			GOST_R_ERROR_COMPUTING_SHARED_KEY);
		goto err;
		}	
				
	EVP_PKEY_free(eph_key);
	GOST_KEY_TRANSPORT_free(gkt);
	DH_free(dh);
	return 1;
err:
	EVP_PKEY_free(eph_key);
	GOST_KEY_TRANSPORT_free(gkt);
	DH_free(dh);
	return -1;
	}	

/* EVP_PKEY_METHOD callback decrypt for
 * GOST R 34.10-94 cryptocom modification
 */

int pkey_GOST94cc_decrypt (EVP_PKEY_CTX *pctx, unsigned char *key, size_t *key_len, const unsigned char *in, size_t in_len)
	{
	/* Form DH params from compute shared key */
	GOST_KEY_TRANSPORT *gkt = NULL;
	const unsigned char *p=in;
	unsigned char shared_key[32];
	unsigned char hmac[4],hmac_comp[4];
	unsigned char iv[8];
	int i;
	gost_ctx ctx;
	DH *dh = DH_new();
	EVP_PKEY *eph_key;
	EVP_PKEY *priv = EVP_PKEY_CTX_get0_pkey(pctx);
	
	if (!key)
		{
		*key_len = 32;
		return 1;
		}
	/* Construct DH structure from the our GOST private key */
	dh->g = BN_dup(priv->pkey.dsa->g);
	dh->p = BN_dup(priv->pkey.dsa->p);
	dh->priv_key = BN_dup(priv->pkey.dsa->priv_key);
	/* Parse passed octet string and find out public key, iv and HMAC*/
	gkt = d2i_GOST_KEY_TRANSPORT(NULL,(const unsigned char **)&p,
		in_len);
	if (!gkt)
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_DECRYPT,GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
		DH_free(dh);
		return 0;
		}	
	eph_key = X509_PUBKEY_get(gkt->key_agreement_info->ephem_key);
	/* Initialization vector is really ignored here */
	OPENSSL_assert(gkt->key_agreement_info->eph_iv->length==8);
	memcpy(iv,gkt->key_agreement_info->eph_iv->data,8);
	/* HMAC should be computed and checked */
	OPENSSL_assert(gkt->key_info->imit->length==4);
	memcpy(hmac,gkt->key_info->imit->data,4);	
	/* Compute shared key */
	i=make_gost_shared_key(dh,eph_key,shared_key);
	EVP_PKEY_free(eph_key);
	DH_free(dh);
	if (!i) 
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_DECRYPT,GOST_R_ERROR_COMPUTING_SHARED_KEY);
		GOST_KEY_TRANSPORT_free(gkt);
		return 0;
		}
	/* Decrypt session key */
	gost_init(&ctx, &GostR3411_94_CryptoProParamSet);
	gost_key(&ctx,shared_key);
	
	if (!decrypt_cryptocom_key(key,*key_len,gkt->key_info->encrypted_key->data, 
			gkt->key_info->encrypted_key->length, &ctx)) 
		{
		GOST_KEY_TRANSPORT_free(gkt);
		return 0;
		}
	GOST_KEY_TRANSPORT_free(gkt);
	/* check HMAC of session key*/
	if (!gost_mac(&ctx,32,key,32,hmac_comp))
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_DECRYPT,GOST_R_ERROR_COMPUTING_MAC);
		return 0;
		}
	/* HMAC of session key is not correct */
    if (memcmp(hmac,hmac_comp,4)!=0)
		{
		GOSTerr(GOST_F_PKEY_GOST94CC_DECRYPT,GOST_R_SESSION_KEY_MAC_DOES_NOT_MATCH);
		return 0;
		}	
	return 1; 
	}	
