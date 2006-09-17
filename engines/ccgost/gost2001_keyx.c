/**********************************************************************
 *                          gost_keyx.c                               *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *   VK0 34.10-2001 key exchange and GOST R 34.10-2001                *
 *   based PKCS7/SMIME support                                        *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <openssl/objects.h>
#include "gost89.h"
#include "gosthash.h"
#include "gost_asn1.h"
#include "e_gost_err.h"
#include "keywrap.h"
#include "crypt.h"
#include "sign.h"
#include "pmeth.h"
#include "tools.h"
#include "gostkeyx.h"

/* Transform ECDH shared key into little endian as required by Cryptocom
 * key exchange */
static void *make_key_le(const void *in, size_t inlen, void *out, size_t *outlen) {
	const char* inbuf= in;
	char* outbuf= out;
	int i;
	if (*outlen < inlen) {
			return NULL;
	}
	for (i=0;i<inlen;i++) {
		outbuf[inlen-1-i]=inbuf[i];
	}
	*outlen = inlen;
	return out;
}	

/* Create gost 2001 ephemeral key with same parameters as peer key */
static EC_KEY *make_ec_ephemeral_key(EC_KEY *peer_key,BIGNUM *seckey) {
	EC_KEY *out = EC_KEY_new();
	EC_KEY_copy(out,peer_key);
	EC_KEY_set_private_key(out,seckey);
	gost2001_compute_public(out);
	return out;
}
/* Packs GOST elliptic curve key into EVP_PKEY setting same parameters
 * as in passed pubkey
 */
static EVP_PKEY *ec_ephemeral_key_to_EVP(EVP_PKEY *pubk,int type,EC_KEY *ephemeral) 
{
	EVP_PKEY *newkey;
	newkey = EVP_PKEY_new();
	EVP_PKEY_assign(newkey,type,ephemeral);
	return newkey;
}	

/*  
 * EVP_PKEY_METHOD callback encrypt  
 * Implementation of GOST2001 key transport, cryptocom variation 
 */

int pkey_GOST01cc_encrypt (EVP_PKEY_CTX *pctx,unsigned char *out, 
	size_t *out_len, const unsigned char *key,size_t key_len)
{
	EVP_PKEY *pubk = EVP_PKEY_CTX_get0_pkey(pctx);
	struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(pctx);	
	GOST_KEY_TRANSPORT *gkt = NULL;
	int ret=0;
	gost_ctx ctx;
	EC_KEY *ephemeral=NULL;
	const EC_POINT *pub_key_point=NULL;
	unsigned char shared_key[32],encrypted_key[32],hmac[4],
				  iv[8]={0,0,0,0,0,0,0,0};
	ephemeral = make_ec_ephemeral_key(EVP_PKEY_get0(pubk), gost_get_priv_key(data->eph_seckey));
	if (!ephemeral) goto err;
	/* compute shared key */
	pub_key_point=EC_KEY_get0_public_key(EVP_PKEY_get0(pubk));
	if (!ECDH_compute_key(shared_key,32,pub_key_point,ephemeral,make_key_le)) 
	{
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_ERROR_COMPUTING_SHARED_KEY);
		goto err;
	}	
	/* encrypt session key */
	gost_init(&ctx, &GostR3411_94_CryptoProParamSet);
	gost_key(&ctx,shared_key);
	encrypt_cryptocom_key(key,key_len,encrypted_key,&ctx);
	/* compute hmac of session key */
	if (!gost_mac(&ctx,32,key,32,hmac)) 
	{
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_ERROR_COMPUTING_MAC);
		return -1;
    }
	gkt = GOST_KEY_TRANSPORT_new();
	if (!gkt) 
	{
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_NO_MEMORY);
		return -1;
	}	
	/* Store IV which is always zero in our case */
	if (!ASN1_OCTET_STRING_set(gkt->key_agreement_info->eph_iv,iv,8))
	{
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_ERROR_STORING_IV);
		goto err;
	}	
	if (!ASN1_OCTET_STRING_set(gkt->key_info->imit,hmac,4)) 
	{
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_ERROR_STORING_MAC);
		goto err;
	}	
	if (!ASN1_OCTET_STRING_set(gkt->key_info->encrypted_key,encrypted_key,32))
	{	
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_ERROR_STORING_ENCRYPTED_KEY);
		goto err;
	}
	
	if (!X509_PUBKEY_set(&gkt->key_agreement_info->ephem_key,data->eph_seckey)) {
		GOSTerr(GOST_F_PKEY_GOST01CC_ENCRYPT,GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
		goto err;
	}	
	ASN1_OBJECT_free(gkt->key_agreement_info->cipher);
	gkt->key_agreement_info->cipher = OBJ_nid2obj(NID_id_Gost28147_89_cc);
	if ((*out_len = i2d_GOST_KEY_TRANSPORT(gkt,&out))>0) ret = 1;
	;
err:
	if (gkt) GOST_KEY_TRANSPORT_free(gkt);
	return ret;
}
/*  
 * EVP_PKEY_METHOD callback decrypt  
 * Implementation of GOST2001 key transport, cryptocom variation 
 */
int pkey_GOST01cc_decrypt (EVP_PKEY_CTX *pctx, unsigned char *key, size_t *key_len, const unsigned char *in, size_t in_len) {
	/* Form DH params from compute shared key */
	EVP_PKEY *priv=EVP_PKEY_CTX_get0_pkey(pctx);
	GOST_KEY_TRANSPORT *gkt = NULL;
	const unsigned char *p=in;
	unsigned char shared_key[32];
	unsigned char hmac[4],hmac_comp[4];
	unsigned char iv[8];
	int i;
	gost_ctx ctx;
	const EC_POINT *pub_key_point;
	EVP_PKEY *eph_key;

	if (!key) {
		*key_len = 32;
		return 1;
	}	
	/* Parse passed octet string and find out public key, iv and HMAC*/
	gkt = d2i_GOST_KEY_TRANSPORT(NULL,(const unsigned char **)&p,
			in_len);
	if (!gkt) {
		GOSTerr(GOST_F_PKEY_GOST01CC_DECRYPT,GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
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
	pub_key_point=EC_KEY_get0_public_key(EVP_PKEY_get0(eph_key));
	i=ECDH_compute_key(shared_key,32,pub_key_point,EVP_PKEY_get0(priv),make_key_le);
	EVP_PKEY_free(eph_key);
	if (!i) 
	{
		GOSTerr(GOST_F_PKEY_GOST01CC_DECRYPT,GOST_R_ERROR_COMPUTING_SHARED_KEY);
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
	if (!gost_mac(&ctx,32,key,32,hmac_comp)) {
		GOSTerr(GOST_F_PKEY_GOST01CC_DECRYPT,GOST_R_ERROR_COMPUTING_MAC);
		return 0;
    }
		/* HMAC of session key is not correct */
    if (memcmp(hmac,hmac_comp,4)!=0) {
		GOSTerr(GOST_F_PKEY_GOST01CC_DECRYPT,GOST_R_SESSION_KEY_MAC_DOES_NOT_MATCH);
		return 0;
	}	
	return 1; 
}

/* Implementation of CryptoPro VKO 34.10-2001 algorithm */
static int VKO_compute_key(unsigned char *shared_key,size_t shared_key_size,const EC_POINT *pub_key,EC_KEY *priv_key,const unsigned char *ukm) {
	unsigned char ukm_be[8],databuf[64],hashbuf[64];
	BIGNUM *UKM=NULL,*p=NULL,*order=NULL,*X=NULL,*Y=NULL;
	const BIGNUM* key=EC_KEY_get0_private_key(priv_key);
	EC_POINT *pnt=EC_POINT_new(EC_KEY_get0_group(priv_key));
	int i;
	gost_hash_ctx hash_ctx;
	BN_CTX *ctx = BN_CTX_new();

	for (i=0;i<8;i++) {
		ukm_be[7-i]=ukm[i];
	}
	BN_CTX_start(ctx);
	UKM=getbnfrombuf(ukm_be,8);
	p=BN_CTX_get(ctx);
	order = BN_CTX_get(ctx);
	X=BN_CTX_get(ctx);
	Y=BN_CTX_get(ctx);
	EC_GROUP_get_order(EC_KEY_get0_group(priv_key),order,ctx);
	BN_mod_mul(p,key,UKM,order,ctx);	
	EC_POINT_mul(EC_KEY_get0_group(priv_key),pnt,NULL,pub_key,p,ctx);
	EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(priv_key),
			pnt,X,Y,ctx);
	/*Serialize elliptic curve point same way as we do it when saving
	 * key */
	store_bignum(Y,databuf,32);
	store_bignum(X,databuf+32,32);
 	/* And reverse byte order of whole buffer */
	for (i=0;i<64;i++) {
		hashbuf[63-i]=databuf[i];
	}
	init_gost_hash_ctx(&hash_ctx,&GostR3411_94_CryptoProParamSet);
	start_hash(&hash_ctx);
	hash_block(&hash_ctx,hashbuf,64);
	finish_hash(&hash_ctx,shared_key);
	done_gost_hash_ctx(&hash_ctx);
	BN_free(UKM);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_POINT_free(pnt);
	return 32;
}

/* Generates ephemeral key based on pubk algorithm
 * computes shared key using VKO and returns filled up
 * GOST_KEY_TRANSPORT structure
 */
/* Public, because it would be needed in SSL implementation */
GOST_KEY_TRANSPORT *make_rfc4490_keytransport_2001(EVP_PKEY *pubk,BIGNUM *eph_key,
		const unsigned char *key,size_t keylen, unsigned char *ukm,
		size_t ukm_len)
{

	const struct gost_cipher_info *param=get_encryption_params(NULL);
	EC_KEY *ephemeral = NULL;
	GOST_KEY_TRANSPORT *gkt=NULL;
	const EC_POINT *pub_key_point = EC_KEY_get0_public_key(EVP_PKEY_get0(pubk));
	unsigned char shared_key[32],crypted_key[44];
	gost_ctx ctx;
	EVP_PKEY *newkey=NULL;
	
	/* Do not use vizir cipher parameters with cryptopro */
	if (!getenv("CRYPT_PARAMS") && param ==  gost_cipher_list) {
		param= gost_cipher_list+1;
	}	
	ephemeral = make_ec_ephemeral_key(EVP_PKEY_get0(pubk),eph_key);
    VKO_compute_key(shared_key,32,pub_key_point,ephemeral,ukm);
	gost_init(&ctx,param->sblock);	
	keyWrapCryptoPro(&ctx,shared_key,ukm,key,crypted_key);
	gkt = GOST_KEY_TRANSPORT_new();
	if (!gkt) {
		goto memerr;
	}	
	if(!ASN1_OCTET_STRING_set(gkt->key_agreement_info->eph_iv,
				                ukm,8)) {
		goto memerr;
	}	
	if (!ASN1_OCTET_STRING_set(gkt->key_info->imit,crypted_key+40,4)) {
		goto memerr;
	}
	if (!ASN1_OCTET_STRING_set(gkt->key_info->encrypted_key,crypted_key+8,32)) {
		goto memerr;
	}
	newkey = ec_ephemeral_key_to_EVP(pubk,NID_id_GostR3410_2001,ephemeral);
	if (!X509_PUBKEY_set(&gkt->key_agreement_info->ephem_key,newkey)) {
		GOSTerr(GOST_F_MAKE_RFC4490_KEYTRANSPORT_2001,GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
		goto err;
	}	
	ASN1_OBJECT_free(gkt->key_agreement_info->cipher);
	gkt->key_agreement_info->cipher = OBJ_nid2obj(param->nid);
	EVP_PKEY_free(newkey);
	return gkt;
memerr:
		GOSTerr(GOST_F_MAKE_RFC4490_KEYTRANSPORT_2001,
				GOST_R_MALLOC_FAILURE);
err:		
		GOST_KEY_TRANSPORT_free(gkt);
		return NULL;
}

/*  
 * EVP_PKEY_METHOD callback encrypt  
 * Implementation of GOST2001 key transport, cryptopo variation 
 */

int pkey_GOST01cp_encrypt (EVP_PKEY_CTX *pctx, unsigned char *out, size_t *out_len, const unsigned char *key,size_t key_len) 
{
	GOST_KEY_TRANSPORT *gkt=NULL; 
	EVP_PKEY *pubk = EVP_PKEY_CTX_get0_pkey(pctx);
	struct gost_pmeth_data *data = EVP_PKEY_CTX_get_data(pctx);
	unsigned char ukm[8];
	int ret=0;
	if (RAND_bytes(ukm,8)<=0) {
		GOSTerr(GOST_F_PKEY_GOST01CP_ENCRYPT,
			GOST_R_RANDOM_GENERATOR_FAILURE);
		return 0;
	}	
		
	if (!(gkt=make_rfc4490_keytransport_2001(pubk,gost_get_priv_key(data->eph_seckey),key, key_len,ukm,8))) {
		goto err;
	}	
	if ((*out_len = i2d_GOST_KEY_TRANSPORT(gkt,&out))>0) ret =1;
	GOST_KEY_TRANSPORT_free(gkt);
	return ret;	
err:		
		GOST_KEY_TRANSPORT_free(gkt);
		return -1;
}
/* Public, because it would be needed in SSL implementation */
int decrypt_rfc4490_shared_key_2001(EVP_PKEY *priv,GOST_KEY_TRANSPORT *gkt,
		unsigned char *key_buf,int key_buf_len) 
{
	unsigned char wrappedKey[44];
	unsigned char sharedKey[32];
	gost_ctx ctx;
	const struct gost_cipher_info *param=NULL;
	EVP_PKEY *eph_key=NULL;
	
	eph_key = X509_PUBKEY_get(gkt->key_agreement_info->ephem_key);
	param = get_encryption_params(gkt->key_agreement_info->cipher);
	gost_init(&ctx,param->sblock);	
	OPENSSL_assert(gkt->key_agreement_info->eph_iv->length==8);
	memcpy(wrappedKey,gkt->key_agreement_info->eph_iv->data,8);
	OPENSSL_assert(gkt->key_info->encrypted_key->length==32);
	memcpy(wrappedKey+8,gkt->key_info->encrypted_key->data,32);
	OPENSSL_assert(gkt->key_info->imit->length==4);
	memcpy(wrappedKey+40,gkt->key_info->imit->data,4);	
	VKO_compute_key(sharedKey,32,EC_KEY_get0_public_key(EVP_PKEY_get0(eph_key)),
			EVP_PKEY_get0(priv),wrappedKey);
	if (!keyUnwrapCryptoPro(&ctx,sharedKey,wrappedKey,key_buf)) {
		GOSTerr(GOST_F_PKCS7_GOST94CP_KEY_TRANSPORT_DECRYPT,
				GOST_R_ERROR_COMPUTING_SHARED_KEY);
		goto err;
	}	
				
	EVP_PKEY_free(eph_key);
	return 32;
err:
	EVP_PKEY_free(eph_key);
	return -1;
}
/*  
 * EVP_PKEY_METHOD callback decrypt  
 * Implementation of GOST2001 key transport, cryptopo variation 
 */
int pkey_GOST01cp_decrypt (EVP_PKEY_CTX *pctx, unsigned char *key, size_t * key_len, const unsigned char *in, size_t in_len) {
	const unsigned char *p = in;
	EVP_PKEY *priv = EVP_PKEY_CTX_get0_pkey(pctx);
	GOST_KEY_TRANSPORT *gkt = NULL;
	int ret=0;	

	if (!key) {
		*key_len = 32;
		return 1;
	}	
	gkt = d2i_GOST_KEY_TRANSPORT(NULL,(const unsigned char **)&p,
			in_len);
	if (!gkt) {
		GOSTerr(GOST_F_PKCS7_GOST94CP_KEY_TRANSPORT_DECRYPT,GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
		return -1;
	}	
	ret = 	decrypt_rfc4490_shared_key_2001(priv,gkt,key,*key_len);
	GOST_KEY_TRANSPORT_free(gkt);
	return ret;
}
