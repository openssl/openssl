
#include "openssl.h"

int boot_cipher()
	{
        SSLeay_add_all_ciphers();
	return(1);
	}

MODULE =  OpenSSL::Cipher	PACKAGE = OpenSSL::Cipher PREFIX = p5_EVP_C_

PROTOTYPES: ENABLE
VERSIONCHECK: DISABLE

void
p5_EVP_C_new(...)
	PREINIT:
		EVP_CIPHER_CTX *ctx;
		const EVP_CIPHER *c;
		char *name;
	PPCODE:
		if ((items == 1) && SvPOK(ST(0)))
			name=SvPV(ST(0),na);
		else if ((items == 2) && SvPOK(ST(1)))
			name=SvPV(ST(1),na);
		else
			croak("Usage: OpenSSL::Cipher::new(type)");
		PUSHs(sv_newmortal());
		c=EVP_get_cipherbyname(name);
		if (c != NULL)
			{
			ctx=malloc(sizeof(EVP_CIPHER_CTX));
			EVP_EncryptInit(ctx,c,NULL,NULL);
			sv_setref_pv(ST(0), "OpenSSL::Cipher", (void*)ctx);
			}

datum
p5_EVP_C_name(ctx)
	EVP_CIPHER_CTX *ctx
	CODE:
		RETVAL.dptr=OBJ_nid2ln(EVP_CIPHER_CTX_nid(ctx));
		RETVAL.dsize=strlen(RETVAL.dptr);
	OUTPUT:
		RETVAL

int
p5_EVP_C_key_length(ctx)
	EVP_CIPHER_CTX *ctx
	CODE:
		RETVAL=EVP_CIPHER_CTX_key_length(ctx);
	OUTPUT:
		RETVAL

int
p5_EVP_C_iv_length(ctx)
	EVP_CIPHER_CTX *ctx
	CODE:
		RETVAL=EVP_CIPHER_CTX_iv_length(ctx);
	OUTPUT:
		RETVAL
	
int
p5_EVP_C_block_size(ctx)
	EVP_CIPHER_CTX *ctx
	CODE:
		RETVAL=EVP_CIPHER_CTX_block_size(ctx);
	OUTPUT:
		RETVAL
	
void
p5_EVP_C_init(ctx,key,iv,enc)
	EVP_CIPHER_CTX *ctx
	datum key
	datum iv
	int enc
	PREINIT:
		char loc_iv[EVP_MAX_IV_LENGTH];
		char loc_key[EVP_MAX_KEY_LENGTH];
		char *ip=loc_iv,*kp=loc_key;
		int i;
		memset(loc_iv,0,EVP_MAX_IV_LENGTH);
		memset(loc_key,0,EVP_MAX_KEY_LENGTH);
	CODE:
		i=key.dsize;
		if (key.dsize > EVP_CIPHER_CTX_key_length(ctx))
			i=EVP_CIPHER_CTX_key_length(ctx);
		if (i > 0)
			{
			memset(kp,0,EVP_MAX_KEY_LENGTH);
			memcpy(kp,key.dptr,i);
			}
		else
			kp=NULL;
		i=iv.dsize;
		if (iv.dsize > EVP_CIPHER_CTX_iv_length(ctx))
			i=EVP_CIPHER_CTX_iv_length(ctx);
		if (i > 0)
			{
			memcpy(ip,iv.dptr,i);
			memset(ip,0,EVP_MAX_IV_LENGTH);
			}
		else
			ip=NULL;
		EVP_CipherInit(ctx,EVP_CIPHER_CTX_cipher(ctx),kp,ip,enc);
		memset(loc_key,0,sizeof(loc_key));
		memset(loc_iv,0,sizeof(loc_iv));

SV *
p5_EVP_C_cipher(ctx,in)
	EVP_CIPHER_CTX *ctx;
	datum in;
	CODE:
		RETVAL=newSVpv("",0);
		SvGROW(RETVAL,in.dsize+EVP_CIPHER_CTX_block_size(ctx)+1);
		EVP_Cipher(ctx,SvPV(RETVAL,na),in.dptr,in.dsize);
		SvCUR_set(RETVAL,in.dsize);
	OUTPUT:
		RETVAL

SV *
p5_EVP_C_update(ctx, in)
	EVP_CIPHER_CTX *ctx
	datum in
	PREINIT:
	int i;
	CODE:
		RETVAL=newSVpv("",0);
		SvGROW(RETVAL,in.dsize+EVP_CIPHER_CTX_block_size(ctx)+1);
		EVP_CipherUpdate(ctx,SvPV(RETVAL,na),&i,in.dptr,in.dsize);
		SvCUR_set(RETVAL,i);
	OUTPUT:
		RETVAL

SV *
p5_EVP_C_final(ctx)
	EVP_CIPHER_CTX *ctx
	PREINIT:
	int i;
	CODE:
		RETVAL=newSVpv("",0);
		SvGROW(RETVAL,EVP_CIPHER_CTX_block_size(ctx)+1);
		if (!EVP_CipherFinal(ctx,SvPV(RETVAL,na),&i))
			sv_setpv(RETVAL,"BAD DECODE");
		else
			SvCUR_set(RETVAL,i);
	OUTPUT:
		RETVAL

void
p5_EVP_C_DESTROY(ctx)
	EVP_CIPHER_CTX *ctx
	CODE:
	free((char *)ctx);

