/* Written by Ben Laurie, 2001 */
/*
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 */

#ifdef OPENSSL_OPENBSD_DEV_CRYPTO

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include "evp_locl.h"
#include <assert.h>

/* longest key supported in hardware */
#define MAX_HW_KEY	24
#define MAX_HW_IV	8

#define MD5_DIGEST_LENGTH	16
#define MD5_CBLOCK		64

static int fd;
static int dev_failed;

typedef struct session_op session_op;

#define data(ctx) EVP_C_DATA(session_op,ctx)

static void err(const char *str)
    {
    fprintf(stderr,"%s: errno %d\n",str,errno);
    }

static int dev_crypto_init(session_op *ses)
    {
    if(dev_failed)
	return 0;
    if(!fd)
	{
	int cryptodev_fd;

        if ((cryptodev_fd=open("/dev/crypto",O_RDWR,0)) < 0)
	    {
	    err("/dev/crypto");
	    dev_failed=1;
	    return 0;
	    }
        if (ioctl(cryptodev_fd,CRIOGET,&fd) == -1)
	    {
	    err("CRIOGET failed");
	    close(cryptodev_fd);
	    dev_failed=1;
	    return 0;
	    }
	close(cryptodev_fd);
	}
    assert(ses);
    memset(ses,'\0',sizeof *ses);

    return 1;
    }

static int dev_crypto_cleanup(EVP_CIPHER_CTX *ctx)
    {
    printf("Cleanup %d\n",data(ctx)->ses);
    if(ioctl(fd,CIOCFSESSION,&data(ctx)->ses) == -1)
	err("CIOCFSESSION failed");

    OPENSSL_free(data(ctx)->key);

    return 1;
    }

static int dev_crypto_init_key(EVP_CIPHER_CTX *ctx,int cipher,
			       const unsigned char *key,int klen)
    {
    if(!dev_crypto_init(data(ctx)))
	return 0;

    data(ctx)->key=OPENSSL_malloc(MAX_HW_KEY);

    assert(ctx->cipher->iv_len <= MAX_HW_IV);

    memcpy(data(ctx)->key,key,klen);
    
    data(ctx)->cipher=cipher;
    data(ctx)->keylen=klen;

    if (ioctl(fd,CIOCGSESSION,data(ctx)) == -1)
	{
	err("CIOCGSESSION failed");
	return 0;
	}
    printf("Init %d\n",data(ctx)->ses);
    return 1;
    }

static int dev_crypto_init_digest(session_op *ses,int mac)
    {
    if(!dev_crypto_init(ses))
	return 0;

    ses->mac=mac;

    if (ioctl(fd,CIOCGSESSION,ses) == -1)
	{
	err("CIOCGSESSION failed");
	return 0;
	}
    printf("Init MAC %d\n",ses->ses);
    return 1;
    }

static int dev_crypto_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
			     const unsigned char *in,unsigned int inl)
    {
    struct crypt_op cryp;
    unsigned char lb[MAX_HW_IV];

    if(!inl)
	return 1;

    assert(data(ctx));
    assert(!dev_failed);

    memset(&cryp,'\0',sizeof cryp);
    cryp.ses=data(ctx)->ses;
    cryp.op=ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;
    cryp.flags=0;
    cryp.len=inl;
    assert((inl&(ctx->cipher->block_size-1)) == 0);
    cryp.src=(caddr_t)in;
    cryp.dst=(caddr_t)out;
    cryp.mac=0;
    if(ctx->cipher->iv_len)
	cryp.iv=(caddr_t)ctx->iv;

    if(!ctx->encrypt)
	memcpy(lb,&in[cryp.len-ctx->cipher->iv_len],ctx->cipher->iv_len);

    if(ioctl(fd, CIOCCRYPT, &cryp) == -1)
	{
	if(errno == EINVAL) /* buffers are misaligned */
	    {
	    unsigned int cinl=0;
	    char *cin=NULL;
	    char *cout=NULL;

	    /* NB: this can only make cinl != inl with stream ciphers */
	    cinl=(inl+3)/4*4;

	    if(((unsigned long)in&3) || cinl != inl)
		{
		cin=OPENSSL_malloc(cinl);
		memcpy(cin,in,inl);
		cryp.src=cin;
		}

	    if(((unsigned long)out&3) || cinl != inl)
		{
		cout=OPENSSL_malloc(cinl);
		cryp.dst=cout;
		}

	    cryp.len=cinl;

	    if(ioctl(fd, CIOCCRYPT, &cryp) == -1)
		{
		err("CIOCCRYPT(2) failed");
		printf("src=%p dst=%p\n",cryp.src,cryp.dst);
		abort();
		return 0;
		}
		
	    if(cout)
		{
		memcpy(out,cout,inl);
		OPENSSL_free(cout);
		}
	    if(cin)
		OPENSSL_free(cin);
	    }
	else 
	    {	    
	    err("CIOCCRYPT failed");
	    abort();
	    return 0;
	    }
	}

    if(ctx->encrypt)
	memcpy(ctx->iv,&out[cryp.len-ctx->cipher->iv_len],ctx->cipher->iv_len);
    else
	memcpy(ctx->iv,lb,ctx->cipher->iv_len);

    return 1;
    }

static int dev_crypto_des_ede3_init_key(EVP_CIPHER_CTX *ctx,
					const unsigned char *key,
					const unsigned char *iv, int enc)
    { return dev_crypto_init_key(ctx,CRYPTO_3DES_CBC,key,24); }

#define dev_crypto_des_ede3_cbc_cipher dev_crypto_cipher

BLOCK_CIPHER_def_cbc(dev_crypto_des_ede3, session_op, NID_des_ede3, 8, 24, 8,
		     0, dev_crypto_des_ede3_init_key,
		     dev_crypto_cleanup, 
		     EVP_CIPHER_set_asn1_iv,
		     EVP_CIPHER_get_asn1_iv,
		     NULL)

static int dev_crypto_rc4_init_key(EVP_CIPHER_CTX *ctx,
					const unsigned char *key,
					const unsigned char *iv, int enc)
    { return dev_crypto_init_key(ctx,CRYPTO_ARC4,key,16); }

static const EVP_CIPHER r4_cipher=
    {
    NID_rc4,
    1,16,0,	/* FIXME: key should be up to 256 bytes */
    EVP_CIPH_VARIABLE_LENGTH,
    dev_crypto_rc4_init_key,
    dev_crypto_cipher,
    dev_crypto_cleanup,
    sizeof(session_op),
    NULL,
    NULL,
    NULL
    };

const EVP_CIPHER *EVP_dev_crypto_rc4(void)
    { return &r4_cipher; }

static int dev_crypto_md5_init(void *md_data)
    { return dev_crypto_init_digest(md_data,CRYPTO_MD5); }

static int dev_crypto_md5_update(void *md_data,const void *data,
				 unsigned long len)
    {
    struct crypt_op cryp;
    session_op *ses=md_data;
    char buf[MD5_DIGEST_LENGTH];

    printf("update\n");
    memset(&cryp,'\0',sizeof cryp);
    cryp.ses=ses->ses;
    cryp.len=len;
    cryp.src=(caddr_t)data;
    cryp.dst=buf;

    if(ioctl(fd, CIOCCRYPT, &cryp) == -1)
	{
	err("CIOCCRYPT(MAC) failed");
	abort();
	return 0;
	}
    printf("update done\n");
    return 1;
    }

static int dev_crypto_md5_final(unsigned char *md,void *md_data)
    {
    struct crypt_op cryp;
    session_op *ses=md_data;

    printf("final\n");
    memset(&cryp,'\0',sizeof cryp);
    cryp.ses=ses->ses;
    cryp.len=0;
    cryp.op=COP_ENCRYPT;/* required to do the MAC rather than check it */
    cryp.src=(caddr_t)md;
    cryp.dst=(caddr_t)md;

    if(ioctl(fd, CIOCCRYPT, &cryp) == -1)
	{
	err("CIOCCRYPT(MAC,final) failed");
	abort();
	return 0;
	}

    printf("final done\n");
    return 1;
    }

static const EVP_MD md5_md=
    {
    NID_md5,
    NID_md5WithRSAEncryption,
    MD5_DIGEST_LENGTH,
    dev_crypto_md5_init,
    dev_crypto_md5_update,
    dev_crypto_md5_final,
    EVP_PKEY_RSA_method,
    MD5_CBLOCK,
    sizeof(session_op),
    };

const EVP_MD *EVP_dev_crypto_md5(void)
    { return &md5_md; }

#else
static void *dummy=&dummy;
#endif
