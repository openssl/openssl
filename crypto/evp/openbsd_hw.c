/*
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
#include "evp_locl.h"
#include <assert.h>

// longest key supported in hardware
#define MAX_HW_KEY	24

static int fd;
static int dev_failed;

static void err(const char *str)
    {
    fprintf(stderr,"%s: errno %d\n",str,errno);
    }

static int dev_crypto_init(EVP_CIPHER_CTX *ctx)
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
    if(!ctx->c.dev_crypto)
	{
	ctx->c.dev_crypto=OPENSSL_malloc(sizeof *ctx->c.dev_crypto);
	memset(ctx->c.dev_crypto,'\0',sizeof *ctx->c.dev_crypto);
	ctx->c.dev_crypto->key=OPENSSL_malloc(MAX_HW_KEY);
	}
    
    return 1;
    }

static int dev_crypto_cleanup(EVP_CIPHER_CTX *ctx)
    {
    if(ioctl(fd,CIOCFSESSION,ctx->c.dev_crypto->ses) == -1)
	err("CIOCFSESSION failed");

    OPENSSL_free(ctx->c.dev_crypto->key);
    OPENSSL_free(ctx->c.dev_crypto);
    ctx->c.dev_crypto=NULL;

    return 1;
    }

// FIXME: there should be some non-fatal way to report we fell back to s/w?
static int dev_crypto_des_ede3_init_key(EVP_CIPHER_CTX *ctx,
					const unsigned char *key,
					const unsigned char *iv, int enc)
    {
    if(!dev_crypto_init(ctx))
	{
	// fall back to using software...
	ctx->cipher=EVP_des_ede3_cbc();
	return ctx->cipher->init(ctx,key,iv,enc);
	}
    memcpy(ctx->c.dev_crypto->key,key,24);
    
    ctx->c.dev_crypto->cipher=CRYPTO_3DES_CBC;
    ctx->c.dev_crypto->mac=0;
    ctx->c.dev_crypto->keylen=24;

    if (ioctl(fd,CIOCGSESSION,ctx->c.dev_crypto) == -1)
	{
	err("CIOCGSESSION failed");
	// fall back to using software...
	dev_crypto_cleanup(ctx);
	ctx->cipher=EVP_des_ede3_cbc();
	return ctx->cipher->init(ctx,key,iv,enc);
	}
    return 1;
    }

static int dev_crypto_des_ede3_cbc_cipher(EVP_CIPHER_CTX *ctx, 
					  unsigned char *out,
					  const unsigned char *in,
					  unsigned int inl)
    {
    struct crypt_op cryp;
    unsigned char lb[8];

    assert(ctx->c.dev_crypto);
    assert(!dev_failed);

    memset(&cryp,'\0',sizeof cryp);
    cryp.ses=ctx->c.dev_crypto->ses;
    cryp.op=ctx->encrypt ? COP_ENCRYPT : COP_DECRYPT;
    cryp.flags=0;
    //    cryp.len=((inl+7)/8)*8;
    cryp.len=inl;
    assert((inl&7) == 0);
    cryp.src=(caddr_t)in;
    cryp.dst=(caddr_t)out;
    cryp.mac=0;
    cryp.iv=(caddr_t)ctx->iv;

    if(!ctx->encrypt)
	memcpy(lb,&in[cryp.len-8],8);

    if (ioctl(fd, CIOCCRYPT, &cryp) == -1)
	{
	err("CIOCCRYPT failed");
	abort();
	return 0;
	}

    if(ctx->encrypt)
	memcpy(ctx->iv,&out[cryp.len-8],8);
    else
	memcpy(ctx->iv,lb,8);

    return 1;
    }

BLOCK_CIPHER_def_cbc(dev_crypto_des_ede3, des_ede,NID_des_ede3, 8, 24, 8,
		     0, dev_crypto_des_ede3_init_key,
		     dev_crypto_cleanup, 
		     EVP_CIPHER_set_asn1_iv,
		     EVP_CIPHER_get_asn1_iv,
		     NULL)
#else
static void *dummy=&dummy;
#endif
