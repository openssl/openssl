/* Written by Ben Laurie <ben@algroup.co.uk> August 2001 */
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

#include <openssl/engine.h>
#include <openssl/evp.h>
#include "eng_int.h"
/* Maybe this is needed? ... */
#ifdef FLAT_INC
#include "evp_locl.h"
#else
#include "../evp/evp_locl.h"
#endif
#include <openssl/conf.h>

#ifndef OPENSSL_OPENBSD_DEV_CRYPTO

void ENGINE_load_openbsd_dev_crypto(void)
	{
	/* This is a NOP unless OPENSSL_OPENBSD_DEV_CRYPTO is defined */
	return;
	}

#else /* OPENSSL_OPENBSD_DEV_CRYPTO */

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <crypto/cryptodev.h>

/****************************************************/
/* Declare the normal generic ENGINE stuff here ... */

static int dev_crypto_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
				const int **nids, int nid);
static int dev_crypto_digests(ENGINE *e, const EVP_MD **digest,
				const int **nids, int nid);

static const char dev_crypto_id[] = "openbsd_dev_crypto";
static const char dev_crypto_name[] = "OpenBSD /dev/crypto";

static long allow_misaligned;

#define DEV_CRYPTO_CMD_ALLOW_MISALIGNED		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN dev_crypto_cmd_defns[]=
	{
	{ DEV_CRYPTO_CMD_ALLOW_MISALIGNED,
	  "allow_misaligned",
	  "Permit misaligned data to be used",
	  ENGINE_CMD_FLAG_NUMERIC },
	{ 0, NULL, NULL, 0 }
	};

static int dev_crypto_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	switch(cmd)
		{
	case DEV_CRYPTO_CMD_ALLOW_MISALIGNED:
		allow_misaligned=i;
		printf("allow misaligned=%ld\n",allow_misaligned);
		break;
		}

	return 1;
	}

static ENGINE *engine_openbsd_dev_crypto(void)
	{
	ENGINE *engine=ENGINE_new();

	if(!ENGINE_set_id(engine, dev_crypto_id) ||
	   !ENGINE_set_name(engine, dev_crypto_name) ||
	   !ENGINE_set_ciphers(engine, dev_crypto_ciphers) ||
	   !ENGINE_set_digests(engine, dev_crypto_digests) ||
	   !ENGINE_set_ctrl_function(engine, dev_crypto_ctrl) ||
	   !ENGINE_set_cmd_defns(engine, dev_crypto_cmd_defns))
		{
		ENGINE_free(engine);
		return NULL;
		}

	return engine;
	}

void ENGINE_load_openbsd_dev_crypto(void)
	{
	/* Copied from eng_[openssl|dyn].c */
	ENGINE *toadd = engine_openbsd_dev_crypto();
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
	}

/******************************************************************************/
/* Clip in the stuff from crypto/evp/openbsd_hw.c here. NB: What has changed? */
/* I've removed the exposed EVP_*** functions, they're accessed through the   */
/* "dev_crypto_[ciphers|digests]" handlers. I've also moved the EVP_CIPHER    */
/* and EVP_MD structures to the bottom where they are close to the handlers   */
/* that expose them. What should be done? The global data (file-descriptors,  */
/* etc) should be put into ENGINE's ex_data support, and per-context data     */
/* (also file-descriptors perhaps) should be put into the contexts. Also code */
/* formatting, fprintf statements, and OpenSSL-style error handling should be */
/* added (dynamically, like the other ENGINEs). Also, "dynamic" support       */
/* be added to this ENGINE once it's up and running so that it could be built */
/* as a shared-library. What else? device initialisation should take place    */
/* inside an ENGINE 'init()' handler (and likewise 'finish()'). ciphers and   */
/* digests won't be used by the framework unless the ENGINE has been          */
/* successfully initialised (that's one of the things you get for free) so    */
/* initialisation, including returning failure if device setup fails, can be  */
/* handled quite cleanly. This could presumably handle the opening (and then  */
/* closing inside 'finish()') of the 'cryptodev_fd' file-descriptor).         */

/* longest key supported in hardware */
#define MAX_HW_KEY	24
#define MAX_HW_IV	8

#define MD5_DIGEST_LENGTH	16
#define MD5_CBLOCK		64

static int fd;
static int dev_failed;

typedef struct session_op session_op;

#define CDATA(ctx) EVP_C_DATA(session_op,ctx)

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
    fprintf(stderr,"cleanup %d\n",CDATA(ctx)->ses);
    if(ioctl(fd,CIOCFSESSION,&CDATA(ctx)->ses) == -1)
	err("CIOCFSESSION failed");

    OPENSSL_free(CDATA(ctx)->key);

    return 1;
    }

static int dev_crypto_init_key(EVP_CIPHER_CTX *ctx,int cipher,
			       const unsigned char *key,int klen)
    {
    if(!dev_crypto_init(CDATA(ctx)))
	return 0;

    CDATA(ctx)->key=OPENSSL_malloc(MAX_HW_KEY);

    assert(ctx->cipher->iv_len <= MAX_HW_IV);

    memcpy(CDATA(ctx)->key,key,klen);
    
    CDATA(ctx)->cipher=cipher;
    CDATA(ctx)->keylen=klen;

    if (ioctl(fd,CIOCGSESSION,CDATA(ctx)) == -1)
	{
	err("CIOCGSESSION failed");
	return 0;
	}
    return 1;
    }

static int dev_crypto_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
			     const unsigned char *in,unsigned int inl)
    {
    struct crypt_op cryp;
    unsigned char lb[MAX_HW_IV];

    if(!inl)
	return 1;

    assert(CDATA(ctx));
    assert(!dev_failed);

    memset(&cryp,'\0',sizeof cryp);
    cryp.ses=CDATA(ctx)->ses;
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

static int dev_crypto_rc4_init_key(EVP_CIPHER_CTX *ctx,
					const unsigned char *key,
					const unsigned char *iv, int enc)
    { return dev_crypto_init_key(ctx,CRYPTO_ARC4,key,16); }

typedef struct
    {
    session_op sess;
    char *data;
    int len;
    unsigned char md[EVP_MAX_MD_SIZE];
    } MD_DATA;

static int dev_crypto_init_digest(MD_DATA *md_data,int mac)
    {
    if(!dev_crypto_init(&md_data->sess))
	return 0;

    md_data->len=0;
    md_data->data=NULL;

    md_data->sess.mac=mac;

    if (ioctl(fd,CIOCGSESSION,&md_data->sess) == -1)
	{
	err("CIOCGSESSION failed");
	return 0;
	}
    fprintf(stderr,"opened %d\n",md_data->sess.ses);
    return 1;
    }

static int dev_crypto_cleanup_digest(MD_DATA *md_data)
    {
    fprintf(stderr,"cleanup %d\n",md_data->sess.ses);
    if (ioctl(fd,CIOCFSESSION,&md_data->sess.ses) == -1)
	{
	err("CIOCFSESSION failed");
	return 0;
	}

    return 1;
    }

/* FIXME: if device can do chained MACs, then don't accumulate */
/* FIXME: move accumulation to the framework */
static int dev_crypto_md5_init(EVP_MD_CTX *ctx)
    { return dev_crypto_init_digest(ctx->md_data,CRYPTO_MD5); }

static int do_digest(int ses,unsigned char *md,const void *data,int len)
    {
    struct crypt_op cryp;
    static unsigned char md5zero[16]=
	{
	0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,
	0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e
	};

    /* some cards can't do zero length */
    if(!len)
	{
	memcpy(md,md5zero,16);
	return 1;
	}

    memset(&cryp,'\0',sizeof cryp);
    cryp.ses=ses;
    cryp.op=COP_ENCRYPT;/* required to do the MAC rather than check it */
    cryp.len=len;
    cryp.src=(caddr_t)data;
    cryp.dst=(caddr_t)data; /* FIXME!!! */
    cryp.mac=(caddr_t)md;

    if(ioctl(fd, CIOCCRYPT, &cryp) == -1)
	{
	if(errno == EINVAL && allow_misaligned) /* buffer is misaligned */
	    {
	    char *dcopy;

	    dcopy=OPENSSL_malloc(len);
	    memcpy(dcopy,data,len);
	    cryp.src=dcopy;
	    cryp.dst=cryp.src; /* FIXME!!! */

	    if(ioctl(fd, CIOCCRYPT, &cryp) == -1)
		{
		err("CIOCCRYPT(MAC2) failed");
		abort();
		return 0;
		}
	    OPENSSL_free(dcopy);
	    }
	else
	    {
	    err("CIOCCRYPT(MAC) failed");
	    abort();
	    return 0;
	    }
	}
    /*    printf("done\n"); */

    return 1;
    }

static int dev_crypto_md5_update(EVP_MD_CTX *ctx,const void *data,
				 unsigned long len)
    {
    MD_DATA *md_data=ctx->md_data;

    if(ctx->flags&EVP_MD_CTX_FLAG_ONESHOT)
	return do_digest(md_data->sess.ses,md_data->md,data,len);

    md_data->data=OPENSSL_realloc(md_data->data,md_data->len+len);
    memcpy(md_data->data+md_data->len,data,len);
    md_data->len+=len;

    return 1;
    }	

static int dev_crypto_md5_final(EVP_MD_CTX *ctx,unsigned char *md)
    {
    int ret;
    MD_DATA *md_data=ctx->md_data;

    if(ctx->flags&EVP_MD_CTX_FLAG_ONESHOT)
	{
	memcpy(md,md_data->md,MD5_DIGEST_LENGTH);
	ret=1;
	}
    else
	{
	ret=do_digest(md_data->sess.ses,md,md_data->data,md_data->len);
	OPENSSL_free(md_data->data);
	md_data->data=NULL;
	md_data->len=0;
	}

    return ret;
    }

static int dev_crypto_md5_copy(EVP_MD_CTX *to,const EVP_MD_CTX *from)
    {
    const MD_DATA *from_md=from->md_data;
    MD_DATA *to_md=to->md_data;

    /* How do we copy sessions? */
    assert(from->digest->flags&EVP_MD_FLAG_ONESHOT);

    to_md->data=OPENSSL_malloc(from_md->len);
    memcpy(to_md->data,from_md->data,from_md->len);

    return 1;
    }

static int dev_crypto_md5_cleanup(EVP_MD_CTX *ctx)
    {
    return dev_crypto_cleanup_digest(ctx->md_data);
    }

/**************************************************************************/
/* Here are the moved declarations of the EVP_CIPHER and EVP_MD           */
/* implementations. They're down here to be within easy editor-distance   */
/* of the digests and ciphers handler functions.                          */

#define dev_crypto_des_ede3_cbc_cipher dev_crypto_cipher

BLOCK_CIPHER_def_cbc(dev_crypto_des_ede3, session_op, NID_des_ede3, 8, 24, 8,
		     0, dev_crypto_des_ede3_init_key,
		     dev_crypto_cleanup, 
		     EVP_CIPHER_set_asn1_iv,
		     EVP_CIPHER_get_asn1_iv,
		     NULL)

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

static const EVP_MD md5_md=
    {
    NID_md5,
    NID_md5WithRSAEncryption,
    MD5_DIGEST_LENGTH,
    EVP_MD_FLAG_ONESHOT,	/* XXX: set according to device info... */
    dev_crypto_md5_init,
    dev_crypto_md5_update,
    dev_crypto_md5_final,
    dev_crypto_md5_copy,
    dev_crypto_md5_cleanup,
    EVP_PKEY_RSA_method,
    MD5_CBLOCK,
    sizeof(MD_DATA),
    };

/****************************************************************/
/* Implement the dev_crypto_[ciphers|digests] handlers here ... */

static int cipher_nids[] = {NID_des_ede3_cbc, NID_rc4};
static int cipher_nids_num = 2;
static int digest_nids[] = {NID_md5};
static int digest_nids_num = 1;

static int dev_crypto_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
				const int **nids, int nid)
	{
        if(!cipher)
                {
                /* We are returning a list of supported nids */
                *nids = cipher_nids;
                return cipher_nids_num;
                }
        /* We are being asked for a specific cipher */
        if(nid == NID_rc4)
                *cipher = &r4_cipher;
        else if(nid == NID_des_ede3_cbc)
                *cipher = &dev_crypto_des_ede3_cbc;
        else
                {
                *cipher = NULL;
                return 0;
                }
        return 1;
	}

static int dev_crypto_digests(ENGINE *e, const EVP_MD **digest,
				const int **nids, int nid)
	{
        if(!digest)
                {
                /* We are returning a list of supported nids */
                *nids = digest_nids;
                return digest_nids_num;
                }
        /* We are being asked for a specific digest */
        if(nid == NID_md5)
                *digest = &md5_md;
        else
                {
                *digest = NULL;
                return 0;
                }
        return 1;
	}

#endif /* OPENSSL_OPENBSD_DEV_CRYPTO */
