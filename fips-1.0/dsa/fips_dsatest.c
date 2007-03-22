/* crypto/dsa/dsatest.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "e_os.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/fips.h>
#include <openssl/fips_rand.h>


#if defined(OPENSSL_NO_DSA) || !defined(OPENSSL_FIPS)
int main(int argc, char *argv[])
{
    printf("No FIPS DSA support\n");
    return(0);
}
#else
#include <openssl/dsa.h>

#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK     _far _loadds
#else
#define MS_CALLBACK
#endif

#include "fips_utl.h"

static int MS_CALLBACK dsa_cb(int p, int n, BN_GENCB *cb);

/* seed, out_p, out_q, out_g are taken from the updated Appendix 5 to
 * FIPS PUB 186 and also appear in Appendix 5 to FIPS PIB 186-1 */
static unsigned char seed[20]={
	0xd5,0x01,0x4e,0x4b,0x60,0xef,0x2b,0xa8,0xb6,0x21,0x1b,0x40,
	0x62,0xba,0x32,0x24,0xe0,0x42,0x7d,0xd3,
	};

static unsigned char out_p[]={
	0x8d,0xf2,0xa4,0x94,0x49,0x22,0x76,0xaa,
	0x3d,0x25,0x75,0x9b,0xb0,0x68,0x69,0xcb,
	0xea,0xc0,0xd8,0x3a,0xfb,0x8d,0x0c,0xf7,
	0xcb,0xb8,0x32,0x4f,0x0d,0x78,0x82,0xe5,
	0xd0,0x76,0x2f,0xc5,0xb7,0x21,0x0e,0xaf,
	0xc2,0xe9,0xad,0xac,0x32,0xab,0x7a,0xac,
	0x49,0x69,0x3d,0xfb,0xf8,0x37,0x24,0xc2,
	0xec,0x07,0x36,0xee,0x31,0xc8,0x02,0x91,
	};

static unsigned char out_q[]={
	0xc7,0x73,0x21,0x8c,0x73,0x7e,0xc8,0xee,
	0x99,0x3b,0x4f,0x2d,0xed,0x30,0xf4,0x8e,
	0xda,0xce,0x91,0x5f,
	};

static unsigned char out_g[]={
	0x62,0x6d,0x02,0x78,0x39,0xea,0x0a,0x13,
	0x41,0x31,0x63,0xa5,0x5b,0x4c,0xb5,0x00,
	0x29,0x9d,0x55,0x22,0x95,0x6c,0xef,0xcb,
	0x3b,0xff,0x10,0xf3,0x99,0xce,0x2c,0x2e,
	0x71,0xcb,0x9d,0xe5,0xfa,0x24,0xba,0xbf,
	0x58,0xe5,0xb7,0x95,0x21,0x92,0x5c,0x9c,
	0xc4,0x2e,0x9f,0x6f,0x46,0x4b,0x08,0x8c,
	0xc5,0x72,0xaf,0x53,0xe6,0xd7,0x88,0x02,
	};

static const unsigned char str1[]="12345678901234567890";

static const char rnd_seed[] = "string to make the random number generator think it has entropy";
static const unsigned char rnd_key1[]="12345678";
static const unsigned char rnd_key2[]="abcdefgh";

int main(int argc, char **argv)
	{
	DSA *dsa=NULL;
	int counter,ret=0,i,j;
	unsigned char buf[256];
	unsigned long h;
	DSA_SIG *sig = NULL;
	BN_GENCB cb;
	BN_GENCB_set(&cb, dsa_cb, stderr);

#ifdef OPENSSL_FIPS
	if(!FIPS_mode_set(1))
	    {
	    do_print_errors();
	    EXIT(1);
	    }
#endif
#if 0
	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif

#if 0
	FIPS_rand_set_key(rnd_key1,rnd_key2);
	RAND_seed(rnd_seed, sizeof rnd_seed);
#endif

	fprintf(stderr,"test generation of DSA parameters\n");

	dsa = FIPS_dsa_new();
	DSA_generate_parameters_ex(dsa, 512,seed,20,&counter,&h,&cb);

	fprintf(stderr,"seed\n");
	for (i=0; i<20; i+=4)
		{
		fprintf(stderr,"%02X%02X%02X%02X ",
			seed[i],seed[i+1],seed[i+2],seed[i+3]);
		}
	fprintf(stderr,"\ncounter=%d h=%ld\n",counter,h);
		
	if (dsa == NULL) goto end;
	/*DSA_print(bio_err,dsa,0);*/
	if (counter != 105) 
		{
		fprintf(stderr,"counter should be 105\n");
		goto end;
		}
	if (h != 2)
		{
		fprintf(stderr,"h should be 2\n");
		goto end;
		}

	i=BN_bn2bin(dsa->q,buf);
	j=sizeof(out_q);
	if ((i != j) || (memcmp(buf,out_q,i) != 0))
		{
		fprintf(stderr,"q value is wrong\n");
		goto end;
		}

	i=BN_bn2bin(dsa->p,buf);
	j=sizeof(out_p);
	if ((i != j) || (memcmp(buf,out_p,i) != 0))
		{
		fprintf(stderr,"p value is wrong\n");
		goto end;
		}

	i=BN_bn2bin(dsa->g,buf);
	j=sizeof(out_g);
	if ((i != j) || (memcmp(buf,out_g,i) != 0))
		{
		fprintf(stderr,"g value is wrong\n");
		goto end;
		}
	DSA_generate_key(dsa);

	sig = DSA_do_sign(str1, 20, dsa);

	if (sig)
		{	
		i = DSA_do_verify(str1, 20, sig, dsa);
		DSA_SIG_free(sig);
		}
	else
		i = 0;
	if (i == 1)
		ret=1;
end:
	if (!ret)
		do_print_errors();
	if (dsa != NULL) FIPS_dsa_free(dsa);
#if 0
	CRYPTO_mem_leaks(bio_err);
#endif
	EXIT(!ret);
	return(!ret);
	}

static int cb_exit(int ec)
	{
	EXIT(ec);
	return(0);		/* To keep some compilers quiet */
	}

static int MS_CALLBACK dsa_cb(int p, int n, BN_GENCB *cb)
	{
	char c='*';
	static int ok=0,num=0;

	if (p == 0) { c='.'; num++; };
	if (p == 1) c='+';
	if (p == 2) { c='*'; ok++; }
	if (p == 3) c='\n';
	fwrite(&c,1, 1, cb->arg);
	fflush(cb->arg);

	if (!ok && (p == 0) && (num > 1))
		{
		fprintf(cb->arg,"error in dsatest\n");
		cb_exit(1);
		}
	return 1;
	}
#endif
