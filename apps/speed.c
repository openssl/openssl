/* apps/speed.c */
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

/* most of this code has been pilfered from my libdes speed.c program */

#undef SECONDS
#define SECONDS		3	
#define RSA_SECONDS	10
#define DSA_SECONDS	10

/* 11-Sep-92 Andrew Daviel   Support for Silicon Graphics IRIX added */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

#undef PROG
#define PROG speed_main

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include "apps.h"
#ifdef NO_STDIO
#define APPS_WIN16
#endif
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#if !defined(MSDOS) && (!defined(VMS) || defined(__DECC))
#define TIMES
#endif

#ifndef _IRIX
#include <time.h>
#endif
#ifdef TIMES
#include <sys/types.h>
#include <sys/times.h>
#endif

/* Depending on the VMS version, the tms structure is perhaps defined.
   The __TMS macro will show if it was.  If it wasn't defined, we should
   undefine TIMES, since that tells the rest of the program how things
   should be handled.				-- Richard Levitte */
#if defined(VMS) && defined(__DECC) && !defined(__TMS)
#undef TIMES
#endif

#ifndef TIMES
#include <sys/timeb.h>
#endif

#if defined(sun) || defined(__ultrix)
#define _POSIX_SOURCE
#include <limits.h>
#include <sys/param.h>
#endif

#ifndef NO_DES
#include <openssl/des.h>
#endif
#ifndef NO_MD2
#include <openssl/md2.h>
#endif
#ifndef NO_MDC2
#include <openssl/mdc2.h>
#endif
#ifndef NO_MD5
#include <openssl/md5.h>
#endif
#ifndef NO_HMAC
#include <openssl/hmac.h>
#endif
#include <openssl/evp.h>
#ifndef NO_SHA
#include <openssl/sha.h>
#endif
#ifndef NO_RIPEMD
#include <openssl/ripemd.h>
#endif
#ifndef NO_RC4
#include <openssl/rc4.h>
#endif
#ifndef NO_RC5
#include <openssl/rc5.h>
#endif
#ifndef NO_RC2
#include <openssl/rc2.h>
#endif
#ifndef NO_IDEA
#include <openssl/idea.h>
#endif
#ifndef NO_BF
#include <openssl/blowfish.h>
#endif
#ifndef NO_CAST
#include <openssl/cast.h>
#endif
#ifndef NO_RSA
#include <openssl/rsa.h>
#include "./testrsa.h"
#endif
#include <openssl/x509.h>
#ifndef NO_DSA
#include "./testdsa.h"
#endif

/* The following if from times(3) man page.  It may need to be changed */
#ifndef HZ
# ifndef CLK_TCK
#  ifndef _BSD_CLK_TCK_ /* FreeBSD hack */
#   define HZ	100.0
#  else /* _BSD_CLK_TCK_ */
#   define HZ ((double)_BSD_CLK_TCK_)
#  endif
# else /* CLK_TCK */
#  define HZ ((double)CLK_TCK)
# endif
#endif

#undef BUFSIZE
#define BUFSIZE	((long)1024*8+1)
int run=0;

static double Time_F(int s);
static void print_message(char *s,long num,int length);
static void pkey_print_message(char *str,char *str2,long num,int bits,int sec);
#ifdef SIGALRM
#if defined(__STDC__) || defined(sgi) || defined(_AIX)
#define SIGRETTYPE void
#else
#define SIGRETTYPE int
#endif 

static SIGRETTYPE sig_done(int sig);
static SIGRETTYPE sig_done(int sig)
	{
	signal(SIGALRM,sig_done);
	run=0;
#ifdef LINT
	sig=sig;
#endif
	}
#endif

#define START	0
#define STOP	1

static double Time_F(int s)
	{
	double ret;
#ifdef TIMES
	static struct tms tstart,tend;

	if (s == START)
		{
		times(&tstart);
		return(0);
		}
	else
		{
		times(&tend);
		ret=((double)(tend.tms_utime-tstart.tms_utime))/HZ;
		return((ret < 1e-3)?1e-3:ret);
		}
#else /* !times() */
	static struct timeb tstart,tend;
	long i;

	if (s == START)
		{
		ftime(&tstart);
		return(0);
		}
	else
		{
		ftime(&tend);
		i=(long)tend.millitm-(long)tstart.millitm;
		ret=((double)(tend.time-tstart.time))+((double)i)/1000.0;
		return((ret < 0.001)?0.001:ret);
		}
#endif
	}

int MAIN(int argc, char **argv)
	{
	unsigned char *buf=NULL,*buf2=NULL;
	int ret=1;
#define ALGOR_NUM	14
#define SIZE_NUM	5
#define RSA_NUM		4
#define DSA_NUM		3
	long count,rsa_count;
	int i,j,k,rsa_num,rsa_num2;
#ifndef NO_MD2
	unsigned char md2[MD2_DIGEST_LENGTH];
#endif
#ifndef NO_MDC2
	unsigned char mdc2[MDC2_DIGEST_LENGTH];
#endif
#ifndef NO_MD5
	unsigned char md5[MD5_DIGEST_LENGTH];
	unsigned char hmac[MD5_DIGEST_LENGTH];
#endif
#ifndef NO_SHA
	unsigned char sha[SHA_DIGEST_LENGTH];
#endif
#ifndef NO_RIPEMD
	unsigned char rmd160[RIPEMD160_DIGEST_LENGTH];
#endif
#ifndef NO_RC4
	RC4_KEY rc4_ks;
#endif
#ifndef NO_RC5
	RC5_32_KEY rc5_ks;
#endif
#ifndef NO_RC2
	RC2_KEY rc2_ks;
#endif
#ifndef NO_IDEA
	IDEA_KEY_SCHEDULE idea_ks;
#endif
#ifndef NO_BF
	BF_KEY bf_ks;
#endif
#ifndef NO_CAST
	CAST_KEY cast_ks;
#endif
	static unsigned char key16[16]=
		{0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
		 0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12};
	unsigned char iv[8];
#ifndef NO_DES
	des_cblock *buf_as_des_cblock = NULL;
	static des_cblock key ={0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
	static des_cblock key2={0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12};
	static des_cblock key3={0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34};
	des_key_schedule sch,sch2,sch3;
#endif
#define	D_MD2		0
#define	D_MDC2		1
#define	D_MD5		2
#define	D_HMAC		3
#define	D_SHA1		4
#define D_RMD160	5
#define	D_RC4		6
#define	D_CBC_DES	7
#define	D_EDE3_DES	8
#define	D_CBC_IDEA	9
#define	D_CBC_RC2	10
#define	D_CBC_RC5	11
#define	D_CBC_BF	12
#define	D_CBC_CAST	13
	double d,results[ALGOR_NUM][SIZE_NUM];
	static int lengths[SIZE_NUM]={8,64,256,1024,8*1024};
	long c[ALGOR_NUM][SIZE_NUM];
	static char *names[ALGOR_NUM]={
		"md2","mdc2","md5","hmac(md5)","sha1","rmd160","rc4",
		"des cbc","des ede3","idea cbc",
		"rc2 cbc","rc5-32/12 cbc","blowfish cbc","cast cbc"};
#define	R_DSA_512	0
#define	R_DSA_1024	1
#define	R_DSA_2048	2
#define	R_RSA_512	0
#define	R_RSA_1024	1
#define	R_RSA_2048	2
#define	R_RSA_4096	3
#ifndef NO_RSA
	RSA *rsa_key[RSA_NUM];
	long rsa_c[RSA_NUM][2];
	double rsa_results[RSA_NUM][2];
	static unsigned int rsa_bits[RSA_NUM]={512,1024,2048,4096};
	static unsigned char *rsa_data[RSA_NUM]=
		{test512,test1024,test2048,test4096};
	static int rsa_data_length[RSA_NUM]={
		sizeof(test512),sizeof(test1024),
		sizeof(test2048),sizeof(test4096)};
#endif
#ifndef NO_DSA
	DSA *dsa_key[DSA_NUM];
	long dsa_c[DSA_NUM][2];
	double dsa_results[DSA_NUM][2];
	static unsigned int dsa_bits[DSA_NUM]={512,1024,2048};
#endif
	int rsa_doit[RSA_NUM];
	int dsa_doit[DSA_NUM];
	int doit[ALGOR_NUM];
	int pr_header=0;

	apps_startup();
#ifndef NO_DSA
	memset(dsa_key,0,sizeof(dsa_key));
#endif

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

#ifndef NO_RSA
	memset(rsa_key,0,sizeof(rsa_key));
	for (i=0; i<RSA_NUM; i++)
		rsa_key[i]=NULL;
#endif

	if ((buf=(unsigned char *)Malloc((int)BUFSIZE)) == NULL)
		{
		BIO_printf(bio_err,"out of memory\n");
		goto end;
		}
#ifndef NO_DES
	buf_as_des_cblock = (des_cblock *)buf;
#endif
	if ((buf2=(unsigned char *)Malloc((int)BUFSIZE)) == NULL)
		{
		BIO_printf(bio_err,"out of memory\n");
		goto end;
		}

	memset(c,0,sizeof(c));
	memset(iv,0,sizeof(iv));

	for (i=0; i<ALGOR_NUM; i++)
		doit[i]=0;
	for (i=0; i<RSA_NUM; i++)
		rsa_doit[i]=0;
	for (i=0; i<DSA_NUM; i++)
		dsa_doit[i]=0;
	
	j=0;
	argc--;
	argv++;
	while (argc)
		{
#ifndef NO_MD2
		if	(strcmp(*argv,"md2") == 0) doit[D_MD2]=1;
		else
#endif
#ifndef NO_MDC2
			if (strcmp(*argv,"mdc2") == 0) doit[D_MDC2]=1;
		else
#endif
#ifndef NO_MD5
			if (strcmp(*argv,"md5") == 0) doit[D_MD5]=1;
		else
#endif
#ifndef NO_MD5
			if (strcmp(*argv,"hmac") == 0) doit[D_HMAC]=1;
		else
#endif
#ifndef NO_SHA
			if (strcmp(*argv,"sha1") == 0) doit[D_SHA1]=1;
		else
			if (strcmp(*argv,"sha") == 0) doit[D_SHA1]=1;
		else
#endif
#ifndef NO_RIPEMD
			if (strcmp(*argv,"ripemd") == 0) doit[D_RMD160]=1;
		else
			if (strcmp(*argv,"rmd160") == 0) doit[D_RMD160]=1;
		else
			if (strcmp(*argv,"ripemd160") == 0) doit[D_RMD160]=1;
		else
#endif
#ifndef NO_RC4
			if (strcmp(*argv,"rc4") == 0) doit[D_RC4]=1;
		else 
#endif
#ifndef NO_DEF
			if (strcmp(*argv,"des-cbc") == 0) doit[D_CBC_DES]=1;
		else	if (strcmp(*argv,"des-ede3") == 0) doit[D_EDE3_DES]=1;
		else
#endif
#ifndef NO_RSA
#ifdef RSAref
			if (strcmp(*argv,"rsaref") == 0) 
			{
			RSA_set_default_method(RSA_PKCS1_RSAref());
			j--;
			}
		else
#endif
			if (strcmp(*argv,"openssl") == 0) 
			{
			RSA_set_default_method(RSA_PKCS1_SSLeay());
			j--;
			}
		else
#endif /* !NO_RSA */
		     if (strcmp(*argv,"dsa512") == 0) dsa_doit[R_DSA_512]=2;
		else if (strcmp(*argv,"dsa1024") == 0) dsa_doit[R_DSA_1024]=2;
		else if (strcmp(*argv,"dsa2048") == 0) dsa_doit[R_DSA_2048]=2;
		else if (strcmp(*argv,"rsa512") == 0) rsa_doit[R_RSA_512]=2;
		else if (strcmp(*argv,"rsa1024") == 0) rsa_doit[R_RSA_1024]=2;
		else if (strcmp(*argv,"rsa2048") == 0) rsa_doit[R_RSA_2048]=2;
		else if (strcmp(*argv,"rsa4096") == 0) rsa_doit[R_RSA_4096]=2;
		else
#ifndef NO_RC2
		     if (strcmp(*argv,"rc2-cbc") == 0) doit[D_CBC_RC2]=1;
		else if (strcmp(*argv,"rc2") == 0) doit[D_CBC_RC2]=1;
		else
#endif
#ifndef NO_RC5
		     if (strcmp(*argv,"rc5-cbc") == 0) doit[D_CBC_RC5]=1;
		else if (strcmp(*argv,"rc5") == 0) doit[D_CBC_RC5]=1;
		else
#endif
#ifndef NO_IDEA
		     if (strcmp(*argv,"idea-cbc") == 0) doit[D_CBC_IDEA]=1;
		else if (strcmp(*argv,"idea") == 0) doit[D_CBC_IDEA]=1;
		else
#endif
#ifndef NO_BF
		     if (strcmp(*argv,"bf-cbc") == 0) doit[D_CBC_BF]=1;
		else if (strcmp(*argv,"blowfish") == 0) doit[D_CBC_BF]=1;
		else if (strcmp(*argv,"bf") == 0) doit[D_CBC_BF]=1;
		else
#endif
#ifndef NO_CAST
		     if (strcmp(*argv,"cast-cbc") == 0) doit[D_CBC_CAST]=1;
		else if (strcmp(*argv,"cast") == 0) doit[D_CBC_CAST]=1;
		else if (strcmp(*argv,"cast5") == 0) doit[D_CBC_CAST]=1;
		else
#endif
#ifndef NO_DES
			if (strcmp(*argv,"des") == 0)
			{
			doit[D_CBC_DES]=1;
			doit[D_EDE3_DES]=1;
			}
		else
#endif
#ifndef NO_RSA
			if (strcmp(*argv,"rsa") == 0)
			{
			rsa_doit[R_RSA_512]=1;
			rsa_doit[R_RSA_1024]=1;
			rsa_doit[R_RSA_2048]=1;
			rsa_doit[R_RSA_4096]=1;
			}
		else
#endif
#ifndef NO_DSA
			if (strcmp(*argv,"dsa") == 0)
			{
			dsa_doit[R_DSA_512]=1;
			dsa_doit[R_DSA_1024]=1;
			}
		else
#endif
			{
			BIO_printf(bio_err,"bad value, pick one of\n");
			BIO_printf(bio_err,"md2      mdc2	md5      hmac      sha1    rmd160\n");
#ifndef NO_IDEA
			BIO_printf(bio_err,"idea-cbc ");
#endif
#ifndef NO_RC2
			BIO_printf(bio_err,"rc2-cbc  ");
#endif
#ifndef NO_RC5
			BIO_printf(bio_err,"rc5-cbc  ");
#endif
#ifndef NO_BF
			BIO_printf(bio_err,"bf-cbc");
#endif
#if !defined(NO_IDEA) && !defined(NO_RC2) && !defined(NO_BF) && !defined(NO_RC5)
			BIO_printf(bio_err,"\n");
#endif
			BIO_printf(bio_err,"des-cbc  des-ede3 ");
#ifndef NO_RC4
			BIO_printf(bio_err,"rc4");
#endif
#ifndef NO_RSA
			BIO_printf(bio_err,"\nrsa512   rsa1024  rsa2048  rsa4096\n");
#endif
#ifndef NO_DSA
			BIO_printf(bio_err,"\ndsa512   dsa1024  dsa2048\n");
#endif
			BIO_printf(bio_err,"idea     rc2      des      rsa    blowfish\n");
			goto end;
			}
		argc--;
		argv++;
		j++;
		}

	if (j == 0)
		{
		for (i=0; i<ALGOR_NUM; i++)
			doit[i]=1;
		for (i=0; i<RSA_NUM; i++)
			rsa_doit[i]=1;
		for (i=0; i<DSA_NUM; i++)
			dsa_doit[i]=1;
		}
	for (i=0; i<ALGOR_NUM; i++)
		if (doit[i]) pr_header++;

#ifndef TIMES
	BIO_printf(bio_err,"To get the most accurate results, try to run this\n");
	BIO_printf(bio_err,"program when this computer is idle.\n");
#endif

#ifndef NO_RSA
	for (i=0; i<RSA_NUM; i++)
		{
		unsigned char *p;

		p=rsa_data[i];
		rsa_key[i]=d2i_RSAPrivateKey(NULL,&p,rsa_data_length[i]);
		if (rsa_key[i] == NULL)
			{
			BIO_printf(bio_err,"internal error loading RSA key number %d\n",i);
			goto end;
			}
#if 0
		else
			{
			BIO_printf(bio_err,"Loaded RSA key, %d bit modulus and e= 0x",BN_num_bits(rsa_key[i]->n));
			BN_print(bio_err,rsa_key[i]->e);
			BIO_printf(bio_err,"\n");
			}
#endif
		}
#endif

#ifndef NO_DSA
	dsa_key[0]=get_dsa512();
	dsa_key[1]=get_dsa1024();
	dsa_key[2]=get_dsa2048();
#endif

#ifndef NO_DES
	des_set_key(&key,sch);
	des_set_key(&key2,sch2);
	des_set_key(&key3,sch3);
#endif
#ifndef NO_IDEA
	idea_set_encrypt_key(key16,&idea_ks);
#endif
#ifndef NO_RC4
	RC4_set_key(&rc4_ks,16,key16);
#endif
#ifndef NO_RC2
	RC2_set_key(&rc2_ks,16,key16,128);
#endif
#ifndef NO_RC5
	RC5_32_set_key(&rc5_ks,16,key16,12);
#endif
#ifndef NO_BF
	BF_set_key(&bf_ks,16,key16);
#endif
#ifndef NO_CAST
	CAST_set_key(&cast_ks,16,key16);
#endif
#ifndef NO_RSA
	memset(rsa_c,0,sizeof(rsa_c));
#endif
#ifndef SIGALRM
	BIO_printf(bio_err,"First we calculate the approximate speed ...\n");
	count=10;
	do	{
		long i;
		count*=2;
		Time_F(START);
		for (i=count; i; i--)
			des_ecb_encrypt(buf_as_des_cblock,buf_as_des_cblock,
				&(sch[0]),DES_ENCRYPT);
		d=Time_F(STOP);
		} while (d <3);
	c[D_MD2][0]=count/10;
	c[D_MDC2][0]=count/10;
	c[D_MD5][0]=count;
	c[D_HMAC][0]=count;
	c[D_SHA1][0]=count;
	c[D_RMD160][0]=count;
	c[D_RC4][0]=count*5;
	c[D_CBC_DES][0]=count;
	c[D_EDE3_DES][0]=count/3;
	c[D_CBC_IDEA][0]=count;
	c[D_CBC_RC2][0]=count;
	c[D_CBC_RC5][0]=count;
	c[D_CBC_BF][0]=count;
	c[D_CBC_CAST][0]=count;

	for (i=1; i<SIZE_NUM; i++)
		{
		c[D_MD2][i]=c[D_MD2][0]*4*lengths[0]/lengths[i];
		c[D_MDC2][i]=c[D_MDC2][0]*4*lengths[0]/lengths[i];
		c[D_MD5][i]=c[D_MD5][0]*4*lengths[0]/lengths[i];
		c[D_HMAC][i]=c[D_HMAC][0]*4*lengths[0]/lengths[i];
		c[D_SHA1][i]=c[D_SHA1][0]*4*lengths[0]/lengths[i];
		c[D_RMD160][i]=c[D_RMD160][0]*4*lengths[0]/lengths[i];
		}
	for (i=1; i<SIZE_NUM; i++)
		{
		long l0,l1;

		l0=(long)lengths[i-1];
		l1=(long)lengths[i];
		c[D_RC4][i]=c[D_RC4][i-1]*l0/l1;
		c[D_CBC_DES][i]=c[D_CBC_DES][i-1]*l0/l1;
		c[D_EDE3_DES][i]=c[D_EDE3_DES][i-1]*l0/l1;
		c[D_CBC_IDEA][i]=c[D_CBC_IDEA][i-1]*l0/l1;
		c[D_CBC_RC2][i]=c[D_CBC_RC2][i-1]*l0/l1;
		c[D_CBC_RC5][i]=c[D_CBC_RC5][i-1]*l0/l1;
		c[D_CBC_BF][i]=c[D_CBC_BF][i-1]*l0/l1;
		c[D_CBC_CAST][i]=c[D_CBC_CAST][i-1]*l0/l1;
		}
#ifndef NO_RSA
	rsa_c[R_RSA_512][0]=count/2000;
	rsa_c[R_RSA_512][1]=count/400;
	for (i=1; i<RSA_NUM; i++)
		{
		rsa_c[i][0]=rsa_c[i-1][0]/8;
		rsa_c[i][1]=rsa_c[i-1][1]/4;
		if ((rsa_doit[i] <= 1) && (rsa_c[i][0] == 0))
			rsa_doit[i]=0;
		else
			{
			if (rsa_c[i][0] == 0)
				{
				rsa_c[i][0]=1;
				rsa_c[i][1]=20;
				}
			}				
		}
#endif

	dsa_c[R_DSA_512][0]=count/1000;
	dsa_c[R_DSA_512][1]=count/1000/2;
	for (i=1; i<DSA_NUM; i++)
		{
		dsa_c[i][0]=dsa_c[i-1][0]/4;
		dsa_c[i][1]=dsa_c[i-1][1]/4;
		if ((dsa_doit[i] <= 1) && (dsa_c[i][0] == 0))
			dsa_doit[i]=0;
		else
			{
			if (dsa_c[i] == 0)
				{
				dsa_c[i][0]=1;
				dsa_c[i][1]=1;
				}
			}				
		}

#define COND(d)	(count < (d))
#define COUNT(d) (d)
#else
#define COND(c)	(run)
#define COUNT(d) (count)
	signal(SIGALRM,sig_done);
#endif

#ifndef NO_MD2
	if (doit[D_MD2])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_MD2],c[D_MD2][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_MD2][j]); count++)
				MD2(buf,(unsigned long)lengths[j],&(md2[0]));
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_MD2],d);
			results[D_MD2][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_MDC2
	if (doit[D_MDC2])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_MDC2],c[D_MDC2][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_MDC2][j]); count++)
				MDC2(buf,(unsigned long)lengths[j],&(mdc2[0]));
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_MDC2],d);
			results[D_MDC2][j]=((double)count)/d*lengths[j];
			}
		}
#endif

#ifndef NO_MD5
	if (doit[D_MD5])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_MD5],c[D_MD5][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_MD5][j]); count++)
				MD5(&(buf[0]),(unsigned long)lengths[j],&(md5[0]));
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_MD5],d);
			results[D_MD5][j]=((double)count)/d*lengths[j];
			}
		}
#endif

#if !defined(NO_MD5) && !defined(NO_HMAC)
	if (doit[D_HMAC])
		{
		HMAC_CTX hctx;
		HMAC_Init(&hctx,(unsigned char *)"This is a key...",
			16,EVP_md5());

		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_HMAC],c[D_HMAC][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_HMAC][j]); count++)
				{
				HMAC_Init(&hctx,NULL,0,NULL);
                                HMAC_Update(&hctx,buf,lengths[j]);
                                HMAC_Final(&hctx,&(hmac[0]),NULL);
				}
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_HMAC],d);
			results[D_HMAC][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_SHA
	if (doit[D_SHA1])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_SHA1],c[D_SHA1][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_SHA1][j]); count++)
				SHA1(buf,(unsigned long)lengths[j],&(sha[0]));
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_SHA1],d);
			results[D_SHA1][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_RIPEMD
	if (doit[D_RMD160])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_RMD160],c[D_RMD160][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_RMD160][j]); count++)
				RIPEMD160(buf,(unsigned long)lengths[j],&(rmd160[0]));
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_RMD160],d);
			results[D_RMD160][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_RC4
	if (doit[D_RC4])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_RC4],c[D_RC4][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_RC4][j]); count++)
				RC4(&rc4_ks,(unsigned int)lengths[j],
					buf,buf);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_RC4],d);
			results[D_RC4][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_DES
	if (doit[D_CBC_DES])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_CBC_DES],c[D_CBC_DES][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_CBC_DES][j]); count++)
				des_ncbc_encrypt(buf,buf,lengths[j],sch,
						 &iv,DES_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_CBC_DES],d);
			results[D_CBC_DES][j]=((double)count)/d*lengths[j];
			}
		}

	if (doit[D_EDE3_DES])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_EDE3_DES],c[D_EDE3_DES][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_EDE3_DES][j]); count++)
				des_ede3_cbc_encrypt(buf,buf,lengths[j],
						     sch,sch2,sch3,
						     &iv,DES_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_EDE3_DES],d);
			results[D_EDE3_DES][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_IDEA
	if (doit[D_CBC_IDEA])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_CBC_IDEA],c[D_CBC_IDEA][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_CBC_IDEA][j]); count++)
				idea_cbc_encrypt(buf,buf,
					(unsigned long)lengths[j],&idea_ks,
					iv,IDEA_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_CBC_IDEA],d);
			results[D_CBC_IDEA][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_RC2
	if (doit[D_CBC_RC2])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_CBC_RC2],c[D_CBC_RC2][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_CBC_RC2][j]); count++)
				RC2_cbc_encrypt(buf,buf,
					(unsigned long)lengths[j],&rc2_ks,
					iv,RC2_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_CBC_RC2],d);
			results[D_CBC_RC2][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_RC5
	if (doit[D_CBC_RC5])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_CBC_RC5],c[D_CBC_RC5][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_CBC_RC5][j]); count++)
				RC5_32_cbc_encrypt(buf,buf,
					(unsigned long)lengths[j],&rc5_ks,
					iv,RC5_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_CBC_RC5],d);
			results[D_CBC_RC5][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_BF
	if (doit[D_CBC_BF])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_CBC_BF],c[D_CBC_BF][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_CBC_BF][j]); count++)
				BF_cbc_encrypt(buf,buf,
					(unsigned long)lengths[j],&bf_ks,
					iv,BF_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_CBC_BF],d);
			results[D_CBC_BF][j]=((double)count)/d*lengths[j];
			}
		}
#endif
#ifndef NO_CAST
	if (doit[D_CBC_CAST])
		{
		for (j=0; j<SIZE_NUM; j++)
			{
			print_message(names[D_CBC_CAST],c[D_CBC_CAST][j],lengths[j]);
			Time_F(START);
			for (count=0,run=1; COND(c[D_CBC_CAST][j]); count++)
				CAST_cbc_encrypt(buf,buf,
					(unsigned long)lengths[j],&cast_ks,
					iv,CAST_ENCRYPT);
			d=Time_F(STOP);
			BIO_printf(bio_err,"%ld %s's in %.2fs\n",
				count,names[D_CBC_CAST],d);
			results[D_CBC_CAST][j]=((double)count)/d*lengths[j];
			}
		}
#endif

	RAND_bytes(buf,30);
#ifndef NO_RSA
	for (j=0; j<RSA_NUM; j++)
		{
		if (!rsa_doit[j]) continue;
		rsa_num=RSA_private_encrypt(30,buf,buf2,rsa_key[j],
			RSA_PKCS1_PADDING);
		pkey_print_message("private","rsa",rsa_c[j][0],rsa_bits[j],
			RSA_SECONDS);
/*		RSA_blinding_on(rsa_key[j],NULL); */
		Time_F(START);
		for (count=0,run=1; COND(rsa_c[j][0]); count++)
			{
			rsa_num=RSA_private_encrypt(30,buf,buf2,rsa_key[j],
				RSA_PKCS1_PADDING);
			if (rsa_num <= 0)
				{
				BIO_printf(bio_err,"RSA private encrypt failure\n");
				ERR_print_errors(bio_err);
				count=1;
				break;
				}
			}
		d=Time_F(STOP);
		BIO_printf(bio_err,"%ld %d bit private RSA's in %.2fs\n",
			count,rsa_bits[j],d);
		rsa_results[j][0]=d/(double)count;
		rsa_count=count;

#if 1
		rsa_num2=RSA_public_decrypt(rsa_num,buf2,buf,rsa_key[j],
			RSA_PKCS1_PADDING);
		pkey_print_message("public","rsa",rsa_c[j][1],rsa_bits[j],
			RSA_SECONDS);
		Time_F(START);
		for (count=0,run=1; COND(rsa_c[j][1]); count++)
			{
			rsa_num2=RSA_public_decrypt(rsa_num,buf2,buf,rsa_key[j],
				RSA_PKCS1_PADDING);
			if (rsa_num2 <= 0)
				{
				BIO_printf(bio_err,"RSA public encrypt failure\n");
				ERR_print_errors(bio_err);
				count=1;
				break;
				}
			}
		d=Time_F(STOP);
		BIO_printf(bio_err,"%ld %d bit public RSA's in %.2fs\n",
			count,rsa_bits[j],d);
		rsa_results[j][1]=d/(double)count;
#endif

		if (rsa_count <= 1)
			{
			/* if longer than 10s, don't do any more */
			for (j++; j<RSA_NUM; j++)
				rsa_doit[j]=0;
			}
		}
#endif

	RAND_bytes(buf,20);
#ifndef NO_DSA
	for (j=0; j<DSA_NUM; j++)
		{
		unsigned int kk;

		if (!dsa_doit[j]) continue;
		DSA_generate_key(dsa_key[j]);
/*		DSA_sign_setup(dsa_key[j],NULL); */
		rsa_num=DSA_sign(EVP_PKEY_DSA,buf,20,buf2,
			&kk,dsa_key[j]);
		pkey_print_message("sign","dsa",dsa_c[j][0],dsa_bits[j],
			DSA_SECONDS);
		Time_F(START);
		for (count=0,run=1; COND(dsa_c[j][0]); count++)
			{
			rsa_num=DSA_sign(EVP_PKEY_DSA,buf,20,buf2,
				&kk,dsa_key[j]);
			if (rsa_num <= 0)
				{
				BIO_printf(bio_err,"DSA sign failure\n");
				ERR_print_errors(bio_err);
				count=1;
				break;
				}
			}
		d=Time_F(STOP);
		BIO_printf(bio_err,"%ld %d bit DSA signs in %.2fs\n",
			count,dsa_bits[j],d);
		dsa_results[j][0]=d/(double)count;
		rsa_count=count;

		rsa_num2=DSA_verify(EVP_PKEY_DSA,buf,20,buf2,
			kk,dsa_key[j]);
		pkey_print_message("verify","dsa",dsa_c[j][1],dsa_bits[j],
			DSA_SECONDS);
		Time_F(START);
		for (count=0,run=1; COND(dsa_c[j][1]); count++)
			{
			rsa_num2=DSA_verify(EVP_PKEY_DSA,buf,20,buf2,
				kk,dsa_key[j]);
			if (rsa_num2 <= 0)
				{
				BIO_printf(bio_err,"DSA verify failure\n");
				ERR_print_errors(bio_err);
				count=1;
				break;
				}
			}
		d=Time_F(STOP);
		BIO_printf(bio_err,"%ld %d bit DSA verify in %.2fs\n",
			count,dsa_bits[j],d);
		dsa_results[j][1]=d/(double)count;

		if (rsa_count <= 1)
			{
			/* if longer than 10s, don't do any more */
			for (j++; j<DSA_NUM; j++)
				dsa_doit[j]=0;
			}
		}
#endif

	fprintf(stdout,"%s\n",SSLeay_version(SSLEAY_VERSION));
        fprintf(stdout,"%s\n",SSLeay_version(SSLEAY_BUILT_ON));
	printf("options:");
	printf("%s ",BN_options());
#ifndef NO_MD2
	printf("%s ",MD2_options());
#endif
#ifndef NO_RC4
	printf("%s ",RC4_options());
#endif
#ifndef NO_DES
	printf("%s ",des_options());
#endif
#ifndef NO_IDEA
	printf("%s ",idea_options());
#endif
#ifndef NO_BF
	printf("%s ",BF_options());
#endif
	fprintf(stdout,"\n%s\n",SSLeay_version(SSLEAY_CFLAGS));

	if (pr_header)
		{
		fprintf(stdout,"The 'numbers' are in 1000s of bytes per second processed.\n"); 
		fprintf(stdout,"type        ");
		for (j=0;  j<SIZE_NUM; j++)
			fprintf(stdout,"%7d bytes",lengths[j]);
		fprintf(stdout,"\n");
		}

	for (k=0; k<ALGOR_NUM; k++)
		{
		if (!doit[k]) continue;
		fprintf(stdout,"%-13s",names[k]);
		for (j=0; j<SIZE_NUM; j++)
			{
			if (results[k][j] > 10000)
				fprintf(stdout," %11.2fk",results[k][j]/1e3);
			else
				fprintf(stdout," %11.2f ",results[k][j]);
			}
		fprintf(stdout,"\n");
		}
#ifndef NO_RSA
	j=1;
	for (k=0; k<RSA_NUM; k++)
		{
		if (!rsa_doit[k]) continue;
		if (j)
			{
			printf("%18ssign    verify    sign/s verify/s\n"," ");
			j=0;
			}
		fprintf(stdout,"rsa %4u bits %8.4fs %8.4fs %8.1f %8.1f",
			rsa_bits[k],rsa_results[k][0],rsa_results[k][1],
			1.0/rsa_results[k][0],1.0/rsa_results[k][1]);
		fprintf(stdout,"\n");
		}
#endif
#ifndef NO_DSA
	j=1;
	for (k=0; k<DSA_NUM; k++)
		{
		if (!dsa_doit[k]) continue;
		if (j)	{
			printf("%18ssign    verify    sign/s verify/s\n"," ");
			j=0;
			}
		fprintf(stdout,"dsa %4u bits %8.4fs %8.4fs %8.1f %8.1f",
			dsa_bits[k],dsa_results[k][0],dsa_results[k][1],
			1.0/dsa_results[k][0],1.0/dsa_results[k][1]);
		fprintf(stdout,"\n");
		}
#endif
	ret=0;
end:
	if (buf != NULL) Free(buf);
	if (buf2 != NULL) Free(buf2);
#ifndef NO_RSA
	for (i=0; i<RSA_NUM; i++)
		if (rsa_key[i] != NULL)
			RSA_free(rsa_key[i]);
#endif
#ifndef NO_DSA
	for (i=0; i<DSA_NUM; i++)
		if (dsa_key[i] != NULL)
			DSA_free(dsa_key[i]);
#endif
	EXIT(ret);
	}

static void print_message(char *s, long num, int length)
	{
#ifdef SIGALRM
	BIO_printf(bio_err,"Doing %s for %ds on %d size blocks: ",s,SECONDS,length);
	(void)BIO_flush(bio_err);
	alarm(SECONDS);
#else
	BIO_printf(bio_err,"Doing %s %ld times on %d size blocks: ",s,num,length);
	(void)BIO_flush(bio_err);
#endif
#ifdef LINT
	num=num;
#endif
	}

static void pkey_print_message(char *str, char *str2, long num, int bits,
	     int tm)
	{
#ifdef SIGALRM
	BIO_printf(bio_err,"Doing %d bit %s %s's for %ds: ",bits,str,str2,tm);
	(void)BIO_flush(bio_err);
	alarm(RSA_SECONDS);
#else
	BIO_printf(bio_err,"Doing %ld %d bit %s %s's: ",num,bits,str,str2);
	(void)BIO_flush(bio_err);
#endif
#ifdef LINT
	num=num;
#endif
	}

