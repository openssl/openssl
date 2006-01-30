/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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
 *
 */

/*
 * This is a FIPS approved PRNG, ANSI X9.31 A.2.4.
 */

#include "e_os.h"

/* If we don't define _XOPEN_SOURCE_EXTENDED, struct timeval won't
   be defined and gettimeofday() won't be declared with strict compilers
   like DEC C in ANSI C mode.  */
#ifndef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED 1
#endif

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/fips_rand.h>
#ifndef OPENSSL_SYS_WIN32
#include <sys/time.h>
#endif
#include <assert.h>
#ifndef OPENSSL_SYS_WIN32
# ifdef OPENSSL_UNISTD
#  include OPENSSL_UNISTD
# else
#  include <unistd.h>
# endif
#endif
#include <string.h>

void *OPENSSL_stderr(void);

#ifdef OPENSSL_FIPS

#define SEED_SIZE	8

static unsigned char seed[SEED_SIZE];
static FIPS_RAND_SIZE_T n_seed;
static FIPS_RAND_SIZE_T o_seed;
static DES_cblock key1;
static DES_cblock key2;
static DES_key_schedule ks1,ks2;
static int key_set;
static int key_init;
static int test_mode;
static unsigned char test_faketime[8];

#ifndef GETPID_IS_MEANINGLESS
static int seed_pid;
static int key_pid;
#endif

static void fips_rand_cleanup(void);
static void fips_rand_add(const void *buf, FIPS_RAND_SIZE_T num, double add_entropy);
static int fips_rand_bytes(unsigned char *buf, FIPS_RAND_SIZE_T num);
static int fips_rand_status(void);

static const RAND_METHOD rand_fips_meth=
    {
    FIPS_rand_seed,
    fips_rand_bytes,
    fips_rand_cleanup,
    fips_rand_add,
    fips_rand_bytes,
    fips_rand_status
    };

static int second;

const RAND_METHOD *FIPS_rand_method(void)
{
  return &rand_fips_meth;
}

void FIPS_set_prng_key(const unsigned char k1[8],const unsigned char k2[8])
    {
    memcpy(&key1,k1,sizeof key1);
    memcpy(&key2,k2,sizeof key2);
    key_set=1;
#ifndef GETPID_IS_MEANINGLESS
    key_pid=getpid();
#endif
    second=0;
    }

void FIPS_test_mode(int test,const unsigned char faketime[8])
    {
    test_mode=test;
    if(!test_mode)
	return;
    memcpy(test_faketime,faketime,sizeof test_faketime);
    }

/* NB: this returns true if _partially_ seeded */
int FIPS_rand_seeded()
    { return key_set || n_seed; }

static void fips_gettime(unsigned char buf[8])
    {
#ifdef OPENSSL_SYS_WIN32
    FILETIME ft;
#else
    struct timeval tv;
#endif

    if(test_mode)
	{
	/* fprintf(OPENSSL_stderr(),"WARNING!!! PRNG IN TEST MODE!!!\n"); */
	memcpy(buf,test_faketime,sizeof test_faketime);
	return;
	}
#ifdef OPENSSL_SYS_WIN32
    GetSystemTimeAsFileTime(&ft);
    buf[0] = (unsigned char) (ft.dwHighDateTime & 0xff);
    buf[1] = (unsigned char) ((ft.dwHighDateTime >> 8) & 0xff);
    buf[2] = (unsigned char) ((ft.dwHighDateTime >> 16) & 0xff);
    buf[3] = (unsigned char) ((ft.dwHighDateTime >> 24) & 0xff);
    buf[4] = (unsigned char) (ft.dwLowDateTime & 0xff);
    buf[5] = (unsigned char) ((ft.dwLowDateTime >> 8) & 0xff);
    buf[6] = (unsigned char) ((ft.dwLowDateTime >> 16) & 0xff);
    buf[7] = (unsigned char) ((ft.dwLowDateTime >> 24) & 0xff);
#else
    gettimeofday(&tv,NULL);
    buf[0] = (unsigned char) (tv.tv_sec & 0xff);
    buf[1] = (unsigned char) ((tv.tv_sec >> 8) & 0xff);
    buf[2] = (unsigned char) ((tv.tv_sec >> 16) & 0xff);
    buf[3] = (unsigned char) ((tv.tv_sec >> 24) & 0xff);
    buf[4] = (unsigned char) (tv.tv_usec & 0xff);
    buf[5] = (unsigned char) ((tv.tv_usec >> 8) & 0xff);
    buf[6] = (unsigned char) ((tv.tv_usec >> 16) & 0xff);
    buf[7] = (unsigned char) ((tv.tv_usec >> 24) & 0xff);
#endif

#if 0  /* This eminently sensible strategy is not acceptable to NIST. Sigh. */
#ifndef GETPID_IS_MEANINGLESS
    /* we mix in the PID to ensure that after a fork the children don't give
     * the same results as each other
     */
    pid=getpid();
    /* make sure we shift the pid to the MSB */
    if((pid&0xffff0000) == 0)
	pid<<=16;
    *(long *)&buf[0]^=pid;
#endif
#endif
    }

static void fips_rand_encrypt(unsigned char *out,const unsigned char *in)
    {
    DES_ecb2_encrypt(in,out,&ks1,&ks2,1);
    }

static void fips_rand_cleanup(void)
    {
    OPENSSL_cleanse(seed,sizeof seed);
    n_seed=0;
    o_seed=0;
    key_init=0;
    }

void FIPS_rand_seed(const void *buf_, FIPS_RAND_SIZE_T num)
    {
    const char *buf=buf_;
    FIPS_RAND_SIZE_T n;

    /* If the key hasn't been set, we can't seed! */
    if(!key_set)
	return;

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    if(!key_init)
	{
	key_init=1;
	DES_set_key(&key1,&ks1);
	DES_set_key(&key2,&ks2);
	}

    /*
     * This algorithm only uses 64 bits of seed, so ensure that we use
     * the most recent 64 bits.
     */
    for(n=0 ; n < num ; )
	{
	FIPS_RAND_SIZE_T t=num-n;

	if(o_seed+t > sizeof seed)
	    t=sizeof seed-o_seed;
	memcpy(seed+o_seed,buf+n,t);
	n+=t;
	o_seed+=t;
	if(o_seed == sizeof seed)
	    o_seed=0;
	if(n_seed < sizeof seed)
	    n_seed+=t;
	}

#ifndef GETPID_IS_MEANINGLESS
    seed_pid=getpid();
#endif

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    }

static void fips_rand_add(const void *buf, FIPS_RAND_SIZE_T num, double add_entropy)
    {
    FIPS_rand_seed(buf,num);
    }

static int fips_rand_bytes(unsigned char *buf,FIPS_RAND_SIZE_T num)
    {
    FIPS_RAND_SIZE_T n;
    unsigned char timeseed[8];
    unsigned char intermediate[SEED_SIZE];
    unsigned char output[SEED_SIZE];
    static unsigned char previous[SEED_SIZE];
#ifndef GETPID_IS_MEANINGLESS
    int pid;
#endif

    if(n_seed < sizeof seed)
	{
	RANDerr(RAND_F_FIPS_RAND_BYTES,RAND_R_PRNG_NOT_SEEDED);
	return 0;
	}

#ifdef FIPS_RAND_MAX_SIZE_T
    if (num > FIPS_RAND_MAX_SIZE_T)
	{
#ifdef RAND_R_PRNG_ASKING_FOR_TOO_MUCH
	RANDerr(RAND_F_FIPS_RAND_BYTES,RAND_R_PRNG_ASKING_FOR_TOO_MUCH);
	return 0;
#else
	return -1; /* signal "not supported" condition */
#endif
	}
#endif

#ifndef GETPID_IS_MEANINGLESS
    pid=getpid();
    if(pid != seed_pid)
	{
	RANDerr(RAND_F_FIPS_RAND_BYTES,RAND_R_PRNG_NOT_RESEEDED);
	return 0;
	}
    if(pid != key_pid)
	{
	RANDerr(RAND_F_FIPS_RAND_BYTES,RAND_R_PRNG_NOT_REKEYED);
	return 0;
	}
#endif

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);

    for(n=0 ; n < num ; )
	{
	unsigned char t[SEED_SIZE];
	FIPS_RAND_SIZE_T l;
	
	/* ANS X9.31 A.2.4:	I = ede*K(DT)
	       timeseed == DT
	       intermediate == I
	*/
	fips_gettime(timeseed);
	fips_rand_encrypt(intermediate,timeseed);

	/* ANS X9.31 A.2.4:     R = ede*K(I^V)
	       intermediate == I
	       seed == V
	       output == R
	*/
	for(l=0 ; l < sizeof t ; ++l)
	    t[l]=intermediate[l]^seed[l];
	fips_rand_encrypt(output,t);

	/* ANS X9.31 A.2.4:     V = ede*K(R^I)
	       output == R
	       intermediate == I
	       seed == V
	*/
	for(l=0 ; l < sizeof t ; ++l)
	    t[l]=output[l]^intermediate[l];
	fips_rand_encrypt(seed,t);

	if(second && !memcmp(output,previous,sizeof previous))
	    {
	    RANDerr(RAND_F_FIPS_RAND_BYTES,RAND_R_PRNG_STUCK);
	    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
	    return 0;
	    }
	memcpy(previous,output,sizeof previous);
	second=1;

	/* Successive values of R may be concatenated to produce a
	   pseudo random number of the desired length */ 
	l=SEED_SIZE < num-n ? SEED_SIZE : num-n;
	memcpy(buf+n,output,l);
	n+=l;
	}

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    return 1;
    }

static int fips_rand_status(void)
    {
    return n_seed == sizeof seed;
    }

#endif /* OPENSSL_FIPS */
