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
 * This is a FIPS approved PRNG, ANSI X9.17, as specified in HAC,
 * Menezes et al., p.173
 */

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/fips_rand.h>
#include "e_os.h"
#include <sys/time.h>
#include <assert.h>
#ifdef OPENSSL_UNISTD
# include OPENSSL_UNISTD
#else
# include <unistd.h>
#endif
#include <string.h>

#define SEED_SIZE	8

static unsigned char seed[SEED_SIZE];
static int n_seed;
static int o_seed;
static DES_cblock key1;
static DES_cblock key2;
static DES_key_schedule ks1,ks2;
static int key_set;
static int test_mode;
static unsigned char test_faketime[8];

static void fips_rand_cleanup(void);
static void fips_rand_add(const void *buf, int num, double add_entropy);
static int fips_rand_bytes(unsigned char *buf, int num);
static int fips_rand_status(void);

RAND_METHOD rand_fips_meth=
    {
    FIPS_rand_seed,
    fips_rand_bytes,
    fips_rand_cleanup,
    fips_rand_add,
    fips_rand_bytes,
    fips_rand_status
    };

void FIPS_set_prng_key(const unsigned char k1[8],const unsigned char k2[8])
    {
    memcpy(&key1,k1,sizeof key1);
    memcpy(&key2,k2,sizeof key2);
    key_set=1;
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
    struct timeval tv;
#ifndef GETPID_IS_MEANINGLESS
    long pid;
#endif

    if(test_mode)
	{
	fprintf(stderr,"WARNING!!! PRNG IN TEST MODE!!!\n");
	memcpy(buf,test_faketime,sizeof test_faketime);
	return;
	}
    gettimeofday(&tv,NULL);
    assert(sizeof(long) == 4);
    *(long *)&buf[0]=tv.tv_sec;
    *(long *)&buf[4]=tv.tv_usec;

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
    }

static void fips_rand_encrypt(unsigned char *out,const unsigned char *in)
    {
    DES_ecb2_encrypt(in,out,&ks1,&ks2,1);
    }

static void fips_rand_cleanup(void)
    {
    OPENSSL_cleanse(seed,sizeof seed);
    n_seed=0;
    }

void FIPS_rand_seed(const void *buf_, int num)
    {
    const char *buf=buf_;
    int n;
    static int init;

    /* If the key hasn't been set, we can't seed! */
    if(!key_set)
	return;

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    if(!init)
	{
	init=1;
	DES_set_key(&key1,&ks1);
	DES_set_key(&key2,&ks2);
	}

    /*
     * This algorithm only uses 64 bits of seed, so ensure that we use
     * the most recent 64 bits.
     */
    for(n=0 ; n < num ; )
	{
	int t=num-n;

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

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    }

static void fips_rand_add(const void *buf, int num, double add_entropy)
    {
    FIPS_rand_seed(buf,num);
    }

static int fips_rand_bytes(unsigned char *buf,int num)
    {
    int n;
    unsigned char timeseed[8];
    unsigned char intermediate[SEED_SIZE];
    unsigned char output[SEED_SIZE];

    if(n_seed < sizeof seed)
	{
	RANDerr(RAND_F_FIPS_RAND_BYTES,RAND_R_PRNG_NOT_SEEDED);
	return 0;
	}

    fips_gettime(timeseed);
    fips_rand_encrypt(intermediate,timeseed);

    CRYPTO_w_lock(CRYPTO_LOCK_RAND);

    for(n=0 ; n < num ; )
	{
	unsigned char t[SEED_SIZE];
	int l;
	
	/* now generate a full 64 bits of "randomness" */
	for(l=0 ; l < sizeof t ; ++l)
	    t[l]=intermediate[l]^seed[l];
	fips_rand_encrypt(output,t);
	for(l=0 ; l < sizeof t ; ++l)
	    t[l]=output[l]^seed[l];
	fips_rand_encrypt(seed,t);

	l=SEED_SIZE < num-n ? SEED_SIZE : num-n;
	memcpy(buf+n,output,l);
	n+=l;
	}

    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    return num;
    }

static int fips_rand_status(void)
    {
    return n_seed == sizeof seed;
    }
