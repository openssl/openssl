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

#include <openssl/fips.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <string.h>
#include <limits.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static int fips_selftest_fail;
static int fips_mode;
static const void *fips_rand_check;

static void fips_set_mode(int onoff)
	{
	int owning_thread = fips_is_owning_thread();

	if (fips_is_started())
		{
		if (!owning_thread) fips_w_lock();
		fips_mode = onoff;
		if (!owning_thread) fips_w_unlock();
		}
	}

static void fips_set_rand_check(const void *rand_check)
	{
	int owning_thread = fips_is_owning_thread();

	if (fips_is_started())
		{
		if (!owning_thread) fips_w_lock();
		fips_rand_check = rand_check;
		if (!owning_thread) fips_w_unlock();
		}
	}

int FIPS_mode(void)
	{
	int ret = 0;
	int owning_thread = fips_is_owning_thread();

	if (fips_is_started())
		{
		if (!owning_thread) fips_r_lock();
		ret = fips_mode;
		if (!owning_thread) fips_r_unlock();
		}
	return ret;
	}

const void *FIPS_rand_check(void)
	{
	const void *ret = 0;
	int owning_thread = fips_is_owning_thread();

	if (fips_is_started())
		{
		if (!owning_thread) fips_r_lock();
		ret = fips_rand_check;
		if (!owning_thread) fips_r_unlock();
		}
	return ret;
	}

int FIPS_selftest_failed(void)
    {
    int ret = 0;
    if (fips_is_started())
	{
	int owning_thread = fips_is_owning_thread();

	if (!owning_thread) fips_r_lock();
	ret = fips_selftest_fail;
	if (!owning_thread) fips_r_unlock();
	}
    return ret;
    }

int FIPS_selftest()
    {
    ERR_load_crypto_strings();

    return FIPS_selftest_sha1()
	&& FIPS_selftest_hmac()
	&& FIPS_selftest_aes()
	&& FIPS_selftest_des()
	&& FIPS_selftest_rsa()
	&& FIPS_selftest_dsa();
    }

extern const void         *FIPS_text_start(),  *FIPS_text_end();
extern const unsigned char FIPS_rodata_start[], FIPS_rodata_end[];
unsigned char              FIPS_signature [20] = { 0 };
static const char          FIPS_hmac_key[]="etaonrishdlcupfm";

unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len)
    {
    const unsigned char *p1 = FIPS_text_start();
    const unsigned char *p2 = FIPS_text_end();
    const unsigned char *p3 = FIPS_rodata_start;
    const unsigned char *p4 = FIPS_rodata_end;
    HMAC_CTX c;

    HMAC_CTX_init(&c);
    HMAC_Init(&c,FIPS_hmac_key,strlen(FIPS_hmac_key),EVP_sha1());

    /* detect overlapping regions */
    if (p1<=p3 && p2>=p3)
	p3=p1, p4=p2>p4?p2:p4, p1=NULL, p2=NULL;
    else if (p3<=p1 && p4>=p1)
	p3=p3, p4=p2>p4?p2:p4, p1=NULL, p2=NULL;

    if (p1)
	HMAC_Update(&c,p1,(size_t)p2-(size_t)p1);

    if (FIPS_signature>=p3 && FIPS_signature<p4)
	{
	/* "punch" hole */
	HMAC_Update(&c,p3,(size_t)FIPS_signature-(size_t)p3);
	p3 = FIPS_signature+sizeof(FIPS_signature);
	if (p3<p4)
	    HMAC_Update(&c,p3,(size_t)p4-(size_t)p3);
	}
    else
	HMAC_Update(&c,p3,(size_t)p4-(size_t)p3);

    HMAC_Final(&c,sig,&len);
    HMAC_CTX_cleanup(&c);

    return len;
    }

int FIPS_check_incore_fingerprint(void)
    {
    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int len;
    extern int OPENSSL_NONPIC_relocated;

    if (FIPS_text_start()==NULL)
	{
	FIPSerr(FIPS_F_FIPS_CHECK_FINGERPRINT,FIPS_R_UNSUPPORTED_PLATFORM);
	return 0;
	}

    len=FIPS_incore_fingerprint (sig,sizeof(sig));

    if (len!=sizeof(FIPS_signature) ||
	memcmp(FIPS_signature,sig,sizeof(FIPS_signature)))
	{
	if (FIPS_signature>=FIPS_rodata_start && FIPS_signature<FIPS_rodata_end)
	    FIPSerr(FIPS_F_FIPS_CHECK_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH_SEGMENT_ALIASING);
	else if (OPENSSL_NONPIC_relocated)
	    FIPSerr(FIPS_F_FIPS_CHECK_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH_NONPIC_RELOCATED);
	else
	    FIPSerr(FIPS_F_FIPS_CHECK_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH);
	return 0;
	}

    return 1;
    }

int FIPS_mode_set(int onoff)
    {
    int fips_set_owning_thread();
    int fips_clear_owning_thread();
    int ret = 0;

    fips_w_lock();
    fips_set_started();
    fips_set_owning_thread();

    if(onoff)
	{
	unsigned char buf[24];

	fips_selftest_fail = 0;

	/* Don't go into FIPS mode twice, just so we can do automagic
	   seeding */
	if(FIPS_mode())
	    {
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_FIPS_MODE_ALREADY_SET);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	if(fips_signature_witness() != FIPS_signature)
	    {
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_CONTRADICTING_EVIDENCE);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	if(!FIPS_check_incore_fingerprint())
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	/* Perform RNG KAT before seeding */
	if (!FIPS_selftest_rng())
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	/* automagically seed PRNG if not already seeded */
	if(!FIPS_rand_seeded())
	    {
	    if(RAND_bytes(buf,sizeof buf) <= 0)
		{
		fips_selftest_fail = 1;
		ret = 0;
		goto end;
		}
	    FIPS_set_prng_key(buf,buf+8);
	    FIPS_rand_seed(buf+16,8);
	    }

	/* now switch into FIPS mode */
	fips_set_rand_check(FIPS_rand_method());
	RAND_set_rand_method(FIPS_rand_method());
	if(FIPS_selftest())
	    fips_set_mode(1);
	else
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }
	ret = 1;
	goto end;
	}
    fips_set_mode(0);
    fips_selftest_fail = 0;
    ret = 1;
end:
    fips_clear_owning_thread();
    fips_w_unlock();
    return ret;
    }

#if 0
/* here just to cause error codes to exist */
static void dummy()
    {
    FIPSerr(FIPS_F_HASH_FINAL,FIPS_F_NON_FIPS_METHOD);
    FIPSerr(FIPS_F_HASH_FINAL,FIPS_R_FIPS_SELFTEST_FAILED);
    }
#endif

#endif
