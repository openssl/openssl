/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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

#define OPENSSL_FIPSAPI

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <string.h>
#include <limits.h>
#include "fips_locl.h"
#include "fips_auth.h"

#ifdef OPENSSL_FIPS

#include <openssl/fips.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define atox(c) ((c)>='a'?((c)-'a'+10):((c)>='A'?(c)-'A'+10:(c)-'0'))

static int fips_selftest_fail = 0;
static int fips_auth_fail = 0;
static int fips_mode = 0;
static int fips_started = 0;

static int fips_is_owning_thread(void);
static int fips_set_owning_thread(void);
static int fips_clear_owning_thread(void);
static unsigned char *fips_signature_witness(void);

#define fips_w_lock()	CRYPTO_w_lock(CRYPTO_LOCK_FIPS)
#define fips_w_unlock()	CRYPTO_w_unlock(CRYPTO_LOCK_FIPS)
#define fips_r_lock()	CRYPTO_r_lock(CRYPTO_LOCK_FIPS)
#define fips_r_unlock()	CRYPTO_r_unlock(CRYPTO_LOCK_FIPS)

static void fips_set_mode(int onoff)
	{
	int owning_thread = fips_is_owning_thread();

	if (fips_started)
		{
		if (!owning_thread) fips_w_lock();
		fips_mode = onoff;
		if (!owning_thread) fips_w_unlock();
		}
	}

int FIPS_module_mode(void)
	{
	int ret = 0;
	int owning_thread = fips_is_owning_thread();

	if (fips_started)
		{
		if (!owning_thread) fips_r_lock();
		ret = fips_mode;
		if (!owning_thread) fips_r_unlock();
		}
	return ret;
	}

int FIPS_selftest_failed(void)
    {
    int ret = 0;
    if (fips_started)
	{
	int owning_thread = fips_is_owning_thread();

	if (!owning_thread) fips_r_lock();
	ret = fips_selftest_fail;
	if (!owning_thread) fips_r_unlock();
	}
    return ret;
    }

/* Selftest failure fatal exit routine. This will be called
 * during *any* cryptographic operation. It has the minimum
 * overhead possible to avoid too big a performance hit.
 */

void FIPS_selftest_check(void)
    {
    if (fips_selftest_fail)
	{
	OpenSSLDie(__FILE__,__LINE__, "FATAL FIPS SELFTEST FAILURE");
	}
    }

void fips_set_selftest_fail(void)
    {
    fips_selftest_fail = 1;
    }

extern const void         *FIPS_text_start(),  *FIPS_text_end();
extern const unsigned char FIPS_rodata_start[], FIPS_rodata_end[];
unsigned char              FIPS_signature [20] = { 0 };
__fips_constseg
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

    if (!fips_post_corrupt(FIPS_TEST_INTEGRITY, 0, NULL))
	HMAC_Update(&c, (unsigned char *)FIPS_hmac_key, 1);

    HMAC_Final(&c,sig,&len);
    HMAC_CTX_cleanup(&c);

    return len;
    }

int FIPS_check_incore_fingerprint(void)
    {
    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int len;
    int rv = 0;
#if defined(__sgi) && (defined(__mips) || defined(mips))
    extern int __dso_displacement[];
#else
    extern int OPENSSL_NONPIC_relocated;
#endif

    if (!fips_post_started(FIPS_TEST_INTEGRITY, 0, NULL))
	return 1;

    if (FIPS_text_start()==NULL)
	{
	FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_UNSUPPORTED_PLATFORM);
	goto err;
	}

    len=FIPS_incore_fingerprint(sig,sizeof(sig));

    if (len!=sizeof(FIPS_signature) ||
	memcmp(FIPS_signature,sig,sizeof(FIPS_signature)))
	{
	if (FIPS_signature>=FIPS_rodata_start && FIPS_signature<FIPS_rodata_end)
	    FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH_SEGMENT_ALIASING);
#if defined(__sgi) && (defined(__mips) || defined(mips))
	else if (__dso_displacement!=NULL)
#else
	else if (OPENSSL_NONPIC_relocated)
#endif
	    FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH_NONPIC_RELOCATED);
	else
	    FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH);
#ifdef OPENSSL_FIPS_DEBUGGER
    	rv = 1;
#endif
	goto err;
	}
    rv = 1;
    err:
    if (rv == 0)
    	fips_post_failed(FIPS_TEST_INTEGRITY, 0, NULL);
    else
	if (!fips_post_success(FIPS_TEST_INTEGRITY, 0, NULL))
		return 0;
    return rv;
    }

static int fips_asc_check(const unsigned char *sig, const char *asc_sig)
    {
    char tsig[20];
    const char *p;
    int i;
    if (strlen(asc_sig) != 40)
	return 0;
    for (i = 0, p = asc_sig; i < 20; i++, p += 2)
	tsig[i] = (atox(p[0]) << 4) | atox(p[1]);
    if (memcmp(tsig, sig, 20))
	return 0;
    return 1;
    }

static int fips_check_auth(const char *auth)
    {
    unsigned char auth_hmac[20];
    unsigned int hmac_len;
    if (fips_auth_fail)
	return 0;
    if (strlen(auth) < FIPS_AUTH_MIN_LEN)
	return 0;
    if (!HMAC(EVP_sha1(), FIPS_AUTH_KEY, strlen(FIPS_AUTH_KEY),
		(unsigned char *)auth, strlen(auth), auth_hmac, &hmac_len))
	return 0;
    if (hmac_len != sizeof(auth_hmac))
	return 0;

    if (fips_asc_check(auth_hmac, FIPS_AUTH_CRYPTO_OFFICER))
	return 1;

    if (fips_asc_check(auth_hmac, FIPS_AUTH_CRYPTO_USER))
	return 1;

    return 0;
    }
	


int FIPS_module_mode_set(int onoff, const char *auth)
    {
    int ret = 0;

    fips_w_lock();
    fips_started = 1;
    fips_set_owning_thread();

    if(onoff)
	{

	fips_selftest_fail = 0;
    	if (!fips_check_auth(auth))
	    {
	    fips_auth_fail = 1;
	    fips_selftest_fail = 1;
	    FIPSerr(FIPS_F_FIPS_MODULE_MODE_SET,FIPS_R_AUTHENTICATION_FAILURE);
	    return 0;
	    }

	/* Don't go into FIPS mode twice, just so we can do automagic
	   seeding */
	if(FIPS_module_mode())
	    {
	    FIPSerr(FIPS_F_FIPS_MODULE_MODE_SET,FIPS_R_FIPS_MODE_ALREADY_SET);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

#ifdef OPENSSL_IA32_SSE2
	{
	extern unsigned int OPENSSL_ia32cap_P[2];
	if ((OPENSSL_ia32cap_P[0] & (1<<25|1<<26)) != (1<<25|1<<26))
	    {
	    FIPSerr(FIPS_F_FIPS_MODULE_MODE_SET,FIPS_R_UNSUPPORTED_PLATFORM);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }
	OPENSSL_ia32cap_P[0] |= (1<<28);	/* set "shared cache"	*/
	OPENSSL_ia32cap_P[1] &= ~(1<<(60-32));	/* clear AVX		*/
	}
#endif

	if(fips_signature_witness() != FIPS_signature)
	    {
	    FIPSerr(FIPS_F_FIPS_MODULE_MODE_SET,FIPS_R_CONTRADICTING_EVIDENCE);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	if(FIPS_selftest())
	    fips_set_mode(onoff);
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

static CRYPTO_THREADID fips_thread;
static int fips_thread_set = 0;

static int fips_is_owning_thread(void)
	{
	int ret = 0;

	if (fips_started)
		{
		CRYPTO_r_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread_set)
			{
			CRYPTO_THREADID cur;
			CRYPTO_THREADID_current(&cur);
			if (!CRYPTO_THREADID_cmp(&cur, &fips_thread))
				ret = 1;
			}
		CRYPTO_r_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

int fips_set_owning_thread(void)
	{
	int ret = 0;

	if (fips_started)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_FIPS2);
		if (!fips_thread_set)
			{
			CRYPTO_THREADID_current(&fips_thread);
			ret = 1;
			fips_thread_set = 1;
			}
		CRYPTO_w_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

int fips_clear_owning_thread(void)
	{
	int ret = 0;

	if (fips_started)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread_set)
			{
			CRYPTO_THREADID cur;
			CRYPTO_THREADID_current(&cur);
			if (!CRYPTO_THREADID_cmp(&cur, &fips_thread))
				fips_thread_set = 0;
			}
		CRYPTO_w_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

unsigned char *fips_signature_witness(void)
	{
	extern unsigned char FIPS_signature[];
	return FIPS_signature;
	}

unsigned long FIPS_module_version(void)
	{
	return FIPS_MODULE_VERSION_NUMBER;
	}

const char *FIPS_module_version_text(void)
	{
	return FIPS_MODULE_VERSION_TEXT;
	}

#if 0
/* The purpose of this is to ensure the error code exists and the function
 * name is to keep the error checking script quiet
 */
void hash_final(void)
	{
	FIPSerr(FIPS_F_HASH_FINAL,FIPS_R_NON_FIPS_METHOD);
	}
#endif


#endif
