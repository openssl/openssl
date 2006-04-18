/* crypto/objects/obj_xref.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include <openssl/objects.h>
#include "obj_xref.h"

static int cmp_sig(const nid_triple *a, const nid_triple *b)
	{
	return **a - **b;
	}

static int cmp_sigx(const nid_triple **a, const nid_triple **b)
	{
	int ret;
	ret = (**a)[1] - (**b)[1];
	if (ret)
		return ret;
	return (**a)[2] - (**b)[2];
	}


int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid)
	{
	nid_triple tmp, *rv;
	tmp[0] = signid;

	rv = (nid_triple *)OBJ_bsearch((char *)&tmp,
				(char *)sigoid_srt,
				sizeof(sigoid_srt) / sizeof(nid_triple),
				sizeof(nid_triple),
				(int (*)(const void *, const void *))cmp_sig);
	if (rv == NULL)
		return 0;
	*pdig_nid = (*rv)[1];
	*ppkey_nid = (*rv)[2];
	return 1;
	}

int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid)
	{
	nid_triple tmp, *t=&tmp, **rv;
	tmp[1] = dig_nid;
	tmp[2] = pkey_nid;

	rv = (nid_triple **)OBJ_bsearch((char *)&t,
				(char *)sigoid_srt_xref,
				sizeof(sigoid_srt_xref) / sizeof(nid_triple *),
				sizeof(nid_triple *),
				(int (*)(const void *, const void *))cmp_sigx);
	if (rv == NULL)
		return 0;
	*psignid = (**rv)[0];
	return 1;
	}

#ifdef OBJ_XREF_TEST

main()
	{
	int n1, n2, n3;

	int i, rv;

	for (i = 0; i <	sizeof(sigoid_srt) / sizeof(nid_triple); i++)
		{
		n1 = sigoid_srt[i][0];
		rv = OBJ_find_sigid_algs(n1, &n2, &n3);
		printf("Forward: %d, %s %s %s\n", rv,
			OBJ_nid2ln(n1), OBJ_nid2ln(n2), OBJ_nid2ln(n3));
		n1=0;
		rv = OBJ_find_sigid_by_algs(&n1, n2, n3);
		printf("Reverse: %d, %s %s %s\n", rv,
			OBJ_nid2ln(n1), OBJ_nid2ln(n2), OBJ_nid2ln(n3));
		}
	}
	
#endif
