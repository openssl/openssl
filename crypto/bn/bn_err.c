/* lib/bn/bn_err.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
#include "err.h"
#include "bn.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA BN_str_functs[]=
	{
{ERR_PACK(0,BN_F_BN_BLINDING_CONVERT,0),	"BN_BLINDING_convert"},
{ERR_PACK(0,BN_F_BN_BLINDING_INVERT,0),	"BN_BLINDING_invert"},
{ERR_PACK(0,BN_F_BN_BLINDING_NEW,0),	"BN_BLINDING_new"},
{ERR_PACK(0,BN_F_BN_BLINDING_UPDATE,0),	"BN_BLINDING_update"},
{ERR_PACK(0,BN_F_BN_BN2DEC,0),	"BN_bn2dec"},
{ERR_PACK(0,BN_F_BN_BN2HEX,0),	"BN_bn2hex"},
{ERR_PACK(0,BN_F_BN_CTX_NEW,0),	"BN_CTX_new"},
{ERR_PACK(0,BN_F_BN_DIV,0),	"BN_div"},
{ERR_PACK(0,BN_F_BN_EXPAND2,0),	"bn_expand2"},
{ERR_PACK(0,BN_F_BN_MOD_EXP_MONT,0),	"BN_mod_exp_mont"},
{ERR_PACK(0,BN_F_BN_MOD_INVERSE,0),	"BN_mod_inverse"},
{ERR_PACK(0,BN_F_BN_MOD_MUL_RECIPROCAL,0),	"BN_mod_mul_reciprocal"},
{ERR_PACK(0,BN_F_BN_MPI2BN,0),	"BN_mpi2bn"},
{ERR_PACK(0,BN_F_BN_NEW,0),	"BN_new"},
{ERR_PACK(0,BN_F_BN_RAND,0),	"BN_rand"},
{0,NULL},
	};

static ERR_STRING_DATA BN_str_reasons[]=
	{
{BN_R_BAD_RECIPROCAL                     ,"bad reciprocal"},
{BN_R_CALLED_WITH_EVEN_MODULUS           ,"called with even modulus"},
{BN_R_DIV_BY_ZERO                        ,"div by zero"},
{BN_R_ENCODING_ERROR                     ,"encoding error"},
{BN_R_INVALID_LENGTH                     ,"invalid length"},
{BN_R_NOT_INITALISED                     ,"not initalised"},
{BN_R_NO_INVERSE                         ,"no inverse"},
{0,NULL},
	};

#endif

void ERR_load_BN_strings()
	{
	static int init=1;

	if (init);
		{;
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_BN,BN_str_functs);
		ERR_load_strings(ERR_LIB_BN,BN_str_reasons);
#endif

		}
	}
