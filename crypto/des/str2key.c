/* crypto/des/str2key.c */
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

#include "des_locl.h"

extern int des_check_key;

void des_string_to_key(str, key)
char *str;
des_cblock (*key);
	{
	des_key_schedule ks;
	int i,length;
	register unsigned char j;

	memset(key,0,8);
	length=strlen(str);
#ifdef OLD_STR_TO_KEY
	for (i=0; i<length; i++)
		(*key)[i%8]^=(str[i]<<1);
#else /* MIT COMPATIBLE */
	for (i=0; i<length; i++)
		{
		j=str[i];
		if ((i%16) < 8)
			(*key)[i%8]^=(j<<1);
		else
			{
			/* Reverse the bit order 05/05/92 eay */
			j=((j<<4)&0xf0)|((j>>4)&0x0f);
			j=((j<<2)&0xcc)|((j>>2)&0x33);
			j=((j<<1)&0xaa)|((j>>1)&0x55);
			(*key)[7-(i%8)]^=j;
			}
		}
#endif
	des_set_odd_parity((des_cblock *)key);
	i=des_check_key;
	des_check_key=0;
	des_set_key((des_cblock *)key,ks);
	des_check_key=i;
	des_cbc_cksum((des_cblock *)str,(des_cblock *)key,(long)length,ks,
		(des_cblock *)key);
	memset(ks,0,sizeof(ks));
	des_set_odd_parity((des_cblock *)key);
	}

void des_string_to_2keys(str, key1, key2)
char *str;
des_cblock (*key1);
des_cblock (*key2);
	{
	des_key_schedule ks;
	int i,length;
	register unsigned char j;

	memset(key1,0,8);
	memset(key2,0,8);
	length=strlen(str);
#ifdef OLD_STR_TO_KEY
	if (length <= 8)
		{
		for (i=0; i<length; i++)
			{
			(*key2)[i]=(*key1)[i]=(str[i]<<1);
			}
		}
	else
		{
		for (i=0; i<length; i++)
			{
			if ((i/8)&1)
				(*key2)[i%8]^=(str[i]<<1);
			else
				(*key1)[i%8]^=(str[i]<<1);
			}
		}
#else /* MIT COMPATIBLE */
	for (i=0; i<length; i++)
		{
		j=str[i];
		if ((i%32) < 16)
			{
			if ((i%16) < 8)
				(*key1)[i%8]^=(j<<1);
			else
				(*key2)[i%8]^=(j<<1);
			}
		else
			{
			j=((j<<4)&0xf0)|((j>>4)&0x0f);
			j=((j<<2)&0xcc)|((j>>2)&0x33);
			j=((j<<1)&0xaa)|((j>>1)&0x55);
			if ((i%16) < 8)
				(*key1)[7-(i%8)]^=j;
			else
				(*key2)[7-(i%8)]^=j;
			}
		}
	if (length <= 8) memcpy(key2,key1,8);
#endif
	des_set_odd_parity((des_cblock *)key1);
	des_set_odd_parity((des_cblock *)key2);
	i=des_check_key;
	des_check_key=0;
	des_set_key((des_cblock *)key1,ks);
	des_cbc_cksum((des_cblock *)str,(des_cblock *)key1,(long)length,ks,
		(des_cblock *)key1);
	des_set_key((des_cblock *)key2,ks);
	des_cbc_cksum((des_cblock *)str,(des_cblock *)key2,(long)length,ks,
		(des_cblock *)key2);
	des_check_key=i;
	memset(ks,0,sizeof(ks));
	des_set_odd_parity(key1);
	des_set_odd_parity(key2);
	}
