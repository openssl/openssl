/* crypto/rc4/rc4test.c */
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
#include <stdlib.h>
#include <string.h>
#include "rc4.h"

unsigned char keys[6][11]={
	{8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
	{8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
	{8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{4,0xef,0x01,0x23,0x45},
	{8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
	};

unsigned char data[6][11]={
	{8,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
	{8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{0},
	};

unsigned char output[6][11]={
	{0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96},
	{0x74,0x94,0xc2,0xe7,0x10,0x4b,0x08,0x79},
	{0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a},
	{0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61},
	{0},
	};

int main(argc,argv)
int argc;
char *argv[];
	{
	int i,err=0;
	unsigned int j;
	unsigned char *p;
	RC4_KEY key;
	unsigned char buf[512],obuf[512];

	for (i=0; i<512; i++) buf[i]=0x01;

	for (i=0; i<4; i++)
		{
		RC4_set_key(&key,keys[i][0],&(keys[i][1]));
		RC4(&key,data[i][0],&(data[i][1]),obuf);
		if (memcmp(obuf,output[i],data[i][0]) != 0)
			{
			printf("error calculating RC4\n");
			printf("output:");
			for (j=0; j<data[i][0]; j++)
				printf(" %02x",obuf[j]);
			printf("\n");
			printf("expect:");
			p= &(output[i][0]);
			for (j=0; j<data[i][0]; j++)
				printf(" %02x",*(p++));
			printf("\n");
			err++;
			}
		else
			printf("test %d ok\n",i);
		}
	exit(err);
	return(0);
	}

