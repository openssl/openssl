/* crypto/sha/sha256t.c */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
 * ====================================================================
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

unsigned char app_b1[SHA256_DIGEST_LENGTH] = {
	0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
	0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
	0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad	};

unsigned char app_b2[SHA256_DIGEST_LENGTH] = {
	0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
	0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
	0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
	0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1	};

unsigned char app_b3[SHA256_DIGEST_LENGTH] = {
	0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,
	0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
	0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,
	0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0	};

int main ()
{ unsigned char md[SHA256_DIGEST_LENGTH];
  int		i;
  SHA256_CTX	ctx;

    fprintf(stdout,"Testing SHA-256 ");

    SHA256("abc",3,md);
    if (memcmp(md,app_b1,sizeof(app_b1)))
    {	fflush(stdout);
	fprintf(stderr,"\nTEST 1 of 3 failed.\n");
	return 1;
    }
    else
	fprintf(stdout,"."); fflush(stdout);

    SHA256("abcdbcde""cdefdefg""efghfghi""ghijhijk"
	   "ijkljklm""klmnlmno""mnopnopq",56,md);
    if (memcmp(md,app_b2,sizeof(app_b2)))
    {	fflush(stdout);
	fprintf(stderr,"\nTEST 2 of 3 failed.\n");
	return 1;
    }
    else
	fprintf(stdout,"."); fflush(stdout);

    SHA256_Init(&ctx);
    for (i=0;i<1000000;i+=64)
	SHA256_Update(&ctx, "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa"
			    "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa",
			    (1000000-i)<64?1000000-i:64);
    SHA256_Final(md,&ctx);

    if (memcmp(md,app_b3,sizeof(app_b3)))
    {	fflush(stdout);
	fprintf(stderr,"\nTEST 3 of 3 failed.\n");
	return 1;
    }
    else
	fprintf(stdout,"."); fflush(stdout);

    fprintf(stdout," passed.\n"); fflush(stdout);
}
