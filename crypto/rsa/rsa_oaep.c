/* crypto/rsa/rsa_oaep.c */
/* Written by Ulf Moeller. This software is distributed on an "AS IS"
   basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. */

/* EME_OAEP as defined in RFC 2437 (PKCS #1 v2.0) */

#if !defined(NO_SHA) && !defined(NO_SHA1)
#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

int MGF1(unsigned char *mask, long len, unsigned char *seed, long seedlen);

int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
	     unsigned char *from, int flen, unsigned char *param, int plen)
    {
    int i, emlen = tlen - 1;
    unsigned char *db, *seed;
    unsigned char *dbmask, seedmask[SHA_DIGEST_LENGTH];

    if (flen > emlen - 2 * SHA_DIGEST_LENGTH - 1)
	{
	RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP,
	       RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
	return (0);
	}

    if (emlen < 2 * SHA_DIGEST_LENGTH + 1)
	{
	RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, RSA_R_KEY_SIZE_TOO_SMALL);
	return (0);
	}
    
    dbmask = OPENSSL_malloc(emlen - SHA_DIGEST_LENGTH);
    if (dbmask == NULL)
	{
	RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, ERR_R_MALLOC_FAILURE);
	return (0);
	}

    to[0] = 0;
    seed = to + 1;
    db = to + SHA_DIGEST_LENGTH + 1;

    SHA1(param, plen, db);
    memset(db + SHA_DIGEST_LENGTH, 0,
	   emlen - flen - 2 * SHA_DIGEST_LENGTH - 1);
    db[emlen - flen - SHA_DIGEST_LENGTH - 1] = 0x01;
    memcpy(db + emlen - flen - SHA_DIGEST_LENGTH, from, (unsigned int) flen);
    if (RAND_bytes(seed, SHA_DIGEST_LENGTH) <= 0)
    	return (0);
#ifdef PKCS_TESTVECT
    memcpy(seed,
	   "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f",
	   20);
#endif

    MGF1(dbmask, emlen - SHA_DIGEST_LENGTH, seed, SHA_DIGEST_LENGTH);
    for (i = 0; i < emlen - SHA_DIGEST_LENGTH; i++)
	db[i] ^= dbmask[i];

    MGF1(seedmask, SHA_DIGEST_LENGTH, db, emlen - SHA_DIGEST_LENGTH);
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
	seed[i] ^= seedmask[i];

    OPENSSL_free(dbmask);
    return (1);
    }

int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
	     unsigned char *from, int flen, int num, unsigned char *param,
	     int plen)
    {
    int i, dblen, mlen = -1;
    unsigned char *maskeddb;
    int lzero;
    unsigned char *db = NULL, seed[SHA_DIGEST_LENGTH], phash[SHA_DIGEST_LENGTH];

    if (--num < 2 * SHA_DIGEST_LENGTH + 1)
	goto decoding_err;

    lzero = num - flen;
    if (lzero < 0)
	goto decoding_err;
    maskeddb = from - lzero + SHA_DIGEST_LENGTH;
    
    dblen = num - SHA_DIGEST_LENGTH;
    db = OPENSSL_malloc(dblen);
    if (db == NULL)
	{
	RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, ERR_R_MALLOC_FAILURE);
	return (-1);
	}

    MGF1(seed, SHA_DIGEST_LENGTH, maskeddb, dblen);
    for (i = lzero; i < SHA_DIGEST_LENGTH; i++)
	seed[i] ^= from[i - lzero];
  
    MGF1(db, dblen, seed, SHA_DIGEST_LENGTH);
    for (i = 0; i < dblen; i++)
	db[i] ^= maskeddb[i];

    SHA1(param, plen, phash);

    if (memcmp(db, phash, SHA_DIGEST_LENGTH) != 0)
	goto decoding_err;
    else
	{
	for (i = SHA_DIGEST_LENGTH; i < dblen; i++)
	    if (db[i] != 0x00)
		break;
	if (db[i] != 0x01 || i++ >= dblen)
	  goto decoding_err;
	else
	    {
	    mlen = dblen - i;
	    if (tlen < mlen)
		{
		RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP, RSA_R_DATA_TOO_LARGE);
		mlen = -1;
		}
	    else
		memcpy(to, db + i, mlen);
	    }
	}
    OPENSSL_free(db);
    return (mlen);

decoding_err:
    /* to avoid chosen ciphertext attacks, the error message should not reveal
     * which kind of decoding error happened */
    RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP, RSA_R_OAEP_DECODING_ERROR);
    if (db != NULL) OPENSSL_free(db);
    return -1;
    }

int MGF1(unsigned char *mask, long len, unsigned char *seed, long seedlen)
    {
    long i, outlen = 0;
    unsigned char cnt[4];
    SHA_CTX c;
    unsigned char md[SHA_DIGEST_LENGTH];

    for (i = 0; outlen < len; i++)
	{
	cnt[0] = (i >> 24) & 255, cnt[1] = (i >> 16) & 255,
	  cnt[2] = (i >> 8) & 255, cnt[3] = i & 255;
	SHA1_Init(&c);
	SHA1_Update(&c, seed, seedlen);
	SHA1_Update(&c, cnt, 4);
	if (outlen + SHA_DIGEST_LENGTH <= len)
	    {
	    SHA1_Final(mask + outlen, &c);
	    outlen += SHA_DIGEST_LENGTH;
	    }
	else
	    {
	    SHA1_Final(md, &c);
	    memcpy(mask + outlen, md, len - outlen);
	    outlen = len;
	    }
	}
    return (0);
    }
#endif
