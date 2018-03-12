#ifndef CRYPTO_HASH_SHA256_H
#define CRYPTO_HASH_SHA256_H

int crypto_hashblocks_sha256(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen);

int crypto_hash_sha256(unsigned char *out,const unsigned char *in,unsigned long long inlen);

#define crypto_hash_sha256_BYTES 32

#endif
