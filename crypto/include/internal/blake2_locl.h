/*
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.
 * You may use this under the terms of the CC0, the OpenSSL Licence, or the
 * Apache Public License 2.0, at your option.  The terms of these licenses can
 * be found at:
 *
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 * - CC0 1.0 Universal : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 */

/* crypto/blake2/blake2_locl.h */

#include <stddef.h>
#include <stdint.h>

# ifdef OPENSSL_NO_BLAKE2
#  error BLAKE2 is disabled.
# endif

#define BLAKE2S_BLOCKBYTES    64
#define BLAKE2S_OUTBYTES      32
#define BLAKE2S_KEYBYTES      32
#define BLAKE2S_SALTBYTES     8
#define BLAKE2S_PERSONALBYTES 8

#define BLAKE2B_BLOCKBYTES    128
#define BLAKE2B_OUTBYTES      64
#define BLAKE2B_KEYBYTES      64
#define BLAKE2B_SALTBYTES     16
#define BLAKE2B_PERSONALBYTES 16

struct blake2s_param_st {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint8_t  node_offset[6];/* 14 */
    uint8_t  node_depth;    /* 15 */
    uint8_t  inner_length;  /* 16 */
    /* uint8_t  reserved[0]; */
    uint8_t  salt[BLAKE2S_SALTBYTES]; /* 24 */
    uint8_t  personal[BLAKE2S_PERSONALBYTES];  /* 32 */
};

typedef struct blake2s_param_st BLAKE2S_PARAM;

struct blake2s_ctx_st {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
};

struct blake2b_param_st {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint64_t node_offset;   /* 16 */
    uint8_t  node_depth;    /* 17 */
    uint8_t  inner_length;  /* 18 */
    uint8_t  reserved[14];  /* 32 */
    uint8_t  salt[BLAKE2B_SALTBYTES]; /* 48 */
    uint8_t  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
};

typedef struct blake2b_param_st BLAKE2B_PARAM;

struct blake2b_ctx_st {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
};

#define BLAKE2B_DIGEST_LENGTH 64
#define BLAKE2S_DIGEST_LENGTH 32

typedef struct blake2s_ctx_st BLAKE2S_CTX;
typedef struct blake2b_ctx_st BLAKE2B_CTX;

int BLAKE2b_Init(BLAKE2B_CTX *c);
int BLAKE2b_Update(BLAKE2B_CTX *c, const void *data, size_t datalen);
int BLAKE2b_Final(unsigned char *md, BLAKE2B_CTX *c);

int BLAKE2s_Init(BLAKE2S_CTX *c);
int BLAKE2s_Update(BLAKE2S_CTX *c, const void *data, size_t datalen);
int BLAKE2s_Final(unsigned char *md, BLAKE2S_CTX *c);
