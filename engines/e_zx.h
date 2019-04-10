#ifndef HEADER_SM4_H
# define HEADER_SM4_H

# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>
# include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define SM3_LONG unsigned int
# define SM3_WORD unsigned int

# define SM3_LBLOCK  16
# define SM3_CBLOCK  (SM3_LBLOCK*4) /* SHA treats input data as a
                                     * contiguous array of 32 bit wide
                                     * big-endian values. */
# define SM3_LAST_BLOCK  (SM3_CBLOCK-8)
# define SM3_DIGEST_LENGTH 32

typedef struct SM3state_st {
    SM3_LONG h[8];
    SM3_LONG Nl, Nh;
    SM3_LONG data[SM3_LBLOCK];
    unsigned int num, md_len;
} SM3_CTX;

# ifdef OPENSSL_NO_SM4
#   error SM4 is disabled.
# endif

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
#define SM4_BLOCK_SIZE  16
#define SM4_KEY_SIZE    16

/* This should be a hidden type, but EVP requires that the size be known */
struct sm4_key_st {
# ifdef SM4_LONG
    unsigned long rd_key[32];
# else
    unsigned int rd_key[32];
# endif
};
typedef struct sm4_key_st SM4_KEY;

#ifdef  __cplusplus
}
#endif

#endif
