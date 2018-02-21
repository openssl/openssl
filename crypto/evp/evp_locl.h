/*
 * Copyright 2000-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* EVP_MD_CTX related stuff */

struct evp_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */ ;

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */ ;

struct evp_mac_ctx_st {
    const EVP_MAC *meth;         /* Method structure */
    void *data;                  /* Individual method data */
} /* EVP_MAC_CTX */;

int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ASN1_TYPE *param,
                             const EVP_CIPHER *c, const EVP_MD *md,
                             int en_de);

struct evp_Encode_Ctx_st {
    /* number saved in a partial encode/decode */
    int num;
    /*
     * The length is either the output line length (in input bytes) or the
     * shortest input line length that is ok.  Once decoding begins, the
     * length is adjusted up each time a longer line is decoded
     */
    int length;
    /* data to encode */
    unsigned char enc_data[80];
    /* number read on current line */
    int line_num;
    unsigned int flags;
};

typedef struct evp_pbe_st EVP_PBE_CTL;
DEFINE_STACK_OF(EVP_PBE_CTL)

/*
 * According to the letter of standard difference between pointers
 * is specified to be valid only within same object. This makes
 * it formally challenging to determine if input and output buffers
 * are not partially overlapping with standard pointer arithmetic.
 */
#ifdef PTRDIFF_T
# undef PTRDIFF_T
#endif
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE==64
/*
 * Then we have VMS that distinguishes itself by adhering to
 * sizeof(size_t)==4 even in 64-bit builds, which means that
 * difference between two pointers might be truncated to 32 bits.
 * In the context one can even wonder how comparison for
 * equality is implemented. To be on the safe side we adhere to
 * PTRDIFF_T even for comparison for equality.
 */
# define PTRDIFF_T uint64_t
#else
# define PTRDIFF_T size_t
#endif

static ossl_inline
int is_any_overlapping(const void *ptr1, int len1, const void *ptr2, int len2)
{
    PTRDIFF_T diff = (PTRDIFF_T)ptr1 - (PTRDIFF_T)ptr2;
    /*
     * Check for any overlapping between
     * [ptr1..ptr1+len1[ and [ptr2..ptr2+len2[.
     * Binary logical operations are used instead of boolean
     * to minimize number of conditional branches.
     */
    int overlapped = (len1 > 0) & (len2 > 0)
                     & ((diff < (PTRDIFF_T)len2)
                        | (diff > (0 - (PTRDIFF_T)len1)));

    return overlapped;
}

static ossl_inline
int is_pointer_offset(const void *ptr1, const void *ptr2, int offset)
{
    PTRDIFF_T diff = (PTRDIFF_T)ptr1 - (PTRDIFF_T)ptr2;

    return diff == (PTRDIFF_T)offset;
}

static ossl_inline
int is_partially_overlapping(const void *out, const void *in, int inl,
                             int i, int bl)
{
    /*
     * inl is input length, bl is block size and i partial data length.
     * If inl < bl - i, there will be no output at all, thus no overlap.
     * If inl < 2*bl - i, the output will be exactly one cipher block.
     * If inl < 3*bl - i, the output will be exactly two cipher blocks.
     * If inl is larger than that, the output will be three or more
     * cipher blocks.
     *
     * If bl == 1 an overlap will be safe if in >= out
     * otherwise an overlap will be safe if in == out + i
     * _or_ if in >= out + 2*bl + i.
     *
     * This is for CBC decrypt mode which accesses IN
     * a second time as IV for the next cipher block.
     * When IN is less than two blocks ahead of OUT
     * the IV can get overwritten.
     */
    int outl;

    if (inl < 2*bl - i)
        outl = bl;
    else if (inl < 3*bl - i)
        outl = 2*bl;
    else
        outl = 2*bl + i;

    return is_any_overlapping(in, inl, out, bl == 1 ? 1 : outl)
           & !is_pointer_offset(in, out, i)
           & (inl >= bl - i);
}
