/*-
 * Support for VIA PadLock Advanced Cryptography Engine (ACE)
 * Written by Michal Ludvig <michal@logix.cz>
 *            http://www.logix.cz/michal
 *
 * Big thanks to Andy Polyakov for a help with optimization,
 * assembler fixes, port to MS Windows and a lot of other
 * valuable work on this engine!
 */

/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_AES
# include <openssl/aes.h>
#endif
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/modes.h>

#ifndef OPENSSL_NO_HW
# ifndef OPENSSL_NO_HW_PADLOCK

/* Attempt to have a single source for both 0.9.7 and 0.9.8 :-) */
#  if (OPENSSL_VERSION_NUMBER >= 0x00908000L)
#   ifndef OPENSSL_NO_DYNAMIC_ENGINE
#    define DYNAMIC_ENGINE
#   endif
#  elif (OPENSSL_VERSION_NUMBER >= 0x00907000L)
#   ifdef ENGINE_DYNAMIC_SUPPORT
#    define DYNAMIC_ENGINE
#   endif
#  else
#   error "Only OpenSSL >= 0.9.7 is supported"
#  endif

/*
 * VIA PadLock AES is available *ONLY* on some x86 CPUs. Not only that it
 * doesn't exist elsewhere, but it even can't be compiled on other platforms!
 */

#  undef COMPILE_HW_PADLOCK
#  if !defined(I386_ONLY) && !defined(OPENSSL_NO_ASM)
#   if    defined(__i386__) || defined(__i386) ||    \
        defined(__x86_64__) || defined(__x86_64) || \
        defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64) || \
        defined(__INTEL__)
#    define COMPILE_HW_PADLOCK
#    ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *ENGINE_padlock(void);
#    endif
#   endif
#  endif

#  ifdef OPENSSL_NO_DYNAMIC_ENGINE

void ENGINE_load_padlock(void)
{
/* On non-x86 CPUs it just returns. */
#   ifdef COMPILE_HW_PADLOCK
    ENGINE *toadd = ENGINE_padlock();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
#   endif
}

#  endif

#  ifdef COMPILE_HW_PADLOCK

/* Function for ENGINE detection and control */
static int padlock_available(void);
static int padlock_init(ENGINE *e);

/* RNG Stuff */
static RAND_METHOD padlock_rand;

/* Cipher Stuff */
#   ifndef OPENSSL_NO_AES
static int padlock_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);
#   endif

/* Engine names */
static const char *padlock_id = "padlock";
static char padlock_name[100];

/* Available features */
static int padlock_use_ace = 0; /* Advanced Cryptography Engine */
static int padlock_use_rng = 0; /* Random Number Generator */

/* ===== Engine "management" functions ===== */

/* Prepare the ENGINE structure for registration */
static int padlock_bind_helper(ENGINE *e)
{
    /* Check available features */
    padlock_available();

    /*
     * RNG is currently disabled for reasons discussed in commentary just
     * before padlock_rand_bytes function.
     */
    padlock_use_rng = 0;

    /* Generate a nice engine name with available features */
    BIO_snprintf(padlock_name, sizeof(padlock_name),
                 "VIA PadLock (%s, %s)",
                 padlock_use_rng ? "RNG" : "no-RNG",
                 padlock_use_ace ? "ACE" : "no-ACE");

    /* Register everything or return with an error */
    if (!ENGINE_set_id(e, padlock_id) ||
        !ENGINE_set_name(e, padlock_name) ||
        !ENGINE_set_init_function(e, padlock_init) ||
#   ifndef OPENSSL_NO_AES
        (padlock_use_ace && !ENGINE_set_ciphers(e, padlock_ciphers)) ||
#   endif
        (padlock_use_rng && !ENGINE_set_RAND(e, &padlock_rand))) {
        return 0;
    }

    /* Everything looks good */
    return 1;
}

#   ifdef OPENSSL_NO_DYNAMIC_ENGINE
/* Constructor */
static ENGINE *ENGINE_padlock(void)
{
    ENGINE *eng = ENGINE_new();

    if (eng == NULL) {
        return NULL;
    }

    if (!padlock_bind_helper(eng)) {
        ENGINE_free(eng);
        return NULL;
    }

    return eng;
}
#   endif

/* Check availability of the engine */
static int padlock_init(ENGINE *e)
{
    return (padlock_use_rng || padlock_use_ace);
}

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
#   ifdef DYNAMIC_ENGINE
static int padlock_bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, padlock_id) != 0)) {
        return 0;
    }

    if (!padlock_bind_helper(e)) {
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(padlock_bind_fn)
#   endif                       /* DYNAMIC_ENGINE */
/* ===== Here comes the "real" engine ===== */
#   ifndef OPENSSL_NO_AES
/* Some AES-related constants */
#    define AES_BLOCK_SIZE          16
#    define AES_KEY_SIZE_128        16
#    define AES_KEY_SIZE_192        24
#    define AES_KEY_SIZE_256        32
    /*
     * Here we store the status information relevant to the current context.
     */
    /*
     * BIG FAT WARNING: Inline assembler in PADLOCK_XCRYPT_ASM() depends on
     * the order of items in this structure.  Don't blindly modify, reorder,
     * etc!
     */
struct padlock_cipher_data {
    unsigned char iv[AES_BLOCK_SIZE]; /* Initialization vector */
    union {
        unsigned int pad[4];
        struct {
            int rounds:4;
            int dgst:1;         /* n/a in C3 */
            int align:1;        /* n/a in C3 */
            int ciphr:1;        /* n/a in C3 */
            unsigned int keygen:1;
            int interm:1;
            unsigned int encdec:1;
            int ksize:2;
        } b;
    } cword;                    /* Control word */
    AES_KEY ks;                 /* Encryption key */
};
#   endif

/* Interface to assembler module */
unsigned int padlock_capability();
void padlock_key_bswap(AES_KEY *key);
void padlock_verify_context(struct padlock_cipher_data *ctx);
void padlock_reload_key();
void padlock_aes_block(void *out, const void *inp,
                       struct padlock_cipher_data *ctx);
int padlock_ecb_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_cbc_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_cfb_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_ofb_encrypt(void *out, const void *inp,
                        struct padlock_cipher_data *ctx, size_t len);
int padlock_ctr32_encrypt(void *out, const void *inp,
                          struct padlock_cipher_data *ctx, size_t len);
int padlock_xstore(void *out, int edx);
void padlock_sha1_oneshot(void *ctx, const void *inp, size_t len);
void padlock_sha1(void *ctx, const void *inp, size_t len);
void padlock_sha256_oneshot(void *ctx, const void *inp, size_t len);
void padlock_sha256(void *ctx, const void *inp, size_t len);

/*
 * Load supported features of the CPU to see if the PadLock is available.
 */
static int padlock_available(void)
{
    unsigned int edx = padlock_capability();

    /* Fill up some flags */
    padlock_use_ace = ((edx & (0x3 << 6)) == (0x3 << 6));
    padlock_use_rng = ((edx & (0x3 << 2)) == (0x3 << 2));

    return padlock_use_ace + padlock_use_rng;
}

/* ===== AES encryption/decryption ===== */
#   ifndef OPENSSL_NO_AES

#    if defined(NID_aes_128_cfb128) && ! defined (NID_aes_128_cfb)
#     define NID_aes_128_cfb NID_aes_128_cfb128
#    endif

#    if defined(NID_aes_128_ofb128) && ! defined (NID_aes_128_ofb)
#     define NID_aes_128_ofb NID_aes_128_ofb128
#    endif

#    if defined(NID_aes_192_cfb128) && ! defined (NID_aes_192_cfb)
#     define NID_aes_192_cfb NID_aes_192_cfb128
#    endif

#    if defined(NID_aes_192_ofb128) && ! defined (NID_aes_192_ofb)
#     define NID_aes_192_ofb NID_aes_192_ofb128
#    endif

#    if defined(NID_aes_256_cfb128) && ! defined (NID_aes_256_cfb)
#     define NID_aes_256_cfb NID_aes_256_cfb128
#    endif

#    if defined(NID_aes_256_ofb128) && ! defined (NID_aes_256_ofb)
#     define NID_aes_256_ofb NID_aes_256_ofb128
#    endif

/* List of supported ciphers. */
static const int padlock_cipher_nids[] = {
    NID_aes_128_ecb,
    NID_aes_128_cbc,
    NID_aes_128_cfb,
    NID_aes_128_ofb,
    NID_aes_128_ctr,

    NID_aes_192_ecb,
    NID_aes_192_cbc,
    NID_aes_192_cfb,
    NID_aes_192_ofb,
    NID_aes_192_ctr,

    NID_aes_256_ecb,
    NID_aes_256_cbc,
    NID_aes_256_cfb,
    NID_aes_256_ofb,
    NID_aes_256_ctr
};

static int padlock_cipher_nids_num = (sizeof(padlock_cipher_nids) /
                                      sizeof(padlock_cipher_nids[0]));

/* Function prototypes ... */
static int padlock_aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv, int enc);

#    define NEAREST_ALIGNED(ptr) ( (unsigned char *)(ptr) +         \
        ( (0x10 - ((size_t)(ptr) & 0x0F)) & 0x0F )      )
#    define ALIGNED_CIPHER_DATA(ctx) ((struct padlock_cipher_data *)\
        NEAREST_ALIGNED(ctx->cipher_data))

static int
padlock_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    return padlock_ecb_encrypt(out_arg, in_arg,
                               ALIGNED_CIPHER_DATA(ctx), nbytes);
}

static int
padlock_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct padlock_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    int ret;

    memcpy(cdata->iv, ctx->iv, AES_BLOCK_SIZE);
    if ((ret = padlock_cbc_encrypt(out_arg, in_arg, cdata, nbytes)))
        memcpy(ctx->iv, cdata->iv, AES_BLOCK_SIZE);
    return ret;
}

static int
padlock_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct padlock_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    size_t chunk;

    if ((chunk = ctx->num)) {   /* borrow chunk variable */
        unsigned char *ivp = ctx->iv;

        if (chunk >= AES_BLOCK_SIZE)
            return 0;           /* bogus value */

        if (ctx->encrypt)
            while (chunk < AES_BLOCK_SIZE && nbytes != 0) {
                ivp[chunk] = *(out_arg++) = *(in_arg++) ^ ivp[chunk];
                chunk++, nbytes--;
        } else
            while (chunk < AES_BLOCK_SIZE && nbytes != 0) {
                unsigned char c = *(in_arg++);
                *(out_arg++) = c ^ ivp[chunk];
                ivp[chunk++] = c, nbytes--;
            }

        ctx->num = chunk % AES_BLOCK_SIZE;
    }

    if (nbytes == 0)
        return 1;

    memcpy(cdata->iv, ctx->iv, AES_BLOCK_SIZE);

    if ((chunk = nbytes & ~(AES_BLOCK_SIZE - 1))) {
        if (!padlock_cfb_encrypt(out_arg, in_arg, cdata, chunk))
            return 0;
        nbytes -= chunk;
    }

    if (nbytes) {
        unsigned char *ivp = cdata->iv;

        out_arg += chunk;
        in_arg += chunk;
        ctx->num = nbytes;
        if (cdata->cword.b.encdec) {
            cdata->cword.b.encdec = 0;
            padlock_reload_key();
            padlock_aes_block(ivp, ivp, cdata);
            cdata->cword.b.encdec = 1;
            padlock_reload_key();
            while (nbytes) {
                unsigned char c = *(in_arg++);
                *(out_arg++) = c ^ *ivp;
                *(ivp++) = c, nbytes--;
            }
        } else {
            padlock_reload_key();
            padlock_aes_block(ivp, ivp, cdata);
            padlock_reload_key();
            while (nbytes) {
                *ivp = *(out_arg++) = *(in_arg++) ^ *ivp;
                ivp++, nbytes--;
            }
        }
    }

    memcpy(ctx->iv, cdata->iv, AES_BLOCK_SIZE);

    return 1;
}

static int
padlock_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct padlock_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    size_t chunk;

    /*
     * ctx->num is maintained in byte-oriented modes, such as CFB and OFB...
     */
    if ((chunk = ctx->num)) {   /* borrow chunk variable */
        unsigned char *ivp = ctx->iv;

        if (chunk >= AES_BLOCK_SIZE)
            return 0;           /* bogus value */

        while (chunk < AES_BLOCK_SIZE && nbytes != 0) {
            *(out_arg++) = *(in_arg++) ^ ivp[chunk];
            chunk++, nbytes--;
        }

        ctx->num = chunk % AES_BLOCK_SIZE;
    }

    if (nbytes == 0)
        return 1;

    memcpy(cdata->iv, ctx->iv, AES_BLOCK_SIZE);

    if ((chunk = nbytes & ~(AES_BLOCK_SIZE - 1))) {
        if (!padlock_ofb_encrypt(out_arg, in_arg, cdata, chunk))
            return 0;
        nbytes -= chunk;
    }

    if (nbytes) {
        unsigned char *ivp = cdata->iv;

        out_arg += chunk;
        in_arg += chunk;
        ctx->num = nbytes;
        padlock_reload_key();   /* empirically found */
        padlock_aes_block(ivp, ivp, cdata);
        padlock_reload_key();   /* empirically found */
        while (nbytes) {
            *(out_arg++) = *(in_arg++) ^ *ivp;
            ivp++, nbytes--;
        }
    }

    memcpy(ctx->iv, cdata->iv, AES_BLOCK_SIZE);

    return 1;
}

static void padlock_ctr32_encrypt_glue(const unsigned char *in,
                                       unsigned char *out, size_t blocks,
                                       struct padlock_cipher_data *ctx,
                                       const unsigned char *ivec)
{
    memcpy(ctx->iv, ivec, AES_BLOCK_SIZE);
    padlock_ctr32_encrypt(out, in, ctx, AES_BLOCK_SIZE * blocks);
}

static int
padlock_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg,
                   const unsigned char *in_arg, size_t nbytes)
{
    struct padlock_cipher_data *cdata = ALIGNED_CIPHER_DATA(ctx);
    unsigned int num = ctx->num;

    CRYPTO_ctr128_encrypt_ctr32(in_arg, out_arg, nbytes,
                                cdata, ctx->iv, ctx->buf, &num,
                                (ctr128_f) padlock_ctr32_encrypt_glue);

    ctx->num = (size_t)num;
    return 1;
}

#    define EVP_CIPHER_block_size_ECB       AES_BLOCK_SIZE
#    define EVP_CIPHER_block_size_CBC       AES_BLOCK_SIZE
#    define EVP_CIPHER_block_size_OFB       1
#    define EVP_CIPHER_block_size_CFB       1
#    define EVP_CIPHER_block_size_CTR       1

/*
 * Declaring so many ciphers by hand would be a pain. Instead introduce a bit
 * of preprocessor magic :-)
 */
#    define DECLARE_AES_EVP(ksize,lmode,umode)      \
static const EVP_CIPHER padlock_aes_##ksize##_##lmode = {       \
        NID_aes_##ksize##_##lmode,              \
        EVP_CIPHER_block_size_##umode,  \
        AES_KEY_SIZE_##ksize,           \
        AES_BLOCK_SIZE,                 \
        0 | EVP_CIPH_##umode##_MODE,    \
        padlock_aes_init_key,           \
        padlock_##lmode##_cipher,       \
        NULL,                           \
        sizeof(struct padlock_cipher_data) + 16,        \
        EVP_CIPHER_set_asn1_iv,         \
        EVP_CIPHER_get_asn1_iv,         \
        NULL,                           \
        NULL                            \
}

DECLARE_AES_EVP(128, ecb, ECB);
DECLARE_AES_EVP(128, cbc, CBC);
DECLARE_AES_EVP(128, cfb, CFB);
DECLARE_AES_EVP(128, ofb, OFB);
DECLARE_AES_EVP(128, ctr, CTR);

DECLARE_AES_EVP(192, ecb, ECB);
DECLARE_AES_EVP(192, cbc, CBC);
DECLARE_AES_EVP(192, cfb, CFB);
DECLARE_AES_EVP(192, ofb, OFB);
DECLARE_AES_EVP(192, ctr, CTR);

DECLARE_AES_EVP(256, ecb, ECB);
DECLARE_AES_EVP(256, cbc, CBC);
DECLARE_AES_EVP(256, cfb, CFB);
DECLARE_AES_EVP(256, ofb, OFB);
DECLARE_AES_EVP(256, ctr, CTR);

static int
padlock_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                int nid)
{
    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = padlock_cipher_nids;
        return padlock_cipher_nids_num;
    }

    /* ... or the requested "cipher" otherwise */
    switch (nid) {
    case NID_aes_128_ecb:
        *cipher = &padlock_aes_128_ecb;
        break;
    case NID_aes_128_cbc:
        *cipher = &padlock_aes_128_cbc;
        break;
    case NID_aes_128_cfb:
        *cipher = &padlock_aes_128_cfb;
        break;
    case NID_aes_128_ofb:
        *cipher = &padlock_aes_128_ofb;
        break;
    case NID_aes_128_ctr:
        *cipher = &padlock_aes_128_ctr;
        break;

    case NID_aes_192_ecb:
        *cipher = &padlock_aes_192_ecb;
        break;
    case NID_aes_192_cbc:
        *cipher = &padlock_aes_192_cbc;
        break;
    case NID_aes_192_cfb:
        *cipher = &padlock_aes_192_cfb;
        break;
    case NID_aes_192_ofb:
        *cipher = &padlock_aes_192_ofb;
        break;
    case NID_aes_192_ctr:
        *cipher = &padlock_aes_192_ctr;
        break;

    case NID_aes_256_ecb:
        *cipher = &padlock_aes_256_ecb;
        break;
    case NID_aes_256_cbc:
        *cipher = &padlock_aes_256_cbc;
        break;
    case NID_aes_256_cfb:
        *cipher = &padlock_aes_256_cfb;
        break;
    case NID_aes_256_ofb:
        *cipher = &padlock_aes_256_ofb;
        break;
    case NID_aes_256_ctr:
        *cipher = &padlock_aes_256_ctr;
        break;

    default:
        /* Sorry, we don't support this NID */
        *cipher = NULL;
        return 0;
    }

    return 1;
}

/* Prepare the encryption key for PadLock usage */
static int
padlock_aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                     const unsigned char *iv, int enc)
{
    struct padlock_cipher_data *cdata;
    int key_len = EVP_CIPHER_CTX_key_length(ctx) * 8;
    unsigned long mode = EVP_CIPHER_CTX_mode(ctx);

    if (key == NULL)
        return 0;               /* ERROR */

    cdata = ALIGNED_CIPHER_DATA(ctx);
    memset(cdata, 0, sizeof(*cdata));

    /* Prepare Control word. */
    if (mode == EVP_CIPH_OFB_MODE || mode == EVP_CIPH_CTR_MODE)
        cdata->cword.b.encdec = 0;
    else
        cdata->cword.b.encdec = (ctx->encrypt == 0);
    cdata->cword.b.rounds = 10 + (key_len - 128) / 32;
    cdata->cword.b.ksize = (key_len - 128) / 64;

    switch (key_len) {
    case 128:
        /*
         * PadLock can generate an extended key for AES128 in hardware
         */
        memcpy(cdata->ks.rd_key, key, AES_KEY_SIZE_128);
        cdata->cword.b.keygen = 0;
        break;

    case 192:
    case 256:
        /*
         * Generate an extended AES key in software. Needed for AES192/AES256
         */
        /*
         * Well, the above applies to Stepping 8 CPUs and is listed as
         * hardware errata. They most likely will fix it at some point and
         * then a check for stepping would be due here.
         */
        if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
            && !enc)
            AES_set_decrypt_key(key, key_len, &cdata->ks);
        else
            AES_set_encrypt_key(key, key_len, &cdata->ks);
#    ifndef AES_ASM
        /*
         * OpenSSL C functions use byte-swapped extended key.
         */
        padlock_key_bswap(&cdata->ks);
#    endif
        cdata->cword.b.keygen = 1;
        break;

    default:
        /* ERROR */
        return 0;
    }

    /*
     * This is done to cover for cases when user reuses the
     * context for new key. The catch is that if we don't do
     * this, padlock_eas_cipher might proceed with old key...
     */
    padlock_reload_key();

    return 1;
}

#   endif                       /* OPENSSL_NO_AES */

/* ===== Random Number Generator ===== */
/*
 * This code is not engaged. The reason is that it does not comply
 * with recommendations for VIA RNG usage for secure applications
 * (posted at http://www.via.com.tw/en/viac3/c3.jsp) nor does it
 * provide meaningful error control...
 */
/*
 * Wrapper that provides an interface between the API and the raw PadLock
 * RNG
 */
static int padlock_rand_bytes(unsigned char *output, int count)
{
    unsigned int eax, buf;

    while (count >= 8) {
        eax = padlock_xstore(output, 0);
        if (!(eax & (1 << 6)))
            return 0;           /* RNG disabled */
        /* this ---vv--- covers DC bias, Raw Bits and String Filter */
        if (eax & (0x1F << 10))
            return 0;
        if ((eax & 0x1F) == 0)
            continue;           /* no data, retry... */
        if ((eax & 0x1F) != 8)
            return 0;           /* fatal failure...  */
        output += 8;
        count -= 8;
    }
    while (count > 0) {
        eax = padlock_xstore(&buf, 3);
        if (!(eax & (1 << 6)))
            return 0;           /* RNG disabled */
        /* this ---vv--- covers DC bias, Raw Bits and String Filter */
        if (eax & (0x1F << 10))
            return 0;
        if ((eax & 0x1F) == 0)
            continue;           /* no data, retry... */
        if ((eax & 0x1F) != 1)
            return 0;           /* fatal failure...  */
        *output++ = (unsigned char)buf;
        count--;
    }
    *(volatile unsigned int *)&buf = 0;

    return 1;
}

/* Dummy but necessary function */
static int padlock_rand_status(void)
{
    return 1;
}

/* Prepare structure for registration */
static RAND_METHOD padlock_rand = {
    NULL,                       /* seed */
    padlock_rand_bytes,         /* bytes */
    NULL,                       /* cleanup */
    NULL,                       /* add */
    padlock_rand_bytes,         /* pseudorand */
    padlock_rand_status,        /* rand status */
};

#  else                         /* !COMPILE_HW_PADLOCK */
#   ifndef OPENSSL_NO_DYNAMIC_ENGINE
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns);
OPENSSL_EXPORT
    int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns)
{
    return 0;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
#   endif
#  endif                        /* COMPILE_HW_PADLOCK */
# endif                         /* !OPENSSL_NO_HW_PADLOCK */
#endif                          /* !OPENSSL_NO_HW */
