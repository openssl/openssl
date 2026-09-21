/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
/* For SSL3_VERSION, TLS1_VERSION etc */
#include <openssl/prov_ssl.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include "internal/constant_time.h"
#include "internal/ssl3_cbc.h"
#include "ciphercommon_local.h"

/*-
 * ssl3_cbc_copy_mac copies |md_size| bytes from the end of the record in
 * |recdata| to |*mac| in constant time (independent of the concrete value of
 * the record length |reclen|, which may vary within a 256-byte window).
 *
 * On entry:
 *   origreclen >= mac_size
 *   mac_size <= EVP_MAX_MD_SIZE
 *
 * If CBC_MAC_ROTATE_IN_PLACE is defined then the rotation is performed with
 * variable accesses in a 64-byte-aligned buffer. Assuming that this fits into
 * a single or pair of cache-lines, then the variable memory accesses don't
 * actually affect the timing. CPUs with smaller cache-lines [if any] are
 * not multi-core and are not considered vulnerable to cache-timing attacks.
 */
#define CBC_MAC_ROTATE_IN_PLACE

static int ssl3_cbc_copy_mac(size_t *reclen,
                             size_t origreclen,
                             unsigned char *recdata,
                             unsigned char **mac,
                             int *alloced,
                             size_t block_size,
                             size_t mac_size,
                             size_t good,
                             OSSL_LIB_CTX *libctx)
{
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    unsigned char rotated_mac_buf[64 + EVP_MAX_MD_SIZE];
    unsigned char *rotated_mac;
    char aux1, aux2, aux3, mask;
#else
    unsigned char rotated_mac[EVP_MAX_MD_SIZE];
#endif
    unsigned char randmac[EVP_MAX_MD_SIZE];
    unsigned char *out;

    /*
     * mac_end is the index of |recdata| just after the end of the MAC.
     */
    size_t mac_end = *reclen;
    size_t mac_start = mac_end - mac_size;
    size_t in_mac;
    /*
     * scan_start contains the number of bytes that we can ignore because the
     * MAC's position can only vary by 255 bytes.
     */
    size_t scan_start = 0;
    size_t i, j;
    size_t rotate_offset;

    if (!ossl_assert(origreclen >= mac_size
                     && mac_size <= EVP_MAX_MD_SIZE))
        return 0;

    /* If no MAC then nothing to be done */
    if (mac_size == 0) {
        /* No MAC so we can do this in non-constant time */
        if (good == 0)
            return 0;
        return 1;
    }

    *reclen -= mac_size;

    if (block_size == 1) {
        /* There's no padding so the position of the MAC is fixed */
        if (mac != NULL)
            *mac = &recdata[*reclen];
        if (alloced != NULL)
            *alloced = 0;
        return 1;
    }

    /* Create the random MAC we will emit if padding is bad */
    if (RAND_bytes_ex(libctx, randmac, mac_size, 0) <= 0)
        return 0;

    if (!ossl_assert(mac != NULL && alloced != NULL))
        return 0;
    *mac = out = OPENSSL_malloc(mac_size);
    if (*mac == NULL)
        return 0;
    *alloced = 1;

#if defined(CBC_MAC_ROTATE_IN_PLACE)
    rotated_mac = rotated_mac_buf + ((0 - (size_t)rotated_mac_buf) & 63);
#endif

    /* This information is public so it's safe to branch based on it. */
    if (origreclen > mac_size + 255 + 1)
        scan_start = origreclen - (mac_size + 255 + 1);

    in_mac = 0;
    rotate_offset = 0;
    memset(rotated_mac, 0, mac_size);
    for (i = scan_start, j = 0; i < origreclen; i++) {
        size_t mac_started = constant_time_eq_s(i, mac_start);
        size_t mac_ended = constant_time_lt_s(i, mac_end);
        unsigned char b = recdata[i];

        in_mac |= mac_started;
        in_mac &= mac_ended;
        rotate_offset |= j & mac_started;
        rotated_mac[j++] |= b & in_mac;
        j &= constant_time_lt_s(j, mac_size);
    }

    /* Now rotate the MAC */
#if defined(CBC_MAC_ROTATE_IN_PLACE)
    j = 0;
    for (i = 0; i < mac_size; i++) {
        /*
         * in case cache-line is 32 bytes,
         * load from both lines and select appropriately
         */
        aux1 = rotated_mac[rotate_offset & ~32];
        aux2 = rotated_mac[rotate_offset | 32];
        mask = constant_time_eq_8((unsigned int)(rotate_offset & ~32),
                                  (unsigned int)rotate_offset);
        aux3 = constant_time_select_8(mask, aux1, aux2);
        rotate_offset++;

        /* If the padding wasn't good we emit a random MAC */
        out[j++] = constant_time_select_8((unsigned char)(good & 0xff),
                                          aux3,
                                          randmac[i]);
        rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
    }
#else
    memset(out, 0, mac_size);
    rotate_offset = mac_size - rotate_offset;
    rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);
    for (i = 0; i < mac_size; i++) {
        for (j = 0; j < mac_size; j++)
            out[j] |= rotated_mac[i] & constant_time_eq_8_s((unsigned int)j, (unsigned int)rotate_offset);
        rotate_offset++;
        rotate_offset &= constant_time_lt_s(rotate_offset, mac_size);

        /* If the padding wasn't good we emit a random MAC */
        out[i] = constant_time_select_8((unsigned char)(good & 0xff), out[i],
            randmac[i]);
    }
#endif

    return 1;
}

/*-
 * tls1_cbc_remove_padding_and_mac removes padding from the decrypted, TLS, CBC
 * record in |recdata| by updating |reclen| in constant time. It also extracts
 * the MAC from the underlying record and places a pointer to it in |mac|. The
 * MAC data can either be newly allocated memory, or a pointer inside the
 * |recdata| buffer. If allocated then |*alloced| is set to 1, otherwise it is
 * set to 0.
 *
 * origreclen: the original record length before any changes were made
 * block_size: the block size of the cipher used to encrypt the record.
 * mac_size: the size of the MAC to be extracted
 * aead: 1 if an AEAD cipher is in use, or 0 otherwise
 * returns:
 *   0: if the record is publicly invalid.
 *   1: if the record is publicly valid. If the padding removal fails then the
 *      MAC returned is random.
 */
static int tls1_cbc_remove_padding_and_mac(size_t *reclen,
                                    size_t origreclen,
                                    unsigned char *recdata,
                                    unsigned char **mac,
                                    int *alloced,
                                    size_t block_size, size_t mac_size,
                                    int aead,
                                    OSSL_LIB_CTX *libctx)
{
    size_t good = -1;
    size_t padding_length, to_check, i;
    size_t overhead = ((block_size == 1) ? 0 : 1) /* padding length byte */
                      + mac_size;

    /*
     * These lengths are all public so we can test them in non-constant
     * time.
     */
    if (overhead > *reclen)
        return 0;

    if (block_size != 1) {

        padding_length = recdata[*reclen - 1];

        if (aead) {
            /* padding is already verified and we don't need to check the MAC */
            *reclen -= padding_length + 1 + mac_size;
            return 1;
        }

        good = constant_time_ge_s(*reclen, overhead + padding_length);
        /*
         * The padding consists of a length byte at the end of the record and
         * then that many bytes of padding, all with the same value as the
         * length byte. Thus, with the length byte included, there are i+1 bytes
         * of padding. We can't check just |padding_length+1| bytes because that
         * leaks decrypted information. Therefore we always have to check the
         * maximum amount of padding possible. (Again, the length of the record
         * is public information so we can use it.)
         */
        to_check = 256; /* maximum amount of padding, inc length byte. */
        if (to_check > *reclen)
            to_check = *reclen;

        for (i = 0; i < to_check; i++) {
            unsigned char mask = constant_time_ge_8_s(padding_length, i);
            unsigned char b = recdata[*reclen - 1 - i];
            /*
             * The final |padding_length+1| bytes should all have the value
             * |padding_length|. Therefore the XOR should be zero.
             */
            good &= ~(mask & (padding_length ^ b));
        }

        /*
         * If any of the final |padding_length+1| bytes had the wrong value, one
         * or more of the lower eight bits of |good| will be cleared.
         */
        good = constant_time_eq_s(0xff, good & 0xff);
        *reclen -= good & (padding_length + 1);
    }

    return ssl3_cbc_copy_mac(reclen, origreclen, recdata, mac, alloced,
                             block_size, mac_size, good, libctx);
}

/*
 * Fills a single block of buffered data from the input, and returns the amount
 * of data remaining in the input that is a multiple of the blocksize. The buffer
 * is only filled if it already has some data in it, isn't full already or we
 * don't have at least one block in the input.
 *
 * buf: a buffer of blocksize bytes
 * buflen: contains the amount of data already in buf on entry. Updated with the
 *         amount of data in buf at the end. On entry *buflen must always be
 *         less than the blocksize
 * blocksize: size of a block. Must be greater than 0 and a power of 2
 * in: pointer to a pointer containing the input data
 * inlen: amount of input data available
 *
 * On return buf is filled with as much data as possible up to a full block,
 * *buflen is updated containing the amount of data in buf. *in is updated to
 * the new location where input data should be read from, *inlen is updated with
 * the remaining amount of data in *in. Returns the largest value <= *inlen
 * which is a multiple of the blocksize.
 */
size_t ossl_cipher_fillblock(unsigned char *buf, size_t *buflen,
    size_t blocksize,
    const unsigned char **in, size_t *inlen)
{
    size_t blockmask = ~(blocksize - 1);
    size_t bufremain = blocksize - *buflen;

    assert(*buflen <= blocksize);
    assert(blocksize > 0 && (blocksize & (blocksize - 1)) == 0);

    if (*inlen < bufremain)
        bufremain = *inlen;
    memcpy(buf + *buflen, *in, bufremain);
    *in += bufremain;
    *inlen -= bufremain;
    *buflen += bufremain;

    return *inlen & blockmask;
}

/*
 * Fills the buffer with trailing data from an encryption/decryption that didn't
 * fit into a full block.
 */
int ossl_cipher_trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
    const unsigned char **in, size_t *inlen)
{
    if (*inlen == 0)
        return 1;

    if (*buflen + *inlen > blocksize) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(buf + *buflen, *in, *inlen);
    *buflen += *inlen;
    *inlen = 0;

    return 1;
}

/* Pad the final block for encryption */
void ossl_cipher_padblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
    size_t i;
    unsigned char pad = (unsigned char)(blocksize - *buflen);

    for (i = *buflen; i < blocksize; i++)
        buf[i] = pad;
}

int ossl_cipher_unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
    size_t pad, i;
    size_t len = *buflen;

    if (len != blocksize) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * The following assumes that the ciphertext has been authenticated.
     * Otherwise it provides a padding oracle.
     */
    pad = buf[blocksize - 1];
    if (pad == 0 || pad > blocksize) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
        return 0;
    }
    for (i = 0; i < pad; i++) {
        if (buf[--len] != pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        }
    }
    *buflen = len;
    return 1;
}

/*-
 * ossl_cipher_tlsunpadblock removes the CBC padding from the decrypted, TLS, CBC
 * record in constant time. Also removes the MAC from the record in constant
 * time.
 *
 * libctx: Our library context
 * tlsversion: The TLS version in use, e.g. TLS1_VERSION, etc
 * buf: The decrypted TLS record data
 * buflen: The length of the decrypted TLS record data. Updated with the new
 *         length after the padding is removed
 * block_size: the block size of the cipher used to encrypt the record.
 * mac: Location to store the pointer to the MAC
 * alloced: Whether the MAC is stored in a newly allocated buffer, or whether
 *          *mac points into *buf
 * macsize: the size of the MAC inside the record (or 0 if there isn't one)
 * aead: whether this is an aead cipher
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: (in constant time) Record is publicly valid. If padding is invalid then
 *      the mac is random
 */
int ossl_cipher_tlsunpadblock(OSSL_LIB_CTX *libctx, unsigned int tlsversion,
    unsigned char *buf, size_t *buflen,
    size_t blocksize,
    unsigned char **mac, int *alloced, size_t macsize,
    int aead)
{
    int ret;

    switch (tlsversion) {
    case TLS1_2_VERSION:
    case DTLS1_2_VERSION:
    case TLS1_1_VERSION:
    case DTLS1_VERSION:
    case DTLS1_BAD_VER:
        /* Remove the explicit IV */
        buf += blocksize;
        *buflen -= blocksize;
        /* Fall through */
    case TLS1_VERSION:
        ret = tls1_cbc_remove_padding_and_mac(buflen, *buflen, buf, mac,
            alloced, blocksize, macsize,
            aead, libctx);
        return ret;

    default:
        return 0;
    }
}
