/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include "internal/nelem.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_DGRAM)

/* Just a ClientHello without a cookie */
static const unsigned char clienthello_nocookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x3A, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x2E, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x2E, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len */
    0x00, 0x04, /* Ciphersuites len */
    0x00, 0x2f, /* AES128-SHA */
    0x00, 0xff, /* Empty reneg info SCSV */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x00 /* Extensions len */
};

/* First fragment of a ClientHello without a cookie */
static const unsigned char clienthello_nocookie_frag[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x30, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x2E, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x24, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00 /* Cookie len */
};

/* First fragment of a ClientHello which is too short */
static const unsigned char clienthello_nocookie_short[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x2F, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x2E, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x23, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00 /* Session id len */
};

/* Second fragment of a ClientHello */
static const unsigned char clienthello_2ndfrag[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x38, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x2E, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x02, /* Fragment offset */
    0x00, 0x00, 0x2C, /* Fragment length */
    /* Version skipped - sent in first fragment */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len */
    0x00, 0x04, /* Ciphersuites len */
    0x00, 0x2f, /* AES128-SHA */
    0x00, 0xff, /* Empty reneg info SCSV */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x00 /* Extensions len */
};

/* A ClientHello with a good cookie */
static const unsigned char clienthello_cookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x4E, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x42, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x42, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x00, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, /* Cookie */
    0x00, 0x04, /* Ciphersuites len */
    0x00, 0x2f, /* AES128-SHA */
    0x00, 0xff, /* Empty reneg info SCSV */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x00 /* Extensions len */
};

/* A fragmented ClientHello with a good cookie */
static const unsigned char clienthello_cookie_frag[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x44, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x42, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x38, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x00, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13 /* Cookie */
};

/* A ClientHello with a bad cookie */
static const unsigned char clienthello_badcookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x4E, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x42, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x42, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x01, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, /* Cookie */
    0x00, 0x04, /* Ciphersuites len */
    0x00, 0x2f, /* AES128-SHA */
    0x00, 0xff, /* Empty reneg info SCSV */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x00 /* Extensions len */
};

/* A fragmented ClientHello with the fragment boundary mid cookie */
static const unsigned char clienthello_cookie_short[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x43, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x42, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x37, /* Fragment length */
    0xFE, 0xFD, /* DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x00, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12 /* Cookie */
};

/* Bad record - too short */
static const unsigned char record_short[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* Record sequence number */
};

/*
 * DTLSv1.3 packet variants.
 *
 * Per RFC 9147, epoch-0 ClientHellos use the same legacy 13-byte record
 * header as DTLS 1.2, with legacy_record_version = 0xFEFD and
 * legacy_client_version = 0xFEFD.  DTLS 1.3 is signalled only via the
 * supported_versions extension (type 0x002B, value 0xFEFC).
 *
 * Each packet below is derived from its DTLS 1.2 counterpart by replacing
 * the empty extensions block (0x00 0x00) with a 9-byte block:
 *   0x00 0x07               extensions_len = 7
 *   0x00 0x2B 0x00 0x03     supported_versions ext, 3 bytes of data
 *   0x02                    versions list len = 2
 *   0xFE 0xFC               DTLSv1.3
 * and adjusting record_len / msg_len / frag_len accordingly (+7).
 * Fragments that stop before the extensions block only have msg_len updated.
 */

/* A DTLSv1.3 ClientHello without a cookie */
static const unsigned char clienthello13_nocookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x7B, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x6F, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x6F, /* Fragment length */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len */
    0x00, 0x04, /* Ciphersuites len */
    0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
    0x13, 0x02, /* TLS_AES_256_GCM_SHA384 */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x41, /* Extensions len = 65 */
    /* supported_versions extension */
    0x00, 0x2B, /* type */
    0x00, 0x03, /* ext data len */
    0x02, /* versions list len */
    0xFE, 0xFC, /* DTLSv1.3 */
    /* supported_groups extension */
    0x00, 0x0A, /* type */
    0x00, 0x04, /* ext data len */
    0x00, 0x02, /* groups list len */
    0x00, 0x1D, /* x25519 */
    /* signature_algorithms extension */
    0x00, 0x0D, /* type */
    0x00, 0x04, /* ext data len */
    0x00, 0x02, /* sigalgs list len */
    0x08, 0x04, /* rsa_pss_rsae_sha256 */
    /* key_share extension */
    0x00, 0x33, /* type */
    0x00, 0x26, /* ext data len = 38 */
    0x00, 0x24, /* client_shares len = 36 */
    0x00, 0x1D, /* x25519 */
    0x00, 0x20, /* key_exchange len = 32 */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 /* dummy x25519 pubkey */
};

/*
 * Second fragment of a DTLSv1.3 ClientHello without a cookie.
 * Mirrors clienthello_2ndfrag but with the DTLSv1.3 full message length.
 * Fragment offset 2 skips the legacy_client_version field sent in the first
 * fragment.  Because the fragment offset is non-zero, DTLSv1_listen must
 * drop this packet (it cannot reconstruct a complete ClientHello from it).
 *
 * Full DTLSv1.3 nocookie message body = 0x35 bytes (0x2E + 7 for the
 * supported_versions extension).  Fragment skips first 2 bytes (version),
 * so fragment length = 0x35 - 2 = 0x33.
 * Record length = 1 + 3 + 2 + 3 + 3 + 0x33 = 0x3F.
 */
static const unsigned char clienthello13_2ndfrag[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x3F, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x35, /* Message length (0x2E + 7 - full nocookie message) */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x02, /* Fragment offset */
    0x00, 0x00, 0x33, /* Fragment length (0x35 - 2 bytes skipped) */
    /* legacy_client_version skipped - sent in first fragment */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len */
    0x00, 0x04, /* Ciphersuites len */
    0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
    0x13, 0x02, /* TLS_AES_256_GCM_SHA384 */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x07, /* Extensions len */
    0x00, 0x2B, /* supported_versions */
    0x00, 0x03, /* ext data len */
    0x02, /* versions list len */
    0xFE, 0xFC /* DTLSv1.3 */
};

static const unsigned char verify[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x23, /* Record Length */
    0x03, /* HelloVerifyRequest */
    0x00, 0x00, 0x17, /* Message length */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x17, /* Fragment length */
    0xFE, 0xFF, /* DTLSv1.0 */
    0x14, /* Cookie len */
    0x00, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13 /* Cookie */
};

typedef struct {
    const unsigned char *in;
    unsigned int inlen;
    /*
     * GOOD == positive return value from DTLSv1_listen, no output yet
     * VERIFY == 0 return value, HelloVerifyRequest sent
     * VERIFY_HRR == 0 return value, HelloRetryRequest sent
     * DROP == 0 return value, no output
     */
    enum { GOOD,
        VERIFY,
        VERIFY_HRR,
        DROP } outtype;
} tests;

static tests testpackets[] = {
    { clienthello_nocookie, sizeof(clienthello_nocookie), VERIFY },
    { clienthello_nocookie_frag, sizeof(clienthello_nocookie_frag), VERIFY },
    { clienthello_nocookie_short, sizeof(clienthello_nocookie_short), DROP },
    { clienthello_2ndfrag, sizeof(clienthello_2ndfrag), DROP },
    { clienthello_cookie, sizeof(clienthello_cookie), GOOD },
    { clienthello_cookie_frag, sizeof(clienthello_cookie_frag), GOOD },
    { clienthello_badcookie, sizeof(clienthello_badcookie), VERIFY },
    { clienthello_cookie_short, sizeof(clienthello_cookie_short), DROP },
    { record_short, sizeof(record_short), DROP }
};

static tests testpackets13[] = {
    { clienthello13_nocookie, sizeof(clienthello13_nocookie), VERIFY_HRR },
    { clienthello_nocookie_short, sizeof(clienthello_nocookie_short), DROP },
    { clienthello13_2ndfrag, sizeof(clienthello13_2ndfrag), DROP },
};

#define COOKIE_LEN 20

static int cookie_gen(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned int i;

    for (i = 0; i < COOKIE_LEN; i++, cookie++)
        *cookie = i;
    *cookie_len = COOKIE_LEN;

    return 1;
}

static int cookie_verify(SSL *ssl, const unsigned char *cookie,
    unsigned int cookie_len)
{
    unsigned int i;

    if (cookie_len != COOKIE_LEN)
        return 0;

    for (i = 0; i < COOKIE_LEN; i++, cookie++) {
        if (*cookie != i)
            return 0;
    }

    return 1;
}

/*
 * TLS 1.3 stateless cookie callbacks used for the DTLS 1.3 HRR path in
 * DTLSv1_listen().  We reuse the same simple 20-byte sequential pattern as
 * the legacy DTLS cookie callbacks above so that verify13[] can be computed
 * statically.
 */
static int stateless_cookie_gen(SSL *ssl, unsigned char *cookie,
    size_t *cookie_len)
{
    unsigned int i;

    for (i = 0; i < COOKIE_LEN; i++, cookie++)
        *cookie = (unsigned char)i;
    *cookie_len = COOKIE_LEN;
    return 1;
}

static int stateless_cookie_verify(SSL *ssl, const unsigned char *cookie,
    size_t cookie_len)
{
    unsigned int i;

    if (cookie_len != COOKIE_LEN)
        return 0;

    for (i = 0; i < COOKIE_LEN; i++, cookie++) {
        if (*cookie != (unsigned char)i)
            return 0;
    }

    return 1;
}

/*
 * Validate that the given data is a DTLS 1.3 HelloRetryRequest.
 */
static int is_hrr_message(const unsigned char *data, size_t datalen)
{
    /* HRR random - SHA256("HelloRetryRequest") per RFC 8446 */
    static const unsigned char hrr_random[] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
        0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };

    /* Check record type is handshake (0x16) */
    if (data[0] != 0x16)
        return 0;

    /* Check handshake message type is ServerHello (0x02) at offset 13 */
    if (data[13] != 0x02)
        return 0;

    /* Check HRR random at offset 27 (13 + 12 + 2) */
    if (memcmp(data + 27, hrr_random, 32) != 0)
        return 0;

    return 1;
}

/*
 * Combined DTLS listen test covering both DTLS 1.2 and DTLS 1.3 packet
 * variants.
 * 0: Test that DTLS 1.2 without a cookie is accepted by DTLSv1_listen().
 * 1: Test that a fragmented DTLS 1.2 ClientHello without a cookie is
 *   accepted by DTLSv1_listen().
 * 2: Test that a truncated DTLS 1.2 ClientHello without a cookie is
 *   dropped by DTLSv1_listen().
 * 3: Test that a second fragment of a DTLS 1.2 ClientHello without a
 *   cookie is dropped by DTLSv1_listen() (it cannot reconstruct a full
 *   ClientHello from it).
 * 4: Test that a DTLS 1.2 ClientHello with a good cookie is accepted by
 *   DTLSv1_listen().
 * 5: Test that a fragmented DTLS 1.2 ClientHello with a good cookie is
 *   accepted by DTLSv1_listen().
 * 6: Test that a DTLS 1.2 ClientHello with a bad cookie is rejected by
 *   DTLSv1_listen() with a HelloVerifyRequest.
 * 7: Test that a DTLS 1.2 ClientHello with a truncated cookie is dropped
 *   by DTLSv1_listen().
 * 8: Test that a short record is dropped by DTLSv1_listen().
 * 9: Test that DTLS 1.3 without a cookie sends a HelloRetryRequest.
 * 10: Test that a truncated DTLS 1.3 ClientHello is dropped by
 *   DTLSv1_listen().
 * 11: Test that a second fragment of a DTLS 1.3 ClientHello is dropped by
 *   DTLSv1_listen() (it cannot reconstruct a full ClientHello from it).
 */
static int dtls_listen_test(int i)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *outbio = NULL;
    BIO *inbio = NULL;
    BIO_ADDR *peer = NULL;
    tests *tp;
    int is_dtls13 = (i >= (int)OSSL_NELEM(testpackets));
    char *data;
    long datalen;
    int ret, success = 0;

    if (is_dtls13) {
        tp = &testpackets13[i - (int)OSSL_NELEM(testpackets)];
#if defined(OSSL_NO_USABLE_DTLS1_3) || defined(OPENSSL_NO_EC) || defined(OPENSSL_NO_ECX)
        TEST_skip("DTLSv1.3 not usable");
        return 1;
#endif
    } else {
        tp = &testpackets[i];
    }

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_ptr(peer = BIO_ADDR_new()))
        goto err;

    /* Constrain to DTLSv1.3 only for the second set of test vectors */
    if (is_dtls13) {
        if (!TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
            goto err;
        /*
         * Pin the server to TLS_AES_128_GCM_SHA256 so that both the full
         * ClientHello (cipher list present) and the fragment (no cipher list,
         * falls back to server preference) produce the same verify13[] output.
         */
        if (!TEST_true(SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256")))
            goto err;
        /*
         * Register the TLS 1.3 stateless cookie callbacks so that
         * DTLSv1_listen() uses the DTLS 1.3 HelloRetryRequest path when it
         * detects DTLS 1.3 in the supported_versions extension.
         */
        SSL_CTX_set_stateless_cookie_generate_cb(ctx, stateless_cookie_gen);
        SSL_CTX_set_stateless_cookie_verify_cb(ctx, stateless_cookie_verify);

        /*
         * DTLS 1.3 raw packet tests use SSL_stateless() which performs full
         * ClientHello processing including cipher and signature algorithm
         * negotiation. This requires the server to have a certificate loaded.
         */
        if (!TEST_true(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
            || !TEST_true(SSL_CTX_use_PrivateKey_file(ctx, privkey, SSL_FILETYPE_PEM)))
            goto err;
    }

    SSL_CTX_set_cookie_generate_cb(ctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify);

    /* Create an SSL object and set the BIO */
    if (!TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(outbio = BIO_new(BIO_s_mem())))
        goto err;
    SSL_set0_wbio(ssl, outbio);

    /*
     * For DTLS 1.3 tests, use the dgram_mem BIO with peek mode enabled.
     * This is required because DTLSv1_listen() peeks at the packet to detect
     * DTLS 1.3 before passing it to SSL_stateless().
     * For DTLS 1.2 tests, a simple memory BIO works fine.
     */
    if (is_dtls13) {
        if (!TEST_ptr(inbio = BIO_new(BIO_s_dgram_mem())))
            goto err;
        /* Enable peek mode so DTLSv1_listen() can peek then re-read */
        if (!TEST_true(BIO_ctrl(inbio, BIO_CTRL_DGRAM_SET_PEEK_MODE, 1, NULL)))
            goto err;
        /* Write the test packet into the dgram_mem BIO */
        if (!TEST_int_eq(BIO_write(inbio, tp->in, tp->inlen), (int)tp->inlen))
            goto err;
    } else {
        if (!TEST_ptr(inbio = BIO_new_mem_buf((char *)tp->in, tp->inlen)))
            goto err;
        BIO_set_mem_eof_return(inbio, -1);
    }
    SSL_set0_rbio(ssl, inbio);

    /* Process the incoming packet */
    if (!TEST_int_ge(ret = DTLSv1_listen(ssl, peer), 0))
        goto err;
    datalen = BIO_get_mem_data(outbio, &data);

    if (tp->outtype == VERIFY) {
        /* DTLS <= 1.2: expect a HelloVerifyRequest */
        if (!TEST_int_eq(ret, 0)
            || !TEST_mem_eq(data, datalen, verify, sizeof(verify)))
            goto err;
    } else if (tp->outtype == VERIFY_HRR) {
        /*
         * DTLS 1.3: expect a HelloRetryRequest.
         * The cookie contains timestamps and hashes so we can't do exact
         * byte comparison - just verify it's a valid HRR message.
         */
        if (!TEST_int_eq(ret, 0)
            || !TEST_true(is_hrr_message((const unsigned char *)data, datalen)))
            goto err;
    } else if (datalen == 0) {
        if (!TEST_true((ret == 0 && tp->outtype == DROP)
                || (ret == 1 && tp->outtype == GOOD)))
            goto err;
    } else {
        TEST_info("Test %d: unexpected data output", i);
        goto err;
    }
    (void)BIO_reset(outbio);
    inbio = NULL;
    SSL_set0_rbio(ssl, NULL);
    success = 1;

err:
    /* Also frees up outbio */
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free(inbio);
    OPENSSL_free(peer);
    return success;
}
#endif /* !OPENSSL_NO_SOCK && !OPENSSL_NO_DGRAM */

#ifndef OPENSSL_NO_DTLS1_3
/*
 * Verify that a DTLS client completes a full handshake through DTLSv1_listen()
 * and negotiates DTLS 1.3.
 *
 * The server is pinned to DTLS 1.3 only and both legacy and TLS 1.3 stateless
 * cookie callbacks are set.  When DTLSv1_listen() receives the first
 * ClientHello it detects DTLS 1.3 in the supported_versions extension and
 * sends a HelloRetryRequest carrying a freshly-generated cookie.  The client
 * sends a second ClientHello containing that cookie in the TLS cookie extension.
 * SSL_stateless inside of DTLSv1_listen() verifies the cookie and returns
 * success, after which SSL_accept() completes the DTLS 1.3 handshake.  We assert
 * DTLS 1.3 was actually negotiated and exchange application data.
 */
static int test_dtls13_listen(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const char msg[] = "Hello DTLS 1.3";
    char buf[sizeof(msg)];
    size_t written, readbytes;
    int testresult = 0;

    /*
     * Server: DTLS 1.3 only.
     * Client: DTLS 1.0 minimum so it can handle the HRR response from
     * DTLSv1_listen(), but prefers DTLS 1.3 as max — the server will enforce
     * DTLS 1.3 for the actual handshake.
     */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Allow the client to speak DTLS 1.0+ for the HRR exchange */
    if (!TEST_true(SSL_CTX_set_min_proto_version(cctx, DTLS1_VERSION)))
        goto end;

    /*
     * Legacy callbacks (used for DTLS <= 1.2 fallback path) and TLS 1.3
     * stateless callbacks (used by the DTLS 1.3 HRR path in DTLSv1_listen).
     */
    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);
    SSL_CTX_set_stateless_cookie_generate_cb(sctx, stateless_cookie_gen);
    SSL_CTX_set_stateless_cookie_verify_cb(sctx, stateless_cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * The last argument of create_bare_ssl_connection() requests that
     * DTLSv1_listen() is used on the server before SSL_accept().
     */
    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    /* Confirm DTLS 1.3 was actually negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_3_VERSION))
        goto end;

    /* Exchange a short application-data message in each direction. */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Verify that a pure DTLS 1.3 client (no DTLS <= 1.2 support) can complete
 * a handshake through DTLSv1_listen() now that it sends a HelloRetryRequest
 * instead of a HelloVerifyRequest.
 *
 * Both server and client are restricted to DTLS 1.3 exclusively.  The server
 * sets both legacy and TLS 1.3 stateless cookie callbacks.  DTLSv1_listen()
 * detects DTLS 1.3 via supported_versions, sends an HRR carrying a cookie,
 * the DTLS 1.3 client echoes it back in a TLS cookie extension, and the
 * handshake completes.
 */
static int test_dtls13_listen_client_dtls13_only(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    /* Both server and client are restricted to DTLS 1.3 exclusively. */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(SSL_CTX_set_min_proto_version(cctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(cctx, DTLS1_3_VERSION)))
        goto end;

    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);
    SSL_CTX_set_stateless_cookie_generate_cb(sctx, stateless_cookie_gen);
    SSL_CTX_set_stateless_cookie_verify_cb(sctx, stateless_cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Pass listen=1: DTLSv1_listen() sends an HRR, the DTLS 1.3-only
     * client echoes the cookie back, and the handshake then completes
     * via SSL_accept().
     */
    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    /* Confirm DTLS 1.3 was actually negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_3_VERSION))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test scenario: Only stateless callbacks set, DTLS 1.3 client.
 *
 * When only stateless callbacks are configured, DTLSv1_listen() uses
 * SSL_stateless() for all clients without needing to peek at the packet.
 * This tests that a DTLS 1.3 client successfully completes the handshake.
 */
static int test_dtls13_listen_stateless_cb_only(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const char msg[] = "Stateless only test";
    char buf[sizeof(msg)];
    size_t written, readbytes;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Only set stateless callbacks - no legacy callbacks */
    SSL_CTX_set_stateless_cookie_generate_cb(sctx, stateless_cookie_gen);
    SSL_CTX_set_stateless_cookie_verify_cb(sctx, stateless_cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    /* Confirm DTLS 1.3 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_3_VERSION))
        goto end;

    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test scenario: Only legacy callbacks set, DTLS 1.2 client.
 *
 * When only legacy callbacks are configured, DTLSv1_listen() uses the
 * HelloVerifyRequest path and sets max version to DTLS 1.2. This tests
 * that a DTLS 1.2 client successfully completes the handshake.
 */
static int test_dtls12_listen_legacy_cb_only(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const char msg[] = "Legacy only test";
    char buf[sizeof(msg)];
    size_t written, readbytes;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Only set legacy callbacks - no stateless callbacks */
    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    /* Confirm DTLS 1.2 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_2_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_2_VERSION))
        goto end;

    /* Verify data can be exchanged */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test scenario: Only legacy callbacks set Client supports DTLS 1.2
 * and DTLS 1.3
 *
 * When only legacy callbacks are configured, DTLSv1_listen() uses the
 * HelloVerifyRequest path and sets max version to DTLS 1.2. This tests
 * that a DTLS 1.2 client successfully completes the handshake.
 */
static int test_dtls12_listen_legacy_cb_only_client_supports_dtls13(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const char msg[] = "Legacy only test";
    char buf[sizeof(msg)];
    size_t written, readbytes;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Only set legacy callbacks - no stateless callbacks */
    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    /* Confirm DTLS 1.2 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_2_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_2_VERSION))
        goto end;

    /* Verify data can be exchanged */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test scenario: Both callbacks set, DTLS 1.2 client.
 *
 * When both callback types are configured, DTLSv1_listen() peeks at the
 * incoming ClientHello to determine the client version. For a DTLS 1.2
 * client (no supported_versions with DTLS 1.3), it uses the legacy
 * HelloVerifyRequest path.
 */
static int test_dtls12_listen_both_cb(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const char msg[] = "Both callbacks DTLS 1.2 test";
    char buf[sizeof(msg)];
    size_t written, readbytes;
    int testresult = 0;

    /* Server supports both DTLS 1.2 and 1.3, client is DTLS 1.2 only */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Restrict client to DTLS 1.2 only */
    if (!TEST_true(SSL_CTX_set_max_proto_version(cctx, DTLS1_2_VERSION)))
        goto end;

    /* Set both legacy and stateless callbacks */
    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);
    SSL_CTX_set_stateless_cookie_generate_cb(sctx, stateless_cookie_gen);
    SSL_CTX_set_stateless_cookie_verify_cb(sctx, stateless_cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    /* Confirm DTLS 1.2 was negotiated (client max was 1.2) */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_2_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_2_VERSION))
        goto end;

    /* Verify data can be exchanged */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test scenario: Only legacy callbacks set, DTLS 1.3 client.
 *
 * When only legacy callbacks are configured, DTLSv1_listen() sets max
 * version to DTLS 1.2. A pure DTLS 1.3 client cannot complete the
 * handshake because the server will not negotiate DTLS 1.3.
 */
static int test_dtls13_listen_legacy_cb_only_fails(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    /* Server and client both want DTLS 1.3 */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Restrict client to DTLS 1.2 only */
    if (!TEST_true(SSL_CTX_set_min_proto_version(cctx, DTLS1_3_VERSION)))
        goto end;

    /* Only set legacy callbacks - no stateless callbacks */
    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Connection should fail because server has only legacy callbacks
     * which forces max version to DTLS 1.2, but client only supports DTLS 1.3
     */
    if (!TEST_false(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test scenario: No callbacks set.
 *
 * When no cookie callbacks are configured, DTLSv1_listen() should fail
 * when trying to generate a cookie.
 */
static int test_dtls_listen_no_cb_fails(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Do NOT set any cookie callbacks */

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /* Connection should fail because no cookie callbacks are set */
    if (!TEST_false(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_DGRAM)
    ADD_ALL_TESTS(dtls_listen_test,
        (int)OSSL_NELEM(testpackets) + (int)OSSL_NELEM(testpackets13));
#ifndef OPENSSL_NO_DTLS1_3
    ADD_TEST(test_dtls13_listen);
    ADD_TEST(test_dtls13_listen_client_dtls13_only);
    ADD_TEST(test_dtls13_listen_stateless_cb_only);
    ADD_TEST(test_dtls12_listen_legacy_cb_only);
    ADD_TEST(test_dtls12_listen_legacy_cb_only_client_supports_dtls13);
    ADD_TEST(test_dtls12_listen_both_cb);
    ADD_TEST(test_dtls13_listen_legacy_cb_only_fails);
    ADD_TEST(test_dtls_listen_no_cb_fails);
#endif
#endif
    return 1;
}
