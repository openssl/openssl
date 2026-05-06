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

#ifndef OPENSSL_NO_SOCK

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
    0x00, 0x41, /* Record Length (0x3A + 7) */
    0x01, /* ClientHello */
    0x00, 0x00, 0x35, /* Message length (0x2E + 7) */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x35, /* Fragment length (0x2E + 7) */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len */
    0x00, 0x04, /* Ciphersuites len */
    0x13, 0x01, /*  TLS_AES_128_GCM_SHA256 */
    0x13, 0x02, /* TLS_AES_256_GCM_SHA384 */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x07, /* Extensions len */
    0x00, 0x2B, /* supported_versions */
    0x00, 0x03, /* ext data len */
    0x02, /* versions list len */
    0xFE, 0xFC /* DTLSv1.3 */
};

/*
 * First fragment of a DTLSv1.3 ClientHello without a cookie.
 * Fragment stops after cookie len (before extensions); only msg_len is
 * updated to reflect the full message size including extensions.
 */
static const unsigned char clienthello13_nocookie_frag[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x30, /* Record Length (unchanged - fragment content same) */
    0x01, /* ClientHello */
    0x00, 0x00, 0x35, /* Message length (0x2E + 7 - full message size) */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x24, /* Fragment length (unchanged) */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00 /* Cookie len */
};

/* A DTLSv1.3 ClientHello with a good cookie in the TLS cookie extension */
static const unsigned char clienthello13_cookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    /*
     * Record length: fixed fields (2+32+1+1+2+4+1+1) = 44 bytes,
     * plus extensions_len(2) + extensions_data(33) = 35,
     * msg body = 44 + 35 = 79 = 0x4F.
     * record body = handshake hdr(12) + 0x4F = 0x5B.
     */
    0x00, 0x5B, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x4F, /* Message length */
    0x00, 0x01, /* Message sequence (second ClientHello after HRR) */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x4F, /* Fragment length */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len (empty - DTLS 1.3 uses extension) */
    0x00, 0x04, /* Ciphersuites len */
    0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
    0x13, 0x02, /* TLS_AES_256_GCM_SHA384 */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x21, /* Extensions len (33 = supported_versions(7) + cookie(26)) */
    0x00, 0x2B, /* supported_versions */
    0x00, 0x03, /* ext data len */
    0x02, /* versions list len */
    0xFE, 0xFC, /* DTLSv1.3 */
    0x00, 0x2C, /* cookie extension type (44) */
    0x00, 0x16, /* ext data len (22 = 2 + 20) */
    0x00, 0x14, /* cookie len (20) */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13 /* Cookie */
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

/* A DTLSv1.3 ClientHello with a bad cookie in the TLS cookie extension */
static const unsigned char clienthello13_badcookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x5B, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x4F, /* Message length */
    0x00, 0x01, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x4F, /* Fragment length */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len (empty) */
    0x00, 0x04, /* Ciphersuites len */
    0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
    0x13, 0x02, /* TLS_AES_256_GCM_SHA384 */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x21, /* Extensions len (33 = supported_versions(7) + cookie(26)) */
    0x00, 0x2B, /* supported_versions */
    0x00, 0x03, /* ext data len */
    0x02, /* versions list len */
    0xFE, 0xFC, /* DTLSv1.3 */
    0x00, 0x2C, /* cookie extension type (44) */
    0x00, 0x16, /* ext data len (22) */
    0x00, 0x14, /* cookie len (20) */
    0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13 /* Cookie (first byte wrong) */
};

/*
 * A DTLSv1.3 fragmented ClientHello with the fragment boundary mid-cookie
 * extension.  The fragment includes all mandatory fields (with empty legacy
 * cookie) plus the supported_versions extension, the cookie extension type
 * and data-length field, and the inner cookie length field, but only the
 * first 6 of the 20 cookie bytes.
 *
 * Because PACKET_get_length_prefixed_2() for the cookie extension data fails
 * (22 bytes declared but only 8 bytes present), hrr_cookie_len stays 0.
 * dtls13 is 1 (supported_versions was already parsed), so DTLSv1_listen
 * sends a HelloRetryRequest asking the client to retry with a full cookie.
 * Expected: VERIFY_HRR (ret=0, HRR sent).
 *
 * Full message length = 0x4B (same as clienthello13_cookie).
 * Fragment: 2+32+1+1+6+2+9(sv)+2+2+2+6(partial) = 65 = 0x41 bytes.
 * Record body = 12 + 0x41 = 0x4D.
 */
static const unsigned char clienthello13_cookie_short[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x4D, /* Record Length */
    0x01, /* ClientHello */
    0x00, 0x00, 0x4B, /* Message length (full message size) */
    0x00, 0x01, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x41, /* Fragment length (truncated) */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x00, /* Cookie len (empty - DTLS 1.3) */
    0x00, 0x04, /* Ciphersuites len */
    0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
    0x13, 0x02, /* TLS_AES_256_GCM_SHA384 */
    0x01, /* Compression methods len */
    0x00, /* Null compression */
    0x00, 0x23, /* Extensions len (full message extensions len = 35) */
    0x00, 0x2B, /* supported_versions type */
    0x00, 0x03, /* ext data len */
    0x02, /* versions list len */
    0xFE, 0xFC, /* DTLSv1.3 */
    0x00, 0x2C, /* cookie extension type */
    0x00, 0x16, /* cookie ext data len = 22 (declares full 22 bytes) */
    0x00, 0x14, /* inner cookie len = 20 */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05 /* only 6 of 20 cookie bytes (truncated) */
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

/*
 * Expected HelloRetryRequest for a DTLS 1.3 ClientHello that has no cookie.
 *
 * Wire format built by DTLSv1_listen() LISTEN_SEND_HELLO_RETRY_REQUEST:
 *
 * DTLS record header (13 bytes):
 *   0x16            content type = Handshake
 *   0xFE 0xFD       legacy_record_version = DTLS 1.2
 *   0x00 0x00       epoch = 0
 *   0x00..0x00      seq  (6 bytes, echoed from ClientHello = all zeros)
 *   0x00 0x5F       record body length (see below)
 *
 * DTLS handshake header (12 bytes):
 *   0x02            msg_type = ServerHello
 *   0x00 0x00 0x53  msg_length (patched = frag_length = body below)
 *   0x00 0x01       msg_seq = 1
 *   0x00 0x00 0x00  frag_offset = 0
 *   0x00 0x00 0x53  frag_length
 *
 * ServerHello body (0x53 = 83 bytes):
 *   0xFE 0xFD       legacy_version = DTLS 1.2
 *   <32 bytes>      hrrrandom
 *   0x00            legacy_session_id_len = 0
 *   0x13 0x01       cipher = TLS_AES_128_GCM_SHA256
 *   0x00            compression = null
 *   0x00 0x26       extensions_len = 38
 *   -- supported_versions ext (6 bytes) --
 *   0x00 0x2B       type
 *   0x00 0x02       data len
 *   0xFE 0xFC       DTLS 1.3
 *   -- cookie ext (32 bytes) --
 *   0x00 0x2C       type
 *   0x00 0x18       data len = 24  (2 + COOKIE_LEN)
 *   0x00 0x14       inner cookie len = 20
 *   0x00..0x13      20-byte cookie {0x00, 0x01, ..., 0x13}
 *
 * extensions_len = 6 + 32 = 38 = 0x26
 * ServerHello body = 2+32+1+2+1+2+6+32 = 78... let me recount:
 *   legacy_version(2) + random(32) + session_id_len(1) + cipher(2) +
 *   compression(1) + extensions_len(2) + supported_versions(6) + cookie(32)
 *   = 2+32+1+2+1+2+6+32 = 78 = 0x4E ... wait, cookie ext is 2+2+2+20=26 bytes
 *   extensions block = 6 + 26 = 32... no: 6(sv) + 26(cookie) = 32 bytes of
 *   extension data; extensions_len field = 32 = 0x20 ... let's be precise:
 *
 *   supported_versions: type(2)+datalen(2)+version(2) = 6 bytes
 *   cookie ext:         type(2)+datalen(2)+cookielen(2)+cookie(20) = 26 bytes
 *   extensions block total = 6 + 26 = 32 = 0x20
 *   extensions_len field = 0x00 0x20
 *
 * ServerHello body = 2+32+1+2+1+2+32 = 72 = 0x48
 * frag_length = msg_length = 0x48
 * record body = 12 + 0x48 = 0x54
 */
static const unsigned char verify13[] = {
    0x16, /* Handshake */
    0xFE, 0xFD, /* legacy_record_version = DTLS 1.2 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number (echoed) */
    0x00, 0x54, /* Record body length = 12 + 0x48 */
    0x02, /* ServerHello */
    0x00, 0x00, 0x48, /* Message length (patched = frag length) */
    0x00, 0x00, /* msg_seq = 0 */
    0x00, 0x00, 0x00, /* fragment_offset = 0 */
    0x00, 0x00, 0x48, /* fragment_length */
    /* ServerHello body */
    0xFE, 0xFD, /* legacy_version = DTLS 1.2 */
    /* hrrrandom (32 bytes) - SHA-256("HelloRetryRequest") per RFC 8446 */
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    0x00, /* legacy_session_id_len = 0 */
    0x13, 0x01, /* cipher_suite = TLS_AES_128_GCM_SHA256 */
    0x00, /* compression = null */
    0x00, 0x20, /* extensions_len = 32 */
    /* supported_versions extension */
    0x00, 0x2B, /* type = supported_versions (43) */
    0x00, 0x02, /* ext data len */
    0xFE, 0xFC, /* DTLS 1.3 */
    /* cookie extension */
    0x00, 0x2C, /* type = cookie (44) */
    0x00, 0x16, /* ext data len = 22 (2 + COOKIE_LEN) */
    0x00, 0x14, /* inner cookie len = 20 */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13
};

typedef struct {
    const unsigned char *in;
    unsigned int inlen;
    /*
     * GOOD      == positive return value from DTLSv1_listen, no output
     * VERIFY    == 0 return value, HelloVerifyRequest sent  (DTLS <= 1.2)
     * VERIFY_HRR== 0 return value, HelloRetryRequest sent   (DTLS 1.3)
     * DROP      == 0 return value, no output
     * ERR       == -1 return value (error)
     */
    enum { GOOD,
        VERIFY,
        VERIFY_HRR,
        DROP,
        ERR } outtype;
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
    { clienthello13_nocookie_frag, sizeof(clienthello13_nocookie_frag), ERR },
    { clienthello_nocookie_short, sizeof(clienthello_nocookie_short), DROP },
    { clienthello13_2ndfrag, sizeof(clienthello13_2ndfrag), DROP },
    { clienthello13_cookie, sizeof(clienthello13_cookie), GOOD },
    { clienthello_cookie_frag, sizeof(clienthello_cookie_frag), GOOD },
    { clienthello13_badcookie, sizeof(clienthello13_badcookie), VERIFY_HRR },
    { clienthello13_cookie_short, sizeof(clienthello13_cookie_short), ERR },
    { record_short, sizeof(record_short), DROP }
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
 * 10: Test that a fragmented DTLS 1.3 ClientHello without a cookie returns
 *   an error (DTLSv1_listen cannot compute transcript hash for fragments).
 * 11: Test that a truncated DTLS 1.3 ClientHello is dropped by
 *   DTLSv1_listen().
 * 12: Test that a second fragment of a DTLS 1.3 ClientHello is dropped by
 *   DTLSv1_listen() (it cannot reconstruct a full ClientHello from it).
 * 13: Test that a DTLS 1.3 ClientHello with a good TLS cookie extension
 *   is accepted by DTLSv1_listen().
 * 14: Test that a fragmented DTLS 1.2-style ClientHello with a good legacy
 *   cookie passes through the DTLS <= 1.2 path (no supported_versions).
 * 15: Test that a DTLS 1.3 ClientHello with a bad TLS cookie extension
 *   sends a HelloRetryRequest.
 * 16: Test that a DTLS 1.3 ClientHello with a truncated cookie extension
 *   returns an error (DTLSv1_listen cannot compute transcript hash for
 *   fragments).
 * 17: Test that a short record is dropped by DTLSv1_listen().
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
#if defined(OSSL_NO_USABLE_DTLS1_3)
        testresult = TEST_skip("DTLSv1.3 not usable");
        goto end;
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
    }

    SSL_CTX_set_cookie_generate_cb(ctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify);

    /* Create an SSL object and set the BIO */
    if (!TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(outbio = BIO_new(BIO_s_mem())))
        goto err;
    SSL_set0_wbio(ssl, outbio);

    /* Set Non-blocking IO behaviour */
    if (!TEST_ptr(inbio = BIO_new_mem_buf((char *)tp->in, tp->inlen)))
        goto err;
    BIO_set_mem_eof_return(inbio, -1);
    SSL_set0_rbio(ssl, inbio);

    /* Process the incoming packet */
    ret = DTLSv1_listen(ssl, peer);

    if (tp->outtype == ERR) {
        /* Expected error return */
        if (!TEST_int_eq(ret, -1))
            goto err;
    } else {
        if (!TEST_int_ge(ret, 0))
            goto err;
        datalen = BIO_get_mem_data(outbio, &data);

        if (tp->outtype == VERIFY) {
            /* DTLS <= 1.2: expect a HelloVerifyRequest */
            if (!TEST_int_eq(ret, 0)
                || !TEST_mem_eq(data, datalen, verify, sizeof(verify)))
                goto err;
        } else if (tp->outtype == VERIFY_HRR) {
            /* DTLS 1.3: expect a HelloRetryRequest */
            if (!TEST_int_eq(ret, 0)
                || !TEST_mem_eq(data, datalen, verify13, sizeof(verify13)))
                goto err;
        } else if (datalen == 0) {
            if (!TEST_true((ret == 0 && tp->outtype == DROP)
                    || (ret == 1 && tp->outtype == GOOD)))
                goto err;
        } else {
            TEST_info("Test %d: unexpected data output", i);
            goto err;
        }
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
#endif

#ifndef OPENSSL_NO_DTLS1_3
/*
 * Verify that DTLSv1_listen() correctly rejects fragmented DTLS 1.3
 * ClientHellos with SSL_R_FRAGMENTED_CLIENT_HELLO.
 *
 * When a client supports multiple DTLS versions (DTLS 1.0 through 1.3), its
 * ClientHello is larger due to additional cipher suites and extensions. This
 * can cause the ClientHello to exceed the MTU and be fragmented.
 *
 * DTLSv1_listen() is stateless and cannot reassemble fragments. For DTLS 1.3,
 * it also needs to compute a transcript hash over the full ClientHello1 when
 * sending a HelloRetryRequest. Since it cannot access the full message when
 * fragmented, it must reject such ClientHellos.
 *
 * Applications using DTLSv1_listen() with DTLS 1.3 and large key exchanges
 * (e.g., post-quantum ML-KEM) that cause fragmentation must use SSL_accept()
 * directly instead.
 */
static int test_dtls13_listen(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    /*
     * Server: DTLS 1.3 only.
     * Client: DTLS 1.0 minimum - this causes a larger ClientHello with more
     * cipher suites and extensions, which may be fragmented.
     */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Allow the client to speak DTLS 1.0+ - this increases ClientHello size */
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
     * The connection should fail because the ClientHello is fragmented.
     * DTLSv1_listen() cannot handle fragmented DTLS 1.3 ClientHellos because
     * it needs the full message to compute the transcript hash.
     *
     * We expect create_bare_ssl_connection() to fail with SSL_ERROR_SSL,
     * and the error stack should contain SSL_R_FRAGMENTED_CLIENT_HELLO.
     */
    if (!TEST_false(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_SSL, 1, 1)))
        goto end;

    /* Verify the expected error is on the stack */
    if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
            SSL_R_FRAGMENTED_CLIENT_HELLO))
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

#ifndef OPENSSL_NO_SOCK
    ADD_ALL_TESTS(dtls_listen_test,
        (int)OSSL_NELEM(testpackets) + (int)OSSL_NELEM(testpackets13));
#ifndef OPENSSL_NO_DTLS1_3
    ADD_TEST(test_dtls13_listen);
    ADD_TEST(test_dtls13_listen_client_dtls13_only);
#endif
#endif
    return 1;
}
