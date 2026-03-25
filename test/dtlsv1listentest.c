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

/* A DTLSv1.3 ClientHello with a good cookie */
static const unsigned char clienthello13_cookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x55, /* Record Length (0x4E + 7) */
    0x01, /* ClientHello */
    0x00, 0x00, 0x49, /* Message length (0x42 + 7) */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x49, /* Fragment length (0x42 + 7) */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x00, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, /* Cookie */
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

/* A DTLSv1.3 ClientHello with a bad cookie */
static const unsigned char clienthello13_badcookie[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x55, /* Record Length (0x4E + 7) */
    0x01, /* ClientHello */
    0x00, 0x00, 0x49, /* Message length (0x42 + 7) */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x49, /* Fragment length (0x42 + 7) */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x01, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, /* Cookie (first byte wrong) */
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
 * A DTLSv1.3 fragmented ClientHello with the fragment boundary mid-cookie.
 * Fragment stops mid-cookie (before extensions); only msg_len is updated.
 */
static const unsigned char clienthello13_cookie_short[] = {
    0x16, /* Handshake */
    0xFE, 0xFF, /* legacy record version = DTLSv1.0 */
    0x00, 0x00, /* Epoch */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Record sequence number */
    0x00, 0x43, /* Record Length (unchanged - fragment content same) */
    0x01, /* ClientHello */
    0x00, 0x00, 0x49, /* Message length (0x42 + 7 - full message size) */
    0x00, 0x00, /* Message sequence */
    0x00, 0x00, 0x00, /* Fragment offset */
    0x00, 0x00, 0x37, /* Fragment length (unchanged) */
    0xFE, 0xFD, /* legacy_client_version = DTLSv1.2 */
    0xCA, 0x18, 0x9F, 0x76, 0xEC, 0x57, 0xCE, 0xE5, 0xB3, 0xAB, 0x79, 0x90,
    0xAD, 0xAC, 0x6E, 0xD1, 0x58, 0x35, 0x03, 0x97, 0x16, 0x10, 0x82, 0x56,
    0xD8, 0x55, 0xFF, 0xE1, 0x8A, 0xA3, 0x2E, 0xF6, /* Random */
    0x00, /* Session id len */
    0x14, /* Cookie len */
    0x00, 0x01, 0x02, 0x03, 0x04, 005, 0x06, 007, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12 /* Cookie (truncated) */
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
     * DROP == 0 return value, no output
     */
    enum { GOOD,
        VERIFY,
        DROP } outtype;
} tests;

static tests testpackets[9] = {
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

static tests testpackets13[9] = {
    { clienthello13_nocookie, sizeof(clienthello13_nocookie), VERIFY },
    { clienthello13_nocookie_frag, sizeof(clienthello13_nocookie_frag), VERIFY },
    { clienthello_nocookie_short, sizeof(clienthello_nocookie_short), DROP },
    { clienthello13_2ndfrag, sizeof(clienthello13_2ndfrag), DROP },
    { clienthello13_cookie, sizeof(clienthello13_cookie), GOOD },
    { clienthello_cookie_frag, sizeof(clienthello_cookie_frag), GOOD },
    { clienthello13_badcookie, sizeof(clienthello13_badcookie), VERIFY },
    { clienthello13_cookie_short, sizeof(clienthello13_cookie_short), DROP },
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
 * Combined DTLS listen test covering both DTLS 1.2 and DTLS 1.3 packet
 * variants.
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
    if (!TEST_int_ge(ret = DTLSv1_listen(ssl, peer), 0))
        goto err;
    datalen = BIO_get_mem_data(outbio, &data);

    if (tp->outtype == VERIFY) {
        if (!TEST_int_eq(ret, 0)
            || !TEST_mem_eq(data, datalen, verify, sizeof(verify)))
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
#endif

#ifndef OPENSSL_NO_DTLS1_3
/*
 * Verify that a DTLS client completes a full handshake through DTLSv1_listen()
 * and negotiates DTLS 1.3.
 *
 * DTLSv1_listen() uses the legacy DTLS 1.2 HelloVerifyRequest mechanism for
 * the stateless cookie exchange, so the client must allow DTLS 1.2 as a
 * minimum to handle that exchange.  The server is pinned to DTLS 1.3 only,
 * which forces the final negotiated version to be DTLS 1.3.  After the
 * handshake completes we verify that DTLS 1.3 was actually selected and that
 * application data can be exchanged in both directions.
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
     * Client: DTLS 1.0 minimum so it can handle the HelloVerifyRequest from
     * DTLSv1_listen(), but prefers DTLS 1.3 as max — the server will enforce
     * DTLS 1.3 for the actual handshake.
     */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Allow the client to speak DTLS 1.2 only for the cookie exchange */
    if (!TEST_true(SSL_CTX_set_min_proto_version(cctx, DTLS1_VERSION)))
        goto end;

    SSL_CTX_set_cookie_generate_cb(sctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(sctx, cookie_verify);

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
 * Use SSL_stateless with DTLS if you want to send a
 * HelloRetryRequest and then continue with the handshake.
 * DTLSv1_listen only support HelloVerifyRequest, so a pure DTLS 1.3
 * client is not supported with DTLSv1_listen.
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

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Pass listen=1 so that create_bare_ssl_connection() calls
     * Verify DTLSv1_listen does not work with a pure DTLS 1.3 client
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
