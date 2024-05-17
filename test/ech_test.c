/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/hpke.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */

/*
 * The command line argument one can provide is the location
 * of test certificates etc, which would be in $TOPDIR/test/certs
 * so if one runs "test/ech_test" from $TOPDIR, then we don't
 * need the command line argument at all.
 */
# define DEF_CERTS_DIR "test/certs"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = NULL;
static BIO *bio_stdout = NULL;
static BIO *bio_null = NULL;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *rootcert = NULL;
static int verbose = 0;

/*
 * ECHConfigList test vectors - the first set are
 * syntactically valid but some have no ECHConfig
 * values.
 */

/*
 * This ECHConfigList has 6 entries with different versions,
 * [13,10,9,13,10,13] - since our runtime no longer supports
 * version 9 or 10, we should see 3 configs loaded.
 */
static const unsigned char echconfig_b64_6_to_3[] =
    "AXn+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS"
    "4Khu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+CQA7AAtleGFtcGxlL"
    "mNvbQAgoyQr+cP8mh42znOp1bjPxpLCBi4A0ftttr8MPXRJPBcAIAAEAAEAAQAA"
    "AAD+DQA6QwAgACB3xsNUtSgipiYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAE"
    "AAQALZXhhbXBsZS5jb20AAP4KADwDACAAIH0BoAdiJCX88gv8nYpGVX5BpGBa9y"
    "T0Pac3Kwx6i8URAAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACDcZIAx7"
    "OcOiQuk90VV7/DO4lFQr5I3Zw9tVbK8MGw1dgAEAAEAAQALZXhhbXBsZS5jb20A"
    "AA==";

/* same as above but binary encoded */
static const unsigned char echconfig_bin_6_to_3[] = {
    0x01, 0x79, 0xfe, 0x0d, 0x00, 0x3a, 0xc5, 0x00,
    0x20, 0x00, 0x20, 0x66, 0xe7, 0x82, 0x92, 0x20,
    0xf5, 0xee, 0xfa, 0x94, 0x2a, 0xda, 0x86, 0x35,
    0xf3, 0x7c, 0x2d, 0xdf, 0x26, 0xf1, 0xec, 0x22,
    0x9b, 0x05, 0x85, 0xf4, 0xa2, 0x03, 0xea, 0xe6,
    0xee, 0x85, 0x7a, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x0a, 0x00, 0x3c, 0xd2, 0x00, 0x20, 0x00,
    0x20, 0x83, 0xfe, 0xd1, 0x0b, 0x74, 0x58, 0x60,
    0x45, 0xdc, 0x7e, 0x5f, 0xcf, 0xc1, 0xee, 0x85,
    0x54, 0x53, 0x08, 0x43, 0x2e, 0x1d, 0x2e, 0x0a,
    0x86, 0xee, 0xa2, 0x6d, 0x1f, 0xfa, 0xa8, 0x44,
    0x78, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x09, 0x00, 0x3b, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x20, 0xa3, 0x24, 0x2b, 0xf9, 0xc3,
    0xfc, 0x9a, 0x1e, 0x36, 0xce, 0x73, 0xa9, 0xd5,
    0xb8, 0xcf, 0xc6, 0x92, 0xc2, 0x06, 0x2e, 0x00,
    0xd1, 0xfb, 0x6d, 0xb6, 0xbf, 0x0c, 0x3d, 0x74,
    0x49, 0x3c, 0x17, 0x00, 0x20, 0x00, 0x04, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe,
    0x0d, 0x00, 0x3a, 0x43, 0x00, 0x20, 0x00, 0x20,
    0x77, 0xc6, 0xc3, 0x54, 0xb5, 0x28, 0x22, 0xa6,
    0x26, 0x29, 0x52, 0x45, 0xba, 0x39, 0x2a, 0xeb,
    0x83, 0x4d, 0xc8, 0xe3, 0x32, 0x04, 0x34, 0xc1,
    0x5a, 0xd0, 0x94, 0x76, 0xf8, 0xc9, 0xb5, 0x5b,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0xfe, 0x0a, 0x00,
    0x3c, 0x03, 0x00, 0x20, 0x00, 0x20, 0x7d, 0x01,
    0xa0, 0x07, 0x62, 0x24, 0x25, 0xfc, 0xf2, 0x0b,
    0xfc, 0x9d, 0x8a, 0x46, 0x55, 0x7e, 0x41, 0xa4,
    0x60, 0x5a, 0xf7, 0x24, 0xf4, 0x3d, 0xa7, 0x37,
    0x2b, 0x0c, 0x7a, 0x8b, 0xc5, 0x11, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0xfe, 0x0d, 0x00,
    0x3a, 0x43, 0x00, 0x20, 0x00, 0x20, 0xdc, 0x64,
    0x80, 0x31, 0xec, 0xe7, 0x0e, 0x89, 0x0b, 0xa4,
    0xf7, 0x45, 0x55, 0xef, 0xf0, 0xce, 0xe2, 0x51,
    0x50, 0xaf, 0x92, 0x37, 0x67, 0x0f, 0x6d, 0x55,
    0xb2, 0xbc, 0x30, 0x6c, 0x35, 0x76, 0x00, 0x04,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x00
};

/* output from ``dig +short https defo.ie`` */
static const unsigned char echconfig_dig_defo[] =
    "1 . ech=AID+DQA88wAgACDhaXQ8S0pHHQ+bwApOPPDjai"
    "YofLs24QPmmOLP8wHtKwAEAAEAAQANY292ZXIuZGVmby5p"
    "ZQAA/g0APNsAIAAgcTC7pC/ZyxhymoL1p1oAdxfvVEgRji"
    "68mhDE4vDZOzUABAABAAEADWNvdmVyLmRlZm8uaWUAAA==";

/* output from ``dig +short https crypto.cloudflare.com`` */
static const unsigned char echconfig_dig_cf[] =
    "1 . alpn=\"http/1.1,h2\" ipv4hint=162.159.137.85"
    ",162.159.138.85 ech=AEX+DQBBCAAgACBsFeUbsAWR7x"
    "WL1aB6P28ppSsj+joHhNUtj2qtwYh+NAAEAAEAAQASY2xv"
    "dWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7:"
    ":a29f:8955,2606:4700:7::a29f:8a55";

/*
 * output from ``dig +short https _11413._https.draft-13.esni.defo.ie``
 * One that's not from port-443 so has a targetName
 */
static const unsigned char echconfig_dig_d13[] =
    "1 draft-13.esni.defo.ie. ech=AMD+DQA8iwAgACAa9ok"
    "y0hXrPm4WPTTxGOo4COT3xewntwtHiGRm3Bq0dAAEAAEAAQA"
    "NY292ZXIuZGVmby5pZQAA/g0APJgAIAAg8wdx3+O2c0zcnPC"
    "zcgSZ4dHbIZMiYEYUD0XVx3ufpEMABAABAAEADWNvdmVyLmR"
    "lZm8uaWUAAP4NADwrACAAIG1DllvsgbEMrVtlfVU17EJog/G"
    "aAjzTHUad6Cbh+X0wAAQAAQABAA1jb3Zlci5kZWZvLmllAAA=";

/*
 * check ASCII-hex handling via output from
 * ``dig +short +unknownformat https _11413._https.draft-13.esni.defo.ie``
 */
static const unsigned char echconfig_dig_u_d13[] =
    "\\# 223 00010864726166742D31330465736E6904646566"
    "6F02696500000500 C200C0FE0D003C8B002000201AF689"
    "32D215EB3E6E163D34F118EA38 08E4F7C5EC27B70B4788"
    "6466DC1AB474000400010001000D636F7665 722E646566"
    "6F2E69650000FE0D003C9800200020F30771DFE3B6734C "
    "DC9CF0B3720499E1D1DB2193226046140F45D5C77B9FA44"
    "300040001 0001000D636F7665722E6465666F2E6965000"
    "0FE0D003C2B00200020 6D43965BEC81B10CAD5B657D553"
    "5EC426883F19A023CD31D469DE826 E1F97D30000400010"
    "001000D636F7665722E6465666F2E69650000";

/*
 * check DNS wire format handling of output from
 * ``dig +short +unknownformat https _11413._https.draft-13.esni.defo.ie``
 */
static const unsigned char echconfig_dns_wire_d13[] = {
    0x00, 0x01, 0x08, 0x64, 0x72, 0x61, 0x66, 0x74,
    0x2D, 0x31, 0x33, 0x04, 0x65, 0x73, 0x6E, 0x69,
    0x04, 0x64, 0x65, 0x66, 0x6F, 0x02, 0x69, 0x65,
    0x00, 0x00, 0x05, 0x00, 0xC2, 0x00, 0xC0, 0xFE,
    0x0D, 0x00, 0x3C, 0x8B, 0x00, 0x20, 0x00, 0x20,
    0x1A, 0xF6, 0x89, 0x32, 0xD2, 0x15, 0xEB, 0x3E,
    0x6E, 0x16, 0x3D, 0x34, 0xF1, 0x18, 0xEA, 0x38,
    0x08, 0xE4, 0xF7, 0xC5, 0xEC, 0x27, 0xB7, 0x0B,
    0x47, 0x88, 0x64, 0x66, 0xDC, 0x1A, 0xB4, 0x74,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0D,
    0x63, 0x6F, 0x76, 0x65, 0x72, 0x2E, 0x64, 0x65,
    0x66, 0x6F, 0x2E, 0x69, 0x65, 0x00, 0x00, 0xFE,
    0x0D, 0x00, 0x3C, 0x98, 0x00, 0x20, 0x00, 0x20,
    0xF3, 0x07, 0x71, 0xDF, 0xE3, 0xB6, 0x73, 0x4C,
    0xDC, 0x9C, 0xF0, 0xB3, 0x72, 0x04, 0x99, 0xE1,
    0xD1, 0xDB, 0x21, 0x93, 0x22, 0x60, 0x46, 0x14,
    0x0F, 0x45, 0xD5, 0xC7, 0x7B, 0x9F, 0xA4, 0x43,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0D,
    0x63, 0x6F, 0x76, 0x65, 0x72, 0x2E, 0x64, 0x65,
    0x66, 0x6F, 0x2E, 0x69, 0x65, 0x00, 0x00, 0xFE,
    0x0D, 0x00, 0x3C, 0x2B, 0x00, 0x20, 0x00, 0x20,
    0x6D, 0x43, 0x96, 0x5B, 0xEC, 0x81, 0xB1, 0x0C,
    0xAD, 0x5B, 0x65, 0x7D, 0x55, 0x35, 0xEC, 0x42,
    0x68, 0x83, 0xF1, 0x9A, 0x02, 0x3C, 0xD3, 0x1D,
    0x46, 0x9D, 0xE8, 0x26, 0xE1, 0xF9, 0x7D, 0x30,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0D,
    0x63, 0x6F, 0x76, 0x65, 0x72, 0x2E, 0x64, 0x65,
    0x66, 0x6F, 0x2E, 0x69, 0x65, 0x00, 0x00
};

/*
 * check DNS wire format handling of output from
 * ``dig +short +unknownformat https defo.ie``
 */
static const unsigned char echconfig_dns_wire_defo[] = {
    0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x04, 0xD5,
    0x6C, 0x6C, 0x65, 0x00, 0x05, 0x00, 0x42, 0x00,
    0x40, 0xFE, 0x0D, 0x00, 0x3C, 0xD4, 0x00, 0x20,
    0x00, 0x20, 0x33, 0x80, 0x56, 0xD5, 0x44, 0xF3,
    0x3C, 0x04, 0x74, 0xFE, 0xD8, 0x08, 0xC3, 0x8C,
    0x96, 0x1D, 0xE9, 0x0C, 0xD6, 0x20, 0x1E, 0xC2,
    0xA1, 0x5E, 0xFE, 0xB6, 0x9B, 0x25, 0x24, 0x82,
    0xC2, 0x6B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x0D, 0x63, 0x6F, 0x76, 0x65, 0x72, 0x2E,
    0x64, 0x65, 0x66, 0x6F, 0x2E, 0x69, 0x65, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x10, 0x2A, 0x00, 0xC6,
    0xC0, 0x00, 0x00, 0x01, 0x16, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10
};

/*
 * output from ``dig +short https defo.ie``  (2 ECHConfigs)
 * catenated ``dig +short https crypto.cloudflare.com``
 * which produces one more ECHConfig, for a total of 3
 */
static const unsigned char echconfig_dig_multi[] =
    "1 . ech=AID+DQA88wAgACDhaXQ8S0pHHQ+bwApOPPDjai"
    "YofLs24QPmmOLP8wHtKwAEAAEAAQANY292ZXIuZGVmby5p"
    "ZQAA/g0APNsAIAAgcTC7pC/ZyxhymoL1p1oAdxfvVEgRji"
    "68mhDE4vDZOzUABAABAAEADWNvdmVyLmRlZm8uaWUAAA==\n"
    "1 . alpn=\"http/1.1,h2\" ipv4hint=162.159.137.85"
    ",162.159.138.85 ech=AEX+DQBBCAAgACBsFeUbsAWR7x"
    "WL1aB6P28ppSsj+joHhNUtj2qtwYh+NAAEAAEAAQASY2xv"
    "dWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7:"
    ":a29f:8955,2606:4700:7::a29f:8a55";

/*
 * format used by echcli.sh test script, ascii-hex
 * grabbed using dig unknown format and tidied
 * up by removing spaces
 */
static const unsigned char echconfig_echcli[] =
    "0001000001000C08687474702F312E3102683200040008A"
    "29F8955A29F8A55000500470045FE0D00410F0020002020"
    "52D8F5B5FF684DC1009FF14AADE169B251D1F3317C81CA4"
    "7ED24CEB08F4D040004000100010012636C6F7564666C61"
    "72652D6563682E636F6D000000060020260647000007000"
    "000000000A29F8955260647000007000000000000A29F8A"
    "55";

/*
 * an HTTPS RR with no ech, e.g. acquired via:
 * ``dig +short https rte.ie``
 */
static const unsigned char echconfig_no_ech[] =
    "1 . alpn=\"h3,h3-29,h2\" ipv4hint=104.18.142.17,1"
    "04.18.143.17 ipv6hint=2606:4700::6812:8e11,2606"
    ":4700::6812:8f11";

/*
 * An ECHConflgList with 2 ECHConfig values that are both
 * of the wrong version. The versions here are 0xfe03 (we
 * currently support only 0xfe0d)
 */
static const unsigned char echconfig_bin_wrong_ver[] = {
    0x00, 0x80, 0xfe, 0x03, 0x00, 0x3c, 0x00, 0x00,
    0x20, 0x00, 0x20, 0x71, 0xa5, 0xe0, 0xb4, 0x6d,
    0xdf, 0xa4, 0xda, 0xed, 0x69, 0xa5, 0xc7, 0x8b,
    0x9d, 0xa5, 0x13, 0x0c, 0x36, 0x83, 0x7a, 0x03,
    0x72, 0x1d, 0xf6, 0x1e, 0xc5, 0x83, 0x1a, 0x11,
    0x73, 0xce, 0x2d, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0d, 0x70, 0x61, 0x72, 0x74, 0x31,
    0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x00, 0x00, 0xfe, 0x03, 0x00, 0x3c, 0x00, 0x00,
    0x20, 0x00, 0x20, 0x69, 0x88, 0xfd, 0x8f, 0xc9,
    0x0b, 0xb7, 0x2d, 0x96, 0x6d, 0xe0, 0x22, 0xf0,
    0xc8, 0x1b, 0x62, 0x2b, 0x1c, 0x94, 0x96, 0xad,
    0xef, 0x55, 0xdb, 0x9f, 0xeb, 0x0d, 0xa1, 0x4b,
    0x0c, 0xd7, 0x36, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0d, 0x70, 0x61, 0x72, 0x74, 0x32,
    0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x00, 0x00
};

/*
 * An ascii-hex ECHConfigList with one ECHConfig
 */
static const unsigned char echconfig_ah[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d0000";

/*
 * An ascii-hex ECHConfigList with one ECHConfig
 * but of the wrong version
 */
static const unsigned char echconfig_ah_bad_ver[] =
    "003efeff003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d0000";

/*
 * An ascii-hex ECHConfigList with one ECHConfig
 * with an all-zero public value.
 * This should be ok, for 25519, but hey, just in case:-)
 */
static const unsigned char echconfig_ah_zero[] =
    "003efe0d003abb002000200000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000004000100"
    "01000b6578616d706c652e636f6d0000";

/*
 * The next set of samples are syntactically invalid
 * Proper fuzzing is still needed but no harm having
 * these too. Generally these are bad version of
 * echconfig_ah with some octet(s) replaced by 0xFF
 * values. Other hex letters are lowercase so you
 * can find the altered octet(s).
 */

/* wrong oveall length (replacing 0x3e with 0xFF) */
static const unsigned char bad_echconfig_olen[] =
    "00FFfe0d003abb002000FF62c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d0000";

/* wrong ECHConfig inner length (replacing 0x3a with 0xFF) */
static const unsigned char bad_echconfig_ilen[] =
    "003efe0d00FFbb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d0000";

/* wrong length for public key (replaced 0x20 with 0xFF) */
static const unsigned char bad_echconfig_pklen[] =
    "003efe0d003abb002000FF62c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d0000";

/* wrong length for ciphersuites (replaced 0x04 with 0xFF) */
static const unsigned char bad_echconfig_cslen[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c00FF000100"
    "01000b6578616d706c652e636f6d0000";

/* wrong length for public name (replaced 0x0b with 0xFF) */
static const unsigned char bad_echconfig_pnlen[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "0100FF6578616d706c652e636f6d0000";

/* non-zero extension length (0xFF at end) but no extension value */
static const unsigned char bad_echconfig_extlen[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d00FF";

/*
 * The next set have bad kem, kdf or aead values - this time with
 * 0xAA as the replacement value
 */

/* wrong KEM ID (replaced 0x20 with 0xAA) */
static const unsigned char bad_echconfig_kemid[] =
    "003efe0d003abb00AA002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "01000b6578616d706c652e636f6d0000";

/* wrong KDF ID (replaced 0x01 with 0xAA) */
static const unsigned char bad_echconfig_kdfid[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c000400AA00"
    "01000b6578616d706c652e636f6d0000";

/* wrong AEAD ID (replaced 0x01 with 0xAA) */
static const unsigned char bad_echconfig_aeadid[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c0004000100"
    "AA000b6578616d706c652e636f6d0000";

/*
 * sorta wrong AEAD ID; replaced 0x0001 with 0xFFFF
 * which is the "export only" pseudo-aead-id - that
 * should not work in our test, same as the others,
 * but worth a specific test, as it'll fail in a
 * different manner
 */
static const unsigned char bad_echconfig_aeadid_ff[] =
    "003efe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c00040001FF"
    "FF000b6578616d706c652e636f6d0000";

/*
 * An ECHConfigList with a bad ECHConfig
 * (aead is 0xFFFF), followed by a good
 * one.
 */
static const unsigned char echconfig_bad_then_good[] =
    "007cfe0d003abb0020002062c7607bf2"
    "c5fe1108446f132ca4339cf19df1552e"
    "5a42960fd02c697360163c00040001FF"
    "FF000b6578616d706c652e636f6d0000"
    "fe0d003abb0020002062c7607bf2c5fe"
    "1108446f132ca4339cf19df1552e5a42"
    "960fd02c697360163c00040001000100"
    "0b6578616d706c652e636f6d0000";

/*
 * An ECHConfigList produced by fuzzer. Unclear so far
 * what's up.
 */
static const unsigned char echconfig_bad_fuzz1[] =
    "AD7+DQA6uAAgACAogff+HZbirYdQCfXI"
    "01GBPP8AEKYyK/D/0DoeXD84fgAQAAEA"
    "AQgLZXhhbUNwbGUuYwYAAAAAQwA=";

# ifndef __STRICT_ANSI__
/*
 * output from ``dig +short https defo.ie``  (2 ECHConfigs)
 * catenated ``dig +short https crypto.cloudflare.com``
 * which produces one more ECHConfig, then plus another
 * that has one good and one bad ECH (similar to
 * echconfig_bad_then_good but with aead ID of 0x1401)
 * which should give us 4 in total
 *
 * -Werror=overlength-strings and -pedantic cause a
 *  problem here in CI builds, so we'll omit this
 *  test in that case, which is ok - if it passes other
 *  tests, we're good.
 */
static const unsigned char echconfig_dig_multi_3[] =
    "1 . ech=AID+DQA88wAgACDhaXQ8S0pHHQ+bwApOPPDjai"
    "YofLs24QPmmOLP8wHtKwAEAAEAAQANY292ZXIuZGVmby5p"
    "ZQAA/g0APNsAIAAgcTC7pC/ZyxhymoL1p1oAdxfvVEgRji"
    "68mhDE4vDZOzUABAABAAEADWNvdmVyLmRlZm8uaWUAAA==\n"
    "1 . alpn=\"http/1.1,h2\" ipv4hint=162.159.137.85"
    ",162.159.138.85 ech=AEX+DQBBCAAgACBsFeUbsAWR7x"
    "WL1aB6P28ppSsj+joHhNUtj2qtwYh+NAAEAAEAAQASY2xv"
    "dWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7:"
    ":a29f:8955,2606:4700:7::a29f:8a55\n"
    "1 . ech=AHz+DQA6uwAgACBix2B78sX+EQhEbxMspDOc8Z"
    "3xVS5aQpYP0Cxpc2AWPAAEFAEAAQALZXhhbXBsZS5jb20A"
    "AP4NADq7ACAAIGLHYHvyxf4RCERvEyykM5zxnfFVLlpClg"
    "/QLGlzYBY8AAQAAQABAAtleGFtcGxlLmNvbQAA";
# endif

/*
 * A struct to tie the above together for tests. Note that
 * the encoded_len should be "sizeof(x) - 1" if the encoding
 * is a string encoding, but just "sizeof(x)" if we're dealing
 * with a binary encoding.
 */
typedef struct {
    const unsigned char *encoded; /* encoded ECHConfigList */
    size_t encoded_len; /* the size of the above */
    int num_expected; /* number of ECHConfig values we expect to decode */
    int rv_expected; /* expected return value from call */
} TEST_ECHCONFIG;

static TEST_ECHCONFIG test_echconfigs[] = {
    { echconfig_b64_6_to_3, sizeof(echconfig_b64_6_to_3) - 1, 3, 1 },
    { echconfig_bin_6_to_3, sizeof(echconfig_bin_6_to_3), 3, 1 },
    { echconfig_dig_defo, sizeof(echconfig_dig_defo) - 1, 2, 1 },
    { echconfig_dig_cf, sizeof(echconfig_dig_cf) - 1, 1, 1 },
    { echconfig_dig_d13, sizeof(echconfig_dig_d13) - 1, 3, 1 },
    { echconfig_dig_u_d13, sizeof(echconfig_dig_u_d13) - 1, 3, 1 },
    { echconfig_dns_wire_d13, sizeof(echconfig_dns_wire_d13), 3, 1 },
    { echconfig_dns_wire_defo, sizeof(echconfig_dns_wire_defo), 1, 1 },
    { echconfig_dig_multi, sizeof(echconfig_dig_multi) - 1, 3, 1 },
    { echconfig_echcli, sizeof(echconfig_echcli) - 1, 1, 1 },
    { echconfig_no_ech, sizeof(echconfig_no_ech) - 1, 0, 1 },
    { echconfig_bin_wrong_ver, sizeof(echconfig_bin_wrong_ver), 0, 1 },
    { echconfig_ah, sizeof(echconfig_ah) -1, 1, 1 },
    { echconfig_ah_bad_ver, sizeof(echconfig_ah_bad_ver) -1, 0, 0 },
    { echconfig_ah_zero, sizeof(echconfig_ah_zero) - 1, 1, 1 },
    { bad_echconfig_olen, sizeof(bad_echconfig_olen) -1, 0, 0 },
    { bad_echconfig_ilen, sizeof(bad_echconfig_ilen) -1, 0, 0 },
    { bad_echconfig_pklen, sizeof(bad_echconfig_pklen) -1, 0, 0 },
    { bad_echconfig_cslen, sizeof(bad_echconfig_cslen) -1, 0, 0 },
    { bad_echconfig_pnlen, sizeof(bad_echconfig_pnlen) -1, 0, 0 },
    { bad_echconfig_extlen, sizeof(bad_echconfig_extlen) -1, 0, 0 },
    { bad_echconfig_kemid, sizeof(bad_echconfig_kemid) -1, 0, 0 },
    { bad_echconfig_kdfid, sizeof(bad_echconfig_kdfid) -1, 0, 0 },
    { bad_echconfig_aeadid, sizeof(bad_echconfig_aeadid) -1, 0, 0 },
    { bad_echconfig_aeadid_ff, sizeof(bad_echconfig_aeadid_ff) - 1, 0, 0 },
    { echconfig_bad_then_good, sizeof(echconfig_bad_then_good) - 1, 1, 1 },
    { echconfig_bad_fuzz1, sizeof(echconfig_bad_fuzz1) - 1, 0, 0 },
# ifndef __STRICT_ANSI__
    { echconfig_dig_multi_3, sizeof(echconfig_dig_multi_3) - 1, 4, 1 },
# endif
};

/* string from which we construct varieties of HPKE suite */
static const char *kem_str_list[] = {
    "P-256", "P-384", "P-521", "x25519", "x448",
};
static const char *kdf_str_list[] = {
    "hkdf-sha256", "hkdf-sha384", "hkdf-sha512",
};
static const char *aead_str_list[] = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
};

/*
 * return the bas64 encoded ECHConfigList from an ECH PEM file
 *
 * note - this isn't really needed as an offical API because
 * real clients will use DNS or scripting clients who need
 * this can do it easier with shell commands
 *
 * the caller should free the returned string
 */
static char *echconfiglist_from_PEM(const char *echkeyfile)
{
    BIO *in = NULL;
    char *ecl_string = NULL;
    char lnbuf[OSSL_ECH_MAX_LINELEN];
    int readbytes = 0;

    if (!TEST_ptr(in = BIO_new(BIO_s_file()))
        || !TEST_int_ge(BIO_read_filename(in, echkeyfile), 0))
        goto out;
    /* read 4 lines before the one we want */
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    ecl_string = OPENSSL_malloc(readbytes + 1);
    if (ecl_string == NULL)
        goto out;
    memcpy(ecl_string, lnbuf, readbytes);
    /* zap any '\n' or '\r' at the end if present */
    while (readbytes >= 0
           && (ecl_string[readbytes - 1] == '\n'
               || ecl_string[readbytes - 1] == '\r')) {
        ecl_string[readbytes - 1] = '\0';
        readbytes--;
    }
    if (readbytes == 0)
        goto out;
    BIO_free_all(in);
    return ecl_string;
out:
    BIO_free_all(in);
    return NULL;
}

/*
 * The define/vars below and the 3 callback functions are modified
 * from test/sslapitest.c
 */
# define TEST_EXT_TYPE1  0xffab /* custom ext type 1: has 1 octet payload */
# define TEST_EXT_TYPE2  0xffcd /* custom ext type 2: no payload */

static int new_add_cb(SSL *s, unsigned int ext_type, unsigned int context,
                      const unsigned char **out, size_t *outlen, X509 *x,
                      size_t chainidx, int *al, void *add_arg)
{
    int *server = (int *)add_arg;
    unsigned char *data;

    if (*server != SSL_is_server(s)
            || (data = OPENSSL_malloc(sizeof(*data))) == NULL)
        return -1;

    if (ext_type == TEST_EXT_TYPE1) {
        *data = 1;
        *out = data;
        *outlen = sizeof(*data);
    } else {
        OPENSSL_free(data);
        *out = NULL;
        *outlen = 0;
    }
    return 1;
}

static void new_free_cb(SSL *s, unsigned int ext_type, unsigned int context,
                        const unsigned char *out, void *add_arg)
{
    OPENSSL_free((unsigned char *)out);
}

static int new_parse_cb(SSL *s, unsigned int ext_type, unsigned int context,
                        const unsigned char *in, size_t inlen, X509 *x,
                        size_t chainidx, int *al, void *parse_arg)
{
    int *server = (int *)parse_arg;

    if (*server != SSL_is_server(s)
            || inlen != sizeof(char) || *in != 1)
        return -1;

    return 1;
}

/* various echconfig handling calls */
static int basic_echconfig(int idx)
{
    int res = 1;
    unsigned char echconfig[400];
    size_t echconfiglen = sizeof(echconfig);
    unsigned char priv[200];
    size_t privlen = sizeof(priv);
    uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
    uint16_t max_name_length = 0;
    char *public_name = "example.com";
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char *extvals = NULL;
    unsigned char badexts[8000];
    size_t extlen = 0;
    SSL_CTX *ctx  = NULL;
    SSL *ssl = NULL;
    OSSL_ECH_INFO *details = NULL;
    int num_dets = 0;

    /* test verious dodgy key gens */
    if (!TEST_false(OSSL_ech_make_echconfig(NULL, NULL,
                                            NULL, NULL,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = 80; /* too short */
    privlen = sizeof(priv);
    if (!TEST_false(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = 10; /* too short */
    if (TEST_true(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                          priv, &privlen,
                                          ech_version, max_name_length,
                                          public_name, hpke_suite,
                                          extvals, extlen)))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = sizeof(priv);
    /* dodgy KEM */
    hpke_suite.kem_id = 0xbad;
    if (!TEST_false(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = sizeof(priv);
    hpke_suite.kem_id = OSSL_HPKE_KEM_ID_X25519;
    /* bad version */
    if (!TEST_false(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            0xbad, max_name_length,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    /* bad max name length */
    if (!TEST_false(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, 1024,
                                            public_name, hpke_suite,
                                            extvals, extlen)))
        goto err;
    /* bad extensions */
    memset(badexts, 0xAA, sizeof(badexts));
    if (!TEST_false(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                            priv, &privlen,
                                            ech_version, 1024,
                                            public_name, hpke_suite,
                                            badexts, sizeof(badexts))))
        goto err;
    echconfiglen = sizeof(echconfig);
    privlen = sizeof(priv);

    /* now a good key gen */
    if (!TEST_true(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                           priv, &privlen,
                                           ech_version, max_name_length,
                                           public_name, hpke_suite,
                                           extvals, extlen)))
        goto err;
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method())))
        goto err;
    /* add that to ctx to start */
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(ctx, echconfig, echconfiglen)))
        goto err;
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    /* repeat add that to ssl to make 2 */
    if (!TEST_true(SSL_ech_set1_echconfig(ssl, echconfig, echconfiglen)))
        goto err;
    /* add a 2nd time for fun, works even if silly */
    if (!TEST_true(SSL_ech_set1_echconfig(ssl, echconfig, echconfiglen)))
        goto err;
    if (!TEST_true(SSL_ech_get_info(ssl, &details, &num_dets)))
        goto err;
    if (!TEST_int_eq(num_dets, 3))
        goto err;
    /* we should have 3 sets of details */
    if (verbose) {
        if (!TEST_true(OSSL_ECH_INFO_print(bio_stdout, details, num_dets)))
            goto err;
    } else {
        if (!TEST_true(OSSL_ECH_INFO_print(bio_null, details, num_dets)))
            goto err;
    }
    /* reduce to one */
    if (!TEST_true(SSL_ech_reduce(ssl, 1)))
        goto err;
    OSSL_ECH_INFO_free(details, num_dets);
    details = NULL;
    if (!TEST_true(SSL_ech_get_info(ssl, &details, &num_dets)))
        goto err;
    /* we should only have 1 sets of details left */
    if (!TEST_int_eq(num_dets, 1))
        goto err;
    res = 1;
err:
    OSSL_ECH_INFO_free(details, num_dets);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return res;
}

static int c_test_cb_called = 0;
static int s_test_cb_called = 0;

static unsigned int c_test_cb(SSL *s, const char *str)
{
    c_test_cb_called = 1;
    return 1;
}

static unsigned int s_test_cb(SSL *s, const char *str)
{
    s_test_cb_called = 1;
    return 1;
}

/* test a roundtrip with an ECHConfig that has extensions */
static int extended_echconfig(int idx)
{
    int res = 0;
    char *echkeyfile = NULL;
    char *echconfig = NULL;
    size_t echconfiglen = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int clientstatus, serverstatus;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;

    if (idx == 0) {
        /* check we barf on a mandatory extension */
        echkeyfile = test_mk_file_path(certsdir, "echwithmand.pem");
        if (!TEST_ptr(echkeyfile))
            goto end;
        echconfig = echconfiglist_from_PEM(echkeyfile);
        if (!TEST_ptr(echconfig))
            goto end;
        echconfiglen = strlen(echconfig);
        if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                           TLS_client_method(),
                                           TLS1_3_VERSION, TLS1_3_VERSION,
                                           &sctx, &cctx, cert, privkey)))
            goto end;
        if (!TEST_false(SSL_CTX_ech_set1_echconfig(cctx,
                                                   (unsigned char *)echconfig,
                                                   echconfiglen)))
            goto end;
        res = 1;
        goto end;
    }

    /*
     * read our pre-cooked ECH PEM file that contains extensions
     * in this case we have 3 extensions:
     * type, len, value
     * 0x0fca, 0, 0
     * 0x0fcb, 12, "hello world"
     * 0x0fcc, 0x1c7 (455), a small PNG file
     * total exts length: 0x1df (479)
     *
     * overall length of our ECHConfigList is 0x21d (541)
     *
     * Note that the extensions are only stored, no action is
     * taken with 'em as they're meaningless for now (there
     * not being any well-defined ECH extensions so far)
     */
    echkeyfile = test_mk_file_path(certsdir, "echwithexts.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    echconfiglen = strlen(echconfig);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    SSL_CTX_ech_set_callback(sctx, s_test_cb);
    SSL_CTX_ech_set_callback(cctx, c_test_cb);
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("extended cfg: server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("extended cfg: client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* check callbacks got called */
    if (!TEST_int_eq(c_test_cb_called, 1))
        goto end;
    c_test_cb_called = 0; /* in case we iterate */
    if (!TEST_int_eq(s_test_cb_called, 1))
        goto end;
    s_test_cb_called = 0;
    /* all good */
    res = 1;
end:
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test a basic roundtrip with ECH, with a PEM file input */
static int ech_roundtrip_test(int idx)
{
    int res = 0;
    char *echkeyfile = NULL;
    char *echconfig = NULL;
    size_t echconfiglen = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int clientstatus, serverstatus;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    echconfiglen = strlen(echconfig);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("ech_roundtrip_test: server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("ech_roundtrip_test: client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* all good */
    res = 1;
end:
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test a basic roundtrip with ECH, with a wrong public key */
static int ech_wrong_pub_test(int idx)
{
    int res = 0;
    char *echkeyfile = NULL;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int clientstatus, serverstatus;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    unsigned char badconfig[400];
    size_t badconfiglen = sizeof(badconfig);
    unsigned char badpriv[200];
    size_t badprivlen = sizeof(badpriv);
    uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    int err = 0, connrv = 0, err_reason = 0;
    unsigned char *retryconfig = NULL;
    size_t retryconfiglen = 0;
    char *good_public_name = "front.server.example";
    char *bad_public_name = "bogus.example";
    char *public_name = good_public_name;
    X509_STORE *vfy = NULL;
    int cver;
    int exp_conn_err = SSL_R_ECH_REQUIRED;

    /* for these tests we want to chain to our root */
    vfy = X509_STORE_new();
    if (vfy == NULL)
        goto end;
    if (rootcert != NULL && !X509_STORE_load_file(vfy, rootcert))
        goto end;

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "newechconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set1_verify_cert_store(cctx, vfy);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    if (idx == 2)
        public_name = bad_public_name;
    if (!TEST_true(OSSL_ech_make_echconfig(badconfig, &badconfiglen,
                                           badpriv, &badprivlen,
                                           ech_version, 0, public_name,
                                           hpke_suite, NULL, 0)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, badconfig,
                                              badconfiglen)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    /* tee up getting the right error when a bad name is used */
    if (idx == 2) {
        if (SSL_add1_host(clientssl, public_name) != 1)
            goto end;
    }
    /* trigger HRR 2nd time */
    if (idx == 1 && !TEST_true(SSL_set1_groups_list(serverssl, "P-384")))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "back.server.example")))
        goto end;
    connrv = create_ssl_connection(serverssl, clientssl, SSL_ERROR_SSL);
    if (!TEST_int_eq(connrv, 0))
        goto end;
    if (idx == 2)
        exp_conn_err = SSL_R_CERTIFICATE_VERIFY_FAILED;
    if (connrv == 0) {
        do {
            err = ERR_get_error();
            if (err == 0) {
                TEST_error("ECH wrong pub: Unexpected error");
                goto end;
            }
            err_reason = ERR_GET_REASON(err);
            if (verbose)
                TEST_info("Error reason: %d", err_reason);
        } while (err_reason != exp_conn_err);
    }
    if (!TEST_true(SSL_ech_get_retry_config(clientssl, &retryconfig,
                                            &retryconfiglen))
        || !TEST_ptr(retryconfig)
        || !TEST_int_ne(retryconfiglen, 0))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("ech_wrong_pub_test: server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_GREASE))
        goto end;
    cver = SSL_get_verify_result(clientssl);
    if (cver != X509_V_OK) {
        TEST_info("ech_wrong_pub_test: x509 error: %d", cver);
    }
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("ech_wrong_pub_test: client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (idx != 2
        && !TEST_int_eq(clientstatus, SSL_ECH_STATUS_FAILED_ECH))
        goto end;
    if (idx == 2
        && !TEST_int_eq(clientstatus, SSL_ECH_STATUS_FAILED_ECH_BAD_NAME))
        goto end;
    /* all good */
    res = 1;
end:
    X509_STORE_free(vfy);
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    OPENSSL_free(retryconfig);
    OPENSSL_free(echkeyfile);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test that ECH doesn't work with a TLS1.2 connection */
static int tls_version_test(void)
{
    int res = 0;
    unsigned char echconfig[400];
    size_t echconfiglen = sizeof(echconfig);
    unsigned char priv[200];
    size_t privlen = sizeof(priv);
    uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                           priv, &privlen,
                                           ech_version, 0, "example.com",
                                           hpke_suite, NULL, 0)))
        goto end;
    /* setup contexts, initially for tlsv1.3 */
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, echconfig,
                                              echconfiglen)))
        goto end;
    /* set client to max tls v1.2 and check setting ech config barfs */
    if (!TEST_true(SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    /* Now see a handshake fail */
    if (!TEST_false(create_ssl_connection(serverssl, clientssl, SSL_ERROR_SSL)))
        goto end;

    /* all good */
    if (verbose)
        TEST_info("tls_version_test: success\n");
    res = 1;
end:
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test ingestion of the vectors from test_echconfigs above */
static int test_ech_find(int idx)
{
    int rv = 0, inner_rv = 0, i, nechs = 0;
    SSL_CTX *con = NULL;
    unsigned char **cfgs = NULL;
    size_t *cfglens = NULL;
    TEST_ECHCONFIG *t;

    if (!TEST_ptr(con = SSL_CTX_new_ex(testctx, testpropq,
                                       TLS_server_method())))
        goto end;
    if (!TEST_true(SSL_CTX_set_max_proto_version(con, TLS1_3_VERSION)))
        goto end;
    t = &test_echconfigs[idx];
    if (verbose)
        TEST_info("test_ech_find input: %s", (char *)t->encoded);
    inner_rv = OSSL_ech_find_echconfigs(&nechs, &cfgs, &cfglens,
                                        t->encoded, t->encoded_len);
    if (!TEST_int_eq(inner_rv, t->rv_expected)) {
        if (verbose)
            TEST_info("unexpected return: input was: %s", (char *)t->encoded);
        goto end;
    }
    if (inner_rv == 1 && !TEST_int_eq(nechs, t->num_expected)) {
        if (verbose)
            TEST_info("unexpected output: input: %s, (got %d instead of %d)",
                      (char *)t->encoded, nechs, t->num_expected);
        goto end;
    }
    if (nechs == 0 && verbose)
        TEST_info("No ECH found, as expected");
    for (i = 0; i != nechs; i++) {
        if (!TEST_true(SSL_CTX_ech_set1_echconfig(con, cfgs[i], cfglens[i]))) {
            if (verbose)
                TEST_info("input was: %s", (char *)t->encoded);
            goto end;
        }
    }
    rv = 1;
end:
    OPENSSL_free(cfglens);
    for (i = 0; i != nechs; i++)
        OPENSSL_free(cfgs[i]);
    OPENSSL_free(cfgs);
    SSL_CTX_free(con);
    if (rv == 1 && verbose)
        TEST_info("test_ech_find: success\n");
    return rv;
}

/* values that can be used in helper below */
# define OSSL_ECH_TEST_BASIC    0
# define OSSL_ECH_TEST_HRR      1
# define OSSL_ECH_TEST_EARLY    2
# define OSSL_ECH_TEST_CUSTOM   3

/*
 * @brief ECH roundtrip test helper
 * @param idx specifies which ciphersuite
 * @araam combo specifies which particular test we want to roundtrip
 * @return 1 for good, 0 for bad
 *
 * The idx input here is from 0..44 and is broken down into a
 * kem, kdf and aead. If you run in verbose more ("-v") then
 * there'll be a "Doing: ..." trace line that says which suite
 * is being tested in string form.
 *
 * The combo input is one of the #define'd OSSL_ECH_TEST_*
 * values
 */
static int test_ech_roundtrip_helper(int idx, int combo)
{
    int res = 0, kemind, kdfind, aeadind, kemsz, kdfsz, aeadsz;
    char suitestr[100];
    unsigned char priv[400], echconfig[300];
    size_t privlen = sizeof(priv), echconfiglen = sizeof(echconfig);
    char echkeybuf[1000];
    size_t echkeybuflen = sizeof(echkeybuf);
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
    uint16_t max_name_length = 0;
    char *public_name = "example.com";
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int clientstatus, serverstatus;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    SSL_SESSION *sess = NULL;
    unsigned char ed[21];
    size_t written = 0, readbytes = 0;
    unsigned char buf[1024];
    unsigned int context;
    int server = 1, client = 0;

    /* split idx into kemind, kdfind, aeadind */
    kemsz = OSSL_NELEM(kem_str_list);
    kdfsz = OSSL_NELEM(kdf_str_list);
    aeadsz = OSSL_NELEM(aead_str_list);
    kemind = (idx / (kdfsz * aeadsz)) % kemsz;
    kdfind = (idx / aeadsz) % kdfsz;
    aeadind = idx % aeadsz;
    /* initialise early data stuff, just in case */
    memset(ed, 'A', sizeof(ed));
    snprintf(suitestr, 100, "%s,%s,%s", kem_str_list[kemind],
             kdf_str_list[kdfind], aead_str_list[aeadind]);
    if (verbose)
        TEST_info("Doing: iter: %d, suite: %s", idx, suitestr);
    if (!TEST_true(OSSL_HPKE_str2suite(suitestr, &hpke_suite)))
        goto end;
    if (!TEST_true(OSSL_ech_make_echconfig(echconfig, &echconfiglen,
                                           priv, &privlen,
                                           ech_version, max_name_length,
                                           public_name, hpke_suite,
                                           NULL, 0)))
        goto end;
    if (!TEST_ptr(echconfig))
        goto end;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    if (combo == OSSL_ECH_TEST_EARLY) {
        /* just to keep the format checker happy :-) */
        int lrv = 0;

        if (!TEST_true(SSL_CTX_set_options(sctx, SSL_OP_NO_ANTI_REPLAY)))
            goto end;
        if (!TEST_true(SSL_CTX_set_max_early_data(sctx,
                                                  SSL3_RT_MAX_PLAIN_LENGTH)))
            goto end;
        lrv = SSL_CTX_set_recv_max_early_data(sctx, SSL3_RT_MAX_PLAIN_LENGTH);
        if (!TEST_true(lrv))
            goto end;
    }
    if (combo == OSSL_ECH_TEST_CUSTOM) {
        /* add custom CH ext to client and server */
        context = SSL_EXT_CLIENT_HELLO;
        if (!TEST_true(SSL_CTX_add_custom_ext(cctx, TEST_EXT_TYPE1, context,
                                              new_add_cb, new_free_cb,
                                              &client, new_parse_cb, &client)))
            goto end;
        if (!TEST_true(SSL_CTX_add_custom_ext(sctx, TEST_EXT_TYPE1, context,
                                              new_add_cb, new_free_cb,
                                              &server, new_parse_cb, &server)))
            goto end;
        if (!TEST_true(SSL_CTX_add_custom_ext(cctx, TEST_EXT_TYPE2, context,
                                              new_add_cb, NULL,
                                              &client, NULL, &client)))
            goto end;
        if (!TEST_true(SSL_CTX_add_custom_ext(sctx, TEST_EXT_TYPE2, context,
                                              new_add_cb, NULL,
                                              &server, NULL, &server)))
            goto end;
    }
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen))) {
        TEST_info("Failed SSL_CTX_ech_set1_echconfig adding %s (len = %d)"
                  " to SSL_CTX: %p", echconfig, (int)echconfiglen,
                  (void *)cctx);
        goto end;
    }
    snprintf(echkeybuf, echkeybuflen,
             "%s-----BEGIN ECHCONFIG-----\n%s\n-----END ECHCONFIG-----\n",
             priv, (char *)echconfig);
    echkeybuflen = strlen(echkeybuf);
    if (verbose)
        TEST_info("PEM file buffer: (%d of %d) =====\n%s\n=====\n",
                  (int) echkeybuflen, (int) sizeof(echkeybuf),
                  echkeybuf);
    if (!TEST_true(SSL_CTX_ech_server_enable_buffer(sctx,
                                                    (unsigned char *)echkeybuf,
                                                    echkeybuflen,
                                                    SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (combo == OSSL_ECH_TEST_HRR
        && !TEST_true(SSL_set1_groups_list(serverssl, "P-384")))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s", serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s", clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* all good */
    if (combo == OSSL_ECH_TEST_BASIC
        || combo == OSSL_ECH_TEST_HRR
        || combo == OSSL_ECH_TEST_CUSTOM) {
        res = 1;
        goto end;
    }
    /* continue for EARLY test */
    if (combo != OSSL_ECH_TEST_EARLY)
        goto end;
    /* shutdown for start over */
    sess = SSL_get1_session(clientssl);
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    sinner = souter = cinner = couter = NULL;
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;
    /* second connection */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(SSL_set_session(clientssl, sess)))
        goto end;
    if (!TEST_true(SSL_write_early_data(clientssl, ed, sizeof(ed), &written)))
        goto end;
    if (!TEST_size_t_eq(written, sizeof(ed)))
        goto end;
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf,
                                         sizeof(buf), &readbytes),
                     SSL_READ_EARLY_DATA_SUCCESS))
        goto end;
    if (!TEST_size_t_eq(written, readbytes))
        goto end;
    /*
     * Server should be able to write data, and client should be able to
     * read it.
     */
    if (!TEST_true(SSL_write_early_data(serverssl, ed, sizeof(ed), &written))
            || !TEST_size_t_eq(written, sizeof(ed))
            || !TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, ed, sizeof(ed)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s", serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s", clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* all good */
    res = 1;
end:
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    SSL_SESSION_free(sess);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test roundtrip with ECH for any suite */
static int test_ech_suites(int idx)
{
    if (verbose)
        TEST_info("Doing: test_ech_suites");
    return test_ech_roundtrip_helper(idx, OSSL_ECH_TEST_BASIC);
}

/* ECH with HRR for the given suite */
static int test_ech_hrr(int idx)
{
    if (verbose)
        TEST_info("Doing: test_ech_hrr");
    return test_ech_roundtrip_helper(idx, OSSL_ECH_TEST_HRR);
}

/* ECH with early data for the given suite */
static int test_ech_early(int idx)
{
    if (verbose)
        TEST_info("Doing: test_ech_early");
    return test_ech_roundtrip_helper(idx, OSSL_ECH_TEST_EARLY);
}

/* Test a roundtrip with ECH, and a custom CH extension */
static int ech_custom_test(int idx)
{
    if (verbose)
        TEST_info("Doing: ech_custom_test");
    return test_ech_roundtrip_helper(idx, OSSL_ECH_TEST_CUSTOM);
}

/* Test roundtrip with GREASE'd ECH, then again with retry-config */
static int ech_grease_test(int idx)
{
    int res = 0, clientstatus, serverstatus;
    char *echkeyfile = NULL, *echconfig = NULL;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    char *public_name = "front.server.example";
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    unsigned char *retryconfig = NULL, priv[400], echconfig1[300];
    unsigned char echkeybuf[1000];
    size_t echconfig1len = sizeof(echconfig1);
    size_t retryconfiglen = 0, privlen = sizeof(priv);
    size_t echkeybuflen = sizeof(echkeybuf);
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
    uint16_t max_name_length = 0;
    X509_STORE *ch = NULL;

    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "newechconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    /* make an extra key pair to make retry-config bigger */
    if (!TEST_true(OSSL_ech_make_echconfig(echconfig1, &echconfig1len,
                                           priv, &privlen,
                                           ech_version, max_name_length,
                                           public_name, hpke_suite,
                                           NULL, 0)))
        goto end;
    snprintf((char *)echkeybuf, echkeybuflen,
             "%s-----BEGIN ECHCONFIG-----\n%s\n-----END ECHCONFIG-----\n",
             priv, (char *)echconfig1);
    echkeybuflen = strlen((char *)echkeybuf);
    /* add a 2nd ECHConfig, but one not to be sent in retry-config */
    if (idx == 2
        && !TEST_true(SSL_CTX_ech_server_enable_buffer(sctx,
                                                       echkeybuf,
                                                       echkeybuflen,
                                                       SSL_ECH_NOT_FOR_RETRY)))
        goto end;
    /* a 3rd, this time to be sent in retry-config */
    if (idx == 2
        && !TEST_true(SSL_CTX_ech_server_enable_buffer(sctx,
                                                       echkeybuf,
                                                       echkeybuflen,
                                                       SSL_ECH_USE_FOR_RETRY)))
        goto end;
    /* and a 4th to skip */
    if (idx == 2
        && !TEST_true(SSL_CTX_ech_server_enable_buffer(sctx,
                                                       echkeybuf,
                                                       echkeybuflen,
                                                       SSL_ECH_NOT_FOR_RETRY)))
        goto end;
    /* set the client GREASE flag via SSL_CTX 1st time, and via SSL* 2nd */
    if (idx == 0 && !TEST_true(SSL_CTX_set_options(cctx, SSL_OP_ECH_GREASE)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "back.server.example")))
        goto end;
    /* set the flag via SSL_CTX 1st time, and via SSL* 2nd & 3rd */
    if (idx >= 1 && !TEST_true(SSL_set_options(clientssl, SSL_OP_ECH_GREASE)))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("ech_grease_test: server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_GREASE))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("ech_grease_test: client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_GREASE_ECH))
        goto end;
    if (!TEST_true(SSL_ech_get_retry_config(clientssl, &retryconfig,
                                            &retryconfiglen)))
        goto end;
    if (!TEST_ptr(retryconfig))
        goto end;
    if (!TEST_int_ne(retryconfiglen, 0))
        goto end;
    if (verbose)
        TEST_info("ech_grease_test: retryconfglen: %d\n", (int)retryconfiglen);
    /* our ECHConfig values are 62 octets each + 2 for length */
    if (idx == 2 && !TEST_size_t_eq(retryconfiglen, 144))
        goto end;
    if (idx < 2 && !TEST_size_t_eq(retryconfiglen, 73))
        goto end;
    /* cleanup */
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    sinner = souter = cinner = couter = NULL;
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;
    /* second connection */
    /* setting an ECHConfig should over-ride GREASE flag */
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, retryconfig,
                                              retryconfiglen)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s", serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s", clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* 3rd connection - this time grease+HRR which had a late fail */
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    sinner = souter = cinner = couter = NULL;
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    /* force GREASE+HRR */
    if (!TEST_true(SSL_set_options(clientssl, SSL_OP_ECH_GREASE)))
        goto end;
    if (!TEST_true(SSL_set1_groups_list(serverssl, "P-384")))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s", serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s", clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* all good */
    res = 1;
end:
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    OPENSSL_free(retryconfig);
    SSL_free(clientssl);
    SSL_free(serverssl);
    X509_STORE_free(ch);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Test roundtrip with SNI/ALPN variations */
static int ech_in_out_test(int idx)
{
    int res = 0;
    char *echkeyfile = NULL, *echconfig = NULL;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int clientstatus, serverstatus;
    char *non_ech_sni = "trad.server.example"; /* SNI set via non-ECH API */
    char *supplied_inner = "inner.server.example"; /* inner set via ECH API */
    char *supplied_outer = "outer.server.example"; /* outer set via ECH API */
    char *public_name = "front.server.example"; /* we know that's inside echconfig.pem */
    /* inner, outer as provided via ECH status API */
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    /* value below is "inner, secret, http/1.1" */
    unsigned char alpn_inner[] = {
        0x05, 0x69, 0x6e, 0x6e, 0x65, 0x72,
        0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
        0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
    size_t echconfiglen, alpn_inner_len = sizeof(alpn_inner);
    /* value below is "outer, public, h2" */
    unsigned char alpn_outer[] = {
        0x05, 0x6f, 0x75, 0x74, 0x65, 0x72,
        0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0x02, 0x68, 0x32};
    size_t alpn_outer_len = sizeof(alpn_outer);
    /* what we expect to see on bothe sides after (depends on idx) */
    char *expected_inner = NULL, *expected_outer = NULL;
    int cres = 0, sres = 0;

    /*
     * Inner and outer names can be supplied to SSL_CTX or SSL
     * connection via ECH APIs, and inner can be supplied via
     * the existing non-ECH API. We can specify that no outer
     * SNI at all be sent if we want. If an outer SNI value is
     * supplied via the ECH API then that over-rides the
     * public_name field from the ECHConfig, which in this
     * cases will be example.com. We have the option of setting
     * both inner, outer and no_outer setting via eiher:
     *
     * int SSL_ech_set_server_names(SSL *s, const char *inner_name,
     *                              const char *outer_name, int no_outer);
     * int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name,
     *                                   int no_outer);
     *
     * So there's a bunch of cases to test, as usual we pick
     * between 'em using the idx parameter.
     *
     * idx : case
     * 0   : set no names via ECH APIs;
     *       set inner to inner.example.com non-ECH API
     *       expect public_name as outer
     * 1   : as for 0, but additionally:
     *       set NULL and "no_outer" via set_outer API
     * 2   : as for 1, but additionally:
     *       set non-NULL outer and "no_outer" via set_outer API
     * 3   : override outer via ECH API
     * 4   : like 1, but using set_server_names API
     * 5   : like 2, but using set_server_names API
     * 6   : like 3, but using set_server_names API
     * 7   : like 4, but overriding previous call to non-ECH SNI
     * 8   : like 5, but overriding previous call to non-ECH SNI
     * 9   : like 6, but overriding previous call to non-ECH SNI
     * 10  : like 7, but reversing call order
     * 11  : like 8, but reversing call order
     * 12  : like 9, but reversing call order
     * 13  : like 1, but with a NULL outer input to API
     *       that's a bit pointless as it's more or less a NO-OP
     *       but worth checking
     */
    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "newechconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto end;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto end;
    echconfiglen = strlen(echconfig);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_server_enable_file(sctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx, (unsigned char *)echconfig,
                                              echconfiglen)))
        goto end;
    /* next one returns zero for success for some reason? */
    if (!TEST_false(SSL_CTX_set_alpn_protos(cctx, alpn_inner, alpn_inner_len)))
        goto end;
    if (!TEST_true(SSL_CTX_ech_set_outer_alpn_protos(cctx, alpn_outer,
                                                     alpn_outer_len)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;
    /* setup specific SSL * tests as per comment above */
    if (idx == 0) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = public_name;
    }
    if (idx == 1) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        if (!TEST_true(SSL_ech_set_outer_server_name(clientssl, NULL, 1)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = NULL;
    }
    if (idx == 2) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        if (!TEST_true(SSL_ech_set_outer_server_name(clientssl, "blah", 1)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = NULL;
    }
    if (idx == 3) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        if (!TEST_true(SSL_ech_set_outer_server_name(clientssl,
                                                     supplied_outer, 0)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = supplied_outer;
    }
    if (idx == 4) {
        if (!TEST_true(SSL_ech_set_server_names(clientssl,
                                                supplied_inner, NULL, 0)))
            goto end;
        expected_inner = supplied_inner;
        expected_outer = public_name;
    }
    if (idx == 5) {
        if (!TEST_true(SSL_ech_set_server_names(clientssl, supplied_inner,
                                                "blah", 1)))
            goto end;
        expected_inner = supplied_inner;
        expected_outer = NULL;
    }
    if (idx == 6) {
        if (!TEST_true(SSL_ech_set_server_names(clientssl, supplied_inner,
                                                supplied_outer, 0)))
            goto end;
        expected_inner = supplied_inner;
        expected_outer = supplied_outer;
    }
    if (idx == 7) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "blah")))
            goto end;
        if (!TEST_true(SSL_ech_set_server_names(clientssl,
                                                supplied_inner, NULL, 0)))
            goto end;
        expected_inner = supplied_inner;
        expected_outer = public_name;
    }
    if (idx == 8) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "blah")))
            goto end;
        if (!TEST_true(SSL_ech_set_server_names(clientssl, supplied_inner,
                                                "blah", 1)))
            goto end;
        expected_inner = supplied_inner;
        expected_outer = NULL;
    }
    if (idx == 9) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "blah")))
            goto end;
        if (!TEST_true(SSL_ech_set_server_names(clientssl, supplied_inner,
                                                supplied_outer, 0)))
            goto end;
        expected_inner = supplied_inner;
        expected_outer = supplied_outer;
    }
    if (idx == 10) {
        if (!TEST_true(SSL_ech_set_server_names(clientssl,
                                                supplied_inner, NULL, 0)))
            goto end;
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = public_name;
    }
    if (idx == 11) {
        if (!TEST_true(SSL_ech_set_server_names(clientssl, supplied_inner,
                                                "blah", 1)))
            goto end;
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = NULL;
    }
    if (idx == 12) {
        if (!TEST_true(SSL_ech_set_server_names(clientssl, supplied_inner,
                                                supplied_outer, 0)))
            goto end;
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = supplied_outer;
    }
    if (idx == 13) {
        if (!TEST_true(SSL_set_tlsext_host_name(clientssl, non_ech_sni)))
            goto end;
        if (!TEST_true(SSL_ech_set_outer_server_name(clientssl,
                                                     NULL, 0)))
            goto end;
        expected_inner = non_ech_sni;
        expected_outer = public_name;
    }
    if (verbose)
        TEST_info("ech_in_out_test: expected I: %s, O: %s",
                  expected_inner, expected_outer);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("ech_in_out_test: server status %d, I: %s, O: %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("ech_in_out_test: client status %d, I: %s, O: %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    cres = sres = 0; /* check result vs. expected */
    if ((expected_inner == NULL && cinner == NULL)
        || (expected_inner != NULL && cinner != NULL
            && strlen(expected_inner) == strlen(cinner)
            && !strcmp(expected_inner, cinner)))
        cres = 1;
    if (!TEST_int_eq(cres, 1))
        goto end;
    if ((expected_inner == NULL && sinner == NULL)
        || (expected_inner != NULL && sinner != NULL
            && strlen(expected_inner) == strlen(sinner)
            && !strcmp(expected_inner, sinner)))
        sres = 1;
    if (!TEST_int_eq(sres, 1))
        goto end;
    cres = sres = 0;
    if ((expected_outer == NULL && couter == NULL)
        || (expected_outer != NULL && couter != NULL
            && strlen(expected_outer) == strlen(couter)
            && !strcmp(expected_outer, couter)))
        cres = 1;
    if (!TEST_int_eq(cres, 1))
        goto end;
    if ((expected_outer == NULL && souter == NULL)
        || (expected_outer != NULL && souter != NULL
            && strlen(expected_outer) == strlen(souter)
            && !strcmp(expected_outer, souter)))
        sres = 1;
    if (!TEST_int_eq(sres, 1))
        goto end;
    /* all good */
    res = 1;
end:
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return res;
}

/* Shuffle to preferred order */
enum OSSLTEST_ECH_ADD_runOrder
    {
     OSSLTEST_ECH_B64_GUESS,
     OSSLTEST_ECH_B64_BASE64,
     OSSLTEST_ECH_B64_GUESS_XS_COUNT,
     OSSLTEST_ECH_B64_GUESS_LO_COUNT,
     OSSLTEST_ECH_B64_JUNK_GUESS,

     OSSLTEST_ECH_NTESTS        /* Keep NTESTS last */
    };

static int test_ech_add(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;        /* assume failure */
    int echcount = 0;
    int returned;
    /*
     * This ECHConfigList has 6 entries with different versions,
     * [13,10,9,13,10,13] - since our runtime no longer supports
     * version 9 or 10, we should see 3 configs loaded.
     */
    size_t echconfiglen;
    OSSL_ECH_INFO *details = NULL;
    int num_dets = 0;

    echconfiglen = sizeof(echconfig_b64_6_to_3) - 1;

    /* Generate fresh context pair for each test with TLSv1.3 as a minimum */
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx2, &cctx, cert, privkey))) {
        TEST_info("test_ech_add: context creation failed for iteration %d",
                  idx);
        goto end;
    }
    if (!TEST_ptr(clientssl = SSL_new(cctx))) {
        TEST_info("test_ech_add: clientssl createion failed");
        goto end;
    }
    switch (idx) {
    case OSSLTEST_ECH_B64_GUESS:
        /* Valid echconfig */
        returned =
            SSL_ech_set1_echconfig(clientssl,
                                   (const unsigned char *)echconfig_b64_6_to_3,
                                   sizeof(echconfig_b64_6_to_3) - 1);
        if (!TEST_int_eq(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS: failure for valid echconfig "
                      " and length\n");
            goto end;
        }
        if (!TEST_true(SSL_ech_get_info(clientssl, &details, &num_dets)))
            goto end;
        if (!TEST_int_eq(num_dets, 3)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS: incorrect ECH count\n");
            goto end;
        }
        OSSL_ECH_INFO_free(details, num_dets);
        details = NULL;
        break;

    case OSSLTEST_ECH_B64_BASE64:
        /* Valid echconfig */
        returned =
            SSL_ech_set1_echconfig(clientssl,
                                   (const unsigned char *)echconfig_b64_6_to_3,
                                   sizeof(echconfig_b64_6_to_3) - 1);
        if (!TEST_int_eq(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_BASE64: failure for valid echconfig\n");
            goto end;
        }
        if (!TEST_true(SSL_ech_get_info(clientssl, &details, &num_dets)))
            goto end;
        if (!TEST_int_eq(num_dets, 3)) {
            TEST_info("OSSLTEST_ECH_B64_BASE64: incorrect ECH count\n");
            goto end;
        }
        OSSL_ECH_INFO_free(details, num_dets);
        details = NULL;
        break;

    case OSSLTEST_ECH_B64_GUESS_XS_COUNT:
        /*
         * Valid echconfig, excess length but just by one octet
         * which will be ok since strings have that added NUL
         * octet. If the excess was >1 then the caller is the
         * one making the error.
         */
        returned =
            SSL_ech_set1_echconfig(clientssl,
                                   (const unsigned char *)echconfig_b64_6_to_3,
                                   sizeof(echconfig_b64_6_to_3));
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: success despite excess "
                      "length (%d/%d)\n",
                      (int)echconfiglen + 1, (int)echconfiglen);
            goto end;
        }
        if (!TEST_true(SSL_ech_get_info(clientssl, &details, &num_dets)))
            goto end;
        if (!TEST_int_eq(num_dets, 0)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_XS_COUNT: ECH count (%d) should "
                      "be zero\n", echcount);
            goto end;
        }
        break;

    case OSSLTEST_ECH_B64_GUESS_LO_COUNT:
        /* Valid echconfig, short length */
        returned =
            SSL_ech_set1_echconfig(clientssl,
                                   echconfig_b64_6_to_3,
                                   sizeof(echconfig_b64_6_to_3) / 2);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_GUESS_LO_COUNT: success despite short "
                      "length (%d/%d)\n",
                      (int)echconfiglen / 2, (int)echconfiglen);
            goto end;
        }
        break;

    case OSSLTEST_ECH_B64_JUNK_GUESS:
        /* Junk echconfig */
        returned = SSL_ech_set1_echconfig(clientssl,
                                          (unsigned char *)"DUMMDUMM;DUMMYDUMM",
                                          18);
        if (!TEST_int_ne(returned, 1)) {
            TEST_info("OSSLTEST_ECH_B64_JUNK_GUESS: junk config success\n");
            goto end;
        }
        break;

    default:
        TEST_error("Bad test index\n");
        goto end;
    }

    if (verbose)
        TEST_info("test_ech_add: success\n");
    testresult = 1;        /* explicit success */

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH tests\n" },
        { NULL }
    };
    return test_options;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;
    int suite_combos;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    certsdir = test_get_argument(0);
    if (certsdir == NULL)
        certsdir = DEF_CERTS_DIR;
    cert = test_mk_file_path(certsdir, "echserver.pem");
    if (cert == NULL)
        goto err;
    privkey = test_mk_file_path(certsdir, "echserver.key");
    if (privkey == NULL)
        goto err;
    rootcert = test_mk_file_path(certsdir, "rootcert.pem");
    if (rootcert == NULL)
        goto err;
    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_null = BIO_new(BIO_s_mem());
    ADD_TEST(tls_version_test);
    ADD_ALL_TESTS(basic_echconfig, 2);
    ADD_ALL_TESTS(extended_echconfig, 2);
    ADD_ALL_TESTS(ech_roundtrip_test, 2);
    ADD_ALL_TESTS(test_ech_add, OSSLTEST_ECH_NTESTS);
    ADD_ALL_TESTS(test_ech_find, OSSL_NELEM(test_echconfigs));
    /*
     * test a roundtrip for all suites, the test iteration
     * number is split into kem, kdf and aead string indices
     * to select the specific suite for that iteration
     */
    suite_combos = OSSL_NELEM(kem_str_list) * OSSL_NELEM(kdf_str_list)
        * OSSL_NELEM(aead_str_list);
    ADD_ALL_TESTS(test_ech_suites, suite_combos);
    ADD_ALL_TESTS(test_ech_hrr, suite_combos);
    ADD_ALL_TESTS(test_ech_early, suite_combos);
    ADD_ALL_TESTS(ech_custom_test, suite_combos);
    ADD_ALL_TESTS(ech_grease_test, 3);
    ADD_ALL_TESTS(ech_in_out_test, 14);
    ADD_ALL_TESTS(ech_wrong_pub_test, 3);
    return 1;
err:
    return 0;
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    BIO_free(bio_null);
    BIO_free(bio_stdout);
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(rootcert);
#endif
}
