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

# define DEF_CERTS_DIR "test/certs"

static OSSL_LIB_CTX *libctx = NULL;
static char *propq = NULL;
static int verbose = 0;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *rootcert = NULL;

/* TODO(ECH): add some testing of SSL_OP_ECH_IGNORE_CID */

/* callback */
static unsigned int test_cb(SSL *s, const char *str)
{
    return 1;
}

/*
 * The define/vars below and the 3 callback functions are modified
 * from test/sslapitest.c
 */
# define TEST_EXT_TYPE1  0xffab /* custom ext type 1: has 1 octet payload */
# define TEST_EXT_TYPE2  0xffcd /* custom ext type 2: no payload */

/* A well-encoded ECH extension value */
static const unsigned char encoded_ech_val[] = {
    0x00, 0x00, 0x01, 0x00, 0x01, 0xf7, 0x00, 0x20,
    0xc9, 0x2c, 0x12, 0xc9, 0xc0, 0x4d, 0x11, 0x5d,
    0x09, 0xe1, 0xeb, 0x7a, 0x18, 0xb2, 0x83, 0x28,
    0x35, 0x00, 0x3c, 0x8d, 0x78, 0x09, 0xfd, 0x09,
    0x84, 0xca, 0x94, 0x77, 0xcf, 0x78, 0xd0, 0x04,
    0x00, 0x90, 0x5e, 0xc7, 0xc0, 0x62, 0x84, 0x8d,
    0x4b, 0x85, 0xd5, 0x6a, 0x9a, 0xc1, 0xc6, 0xc2,
    0x28, 0xac, 0x87, 0xb9, 0x2f, 0x36, 0xa0, 0xf7,
    0x5f, 0xd0, 0x23, 0x7b, 0xf4, 0xc1, 0x62, 0x1c,
    0xf1, 0x91, 0xfd, 0x46, 0x35, 0x41, 0xc9, 0x06,
    0xd3, 0x19, 0xd6, 0x34, 0x01, 0xc3, 0xb3, 0x66,
    0x4e, 0x7a, 0x28, 0xac, 0xd4, 0xd2, 0x35, 0x2b,
    0xd0, 0xc6, 0x94, 0x34, 0xc1, 0x94, 0x62, 0x77,
    0x1b, 0x5a, 0x02, 0x3c, 0xdd, 0xa2, 0x4d, 0x33,
    0xa5, 0xd0, 0x59, 0x12, 0xf5, 0x17, 0x03, 0xe5,
    0xab, 0xbd, 0x83, 0x52, 0x40, 0x6c, 0x99, 0xac,
    0x25, 0x07, 0x63, 0x8c, 0x16, 0x5d, 0x93, 0x34,
    0x56, 0x34, 0x60, 0x86, 0x25, 0xa7, 0x0d, 0xac,
    0xb8, 0x5e, 0x87, 0xc6, 0xf7, 0x23, 0xaf, 0xf8,
    0x3e, 0x2a, 0x46, 0x75, 0xa9, 0x5f, 0xaf, 0xd2,
    0x91, 0xe6, 0x44, 0xcb, 0xe7, 0xe0, 0x85, 0x36,
    0x9d, 0xd2, 0xaf, 0xae, 0xb3, 0x0f, 0x70, 0x6a,
    0xaf, 0x42, 0xc0, 0xb3, 0xe4, 0x65, 0x53, 0x01,
    0x75, 0xbf
};

static int new_add_cb(SSL *s, unsigned int ext_type, unsigned int context,
                      const unsigned char **out, size_t *outlen, X509 *x,
                      size_t chainidx, int *al, void *add_arg)
{
    int *server = (int *)add_arg;
    unsigned char *data;

    if (*server != SSL_is_server(s))
        return -1;
    if (ext_type == TEST_EXT_TYPE1) {
        if ((data = OPENSSL_malloc(sizeof(*data))) == NULL)
            return -1;
        *data = 1;
        *out = data;
        *outlen = sizeof(*data);
    } else if (ext_type == OSSL_ECH_CURRENT_VERSION) {
        /* inject a sample ECH extension value into the CH */
        if ((data = OPENSSL_memdup(encoded_ech_val,
                                   sizeof(encoded_ech_val))) == NULL)
            return -1;
        *out = data;
        *outlen = sizeof(encoded_ech_val);
    } else {
        /* inject a TEST_EXT_TYPE2, with a zero-length payload */
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

/* general test vector values */

/* standard x25519 ech key pair with public key example.com */
static const char pem_kp1[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEILDIeo9Eqc4K9/uQ0PNAyMaP60qrxiSHT2tNZL3ksIZS\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/* standard x25519 ECHConfigList with public key example.com */
static const char pem_pk1[] =
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/* an ECDSA private with an x25519 ech public key example.com */
static const char pem_mismatch_priv[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIGKONznbHOMEKT4AKMufc37O9lUEBHO+Nb6ztkXhGXLcoAoGCCqGSM49\n"
    "AwEHoUQDQgAEYDznfezvj5ufhQsZOQvSdiNpYKCd8tRI1aI3gc4y7gmdDUKpwzHa\n"
    "VS4Qq0xyeG6fDMJv668UCotQANFsifGirQ==\n"
    "-----END EC PRIVATE KEY-----\n"
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

/*
 * This ECHConfigList has 4 entries with different versions,
 * from drafts: 13,10,13,9 - since our runtime no longer supports
 * version 9 or 10, we should see 2 configs loaded.
 */
static const char pem_4_to_2[] =
    "-----BEGIN ECHCONFIG-----\n"
    "APv+DQA6xQAgACBm54KSIPXu+pQq2oY183wt3ybx7CKbBYX0ogPq5u6FegAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAP4KADzSACAAIIP+0Qt0WGBF3H5fz8HuhVRTCEMuHS4K\n"
    "hu6ibR/6qER4AAQAAQABAAAAC2V4YW1wbGUuY29tAAD+DQA6QwAgACB3xsNUtSgi\n"
    "piYpUkW6OSrrg03I4zIENMFa0JR2+Mm1WwAEAAEAAQALZXhhbXBsZS5jb20AAP4J\n"
    "ADsAC2V4YW1wbGUuY29tACCjJCv5w/yaHjbOc6nVuM/GksIGLgDR+222vww9dEk8\n"
    "FwAgAAQAAQABAAAAAA==\n"
    "-----END ECHCONFIG-----\n";

/* mis-spelled PEM string */
static const char pem_typo[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEILDIeo9Eqc4K9/uQ0PNAyMaP60qrxiSHT2tNZL3ksIZS\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN ExHCOxFIG-----\n"
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA\n"
    "AQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ExHCOxFIG-----\n";

/* single-line base64(ECHConfigList) form of pem_pk1 */
static const char b64_pk1[] =
    "AD7+DQA6bAAgACCY7B0f/3KvHIFdoqFaObdU8YYU+MdBf4vzbLhAAL2QCwAEAAEA"
    "AQALZXhhbXBsZS5jb20AAA==";

/* single-line base64(ECHConfigList) form of pem_6_to3 */
static const char b64_6_to_3[] =
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
static const unsigned char bin_6_to_3[] = {
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

/* base64(ECHConfigList) with corrupt ciphersuite length and public_name */
static const char b64_bad_cs[] =
    "AD7+DQA6uAAgACAogff+HZbirYdQCfXI01GBPP8AEKYyK/D/0DoeXD84fgAQAAE"
    "AAQgLZXhhbUNwbGUuYwYAAAAAQwA=";

/* An ECHConfigList with one ECHConfig but of the wrong version */
static const unsigned char bin_bad_ver[] = {
    0x00, 0x3e, 0xfe, 0xff, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * An ECHConflgList with 2 ECHConfig values that are both
 * of the wrong version. The versions here are 0xfe03 (we
 * currently support only 0xfe0d)
 */
static const unsigned char bin_bad_ver2[] = {
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
 * An ECHConfigList with one ECHConfig with an all-zero public value.
 * That should be ok, for 25519, but hey, just in case:-)
 */
static const unsigned char bin_zero[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * The next set of samples are syntactically invalid
 * Proper fuzzing is still needed but no harm having
 * these too. Generally these are bad version of
 * our nominal encoding with some octet(s) replaced
 * by 0xFF values. Other hex letters are lowercase
 * so you can find the altered octet(s).
 */

/* wrong overall length (replacing 0x3e with 0xFF) */
static const unsigned char bin_bad_olen[] = {
    0x00, 0xFF, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0xFF, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong ECHConfig inner length (replacing 0x3a with 0xFF) */
static const unsigned char bin_bad_ilen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0xFF, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong length for public key (replaced 0x20 with 0xFF) */
static const unsigned char bin_bad_pklen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0xFF, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong length for ciphersuites (replaced 0x04 with 0xFF) */
static const unsigned char bin_bad_cslen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0xFF, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong length for public name (replaced 0x0b with 0xFF) */
static const unsigned char bin_bad_pnlen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0xFF, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* non-zero extension length (0xFF at end) but no extension value */
static const unsigned char bin_bad_extlen[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0xFF
};

/*
 * The next set have bad kem, kdf or aead values - this time with
 * 0xAA as the replacement value
 */

/* wrong KEM ID (replaced 0x20 with 0xAA) */
static const unsigned char bin_bad_kemid[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0xAA, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong KDF ID (replaced 0x01 with 0xAA) */
static const unsigned char bin_bad_kdfid[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0xAA, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* wrong AEAD ID (replaced 0x01 with 0xAA) */
static const unsigned char bin_bad_aeadid[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0xAA, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* ECHConfig supports two symmetric suites */
static const unsigned char bin_multi_suite[] = {
    0x00, 0x42, 0xfe, 0x0d, 0x00, 0x3e, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x01,
    0x00, 0x02, 0x00, 0x02,
    0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * sorta wrong AEAD ID; replaced 0x0001 with 0xFFFF
 * which is the export only pseudo-aead-id - that
 * should not work in our test, same as the others,
 * but worth a specific test, as it'll fail in a
 * different manner
 */
static const unsigned char bin_bad_aeadid_ff[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0xFF,
    0xFF, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/*
 * An ECHConfigList with a bad ECHConfig
 * (aead is 0xFFFF), followed by a good
 * one.
 */
static const unsigned char bin_bad_then_good[] = {
    0x00, 0x7c, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0xFF,
    0xFF, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00, 0x20, 0x00,
    0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2, 0xc5, 0xfe,
    0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c, 0xa4, 0x33,
    0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e, 0x5a, 0x42,
    0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73, 0x60, 0x16,
    0x3c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* couple of harmless extensions */
static const unsigned char bin_ok_exts[] = {
    0x00, 0x47, 0xfe, 0x0d, 0x00, 0x43, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x09,
    0x0a, 0x0b, 0x00, 0x00, 0x0c, 0x0d, 0x00, 0x01,
    0x02
};

/* one "mandatory" extension (high bit of type set) */
static const unsigned char bin_mand_ext[] = {
    0x00, 0x47, 0xfe, 0x0d, 0x00, 0x43, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x09,
    0x0a, 0x0b, 0x00, 0x00, 0xFc, 0x0d, 0x00, 0x01,
    0x02
};

/* extension with bad length (0xFFFF) */
static const unsigned char bin_bad_inner_extlen[] = {
    0x00, 0x47, 0xfe, 0x0d, 0x00, 0x43, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x09,
    0x0a, 0x0b, 0x00, 0x00, 0x0c, 0x0d, 0x00, 0xFF,
    0x02
};

/* good, other than a NUL inside the public_name */
static const unsigned char bin_nul_in_pn[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x00, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* good, other than a dot at the end of the public_name */
static const unsigned char bin_pn_dot_at_end[] = {
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x2e, 0x00, 0x00
};

/*
 * An ECHConfigList with a good ECHConfig followed by a bad
 * one with the 1st internal length (0xFFFF) too big
 */
static const unsigned char bin_good_then_bad[] = {
    0x00, 0x7c, 0xfe, 0x0d, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0xfe, 0x0d, 0xFF, 0xFF, 0xbb, 0x00, 0x20, 0x00,
    0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2, 0xc5, 0xfe,
    0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c, 0xa4, 0x33,
    0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e, 0x5a, 0x42,
    0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73, 0x60, 0x16,
    0x3c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00
};

/* generally very short:-) */
static const unsigned char bin_short[] = {
    0x00, 0x05, 0xfe, 0x0d, 0x00, 0x01, 0x01
};

/* kind of an empty value */
static const unsigned char bin_empty[] = {
    0x00, 0x00
};

/*
 * An ECHConfigList with an unsupported ECHConfig and
 * that's too short.
 */
static const unsigned char bin_ver_short[] = {
    0x00, 0x3e, 0xfe, 0xFF, 0x00, 0x3a, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
 * too-long extension - OSSL_ECH_MAX_ECHCONFIGEXT_LEN is
 * 512, this is 513 (0x0201), end of the 8-th line
 * */
static const unsigned char bin_long_ext[] = {
    0x02, 0x43, 0xfe, 0x0d, 0x02, 0x3f, 0xbb, 0x00,
    0x20, 0x00, 0x20, 0x62, 0xc7, 0x60, 0x7b, 0xf2,
    0xc5, 0xfe, 0x11, 0x08, 0x44, 0x6f, 0x13, 0x2c,
    0xa4, 0x33, 0x9c, 0xf1, 0x9d, 0xf1, 0x55, 0x2e,
    0x5a, 0x42, 0x96, 0x0f, 0xd0, 0x2c, 0x69, 0x73,
    0x60, 0x16, 0x3c, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x05,
    0xFF, 0xFF, 0x02, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
};

/* struct for ingest test vector and results */
typedef struct INGEST_TV_T {
    char *name; /* name for verbose output */
    const unsigned char *tv; /* test vector */
    size_t len; /* len(tv) - sizeof(tv) if binary, subtract 1 for strings */
    int pemenc; /* whether PEM encoded (1) or not (0) */
    int read; /* result expected from read function on tv */
    int keysb4; /* the number of private keys expected before downselect */
    int entsb4; /* the number of public keys b4 */
    int index; /* the index to use for downselect */
    int expected; /* the result expected from a downselect */
    int keysaftr; /* the number of keys expected after downselect */
    int entsaftr; /* the number of public keys after */
} ingest_tv_t;

static ingest_tv_t ingest_tvs[] = {
    /* PEM test vectors */
    { "PEM basic/last", (unsigned char *)pem_kp1, sizeof(pem_kp1) - 1,
      1, 1, 1, 1, OSSL_ECHSTORE_LAST, 1, 1, 1 },
    { "PEM basic/0", (unsigned char *)pem_pk1, sizeof(pem_pk1) - 1,
      1, 1, 0, 1, 0, 1, 0, 1 },
    { "PEM basic/2nd", (unsigned char *)pem_pk1, sizeof(pem_pk1) - 1,
      1, 1, 0, 1, 2, 0, 0, 1 },
    { "ECDSA priv + 25519 pub", (unsigned char *)pem_mismatch_priv,
      sizeof(pem_mismatch_priv) - 1,
      1, 0, 0, 0, 0, 0, 0, 0 },
    { "PEM string typo", (unsigned char *)pem_typo, sizeof(pem_typo) - 1,
      1, 0, 0, 0, 0, 0, 0, 0 },
    /* downselect from the 2, at each position */
    { "PEM 4->2/0", (unsigned char *)pem_4_to_2, sizeof(pem_4_to_2) - 1,
      1, 1, 0, 2, 0, 1, 0, 1 },
    { "PEM 4->2/1", (unsigned char *)pem_4_to_2, sizeof(pem_4_to_2) - 1,
      1, 1, 0, 2, 1, 1, 0, 1 },
    /* in the next one below, downselect fails, so we still have 2 entries */
    { "PEM 4->2/2", (unsigned char *)pem_4_to_2, sizeof(pem_4_to_2) - 1,
      1, 1, 0, 2, 3, 0, 0, 2 },
    /* b64 test vectors */
    { "B64 basic/last", (unsigned char *)b64_pk1, sizeof(b64_pk1) - 1,
      0, 1, 0, 1, OSSL_ECHSTORE_LAST, 1, 0, 1 },
    { "B64 6->3/2", (unsigned char *)b64_6_to_3, sizeof(b64_6_to_3) - 1,
      0, 1, 0, 3, 2, 1, 0, 1 },
    { "B64 bad suitelen", (unsigned char *)b64_bad_cs, sizeof(b64_bad_cs) - 1,
      0, 0, 0, 0, 0, 0, 0, 0 },
    /* binary test vectors */
    { "bin 6->3/2", (unsigned char *)bin_6_to_3, sizeof(bin_6_to_3),
      0, 1, 0, 3, 2, 1, 0, 1 },
    { "bin 2 symm suites", (unsigned char *)bin_multi_suite,
      sizeof(bin_multi_suite),
      0, 1, 0, 1, OSSL_ECHSTORE_LAST, 1, 0, 1 },
    { "bin all-zero pub", (unsigned char *)bin_zero, sizeof(bin_zero),
      0, 1, 0, 1, OSSL_ECHSTORE_LAST, 1, 0, 1 },
    { "bin ok exts", (unsigned char *)bin_ok_exts, sizeof(bin_ok_exts),
      0, 1, 0, 1, OSSL_ECHSTORE_LAST, 1, 0, 1 },
    { "bin bad ver", (unsigned char *)bin_bad_ver, sizeof(bin_bad_ver),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin 2 bad ver", (unsigned char *)bin_bad_ver2, sizeof(bin_bad_ver2),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad len", (unsigned char *)bin_bad_olen, sizeof(bin_bad_olen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad inner len", (unsigned char *)bin_bad_ilen, sizeof(bin_bad_ilen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad pk len", (unsigned char *)bin_bad_pklen, sizeof(bin_bad_pklen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad suitelen", (unsigned char *)bin_bad_cslen, sizeof(bin_bad_cslen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad pn len", (unsigned char *)bin_bad_pnlen, sizeof(bin_bad_pnlen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad extlen", (unsigned char *)bin_bad_extlen, sizeof(bin_bad_extlen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad kemid", (unsigned char *)bin_bad_kemid, sizeof(bin_bad_kemid),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad kdfid", (unsigned char *)bin_bad_kdfid, sizeof(bin_bad_kdfid),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad aeadid", (unsigned char *)bin_bad_aeadid, sizeof(bin_bad_aeadid),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin exp aeadid", (unsigned char *)bin_bad_aeadid_ff,
      sizeof(bin_bad_aeadid_ff),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad,good", (unsigned char *)bin_bad_then_good,
      sizeof(bin_bad_then_good),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin mand ext", (unsigned char *)bin_mand_ext, sizeof(bin_mand_ext),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin bad inner extlen", (unsigned char *)bin_bad_inner_extlen,
      sizeof(bin_bad_inner_extlen),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin NUL in PN", (unsigned char *)bin_nul_in_pn, sizeof(bin_nul_in_pn),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin PN ends in dot", (unsigned char *)bin_pn_dot_at_end,
      sizeof(bin_pn_dot_at_end),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin short", (unsigned char *)bin_short, sizeof(bin_short),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin empty", (unsigned char *)bin_empty, sizeof(bin_empty),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin ver short", (unsigned char *)bin_ver_short, sizeof(bin_ver_short),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin long ext", (unsigned char *)bin_long_ext, sizeof(bin_long_ext),
      0, 0, 0, 0, 0, 0, 0, 0 },
    { "bin good then bad", (unsigned char *)bin_good_then_bad,
      sizeof(bin_good_then_bad),
      0, 0, 0, 0, 0, 0, 0, 0 },
};

/* similar, but slightly simpler setup for file reading tests */
typedef struct FNT_T {
    char *fname; /* relative file name */
    int read; /* expected result from a pem_read of that */
} fnt_t;

static fnt_t fnames[] = {
    { "ech-eg.pem", 1 },
    { "ech-mid.pem", 1 },
    { "ech-big.pem", 1 },
    { "ech-giant.pem", 0 },
    { "ech-rsa.pem", 0 },
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

/*
 * For the relevant test vector in our array above:
 * - try decode
 * - if not expected to decode, we're done
 * - check we got the right number of keys/ECHConfig values
 * - do some calls with getting info, downselecting etc. and
 *   check results as expected
 * - do a write_pem call on the results
 * - flush keys 'till now and check they're all gone
 */
static int ech_ingest_test(int run)
{
    OSSL_ECHSTORE *es = NULL;
    BIO *in = NULL, *out = NULL;
    int i, rv = 0, keysb4, keysaftr, actual_ents = 0, has_priv, for_retry;
    ingest_tv_t *tv = &ingest_tvs[run];
    time_t secs = 0, add_time = 0, flush_time = 0;
    char *pn = NULL, *ec = NULL;

    if ((in = BIO_new(BIO_s_mem())) == NULL
        || BIO_write(in, tv->tv, tv->len) <= 0
        || (out = BIO_new(BIO_s_mem())) == NULL
        || (es = OSSL_ECHSTORE_new(NULL, NULL)) == NULL)
        goto end;
    if (verbose)
        TEST_info("Iteration: %d %s", run + 1, tv->name);
    /* just in case of bad edits to table */
    if (tv->pemenc != 1 && tv->pemenc != 0) {
        TEST_info("Bad test vector entry");
        goto end;
    }
    add_time = time(0);
    if (tv->pemenc == 1
        && !TEST_int_eq(OSSL_ECHSTORE_read_pem(es, in, OSSL_ECH_NO_RETRY),
                        tv->read))
        goto end;
    if (tv->pemenc != 1
        && !TEST_int_eq(OSSL_ECHSTORE_read_echconfiglist(es, in), tv->read))
        goto end;
    /* if we provided a deliberately bad tv then we're done */
    if (tv->read != 1) {
        rv = 1;
        goto end;
    }
    if (!TEST_true(OSSL_ECHSTORE_num_keys(es, &keysb4))
        || !TEST_true(OSSL_ECHSTORE_num_entries(es, &actual_ents))
        || !TEST_int_eq(keysb4, tv->keysb4)
        || !TEST_int_eq(actual_ents, tv->entsb4)
        || !TEST_int_eq(OSSL_ECHSTORE_get1_info(es, -1, &secs, &pn, &ec,
                                                &has_priv, &for_retry), 0))
        goto end;
    OPENSSL_free(pn);
    pn = NULL;
    OPENSSL_free(ec);
    ec = NULL;
    for (i = 0; i != actual_ents; i++) {
        if (!TEST_true(OSSL_ECHSTORE_get1_info(es, i, &secs, &pn, &ec,
                                               &has_priv, &for_retry)))
            goto end;
        OPENSSL_free(pn);
        pn = NULL;
        OPENSSL_free(ec);
        ec = NULL;
    }
    /* ensure silly index fails ok */
    if (!TEST_false(OSSL_ECHSTORE_downselect(es, -20))
        || !TEST_int_eq(OSSL_ECHSTORE_downselect(es, tv->index), tv->expected)
        || !TEST_true(OSSL_ECHSTORE_num_keys(es, &keysaftr))
        || !TEST_int_eq(keysaftr, tv->keysaftr)
        || !TEST_true(OSSL_ECHSTORE_num_entries(es, &actual_ents))
        || !TEST_int_eq(actual_ents, tv->entsaftr)
        || !TEST_true(OSSL_ECHSTORE_write_pem(es, OSSL_ECHSTORE_LAST, out))
        || !TEST_true(OSSL_ECHSTORE_write_pem(es, OSSL_ECHSTORE_ALL, out))
        || !TEST_false(OSSL_ECHSTORE_write_pem(es, 100, out)))
        goto end;
    flush_time = time(0);
    /*
     * Occasionally, flush_time will be 1 more than add_time. We'll
     * check for that as that should catch a few more code paths
     * in the flush_keys API.
     * When flush_time is 1 more, we may or may not have flushed
     * the one and only key (depending on which "side" of the second
     * it was generated, so we may be left with 0 or 1 keys.
     */
    if (!TEST_true(OSSL_ECHSTORE_flush_keys(es, flush_time - add_time))
        || !TEST_int_eq(OSSL_ECHSTORE_num_keys(es, &keysaftr), 1)
        || ((flush_time <= add_time) && !TEST_int_eq(keysaftr, 0))
        || ((flush_time > add_time) && !TEST_int_eq(keysaftr, 1)
             && !TEST_int_eq(keysaftr, 1))) {
        TEST_info("Flush time: %lld, add_time: %lld", (long long)flush_time,
                  (long long)add_time);
        goto end;
    }
    rv = 1;
end:
    OPENSSL_free(pn);
    OPENSSL_free(ec);
    OSSL_ECHSTORE_free(es);
    BIO_free_all(in);
    BIO_free_all(out);
    return rv;
}

/* make a bunch of calls with bad, mostly NULL, arguments */
static int ech_store_null_calls(void)
{
    int rv = 0, count = 0, has_priv, for_retry;
    OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    BIO *inout = BIO_new(BIO_s_mem());
    EVP_PKEY *priv = EVP_PKEY_new();
    time_t secs;
    char *pn = NULL, *ec = NULL;

    OSSL_ECHSTORE_free(NULL);
    if (!TEST_false(OSSL_ECHSTORE_new_config(NULL, OSSL_ECH_CURRENT_VERSION,
                                             0, "example.com", hpke_suite))
        || !TEST_false(OSSL_ECHSTORE_new_config(es, OSSL_ECH_CURRENT_VERSION,
                                                0, NULL, hpke_suite))
        || !TEST_false(OSSL_ECHSTORE_new_config(es, 0xffff, 0,
                                                "example.com", hpke_suite)))
        goto end;
    hpke_suite.kdf_id = 0xAAAA; /* a bad value */
    if (!TEST_false(OSSL_ECHSTORE_new_config(es, OSSL_ECH_CURRENT_VERSION,
                                             0, "example.com", hpke_suite))
        || !TEST_false(OSSL_ECHSTORE_write_pem(NULL, 0, inout))
        || !TEST_false(OSSL_ECHSTORE_write_pem(es, 0, NULL))
        || !TEST_false(OSSL_ECHSTORE_write_pem(es, 100, inout))
        || !TEST_false(OSSL_ECHSTORE_read_echconfiglist(NULL, inout))
        || !TEST_false(OSSL_ECHSTORE_read_echconfiglist(es, NULL))
        || !TEST_false(OSSL_ECHSTORE_get1_info(NULL, 0, &secs, &pn, &ec,
                                               &has_priv, &for_retry))
        || !TEST_false(OSSL_ECHSTORE_downselect(NULL, 0))
        || !TEST_false(OSSL_ECHSTORE_downselect(es, 100))
        || !TEST_false(OSSL_ECHSTORE_set1_key_and_read_pem(NULL, priv,
                                                           inout, 0))
        || !TEST_false(OSSL_ECHSTORE_set1_key_and_read_pem(es, NULL, inout, 0))
        || !TEST_false(OSSL_ECHSTORE_set1_key_and_read_pem(es, priv, NULL, 0))
        || !TEST_false(OSSL_ECHSTORE_set1_key_and_read_pem(es, priv,
                                                           inout, 100))
        /* this one fails 'cause priv has no real value, even if non NULL */
        || !TEST_false(OSSL_ECHSTORE_set1_key_and_read_pem(es, priv, inout,
                                                           OSSL_ECH_NO_RETRY))
        || !TEST_false(OSSL_ECHSTORE_read_pem(NULL, inout, OSSL_ECH_NO_RETRY))
        || !TEST_false(OSSL_ECHSTORE_read_pem(es, NULL, OSSL_ECH_NO_RETRY))
        || !TEST_false(OSSL_ECHSTORE_read_pem(es, inout, 100))
        || !TEST_false(OSSL_ECHSTORE_num_keys(NULL, &count))
        || !TEST_false(OSSL_ECHSTORE_num_keys(es, NULL))
        || !TEST_false(OSSL_ECHSTORE_flush_keys(NULL, 0))
        || !TEST_false(OSSL_ECHSTORE_flush_keys(es, -1))
        || !TEST_false(OSSL_ECHSTORE_num_entries(es, NULL)))
        goto end;
    rv = 1;
end:
    OSSL_ECHSTORE_free(es);
    BIO_free_all(inout);
    EVP_PKEY_free(priv);
    return rv;
}

/* read some files, some that work, some that fail */
static int ech_test_file_read(int run)
{
    int rv = 0;
    OSSL_ECHSTORE *es = NULL;
    BIO *in = NULL;
    fnt_t *ft = &fnames[run];
    char *fullname = NULL;
    size_t fnlen = 0;

    es = OSSL_ECHSTORE_new(NULL, NULL);
    if (es == NULL)
        goto end;
    fnlen = strlen(certsdir) + 1 + strlen(ft->fname) + 1;
    fullname = OPENSSL_malloc(fnlen);
    if (fullname == NULL)
        goto end;
    snprintf(fullname, fnlen, "%s/%s", certsdir, ft->fname);
    if (verbose)
        TEST_info("testing read of %s", fullname);
    in = BIO_new_file(fullname, "r");
    if (in == NULL) {
        TEST_info("BIO_new_file failed for %s", ft->fname);
        goto end;
    }
    if (!TEST_int_eq(OSSL_ECHSTORE_read_pem(es, in, OSSL_ECH_NO_RETRY),
                     ft->read))
        goto end;
    rv = 1;
end:
    OPENSSL_free(fullname);
    OSSL_ECHSTORE_free(es);
    BIO_free_all(in);
    return rv;
}

/* calls with bad, NULL, and simple, arguments, for generic code coverage  */
static int ech_api_basic_calls(void)
{
    int rv = 0;
    SSL_CTX *ctx = NULL;
    SSL *s = NULL;
    OSSL_ECHSTORE *es = NULL, *es1 = NULL;
    char *rinner, *inner = "inner.example.com";
    char *router, *outer = "example.com";
    unsigned char alpns[] = { 'h', '2' };
    size_t alpns_len = sizeof(alpns);
    char *gsuite = "X25519,hkdf-sha256,aes-256-gcm";
    uint16_t gtype = 0xfe09;
    unsigned char *rc = NULL;
    size_t rclen = 0;
    BIO *in = NULL;

    /* NULL args */
    if (!TEST_false(SSL_CTX_set1_echstore(NULL, NULL))
        || !TEST_false(SSL_set1_echstore(NULL, NULL))
        || !TEST_ptr_eq(SSL_CTX_get1_echstore(NULL), NULL)
        || !TEST_ptr_eq(SSL_get1_echstore(NULL), NULL)
        || !TEST_false(SSL_ech_set1_server_names(NULL, NULL, NULL, -1))
        || !TEST_false(SSL_ech_set1_outer_server_name(NULL, NULL, -1))
        || !TEST_false(SSL_CTX_ech_set1_outer_alpn_protos(NULL, NULL, -1))
        || !TEST_false(SSL_ech_set1_outer_alpn_protos(NULL, NULL, -1))
        || !TEST_false(SSL_ech_set1_grease_suite(NULL, NULL))
        || !TEST_false(SSL_ech_set_grease_type(NULL, 0)))
        goto end;
    SSL_CTX_ech_set_callback(NULL, NULL);
    SSL_ech_set_callback(NULL, NULL);
    if (!TEST_false(SSL_ech_get1_retry_config(NULL, NULL, NULL))
        || !TEST_false(SSL_CTX_ech_raw_decrypt(NULL, NULL, NULL, NULL,
                                               NULL, 0, NULL, NULL,
                                               NULL, NULL))
        || !TEST_int_eq(SSL_ech_get1_status(NULL, &rinner, &router),
                        SSL_ECH_STATUS_FAILED))
        goto end;

    /* add an ECHConfigList with extensions to exercise init code */
    if (!TEST_ptr(es = OSSL_ECHSTORE_new(NULL, NULL))
        || !TEST_ptr(in = BIO_new(BIO_s_mem()))
        || !TEST_int_gt(BIO_write(in, bin_ok_exts, sizeof(bin_ok_exts)), 0)
        || !TEST_true(OSSL_ECHSTORE_read_echconfiglist(es, in))
        || !TEST_ptr(ctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method())))
        goto end;
    /* check status of SSL connection before OSSL_ECHSTORE set */
    if (!TEST_ptr(s = SSL_new(ctx))
        || !TEST_int_eq(SSL_ech_get1_status(s, NULL, NULL),
                        SSL_ECH_STATUS_FAILED)
        || !TEST_int_eq(SSL_ech_get1_status(s, &rinner, &router),
                        SSL_ECH_STATUS_NOT_CONFIGURED))
        goto end;
    SSL_set_options(s, SSL_OP_ECH_GREASE);
    if (!TEST_int_eq(SSL_ech_get1_status(s, &rinner, &router),
                     SSL_ECH_STATUS_GREASE))
        goto end;
    SSL_free(s);
    s = NULL; /* for some other tests */
    if (!TEST_true(SSL_CTX_set1_echstore(ctx, es)))
        goto end;
    if (!TEST_ptr((es1 = SSL_CTX_get1_echstore(ctx))))
        goto end;
    OSSL_ECHSTORE_free(es1);
    es1 = NULL;
    if (!TEST_false(SSL_set1_echstore(s, es)))
        goto end;
    /* do this one before SSL_new to exercise a bit of init code */
    if (!TEST_true(SSL_CTX_ech_set1_outer_alpn_protos(ctx, alpns, alpns_len)))
        goto end;
    s = SSL_new(ctx);
    if (!TEST_true(SSL_set1_echstore(s, es)))
        goto end;
    if (!TEST_ptr(es1 = SSL_get1_echstore(s)))
        goto end;
    OSSL_ECHSTORE_free(es1);
    es1 = NULL;
    if (!TEST_true(SSL_ech_set1_server_names(s, inner, outer, 0))
        || !TEST_true(SSL_ech_set1_outer_server_name(s, outer, 0))
        || !TEST_true(SSL_ech_set1_outer_alpn_protos(s, alpns, alpns_len))
        || !TEST_true(SSL_ech_set1_grease_suite(s, gsuite))
        || !TEST_true(SSL_ech_set_grease_type(s, gtype))
        || !TEST_true(SSL_ech_get1_retry_config(s, &rc, &rclen))
        || !TEST_false(rclen)
        || !TEST_ptr_eq(rc, NULL))
        goto end;
    SSL_CTX_ech_set_callback(ctx, test_cb);
    SSL_ech_set_callback(s, test_cb);

    /* all good */
    rv = 1;
end:
    BIO_free_all(in);
    OSSL_ECHSTORE_free(es1);
    OSSL_ECHSTORE_free(es);
    SSL_CTX_free(ctx);
    SSL_free(s);
    return rv;
}

/*
 * Test boringssl compatibility API. We don't need exhaustive
 * tests here as this is a simple enough wrapper on things
 * tested elsewhere.
 */
static int ech_boring_compat(void)
{
    int rv = 0;
    SSL_CTX *ctx = NULL;
    SSL *s = NULL;

    if (!TEST_false(SSL_set1_ech_config_list(NULL, NULL, 0))
        || !TEST_ptr(ctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method()))
        || !TEST_ptr(s = SSL_new(ctx))
        || !TEST_true(SSL_set1_ech_config_list(s, NULL, 0))
        || !TEST_true(SSL_set1_ech_config_list(s, (uint8_t *)b64_pk1,
                                               sizeof(b64_pk1) - 1))
        || !TEST_true(SSL_set1_ech_config_list(s, (uint8_t *)bin_6_to_3,
                                               sizeof(bin_6_to_3)))
        /* test a fail */
        || !TEST_false(SSL_set1_ech_config_list(s, (uint8_t *)b64_pk1,
                                                sizeof(b64_pk1) - 2)))
        goto end;
    rv = 1;
end:
    SSL_CTX_free(ctx);
    SSL_free(s);
    return rv;
}

/* values that can be used in helper below */
# define OSSL_ECH_TEST_BASIC    0
# define OSSL_ECH_TEST_HRR      1
# define OSSL_ECH_TEST_EARLY    2
# define OSSL_ECH_TEST_CUSTOM   3
# define OSSL_ECH_TEST_ENOE     4 /* early + no-ech */
/* note: early-data is prohibited after HRR so no tests for that */

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
 * values above.
 */
static int test_ech_roundtrip_helper(int idx, int combo)
{
    int res = 0, kemind, kdfind, aeadind, kemsz, kdfsz, aeadsz;
    int clientstatus, serverstatus, server = 1, client = 0;
    unsigned int context;
    OSSL_ECHSTORE *es = NULL;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    uint16_t ech_version = OSSL_ECH_CURRENT_VERSION;
    uint8_t max_name_length = 0;
    char *public_name = "example.com", suitestr[100];
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    SSL_SESSION *sess = NULL;
    size_t written = 0, readbytes = 0;
    unsigned char ed[21], buf[1024];

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
    if (!TEST_true(OSSL_HPKE_str2suite(suitestr, &hpke_suite))
        || !TEST_ptr(es = OSSL_ECHSTORE_new(libctx, propq))
        || !TEST_true(OSSL_ECHSTORE_new_config(es, ech_version, max_name_length,
                                               public_name, hpke_suite))
        || !TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                          TLS_client_method(),
                                          TLS1_3_VERSION, TLS1_3_VERSION,
                                          &sctx, &cctx, cert, privkey)))
        goto end;
    if (combo == OSSL_ECH_TEST_EARLY || combo == OSSL_ECH_TEST_ENOE) {
        if (!TEST_true(SSL_CTX_set_options(sctx, SSL_OP_NO_ANTI_REPLAY))
            || !TEST_true(SSL_CTX_set_max_early_data(sctx,
                                                     SSL3_RT_MAX_PLAIN_LENGTH))
            || !TEST_true(SSL_CTX_set_recv_max_early_data(sctx,
                                                          SSL3_RT_MAX_PLAIN_LENGTH)))
            goto end;
    }
    if (combo == OSSL_ECH_TEST_CUSTOM) {
        context = SSL_EXT_CLIENT_HELLO; /* add custom CH ext to client/server */
        if (!TEST_true(SSL_CTX_add_custom_ext(cctx, TEST_EXT_TYPE1, context,
                                              new_add_cb, new_free_cb,
                                              &client, new_parse_cb, &client))
            || !TEST_true(SSL_CTX_add_custom_ext(sctx, TEST_EXT_TYPE1, context,
                                                 new_add_cb, new_free_cb,
                                                 &server, new_parse_cb, &server))
            || !TEST_true(SSL_CTX_add_custom_ext(cctx, TEST_EXT_TYPE2, context,
                                                 new_add_cb, NULL,
                                                 &client, NULL, &client))
            || !TEST_true(SSL_CTX_add_custom_ext(sctx, TEST_EXT_TYPE2, context,
                                                 new_add_cb, NULL,
                                                 &server, NULL, &server)))
            goto end;
    }
    if (combo != OSSL_ECH_TEST_ENOE
        && !TEST_true(SSL_CTX_set1_echstore(cctx, es)))
        goto end;
    if (!TEST_true(SSL_CTX_set1_echstore(sctx, es))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
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
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get1_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s", clientstatus, cinner, couter);
    serverstatus = SSL_ech_get1_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s", serverstatus, sinner, souter);
    if (combo != OSSL_ECH_TEST_ENOE 
        && !TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    if (combo == OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(serverstatus, SSL_ECH_STATUS_NOT_TRIED))
        goto end;
    if (combo != OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    if (combo == OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(clientstatus, SSL_ECH_STATUS_NOT_CONFIGURED))
        goto end;
    /* all good */
    if (combo == OSSL_ECH_TEST_BASIC || combo == OSSL_ECH_TEST_HRR
        || combo == OSSL_ECH_TEST_CUSTOM) {
        res = 1;
        goto end;
    }
    /* continue for EARLY test */
    if (combo != OSSL_ECH_TEST_EARLY && combo != OSSL_ECH_TEST_ENOE)
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
                                      &clientssl, NULL, NULL))
        || !TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example"))
        || !TEST_true(SSL_set_session(clientssl, sess))
        || !TEST_true(SSL_write_early_data(clientssl, ed, sizeof(ed), &written))
        || !TEST_size_t_eq(written, sizeof(ed))
        || !TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                            &readbytes),
                        SSL_READ_EARLY_DATA_SUCCESS)
        || !TEST_size_t_eq(written, readbytes))
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
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get1_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s", clientstatus, cinner, couter);
    serverstatus = SSL_ech_get1_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s", serverstatus, sinner, souter);
    if (combo != OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(serverstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    if (combo == OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(serverstatus, SSL_ECH_STATUS_NOT_TRIED))
        goto end;
    if (combo != OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(clientstatus, SSL_ECH_STATUS_SUCCESS))
        goto end;
    if (combo == OSSL_ECH_TEST_ENOE
        && !TEST_int_eq(clientstatus, SSL_ECH_STATUS_NOT_CONFIGURED))
        goto end;
    /* all good */
    res = 1;
end:
    OSSL_ECHSTORE_free(es);
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

/* Test a roundtrip with No ECH, and early data */
static int ech_enoe_test(int idx)
{
    if (verbose)
        TEST_info("Doing: ech_no ech + early test ");
    return test_ech_roundtrip_helper(idx, OSSL_ECH_TEST_ENOE);
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
    ADD_ALL_TESTS(ech_ingest_test, OSSL_NELEM(ingest_tvs));
    ADD_TEST(ech_store_null_calls);
    ADD_ALL_TESTS(ech_test_file_read, OSSL_NELEM(fnames));
    ADD_TEST(ech_api_basic_calls);
    ADD_TEST(ech_boring_compat);
    suite_combos = OSSL_NELEM(kem_str_list) * OSSL_NELEM(kdf_str_list)
        * OSSL_NELEM(aead_str_list);
    ADD_ALL_TESTS(test_ech_suites, suite_combos);
    ADD_ALL_TESTS(test_ech_hrr, suite_combos);
    ADD_ALL_TESTS(test_ech_early, suite_combos);
    ADD_ALL_TESTS(ech_custom_test, suite_combos);
    ADD_ALL_TESTS(ech_enoe_test, suite_combos);
    /* TODO(ECH): add more test code as other PRs done */
    return 1;
err:
    return 0;
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(rootcert);
#endif
}
