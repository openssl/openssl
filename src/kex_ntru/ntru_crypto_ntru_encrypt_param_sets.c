/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

/******************************************************************************
 *
 * File: ntru_crypto_ntru_encrypt_param_sets.c
 *
 * Contents: Defines the NTRUEncrypt parameter sets.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"

/* parameter sets */

static NTRU_ENCRYPT_PARAM_SET ntruParamSets[] = {

    {
        NTRU_EES401EP1,              /* parameter-set id */
        "ees401ep1",                 /* human readable param set name */
        {0x00, 0x02, 0x04},          /* OID */
        0x22,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        14,                          /* security strength in octets */
        14,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        113,                         /* df, dr */
        133,                         /* dg */
        60,                          /* maxMsgLenBytes */
        113,                         /* dm0 */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        41,                          /* min. no. of hash calls for IGF-2 */
        7,                           /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES449EP1,              /* parameter-set id */
        "ees449ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x03},          /* OID */
        0x23,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        449,                         /* N */
        16,                          /* security strength in octets */
        16,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        134,                         /* df, dr */
        149,                         /* dg */
        67,                          /* maxMsgLenBytes */
        134,                         /* dm0 */
        449,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        1,                           /* lLen */
        47,                          /* min. no. of hash calls for IGF-2 */
        8,                           /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES677EP1,                /* parameter-set id */
        "ees677ep1",                   /* human readable param set name */
        {0x00, 0x05, 0x03},            /* OID */
        0x24,                          /* DER id */
        10,                            /* no. of bits in N (i.e., in an index) */
        677,                           /* N */
        24,                            /* security strength in octets */
        24,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        FALSE,                         /* product form */
        157,                           /* df, dr */
        225,                           /* dg */
        101,                           /* maxMsgLenBytes */
        157,                           /* dm0 */
        2031,                          /* 2^c - (2^c mod N) */
        11,                            /* c */
        1,                             /* lLen */
        32,                            /* min. no. of hash calls for IGF-2 */
        8,                             /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES1087EP2,               /* parameter-set id */
        "ees1087ep2",                  /* human readable param set name */
        {0x00, 0x06, 0x03},            /* OID */
        0x25,                          /* DER id */
        11,                            /* no. of bits in N (i.e., in an index) */
        1087,                          /* N */
        32,                            /* security strength in octets */
        32,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        FALSE,                         /* product form */
        120,                           /* df, dr */
        362,                           /* dg */
        170,                           /* maxMsgLenBytes */
        120,                           /* dm0 */
        7609,                          /* 2^c - (2^c mod N) */
        13,                            /* c */
        1,                             /* lLen */
        27,                            /* min. no. of hash calls for IGF-2 */
        11,                            /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES541EP1,              /* parameter-set id */
        "ees541ep1",                 /* human readable param set name */
        {0x00, 0x02, 0x05},          /* OID */
        0x26,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        541,                         /* N */
        14,                          /* security strength in octets */
        14,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        49,                          /* df, dr */
        180,                         /* dg */
        86,                          /* maxMsgLenBytes */
        49,                          /* dm0 */
        3787,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        16,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES613EP1,              /* parameter-set id */
        "ees613ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x04},          /* OID */
        0x27,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        613,                         /* N */
        16,                          /* securuity strength in octets */
        16,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        55,                          /* df, dr */
        204,                         /* dg */
        97,                          /* maxMsgLenBytes */
        55,                          /* dm0 */
        1839,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        18,                          /* min. no. of hash calls for IGF-2 */
        10,                          /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES887EP1,                /* parameter-set id */
        "ees887ep1",                   /* human readable param set name */
        {0x00, 0x05, 0x04},            /* OID */
        0x28,                          /* DER id */
        10,                            /* no. of bits in N (i.e., in an index) */
        887,                           /* N */
        24,                            /* security strength in octets */
        24,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        FALSE,                         /* product form */
        81,                            /* df, dr */
        295,                           /* dg */
        141,                           /* maxMsgLenBytes */
        81,                            /* dm0 */
        887,                           /* 2^c - (2^c mod N) */
        10,                            /* c */
        1,                             /* lLen */
        16,                            /* min. no. of hash calls for IGF-2 */
        9,                             /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES1171EP1,               /* parameter-set id */
        "ees1171ep1",                  /* human readable param set name */
        {0x00, 0x06, 0x04},            /* OID */
        0x29,                          /* DER id */
        11,                            /* no. of bits in N (i.e., in an index) */
        1171,                          /* N */
        32,                            /* security strength in octets */
        32,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        FALSE,                         /* product form */
        106,                           /* df, dr */
        390,                           /* dg */
        186,                           /* maxMsgLenBytes */
        106,                           /* dm0 */
        3513,                          /* 2^c - (2^c mod N) */
        12,                            /* c */
        1,                             /* lLen */
        25,                            /* min. no. of hash calls for IGF-2 */
        12,                            /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES659EP1,              /* parameter-set id */
        "ees659ep1",                 /* human readable param set name */
        {0x00, 0x02, 0x06},          /* OID */
        0x2a,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        659,                         /* N */
        14,                          /* security strength in octets */
        14,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        38,                          /* df, dr */
        219,                         /* dg */
        108,                         /* maxMsgLenBytes */
        38,                          /* dm0 */
        1977,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        11,                          /* min. no. of hash calls for IGF-2 */
        10,                          /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES761EP1,              /* parameter-set id */
        "ees761ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x05},          /* OID */
        0x2b,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        761,                         /* N */
        16,                          /* security strength in octets */
        16,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        42,                          /* df, dr */
        253,                         /* dg */
        125,                         /* maxMsgLenBytes */
        42,                          /* dm0 */
        3805,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        14,                          /* min. no. of hash calls for IGF-2 */
        12,                          /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES1087EP1,               /* parameter-set id */
        "ees1087ep1",                  /* human readable param set name */
        {0x00, 0x05, 0x05},            /* OID */
        0x2c,                          /* DER id */
        11,                            /* no. of bits in N (i.e., in an index) */
        1087,                          /* N */
        24,                            /* security strength in octets */
        24,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        FALSE,                         /* product form */
        63,                            /* df, dr */
        362,                           /* dg */
        178,                           /* maxMsgLenBytes */
        63,                            /* dm0 */
        7609,                          /* 2^c - (2^c mod N) */
        13,                            /* c */
        1,                             /* lLen */
        14,                            /* min. no. of hash calls for IGF-2 */
        11,                            /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES1499EP1,               /* parameter-set id */
        "ees1499ep1",                  /* human readable param set name */
        {0x00, 0x06, 0x05},            /* OID */
        0x2d,                          /* DER id */
        11,                            /* no. of bits in N (i.e., in an index) */
        1499,                          /* N */
        32,                            /* security strength in octets */
        32,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        FALSE,                         /* product form */
        79,                            /* df, dr */
        499,                           /* dg */
        247,                           /* maxMsgLenBytes */
        79,                            /* dm0 */
        7495,                          /* 2^c - (2^c mod N) */
        13,                            /* c */
        1,                             /* lLen */
        18,                            /* min. no. of hash calls for IGF-2 */
        14,                            /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES401EP2,              /* parameter-set id */
        "ees401ep2",                 /* human readable param set name */
        {0x00, 0x02, 0x10},          /* OID */
        0x2e,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        14,                          /* security strength in octets */
        14,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (6 << 16),    /* df, dr */
        133,                         /* dg */
        60,                          /* maxMsgLenBytes */
        101,                         /* dm0 */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        7,                           /* min. no. of hash calls for IGF-2 */
        7,                           /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES439EP1,              /* parameter-set id */
        "ees439ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x10},          /* OID */
        0x2f,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        439,                         /* N */
        16,                          /* security strength in octets */
        16,                          /* no. of octets for random string b */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        9 + (8 << 8) + (5 << 16),    /* df, dr */
        146,                         /* dg */
        65,                          /* maxMsgLenBytes */
        112,                         /* dm0 */
        439,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        1,                           /* lLen */
        8,                           /* min. no. of hash calls for IGF-2 */
        8,                           /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA1, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES593EP1,                /* parameter-set id */
        "ees593ep1",                   /* human readable param set name */
        {0x00, 0x05, 0x10},            /* OID */
        0x30,                          /* DER id */
        10,                            /* no. of bits in N (i.e., in an index) */
        593,                           /* N */
        24,                            /* security strength in octets */
        24,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        TRUE,                          /* product form */
        10 + (10 << 8) + (8 << 16),    /* df, dr */
        197,                           /* dg */
        86,                            /* maxMsgLenBytes */
        158,                           /* dm0 */
        1779,                          /* 2^c - (2^c mod N) */
        11,                            /* c */
        1,                             /* lLen */
        9,                             /* min. no. of hash calls for IGF-2 */
        7,                             /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES743EP1,                /* parameter-set id */
        "ees743ep1",                   /* human readable param set name */
        {0x00, 0x06, 0x10},            /* OID */
        0x31,                          /* DER id */
        10,                            /* no. of bits in N (i.e., in an index) */
        743,                           /* N */
        32,                            /* security strength in octets */
        32,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        TRUE,                          /* product form */
        11 + (11 << 8) + (15 << 16),   /* df, dr */
        247,                           /* dg */
        106,                           /* maxMsgLenBytes */
        204,                           /* dm0 */
        8173,                          /* 2^c - (2^c mod N) */
        13,                            /* c */
        1,                             /* lLen */
        9,                             /* min. no. of hash calls for IGF-2 */
        9,                             /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES443EP1,                /* parameter-set id */
        "ees443ep1",                   /* human readable param set name */
        {0x00, 0x03, 0x11},            /* OID */
        0x32,                          /* DER id */
        9,                             /* no. of bits in N (i.e., in an index) */
        443,                           /* N */
        16,                            /* security strength in octets */
        32,                            /* no. of octets for random string b */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        TRUE,                          /* product form */
        9 + (8 << 8) + (5 << 16),      /* df, dr */
        148,                           /* dg */
        49,                            /* maxMsgLenBytes */
        115,                           /* dm0 */
        443,                           /* 2^c - (2^c mod N) */
        9,                             /* c */
        1,                             /* lLen */
        5,                             /* min. no. of hash calls for IGF-2 */
        5,                             /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                        HMAC-DRBG, etc. */
    },

    {
        NTRU_EES587EP1,                /* parameter-set id */
        "ees587ep1",                   /* human readable param set name */
        {0x00, 0x05, 0x11},            /* OID */
        0x33,                          /* DER id */
        10,                            /* no. of bits in N (i.e., in an index) */
        587,                           /* N */
        24,                            /* security strength in octets */
        32,                            /* no. of octets for random string b  */
        2048,                          /* q */
        11,                            /* no. of bits in q (i.e., in a coeff) */
        TRUE,                          /* product form */
        10 + (10 << 8) + (8 << 16),    /* df, dr */
        196,                           /* dg */
        76,                            /* maxMsgLenBytes */
        157,                           /* dm0 */
        1761,                          /* 2^c - (2^c mod N) */
        11,                            /* c */
        1,                             /* lLen */
        7,                             /* min. no. of hash calls for IGF-2 */
        7,                             /* min. no. of hash calls for MGF-TP-1 */
        NTRU_CRYPTO_HASH_ALGID_SHA256, /* hash function for MGF-TP-1,
                                           HMAC-DRBG, etc. */
    },
};

static size_t numParamSets =
    sizeof(ntruParamSets) / sizeof(NTRU_ENCRYPT_PARAM_SET);

/* functions */

/* ntru_encrypt_get_params_with_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id) /*  in - parameter-set id */
{
	size_t i;

	for (i = 0; i < numParamSets; i++) {
		if (ntruParamSets[i].id == id) {
			return &(ntruParamSets[i]);
		}
	}

	return NULL;
}

/* ntru_encrypt_get_params_with_OID
 *
 * Looks up a set of NTRUEncrypt parameters based on the OID of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_OID(
    uint8_t const *oid) /*  in - pointer to parameter-set OID */
{
	size_t i;

	for (i = 0; i < numParamSets; i++) {
		if (!memcmp(ntruParamSets[i].OID, oid, 3)) {
			return &(ntruParamSets[i]);
		}
	}

	return NULL;
}

/* ntru_encrypt_get_params_with_DER_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the DER id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_DER_id(
    uint8_t der_id) /*  in - parameter-set DER id */
{
	size_t i;

	for (i = 0; i < numParamSets; i++) {
		if (ntruParamSets[i].der_id == der_id) {
			return &(ntruParamSets[i]);
		}
	}
	return NULL;
}

const char *
ntru_encrypt_get_param_set_name(
    NTRU_ENCRYPT_PARAM_SET_ID id) /*  in - parameter-set id */
{
	size_t i;

	for (i = 0; i < numParamSets; i++) {
		if (ntruParamSets[i].id == id) {
			return ntruParamSets[i].name;
		}
	}

	return NULL;
}
