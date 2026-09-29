/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/objects.h>
#include <openssl/x509.h>

#include "crypto/mtc_cert.h"
#include "internal/nelem.h"
#include "testutil.h"

/*
 * Experimentation OID for id-alg-mtcProof used by the test certificates (the
 * standardised OID is not yet assigned).
 */
#define MTC_ALG_OID "1.3.6.1.4.1.44363.47.0"

static const char *certs_dir = NULL;

/*
 * Load the certificate named `name`, confirm its signatureAlgorithm is
 * id-alg-mtcProof, and return the signatureValue (the MTCProof) bytes.  On
 * success *cert is set and owned by the caller; the returned span references
 * it.
 */
static int get_mtcproof(const char *name, X509 **cert, const uint8_t **data,
    size_t *len)
{
    char *path = NULL;
    const ASN1_BIT_STRING *sig = NULL;
    const X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *alg_obj = NULL;
    ASN1_OBJECT *mtc_obj = NULL;
    int ret = 0;

    *cert = NULL;
    if (!TEST_ptr(path = test_mk_file_path(certs_dir, name))
        || !TEST_ptr(*cert = load_cert_pem(path, NULL)))
        goto err;

    X509_get0_signature(&sig, &alg, *cert);
    X509_ALGOR_get0(&alg_obj, NULL, NULL, alg);
    if (!TEST_ptr(mtc_obj = OBJ_txt2obj(MTC_ALG_OID, 1))
        || !TEST_int_eq(OBJ_cmp(alg_obj, mtc_obj), 0))
        goto err;

    *data = ASN1_STRING_get0_data(sig);
    *len = ASN1_STRING_get_length(sig);
    ret = 1;
err:
    if (!ret) {
        X509_free(*cert);
        *cert = NULL;
    }
    ASN1_OBJECT_free(mtc_obj);
    OPENSSL_free(path);
    return ret;
}

/* One expected cosignature. */
struct cosig_expect {
    const uint8_t *id;
    size_t id_len;
    size_t sig_len;
};

/*
 * A certificate whose MTCProof is well-formed: check the decoded subtree, and
 * that the cosignatures are exactly those in exp.
 */
static int check_valid(const char *name, uint64_t exp_start, uint64_t exp_end,
    size_t exp_ext_len, size_t exp_incl_len,
    const struct cosig_expect *exp, size_t nexp)
{
    X509 *cert = NULL;
    const uint8_t *data = NULL;
    size_t len = 0, count = 0, i;
    OSSL_MTC_PROOF proof;
    OSSL_MTC_COSIGNATURE cosig[8];
    int ret = 0;

    if (!get_mtcproof(name, &cert, &data, &len))
        return 0;

    if (!TEST_true(ossl_mtc_proof_parse(data, len, &proof))
        || !TEST_uint64_t_eq(proof.start, exp_start)
        || !TEST_uint64_t_eq(proof.end, exp_end)
        || !TEST_size_t_eq(proof.extensions_len, exp_ext_len)
        || !TEST_size_t_eq(proof.inclusion_proof_len, exp_incl_len))
        goto err;

    if (!TEST_true(ossl_mtc_proof_get_cosignatures(&proof, cosig,
            OSSL_NELEM(cosig), &count))
        || !TEST_size_t_eq(count, nexp))
        goto err;

    for (i = 0; i < nexp; i++)
        if (!TEST_mem_eq(cosig[i].cosigner_id, cosig[i].cosigner_id_len,
                exp[i].id, exp[i].id_len)
            || !TEST_size_t_eq(cosig[i].signature_len, exp[i].sig_len))
            goto err;

    ret = 1;
err:
    X509_free(cert);
    return ret;
}

/* A certificate whose MTCProof is structurally invalid: parsing must fail. */
static int check_parse_fails(const char *name)
{
    X509 *cert = NULL;
    const uint8_t *data = NULL;
    size_t len = 0;
    OSSL_MTC_PROOF proof;
    int ret = 0;

    if (!get_mtcproof(name, &cert, &data, &len))
        return 0;
    if (!TEST_false(ossl_mtc_proof_parse(data, len, &proof)))
        goto err;
    ret = 1;
err:
    X509_free(cert);
    return ret;
}

/* Subtree [0, 10), no cosignatures (landmark-relative leaf). */
static int test_landmark_relative(void)
{
    return check_valid("mtc-leaf.pem", 0, 10, 0, 128, NULL, 0);
}

/* Intermediate issued by the MTC CA; also landmark-relative here. */
static int test_intermediate(void)
{
    return check_valid("mtc-ica.pem", 0, 10, 0, 128, NULL, 0);
}

/* The cosigner IDs the fixtures use, 32473.0 through 32473.2. */
static const uint8_t cosigner_0[] = { 0x81, 0xfd, 0x59, 0x00 };
static const uint8_t cosigner_1[] = { 0x81, 0xfd, 0x59, 0x01 };
static const uint8_t cosigner_2[] = { 0x81, 0xfd, 0x59, 0x02 };

/* Standalone leaf with one ML-DSA-44 cosignature from the CA cosigner. */
static int test_standalone(void)
{
    static const struct cosig_expect exp[] = {
        { cosigner_1, sizeof(cosigner_1), 2420 }
    };

    return check_valid("mtc-leaf-standalone.pem", 0, 10, 0, 128, exp,
        OSSL_NELEM(exp));
}

/* Standalone leaf with three ascending cosignatures (32473.0/.1/.2). */
static int test_three_cosigners(void)
{
    static const struct cosig_expect exp[] = {
        { cosigner_0, sizeof(cosigner_0), 2420 },
        { cosigner_1, sizeof(cosigner_1), 2420 },
        { cosigner_2, sizeof(cosigner_2), 2420 }
    };

    return check_valid("mtc-leaf-standalone-3cosigners.pem", 0, 10, 0, 128, exp,
        OSSL_NELEM(exp));
}

/*
 * A single cosignature that is not from the CA cosigner.  This is
 * structurally valid at the parsing layer (the CA-signature requirement is a
 * verification-time check, not a parsing one).
 */
static int test_no_ca_signer(void)
{
    static const struct cosig_expect exp[] = {
        { cosigner_0, sizeof(cosigner_0), 2420 }
    };

    return check_valid("mtc-leaf-standalone-no_ca_signer.pem", 0, 10, 0, 128,
        exp, OSSL_NELEM(exp));
}

/* Cosignatures not in ascending cosigner_id order: parsing must fail. */
static int test_cosigners_out_of_order(void)
{
    return check_parse_fails("mtc-leaf-standalone-cosigner_wrong_order.pem");
}

/* Duplicate cosigner_id: parsing must fail. */
static int test_cosigners_duplicate(void)
{
    return check_parse_fails("mtc-leaf-standalone-duplicate_ca_signer.pem");
}

/* MTCProof with an extra trailing byte: parsing must fail. */
static int test_proof_trailing_byte(void)
{
    return check_parse_fails("mtc-leaf-standalone-trailing.pem");
}

/* MTCProof truncated by one byte: parsing must fail. */
static int test_proof_truncated(void)
{
    return check_parse_fails("mtc-leaf-standalone-truncated.pem");
}

/*-
 * The proofs below are assembled here rather than carried in certificates: the
 * signatureValue is opaque and covered by no signature, so any byte string
 * reaches the parser, including ones no editing of a real proof produces.
 *
 * A well-formed proof is
 *   00 00                 extensions, empty
 *   00 00 00 00 00 00     start = 0
 *   00 00 00 00 00 0a     end = 10
 *   00 00                 inclusion_proof, empty
 *   00 00 00              signatures, empty
 * and a cosignature is a one-byte-prefixed cosigner_id followed by a
 * two-byte-prefixed signature, so "01 01 00 00" is cosigner 0x01 with an empty
 * signature.
 */

/* Subtree [0, 10), nothing else: the smallest well-formed proof. */
static const uint8_t proof_minimal[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x00
};

/* The same, with one byte more than the structure accounts for. */
static const uint8_t proof_trailing[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x00,
    0x00
};

/* An empty subtree, start == end. */
static const uint8_t proof_empty_subtree[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x00
};

/* An inverted subtree, end < start. */
static const uint8_t proof_inverted_subtree[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00, 0x00
};

/* An extensions length that runs past the end of the input. */
static const uint8_t proof_extensions_overrun[] = {
    0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x00
};

/* A signatures length that claims more than the bytes present. */
static const uint8_t proof_signatures_overrun[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00
};

/* A cosigner_id of length zero, which TrustAnchorID<1..2^8-1> forbids. */
static const uint8_t proof_empty_cosigner_id[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x03, 0x00, 0x00, 0x00
};

/* Cosigners 0x01 and 0x02, correctly ordered. */
static const uint8_t proof_two_cosigners[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00
};

/* The same cosigner twice. */
static const uint8_t proof_duplicate_cosigners[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00
};

/* Cosigners 0x02 then 0x01: equal lengths, descending. */
static const uint8_t proof_unordered_cosigners[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x08, 0x01, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00
};

/* Cosigner 0x01 then 0x01 0x00: the shorter id sorts first, so this is fine. */
static const uint8_t proof_length_ordered_cosigners[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00,
    0x00, 0x00, 0x09, 0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00
};

/* Parse each of the above, checking only whether it is accepted. */
static int test_parse_synthetic(void)
{
    static const struct {
        const char *desc;
        const uint8_t *proof;
        size_t len;
        int expected;
    } cases[] = {
        { "minimal", proof_minimal, sizeof(proof_minimal), 1 },
        { "empty input", proof_minimal, 0, 0 },
        { "truncated", proof_minimal, sizeof(proof_minimal) - 1, 0 },
        { "trailing byte", proof_trailing, sizeof(proof_trailing), 0 },
        { "empty subtree", proof_empty_subtree,
            sizeof(proof_empty_subtree), 0 },
        { "inverted subtree", proof_inverted_subtree,
            sizeof(proof_inverted_subtree), 0 },
        { "extensions overrun", proof_extensions_overrun,
            sizeof(proof_extensions_overrun), 0 },
        { "signatures overrun", proof_signatures_overrun,
            sizeof(proof_signatures_overrun), 0 },
        { "empty cosigner_id", proof_empty_cosigner_id,
            sizeof(proof_empty_cosigner_id), 0 },
        { "two cosigners", proof_two_cosigners,
            sizeof(proof_two_cosigners), 1 },
        { "duplicate cosigners", proof_duplicate_cosigners,
            sizeof(proof_duplicate_cosigners), 0 },
        { "unordered cosigners", proof_unordered_cosigners,
            sizeof(proof_unordered_cosigners), 0 },
        { "length-ordered cosigners", proof_length_ordered_cosigners,
            sizeof(proof_length_ordered_cosigners), 1 }
    };
    OSSL_MTC_PROOF proof;
    size_t i;
    int ret = 1;

    for (i = 0; i < OSSL_NELEM(cases); i++) {
        if (!TEST_int_eq(ossl_mtc_proof_parse(cases[i].proof, cases[i].len,
                             &proof),
                cases[i].expected)) {
            TEST_info("case: %s", cases[i].desc);
            ret = 0;
        }
    }
    return ret;
}

/* The two-pass contract of ossl_mtc_proof_get_cosignatures(). */
static int test_cosignature_passes(void)
{
    static const uint8_t first[] = { 0x01 }, second[] = { 0x02 };
    OSSL_MTC_PROOF proof;
    OSSL_MTC_COSIGNATURE cosig[2];
    size_t count = 0;

    if (!TEST_true(ossl_mtc_proof_parse(proof_two_cosigners,
            sizeof(proof_two_cosigners), &proof)))
        return 0;

    /* Counting takes no array. */
    if (!TEST_true(ossl_mtc_proof_get_cosignatures(&proof, NULL, 0, &count))
        || !TEST_size_t_eq(count, 2))
        return 0;

    /* An array smaller than the count fails and writes nothing. */
    count = 0;
    if (!TEST_false(ossl_mtc_proof_get_cosignatures(&proof, cosig, 1, &count))
        || !TEST_size_t_eq(count, 0))
        return 0;

    if (!TEST_true(ossl_mtc_proof_get_cosignatures(&proof, cosig,
            OSSL_NELEM(cosig), &count))
        || !TEST_size_t_eq(count, 2)
        || !TEST_mem_eq(cosig[0].cosigner_id, cosig[0].cosigner_id_len,
            first, sizeof(first))
        || !TEST_mem_eq(cosig[1].cosigner_id, cosig[1].cosigner_id_len,
            second, sizeof(second))
        || !TEST_size_t_eq(cosig[0].signature_len, 0))
        return 0;
    return 1;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certs_dir = test_get_argument(0)))
        return 0;

    ADD_TEST(test_landmark_relative);
    ADD_TEST(test_intermediate);
    ADD_TEST(test_standalone);
    ADD_TEST(test_three_cosigners);
    ADD_TEST(test_no_ca_signer);
    ADD_TEST(test_cosigners_out_of_order);
    ADD_TEST(test_cosigners_duplicate);
    ADD_TEST(test_proof_trailing_byte);
    ADD_TEST(test_proof_truncated);
    ADD_TEST(test_parse_synthetic);
    ADD_TEST(test_cosignature_passes);
    return 1;
}
