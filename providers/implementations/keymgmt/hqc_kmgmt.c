/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/self_test.h>
#include <openssl/param_build.h>
#include <openssl/cms.h>
#include "crypto/hqc_kem.h"
#include "internal/fips.h"
#include "internal/param_build_set.h"
#include "internal/sizes.h"
#include "internal/endian.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include "providers/implementations/keymgmt/hqc_kmgmt.inc"

static OSSL_FUNC_keymgmt_new_fn hqc_kem_128_new;
static OSSL_FUNC_keymgmt_new_fn hqc_kem_192_new;
static OSSL_FUNC_keymgmt_new_fn hqc_kem_256_new;
static OSSL_FUNC_keymgmt_gen_fn hqc_kem_gen;
static OSSL_FUNC_keymgmt_gen_init_fn hqc_kem_128_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn hqc_kem_192_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn hqc_kem_256_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn hqc_kem_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn hqc_kem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn hqc_kem_gen_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn hqc_kem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn hqc_kem_gettable_params;
static OSSL_FUNC_keymgmt_has_fn hqc_key_has;
static OSSL_FUNC_keymgmt_match_fn hqc_key_match;
static OSSL_FUNC_keymgmt_validate_fn hqc_kem_validate;
static OSSL_FUNC_keymgmt_import_fn hqc_kem_import;
static OSSL_FUNC_keymgmt_export_fn hqc_key_export;
static OSSL_FUNC_keymgmt_import_types_fn hqc_kem_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn hqc_kem_imexport_types;
static OSSL_FUNC_keymgmt_dup_fn hqc_kem_dup;

static int xof_get_bytes(EVP_MD_CTX *xof_ctx, uint8_t *output, uint32_t output_size);
static int hqc_sample_xof(EVP_MD_CTX *md_ctx, uint64_t *vec, const HQC_VARIANT_INFO *info);
/**
 * @def HQC_PRNG_DOMAIN_SEP
 * @brief Domain separation constant for the HQC PRNG (Pseudo-Random
 *        Number Generator).
 *
 * Used to distinguish the PRNG context from other cryptographic
 * primitives in HQC operations, ensuring unique input domains for
 * hashing or seed expansion functions.
 */
#define HQC_PRNG_DOMAIN_SEP 0

/**
 * @def HQC_XOF_SEP
 * @brief Domain separation constant for the HQC XOF (eXtendable Output
 *        Function).
 *
 * Ensures that XOF operations are cryptographically independent from
 * PRNG and other HQC domains by providing a unique separation value.
 */
#define HQC_XOF_SEP 1

/**
 * @def HQC_I_DOMAIN_SEP
 * @brief Domain separation constant for HQC intermediate computations.
 *
 * Used to separate internal or intermediate values from other HQC
 * function domains, preventing collisions or cross-domain reuse of
 * data in cryptographic processes.
 */
#define HQC_I_DOMAIN_SEP 2

/**
 * @def KARATSUBA_THRESHOLD
 * @brief Threshold for switching to the Karatsuba multiplication
 *        algorithm.
 *
 * When the operand size (in coefficients, words, or bits—depending on
 * context) exceeds this threshold, the Karatsuba multiplication method
 * is used instead of the standard (schoolbook) multiplication.
 *
 * This value balances performance and overhead: smaller sizes use
 * simpler algorithms to reduce setup cost, while larger sizes benefit
 * from Karatsuba’s reduced asymptotic complexity.
 */
#define KARATSUBA_THRESHOLD 16

/**
 * @def SEED_BYTES
 * @brief define the length of the seed used for key generation
 *
 * All variants of HQC use the same seed size when generating keys
 * Define that value here
 */
#define SEED_BYTES 32

/**
 * @def VEC_SIZE(a, b)
 * @brief Computes the number of elements of size @p b required to store
 *        @p a units.
 *
 * This macro performs ceiling division of @p a by @p b, effectively
 * returning the smallest integer greater than or equal to (a / b).
 * Commonly used to determine the number of words or vector blocks
 * needed to hold a certain number of bits or bytes.
 *
 * @param a Total size (e.g., number of bits or bytes).
 * @param b Unit size (e.g., bits or bytes per word).
 * @return The number of full units of size @p b needed to store @p a.
 */
#define VEC_SIZE(a, b) (((a) / (b)) + ((a) % (b) == 0 ? 0 : 1))

/**
 * @def VEC_BITMASK(a, s)
 * @brief Generates a bitmask for the remainder bits of @p a relative to
 *        size @p s.
 *
 * This macro produces a mask with the lowest (a % s) bits set to 1 and
 * the remaining bits cleared. It is typically used to isolate or
 * operate on the trailing bits of a partially filled vector or word.
 *
 * @param a Bit index or size value.
 * @param s Word or vector size in bits.
 * @return A bitmask with (a % s) least significant bits set.
 */
#define VEC_BITMASK(a, s) ((1ULL << (a % s)) - 1)

/**
 * @var variant_info
 * @brief Static table containing parameter sets for supported HQC KEM
 *        variants.
 *
 * Each entry defines the configuration parameters for a specific HQC
 * (Hamming Quasi-Cyclic) Key Encapsulation Mechanism variant identified
 * by its EVP_PKEY_HQC_KEM_* type.
 *
 * The fields specify algorithm-specific constants used for key and
 * ciphertext sizes, as well as cryptographic parameters controlling
 * performance and security levels.
 *
 * | Field                | Description |
 * |----------------------|-------------|
 * | type                 | HQC key type identifier (e.g., EVP_PKEY_HQC_KEM_128). |
 * | ek/priv key len      | Encapsulation (public) key length in bytes. |
 * | dk/pub key len       | Decapsulation (private) key length in bytes. |
 * | seed length          | Length of the seed used for random generation. |
 * | security bytes       | Number of bytes representing the security level. |
 * | security category    | NIST security category (1–5). |
 * | secbits              | Effective security strength in bits. |
 * | N value              | Core polynomial modulus parameter. |
 * | N Mu value           | Derived constant for arithmetic operations. |
 * | Omega value          | Weight parameter used in error vector generation. |
 * | Omega-R value        | Weight parameter for redundancy or recovery data. |
 * | Rejection threshold  | Threshold used in probabilistic rejection sampling. |
 *
 * This structure is used internally by the HQC KEM implementation to
 * select and configure algorithm parameters based on the desired
 * security level.
 */
static const HQC_VARIANT_INFO variant_info[EVP_PKEY_HQC_KEM_MAX] = {
    {
        .type = EVP_PKEY_HQC_KEM_128, /* type */
        .ek_size = 2241, /* ek/priv key len */
        .dk_size = 2321, /* dk/pub key len */
        .seed_len = 48, /* seed length */
        .security_bytes = 16, /* security bytes */
        .security_category = 1, /* security category */
        .secbits = 128, /* secbits */
        .n = 17669, /* N value */
        .n_mu = 243079ULL, /* N Mu value */
        .omega = 66, /* Omega value */
        .omega_r = 75, /* Omega-R value */
        .rej_threshold = 16767881 /* Rejection threshold */
    },
    { .type = EVP_PKEY_HQC_KEM_192,
        .ek_size = 4514,
        .dk_size = 4602,
        .seed_len = 48,
        .security_bytes = 24,
        .security_category = 3,
        .secbits = 192,
        .n = 35851,
        .n_mu = 119800ULL,
        .omega = 100,
        .omega_r = 114,
        .rej_threshold = 16742417 },
    { .type = EVP_PKEY_HQC_KEM_256,
        .ek_size = 7237,
        .dk_size = 7333,
        .seed_len = 48,
        .security_bytes = 32,
        .security_category = 5,
        .secbits = 256,
        .n = 57637,
        .n_mu = 74517ULL,
        .omega = 131,
        .omega_r = 149,
        .rej_threshold = 16772367 }
};

/**
 * @struct hqc_kem_gen_ctx_st
 * @brief Context structure for HQC KEM key generation operations.
 *
 * This structure maintains the operational context and configuration
 * data used during the generation of HQC (Hamming Quasi-Cyclic) KEM
 * key pairs. It stores provider-specific information, algorithm
 * parameters, and references to hashing primitives.
 *
 * @var PROV_HQC_GEN_CTX::provctx
 *   Pointer to the provider context, enabling access to shared
 *   resources and configuration within the OpenSSL provider framework.
 *
 * @var PROV_HQC_GEN_CTX::propq
 *   Property query string used to resolve algorithm implementations
 *   (e.g., selecting specific digest variants or hardware providers).
 *
 * @var PROV_HQC_GEN_CTX::selection
 *   Bitmask indicating which portions of the key material (e.g., key
 *   pair, seed, or parameters) are selected for generation.
 *
 * @var PROV_HQC_GEN_CTX::evp_type
 *   Enumeration specifying the HQC key type or variant (e.g.,
 *   EVP_PKEY_HQC_KEM_128, EVP_PKEY_HQC_KEM_192, etc.).
 *
 * @var PROV_HQC_GEN_CTX::seed_len
 *   Length in bytes of the random seed used for deterministic key
 *   generation.
 *
 * @var PROV_HQC_GEN_CTX::seed
 *   Pointer to the seed buffer used in the pseudorandom generation
 *   process; may be user-supplied or internally generated.
 *
 * @var PROV_HQC_GEN_CTX::shake
 *   Pointer to the XOF (eXtendable Output Function) digest context
 *   (e.g., SHAKE128 or SHAKE256) used for randomness expansion.
 *
 * @var PROV_HQC_GEN_CTX::sha3
 *   Pointer to the SHA3 digest context (e.g., SHA3-256 or SHA3-512)
 *   used for auxiliary hashing operations during key generation.
 */
typedef struct hqc_kem_gen_ctx_st {
    PROV_CTX *provctx;
    char *propq;
    int selection;
    hqc_key_type evp_type;
    size_t seed_len;
    uint8_t *seed;
    EVP_MD *shake;
    EVP_MD *sha3;
    uint8_t *sigma;
    uint64_t *x;
    uint64_t *y;
    uint64_t *h;
    uint64_t *s;
} PROV_HQC_GEN_CTX;

/**
 * @brief Frees all memory associated with an HQC key structure.
 *
 * This function safely releases the memory held by an HQC_KEY object,
 * including its public and private key buffers, and the key structure
 * itself. If the provided pointer is NULL, the function performs no
 * action.
 *
 * @param key
 *   Pointer to the HQC_KEY structure to be freed. May be NULL.
 *
 * @note
 *   - The function uses OpenSSL's memory management routines
 *     (`OPENSSL_free`) for deallocation.
 *   - Both the public key buffer (`ek`) and private key buffer (`dk`)
 *     are freed before the key structure itself.
 *   - The pointer passed to this function becomes invalid after the
 *     call and must not be used again.
 */
static void hqc_kem_key_free(HQC_KEY *key)
{
    ossl_hqc_kem_key_free(key);
}

/**
 * @brief Allocates and initializes a new HQC key structure.
 *
 * This function creates a new HQC_KEY object, initializes it with the
 * specified HQC KEM variant information, and allocates memory for its
 * public and private key buffers. It uses OpenSSL’s memory management
 * routines for secure allocation.
 *
 * @param ctx
 *   Pointer to the provider context (PROV_CTX) used for managing
 *   provider-specific state. May be unused in this implementation but
 *   maintained for API consistency.
 *
 * @param propq
 *   Property query string used to control algorithm or provider
 *   selection. Stored in the HQC_KEY context if required by higher-level
 *   logic.
 *
 * @param evp_type
 *   Integer identifier corresponding to the HQC KEM variant (e.g.,
 *   EVP_PKEY_HQC_KEM_128, EVP_PKEY_HQC_KEM_192, etc.). Used to select
 *   the appropriate entry from the @c variant_info table.
 *
 * @return
 *   A pointer to a newly allocated HQC_KEY structure on success, or
 *   NULL if allocation or buffer initialization fails.
 *
 * @note
 *   - On failure, any allocated memory is securely freed using
 *     @c hqc_kem_key_free().
 *   - The returned HQC_KEY pointer must later be freed with
 *     @c hqc_kem_key_free() to avoid memory leaks.
 */
static HQC_KEY *ossl_prov_hqc_kem_new(PROV_CTX *ctx, const char *propq, int evp_type)
{
    return ossl_hqc_kem_key_new(&variant_info[evp_type], ctx);
}

/**
 * @brief Checks whether a given HQC key contains the requested key components.
 *
 * This function determines if the provided HQC key structure (`HQC_KEY`)
 * includes the components specified by the `selection` bitmask. The selection
 * may request the presence of the public key, private key, or both. The
 * function returns true only if all requested components are present.
 *
 * @param vkey       Pointer to the HQC key structure to be checked.
 * @param selection  Bitmask indicating which key components to verify.
 *                   Possible values (can be combined using bitwise OR):
 *                   - OSSL_KEYMGMT_SELECT_PUBLIC_KEY
 *                   - OSSL_KEYMGMT_SELECT_PRIVATE_KEY
 *
 * @return 1 if the key contains all requested components, 0 otherwise.
 */
static int hqc_key_has(const void *vkey, int selection)
{
    int has = 0;
    int req = 0;
    const HQC_KEY *key = vkey;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        req++;
        if (key->selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
            has++;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        req++;
        if (key->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
            has++;
    }
    return (has == req);
}

/**
 * @brief Compares two HQC keys for equality based on the requested components.
 *
 * This function checks whether two HQC key structures (`HQC_KEY`) match for
 * the components specified by the `selection` bitmask. It first ensures that
 * both keys contain the requested components using ::hqc_key_has, then compares
 * their corresponding public or private key data for equality.
 *
 * @param vkey1      Pointer to the first HQC key structure.
 * @param vkey2      Pointer to the second HQC key structure.
 * @param selection  Bitmask specifying which key components to compare.
 *                   Possible values (can be combined using bitwise OR):
 *                   - OSSL_KEYMGMT_SELECT_PUBLIC_KEY
 *                   - OSSL_KEYMGMT_SELECT_PRIVATE_KEY
 *
 * @return 1 if all requested key components match, 0 otherwise.
 *
 * @note Both keys must contain all components specified by `selection`
 *       for the comparison to succeed.
 */
static int hqc_key_match(const void *vkey1, const void *vkey2, int selection)
{
    const HQC_KEY *key1 = vkey1;
    const HQC_KEY *key2 = vkey2;

    if (!hqc_key_has(key1, selection) || !hqc_key_has(key2, selection))
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (key1->info->ek_size != key2->info->ek_size)
            return 0;

        if (!memcmp(key1->ek, key2->ek, key1->info->ek_size))
            return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (key1->info->dk_size != key2->info->dk_size)
            return 0;

        if (!memcmp(key1->dk, key2->dk, key1->info->dk_size))
            return 0;
    }

    return 1;
}

static size_t hqc_compute_hamming_weight(const uint64_t *keybuf, size_t size)
{
    size_t i, total_population;
#if !defined(__GNUC__) && !defined(__CLANG__)
    size_t j;
#endif

    total_population = 0;

    for (i = 0; i < size; i++) {
#if defined(__GNUC__) || defined(__CLANG__)
        total_population += __builtin_popcountll(keybuf[i]);
#else
        for (j = 0; j < sizeof(uint64_t); j++)
            total_population += (keybuf[i] & (uint64_t)(1ULL << j)) ? 1 : 0;
#endif
    }
    return total_population;
}

static int hqc_kem_validate(const void *vkey, int selection, int check_type)
{
    const HQC_KEY *key = vkey;
    EVP_MD *shake = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int ret = 0;
    uint8_t *dk_seed;
    uint8_t xof_separator = HQC_XOF_SEP;
    uint64_t *x = NULL, *y = NULL;

    if (key == NULL)
        return 0;

    /*
     * Check they key sizes
     * This is trivial as the key is allocated based on variant
     * so this is really just a sanity check
     */
    if (key->info == NULL || key->info != &variant_info[key->info->type])
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        size_t hamming_weight;
        x = OPENSSL_zalloc(VEC_SIZE(key->info->n, 64) * sizeof(uint64_t));
        y = OPENSSL_zalloc(VEC_SIZE(key->info->n, 64) * sizeof(uint64_t));

        if (x == NULL || y == NULL)
            goto err;

        dk_seed = key->dk + key->info->ek_size; /* original seed offset to here */
        /*
         * allocate a shake256 digest to help reconstruct our x,y vectors
         */
        shake = EVP_MD_fetch(PROV_LIBCTX_OF((PROV_CTX *)key->ctx), "SHAKE256", NULL);
        if (shake == NULL)
            goto err;
        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL)
            goto err;

        /*
         * Initialize our shake digest as though we are deriving this key
         */
        if (!EVP_DigestInit_ex2(md_ctx, shake, NULL)
            || !EVP_DigestUpdate(md_ctx, dk_seed, SEED_BYTES)
            || !EVP_DigestUpdate(md_ctx, &xof_separator, 1))
            goto err;

        /*
         * Recompute our x and y vectors
         */
        if (!hqc_sample_xof(md_ctx, y, key->info)
            || !hqc_sample_xof(md_ctx, x, key->info))
            goto err;
        /*
         * Now confirm that the hamming weights for x and y are what
         * we expect for this key variant (should be equal to the omega value)
         */
        hamming_weight = hqc_compute_hamming_weight(x, VEC_SIZE(key->info->n, 64));
        if (hamming_weight != key->info->omega)
            goto err;
        hamming_weight = hqc_compute_hamming_weight(x, VEC_SIZE(key->info->n, 64));
        if (hamming_weight != key->info->omega)
            goto err;
    }

    ret = 1;
err:
    /*
     * If we computed x and y above, make sure we clear it from the stack
     */
    OPENSSL_clear_free(x, VEC_SIZE(key->info->n, 64) * sizeof(uint64_t));
    OPENSSL_clear_free(y, VEC_SIZE(key->info->n, 64) * sizeof(uint64_t));
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(shake);
    return ret;
}

/**
 * @brief Returns the set of import/export parameter types for HQC KEM
 *        keys based on the given selection mask.
 *
 * This function determines which parameter list should be used when
 * importing or exporting key material for an HQC (Hamming Quasi-Cyclic)
 * Key Encapsulation Mechanism key. If the selection includes the key
 * pair, it returns the predefined list of key type parameters;
 * otherwise, it returns NULL.
 *
 * @param selection
 *   Bitmask specifying the key components to be imported or exported.
 *   Typically includes values such as @c OSSL_KEYMGMT_SELECT_KEYPAIR.
 *
 * @return
 *   A pointer to a constant @c OSSL_PARAM array describing the
 *   parameters available for import/export, or NULL if the selection
 *   does not include key pair data.
 *
 * @note
 *   - The returned pointer refers to a static parameter list; it must
 *     not be modified or freed by the caller.
 *   - This function is used by the OpenSSL provider’s key management
 *     interface to advertise supported import/export capabilities.
 */
static const OSSL_PARAM *hqc_kem_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return hqc_kem_key_type_params_list;
    return NULL;
}

/**
 * @brief Exports components of an HQC key as OSSL parameters.
 *
 * This function builds a parameter list representing the selected components
 * of an HQC key and passes them to a user-supplied callback. It supports
 * exporting the public key, private key, or both, based on the specified
 * `selection` bitmask. The generated parameters are provided through the
 * callback function `param_cb`.
 *
 * @param vkey       Pointer to the HQC key structure to export.
 * @param selection  Bitmask specifying which key components to export.
 *                   Possible values (can be combined using bitwise OR):
 *                   - OSSL_KEYMGMT_SELECT_PUBLIC_KEY
 *                   - OSSL_KEYMGMT_SELECT_PRIVATE_KEY
 * @param param_cb   Callback function that receives the built parameters.
 *                   The callback is expected to return 1 for success and
 *                   0 for failure.
 * @param cbarg      Pointer to user-defined data passed to the callback.
 *
 * @return 1 on success (parameters successfully exported and callback
 *         returned success), 0 on failure.
 *
 * @note The function validates that the provider is running and that the
 *       provided key includes all requested components via ::hqc_key_has.
 *       It also handles error cleanup for parameter builders and buffers.
 *
 * @warning This function assumes that `key->ek` and `key->dk` contain the
 *          encoded public and private key data respectively, with sizes
 *          defined in `key->info->ek_size` and `key->info->dk_size`.
 */
static int hqc_key_export(void *vkey, int selection, OSSL_CALLBACK *param_cb,
    void *cbarg)
{
    HQC_KEY *key = vkey;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if (!hqc_key_has(key, selection)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();

    if (tmpl == NULL)
        goto err;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (!ossl_param_build_set_octet_string(tmpl, params, OSSL_PKEY_PARAM_PRIV_KEY,
                key->ek, key->info->ek_size))
            goto err;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (!ossl_param_build_set_octet_string(tmpl, params, OSSL_PKEY_PARAM_PUB_KEY,
                key->dk, key->info->dk_size))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);

err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

/**
 * @brief Initializes an HQC key structure from serialized key data.
 *
 * This function populates an existing HQC_KEY structure using key data
 * provided through an @c OSSL_PARAM array. It decodes and validates the
 * public (and optionally private) key components, ensuring they match
 * the expected sizes defined for the HQC variant. The decoded buffers
 * are then stored within the HQC_KEY object.
 *
 * @param key
 *   Pointer to the HQC_KEY structure to be initialized.
 *
 * @param params
 *   Array of @c OSSL_PARAM structures containing the encoded key data.
 *   Must include at least a public key entry, and optionally a private
 *   key entry if @p include_private is nonzero.
 *
 * @param include_private
 *   Nonzero if the private key should also be imported. When set, the
 *   function expects a valid private key entry in @p params.
 *
 * @return
 *   Returns 1 on success, or 0 on failure (e.g., invalid parameters,
 *   decoding errors, or size mismatches).
 *
 * @note
 *   - The function validates key lengths against @c key->info->ek_size
 *     and @c key->info->dk_size.
 *   - On error, any partially allocated buffers are securely freed.
 *   - The caller must ensure that @p key is already allocated and that
 *     @p params contains valid HQC KEM key data.
 */
static int hqc_kem_key_fromdata(HQC_KEY *key,
    const OSSL_PARAM params[],
    int include_private)
{
    size_t pubkeylen, privkeylen;
    uint8_t *pubkey = NULL, *privkey = NULL;
    struct hqc_kem_key_type_params_st p;

    if (key == NULL || !hqc_kem_key_type_params_decoder(params, &p))
        goto err;

    key->selection = 0;
    if (p.pubkey == NULL)
        goto err;

    if (!OSSL_PARAM_get_octet_string(p.pubkey, (void **)&pubkey, 0,
            &pubkeylen))
        goto err;

    if (pubkeylen != key->info->ek_size)
        goto err;

    key->selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    memcpy(key->ek, pubkey, pubkeylen);

    if (include_private) {
        if (p.privkey == NULL)
            goto err;
        if (!OSSL_PARAM_get_octet_string(p.privkey, (void **)&privkey, 0,
                &privkeylen))
            goto err;
        if (privkeylen != key->info->dk_size)
            goto err;
        key->selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        memcpy(key->dk, privkey, privkeylen);
    }

    return 1;

err:
    OPENSSL_free(pubkey);
    OPENSSL_free(privkey);
    return 0;
}

static int hqc_kem_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    return hqc_kem_key_fromdata(vkey, params, selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
}

/**
 * @brief Returns the list of gettable parameters for the HQC KEM
 *        provider implementation.
 *
 * This function provides OpenSSL with the static list of parameters
 * that can be queried from the HQC KEM (Hamming Quasi-Cyclic Key
 * Encapsulation Mechanism) algorithm implementation. It is typically
 * used by the provider framework to advertise supported metadata such
 * as algorithm names, security levels, or key sizes.
 *
 * @param provctx
 *   Pointer to the provider context. This parameter is unused but
 *   included for compatibility with the OpenSSL provider API.
 *
 * @return
 *   A pointer to a constant @c OSSL_PARAM array describing the
 *   gettable parameters supported by the HQC KEM implementation.
 *
 * @note
 *   - The returned pointer refers to a static, read-only parameter
 *     list and must not be modified or freed by the caller.
 *   - This function is part of the OpenSSL provider dispatch table for
 *     the HQC KEM key management interface.
 */
static const OSSL_PARAM *hqc_kem_gettable_params(void *provctx)
{
    return hqc_kem_get_params_list;
}

/**
 * @brief Exports HQC KEM key parameters into an OSSL_PARAM array.
 *
 * This function encodes data from an existing HQC_KEY structure into
 * an array of @c OSSL_PARAM objects. It allows OpenSSL's provider
 * framework to query the key’s public and private components, as well
 * as its security parameters (e.g., category and bit strength).
 *
 * @param vkey
 *   Pointer to the HQC_KEY structure containing the key material to be
 *   exported. Must not be NULL.
 *
 * @param params
 *   Array of @c OSSL_PARAM structures representing the output
 *   parameters. Each expected field (e.g., public key, private key,
 *   security category, bit strength) should be pre-initialized by the
 *   caller.
 *
 * @return
 *   Returns 1 on success, or 0 if decoding, encoding, or validation
 *   fails.
 *
 * @note
 *   - The function populates the following fields in @p params (if
 *     provided):
 *       - @c pubkey   → Public key bytes from @c key->ek
 *       - @c privkey  → Private key bytes from @c key->dk
 *       - @c seccat   → Security category (e.g., NIST level 1–5)
 *       - @c bits     → Security strength in bits
 *       - @c maxsize  → Public key length in bytes
 *   - The function uses @c OSSL_PARAM_set_* functions to safely encode
 *     data into the output parameter array.
 *   - If any field fails to encode, the function returns 0 immediately.
 *   - The caller must ensure that @p params is large enough to hold all
 *     requested values.
 */
static int hqc_kem_get_params(void *vkey, OSSL_PARAM params[])
{
    HQC_KEY *key = vkey;
    struct hqc_kem_get_params_st p;

    if (key == NULL || !hqc_kem_get_params_decoder(params, &p))
        return 0;

    if (p.pubkey != NULL && key->ek != NULL) {
        if (!OSSL_PARAM_set_octet_string(p.pubkey, key->ek, key->info->ek_size))
            return 0;
    }
    if (p.privkey != NULL && key->dk != NULL) {
        if (!OSSL_PARAM_set_octet_string(p.privkey, key->dk, key->info->dk_size))
            return 0;
    }
    if (p.seccat != NULL) {
        if (!OSSL_PARAM_set_int(p.seccat, key->info->security_category))
            return 0;
    }
    if (p.bits != NULL) {
        if (!OSSL_PARAM_set_int(p.bits, key->info->secbits))
            return 0;
    }
    if (p.maxsize != NULL) {
        if (!OSSL_PARAM_set_size_t(p.bits, key->info->ek_size))
            return 0;
    }

    return 1;
}

/**
 * @brief Applies user-specified parameters to an HQC KEM key generation
 *        context.
 *
 * This function updates the @c PROV_HQC_GEN_CTX structure with
 * configuration values provided through an @c OSSL_PARAM array. It
 * supports updating the property query string and the deterministic
 * seed used for HQC KEM key generation.
 *
 * @param vgctx
 *   Pointer to the HQC KEM key generation context
 *   (@c PROV_HQC_GEN_CTX). Must not be NULL.
 *
 * @param params
 *   Array of @c OSSL_PARAM structures containing the configuration
 *   parameters to set. Recognized parameters include:
 *   - @c propq : UTF-8 string specifying the property query.
 *   - @c seed  : Octet string providing the random seed value.
 *
 * @return
 *   Returns 1 on success, or 0 if any parameter validation or memory
 *   allocation fails.
 *
 * @details
 *   - If the @c propq parameter is provided, the existing property
 *     query string in @p gctx is freed and replaced with a copy of the
 *     new value.
 *   - If the @c seed parameter is provided, its contents are validated
 *     and copied into the context. The seed length must exactly match
 *     the expected value for the selected HQC variant.
 *   - The function validates parameter data types before use (e.g.,
 *     @c propq must be a UTF-8 string).
 *
 * @note
 *   - On failure, the function ensures no partial updates are applied
 *     to the context.
 *   - The @c gctx->seed field is allocated using @c OPENSSL_memdup()
 *     and must be freed appropriately by the caller or higher-level
 *     cleanup routines.
 *   - This function is typically called through the OpenSSL provider
 *     API during HQC key generation setup.
 */
static int hqc_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    PROV_HQC_GEN_CTX *gctx = vgctx;
    struct hqc_kem_gen_set_params_st p;
    uint8_t *seed_ptr = NULL;

    if (gctx == NULL || !hqc_kem_gen_set_params_decoder(params, &p))
        return 0;

    if (p.propq != NULL) {
        if (p.propq->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        if ((gctx->propq = OPENSSL_strdup(p.propq->data)) == NULL)
            return 0;
    }

    if (p.seed != NULL) {
        if (!OSSL_PARAM_get_octet_string_ptr(p.seed, (const void **)&seed_ptr, &gctx->seed_len))
            return 0;

        /*
         * Make sure we have a minimal seed length
         */
        if (gctx->seed_len != variant_info[gctx->evp_type].seed_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            return 0;
        }
        gctx->seed = OPENSSL_memdup(seed_ptr, gctx->seed_len);
        if (gctx->seed == NULL)
            return 0;
    }

    return 1;
}

/**
 * @brief Frees all resources associated with an HQC KEM key generation
 *        context.
 *
 * This function securely releases all dynamically allocated memory and
 * cryptographic resources held by a @c PROV_HQC_GEN_CTX structure. It
 * is typically called at the end of a key generation operation or when
 * an error occurs during context initialization.
 *
 * @param gctx
 *   Pointer to the HQC KEM key generation context to free. If NULL, the
 *   function performs no action.
 *
 * @details
 *   - Frees the property query string (@c gctx->propq).
 *   - Frees the deterministic seed buffer (@c gctx->seed).
 *   - Releases the digest contexts used for SHAKE and SHA3 operations.
 *   - Frees the @c PROV_HQC_GEN_CTX structure itself.
 *
 * @note
 *   - All memory deallocation is performed using OpenSSL’s secure
 *     memory management routines.
 *   - After calling this function, the @p gctx pointer becomes invalid
 *     and must not be reused.
 *   - This cleanup function ensures proper resource release within the
 *     OpenSSL provider framework.
 */
static void hqc_kem_cleanup_gen_ctx(PROV_HQC_GEN_CTX *gctx)
{
    if (gctx == NULL)
        return;

    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx->seed);
    EVP_MD_free(gctx->shake);
    EVP_MD_free(gctx->sha3);
    OPENSSL_free(gctx->sigma);
    OPENSSL_free(gctx->x);
    OPENSSL_free(gctx->y);
    OPENSSL_free(gctx->h);
    OPENSSL_free(gctx->s);

    OPENSSL_free(gctx);
}

/**
 * @brief Initializes a new HQC KEM key generation context.
 *
 * This function allocates, initializes, and configures a
 * @c PROV_HQC_GEN_CTX structure for HQC (Hamming Quasi-Cyclic) Key
 * Encapsulation Mechanism key generation. It sets up the internal
 * context fields, applies user-specified parameters, and fetches the
 * required digest algorithms.
 *
 * @param provctx
 *   Pointer to the provider context used by the OpenSSL provider
 *   framework. Provides access to the library context and configuration
 *   data.
 *
 * @param selection
 *   Bitmask indicating which key components should be generated (e.g.,
 *   public key, private key, or both).
 *
 * @param params
 *   Optional array of @c OSSL_PARAM structures used to configure
 *   context parameters such as seed or property query strings. May be
 *   NULL if no parameters are provided.
 *
 * @param evp_type
 *   Integer identifier for the HQC KEM variant (e.g.,
 *   @c EVP_PKEY_HQC_KEM_128). Used to associate the correct parameter
 *   set and seed length.
 *
 * @return
 *   A pointer to a fully initialized @c PROV_HQC_GEN_CTX on success, or
 *   NULL on failure.
 *
 * @details
 *   - Allocates and zero-initializes the @c PROV_HQC_GEN_CTX structure.
 *   - Populates key generation parameters via
 *     @c hqc_kem_gen_set_params().
 *   - Fetches the SHAKE256 and SHA3-512 digest implementations from the
 *     provider library context.
 *   - On error, the function performs full cleanup via
 *     @c hqc_kem_cleanup_gen_ctx() before returning NULL.
 *
 * @note
 *   - The caller is responsible for freeing the returned context using
 *     @c hqc_kem_cleanup_gen_ctx() after use.
 *   - If digest initialization fails, the entire context is discarded
 *     to avoid inconsistent state.
 */
static void *hqc_kem_gen_init(void *provctx, int selection,
    const OSSL_PARAM params[], int evp_type)
{
    PROV_HQC_GEN_CTX *gctx = NULL;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        goto err;

    gctx->selection = selection;
    gctx->evp_type = evp_type;
    gctx->provctx = provctx;
    if (!hqc_kem_gen_set_params(gctx, params))
        goto err;

    /*
     * HQC key generation relies on SHAKE256 and SHA3-512 internally, allocate ciphers
     * for each here
     */
    gctx->shake = EVP_MD_fetch(PROV_LIBCTX_OF(provctx), "SHAKE256", gctx->propq);
    if (gctx->shake == NULL)
        goto err;

    gctx->sha3 = EVP_MD_fetch(PROV_LIBCTX_OF(provctx), "SHA3-512", gctx->propq);
    if (gctx->sha3 == NULL)
        goto err;

    gctx->sigma = OPENSSL_zalloc(variant_info[evp_type].security_bytes);
    gctx->x = OPENSSL_zalloc(VEC_SIZE(variant_info[evp_type].n, 64) * sizeof(uint64_t));
    gctx->y = OPENSSL_zalloc(VEC_SIZE(variant_info[evp_type].n, 64) * sizeof(uint64_t));
    gctx->h = OPENSSL_zalloc(VEC_SIZE(variant_info[evp_type].n, 64) * sizeof(uint64_t));
    gctx->s = OPENSSL_zalloc(VEC_SIZE(variant_info[evp_type].n, 64) * sizeof(uint64_t));

    if (gctx->sigma == NULL || gctx->x == NULL || gctx->y == NULL
        || gctx->h == NULL || gctx->s == NULL)
        goto err;

    return gctx;
err:
    hqc_kem_cleanup_gen_ctx(gctx);
    return NULL;
}

/**
 * @brief Returns the list of settable parameters for HQC KEM key
 *        generation.
 *
 * This function provides OpenSSL with the static list of parameters
 * that can be configured when initializing or modifying an HQC KEM
 * (Hamming Quasi-Cyclic Key Encapsulation Mechanism) key generation
 * context. It is used by the provider framework to advertise supported
 * configuration options for key generation.
 *
 * @param vgctx
 *   Pointer to the HQC KEM key generation context. This parameter is
 *   unused but retained for compatibility with the provider API.
 *
 * @param provctx
 *   Pointer to the provider context. This parameter is also unused but
 *   required by the OpenSSL provider interface.
 *
 * @return
 *   A pointer to a constant @c OSSL_PARAM array describing the
 *   parameters that may be set for HQC KEM key generation.
 *
 * @note
 *   - The returned list is static and must not be modified or freed by
 *     the caller.
 *   - Typical settable parameters include items such as property query
 *     strings and deterministic seed values.
 *   - This function forms part of the OpenSSL provider’s key generation
 *     dispatch table for HQC KEM implementations.
 */
static const OSSL_PARAM *hqc_kem_gen_settable_params(ossl_unused void *vgctx,
    ossl_unused void *provctx)
{
    return hqc_kem_gen_set_params_list;
}

/**
 * @brief Performs modular reduction using Barrett reduction for HQC
 *        arithmetic operations.
 *
 * This function computes the value of @p x modulo @c info->n using
 * Barrett reduction, a fast method for modular reduction that avoids
 * expensive division operations. It is used internally within the HQC
 * (Hamming Quasi-Cyclic) cryptographic routines for efficient modular
 * arithmetic.
 *
 * @param x
 *   The input value to be reduced.
 *
 * @param info
 *   Pointer to an @c HQC_VARIANT_INFO structure containing variant-
 *   specific parameters:
 *   - @c n     : The modulus.
 *   - @c n_mu  : The precomputed Barrett constant
 *                (⌊2³² / n⌋ or a scaled equivalent).
 *
 * @return
 *   The reduced value @c r such that @c 0 ≤ r < info->n.
 *
 * @details
 *   - Computes an approximate quotient @c q = ⌊(x * n_mu) / 2³²⌋.
 *   - Calculates the provisional remainder @c r = x − q × n.
 *   - Conditionally subtracts @c n if @c r ≥ n to ensure the result is
 *     within the correct range.
 *   - Uses bitwise operations instead of branching for constant-time
 *     behavior.
 *
 * @note
 *   - The computation is designed to be constant-time, avoiding
 *     conditional branches that could leak timing information.
 *   - The correctness of the reduction depends on the accuracy of the
 *     precomputed @c n_mu parameter for the given HQC variant.
 *   - This function is typically used in finite-field or polynomial
 *     arithmetic within HQC encryption and key encapsulation routines.
 */
static uint32_t barrett_reduce(uint32_t x, const HQC_VARIANT_INFO *info)
{
    uint64_t q = ((uint64_t)x * info->n_mu) >> 32;
    uint32_t r = x - (uint32_t)(q * info->n);
    uint32_t reduce_flag = (((r - info->n) >> 31) ^ 1);
    /*
     * Windows get all cranky about trying to negate a uint32_t
     * Tell it to chill out with some casting
     */
    uint32_t mask = (uint32_t)(-((int32_t)reduce_flag));
    r -= mask & info->n;
    return r;
}

/**
 * @brief Samples a sparse binary vector deterministically using an
 *        extendable-output function (XOF).
 *
 * This function generates a binary vector with exactly
 * @c info->omega bits set, according to the HQC (Hamming Quasi-Cyclic)
 * cryptographic specification. The sampling is performed using a
 * pseudorandom byte stream derived from the provided XOF context.
 * Duplicate positions are rejected to ensure unique bit indices.
 *
 * @param md_ctx
 *   Pointer to the initialized @c EVP_MD_CTX representing the XOF
 *   context (e.g., SHAKE256). Used to generate pseudorandom bytes.
 *
 * @param vec
 *   Pointer to the output vector buffer where sampled bits will be set.
 *   Must be large enough to store @c VEC_SIZE(info->n, 64) 64-bit
 *   blocks.
 *
 * @param info
 *   Pointer to an @c HQC_VARIANT_INFO structure providing variant-
 *   specific parameters:
 *   - @c omega        : Number of bits to set in the vector.
 *   - @c omega_r      : Support vector size.
 *   - @c n            : Modulus size in bits.
 *   - @c rej_threshold: Rejection threshold for candidate values.
 *
 * @return
 *   Returns 1 on success, or 0 on failure (e.g., when random byte
 *   generation via @c xof_get_bytes() fails).
 *
 * @details
 *   - Random 24-bit integers are extracted from the XOF stream and
 *     reduced modulo @c n using @c barrett_reduce().
 *   - Duplicate indices are discarded to ensure uniqueness among
 *     selected bit positions.
 *   - For each valid index, the bit position and corresponding 64-bit
 *     word offset are recorded in lookup tables.
 *   - The final binary vector is assembled using bitwise OR operations
 *     across all selected indices.
 *   - The procedure avoids branching where possible to maintain
 *     constant-time behavior.
 *
 * @note
 *   - The caller must ensure that @c md_ctx has been properly seeded
 *     before calling this function.
 *   - The @c vec buffer is modified in place and should be zeroed
 *     before use if accumulation of bits is not intended.
 *   - This function is critical for HQC's error vector and random
 *     support generation steps, where cryptographic uniformity and
 *     reproducibility are required.
 */
static int hqc_sample_xof(EVP_MD_CTX *md_ctx, uint64_t *vec, const HQC_VARIANT_INFO *info)
{
    uint32_t *support;
    size_t random_bytes_size = 3 * info->omega;
    uint8_t *rand_bytes;
    uint8_t inc;
    size_t i, j, k;
    uint32_t *index_tab;
    uint64_t *bit_tab;
    int32_t pos;
    uint64_t val;
    uint32_t tmp;
    int val1;
    uint64_t mask;
    int ret = 0;

    support = OPENSSL_zalloc(info->omega_r * sizeof(uint32_t));
    rand_bytes = OPENSSL_zalloc(info->omega * 3);
    index_tab = OPENSSL_zalloc(info->omega_r * sizeof(uint32_t));
    bit_tab = OPENSSL_zalloc(info->omega_r * sizeof(uint64_t));

    if (support == NULL || rand_bytes == NULL || index_tab == NULL || bit_tab == NULL)
        goto err;

    i = 0;
    j = random_bytes_size;
    while (i < info->omega) {
        do {
            if (j == random_bytes_size) {
                if (!xof_get_bytes(md_ctx, rand_bytes, (uint32_t)random_bytes_size))
                    return 0;
                j = 0;
            }
            support[i] = ((uint32_t)rand_bytes[j++]) << 16;
            support[i] |= ((uint32_t)rand_bytes[j++]) << 8;
            support[i] |= rand_bytes[j++];
        } while (support[i] >= info->rej_threshold);

        support[i] = barrett_reduce(support[i], info);

        inc = 1;
        for (k = 0; k < i; k++) {
            if (support[k] == support[i])
                inc = 0;
        }
        i += inc;
    }

    for (i = 0; i < info->omega; i++) {
        index_tab[i] = support[i] >> 6;
        pos = support[i] & 0x3f;
        bit_tab[i] = ((uint64_t)1) << pos;
    }

    val = 0;
    for (i = 0; i < VEC_SIZE(info->n, 64); i++) {
        val = 0;
        for (j = 0; j < info->omega; j++) {
            tmp = (uint32_t)i - index_tab[j];
            val1 = 1 ^ ((tmp | (uint32_t)(-(int32_t)tmp)) >> 31);
            mask = -val1;
            val |= (bit_tab[j] & mask);
        }
        vec[i] |= val;
    }
    ret = 1;
err:
    OPENSSL_free(support);
    OPENSSL_free(rand_bytes);
    OPENSSL_free(index_tab);
    OPENSSL_free(bit_tab);
    return ret;
}

/**
 * @brief Performs polynomial multiplication using the schoolbook method
 *        over GF(2).
 *
 * This function multiplies two binary polynomials represented as
 * 64-bit word arrays and stores the 128-bit result in the output
 * buffer. Each input operand is treated as a polynomial with binary
 * coefficients, and multiplication is performed modulo 2 (XOR-based
 * accumulation).
 *
 * @param r
 *   Pointer to the output buffer of size @c 2 * n 64-bit words. The
 *   buffer is zero-initialized at the start of the operation.
 *
 * @param a
 *   Pointer to the first input operand (multiplicand), represented as
 *   an array of @c n 64-bit words.
 *
 * @param b
 *   Pointer to the second input operand (multiplier), represented as
 *   an array of @c n 64-bit words.
 *
 * @param n
 *   Number of 64-bit words in each input operand.
 *
 * @details
 *   - Implements classic “schoolbook” polynomial multiplication in
 *     GF(2)[x].
 *   - Each bit of @p a is examined; if the bit is set, the polynomial
 *     @p b is XORed into the result @p r shifted by the bit’s position.
 *   - Bit-level shifts and XOR operations are used instead of
 *     arithmetic multiplication or addition.
 *   - Handles bit shifts across word boundaries, propagating high bits
 *     into the next word.
 *
 * @note
 *   - The result buffer @p r must be large enough to hold 2 × n 64-bit
 *     words.
 *   - Operates entirely in constant-time bitwise logic (no conditional
 *     branches on secret data).
 *   - This is a reference (non-optimized) implementation suitable for
 *     small operand sizes or as a fallback when Karatsuba or FFT-based
 *     multiplication is not beneficial.
 */
static void schoolbook_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t n)
{
    size_t i, j, base;
    int bit, sh, inv;
    uint64_t mask, ai;

    memset(r, 0, 2 * n * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        ai = a[i];
        for (bit = 0; bit < 64; bit++) {
            mask = (uint64_t)(-((int64_t)((ai >> bit) & 1ULL)));
            base = i;
            sh = bit;
            inv = 64 - sh;
            if (sh == 0) {
                for (j = 0; j < n; j++) {
                    r[base + j] ^= b[j] & mask;
                }
            } else {
                for (j = 0; j < n; j++) {
                    r[base + j] ^= (b[j] << sh) & mask;
                    r[base + j + 1] ^= (b[j] >> inv) & mask;
                }
            }
        }
    }
}

/**
 * @brief Performs polynomial multiplication using the recursive
 *        Karatsuba algorithm over GF(2).
 *
 * This function computes the product of two binary polynomials
 * represented as arrays of 64-bit words, using the Karatsuba
 * divide-and-conquer algorithm for improved efficiency over the
 * classical schoolbook method. Multiplication and accumulation are
 * performed with XOR operations, as arithmetic is carried out in GF(2).
 *
 * @param r
 *   Pointer to the output buffer of size @c 2 * n 64-bit words, which
 *   will hold the resulting product. The buffer is cleared before
 *   accumulation.
 *
 * @param a
 *   Pointer to the first input operand (multiplicand), represented as
 *   an array of @c n 64-bit words.
 *
 * @param b
 *   Pointer to the second input operand (multiplier), represented as
 *   an array of @c n 64-bit words.
 *
 * @param n
 *   Number of 64-bit words in each input operand.
 *
 * @param tmp_buffer
 *   Pointer to a temporary buffer used for storing intermediate
 *   results and recursive workspace. The buffer must be large enough
 *   to accommodate several subproducts and temporary vectors.
 *
 * @details
 *   - For small operand sizes (@c n ≤ @c KARATSUBA_THRESHOLD), the
 *     function falls back to @c schoolbook_mul() for simplicity.
 *   - The operands are split into low and high halves:
 *     @f$a = a_0 + x^m a_1@f$, @f$b = b_0 + x^m b_1@f$.
 *   - The recursive Karatsuba formulation computes:
 *       - @c z0 = a0 * b0  (low product)
 *       - @c z2 = a1 * b1  (high product)
 *       - @c zmid = (a0 + a1) * (b0 + b1)
 *     and combines them via:
 *       @f$r = z0 + ((zmid ⊕ z0 ⊕ z2) << m) + (z2 << 2m)@f$.
 *   - XOR replaces addition to represent modular arithmetic in GF(2).
 *
 * @note
 *   - The algorithm runs in approximately O(n^1.585) time, offering
 *     better asymptotic performance than the quadratic schoolbook
 *     method for large n.
 *   - All arithmetic is constant-time with respect to data values,
 *     minimizing side-channel leakage.
 *   - Ensure @p tmp_buffer is sufficiently large; insufficient space
 *     may cause memory corruption.
 *   - Used internally for HQC finite-field and polynomial arithmetic
 *     operations where efficiency is critical.
 */
static void karatsuba_mul(uint64_t *r, const uint64_t *a, const uint64_t *b,
    size_t n, uint64_t *tmp_buffer)
{
    if (n <= KARATSUBA_THRESHOLD) {
        schoolbook_mul(r, a, b, n);
        return;
    }

    size_t m = n >> 1;
    size_t n0 = m;
    size_t n1 = n - m;

    /* take successive chunks of tmp_buffer for each intermediate result */
    uint64_t *z0 = tmp_buffer; /* low-half product, size 2*n words */
    uint64_t *z2 = z0 + 2 * n; /* high-half product, size 2*n words */
    uint64_t *zmid = z2 + 2 * n; /* middle product, size 2*n words */

    /* ta and tb hold the sums of low and high halves: */
    /* ta[i] = a0[i] XOR a1[i], tb[i] = b0[i] XOR b1[i] for i < n1 */
    uint64_t *ta = zmid + 2 * n;
    uint64_t *tb = ta + n;

    /* buffer for child recursions */
    uint64_t *child_buffer = tmp_buffer + 8 * n;

    /* 1) low * low */
    karatsuba_mul(z0, a, b, n0, child_buffer);

    /* 2) high * high */
    karatsuba_mul(z2, a + m, b + m, n1, child_buffer);

    /* 3) (a0+a1)*(b0+b1) */
    for (size_t i = 0; i < n1; i++) {
        uint64_t loa = (i < n0 ? a[i] : 0);
        uint64_t lob = (i < n0 ? b[i] : 0);
        ta[i] = loa ^ a[m + i];
        tb[i] = lob ^ b[m + i];
    }
    karatsuba_mul(zmid, ta, tb, n1, child_buffer);

    /* 4) assemble into r */
    memset(r, 0, 2 * n * sizeof(uint64_t));
    for (size_t i = 0; i < 2 * n0; i++)
        r[i] ^= z0[i];
    for (size_t i = 0; i < 2 * n1; i++)
        r[2 * m + i] ^= z2[i];
    for (size_t i = 0; i < 2 * n1; i++) {
        uint64_t z0i = (i < 2 * n0 ? z0[i] : 0);
        uint64_t z2i = (i < 2 * n1 ? z2[i] : 0);
        uint64_t mid = zmid[i] ^ z0i ^ z2i;
        r[m + i] ^= mid;
    }
}

/**
 * @brief Reduces a polynomial modulo (xⁿ + 1) for HQC arithmetic over GF(2).
 *
 * This function performs modular reduction of a doubled-length
 * polynomial represented as an array of 64-bit words. It reduces
 * the input polynomial @p a modulo (xⁿ + 1), where @p n is derived
 * from the HQC variant parameters, and stores the result in @p out.
 *
 * Reduction is done by XOR-folding the higher-degree part of the
 * polynomial back into the lower part, consistent with the ring
 * GF(2)[x]/(xⁿ + 1).
 *
 * @param out
 *   Pointer to the output buffer that will receive the reduced
 *   polynomial. Must have space for @c VEC_SIZE(info->n, 64) 64-bit
 *   words.
 *
 * @param a
 *   Pointer to the input polynomial to be reduced. The array must
 *   contain at least @c 2 * VEC_SIZE(info->n, 64) 64-bit words,
 *   representing the unreduced product.
 *
 * @param info
 *   Pointer to an @c HQC_VARIANT_INFO structure containing variant-
 *   specific parameters:
 *   - @c n : The modulus degree for the reduction (typically the HQC
 *            code length).
 *
 * @details
 *   - The function folds higher bits back into the lower half by
 *     shifting and XORing the upper words of @p a.
 *   - The shifting amount depends on @c info->n mod 64 to handle
 *     partial-word alignment.
 *   - The final word is masked using @c VEC_BITMASK() to ensure
 *     that bits above degree n−1 are cleared.
 *
 * @note
 *   - The operation is performed in-place on @p out, independent
 *     of @p a.
 *   - This reduction implements the standard HQC ring arithmetic
 *     requirement for polynomial operations modulo (xⁿ + 1).
 *   - All bitwise operations are constant-time and branch-free,
 *     maintaining side-channel resistance.
 */
static void reduce(uint64_t *out, const uint64_t *a, const HQC_VARIANT_INFO *info)
{
    for (size_t i = 0; i < VEC_SIZE(info->n, 64); i++) {
        uint64_t r = a[i + VEC_SIZE(info->n, 64) - 1] >> (info->n & 0x3F);
        uint64_t carry = a[i + VEC_SIZE(info->n, 64)] << (64 - (info->n & 0x3F));
        out[i] = a[i] ^ r ^ carry;
    }
    out[VEC_SIZE(info->n, 64) - 1] &= VEC_BITMASK(info->n, 64);
}

/**
 * @brief Multiplies two binary polynomials and reduces the result modulo
 *        (xⁿ + 1) for HQC arithmetic.
 *
 * This function computes the product of two polynomials over GF(2),
 * represented as arrays of 64-bit words, and performs modular reduction
 * to ensure the result fits within the polynomial ring
 * GF(2)[x]/(xⁿ + 1). It uses Karatsuba multiplication for efficiency
 * and the HQC-specific reduction function for modular folding.
 *
 * @param out
 *   Pointer to the output buffer where the reduced product is stored.
 *   Must have space for @c VEC_SIZE(info->n, 64) 64-bit words.
 *
 * @param a
 *   Pointer to the first input polynomial operand, represented as an
 *   array of @c VEC_SIZE(info->n, 64) 64-bit words.
 *
 * @param b
 *   Pointer to the second input polynomial operand, represented as an
 *   array of @c VEC_SIZE(info->n, 64) 64-bit words.
 *
 * @param info
 *   Pointer to an @c HQC_VARIANT_INFO structure that provides
 *   variant-specific parameters, including:
 *   - @c n : The modulus degree used in polynomial reduction.
 *
 * @details
 *   - The function first computes the unreduced polynomial product
 *     using @c karatsuba_mul(), which efficiently handles large-degree
 *     operands.
 *   - The intermediate result, stored in @c unreduced, contains up to
 *     2 × n bits.
 *   - The @c reduce() function then folds and masks the result modulo
 *     (xⁿ + 1) to ensure the final polynomial is within the desired
 *     ring.
 *   - Temporary buffers are stack-allocated for performance and
 *     security, avoiding heap allocations.
 *
 * @note
 *   - All operations are performed in GF(2) using XOR instead of
 *     arithmetic addition.
 *   - The function assumes that @c n and related parameters are valid
 *     for the HQC variant specified by @p info.
 *   - Used internally in HQC key generation and encapsulation routines
 *     where efficient and constant-time polynomial arithmetic is
 *     required.
 */
static void vec_mul(uint64_t *out, const uint64_t *a, const uint64_t *b, const HQC_VARIANT_INFO *info)
{
    uint64_t *unreduced;
    uint64_t *tmp_buffer;

    unreduced = OPENSSL_malloc(2 * VEC_SIZE(info->n, 64) * sizeof(uint64_t));
    tmp_buffer = OPENSSL_malloc(16 * VEC_SIZE(info->n, 64) * sizeof(uint64_t));

    if (unreduced == NULL || tmp_buffer == NULL)
        goto err;

    karatsuba_mul(unreduced, a, b, VEC_SIZE(info->n, 64), tmp_buffer);

    reduce(out, unreduced, info);
err:
    OPENSSL_free(unreduced);
    OPENSSL_free(tmp_buffer);
}

/**
 * @brief Performs bitwise vector addition (XOR) over GF(2).
 *
 * This function computes the bitwise XOR of two equal-length binary
 * vectors, storing the result in the output buffer. In the context of
 * HQC operations, this corresponds to polynomial addition modulo 2.
 *
 * @param o
 *   Pointer to the output buffer where the result is stored. Must have
 *   space for @p size 64-bit words.
 *
 * @param v1
 *   Pointer to the first input vector operand.
 *
 * @param v2
 *   Pointer to the second input vector operand.
 *
 * @param size
 *   The number of 64-bit words in each input vector.
 *
 * @details
 *   - Each output element is computed as:
 *     @code
 *     o[i] = v1[i] ^ v2[i];
 *     @endcode
 *   - This operation implements addition in the finite field GF(2),
 *     where XOR serves as the addition operator.
 *   - No carry or overflow occurs, as all operations are bitwise.
 *
 * @note
 *   - The input and output buffers may overlap safely.
 *   - The function runs in constant time with respect to the data
 *     values, suitable for use in cryptographic code.
 *   - Commonly used in HQC key generation, encryption, and error
 *     vector manipulation steps.
 */
static void vec_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size)
{
    for (uint32_t i = 0; i < size; ++i) {
        o[i] = v1[i] ^ v2[i];
    }
}

/**
 * @brief Extracts a specified number of bytes from an extendable-output
 *        function (XOF) context.
 *
 * This function retrieves pseudorandom bytes from an initialized XOF
 * digest context (e.g., SHAKE256) using the OpenSSL provider API. It
 * ensures that the requested number of bytes is produced even if the
 * total output size is not aligned to 64-bit boundaries.
 *
 * @param xof_ctx
 *   Pointer to the @c EVP_MD_CTX XOF context from which bytes are
 *   squeezed. Must be properly initialized with a SHAKE-based digest.
 *
 * @param output
 *   Pointer to the destination buffer that will receive the generated
 *   pseudorandom bytes.
 *
 * @param output_size
 *   Number of bytes to extract from the XOF stream.
 *
 * @return
 *   Returns 1 on success, or 0 if any call to
 *   @c EVP_DigestSqueeze() fails.
 *
 * @details
 *   - The function first extracts all full 64-bit blocks directly into
 *     the output buffer.
 *   - If @p output_size is not a multiple of 8, an additional 64-bit
 *     block is squeezed into a temporary buffer, and the remaining
 *     bytes are copied to complete the output.
 *   - This design ensures full coverage of the requested output size
 *     without alignment or padding issues.
 *
 * @note
 *   - The @p xof_ctx must be configured for a XOF-capable digest
 *     (e.g., SHAKE128 or SHAKE256).
 *   - This function maintains XOF state continuity — subsequent calls
 *     continue generating the next bytes in the pseudorandom sequence.
 *   - Commonly used in HQC for deterministic sampling and key material
 *     generation.
 */
static int xof_get_bytes(EVP_MD_CTX *xof_ctx, uint8_t *output, uint32_t output_size)
{
    const uint8_t bsize = sizeof(uint64_t);
    const uint8_t remainder = output_size % bsize;
    uint8_t tmp[sizeof(uint64_t)];

    if (!EVP_DigestSqueeze(xof_ctx, output, output_size - remainder))
        return 0;
    if (remainder != 0) {
        if (!EVP_DigestSqueeze(xof_ctx, tmp, bsize))
            return 0;
        output += output_size - remainder;
        for (uint8_t i = 0; i < remainder; i++) {
            output[i] = tmp[i];
        }
    }

    return 1;
}

/**
 * @brief Generates a new HQC KEM public/private keypair.
 *
 * This function implements the full deterministic key generation
 * procedure for the HQC (Hamming Quasi-Cyclic) Key Encapsulation
 * Mechanism. It derives all necessary seeds, vectors, and
 * cryptographic components using extendable-output and hash-based
 * pseudorandom functions, producing both the public and private keys.
 *
 * @param vgctx
 *   Pointer to the HQC key generation context
 *   (@c PROV_HQC_GEN_CTX), which contains digest algorithms,
 *   property strings, and variant information.
 *
 * @param osslcb
 *   Optional callback function for progress or status reporting.
 *   Unused in this implementation.
 *
 * @param cbarg
 *   Optional callback argument passed to @p osslcb. Unused in this
 *   implementation.
 *
 * @return
 *   Returns a pointer to a fully populated @c HQC_KEY structure on
 *   success, or @c NULL on failure. On failure, all intermediate
 *   memory is securely freed.
 *
 * @details
 *   - Allocates a new HQC key structure via @c ossl_prov_hqc_kem_new().
 *   - Ensures deterministic operation via a fixed seed (either supplied
 *     by the user or generated randomly).
 *   - Uses SHAKE and SHA3 digests to derive sub-seeds:
 *       1. @c seed_kem  — base seed for keypair derivation.
 *       2. @c seed_pke  — seed for public key expansion.
 *       3. @c sigma     — random secret component.
 *       4. @c keypair_seed — concatenated decryption/encryption seeds.
 *   - Samples sparse vectors @c x and @c y using
 *     @c hqc_sample_xof(), computes the public polynomial @c h and
 *     derives the support vector @c s = x + y * h mod (xⁿ + 1).
 *   - Assembles the final keys:
 *       - Public key = (ek_seed || s)
 *       - Private key = (public key || dk_seed || sigma || seed_kem)
 *
 * @note
 *   - This function performs all operations in constant time where
 *     possible to maintain side-channel resistance.
 *   - Memory for sensitive data (e.g., seeds, sigma) is securely
 *     cleared before returning.
 *   - Requires properly initialized digest contexts for SHAKE256 and
 *     SHA3-512, as specified in @c PROV_HQC_GEN_CTX.
 *   - The caller is responsible for freeing the returned key with
 *     @c hqc_kem_key_free().
 */
static void *hqc_kem_gen(void *vgctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    PROV_HQC_GEN_CTX *gctx = vgctx;
    HQC_KEY *key;
    uint8_t keypair_seed[2 * SEED_BYTES];
    uint8_t seed_kem[SEED_BYTES];
    uint8_t seed_pke[SEED_BYTES];
    uint8_t *dk_seed = keypair_seed;
    uint8_t *ek_seed = &keypair_seed[SEED_BYTES];
    uint8_t domain_separator = HQC_I_DOMAIN_SEP;
    uint8_t xof_separator = HQC_XOF_SEP;
    uint8_t domain = HQC_PRNG_DOMAIN_SEP;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int len;
    int ret = 0;
#ifdef B_ENDIAN
    size_t idx;
#endif

    key = ossl_prov_hqc_kem_new(gctx->provctx, gctx->propq, gctx->evp_type);
    if (key == NULL)
        goto err;

    /* we may need to generate a seed */
    if (gctx->seed == NULL) {
        gctx->seed = OPENSSL_malloc(VEC_SIZE(key->info->seed_len, 1));
        if (gctx->seed == NULL)
            return 0; /*seed gets freed when we free the ctx */
        if (!RAND_bytes_ex(PROV_LIBCTX_OF(gctx->provctx), gctx->seed,
                key->info->seed_len, 0))
            return 0;
    }

    /*
     * Initialize our shake digest as a prng to generate our key seed from
     * the provided seed
     */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    if (!EVP_DigestInit_ex2(md_ctx, gctx->shake, NULL))
        goto err;
    if (!EVP_DigestUpdate(md_ctx, gctx->seed, key->info->seed_len))
        goto err;
    if (!EVP_DigestUpdate(md_ctx, &domain, 1))
        goto err;
    if (!EVP_DigestSqueeze(md_ctx, (unsigned char *)seed_kem, SEED_BYTES))
        goto err;

    /*
     * Now use shake256 again to derive our seed_pke and sigma values
     */
    if (!EVP_DigestInit_ex2(md_ctx, gctx->shake, NULL))
        goto err;
    if (!EVP_DigestUpdate(md_ctx, seed_kem, SEED_BYTES))
        goto err;
    if (!EVP_DigestUpdate(md_ctx, &xof_separator, 1))
        goto err;
    if (!xof_get_bytes(md_ctx, seed_pke, SEED_BYTES))
        goto err;
    if (!xof_get_bytes(md_ctx, gctx->sigma, (uint32_t)key->info->security_bytes))
        goto err;

    /*
     * Derive keypair seeds
     */
    if (!EVP_DigestInit_ex2(md_ctx, gctx->sha3, NULL))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, seed_pke, SEED_BYTES))
        goto err;

    /*
     * Add a domain separator
     */
    if (!EVP_DigestUpdate(md_ctx, &domain_separator, 1))
        goto err;

    if (!EVP_DigestFinal_ex(md_ctx, keypair_seed, &len))
        goto err;

    /*
     * Compute decryption key
     */
    if (!EVP_DigestInit_ex2(md_ctx, gctx->shake, NULL))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, dk_seed, SEED_BYTES))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, &xof_separator, 1))
        goto err;

    /*
     * Sample the digest to get our x and y vectors
     */
    if (!hqc_sample_xof(md_ctx, gctx->y, key->info))
        goto err;
    if (!hqc_sample_xof(md_ctx, gctx->x, key->info))
        goto err;

    /*
     * Compute encryption key
     */
    if (!EVP_DigestInit_ex2(md_ctx, gctx->shake, NULL))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, ek_seed, SEED_BYTES))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, &xof_separator, 1))
        goto err;

    if (!EVP_DigestSqueeze(md_ctx, (unsigned char *)gctx->h, VEC_SIZE(key->info->n, 8)))
        goto err;

/*
 * The DigestSqueeze above treats h as a byte array, but the
 * vector operations below treat it as uint64_t which the
 * karatsuba algorithm expects to be in little endian
 * so do that swap on big endian systems here
 */
#ifdef B_ENDIAN
    for (idx = 0; idx < VEC_SIZE(key->info->n, 64); idx++)
        gctx->h[idx] = htole64(gctx->h[idx]);
#endif

    gctx->h[VEC_SIZE(key->info->n, 64) - 1] &= VEC_BITMASK(key->info->n, 64);

    vec_mul(gctx->s, gctx->y, gctx->h, key->info);
    vec_add(gctx->s, gctx->x, gctx->s, VEC_SIZE(key->info->n, 64));

    /*
     * Swap the results back prior to serializing to the key below
     */
#ifdef B_ENDIAN
    for (idx = 0; idx < VEC_SIZE(key->info->n, 64); idx++)
        gctx->s[idx] = htole64(gctx->s[idx]);
#endif

    /*
     * Place the encryption and decryption values into the key
     */
    memcpy(key->ek, ek_seed, SEED_BYTES);
    memcpy(key->ek + SEED_BYTES, gctx->s, VEC_SIZE(key->info->n, 8));
    memcpy(key->dk, key->ek, key->info->ek_size);
    memcpy(key->dk + key->info->ek_size, dk_seed, SEED_BYTES);
    memcpy(key->dk + key->info->ek_size + SEED_BYTES, gctx->sigma, key->info->security_bytes);
    memcpy(key->dk + key->info->ek_size + SEED_BYTES + key->info->security_bytes,
        seed_kem, SEED_BYTES);

    key->selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    ret = 1;
err:
    memset(keypair_seed, 0, 2 * SEED_BYTES);
    memset(seed_kem, 0, sizeof(seed_kem));
    EVP_MD_CTX_free(md_ctx);
    if (ret == 0)
        hqc_kem_key_free(key);
    return ret == 1 ? key : NULL;
}

/**
 * @brief Cleans up and frees an HQC KEM key generation context.
 *
 * This function releases all resources associated with a
 * @c PROV_HQC_GEN_CTX structure, including allocated memory and
 * digest contexts. It serves as the cleanup routine for the HQC KEM
 * key generation interface in the OpenSSL provider framework.
 *
 * @param vgctx
 *   Pointer to the HQC key generation context to be freed. May be NULL.
 *
 * @details
 *   - Delegates cleanup to @c hqc_kem_cleanup_gen_ctx(), which handles
 *     deallocation of all internal buffers, seed memory, and digest
 *     contexts.
 *   - Ensures consistent cleanup behavior regardless of partial or
 *     failed initialization states.
 *
 * @note
 *   - After this function is called, the context pointer becomes invalid
 *     and must not be reused.
 *   - This function is typically registered in the OpenSSL provider’s
 *     key generation dispatch table for HQC KEM operations.
 */
static void hqc_kem_gen_cleanup(void *vgctx)
{
    PROV_HQC_GEN_CTX *gctx = vgctx;
    hqc_kem_cleanup_gen_ctx(gctx);
}

/**
 * @brief Creates a duplicate of an HQC key with the selected components.
 *
 * This function allocates and initializes a new HQC key structure as a
 * duplicate of the provided key. It copies the requested components
 * (public key, private key, or both) from the source key into the new one.
 * The duplicated key retains the same type information as the original.
 *
 * @param vkey       Pointer to the HQC key structure to duplicate.
 * @param selection  Bitmask specifying which key components to copy.
 *                   Possible values (can be combined using bitwise OR):
 *                   - OSSL_KEYMGMT_SELECT_PUBLIC_KEY
 *                   - OSSL_KEYMGMT_SELECT_PRIVATE_KEY
 *
 * @return A pointer to the newly allocated HQC key structure on success,
 *         or NULL if duplication fails or if the source key does not
 *         contain the requested components.
 *
 * @note The function verifies that the source key contains the requested
 *       components using ::hqc_key_has before attempting duplication.
 *
 * @warning The returned key must be freed by the caller using the
 *          appropriate key free function (e.g., ::hqc_key_free) to avoid
 *          memory leaks.
 */
static void *hqc_kem_dup(const void *vkey, int selection)
{
    const HQC_KEY *key = vkey;
    HQC_KEY *dup;

    if (!hqc_key_has(key, selection))
        return NULL;

    dup = ossl_prov_hqc_kem_new(NULL, NULL, key->info->type);
    if (dup == NULL)
        return NULL;

    memcpy(dup->ek, key->ek, key->info->ek_size);
    memcpy(dup->dk, key->dk, key->info->dk_size);
    dup->selection = selection;

    return dup;
}

#define DECLARE_VARIANT(bits)                                                              \
    static OSSL_FUNC_keymgmt_new_fn hqc_kem_##bits##_new;                                  \
    static OSSL_FUNC_keymgmt_gen_init_fn hqc_kem_##bits##_gen_init;                        \
    static void *hqc_kem_##bits##_new(void *provctx)                                       \
    {                                                                                      \
        return ossl_prov_hqc_kem_new(provctx, NULL, EVP_PKEY_HQC_KEM_##bits);              \
    }                                                                                      \
    static void *hqc_kem_##bits##_gen_init(void *provctx, int selection,                   \
        const OSSL_PARAM params[])                                                         \
    {                                                                                      \
        return hqc_kem_gen_init(provctx, selection, params,                                \
            EVP_PKEY_HQC_KEM_##bits);                                                      \
    }                                                                                      \
    const OSSL_DISPATCH ossl_hqc_##bits##_keymgmt_functions[] = {                          \
        { OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)hqc_kem_##bits##_new },                        \
        { OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)hqc_kem_key_free },                           \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)hqc_kem_get_params },                   \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC)hqc_kem_gettable_params },         \
        { OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)hqc_key_has },                                 \
        { OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)hqc_key_match },                             \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (OSSL_FUNC)hqc_kem_validate },                       \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (OSSL_FUNC)hqc_kem_##bits##_gen_init },              \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (OSSL_FUNC)hqc_kem_gen_set_params },           \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (OSSL_FUNC)hqc_kem_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (OSSL_FUNC)hqc_kem_gen },                                 \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (OSSL_FUNC)hqc_kem_gen_cleanup },                 \
        { OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)hqc_kem_dup },                                 \
        { OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)hqc_kem_import },                           \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)hqc_kem_imexport_types },             \
        { OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)hqc_key_export },                           \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)hqc_kem_imexport_types },             \
        OSSL_DISPATCH_END                                                                  \
    }

/*
 * Declare the algorithm dispatch tables for all our key size variants
 */
DECLARE_VARIANT(128);
DECLARE_VARIANT(192);
DECLARE_VARIANT(256);
