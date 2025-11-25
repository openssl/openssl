/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * TPM 2.0 Compatibility Layer - Complete Algorithm Support
 *
 * This header provides a comprehensive TPM 2.0 compatible cryptographic
 * API with 88 algorithms backed by OpenSSL implementations. Designed for
 * use with DSMIL security profiles.
 *
 * Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY
 * Version: 2.0.0
 * Date: 2025-11-25
 */

#ifndef DSMIL_TPM2_COMPAT_H
#define DSMIL_TPM2_COMPAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TPM 2.0 Return Codes
 */
typedef uint32_t tpm2_rc_t;

#define TPM2_RC_SUCCESS         0x000
#define TPM2_RC_FAILURE         0x001
#define TPM2_RC_NOT_SUPPORTED   0x002
#define TPM2_RC_BAD_PARAMETER   0x003
#define TPM2_RC_INSUFFICIENT_BUFFER 0x004
#define TPM2_RC_MEMORY          0x005
#define TPM2_RC_INITIALIZE      0x006

/*
 * Cryptographic Algorithm Identifiers
 * Total: 88 algorithms across all categories
 */
typedef enum {
    /* Hash Algorithms (10 total) */
    CRYPTO_ALG_SHA1 = 0x0004,
    CRYPTO_ALG_SHA256 = 0x000B,
    CRYPTO_ALG_SHA384 = 0x000C,
    CRYPTO_ALG_SHA512 = 0x000D,
    CRYPTO_ALG_SHA3_256 = 0x0027,
    CRYPTO_ALG_SHA3_384 = 0x0028,
    CRYPTO_ALG_SHA3_512 = 0x0029,
    CRYPTO_ALG_SM3_256 = 0x0012,
    CRYPTO_ALG_SHAKE128 = 0x002A,
    CRYPTO_ALG_SHAKE256 = 0x002B,

    /* Symmetric Encryption - AES Modes (16 total) */
    CRYPTO_ALG_AES_128_ECB = 0x1001,
    CRYPTO_ALG_AES_256_ECB = 0x1002,
    CRYPTO_ALG_AES_128_CBC = 0x1003,
    CRYPTO_ALG_AES_256_CBC = 0x1004,
    CRYPTO_ALG_AES_128_CTR = 0x1005,
    CRYPTO_ALG_AES_256_CTR = 0x1006,
    CRYPTO_ALG_AES_128_OFB = 0x1007,
    CRYPTO_ALG_AES_256_OFB = 0x1008,
    CRYPTO_ALG_AES_128_CFB = 0x1009,
    CRYPTO_ALG_AES_256_CFB = 0x100A,
    CRYPTO_ALG_AES_128_GCM = 0x100B,
    CRYPTO_ALG_AES_256_GCM = 0x100C,
    CRYPTO_ALG_AES_128_CCM = 0x100D,
    CRYPTO_ALG_AES_256_CCM = 0x100E,
    CRYPTO_ALG_AES_128_XTS = 0x100F,
    CRYPTO_ALG_AES_256_XTS = 0x1010,

    /* Other Symmetric Ciphers (6 total) */
    CRYPTO_ALG_3DES_EDE = 0x1011,
    CRYPTO_ALG_CAMELLIA_128 = 0x1012,
    CRYPTO_ALG_CAMELLIA_256 = 0x1013,
    CRYPTO_ALG_SM4_128 = 0x1014,
    CRYPTO_ALG_CHACHA20 = 0x1015,
    CRYPTO_ALG_CHACHA20_POLY1305 = 0x1016,

    /* RSA Key Sizes (5 total) */
    CRYPTO_ALG_RSA_1024 = 0x2001,
    CRYPTO_ALG_RSA_2048 = 0x2002,
    CRYPTO_ALG_RSA_3072 = 0x2003,
    CRYPTO_ALG_RSA_4096 = 0x2004,
    CRYPTO_ALG_RSA_8192 = 0x2005,

    /* Elliptic Curves (12 total) */
    CRYPTO_ALG_ECC_P192 = 0x3001,
    CRYPTO_ALG_ECC_P224 = 0x3002,
    CRYPTO_ALG_ECC_P256 = 0x3003,
    CRYPTO_ALG_ECC_P384 = 0x3004,
    CRYPTO_ALG_ECC_P521 = 0x3005,
    CRYPTO_ALG_ECC_SM2_P256 = 0x3006,
    CRYPTO_ALG_ECC_BN_P256 = 0x3007,
    CRYPTO_ALG_ECC_BN_P638 = 0x3008,
    CRYPTO_ALG_ECC_CURVE25519 = 0x3009,
    CRYPTO_ALG_ECC_CURVE448 = 0x300A,
    CRYPTO_ALG_ECC_ED25519 = 0x300B,
    CRYPTO_ALG_ECC_ED448 = 0x300C,

    /* HMAC Algorithms (5 total) */
    CRYPTO_ALG_HMAC_SHA1 = 0x4001,
    CRYPTO_ALG_HMAC_SHA256 = 0x4002,
    CRYPTO_ALG_HMAC_SHA384 = 0x4003,
    CRYPTO_ALG_HMAC_SHA512 = 0x4004,
    CRYPTO_ALG_HMAC_SM3 = 0x4005,

    /* Key Derivation Functions (11 total) */
    CRYPTO_ALG_KDF_SP800_108 = 0x5001,
    CRYPTO_ALG_KDF_SP800_56A = 0x5002,
    CRYPTO_ALG_HKDF_SHA256 = 0x5003,
    CRYPTO_ALG_HKDF_SHA384 = 0x5004,
    CRYPTO_ALG_HKDF_SHA512 = 0x5005,
    CRYPTO_ALG_PBKDF2_SHA256 = 0x5006,
    CRYPTO_ALG_PBKDF2_SHA512 = 0x5007,
    CRYPTO_ALG_SCRYPT = 0x5008,
    CRYPTO_ALG_ARGON2I = 0x5009,
    CRYPTO_ALG_ARGON2D = 0x500A,
    CRYPTO_ALG_ARGON2ID = 0x500B,

    /* Signature Schemes (8 total) */
    CRYPTO_ALG_RSA_SSA_PKCS1V15 = 0x6001,
    CRYPTO_ALG_RSA_PSS = 0x6002,
    CRYPTO_ALG_ECDSA_SHA256 = 0x6003,
    CRYPTO_ALG_ECDSA_SHA384 = 0x6004,
    CRYPTO_ALG_ECDSA_SHA512 = 0x6005,
    CRYPTO_ALG_SCHNORR = 0x6006,
    CRYPTO_ALG_SM2_SIGN = 0x6007,
    CRYPTO_ALG_ECDAA = 0x6008,

    /* Key Agreement (3 total) */
    CRYPTO_ALG_ECDH = 0x7001,
    CRYPTO_ALG_ECMQV = 0x7002,
    CRYPTO_ALG_DH = 0x7003,

    /* Mask Generation Functions (4 total) */
    CRYPTO_ALG_MGF1_SHA1 = 0x8001,
    CRYPTO_ALG_MGF1_SHA256 = 0x8002,
    CRYPTO_ALG_MGF1_SHA384 = 0x8003,
    CRYPTO_ALG_MGF1_SHA512 = 0x8004,

    /* Post-Quantum Cryptography (8 total) - ML-KEM/ML-DSA from DSSSL */
    CRYPTO_ALG_KYBER512 = 0x9001,
    CRYPTO_ALG_KYBER768 = 0x9002,
    CRYPTO_ALG_KYBER1024 = 0x9003,
    CRYPTO_ALG_DILITHIUM2 = 0x9004,
    CRYPTO_ALG_DILITHIUM3 = 0x9005,
    CRYPTO_ALG_DILITHIUM5 = 0x9006,
    CRYPTO_ALG_FALCON512 = 0x9007,
    CRYPTO_ALG_FALCON1024 = 0x9008
} tpm2_crypto_algorithm_t;

/*
 * Security Levels
 */
typedef enum {
    TPM2_SECURITY_LEGACY = 80,      /* 80-bit security (deprecated) */
    TPM2_SECURITY_BASELINE = 112,   /* 112-bit security */
    TPM2_SECURITY_STANDARD = 128,   /* 128-bit security */
    TPM2_SECURITY_HIGH = 192,       /* 192-bit security */
    TPM2_SECURITY_MAXIMUM = 256     /* 256-bit security */
} tpm2_security_level_t;

/*
 * Acceleration Flags
 */
typedef enum {
    TPM2_ACCEL_NONE = 0x0000,
    TPM2_ACCEL_AES_NI = 0x0001,
    TPM2_ACCEL_SHA_NI = 0x0002,
    TPM2_ACCEL_AVX2 = 0x0004,
    TPM2_ACCEL_AVX512 = 0x0008,
    TPM2_ACCEL_NPU = 0x0010,
    TPM2_ACCEL_GNA = 0x0020,
    TPM2_ACCEL_ALL = 0xFFFF
} tpm2_acceleration_flags_t;

/*
 * Opaque Handles
 */
typedef struct tpm2_crypto_context_st *tpm2_crypto_context_handle_t;
typedef struct tpm2_key_handle_st *tpm2_key_handle_t;

/*
 * Initialization and Cleanup
 */

/**
 * Initialize TPM2 cryptographic subsystem
 *
 * @param accel_flags  Hardware acceleration preferences
 * @param min_security_level  Minimum security level to enforce
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_init(tpm2_acceleration_flags_t accel_flags,
                           tpm2_security_level_t min_security_level);

/**
 * Clean up TPM2 cryptographic subsystem
 */
void tpm2_crypto_cleanup(void);

/*
 * Hash Functions
 */

/**
 * Compute cryptographic hash
 *
 * @param hash_alg  Hash algorithm to use
 * @param data  Input data
 * @param data_size  Size of input data
 * @param hash_out  Output buffer for hash
 * @param hash_size_inout  Input: buffer size, Output: actual hash size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_hash(tpm2_crypto_algorithm_t hash_alg,
                           const uint8_t *data,
                           size_t data_size,
                           uint8_t *hash_out,
                           size_t *hash_size_inout);

/*
 * HMAC Functions
 */

/**
 * Compute HMAC
 *
 * @param hmac_alg  HMAC algorithm to use
 * @param key  HMAC key
 * @param key_size  Size of HMAC key
 * @param data  Input data
 * @param data_size  Size of input data
 * @param hmac_out  Output buffer for HMAC
 * @param hmac_size_inout  Input: buffer size, Output: actual HMAC size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_hmac(tpm2_crypto_algorithm_t hmac_alg,
                           const uint8_t *key,
                           size_t key_size,
                           const uint8_t *data,
                           size_t data_size,
                           uint8_t *hmac_out,
                           size_t *hmac_size_inout);

/*
 * Symmetric Encryption Context
 */

/**
 * Create symmetric encryption context
 *
 * @param cipher_alg  Cipher algorithm
 * @param key  Encryption key
 * @param key_size  Size of encryption key
 * @param context_out  Output handle to created context
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_context_create(tpm2_crypto_algorithm_t cipher_alg,
                                     const uint8_t *key,
                                     size_t key_size,
                                     tpm2_crypto_context_handle_t *context_out);

/**
 * Destroy symmetric encryption context
 *
 * @param context  Context to destroy
 */
void tpm2_crypto_context_destroy(tpm2_crypto_context_handle_t context);

/**
 * Encrypt data
 *
 * @param context  Encryption context
 * @param plaintext  Input plaintext
 * @param plaintext_size  Size of plaintext
 * @param iv  Initialization vector (for modes that need it)
 * @param iv_size  Size of IV
 * @param ciphertext_out  Output buffer for ciphertext
 * @param ciphertext_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_encrypt(tpm2_crypto_context_handle_t context,
                              const uint8_t *plaintext,
                              size_t plaintext_size,
                              const uint8_t *iv,
                              size_t iv_size,
                              uint8_t *ciphertext_out,
                              size_t *ciphertext_size_inout);

/**
 * Decrypt data
 *
 * @param context  Decryption context
 * @param ciphertext  Input ciphertext
 * @param ciphertext_size  Size of ciphertext
 * @param iv  Initialization vector
 * @param iv_size  Size of IV
 * @param plaintext_out  Output buffer for plaintext
 * @param plaintext_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_decrypt(tpm2_crypto_context_handle_t context,
                              const uint8_t *ciphertext,
                              size_t ciphertext_size,
                              const uint8_t *iv,
                              size_t iv_size,
                              uint8_t *plaintext_out,
                              size_t *plaintext_size_inout);

/*
 * AEAD (Authenticated Encryption with Associated Data)
 */

/**
 * AEAD encryption
 *
 * @param aead_alg  AEAD algorithm (GCM, CCM, ChaCha20-Poly1305)
 * @param key  Encryption key
 * @param key_size  Size of key
 * @param nonce  Nonce/IV
 * @param nonce_size  Size of nonce
 * @param aad  Additional authenticated data
 * @param aad_size  Size of AAD
 * @param plaintext  Input plaintext
 * @param plaintext_size  Size of plaintext
 * @param ciphertext_out  Output ciphertext buffer
 * @param ciphertext_size_inout  Input: buffer size, Output: actual size
 * @param tag_out  Authentication tag output
 * @param tag_size  Size of authentication tag
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_aead_encrypt(tpm2_crypto_algorithm_t aead_alg,
                                   const uint8_t *key,
                                   size_t key_size,
                                   const uint8_t *nonce,
                                   size_t nonce_size,
                                   const uint8_t *aad,
                                   size_t aad_size,
                                   const uint8_t *plaintext,
                                   size_t plaintext_size,
                                   uint8_t *ciphertext_out,
                                   size_t *ciphertext_size_inout,
                                   uint8_t *tag_out,
                                   size_t tag_size);

/**
 * AEAD decryption and verification
 *
 * @param aead_alg  AEAD algorithm
 * @param key  Decryption key
 * @param key_size  Size of key
 * @param nonce  Nonce/IV
 * @param nonce_size  Size of nonce
 * @param aad  Additional authenticated data
 * @param aad_size  Size of AAD
 * @param ciphertext  Input ciphertext
 * @param ciphertext_size  Size of ciphertext
 * @param tag  Authentication tag
 * @param tag_size  Size of tag
 * @param plaintext_out  Output plaintext buffer
 * @param plaintext_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, TPM2_RC_FAILURE if auth fails
 */
tpm2_rc_t tpm2_crypto_aead_decrypt(tpm2_crypto_algorithm_t aead_alg,
                                   const uint8_t *key,
                                   size_t key_size,
                                   const uint8_t *nonce,
                                   size_t nonce_size,
                                   const uint8_t *aad,
                                   size_t aad_size,
                                   const uint8_t *ciphertext,
                                   size_t ciphertext_size,
                                   const uint8_t *tag,
                                   size_t tag_size,
                                   uint8_t *plaintext_out,
                                   size_t *plaintext_size_inout);

/*
 * Key Derivation Functions
 */

/**
 * HKDF (HMAC-based Key Derivation Function)
 *
 * @param hash_alg  Hash algorithm for HKDF
 * @param salt  Salt value
 * @param salt_size  Size of salt
 * @param ikm  Input key material
 * @param ikm_size  Size of IKM
 * @param info  Context/application info
 * @param info_size  Size of info
 * @param okm  Output key material
 * @param okm_size  Desired size of OKM
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_hkdf(tpm2_crypto_algorithm_t hash_alg,
                           const uint8_t *salt,
                           size_t salt_size,
                           const uint8_t *ikm,
                           size_t ikm_size,
                           const uint8_t *info,
                           size_t info_size,
                           uint8_t *okm,
                           size_t okm_size);

/**
 * PBKDF2 (Password-Based Key Derivation Function 2)
 *
 * @param hash_alg  Hash algorithm for PBKDF2
 * @param password  Password/passphrase
 * @param password_size  Size of password
 * @param salt  Salt value
 * @param salt_size  Size of salt
 * @param iterations  Number of iterations
 * @param derived_key  Output derived key
 * @param key_size  Desired key size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_pbkdf2(tpm2_crypto_algorithm_t hash_alg,
                             const uint8_t *password,
                             size_t password_size,
                             const uint8_t *salt,
                             size_t salt_size,
                             uint32_t iterations,
                             uint8_t *derived_key,
                             size_t key_size);

/*
 * Asymmetric Cryptography - Key Generation
 */

/**
 * Generate RSA key pair
 *
 * @param rsa_alg  RSA algorithm (determines key size)
 * @param public_key  Output buffer for public key (DER format)
 * @param public_key_size_inout  Input: buffer size, Output: actual size
 * @param private_key  Output buffer for private key (DER format)
 * @param private_key_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_rsa_keygen(tpm2_crypto_algorithm_t rsa_alg,
                                 uint8_t *public_key,
                                 size_t *public_key_size_inout,
                                 uint8_t *private_key,
                                 size_t *private_key_size_inout);

/**
 * Generate ECC key pair
 *
 * @param ecc_curve  ECC curve algorithm
 * @param public_key  Output buffer for public key
 * @param public_key_size_inout  Input: buffer size, Output: actual size
 * @param private_key  Output buffer for private key
 * @param private_key_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_ecc_keygen(tpm2_crypto_algorithm_t ecc_curve,
                                 uint8_t *public_key,
                                 size_t *public_key_size_inout,
                                 uint8_t *private_key,
                                 size_t *private_key_size_inout);

/*
 * Key Agreement
 */

/**
 * ECDH key agreement
 *
 * @param curve  ECC curve
 * @param private_key  Our private key
 * @param private_key_size  Size of private key
 * @param peer_public_key  Peer's public key
 * @param peer_public_key_size  Size of peer's public key
 * @param shared_secret  Output shared secret
 * @param shared_secret_size  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_ecdh(tpm2_crypto_algorithm_t curve,
                           const uint8_t *private_key,
                           size_t private_key_size,
                           const uint8_t *peer_public_key,
                           size_t peer_public_key_size,
                           uint8_t *shared_secret,
                           size_t *shared_secret_size);

/**
 * Generate ECDH ephemeral key pair (for key agreement)
 *
 * @param curve  ECC curve
 * @param private_key  Output private key
 * @param private_key_size_inout  Input: buffer size, Output: actual size
 * @param public_key  Output public key
 * @param public_key_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_ecdh_keygen(tpm2_crypto_algorithm_t curve,
                                  uint8_t *private_key,
                                  size_t *private_key_size_inout,
                                  uint8_t *public_key,
                                  size_t *public_key_size_inout);

/*
 * Post-Quantum Cryptography (ML-KEM / ML-DSA)
 */

/**
 * ML-KEM (Kyber) Encapsulation
 *
 * @param kem_alg  ML-KEM algorithm (512/768/1024)
 * @param public_key  Recipient's public key
 * @param public_key_size  Size of public key
 * @param ciphertext  Output encapsulated ciphertext
 * @param ciphertext_size_inout  Input: buffer size, Output: actual size
 * @param shared_secret  Output shared secret
 * @param shared_secret_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_mlkem_encapsulate(tpm2_crypto_algorithm_t kem_alg,
                                        const uint8_t *public_key,
                                        size_t public_key_size,
                                        uint8_t *ciphertext,
                                        size_t *ciphertext_size_inout,
                                        uint8_t *shared_secret,
                                        size_t *shared_secret_size_inout);

/**
 * ML-KEM (Kyber) Decapsulation
 *
 * @param kem_alg  ML-KEM algorithm
 * @param private_key  Our private key
 * @param private_key_size  Size of private key
 * @param ciphertext  Encapsulated ciphertext
 * @param ciphertext_size  Size of ciphertext
 * @param shared_secret  Output shared secret
 * @param shared_secret_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_crypto_mlkem_decapsulate(tpm2_crypto_algorithm_t kem_alg,
                                        const uint8_t *private_key,
                                        size_t private_key_size,
                                        const uint8_t *ciphertext,
                                        size_t ciphertext_size,
                                        uint8_t *shared_secret,
                                        size_t *shared_secret_size_inout);

/*
 * TPM-Backed Key Storage
 */

/**
 * Seal a key to TPM (hardware-backed storage)
 *
 * @param key_data  Key material to seal
 * @param key_size  Size of key
 * @param sealed_blob  Output TPM-sealed blob
 * @param sealed_blob_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_key_seal(const uint8_t *key_data,
                        size_t key_size,
                        uint8_t *sealed_blob,
                        size_t *sealed_blob_size_inout);

/**
 * Unseal a key from TPM
 *
 * @param sealed_blob  TPM-sealed blob
 * @param sealed_blob_size  Size of sealed blob
 * @param key_data  Output unsealed key
 * @param key_size_inout  Input: buffer size, Output: actual size
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_key_unseal(const uint8_t *sealed_blob,
                          size_t sealed_blob_size,
                          uint8_t *key_data,
                          size_t *key_size_inout);

/**
 * Create TPM-backed key handle (persistent storage)
 *
 * @param key_type  Type of key (RSA, ECC, AES, etc.)
 * @param key_size_bits  Size of key in bits
 * @param key_handle_out  Output key handle
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_key_create(tpm2_crypto_algorithm_t key_type,
                          uint32_t key_size_bits,
                          tpm2_key_handle_t *key_handle_out);

/**
 * Load key into TPM
 *
 * @param key_blob  Key blob to load
 * @param key_blob_size  Size of key blob
 * @param key_handle_out  Output key handle
 * @return TPM2_RC_SUCCESS on success, error code otherwise
 */
tpm2_rc_t tpm2_key_load(const uint8_t *key_blob,
                        size_t key_blob_size,
                        tpm2_key_handle_t *key_handle_out);

/**
 * Destroy TPM key handle
 *
 * @param key_handle  Key handle to destroy
 */
void tpm2_key_destroy(tpm2_key_handle_t key_handle);

/*
 * Utility Functions
 */

/**
 * Get algorithm name string
 *
 * @param alg  Algorithm identifier
 * @return Algorithm name string, or "UNKNOWN"
 */
const char *tpm2_crypto_algorithm_name(tpm2_crypto_algorithm_t alg);

/**
 * Get hash output size
 *
 * @param hash_alg  Hash algorithm
 * @return Size in bytes, or 0 if not a hash algorithm
 */
size_t tpm2_crypto_hash_size(tpm2_crypto_algorithm_t hash_alg);

/**
 * Get security level for algorithm
 *
 * @param alg  Algorithm identifier
 * @return Security level in bits
 */
uint32_t tpm2_crypto_algorithm_security_bits(tpm2_crypto_algorithm_t alg);

/**
 * Check if algorithm is FIPS 140-2 approved
 *
 * @param alg  Algorithm identifier
 * @return 1 if FIPS approved, 0 otherwise
 */
int tpm2_crypto_is_fips_approved(tpm2_crypto_algorithm_t alg);

#ifdef __cplusplus
}
#endif

#endif /* DSMIL_TPM2_COMPAT_H */
