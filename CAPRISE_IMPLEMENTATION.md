# CAPRISE Implementation for OpenSSL

## Overview

This implementation adds the **CAPRISE** (Conditional Approximate Distance-Comparison-Preserving Symmetric Encryption) algorithm to OpenSSL as a provider-based symmetric cipher. CAPRISE is a novel encryption scheme designed for privacy-preserving Retrieval-Augmented Generation (RAG) systems.

### Key Features

- **Distance-Preserving Encryption**: Preserves distance comparisons between encrypted query embeddings and encrypted database embeddings while obscuring relationships among database embeddings
- **Vector-Based Operation**: Works directly with double-precision floating-point vectors (embeddings)
- **Dual Mode Support**:
  - DB mode: For encrypting stored database embeddings
  - QUERY mode: For encrypting query embeddings
- **Configurable Parameters**:
  - `s` (scaling factor): Default 3.0
  - `β` (beta, security parameter): Default 0.2
  - `dim` (embedding dimension): Default 768 (configurable)

## Algorithm Summary

CAPRISE is based on the paper: "Efficient Privacy-Preserving Retrieval Augmented Generation with Distance-Preserving Encryption" (arXiv:2601.12331)

### Encryption Process

**For Database Embeddings (Enc_db):**
```
λ_e = (3/8) * (n * s * β / ||n||) * (u)^(1/d)
e' = s * e + λ_e
```

**For Query Embeddings (Enc_q):**
```
η_e = (1/8) * (n * s * β / ||n||) * (u)^(1/d)
e' = s * e + η_e
```

Where:
- `s` = scaling factor (from key space)
- `β` = security parameter
- `n` = Gaussian vector sampled via PRF
- `u` = uniform random in [0,1]
- `d` = embedding dimension
- `||n||` = L2 norm of n

### Security Properties

1. **Distance Comparison Preservation**: If `||e_q - e_1|| < ||e_q - e_2|| - β`, then `||e'_q - e'_1|| < ||e'_q - e'_2||`
2. **Vector Structure Obscuration**: Distance comparisons between database embeddings are NOT preserved, preventing vector analysis attacks
3. **Vec2Text Defense**: The added noise disrupts embedding inversion attacks

## Files Created

### Source Files
- `providers/implementations/ciphers/cipher_caprise.h` - Header with algorithm definitions
- `providers/implementations/ciphers/cipher_caprise.c` - Core implementation
- `providers/implementations/ciphers/cipher_caprise.inc` - Parameter tables

### Test Files
- `test/caprise_test.c` - Comprehensive test suite

### Modified Files
- `providers/defltprov.c` - Registered CAPRISE with default provider
- `providers/implementations/ciphers/build.info` - Added to build system
- `providers/implementations/include/prov/names.h` - Added algorithm name
- `providers/implementations/include/prov/implementations.h` - Added function declarations
- `test/build.info` - Added test to build system

## Usage

### Basic Encryption/Decryption

```c
#include <openssl/evp.h>
#include <openssl/params.h>

// Generate random key and IV
unsigned char key[32];
unsigned char iv[16];
RAND_bytes(key, sizeof(key));
RAND_bytes(iv, sizeof(iv));

// Fetch CAPRISE cipher
EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "CAPRISE", NULL);
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// Initialize encryption (DB mode)
unsigned int mode = 0;  // CAPRISE_MODE_DB
size_t dim = 768;      // Embedding dimension
double s = 3.0;         // Scaling factor
double beta = 0.2;      // Security parameter

OSSL_PARAM params[5];
params[0] = OSSL_PARAM_construct_uint("caprise_mode", &mode);
params[1] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
params[2] = OSSL_PARAM_construct_double("caprise_s", &s);
params[3] = OSSL_PARAM_construct_double("caprise_beta", &beta);
params[4] = OSSL_PARAM_construct_end();

EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1);
EVP_CIPHER_CTX_set_params(ctx, params);

// Encrypt embedding (double array)
double embedding[768] = {...};  // Your embedding vector
unsigned char plaintext[sizeof(embedding)];
unsigned char ciphertext[sizeof(embedding)];
memcpy(plaintext, embedding, sizeof(embedding));

int outlen, tmplen;
outlen = tmplen = 0;
EVP_CipherUpdate(ctx, ciphertext, &outlen, plaintext, sizeof(plaintext));
EVP_CipherFinal(ctx, ciphertext + outlen, &tmplen);

// For decryption, use mode 0 (DB mode) with enc=0
```

### Distance-Preserving Usage Pattern

```c
// Database setup phase (client-side)
EVP_CIPHER_CTX *db_ctx = EVP_CIPHER_CTX_new();
unsigned int db_mode = 0;  // CAPRISE_MODE_DB
OSSL_PARAM db_params[5];
db_params[0] = OSSL_PARAM_construct_uint("caprise_mode", &db_mode);
db_params[1] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
db_params[2] = OSSL_PARAM_construct_double("caprise_s", &s);
db_params[3] = OSSL_PARAM_construct_double("caprise_beta", &beta);
db_params[4] = OSSL_PARAM_construct_end();

EVP_CipherInit_ex(db_ctx, cipher, NULL, key, iv_db, 1);
EVP_CIPHER_CTX_set_params(db_ctx, db_params);

// Encrypt database embeddings and upload to cloud
for (each embedding) {
    EVP_CipherUpdate(db_ctx, ciphertext, &len, plaintext, len);
    EVP_CipherFinal(db_ctx, ciphertext + len, &tmplen);
    upload_to_cloud(ciphertext, len);
}

// Query phase (client-side)
EVP_CIPHER_CTX *q_ctx = EVP_CIPHER_CTX_new();
unsigned int q_mode = 1;  // CAPRISE_MODE_QUERY
OSSL_PARAM q_params[5];
q_params[0] = OSSL_PARAM_construct_uint("caprise_mode", &q_mode);
q_params[1] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
q_params[2] = OSSL_PARAM_construct_double("caprise_s", &s);
q_params[3] = OSSL_PARAM_construct_double("caprise_beta", &beta);
q_params[4] = OSSL_PARAM_construct_end();

EVP_CipherInit_ex(q_ctx, cipher, NULL, key, iv_q, 1);
EVP_CIPHER_CTX_set_params(q_ctx, q_params);

// Encrypt query embedding
EVP_CipherUpdate(q_ctx, q_ciphertext, &len, q_plaintext, len);
EVP_CipherFinal(q_ctx, q_ciphertext + len, &tmplen);

// Send encrypted query to cloud for similarity search
results = cloud_search(q_ciphertext);
```

## Building and Testing

### Build OpenSSL with CAPRISE

```bash
cd /path/to/openssl
./Configure
make
```

The CAPRISE cipher will be automatically built as part of the default provider.

### Run Tests

```bash
# Run all CAPRISE tests
./test/caprise_test

# Run specific test
./test/caprise_test test_caprise_basic
./test/caprise_test test_caprise_distance_preservation
./test/caprise_test test_caprise_dimensions
./test/caprise_test test_caprise_parameters
```

### Test Coverage

1. **test_caprise_basic**: Basic encryption/decryption roundtrip
2. **test_caprise_distance_preservation**: Validates the distance-preserving property
3. **test_caprise_dimensions**: Tests various embedding dimensions (2, 4, 8, 16)
4. **test_caprise_parameters**: Tests different parameter combinations (s, β values)

## Performance Considerations

- **Throughput**: CAPRISE achieves ~2,339 vectors/second for 768-dim embeddings (9× faster than PHE-based alternatives)
- **Overhead**: Encryption overhead is < 19% of embedding computation time
- **Memory**: O(d) space complexity where d is embedding dimension

## Security Considerations

### Recommendations

1. **Key Management**: Store the PRF key (`K`) securely
2. **Nonce Reuse**: Never reuse the same nonce (r) for different embeddings with the same key
3. **Parameter Selection**:
   - `s = 3.0` and `β = 0.2` provide good balance between privacy and utility
   - Larger β values increase privacy but reduce retrieval accuracy
   - Smaller β values improve accuracy but may leak more information
4. **Differential Privacy**: For production use with repeated queries, consider adding DP noise to query embeddings (as described in the paper)

### Known Limitations

1. **Deterministic Noise**: Same (key, nonce, embedding) always produces same ciphertext
2. **Floating-Point Precision**: Uses double-precision arithmetic; consider precision requirements for your use case
3. **Dimension Limits**: Maximum supported dimension is 4096 (configurable)

## Integration with RAG Systems

### Typical Workflow

```
1. Setup Phase (One-time):
   - Generate random key K (32 bytes)
   - Choose security parameters (s, β)
   - Configure embedding dimension d

2. Database Upload Phase:
   - For each document:
     a. Generate embedding using your favorite model (e.g., GTR-T5-base)
     b. Encrypt embedding using CAPRISE in DB mode
     c. Upload both AES-encrypted content and CAPRISE-encrypted embedding to cloud

3. Query Phase:
   a. Generate query embedding
   b. Optionally add DP noise (see paper for details)
   c. Encrypt using CAPRISE in QUERY mode
   d. Send to cloud for similarity search
   e. Retrieve top-k AES-encrypted documents
   f. Decrypt documents locally
   g. Use retrieved documents for LLM augmentation
```

## References

- Paper: "Efficient Privacy-Preserving Retrieval Augmented Generation with Distance-Preserving Encryption"
  - arXiv: 2601.12331
  - https://arxiv.org/abs/2601.12331
- ADCPE: "Approximate Distance-Comparison-Preserving Encryption" (Fuchsbauer et al.)
- Vec2Text Attack: Morris et al.

## License

This implementation is licensed under the Apache License 2.0, consistent with the OpenSSL project.

## Contributing

To extend or modify this implementation:

1. **Change noise generation**: Modify `generate_noise_vector_prf()` in `cipher_caprise.c`
2. **Adjust parameters**: Update default values in `cipher_caprise.h`
3. **Add modes**: Extend the mode parameter for different encryption schemes
4. **Optimize performance**: The current implementation uses OpenSSL's HMAC; consider hardware acceleration for production

## Future Enhancements

- [ ] SIMD optimization for vector operations
- [ ] Hardware acceleration support (AVX, ARM NEON)
- [ ] Batch encryption support
- [ ] GPU-based noise generation
- [ ] FIPS mode compliance
- [ ] Integration with OpenSSL's EVP_AEAD interface for authenticated encryption
