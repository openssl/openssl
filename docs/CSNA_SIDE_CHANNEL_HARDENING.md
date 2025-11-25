# CSNA Integration & Side-Channel Hardening
**Phase 6 Implementation Guide**

Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY
Version: 1.0.0
Date: 2025-11-25

---

## Table of Contents

1. [Overview](#overview)
2. [CSNA 2.0 Annotations](#csna-20-annotations)
3. [Constant-Time Utilities](#constant-time-utilities)
4. [Timing Variance Testing](#timing-variance-testing)
5. [Side-Channel Analysis](#side-channel-analysis)
6. [Usage Guidelines](#usage-guidelines)
7. [Performance Considerations](#performance-considerations)
8. [Testing and Validation](#testing-and-validation)

---

## Overview

Phase 6 implements comprehensive side-channel hardening for DSMIL OpenSSL using DSLLVM's CSNA 2.0 (Constant-time Static Analysis) framework. This provides compiler-verified constant-time execution for cryptographic operations, preventing timing side-channel attacks.

### Key Features

- **Compiler-Verified Constant-Time**: DSLLVM checks that annotated code executes in constant time
- **Secret Data Tracking**: Compiler tracks secret data flow through functions
- **Timing Measurement**: High-resolution timing primitives for validation
- **Architecture Support**: x86/x86_64 and ARM64 architectures
- **Zero Runtime Overhead**: Annotations compile away in non-DSLLVM builds

---

## CSNA 2.0 Annotations

### Header Location

```c
#include "providers/dsmil/csna.h"
```

### Core Annotations

#### CSNA_CONSTANT_TIME

Marks a function as constant-time. DSLLVM will verify that execution time does not depend on secret data.

```c
CSNA_CONSTANT_TIME
static int verify_signature(const uint8_t *signature, size_t sig_len,
                            CSNA_SECRET_PARAM(const uint8_t *secret_key))
{
    /* Compiler verifies constant-time execution */
    return constant_time_verify(signature, secret_key);
}
```

#### CSNA_SECRET

Marks a variable as containing secret data. The compiler tracks this data through the program.

```c
CSNA_SECRET uint8_t private_key[32];
CSNA_SECRET uint8_t session_key[16];
```

#### CSNA_SECRET_PARAM

Marks a function parameter as secret.

```c
int encrypt_data(const uint8_t *plaintext,
                 CSNA_SECRET_PARAM(const uint8_t *key),
                 uint8_t *ciphertext);
```

#### CSNA_DECLASSIFY

Declassifies secret data (use with extreme caution!). Tells the compiler that timing dependencies beyond this point are acceptable.

```c
CSNA_SECRET int comparison_result = constant_time_compare(a, b);
/* Result is now public - OK to branch on it */
int public_result = CSNA_DECLASSIFY(comparison_result);
if (public_result != 0) {
    /* Branch is OK - data is declassified */
    return ERROR;
}
```

#### CSNA_BARRIER

Memory barrier to prevent compiler optimizations that might introduce timing variations.

```c
CSNA_CONSTANT_TIME
void secure_clear(uint8_t *buffer, size_t len)
{
    memset(buffer, 0, len);
    CSNA_BARRIER();  /* Prevents compiler from optimizing away memset */
}
```

### Analysis Mode Annotations

When `CSNA_ANALYSIS_MODE` is defined, additional annotations help with side-channel analysis:

```c
CSNA_CT_BRANCH()    /* Marks a constant-time branch */
CSNA_CT_LOOP()      /* Marks a constant-iteration loop */
CSNA_CT_MEMACCESS() /* Marks constant-time memory access */
```

---

## Constant-Time Utilities

### Constant-Time Memory Comparison

```c
CSNA_CONSTANT_TIME
static inline int csna_memcmp_const(const void *a, const void *b, size_t len);
```

**Usage:**

```c
CSNA_SECRET uint8_t expected_hmac[32];
uint8_t received_hmac[32];

/* Constant-time comparison */
int diff = csna_memcmp_const(expected_hmac, received_hmac, 32);
if (diff != 0) {
    return VERIFICATION_FAILED;
}
```

### Constant-Time Conditional Select

```c
CSNA_CONSTANT_TIME
static inline unsigned char csna_select_byte(unsigned char condition,
                                              unsigned char a,
                                              unsigned char b);
```

**Usage:**

```c
/* Select value based on condition, in constant time */
unsigned char result = csna_select_byte(is_valid, SUCCESS_VALUE, ERROR_VALUE);
```

### Constant-Time Zero Check

```c
CSNA_CONSTANT_TIME
static inline int csna_is_zero(unsigned int x);
```

**Returns:** 1 if `x` is zero, 0 otherwise, in constant time.

```c
/* Check if value is zero without timing leak */
int is_zero = csna_is_zero(error_code);
```

### Constant-Time Equality

```c
CSNA_CONSTANT_TIME
static inline int csna_eq(unsigned int a, unsigned int b);
```

**Returns:** 1 if `a == b`, 0 otherwise, in constant time.

```c
/* Compare values in constant time */
int is_equal = csna_eq(received_nonce, expected_nonce);
```

---

## Timing Variance Testing

### Enabling Timing Tests

Compile with `-DCSNA_TIMING_TESTS`:

```bash
./Configure dsllvm-dsmil -DCSNA_TIMING_TESTS
```

### Timing Primitives

#### High-Resolution Timestamp

```c
uint64_t csna_rdtsc(void);
```

Uses `RDTSC` on x86/x86_64 or `CNTVCT_EL0` on ARM64 to get cycle-accurate timestamps.

#### Pipeline Serialization

```c
void csna_cpuid_barrier(void);
```

Ensures all prior instructions complete before timing measurement.

#### Timing Measurement Macros

```c
uint64_t start_time, elapsed_time;

CSNA_TIMING_START(start_time);
/* Operation to measure */
perform_constant_time_operation();
CSNA_TIMING_END(elapsed_time);

printf("Operation took %llu cycles\n", (unsigned long long)elapsed_time);
```

### Statistical Analysis

For constant-time validation, measure the same operation with different inputs and verify timing variance is minimal:

```c
#define NUM_SAMPLES 10000
uint64_t timings[NUM_SAMPLES];

for (int i = 0; i < NUM_SAMPLES; i++) {
    uint64_t t;
    CSNA_TIMING_START(t);
    constant_time_operation(inputs[i]);
    CSNA_TIMING_END(t);
    timings[i] = t;
}

/* Analyze variance - should be < 1% for constant-time */
double mean, stddev;
calculate_stats(timings, NUM_SAMPLES, &mean, &stddev);
double cv = stddev / mean;  /* Coefficient of variation */

if (cv > 0.01) {
    fprintf(stderr, "WARNING: Timing variance %.2f%% - may not be constant-time\n",
            cv * 100);
}
```

---

## Side-Channel Analysis

### DSLLVM Compiler Checks

When building with DSLLVM and `-DCSNA_CONSTANT_TIME_CHECK`:

```bash
export CC=dsclang
export CXX=dsclang++
./Configure dsllvm-dsmil -DCSNA_CONSTANT_TIME_CHECK
make
```

The compiler will:

1. **Track Secret Data**: Follow `CSNA_SECRET` annotated data through the program
2. **Verify Constant-Time**: Check that `CSNA_CONSTANT_TIME` functions don't branch on secrets
3. **Emit Warnings**: Alert on potential timing leaks

### Common Violations

#### Branching on Secrets

```c
/* BAD - timing depends on secret */
CSNA_CONSTANT_TIME
int bad_verify(CSNA_SECRET_PARAM(const uint8_t *key))
{
    if (key[0] == 0x42) {  /* ❌ Branch on secret - VIOLATION */
        return process_special_case();
    }
    return normal_process();
}
```

**Fix:** Use constant-time select:

```c
/* GOOD - constant time */
CSNA_CONSTANT_TIME
int good_verify(CSNA_SECRET_PARAM(const uint8_t *key))
{
    int is_special = csna_eq(key[0], 0x42);
    int normal_result = normal_process();
    int special_result = process_special_case();
    return csna_select_byte(is_special, special_result, normal_result);
}
```

#### Variable-Time Loops

```c
/* BAD - loop count depends on secret */
CSNA_CONSTANT_TIME
int bad_process(CSNA_SECRET_PARAM(const uint8_t *data), size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (data[i] == 0x00) break;  /* ❌ Early exit on secret */
        process_byte(data[i]);
    }
}
```

**Fix:** Process all bytes regardless:

```c
/* GOOD - fixed iteration count */
CSNA_CONSTANT_TIME
int good_process(CSNA_SECRET_PARAM(const uint8_t *data), size_t len)
{
    for (size_t i = 0; i < len; i++) {
        /* Process all bytes, result masked if zero */
        int is_zero = csna_is_zero(data[i]);
        process_byte_masked(data[i], !is_zero);
    }
}
```

#### Table Lookups on Secret Indices

```c
/* BAD - memory access time may vary by address */
CSNA_CONSTANT_TIME
uint8_t bad_sbox(CSNA_SECRET_PARAM(uint8_t index))
{
    return sbox_table[index];  /* ❌ Cache timing leak possible */
}
```

**Fix:** Use constant-time table access or bitslicing.

---

## Usage Guidelines

### When to Use Annotations

**Always annotate:**

- Private key operations (sign, decrypt, key agreement)
- Password/passphrase comparisons
- HMAC/signature verification
- KEM decapsulation
- Padding oracle-sensitive code

**Generally safe without annotations:**

- Public key operations (encrypt, verify)
- Hash computations on public data
- Non-cryptographic operations

### Annotation Checklist

- [ ] Mark all secret keys with `CSNA_SECRET`
- [ ] Annotate constant-time functions with `CSNA_CONSTANT_TIME`
- [ ] Use `csna_memcmp_const()` for all secret comparisons
- [ ] Avoid branching on secret-derived values
- [ ] Use fixed iteration counts for loops
- [ ] Be careful with table lookups (cache timing)
- [ ] Declassify data explicitly when moving to public domain

### Integration with OpenSSL

Example: ML-KEM decapsulation (constant-time critical):

```c
#include "providers/dsmil/csna.h"

CSNA_CONSTANT_TIME
int ml_kem_decapsulate(CSNA_SECRET_PARAM(const uint8_t *secret_key),
                       const uint8_t *ciphertext,
                       uint8_t *shared_secret)
{
    /* Decapsulation must be constant-time to prevent key recovery */
    CSNA_SECRET uint8_t decap_result[32];

    /* Perform decapsulation */
    int status = internal_decap(secret_key, ciphertext, decap_result);

    /* Use constant-time operations throughout */
    CSNA_BARRIER();
    memcpy(shared_secret, decap_result, 32);

    return status;
}
```

---

## Performance Considerations

### Overhead

- **DSLLVM build with annotations**: ~0-2% overhead (mostly from prevented optimizations)
- **Non-DSLLVM build**: 0% overhead (annotations compile away)
- **Constant-time utilities**: Minimal overhead (branchless operations)

### Optimization Tips

1. **Limit annotation scope**: Only annotate truly secret-dependent code
2. **Declassify early**: Move data to public domain as soon as safe
3. **Profile timing**: Use `CSNA_TIMING_*` macros to identify bottlenecks
4. **Batch operations**: Process multiple secrets in one constant-time function

---

## Testing and Validation

### Running Tests

```bash
# Run timing variance test suite
cd test/dsmil
./test-timing-variance.sh
```

### Expected Output

```
==========================================
DSMIL Timing Variance Test Suite
Phase 6: CSNA Integration & Side-Channel Hardening
==========================================

[TEST] Checking for CSNA annotation header
[PASS] CSNA header exists: providers/dsmil/csna.h
[TEST] Checking CSNA macro definitions
[PASS] CSNA_CONSTANT_TIME macro defined
[PASS] CSNA_SECRET macro defined
...
Total tests: 45
Passed: 45
Failed: 0

✓ All timing variance tests passed!
```

### Functional Testing

The test suite compiles a small program to verify constant-time utilities work correctly:

```c
/* Test constant-time memcmp */
int res1 = csna_memcmp_const(same_data_a, same_data_b, 16);  /* Should be 0 */
int res2 = csna_memcmp_const(same_data, diff_data, 16);      /* Should be non-zero */

/* Test constant-time select */
unsigned char sel1 = csna_select_byte(1, 42, 99);  /* Should return 42 */
unsigned char sel2 = csna_select_byte(0, 42, 99);  /* Should return 99 */
```

### Timing Variance Validation

For production validation, use statistical timing analysis:

```bash
# Enable timing tests
./Configure dsllvm-dsmil -DCSNA_TIMING_TESTS
make clean && make

# Run benchmarks with different inputs
./test/timing_benchmark --operation=kem_decap --samples=10000

# Analyze results (coefficient of variation should be < 1%)
```

---

## References

1. **DSLLVM Compiler**: https://github.com/SWORDIntel/DSLLVM
2. **CSNA 2.0 Specification**: Internal DSMIL documentation
3. **Constant-Time Programming**: https://www.bearssl.org/ctmul.html
4. **Timing Attack Survey**: Kocher et al., "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems"

---

**Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY
**Contact:** DSMIL Security Team
**Version:** 1.0.0
