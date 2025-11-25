/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * CSNA 2.0 Integration - Constant-Time Annotations for DSLLVM
 *
 * This header provides constant-time annotations for use with the DSLLVM
 * compiler to prevent timing side-channel vulnerabilities. When compiled
 * with DSLLVM, the compiler will verify that annotated functions execute
 * in constant time with respect to secret data.
 */

#ifndef DSMIL_CSNA_H
#define DSMIL_CSNA_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CSNA 2.0 Constant-Time Annotations
 *
 * These macros expand to DSLLVM-specific attributes when building with
 * DSLLVM, otherwise they are no-ops for compatibility with standard compilers.
 */

#if defined(DSLLVM_BUILD) && defined(__clang__)
    /*
     * Mark a function as constant-time
     * The compiler will verify that execution time does not depend on secret data
     */
    #define CSNA_CONSTANT_TIME \
        __attribute__((annotate("csna::constant_time")))

    /*
     * Mark a variable as containing secret data
     * The compiler will track data flow and ensure constant-time operations
     */
    #define CSNA_SECRET \
        __attribute__((annotate("csna::secret")))

    /*
     * Mark a function parameter as secret
     */
    #define CSNA_SECRET_PARAM(name) \
        name __attribute__((annotate("csna::secret")))

    /*
     * Declassify secret data (use with extreme caution!)
     * This tells the compiler that timing dependencies are acceptable beyond this point
     */
    #define CSNA_DECLASSIFY(x) \
        __builtin_annotation((x), "csna::declassify")

    /*
     * Memory barrier for constant-time code
     * Prevents compiler optimizations that might introduce timing variations
     */
    #define CSNA_BARRIER() \
        __asm__ __volatile__("" ::: "memory")

#else
    /* No-op versions for non-DSLLVM builds */
    #define CSNA_CONSTANT_TIME
    #define CSNA_SECRET
    #define CSNA_SECRET_PARAM(name) name
    #define CSNA_DECLASSIFY(x) (x)
    #define CSNA_BARRIER() do { } while (0)
#endif

/*
 * Constant-time comparison function
 * Returns 0 if equal, non-zero otherwise, in constant time
 */
CSNA_CONSTANT_TIME
static inline int csna_memcmp_const(const void *a, const void *b, size_t len)
{
    const unsigned char *aa = (const unsigned char *)a;
    const unsigned char *bb = (const unsigned char *)b;
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= aa[i] ^ bb[i];
    }

    return diff;
}

/*
 * Constant-time conditional select
 * Returns a if condition is non-zero, b otherwise
 * Timing does not depend on condition value
 */
CSNA_CONSTANT_TIME
static inline unsigned char csna_select_byte(unsigned char condition,
                                              unsigned char a,
                                              unsigned char b)
{
    unsigned char mask = (unsigned char)(-(signed char)(condition != 0));
    return (a & mask) | (b & ~mask);
}

/*
 * Constant-time zero check
 * Returns 1 if x is zero, 0 otherwise, in constant time
 */
CSNA_CONSTANT_TIME
static inline int csna_is_zero(unsigned int x)
{
    return (int)((~x & (x - 1)) >> 31);
}

/*
 * Constant-time equality check
 * Returns 1 if equal, 0 otherwise, in constant time
 */
CSNA_CONSTANT_TIME
static inline int csna_eq(unsigned int a, unsigned int b)
{
    return csna_is_zero(a ^ b);
}

/*
 * Timing Variance Measurement Support
 *
 * These functions help measure timing variations in constant-time code
 * for validation and testing purposes.
 */

#ifdef CSNA_TIMING_TESTS

#include <stdint.h>

/* High-resolution timestamp */
static inline uint64_t csna_rdtsc(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    #error "Unsupported architecture for RDTSC"
#endif
}

/* Serialize instruction pipeline (for accurate timing) */
static inline void csna_cpuid_barrier(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(0)
                         : "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("isb" ::: "memory");
#endif
}

/* Timing measurement macros */
#define CSNA_TIMING_START(var) \
    do { \
        csna_cpuid_barrier(); \
        var = csna_rdtsc(); \
    } while (0)

#define CSNA_TIMING_END(var) \
    do { \
        csna_cpuid_barrier(); \
        var = csna_rdtsc() - (var); \
    } while (0)

#endif /* CSNA_TIMING_TESTS */

/*
 * Side-Channel Analysis Hints
 *
 * These annotations help with side-channel analysis during development
 */

#ifdef CSNA_ANALYSIS_MODE
    /* Mark a branch that should be constant-time */
    #define CSNA_CT_BRANCH() \
        __attribute__((annotate("csna::ct_branch")))

    /* Mark a loop that should have constant iteration count */
    #define CSNA_CT_LOOP() \
        __attribute__((annotate("csna::ct_loop")))

    /* Mark memory access that should be constant-time */
    #define CSNA_CT_MEMACCESS() \
        __attribute__((annotate("csna::ct_memaccess")))
#else
    #define CSNA_CT_BRANCH()
    #define CSNA_CT_LOOP()
    #define CSNA_CT_MEMACCESS()
#endif

#ifdef __cplusplus
}
#endif

#endif /* DSMIL_CSNA_H */
