/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of the Apache Public License 2.0.
 * The terms of this licenses can be found at:
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of the license along with this
 * software. If not, it may be obtained at the above URL.
 */

#ifndef ARGON2_H
# define ARGON2_H

# include <stdint.h>
# include <stddef.h>
# include <limits.h>

# include <openssl/crypto.h>

/*
 * Argon2 input parameter restrictions
 */

/* Minimum and maximum number of lanes (degree of parallelism) */
# define ARGON2_MIN_LANES UINT32_C(1)
# define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)

/* Minimum and maximum number of threads */
# define ARGON2_MIN_THREADS UINT32_C(1)
# define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)

/* Number of synchronization points between lanes per pass */
# define ARGON2_SYNC_POINTS UINT32_C(4)

/* Minimum and maximum digest size in bytes */
# define ARGON2_MIN_OUTLEN UINT32_C(4)
# define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
# define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS) /* 2 blocks per slice */

# define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
/* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
# define ARGON2_MAX_MEMORY_BITS                                                 \
    ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
# define ARGON2_MAX_MEMORY                                                      \
    ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)

/* Minimum and maximum number of passes */
# define ARGON2_MIN_TIME UINT32_C(1)
# define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)

/* Minimum and maximum password length in bytes */
# define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
# define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum associated data length in bytes */
# define ARGON2_MIN_AD_LENGTH UINT32_C(0)
# define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum salt length in bytes */
# define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
# define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum key length in bytes */
# define ARGON2_MIN_SECRET UINT32_C(0)
# define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)

/* Flags to determine which fields are securely wiped (default = no wipe). */
# define ARGON2_DEFAULT_FLAGS UINT32_C(0)
# define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
# define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)

/* Error codes */
typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = -1,

    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,

    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,

    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,

    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,

    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,

    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,

    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,

    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,

    ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
    ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
    ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
    ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */

    ARGON2_MEMORY_ALLOCATION_ERROR = -22,

    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,

    ARGON2_OUT_PTR_MISMATCH = -27,

    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,

    ARGON2_MISSING_ARGS = -30,

    ARGON2_ENCODING_FAIL = -31,

    ARGON2_DECODING_FAIL = -32,

    ARGON2_THREAD_FAIL = -33,

    ARGON2_DECODING_LENGTH_FAIL = -34,

    ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

/* Memory allocator types --- for external allocation */
typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes);
typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes);

int ossl_alloc(uint8_t **memory, size_t bytes);
void ossl_dealloc(uint8_t *memory, size_t bytes);

/* Argon2 primitive type */
typedef enum Argon2_type {
  Argon2_d = 0,
  Argon2_i = 1,
  Argon2_id = 2
} argon2_type;

/*
 *****
 * Context: structure to hold Argon2 inputs:
 *  output array and its length,
 *  password and its length,
 *  salt and its length,
 *  secret and its length,
 *  associated data and its length,
 *  number of passes, amount of used memory (in KBytes, can be rounded up a bit)
 *  number of parallel threads that will be run.
 * All the parameters above affect the output hash value.
 * Additionally, two function pointers can be provided to allocate and
 * deallocate the memory (if NULL, memory will be allocated internally).
 * Also, three flags indicate whether to erase password, secret as soon as they
 * are pre-hashed (and thus not needed anymore), and the entire memory
 *****
 * Simplest situation: you have output array out[8], password is stored in
 * pwd[32], salt is stored in salt[16], you do not have keys nor associated
 * data. You need to spend 1 GB of RAM and you run 5 passes of Argon2d with
 * 4 parallel lanes.
 * You want to erase the password, but you're OK with last pass not being
 * erased. You want to use the default memory allocator.
 * Then you initialize:
 Argon2_Context(out,8,pwd,32,salt,16,NULL,0,NULL,0,5,1<<20,4,4,NULL,NULL,true,false,false,false)
 */
typedef struct Argon2_Context {
    uint8_t *out;    /* output array */
    uint32_t outlen; /* digest length */

    uint8_t *pwd;    /* password array */
    uint32_t pwdlen; /* password length */

    uint8_t *salt;    /* salt array */
    uint32_t saltlen; /* salt length */

    uint8_t *secret;    /* key array */
    uint32_t secretlen; /* key length */

    uint8_t *ad;    /* associated data array */
    uint32_t adlen; /* associated data length */

    uint32_t t_cost;  /* number of passes */
    uint32_t m_cost;  /* amount of memory requested (KB) */
    uint32_t lanes;   /* number of lanes */
    uint32_t threads; /* maximum number of threads */

    uint32_t version; /* version number */

    allocate_fptr allocate_cbk; /* pointer to memory allocator */
    deallocate_fptr free_cbk;   /* pointer to memory deallocator */

    argon2_type type;

    uint32_t flags; /* array of bool options */
} argon2_context;

typedef argon2_context ARGON2_CTX;

int ARGON2_Init(ARGON2_CTX *c, argon2_type type);
int ARGON2_Update(ARGON2_CTX *c, uint8_t *data, size_t datalen);
int ARGON2_Final(unsigned char *md, ARGON2_CTX *c);

/* Version of the algorithm */
typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

#endif
