#include <stdio.h>
#include <stdint.h>
#include <string.h>

// MD6 constants
#define MD6_HASH_SIZE 32
#define MD6_BLOCK_SIZE 64
#define MD6_ROUNDS 64

// MD6 state
uint8_t state[MD6_HASH_SIZE];

// MD6 round constants
const uint64_t MD6_K[MD6_ROUNDS] = {
    0x8082d8ef4b3f7ca5, 0x7ce8fcb759e1a908, 0xcf4301f8d6b7f2e9, 0x6d6b8af5c5e6a5f4,
    0x8f5d7dc96b3c5187, 0x5e2b6f9dd9df22e6, 0x6b8d5cd7b3f3b6f8, 0xd8efcbf34b931e0c,
    0x8fa5d7ceb75e2b60, 0x1a908cf4d6b7f2e9, 0x8ef4b3f7ca5d6b8a, 0xf3f7ca5d6b8af5c5,
    0x7ca5d6b8af5c5e6a, 0x7f2e9cf4301f8d6b, 0x7f2e9cf4d6b7f2e9, 0xcf4301f8d6b7f2e9,
    0x8d6b7f2e9cf4301f, 0x8af5c5e6a5f47ce8, 0x8fcb759e1a908cf4, 0x7f2e9cf4d6b7f2e9,
    0x8d6b7f2e9cf4301f, 0x8af5c5e6a5f47ce8, 0x8fcb759e1a908cf4, 0x8ef4b3f7ca5d6b8a,
    0x7ce8fcb759e1a908, 0xcf4301f8d6b7f2e9, 0x6d6b8af5c5e6a5f4, 0x8f5d7dc96b3c5187,
    0x5e2b6f9dd9df22e6, 0x6b8d5cd7b3f3b6f8, 0xd8efcbf34b931e0c, 0x8fa5d7ceb75e2b60,
    0x1a908cf4d6b7f2e9, 0x8ef4b3f7ca5d6b8a, 0xf3f7ca5d6b8af5c5, 0x7ca5d6b8af5c5e6a,
    0x7f2e9cf4301f8d6b, 0x7f2e9cf4d6b7f2e9, 0xcf4301f8d6b7f2e9, 0x8d6b7f2e9cf4301f,
    0x8af5c5e6a5f47ce8, 0x8fcb759e1a908cf4, 0x7f2e9cf4d6b7f2e9, 0x8d6b7f2e9cf4301f,
    0x8af5c5e6a5f47ce8, 0x8fcb759e1a908cf4, 0x8ef4b3f7ca5d6b8a, 0x7ce8fcb759e1a908,
    0xcf4301f8d6b7f2e9, 0x6d6b8af5c5e6a5f4, 0x8f5d7dc96b3c5187, 0x5e2b6f9dd9df22e6,
    0x6b8d5cd7b3f3b6f8, 0xd8efcbf34b931e0c, 0x8fa5d7ceb75e2b60, 0x1a908cf4d6b7f2e9,
    0x8ef4b3f7ca5d6b8a, 0xf3f7ca5d6b8af5c5, 0x7ca5d6b8af5c5e6a, 0x7f2e9cf4301f8d6b,
    0x7f2e9cf4d6b7f2e9, 0xcf4301f8d6b7f2e9, 0x8d6b7f2e9cf4301f, 0x8af5c5e6a5f47ce8,
    0x8fcb759e1a908cf4, 0x7f2e9cf4d6b7f2e9, 0x8d6b7f2e9cf4301f, 0x8af5c5e6a5f47ce8,
    0x8fcb759e1a908cf4, 0x8ef4b3f7ca5d6b8a, 0x7ce8fcb759e1a908, 0xcf4301f8d6b7f2e9,
    0x6d6b8af5c5e6a5f4, 0x8f5d7dc96b3c5187, 0x5e2b6f9dd9df22e6, 0x6b8d5cd7b3f3b6f8,
    0xd8efcbf34b931e0c, 0x8fa5d7ceb75e2b60, 0x1a908cf4d6b7f2e9, 0x8ef4b3f7ca5d6b8a,
    0xf3f7ca5d6b8af5c5, 0x7ca5d6b8af5c5e6a, 0x7f2e9cf4301f8d6b, 0x7f2e9cf4d6b7f2e9,
    0xcf4301f8d6b7f2e9, 0x8d6b7f2e9cf4301f, 0x8af5c5e6a5f47ce8, 0x8fcb759e1a908cf4,
    0x7f2e9cf4d6b7f2e9, 0x8d6b7f2e9cf4301f, 0x8af5c5e6a5f47ce8, 0x8fcb759e1a908cf4
};

// MD6 transformation functions
uint64_t T0(uint64_t x) { return (x >>  1) ^ (x <<  3) ^ (x << 10); }
uint64_t T1(uint64_t x) { return (x >>  1) ^ (x <<  2) ^ (x <<  8); }
uint64_t T2(uint64_t x) { return (x >>  2) ^ (x <<  1) ^ (x <<  7); }
uint64_t T3(uint64_t x) { return (x >>  2) ^ (x <<  2) ^ (x << 16); }
uint64_t T4(uint64_t x) { return (x >>  1) ^ (x <<  2) ^ (x <<  8); }
uint64_t T5(uint64_t x) { return (x >>  2) ^ (x <<  1) ^ (x <<  7); }
uint64_t T6(uint64_t x) { return (x >>  1) ^ (x <<  3) ^ (x << 10); }
uint64_t T7(uint64_t x) { return (x >>  1) ^ (x <<  2) ^ (x <<  8); }

// MD6 operations
uint64_t ADD(uint64_t x, uint64_t y) { return x + y; }
uint64_t MUL(uint64_t x, uint64_t y) { return x * y; }

// MD6 compression
void compression(uint64_t *M) {
    uint64_t B[8];
    uint64_t C[2];
    uint64_t T;

    // Initialize B
    B[0] = ((uint64_t *) state)[0];
    B[1] = ((uint64_t *) state)[1];
    B[2] = ((uint64_t *) state)[2];
    B[3] = ((uint64_t *) state)[3];
    B[4] = ((uint64_t *) state)[4];
    B[5] = ((uint64_t *) state)[5];
    B[6] = ((uint64_t *) state)[6];
    B[7] = ((uint64_t *) state)[7];

    // Initialize C
    C[0] = 0x0123456789abcdef;
    C[1] = 0xfedcba9876543210;

    // MD6 compression
    for (int i = 0; i < MD6_ROUNDS; i++) {
        // Round 1
        T = ADD(B[1], M[i % 8]);
        B[0] = ADD(T, ADD(B[0], MUL(T0(B[1]), T1(B[2]))));

        // Round 2
        T = ADD(B[2], M[(i + 1) % 8]);
        B[1] = ADD(T, ADD(B[1], MUL(T1(B[2]), T2(B[3]))));

        // Round 3
        T = ADD(B[3], M[(i + 2) % 8]);
        B[2] = ADD(T, ADD(B[2], MUL(T2(B[3]), T3(B[4]))));

        // Round 4
        T = ADD(B[4], M[(i + 3) % 8]);
        B[3] = ADD(T, ADD(B[3], MUL(T3(B[4]), T4(B[5]))));

        // Round 5
        T = ADD(B[5], M[(i + 4) % 8]);
        B[4] = ADD(T, ADD(B[4], MUL(T4(B[5]), T5(B[6]))));

        // Round 6
        T = ADD(B[6], M[(i + 5) % 8]);
        B[5] = ADD(T, ADD(B[5], MUL(T5(B[6]), T6(B[7]))));

        // Round 7
        T = ADD(B[7], M[(i + 6) % 8]);
        B[6] = ADD(T, ADD(B[6], MUL(T6(B[7]), T7(B[0]))));

        // Round 8
        T = ADD(B[0], M[(i + 7) % 8]);
        B[7] = ADD(T, ADD(B[7], MUL(T7(B[0]), T0(B[1]))));

        // Round 9
        T = ADD(B[0], MD6_K[i]);
        B[0] = ADD(T, ADD(B[0], MUL(T0(B[1]), T1(B[2]))));

        // Round 10
        T = ADD(B[1], MD6_K[i]);
        B[1] = ADD(T, ADD(B[1], MUL(T1(B[2]), T2(B[3]))));

        // Round 11
        T = ADD(B[2], MD6_K[i]);
        B[2] = ADD(T, ADD(B[2], MUL(T2(B[3]), T3(B[4]))));

        // Round 12
        T = ADD(B[3], MD6_K[i]);
        B[3] = ADD(T, ADD(B[3], MUL(T3(B[4]), T4(B[5]))));

        // Round 13
        T = ADD(B[4], MD6_K[i]);
        B[4] = ADD(T, ADD(B[4], MUL(T4(B[5]), T5(B[6]))));

        // Round 14
        T = ADD(B[5], MD6_K[i]);
        B[5] = ADD(T, ADD(B[5], MUL(T5(B[6]), T6(B[7]))));

        // Round 15
        T = ADD(B[6], MD6_K[i]);
        B[6] = ADD(T, ADD(B[6], MUL(T6(B[7]), T7(B[0]))));

        // Round 16
        T = ADD(B[7], MD6_K[i]);
        B[7] = ADD(T, ADD(B[7], MUL(T7(B[0]), T0(B[1]))));

        // Update C
        T = ADD(B[0], C[0]);
        C[0] = ADD(T, ADD(C[0], MUL(T0(B[0]), T1(B[1]))));

        T = ADD(B[1], C[1]);
        C[1] = ADD(T, ADD(C[1], MUL(T1(B[1]), T2(B[2]))));

        T = ADD(B[2], C[0]);
        C[0] = ADD(T, ADD(C[0], MUL(T2(B[2]), T3(B[3]))));

        T = ADD(B[3], C[1]);
        C[1] = ADD(T, ADD(C[1], MUL(T3(B[3]), T4(B[4]))));

        T = ADD(B[4], C[0]);
        C[0] = ADD(T, ADD(C[0], MUL(T4(B[4]), T5(B[5]))));

        T = ADD(B[5], C[1]);
        C[1] = ADD(T, ADD(C[1], MUL(T5(B[5]), T6(B[6]))));

        T = ADD(B[6], C[0]);
        C[0] = ADD(T, ADD(C[0], MUL(T6(B[6]), T7(B[7]))));

        T = ADD(B[7], C[1]);
        C[1] = ADD(T, ADD(C[1], MUL(T7(B[7]), T0(B[0]))));
    }

    // Update state
    ((uint64_t *) state)[0] ^= B[0];
    ((uint64_t *) state)[1] ^= B[1];
    ((uint64_t *) state)[2] ^= B[2];
    ((uint64_t *) state)[3] ^= B[3];
    ((uint64_t *) state)[4] ^= B[4];
    ((uint64_t *) state)[5] ^= B[5];
    ((uint64_t *) state)[6] ^= B[6];
    ((uint64_t *) state)[7] ^= B[7];
}

// MD6 initialization
void init() {
    // Set state to 0
    memset(state, 0, MD6_HASH_SIZE);
}

// MD6 update
void update(uint8_t *M, uint32_t M_len) {
    uint32_t i = 0;
    uint32_t j = 0;

    // Compression
    for (i = 0; i < M_len / MD6_BLOCK_SIZE; i++) {
        compression((uint64_t *) &M[i * MD6_BLOCK_SIZE]);
    }

    // Final compression
    uint32_t remain = M_len % MD6_BLOCK_SIZE;
    uint8_t final_block[MD6_BLOCK_SIZE];
    memset(final_block, 0, MD6_BLOCK_SIZE);
    memcpy(final_block, &M[i * MD6_BLOCK_SIZE], remain);
    final_block[remain] = 0x80;
    if (MD6_BLOCK_SIZE - remain <= 4) {
        compression((uint64_t *) final_block);
        memset(final_block, 0, MD6_BLOCK_SIZE);
    }
    final_block[MD6_BLOCK_SIZE - 4] = M_len & 0xff;
    final_block[MD6_BLOCK_SIZE - 3] = (M_len >> 8) & 0xff;
    final_block[MD6_BLOCK_SIZE - 2] = (M_len >> 16) & 0xff;
    final_block[MD6_BLOCK_SIZE - 1] = (M_len >> 24) & 0xff;
    compression((uint64_t *) final_block);
}

// MD6 finalization
void final(uint8_t *hash, uint32_t hash_len) {
    // Truncate hash if necessary
    if (hash_len > MD6_HASH_SIZE) {
        hash_len = MD6_HASH_SIZE;
    }

    // Copy hash value
    memcpy(hash, state, hash_len);
}

// MD6 hash
void hash(uint8_t *hash, uint32_t hash_len, uint8_t *M, uint32_t M_len) {
    // Initialization
    init();

    // Update
    update(M, M_len);

    // Finalization
    final(hash, hash_len);
}

void MD6(uint8_t* hash, size_t hash_len, const uint8_t* M, size_t M_len)
{
    // Set up MD6 state
    memset(state, 0, sizeof(state));

    // Compute MD6 hash of input data
    for (size_t i = 0; i < M_len; i++)
    {
        state[i % MD6_HASH_SIZE] ^= M[i];
    }

    // Apply MD6 compression function
    for (size_t i = 0; i < MD6_ROUNDS; i++)
    {
        state[0] += state[1] + MD6_K[i];
        for (size_t j = 0; j < MD6_HASH_SIZE - 1; j++)
        {
            state[j] = state[j + 1];
        }
        state[MD6_HASH_SIZE - 1] = state[0];
    }

    // Copy result to output buffer
    memcpy(hash, state, hash_len);
}
