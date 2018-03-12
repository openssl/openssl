// INFO: Tested on Cortex-A53(odroid-c2), using gcc.
// WARNING: These functions work only on little endian CPU with ARMv8a + NEON architecture
// WARNING: State must be 512 bit (64 bytes) aligned.
// WARNING: Don't use V8-V15 or X19-X28 since we aren't saving them

// Note that byte order, same as the Keyakv2 Convection:
// v19 = A[0] || A[4]
// v19.2d[0] = A[0]
// v19.2d[1] = A[4]

// Register-Lane Lookup
// v19 = A[0]  || A[4]
// v20 = A[1]  || A[5]
// v21 = A[2]  || A[6]
// v22 = A[3]  || A[7]

// v23 = A[8]  || A[12]
// v24 = A[9]  || A[13]
// v25 = A[10] || A[14]
// v26 = A[11] || A[15]

// v27 = A[16] || A[20]
// v28 = A[17] || A[21]
// v29 = A[18] || A[22]
// v30 = A[19] || A[23]

// v31 = A[24] || ?????

// Transpose
// trn1 v0.2d, v19.2d, v20.2d
// trn2 v2.2d, v19.2d, v20.2d
// v0  = A[0] || A[1]
// v1  = A[4] || A[5]

// Extract
// ext v0.16b, v19.16b, v20.16b, #8
// v0  = A[4] || A[1]

.macro    LoadState
    ld4     { v19.2d, v20.2d, v21.2d, v22.2d }, [x0], #64
    ld4     { v23.2d, v24.2d, v25.2d, v26.2d }, [x0], #64
    ld4     { v27.2d, v28.2d, v29.2d, v30.2d }, [x0], #64
    ld1     { v31.d }[0], [x0], #8
    sub     x0, x0, #200
    movi    v16.2d, #0
    .endm

.macro    StoreState
    st4     { v19.2d, v20.2d, v21.2d, v22.2d }, [x0], #64
    st4     { v23.2d, v24.2d, v25.2d, v26.2d }, [x0], #64
    st4     { v27.2d, v28.2d, v29.2d, v30.2d }, [x0], #64
    st1     { v31.d }[0], [x0], #8
    .endm

.macro    RhoPi dst, src, sav, rot
    ror     \src, \src, #64-\rot
    mov     \sav, \dst
    mov     \dst, \src
    .endm

// NEON has no BIT-wise vector rotate operation
.macro    ROTL64  dst, src, rot
    .if (\rot & 7) != 0                 // Bit-wise rotation
    shl     \dst\().2d, \src\().2d, #\rot
    sri     \dst\().2d, \src\().2d, #64-\rot
    .else                               // Byte-wise rotation, we can use EXT
    ext     \dst\().16b, \src\().16b, \src\().16b, #\rot/8
    .endif
    .endm

.macro    KeccakRound
    // Theta - Build new lanes
    eor     v0.16b, v19.16b, v25.16b      // v0 = (A[0] ^ A[10]) || (A[4] ^ A[14])
    eor     v1.16b, v20.16b, v26.16b      // v1 = (A[1] ^ A[11]) || (A[5] ^ A[15])
    eor     v2.16b, v21.16b, v28.16b      // v2 = (A[2] ^ A[17]) || (A[6] ^ A[21])
    eor     v3.16b, v22.16b, v23.16b      // v3 = (A[3] ^ A[8])  || (A[7] ^ A[12])
    eor     v4.16b, v24.16b, v30.16b      // v4 = (A[9] ^ A[19]) || (A[13] ^ A[23])

    eor     v1.16b, v1.16b,  v27.16b      // v1 = (A[1] ^ A[11] ^ A[16]) || (A[5] ^ A[15] ^ A[20])
    eor     v3.16b, v3.16b,  v29.16b      // v3 = (A[3] ^ A[8] ^ A[18])  || (A[7] ^ A[12] ^ A[22])

    trn1    v5.2d, v0.2d, v1.2d           // v5 = (A[0] ^ A[10]) || (A[1] ^ A[11] ^ A[16])
    trn2    v6.2d, v1.2d, v2.2d           // v6 = (A[5] ^ A[15] ^ A[20]) ||  (A[6] ^ A[21])
    eor     v1.16b, v5.16b, v6.16b        // v1 = B[0] || B[1]

    ext     v5.16b, v4.16b, v2.16b, #8    // v5 = (A[13] ^ A[23]) || (A[2] ^ A[17])
    eor     v3.16b, v3.16b, v5.16b        // v3 = B[3] || B[2]

    mov     v5.2d[0], v0.2d[1]            // v5 = (A[4] ^ A[14]) || ????
    eor     v4.16b, v4.16b, v5.16b        // v4 = (A[9] ^ A[19] ^ A[4] ^ A[14]) || ????
    eor     v4.16b, v4.16b, v31.16b       // v4 = B[4] || ????

    ext     v2.16b, v1.16b, v1.16b, #8    // v2 = B[1] || B[0]
    mov     v4.2d[1], v3.2d[0]            // v4 = B[4] || B[3]
    trn2    v0.2d, v3.2d, v1.2d           // v0 = B[2] || B[1]

    ROTL64  v5, v2, 1                     // v5 = ROTL64(B[1], 1) || ROTL64(B[0], 1)
    ROTL64  v6, v3, 1                     // v6 = ROTL64(B[3], 1) || ROTL64(B[2], 1)
    ROTL64  v7, v4, 1                     // v7 = ROTL64(B[4], 1) || ROTL64(B[3], 1)

    eor     v18.16b, v4.16b, v5.16b       // v18 = B[4] ^ ROTL64(B[1], 1) || B[3] ^ ROTL64(B[0], 1)
    eor     v2.16b, v2.16b, v6.16b        // v2  = B[1] ^ ROTL64(B[3], 1) || B[0] ^ ROTL64(B[2], 1)
    eor     v0.16b, v0.16b, v7.16b        // v0  = B[2] ^ ROTL64(B[4], 1) || B[1] ^ ROTL64(B[3], 1)

    ext     v7.16b, v5.16b, v7.16b, #8    // v7 = ROTL64(B[0], 1) || ROTL64(B[4], 1)
    eor     v7.16b, v3.16b, v7.16b        // v7 = B[3] ^ ROTL64(B[0], 1) || B[2] ^ ROTL64(B[4], 1)

    ext     v6.16b, v6.16b, v5.16b, #8    // v6 = ROTL64(B[2], 1) || ROTL64(B[1], 1)
    trn1    v4.2d, v1.2d, v4.2d           // v4 = B[0] || B[4]
    eor     v6.16b, v4.16b, v6.16b        // v6 = B[0] ^ ROTL64(B[2], 1) || B[4] ^ ROTL64(B[1], 1)

    // Theta - Apply lanes
    eor     v19.16b, v19.16b, v18.16b     // A[0]  ^= B[4] ^ ROTL64(B[1], 1), A[4] ^= B[3] ^ ROTL64(B[0], 1)
    eor     v20.16b, v20.16b, v6.16b      // A[1]  ^= B[0] ^ ROTL64(B[2], 1), A[5] ^= B[4] ^ ROTL64(B[1], 1)
    eor     v21.16b, v21.16b, v2.16b      // A[2]  ^= B[1] ^ ROTL64(B[3], 1), A[6] ^= B[0] ^ ROTL64(B[2], 1)
    eor     v22.16b, v22.16b, v0.16b      // A[3]  ^= B[2] ^ ROTL64(B[4], 1), A[7] ^= B[1] ^ ROTL64(B[3], 1)
    eor     v23.16b, v23.16b, v0.16b      // A[8]  ^= B[2] ^ ROTL64(B[4], 1), A[12] ^= B[1] ^ ROTL64(B[3], 1)
    eor     v24.16b, v24.16b, v7.16b      // A[9]  ^= B[3] ^ ROTL64(B[0], 1), A[13] ^= B[2] ^ ROTL64(B[4], 1)
    eor     v25.16b, v25.16b, v18.16b     // A[10] ^= B[4] ^ ROTL64(B[1], 1), A[14] ^= B[3] ^ ROTL64(B[0], 1)
    eor     v26.16b, v26.16b, v6.16b      // A[11] ^= B[0] ^ ROTL64(B[2], 1), A[15] ^= B[4] ^ ROTL64(B[1], 1)
    eor     v27.16b, v27.16b, v6.16b      // A[16] ^= B[0] ^ ROTL64(B[2], 1), A[20] ^= B[4] ^ ROTL64(B[1], 1)
    eor     v28.16b, v28.16b, v2.16b      // A[17] ^= B[1] ^ ROTL64(B[3], 1), A[21] ^= B[0] ^ ROTL64(B[2], 1)
    eor     v29.16b, v29.16b, v0.16b      // A[18] ^= B[2] ^ ROTL64(B[4], 1), A[22] ^= B[1] ^ ROTL64(B[3], 1)
    eor     v30.16b, v30.16b, v7.16b      // A[19] ^= B[3] ^ ROTL64(B[0], 1), A[23] ^= B[2] ^ ROTL64(B[4], 1)
    eor     v31.16b, v31.16b, v7.16b      // A[24] ^= B[3] ^ ROTL64(B[0], 1), ????

    // Rho Pi
    mov     x11, v20.2d[0]                // x11   = A[1]

    RhoPi   v25.2d[0], x11, x10, 1        // A[10] = ROTL64(A[1], 1)
    RhoPi   v22.2d[1], x10, x11, 3        // A[7]  = ROTL64(A[10], 3)
    RhoPi   v26.2d[0], x11, x10, 6        // A[11] = ROTL64(A[7], 6)
    RhoPi   v28.2d[0], x10, x11, 10       // A[17] = ROTL64(A[11], 10)
    RhoPi   v29.2d[0], x11, x10, 15       // A[18] = ROTL64(A[17], 15)
    RhoPi   v22.2d[0], x10, x11, 21       // A[3]  = ROTL64(A[18], 21)
    RhoPi   v20.2d[1], x11, x10, 28       // A[5]  = ROTL64(A[3], 28)
    RhoPi   v27.2d[0], x10, x11, 36       // A[16] = ROTL64(A[5], 36)
    RhoPi   v23.2d[0], x11, x10, 45       // A[8]  = ROTL64(A[16], 45)
    RhoPi   v28.2d[1], x10, x11, 55       // A[21] = ROTL64(A[8], 55)
    RhoPi   v31.2d[0], x11, x10, 2        // A[24] = ROTL64(A[21], 2)
    RhoPi   v19.2d[1], x10, x11, 14       // A[4]  = ROTL64(A[24], 14)
    RhoPi   v26.2d[1], x11, x10, 27       // A[15] = ROTL64(A[4], 27)
    RhoPi   v30.2d[1], x10, x11, 41       // A[23] = ROTL64(A[15], 41)
    RhoPi   v30.2d[0], x11, x10, 56       // A[19] = ROTL64(A[23], 56)
    RhoPi   v24.2d[1], x10, x11, 8        // A[13] = ROTL64(A[19], 8)
    RhoPi   v23.2d[1], x11, x10, 25       // A[12] = ROTL64(A[13], 25)
    RhoPi   v21.2d[0], x10, x11, 43       // A[2]  = ROTL64(A[12], 43)
    RhoPi   v27.2d[1], x11, x10, 62       // A[20] = ROTL64(A[2], 62)
    RhoPi   v25.2d[1], x10, x11, 18       // A[14] = ROTL64(A[20], 18)
    RhoPi   v29.2d[1], x11, x10, 39       // A[22] = ROTL64(A[14], 39)
    RhoPi   v24.2d[0], x10, x11, 61       // A[9]  = ROTL64(A[22], 61)
    RhoPi   v21.2d[1], x11, x10, 20       // A[6]  = ROTL64(A[9], 20)

    ror     x10, x10, #20
    mov     v20.2d[0], x10                // A[1]  = ROTL64(A[6], 44)

    // Chi - Some lanes are applied earlier so we can reuse registers
    ext     v18.16b, v26.16b, v31.16b, #8 // v18 = A[15] || A[24]
    bic     v6.16b, v27.16b, v18.16b      // v6 = ~A[15] & A[16] || ~A[24] & A[20]

    ext     v17.16b, v26.16b, v31.16b, #8 // v17 =  A[15] ||  A[24]
    bic     v5.16b, v17.16b, v30.16b      // v5 = ~A[19] & A[15] || ~A[23] & A[24]

    bic     v3.16b, v30.16b, v29.16b      // v3 = ~A[18] & A[19] || ~A[22] & A[23]

    eor     v30.16b, v30.16b, v6.16b      // A[19] ^= ~A[15] & A[16], A[23] ^= ~A[24] & A[20]

    trn1    v18.2d, v26.2d, v25.2d        // v18 =  A[11] ||  A[10]
    ext     v17.16b, v23.16b, v26.16b, #8 // v17 =  A[12] ||  A[11]
    bic     v7.16b, v17.16b, v18.16b      // v7  =  ~A[11] & A[12] || ~A[10] & A[11]

    trn2    v18.2d, v20.2d, v25.2d        // v18 =  A[5]  ||  A[14]
    ext     v17.16b, v21.16b, v25.16b, #8 // v17 =  A[6]  ||  A[10]
    bic     v6.16b, v17.16b, v18.16b      // v6  = ~A[5] & A[6] || ~A[14] & A[10]

    trn1    v18.2d, v20.2d, v19.2d        // v18 =  A[1] ||  A[0]
    trn1    v17.2d, v21.2d, v20.2d        // v17 =  A[2] ||  A[1]
    bic     v1.16b, v17.16b, v18.16b      // v1  = ~A[1] & A[2] || ~A[0] & A[1]

    ext     v18.16b, v19.16b, v23.16b, #8 // v18 =  A[4] ||  A[8]
    trn1    v17.2d, v19.2d, v24.2d        // v17 =  A[0] ||  A[9]
    bic     v0.16b, v17.16b, v18.16b      // v0  = ~A[4] & A[0] || ~A[8] & A[9]

    ext     v18.16b, v23.16b, v27.16b, #8 // v18 =  A[12] ||  A[16]
    ext     v17.16b, v24.16b, v28.16b, #8 // v17 =  A[13] ||  A[17]
    bic     v4.16b, v17.16b, v18.16b      // v4  = ~A[12] & A[13] || ~A[16] & A[17]

    mov     v18.2d[0], v27.2d[1]          // v18 =  A[20] || ????
    mov     v17.2d[0], v28.2d[1]          // v17 =  A[21] || ????
    bic     v2.16b, v17.16b, v18.16b      // v2  = ~A[20] & A[21] || ????
    eor     v31.16b, v31.16b, v2.16b      // A[24] ^= ~A[20] & A[21], ????

    bic     v2.16b, v29.16b, v28.16b      // v2  = ~A[17] & A[18] || ~A[21] & A[22]
    eor     v27.16b, v27.16b, v2.16b      // A[16] ^= ~A[17] & A[18], A[20] ^= ~A[21] & A[22]

    bic     v2.16b, v22.16b, v21.16b      // v2  = ~A[2]  & A[3]  || ~A[6]  & A[7]

    eor     v28.16b, v28.16b, v3.16b      // A[17] ^= ~A[18] & A[19], A[21] ^= ~A[22] & A[23]
    eor     v29.16b, v29.16b, v5.16b      // A[18] ^= ~A[19] & A[15], A[22] ^= ~A[23] & A[24]

    ext     v17.16b, v19.16b, v23.16b, #8 // v17 =  A[4] || A[8]
    bic     v3.16b, v17.16b, v22.16b      // v3  = ~A[3]  & A[4]  || ~A[7]  & A[8]

    trn2    v17.2d, v20.2d, v25.2d        // v17 =  A[5]  || A[14]
    bic     v5.16b, v17.16b, v24.16b      // v5  = ~A[9]  & A[5]  || ~A[13] & A[14]

    // Chi - Apply remaining lanes
    eor     v19.16b, v19.16b, v1.16b      // A[0] ^= ~A[1] & A[2], A[4] ^= ~A[0] & A[1]
    eor     v20.16b, v20.16b, v2.16b      // A[1] ^= ~A[2] & A[3], A[5] ^= ~A[6] & A[7]
    eor     v21.16b, v21.16b, v3.16b      // A[2] ^= ~A[3] & A[4], A[6] ^= ~A[7] & A[8]
    eor     v22.16b, v22.16b, v0.16b      // A[3] ^= ~A[4] & A[0], A[7] ^= ~A[8] & A[9]
    eor     v23.16b, v23.16b, v5.16b      // A[8] ^= ~A[9] & A[5], A[12] ^= ~A[13] & A[14]
    eor     v24.16b, v24.16b, v6.16b      // A[9] ^= ~A[5] & A[6], A[13] ^= ~A[14] & A[10]
    eor     v25.16b, v25.16b, v7.16b      // A[10] ^= ~A[11] & A[12], A[14] ^= ~A[10] & A[11]
    eor     v26.16b, v26.16b, v4.16b      // A[11] ^= ~A[12] & A[13], A[15] ^= ~A[16] & A[17]

    // Iota
    ld1     { v16.d }[0], [x1], #8
    eor     v19.16b, v19.16b, v16.16b
    .endm

.align 8
KeccakP1600_Permute_RoundConstants24:
    .quad   0x0000000000000001
    .quad   0x0000000000008082
    .quad   0x800000000000808a
    .quad   0x8000000080008000
    .quad   0x000000000000808b
    .quad   0x0000000080000001
    .quad   0x8000000080008081
    .quad   0x8000000000008009
    .quad   0x000000000000008a
    .quad   0x0000000000000088
    .quad   0x0000000080008009
    .quad   0x000000008000000a
KeccakP1600_Permute_RoundConstants12:
    .quad   0x000000008000808b
    .quad   0x800000000000008b
    .quad   0x8000000000008089
    .quad   0x8000000000008003
    .quad   0x8000000000008002
    .quad   0x8000000000000080
    .quad   0x000000000000800a
    .quad   0x800000008000000a
    .quad   0x8000000080008081
    .quad   0x8000000000008080
    .quad   0x0000000080000001
    .quad   0x8000000080008008
KeccakP1600_Permute_RoundConstants0:

//----------------------------------------------------------------------------
//
// void KeccakP1600_Initialize(void *state)
//
.align 8
.global   KeccakP1600_Initialize
KeccakP1600_Initialize:
    movi    v0.2d, #0
    movi    v1.2d, #0
    movi    v2.2d, #0
    movi    v3.2d, #0
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64  // Clear 8lanes=64 bytes at a time
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    st1     { v0.d }[0], [x0], #8
    ret


// ----------------------------------------------------------------------------
//
//  void KeccakP1600_AddByte(void *state, unsigned char byte, unsigned int offset)
//
.align 8
.global   KeccakP1600_AddByte
KeccakP1600_AddByte:
    ldrb    w3, [x0, x2]
    eor     w3, w3, w1
    strb    w3, [x0, x2]
    ret


// ----------------------------------------------------------------------------
//
//  void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
//
.align 8
.global   KeccakP1600_AddBytes
KeccakP1600_AddBytes:
    add     x0, x0, x2
    subs    w4, w3, #1
    b.cc    KeccakP1600_AddBytes_Exit // length 0, move along
KeccakP1600_AddBytes_8LanesLoop: // Go 8 lanes=64 bytes at a time
    subs    w3, w3, #64
    b.cc    KeccakP1600_AddBytes_Lanes // Jump if length is negative
    ld4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0]
    ld4     { v4.2d, v5.2d, v6.2d, v7.2d }, [x1], #64
    eor     v0.16b, v0.16b, v4.16b
    eor     v1.16b, v1.16b, v5.16b
    eor     v2.16b, v2.16b, v6.16b
    eor     v3.16b, v3.16b, v7.16b
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    b       KeccakP1600_AddBytes_8LanesLoop
KeccakP1600_AddBytes_Lanes: // If length ever becomes negative, we have to fix it
    add     w3, w3, #64
KeccakP1600_AddBytes_LanesLoop: // Same thing but go 1 lanes=8 bytes at a time
    subs    w3, w3, #8
    b.cc    KeccakP1600_AddBytes_Bytes
    ld1     { v0.d }[0], [x0]
    ld1     { v4.d }[0], [x1], #8
    eor     v0.8b, v0.8b, v4.8b
    st1     { v0.d }[0], [x0], #8
    b       KeccakP1600_AddBytes_LanesLoop
KeccakP1600_AddBytes_Bytes:
    add     w3, w3, #8
KeccakP1600_AddBytes_BytesLoop: // Same thing but go 1 byte at a time
    subs    w3, w3, #1
    b.cc    KeccakP1600_AddBytes_Exit
    ldrb    w4, [x0]
    ldrb    w5, [x1], #1
    eor     w4, w4, w5
    strb    w4, [x0], #1
    b       KeccakP1600_AddBytes_BytesLoop
KeccakP1600_AddBytes_Exit:
    ret

// ----------------------------------------------------------------------------
//
//  void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
//
.align 8
.global   KeccakP1600_OverwriteBytes
KeccakP1600_OverwriteBytes:
    add     x0, x0, x2
    subs    w4, w3, #1
    b.cc    KeccakP1600_OverwriteBytes_Exit
KeccakP1600_OverwriteBytes_8LanesLoop:
    subs    w3, w3, #64
    b.cc    KeccakP1600_OverwriteBytes_Lanes
    ld4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x1], #64
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    b       KeccakP1600_OverwriteBytes_8LanesLoop
KeccakP1600_OverwriteBytes_Lanes:
    add    w3, w3, #64
KeccakP1600_OverwriteBytes_LanesLoop:
    subs    w3, w3, #8
    b.cc    KeccakP1600_OverwriteBytes_Bytes
    ld1     { v0.d }[0], [x1], #8
    st1     { v0.d }[0], [x0], #8
    b       KeccakP1600_OverwriteBytes_LanesLoop
KeccakP1600_OverwriteBytes_Bytes:
    add    w3, w3, #8
KeccakP1600_OverwriteBytes_BytesLoop:
    subs    w3, w3, #1
    b.cc    KeccakP1600_OverwriteBytes_Exit
    ldrb    w4, [x1], #1
    strb    w4, [x0], #1
    b       KeccakP1600_OverwriteBytes_BytesLoop
KeccakP1600_OverwriteBytes_Exit:
    ret


//----------------------------------------------------------------------------
//
// void KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount)
//
.align 8
.global   KeccakP1600_OverwriteWithZeroes
KeccakP1600_OverwriteWithZeroes:
    subs    w2, w1, #1
    b.cc    KeccakP1600_OverwriteWithZeroes_Exit
    movi    v0.2d, #0
    movi    v1.2d, #0
    movi    v2.2d, #0
    movi    v3.2d, #0
    mov     w2, #0
KeccakP1600_OverwriteWithZeroes_8LanesLoop:
    subs    w1, w1, #64
    b.cc    KeccakP1600_OverwriteWithZeroes_Lanes
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    b       KeccakP1600_OverwriteWithZeroes_8LanesLoop
KeccakP1600_OverwriteWithZeroes_Lanes:
    add     w1, w1, #64
KeccakP1600_OverwriteWithZeroes_LanesLoop:
    subs    w1, w1, #8
    b.cc    KeccakP1600_OverwriteWithZeroes_Bytes
    st1     { v0.d }[0], [x0], #8
    b       KeccakP1600_OverwriteWithZeroes_LanesLoop
KeccakP1600_OverwriteWithZeroes_Bytes:
    add     w1, w1, #8
KeccakP1600_OverwriteWithZeroes_LoopBytes:
    subs    w1, w1, #1
    b.cc    KeccakP1600_OverwriteWithZeroes_Exit
    strb    w2, [x0], #1
    b       KeccakP1600_OverwriteWithZeroes_LoopBytes
KeccakP1600_OverwriteWithZeroes_Exit:
    ret


// ----------------------------------------------------------------------------
//
//  void KeccakP1600_ExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
//
.align 8
.global   KeccakP1600_ExtractBytes
KeccakP1600_ExtractBytes:
    add     x0, x0, x2
    subs    w4, w3, #1
    b.cc    KeccakP1600_ExtractBytes_Exit
KeccakP1600_ExtractBytes_8LanesLoop:
    subs    w3, w3, #64
    b.cc    KeccakP1600_ExtractBytes_Lanes
    ld4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x1], #64
    b       KeccakP1600_ExtractBytes_8LanesLoop
KeccakP1600_ExtractBytes_Lanes:
    add     w3, w3, #64
KeccakP1600_ExtractBytes_LanesLoop:
    subs    w3, w3, #8
    b.cc    KeccakP1600_ExtractBytes_Bytes
    ld1     { v0.d }[0], [x0], #8
    st1     { v0.d }[0], [x1], #8
    b       KeccakP1600_ExtractBytes_LanesLoop
KeccakP1600_ExtractBytes_Bytes:
    add     w3, w3, #8
KeccakP1600_ExtractBytes_BytesLoop:
    subs    w3, w3, #1
    b.cc    KeccakP1600_ExtractBytes_Exit
    ldrb    w4, [x0], #1
    strb    w4, [x1], #1
    b       KeccakP1600_ExtractBytes_BytesLoop
KeccakP1600_ExtractBytes_Exit:
    ret


// ----------------------------------------------------------------------------
//
//  void KeccakP800_ExtractAndAddBytes(void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
//
.align 8
.global   KeccakP1600_ExtractAndAddBytes
KeccakP1600_ExtractAndAddBytes:
    add     x0, x0, x3
    subs    w5, w4, #1
    b.cc    KeccakP1600_ExtractAndAddBytes_Exit
KeccakP1600_ExtractAndAddBytes_8LanesLoop:
    subs    w4, w4, #64
    b.cc    KeccakP1600_ExtractAndAddBytes_Lanes
    ld4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x0], #64
    ld4     { v4.2d, v5.2d, v6.2d, v7.2d }, [x1], #64
    eor     v0.16b, v0.16b, v4.16b
    eor     v1.16b, v1.16b, v5.16b
    eor     v2.16b, v2.16b, v6.16b
    eor     v3.16b, v3.16b, v7.16b
    st4     { v0.2d, v1.2d, v2.2d, v3.2d }, [x2], #64
    b       KeccakP1600_ExtractAndAddBytes_8LanesLoop
KeccakP1600_ExtractAndAddBytes_Lanes:
    add     w4, w4, #64
KeccakP1600_ExtractAndAddBytes_LanesLoop:
    subs    w4, w4, #8
    b.cc    KeccakP1600_ExtractAndAddBytes_Bytes
    ld1     { v0.d }[0], [x0], #8
    ld1     { v4.d }[0], [x1], #8
    eor     v0.8b, v0.8b, v4.8b
    st1     { v0.d }[0], [x2], #8
    b       KeccakP1600_ExtractAndAddBytes_LanesLoop
KeccakP1600_ExtractAndAddBytes_Bytes:
    add     w4, w4, #8
KeccakP1600_ExtractAndAddBytes_BytesLoop:
    subs    w4, w4, #1
    b.cc    KeccakP1600_ExtractAndAddBytes_Exit
    ldrb    w5, [x0], #1
    ldrb    w6, [x1], #1
    eor     w5, w5, w6
    strb    w5, [x2], #1
    b       KeccakP1600_ExtractAndAddBytes_BytesLoop
KeccakP1600_ExtractAndAddBytes_Exit:
    ret

// ----------------------------------------------------------------------------
//
//  void KeccakP1600_Permute_Nrounds( void *state, unsigned int nrounds )
//
.align 8
.global   KeccakP1600_Permute_Nrounds
KeccakP1600_Permute_Nrounds:
    mov     x2, x1
    adr     x1, KeccakP1600_Permute_RoundConstants0
	lsl		x3, x2, #3
	sub		x1, x1, x3
    b       KeccakP1600_Permute

// ----------------------------------------------------------------------------
//
//  void KeccakP1600_Permute_12rounds( void *state )
//
.align 8
.global   KeccakP1600_Permute_12rounds
KeccakP1600_Permute_12rounds:
    adr     x1, KeccakP1600_Permute_RoundConstants12
    mov     x2, #12
    b       KeccakP1600_Permute


// ----------------------------------------------------------------------------
//
//  void KeccakP1600_Permute_24rounds( void *state )
//
.align 8
.global   KeccakP1600_Permute_24rounds
KeccakP1600_Permute_24rounds:
    adr     x1, KeccakP1600_Permute_RoundConstants24
    mov     x2, #24
    b       KeccakP1600_Permute

//----------------------------------------------------------------------------
//
// void KeccakP1600_Permute( void *state, uint64_t *rc, unsigned int nrounds )
//
.align 8
.global   KeccakP1600_Permute
KeccakP1600_Permute:
    LoadState
KeccakP1600_Permute_RoundLoop:
    KeccakRound
    subs    w2, w2, #1
    bne     KeccakP1600_Permute_RoundLoop
KeccakP1600_Permute_Exit:
    StoreState
    ret
