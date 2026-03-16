#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# AES for ARMv9 via SME Streaming SVE (SSVE)
# ====================================================================
#
# This module implements AES-CTR (ctr32) and AES-CBC-decrypt using
# ARM's Scalable Matrix Extension (SME) in Streaming SVE mode.
#
# The key benefit over plain NEON AES is scalability: when the
# Streaming Vector Length (SVL) exceeds 128 bits, NVEC = SVL/16
# AES blocks are processed simultaneously per AES instruction:
#
#   SVL=128  bits (NVEC=1): comparable to NEON baseline
#   SVL=256  bits (NVEC=2): ~2x throughput
#   SVL=512  bits (NVEC=4): ~4x throughput
#   SVL=1024 bits (NVEC=8): ~8x throughput
#
# Requires: FEAT_SME (streaming SVE mode) AND FEAT_SSVE_AES
#           (SVE AES z-register instructions available in Streaming SVE mode).
# Detection: ARMV9_SME and ARMV9_SME_AES both set in OPENSSL_armcap_P.
#
# Exported functions:
#   aes_v8_sme_ctr32_encrypt_blocks  – AES-CTR encrypt/decrypt
#   aes_v8_sme_cbc_decrypt           – AES-CBC decrypt
#
# ---- z-register layout ----
#   z0      – CTR: counter state (NVEC distinct ctr32 values)
#             CBC: ciphertext input
#   z1      – AES working state (enc or dec)
#   z2      – plaintext input (CTR XOR operand, CBC tail prev-IV)
#   z8-z10  – counter-setup temporaries
#   z16-z30 – round keys rk[0..14] (broadcast via ld1rqb)
#   p0.b    – all-true byte predicate   (full-SVL load/store)
#   p1.s    – all-true 32-bit predicate (counter setup)
#   p2.s    – selects the ctr32 word in each 128-bit lane
#   p3.b    – tail / single-block predicate
#
# ---- SME ABI notes ----
#   smstart sm  enters Streaming SVE mode; hardware lazy-saves the
#               non-streaming FP/SIMD register bank.
#   smstop  sm  exits Streaming SVE mode, restoring that bank.
#   General-purpose registers x0-x30 are unchanged by smstart/smstop.
#   All z/p register work happens inside the streaming-mode region.
# ====================================================================

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

# ====================================================================
# Instruction helpers
#
# smstart/smstop/rdsvl are encoded via .inst for broad toolchain
# compatibility.  Assemblers with full SME support emit the same bytes
# from the mnemonics; .inst avoids a hard minimum assembler version.
#
#   smstart sm  = MSR SVCRSM, #1  = 0xD503437F
#   smstop  sm  = MSR SVCRSM, #0  = 0xD503433F
#   rdsvl   x5, #1               = 0x04BF5825
# ====================================================================
sub smstart_sm  { "\t.inst\t0xD503437F\t\t// smstart sm\n"  }
sub smstop_sm   { "\t.inst\t0xD503433F\t\t// smstop  sm\n"  }
sub rdsvl_x5    { "\t.inst\t0x04BF5825\t\t// rdsvl  x5, #1\n" }

# SVE AES instruction shorthands (destructive forms):
#   aese zd,zk  : zd = SubBytes(ShiftRows(zd XOR zk))
#   aesd zd,zk  : zd = InvShiftRows(InvSubBytes(zd XOR zk))
#   aesmc  zd   : zd = MixColumns(zd)
#   aesimc zd   : zd = InvMixColumns(zd)
sub _aese   { my($d,$k)=@_; "\taese\tz${d}.b, z${d}.b, z${k}.b\n"  }
sub _aesd   { my($d,$k)=@_; "\taesd\tz${d}.b, z${d}.b, z${k}.b\n"  }
sub _aesmc  { my($d)=@_;    "\taesmc\tz${d}.b, z${d}.b\n"           }
sub _aesimc { my($d)=@_;    "\taesimc\tz${d}.b, z${d}.b\n"          }

# ====================================================================
# aes_enc_rounds($zd, $first_rk, $rounds)
#   Emit ($rounds-1) AESE+AESMC pairs, one final AESE, plus EOR with
#   the last round key.  Round keys live in z$first_rk..z$(first_rk+rounds).
# ====================================================================
sub aes_enc_rounds {
    my ($zd, $first_rk, $rounds) = @_;
    my ($code, $rk) = ("", $first_rk);
    for my $r (0 .. $rounds - 2) {
        $code .= _aese($zd, $rk) . _aesmc($zd);
        $rk++;
    }
    $code .= _aese($zd, $rk);            # final AESE (no AESMC)
    $rk++;
    $code .= "\teor\tz${zd}.d, z${zd}.d, z${rk}.d\t// final AddRoundKey\n";
    return $code;
}

# ====================================================================
# aes_dec_rounds($zd, $first_rk, $rounds)
#   Emit AES decryption using the pre-processed decryption key schedule
#   (aes_v8_set_decrypt_key):  EOR with rk[rounds], then ($rounds-1)
#   AESD+AESIMC pairs, then one final AESD with rk[0].
#   Round keys live in z$first_rk..z$(first_rk+rounds).
# ====================================================================
sub aes_dec_rounds {
    my ($zd, $first_rk, $rounds) = @_;
    my $last_rk = $first_rk + $rounds;
    my ($code, $rk) = ("", $last_rk);
    $code .= "\teor\tz${zd}.d, z${zd}.d, z${rk}.d\t// initial AddRoundKey\n";
    $rk--;
    for my $r (0 .. $rounds - 2) {
        $code .= _aesd($zd, $rk) . _aesimc($zd);
        $rk--;
    }
    $code .= _aesd($zd, $rk);            # final AESD (no AESIMC)
    return $code;
}

# ====================================================================
# load_all_round_keys()
#   Broadcast each 128-bit round key across all 128-bit lanes of
#   z16..z30 using ld1rqb (load 16 bytes and replicate to fill z-reg).
#   Uses x7 as a scratch pointer; x3 (key base) is unchanged.
# ====================================================================
sub load_all_round_keys {
    my $c = "\tmov\tx7, x3\t\t\t// x7 = key schedule base\n";
    for my $i (0 .. 14) {
        my $zn = 16 + $i;
        $c .= "\tld1rqb\tz${zn}.b, p0/z, [x7]\n";
        $c .= "\tadd\tx7, x7, #16\n" unless $i == 14;
    }
    return $c;
}

# ====================================================================
# ctr32_setup_counter()
#   Build NVEC distinct ctr32 counter values in z0 (already loaded
#   with the broadcast IV via ld1rqb, so all NVEC lanes are identical).
#
#   ctr32 convention: the low 32 bits of the 128-bit counter block
#   (bytes [12..15], big-endian) are incremented as an unsigned counter.
#
#   In SVE element-type .s (32-bit), each 128-bit lane holds 4 words;
#   the ctr32 word is element 3 within each lane (global indices 3,7,11,...).
#
#   After this block:
#     z0.s[4i+3] = original_ctr32 + i  (in big-endian byte order)
#     p2.s       = predicate for elements 3,7,11,...  (ctr32 positions)
# ====================================================================
sub ctr32_setup_counter { return <<'___'; }
	// Build p2: marks the ctr32 word (element index % 4 == 3) in each lane.
	index	z8.s, #0, #1		// z8.s = [0,1,2,3, 4,5,...] element indices
	mov	z9.d, z8.d		// copy for in-place AND
	and	z9.s, z9.s, #3		// z9.s = [0,1,2,3, 0,1,2,3,...] pos in lane
	cmpeq	p2.s, p1/z, z9.s, #3	// p2 = true at positions 3,7,11,...
	lsr	z9.s, z8.s, #2		// z9.s = [0,0,0,0, 1,1,1,1,...] lane indices
	mov	z10.d, #0
	mov	z10.s, p2/m, z9.s	// z10.s = [0,0,0,0, 0,0,0,1, ..., 0,0,0,NVEC-1]

	// Add per-lane offsets to the big-endian ctr32 field.
	// Steps: byte-swap ctr32 word to LE  →  add  →  byte-swap back to BE.
	revb	z0.s, p2/m, z0.s	// ctr32 words → little-endian
	add	z0.s, p2/m, z0.s, z10.s// add lane indices [0,1,...,NVEC-1]
	revb	z0.s, p2/m, z0.s	// ctr32 words → big-endian again
___

# ====================================================================
# Now emit the assembly source
# ====================================================================

my $code = "#include \"arm_arch.h\"\n";
$code .= ".arch\tarmv9-a\n";
$code .= ".text\n";
$code .= ".arch_extension\tsve2-aes\n";
$code .= "\n";

# --------------------------------------------------------------------
# aes_v8_sme_ctr32_encrypt_blocks
#
#   void aes_v8_sme_ctr32_encrypt_blocks(
#       const unsigned char *in,       // x0
#       unsigned char       *out,      // x1
#       size_t               blocks,   // x2
#       const AES_KEY       *key,      // x3
#       const unsigned char  ivec[16]) // x4
#
#   Encrypts or decrypts 'blocks' AES blocks in CTR mode using the
#   ctr32 convention (low 32 bits of ivec incremented as unsigned BE
#   counter).  Signature matches aes_v8_ctr32_encrypt_blocks.
#   ivec is NOT modified (caller tracks the counter).
# --------------------------------------------------------------------

$code .= <<___;
.globl	aes_v8_sme_ctr32_encrypt_blocks
.type	aes_v8_sme_ctr32_encrypt_blocks,%function
.align	5
aes_v8_sme_ctr32_encrypt_blocks:
	AARCH64_VALID_CALL_TARGET
	cbz	x2, .Lsme_ctr32_done

	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

___
$code .= smstart_sm();
$code .= rdsvl_x5();
$code .= <<"___";
	lsr	x6, x5, #4		// NVEC = SVL / 16

	ptrue	p0.b			// all-true byte predicate
	ptrue	p1.s			// all-true 32-bit predicate

	ldr	w8, [x3, #240]		// AES round count (10 / 12 / 14)

___
$code .= load_all_round_keys();
$code .= <<"___";

	// Load IV; ld1rqb replicates 16 bytes across all NVEC 128-bit lanes.
	ld1rqb	z0.b, p0/z, [x4]

___
$code .= ctr32_setup_counter();
$code .= <<"___";

	mov	z8.s, w6			// broadcast NVEC for predicated counter increment

	// Dispatch to per-key-size loop (avoids branches inside hot loop).
	cmp	w8, #12
	b.hi	.Lsme_ctr32_256
	b.eq	.Lsme_ctr32_192

// ---- AES-128 CTR (rounds = 10) ----
.Lsme_ctr32_128:
	cmp	x2, x6			// do we have a full NVEC-block batch?
	b.lo	.Lsme_ctr32_128_tail
.Lsme_ctr32_128_loop:
	mov	z1.d, z0.d		// z1 = working copy of counters
___
$code .= aes_enc_rounds(1, 16, 10);
$code .= <<"___";
	ld1b	z2.b, p0/z, [x0]	// load NVEC blocks of plaintext
	eor	z1.d, z1.d, z2.d	// z1 = keystream XOR plaintext
	st1b	z1.b, p0, [x1]		// store NVEC blocks of ciphertext
	add	x0, x0, x5		// in  += SVL
	add	x1, x1, x5		// out += SVL
	// Increment all ctr32 fields by NVEC (big-endian arithmetic):
	revb	z0.s, p2/m, z0.s	// ctr32 words → LE
	add	z0.s, p2/m, z0.s, z8.s	// add NVEC
	revb	z0.s, p2/m, z0.s	// ctr32 words → BE
	sub	x2, x2, x6		// blocks -= NVEC
	cmp	x2, x6
	b.hs	.Lsme_ctr32_128_loop
	cbz	x2, .Lsme_ctr32_done
.Lsme_ctr32_128_tail:			// 0 < x2 < NVEC remaining blocks
	mov	z1.d, z0.d
___
$code .= aes_enc_rounds(1, 16, 10);
$code .= <<"___";
	lsl	x9, x2, #4		// x9 = remaining bytes (x2 * 16)
	whilelo	p3.b, xzr, x9		// p3 = true for first x9 bytes
	ld1b	z2.b, p3/z, [x0]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p3, [x1]
	b	.Lsme_ctr32_done

// ---- AES-192 CTR (rounds = 12) ----
.Lsme_ctr32_192:
	cmp	x2, x6
	b.lo	.Lsme_ctr32_192_tail
.Lsme_ctr32_192_loop:
	mov	z1.d, z0.d
___
$code .= aes_enc_rounds(1, 16, 12);
$code .= <<"___";
	ld1b	z2.b, p0/z, [x0]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p0, [x1]
	add	x0, x0, x5
	add	x1, x1, x5
	revb	z0.s, p2/m, z0.s
	add	z0.s, p2/m, z0.s, z8.s
	revb	z0.s, p2/m, z0.s
	sub	x2, x2, x6
	cmp	x2, x6
	b.hs	.Lsme_ctr32_192_loop
	cbz	x2, .Lsme_ctr32_done
.Lsme_ctr32_192_tail:
	mov	z1.d, z0.d
___
$code .= aes_enc_rounds(1, 16, 12);
$code .= <<"___";
	lsl	x9, x2, #4
	whilelo	p3.b, xzr, x9
	ld1b	z2.b, p3/z, [x0]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p3, [x1]
	b	.Lsme_ctr32_done

// ---- AES-256 CTR (rounds = 14) ----
.Lsme_ctr32_256:
	cmp	x2, x6
	b.lo	.Lsme_ctr32_256_tail
.Lsme_ctr32_256_loop:
	mov	z1.d, z0.d
___
$code .= aes_enc_rounds(1, 16, 14);
$code .= <<"___";
	ld1b	z2.b, p0/z, [x0]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p0, [x1]
	add	x0, x0, x5
	add	x1, x1, x5
	revb	z0.s, p2/m, z0.s
	add	z0.s, p2/m, z0.s, z8.s
	revb	z0.s, p2/m, z0.s
	sub	x2, x2, x6
	cmp	x2, x6
	b.hs	.Lsme_ctr32_256_loop
	cbz	x2, .Lsme_ctr32_done
.Lsme_ctr32_256_tail:
	mov	z1.d, z0.d
___
$code .= aes_enc_rounds(1, 16, 14);
$code .= <<"___";
	lsl	x9, x2, #4
	whilelo	p3.b, xzr, x9
	ld1b	z2.b, p3/z, [x0]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p3, [x1]

.Lsme_ctr32_done:
___
$code .= smstop_sm();
$code .= <<"___";
	ldp	x29, x30, [sp], #16
	ret
.size	aes_v8_sme_ctr32_encrypt_blocks,.-aes_v8_sme_ctr32_encrypt_blocks

___

# --------------------------------------------------------------------
# aes_v8_sme_cbc_decrypt
#
#   void aes_v8_sme_cbc_decrypt(
#       const unsigned char *in,     // x0  (ciphertext)
#       unsigned char       *out,    // x1  (plaintext)
#       size_t               length, // x2  (bytes, must be multiple of 16)
#       const AES_KEY       *key,    // x3  (set by aes_v8_set_decrypt_key)
#       unsigned char       *ivec)   // x4  (updated on return)
#
#   Implementation strategy:
#     - Main loop: AES-decrypt NVEC ciphertext blocks in parallel using
#       SVE z-register AES instructions (the dominant latency).
#     - ABC IV-XOR chain: applied 16 bytes at a time using GPR ldp/stp
#       (a lightweight sequential pass over the decrypted scratch data).
#     - Tail: remaining 1..NVEC-1 blocks processed one block at a time.
#
#   Stack frame layout:
#     [x29 +  0]: x29, x30   (16 B)
#     [x29 + 16]: x19, x20   (16 B)
#     [x29 + 32]: x21, x22   (16 B)
#     [x29 + 48]: alignment pad (16 B)
#     ---- VLA frame (allocated after smstart/rdsvl) ----
#     x22 -> prev_iv   (16 B at sp + 0)
#     x21 -> z_dec scratch (SVL B at sp + 16)
#
#   The prev_iv and scratch are laid out contiguously so that reading
#   [x22..x22+SVL-1] yields [prev_iv | ct[0..NVEC-2]], exactly the
#   CBC IV chain for a single NVEC-block batch.  The XOR loop
#   implements this by using x22 for the first block (prev_iv) and
#   advancing through the original ciphertext for subsequent blocks.
# --------------------------------------------------------------------

$code .= <<___;
.globl	aes_v8_sme_cbc_decrypt
.type	aes_v8_sme_cbc_decrypt,%function
.align	5
aes_v8_sme_cbc_decrypt:
	AARCH64_VALID_CALL_TARGET
	cbz	x2, .Lsme_cbc_ret
	tst	x2, #15
	b.ne	.Lsme_cbc_ret		// reject unaligned lengths
	lsr	x2, x2, #4		// blocks = length / 16

	stp	x29, x30, [sp, #-64]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]

___
$code .= smstart_sm();
$code .= rdsvl_x5();
$code .= <<"___";
	lsr	x6, x5, #4		// NVEC = SVL / 16

	ptrue	p0.b
	ptrue	p1.s

	ldr	w8, [x3, #240]

___
$code .= load_all_round_keys();
$code .= <<"___";

	// Allocate VLA stack frame: (SVL + 16) bytes rounded to 16.
	// prev_iv at [sp + 0..15], z_dec scratch at [sp + 16..16+SVL-1].
	add	x9, x5, #16 + 15
	bic	x9, x9, #15
	sub	sp, sp, x9
	mov	x22, sp			// x22 = &prev_iv
	add	x21, sp, #16		// x21 = z_dec scratch

	ldp	x12, x13, [x4]
	stp	x12, x13, [x22]		// prev_iv = *ivec

	cmp	w8, #12
	b.hi	.Lsme_cbc_256
	b.eq	.Lsme_cbc_192

// ---- AES-128 CBC decrypt (rounds = 10) ----
// ---- Full-NVEC-batch loop ----
.Lsme_cbc_128:
	cmp	x2, x6
	b.lo	.Lsme_cbc_128_tail
.Lsme_cbc_128_loop:
	ld1b	z0.b, p0/z, [x0]	// z0 = NVEC ciphertext blocks
	mov	z1.d, z0.d
___
$code .= aes_dec_rounds(1, 16, 10);
$code .= <<"___";
	st1b	z1.b, p0, [x21]		// store decrypted blocks to scratch

	// Sequential CBC XOR pass (16 bytes per iteration):
	//   x9  = byte offset within batch  (0, 16, 32, ...)
	//   x10 = pointer to IV/prev-ct     (x22 for i==0, x0+offset for i>0)
	mov	x9, xzr
	mov	x10, x22
.Lsme_cbc128_xor:
	ldp	x11, x12, [x10]		// prev block (64-bit halves)
	add	x15, x21, x9
	ldp	x13, x14, [x15]		// decrypted block
	eor	x11, x11, x13
	eor	x12, x12, x14
	add	x15, x1, x9
	stp	x11, x12, [x15]		// plaintext output
	add	x10, x0, x9		// next prev = &ct[i]
	add	x9, x9, #16
	cmp	x9, x5
	b.lo	.Lsme_cbc128_xor

	// prev_iv <- last ciphertext block of batch
	add	x15, x0, x5
	ldp	x11, x12, [x15, #-16]!
	stp	x11, x12, [x22]

	add	x0, x0, x5
	add	x1, x1, x5
	sub	x2, x2, x6
	cmp	x2, x6
	b.hs	.Lsme_cbc_128_loop
	cbz	x2, .Lsme_cbc_done

// ---- Tail: process remaining blocks one at a time ----
.Lsme_cbc_128_tail:
	ptrue	p3.b, vl16
.Lsme_cbc128_tail_one:
	ld1b	z0.b, p3/z, [x0]	// load one ciphertext block
	mov	z1.d, z0.d
___
$code .= aes_dec_rounds(1, 16, 10);
$code .= <<"___";
	ld1b	z2.b, p3/z, [x22]	// load prev_iv
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p3, [x1]		// store plaintext
	st1b	z0.b, p3, [x22]		// prev_iv <- current ciphertext block
	add	x0, x0, #16
	add	x1, x1, #16
	subs	x2, x2, #1
	b.ne	.Lsme_cbc128_tail_one
	b	.Lsme_cbc_done

// ---- AES-192 CBC decrypt (rounds = 12) ----
.Lsme_cbc_192:
	cmp	x2, x6
	b.lo	.Lsme_cbc_192_tail
.Lsme_cbc_192_loop:
	ld1b	z0.b, p0/z, [x0]
	mov	z1.d, z0.d
___
$code .= aes_dec_rounds(1, 16, 12);
$code .= <<"___";
	st1b	z1.b, p0, [x21]
	mov	x9, xzr
	mov	x10, x22
.Lsme_cbc192_xor:
	ldp	x11, x12, [x10]
	add	x15, x21, x9
	ldp	x13, x14, [x15]
	eor	x11, x11, x13
	eor	x12, x12, x14
	add	x15, x1, x9
	stp	x11, x12, [x15]
	add	x10, x0, x9
	add	x9, x9, #16
	cmp	x9, x5
	b.lo	.Lsme_cbc192_xor
	add	x15, x0, x5
	ldp	x11, x12, [x15, #-16]!
	stp	x11, x12, [x22]
	add	x0, x0, x5
	add	x1, x1, x5
	sub	x2, x2, x6
	cmp	x2, x6
	b.hs	.Lsme_cbc_192_loop
	cbz	x2, .Lsme_cbc_done
.Lsme_cbc_192_tail:
	ptrue	p3.b, vl16
.Lsme_cbc192_tail_one:
	ld1b	z0.b, p3/z, [x0]
	mov	z1.d, z0.d
___
$code .= aes_dec_rounds(1, 16, 12);
$code .= <<"___";
	ld1b	z2.b, p3/z, [x22]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p3, [x1]
	st1b	z0.b, p3, [x22]
	add	x0, x0, #16
	add	x1, x1, #16
	subs	x2, x2, #1
	b.ne	.Lsme_cbc192_tail_one
	b	.Lsme_cbc_done

// ---- AES-256 CBC decrypt (rounds = 14) ----
.Lsme_cbc_256:
	cmp	x2, x6
	b.lo	.Lsme_cbc_256_tail
.Lsme_cbc_256_loop:
	ld1b	z0.b, p0/z, [x0]
	mov	z1.d, z0.d
___
$code .= aes_dec_rounds(1, 16, 14);
$code .= <<"___";
	st1b	z1.b, p0, [x21]
	mov	x9, xzr
	mov	x10, x22
.Lsme_cbc256_xor:
	ldp	x11, x12, [x10]
	add	x15, x21, x9
	ldp	x13, x14, [x15]
	eor	x11, x11, x13
	eor	x12, x12, x14
	add	x15, x1, x9
	stp	x11, x12, [x15]
	add	x10, x0, x9
	add	x9, x9, #16
	cmp	x9, x5
	b.lo	.Lsme_cbc256_xor
	add	x15, x0, x5
	ldp	x11, x12, [x15, #-16]!
	stp	x11, x12, [x22]
	add	x0, x0, x5
	add	x1, x1, x5
	sub	x2, x2, x6
	cmp	x2, x6
	b.hs	.Lsme_cbc_256_loop
	cbz	x2, .Lsme_cbc_done
.Lsme_cbc_256_tail:
	ptrue	p3.b, vl16
.Lsme_cbc256_tail_one:
	ld1b	z0.b, p3/z, [x0]
	mov	z1.d, z0.d
___
$code .= aes_dec_rounds(1, 16, 14);
$code .= <<"___";
	ld1b	z2.b, p3/z, [x22]
	eor	z1.d, z1.d, z2.d
	st1b	z1.b, p3, [x1]
	st1b	z0.b, p3, [x22]
	add	x0, x0, #16
	add	x1, x1, #16
	subs	x2, x2, #1
	b.ne	.Lsme_cbc256_tail_one

.Lsme_cbc_done:
	// Update caller's ivec with the last ciphertext block.
	ldp	x12, x13, [x22]
	stp	x12, x13, [x4]

	// Epilogue: restore SP past the VLA frame using the frame pointer,
	// then exit streaming SVE mode.
	mov	sp, x29
___
$code .= smstop_sm();
$code .= <<"___";
	ldp	x21, x22, [x29, #32]
	ldp	x19, x20, [x29, #16]
	ldp	x29, x30, [sp], #64
.Lsme_cbc_ret:
	ret
.size	aes_v8_sme_cbc_decrypt,.-aes_v8_sme_cbc_decrypt
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
