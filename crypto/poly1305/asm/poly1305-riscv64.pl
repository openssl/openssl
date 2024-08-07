# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# Applied condition:
# POLY1305_BLOCK_SIZE was supposed to be 16

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my $code.=<<___;

#/**
# *
# * void poly1305_init(
# *  void *ctx,
# *  const unsigned char key[16],
# *  void *func)
# *
#**/

.text
.p2align 3
.globl poly1305_init
.type poly1305_init,\@function
poly1305_init:


    li                      t2, 0x0fff
    li                      t4, 0xfffc
    li                      t3, 0xffff
    slli                    t2, t2, 16

    #t4 = 0x0ffffffc
    add                     t4, t2, t4
    #t5 = 0x0ffffffc 00000000
    slli                    t5, t4, 32
    #t3 = 0x0fffffff
    add                     t3, t2, t3

    #clamp_0(t3) = 0x0ffffffc0fffffff
    add                     t3, t5, t3
    #clamp_1(t4) = 0x0ffffffc0ffffffc
    add                     t4, t5, t4


    sd                      x0, 0(a0)          # h0
    sd                      x0, 8(a0)          # h1
    sd                      x0, 16(a0)         # h2
    sd                      x0, 24(a0)

    ld                      t0, 0(a1)
    ld                      t1, 8(a1)
    and                     t0, t0, t3
    and                     t1, t1, t4

    sd                      t0, 32(a0)         # h0
    sd                      t1, 40(a0)         # h1

    mv                      a0, x0             # return 0


.poly1305_init_end:
    ret
.size poly1305_init,.-poly1305_init



#/**
# *
# * void poly1305_blocks(
# *    void *ctx,
# *    const unsigned char *inp,
# *    size_t len,
# *    u32 padbit)
# *
#**/

.text
.p2align 3
.globl poly1305_blocks
.type poly1305_blocks,\@function
poly1305_blocks:


    #blt    a2, POLY1305_BLOCK_SIZE, .poly1305_blocks_end
    li                      t0, 16
    blt                     a2, t0, .poly1305_blocks_end

    addi                    sp, sp, -56
    sd                      s2, 0(sp)
    sd                      s3, 8(sp)
    sd                      s4, 16(sp)
    sd                      s5, 24(sp)
    sd                      s6, 32(sp)
    sd                      s7, 40(sp)
    sd                      s8, 48(sp)


    ld                      x14, 0(a0)
    ld                      x15, 8(a0)
    lwu                     x16, 16(a0)
    ld                      x17, 32(a0)
    ld                      x18, 40(a0)

    andi                    a2, a2, -16
    srli                    x19, x18, 2
    add                     x19, x18, x19

    .align 4
    _BLK_LPST:

    ld                      x20, 0(a1)
    ld                      x21, 8(a1)
    addi                    a1, a1, 16
    addi                    a2, a2, -16

    #/* h += m[i] */
    add                     x14, x14, x20      # h0
    sltu                    x30, x14, x20

    add                     x15, x15, x21
    sltu                    x31, x15, x21
    add                     x15, x15, x30
    sltu                    x30, x15, x30
    add                     x31, x31, x30

    mulhu                   x23, x14, x17
    mul                     x22, x14, x17      # ((u128)h0 * r0)
    add                     x16, x16, x31
    add                     x16, x16, a3

    mulhu                   x21, x15, x19
    mul                     x20, x15, x19      # ((u128)h1 * s1)
    add                     x22, x22, x20
    sltu                    x30, x22, x20
    add                     x23, x23, x21
    add                     x23, x23, x30
    mulhu                   x24, x14, x18
    mul                     x20, x14, x18

    add                     x23, x23, x20
    sltu                    x30, x23, x20
    add                     x24, x24, x30
    mulhu                   x21, x15, x17
    mul                     x20, x15, x17

    add                     x23, x23, x20
    sltu                    x30, x23, x20
    mul                     x20, x16, x19
    add                     x24, x24, x21
    add                     x24, x24, x30
    mul                     x21, x16, x17

    add                     x23, x23, x20
    sltu                    x30, x23, x20
    add                     x24, x24, x21
    add                     x24, x24, x30

    and                     x20, x24, -4
    and                     x16, x24, 3
    srli                    x31, x24, 2
    add                     x20, x20, x31

    add                     x14, x22, x20
    sltu                    x30, x14, x22

    add                     x15, x23, x30
    sltu                    x31, x15, x23
    add                     x16, x16, x31
    bnez                    a2, _BLK_LPST

    sd                      x14, 0(a0)         # st d
    sd                      x15, 8(a0)
    sw                      x16, 16(a0)


    ld                      s2, 0(sp)
    ld                      s3, 8(sp)
    ld                      s4, 16(sp)
    ld                      s5, 24(sp)
    ld                      s6, 32(sp)
    ld                      s7, 40(sp)
    ld                      s8, 48(sp)
    addi                    sp, sp, 56


.poly1305_blocks_end:
    ret
.size poly1305_blocks,.-poly1305_blocks



#/**
# *
# * void poly1305_emit(
# *    void *ctx,
# *    unsigned char mac[16],
# *    const u32 nonce[4])
# *
#**/

.text
.p2align 3
.globl poly1305_emit
.type poly1305_emit,\@function
poly1305_emit:


    addi                    sp, sp, -40
    sd                      s2, 0(sp)
    sd                      s3, 8(sp)
    sd                      s4, 16(sp)
    sd                      s5, 24(sp)
    sd                      s6, 32(sp)


    lw                      s6, 0(a0)          # h0
    lw                      t6, 4(a0)          # h1
    lw                      a7, 8(a0)          # h2
    lw                      a3, 12(a0)         # h3
    lw                      a4, 16(a0)         # h4
    lw                      s2, 0(a2)          # nonce0
    lw                      s3, 4(a2)          # nonce1
    lw                      s4, 8(a2)          # nonce2
    lw                      s5, 12(a2)         # nonce3
    #/* compare to modulus by computing h + -p */
    addi                    t0, s6, 5          # g0 ld 32bit unsigned,
    sltu                    a5, t0, s6
    add                     t1, t6, a5         # g1
    sltu                    a5, t1, t6
    add                     t2, a7, a5         # g2
    sltu                    a5, t2, a7
    add                     t3, a3, a5         # g3
    sltu                    a5, t3, a3
    add                     t4, a4, a5         # g4 high part of t4 could be dirty
    sltu                    a5, t4, a7
    #/* if there was carry into 131st bit, h3:h0 = g3:g0 */
    srli                    t5, t4, 2
    neg                     t5, t5             # mask
    and                     t0, t0, t5
    and                     t1, t1, t5
    and                     t2, t2, t5
    and                     t3, t3, t5
    not                     t5, t5             # ~mask
    and                     s6, s6, t5
    and                     t6, t6, t5
    and                     a7, a7, t5
    and                     a3, a3, t5
    or                      s6, s6, t0
    or                      t6, t6, t1
    or                      a7, a7, t2
    or                      a3, a3, t3
    #/* mac = (h + nonce) % (2^128) */
    add                     s6, s6, s2         # h0
    sltu                    a5, s6, s2
    add                     t6, t6, a5
    sltu                    a5, t6, a5
    add                     t6, t6, s3         # h1
    sltu                    a6, t6, s3
    add                     a6, a5, a6
    add                     a7, a7, a6
    sltu                    a5, a7, a6
    add                     a7, a7, s4         # h2
    sltu                    a6, a7, s4
    add                     a6, a5, a6
    add                     a3, a3, a6
    add                     a3, a3, s5         # h3
    sw                      s6, 0(a1)          # h0
    sw                      t6, 4(a1)          # h1
    sw                      a7, 8(a1)          # h2
    sw                      a3, 12(a1)         # h3
    sw                      t5, 16(a1)         # h3
    sw                      t5, 16(a1)         # h3


    ld                      s2, 0(sp)
    ld                      s3, 8(sp)
    ld                      s4, 16(sp)
    ld                      s5, 24(sp)
    ld                      s6, 32(sp)
    addi                    sp, sp, 40


.poly1305_emit_end:
    ret
.size poly1305_emit,.-poly1305_emit
___

print $code;

close STDOUT or die "error closing STDOUT: $!";