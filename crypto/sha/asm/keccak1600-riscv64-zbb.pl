#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https:#www.openssl.org/source/license.html

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

################################################################################
# Utility functions to help with keeping track of which registers to stack/
# unstack when entering / exiting routines.
################################################################################
{
    # Callee-saved registers
    my @callee_saved = map("x$_",(2,8,9,18..27));
    # Caller-saved registers
    my @caller_saved = map("x$_",(1,5..7,10..17,28..31));
    my @must_save;
    sub use_reg {
        my $reg = shift;
        if (grep(/^$reg$/, @callee_saved)) {
            push(@must_save, $reg);
        } elsif (!grep(/^$reg$/, @caller_saved)) {
            # Register is not usable!
            die("Unusable register ".$reg);
        }
        return $reg;
    }
    sub use_regs {
        return map(use_reg("x$_"), @_);
    }
    sub save_regs {
        my $ret = '';
        my $stack_reservation = ($#must_save + 1) * 8;
        my $stack_offset = $stack_reservation;
        if ($stack_reservation % 16) {
            $stack_reservation += 8;
        }
        $ret.="    addi    sp,sp,-$stack_reservation\n";
        foreach (@must_save) {
            $stack_offset -= 8;
            $ret.="    sd      $_,$stack_offset(sp)\n";
        }
        return $ret;
    }
    sub load_regs {
        my $ret = '';
        my $stack_reservation = ($#must_save + 1) * 8;
        my $stack_offset = $stack_reservation;
        if ($stack_reservation % 16) {
            $stack_reservation += 8;
        }
        foreach (@must_save) {
            $stack_offset -= 8;
            $ret.="    ld      $_,$stack_offset(sp)\n";
        }
        $ret.="    addi    sp,sp,$stack_reservation\n";
        return $ret;
    }
    sub clear_regs {
        @must_save = ();
    }
}

################################################################################
# Register assignment
################################################################################
# A[5][5], input block pointer, len, r
my ($A,$INP,$LEN,$R,$NEXT) = use_regs(10..14);

# A[5][5]
my ($A0,$A1,$A2,$A3,$A4) = use_regs(10..14);
my ($A5,$A6,$A7) = use_regs(15..17);
my ($A8,$A9,$A10) = use_regs(5..7);
my ($A11,$A12,$A13,$A14) = use_regs(28..31);
my ($A15) = use_regs(9);
my ($A16,$A17,$A18,$A19,$A20,$A21,$A22,$A23,$A24) = use_regs(18..26);

# Temporaries
my ($T0) = use_regs(27);
my ($T1) = use_regs(8);
my ($T2) = use_regs(1);

###############################################################################
# Constants (iotas)
###############################################################################
my $code .= <<___;

.section .rodata
.p2align    8
.quad   0,0,0,0,0,0,0,0
.type iotas,\@object
iotas:
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
.size iotas,.-iotas
___

###############################################################################
# KeccakF1600_int
###############################################################################
$code .= <<___;
.text
.p2align    5
.type KeccakF1600_int, \@function
KeccakF1600_int:
    la $T0, iotas
    sd $T0, 32(sp)
    sd $T2, 32+8(sp)
    j .Loop

.p2align    4
.Loop:
    ##################### Theta
    xor $T0, $A0, $A5
    sd  $A5, 0(sp)         # A5->sp0
    sd  $A0, 0+8(sp)       # A0->sp8
    sd  $A4, 16(sp)        # A4->sp16
    sd  $A9, 16+8(sp)      # A9->sp24
    xor $A0, $A1, $A6
    xor $T1, $A2, $A7
    xor $T2, $A3, $A8
    xor $A4, $A4, $A9
    xor $T0, $T0, $A10
    xor $A0, $A0, $A11
    xor $T1, $T1, $A12
    xor $T2, $T2, $A13
    xor $A4, $A4, $A14
    xor $T0, $T0, $A15
    xor $A0, $A0, $A16
    xor $T1, $T1, $A17
    xor $T2, $T2, $A18
    xor $A4, $A4, $A19
    xor $T0, $T0, $A20
    xor $A0, $A0, $A21
    xor $T1, $T1, $A22
    xor $T2, $T2, $A23
    xor $A4, $A4, $A24

    @{[rori $A5, $T1, 63]}
    xor $A9, $T0, $A5
    xor $A1, $A1, $A9
    xor $A6, $A6, $A9
    xor $A11, $A11, $A9
    xor $A16, $A16, $A9
    xor $A21, $A21, $A9

    @{[rori $A5, $T2, 63]}
    xor $A9, $A0, $A5

    @{[rori $A5, $A4, 63]}
    xor $T1, $T1, $A5

    @{[rori $A5, $T0, 63]}
    xor $T2, $T2, $A5

    @{[rori $A5, $A0, 63]}
    xor $A4, $A4, $A5

    xor $A0, $A2, $A9
    ld  $A5, 0(sp)         # sp0->A5
    xor $A7, $A7, $A9
    xor $A12, $A12, $A9
    sd  $A0, 0(sp)         # x27->sp0
    xor $A17, $A17, $A9
    xor $A22, $A22, $A9

    ld  $A0, 8(sp)         # sp8->A0

    xor $A0, $A0, $A4
    xor $A5, $A5, $A4
    xor $A10, $A10, $A4
    xor $A15, $A15, $A4
    xor $A20, $A20, $A4
    ld  $A4, 16(sp)        # sp16->A4
    xor $T0, $A3, $T1
    xor $A8, $A8, $T1
    xor $A13, $A13, $T1
    ld  $A9, 16+8(sp)      # sp24->A9
    xor $A18, $A18, $T1
    xor $A23, $A23, $T1

    xor $T1, $A4, $T2
    xor $A9, $A9, $T2
    xor $A14, $A14, $T2
    xor $A19, $A19, $T2
    xor $A24, $A24, $T2

    ##################### Rho+Pi
    mv $T2, $A1
    @{[rori $A1, $A6, 64-44]}
    @{[rori $A2, $A12, 64-43]}
    @{[rori $A3, $A18, 64-21]}
    @{[rori $A4, $A24, 64-14]}

    @{[rori $A6, $A9, 64-20]}
    @{[rori $A12, $A13, 64-25]}
    @{[rori $A18, $A17, 64-15]}
    @{[rori $A24, $A21, 64-2]}

    @{[rori $A9, $A22, 64-61]}
    @{[rori $A13, $A19, 64-8]}
    @{[rori $A17, $A11, 64-10]}
    @{[rori $A21, $A8, 64-55]}
    sd  $A24, 8(sp)         # A24->sp8

    @{[rori $A22, $A14, 64-39]}
    @{[rori $A19, $A23, 64-56]}
    @{[rori $A11, $A7, 64-6]}
    @{[rori $A8, $A16, 64-45]}

    @{[rori $A14, $A20, 64-18]}
    @{[rori $A23, $A15, 64-41]}
    @{[rori $A7, $A10, 64-3]}
    @{[rori $A16, $A5, 64-36]}

    ld  $A24, 0(sp)         # sp0->x26
    @{[rori $A5, $T0, 64-28]}
    @{[rori $A10, $T2, 64-1]}
    @{[rori $A15, $T1, 64-27]}
    @{[rori $A20, $A24, 64-62]}

    ##################### Chi+Iota
    @{[andn $T0,  $A2, $A1]}
    @{[andn $A24, $A3, $A2]}
    @{[andn $T1, $A0, $A4]}
    @{[andn $T2,  $A1, $A0]}
    xor $A0, $A0, $T0
    @{[andn $T0, $A4, $A3]}
    xor $A1, $A1, $A24
    ld  $A24, 32(sp)        # sp32->iotas
    xor $A3, $A3, $T1
    xor $A4, $A4, $T2
    xor $A2, $A2, $T0
    ld $T2, 0($A24)
    addi $A24, $A24, 8

    @{[andn $T0, $A7, $A6]}
    sd  $A24, 32(sp)        # iotas++->sp48
    @{[andn $A24, $A8, $A7]}
    @{[andn $T1, $A5, $A9]}
    xor $A0, $A0, $T2
    @{[andn $T2, $A6, $A5]}
    xor $A5, $A5, $T0
    @{[andn $T0, $A9, $A8]}
    xor $A6, $A6, $A24
    xor $A8, $A8, $T1
    xor $A9, $A9, $T2
    xor $A7, $A7, $T0
    sd  $A0, 0(sp)          # A0->sp0

    @{[andn $T0, $A12, $A11]}
    @{[andn $A24, $A13, $A12]}
    @{[andn $T1, $A10, $A14]}
    @{[andn $T2, $A11, $A10]}
    xor $A10, $A10, $T0
    @{[andn $T0, $A14, $A13]}
    xor $A11, $A11, $A24
    xor $A13, $A13, $T1
    xor $A14, $A14, $T2
    xor $A12, $A12, $T0

    @{[andn $T0, $A17, $A16]}
    @{[andn $A24, $A18, $A17]}
    @{[andn $T1, $A15, $A19]}
    @{[andn $T2, $A16, $A15]}
    xor $A15, $A15, $T0
    @{[andn $T0, $A19, $A18]}
    xor $A16, $A16, $A24
    xor $A18, $A18, $T1
    xor $A19, $A19, $T2
    xor $A17, $A17, $T0

    ld  $A24, 8(sp)        # sp8->A24
    @{[andn $T0, $A22, $A21]}
    @{[andn $A0, $A23, $A22]}
    @{[andn $T1, $A20, $A24]}
    @{[andn $T2, $A21, $A20]}
    xor $A20, $A20, $T0
    @{[andn $T0, $A24, $A23]}
    xor $A21, $A21, $A0
    xor $A23, $A23, $T1
    ld $T1, 32(sp)         # sp32->iotas
    xor $A24, $A24, $T2
    xor $A22, $A22, $T0
    ld  $A0, 0(sp)         # sp0->A0

    andi $T0, $T1, 255
    bnez $T0, .Loop

    ld $T2, 32+8(sp)
    ret
.size   KeccakF1600_int,.-KeccakF1600_int

###############################################################################
# KeccakF1600
###############################################################################
.p2align    5
.type KeccakF1600, \@function
.balign 16
KeccakF1600:
    addi sp, sp, -192
    sd $T1, 64(sp)
    sd $A15, 64+8(sp)
    sd $A16, 80(sp)
    sd $A17, 80+8(sp)
    sd $A18, 96(sp)
    sd $A19, 96+8(sp)
    sd $A20, 112(sp)
    sd $A21, 112+8(sp)
    sd $A22, 128(sp)
    sd $A23, 128+8(sp)
    sd $A24, 144(sp)
    sd $T0, 144+8(sp)
    sd $T2, 160(sp)

    sd $A, 160+8(sp)       # offload argument
    mv $T0, $A

    # Load state matrices A[0]... A[24] into registers
    ld $A0, 0($T0)
    ld $A1, 0+8($T0)
    ld $A2, 16($T0)
    ld $A3, 16+8($T0)
    ld $A4, 32($T0)
    ld $A5, 32+8($T0)
    ld $A6, 48($T0)
    ld $A7, 48+8($T0)
    ld $A8, 64($T0)
    ld $A9, 64+8($T0)
    ld $A10, 80($T0)
    ld $A11, 80+8($T0)
    ld $A12, 96($T0)
    ld $A13, 96+8($T0)
    ld $A14, 112($T0)
    ld $A15, 112+8($T0)
    ld $A16, 128($T0)
    ld $A17, 128+8($T0)
    ld $A18, 144($T0)
    ld $A19, 144+8($T0)
    ld $A20, 160($T0)
    ld $A21, 160+8($T0)
    ld $A22, 176($T0)
    ld $A23, 176+8($T0)
    ld $A24, 192($T0)

    jal $T2, KeccakF1600_int

    # Write back the status to memory
    ld $T0, 160+8(sp)      # restore state pointer(a0)
    sd $A0, 0($T0)
    sd $A1, 0+8($T0)
    sd $A2, 16($T0)
    sd $A3, 16+8($T0)
    sd $A4, 32($T0)
    sd $A5, 32+8($T0)
    sd $A6, 48($T0)
    sd $A7, 48+8($T0)
    sd $A8, 64($T0)
    sd $A9, 64+8($T0)
    sd $A10, 80($T0)
    sd $A11, 80+8($T0)
    sd $A12, 96($T0)
    sd $A13, 96+8($T0)
    sd $A14, 112($T0)
    sd $A15, 112+8($T0)
    sd $A16, 128($T0)
    sd $A17, 128+8($T0)
    sd $A18, 144($T0)
    sd $A19, 144+8($T0)
    sd $A20, 160($T0)
    sd $A21, 160+8($T0)
    sd $A22, 176($T0)
    sd $A23, 176+8($T0)
    sd $A24, 192($T0)

    ld $T1, 64(sp)
    ld $A15, 64+8(sp)
    ld $A16, 80(sp)
    ld $A17, 80+8(sp)
    ld $A18, 96(sp)
    ld $A19, 96+8(sp)
    ld $A20, 112(sp)
    ld $A21, 112+8(sp)
    ld $A22, 128(sp)
    ld $A23, 128+8(sp)
    ld $A24, 144(sp)
    ld $T0, 144+8(sp)
    ld $T2, 160(sp)
    addi sp, sp, 192
    ret
.size KeccakF1600, .-KeccakF1600
___

###############################################################################
# SHA3_absorb_zbb
###############################################################################
$code .= <<___;
# size_t SHA3_absorb_zbb(uint64_t A[5][5], const unsigned char *inp, size_t len, size_t r);
# x10 = A, x11 = inp, x12 = len, x13 = r
.text
.p2align    5
.globl SHA3_absorb_zbb
.type SHA3_absorb_zbb, \@function
SHA3_absorb_zbb:
    addi sp, sp, -208
    sd $T1, 96(sp)
    sd $A15, 96+8(sp)
    sd $A16, 112(sp)
    sd $A17, 112+8(sp)
    sd $A18, 128(sp)
    sd $A19, 128+8(sp)
    sd $A20, 144(sp)
    sd $A21, 144+8(sp)
    sd $A22, 160(sp)
    sd $A23, 160+8(sp)
    sd $A24, 176(sp)
    sd $T0, 176+8(sp)
    sd $T2, 192(sp)

    sd $A, 64(sp)         # offload arguments
    sd $INP, 64+8(sp)
    sd $LEN, 80(sp)
    sd $R, 80+8(sp)

    mv $T0, $A            # uint64_t A[5][5]
    mv $T1, $LEN          # size_t len
    mv $T2, $R            # size_t r

    # Load state matrices A[0]... A[24] into registers
    ld $A0, 0($T0)
    ld $A1, 0+8($T0)
    ld $A2, 16($T0)
    ld $A3, 16+8($T0)
    ld $A4, 32($T0)
    ld $A5, 32+8($T0)
    ld $A6, 48($T0)
    ld $A7, 48+8($T0)
    ld $A8, 64($T0)
    ld $A9, 64+8($T0)
    ld $A10, 80($T0)
    ld $A11, 80+8($T0)
    ld $A12, 96($T0)
    ld $A13, 96+8($T0)
    ld $A14, 112($T0)
    ld $A15, 112+8($T0)
    ld $A16, 128($T0)
    ld $A17, 128+8($T0)
    ld $A18, 144($T0)
    ld $A19, 144+8($T0)
    ld $A20, 160($T0)
    ld $A21, 160+8($T0)
    ld $A22, 176($T0)
    ld $A23, 176+8($T0)
    ld $A24, 192($T0)
    j  .Loop_absorb

.p2align    4
.Loop_absorb:
    sub $T0, $T1, $T2           # len - bsz
    bltu $T1, $T2, .Labsorbed   # if len < bsz break

    # --- A[0]
    sd $T0, 56(sp)
    ld $T1, 72(sp)              # reload inp pointer

    ld $T0, 0($T1)
    addi $T1, $T1, 8            # *inp++
    xor $A0, $A0, $T0
    li $T0, (8*(0+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[1]
    ld $T0, 0($T1)
    addi $T1, $T1, 8            # *inp++
    xor $A1, $A1, $T0
    li $T0, (8*(0+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[2]
    ld $T0, 0($T1)
    addi $T1, $T1, 8            # *inp++
    xor $A2, $A2, $T0
    li $T0, (8*(2+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[3]
    ld $T0, 0($T1)
    addi $T1, $T1, 8            # *inp++
    xor $A3, $A3, $T0
    li $T0, (8*(2+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[4]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A4, $A4, $T0
    li $T0, (8*(4+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[5]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A5, $A5, $T0
    li $T0, (8*(4+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[6]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A6, $A6, $T0
    li $T0, (8*(6+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[7]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A7, $A7, $T0
    li $T0, (8*(6+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[8]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A8, $A8, $T0
    li $T0, (8*(8+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[9]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A9, $A9, $T0
    li $T0, (8*(8+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[10]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A10, $A10, $T0
    li $T0, (8*(10+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[11]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A11, $A11, $T0
    li $T0, (8*(10+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[12]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A12, $A12, $T0
    li $T0, (8*(12+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[13]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A13, $A13, $T0
    li $T0, (8*(12+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[14]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A14, $A14, $T0
    li $T0, (8*(14+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[15]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A15, $A15, $T0
    li $T0, (8*(14+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[16]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A16, $A16, $T0
    li $T0, (8*(16+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[17]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A17, $A17, $T0
    li $T0, (8*(16+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[18]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A18, $A18, $T0
    li $T0, (8*(18+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[19]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A19, $A19, $T0
    li $T0, (8*(18+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[20]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A20, $A20, $T0
    li $T0, (8*(20+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[21]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A21, $A21, $T0
    li $T0, (8*(20+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[22]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A22, $A22, $T0
    li $T0, (8*(22+2))
    bltu $T2, $T0, .Lprocess_block
    # --- A[23]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A23, $A23, $T0
    li $T0, (8*(22+2))
    beq $T2, $T0, .Lprocess_block
    # --- A[24]
    ld $T0, 0($T1)
    addi $T1, $T1, 8
    xor $A24, $A24, $T0

.p2align    4
.Lprocess_block:
    sd $T1, 64+8(sp)          # save inp pointer

    jal $T2, KeccakF1600_int

    ld $T1, 56(sp)            # restore len
    ld $T2, 80+8(sp)          # restore bsz
    j .Loop_absorb

.Labsorbed:
    # Write back the status to memory
    ld $T0, 64(sp)            # restore state pointer
    sd $A0, 0($T0)
    sd $A1, 0+8($T0)
    sd $A2, 16($T0)
    sd $A3, 16+8($T0)
    sd $A4, 32($T0)
    sd $A5, 32+8($T0)
    sd $A6, 48($T0)
    sd $A7, 48+8($T0)
    sd $A8, 64($T0)
    sd $A9, 64+8($T0)
    sd $A10, 80($T0)
    sd $A11, 80+8($T0)
    sd $A12, 96($T0)
    sd $A13, 96+8($T0)
    sd $A14, 112($T0)
    sd $A15, 112+8($T0)
    sd $A16, 128($T0)
    sd $A17, 128+8($T0)
    sd $A18, 144($T0)
    sd $A19, 144+8($T0)
    sd $A20, 160($T0)
    sd $A21, 160+8($T0)
    sd $A22, 176($T0)
    sd $A23, 176+8($T0)
    sd $A24, 192($T0)

    # Return the remaining value of len
    mv $A, $T1

    ld $T1, 96(sp)
    ld $A15, 96+8(sp)
    ld $A16, 112(sp)
    ld $A17, 112+8(sp)
    ld $A18, 128(sp)
    ld $A19, 128+8(sp)
    ld $A20, 144(sp)
    ld $A21, 144+8(sp)
    ld $A22, 160(sp)
    ld $A23, 160+8(sp)
    ld $A24, 176(sp)
    ld $T0, 176+8(sp)
    ld $T2, 192(sp)
    addi sp, sp, 208
    ret
.size SHA3_absorb_zbb, .-SHA3_absorb_zbb
___

###############################################################################
# SHA3_squeeze_zbb
###############################################################################
$code .= <<___;
# void SHA3_squeeze_zbb(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next);
# x10 = A, x11 = out, x12 = len, x13 = r, x14 = next
.text
.p2align    5
.globl SHA3_squeeze_zbb
.type SHA3_squeeze_zbb, \@function
SHA3_squeeze_zbb:
    addi sp, sp, -48
    sd $T2, 0(sp)
    sd $A15, 8(sp)
    sd $A16, 16(sp)
    sd $A17, 16+8(sp)
    sd $A18, 32(sp)
    sd $A19, 32+8(sp)

    mv $A16, $A      # put aside arguments
    mv $A17, $INP    # out ptr
    mv $A18, $LEN    # outlen remaining
    mv $A19, $R      # block remaining

    bnez $NEXT, .Lnext_block # if next != 0 jump to next block logic

.Loop_squeeze:
    ld $A4, 0($A)
    addi $A, $A, 8

    li $A15, 8
    bltu $A18, $A15, .Lsqueeze_tail

    sd $A4, 0($A17)
    addi $A17, $A17, 8
    addi $A18, $A18, -8
    beqz $A18, .Lsqueeze_done

    addi $R, $R, -8
    bgtu $R, x0, .Loop_squeeze
.Lnext_block:
    mv $A, $A16              # state pointer
    jal KeccakF1600          # Generate new block
    mv $A, $A16              # Restore state pointer
    mv $R, $A19              # Reset the remaining bytes of the block
    j .Loop_squeeze

.p2align    4
.Lsqueeze_tail:
    sb $A4, 0($A17)
    addi $A17, $A17, 1
    srli $A4, $A4, 8
    addi $A18, $A18, -1
    beq $A18, x0, .Lsqueeze_done

    sb $A4, 0($A17)
    addi $A17, $A17, 1
    srli $A4, $A4, 8
    addi $A18, $A18, -1
    beq $A18, x0, .Lsqueeze_done

    sb $A4, 0($A17)
    addi $A17, $A17, 1
    srli $A4, $A4, 8
    addi $A18, $A18, -1
    beq $A18, x0, .Lsqueeze_done

    sb $A4, 0($A17)
    addi $A17, $A17, 1
    srli $A4, $A4, 8
    addi $A18, $A18, -1
    beq $A18, x0, .Lsqueeze_done

    sb $A4, 0($A17)
    addi $A17, $A17, 1
    srli $A4, $A4, 8
    addi $A18, $A18, -1
    beq $A18, x0, .Lsqueeze_done

    sb $A4, 0($A17)
    addi $A17, $A17, 1
    srli $A4, $A4, 8
    addi $A18, $A18, -1
    beq $A18, x0, .Lsqueeze_done

    sb $A4, 0($A17)

.Lsqueeze_done:
    ld $T2, 0(sp)
    ld $A15, 8(sp)
    ld $A16, 16(sp)
    ld $A17, 16+8(sp)
    ld $A18, 32(sp)
    ld $A19, 32+8(sp)
    addi sp, sp, 48
    ret
.size SHA3_squeeze_zbb, .-SHA3_squeeze_zbb
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
