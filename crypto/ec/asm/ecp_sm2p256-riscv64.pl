#! /usr/bin/env perl
# Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

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

my $code=<<___;
.text
___

# Function arguments
# Input block pointer, output block pointer, key pointer
my ($i0, $i1, $i2) = use_regs(10 .. 12);
my ($t0, $t1, $t2, $t3, $t4, $t5, $t6, $t7, $c0, $c1, $c2, $c3) = use_regs(5 .. 7, 13 ... 17, 28 .. 31);
my ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10) = use_regs(9, 18 .. 27);

sub bn_mod_add() {
    my $mod = shift;
$code.=<<___;
	// Load inputs
	ld $t0, 0($i1)
	ld $t1, 8($i1)
	ld $t2, 16($i1)
	ld $t3, 24($i1)

	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)

	// Addition
	add $t0, $t0, $t4
	sltu $c0, $t0, $t4  //carry

	add $t1, $t1, $t5
	sltu $c1, $t1, $t5
	add $t1, $t1, $c0
	sltu $c0, $t1, $c0
	add $c0, $c0, $c1

	add $t2, $t2, $t6
	sltu $c1, $t2, $t6
	add $t2, $t2, $c0
	sltu $c0, $t2, $c0
	add $c0, $c0, $c1

	add $t3, $t3, $t7
	sltu $c1, $t3, $t7
	add $t3, $t3, $c0
	sltu $c0, $t3, $c0
	add $c0, $c0, $c1

	// Load polynomial
	la $i2, $mod
	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)

	// Sub polynomial
	sltu $c3, $t0, $t4  //borrow
	sub $t4, $t0, $t4
	sltu $c1, $t1, $t5
	sub $t5, $t1, $t5
	sltu $c2, $t5, $c3
	sub $t5, $t5, $c3
	add $c1, $c1, $c2  //borrow
	sltu $c3, $t2, $t6
	sub $t6, $t2, $t6
	sltu $c2, $t6, $c1
	sub $t6, $t6, $c1
	add $c3, $c3, $c2  //borrow
	sltu $c1, $t3, $t7
	sub $t7, $t3, $t7
	sltu $c2, $t7, $c3
	sub $t7, $t7, $c3
	add $c3, $c1, $c2  //borrow

	// Select based on carry
	sltu $c0, $c0, $c3
	czero.eqz $t0, $t0, $c0
	czero.eqz $t1, $t1, $c0
	czero.eqz $t2, $t2, $c0
	czero.eqz $t3, $t3, $c0
	czero.nez $t4, $t4, $c0
	czero.nez $t5, $t5, $c0
	czero.nez $t6, $t6, $c0
	czero.nez $t7, $t7, $c0
	or $t0, $t4, $t0
	or $t1, $t5, $t1
	or $t2, $t6, $t2
	or $t3, $t7, $t3

	// Store results
	sd $t0, 0($i0)
	sd $t1, 8($i0)
	sd $t2, 16($i0)
	sd $t3, 24($i0)
___
}

sub bn_mod_sub() {
    my $mod = shift;
$code.=<<___;
	// Load inputs
	ld $t0, 0($i1)
	ld $t1, 8($i1)
	ld $t2, 16($i1)
	ld $t3, 24($i1)

	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)

	// Subtraction
	sltu $c3, $t0, $t4  //borrow
	sub $t0, $t0, $t4

	sltu $c1, $t1, $t5
	sub $t1, $t1, $t5
	sltu $c2, $t1, $c3
	sub $t1, $t1, $c3
	add $c3, $c2, $c1

	sltu $c1, $t2, $t6
	sub $t2, $t2, $t6
	sltu $c2, $t2, $c3
	sub $t2, $t2, $c3
	add $c3, $c2, $c1

	sltu $c1, $t3, $t7
	sub $t3, $t3, $t7
	sltu $c2, $t3, $c3
	sub $t3, $t3, $c3
	add $c3, $c2, $c1

	// Load polynomial
	la $i2, $mod
	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)

	// Add polynomial
	add $t4, $t0, $t4
	sltu $c0, $t4, $t0

	add $t5, $t1, $t5
	sltu $c1, $t5, $t1
	add $t5, $t5, $c0
	sltu $c0, $t5, $c0
	add $c0, $c0, $c1

	add $t6, $t2, $t6
	sltu $c1, $t6, $t2
	add $t6, $t6, $c0
	sltu $c0, $t6, $c0
	add $c0, $c0, $c1

	add $t7, $t3, $t7
	add $t7, $t7, $c0

	czero.eqz $t4, $t4, $c3
	czero.eqz $t5, $t5, $c3
	czero.eqz $t6, $t6, $c3
	czero.eqz $t7, $t7, $c3
	czero.nez $t0, $t0, $c3
	czero.nez $t1, $t1, $c3
	czero.nez $t2, $t2, $c3
	czero.nez $t3, $t3, $c3
	or $t0, $t0, $t4
	or $t1, $t1, $t5
	or $t2, $t2, $t6
	or $t3, $t3, $t7

	sd $t0, 0($i0)
	sd $t1, 8($i0)
	sd $t2, 16($i0)
	sd $t3, 24($i0)
___
}

sub bn_mod_div_by_2() {
    my $mod = shift;
$code.=<<___;
	// Load inputs
	ld $t0, 0($i1)
	ld $t1, 8($i1)
	ld $t2, 16($i1)
	ld $t3, 24($i1)

	// Save the least significant bit
	andi $c0, $t0, 0x1

	// Right shift 1
	slli $t4, $t1, 63
	srli $t0, $t0, 1
	or $t0, $t0, $t4
	slli $t5, $t2, 63
	srli $t1, $t1, 1
	or $t1, $t1, $t5
	slli $t6, $t3, 63
	srli $t2, $t2, 1
	or $t2, $t2, $t6
	srli $t3, $t3, 1

	// Load mod
	la $i2, $mod
	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)

	czero.eqz $t4, $t4, $c0
	czero.eqz $t5, $t5, $c0
	czero.eqz $t6, $t6, $c0
	czero.eqz $t7, $t7, $c0

	add $t0, $t0, $t4
	sltu $c0, $t0, $t4

	add $t1, $t1, $t5
	sltu $c1, $t1, $t5
	add $t1, $t1, $c0
	sltu $c0, $t1, $c0
	add $c0, $c0, $c1

	add $t2, $t2, $t6
	sltu $c1, $t2, $t6
	add $t2, $t2, $c0
	sltu $c0, $t2, $c0
	add $c0, $c0, $c1

	add $t3, $t3, $t7
	add $t3, $t3, $c0

	sd $t0, 0($i0)
	sd $t1, 8($i0)
	sd $t2, 16($i0)
	sd $t3, 24($i0)
___
}

{
$code.=<<___;

.section .rodata
.p2align 5
// The polynomial p
.type .Lpoly,\@object
.Lpoly:
.dword	0xffffffffffffffff,0xffffffff00000000,0xffffffffffffffff,0xfffffffeffffffff

// The order of polynomial n
.type .Lord,\@object
.Lord:
.dword	0x53bbf40939d54123,0x7203df6b21c6052b,0xffffffffffffffff,0xfffffffeffffffff

// (p + 1) / 2
.type .Lpoly_div_2,\@object
.Lpoly_div_2:
.dword	0x8000000000000000,0xffffffff80000000,0xffffffffffffffff,0x7fffffff7fffffff

// (n + 1) / 2
.type .Lord_div_2,\@object
.Lord_div_2:
.dword	0xa9ddfa049ceaa092,0xb901efb590e30295,0xffffffffffffffff,0x7fffffff7fffffff


// void bn_rshift1(BN_ULONG *a);
.globl	bn_rshift1
.type	bn_rshift1,%function
.p2align 5
bn_rshift1:
	// Load inputs
	ld $t0, 0($i0)
	ld $t1, 8($i0)
	ld $t2, 16($i0)
	ld $t3, 24($i0)

	// Right shift 1
	slli $t4, $t1, 63
	srli $t0, $t0, 1
	or $t0, $t0, $t4
	slli $t5, $t2, 63
	srli $t1, $t1, 1
	or $t1, $t1, $t5
	slli $t6, $t3, 63
	srli $t2, $t2, 1
	or $t2, $t2, $t6
	srli $t7, $t3, 1

	// Store results
	sd $t0, 0($i0)
	sd $t1, 8($i0)
	sd $t2, 16($i0)
	sd $t7, 24($i0)

	ret
.size bn_rshift1,.-bn_rshift1

// void bn_sub(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b);
.globl	bn_sub
.type	bn_sub,%function
.p2align 5
bn_sub:
	// Load inputs
	ld $t0, 0($i1)
	ld $t1, 8($i1)
	ld $t2, 16($i1)
	ld $t3, 24($i1)

	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)

	// Subtraction
	sltu $c3, $t0, $t4  //borrow
	sub $t0, $t0, $t4

	sltu $c1, $t1, $t5
	sub $t1, $t1, $t5
	sltu $c0, $t1, $c3
	sub $t1, $t1, $c3
	add $c3, $c1, $c0

	sltu $c2, $t2, $t6
	sub $t2, $t2, $t6
	sltu $c1, $t2, $c3
	sub $t2, $t2, $c3
	add $c2, $c2, $c1

	sub $t3, $t3, $t7
	sub $t3, $t3, $c2

	// Store results
	sd $t0, 0($i0)
	sd $t1, 8($i0)
	sd $t2, 16($i0)
	sd $t3, 24($i0)

	ret
.size bn_sub,.-bn_sub

// void ecp_sm2p256_mul_by_3(BN_ULONG *r,const BN_ULONG *a);
.globl	ecp_sm2p256_mul_by_3
.type	ecp_sm2p256_mul_by_3,%function
.p2align 5
ecp_sm2p256_mul_by_3:
___
$code.= save_regs();
$code.=<<___;
	// Load inputs
	ld $t0, 0($i1)
	ld $t1, 8($i1)
	ld $t2, 16($i1)
	ld $t3, 24($i1)

	// 2*a
	add $t4, $t0, $t0
	sltu $c0, $t4, $t0

	slli $t5, $t1, 1
	sltu $c1, $t5, $t1
	add $t5, $t5, $c0

	slli $t6, $t2, 1
	sltu $c3, $t6, $t2
	add $t6, $t6, $c1

	slli $t7, $t3, 1
	sltu $c0, $t7, $t3
	add $t7, $t7, $c3

	la $i2, .Lpoly
	ld $s0, 0($i2)
	ld $s1, 8($i2)
	ld $s2, 16($i2)
	ld $s3, 24($i2)

	// Sub polynomial
	sltu $c3, $t4, $s0
	sub $s4, $t4, $s0

	sltu $c1, $t5, $c3
	sub $s5, $t5, $c3
	sltu $c3, $s5, $s1
	sub $s5, $s5, $s1
	add $c3, $c3, $c1

	sltu $c1, $t6, $c3
	sub $s6, $t6, $c3
	sltu $c3, $s6, $s2
	sub $s6, $s6, $s2
	add $c3, $c3, $c1

	sltu $c1, $t7, $c3
	sub $s7, $t7, $c3
	sltu $c3, $s7, $s3
	sub $s7, $s7, $s3
	add $c3, $c3, $c1

	sub $c0, $c0, $c3
	czero.eqz $t4, $t4, $c0
	czero.eqz $t5, $t5, $c0
	czero.eqz $t6, $t6, $c0
	czero.eqz $t7, $t7, $c0
	czero.nez $s4, $s4, $c0
	czero.nez $s5, $s5, $c0
	czero.nez $s6, $s6, $c0
	czero.nez $s7, $s7, $c0

	or $t4, $t4, $s4
	or $t5, $t5, $s5
	or $t6, $t6, $s6
	or $t7, $t7, $s7

	// 3*a
	add $t4, $t4, $t0
	sltu $c0, $t4, $t0

	add $t5, $t5, $t1
	sltu $c1, $t5, $t1
	add $t5, $t5, $c0
	sltu $c0, $t5, $c0
	add $c0, $c0, $c1

	add $t6, $t6, $t2
	sltu $c1, $t6, $t2
	add $t6, $t6, $c0
	sltu $c0, $t6, $c0
	add $c0, $c0, $c1

	add $t7, $t7, $t3
	sltu $c1, $t7, $t3
	add $t7, $t7, $c0
	sltu $c0, $t7, $c0
	add $c0, $c0, $c1

	// Sub polynomial
	sltu $c3, $t4, $s0
 	sub $s4, $t4, $s0

	sltu $c1, $t5, $c3
	sub $s5, $t5, $c3
	sltu $c3, $s5, $s1
	sub $s5, $s5, $s1
	add $c3, $c3, $c1

	sltu $c1, $t6, $c3
	sub $s6, $t6, $c3
	sltu $c3, $s6, $s2
	sub $s6, $s6, $s2
	add $c3, $c3, $c1

	sltu $c1, $t7, $c3
	sub $s7, $t7, $c3
	sltu $c3, $s7, $s3
	sub $s7, $s7, $s3
	add $c3, $c3, $c1

	sub $c0, $c0, $c3
	czero.eqz $t4, $t4, $c0
	czero.eqz $t5, $t5, $c0
	czero.eqz $t6, $t6, $c0
	czero.eqz $t7, $t7, $c0
	czero.nez $s4, $s4, $c0
	czero.nez $s5, $s5, $c0
	czero.nez $s6, $s6, $c0
	czero.nez $s7, $s7, $c0
	or $t4, $s4, $t4
	or $t5, $s5, $t5
	or $t6, $s6, $t6
	or $t7, $s7, $t7

	// Store results
	sd $t4, 0($i0)
	sd $t5, 8($i0)
	sd $t6, 16($i0)
	sd $t7, 24($i0)
___
$code.= load_regs();
$code.=<<___;
	ret
.size ecp_sm2p256_mul_by_3,.-ecp_sm2p256_mul_by_3


// void ecp_sm2p256_add(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_add
.type	ecp_sm2p256_add,%function
.p2align 5
ecp_sm2p256_add:
___
    &bn_mod_add(".Lpoly");
$code.=<<___;
	ret
.size ecp_sm2p256_add,.-ecp_sm2p256_add

// void ecp_sm2p256_sub(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_sub
.type	ecp_sm2p256_sub,%function
.p2align 5
ecp_sm2p256_sub:
___
    &bn_mod_sub(".Lpoly");
$code.=<<___;
	ret
.size ecp_sm2p256_sub,.-ecp_sm2p256_sub

// void ecp_sm2p256_sub_mod_ord(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_sub_mod_ord
.type	ecp_sm2p256_sub_mod_ord,%function
.p2align 5
ecp_sm2p256_sub_mod_ord:
___
    &bn_mod_sub(".Lord");
$code.=<<___;
	ret
.size ecp_sm2p256_sub_mod_ord,.-ecp_sm2p256_sub_mod_ord

// void ecp_sm2p256_div_by_2(BN_ULONG *r,const BN_ULONG *a);
.globl	ecp_sm2p256_div_by_2
.type	ecp_sm2p256_div_by_2,%function
.p2align 5
ecp_sm2p256_div_by_2:
___
    &bn_mod_div_by_2(".Lpoly_div_2");
$code.=<<___;
	ret
.size ecp_sm2p256_div_by_2,.-ecp_sm2p256_div_by_2

// void ecp_sm2p256_div_by_2_mod_ord(BN_ULONG *r,const BN_ULONG *a);
.globl	ecp_sm2p256_div_by_2_mod_ord
.type	ecp_sm2p256_div_by_2_mod_ord,%function
.p2align 5
ecp_sm2p256_div_by_2_mod_ord:
___
    &bn_mod_div_by_2(".Lord_div_2");
$code.=<<___;
	ret
.size ecp_sm2p256_div_by_2_mod_ord,.-ecp_sm2p256_div_by_2_mod_ord

.altmacro
.macro RDC
	// a = |  t7   | ... | t0  |, where ti are 64-bit quantitiet
	//   = | s7| s6| ... |--|--|, where ai are 32-bit quantitiet
	// |    t7     |    t6     |    t5     |    t4     |
	// |  s7 |  s6 |  s5 |  s4 |  s3 |  s2 | s1  | s0  |
	// |    t3     |    t2     |    t1     |    t0     |
	// |           |           |           |           |
	// =================================================
	// |  s0 |  s3 |  s2 | s1  |  s0 |   0 |    t4     | (+)
	// |  s1 |  s7 |    t6     |  s3 |   0 |  s2 |  s1 | (+)
	// |  s2 |   0 |  s6 |  s5 |  s4 |   0 |    t5     | (+)
	// |  s3 |   0 |    t7     |  s5 |   0 |  s4 |  s3 | (+)
	// |  s4 |   0 |    t7     |  s5 |   0 |    t6     | (+)
	// |  s4 |   0 |   0 |  s7 |  s6 |   0 |  s6 |  s5 | (+)
	// |  s5 |   0 |   0 |   0 |  s7 |   0 |  s6 |  s5 | (+)
	// |  s5 |   0 |   0 |   0 |   0 |   0 |    t7     | (+)
	// |  s6 |   0 |   0 |   0 |   0 |   0 |    t7     | (+)
	// |  s6 |   0 |   0 |   0 |   0 |   0 |   0 |  s7 | (+)
	// |  s7 |   0 |   0 |   0 |   0 |   0 |   0 |  s7 | (+)
	// |  s7 |   0 |   0 |   0 |   0 |   0 |   0 |   0 | (+)
	// |    t7     |   0 |   0 |   0 |   0 |   0 |   0 | (+)
	// |   0 |   0 |   0 |   0 |   0 | s0  |   0 |   0 | (-)
	// |   0 |   0 |   0 |   0 |   0 | s1  |   0 |   0 | (-)
	// |   0 |   0 |   0 |   0 |   0 | s5  |   0 |   0 | (-)
	// |   0 |   0 |   0 |   0 |   0 | s6  |   0 |   0 | (-)
	// | U[7]| U[6]| U[5]| U[4]| U[3]| U[2]| U[1]| U[0]|
	// |  t7 |  t6 |  t5 |  t4 |  s3 |  s2 |   s1 | s0 | (+)
	// |    V[3]   |    V[2]   |    V[1]   |    V[0]   |

	// 1. 64-bit addition
	// s0=t6+t7+t7
	add $s0, $t6, $t7
	sltu $c0, $s0, $t6
	add $s0, $s0, $t7
	sltu $c1, $s0, $t7
	add $s10, $c0, $c1  //t6+t7+t7 carry

	// s2=t4+t5+s0
	add $s2, $t4, $t5
	sltu $c2, $s2, $t4
	add $c0, $c2, $s10
	add $s2, $s2, $s0
	sltu $c3, $s2, $s0
	add $c0, $c0, $c3

	// sum
	add $t0, $t0, $s2
	sltu $c1, $t0, $s2
	add $t1, $t1, $c0
	sltu $c0, $t1, $c0
	add $t1, $t1, $c1
	sltu $c1, $t1, $c1
	add $c0, $c0, $c1
	add $t2, $t2, $s0
	sltu $c2, $t2, $s0
	add $t2, $t2, $c0
	sltu $c0, $t2, $c0
	add $c0, $c0, $c2
	add $t3, $t3, $t7
	sltu $c1, $t3, $t7
	add $t3, $t3, $c0
	sltu $c0, $t3, $c0
	add $c0, $c0, $c1
	add $t3, $t3, $s10
	sltu $c1, $t3, $s10
	add $s8, $c0, $c1

	// 2. 64-bit to 32-bit spread
	zext.w $s0, $t4
	zext.w $s2, $t5
	zext.w $s4, $t6
	zext.w $s6, $t7

	srli $s1, $t4, 32
	srli $s3, $t5, 32
	srli $s5, $t6, 32
	srli $s7, $t7, 32

	// 3. 32-bit addition
	add $c0, $s4, $s6
	add $c1, $s5, $s7
	add $c2, $s0, $s1
	add $t5, $s6, $s2  // t5 :s2 + s6
	add $t6, $s7, $s3  // t6: s3 + s7
	add $s4, $c1, $c0  // s4 + s5 + s6 + s7
	add $s2, $s2, $s4
	add $s2, $s2, $s4
	add $c3, $s3, $c2
	add $t7, $s2, $c3  //  t7: s0 + s1 + s2 + s3 + 2*(s4 + s5 + s6 + s7)
	add $s4, $s4, $s5
	add $s4, $s4, $s3
	add $s4, $s4, $s0  // s0 + s3 + s4 + s5*2 + s6 + s7
	add $c2, $c2, $s6
	add $s2, $c2, $s5  // s2: s0 + s1 + s5 + s6
	add $t4, $s1, $c1  // t4: s1 +s5 +s7
	add $s3, $s3, $t4
	add $s0, $s3, $c1  // s0: s1 + s3 + (s5 + s7)*2
	add $s1, $c0, $t5  // s1: s2 + s4 + s6*2
	mv $s3, $s4

	// 4. 32-bit to 64-bit
	slli $s9, $s1, 32
	slli $c0, $s3, 32
	srli $c1, $s1, 32
	or $s1, $c1, $c0
	slli $c2, $t5, 32
	srli $c3, $s3, 32
	or $s3, $c3, $c2
	slli $c0, $t7, 32
	srli $c1, $t5, 32
	or $t5, $c0, $c1
	srli $t7, $t7, 32

	// 5. 64-bit addition
	add $s0, $s0, $s9
	sltu $c0, $s0, $s9
	add $s1, $s1, $c0
	sltu $c1, $s1, $c0
	add $s3, $t4, $s3
	sltu $c2, $s3, $t4
	add $s3, $s3, $c1
	sltu $c3, $s3, $c1
	add $c0, $c2, $c3
	add $s4, $t6, $t5
	sltu $c1, $s4, $t6
	add $s4, $s4, $c0
	sltu $c2, $s4, $c0
	add $c0, $c1, $c2
	add $c0, $c0, $s8
	add $c0, $c0, $t7

	// V[0]	s0
	// V[1]	s1
	// V[2]	s3
	// V[3]	s4
	// carry	c0
	// sub	s2

	// add with V0-V3
	add $t0, $t0, $s0
	sltu $c1, $t0, $s0
	add $t1, $t1, $s1
	sltu $c2, $t1, $s1
	add $t1, $t1, $c1
	sltu $c1, $t1, $c1
	add $c1, $c1, $c2
	add $t2, $t2, $s3
	sltu $c2, $t2, $s3
	add $t2, $t2, $c1
	sltu $c1, $t2, $c1
	add $c1, $c1, $c2
	add $t3, $t3, $s4
	sltu $c2, $t3, $s4
	add $t3, $t3, $c1
	sltu $c1, $t3, $c1
	add $c1, $c1, $c2
	add $c0, $c0, $c1
	// sub with s2
	sltu $c2, $t1, $s2
	sub $t1, $t1, $s2
	sltu $c3, $t2, $c2
	sub $t2, $t2, $c2
	sltu $c1, $t3, $c3
	sub $t3, $t3, $c3
	sub $c0, $c0, $c1

	// 6. MOD
	// First Mod
	slli $s5, $c0, 32
	sub $s6, $s5, $c0

	add $t0, $t0, $c0
	sltu $c1, $t0, $c0
	add $t1, $t1, $s6
	sltu $c2, $t1, $s6
	add $t1, $t1, $c1
	add $c1, $c1, $c2
	add $t2, $t2, $c1
	sltu $c1, $t2, $c1
	add $t3, $t3, $s5
	sltu $c2, $t3, $s5
	add $t3, $t3, $c1
	sltu $c1, $t3, $c1
	add $c0, $c2, $c1

	// Last Mod
	// return y - p if y > p else y
	la $i2, .Lpoly
	ld $s0, 0($i2)
	ld $s1, 8($i2)
	ld $s2, 16($i2)
	ld $s3, 24($i2)

	sltu $c1, $t0, $s0
	sub $t4, $t0, $s0
	sltu $c2, $t1, $s1
	sub $t5, $t1, $s1
	sltu $c3, $t5, $c1
	sub $t5, $t5, $c1
	add $c1, $c2, $c3
	sltu $c2, $t2, $s2
	sub $t6, $t2, $s2
	sltu $c3, $t6, $c1
	sub $t6, $t6, $c1
	add $c1, $c2, $c3
	sltu $c2, $t3, $s3
	sub $t7, $t3, $s3
	sltu $c3, $t7, $c1
	sub $t7, $t7, $c1
	add $c1, $c2, $c3
	sub $c0, $c0, $c1

	czero.eqz $t0, $t0, $c0
	czero.eqz $t1, $t1, $c0
	czero.eqz $t2, $t2, $c0
	czero.eqz $t3, $t3, $c0
	czero.nez $t4, $t4, $c0
	czero.nez $t5, $t5, $c0
	czero.nez $t6, $t6, $c0
	czero.nez $t7, $t7, $c0
	or $t0, $t0, $t4
	or $t1, $t1, $t5
	or $t2, $t2, $t6
	or $t3, $t3, $t7

	sd $t0, 0($i0)
	sd $t1, 8($i0)
	sd $t2, 16($i0)
	sd $t3, 24($i0)
.endm


// void ecp_sm2p256_mul(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b);
.globl	ecp_sm2p256_mul
.type	ecp_sm2p256_mul,%function
.p2align 5
ecp_sm2p256_mul:
___
$code.= save_regs();
$code.=<<___;
	// Load inputs
	ld $t0, 0($i1)
	ld $t1, 8($i1)
	ld $t2, 16($i1)
	ld $t3, 24($i1)
	ld $t4, 0($i2)
	ld $t5, 8($i2)
	ld $t6, 16($i2)
	ld $t7, 24($i2)
// ### multiplication ###
	// ========================
	//             t3 t2 t1 t0
	// *           t7 t6 t5 t4
	// ------------------------
	// +           t0 t0 t0 t0
	//              *  *  *  *
	//             t7 t6 t5 t4
	//          t1 t1 t1 t1
	//           *  *  *  *
	//          t7 t6 t5 t4
	//       t2 t2 t2 t2
	//        *  *  *  *
	//       t7 t6 t5 t4
	//    t3 t3 t3 t3
	//     *  *  *  *
	//    t7 t6 t5 t4
	// ------------------------
	// t7 t6 t5 t4 t3 t2 t1 t0
	// ========================

// ### t0*t4 ###
	mul $s0, $t0, $t4
	mulhu $s1, $t0, $t4

//	### t0*t5+t1*t4 ###
	mul $s2, $t0, $t5
	mulhu $s3, $t0, $t5
	mul $s4, $t1, $t4
	mulhu $s5, $t1, $t4

	add $s1, $s1, $s2
	sltu $c0, $s1, $s2
	add $s3, $s3, $s5
	sltu $c1, $s3, $s5

	add $s1, $s1, $s4
	sltu $c2, $s1, $s4
	add $c0, $c0, $c2
	add $s3, $s3, $c0
	sltu $c0, $s3, $c0
	add $c0, $c0, $c1

//	### t0*t6+t1*t5+t2*t4 ###
	mul $s2, $t0, $t6
	mulhu $s4, $t0, $t6
	mul $s5, $t1, $t5
	mulhu $s6, $t1, $t5
	mul $s7, $t2, $t4
	mulhu $s8, $t2, $t4

	add $s2, $s2, $s3
	sltu $c1, $s2, $s3
	add $s5, $s5, $s7
	sltu $c3, $s5, $s7
	add $s2, $s2, $s5
	sltu $c2, $s2, $s5
	add $c1, $c1, $c3
	add $c0, $c0, $c2
	add $c0, $c0, $c1

	add $s4, $s4, $s6
	sltu $c2, $s4, $s6
	add $s8, $s8, $c0
	sltu $c0, $s8, $c0
	add $s4, $s4, $s8
	sltu $c3, $s4, $s8
	add $c0, $c2, $c0
	add $c0, $c0, $c3

//	### t0*t7+t1*t6+t2*t5+t3*t4 ###
	mul $s3, $t0, $t7
	mulhu $s5, $t0, $t7
	mv $t0, $s0
	mul $s9, $t1, $t6
	mulhu $s10, $t1, $t6
	mul $s0, $t2, $t5
	mulhu $s6, $t2, $t5
	mul $s7, $t3, $t4
	mulhu $s8, $t3, $t4

	add $s3, $s3, $s9
	sltu $c1, $s3, $s9
	add $s0, $s0, $s4
	sltu $c2, $s0, $s4
	add $c1, $c1, $c2
	add $s3, $s3, $s7
	sltu $c3, $s3, $s7
	add $s3, $s3, $s0
	sltu $c2, $s3, $s0
	add $c3, $c3, $c2
	add $c0, $c0, $c1
	add $c0, $c0, $c3

	add $s5, $s5, $s10
	sltu $c1, $s5, $s10
	add $s6, $s6, $s8
	sltu $c2, $s6, $s8
	add $c1, $c1, $c2
	add $s5, $s5, $c0
	sltu $c0, $s5, $c0
	add $s5, $s5, $s6
	sltu $c3, $s5, $s6
	add $c0, $c0, $c1
	add $c0, $c0, $c3

//	### t1*t7+t2*t6+t3*t5 ###
	mul $s4, $t1, $t7
	mulhu $s6, $t1, $t7
	mv $t1, $s1
	mul $s0, $t2, $t6
	mulhu $s1, $t2, $t6
	mul $s7, $t3, $t5
	mulhu $s8, $t3, $t5

	add $s4, $s4, $s5
	sltu $c1, $s4, $s5
	add $s0, $s0, $s7
	sltu $c2, $s0, $s7
	add $c1, $c1, $c2
	add $t4, $s4, $s0
	sltu $c3, $t4, $s0
	add $c1, $c1, $c3
	add $c0, $c0, $c1

	add $s6, $s6, $s1
	sltu $c2, $s6, $s1
	add $s8, $s8, $c0
	sltu $c0, $s8, $c0
	add $c0, $c0, $c2
	add $s6, $s6, $s8
	sltu $c3, $s6, $s8
	add $c0, $c0, $c3

//	### t2*t7+t3*t6 ###
	mul $s0, $t2, $t7
	mulhu $s1, $t2, $t7
	mv $t2, $s2
	mul $s5, $t3, $t6
	mulhu $t6, $t3, $t6

	add $s0, $s0, $s5
	sltu $c1, $s0, $s5
	add $t5, $s0, $s6
	sltu $c2, $t5, $s6
	add $c0, $c0, $c1
	add $c0, $c0, $c2

	add $t6, $t6, $s1
	sltu $c1, $t6, $s1
	add $t6, $t6, $c0
	sltu $c0, $t6, $c0
	add $c0, $c0, $c1

//	### t3*t7 ###
	mul $s2, $t3, $t7
	mulhu $t7, $t3, $t7
	mv $t3, $s3

	add $t6, $t6, $s2
	sltu $c1, $t6, $s2
	add $t7, $t7, $c0
	add $t7, $t7, $c1

	// ### Reduction ###
	RDC
___
$code.= load_regs();
$code.=<<___;
	ret
.size ecp_sm2p256_mul,.-ecp_sm2p256_mul

// void ecp_sm2p256_sqr(BN_ULONG *r, const BN_ULONG *a);
.globl	ecp_sm2p256_sqr
.type	ecp_sm2p256_sqr,%function
.p2align 5
ecp_sm2p256_sqr:
___
$code.= save_regs();
$code.=<<___;
	// Load inputs
	ld $s0, 0($i1)
	ld $s1, 8($i1)
	ld $s2, 16($i1)
	ld $s3, 24($i1)

	// ========================
	//             s3 s2 s1 s0
	// *           s3 s2 s1 s0
	// ------------------------
	// +           s0 s0 s0 s0
	//              *  *  *  *
	//             s3 s2 s1 s0
	//          s1 s1 s1 s1
	//           *  *  *  *
	//          s3 s2 s1 s0
	//       s2 s2 s2 s2
	//        *  *  *  *
	//       s3 s2 s1 s0
	//    s3 s3 s3 s3
	//     *  *  *  *
	//    s3 s2 s1 s0
	// ------------------------
	// t7 t6 t5 t4 t3 t2 t1 t0
	// ========================

// ### s0*s0 ###
	mul $t0, $s0, $s0
	mulhu $t1, $s0, $s0

// ### s0*s1*2 ###
	mul $s4, $s0, $s1
	mulhu $s5, $s0, $s1

	slli $s6, $s4, 1
	sltu $c0, $s6, $s4
	add $t1, $t1, $s6
	sltu $c1, $t1, $s6
	add $c0, $c0, $c1

	slli $t2, $s5, 1
	sltu $c2, $t2, $s5
	add $t2, $t2, $c0
	sltu $c3, $t2, $c0
	add $c0, $c2, $c3

// ### s0*s2*2+s1*s1 ###
	mul $s7, $s0, $s2
	mulhu $s8, $s0, $s2
	mul $s9, $s1, $s1
	mulhu $s10, $s1, $s1

	slli $t4, $s7, 1
	sltu $c1, $t4, $s7
	add $t2, $t2, $s9
	sltu $c2, $t2, $s9
	add $c0, $c0, $c1
	add $t2, $t2, $t4
	sltu $c3, $t2, $t4
	add $c0, $c0, $c2
	add $c0, $c0, $c3

	slli $t3, $s8, 1
	sltu $c1, $t3, $s8
	add $s10, $s10, $c0
	sltu $c0, $s10, $c0
	add $t3, $t3, $s10
	sltu $c2, $t3, $s10
	add $c0, $c0, $c1
	add $c0, $c0, $c2

// ### (s0*s3+s1*s2)*2 ###
	mul $s4, $s0, $s3
	mulhu $s5, $s0, $s3
	mul $s6, $s1, $s2
	mulhu $s7, $s1, $s2

	add $s4, $s4, $s6
	sltu $c1, $s4, $s6
	slli $c1, $c1, 1
	slli $s6, $s4, 1
	sltu $c2, $s6, $s4
	add $c1, $c1, $c2
	add $t3, $t3, $s6
	sltu $c3, $t3, $s6
	add $c0, $c0, $c1
	add $c0, $c0, $c3

	add $s5, $s5, $s7
	sltu $c1, $s5, $s7
	slli $c1, $c1, 1
	slli $s8, $s5, 1
	sltu $c2, $s8, $s5
	add $c1, $c1, $c2
	add $t4, $c0, $s8
	sltu $c3, $t4, $s8
	add $c0, $c1, $c3

// ### s1*s3*2+s2*s2 ###
	mul $s4, $s1, $s3
	mulhu $s5, $s1, $s3
	mul $s6, $s2, $s2
	mulhu $s7, $s2, $s2

	slli $s8, $s4, 1
	sltu $c1, $s8, $s4
	add $c0, $c0, $c1
	add $t4, $t4, $s6
	sltu $c2, $t4, $s6
	add $c0, $c0, $c2
	add $t4, $t4, $s8
	sltu $c3, $t4, $s8
	add $c0, $c0, $c3

	slli $s9, $s5, 1
	sltu $c1, $s9, $s5
	add $t5, $c0, $s7
	sltu $c2, $t5, $s7
	add $c0, $c1, $c2
	add $t5, $t5, $s9
	sltu $c3, $t5, $s9
	add $c0, $c0, $c3

// ### s2*s3*2 ###
	mul $s4, $s2, $s3
	mulhu $s5, $s2, $s3

	slli $s6, $s4, 1
	sltu $c1, $s6, $s4
	add $t5, $t5, $s6
	sltu $c2, $t5, $s6
	add $c0, $c0, $c1
	add $c0, $c0, $c2

	slli $t6, $s5, 1
	sltu $c3, $t6, $s5
	add $t6, $t6, $c0
	sltu $c0, $t6, $c0
	add $c0, $c0, $c3

// ### s3*s3 ###
	mul $s8, $s3, $s3
	mulhu $s9, $s3, $s3

	add $t6, $t6, $s8
	sltu $c1, $t6, $s8

	add $t7, $s9, $c0
	add $t7, $t7, $c1

	// ### Reduction ###
	RDC
___
$code.= load_regs();
$code.=<<___;
	ret
.size ecp_sm2p256_sqr,.-ecp_sm2p256_sqr
___
}

foreach (split("\n",$code)) {
    s/\`([^\`]*)\`/eval $1/ge;

    print $_,"\n";
}
close STDOUT or die "error closing STDOUT: $!";		# enforce flush
