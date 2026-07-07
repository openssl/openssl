#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# ====================================================================
# NIST P-256 field arithmetic for RISC-V (RV64GC, no extra extensions).
#
# Provides the field-level primitives consumed by crypto/ec/ecp_nistz256.c:
#   ecp_nistz256_mul_mont  ecp_nistz256_sqr_mont
#   ecp_nistz256_add       ecp_nistz256_sub      ecp_nistz256_neg
#   ecp_nistz256_mul_by_2  ecp_nistz256_mul_by_3 ecp_nistz256_div_by_2
#   ecp_nistz256_to_mont   ecp_nistz256_from_mont
# plus the hard-coded generator table ecp_nistz256_precomputed.
#
# Point arithmetic and the constant-time table scatter/gather are supplied
# by the portable C reference code in ecp_nistz256.c (built with
# -DECP_NISTZ256_REFERENCE_IMPLEMENTATION), so this module only needs to
# be correct and fast on the field operations, which dominate the cost of
# an EC scalar multiplication.
#
# Montgomery reduction uses Koc's CIOS with s=4 limbs.  For the P-256 field
# prime  p = 2^256 - 2^224 + 2^192 + 2^96 - 1  we have p == -1 (mod 2^64),
# hence the Montgomery constant n0' = -p^-1 mod 2^64 = 1, so the reduction
# digit is simply the current low limb.
#
# Input/output contract: every field-element argument must already be
# reduced, i.e. in [0, p), same as on every other ecp_nistz256 backend
# (x86_64, ARMv8, ppc64, ...) and as required by ecp_nistz256.c, which
# always keeps intermediate values in that range.  Given inputs in [0, p),
# mul_mont/sqr_mont/to_mont/from_mont produce a result in [0, p) via a
# single conditional subtraction of p (the standard bound: a,b < p implies
# the pre-reduction accumulator is < 2p).  Feeding an out-of-contract
# (>= p) input is *not* supported: the single subtraction only removes one
# copy of p, so the result is congruent to the correct value mod p but not
# necessarily canonical (e.g. it can come out as correct_value + p).
#
# The instruction sequence is a 1:1 transcription of a limb-exact C model
# that was validated against a big-integer oracle over random inputs in
# the documented [0, p) contract.
#
# Constant-time note: control flow and memory addressing are fully
# input-independent (modular reductions use seqz/neg/and/or masking, never
# branches).  As with the ARMv8 backend and the in-tree ecp_sm2p256-riscv64
# module, constant-time behaviour additionally assumes a data-independent
# hardware integer multiplier (mul/mulhu).  The base RISC-V ISA does *not*
# guarantee this: it is a property of the implementation, not of RV64GC
# itself.  The RISC-V Zkt extension (data-independent execution latency,
# see the riscv-crypto scalar Zkt specification) is the ISA-level guarantee
# to look for; on Linux it is discoverable at runtime via the riscv_hwprobe
# syscall's RISCV_HWPROBE_EXT_ZKT bit (key RISCV_HWPROBE_KEY_IMA_EXT_0).
# OpenSSL already defines a corresponding RISCV_HAS_ZKT() capability check
# (include/arch/riscv_arch.def) built on that same hwprobe mechanism, but
# no riscv64 module -- including ecp_sm2p256-riscv64.pl -- currently
# branches on it; this module follows that same precedent and does not
# gate on it either. On cores without Zkt or an equivalent vendor
# guarantee, timing side-channels through the multiplier are a residual
# risk deployers should be aware of, exactly as for ecp_sm2p256-riscv64;
# making riscv64 EC assembly Zkt-aware (using the capability bit that
# already exists but is currently unconsumed) is left as follow-up work.
# ====================================================================

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

my $output  = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT, ">$output";

my $code = <<___;
.text
___

################################################################################
# Callee/caller-saved bookkeeping (borrowed from ecp_sm2p256-riscv64.pl).
################################################################################
my (@must_save);
{
    my @callee_saved = map("x$_", (2, 8, 9, 18 .. 27));
    my @caller_saved = map("x$_", (1, 5 .. 7, 10 .. 17, 28 .. 31));
    sub use_reg {
        my $reg = shift;
        if (grep(/^$reg$/, @callee_saved)) {
            push(@must_save, $reg) unless grep(/^$reg$/, @must_save);
        } elsif (!grep(/^$reg$/, @caller_saved)) {
            die("Unusable register " . $reg);
        }
        return $reg;
    }
    sub use_regs { return map(use_reg("x$_"), @_); }
    sub save_regs {
        my $ret = '';
        my $n = scalar(@must_save);
        my $resv = $n * 8;
        $resv += 8 if ($resv % 16);
        my $off = $n * 8;
        $ret .= "    addi    sp,sp,-$resv\n";
        foreach (@must_save) { $off -= 8; $ret .= "    sd      $_,$off(sp)\n"; }
        return $ret;
    }
    sub load_regs {
        my $ret = '';
        my $n = scalar(@must_save);
        my $resv = $n * 8;
        $resv += 8 if ($resv % 16);
        my $off = $n * 8;
        foreach (@must_save) { $off -= 8; $ret .= "    ld      $_,$off(sp)\n"; }
        $ret .= "    addi    sp,sp,$resv\n";
        return $ret;
    }
    sub clear_regs { @must_save = (); }
}

# ABI arguments
my ($rp, $ap, $bp) = use_regs(10 .. 12);

################################################################################
# Field constants
################################################################################
$code .= <<___;
.p2align 5
.Lpoly:
.dword 0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001
# R^2 mod p (to Montgomery domain)
.LRR:
.dword 0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd
# plain 1 (from Montgomery domain: multiply by 1)
.Lone:
.dword 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
___

################################################################################
# Register map shared by the Montgomery mul/sqr core.
#   a[0..3]   input a (persistent across the 4 outer rounds)
#   t[0..5]   CIOS accumulator (6 words)
#   bi/m      current b-limb / reduction digit
#   lo,hi     product halves
#   C         carry word
#   ca,cb     one-bit carries
#   pp        pointer to .Lpoly ; pj scratch for a modulus limb
################################################################################
my @A  = use_regs(5, 6, 7, 28);          # x5,x6,x7,x28
my @T  = use_regs(29, 30, 31, 13, 14, 15); # x29,x30,x31,x13,x14,x15
my $bi = use_reg("x16");
my $lo = use_reg("x17");
my $hi = use_reg("x8");
my $C  = use_reg("x9");
my $ca = use_reg("x18");
my $cb = use_reg("x19");
my $pp = use_reg("x20");
my $pj = use_reg("x11");                 # reuse ap after a[] loaded
my $m  = $bi;                            # reduction digit reuses $bi

# add-with-carry: dst += src (dst holds running value), collect carry into $ca
# emits: add dst,dst,src ; sltu ca,dst,src
sub adc1 {
    my ($dst, $src, $cout) = @_;
    return "    add     $dst,$dst,$src\n    sltu    $cout,$dst,$src\n";
}

# One CIOS step body: given register names, emit the full Montgomery multiply.
sub mul_core {
    my $c = "";
    # zero accumulator t[0..5]
    for my $j (0 .. 5) { $c .= "    li      $T[$j],0\n"; }
    $c .= "    la      $pp,.Lpoly\n";

    for my $i (0 .. 3) {
        $c .= "    ld      $bi,".($i*8)."($bp)\n";
        $c .= "    li      $C,0\n";
        # t += a * b[i]
        for my $j (0 .. 3) {
            $c .= "    mul     $lo,$A[$j],$bi\n";
            $c .= "    mulhu   $hi,$A[$j],$bi\n";
            # t[j] += lo ; carry ca
            $c .= "    add     $T[$j],$T[$j],$lo\n    sltu    $ca,$T[$j],$lo\n";
            # t[j] += C  ; carry cb
            $c .= "    add     $T[$j],$T[$j],$C\n    sltu    $cb,$T[$j],$C\n";
            # C = hi + ca + cb
            $c .= "    add     $C,$hi,$ca\n    add     $C,$C,$cb\n";
        }
        # t[4]=adc(t[4],C,0)->cc(in t[5]); t[5]=cc
        $c .= "    add     $T[4],$T[4],$C\n    sltu    $T[5],$T[4],$C\n";

        # --- Montgomery reduction of one limb (n0'=1 => m = t[0]) ---
        $c .= "    mv      $m,$T[0]\n";
        $c .= "    li      $C,0\n";
        # j=0: t[0] += m*P0 (result discarded, guaranteed 0); C = hi + carry
        $c .= "    ld      $pj,0($pp)\n";
        $c .= "    mul     $lo,$m,$pj\n    mulhu   $hi,$m,$pj\n";
        $c .= "    add     $T[0],$T[0],$lo\n    sltu    $ca,$T[0],$lo\n";
        $c .= "    add     $T[0],$T[0],$C\n    sltu    $cb,$T[0],$C\n";
        $c .= "    add     $C,$hi,$ca\n    add     $C,$C,$cb\n";
        # j=1..3: t[j-1] = t[j] + m*Pj + C ; C = hi + carry
        for my $j (1 .. 3) {
            $c .= "    ld      $pj,".($j*8)."($pp)\n";
            $c .= "    mul     $lo,$m,$pj\n    mulhu   $hi,$m,$pj\n";
            $c .= "    add     $T[$j],$T[$j],$lo\n    sltu    $ca,$T[$j],$lo\n";
            $c .= "    add     $T[$j],$T[$j],$C\n    sltu    $cb,$T[$j],$C\n";
            $c .= "    mv      $T[$j-1],$T[$j]\n";
            $c .= "    add     $C,$hi,$ca\n    add     $C,$C,$cb\n";
        }
        # t[3] = t[4] + C (carry ca) ; t[4] = t[5] + ca
        $c .= "    add     $T[3],$T[4],$C\n    sltu    $ca,$T[3],$C\n";
        $c .= "    add     $T[4],$T[5],$ca\n";
    }
    return $c;
}

# Final conditional subtract of p and store t[0..3] to rp.
# Result value spread over t[0..3] with top word t[4] in {0,1}.
sub reduce_store {
    my $c = "";
    # d = t - p, borrow chain, plus borrow out of t[4]
    $c .= "    ld      $pj,0($pp)\n";
    $c .= "    sltu    $ca,$T[0],$pj\n    sub     $lo,$T[0],$pj\n";       # d0 in lo (temp)
    # We need d0..d3 kept; use A[] as scratch? A[] no longer needed after core.
    # store d limbs into a[]-registers (free now) : reuse @A as d[0..3]
    $c .= "    mv      $A[0],$lo\n";
    for my $j (1 .. 3) {
        $c .= "    ld      $pj,".($j*8)."($pp)\n";
        $c .= "    sltu    $cb,$T[$j],$pj\n    sub     $lo,$T[$j],$pj\n"; # borrow1 & diff
        $c .= "    sltu    $hi,$lo,$ca\n    sub     $lo,$lo,$ca\n";       # subtract prev borrow
        $c .= "    add     $ca,$cb,$hi\n";                               # new borrow
        $c .= "    mv      $A[$j],$lo\n";
    }
    # borrow out of top word t[4]
    $c .= "    sltu    $cb,$T[4],$ca\n";     # cb = (t4 < borrow) -> final borrow
    # mask = (final borrow == 0) ? all ones : 0   (i.e. t >= p, select d)
    $c .= "    seqz    $lo,$cb\n    neg     $lo,$lo\n";    # lo = mask
    $c .= "    not     $hi,$lo\n";                          # hi = ~mask
    for my $j (0 .. 3) {
        $c .= "    and     $A[$j],$A[$j],$lo\n";
        $c .= "    and     $T[$j],$T[$j],$hi\n";
        $c .= "    or      $A[$j],$A[$j],$T[$j]\n";
        $c .= "    sd      $A[$j],".($j*8)."($rp)\n";
    }
    return $c;
}

################################################################################
# void ecp_nistz256_mul_mont(u64 r[4], const u64 a[4], const u64 b[4]);
################################################################################
$code .= <<___;
.globl	ecp_nistz256_mul_mont
.type	ecp_nistz256_mul_mont,\@function
.p2align 5
ecp_nistz256_mul_mont:
___
$code .= save_regs();
$code .= <<___;
	ld	$A[0],0($ap)
	ld	$A[1],8($ap)
	ld	$A[2],16($ap)
	ld	$A[3],24($ap)
___
$code .= mul_core();
$code .= reduce_store();
$code .= load_regs();
$code .= <<___;
	ret
.size	ecp_nistz256_mul_mont,.-ecp_nistz256_mul_mont

################################################################################
# void ecp_nistz256_sqr_mont(u64 r[4], const u64 a[4]);   (= mul_mont(a,a))
################################################################################
.globl	ecp_nistz256_sqr_mont
.type	ecp_nistz256_sqr_mont,\@function
.p2align 5
ecp_nistz256_sqr_mont:
___
$code .= save_regs();
$code .= <<___;
	mv	$bp,$ap
	ld	$A[0],0($ap)
	ld	$A[1],8($ap)
	ld	$A[2],16($ap)
	ld	$A[3],24($ap)
___
$code .= mul_core();
$code .= reduce_store();
$code .= load_regs();
$code .= <<___;
	ret
.size	ecp_nistz256_sqr_mont,.-ecp_nistz256_sqr_mont

################################################################################
# void ecp_nistz256_to_mont(u64 r[4], const u64 a[4]);    (= mul_mont(a,RR))
################################################################################
.globl	ecp_nistz256_to_mont
.type	ecp_nistz256_to_mont,\@function
.p2align 5
ecp_nistz256_to_mont:
___
$code .= save_regs();
$code .= <<___;
	la	$bp,.LRR
	ld	$A[0],0($ap)
	ld	$A[1],8($ap)
	ld	$A[2],16($ap)
	ld	$A[3],24($ap)
___
$code .= mul_core();
$code .= reduce_store();
$code .= load_regs();
$code .= <<___;
	ret
.size	ecp_nistz256_to_mont,.-ecp_nistz256_to_mont

################################################################################
# void ecp_nistz256_from_mont(u64 r[4], const u64 a[4]);  (= mul_mont(a,1))
################################################################################
.globl	ecp_nistz256_from_mont
.type	ecp_nistz256_from_mont,\@function
.p2align 5
ecp_nistz256_from_mont:
___
$code .= save_regs();
$code .= <<___;
	la	$bp,.Lone
	ld	$A[0],0($ap)
	ld	$A[1],8($ap)
	ld	$A[2],16($ap)
	ld	$A[3],24($ap)
___
$code .= mul_core();
$code .= reduce_store();
$code .= load_regs();
$code .= <<___;
	ret
.size	ecp_nistz256_from_mont,.-ecp_nistz256_from_mont
___

clear_regs();

################################################################################
# Modular add/sub/neg/mul_by_2/mul_by_3/div_by_2 (no callee-saved regs needed).
# Temporaries: s0..s3 result, s4..s7 second operand / modulus, c0..c3 carries.
################################################################################
my ($s0,$s1,$s2,$s3) = use_regs(5, 6, 7, 28);
my ($u0,$u1,$u2,$u3) = use_regs(29, 30, 31, 13);
my ($k0,$k1,$k2,$k3) = use_regs(14, 15, 16, 17);
my $cc = use_reg("x8");
my $b0 = use_reg("x9");
my $tmp = use_reg("x18");
my $pptr = use_reg("x19");

# These leaf helpers use four callee-saved scratch registers; save/restore them.
my $MSAVE = "\taddi\tsp,sp,-32\n\tsd\tx8,24(sp)\n\tsd\tx9,16(sp)\n\tsd\tx18,8(sp)\n\tsd\tx19,0(sp)\n";
my $MREST = "\tld\tx8,24(sp)\n\tld\tx9,16(sp)\n\tld\tx18,8(sp)\n\tld\tx19,0(sp)\n\taddi\tsp,sp,32\n";

# emit: add p (into k[]) conditionally chosen; helper builds a full add-with-carry
# a[]+b[] -> s[], carry-out -> $cc  (a,b in [0,p) so result < 2^257)
sub add4 {
    my ($d, $x, $y, $carryout) = @_;
    my $c = "";
    $c .= "    add     $d->[0],$x->[0],$y->[0]\n    sltu    $carryout,$d->[0],$y->[0]\n";
    for my $j (1 .. 3) {
        $c .= "    add     $d->[$j],$x->[$j],$y->[$j]\n    sltu    $tmp,$d->[$j],$y->[$j]\n";
        $c .= "    add     $d->[$j],$d->[$j],$carryout\n    sltu    $carryout,$d->[$j],$carryout\n";
        $c .= "    add     $carryout,$carryout,$tmp\n";
    }
    return $c;
}

# ecp_nistz256_add: r = (a+b) mod p
$code .= <<___;
.globl	ecp_nistz256_add
.type	ecp_nistz256_add,\@function
.p2align 5
ecp_nistz256_add:
$MSAVE	ld	$s0,0($ap)
	ld	$s1,8($ap)
	ld	$s2,16($ap)
	ld	$s3,24($ap)
	ld	$u0,0($bp)
	ld	$u1,8($bp)
	ld	$u2,16($bp)
	ld	$u3,24($bp)
___
# s[] = a+b, carry into cc
$code .= "    add     $s0,$s0,$u0\n    sltu    $cc,$s0,$u0\n";
$code .= "    add     $s1,$s1,$u1\n    sltu    $tmp,$s1,$u1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$u2\n    sltu    $tmp,$s2,$u2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$u3\n    sltu    $tmp,$s3,$u3\n    add     $s3,$s3,$cc\n    sltu    $cc,$s3,$cc\n    add     $cc,$cc,$tmp\n";
# now (cc:s3:s2:s1:s0) = a+b. compute d = s - p (borrow chain), final borrow across cc.
$code .= <<___;
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
___
$code .= "    sltu    $b0,$s0,$k0\n    sub     $u0,$s0,$k0\n";
$code .= "    sltu    $tmp,$s1,$k1\n    sub     $u1,$s1,$k1\n    sltu    $pptr,$u1,$b0\n    sub     $u1,$u1,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s2,$k2\n    sub     $u2,$s2,$k2\n    sltu    $pptr,$u2,$b0\n    sub     $u2,$u2,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s3,$k3\n    sub     $u3,$s3,$k3\n    sltu    $pptr,$u3,$b0\n    sub     $u3,$u3,$b0\n    add     $b0,$tmp,$pptr\n";
# final borrow: cc - b0
$code .= "    sltu    $tmp,$cc,$b0\n";      # tmp = final borrow (1 => a+b < p, keep s)
# mask = (borrow==0)? ~0 : 0  -> select d
$code .= "    seqz    $cc,$tmp\n    neg     $cc,$cc\n    not     $tmp,$cc\n";
$code .= "    and     $u0,$u0,$cc\n    and     $s0,$s0,$tmp\n    or      $s0,$s0,$u0\n    sd      $s0,0($rp)\n";
$code .= "    and     $u1,$u1,$cc\n    and     $s1,$s1,$tmp\n    or      $s1,$s1,$u1\n    sd      $s1,8($rp)\n";
$code .= "    and     $u2,$u2,$cc\n    and     $s2,$s2,$tmp\n    or      $s2,$s2,$u2\n    sd      $s2,16($rp)\n";
$code .= "    and     $u3,$u3,$cc\n    and     $s3,$s3,$tmp\n    or      $s3,$s3,$u3\n    sd      $s3,24($rp)\n";
$code .= <<___;
$MREST	ret
.size	ecp_nistz256_add,.-ecp_nistz256_add
___

# ecp_nistz256_sub: r = (a-b) mod p    (a-b; if borrow add p)
$code .= <<___;
.globl	ecp_nistz256_sub
.type	ecp_nistz256_sub,\@function
.p2align 5
ecp_nistz256_sub:
$MSAVE	ld	$s0,0($ap)
	ld	$s1,8($ap)
	ld	$s2,16($ap)
	ld	$s3,24($ap)
	ld	$u0,0($bp)
	ld	$u1,8($bp)
	ld	$u2,16($bp)
	ld	$u3,24($bp)
___
# s[] = a - b, borrow into cc
$code .= "    sltu    $cc,$s0,$u0\n    sub     $s0,$s0,$u0\n";
$code .= "    sltu    $tmp,$s1,$u1\n    sub     $s1,$s1,$u1\n    sltu    $b0,$s1,$cc\n    sub     $s1,$s1,$cc\n    add     $cc,$tmp,$b0\n";
$code .= "    sltu    $tmp,$s2,$u2\n    sub     $s2,$s2,$u2\n    sltu    $b0,$s2,$cc\n    sub     $s2,$s2,$cc\n    add     $cc,$tmp,$b0\n";
$code .= "    sltu    $tmp,$s3,$u3\n    sub     $s3,$s3,$u3\n    sltu    $b0,$s3,$cc\n    sub     $s3,$s3,$cc\n    add     $cc,$tmp,$b0\n";
# mask = (borrow==1)? ~0 : 0  -> add p
$code .= <<___;
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
___
$code .= "    neg     $cc,$cc\n";     # cc = mask (all-ones if borrow)
# masked p
$code .= "    and     $k0,$k0,$cc\n    and     $k1,$k1,$cc\n    and     $k2,$k2,$cc\n    and     $k3,$k3,$cc\n";
# s[] += (p & mask)
$code .= "    add     $s0,$s0,$k0\n    sltu    $cc,$s0,$k0\n";
$code .= "    add     $s1,$s1,$k1\n    sltu    $tmp,$s1,$k1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$k2\n    sltu    $tmp,$s2,$k2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$k3\n    add     $s3,$s3,$cc\n";
$code .= <<___;
	sd	$s0,0($rp)
	sd	$s1,8($rp)
	sd	$s2,16($rp)
	sd	$s3,24($rp)
$MREST	ret
.size	ecp_nistz256_sub,.-ecp_nistz256_sub
___

# ecp_nistz256_neg: r = (0 - a) mod p ; implement as sub with a-operand = 0
$code .= <<___;
.globl	ecp_nistz256_neg
.type	ecp_nistz256_neg,\@function
.p2align 5
ecp_nistz256_neg:
$MSAVE	li	$s0,0
	li	$s1,0
	li	$s2,0
	li	$s3,0
	ld	$u0,0($ap)
	ld	$u1,8($ap)
	ld	$u2,16($ap)
	ld	$u3,24($ap)
___
$code .= "    sltu    $cc,$s0,$u0\n    sub     $s0,$s0,$u0\n";
$code .= "    sltu    $tmp,$s1,$u1\n    sub     $s1,$s1,$u1\n    sltu    $b0,$s1,$cc\n    sub     $s1,$s1,$cc\n    add     $cc,$tmp,$b0\n";
$code .= "    sltu    $tmp,$s2,$u2\n    sub     $s2,$s2,$u2\n    sltu    $b0,$s2,$cc\n    sub     $s2,$s2,$cc\n    add     $cc,$tmp,$b0\n";
$code .= "    sltu    $tmp,$s3,$u3\n    sub     $s3,$s3,$u3\n    sltu    $b0,$s3,$cc\n    sub     $s3,$s3,$cc\n    add     $cc,$tmp,$b0\n";
$code .= <<___;
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
___
$code .= "    neg     $cc,$cc\n";
$code .= "    and     $k0,$k0,$cc\n    and     $k1,$k1,$cc\n    and     $k2,$k2,$cc\n    and     $k3,$k3,$cc\n";
$code .= "    add     $s0,$s0,$k0\n    sltu    $cc,$s0,$k0\n";
$code .= "    add     $s1,$s1,$k1\n    sltu    $tmp,$s1,$k1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$k2\n    sltu    $tmp,$s2,$k2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$k3\n    add     $s3,$s3,$cc\n";
$code .= <<___;
	sd	$s0,0($rp)
	sd	$s1,8($rp)
	sd	$s2,16($rp)
	sd	$s3,24($rp)
$MREST	ret
.size	ecp_nistz256_neg,.-ecp_nistz256_neg
___

# ecp_nistz256_mul_by_2: r = (a+a) mod p   -> same tail as add with b=a
$code .= <<___;
.globl	ecp_nistz256_mul_by_2
.type	ecp_nistz256_mul_by_2,\@function
.p2align 5
ecp_nistz256_mul_by_2:
$MSAVE	ld	$s0,0($ap)
	ld	$s1,8($ap)
	ld	$s2,16($ap)
	ld	$s3,24($ap)
	mv	$u0,$s0
	mv	$u1,$s1
	mv	$u2,$s2
	mv	$u3,$s3
___
$code .= "    add     $s0,$s0,$u0\n    sltu    $cc,$s0,$u0\n";
$code .= "    add     $s1,$s1,$u1\n    sltu    $tmp,$s1,$u1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$u2\n    sltu    $tmp,$s2,$u2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$u3\n    sltu    $tmp,$s3,$u3\n    add     $s3,$s3,$cc\n    sltu    $cc,$s3,$cc\n    add     $cc,$cc,$tmp\n";
$code .= <<___;
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
___
$code .= "    sltu    $b0,$s0,$k0\n    sub     $u0,$s0,$k0\n";
$code .= "    sltu    $tmp,$s1,$k1\n    sub     $u1,$s1,$k1\n    sltu    $pptr,$u1,$b0\n    sub     $u1,$u1,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s2,$k2\n    sub     $u2,$s2,$k2\n    sltu    $pptr,$u2,$b0\n    sub     $u2,$u2,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s3,$k3\n    sub     $u3,$s3,$k3\n    sltu    $pptr,$u3,$b0\n    sub     $u3,$u3,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$cc,$b0\n";
$code .= "    seqz    $cc,$tmp\n    neg     $cc,$cc\n    not     $tmp,$cc\n";
$code .= "    and     $u0,$u0,$cc\n    and     $s0,$s0,$tmp\n    or      $s0,$s0,$u0\n    sd      $s0,0($rp)\n";
$code .= "    and     $u1,$u1,$cc\n    and     $s1,$s1,$tmp\n    or      $s1,$s1,$u1\n    sd      $s1,8($rp)\n";
$code .= "    and     $u2,$u2,$cc\n    and     $s2,$s2,$tmp\n    or      $s2,$s2,$u2\n    sd      $s2,16($rp)\n";
$code .= "    and     $u3,$u3,$cc\n    and     $s3,$s3,$tmp\n    or      $s3,$s3,$u3\n    sd      $s3,24($rp)\n";
$code .= <<___;
$MREST	ret
.size	ecp_nistz256_mul_by_2,.-ecp_nistz256_mul_by_2
___

# ecp_nistz256_mul_by_3: r = 3a mod p = add(add(a,a),a)
# implemented via two calls to ecp_nistz256_add-equivalent tail; simplest:
# t = 2a mod p (as above) into stack, then r = (t + a) mod p.
$code .= <<___;
.globl	ecp_nistz256_mul_by_3
.type	ecp_nistz256_mul_by_3,\@function
.p2align 5
ecp_nistz256_mul_by_3:
	addi	sp,sp,-64
	sd	$rp,32(sp)
	sd	$ap,40(sp)
	sd	x8,0(sp)
	sd	x9,8(sp)
	sd	x18,16(sp)
	sd	x19,24(sp)
	# compute 2a into stack [0..31] using mul_by_2 semantics inline
	ld	$s0,0($ap)
	ld	$s1,8($ap)
	ld	$s2,16($ap)
	ld	$s3,24($ap)
	mv	$u0,$s0
	mv	$u1,$s1
	mv	$u2,$s2
	mv	$u3,$s3
___
$code .= "    add     $s0,$s0,$u0\n    sltu    $cc,$s0,$u0\n";
$code .= "    add     $s1,$s1,$u1\n    sltu    $tmp,$s1,$u1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$u2\n    sltu    $tmp,$s2,$u2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$u3\n    sltu    $tmp,$s3,$u3\n    add     $s3,$s3,$cc\n    sltu    $cc,$s3,$cc\n    add     $cc,$cc,$tmp\n";
$code .= <<___;
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
___
$code .= "    sltu    $b0,$s0,$k0\n    sub     $u0,$s0,$k0\n";
$code .= "    sltu    $tmp,$s1,$k1\n    sub     $u1,$s1,$k1\n    sltu    $pptr,$u1,$b0\n    sub     $u1,$u1,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s2,$k2\n    sub     $u2,$s2,$k2\n    sltu    $pptr,$u2,$b0\n    sub     $u2,$u2,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s3,$k3\n    sub     $u3,$s3,$k3\n    sltu    $pptr,$u3,$b0\n    sub     $u3,$u3,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$cc,$b0\n";
$code .= "    seqz    $cc,$tmp\n    neg     $cc,$cc\n    not     $tmp,$cc\n";
$code .= "    and     $u0,$u0,$cc\n    and     $s0,$s0,$tmp\n    or      $s0,$s0,$u0\n";
$code .= "    and     $u1,$u1,$cc\n    and     $s1,$s1,$tmp\n    or      $s1,$s1,$u1\n";
$code .= "    and     $u2,$u2,$cc\n    and     $s2,$s2,$tmp\n    or      $s2,$s2,$u2\n";
$code .= "    and     $u3,$u3,$cc\n    and     $s3,$s3,$tmp\n    or      $s3,$s3,$u3\n";
# now s[] = 2a mod p ; add a (reload from saved ap)
$code .= <<___;
	ld	$ap,40(sp)
	ld	$u0,0($ap)
	ld	$u1,8($ap)
	ld	$u2,16($ap)
	ld	$u3,24($ap)
___
$code .= "    add     $s0,$s0,$u0\n    sltu    $cc,$s0,$u0\n";
$code .= "    add     $s1,$s1,$u1\n    sltu    $tmp,$s1,$u1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$u2\n    sltu    $tmp,$s2,$u2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$u3\n    sltu    $tmp,$s3,$u3\n    add     $s3,$s3,$cc\n    sltu    $cc,$s3,$cc\n    add     $cc,$cc,$tmp\n";
$code .= <<___;
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
___
$code .= "    sltu    $b0,$s0,$k0\n    sub     $u0,$s0,$k0\n";
$code .= "    sltu    $tmp,$s1,$k1\n    sub     $u1,$s1,$k1\n    sltu    $pptr,$u1,$b0\n    sub     $u1,$u1,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s2,$k2\n    sub     $u2,$s2,$k2\n    sltu    $pptr,$u2,$b0\n    sub     $u2,$u2,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$s3,$k3\n    sub     $u3,$s3,$k3\n    sltu    $pptr,$u3,$b0\n    sub     $u3,$u3,$b0\n    add     $b0,$tmp,$pptr\n";
$code .= "    sltu    $tmp,$cc,$b0\n";
$code .= "    seqz    $cc,$tmp\n    neg     $cc,$cc\n    not     $tmp,$cc\n";
$code .= "    ld      $rp,32(sp)\n";
$code .= "    and     $u0,$u0,$cc\n    and     $s0,$s0,$tmp\n    or      $s0,$s0,$u0\n    sd      $s0,0($rp)\n";
$code .= "    and     $u1,$u1,$cc\n    and     $s1,$s1,$tmp\n    or      $s1,$s1,$u1\n    sd      $s1,8($rp)\n";
$code .= "    and     $u2,$u2,$cc\n    and     $s2,$s2,$tmp\n    or      $s2,$s2,$u2\n    sd      $s2,16($rp)\n";
$code .= "    and     $u3,$u3,$cc\n    and     $s3,$s3,$tmp\n    or      $s3,$s3,$u3\n    sd      $s3,24($rp)\n";
$code .= <<___;
	ld	x8,0(sp)
	ld	x9,8(sp)
	ld	x18,16(sp)
	ld	x19,24(sp)
	addi	sp,sp,64
	ret
.size	ecp_nistz256_mul_by_3,.-ecp_nistz256_mul_by_3
___

# ecp_nistz256_div_by_2: if odd add p (5-word), then >>1
$code .= <<___;
.globl	ecp_nistz256_div_by_2
.type	ecp_nistz256_div_by_2,\@function
.p2align 5
ecp_nistz256_div_by_2:
$MSAVE	ld	$s0,0($ap)
	ld	$s1,8($ap)
	ld	$s2,16($ap)
	ld	$s3,24($ap)
	la	$pptr,.Lpoly
	ld	$k0,0($pptr)
	ld	$k1,8($pptr)
	ld	$k2,16($pptr)
	ld	$k3,24($pptr)
	andi	$cc,$s0,1
	neg	$cc,$cc			# mask = odd? ~0 : 0
	and	$k0,$k0,$cc
	and	$k1,$k1,$cc
	and	$k2,$k2,$cc
	and	$k3,$k3,$cc
___
# s[] += (p & mask), capture top carry in b0
$code .= "    add     $s0,$s0,$k0\n    sltu    $cc,$s0,$k0\n";
$code .= "    add     $s1,$s1,$k1\n    sltu    $tmp,$s1,$k1\n    add     $s1,$s1,$cc\n    sltu    $cc,$s1,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s2,$s2,$k2\n    sltu    $tmp,$s2,$k2\n    add     $s2,$s2,$cc\n    sltu    $cc,$s2,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    add     $s3,$s3,$k3\n    sltu    $tmp,$s3,$k3\n    add     $s3,$s3,$cc\n    sltu    $cc,$s3,$cc\n    add     $cc,$cc,$tmp\n";
$code .= "    mv      $b0,$cc\n";     # b0 = top bit (s4)
# shift right by 1:  r0=(s0>>1)|(s1<<63) ... r3=(s3>>1)|(s4<<63)
$code .= "    srli    $u0,$s0,1\n    slli    $tmp,$s1,63\n    or      $u0,$u0,$tmp\n    sd      $u0,0($rp)\n";
$code .= "    srli    $u1,$s1,1\n    slli    $tmp,$s2,63\n    or      $u1,$u1,$tmp\n    sd      $u1,8($rp)\n";
$code .= "    srli    $u2,$s2,1\n    slli    $tmp,$s3,63\n    or      $u2,$u2,$tmp\n    sd      $u2,16($rp)\n";
$code .= "    srli    $u3,$s3,1\n    slli    $tmp,$b0,63\n    or      $u3,$u3,$tmp\n    sd      $u3,24($rp)\n";
$code .= <<___;
$MREST	ret
.size	ecp_nistz256_div_by_2,.-ecp_nistz256_div_by_2
___

################################################################################
# Hard-coded generator table, converted from ecp_nistz256_table.c to the
# natural PRECOMP256_ROW layout expected by the portable C gather_w7.
################################################################################
$code .= <<___;
.section .rodata
.globl	ecp_nistz256_precomputed
.type	ecp_nistz256_precomputed,\@object
.p2align 6
ecp_nistz256_precomputed:
___
{
    $0 =~ m/(.*[\/\\])[^\/\\]+$/;
    my $dir = $1 // "";
    open(TABLE, "<ecp_nistz256_table.c") or
    open(TABLE, "<${dir}../ecp_nistz256_table.c") or
    die "failed to open ecp_nistz256_table.c: $!";
    my @arr;
    foreach (<TABLE>) {
        s/TOBN\(\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+)\s*\)/push @arr, hex($2), hex($1)/geo;
    }
    close TABLE;
    die "insane number of elements: ".scalar(@arr) if ($#arr != 64*16*37-1);
    # @arr is a stream of 32-bit halves in little-endian order (lo, hi, ...).
    # Emit as .word pairs -> natural little-endian 64-bit limbs, i.e. the
    # X[4],Y[4] layout of P256_POINT_AFFINE, 64 points per row, 37 rows.
    while (@arr) {
        my @line = splice(@arr, 0, 8);
        $code .= ".word " . join(",", map { sprintf "0x%08x", $_ } @line) . "\n";
    }
    $code .= ".size	ecp_nistz256_precomputed,.-ecp_nistz256_precomputed\n";
}

foreach (split("\n", $code)) {
    s/\`([^\`]*)\`/eval $1/ge;
    print $_, "\n";
}
close STDOUT or die "error closing STDOUT: $!";
