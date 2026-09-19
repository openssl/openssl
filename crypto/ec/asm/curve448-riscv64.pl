#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# RISC-V Vector (RVV) implementations of the Curve448 field helpers
# gf_sub_RAW(), gf_weak_reduce() and gf_cond_swap().
#
# Requires RV64I plus the 'V' extension with VLEN >= 128.  No Zvk* extension
# is used.  These helpers are reached only from code compiled with
# __riscv_vector and __riscv_v_min_vlen <= 128 (see crypto/ec/curve448/field.h),
# so the build configuration is the guard; there is no runtime RISCV_HAS_V()
# test here.
#
# Vector instructions are emitted as raw .word encodings (see riscv.pm): the
# assembler rejects vector mnemonics unless the build is configured with
# -march=<...>v, and linux64-riscv64 passes no -march at all.  Encoding them
# directly also keeps this file independent of the assembler version and of
# the VLEN of the machine that builds it.
#
# Vector width.  A gf_s is NLIMBS == 8 limbs of 64 bits, i.e. 512 bits, and
# each helper wants all 8 limbs in one vector register group so that the whole
# array is handled in a single pass.  e64/m2 holds 8 limbs when VLEN >= 256 and
# e64/m4 holds 8 limbs when VLEN >= 128; since the ISA guarantees VLEN >= 128,
# e64/m4 always suffices, but on a VLEN >= 256 machine it wastes half of the
# register group and doubles the register pressure in the caller.  Each helper
# therefore probes for the wider vector once, on entry, and branches to
# whichever body fits.
#
# The probe is vsetvli with rd != x0, which writes the resulting vl.  AVL comes
# from t2 and vsetvli leaves rs1 untouched, so the returned vl can be compared
# against the value that was requested.  The probe has no effect other than
# setting vl and vtype, so it does not disturb the caller's state beyond the
# vector length it is about to use anyway.
#
# vsetvli is an ordinary V-extension instruction, not a hint: it raises an
# illegal-instruction exception on a hart without V, so it is only reachable
# because the compile-time gate above guarantees the build requires V.

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

my $code=<<___;
.text
___

# ABI: a0 = out, a1 = a, a2 = b   (gf_sub_RAW)
#      a0 = inout                  (gf_weak_reduce)
#      a0 = x, a1 = y, a2 = swap   (gf_cond_swap)
#
# All three helpers are leaf functions.  They only touch t0-t2 and v8-v24.
# The psABI makes both caller-saved: under the standard vector calling
# convention (the one in force here; the callee-saved v1-v7/v24-v31 split
# applies only to the opt-in riscv_vector_cc variant) all of v0-v31, vl and
# vtype are temporary and not preserved across calls.  No stack frame is
# needed.

################################################################################
# Probe VLMAX(e64, m2) >= NLIMBS.  Falls through when e64/m2 can hold all 8
# limbs, branches to $to otherwise.  Clobbers t0; t2 keeps the requested AVL
# so that the caller can reuse it, and is reloaded by each body as needed.
################################################################################
sub vlen_probe {
    my $to = shift;

    return <<___;
    li      t2, 8
    @{[vsetvli "t0", "t2", "e64", "m2", "ta", "ma"]}
    bne     t0, t2, $to
___
}

################################################################################
# void ossl_gf_sub_RAW_rvv(gf out, const gf a, const gf b);
#
# out->limb[i] = a->limb[i] - b->limb[i] + co1, then out->limb[4] -= 2,
# then gf_weak_reduce(out).  co1 = ((1 << 56) - 1) * 2 = 2^57 - 2.
################################################################################
sub gf_sub_raw {
    my $name = shift;
    my ($out, $a, $b) = ("a0", "a1", "a2");
    my ($tmp, $co1) = ("t0", "t1");
    my ($va, $vb, $vr) = ("v8", "v16", "v24");

    $code .= <<___;
.p2align 3
.globl $name
.type $name,\@function
$name:
___
    $code .= vlen_probe(".Lsub_RAW_m4");
    $code .= <<___;
    li      $co1, 2
    slli    $co1, $co1, 56
    addi    $co1, $co1, -2
___
    # vsetivli zero, 8, e64, m2, ta, ma
    $code .= "    ".vsetivli("zero", 8, "e64", "m2", "ta", "ma")."\n";
    $code .= <<___;
    @{[vle64_v $va, $a]}
    @{[vle64_v $vb, $b]}
    @{[vsub_vv $vr, $va, $vb]}
    @{[vadd_vx $vr, $vr, $co1]}
    @{[vse64_v $vr, $out]}
    ld      $tmp, 32($out)
    addi    $tmp, $tmp, -2
    sd      $tmp, 32($out)
    j       .Lweak_reduce_m2
.p2align 3
.Lsub_RAW_m4:
    li      $co1, 2
    slli    $co1, $co1, 56
    addi    $co1, $co1, -2
___
    # vsetivli zero, 8, e64, m4, ta, ma
    $code .= "    ".vsetivli("zero", 8, "e64", "m4", "ta", "ma")."\n";
    $code .= <<___;
    @{[vle64_v $va, $a]}
    @{[vle64_v $vb, $b]}
    @{[vsub_vv $vr, $va, $vb]}
    @{[vadd_vx $vr, $vr, $co1]}
    @{[vse64_v $vr, $out]}
    ld      $tmp, 32($out)
    addi    $tmp, $tmp, -2
    sd      $tmp, 32($out)
    j       .Lweak_reduce_m4
.size $name,.-$name
___
}

################################################################################
# void ossl_gf_weak_reduce_rvv(gf inout);
#
#     tmp = inout->limb[7] >> 56;
#     inout->limb[4] += tmp;
#     inout->limb[i] = (inout->limb[i] & mask) + (inout->limb[i-1] >> 56);
#     inout->limb[0] = (inout->limb[0] & mask) + tmp;
#
# The scalar loop is a carry chain: lane i consumes the high bits of lane i-1.
# In a vector register that is exactly vslide1up, which shifts in tmp as the
# new lane 0, so all 8 limbs reduce in one pass.  mask = (1 << 56) - 1.
#
# The two bodies are also the tail-jump targets of gf_sub_RAW, which enters
# them directly to avoid re-probing.
################################################################################
sub gf_weak_reduce {
    my $name = shift;
    my $inout = "a0";
    my ($tmp, $mask, $shift) = ("t0", "t1", "t2");
    # The base register of a vector operand must be a multiple of the LMUL, so
    # at m4 only v0/v4/v8/.../v28 are usable.  v8-v24 are all caller-saved, so
    # five of them are available here.
    my ($va, $vs, $vc, $vm, $vtmp) = ("v8", "v12", "v16", "v20", "v24");

    $code .= <<___;
.p2align 3
.globl $name
.type $name,\@function
$name:
___
    $code .= vlen_probe(".Lweak_reduce_m4");
    $code .= <<___;
.Lweak_reduce_m2:
    ld      $tmp, 56($inout)
    srli    $tmp, $tmp, 56
    ld      $mask, 32($inout)
    add     $mask, $mask, $tmp
    sd      $mask, 32($inout)
___
    # vsetivli zero, 8, e64, m2, ta, ma
    $code .= "    ".vsetivli("zero", 8, "e64", "m2", "ta", "ma")."\n";
    $code .= <<___;
    li      $mask, 1
    slli    $mask, $mask, 56
    addi    $mask, $mask, -1
    li      $shift, 56
    @{[vle64_v $va, $inout]}
    @{[vsrl_vx $vs, $va, $shift]}
    @{[vslide1up_vx $vc, $vs, $tmp]}
    @{[vand_vx $vm, $va, $mask]}
    @{[vadd_vv $vtmp, $vm, $vc]}
    @{[vse64_v $vtmp, $inout]}
    ret
.p2align 3
.Lweak_reduce_m4:
    ld      $tmp, 56($inout)
    srli    $tmp, $tmp, 56
    ld      $mask, 32($inout)
    add     $mask, $mask, $tmp
    sd      $mask, 32($inout)
___
    # vsetivli zero, 8, e64, m4, ta, ma
    $code .= "    ".vsetivli("zero", 8, "e64", "m4", "ta", "ma")."\n";
    $code .= <<___;
    li      $mask, 1
    slli    $mask, $mask, 56
    addi    $mask, $mask, -1
    li      $shift, 56
    @{[vle64_v $va, $inout]}
    @{[vsrl_vx $vs, $va, $shift]}
    @{[vslide1up_vx $vc, $vs, $tmp]}
    @{[vand_vx $vm, $va, $mask]}
    @{[vadd_vv $vtmp, $vm, $vc]}
    @{[vse64_v $vtmp, $inout]}
    ret
.size $name,.-$name
___
}

################################################################################
# void ossl_gf_cond_swap_rvv(gf x, gf y, mask_t swap);
#
# t = (x ^ y) & swap;  x ^= t;  y ^= t;
#
# Constant time in |swap|: no branch and no memory access depends on it, only
# the vand.vx data operand.  A gf_s is 64 bytes and gf_s is declared
# __attribute__((aligned(16))), so both vle64.v/vse64.v accesses are aligned
# for either lmul.
################################################################################
sub gf_cond_swap {
    my $name = shift;
    my ($x, $y, $swap) = ("a0", "a1", "a2");
    my ($vx, $vy, $vt) = ("v8", "v16", "v24");

    $code .= <<___;
.p2align 3
.globl $name
.type $name,\@function
$name:
___
    $code .= vlen_probe(".Lcond_swap_m4");
    # vsetivli zero, 8, e64, m2, ta, ma
    $code .= "    ".vsetivli("zero", 8, "e64", "m2", "ta", "ma")."\n";
    $code .= <<___;
    @{[vle64_v $vx, $x]}
    @{[vle64_v $vy, $y]}
    @{[vxor_vv $vt, $vx, $vy]}
    @{[vand_vx $vt, $vt, $swap]}
    @{[vxor_vv $vx, $vx, $vt]}
    @{[vxor_vv $vy, $vy, $vt]}
    @{[vse64_v $vx, $x]}
    @{[vse64_v $vy, $y]}
    ret
.p2align 3
.Lcond_swap_m4:
___
    # vsetivli zero, 8, e64, m4, ta, ma
    $code .= "    ".vsetivli("zero", 8, "e64", "m4", "ta", "ma")."\n";
    $code .= <<___;
    @{[vle64_v $vx, $x]}
    @{[vle64_v $vy, $y]}
    @{[vxor_vv $vt, $vx, $vy]}
    @{[vand_vx $vt, $vt, $swap]}
    @{[vxor_vv $vx, $vx, $vt]}
    @{[vxor_vv $vy, $vy, $vt]}
    @{[vse64_v $vx, $x]}
    @{[vse64_v $vy, $y]}
    ret
.size $name,.-$name
___
}

gf_sub_raw("ossl_gf_sub_RAW_rvv");
gf_weak_reduce("ossl_gf_weak_reduce_rvv");
gf_cond_swap("ossl_gf_cond_swap_rvv");

print $code;

close STDOUT or die "error closing STDOUT: $!";
