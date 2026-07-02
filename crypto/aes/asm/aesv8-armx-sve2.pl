#!/usr/bin/env perl
#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use File::Basename;

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;
my $dir = dirname($0) || ".";
my $xlate;

foreach ("$dir/arm-xlate.pl", "$dir/../../perlasm/arm-xlate.pl") {
    if (-f $_) {
        $xlate = $_;
        last;
    }
}
die "can't locate arm-xlate.pl" if !$xlate;

open OUT, "| \"$^X\" $xlate $flavour \"$output\"" or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $code = "";

my @data = map("z$_", 0..7);
my @twk  = map("z$_", 18..25);
my @rks  = ("z9", "z10", "z16", "z17", "z26",
            "z27", "z28", "z29", "z30", "z31");
my $final_rk = "z8";
my @saved_zregs = ("z8", "z9", "z10");
my $num_vecs = scalar @data;
my $stack_vecs = $num_vecs + scalar @saved_zregs;
my $hot_vl_bytes = 32;                 # VL=256 on the target machine.
my $hot_bytes = $num_vecs * $hot_vl_bytes;
my $hot_tweaks = $hot_bytes / 16;

sub load_round_key {
    my ($key, $idx, $reg) = @_;
    my $off = $idx * 16;

    return <<___;
    mov     x10, #$off
    ld1rqb  {$reg.b}, p0/z, [$key, x10]
___
}

sub aes_rounds {
    my ($op, $mc, $key, $rounds, $side_ops_ref) = @_;
    my $ret = "";
    my @side_ops = $side_ops_ref ? @$side_ops_ref : ();

    for (my $r = 0; $r < $rounds; $r++) {
        my $rounds_left = $rounds - $r;
        my $side_ops_this_round = @side_ops ?
            int((@side_ops + $rounds_left - 1) / $rounds_left) : 0;

        $ret .= load_round_key($key, $r, "z26");
        foreach my $z (@data) {
            $ret .= "    $op    $z.b, $z.b, z26.b\n";
            if ($r < $rounds - 1) {
                $ret .= "    $mc   $z.b, $z.b\n";
            }
        }
        for (1..$side_ops_this_round) {
            $ret .= shift(@side_ops);
        }
    }

    return $ret;
}

sub wreg {
    my ($reg) = @_;
    $reg =~ s/^x/w/;
    return $reg;
}

sub load_round_keys {
    my ($key) = @_;
    my $ret = "";

    for (my $i = 0; $i < @rks; $i++) {
        $ret .= load_round_key($key, $i, $rks[$i]);
    }

    return $ret;
}

sub load_final_round_key {
    my ($key, $rounds) = @_;

    return load_round_key($key, $rounds, $final_rk);
}

sub encrypt_initial_tweak {
    my ($rounds) = @_;
    my $ret = "";

    for (my $i = 0; $i < $rounds; $i++) {
        $ret .= load_round_key("x4", $i, "z30");
        $ret .= "    aese    z18.b, z18.b, z30.b\n";
        $ret .= "    aesmc   z18.b, z18.b\n" if ($i < $rounds - 1);
    }

    $ret .= load_round_key("x4", $rounds, "z30");
    $ret .= "    eor     z18.d, z18.d, z30.d\n";

    return $ret;
}

sub step_tweak_gpr {
    my ($lo, $hi, $const, $tmp) = @_;

    return <<___;
    extr    $tmp, $hi, $hi, #32
    and     @{[wreg($tmp)]}, @{[wreg($const)]}, @{[wreg($tmp)]}, asr #31
    extr    $hi, $hi, $lo, #63
    eor     $lo, $tmp, $lo, lsl #1
___
}

sub store_tweak_gpr {
    my ($ptr, $lo, $hi, $const, $tmp) = @_;

    return <<___ . step_tweak_gpr($lo, $hi, $const, $tmp);
    stp     $lo, $hi, [$ptr], #16
___
}

sub store_tweak_gpr_at {
    my ($base, $off, $lo, $hi, $const, $tmp) = @_;

    return <<___ . step_tweak_gpr($lo, $hi, $const, $tmp);
    stp     $lo, $hi, [$base, #$off]
___
}

sub store_tweak_group4_at {
    my ($base, $start_off, $src_lo, $src_hi, $tmp_lo, $tmp_hi,
        $const, $tmp) = @_;
    my $ret = <<___;
    mov     $tmp_lo, $src_lo
    mov     $tmp_hi, $src_hi
___

    for (my $i = 0; $i < 4; $i++) {
        my $off = $start_off + $i * 16;
        $ret .= store_tweak_gpr_at($base, $off, $tmp_lo, $tmp_hi,
                                   $const, $tmp);
    }

    $ret .= <<___;
    mov     $src_lo, $tmp_lo
    mov     $src_hi, $tmp_hi
___

    return $ret;
}

sub fill_tweak_buffer {
    my ($done_label, $generic_label, $loop_label) = @_;
    my $ret = <<___;
    cmp     x11, #$hot_bytes
    b.ne    $generic_label
___

    for (my $i = 0; $i < $hot_tweaks; $i += 4) {
        my $off = $i * 16;
        $ret .= store_tweak_group4_at("sp", $off, "x12", "x13", "x6", "x7",
                                      "x14", "x15");
    }

    $ret .= <<___;
    b       $done_label

$generic_label:
    mov     x9, sp
    lsr     x8, x11, #4
$loop_label:
___
    $ret .= store_tweak_gpr("x9", "x12", "x13", "x14", "x15");
    $ret .= <<___;
    subs    x8, x8, #1
    b.ne    $loop_label
$done_label:
___

    return $ret;
}

sub tweak_buffer_hot_ops {
    my @ops = ();

    for (my $i = 0; $i < $hot_tweaks; $i += 4) {
        my $off = $i * 16;
        push @ops, store_tweak_group4_at("sp", $off, "x12", "x13", "x6", "x7",
                                         "x14", "x15");
    }

    return @ops;
}

sub load_tweaks {
    my $ret = "";

    for (my $i = 0; $i < @twk; $i++) {
        $ret .= "    ld1b    {$twk[$i].b}, p0/z, [sp, #$i, mul vl]\n";
    }

    return $ret;
}

sub load_tweaks_d {
    my $ret = "";

    for (my $i = 0; $i < @twk; $i++) {
        $ret .= "    ld1d    {$twk[$i].d}, p0/z, [sp, #$i, mul vl]\n";
    }

    return $ret;
}

sub load_data {
    my (@preds) = @_;
    my $ret = "";

    for (my $i = 0; $i < @data; $i++) {
        my $pred = $preds[$i] || "p0";
        my $dat = $data[$i];
        my $tweak = $twk[$i];
        $ret .= "    ld1b    {$data[$i].b}, $pred/z, [x0, #$i, mul vl]\n";
        $ret .= "    eor     $dat.d, $dat.d, $tweak.d\n";
    }

    return $ret;
}

sub final_xor_and_store_for {
    my ($final_key, $data_ref, $twk_ref, $pred_ref) = @_;
    my @regs = @$data_ref;
    my @tweaks = @$twk_ref;
    my @preds = @$pred_ref;
    my $ret = "";

    for (my $i = 0; $i < @regs; $i++) {
        $ret .= "    eor     $regs[$i].d, $regs[$i].d, $final_key.d\n";
        $ret .= "    eor     $regs[$i].d, $regs[$i].d, $tweaks[$i].d\n";
        $ret .= "    st1b    {$regs[$i].b}, $preds[$i], [x1, #$i, mul vl]\n";
    }

    return $ret;
}

sub final_xor_and_store {
    my (@preds) = @_;
    my $ret = "";

    for (my $i = 0; $i < @data; $i++) {
        my $pred = $preds[$i] || "p0";
        my $dat = $data[$i];
        my $tweak = $twk[$i];
        $ret .= "    eor     $dat.d, $dat.d, $final_rk.d\n";
        $ret .= "    eor     $dat.d, $dat.d, $tweak.d\n";
        $ret .= "    st1b    {$data[$i].b}, $pred, [x1, #$i, mul vl]\n";
    }

    return $ret;
}

sub save_zregs {
    my $ret = "";

    $ret .= "    addvl   x9, sp, #$num_vecs\n";
    for (my $i = 0; $i < @saved_zregs; $i++) {
        $ret .= "    st1b    {$saved_zregs[$i].b}, p0, [x9, #$i, mul vl]\n";
    }

    return $ret;
}

sub restore_zregs {
    my $ret = "";

    $ret .= "    addvl   x9, sp, #$num_vecs\n";
    for (my $i = 0; $i < @saved_zregs; $i++) {
        $ret .= "    ld1b    {$saved_zregs[$i].b}, p0/z, [x9, #$i, mul vl]\n";
    }

    return $ret;
}

sub tail_predicates {
    my $ret = <<___;
    cntb    x10
    mov     x8, x2
___

    for (my $i = 0; $i < $num_vecs; $i++) {
        $ret .= "    whilelo p$i.b, xzr, x8\n";
        if ($i != $num_vecs - 1) {
            $ret .= <<___;
    subs    x8, x8, x10
    csel    x8, xzr, x8, lo
___
        }
    }

    return $ret;
}

sub sve2_512_exact_case {
    my ($label, $op, $mc, $rounds) = @_;
    my @preds = ("p0") x $num_vecs;
    my $ret = <<___;
$label:
    ptrue   p0.b, ALL

    // T0 = AES_encrypt(iv, tweak_key).
    ld1rqb  {z18.b}, p0/z, [x5]
___

    $ret .= encrypt_initial_tweak($rounds);
    $ret .= <<___;
    fmov    x12, d18
    fmov    x13, v18.d[1]
    mov     x14, #0x87
    addvl   sp, sp, #-$num_vecs
___

    for (my $i = 0; $i < $hot_tweaks; $i += 4) {
        my $off = $i * 16;
        $ret .= store_tweak_group4_at("sp", $off, "x12", "x13", "x6",
                                      "x7", "x14", "x15");
    }

    $ret .= load_round_key("x3", $rounds, "z31");
    $ret .= load_tweaks_d();
    $ret .= load_data(@preds);
    my @next_tweak_ops = tweak_buffer_hot_ops();
    $ret .= aes_rounds($op, $mc, "x3", $rounds, \@next_tweak_ops);
    $ret .= final_xor_and_store_for("z31", \@data, \@twk, \@preds);

    $ret .= <<___;
    add     x0, x0, #$hot_bytes
    add     x1, x1, #$hot_bytes
___

    $ret .= load_tweaks_d();
    $ret .= load_data(@preds);
    $ret .= aes_rounds($op, $mc, "x3", $rounds);
    $ret .= final_xor_and_store_for("z31", \@data, \@twk, \@preds);
    $ret .= <<___;
    addvl   sp, sp, #$num_vecs
    ret

___

    return $ret;
}

$code .= <<___;
#include "arch/arm_arch.h"
.text
.arch armv9-a+sve2+sve2-aes
.p2align 6
___

sub emit_xts_func {
    my ($bits, $direction, $op, $mc, $rounds) = @_;
    my $ossl_name = "aes_v8_sve2_xts_${bits}_${direction}";
    my $L = ".L${bits}_${direction}";
    my $fallback = $direction eq "encrypt" ? "aes_v8_xts_encrypt" : "aes_v8_xts_decrypt";
    my $xts512_target = $bits == 128 ? $fallback : "${L}_small_512";

    $code .= <<___;

.global $ossl_name
.type   $ossl_name,%function
$ossl_name:
    AARCH64_VALID_CALL_TARGET
___
    $code .= <<___;
    tst     x2, #15
    b.ne    $fallback
    cbz     x2, ${L}_ret
    cmp     x2, #256
    b.ls    $fallback
    cmp     x2, #512
    b.eq    $xts512_target
    ptrue   p0.b, ALL

    // Temporary tweak buffer plus saved Z registers used by the hot loop.
    addvl   sp, sp, #-$stack_vecs
___
    $code .= save_zregs();
    $code .= <<___;
    cntb    x11, ALL, mul #$num_vecs

    // T0 = AES_encrypt(iv, tweak_key). It is replicated only long enough to
    // extract the first 128-bit value into GPRs.
    ld1rqb  {z18.b}, p0/z, [x5]
___
    $code .= encrypt_initial_tweak($rounds);
    $code .= <<___;
    fmov    x12, d18
    fmov    x13, v18.d[1]
    mov     x14, #0x87
___

    $code .= fill_tweak_buffer("${L}_tweak_init_done",
                               "${L}_tweak_init_generic",
                               "${L}_tweak_init_loop");

    $code .= load_final_round_key("x3", $rounds);

    $code .= <<___;
    cmp     x11, #$hot_bytes
    b.ne    ${L}_generic_loop

${L}_loop:
    cmp     x2, x11
    b.lo    ${L}_tail

___

    $code .= load_tweaks();
    $code .= load_data(("p0") x $num_vecs);

    my @next_tweak_ops = tweak_buffer_hot_ops();
    $code .= aes_rounds($op, $mc, "x3", $rounds, \@next_tweak_ops);

    $code .= <<___;
${L}_tweak_next_done:
___
    $code .= final_xor_and_store(("p0") x $num_vecs);

    $code .= <<___;
    subs    x2, x2, x11
    add     x0, x0, x11
    add     x1, x1, x11
    b.ne    ${L}_loop
    b       ${L}_done

${L}_generic_loop:
    cmp     x2, x11
    b.lo    ${L}_tail

___
    $code .= load_tweaks();

    $code .= <<___;
    mov     x9, sp
    lsr     x8, x11, #4
${L}_tweak_next_generic_loop:
___
    $code .= store_tweak_gpr("x9", "x12", "x13", "x14", "x15");
    $code .= <<___;
    subs    x8, x8, #1
    b.ne    ${L}_tweak_next_generic_loop

___
    $code .= load_data(("p0") x $num_vecs);
    $code .= aes_rounds($op, $mc, "x3", $rounds);
    $code .= final_xor_and_store(("p0") x $num_vecs);

    $code .= <<___;
    subs    x2, x2, x11
    add     x0, x0, x11
    add     x1, x1, x11
    b.ne    ${L}_generic_loop
    b       ${L}_done

${L}_tail:
    cbz     x2, ${L}_done
___

    $code .= load_tweaks();
    $code .= tail_predicates();
    my @tail_preds = map("p$_", 0..($num_vecs - 1));
    $code .= load_data(@tail_preds);
    $code .= aes_rounds($op, $mc, "x3", $rounds);
    $code .= final_xor_and_store(@tail_preds);

    $code .= <<___;

${L}_done:
    ptrue   p0.b, ALL
___
    $code .= restore_zregs();
    $code .= <<___;
    addvl   sp, sp, #$stack_vecs
${L}_ret:
    ret
.size   $ossl_name,.-$ossl_name
___
    $code .= sve2_512_exact_case("${L}_small_512", $op, $mc, $rounds)
        if $bits != 128;
}

emit_xts_func(128, "encrypt", "aese", "aesmc", 10);
emit_xts_func(128, "decrypt", "aesd", "aesimc", 10);
emit_xts_func(256, "encrypt", "aese", "aesmc", 14);
emit_xts_func(256, "decrypt", "aesd", "aesimc", 14);

print $code;
close STDOUT;
