#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by Rohan McLure <rmclure@linux.ibm.com> for the OpenSSL
# project.
# ====================================================================
#
# p384 lower-level primitives for PPC64 using vector instructions.
#

use strict;
use warnings;

my $flavour = shift;
my $output = "";
while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
if (!$output) {
    $output = "-";
}

my ($xlate, $dir);
$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

my $code = "";

my ($sp, $outp, $savelr, $tbl) = ("r1", "r3", "r0", "r10");
my ($tmp1, $tmp2) = ("r8", "r9");

my $vzero = "v32";

sub startproc($)
{
    my ($name) = @_;

    $code.=<<___;
    .globl ${name}
    .align 5
${name}:

___
}

sub endproc($)
{
    my ($name) = @_;

    $code.=<<___;
    blr
        .size ${name},.-${name}

___
}

sub load_vrs($$)
{
    my ($pointer, $reg_list) = @_;

    for (my $i = 0; $i <= 6; $i++) {
        my $offset = $i * 8;
        $code.=<<___;
    lxsd        $reg_list->[$i],$offset($pointer)
___
    }
}

sub forward_vrs($$)
{
    my ($dst_vrs, $src_vrs) = @_;

    for (my $i = 0; $i <= 12; $i++) {
        $code.=<<___;
    xxmr        $dst_vrs->[$i],$src_vrs->[$i]
___
    }
}

$code.=<<___;
.machine    "any"
.text

___

{
    # mul/square common
    my ($t1, $t2, $t3, $t4) = ("v33", "v34", "v42", "v43");
    my ($zero, $one) = ("r8", "r9");
    my $out = "v51";
    my @r = map("v$_",(0..12));

    # reduce's inputs
    my @acc = map("v$_",(35..47));

    sub writeback($$)
    {
        my ($eager, $idx) = @_; 

        if ($eager) {
            $code.=<<___;
    stxv        $out,$idx*16($outp)
___
        } else {
            $code.=<<___;
    xxmr        $r[$idx],$out
___
        }
    }

    {
        #
        # p384_felem_mul
        #

        my ($in1p, $in2p) = ("r4", "r5");
        my @in1 = map("v$_",(44..50));
        my @in2 = map("v$_",(35..41));

        sub mul_body($)
        {
            my $eager = $_[0];
            $code.=<<___;
    vmsumudm    $out,$in1[0],$in2[0],$vzero
___
            writeback($eager, 0);

        $code.=<<___;
    xxpermdi    $t1,$in1[0],$in1[1],0b00
    xxpermdi    $t2,$in2[1],$in2[0],0b00
    vmsumudm    $out,$t1,$t2,$vzero
___
            writeback($eager, 1);

            $code.=<<___;
    xxpermdi    $t2,$in2[2],$in2[1],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in1[2],$in2[0],$out
___
            writeback($eager, 2);

            $code.=<<___;
    xxpermdi    $t2,$in2[1],$in2[0],0b00
    xxpermdi    $t3,$in1[2],$in1[3],0b00
    xxpermdi    $t4,$in2[3],$in2[2],0b00
    vmsumudm    $out,$t1,$t4,$vzero
    vmsumudm    $out,$t3,$t2,$out
___
            writeback($eager, 3);

            $code.=<<___;
    xxpermdi    $t2,$in2[4],$in2[3],0b00
    xxpermdi    $t4,$in2[2],$in2[1],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    vmsumudm    $out,$in1[4],$in2[0],$out
___
            writeback($eager, 4);

            $code.=<<___;
    xxpermdi    $t2,$in2[5],$in2[4],0b00
    xxpermdi    $t4,$in2[3],$in2[2],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    xxpermdi    $t4,$in2[1],$in2[0],0b00
    xxpermdi    $t1,$in1[4],$in1[5],0b00
    vmsumudm    $out,$t1,$t4,$out
___
            writeback($eager, 5);

            $code.=<<___;
    xxpermdi    $t1,$in1[0],$in1[1],0b00
    xxpermdi    $t2,$in2[6],$in2[5],0b00
    xxpermdi    $t4,$in2[4],$in2[3],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    xxpermdi    $t2,$in2[2],$in2[1],0b00
    xxpermdi    $t1,$in1[4],$in1[5],0b00
    vmsumudm    $out,$t1,$t2,$out
    vmsumudm    $out,$in1[6],$in2[0],$out
___
            writeback($eager, 6);

            $code.=<<___;
    xxpermdi    $t1,$in1[1],$in1[2],0b00
    xxpermdi    $t2,$in2[6],$in2[5],0b00
    xxpermdi    $t3,$in1[3],$in1[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    xxpermdi    $t3,$in2[2],$in2[1],0b00
    xxpermdi    $t1,$in1[5],$in1[6],0b00
    vmsumudm    $out,$t1,$t3,$out
___
            writeback($eager, 7);

            $code.=<<___;
    xxpermdi    $t1,$in1[2],$in1[3],0b00
    xxpermdi    $t3,$in1[4],$in1[5],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    vmsumudm    $out,$in1[6],$in2[2],$out
___
            writeback($eager, 8);

            $code.=<<___;
    xxpermdi    $t1,$in1[3],$in1[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    xxpermdi    $t1,$in1[5],$in1[6],0b00
    vmsumudm    $out,$t1,$t4,$out
___
            writeback($eager, 9);

            $code.=<<___;
    vmsumudm    $out,$t3,$t2,$vzero
    vmsumudm    $out,$in1[6],$in2[4],$out
___
            writeback($eager, 10);

            $code.=<<___;
    vmsumudm    $out,$t1,$t2,$vzero
___
            writeback($eager, 11);

            $code.=<<___;
    vmsumudm    $out,$in1[6],$in2[6],$vzero
___
            writeback($eager, 12);
        }

        startproc("p384_felem_mul");

        $code.=<<___;
    vspltisw    $vzero,0
___

        load_vrs($in1p, \@in1);
        load_vrs($in2p, \@in2);

        mul_body(1);

        endproc("p384_felem_mul");

        #
        # p384_felem_mul_reduce
        #
        
        startproc("p384_felem_mul_reduce");

        $code.=<<___;
    vspltisw    $vzero,0
___

        load_vrs($in1p, \@in1);
        load_vrs($in2p, \@in2);

        mul_body(0);
        forward_vrs(\@acc,\@r);

            $code.=<<___;
    b           .Lreduce_common
    .size p384_felem_mul_reduce,.-p384_felem_mul_reduce
___
    }

    {
        #
        # p384_felem_square
        #

        my $inp = "r4";
        my @in = map("v$_",(44..50));
        my @inx2 = map("v$_",(35..41));

        sub square_body($)
        {
            my $eager = $_[0];

            $code.=<<___;
    vmsumudm    $out,$in[0],$in[0],$vzero
___
            writeback($eager, 0);

            $code.=<<___;
    vmsumudm    $out,$in[0],$inx2[1],$vzero
___
            writeback($eager, 1);

            $code.=<<___;
    vmsumudm    $out,$in[0],$inx2[2],$vzero
    vmsumudm    $out,$in[1],$in[1],$out
___
            writeback($eager, 2);

            $code.=<<___;
    xxpermdi    $t1,$in[0],$in[1],0b00
    xxpermdi    $t2,$inx2[3],$inx2[2],0b00
    vmsumudm    $out,$t1,$t2,$vzero
___
            writeback($eager, 3);

            $code.=<<___;
    xxpermdi    $t4,$inx2[4],$inx2[3],0b00
    vmsumudm    $out,$t1,$t4,$vzero
    vmsumudm    $out,$in[2],$in[2],$out
___
            writeback($eager, 4);

            $code.=<<___;
    xxpermdi    $t2,$inx2[5],$inx2[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in[2],$inx2[3],$out
___
            writeback($eager, 5);

            $code.=<<___;
    xxpermdi    $t2,$inx2[6],$inx2[5],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in[2],$inx2[4],$out
    vmsumudm    $out,$in[3],$in[3],$out
___
            writeback($eager, 6);

            $code.=<<___;
    xxpermdi    $t3,$in[1],$in[2],0b00
    vmsumudm    $out,$t3,$t2,$vzero
    vmsumudm    $out,$in[3],$inx2[4],$out
___
            writeback($eager, 7);

            $code.=<<___;
    xxpermdi    $t1,$in[2],$in[3],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in[4],$in[4],$out
___
            writeback($eager, 8);

            $code.=<<___;
    xxpermdi    $t1,$in[3],$in[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
___
            writeback($eager, 9);

            $code.=<<___;
    vmsumudm    $out,$in[4],$inx2[6],$vzero
    vmsumudm    $out,$in[5],$in[5],$out
___
            writeback($eager, 10);

            $code.=<<___;
    vmsumudm    $out,$in[5],$inx2[6],$vzero
___
            writeback($eager, 11);

            $code.=<<___;
    vmsumudm    $out,$in[6],$in[6],$vzero
___
            writeback($eager, 12);
        }

        startproc("p384_felem_square");

        $code.=<<___;
    vspltisw    $vzero,0
___

        load_vrs($inp, \@in);

        $code.=<<___;
    li        $zero,0
    li        $one,1
    mtvsrdd        $t1,$one,$zero
___

        for (my $i = 0; $i <= 6; $i++) {
            $code.=<<___;
    vsld        $inx2[$i],$in[$i],$t1
___
        }

        square_body(1);

        endproc("p384_felem_square");

        #
        # p384_felem_square_reduce
        #
        
        startproc("p384_felem_square_reduce");

        $code.=<<___;
    vspltisw    $vzero,0
___

        load_vrs($inp, \@in);

        $code.=<<___;
    li        $zero,0
    li        $one,1
    mtvsrdd        $t1,$one,$zero
___

        for (my $i = 0; $i <= 6; $i++) {
            $code.=<<___;
    vsld        $inx2[$i],$in[$i],$t1
___
        }

        square_body(0);
        forward_vrs(\@acc,\@r);

            $code.=<<___;
    b           .Lreduce_common
    .size p384_felem_square_reduce,.-p384_felem_square_reduce
___
    }

    {
        #
        # p384_felem_reduce
        #

        my $inp = "r4";
        my @t = map("v$_",(48..51));
        my @delta1 = map("v$_",(0..3));
        my @delta2 = map("v$_",(4..6));
        my $l56  = "v7";

        startproc("p384_felem_reduce");

        $code.=<<___;
    xxspltib    $vzero,0
___

    # Load the input

        for (my $i = 0; $i < 13; $i++) {
            $code.=<<___;
    lxv         $acc[$i],$i*16($inp)
___
        }

        $code.=<<___;
.Lreduce_common:
    addis       $tbl,r2,.Ladd\@toc\@ha
    addi        $tbl,$tbl,.Ladd\@toc\@l
___

    # Underflow avoidance

        for (my $i = 0; $i < 4; $i++) {
            $code.=<<___;
    lxv         $t[$i],$i*16($tbl)
___
        }

        $code.=<<___;
    vadduqm     $acc[0],$acc[0],$t[0]
    vadduqm     $acc[1],$acc[1],$t[1]
    vadduqm     $acc[2],$acc[2],$t[2]
    vadduqm     $acc[3],$acc[3],$t[3]
    vadduqm     $acc[4],$acc[4],$t[3]
    vadduqm     $acc[5],$acc[5],$t[3]
    vadduqm     $acc[6],$acc[6],$t[3]
___

    # [1-2]: Delta-substitutions

        for (my $i = 0; $i < 4; $i++) {
            $code.=<<___;
    lxv         $delta1[$i],${\($i+4)}*16($tbl)
___
        }

    # vsldoi instructions used as cheap rightward logical shifts

        for (my $k = 12; $k >= 7; $k--) {
            $code.=<<___;
    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$acc[$k],16-4
    xxpermr     $t[1],$acc[$k],$delta1[0]
    vadduqm     $acc[${\($k-4)}],$acc[${\($k-4)}],$t[0]
    vadduqm     $acc[${\($k-5)}],$acc[${\($k-5)}],$t[1]

    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$acc[$k],16-1
    xxpermr     $t[1],$acc[$k],$delta1[1]
    vadduqm     $acc[${\($k-5)}],$acc[${\($k-5)}],$t[0]
    vadduqm     $acc[${\($k-6)}],$acc[${\($k-6)}],$t[1]

    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$acc[$k],16-2
    xxpermr     $t[1],$acc[$k],$delta1[2]
    vsubuqm     $acc[${\($k-6)}],$acc[${\($k-6)}],$t[0]
    vsubuqm     $acc[${\($k-7)}],$acc[${\($k-7)}],$t[1]

    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$acc[$k],16-6
    xxpermr     $t[1],$acc[$k],$delta1[3]
    vadduqm     $acc[${\($k-6)}],$acc[${\($k-6)}],$t[0]
    vadduqm     $acc[${\($k-7)}],$acc[${\($k-7)}],$t[1]
___

        }

    # Preemptive Carry

        $code.=<<___;
    li          $tmp1,-1
    clrldi      $tmp1,$tmp1,64-56
    mtvsrdd     $l56,0,$tmp1

    xxspltib    $t[0],56

    vsro        $t[1],$acc[4],$t[0]
    xxland      $acc[4],$acc[4],$l56
    vadduqm     $acc[5],$acc[5],$t[1]

    vsro        $t[2],$acc[5],$t[0]
    xxland      $acc[5],$acc[5],$l56
    vadduqm     $acc[6],$acc[6],$t[2]
___

    # [3]: Delta-substitution
        $code.=<<___;
    vsldoi      $t[3],$vzero,$acc[6],16-6
    li          $tmp1,-1
    clrldi      $tmp1,$tmp1,64-48
    mtvsrdd     $t[0],0,$tmp1
    xxland      $acc[6],$acc[6],$t[0]
___

        for (my $i = 0; $i < 3; $i++) {
            $code.=<<___;
    lxv         $delta2[$i],${\($i+8)}*16($tbl)
___
        }

        $code.=<<___;
    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$t[3],16-5
    xxpermr     $t[1],$t[3],$delta2[0]
    vadduqm     $acc[3],$acc[3],$t[0]
    vadduqm     $acc[2],$acc[2],$t[1]

    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$t[3],16-2
    xxpermr     $t[1],$t[3],$delta2[1]
    vadduqm     $acc[2],$acc[2],$t[0]
    vadduqm     $acc[1],$acc[1],$t[1]

    vmr         $t[1],$vzero
    vsldoi      $t[0],$vzero,$t[3],16-3
    xxpermr     $t[1],$t[3],$delta2[2]
    vsubuqm     $acc[1],$acc[1],$t[0]
    vsubuqm     $acc[0],$acc[0],$t[1]
    vadduqm     $acc[0],$acc[0],$t[3]
___

    # Full Carry

        for (my $i = 0; $i < 6; $i++) {
            $code.=<<___;
    vsldoi      $t[1],$vzero,$acc[$i],16-7
    xxland      $acc[$i],$acc[$i],$l56
    vadduqm     $acc[${\($i+1)}],$acc[${\($i+1)}],$t[1]
___

        }

    # Write out reduced form
        for (my $i = 0; $i < 6; $i += 2) {
            $code.=<<___;
    xxpermdi    $acc[$i],$acc[${\($i+1)}],$acc[$i],0b11
    stxv        $acc[$i],$i*8($outp)
___
        }

        $code.=<<___;
    xxpermdi    $acc[6],$acc[6],$vzero,0b11
    stxsd       $acc[6],6*8($outp)

    blr

.align 4
.Ladd:
    # two124p108m76
    .octa   0x10000ffffffff0000000000000000000
    # two124m116m68
    .octa   0x0feffffffffffff00000000000000000
    # two124m92m68
    .octa   0x0fffffffeffffff00000000000000000
    # two124m68
    .octa   0x0ffffffffffffff00000000000000000
    # Delta-substitutions [1-2]
    .octa	0x00000000000000000013121110000000
    .octa	0x00000000000000000010000000000000
    .octa	0x00000000000000000011100000000000
    .octa	0x00000000000000000015141312111000
    # Delta-substitution [3]
    .octa	0x00000000000000000014131211100000
    .octa	0x00000000000000000011100000000000
    .octa	0x00000000000000000012111000000000

    .size p384_felem_reduce,.-p384_felem_reduce
___
    }

    {
        #
        # p384_felem_diff_128_64
        #

        my $outp = "r3";
        my $inp = "r4";
        my @acc = map("v$_",(35..41));
        my @t = map("v$_",(48..51));

        startproc("p384_felem_diff_128_64");

        $code.=<<___;
    xxspltib    $vzero,0
___

        for (my $i = 0; $i < 7; $i++) {
            $code.=<<___;
    lxv         $acc[$i],$i*16($outp)
___
        }

        $code.=<<___;
    addis       $tbl,r2,.Ladd_128_64\@toc\@ha
    addi        $tbl,$tbl,.Ladd_128_64\@toc\@l
___

        for (my $i = 0; $i < 4; $i++) {
            $code.=<<___;
    lxv         $t[$i],$i*16($tbl)
___
        }

        $code.=<<___;
    vadduqm     $acc[0],$acc[0],$t[0]
    vadduqm     $acc[1],$acc[1],$t[1]
    vadduqm     $acc[2],$acc[2],$t[2]
    vadduqm     $acc[3],$acc[3],$t[3]
    vadduqm     $acc[4],$acc[4],$t[3]
    vadduqm     $acc[5],$acc[5],$t[3]
    vadduqm     $acc[6],$acc[6],$t[3]
___

        for (my $i = 0; $i < 7; $i++) {
            $code.=<<___;
    ld          $tmp1,$i*8($inp)
    mtvsrdd     $t[0],0,$tmp1
    vsubuqm     $acc[$i],$acc[$i],$t[0]
___
        }

        for (my $i = 0; $i < 7; $i++) {
            $code.=<<___;
    stxv        $acc[$i],$i*16($outp)
___
        }

        $code.=<<___;

    blr

.align 4
.Ladd_128_64:
    # two64p48m16
    .octa   0x00000000000000010000ffffffff0000
    # two64m56m8
    .octa   0x0000000000000000feffffffffffff00
    # two64m32m8
    .octa   0x0000000000000000fffffffeffffff00
    # two64m8
    .octa   0x0000000000000000ffffffffffffff00

    .size p384_felem_diff_128_64,.-p384_felem_diff_128_64
___
    }

    {
        #
        # p384_felem_diff128
        #

        my $outp = "r3";
        my $inp = "r4";
        my @acc = map("v$_",(35..47));
        my @t = map("v$_",(48..51));

        startproc("p384_felem_diff128");

        $code.=<<___;
    xxspltib    $vzero,0
___

        for (my $i = 0; $i < 13; $i++) {
            $code.=<<___;
    lxv         $acc[$i],$i*16($outp)
___
        }

        $code.=<<___;
    addis       $tbl,r2,.Ladd_128\@toc\@ha
    addi        $tbl,$tbl,.Ladd_128\@toc\@l

    lxv         $t[0],0*16($tbl)
    vadduqm     $acc[0],$acc[0],$t[0]
___

        for (my $i = 1; $i < 5; $i++) {
            $code.=<<___;
    lxv         $t[${\($i-1)}],$i*16($tbl)
___
        }

        $code.=<<___;
    vadduqm     $acc[1],$acc[1],$t[0]
    vadduqm     $acc[2],$acc[2],$t[0]
    vadduqm     $acc[3],$acc[3],$t[0]
    vadduqm     $acc[4],$acc[4],$t[0]
    vadduqm     $acc[5],$acc[5],$t[0]
    vadduqm     $acc[6],$acc[6],$t[1]
    vadduqm     $acc[7],$acc[7],$t[2]
    vadduqm     $acc[8],$acc[8],$t[3]
    vadduqm     $acc[9],$acc[9],$t[0]
    vadduqm     $acc[10],$acc[10],$t[0]
    vadduqm     $acc[11],$acc[11],$t[0]
    vadduqm     $acc[12],$acc[12],$t[0]
___

        for (my $i = 0; $i < 13; $i++) {
            $code.=<<___;
    lxv         $t[${\($i%4)}],$i*16($inp)
    vsubuqm     $acc[$i],$acc[$i],$t[${\($i%4)}]
___
        }

        for (my $i = 0; $i < 13; $i++) {
            $code.=<<___;
    stxv        $acc[$i],$i*16($outp)
___
        }

        $code.=<<___;

    blr

.align 4
.Ladd_128:
    # two127
    .octa   0x80000000000000000000000000000000
    # two127m71
    .octa   0x7fffffffffffff800000000000000000
    # two127p111m79m71
    .octa   0x80007fffffff7f800000000000000000
    # two127m119m71
    .octa   0x7f7fffffffffff800000000000000000
    # two127m95m71
    .octa   0x7fffffff7fffff800000000000000000

    .size p384_felem_diff128,.-p384_felem_diff128
___
    }
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
