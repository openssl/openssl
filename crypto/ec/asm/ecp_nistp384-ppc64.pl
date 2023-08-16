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

my ($sp, $outp, $savelr, $savesp) = ("r1", "r3", "r10", "r12");

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

    $code.=<<___;

___
}

sub store_vrs($$)
{
    my ($pointer, $reg_list) = @_;

    for (my $i = 0; $i <= 12; $i++) {
        my $offset = $i * 16;
        $code.=<<___;
    stxv        $reg_list->[$i],$offset($pointer)
___
    }

    $code.=<<___;

___
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

    {
        #
        # p384_felem_mul
        #

        my ($in1p, $in2p) = ("r4", "r5");
        my @in1 = map("v$_",(44..50));
        my @in2 = map("v$_",(35..41));

        startproc("p384_felem_mul");

        $code.=<<___;
    vspltisw    $vzero,0

___

        load_vrs($in1p, \@in1);
        load_vrs($in2p, \@in2);

        $code.=<<___;
    vmsumudm    $out,$in1[0],$in2[0],$vzero
    stxv        $out,0($outp)

    xxpermdi    $t1,$in1[0],$in1[1],0b00
    xxpermdi    $t2,$in2[1],$in2[0],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    stxv        $out,16($outp)

    xxpermdi    $t2,$in2[2],$in2[1],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in1[2],$in2[0],$out
    stxv        $out,32($outp)

    xxpermdi    $t2,$in2[1],$in2[0],0b00
    xxpermdi    $t3,$in1[2],$in1[3],0b00
    xxpermdi    $t4,$in2[3],$in2[2],0b00
    vmsumudm    $out,$t1,$t4,$vzero
    vmsumudm    $out,$t3,$t2,$out
    stxv        $out,48($outp)

    xxpermdi    $t2,$in2[4],$in2[3],0b00
    xxpermdi    $t4,$in2[2],$in2[1],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    vmsumudm    $out,$in1[4],$in2[0],$out
    stxv        $out,64($outp)

    xxpermdi    $t2,$in2[5],$in2[4],0b00
    xxpermdi    $t4,$in2[3],$in2[2],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    xxpermdi    $t4,$in2[1],$in2[0],0b00
    xxpermdi    $t1,$in1[4],$in1[5],0b00
    vmsumudm    $out,$t1,$t4,$out
    stxv        $out,80($outp)

    xxpermdi    $t1,$in1[0],$in1[1],0b00
    xxpermdi    $t2,$in2[6],$in2[5],0b00
    xxpermdi    $t4,$in2[4],$in2[3],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    xxpermdi    $t2,$in2[2],$in2[1],0b00
    xxpermdi    $t1,$in1[4],$in1[5],0b00
    vmsumudm    $out,$t1,$t2,$out
    vmsumudm    $out,$in1[6],$in2[0],$out
    stxv        $out,96($outp)

    xxpermdi    $t1,$in1[1],$in1[2],0b00
    xxpermdi    $t2,$in2[6],$in2[5],0b00
    xxpermdi    $t3,$in1[3],$in1[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    xxpermdi    $t3,$in2[2],$in2[1],0b00
    xxpermdi    $t1,$in1[5],$in1[6],0b00
    vmsumudm    $out,$t1,$t3,$out
    stxv        $out,112($outp)

    xxpermdi    $t1,$in1[2],$in1[3],0b00
    xxpermdi    $t3,$in1[4],$in1[5],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$t3,$t4,$out
    vmsumudm    $out,$in1[6],$in2[2],$out
    stxv        $out,128($outp)

    xxpermdi    $t1,$in1[3],$in1[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    xxpermdi    $t1,$in1[5],$in1[6],0b00
    vmsumudm    $out,$t1,$t4,$out
    stxv        $out,144($outp)

    vmsumudm    $out,$t3,$t2,$vzero
    vmsumudm    $out,$in1[6],$in2[4],$out
    stxv        $out,160($outp)

    vmsumudm    $out,$t1,$t2,$vzero
    stxv        $out,176($outp)

    vmsumudm    $out,$in1[6],$in2[6],$vzero
    stxv        $out,192($outp)
___

        endproc("p384_felem_mul");
    }

    {
        #
        # p384_felem_square
        #

        my ($inp) = ("r4");
        my @in = map("v$_",(44..50));
        my @inx2 = map("v$_",(35..41));

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

        $code.=<<___;
    vmsumudm    $out,$in[0],$in[0],$vzero
    stxv        $out,0($outp)

    vmsumudm    $out,$in[0],$inx2[1],$vzero
    stxv        $out,16($outp)

    vmsumudm    $out,$in[0],$inx2[2],$vzero
    vmsumudm    $out,$in[1],$in[1],$out
    stxv        $out,32($outp)

    xxpermdi    $t1,$in[0],$in[1],0b00
    xxpermdi    $t2,$inx2[3],$inx2[2],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    stxv        $out,48($outp)

    xxpermdi    $t4,$inx2[4],$inx2[3],0b00
    vmsumudm    $out,$t1,$t4,$vzero
    vmsumudm    $out,$in[2],$in[2],$out
    stxv        $out,64($outp)

    xxpermdi    $t2,$inx2[5],$inx2[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in[2],$inx2[3],$out
    stxv        $out,80($outp)

    xxpermdi    $t2,$inx2[6],$inx2[5],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in[2],$inx2[4],$out
    vmsumudm    $out,$in[3],$in[3],$out
    stxv        $out,96($outp)

    xxpermdi    $t3,$in[1],$in[2],0b00
    vmsumudm    $out,$t3,$t2,$vzero
    vmsumudm    $out,$in[3],$inx2[4],$out
    stxv        $out,112($outp)

    xxpermdi    $t1,$in[2],$in[3],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    vmsumudm    $out,$in[4],$in[4],$out
    stxv        $out,128($outp)

    xxpermdi    $t1,$in[3],$in[4],0b00
    vmsumudm    $out,$t1,$t2,$vzero
    stxv        $out,144($outp)

    vmsumudm    $out,$in[4],$inx2[6],$vzero
    vmsumudm    $out,$in[5],$in[5],$out
    stxv        $out,160($outp)

    vmsumudm    $out,$in[5],$inx2[6],$vzero
    stxv        $out,176($outp)

    vmsumudm    $out,$in[6],$in[6],$vzero
    stxv        $out,192($outp)
___

        endproc("p384_felem_square");
    }
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
