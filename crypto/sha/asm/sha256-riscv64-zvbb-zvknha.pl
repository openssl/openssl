#! /usr/bin/env perl
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Christoph Müllner <christoph.muellner@vrull.eu>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V vector ('V') with VLEN >= 128
# - Vector Bit-manipulation used in Cryptography ('Zvbb')
# - Vector SHA-2 Secure Hash ('Zvknha')

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

my ($V0, $V10, $V11, $V12, $V13, $V14, $V15, $V16, $V17) = ("v0", "v10", "v11", "v12", "v13", "v14","v15", "v16", "v17");
my ($V26, $V27) = ("v26", "v27");

my $K256 = "K256";

# Function arguments
my ($H, $INP, $LEN, $KT, $STRIDE) = ("a0", "a1", "a2", "a3", "t3");

################################################################################
# void sha256_block_data_order_zvbb_zvknha(void *c, const void *p, size_t len)
$code .= <<___;
.p2align 2
.globl sha256_block_data_order_zvbb_zvknha
.type   sha256_block_data_order_zvbb_zvknha,\@function
sha256_block_data_order_zvbb_zvknha:
    @{[vsetivli__x0_4_e32_m1_tu_mu]}

    # H is stored as {a,b,c,d},{e,f,g,h}, but we need {f,e,b,a},{h,g,d,c}
    # We achieve this by reading with a negative stride followed by
    # element sliding.
    li $STRIDE, -4
    addi $H, $H, 12
    @{[vlse32_v $V16, $H, $STRIDE]} # {d,c,b,a}
    addi $H, $H, 16
    @{[vlse32_v $V17, $H, $STRIDE]} # {h,g,f,e}
    # Keep H advanced by 12
    addi $H, $H, -16

    @{[vmv_v_v $V27, $V16]} # {d,c,b,a}
    @{[vslidedown_vi $V26, $V16, 2]} # {b,a,0,0}
    @{[vslidedown_vi $V16, $V17, 2]} # {f,e,0,0}
    @{[vslideup_vi $V16, $V26, 2]} # {f,e,b,a}
    @{[vslideup_vi $V17, $V27, 2]} # {h,g,d,c}

    # Keep the old state as we need it later: H' = H+{a',b',c',...,h'}.
    @{[vmv_v_v $V26, $V16]}
    @{[vmv_v_v $V27, $V17]}

L_round_loop:
    la $KT, $K256 # Load round constants K256

    # Load the 512-bits of the message block in v10-v13 and perform
    # an endian swap on each 4 bytes element.
    @{[vle32_v $V10, $INP]}
    @{[vrev8_v $V10, $V10]}
    add $INP, $INP, 16
    @{[vle32_v $V11, $INP]}
    @{[vrev8_v $V11, $V11]}
    add $INP, $INP, 16
    @{[vle32_v $V12, $INP]}
    @{[vrev8_v $V12, $V12]}
    add $INP, $INP, 16
    @{[vle32_v $V13, $INP]}
    @{[vrev8_v $V13, $V13]}
    add $INP, $INP, 16

    # Decrement length by 1
    add $LEN, $LEN, -1

    # Set v0 up for the vmerge that replaces the first word (idx==0)
    @{[vid_v $V0]}
    @{[vmseq_vi $V0, $V0, 0x0]}    # v0.mask[i] = (i == 0 ? 1 : 0)

    # Quad-round 0 (+0, Wt from oldest to newest in v10->v11->v12->v13)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V10]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V12, $V11, $V0]}
    @{[vsha2ms_vv $V10, $V14, $V13]}  # Generate W[19:16]

    # Quad-round 1 (+1, v11->v12->v13->v10)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V11]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V13, $V12, $V0]}
    @{[vsha2ms_vv $V11, $V14, $V10]}  # Generate W[23:20]

    # Quad-round 2 (+2, v12->v13->v10->v11)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V12]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V10, $V13, $V0]}
    @{[vsha2ms_vv $V12, $V14, $V11]}  # Generate W[27:24]

    # Quad-round 3 (+3, v13->v10->v11->v12)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V13]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V11, $V10, $V0]}
    @{[vsha2ms_vv $V13, $V14, $V12]}  # Generate W[31:28]

    # Quad-round 4 (+0, v10->v11->v12->v13)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V10]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V12, $V11, $V0]}
    @{[vsha2ms_vv $V10, $V14, $V13]}  # Generate W[35:32]

    # Quad-round 5 (+1, v11->v12->v13->v10)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V11]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V13, $V12, $V0]}
    @{[vsha2ms_vv $V11, $V14, $V10]}  # Generate W[39:36]

    # Quad-round 6 (+2, v12->v13->v10->v11)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V12]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V10, $V13, $V0]}
    @{[vsha2ms_vv $V12, $V14, $V11]}  # Generate W[43:40]

    # Quad-round 7 (+3, v13->v10->v11->v12)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V13]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V11, $V10, $V0]}
    @{[vsha2ms_vv $V13, $V14, $V12]}  # Generate W[47:44]

    # Quad-round 8 (+0, v10->v11->v12->v13)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V10]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V12, $V11, $V0]}
    @{[vsha2ms_vv $V10, $V14, $V13]}  # Generate W[51:48]

    # Quad-round 9 (+1, v11->v12->v13->v10)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V11]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V13, $V12, $V0]}
    @{[vsha2ms_vv $V11, $V14, $V10]}  # Generate W[55:52]

    # Quad-round 10 (+2, v12->v13->v10->v11)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V12]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V10, $V13, $V0]}
    @{[vsha2ms_vv $V12, $V14, $V11]}  # Generate W[59:56]

    # Quad-round 11 (+3, v13->v10->v11->v12)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V13]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}
    @{[vmerge_vvm $V14, $V11, $V10, $V0]}
    @{[vsha2ms_vv $V13, $V14, $V12]}  # Generate W[63:60]

    # Quad-round 12 (+0, v10->v11->v12->v13)
    # Note that we stop generating new message schedule words (Wt, v10-13)
    # as we already generated all the words we end up consuming (i.e., W[63:60]).
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V10]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}

    # Quad-round 13 (+1, v11->v12->v13->v10)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V11]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}

    # Quad-round 14 (+2, v12->v13->v10->v11)
    @{[vle32_v $V15, $KT]}
    addi $KT, $KT, 16
    @{[vadd_vv $V14, $V15, $V12]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}

    # Quad-round 15 (+3, v13->v10->v11->v12)
    @{[vle32_v $V15, $KT]}
    # No kt increment needed.
    @{[vadd_vv $V14, $V15, $V13]}
    @{[vsha2cl_vv $V17, $V16, $V14]}
    @{[vsha2ch_vv $V16, $V17, $V14]}

    # H' = H+{a',b',c',...,h'}
    @{[vadd_vv $V16, $V26, $V16]}
    @{[vadd_vv $V17, $V27, $V17]}
    @{[vmv_v_v $V26, $V16]}
    @{[vmv_v_v $V27, $V17]}
    bnez $LEN, L_round_loop

    # v26 = v16 = {f,e,b,a}
    # v27 = v17 = {h,g,d,c}
    # Let's do the opposit transformation like on entry.

    @{[vslideup_vi $V17, $V16, 2]} # {h,g,f,e}

    @{[vslidedown_vi $V16, $V27, 2]} # {d,c,0,0}
    @{[vslidedown_vi $V26, $V26, 2]} # {b,a,0,0}
    @{[vslideup_vi $V16, $V26, 2]} # {d,c,b,a}

    # H is already advanced by 12
    @{[vsse32_v $V16, $H, $STRIDE]} # {a,b,c,d}
    addi $H, $H, 16
    @{[vsse32_v $V17, $H, $STRIDE]} # {e,f,g,h}

    ret
.size sha256_block_data_order_zvbb_zvknha,.-sha256_block_data_order_zvbb_zvknha

.p2align 2
.type $K256,\@object
$K256:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
.size $K256,.-$K256
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
