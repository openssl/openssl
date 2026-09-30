#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# FIPS 203, Algorithms 9 and 10. Each 16-bit lane contains a canonical
# coefficient.
# Shoup multiplication uses floor(zeta * 2^16 / q) to avoid division:
#   t = a*zeta - floor(a*zeta_shoup/2^16)*q, 0 <= t < 2*q.
# Both products in the subtraction need only their low 16 bits. The forward
# transform keeps bounded intermediate values and reduces its final output to
# [0,q), as required by ml_kem.c.

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;
$win64 = ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);
$arg = $win64 ? "%rcx" : "%rdi";

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
$dir = $1;
($xlate = "${dir}x86_64-xlate.pl" and -f $xlate)
  or ($xlate = "${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate)
  or die "can't locate x86_64-xlate.pl";

$avx2 = 0;
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
    =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
    $avx2 = ($1 >= 2.22);
}
if (!$avx2 && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/)
    && `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/) {
    $avx2 = ($1 >= 2.10);
}
if (!$avx2 && `$ENV{CC} -v 2>&1`
    =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2 >= 3.3);
}

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
  or die "can't call $xlate: $!";
*STDOUT = *OUT;

sub bitreverse7 {
    my $v = shift;
    my $r = 0;
    for (1..7) {
        $r = ($r << 1) | ($v & 1);
        $v >>= 1;
    }
    return $r;
}

sub powmod {
    my ($base, $exponent, $modulus) = @_;
    my $result = 1;
    while ($exponent) {
        $result = ($result * $base) % $modulus if $exponent & 1;
        $base = ($base * $base) % $modulus;
        $exponent >>= 1;
    }
    return $result;
}

my @roots = map { powmod(17, bitreverse7($_), 3329) } 0..127;
my @shoup = map { int($_ * 65536 / 3329) } @roots;
my @invroots = (0, map { 3329 - $roots[128 - $_] } 1..127);
my @invshoup = map { int($_ * 65536 / 3329) } @invroots;
my @modroots = map { powmod(17, 2 * bitreverse7($_) + 1, 3329) } 0..127;
my @modshoup = map { int($_ * 65536 / 3329) } @modroots;
my $code = "";
# Windows preserves XMM6..XMM15, so clear only the volatile vector registers.
# Unix has no nonvolatile vector registers and can clear all of them at once.
my $clear_vectors = $win64
    ? (join('', map { "    vpxor %ymm$_, %ymm$_, %ymm$_\n" } 0..5)
       . "    vzeroupper\n")
    : "    vzeroall\n";

if ($avx2) {
    $code .= <<___;
.text
.extern OPENSSL_ia32cap_P
.globl mlkem_avx2_capable
.type mlkem_avx2_capable,\@abi-omnipotent
.align 16
mlkem_avx2_capable:
    mov OPENSSL_ia32cap_P+8(%rip), %eax
    and \$32, %eax
    ret
.Lmlkem_avx2_capable_end:
.size mlkem_avx2_capable, .-mlkem_avx2_capable

.globl mlkem_ntt_avx2
.type mlkem_ntt_avx2,\@abi-omnipotent
.align 32
mlkem_ntt_avx2:
    vpbroadcastw .Lmlkem_q(%rip), %ymm4
___

    # Multiply the peer by its twiddle factor, then do the butterfly. After
    # stage n, each output is below (2*n+3)*q, hence below 15*q at the end.
    # Shoup multiplication remains valid for every 16-bit input.
    # Input: ymm0 = even, ymm1 = peer, ymm2 = zeta, ymm3 = Shoup factor.
    # Output: ymm5 = new even, ymm0 = new peer. Only ymm0..ymm5 are used,
    # so no vector register save is needed on either x86-64 ABI.
    my $butterfly = <<'___';
    vpmulhuw %ymm3, %ymm1, %ymm5
    vpmullw %ymm2, %ymm1, %ymm1
    vpmullw %ymm4, %ymm5, %ymm5
    vpsubw %ymm5, %ymm1, %ymm1
    vpaddw %ymm1, %ymm0, %ymm5
    vpsubw %ymm1, %ymm0, %ymm0
    vpaddw %ymm4, %ymm0, %ymm0
    vpaddw %ymm4, %ymm0, %ymm0
___

    # Stages with distances 128, 64, 32, and 16. One vector holds
    # 16 independent butterflies; each group has a single twiddle factor.
    for my $stage (0..3) {
        my $distance = 128 >> $stage;
        my $base = 1 << $stage;
        for my $group (0..($base - 1)) {
            my $index = $base + $group;
            for (my $pos = 0; $pos < $distance; $pos += 16) {
                my $left = 2 * ($group * 2 * $distance + $pos);
                my $right = $left + 2 * $distance;
                $code .= "    vmovdqu $left($arg), %ymm0\n";
                $code .= "    vmovdqu $right($arg), %ymm1\n";
                $code .= "    vpbroadcastw .Lmlkem_root_$index(%rip), %ymm2\n";
                $code .= "    vpbroadcastw .Lmlkem_root_$index+2(%rip), %ymm3\n";
                $code .= $butterfly;
                $code .= "    vmovdqu %ymm5, $left($arg)\n";
                $code .= "    vmovdqu %ymm0, $right($arg)\n";
            }
        }
    }

    # For the final three stages, butterflies stay inside a 16-word
    # vector. Shuffle the partners together, and then blend the results.
    for my $distance (8, 4, 2) {
        $code .= <<___;
    lea .Lmlkem_zetas_$distance(%rip), %rdx
    xor %eax, %eax
.Lmlkem_stage_$distance:
    vmovdqu ($arg,%rax), %ymm0
___
        if ($distance == 8) {
            $code .= <<'___';
    vperm2i128 $0x11, %ymm0, %ymm0, %ymm1
    vperm2i128 $0x00, %ymm0, %ymm0, %ymm0
___
        } elsif ($distance == 4) {
            $code .= <<'___';
    vpshufd $0xee, %ymm0, %ymm1
    vpshufd $0x44, %ymm0, %ymm0
___
        } else {
            $code .= <<'___';
    vpshufd $0xf5, %ymm0, %ymm1
    vpshufd $0xa0, %ymm0, %ymm0
___
        }
        $code .= <<___;
    vmovdqu (%rdx,%rax), %ymm2
    vmovdqu 512(%rdx,%rax), %ymm3
___
        $code .= $butterfly;
        if ($distance == 8) {
            $code .= <<'___';
    vperm2i128 $0x20, %ymm0, %ymm5, %ymm1
___
        } else {
            my $mask = $distance == 4 ? '0xcc' : '0xaa';
            $code .= "    vpblendd \$$mask, %ymm0, %ymm5, %ymm1\n";
        }
        $code .= <<___;
    vmovdqu %ymm1, ($arg,%rax)
    add \$32, %rax
    cmp \$512, %rax
    jb .Lmlkem_stage_$distance
___
    }

    $code .= <<___;
    vpbroadcastw .Lmlkem_barrett(%rip), %ymm2
    xor %eax, %eax
.Lmlkem_forward_reduce:
    vmovdqu ($arg,%rax), %ymm0
    vpmulhuw %ymm2, %ymm0, %ymm1
    vpmullw %ymm4, %ymm1, %ymm1
    vpsubw %ymm1, %ymm0, %ymm0
    vpsubw %ymm4, %ymm0, %ymm1
    vpminuw %ymm1, %ymm0, %ymm0
    vmovdqu %ymm0, ($arg,%rax)
    add \$32, %rax
    cmp \$512, %rax
    jb .Lmlkem_forward_reduce
    xor $arg, $arg
___
    $code .= $clear_vectors;
    $code .= <<'___';
    ret
.Lmlkem_ntt_avx2_end:
.size mlkem_ntt_avx2, .-mlkem_ntt_avx2
___

    # The inverse uses the negated forward roots in reverse order. This
    # lets its peer butterfly multiply (even - odd), matching ml_kem.c.
    # The sum doubles the input bound, while Shoup multiplication keeps the
    # peer below 2*q. Unix keeps the bound in ymm6. Windows reads it from a
    # constant table to avoid saving a nonvolatile vector register.
    my $inverse_butterfly = <<'___';
    vpaddw %ymm1, %ymm0, %ymm5
    vpsubw %ymm1, %ymm0, %ymm0
    vpaddw %ymm6, %ymm0, %ymm0
    vpmulhuw %ymm3, %ymm0, %ymm1
    vpmullw %ymm2, %ymm0, %ymm0
    vpmullw %ymm4, %ymm1, %ymm1
    vpsubw %ymm1, %ymm0, %ymm0
___

    $code .= <<___;
.globl mlkem_inverse_ntt_avx2
.type mlkem_inverse_ntt_avx2,\@abi-omnipotent
.align 32
mlkem_inverse_ntt_avx2:
    vpbroadcastw .Lmlkem_q(%rip), %ymm4
___

    for my $distance (2, 4, 8) {
        my $bound = $distance == 2 ? 'q'
                  : $distance == 4 ? 'twice_q' : 'four_q';
        $code .= "    vpbroadcastw .Lmlkem_$bound(%rip), %ymm6\n"
            unless $win64;
        $code .= <<___;
    lea .Lmlkem_invzetas_$distance(%rip), %rdx
    xor %eax, %eax
.Lmlkem_invstage_$distance:
    vmovdqu ($arg,%rax), %ymm0
___
        if ($distance == 8) {
            $code .= <<'___';
    vperm2i128 $0x11, %ymm0, %ymm0, %ymm1
    vperm2i128 $0x00, %ymm0, %ymm0, %ymm0
___
        } elsif ($distance == 4) {
            $code .= <<'___';
    vpshufd $0xee, %ymm0, %ymm1
    vpshufd $0x44, %ymm0, %ymm0
___
        } else {
            $code .= <<'___';
    vpshufd $0xf5, %ymm0, %ymm1
    vpshufd $0xa0, %ymm0, %ymm0
___
        }
        $code .= <<___;
    vmovdqu (%rdx,%rax), %ymm2
    vmovdqu 512(%rdx,%rax), %ymm3
___
        my $ops = $inverse_butterfly;
        $ops =~ s/%ymm6/.Lmlkem_vec_$bound(%rip)/g if $win64;
        $code .= $ops;
        if ($distance == 8) {
            $code .= <<'___';
    vperm2i128 $0x20, %ymm0, %ymm5, %ymm1
___
        } else {
            my $mask = $distance == 4 ? '0xcc' : '0xaa';
            $code .= "    vpblendd \$$mask, %ymm0, %ymm5, %ymm1\n";
        }
        $code .= <<___;
    vmovdqu %ymm1, ($arg,%rax)
    add \$32, %rax
    cmp \$512, %rax
    jb .Lmlkem_invstage_$distance
___
    }

    # After three stages every value is below 8*q. Restore canonical
    # coefficients before the last four stages so their sums fit 16 bits.
    $code .= <<___;
    vpbroadcastw .Lmlkem_barrett(%rip), %ymm2
    xor %eax, %eax
.Lmlkem_inverse_reduce:
    vmovdqu ($arg,%rax), %ymm0
    vpmulhuw %ymm2, %ymm0, %ymm1
    vpmullw %ymm4, %ymm1, %ymm1
    vpsubw %ymm1, %ymm0, %ymm0
    vpsubw %ymm4, %ymm0, %ymm1
    vpminuw %ymm1, %ymm0, %ymm0
    vmovdqu %ymm0, ($arg,%rax)
    add \$32, %rax
    cmp \$512, %rax
    jb .Lmlkem_inverse_reduce
___

    for my $stage (0..3) {
        my $distance = 16 << $stage;
        my $base = 129 - 256 / $distance;
        my $bound = ('q', 'twice_q', 'four_q', 'eight_q')[$stage];
        $code .= "    vpbroadcastw .Lmlkem_$bound(%rip), %ymm6\n"
            unless $win64;
        for my $group (0..(128 / $distance - 1)) {
            my $index = $base + $group;
            for (my $pos = 0; $pos < $distance; $pos += 16) {
                my $left = 2 * ($group * 2 * $distance + $pos);
                my $right = $left + 2 * $distance;
                $code .= "    vmovdqu $left($arg), %ymm0\n";
                $code .= "    vmovdqu $right($arg), %ymm1\n";
                $code .= "    vpbroadcastw .Lmlkem_invroot_$index(%rip), %ymm2\n";
                $code .= "    vpbroadcastw .Lmlkem_invroot_$index+2(%rip), %ymm3\n";
                my $ops = $inverse_butterfly;
                $ops =~ s/%ymm6/.Lmlkem_vec_$bound(%rip)/g if $win64;
                $code .= $ops;
                $code .= "    vmovdqu %ymm5, $left($arg)\n";
                $code .= "    vmovdqu %ymm0, $right($arg)\n";
            }
        }
    }

    # Multiply every output coefficient by 128^-1 mod q.
    $code .= <<___;
    vpbroadcastw .Lmlkem_inverse_degree(%rip), %ymm2
    vpbroadcastw .Lmlkem_inverse_degree+2(%rip), %ymm3
    xor %eax, %eax
.Lmlkem_inverse_scale:
    vmovdqu ($arg,%rax), %ymm0
    vpmulhuw %ymm3, %ymm0, %ymm1
    vpmullw %ymm2, %ymm0, %ymm0
    vpmullw %ymm4, %ymm1, %ymm1
    vpsubw %ymm1, %ymm0, %ymm0
    vpsubw %ymm4, %ymm0, %ymm1
    vpminuw %ymm1, %ymm0, %ymm0
    vmovdqu %ymm0, ($arg,%rax)
    add \$32, %rax
    cmp \$512, %rax
    jb .Lmlkem_inverse_scale
    xor $arg, $arg
___
    $code .= $clear_vectors;
    $code .= <<'___';
    ret
.Lmlkem_inverse_ntt_avx2_end:
.size mlkem_inverse_ntt_avx2, .-mlkem_inverse_ntt_avx2
___

    # Each AVX2 vector holds eight quadratic NTT elements. Shoup-scale the
    # odd left coefficients by their known roots, then VPMADDWD computes the
    # two 32-bit coefficients. Four products still fit a signed 32-bit lane.
    # Montgomery reduction followed by multiplication by R mod q gives the
    # canonical, unscaled result required at the C function boundary.
    # The transpose-add form strides over the matrix and adds the existing
    # error polynomial in the output, without copying a matrix column.
    for my $variant (['mlkem_basemul_acc_avx2', 0],
                     ['mlkem_basemul_acc_transpose_add_avx2', 1]) {
        my ($name, $transpose_add) = @$variant;
        $code .= ".globl $name\n.type $name,\@abi-omnipotent\n.align 32\n$name:\n";
        if ($win64) {
            $code .= "    mov %rcx, %r10\n    mov %rdx, %r11\n";
        } else {
            $code .= "    mov %rdi, %r10\n    mov %rsi, %r11\n"
                . "    mov %rdx, %r8\n";
            $code .= "    mov %ecx, %r9d\n";
        }
        $code .= "    mov %r9d, %r9d\n    shl \$9, %r9\n"
            if $transpose_add;
        my $rank_load = $transpose_add
            ? "    mov %r9, %rcx\n    shr \$9, %rcx"
            : "    mov %r9d, %ecx";
        my $lhs_advance = $transpose_add
            ? "    add %r9, %r11" : "    add \$512, %r11";
        my $rewind = $transpose_add
            ? "    mov %r9, %rcx\n    shr \$9, %rcx\n"
              . "    imulq %r9, %rcx\n    sub %rcx, %r11\n"
              . "    sub %r9, %r8"
            : "    mov %r9d, %ecx\n    shl \$9, %rcx\n"
              . "    sub %rcx, %r11\n    sub %rcx, %r8";
        my $body = <<'___';
    lea .Lmlkem_modroots(%rip), %rdx
    xor %eax, %eax
.L@NAME@_block:
    vpxor %ymm0, %ymm0, %ymm0
    vpxor %ymm1, %ymm1, %ymm1
@RANK_LOAD@
.L@NAME@_rank:
    vmovdqu (%r11,%rax), %ymm2
    vmovdqu (%r8,%rax), %ymm3
    vmovdqu (%rdx,%rax,2), %ymm4
    vpmullw %ymm2, %ymm4, %ymm4
    vmovdqu 32(%rdx,%rax,2), %ymm5
    vpmulhuw %ymm2, %ymm5, %ymm5
    vpmullw .Lmlkem_vec_q(%rip), %ymm5, %ymm5
    vpsubw %ymm5, %ymm4, %ymm4
    vpmaddwd %ymm3, %ymm4, %ymm5
    vpaddd %ymm5, %ymm0, %ymm0
    vpshufb .Lmlkem_swap_pairs(%rip), %ymm3, %ymm5
    vpmaddwd %ymm5, %ymm2, %ymm5
    vpaddd %ymm5, %ymm1, %ymm1
@LHS_ADVANCE@
    add $512, %r8
    dec %ecx
    jnz .L@NAME@_rank
@REWIND@

    vpmulld .Lmlkem_vec_qinv(%rip), %ymm0, %ymm4
    vpand .Lmlkem_vec_mask16(%rip), %ymm4, %ymm4
    vpmulld .Lmlkem_vec_q32(%rip), %ymm4, %ymm4
    vpaddd %ymm4, %ymm0, %ymm0
    vpsrld $16, %ymm0, %ymm0
    vpsubd .Lmlkem_vec_q32(%rip), %ymm0, %ymm4
    vpminud %ymm4, %ymm0, %ymm0

    vpmulld .Lmlkem_vec_qinv(%rip), %ymm1, %ymm4
    vpand .Lmlkem_vec_mask16(%rip), %ymm4, %ymm4
    vpmulld .Lmlkem_vec_q32(%rip), %ymm4, %ymm4
    vpaddd %ymm4, %ymm1, %ymm1
    vpsrld $16, %ymm1, %ymm1
    vpsubd .Lmlkem_vec_q32(%rip), %ymm1, %ymm4
    vpminud %ymm4, %ymm1, %ymm1

    vpackusdw %ymm1, %ymm0, %ymm2
    vpshufb .Lmlkem_interleave(%rip), %ymm2, %ymm2
    vpmulhuw .Lmlkem_vec_r_shoup(%rip), %ymm2, %ymm3
    vpmullw .Lmlkem_vec_r(%rip), %ymm2, %ymm2
    vpmullw .Lmlkem_vec_q(%rip), %ymm3, %ymm3
    vpsubw %ymm3, %ymm2, %ymm2
    vpsubw .Lmlkem_vec_q(%rip), %ymm2, %ymm3
    vpminuw %ymm3, %ymm2, %ymm2
___
        $body =~ s/\@NAME\@/$name/g;
        $body =~ s/\@RANK_LOAD\@/$rank_load/;
        $body =~ s/\@LHS_ADVANCE\@/$lhs_advance/;
        $body =~ s/\@REWIND\@/$rewind/;
        $code .= $body;
        if ($transpose_add) {
            $code .= <<'___';
    vmovdqu (%r10,%rax), %ymm3
    vpaddw %ymm3, %ymm2, %ymm2
    vpsubw .Lmlkem_vec_q(%rip), %ymm2, %ymm3
    vpminuw %ymm3, %ymm2, %ymm2
___
        }
        $code .= <<'___';
    vmovdqu %ymm2, (%r10,%rax)
    add $32, %rax
    cmp $512, %rax
___
        $code .= "    jb .L" . $name . "_block\n";
        $code .= <<'___';
    xor %r8, %r8
    xor %r10, %r10
    xor %r11, %r11
    xor %rdx, %rdx
___
        $code .= "    xor %rdi, %rdi\n    xor %rsi, %rsi\n" unless $win64;
        $code .= $clear_vectors;
        $code .= "    ret\n.L" . $name . "_end:\n.size $name, .-$name\n";
    }

    $code .= <<'___';

.section .rodata
.align 32
.Lmlkem_q:
    .long 3329
.Lmlkem_twice_q:
    .long 6658
.Lmlkem_four_q:
    .long 13316
.Lmlkem_eight_q:
    .long 26632
.Lmlkem_barrett:
    .long 19
___
    if ($win64) {
        for my $bound (['q', 3329], ['twice_q', 6658],
                       ['four_q', 13316], ['eight_q', 26632]) {
            my $pair = $bound->[1] + ($bound->[1] << 16);
            $code .= ".align 32\n.Lmlkem_vec_" . $bound->[0] . ":\n";
            $code .= "    .long " . join(", ", ($pair) x 8) . "\n";
        }
    }
    $code .= ".Lmlkem_inverse_degree:\n";
    $code .= "    .long " . (3303 + (int(3303 * 65536 / 3329) << 16)) . "\n";
    for my $index (1..15) {
        $code .= ".Lmlkem_root_$index:\n";
        $code .= "    .long " . ($roots[$index] + ($shoup[$index] << 16)) . "\n";
    }
    for my $index (113..127) {
        $code .= ".Lmlkem_invroot_$index:\n";
        $code .= "    .long " . ($invroots[$index]
            + ($invshoup[$index] << 16)) . "\n";
    }
    for my $distance (8, 4, 2) {
        my $base = 128 / $distance;
        $code .= ".align 32\n.Lmlkem_zetas_$distance:\n";
        for my $factor (0, 1) {
            for my $chunk (0..15) {
                my @words;
                for my $lane (0..15) {
                    my $index = $base + $chunk * (16 / (2 * $distance))
                        + int($lane / (2 * $distance));
                    push @words, $factor ? $shoup[$index] : $roots[$index];
                }
                my @packed = map { $words[2 * $_]
                    + ($words[2 * $_ + 1] << 16) } 0..7;
                $code .= "    .long " . join(", ", @packed) . "\n";
            }
        }
    }
    for my $distance (2, 4, 8) {
        my $base = $distance == 2 ? 1 : $distance == 4 ? 65 : 97;
        $code .= ".align 32\n.Lmlkem_invzetas_$distance:\n";
        for my $factor (0, 1) {
            for my $chunk (0..15) {
                my @words;
                for my $lane (0..15) {
                    my $index = $base + $chunk * (16 / (2 * $distance))
                        + int($lane / (2 * $distance));
                    push @words, $factor ? $invshoup[$index]
                        : $invroots[$index];
                }
                my @packed = map { $words[2 * $_]
                    + ($words[2 * $_ + 1] << 16) } 0..7;
                $code .= "    .long " . join(", ", @packed) . "\n";
            }
        }
    }
    my $packed16 = sub {
        my ($value) = @_;
        return $value + ($value << 16);
    };
    if (!$win64) {
        $code .= ".align 32\n.Lmlkem_vec_q:\n    .long "
            . join(", ", ($packed16->(3329)) x 8) . "\n";
    }
    $code .= ".align 32\n.Lmlkem_vec_r:\n    .long "
        . join(", ", ($packed16->(65536 % 3329)) x 8) . "\n";
    $code .= ".Lmlkem_vec_r_shoup:\n    .long "
        . join(", ", ($packed16->(int((65536 % 3329) * 65536 / 3329))) x 8) . "\n";
    for my $constant (['q32', 3329], ['qinv', 3327],
                      ['mask16', 65535]) {
        $code .= ".Lmlkem_vec_" . $constant->[0] . ":\n    .long "
            . join(", ", ($constant->[1]) x 8) . "\n";
    }
    my @swap = (2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13);
    my @interleave = (0,1,8,9,2,3,10,11,4,5,12,13,6,7,14,15);
    $code .= ".Lmlkem_swap_pairs:\n    .byte "
        . join(", ", (@swap, @swap)) . "\n";
    $code .= ".Lmlkem_interleave:\n    .byte "
        . join(", ", (@interleave, @interleave)) . "\n";
    $code .= ".align 32\n.Lmlkem_modroots:\n";
    for my $block (0..15) {
        for my $kind (0, 1) {
            my @words = map { ($_ & 1)
                ? ($kind ? $modshoup[8 * $block + ($_ >> 1)]
                         : $modroots[8 * $block + ($_ >> 1)])
                : ($kind ? 0 : 1) } 0..15;
            my @packed = map { $words[2 * $_]
                + ($words[2 * $_ + 1] << 16) } 0..7;
            $code .= "    .long " . join(", ", @packed) . "\n";
        }
    }
} else {
    $code .= <<'___';
.text
.globl mlkem_avx2_capable
.type mlkem_avx2_capable,@abi-omnipotent
mlkem_avx2_capable:
    xor %eax, %eax
    ret
.Lmlkem_avx2_capable_end:
.size mlkem_avx2_capable, .-mlkem_avx2_capable
.globl mlkem_ntt_avx2
.type mlkem_ntt_avx2,@abi-omnipotent
mlkem_ntt_avx2:
    .byte 0x0f,0x0b
.Lmlkem_ntt_avx2_end:
.size mlkem_ntt_avx2, .-mlkem_ntt_avx2
.globl mlkem_inverse_ntt_avx2
.type mlkem_inverse_ntt_avx2,@abi-omnipotent
mlkem_inverse_ntt_avx2:
    .byte 0x0f,0x0b
.Lmlkem_inverse_ntt_avx2_end:
.size mlkem_inverse_ntt_avx2, .-mlkem_inverse_ntt_avx2
.globl mlkem_basemul_acc_avx2
.type mlkem_basemul_acc_avx2,@abi-omnipotent
mlkem_basemul_acc_avx2:
    .byte 0x0f,0x0b
.Lmlkem_basemul_acc_avx2_end:
.size mlkem_basemul_acc_avx2, .-mlkem_basemul_acc_avx2
.globl mlkem_basemul_acc_transpose_add_avx2
.type mlkem_basemul_acc_transpose_add_avx2,@abi-omnipotent
mlkem_basemul_acc_transpose_add_avx2:
    .byte 0x0f,0x0b
.Lmlkem_basemul_acc_transpose_add_avx2_end:
.size mlkem_basemul_acc_transpose_add_avx2, .-mlkem_basemul_acc_transpose_add_avx2
___
}

if ($win64) {
    # Win64 uses only volatile GPRs and YMM0..YMM5. The preserved halves of
    # XMM6..XMM15 and all nonvolatile GPRs stay unchanged, so no register
    # save/restore is needed. These leaf functions leave RSP unchanged;
    # zero-code UNWIND_INFO describes each one.
    $code .= <<'___';
.section .pdata
.align 4
    .rva mlkem_avx2_capable
    .rva .Lmlkem_avx2_capable_end
    .rva .Lmlkem_avx2_capable_unwind
    .rva mlkem_ntt_avx2
    .rva .Lmlkem_ntt_avx2_end
    .rva .Lmlkem_ntt_avx2_unwind
    .rva mlkem_inverse_ntt_avx2
    .rva .Lmlkem_inverse_ntt_avx2_end
    .rva .Lmlkem_inverse_ntt_avx2_unwind
    .rva mlkem_basemul_acc_avx2
    .rva .Lmlkem_basemul_acc_avx2_end
    .rva .Lmlkem_basemul_acc_avx2_unwind
    .rva mlkem_basemul_acc_transpose_add_avx2
    .rva .Lmlkem_basemul_acc_transpose_add_avx2_end
    .rva .Lmlkem_basemul_acc_transpose_add_avx2_unwind

.section .xdata
.align 4
.Lmlkem_avx2_capable_unwind:
    .byte 1,0,0,0
.Lmlkem_ntt_avx2_unwind:
    .byte 1,0,0,0
.Lmlkem_inverse_ntt_avx2_unwind:
    .byte 1,0,0,0
.Lmlkem_basemul_acc_avx2_unwind:
    .byte 1,0,0,0
.Lmlkem_basemul_acc_transpose_add_avx2_unwind:
    .byte 1,0,0,0
___
}

print $code;
close STDOUT or die "error closing STDOUT: $!";
