#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my @regs = map("x$_",(0..31));
my @regaliases = ('zero','ra','sp','gp','tp','t0','t1','t2','s0','s1',
    map("a$_",(0..7)),
    map("s$_",(2..11)),
    map("t$_",(3..6))
);

my %reglookup;
@reglookup{@regs} = @regs;
@reglookup{@regaliases} = @regs;

# Takes a register name, possibly an alias, and converts it to a register index
# from 0 to 31
sub read_reg {
    my $reg = lc shift;
    if (!exists($reglookup{$reg})) {
        die("Unknown register ".$reg);
    }
    my $regstr = $reglookup{$reg};
    if (!($regstr =~ /^x([0-9]+)$/)) {
        die("Could not process register ".$reg);
    }
    return $1;
}

sub rv64_rev8 {
    # Encoding for rev8 rd, rs instruction on RV64
    #               XXXXXXXXXXXXX_ rs  _XXX_ rd  _XXXXXXX
    my $template = 0b011010111000_00000_101_00000_0010011;
    my $rd = read_reg shift;
    my $rs = read_reg shift;

    return ".word ".($template | ($rs << 15) | ($rd << 7));
}

sub rv64_clmul {
    # Encoding for clmul rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0000101_00000_00000_001_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;

    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub rv64_clmulh {
    # Encoding for clmulh rd, rs1, rs2 instruction on RV64
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0000101_00000_00000_011_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;

    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

################################################################################
# gcm_init_clmul_rv64i_zbb_zbc(u128 Htable[16], const u64 Xi[2])
# Initialization function for clmul-based implementation of GMULT
# This function is used in tandem with gcm_gmult_clmul_rv64i_zbb_zbc
################################################################################
{
my ($Haddr,$Xi,$TEMP) = ("a0","a1","a2");

$code .= <<___;
.text
.balign 16
.globl gcm_init_clmul_rv64i_zbb_zbc
.type gcm_init_clmul_rv64i_zbb_zbc,\@function
# Initialize clmul-based implementation of galois field multiplication routine.
# gcm_init_clmul_rv64i_zbb_zbc(ctx->Htable, ctx->H.u)
gcm_init_clmul_rv64i_zbb_zbc:
    # argument 0 = ctx->Htable (store H here)
    # argument 1 = H.u[] (2x 64-bit words) [H_high64, H_low64]

    # Simply store [H_high64, H_low64] for later
    ld      $TEMP,0($Xi)
    sd      $TEMP,0($Haddr)
    ld      $TEMP,8($Xi)
    sd      $TEMP,8($Haddr)

    ret

___

}

################################################################################
# gcm_gmult_clmul_rv64i_zbb_zbc(u64 Xi[2], const u128 Htable[16])
# Compute GMULT (X*H mod f) using the Zbc (clmul) and Zbb (basic bit manip)
# extensions, and the Modified Barrett Reduction technique
################################################################################
{
my ($Xi,$Haddr,$A1,$A0,$B1,$B0,$C1,$C0,$D1,$D0,$E1,$E0,$TEMP,$TEMP2,$qp_low) =
 ("a0","a1","a2","a3","a4","a5","a6","a7","t0","t1","t2","t3","t4","t5","t6");

$code .= <<___;
.text
.balign 16
.globl gcm_gmult_clmul_rv64i_zbb_zbc
.type gcm_gmult_clmul_rv64i_zbb_zbc,\@function
# static void gcm_gmult_clmul_rv64i_zbb_zbc(u64 Xi[2], const u128 Htable[16])
# Computes product of X*H mod f
gcm_gmult_clmul_rv64i_zbb_zbc:

    # Load X and H (H is saved previously in gcm_init_clmul_rv64i_zbb_zbc)
    ld              $A1,0($Xi)
    ld              $A0,8($Xi)

    ld              $B1,0($Haddr)
    ld              $B0,8($Haddr)

    li              $qp_low,0xe100000000000000

    # Perform Katratsuba Multiplication to generate a 255-bit intermediate
    # A = [A1:A0]
    # B = [B1:B0]
    # Let:
    # [C1:C0] = A1*B1
    # [D1:D0] = A0*B0
    # [E1:E0] = (A0+A1)*(B0+B1)
    # Then:
    # A*B = [C1:C0+C1+D1+E1:D1+C0+D0+E0:D0]

    @{[rv64_rev8    $A1, $A1]}
    @{[rv64_clmul   $C0,$A1,$B1]}
    @{[rv64_clmulh  $C1,$A1,$B1]}

    @{[rv64_rev8    $A0,$A0]}
    @{[rv64_clmul   $D0,$A0,$B0]}
    @{[rv64_clmulh  $D1,$A0,$B0]}

    xor             $TEMP,$A0,$A1
    xor             $TEMP2,$B0,$B1

    @{[rv64_clmul   $E0,$TEMP,$TEMP2]}
    @{[rv64_clmulh  $E1,$TEMP,$TEMP2]}

    # 0th term is just C1

    # Construct term 1 in E1 (E1 only appears in dword 1)
    xor             $E1,$E1,$D1
    xor             $E1,$E1,$C1
    xor             $E1,$E1,$C0

    # Term 1 is E1

    # Construct term 2 in E0 (E0 only appears in dword 2)
    xor             $E0,$E0,$D0
    xor             $E0,$E0,$C0
    xor             $E0,$E0,$D1

    # Term 2 is E0

    # final term is just D0

    # X*H is now stored in [C1,E1,E0,D0]

    # Left-justify
    slli            $C1,$C1,1
    # Or in the high bit of E1
    srli            $TEMP,$E1,63
    or              $C1,$C1,$TEMP

    slli            $E1,$E1,1
    # Or in the high bit of E0
    srli            $TEMP2,$E0,63
    or              $E1,$E1,$TEMP2

    slli            $E0,$E0,1
    # Or in the high bit of D0
    srli            $TEMP,$D0,63
    or              $E0,$E0,$TEMP

    slli            $D0,$D0,1

    # Barrett Reduction
    # c = [E0, D0]
    # We want the top 128 bits of the result of c*f
    # We'll get this by computing the low-half (most significant 128 bits in
    # the reflected domain) of clmul(c,fs)<<1 first, then
    # xor in c to complete the calculation

    # AA = [AA1:AA0] = [E0,D0] = c
    # BB = [BB1:BB0] = [qp_low,0]
    # [CC1:CC0] = AA1*BB1
    # [DD1:DD0] = AA0*BB0
    # [EE1:EE0] = (AA0+AA1)*(BB0+BB1)
    # Then:
    # AA*BB = [CC1:CC0+CC1+DD1+EE1:DD1+CC0+DD0+EE0:DD0]
    # We only need CC0,DD1,DD0,EE0 to compute the low 128 bits of c * qp_low
___

my ($CC0,$EE0,$AA1,$AA0,$BB1) = ($A0,$B1,$E0,$D0,$qp_low);

$code .= <<___;

    @{[rv64_clmul   $CC0,$AA1,$BB1]}
    #clmul          DD0,AA0,BB0     # BB0 is 0, so DD0 = 0
    #clmulh         DD1,AA0,BB0     # BB0 is 0, so DD1 = 0
    xor             $TEMP,$AA0,$AA1
    #xor            TEMP2,BB0,BB1   # TEMP2 = BB1 = qp_low
    @{[rv64_clmul   $EE0,$TEMP,$BB1]}

    # Result is [N/A:N/A:DD1+CC0+DD0+EE0:DD0]
    # Simplifying: [CC0+EE0:0]
    xor             $TEMP2,$CC0,$EE0
    # Shift left by 1 to correct for bit reflection
    slli            $TEMP2,$TEMP2,1

    # xor into c = [E0,D0]
    # Note that only E0 is affected
    xor             $E0,$E0,$TEMP2

    # Now, q = [E0,D0]

    # The final step is to compute clmul(q,[qp_low:0])<<1
    # The leftmost 128 bits are the reduced result.
    # Once again, we use Karatsuba multiplication, but many of the terms
    # simplify or cancel out.
    # AA = [AA1:AA0] = [E0,D0] = c
    # BB = [BB1:BB0] = [qp_low,0]
    # [CC1:CC0] = AA1*BB1
    # [DD1:DD0] = AA0*BB0
    # [EE1:EE0] = (AA0+AA1)*(BB0+BB1)
    # Then:
    # AA*BB = [CC1:CC0+CC1+DD1+EE1:DD1+CC0+DD0+EE0:DD0]
    # We need CC1,CC0,DD0,DD1,EE1,EE0 to compute the leftmost 128 bits of AA*BB

___

my ($AA1,$AA0,$BB1,$CC1,$CC0,$EE1,$EE0) = ($E0,$D0,$qp_low,$A0,$A1,$C0,$B0);

$code .= <<___;

    @{[rv64_clmul   $CC0,$AA1,$BB1]}
    @{[rv64_clmulh  $CC1,$AA1,$BB1]}

    #clmul          DD0,AA0,BB0   # BB0 = 0 so DD0 = 0
    #clmulh         DD1,AA0,BB0   # BB0 = 0 so DD1 = 0

    xor             $TEMP,$AA0,$AA1
    #xor            TEMP2,BB0,BB1 # BB0 = 0 to TEMP2 == BB1 == qp_low

    @{[rv64_clmul   $EE0,$TEMP,$BB1]}
    @{[rv64_clmulh  $EE1,$TEMP,$BB1]}

    # Need the DD1+CC0+DD0+EE0 term to shift its leftmost bit into the
    # intermediate result.
    # This is just CC0+EE0, store it in TEMP
    xor             $TEMP,$CC0,$EE0

    # Result is [CC1:CC0+CC1+EE1:(a single bit)]<<1
    # Combine into [CC1:CC0]
    xor             $CC0,$CC0,$CC1
    xor             $CC0,$CC0,$EE1

    # Shift 128-bit quantity, xor in [C1,E1] and store
    slli            $CC1,$CC1,1
    srli            $TEMP2,$CC0,63
    or              $CC1,$CC1,$TEMP2
    # xor in C1
    xor             $CC1,$CC1,$C1
    @{[rv64_rev8    $CC1,$CC1]}

    slli            $CC0,$CC0,1
    srli            $TEMP,$TEMP,63
    or              $CC0,$CC0,$TEMP
    # xor in E1
    xor             $CC0,$CC0,$E1
    @{[rv64_rev8    $CC0,$CC0]}
    sd              $CC1,0(a0)
    sd              $CC0,8(a0)

    ret
___

}

print $code;

close STDOUT or die "error closing STDOUT: $!";
