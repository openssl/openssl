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
# util for encoding scalar crypto extension instructions
################################################################################

my @regs = map("x$_",(0..31));
my %reglookup;
@reglookup{@regs} = @regs;

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

sub sm4ed {
    # Encoding for sm4ed rd, rs1, rs2, bs instruction
    #                bs_XXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b00_11000_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    my $bs = shift;

    return ".word ".($template | ($bs << 30) | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub sm4ks {
    # Encoding for sm4ks rd, rs1, rs2, bs instruction
    #                bs_XXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b00_11010_00000_00000_000_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;
    my $bs = shift;

    return ".word ".($template | ($bs << 30) | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

sub rv_pack {
    # Encoding for sm4ks rd, rs1, rs2, bs instruction
    #                XXXXXXX_ rs2 _ rs1 _XXX_ rd  _XXXXXXX
    my $template = 0b0000100_00000_00000_100_00000_0110011;
    my $rd = read_reg shift;
    my $rs1 = read_reg shift;
    my $rs2 = read_reg shift;

    return ".word ".($template | ($rs2 << 20) | ($rs1 << 15) | ($rd << 7));
}

################################################################################
# Register assignment for rvi_zksed_cipher
################################################################################

# Registers to hold SM4 state (called s0-s3 or y0-y3 elsewhere)
# avoid callee-saved reg because this asm is for both rv32/rv64
my ($Q0,$Q1,$Q2,$Q3) = use_regs(6..7,28..29);

# Function arguments (x10-x12 are a0-a2 in the ABI)
# Input block pointer, output block pointer, key pointer
my ($INP,$OUTP,$KEYP) = use_regs(10..12);

# Key
my ($T0,$T1,$T2,$T3) = use_regs(13..16);

# Temp
my ($T) = use_regs(17);

# Intermediate XOR
my ($XOR) = use_regs(31);

# Loop counter
my ($loopcntr) = use_regs(30);

################################################################################
# Utility for rvi_zksed_cipher
################################################################################

sub input {
    my $ret = '';
$ret .= <<___;
    lw      $Q0,0($INP)
    lw      $Q1,4($INP)
    lw      $Q2,8($INP)
    lw      $Q3,12($INP)
___
    return $ret;
}

sub key {
    my $ret = '';
$ret .= <<___;
    lw      $T0,0($KEYP)
    lw      $T1,4($KEYP)
    lw      $T2,8($KEYP)
    lw      $T3,12($KEYP)
___
    return $ret;
}

sub output {
    my $ret = '';
$ret .= <<___;
    sw      $Q3,0($OUTP)
    sw      $Q2,4($OUTP)
    sw      $Q1,8($OUTP)
    sw      $Q0,12($OUTP)
___
    return $ret;
}

# 4 byte
sub sm4ed4 {
    my $rd = shift;
    my $rs1 = shift;
    my $rs2 = shift;
    my $ret = '';
$ret .= <<___;
    @{[sm4ed   $rd,$rs1,$rs2,0]}
    @{[sm4ed   $rd,$rs1,$rs2,1]}
    @{[sm4ed   $rd,$rs1,$rs2,2]}
    @{[sm4ed   $rd,$rs1,$rs2,3]}
___
    return $ret;
}

# 4 round
# input Q0,Q1,Q2,Q3 (with X0-X3) T0,T1,T2,T3 (with K0-K3)
# output Q0,Q1,Q2,Q3 (with X4-X7)
# use XOR and T reg
sub sm4ed4r {
    my $ret = '';
$ret .= <<___;
    # round 0
    xor     $XOR,$Q2,$Q3 # X2 ^ X3
    xor     $T,$Q1,$T0 # X1 ^ K0
    xor     $T,$T,$XOR # X1 ^ X2 ^ X3 ^ K0
    @{[sm4ed4 $Q0,$Q0,$T]} # X0 ^ F(T) = X4

    # round 1
    # reuse XOR
    xor     $T,$Q0,$T1 # X4 ^ K1
    xor     $T,$T,$XOR # X2 ^ X3 ^ X4 ^ K1
    @{[sm4ed4 $Q1,$Q1,$T]} # X1 ^ F(T) = X5

    # round 2
    xor     $XOR,$Q0,$Q1 # X4 ^ X5
    xor     $T,$Q3,$T2 # X3 ^ K2
    xor     $T,$T,$XOR # X3 ^ X4 ^ X5 ^ K2
    @{[sm4ed4 $Q2,$Q2,$T]} # X2 ^ F(T) = X6

    # round 3
    # reuse XOR
    xor     $T,$Q2,$T3 # X6 ^ K3
    xor     $T,$T,$XOR # X4 ^ X5 ^ X6 ^ K3
    @{[sm4ed4 $Q3,$Q3,$T]} # X3 ^ F(T) = X7
___
    return $ret;
}

# 8x4 round
sub sm4ed32r {
    my $ret = '';
    my $i = 0;
    while ($i < 8) {
$ret .= <<___;
    @{[key]}
    @{[sm4ed4r]}
    add     $KEYP,$KEYP,16
___
        $i++;
    }
    return $ret;
}

################################################################################
# void rvi_zksed_cipher(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
################################################################################
my $code .= <<___;
.text
.balign 16
.globl rvi_zksed_cipher
.type   rvi_zksed_cipher,\@function
rvi_zksed_cipher:
___
$code .= save_regs();
$code .= <<___;
    @{[input]}
    @{[sm4ed32r]}
    @{[output]}
    # Pop registers and return
___
$code .= load_regs();
$code .= <<___;
    ret
___

clear_regs();

################################################################################
# Register assignment for rvi_zksed_set_[en/de]crypt_key
################################################################################

# Function arguments (x10-x11 are a0-a1 in the ABI)
# userkey, key pointer
my ($UKEY,$KEYP) = use_regs(10..11);

# Registers to hold userkey (called s0-s3 or y0-y3 elsewhere)
# avoid callee-saved reg because this asm is for both rv32/rv64
my ($Q0,$Q1,$Q2,$Q3) = use_regs(6..7,28..29);

# CKP
my ($CKP) = use_regs(31);

# Content in CK
my ($T0,$T1,$T2,$T3) = use_regs(13..16);

# Temporary
my ($T) = use_regs(17);

my ($XOR) = use_regs(30);

################################################################################
# Utility for rvi_zksed_set_[en/de]crypt_key
################################################################################

sub ukey {
    my $ret = '';
$ret .= <<___;
    lw      $Q0,0($INP)
    lw      $Q1,4($INP)
    lw      $Q2,8($INP)
    lw      $Q3,12($INP)
    li      $T,0xC6BAB1A3
    xor     $Q0,$Q0,$T
    li      $T,0x5033AA56
    xor     $Q1,$Q1,$T
    li      $T,0x97917D67
    xor     $Q2,$Q2,$T
    li      $T,0xDC2270B2
    xor     $Q3,$Q3,$T
___
    return $ret;
}

sub ckey {
    my $ret = '';
$ret .= <<___;
    lw      $T0,0($CKP)
    lw      $T1,4($CKP)
    lw      $T2,8($CKP)
    lw      $T3,12($CKP)
___
    return $ret;
}

sub keypenc {
    my $ret = '';
$ret .= <<___;
    sw      $Q0,0($OUTP)
    sw      $Q1,4($OUTP)
    sw      $Q2,8($OUTP)
    sw      $Q3,12($OUTP)
___
    return $ret;
}

sub keypdec {
    my $ret = '';
$ret .= <<___;
    sw      $Q3,0($OUTP)
    sw      $Q2,4($OUTP)
    sw      $Q1,8($OUTP)
    sw      $Q0,12($OUTP)
___
    return $ret;
}

# 4 byte
sub sm4ks4 {
    my $rd = shift;
    my $rs1 = shift;
    my $rs2 = shift;
    my $ret = '';
$ret .= <<___;
    @{[sm4ks $rd,$rs1,$rs2,0]}
    @{[sm4ks $rd,$rs1,$rs2,1]}
    @{[sm4ks $rd,$rs1,$rs2,2]}
    @{[sm4ks $rd,$rs1,$rs2,3]}
___
    return $ret;
}

# 4 round
# input Q0,Q1,Q2,Q3 (with X0-X3) T0,T1,T2,T3 (with K0-K3)
# output Q0,Q1,Q2,Q3 (with X4-X7)
# use XOR and T reg
sub sm4ks4r {
    my $ret = '';
$ret .= <<___;
    # round 0
    xor     $XOR,$Q2,$Q3 # X2 ^ X3
    xor     $T,$Q1,$T0 # X1 ^ K0
    xor     $T,$T,$XOR # X1 ^ X2 ^ X3 ^ K0
    @{[sm4ks4 $Q0,$Q0,$T]} # X0 ^ F(T) = X4

    # round 1
    # reuse XOR
    xor     $T,$Q0,$T1 # X4 ^ K1
    xor     $T,$T,$XOR # X2 ^ X3 ^ X4 ^ K1
    @{[sm4ks4 $Q1,$Q1,$T]} # X1 ^ F(T) = X5

    # round 2
    xor     $XOR,$Q0,$Q1 # X4 ^ X5
    xor     $T,$Q3,$T2 # X3 ^ K2
    xor     $T,$T,$XOR # X3 ^ X4 ^ X5 ^ K2
    @{[sm4ks4 $Q2,$Q2,$T]} # X2 ^ F(T) = X6

    # round 3
    # reuse XOR
    xor     $T,$Q2,$T3 # X6 ^ K3
    xor     $T,$T,$XOR # X4 ^ X5 ^ X6 ^ K3
    @{[sm4ks4 $Q3,$Q3,$T]} # X3 ^ F(T) = X7
___
    return $ret;
}

# 8x4 round
sub sm4ks32r {
    my $ret = '';
    my $i = 0;
    my $save = shift;
    while ($i < 8) {
$ret .= <<___;
    @{[ckey]}
    @{[sm4ks4r]}
    add     $CKP,$CKP,16
    $save
___
        $i++;
    }
    return $ret;
}

sub sm4ksenc {
    my $save = <<___;
    @{[keypenc]}
    add     $KEYP,$KEYP,16
___
    return sm4ks32r($save);
}

sub sm4ksdec {
    my $save = <<___;
    @{[keypdec]}
    add     $KEYP,$KEYP,-16
___
    return sm4ks32r($save);
}

################################################################################
# void rvi_zksed_set_encrypt_key(const uint8_t *key, SM4_KEY *ks)
################################################################################

$code .= <<___;
.text
.balign 16
.globl rvi_zksed_set_encrypt_key
.type   rvi_zksed_set_encrypt_key,\@function
rvi_zksed_set_encrypt_key:
___
$code .= save_regs();
$code .= <<___;
    @{[ukey]}
    la  $CKP,CK
    @{[sm4ksenc]}
___
$code .= load_regs();
$code .= <<___;
    ret
___

################################################################################
# void rvi_zksed_set_decrypt_key(const uint8_t *key, SM4_KEY *ks)
################################################################################

$code .= <<___;
.text
.balign 16
.globl rvi_zksed_set_decrypt_key
.type   rvi_zksed_set_decrypt_key,\@function
rvi_zksed_set_decrypt_key:
___
$code .= save_regs();
$code .= <<___;
    @{[ukey]}
    la  $CKP,CK
    add $KEYP,$KEYP,112 # 128 - 16
    @{[sm4ksdec]}
___
$code .= load_regs();
$code .= <<___;
    ret
___

$code .= <<___;
.section .rodata
.p2align    12
.type   CK,\@object
CK:
.word 0x150E0700U, 0x312A231CU, 0x4D463F38U, 0x69625B54U
.word 0x857E7770U, 0xA19A938CU, 0xBDB6AFA8U, 0xD9D2CBC4U
.word 0xF5EEE7E0U, 0x110A03FCU, 0x2D261F18U, 0x49423B34U
.word 0x655E5750U, 0x817A736CU, 0x9D968F88U, 0xB9B2ABA4U
.word 0xD5CEC7C0U, 0xF1EAE3DCU, 0x0D06FFF8U, 0x29221B14U
.word 0x453E3730U, 0x615A534CU, 0x7D766F68U, 0x99928B84U
.word 0xB5AEA7A0U, 0xD1CAC3BCU, 0xEDE6DFD8U, 0x0902FBF4U
.word 0x251E1710U, 0x413A332CU, 0x5D564F48U, 0x79726B64U
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
