# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# Applied condition:
# POLY1305_BLOCK_SIZE was supposed to be 16

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

___

    my $Camellia_SBOX = "Camellia_SBOX";
    my $SIGMA = "SIGMA";

    my $s0 = "x18";
    my $s1 = "x19";
    my $s2 = "x20";
    my $s3 = "x21";

    # Camellia_EncryptBlock_Rounds or Camellia_DecryptBlock_Rounds
    my $SBOX = "x22";
    my $TBL_0 = "x5";
    my $TBL_1 = "x6";
    my $TBL_2 = "x7";
    my $CONST = "x8";
    my $TBL_3 = "x9";

    # Camellia_Ekeygen
    my $pSIGMA = "x22";
    my $K_0 = "x5";
    my $K_1 = "x6";
    my $K_2 = "x7";
    my $K_3 = "x9";

    my $grandRounds = "x10";
    my $pInput = "x11";
    my $pKTBL = "x12";
    my $pOutput = "x13";

    my $T_0 = "x14";
    my $T_1 = "x15";
    my $T_2 = "x16";
    my $T_3 = "x17";

    my $p0 = "x25";
    my $p1 = "x26";
    my $p2 = "x27";
    my $p3 = "x28";

    my $K_ADD2 = "addi                    $pKTBL, $pKTBL, 8";  # k += 2;
    my $K_SUB2 = "addi                    $pKTBL, $pKTBL, -8"; # k -= 2;
    my $S_ADD2 = "addi                    $pSIGMA, $pSIGMA, 8";
    my $K_NOP = "";


sub Camellia_Feistel {
    my ($S_0, $S_1, $S_2, $S_3, $ptr, $ptr_PM) = @_;

    my $KEY_0 = "x23";
    my $KEY_1 = "x24";

    my $tmp1 = "x29";
    my $tmp2 = "x30";
    my $tmp3 = "x31";

    $code.= <<___

    # Camellia_Feistel($S_0, $S_1, $S_2, $S_3, k);
    lwu                     $KEY_0, 0($ptr)            # (_key)[0]
    lwu                     $KEY_1, 4($ptr)            # (_key)[1]

    xor                     $T_0, $S_0, $KEY_0        # t0
    xor                     $T_1, $S_1, $KEY_1        # t1

    srli                    $p1, $T_0, 8
    srli                    $p2, $T_0, 16
    srli                    $p3, $T_0, 24
    and                     $p0, $T_0, $CONST
    and                     $p1, $p1, $CONST
    and                     $p2, $p2, $CONST
    and                     $p3, $p3, $CONST

    slli                    $p0, $p0, 2               # offset_t0_0_4Byte
    slli                    $p1, $p1, 2               # offset_t0_1_4Byte
    slli                    $p2, $p2, 2               # offset_t0_2_4Byte
    slli                    $p3, $p3, 2               # offset_t0_3_4Byte

    add                     $p0, $TBL_1, $p0          # SBOX4_4404 TBL_1
    add                     $p1, $TBL_3, $p1          # SBOX3_3033 TBL_3
    add                     $p2, $TBL_2, $p2          # SBOX2_0222 TBL_2
    add                     $p3, $TBL_0, $p3          # SBOX1_1110 TBL_0

    lwu                     $T_3, 0($p0)
    lwu                     $tmp1, 0($p1)
    lwu                     $tmp2, 0($p2)
    lwu                     $tmp3, 0($p3)

    xor                     $T_3, $T_3, $tmp1
    xor                     $T_3, $T_3, $tmp2
    xor                     $T_3, $T_3, $tmp3

    srli                    $p1, $T_1, 8
    srli                    $p2, $T_1, 16
    srli                    $p3, $T_1, 24
    and                     $p0, $T_1, $CONST
    and                     $p1, $p1, $CONST
    and                     $p2, $p2, $CONST
    and                     $p3, $p3, $CONST

    slli                    $p0, $p0, 2                # offset_t0_4Byte
    slli                    $p1, $p1, 2                # offset_t1_4Byte
    slli                    $p2, $p2, 2                # offset_t2_4Byte
    slli                    $p3, $p3, 2                # offset_t3_4Byte

    add                     $p0, $TBL_0, $p0           # SBOX1_1110 TBL_0
    add                     $p1, $TBL_1, $p1           # SBOX4_4404 TBL_1
    add                     $p2, $TBL_3, $p2           # SBOX3_3033 TBL_3
    add                     $p3, $TBL_2, $p3           # SBOX2_0222 TBL_2

    lwu                     $T_2, 0($p0)
    lwu                     $tmp1, 0($p1)
    lwu                     $tmp2, 0($p2)
    lwu                     $tmp3, 0($p3)

    xor                     $T_2, $T_3, $T_2
    xor                     $T_2, $T_2, $tmp1
    xor                     $T_2, $T_2, $tmp2
    xor                     $T_2, $T_2, $tmp3

    $ptr_PM
    roriw                   $T_3, $T_3, 8               # _t3  = RightRotate(_t3,8);
    xor                     $S_3, $S_3, $T_3            # _s3 ^= _t3;
    xor                     $S_2, $S_2, $T_2            # _s2 ^= _t2;
    xor                     $S_3, $S_3, $T_2            # _s3 ^= _t2;

___

}




$code.=<<___;

#/**
# *
# * int Camellia_Ekeygen(
# *      int keyBitLength,
# *      const u8 *rawKey,
# *      KEY_TABLE_TYPE k,
# *
#**/

.text
.p2align 3
.globl Camellia_Ekeygen
.type Camellia_Ekeygen,\@function
Camellia_Ekeygen:

    # Save all callee-saved registers
    addi                    sp, sp, -96
    sd                      s0, 0(sp)
    sd                      s1, 8(sp)
    sd                      s2, 16(sp)
    sd                      s3, 24(sp)
    sd                      s4, 32(sp)
    sd                      s5, 40(sp)
    sd                      s6, 48(sp)
    sd                      s7, 56(sp)
    sd                      s8, 64(sp)
    sd                      s9, 72(sp)
    sd                      s10, 80(sp)
    sd                      s11, 88(sp)

    lwu                     $K_0, 0(x11)
    lwu                     $K_1, 4(x11)
    lwu                     $K_2, 8(x11)
    lwu                     $K_3, 12(x11)

    rev8                    $K_0, $K_0
    rev8                    $K_1, $K_1
    rev8                    $K_2, $K_2
    rev8                    $K_3, $K_3

    srli                    $K_0, $K_0, 32
    srli                    $K_1, $K_1, 32
    srli                    $K_2, $K_2, 32
    srli                    $K_3, $K_3, 32

    li                      $CONST, 128
    sw                      $K_0, 0(x12)
    sw                      $K_1, 4(x12)
    sw                      $K_2, 8(x12)
    sw                      $K_3, 12(x12)

    mv                      $s0, $K_0
    mv                      $s1, $K_1
    mv                      $s2, $K_2
    mv                      $s3, $K_3

    _kBLen_NEQ128_0BR:

    beq                     x10, $CONST, _kBLen_NEQ128_0BRND

    lwu                     $s0, 16(x11)
    lwu                     $s1, 20(x11)
    lwu                     $s2, 24(x11)
    lwu                     $s3, 28(x11)

    rev8                    $s0, $s0
    rev8                    $s1, $s1
    rev8                    $s2, $s2
    rev8                    $s3, $s3

    li                      $CONST, 192
    srli                    $s0, $s0, 32
    srli                    $s1, $s1, 32
    srli                    $s2, $s2, 32
    srli                    $s3, $s3, 32

    bne                     x10, $CONST, _kBLen_NEQ192_0BR

    not                     $s2, $s0
    not                     $s3, $s1

    _kBLen_NEQ192_0BR:

    sw                      $s0, 32(x12)
    sw                      $s1, 36(x12)
    sw                      $s2, 40(x12)
    sw                      $s3, 44(x12)

    li                      $CONST, 128          # prepare CONST of Feistel
    xor                     $s0, $K_0, $s0       # s0
    xor                     $s1, $K_1, $s1       # s1
    xor                     $s2, $K_2, $s2       # s2
    xor                     $s3, $K_3, $s3       # s3

    _kBLen_NEQ128_0BRND:


    # prepare for Feistel
    la                      $SBOX, $Camellia_SBOX # Load constants Camellia_SBOX
    li                      $CONST, 256*4

    mv                      $TBL_0, $SBOX             # TBL_0
    add                     $TBL_1, $CONST, $SBOX     # TBL_1
    la                      $pSIGMA, $SIGMA
    add                     $TBL_2, $CONST, $TBL_1    # TBL_2
    add                     $TBL_3, $CONST, $TBL_2    # TBL_3

    li                      $CONST, 255
___

    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pSIGMA", "$S_ADD2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pSIGMA", "$S_ADD2");}

$code.=<<___;
    lwu                     $T_0, 0(x12)
    lwu                     $T_1, 4(x12)
    lwu                     $T_2, 8(x12)
    lwu                     $T_3, 12(x12)

    xor                     $s0, $T_0, $s0       # s0
    xor                     $s1, $T_1, $s1       # s1
    xor                     $s2, $T_2, $s2       # s2
    xor                     $s3, $T_3, $s3       # s3

___

    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pSIGMA", "$S_ADD2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pSIGMA", "$S_ADD2");}

$code.=<<___;

    li                      $CONST, 128
    bne                     x10, $CONST, _kBLen_NEQ128_1BR

    # /* Fill the keyTable. Requires many block rotations. */
    _kBLen_EQ128_1BR:

    # /* KA */
    sw                      $s0, 4*4(x12)
    sw                      $s1, 5*4(x12)
    sw                      $s2, 6*4(x12)
    sw                      $s3, 7*4(x12)

    addi                    $CONST, x0, -1
    srli                    $CONST, $CONST, 32

    and                     $s0, $s0, $CONST
    and                     $s1, $s1, $CONST
    and                     $s2, $s2, $CONST
    and                     $s3, $s3, $CONST

    slli                    $T_0, $s0, 32
    slli                    $T_1, $s1, 32
    slli                    $T_2, $s2, 32
    slli                    $T_3, $s3, 32

    or                      $T_0, $T_0, $s1    # s0 | s1
    or                      $T_1, $T_1, $s2    # s1 | s2
    or                      $T_2, $T_2, $s3    # s2 | s3
    or                      $T_3, $T_3, $s0    # s3 | s0

    srli                    $p0, $T_0, 17
    srli                    $p1, $T_1, 17
    srli                    $p2, $T_2, 17
    srli                    $p3, $T_3, 17

    sw                      $p0, 12*4(x12)
    sw                      $p1, 13*4(x12)
    sw                      $p2, 14*4(x12)
    sw                      $p3, 15*4(x12)

    srli                    $p0, $T_0, 2
    srli                    $p1, $T_1, 2
    srli                    $p2, $T_2, 2
    srli                    $p3, $T_3, 2
    srli                    $s0, $T_1, 19
    srli                    $s1, $T_2, 19

    sw                      $p0, 16*4(x12)
    sw                      $p1, 17*4(x12)
    sw                      $p2, 18*4(x12)
    sw                      $p3, 19*4(x12)
    sw                      $s0, 24*4(x12)
    sw                      $s1, 25*4(x12)

    srli                    $p0, $T_1, 4
    srli                    $p1, $T_2, 4
    srli                    $p2, $T_3, 4
    srli                    $p3, $T_0, 4

    sw                      $p0, 28*4(x12)
    sw                      $p1, 29*4(x12)
    sw                      $p2, 30*4(x12)
    sw                      $p3, 31*4(x12)

    srli                    $p0, $T_2, 2
    srli                    $p1, $T_3, 2
    srli                    $p2, $T_0, 2
    srli                    $p3, $T_1, 2

    sw                      $p0, 40*4(x12)
    sw                      $p1, 41*4(x12)
    sw                      $p2, 42*4(x12)
    sw                      $p3, 43*4(x12)

    lwu                     $s0, 0(x12)
    lwu                     $s1, 4(x12)
    lwu                     $s2, 2*4(x12)
    lwu                     $s3, 3*4(x12)

    srli                    $p0, $T_3, 17
    srli                    $p1, $T_0, 17
    srli                    $p2, $T_1, 17
    srli                    $p3, $T_2, 17

    sw                      $p0, 48*4(x12)
    sw                      $p1, 49*4(x12)
    sw                      $p2, 50*4(x12)
    sw                      $p3, 51*4(x12)

    # /* KL */
    and                     $s0, $s0, $CONST
    and                     $s1, $s1, $CONST
    and                     $s2, $s2, $CONST
    and                     $s3, $s3, $CONST

    slli                    $T_0, $s0, 32
    slli                    $T_1, $s1, 32
    slli                    $T_2, $s2, 32
    slli                    $T_3, $s3, 32

    or                      $T_0, $T_0, $s1     # s0 | s1
    or                      $T_1, $T_1, $s2     # s1 | s2
    or                      $T_2, $T_2, $s3     # s2 | s3
    or                      $T_3, $T_3, $s0     # s3 | s0

    srli                    $p0, $T_0, 17
    srli                    $p1, $T_1, 17
    srli                    $p2, $T_2, 17
    srli                    $p3, $T_3, 17

    sw                      $p0, 8*4(x12)
    sw                      $p1, 9*4(x12)
    sw                      $p2, 10*4(x12)
    sw                      $p3, 11*4(x12)

    srli                    $p0, $T_1, 19
    srli                    $p1, $T_2, 19
    srli                    $p2, $T_3, 19
    srli                    $p3, $T_0, 19
    srli                    $s2, $T_3, 4
    srli                    $s3, $T_0, 4

    sw                      $p0, 20*4(x12)
    sw                      $p1, 21*4(x12)
    sw                      $p2, 22*4(x12)
    sw                      $p3, 23*4(x12)
    sw                      $s2, 26*4(x12)
    sw                      $s3, 27*4(x12)

    srli                    $p0, $T_2, 19
    srli                    $p1, $T_3, 19
    srli                    $p2, $T_0, 19
    srli                    $p3, $T_1, 19

    sw                      $p0, 32*4(x12)
    sw                      $p1, 33*4(x12)
    sw                      $p2, 34*4(x12)
    sw                      $p3, 35*4(x12)

    srli                    $p0, $T_2, 2
    srli                    $p1, $T_3, 2
    srli                    $p2, $T_0, 2
    srli                    $p3, $T_1, 2

    sw                      $p0, 36*4(x12)
    sw                      $p1, 37*4(x12)
    sw                      $p2, 38*4(x12)
    sw                      $p3, 39*4(x12)

    srli                    $p0, $T_3, 17
    srli                    $p1, $T_0, 17
    srli                    $p2, $T_1, 17
    srli                    $p3, $T_2, 17

    sw                      $p0, 44*4(x12)
    sw                      $p1, 45*4(x12)
    sw                      $p2, 46*4(x12)
    sw                      $p3, 47*4(x12)

    li                      x10, 3              # return 3
    j                       _kBLen_NEQ128_1BRND


    _kBLen_NEQ128_1BR:

    lwu                     $p0, 8*4(x12)
    lwu                     $p1, 9*4(x12)
    lwu                     $p2, 10*4(x12)
    lwu                     $p3, 11*4(x12)

    sw                      $s0, 12*4(x12)
    sw                      $s1, 13*4(x12)
    sw                      $s2, 14*4(x12)
    sw                      $s3, 15*4(x12)

    xor                     $s0, $p0, $s0       # s0
    xor                     $s1, $p1, $s1       # s1
    xor                     $s2, $p2, $s2       # s2
    xor                     $s3, $p3, $s3       # s3


    # prepare for Feistel
    la                      $SBOX, $Camellia_SBOX # Load constants Camellia_SBOX
    li                      $CONST, 256*4

    mv                      $TBL_0, $SBOX             # TBL_0
    add                     $TBL_1, $CONST, $SBOX     # TBL_1
    la                      $pSIGMA, $SIGMA
    add                     $TBL_2, $CONST, $TBL_1    # TBL_2
    add                     $TBL_3, $CONST, $TBL_2    # TBL_3
    addi                    $pSIGMA, $pSIGMA, 32      # TBL_3

    li                      $CONST, 255
___

    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pSIGMA", "$S_ADD2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pSIGMA", "$K_NOP");}

$code.=<<___;

    sw                      $s0, 4*4(x12)
    sw                      $s1, 5*4(x12)
    sw                      $s2, 6*4(x12)
    sw                      $s3, 7*4(x12)

    addi                    $CONST, x0, -1
    srli                    $CONST, $CONST, 32

    and                     $s0, $s0, $CONST
    and                     $s1, $s1, $CONST
    and                     $s2, $s2, $CONST
    and                     $s3, $s3, $CONST

    slli                    $T_0, $s0, 32
    slli                    $T_1, $s1, 32
    slli                    $T_2, $s2, 32
    slli                    $T_3, $s3, 32

    or                      $T_0, $T_0, $s1    # s0 | s1
    or                      $T_1, $T_1, $s2    # s1 | s2
    or                      $T_2, $T_2, $s3    # s2 | s3
    or                      $T_3, $T_3, $s0    # s3 | s0

    srli                    $p0, $T_0, 2
    srli                    $p1, $T_1, 2
    srli                    $p2, $T_2, 2
    srli                    $p3, $T_3, 2

    sw                      $p0, 20*4(x12)
    sw                      $p1, 21*4(x12)
    sw                      $p2, 22*4(x12)
    sw                      $p3, 23*4(x12)

    srli                    $p0, $T_1, 4
    srli                    $p1, $T_2, 4
    srli                    $p2, $T_3, 4
    srli                    $p3, $T_0, 4

    sw                      $p0, 40*4(x12)
    sw                      $p1, 41*4(x12)
    sw                      $p2, 42*4(x12)
    sw                      $p3, 43*4(x12)

    lwu                     $s0, 8*4(x12)
    lwu                     $s1, 9*4(x12)
    lwu                     $s2, 10*4(x12)
    lwu                     $s3, 11*4(x12)

    srli                    $p0, $T_3, 17
    srli                    $p1, $T_0, 17
    srli                    $p2, $T_1, 17
    srli                    $p3, $T_2, 17

    sw                      $p0, 64*4(x12)
    sw                      $p1, 65*4(x12)
    sw                      $p2, 66*4(x12)
    sw                      $p3, 67*4(x12)

    # s0 = k[8], s1 = k[9], s2 = k[10], s3 = k[11];
    slli                    $T_0, $s0, 32
    slli                    $T_1, $s1, 32
    slli                    $T_2, $s2, 32
    slli                    $T_3, $s3, 32

    or                      $T_0, $T_0, $s1    # s0 | s1
    or                      $T_1, $T_1, $s2    # s1 | s2
    or                      $T_2, $T_2, $s3    # s2 | s3
    or                      $T_3, $T_3, $s0    # s3 | s0

    srli                    $p0, $T_0, 17
    srli                    $p1, $T_1, 17
    srli                    $p2, $T_2, 17
    srli                    $p3, $T_3, 17

    sw                      $p0, 8*4(x12)
    sw                      $p1, 9*4(x12)
    sw                      $p2, 10*4(x12)
    sw                      $p3, 11*4(x12)

    srli                    $p0, $T_0, 2
    srli                    $p1, $T_1, 2
    srli                    $p2, $T_2, 2
    srli                    $p3, $T_3, 2

    sw                      $p0, 16*4(x12)
    sw                      $p1, 17*4(x12)
    sw                      $p2, 18*4(x12)
    sw                      $p3, 19*4(x12)

    srli                    $p0, $T_1, 4
    srli                    $p1, $T_2, 4
    srli                    $p2, $T_3, 4
    srli                    $p3, $T_0, 4

    sw                      $p0, 36*4(x12)
    sw                      $p1, 37*4(x12)
    sw                      $p2, 38*4(x12)
    sw                      $p3, 39*4(x12)

    lwu                     $s0, 12*4(x12)
    lwu                     $s1, 13*4(x12)
    lwu                     $s2, 14*4(x12)
    lwu                     $s3, 15*4(x12)

    srli                    $p0, $T_2, 2
    srli                    $p1, $T_3, 2
    srli                    $p2, $T_0, 2
    srli                    $p3, $T_1, 2

    sw                      $p0, 52*4(x12)
    sw                      $p1, 53*4(x12)
    sw                      $p2, 54*4(x12)
    sw                      $p3, 55*4(x12)

    # s0 = k[12], s1 = k[13], s2 = k[14], s3 = k[15];
    slli                    $T_0, $s0, 32
    slli                    $T_1, $s1, 32
    slli                    $T_2, $s2, 32
    slli                    $T_3, $s3, 32

    or                      $T_0, $T_0, $s1    # s0 | s1
    or                      $T_1, $T_1, $s2    # s1 | s2
    or                      $T_2, $T_2, $s3    # s2 | s3
    or                      $T_3, $T_3, $s0    # s3 | s0

    srli                    $p0, $T_0, 17
    srli                    $p1, $T_1, 17
    srli                    $p2, $T_2, 17
    srli                    $p3, $T_3, 17

    sw                      $p0, 12*4(x12)
    sw                      $p1, 13*4(x12)
    sw                      $p2, 14*4(x12)
    sw                      $p3, 15*4(x12)

    srli                    $p0, $T_1, 19
    srli                    $p1, $T_2, 19
    srli                    $p2, $T_3, 19
    srli                    $p3, $T_0, 19

    sw                      $p0, 28*4(x12)
    sw                      $p1, 29*4(x12)
    sw                      $p2, 30*4(x12)
    sw                      $p3, 31*4(x12)

    sw                      $p1, 48*4(x12)
    sw                      $p2, 49*4(x12)
    sw                      $p3, 50*4(x12)
    sw                      $p0, 51*4(x12)

    lwu                     $s0, 0(x12)
    lwu                     $s1, 4(x12)
    lwu                     $s2, 2*4(x12)
    lwu                     $s3, 3*4(x12)

    srli                    $p0, $T_2, 2
    srli                    $p1, $T_3, 2
    srli                    $p2, $T_0, 2
    srli                    $p3, $T_1, 2

    sw                      $p0, 56*4(x12)
    sw                      $p1, 57*4(x12)
    sw                      $p2, 58*4(x12)
    sw                      $p3, 59*4(x12)

    # s0 = k[0], s1 = k[1], s2 = k[2], s3 = k[3];
    slli                    $T_0, $s0, 32
    slli                    $T_1, $s1, 32
    slli                    $T_2, $s2, 32
    slli                    $T_3, $s3, 32

    or                      $T_0, $T_0, $s1    # s0 | s1
    or                      $T_1, $T_1, $s2    # s1 | s2
    or                      $T_2, $T_2, $s3    # s2 | s3
    or                      $T_3, $T_3, $s0    # s3 | s0

    srli                    $p0, $T_1, 19
    srli                    $p1, $T_2, 19
    srli                    $p2, $T_3, 19
    srli                    $p3, $T_0, 19

    sw                      $p0, 24*4(x12)
    sw                      $p1, 25*4(x12)
    sw                      $p2, 26*4(x12)
    sw                      $p3, 27*4(x12)

    srli                    $p0, $T_1, 4
    srli                    $p1, $T_2, 4
    srli                    $p2, $T_3, 4
    srli                    $p3, $T_0, 4

    sw                      $p0, 32*4(x12)
    sw                      $p1, 33*4(x12)
    sw                      $p2, 34*4(x12)
    sw                      $p3, 35*4(x12)

    srli                    $p0, $T_2, 19
    srli                    $p1, $T_3, 19
    srli                    $p2, $T_0, 19
    srli                    $p3, $T_1, 19

    sw                      $p0, 44*4(x12)
    sw                      $p1, 45*4(x12)
    sw                      $p2, 46*4(x12)
    sw                      $p3, 47*4(x12)

    srli                    $p0, $T_3, 17
    srli                    $p1, $T_0, 17
    srli                    $p2, $T_1, 17
    srli                    $p3, $T_2, 17

    sw                      $p0, 60*4(x12)
    sw                      $p1, 61*4(x12)
    sw                      $p2, 62*4(x12)
    sw                      $p3, 63*4(x12)

    li                      x10, 4              # return 4

    _kBLen_NEQ128_1BRND:


    # Save all callee-saved registers
    ld                      s0, 0(sp)
    ld                      s1, 8(sp)
    ld                      s2, 16(sp)
    ld                      s3, 24(sp)
    ld                      s4, 32(sp)
    ld                      s5, 40(sp)
    ld                      s6, 48(sp)
    ld                      s7, 56(sp)
    ld                      s8, 64(sp)
    ld                      s9, 72(sp)
    ld                      s10, 80(sp)
    ld                      s11, 88(sp)
    addi                    sp, sp, 96

.Camellia_Ekeygen_end:
    ret
.size Camellia_Ekeygen,.-Camellia_Ekeygen

___


$code.=<<___;

#/**
# *
# * void Camellia_EncryptBlock(
# *      int keyBitLength,
# *      const u8 plaintext[],
# *      const KEY_TABLE_TYPE keyTable,
# *      u8 ciphertext[]
# *
#**/

.text
.p2align 3
.globl Camellia_EncryptBlock
.type Camellia_EncryptBlock,\@function
Camellia_EncryptBlock:


    li                      t0, 128
    mv                      t1, a0
    li                      a0, 3

    beq                     t1, t0, _Call_Camellia_EncryptBlock_Rounds
    li                      a0, 4

    _Call_Camellia_EncryptBlock_Rounds:
    j                       Camellia_EncryptBlock_Rounds


.Camellia_EncryptBlock_end:
    ret
.size Camellia_EncryptBlock,.-Camellia_EncryptBlock

___



$code.=<<___;

#/**
# *
# * void Camellia_EncryptBlock_Rounds(
# *      int grandRounds,
# *      const u8 plaintext[],
# *      const KEY_TABLE_TYPE pKTBL,
# *      u8 ciphertext[])
# *
#**/

.text
.p2align 3
.globl Camellia_EncryptBlock_Rounds
.type Camellia_EncryptBlock_Rounds,\@function
Camellia_EncryptBlock_Rounds:

    # Save all callee-saved registers
    addi                    sp, sp, -96
    sd                      s0, 0(sp)
    sd                      s1, 8(sp)
    sd                      s2, 16(sp)
    sd                      s3, 24(sp)
    sd                      s4, 32(sp)
    sd                      s5, 40(sp)
    sd                      s6, 48(sp)
    sd                      s7, 56(sp)
    sd                      s8, 64(sp)
    sd                      s9, 72(sp)
    sd                      s10, 80(sp)
    sd                      s11, 88(sp)

    # *kend = pKTBL + grandRounds * 16;
    slli                    x10, x10, 6

    lwu                     x28, 0(x11)
    lwu                     x29, 4(x11)
    lwu                     x30, 8(x11)
    lwu                     x31, 12(x11)
    add                     x10, x10, x12

    rev8                    x28, x28
    rev8                    x29, x29
    rev8                    x30, x30
    rev8                    x31, x31

    lwu                     x24, 0(x12)
    lwu                     x25, 4(x12)
    lwu                     x26, 8(x12)
    lwu                     x27, 12(x12)

    srli                    x28, x28, 32
    srli                    x29, x29, 32
    srli                    x30, x30, 32
    srli                    x31, x31, 32

    xor                     x18, x28, x24       # s0
    xor                     x19, x29, x25       # s1
    xor                     x20, x30, x26       # s2
    xor                     x21, x31, x27       # s3

    addi                    x12, x12, 16        # k += 4;
    la                      $SBOX, $Camellia_SBOX # Load constants Camellia_SBOX

    li                      $CONST, 256*4

    mv                      $TBL_0, $SBOX             # TBL_0
    add                     $TBL_1, $CONST, $SBOX     # TBL_1
    add                     $TBL_2, $CONST, $TBL_1    # TBL_2
    add                     $TBL_3, $CONST, $TBL_2    # TBL_3

    li                      $CONST, 255

    _Camellia_EncryptBlock_Rounds_LPST:
___

    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pKTBL", "$K_ADD2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pKTBL", "$K_ADD2");}
    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pKTBL", "$K_ADD2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pKTBL", "$K_ADD2");}
    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pKTBL", "$K_ADD2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pKTBL", "$K_ADD2");}

$code.=<<___;

    bge                     x12, x10, _Camellia_EncryptBlock_Rounds_LPND    # break;

    lwu                     x24, 0(x12)
    lwu                     x25, 4(x12)
    lwu                     x26, 8(x12)
    lwu                     x27, 12(x12)

    and                     x17, $s0, x24     # s1 ^= LeftRotate(s0 & k[0], 1);
    or                      x14, $s3, x27     # s2 ^= s3 | k[3];

    roriw                   x17, x17, 31
    xor                     $s2, $s2, x14     # s2 = $s2
    xor                     $s1, $s1, x17     # s1 = $s1
    and                     x15, $s2, x26       # s3 ^= LeftRotate(s2 & k[2], 1);
    or                      x16, $s1, x25       # s0 ^= s1 | k[1];

    roriw                   x15, x15, 31
    xor                     $s0, $s0, x16     # s0 = $s0
    xor                     $s3, $s3, x15     # s3 = $s3

    addi                    x12, x12, 16       # k += 4;
    j                       _Camellia_EncryptBlock_Rounds_LPST

    _Camellia_EncryptBlock_Rounds_LPND:


    lwu                     x24, 0(x12)
    lwu                     x25, 4(x12)
    lwu                     x26, 8(x12)
    lwu                     x27, 12(x12)

    xor                     x20, $s2, x24
    xor                     x21, $s3, x25
    xor                     x22, $s0, x26
    xor                     x23, $s1, x27

    rev8                    x28, x20
    rev8                    x29, x21
    rev8                    x30, x22
    rev8                    x31, x23

    srli                    x20, x28, 32
    srli                    x21, x29, 32
    srli                    x22, x30, 32
    srli                    x23, x31, 32

    sw                      x20, 0(x13)
    sw                      x21, 4(x13)
    sw                      x22, 8(x13)
    sw                      x23, 12(x13)


    # Save all callee-saved registers
    ld                      s0, 0(sp)
    ld                      s1, 8(sp)
    ld                      s2, 16(sp)
    ld                      s3, 24(sp)
    ld                      s4, 32(sp)
    ld                      s5, 40(sp)
    ld                      s6, 48(sp)
    ld                      s7, 56(sp)
    ld                      s8, 64(sp)
    ld                      s9, 72(sp)
    ld                      s10, 80(sp)
    ld                      s11, 88(sp)
    addi                    sp, sp, 96


.Camellia_EncryptBlock_Rounds_end:
    ret
.size Camellia_EncryptBlock_Rounds,.-Camellia_EncryptBlock_Rounds

___


$code.=<<___;

#/**
# *
# * void Camellia_EncryptBlock(
# *      int keyBitLength,
# *      const u8 plaintext[],
# *      const KEY_TABLE_TYPE keyTable,
# *      u8 ciphertext[]
# *
#**/

.text
.p2align 3
.globl Camellia_DecryptBlock
.type Camellia_DecryptBlock,\@function
Camellia_DecryptBlock:


    li                      t0, 128
    mv                      t1, a0
    li                      a0, 3

    beq                     t1, t0, _Call_Camellia_DecryptBlock_Rounds
    li                      a0, 4

    _Call_Camellia_DecryptBlock_Rounds:
    j                       Camellia_DecryptBlock_Rounds


.Camellia_DecryptBlock_end:
    ret
.size Camellia_DecryptBlock,.-Camellia_DecryptBlock

___


$code.=<<___;

#/**
# *
# * void Camellia_DecryptBlock_Rounds(
# *      int grandRounds,
# *      const u8 ciphertext[],
# *      const KEY_TABLE_TYPE pKTBL,
# *      u8 plaintext[])
# *
#**/


.text
.p2align 3
.globl Camellia_DecryptBlock_Rounds
.type Camellia_DecryptBlock_Rounds,\@function
Camellia_DecryptBlock_Rounds:


    # Save all callee-saved registers
    addi                    sp, sp, -96
    sd                      s0, 0(sp)
    sd                      s1, 8(sp)
    sd                      s2, 16(sp)
    sd                      s3, 24(sp)
    sd                      s4, 32(sp)
    sd                      s5, 40(sp)
    sd                      s6, 48(sp)
    sd                      s7, 56(sp)
    sd                      s8, 64(sp)
    sd                      s9, 72(sp)
    sd                      s10, 80(sp)
    sd                      s11, 88(sp)

    # *k = pKTBL + grandRounds * 16;
    # *kend = pKTBL + 4;
    slli                    x18, x10, 6

    lwu                     x28, 0(x11)
    lwu                     x29, 4(x11)
    lwu                     x30, 8(x11)
    lwu                     x31, 12(x11)
    addi                    x10, x12, 16
    add                     x12, x18, x12

    rev8                    x28, x28
    rev8                    x29, x29
    rev8                    x30, x30
    rev8                    x31, x31

    lwu                     x24, 0(x12)
    lwu                     x25, 4(x12)
    lwu                     x26, 8(x12)
    lwu                     x27, 12(x12)

    srli                    x28, x28, 32
    srli                    x29, x29, 32
    srli                    x30, x30, 32
    srli                    x31, x31, 32

    xor                     x18, x28, x24       # s0
    xor                     x19, x29, x25       # s1
    xor                     x20, x30, x26       # s2
    xor                     x21, x31, x27       # s3

    # prepare for Feistel
    la                      $SBOX, $Camellia_SBOX # Load constants Camellia_SBOX
    li                      $CONST, 256*4

    mv                      $TBL_0, $SBOX             # TBL_0
    add                     $TBL_1, $CONST, $SBOX     # TBL_1
    add                     $TBL_2, $CONST, $TBL_1    # TBL_2
    add                     $TBL_3, $CONST, $TBL_2    # TBL_3

    li                      $CONST, 255
    addi                    x12, x12, -8        # k -= 2;

    _Camellia_DecryptBlock_Rounds_LPST:
___

    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pKTBL", "$K_SUB2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pKTBL", "$K_SUB2");}
    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pKTBL", "$K_SUB2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pKTBL", "$K_SUB2");}
    {&Camellia_Feistel("$s0", "$s1", "$s2", "$s3", "$pKTBL", "$K_SUB2");}
    {&Camellia_Feistel("$s2", "$s3", "$s0", "$s1", "$pKTBL", "$K_NOP");}

$code.=<<___;

    ble                     x12, x10, _Camellia_DecryptBlock_Rounds_LPND    # break;

    addi                    x12, x12, -16     # k -= 4;

    lwu                     x24, 0(x12)
    lwu                     x25, 4(x12)
    lwu                     x26, 8(x12)
    lwu                     x27, 12(x12)

    addi                    x12, x12, -8      # k -= 2; prepare P of LW in LPST
    and                     x17, $s0, x26     # s1 ^= LeftRotate(s0 & k[2], 1);
    or                      x14, $s3, x25     # s2 ^= s3 | k[1];

    roriw                   x17, x17, 31
    xor                     $s2, $s2, x14     # s2 = $s2
    xor                     $s1, $s1, x17     # s1 = $s1
    and                     x15, $s2, x24     # s3 ^= LeftRotate(s2 & k[0], 1);
    or                      x16, $s1, x27     # s0 ^= s1 | k[3];

    roriw                   x15, x15, 31
    xor                     $s0, $s0, x16     # s0 = $s0
    xor                     $s3, $s3, x15     # s3 = $s3

    j                       _Camellia_DecryptBlock_Rounds_LPST

    _Camellia_DecryptBlock_Rounds_LPND:


    addi                    x12, x12, -16     # k -= 4;
    lwu                     x24, 0(x12)
    lwu                     x25, 4(x12)
    lwu                     x26, 8(x12)
    lwu                     x27, 12(x12)

    xor                     x20, $s2, x24
    xor                     x21, $s3, x25
    xor                     x22, $s0, x26
    xor                     x23, $s1, x27

    rev8                    x28, x20
    rev8                    x29, x21
    rev8                    x30, x22
    rev8                    x31, x23

    srli                    x20, x28, 32
    srli                    x21, x29, 32
    srli                    x22, x30, 32
    srli                    x23, x31, 32

    sw                      x20, 0(x13)
    sw                      x21, 4(x13)
    sw                      x22, 8(x13)
    sw                      x23, 12(x13)


    # Save all callee-saved registers
    ld                      s0, 0(sp)
    ld                      s1, 8(sp)
    ld                      s2, 16(sp)
    ld                      s3, 24(sp)
    ld                      s4, 32(sp)
    ld                      s5, 40(sp)
    ld                      s6, 48(sp)
    ld                      s7, 56(sp)
    ld                      s8, 64(sp)
    ld                      s9, 72(sp)
    ld                      s10, 80(sp)
    ld                      s11, 88(sp)
    addi                    sp, sp, 96


.Camellia_DecryptBlock_Rounds_end:
    ret
.size Camellia_DecryptBlock_Rounds,.-Camellia_DecryptBlock_Rounds
___


$code.=<<___;
.p2align 2
.type $Camellia_SBOX,\@object
$Camellia_SBOX:

    .word 0x70707000, 0x82828200, 0x2c2c2c00, 0xececec00, 0xb3b3b300, 0x27272700
    .word 0xc0c0c000, 0xe5e5e500, 0xe4e4e400, 0x85858500, 0x57575700, 0x35353500
    .word 0xeaeaea00, 0x0c0c0c00, 0xaeaeae00, 0x41414100, 0x23232300, 0xefefef00
    .word 0x6b6b6b00, 0x93939300, 0x45454500, 0x19191900, 0xa5a5a500, 0x21212100
    .word 0xededed00, 0x0e0e0e00, 0x4f4f4f00, 0x4e4e4e00, 0x1d1d1d00, 0x65656500
    .word 0x92929200, 0xbdbdbd00, 0x86868600, 0xb8b8b800, 0xafafaf00, 0x8f8f8f00
    .word 0x7c7c7c00, 0xebebeb00, 0x1f1f1f00, 0xcecece00, 0x3e3e3e00, 0x30303000
    .word 0xdcdcdc00, 0x5f5f5f00, 0x5e5e5e00, 0xc5c5c500, 0x0b0b0b00, 0x1a1a1a00
    .word 0xa6a6a600, 0xe1e1e100, 0x39393900, 0xcacaca00, 0xd5d5d500, 0x47474700
    .word 0x5d5d5d00, 0x3d3d3d00, 0xd9d9d900, 0x01010100, 0x5a5a5a00, 0xd6d6d600
    .word 0x51515100, 0x56565600, 0x6c6c6c00, 0x4d4d4d00, 0x8b8b8b00, 0x0d0d0d00
    .word 0x9a9a9a00, 0x66666600, 0xfbfbfb00, 0xcccccc00, 0xb0b0b000, 0x2d2d2d00
    .word 0x74747400, 0x12121200, 0x2b2b2b00, 0x20202000, 0xf0f0f000, 0xb1b1b100
    .word 0x84848400, 0x99999900, 0xdfdfdf00, 0x4c4c4c00, 0xcbcbcb00, 0xc2c2c200
    .word 0x34343400, 0x7e7e7e00, 0x76767600, 0x05050500, 0x6d6d6d00, 0xb7b7b700
    .word 0xa9a9a900, 0x31313100, 0xd1d1d100, 0x17171700, 0x04040400, 0xd7d7d700
    .word 0x14141400, 0x58585800, 0x3a3a3a00, 0x61616100, 0xdedede00, 0x1b1b1b00
    .word 0x11111100, 0x1c1c1c00, 0x32323200, 0x0f0f0f00, 0x9c9c9c00, 0x16161600
    .word 0x53535300, 0x18181800, 0xf2f2f200, 0x22222200, 0xfefefe00, 0x44444400
    .word 0xcfcfcf00, 0xb2b2b200, 0xc3c3c300, 0xb5b5b500, 0x7a7a7a00, 0x91919100
    .word 0x24242400, 0x08080800, 0xe8e8e800, 0xa8a8a800, 0x60606000, 0xfcfcfc00
    .word 0x69696900, 0x50505000, 0xaaaaaa00, 0xd0d0d000, 0xa0a0a000, 0x7d7d7d00
    .word 0xa1a1a100, 0x89898900, 0x62626200, 0x97979700, 0x54545400, 0x5b5b5b00
    .word 0x1e1e1e00, 0x95959500, 0xe0e0e000, 0xffffff00, 0x64646400, 0xd2d2d200
    .word 0x10101000, 0xc4c4c400, 0x00000000, 0x48484800, 0xa3a3a300, 0xf7f7f700
    .word 0x75757500, 0xdbdbdb00, 0x8a8a8a00, 0x03030300, 0xe6e6e600, 0xdadada00
    .word 0x09090900, 0x3f3f3f00, 0xdddddd00, 0x94949400, 0x87878700, 0x5c5c5c00
    .word 0x83838300, 0x02020200, 0xcdcdcd00, 0x4a4a4a00, 0x90909000, 0x33333300
    .word 0x73737300, 0x67676700, 0xf6f6f600, 0xf3f3f300, 0x9d9d9d00, 0x7f7f7f00
    .word 0xbfbfbf00, 0xe2e2e200, 0x52525200, 0x9b9b9b00, 0xd8d8d800, 0x26262600
    .word 0xc8c8c800, 0x37373700, 0xc6c6c600, 0x3b3b3b00, 0x81818100, 0x96969600
    .word 0x6f6f6f00, 0x4b4b4b00, 0x13131300, 0xbebebe00, 0x63636300, 0x2e2e2e00
    .word 0xe9e9e900, 0x79797900, 0xa7a7a700, 0x8c8c8c00, 0x9f9f9f00, 0x6e6e6e00
    .word 0xbcbcbc00, 0x8e8e8e00, 0x29292900, 0xf5f5f500, 0xf9f9f900, 0xb6b6b600
    .word 0x2f2f2f00, 0xfdfdfd00, 0xb4b4b400, 0x59595900, 0x78787800, 0x98989800
    .word 0x06060600, 0x6a6a6a00, 0xe7e7e700, 0x46464600, 0x71717100, 0xbababa00
    .word 0xd4d4d400, 0x25252500, 0xababab00, 0x42424200, 0x88888800, 0xa2a2a200
    .word 0x8d8d8d00, 0xfafafa00, 0x72727200, 0x07070700, 0xb9b9b900, 0x55555500
    .word 0xf8f8f800, 0xeeeeee00, 0xacacac00, 0x0a0a0a00, 0x36363600, 0x49494900
    .word 0x2a2a2a00, 0x68686800, 0x3c3c3c00, 0x38383800, 0xf1f1f100, 0xa4a4a400
    .word 0x40404000, 0x28282800, 0xd3d3d300, 0x7b7b7b00, 0xbbbbbb00, 0xc9c9c900
    .word 0x43434300, 0xc1c1c100, 0x15151500, 0xe3e3e300, 0xadadad00, 0xf4f4f400
    .word 0x77777700, 0xc7c7c700, 0x80808000, 0x9e9e9e00
    .word 0x70700070, 0x2c2c002c, 0xb3b300b3, 0xc0c000c0, 0xe4e400e4, 0x57570057
    .word 0xeaea00ea, 0xaeae00ae, 0x23230023, 0x6b6b006b, 0x45450045, 0xa5a500a5
    .word 0xeded00ed, 0x4f4f004f, 0x1d1d001d, 0x92920092, 0x86860086, 0xafaf00af
    .word 0x7c7c007c, 0x1f1f001f, 0x3e3e003e, 0xdcdc00dc, 0x5e5e005e, 0x0b0b000b
    .word 0xa6a600a6, 0x39390039, 0xd5d500d5, 0x5d5d005d, 0xd9d900d9, 0x5a5a005a
    .word 0x51510051, 0x6c6c006c, 0x8b8b008b, 0x9a9a009a, 0xfbfb00fb, 0xb0b000b0
    .word 0x74740074, 0x2b2b002b, 0xf0f000f0, 0x84840084, 0xdfdf00df, 0xcbcb00cb
    .word 0x34340034, 0x76760076, 0x6d6d006d, 0xa9a900a9, 0xd1d100d1, 0x04040004
    .word 0x14140014, 0x3a3a003a, 0xdede00de, 0x11110011, 0x32320032, 0x9c9c009c
    .word 0x53530053, 0xf2f200f2, 0xfefe00fe, 0xcfcf00cf, 0xc3c300c3, 0x7a7a007a
    .word 0x24240024, 0xe8e800e8, 0x60600060, 0x69690069, 0xaaaa00aa, 0xa0a000a0
    .word 0xa1a100a1, 0x62620062, 0x54540054, 0x1e1e001e, 0xe0e000e0, 0x64640064
    .word 0x10100010, 0x00000000, 0xa3a300a3, 0x75750075, 0x8a8a008a, 0xe6e600e6
    .word 0x09090009, 0xdddd00dd, 0x87870087, 0x83830083, 0xcdcd00cd, 0x90900090
    .word 0x73730073, 0xf6f600f6, 0x9d9d009d, 0xbfbf00bf, 0x52520052, 0xd8d800d8
    .word 0xc8c800c8, 0xc6c600c6, 0x81810081, 0x6f6f006f, 0x13130013, 0x63630063
    .word 0xe9e900e9, 0xa7a700a7, 0x9f9f009f, 0xbcbc00bc, 0x29290029, 0xf9f900f9
    .word 0x2f2f002f, 0xb4b400b4, 0x78780078, 0x06060006, 0xe7e700e7, 0x71710071
    .word 0xd4d400d4, 0xabab00ab, 0x88880088, 0x8d8d008d, 0x72720072, 0xb9b900b9
    .word 0xf8f800f8, 0xacac00ac, 0x36360036, 0x2a2a002a, 0x3c3c003c, 0xf1f100f1
    .word 0x40400040, 0xd3d300d3, 0xbbbb00bb, 0x43430043, 0x15150015, 0xadad00ad
    .word 0x77770077, 0x80800080, 0x82820082, 0xecec00ec, 0x27270027, 0xe5e500e5
    .word 0x85850085, 0x35350035, 0x0c0c000c, 0x41410041, 0xefef00ef, 0x93930093
    .word 0x19190019, 0x21210021, 0x0e0e000e, 0x4e4e004e, 0x65650065, 0xbdbd00bd
    .word 0xb8b800b8, 0x8f8f008f, 0xebeb00eb, 0xcece00ce, 0x30300030, 0x5f5f005f
    .word 0xc5c500c5, 0x1a1a001a, 0xe1e100e1, 0xcaca00ca, 0x47470047, 0x3d3d003d
    .word 0x01010001, 0xd6d600d6, 0x56560056, 0x4d4d004d, 0x0d0d000d, 0x66660066
    .word 0xcccc00cc, 0x2d2d002d, 0x12120012, 0x20200020, 0xb1b100b1, 0x99990099
    .word 0x4c4c004c, 0xc2c200c2, 0x7e7e007e, 0x05050005, 0xb7b700b7, 0x31310031
    .word 0x17170017, 0xd7d700d7, 0x58580058, 0x61610061, 0x1b1b001b, 0x1c1c001c
    .word 0x0f0f000f, 0x16160016, 0x18180018, 0x22220022, 0x44440044, 0xb2b200b2
    .word 0xb5b500b5, 0x91910091, 0x08080008, 0xa8a800a8, 0xfcfc00fc, 0x50500050
    .word 0xd0d000d0, 0x7d7d007d, 0x89890089, 0x97970097, 0x5b5b005b, 0x95950095
    .word 0xffff00ff, 0xd2d200d2, 0xc4c400c4, 0x48480048, 0xf7f700f7, 0xdbdb00db
    .word 0x03030003, 0xdada00da, 0x3f3f003f, 0x94940094, 0x5c5c005c, 0x02020002
    .word 0x4a4a004a, 0x33330033, 0x67670067, 0xf3f300f3, 0x7f7f007f, 0xe2e200e2
    .word 0x9b9b009b, 0x26260026, 0x37370037, 0x3b3b003b, 0x96960096, 0x4b4b004b
    .word 0xbebe00be, 0x2e2e002e, 0x79790079, 0x8c8c008c, 0x6e6e006e, 0x8e8e008e
    .word 0xf5f500f5, 0xb6b600b6, 0xfdfd00fd, 0x59590059, 0x98980098, 0x6a6a006a
    .word 0x46460046, 0xbaba00ba, 0x25250025, 0x42420042, 0xa2a200a2, 0xfafa00fa
    .word 0x07070007, 0x55550055, 0xeeee00ee, 0x0a0a000a, 0x49490049, 0x68680068
    .word 0x38380038, 0xa4a400a4, 0x28280028, 0x7b7b007b, 0xc9c900c9, 0xc1c100c1
    .word 0xe3e300e3, 0xf4f400f4, 0xc7c700c7, 0x9e9e009e
    .word 0x00e0e0e0, 0x00050505, 0x00585858, 0x00d9d9d9, 0x00676767, 0x004e4e4e
    .word 0x00818181, 0x00cbcbcb, 0x00c9c9c9, 0x000b0b0b, 0x00aeaeae, 0x006a6a6a
    .word 0x00d5d5d5, 0x00181818, 0x005d5d5d, 0x00828282, 0x00464646, 0x00dfdfdf
    .word 0x00d6d6d6, 0x00272727, 0x008a8a8a, 0x00323232, 0x004b4b4b, 0x00424242
    .word 0x00dbdbdb, 0x001c1c1c, 0x009e9e9e, 0x009c9c9c, 0x003a3a3a, 0x00cacaca
    .word 0x00252525, 0x007b7b7b, 0x000d0d0d, 0x00717171, 0x005f5f5f, 0x001f1f1f
    .word 0x00f8f8f8, 0x00d7d7d7, 0x003e3e3e, 0x009d9d9d, 0x007c7c7c, 0x00606060
    .word 0x00b9b9b9, 0x00bebebe, 0x00bcbcbc, 0x008b8b8b, 0x00161616, 0x00343434
    .word 0x004d4d4d, 0x00c3c3c3, 0x00727272, 0x00959595, 0x00ababab, 0x008e8e8e
    .word 0x00bababa, 0x007a7a7a, 0x00b3b3b3, 0x00020202, 0x00b4b4b4, 0x00adadad
    .word 0x00a2a2a2, 0x00acacac, 0x00d8d8d8, 0x009a9a9a, 0x00171717, 0x001a1a1a
    .word 0x00353535, 0x00cccccc, 0x00f7f7f7, 0x00999999, 0x00616161, 0x005a5a5a
    .word 0x00e8e8e8, 0x00242424, 0x00565656, 0x00404040, 0x00e1e1e1, 0x00636363
    .word 0x00090909, 0x00333333, 0x00bfbfbf, 0x00989898, 0x00979797, 0x00858585
    .word 0x00686868, 0x00fcfcfc, 0x00ececec, 0x000a0a0a, 0x00dadada, 0x006f6f6f
    .word 0x00535353, 0x00626262, 0x00a3a3a3, 0x002e2e2e, 0x00080808, 0x00afafaf
    .word 0x00282828, 0x00b0b0b0, 0x00747474, 0x00c2c2c2, 0x00bdbdbd, 0x00363636
    .word 0x00222222, 0x00383838, 0x00646464, 0x001e1e1e, 0x00393939, 0x002c2c2c
    .word 0x00a6a6a6, 0x00303030, 0x00e5e5e5, 0x00444444, 0x00fdfdfd, 0x00888888
    .word 0x009f9f9f, 0x00656565, 0x00878787, 0x006b6b6b, 0x00f4f4f4, 0x00232323
    .word 0x00484848, 0x00101010, 0x00d1d1d1, 0x00515151, 0x00c0c0c0, 0x00f9f9f9
    .word 0x00d2d2d2, 0x00a0a0a0, 0x00555555, 0x00a1a1a1, 0x00414141, 0x00fafafa
    .word 0x00434343, 0x00131313, 0x00c4c4c4, 0x002f2f2f, 0x00a8a8a8, 0x00b6b6b6
    .word 0x003c3c3c, 0x002b2b2b, 0x00c1c1c1, 0x00ffffff, 0x00c8c8c8, 0x00a5a5a5
    .word 0x00202020, 0x00898989, 0x00000000, 0x00909090, 0x00474747, 0x00efefef
    .word 0x00eaeaea, 0x00b7b7b7, 0x00151515, 0x00060606, 0x00cdcdcd, 0x00b5b5b5
    .word 0x00121212, 0x007e7e7e, 0x00bbbbbb, 0x00292929, 0x000f0f0f, 0x00b8b8b8
    .word 0x00070707, 0x00040404, 0x009b9b9b, 0x00949494, 0x00212121, 0x00666666
    .word 0x00e6e6e6, 0x00cecece, 0x00ededed, 0x00e7e7e7, 0x003b3b3b, 0x00fefefe
    .word 0x007f7f7f, 0x00c5c5c5, 0x00a4a4a4, 0x00373737, 0x00b1b1b1, 0x004c4c4c
    .word 0x00919191, 0x006e6e6e, 0x008d8d8d, 0x00767676, 0x00030303, 0x002d2d2d
    .word 0x00dedede, 0x00969696, 0x00262626, 0x007d7d7d, 0x00c6c6c6, 0x005c5c5c
    .word 0x00d3d3d3, 0x00f2f2f2, 0x004f4f4f, 0x00191919, 0x003f3f3f, 0x00dcdcdc
    .word 0x00797979, 0x001d1d1d, 0x00525252, 0x00ebebeb, 0x00f3f3f3, 0x006d6d6d
    .word 0x005e5e5e, 0x00fbfbfb, 0x00696969, 0x00b2b2b2, 0x00f0f0f0, 0x00313131
    .word 0x000c0c0c, 0x00d4d4d4, 0x00cfcfcf, 0x008c8c8c, 0x00e2e2e2, 0x00757575
    .word 0x00a9a9a9, 0x004a4a4a, 0x00575757, 0x00848484, 0x00111111, 0x00454545
    .word 0x001b1b1b, 0x00f5f5f5, 0x00e4e4e4, 0x000e0e0e, 0x00737373, 0x00aaaaaa
    .word 0x00f1f1f1, 0x00dddddd, 0x00595959, 0x00141414, 0x006c6c6c, 0x00929292
    .word 0x00545454, 0x00d0d0d0, 0x00787878, 0x00707070, 0x00e3e3e3, 0x00494949
    .word 0x00808080, 0x00505050, 0x00a7a7a7, 0x00f6f6f6, 0x00777777, 0x00939393
    .word 0x00868686, 0x00838383, 0x002a2a2a, 0x00c7c7c7, 0x005b5b5b, 0x00e9e9e9
    .word 0x00eeeeee, 0x008f8f8f, 0x00010101, 0x003d3d3d
    .word 0x38003838, 0x41004141, 0x16001616, 0x76007676, 0xd900d9d9, 0x93009393
    .word 0x60006060, 0xf200f2f2, 0x72007272, 0xc200c2c2, 0xab00abab, 0x9a009a9a
    .word 0x75007575, 0x06000606, 0x57005757, 0xa000a0a0, 0x91009191, 0xf700f7f7
    .word 0xb500b5b5, 0xc900c9c9, 0xa200a2a2, 0x8c008c8c, 0xd200d2d2, 0x90009090
    .word 0xf600f6f6, 0x07000707, 0xa700a7a7, 0x27002727, 0x8e008e8e, 0xb200b2b2
    .word 0x49004949, 0xde00dede, 0x43004343, 0x5c005c5c, 0xd700d7d7, 0xc700c7c7
    .word 0x3e003e3e, 0xf500f5f5, 0x8f008f8f, 0x67006767, 0x1f001f1f, 0x18001818
    .word 0x6e006e6e, 0xaf00afaf, 0x2f002f2f, 0xe200e2e2, 0x85008585, 0x0d000d0d
    .word 0x53005353, 0xf000f0f0, 0x9c009c9c, 0x65006565, 0xea00eaea, 0xa300a3a3
    .word 0xae00aeae, 0x9e009e9e, 0xec00ecec, 0x80008080, 0x2d002d2d, 0x6b006b6b
    .word 0xa800a8a8, 0x2b002b2b, 0x36003636, 0xa600a6a6, 0xc500c5c5, 0x86008686
    .word 0x4d004d4d, 0x33003333, 0xfd00fdfd, 0x66006666, 0x58005858, 0x96009696
    .word 0x3a003a3a, 0x09000909, 0x95009595, 0x10001010, 0x78007878, 0xd800d8d8
    .word 0x42004242, 0xcc00cccc, 0xef00efef, 0x26002626, 0xe500e5e5, 0x61006161
    .word 0x1a001a1a, 0x3f003f3f, 0x3b003b3b, 0x82008282, 0xb600b6b6, 0xdb00dbdb
    .word 0xd400d4d4, 0x98009898, 0xe800e8e8, 0x8b008b8b, 0x02000202, 0xeb00ebeb
    .word 0x0a000a0a, 0x2c002c2c, 0x1d001d1d, 0xb000b0b0, 0x6f006f6f, 0x8d008d8d
    .word 0x88008888, 0x0e000e0e, 0x19001919, 0x87008787, 0x4e004e4e, 0x0b000b0b
    .word 0xa900a9a9, 0x0c000c0c, 0x79007979, 0x11001111, 0x7f007f7f, 0x22002222
    .word 0xe700e7e7, 0x59005959, 0xe100e1e1, 0xda00dada, 0x3d003d3d, 0xc800c8c8
    .word 0x12001212, 0x04000404, 0x74007474, 0x54005454, 0x30003030, 0x7e007e7e
    .word 0xb400b4b4, 0x28002828, 0x55005555, 0x68006868, 0x50005050, 0xbe00bebe
    .word 0xd000d0d0, 0xc400c4c4, 0x31003131, 0xcb00cbcb, 0x2a002a2a, 0xad00adad
    .word 0x0f000f0f, 0xca00caca, 0x70007070, 0xff00ffff, 0x32003232, 0x69006969
    .word 0x08000808, 0x62006262, 0x00000000, 0x24002424, 0xd100d1d1, 0xfb00fbfb
    .word 0xba00baba, 0xed00eded, 0x45004545, 0x81008181, 0x73007373, 0x6d006d6d
    .word 0x84008484, 0x9f009f9f, 0xee00eeee, 0x4a004a4a, 0xc300c3c3, 0x2e002e2e
    .word 0xc100c1c1, 0x01000101, 0xe600e6e6, 0x25002525, 0x48004848, 0x99009999
    .word 0xb900b9b9, 0xb300b3b3, 0x7b007b7b, 0xf900f9f9, 0xce00cece, 0xbf00bfbf
    .word 0xdf00dfdf, 0x71007171, 0x29002929, 0xcd00cdcd, 0x6c006c6c, 0x13001313
    .word 0x64006464, 0x9b009b9b, 0x63006363, 0x9d009d9d, 0xc000c0c0, 0x4b004b4b
    .word 0xb700b7b7, 0xa500a5a5, 0x89008989, 0x5f005f5f, 0xb100b1b1, 0x17001717
    .word 0xf400f4f4, 0xbc00bcbc, 0xd300d3d3, 0x46004646, 0xcf00cfcf, 0x37003737
    .word 0x5e005e5e, 0x47004747, 0x94009494, 0xfa00fafa, 0xfc00fcfc, 0x5b005b5b
    .word 0x97009797, 0xfe00fefe, 0x5a005a5a, 0xac00acac, 0x3c003c3c, 0x4c004c4c
    .word 0x03000303, 0x35003535, 0xf300f3f3, 0x23002323, 0xb800b8b8, 0x5d005d5d
    .word 0x6a006a6a, 0x92009292, 0xd500d5d5, 0x21002121, 0x44004444, 0x51005151
    .word 0xc600c6c6, 0x7d007d7d, 0x39003939, 0x83008383, 0xdc00dcdc, 0xaa00aaaa
    .word 0x7c007c7c, 0x77007777, 0x56005656, 0x05000505, 0x1b001b1b, 0xa400a4a4
    .word 0x15001515, 0x34003434, 0x1e001e1e, 0x1c001c1c, 0xf800f8f8, 0x52005252
    .word 0x20002020, 0x14001414, 0xe900e9e9, 0xbd00bdbd, 0xdd00dddd, 0xe400e4e4
    .word 0xa100a1a1, 0xe000e0e0, 0x8a008a8a, 0xf100f1f1, 0xd600d6d6, 0x7a007a7a
    .word 0xbb00bbbb, 0xe300e3e3, 0x40004040, 0x4f004f4f

.size $Camellia_SBOX,.-$Camellia_SBOX


.p2align 2
.type $SIGMA,\@object
$SIGMA:
    .word 0xa09e667f, 0x3bcc908b, 0xb67ae858, 0x4caa73b2
    .word 0xc6ef372f, 0xe94f82be, 0x54ff53a5, 0xf1d36f1c
    .word 0x10e527fa, 0xde682d1d, 0xb05688c2, 0xb3e6c1fd
.size $SIGMA,.-$SIGMA
___

print $code;

close STDOUT or die "error closing STDOUT: $!";