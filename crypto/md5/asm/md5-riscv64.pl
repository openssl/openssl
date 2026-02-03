# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V Bit-manipulation extension ('Zbb')

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

my $code.=<<___;

#/**
# *
# * void md5_block_data_order(
# *  MD5_CTX *c,
# *  const void *data_,
# *  size_t num)
# *
#**/

.text
.p2align 3
.globl ossl_md5_block_asm_data_order
.type ossl_md5_block_asm_data_order,\@function
ossl_md5_block_asm_data_order:


    beqz                    a2, .MD5_END

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

    mv                      x29, x10
    mv                      x30, x11
    fmv.d.x                 ft0, x12

    lw                      x10, 0(x29)         # .Load MD5 state->A
    lw                      x11, 4(x29)         # .Load MD5 state->B
    lw                      x12, 8(x29)         # .Load MD5 state->C
    lw                      x13, 12(x29)        # .Load MD5 state->D

.align    5
_MD5_LOOP:

    xor                     x17, x12, x13       # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    and                     x16, x17, x11
    lw                      x15, 0(x30)         # .Load 1 words of input data0 M[0]
    lw                      x20, 4(x30)         # .Load 1 words of input data0 M[1]
    lw                      x31, 8(x30)         # .Load 1 words of input data0 M[2]
    lw                      x21, 12(x30)        # .Load 1 words of input data0 M[3]
    xor                     x14, x16, x13       # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xd76a
    li                      x9, 0xa478
    slli                    x28, x28, 16
    add                     x9, x28, x9         # .Load upper half of constant 0xd76aa478
    addw                    x8, x10, x15        # Add dest value
    addw                    x7, x8, x9          # Add constant 0xd76aa478
    addw                    x6, x7, x14         # Add aux function result
    roriw                   x6, x6, 25          # Rotate left s=7 bits
    xor                     x5, x11, x12        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x18, x11, x6        # round 1
    and                     x8, x5, x18         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x17, x8, x12        # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xe8c7         # .Load upper half of constant 0xe8c7b756
    li                      x16, 0xb756
    slli                    x28, x28, 16
    add                     x16, x28, x16
    addw                    x9, x13, x20        # Add dest value
    addw                    x7, x9, x16         # Add constant 0xe8c7b756
    addw                    x14, x7, x17        # Add aux function result
    roriw                   x14, x14, 20        # Rotate left s=12 bits
    xor                     x6, x18, x11        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x5, x18, x14        # round 1
    and                     x8, x6, x5          # aux function round 1 F(x,y,z)=(((y^z)&x)^z)

    xor                     x9, x8, x11         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x2420         # .Load upper half of constant 0x242070db
    li                      x16, 0x70db         # .Load lower half of constant 0x242070db
    slli                    x28, x28, 16
    add                     x16, x28, x16
    addw                    x7, x12, x31        # Add dest value
    addw                    x17, x7, x16        # Add constant 0x242070db
    addw                    x14, x17, x9        # Add aux function result
    roriw                   x14, x14, 15        # Rotate left s=17 bits
    xor                     x6, x5, x18         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x8, x5, x14         # round 1
    and                     x7, x6, x8          # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x16, x7, x18        # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xc1bd         # .Load upper half of constant 0xc1bdceee
    li                      x9, 0xceee          # .Load lower half of constant 0xc1bdceee
    slli                    x28, x28, 16
    add                     x9, x28, x9
    addw                    x14, x11, x21       # Add dest value
    addw                    x6, x14, x9         # Add constant 0xc1bdceee
    addw                    x7, x6, x16         # Add aux function result
    roriw                   x7, x7, 10          # Rotate left s=22 bits
    xor                     x17, x8, x5         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    add                     x9, x8, x7          # round 1 B=FF(B, C, D, A, 0xc1bdceee, s=22, M[3])
    lw                      x14, 16(x30)        # .Load 1 words of input data0 M[4]
    lw                      x22, 20(x30)        # .Load 1 words of input data0 M[5]
    lw                      x7,  24(x30)        # .Load 1 words of input data0 M[6]
    lw                      x23, 28(x30)        # .Load 1 words of input data0 M[7]

    and                     x16, x17, x9        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x6, x16, x5         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xf57c         # .Load upper half of constant 0xc1bdceee
    li                      x16, 0xfaf          # .Load lower half of constant 0xc1bdceee
    slli                    x28, x28, 16
    add                     x16, x28, x16
    addw                    x17, x18, x14       # Add dest value
    addw                    x16, x17, x16       # Add constant 0xf57c0faf
    addw                    x18, x16, x6        # Add aux function result
    roriw                   x18, x18, 25        # Rotate left s=7 bits
    xor                     x16, x9, x8         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x17, x9, x18        # round 1 A=FF(A, B, C, D, 0xf57c0faf, s=7, M[4])
    and                     x16, x16, x17       # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x6, x16, x8         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x4787         # .Load upper half of constant 0x4787c62a
    li                      x18, 0xc62a         # .Load lower half of constant 0x4787c62a
    slli                    x28, x28, 16
    add                     x18, x28, x18
    addw                    x16, x5, x22        # Add dest value
    addw                    x16, x16, x18       # Add constant 0x4787c62a
    addw                    x5, x16, x6         # Add aux function result
    roriw                   x5, x5, 20          # Rotate left s=12 bits
    xor                     x18, x17, x9        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x19, x17, x5        # round 1 D=FF(D, A, B, C, 0x4787c62a, s=12, M[5])
    and                     x6, x18, x19        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x5, x6, x9          # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xa830         # .Load upper half of constant 0xa8304613
    li                      x18, 0x4613         # .Load lower half of constant 0xa8304613
    slli                    x28, x28, 16
    add                     x18, x28, x18
    addw                    x6, x8, x7          # Add dest value
    addw                    x8, x6, x18         # Add constant 0xa8304613
    addw                    x18, x8, x5         # Add aux function result
    roriw                   x18, x18, 15        # Rotate left s=17 bits
    xor                     x6, x19, x17        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x8, x19, x18        # round 1 C=FF(C, D, A, B, 0xa8304613, s=17, M[6])
    and                     x5, x6, x8          # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x18, x5, x17        # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xfd46         # .Load upper half of constant 0xfd469501
    li                      x6, 0x9501          # .Load lower half of constant 0xfd469501
    slli                    x28, x28, 16
    add                     x6, x28, x6
    addw                    x9, x9, x23         # Add dest value
    addw                    x5, x9, x6          # Add constant 0xfd469501
    addw                    x9, x5, x18         # Add aux function result
    roriw                   x9, x9, 10          # Rotate left s=22 bits
    xor                     x6, x8, x19         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x18, x8, x9         # round 1 B=FF(B, C, D, A, 0xfd469501, s=22, M[7])
    lw                      x5, 32(x30)         # .Load 1 words of input data0 M[8]
    lw                      x24, 36(x30)        # .Load 1 words of input data0 M[9]
    lw                      x16, 40(x30)        # .Load 1 words of input data0 M[10]
    lw                      x25, 44(x30)        # .Load 1 words of input data0 M[11]

    and                     x9, x6, x18         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x6, x9, x19         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x6980         # .Load upper half of constant 0x698098d8
    li                      x9, 0x98d8          # .Load lower half of constant 0x698098d8
    slli                    x28, x28, 16
    add                     x9, x28, x9
    addw                    x17, x17, x5        # Add dest value
    addw                    x9, x17, x9         # Add constant 0x698098d8
    addw                    x17, x9, x6         # Add aux function result
    roriw                   x17, x17, 25        # Rotate left s=7 bits
    xor                     x9, x18, x8         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x6, x18, x17        # round 1 A=FF(A, B, C, D, 0x698098d8, s=7, M[8])
    and                     x17, x9, x6         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x9, x17, x8         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x8b44         # .Load upper half of constant 0x8b44f7af
    li                      x17, 0xf7af         # .Load lower half of constant 0x8b44f7af
    slli                    x28, x28, 16
    add                     x17, x28, x17
    addw                    x19, x19, x24       # Add dest value
    addw                    x17, x19, x17       # Add constant 0x8b44f7af
    addw                    x19, x17, x9        # Add aux function result
    roriw                   x19, x19, 20        # Rotate left s=12 bits
    xor                     x9, x6, x18         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x17, x6, x19        # round 1 D=FF(D, A, B, C, 0x8b44f7af, s=12, M[9])
    and                     x9, x9, x17         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x9, x9, x18         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xffff         # .Load upper half of constant 0xffff5bb1
    li                      x11, 0x5bb1         # .Load lower half of constant 0xffff5bb1
    slli                    x28, x28, 16
    add                     x11, x28, x11
    addw                    x8, x8, x16         # Add dest value
    addw                    x8, x8, x11         # Add constant 0xffff5bb1
    addw                    x8, x8, x9          # Add aux function result
    roriw                   x8, x8, 15          # Rotate left s=17 bits
    xor                     x9, x17, x6         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x8, x17, x8         # round 1 C=FF(C, D, A, B, 0xffff5bb1, s=17, M[10])
    and                     x9, x9, x8          # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x9, x9, x6          # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x895c         # .Load upper half of constant 0x895cd7be
    li                      x11, 0xd7be         # .Load lower half of constant 0x895cd7be
    slli                    x28, x28, 16
    add                     x11, x28, x11
    addw                    x18, x18, x25       # Add dest value
    addw                    x18, x18, x11       # Add constant 0x895cd7be
    addw                    x9, x18, x9         # Add aux function result
    roriw                   x9, x9, 10          # Rotate left s=22 bits
    xor                     x18, x8, x17        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x9, x8, x9          # round 1 B=FF(B, C, D, A, 0x895cd7be, s=22, M[11])
    lw                      x11, 48(x30)        # .Load 1 words of input data0 M[12]
    lw                      x26, 52(x30)        # .Load 1 words of input data0 M[13]
    lw                      x12, 56(x30)        # .Load 1 words of input data0 M[14]
    lw                      x27, 60(x30)        # .Load 1 words of input data0 M[15]

    and                     x18, x18, x9        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x18, x18, x17       # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x6b90         # .Load upper half of constant 0x6b901122
    li                      x19, 0x1122         # .Load lower half of constant 0x6b901122
    slli                    x28, x28, 16
    add                     x19, x28, x19
    addw                    x6, x6, x11         # Add dest value
    addw                    x6, x6, x19         # Add constant 0x6b901122
    addw                    x18, x6, x18        # Add aux function result
    roriw                   x18, x18, 25        # Rotate left s=7 bits
    xor                     x6, x9, x8          # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x18, x9, x18        # round 1 A=FF(A, B, C, D, 0x6b901122, s=7, M[12])
    and                     x6, x6, x18         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x6, x6, x8          # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xfd98         # .Load upper half of constant 0xfd987193
    li                      x19, 0x7193         # .Load lower half of constant 0xfd987193
    slli                    x28, x28, 16
    add                     x19, x28, x19
    addw                    x17, x17, x26       # Add dest value
    addw                    x17, x17, x19       # Add constant 0xfd987193
    addw                    x17, x17, x6        # Add aux function result
    roriw                   x17, x17, 20        # Rotate left s=12 bits
    xor                     x6, x18, x9         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x17, x18, x17       # round 1 D=FF(D, A, B, C, 0xfd987193, s=12, M[13])
    and                     x6, x6, x17         # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x6, x6, x9          # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0xa679         # .Load upper half of constant 0xa679438e
    li                      x13, 0x438e         # .Load lower half of constant 0xa679438e
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x12         # Add dest value
    addw                    x8, x8, x13         # Add constant 0xa679438e
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 15          # Rotate left s=17 bits
    xor                     x6, x17, x18        # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    addw                    x8, x17, x8         # round 1 C=FF(C, D, A, B, 0xa679438e, s=17, M[14])
    and                     x6, x6, x8          # aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    xor                     x6, x6, x18         # End aux function round 1 F(x,y,z)=(((y^z)&x)^z)
    li                      x28, 0x49b4         # .Load upper half of constant 0x49b40821
    li                      x13, 0x821          # .Load lower half of constant 0x49b40821
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x27         # Add dest value
    addw                    x9, x9, x13         # Add constant 0x49b40821
    addw                    x9, x9, x6          # Add aux function result
    roriw                   x9, x9, 10          # Rotate left s=22 bits
    andn                    x6, x8, x17         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x9, x8, x9          # round 1 B=FF(B, C, D, A, 0x49b40821, s=22, M[15])
    and                     x13, x9, x17        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xf61e         # .Load upper half of constant 0xf61e2562
    li                      x13, 0x2562         # .Load lower half of constant 0xf61e2562
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x18, x18, x20       # Add dest value
    addw                    x18, x18, x13       # Add constant 0xf61e2562
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 27        # Rotate left s=5 bits
    andn                    x6, x9, x8          # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x18, x9, x18        # round 2 A=GG(A, B, C, D, 0xf61e2562, s=5, M[1])
    and                     x13, x18, x8        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xc040         # .Load upper half of constant 0xc040b340
    li                      x13, 0xb340         # .Load lower half of constant 0xc040b340
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x17, x17, x7        # Add dest value
    addw                    x17, x17, x13       # Add constant 0xc040b340
    addw                    x17, x17, x6        # Add aux function result
    roriw                   x17, x17, 23        # Rotate left s=9 bits
    andn                    x6, x18, x9         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x17, x18, x17       # round 2 D=GG(D, A, B, C, 0xc040b340, s=9, M[6])
    and                     x13, x17, x9        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))

    li                      x28, 0x265e         # .Load upper half of constant 0x265e5a51
    li                      x13, 0x5a51         # .Load lower half of constant 0x265e5a51
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x25         # Add dest value
    addw                    x8, x8, x13         # Add constant 0x265e5a51
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 18          # Rotate left s=14 bits
    andn                    x6, x17, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x8, x17, x8         # round 2 C=GG(C, D, A, B, 0x265e5a51, s=14, M[11])
    and                     x13, x8, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xe9b6         # .Load upper half of constant 0xe9b6c7aa
    li                      x13, 0xc7aa         # .Load lower half of constant 0xe9b6c7aa
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x15         # Add dest value
    addw                    x9, x9, x13         # Add constant 0xe9b6c7aa
    addw                    x9, x9, x6          # Add aux function result
    roriw                   x9, x9, 12          # Rotate left s=20 bits

    andn                    x6, x8, x17         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x9, x8, x9          # round 2 B=GG(B, C, D, A, 0xe9b6c7aa, s=20, M[0])
    and                     x13, x9, x17        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xd62f         # .Load upper half of constant 0xd62f105d
    li                      x13, 0x105d         # .Load lower half of constant 0xd62f105d
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x18, x18, x22       # Add dest value
    addw                    x18, x18, x13       # Add constant 0xd62f105d
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 27        # Rotate left s=5 bits
    andn                    x6, x9, x8          # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x18, x9, x18        # round 2 A=GG(A, B, C, D, 0xd62f105d, s=5, M[5])
    and                     x13, x18, x8        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0x244          # .Load upper half of constant 0x2441453
    li                      x13, 0x1453         # .Load lower half of constant 0x2441453
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x17, x17, x16       # Add dest value
    addw                    x17, x17, x13       # Add constant 0x2441453
    addw                    x17, x17, x6        # Add aux function result
    roriw                   x17, x17, 23        # Rotate left s=9 bits
    andn                    x6, x18, x9         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x17, x18, x17       # round 2 D=GG(D, A, B, C, 0x2441453, s=9, M[10])
    and                     x13, x17, x9        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xd8a1         # .Load upper half of constant 0xd8a1e681
    li                      x13, 0xe681         # .Load lower half of constant 0xd8a1e681
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x27         # Add dest value
    addw                    x8, x8, x13         # Add constant 0xd8a1e681
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 18          # Rotate left s=14 bits
    andn                    x6, x17, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x8, x17, x8         # round 2 C=GG(C, D, A, B, 0xd8a1e681, s=14, M[15])
    and                     x13, x8, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xe7d3         # .Load upper half of constant 0xe7d3fbc8
    li                      x13, 0xfbc8         # .Load lower half of constant 0xe7d3fbc8
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x14         # Add dest value
    addw                    x9, x9, x13         # Add constant 0xe7d3fbc8
    addw                    x9, x9, x6          # Add aux function result
    roriw                   x9, x9, 12          # Rotate left s=20 bits
    andn                    x6, x8, x17         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x9, x8, x9          # round 2 B=GG(B, C, D, A, 0xe7d3fbc8, s=20, M[4])
    and                     x13, x9, x17        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0x21e1         # .Load upper half of constant 0x21e1cde6
    li                      x13, 0xcde6         # .Load lower half of constant 0x21e1cde6
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x18, x18, x24       # Add dest value
    addw                    x18, x18, x13       # Add constant 0x21e1cde6
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 27        # Rotate left s=5 bits
    andn                    x6, x9, x8          # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x18, x9, x18        # round 2 A=GG(A, B, C, D, 0x21e1cde6, s=5, M[9])
    and                     x13, x18, x8        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xc337         # .Load upper half of constant 0xc33707d6
    li                      x13, 0x7d6          # .Load lower half of constant 0xc33707d6
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x17, x17, x12       # Add dest value
    addw                    x17, x17, x13       # Add constant 0xc33707d6
    addw                    x17, x17, x6        # Add aux function result
    roriw                   x17, x17, 23        # Rotate left s=9 bits
    andn                    x6, x18, x9         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x17, x18, x17       # round 2 D=GG(D, A, B, C, 0xc33707d6, s=9, M[14])
    and                     x13, x17, x9        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xf4d5         # .Load upper half of constant 0xf4d50d87
    li                      x13, 0xd87          # .Load lower half of constant 0xf4d50d87
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x21         # Add dest value
    addw                    x8, x8, x13         # Add constant 0xf4d50d87
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 18          # Rotate left s=14 bits
    andn                    x6, x17, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x8, x17, x8         # round 2 C=GG(C, D, A, B, 0xf4d50d87, s=14, M[3])
    and                     x13, x8, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0x455a         # .Load upper half of constant 0x455a14ed
    li                      x13, 0x14ed         # .Load lower half of constant 0x455a14ed
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x5          # Add dest value
    addw                    x9, x9, x13         # Add constant 0x455a14ed
    addw                    x9, x9, x6          # Add aux function result
    roriw                   x9, x9, 12          # Rotate left s=20 bits
    andn                    x6, x8, x17         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x9, x8, x9          # round 2 B=GG(B, C, D, A, 0x455a14ed, s=20, M[8])
    and                     x13, x9, x17        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xa9e3         # .Load upper half of constant 0xa9e3e905
    li                      x13, 0xe905         # .Load lower half of constant 0xa9e3e905
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x18, x18, x26       # Add dest value
    addw                    x18, x18, x13       # Add constant 0xa9e3e905
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 27        # Rotate left s=5 bits
    andn                    x6, x9, x8          # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x18, x9, x18        # round 2 A=GG(A, B, C, D, 0xa9e3e905, s=5, M[13])
    and                     x13, x18, x8        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0xfcef         # .Load upper half of constant 0xfcefa3f8
    li                      x13, 0xa3f8         # .Load lower half of constant 0xfcefa3f8
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x17, x17, x31       # Add dest value
    addw                    x17, x17, x13       # Add constant 0xfcefa3f8
    addw                    x17, x17, x6        # Add aux function result
    roriw                   x17, x17, 23        # Rotate left s=9 bits
    andn                    x6, x18, x9         # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x17, x18, x17       # round 2 D=GG(D, A, B, C, 0xfcefa3f8, s=9, M[2])
    and                     x13, x17, x9        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0x676f         # .Load upper half of constant 0x676f02d9
    li                      x13, 0x2d9          # .Load lower half of constant 0x676f02d9
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x23         # Add dest value
    addw                    x8, x8, x13         # Add constant 0x676f02d9
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 18          # Rotate left s=14 bits
    andn                    x6, x17, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    addw                    x8, x17, x8         # round 2 C=GG(C, D, A, B, 0x676f02d9, s=14, M[7])
    and                     x13, x8, x18        # Aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    or                      x6, x6, x13         # End aux function round 2 G(x,y,z)=((x&z)|(~z&y))
    li                      x28, 0x8d2a         # .Load upper half of constant 0x8d2a4c8a
    li                      x13, 0x4c8a         # .Load lower half of constant 0x8d2a4c8a
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x11         # Add dest value
    addw                    x9, x9, x13         # Add constant 0x8d2a4c8a
    addw                    x9, x9, x6          # Add aux function result
    xor                     x6, x8, x17         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x9, x9, 12          # Rotate left s=20 bits
    li                      x28, 0xfffa         # .Load upper half of constant 0xfffa3942
    li                      x10, 0x3942         # .Load lower half of constant 0xfffa3942
    addw                    x9, x8, x9          # round 2 B=GG(B, C, D, A, 0x8d2a4c8a, s=20, M[12])
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x18, x18, x22       # Add dest value
    xor                     x6, x6, x9          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x18, x18, x10       # Add constant 0xfffa3942
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 28        # Rotate left s=4 bits
    xor                     x6, x9, x8          # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0x8771         # .Load upper half of constant 0x8771f681
    addw                    x18, x9, x18        # round 3 A=HH(A, B, C, D, 0xfffa3942, s=4, M[5])
    li                      x10, 0xf681         # .Load lower half of constant 0x8771f681
    slli                    x28, x28, 16
    add                     x10, x28, x10

    addw                    x17, x17, x5        # Add dest value
    xor                     x6, x6, x18         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x17, x17, x10       # Add constant 0x8771f681
    addw                    x17, x17, x6        # Add aux function result
    xor                     x6, x18, x9         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x17, x17, 21        # Rotate left s=11 bits
    li                      x28, 0x6d9d         # .Load upper half of constant 0x6d9d6122
    addw                    x17, x18, x17       # round 3 D=HH(D, A, B, C, 0x8771f681, s=11, M[8])
    li                      x13, 0x6122         # .Load lower half of constant 0x6d9d6122
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x25         # Add dest value
    xor                     x6, x6, x17         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x8, x8, x13         # Add constant 0x6d9d6122
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 16          # Rotate left s=16 bits
    xor                     x6, x17, x18        # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0xfde5         # .Load upper half of constant 0xfde5380c
    addw                    x8, x17, x8         # round 3 C=HH(C, D, A, B, 0x6d9d6122, s=16, M[11])
    li                      x13, 0x380c         # .Load lower half of constant 0xfde5380c
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x12         # Add dest value
    xor                     x6, x6, x8          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x9, x9, x13         # Add constant 0xfde5380c
    addw                    x9, x9, x6          # Add aux function result
    xor                     x6, x8, x17         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x9, x9, 9           # Rotate left s=23 bits
    li                      x28, 0xa4be         # .Load upper half of constant 0xa4beea44
    addw                    x9, x8, x9          # round 3 B=HH(B, C, D, A, 0xfde5380c, s=23, M[14])
    li                      x10, 0xea44         # .Load lower half of constant 0xa4beea44
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x18, x18, x20       # Add dest value
    xor                     x6, x6, x9          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x18, x18, x10       # Add constant 0xa4beea44
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 28        # Rotate left s=4 bits
    xor                     x6, x9, x8          # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0x4bde         # .Load upper half of constant 0x4bdecfa9
    addw                    x18, x9, x18        # round 3 A=HH(A, B, C, D, 0xa4beea44, s=4, M[1])
    li                      x10, 0xcfa9         # .Load lower half of constant 0x4bdecfa9
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x17, x17, x14       # Add dest value
    xor                     x6, x6, x18         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x17, x17, x10       # Add constant 0x4bdecfa9
    addw                    x17, x17, x6        # Add aux function result
    xor                     x6, x18, x9         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x17, x17, 21        # Rotate left s=11 bits
    li                      x28, 0xf6bb         # .Load upper half of constant 0xf6bb4b60
    addw                    x17, x18, x17       # round 3 D=HH(D, A, B, C, 0x4bdecfa9, s=11, M[4])
    li                      x13, 0x4b60         # .Load lower half of constant 0xf6bb4b60
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x23         # Add dest value

    xor                     x6, x6, x17         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x8, x8, x13         # Add constant 0xf6bb4b60
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 16          # Rotate left s=16 bits
    xor                     x6, x17, x18        # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0xbebf         # .Load upper half of constant 0xbebfbc70
    addw                    x8, x17, x8         # round 3 C=HH(C, D, A, B, 0xf6bb4b60, s=16, M[7])
    li                      x13, 0xbc70         # .Load lower half of constant 0xbebfbc70
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x16         # Add dest value
    xor                     x6, x6, x8          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x9, x9, x13         # Add constant 0xbebfbc70
    addw                    x9, x9, x6          # Add aux function result
    xor                     x6, x8, x17         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x9, x9, 9           # Rotate left s=23 bits
    li                      x28, 0x289b         # .Load upper half of constant 0x289b7ec6
    addw                    x9, x8, x9          # round 3 B=HH(B, C, D, A, 0xbebfbc70, s=23, M[10])
    li                      x10, 0x7ec6         # .Load lower half of constant 0x289b7ec6
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x18, x18, x26       # Add dest value
    xor                     x6, x6, x9          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x18, x18, x10       # Add constant 0x289b7ec6
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 28        # Rotate left s=4 bits
    xor                     x6, x9, x8          # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0xeaa1         # .Load upper half of constant 0xeaa127fa
    addw                    x18, x9, x18        # round 3 A=HH(A, B, C, D, 0x289b7ec6, s=4, M[13])
    li                      x10, 0x27fa         # .Load lower half of constant 0xeaa127fa
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x17, x17, x15       # Add dest value
    xor                     x6, x6, x18         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x17, x17, x10       # Add constant 0xeaa127fa
    addw                    x17, x17, x6        # Add aux function result
    xor                     x6, x18, x9         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x17, x17, 21        # Rotate left s=11 bits
    li                      x28, 0xd4ef         # .Load upper half of constant 0xd4ef3085
    addw                    x17, x18, x17       # round 3 D=HH(D, A, B, C, 0xeaa127fa, s=11, M[0])
    li                      x13, 0x3085         # .Load lower half of constant 0xd4ef3085
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x21         # Add dest value
    xor                     x6, x6, x17         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x8, x8, x13         # Add constant 0xd4ef3085
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 16          # Rotate left s=16 bits
    xor                     x6, x17, x18        # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0x488          # .Load upper half of constant 0x4881d05
    addw                    x8, x17, x8         # round 3 C=HH(C, D, A, B, 0xd4ef3085, s=16, M[3])
    li                      x13, 0x1d05         # .Load lower half of constant 0x4881d05
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x7          # Add dest value
    xor                     x6, x6, x8          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x9, x9, x13         # Add constant 0x4881d05
    addw                    x9, x9, x6          # Add aux function result
    xor                     x6, x8, x17         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x9, x9, 9           # Rotate left s=23 bits
    li                      x28, 0xd9d4         # .Load upper half of constant 0xd9d4d039
    addw                    x9, x8, x9          # round 3 B=HH(B, C, D, A, 0x4881d05, s=23, M[6])
    li                      x10, 0xd039         # .Load lower half of constant 0xd9d4d039
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x18, x18, x24       # Add dest value
    xor                     x6, x6, x9          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x18, x18, x10       # Add constant 0xd9d4d039
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 28        # Rotate left s=4 bits
    xor                     x6, x9, x8          # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0xe6db         # .Load upper half of constant 0xe6db99e5
    addw                    x18, x9, x18        # round 3 A=HH(A, B, C, D, 0xd9d4d039, s=4, M[9])
    li                      x10, 0x99e5         # .Load lower half of constant 0xe6db99e5
    slli                    x28, x28, 16
    add                     x10, x28, x10
    addw                    x17, x17, x11       # Add dest value
    xor                     x6, x6, x18         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x17, x17, x10       # Add constant 0xe6db99e5
    addw                    x17, x17, x6        # Add aux function result
    xor                     x6, x18, x9         # aux function round 3 H(x,y,z)=(x^y^z)
    roriw                   x17, x17, 21        # Rotate left s=11 bits
    li                      x28, 0x1fa2         # .Load upper half of constant 0x1fa27cf8
    addw                    x17, x18, x17       # round 3 D=HH(D, A, B, C, 0xe6db99e5, s=11, M[12])
    li                      x13, 0x7cf8         # .Load lower half of constant 0x1fa27cf8
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x8, x8, x27         # Add dest value
    xor                     x6, x6, x17         # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x8, x8, x13         # Add constant 0x1fa27cf8
    addw                    x8, x8, x6          # Add aux function result
    roriw                   x8, x8, 16          # Rotate left s=16 bits
    xor                     x6, x17, x18        # aux function round 3 H(x,y,z)=(x^y^z)
    li                      x28, 0xc4ac         # .Load upper half of constant 0xc4ac5665
    addw                    x8, x17, x8         # round 3 C=HH(C, D, A, B, 0x1fa27cf8, s=16, M[15])
    li                      x13, 0x5665         # .Load lower half of constant 0xc4ac5665
    slli                    x28, x28, 16
    add                     x13, x28, x13
    addw                    x9, x9, x31         # Add dest value
    xor                     x6, x6, x8          # End aux function round 3 H(x,y,z)=(x^y^z)
    addw                    x9, x9, x13         # Add constant 0xc4ac5665
    addw                    x9, x9, x6          # Add aux function result
    roriw                   x9, x9, 9           # Rotate left s=23 bits
    li                      x28, 0xf429         # .Load upper half of constant 0xf4292244
    li                      x6, 0x2244          # .Load lower half of constant 0xf4292244
    slli                    x28, x28, 16
    add                     x6, x28, x6
    addw                    x9, x8, x9          # round 3 B=HH(B, C, D, A, 0xc4ac5665, s=23, M[2])
    addw                    x18, x18, x15       # Add dest value
    orn                     x13, x9, x17        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x18, x18, x6        # Add constant 0xf4292244
    xor                     x6, x8, x13         # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x18, x18, x6        # Add aux function result
    roriw                   x18, x18, 26        # Rotate left s=6 bits
    li                      x28, 0x432a         # .Load upper half of constant 0x432aff97
    li                      x6, 0xff97          # .Load lower half of constant 0x432aff97
    slli                    x28, x28, 16
    add                     x6, x28, x6
    addw                    x18, x9, x18        # round 4 A=II(A, B, C, D, 0xf4292244, s=6, M[0])
    orn                     x10, x18, x8        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x17, x17, x23       # Add dest value
    xor                     x10, x9, x10        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x17, x17, x6        # Add constant 0x432aff97
    addw                    x6, x17, x10        # Add aux function result
    roriw                   x6, x6, 22          # Rotate left s=10 bits
    li                      x28, 0xab94         # .Load upper half of constant 0xab9423a7
    li                      x17, 0x23a7         # .Load lower half of constant 0xab9423a7
    slli                    x28, x28, 16
    add                     x17, x28, x17
    addw                    x6, x18, x6         # round 4 D=II(D, A, B, C, 0x432aff97, s=10, M[7])
    addw                    x8, x8, x12         # Add dest value
    orn                     x10, x6, x9         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x8, x8, x17         # Add constant 0xab9423a7
    xor                     x17, x18, x10       # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x8, x8, x17         # Add aux function result
    roriw                   x8, x8, 17          # Rotate left s=15 bits
    li                      x28, 0xfc93         # .Load upper half of constant 0xfc93a039
    li                      x17, 0xa039         # .Load lower half of constant 0xfc93a039
    slli                    x28, x28, 16
    add                     x17, x28, x17
    addw                    x8, x6, x8          # round 4 C=II(C, D, A, B, 0xab9423a7, s=15, M[14])
    orn                     x13, x8, x18        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x9, x9, x22         # Add dest value
    xor                     x13, x6, x13        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x9, x9, x17         # Add constant 0xfc93a039
    addw                    x17, x9, x13        # Add aux function result
    roriw                   x17, x17, 11        # Rotate left s=21 bits
    li                      x28, 0x655b         # .Load upper half of constant 0x655b59c3
    li                      x9, 0x59c3          # .Load lower half of constant 0x655b59c3
    slli                    x28, x28, 16
    add                     x9, x28, x9
    addw                    x17, x8, x17        # round 4 B=II(B, C, D, A, 0xfc93a039, s=21, M[5])
    addw                    x18, x18, x11       # Add dest value
    orn                     x13, x17, x6        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x9, x18, x9         # Add constant 0x655b59c3
    xor                     x18, x8, x13        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x9, x9, x18         # Add aux function result
    roriw                   x9, x9, 26          # Rotate left s=6 bits
    li                      x28, 0x8f0c         # .Load upper half of constant 0x8f0ccc92
    li                      x18, 0xcc92         # .Load lower half of constant 0x8f0ccc92
    slli                    x28, x28, 16
    add                     x18, x28, x18
    addw                    x9, x17, x9         # round 4 A=II(A, B, C, D, 0x655b59c3, s=6, M[12])
    orn                     x10, x9, x8         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x6, x6, x21         # Add dest value
    xor                     x10, x17, x10       # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x18, x6, x18        # Add constant 0x8f0ccc92
    addw                    x6, x18, x10        # Add aux function result
    roriw                   x6, x6, 22          # Rotate left s=10 bits
    li                      x28, 0xffef         # .Load upper half of constant 0xffeff47d
    li                      x18, 0xf47d         # .Load lower half of constant 0xffeff47d
    slli                    x28, x28, 16
    add                     x18, x28, x18
    addw                    x6, x9, x6          # round 4 D=II(D, A, B, C, 0x8f0ccc92, s=10, M[3])
    addw                    x8, x8, x16         # Add dest value
    orn                     x10, x6, x17        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x8, x8, x18         # Add constant 0xffeff47d
    xor                     x18, x9, x10        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x8, x8, x18         # Add aux function result
    roriw                   x8, x8, 17          # Rotate left s=15 bits
    li                      x28, 0x8584         # .Load upper half of constant 0x85845dd1
    li                      x18, 0x5dd1         # .Load lower half of constant 0x85845dd1
    slli                    x28, x28, 16
    add                     x18, x28, x18
    addw                    x8, x6, x8          # round 4 C=II(C, D, A, B, 0xffeff47d, s=15, M[10])
    orn                     x10, x8, x9         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x15, x17, x20       # Add dest value
    xor                     x17, x6, x10        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x15, x15, x18       # Add constant 0x85845dd1
    addw                    x18, x15, x17       # Add aux function result
    roriw                   x18, x18, 11        # Rotate left s=21 bits
    li                      x28, 0x6fa8         # .Load upper half of constant 0x6fa87e4f
    li                      x15, 0x7e4f         # .Load lower half of constant 0x6fa87e4f
    slli                    x28, x28, 16
    add                     x15, x28, x15
    addw                    x17, x8, x18        # round 4 B=II(B, C, D, A, 0x85845dd1, s=21, M[1])
    addw                    x18, x9, x5         # Add dest value
    orn                     x9, x17, x6         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x15, x18, x15       # Add constant 0x6fa87e4f
    xor                     x18, x8, x9         # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x9, x15, x18        # Add aux function result
    roriw                   x9, x9, 26          # Rotate left s=6 bits
    li                      x28, 0xfe2c         # .Load upper half of constant 0xfe2ce6e0
    li                      x15, 0xe6e0         # .Load lower half of constant 0xfe2ce6e0
    slli                    x28, x28, 16
    add                     x15, x28, x15
    addw                    x18, x17, x9        # round 4 A=II(A, B, C, D, 0x6fa87e4f, s=6, M[8])
    orn                     x9, x18, x8         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x6, x6, x27         # Add dest value
    xor                     x9, x17, x9         # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x15, x6, x15        # Add constant 0xfe2ce6e0
    addw                    x6, x15, x9         # Add aux function result
    roriw                   x6, x6, 22          # Rotate left s=10 bits
    li                      x28, 0xa301         # .Load upper half of constant 0xa3014314
    li                      x9, 0x4314          # .Load lower half of constant 0xa3014314
    slli                    x28, x28, 16
    add                     x9, x28, x9
    addw                    x15, x18, x6        # round 4 D=II(D, A, B, C, 0xfe2ce6e0, s=10, M[15])
    addw                    x6, x8, x7          # Add dest value
    orn                     x7, x15, x17        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x8, x6, x9          # Add constant 0xa3014314
    xor                     x9, x18, x7         # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x6, x8, x9          # Add aux function result
    roriw                   x6, x6, 17          # Rotate left s=15 bits
    li                      x28, 0x4e08         # .Load upper half of constant 0x4e0811a1
    li                      x7, 0x11a1          # .Load lower half of constant 0x4e0811a1
    slli                    x28, x28, 16
    add                     x7, x28, x7
    addw                    x8, x15, x6         # round 4 C=II(C, D, A, B, 0xa3014314, s=15, M[6])
    orn                     x9, x8, x18         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x6, x17, x26        # Add dest value
    xor                     x17, x15, x9        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x9, x6, x7          # Add constant 0x4e0811a1
    addw                    x7, x9, x17         # Add aux function result
    roriw                   x7, x7, 11          # Rotate left s=21 bits
    li                      x28, 0xf753         # .Load upper half of constant 0xf7537e82
    li                      x6, 0x7e82          # .Load lower half of constant 0xf7537e82
    slli                    x28, x28, 16
    add                     x6, x28, x6
    addw                    x9, x8, x7          # round 4 B=II(B, C, D, A, 0x4e0811a1, s=21, M[13])
    addw                    x17, x18, x14       # Add dest value
    orn                     x7, x9, x15         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x14, x17, x6        # Add constant 0xf7537e82
    xor                     x18, x8, x7         # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x17, x14, x18       # Add aux function result
    roriw                   x17, x17, 26        # Rotate left s=6 bits
    li                      x28, 0xbd3a         # .Load upper half of constant 0xbd3af235
    li                      x6, 0xf235          # .Load lower half of constant 0xbd3af235
    slli                    x28, x28, 16
    add                     x6, x28, x6
    addw                    x7, x9, x17         # round 4 A=II(A, B, C, D, 0xf7537e82, s=6, M[4])
    orn                     x14, x7, x8         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x18, x15, x25       # Add dest value
    xor                     x17, x9, x14        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x15, x18, x6        # Add constant 0xbd3af235
    addw                    x16, x15, x17       # Add aux function result
    roriw                   x16, x16, 22        # Rotate left s=10 bits
    li                      x28, 0x2ad7         # .Load upper half of constant 0x2ad7d2bb
    li                      x14, 0xd2bb         # .Load lower half of constant 0x2ad7d2bb
    slli                    x28, x28, 16
    add                     x14, x28, x14
    addw                    x18, x7, x16        # round 4 D=II(D, A, B, C, 0xbd3af235, s=10, M[11])
    addw                    x6, x8, x31         # Add dest value
    orn                     x15, x18, x9        # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x17, x6, x14        # Add constant 0x2ad7d2bb
    xor                     x16, x7, x15        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x8, x17, x16        # Add aux function result
    roriw                   x8, x8, 17          # Rotate left s=15 bits
    li                      x28, 0xeb86         # .Load upper half of constant 0xeb86d391
    li                      x31, 0xd391         # .Load lower half of constant 0xeb86d391
    slli                    x28, x28, 16
    add                     x31, x28, x31
    addw                    x14, x18, x8        # round 4 C=II(C, D, A, B, 0x2ad7d2bb, s=15, M[2])
    orn                     x6, x14, x7         # aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x15, x9, x24        # Add dest value
    xor                     x17, x18, x6        # End aux function round 4 I(x,y,z)=((~z|x)^y)
    addw                    x16, x15, x31       # Add constant 0xeb86d391
    addw                    x8, x16, x17        # Add aux function result
    roriw                   x8, x8, 11          # Rotate left s=21 bits
    lw                      x6, 0(x29)          # Reload MD5 state->A
    lw                      x15, 4(x29)         # Reload MD5 state->B
    lw                      x5,  8(x29)         # Reload MD5 state->C
    lw                      x9, 12(x29)         # Reload MD5 state->D

    fmv.x.d                 x23, ft0
    addw                    x31, x14, x8        # round 4 B=II(B, C, D, A, 0xeb86d391, s=21, M[9])
    addw                    x13, x18, x9        # Add result of MD5 rounds to state->D
    addw                    x12, x14, x5        # Add result of MD5 rounds to state->C
    addw                    x10, x7, x6         # Add result of MD5 rounds to state->A
    addw                    x11, x31, x15       # Add result of MD5 rounds to state->B
    sw                      x12, 8(x29)         # Store MD5 states C
    sw                      x13, 12(x29)        # Store MD5 states D
    sw                      x10, 0(x29)         # Store MD5 states A
    sw                      x11, 4(x29)         # Store MD5 states B
    addi                    x30, x30, 64        # Increment data pointer
    addi                    x23, x23, -1          # Decrement block counter
    fmv.d.x                 ft0, x23
    bnez                    x23, _MD5_LOOP


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


.MD5_END:
    ret
.size ossl_md5_block_asm_data_order,.-ossl_md5_block_asm_data_order
___

print $code;

close STDOUT or die "error closing STDOUT: $!";