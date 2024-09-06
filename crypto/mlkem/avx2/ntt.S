#include "consts.h"
.include "shuffle.inc"

.macro mul rh0,rh1,rh2,rh3,zl0=15,zl1=15,zh0=2,zh1=2
vpmullw		%ymm\zl0,%ymm\rh0,%ymm12
vpmullw		%ymm\zl0,%ymm\rh1,%ymm13

vpmullw		%ymm\zl1,%ymm\rh2,%ymm14
vpmullw		%ymm\zl1,%ymm\rh3,%ymm15

vpmulhw		%ymm\zh0,%ymm\rh0,%ymm\rh0
vpmulhw		%ymm\zh0,%ymm\rh1,%ymm\rh1

vpmulhw		%ymm\zh1,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm\zh1,%ymm\rh3,%ymm\rh3
.endm

.macro reduce
vpmulhw		%ymm0,%ymm12,%ymm12
vpmulhw		%ymm0,%ymm13,%ymm13

vpmulhw		%ymm0,%ymm14,%ymm14
vpmulhw		%ymm0,%ymm15,%ymm15
.endm

.macro update rln,rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rln
vpsubw		%ymm\rh0,%ymm\rl0,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl0

vpsubw		%ymm\rh1,%ymm\rl1,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl1
vpsubw		%ymm\rh2,%ymm\rl2,%ymm\rh2

vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl2
vpsubw		%ymm\rh3,%ymm\rl3,%ymm\rh3

vpsubw		%ymm12,%ymm\rln,%ymm\rln
vpaddw		%ymm12,%ymm\rh0,%ymm\rh0
vpsubw		%ymm13,%ymm\rl0,%ymm\rl0

vpaddw		%ymm13,%ymm\rh1,%ymm\rh1
vpsubw		%ymm14,%ymm\rl1,%ymm\rl1
vpaddw		%ymm14,%ymm\rh2,%ymm\rh2

vpsubw		%ymm15,%ymm\rl2,%ymm\rl2
vpaddw		%ymm15,%ymm\rh3,%ymm\rh3
.endm

.macro level0 off
vpbroadcastq	(_ZETAS_EXP+0)*2(%rsi),%ymm15
vmovdqa		(64*\off+128)*2(%rdi),%ymm8
vmovdqa		(64*\off+144)*2(%rdi),%ymm9
vmovdqa		(64*\off+160)*2(%rdi),%ymm10
vmovdqa		(64*\off+176)*2(%rdi),%ymm11
vpbroadcastq	(_ZETAS_EXP+4)*2(%rsi),%ymm2

mul		8,9,10,11

vmovdqa		(64*\off+  0)*2(%rdi),%ymm4
vmovdqa		(64*\off+ 16)*2(%rdi),%ymm5
vmovdqa		(64*\off+ 32)*2(%rdi),%ymm6
vmovdqa		(64*\off+ 48)*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

vmovdqa		%ymm3,(64*\off+  0)*2(%rdi)
vmovdqa		%ymm4,(64*\off+ 16)*2(%rdi)
vmovdqa		%ymm5,(64*\off+ 32)*2(%rdi)
vmovdqa		%ymm6,(64*\off+ 48)*2(%rdi)
vmovdqa		%ymm8,(64*\off+128)*2(%rdi)
vmovdqa		%ymm9,(64*\off+144)*2(%rdi)
vmovdqa		%ymm10,(64*\off+160)*2(%rdi)
vmovdqa		%ymm11,(64*\off+176)*2(%rdi)
.endm

.macro levels1t6 off
/* level 1 */
vmovdqa		(_ZETAS_EXP+224*\off+16)*2(%rsi),%ymm15
vmovdqa		(128*\off+ 64)*2(%rdi),%ymm8
vmovdqa		(128*\off+ 80)*2(%rdi),%ymm9
vmovdqa		(128*\off+ 96)*2(%rdi),%ymm10
vmovdqa		(128*\off+112)*2(%rdi),%ymm11
vmovdqa		(_ZETAS_EXP+224*\off+32)*2(%rsi),%ymm2

mul		8,9,10,11

vmovdqa		(128*\off+  0)*2(%rdi),%ymm4
vmovdqa	 	(128*\off+ 16)*2(%rdi),%ymm5
vmovdqa		(128*\off+ 32)*2(%rdi),%ymm6
vmovdqa		(128*\off+ 48)*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

/* level 2 */
shuffle8	5,10,7,10
shuffle8	6,11,5,11

vmovdqa		(_ZETAS_EXP+224*\off+48)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+64)*2(%rsi),%ymm2

mul		7,10,5,11

shuffle8	3,8,6,8
shuffle8	4,9,3,9

reduce
update		4,6,8,3,9,7,10,5,11

/* level 3 */
shuffle4	8,5,9,5
shuffle4	3,11,8,11

vmovdqa		(_ZETAS_EXP+224*\off+80)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+96)*2(%rsi),%ymm2

mul		9,5,8,11

shuffle4	4,7,3,7
shuffle4	6,10,4,10

reduce
update		6,3,7,4,10,9,5,8,11

/* level 4 */
shuffle2	7,8,10,8
shuffle2	4,11,7,11

vmovdqa		(_ZETAS_EXP+224*\off+112)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+128)*2(%rsi),%ymm2

mul		10,8,7,11

shuffle2	6,9,4,9
shuffle2	3,5,6,5

reduce
update		3,4,9,6,5,10,8,7,11

/* level 5 */
shuffle1	9,7,5,7
shuffle1	6,11,9,11

vmovdqa		(_ZETAS_EXP+224*\off+144)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+160)*2(%rsi),%ymm2

mul		5,7,9,11

shuffle1	3,10,6,10
shuffle1	4,8,3,8

reduce
update		4,6,10,3,8,5,7,9,11

/* level 6 */
vmovdqa		(_ZETAS_EXP+224*\off+176)*2(%rsi),%ymm14
vmovdqa		(_ZETAS_EXP+224*\off+208)*2(%rsi),%ymm15
vmovdqa		(_ZETAS_EXP+224*\off+192)*2(%rsi),%ymm8
vmovdqa		(_ZETAS_EXP+224*\off+224)*2(%rsi),%ymm2

mul		10,3,9,11,14,15,8,2

reduce
update		8,4,6,5,7,10,3,9,11

vmovdqa		%ymm8,(128*\off+  0)*2(%rdi)
vmovdqa		%ymm4,(128*\off+ 16)*2(%rdi)
vmovdqa		%ymm10,(128*\off+ 32)*2(%rdi)
vmovdqa		%ymm3,(128*\off+ 48)*2(%rdi)
vmovdqa		%ymm6,(128*\off+ 64)*2(%rdi)
vmovdqa		%ymm5,(128*\off+ 80)*2(%rdi)
vmovdqa		%ymm9,(128*\off+ 96)*2(%rdi)
vmovdqa		%ymm11,(128*\off+112)*2(%rdi)
.endm

.text
.global cdecl(ntt_avx)
cdecl(ntt_avx):
vmovdqa		_16XQ*2(%rsi),%ymm0

level0		0
level0		1

levels1t6	0
levels1t6	1

ret
