#include "consts.h"

.macro schoolbook off
vmovdqa		_16XQINV*2(%rcx),%ymm0
vmovdqa		(64*\off+ 0)*2(%rsi),%ymm1		# a0
vmovdqa		(64*\off+16)*2(%rsi),%ymm2		# b0
vmovdqa		(64*\off+32)*2(%rsi),%ymm3		# a1
vmovdqa		(64*\off+48)*2(%rsi),%ymm4		# b1

vpmullw		%ymm0,%ymm1,%ymm9			# a0.lo
vpmullw		%ymm0,%ymm2,%ymm10			# b0.lo
vpmullw		%ymm0,%ymm3,%ymm11			# a1.lo
vpmullw		%ymm0,%ymm4,%ymm12			# b1.lo

vmovdqa		(64*\off+ 0)*2(%rdx),%ymm5		# c0
vmovdqa		(64*\off+16)*2(%rdx),%ymm6		# d0

vpmulhw		%ymm5,%ymm1,%ymm13			# a0c0.hi
vpmulhw		%ymm6,%ymm1,%ymm1			# a0d0.hi
vpmulhw		%ymm5,%ymm2,%ymm14			# b0c0.hi
vpmulhw		%ymm6,%ymm2,%ymm2			# b0d0.hi

vmovdqa		(64*\off+32)*2(%rdx),%ymm7		# c1
vmovdqa		(64*\off+48)*2(%rdx),%ymm8		# d1

vpmulhw		%ymm7,%ymm3,%ymm15			# a1c1.hi
vpmulhw		%ymm8,%ymm3,%ymm3			# a1d1.hi
vpmulhw		%ymm7,%ymm4,%ymm0			# b1c1.hi
vpmulhw		%ymm8,%ymm4,%ymm4			# b1d1.hi

vmovdqa		%ymm13,(%rsp)

vpmullw		%ymm5,%ymm9,%ymm13			# a0c0.lo
vpmullw		%ymm6,%ymm9,%ymm9			# a0d0.lo
vpmullw		%ymm5,%ymm10,%ymm5			# b0c0.lo
vpmullw		%ymm6,%ymm10,%ymm10			# b0d0.lo

vpmullw		%ymm7,%ymm11,%ymm6			# a1c1.lo
vpmullw		%ymm8,%ymm11,%ymm11			# a1d1.lo
vpmullw		%ymm7,%ymm12,%ymm7			# b1c1.lo
vpmullw		%ymm8,%ymm12,%ymm12			# b1d1.lo

vmovdqa		_16XQ*2(%rcx),%ymm8
vpmulhw		%ymm8,%ymm13,%ymm13
vpmulhw		%ymm8,%ymm9,%ymm9
vpmulhw		%ymm8,%ymm5,%ymm5
vpmulhw		%ymm8,%ymm10,%ymm10
vpmulhw		%ymm8,%ymm6,%ymm6
vpmulhw		%ymm8,%ymm11,%ymm11
vpmulhw		%ymm8,%ymm7,%ymm7
vpmulhw		%ymm8,%ymm12,%ymm12

vpsubw		(%rsp),%ymm13,%ymm13			# -a0c0
vpsubw		%ymm9,%ymm1,%ymm9			# a0d0
vpsubw		%ymm5,%ymm14,%ymm5			# b0c0
vpsubw		%ymm10,%ymm2,%ymm10			# b0d0

vpsubw		%ymm6,%ymm15,%ymm6			# a1c1
vpsubw		%ymm11,%ymm3,%ymm11			# a1d1
vpsubw		%ymm7,%ymm0,%ymm7			# b1c1
vpsubw		%ymm12,%ymm4,%ymm12			# b1d1

vmovdqa		(%r9),%ymm0
vmovdqa		32(%r9),%ymm1
vpmullw		%ymm0,%ymm10,%ymm2
vpmullw		%ymm0,%ymm12,%ymm3
vpmulhw		%ymm1,%ymm10,%ymm10
vpmulhw		%ymm1,%ymm12,%ymm12
vpmulhw		%ymm8,%ymm2,%ymm2
vpmulhw		%ymm8,%ymm3,%ymm3
vpsubw		%ymm2,%ymm10,%ymm10			# rb0d0
vpsubw		%ymm3,%ymm12,%ymm12			# rb1d1

vpaddw		%ymm5,%ymm9,%ymm9
vpaddw		%ymm7,%ymm11,%ymm11
vpsubw		%ymm13,%ymm10,%ymm13
vpsubw		%ymm12,%ymm6,%ymm6

vmovdqa		%ymm13,(64*\off+ 0)*2(%rdi)
vmovdqa		%ymm9,(64*\off+16)*2(%rdi)
vmovdqa		%ymm6,(64*\off+32)*2(%rdi)
vmovdqa		%ymm11,(64*\off+48)*2(%rdi)
.endm

.text
.global cdecl(basemul_avx)
cdecl(basemul_avx):
mov		%rsp,%r8
and		$-32,%rsp
sub		$32,%rsp

lea		(_ZETAS_EXP+176)*2(%rcx),%r9
schoolbook	0

add		$32*2,%r9
schoolbook	1

add		$192*2,%r9
schoolbook	2

add		$32*2,%r9
schoolbook	3

mov		%r8,%rsp
ret
