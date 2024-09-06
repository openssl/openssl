#include "consts.h"
.include "fq.inc"
.include "shuffle.inc"

/*
nttpack_avx:
#load
vmovdqa		(%rdi),%ymm4
vmovdqa		32(%rdi),%ymm5
vmovdqa		64(%rdi),%ymm6
vmovdqa		96(%rdi),%ymm7
vmovdqa		128(%rdi),%ymm8
vmovdqa		160(%rdi),%ymm9
vmovdqa		192(%rdi),%ymm10
vmovdqa		224(%rdi),%ymm11

shuffle1	4,5,3,5
shuffle1	6,7,4,7
shuffle1	8,9,6,9
shuffle1	10,11,8,11

shuffle2	3,4,10,4
shuffle2	6,8,3,8
shuffle2	5,7,6,7
shuffle2	9,11,5,11

shuffle4	10,3,9,3
shuffle4	6,5,10,5
shuffle4	4,8,6,8
shuffle4	7,11,4,11

shuffle8	9,10,7,10
shuffle8	6,4,9,4
shuffle8	3,5,6,5
shuffle8	8,11,3,11

#store
vmovdqa		%ymm7,(%rdi)
vmovdqa		%ymm9,32(%rdi)
vmovdqa		%ymm6,64(%rdi)
vmovdqa		%ymm3,96(%rdi)
vmovdqa		%ymm10,128(%rdi)
vmovdqa		%ymm4,160(%rdi)
vmovdqa		%ymm5,192(%rdi)
vmovdqa		%ymm11,224(%rdi)

ret
*/

.text
nttunpack128_avx:
#load
vmovdqa		(%rdi),%ymm4
vmovdqa		32(%rdi),%ymm5
vmovdqa		64(%rdi),%ymm6
vmovdqa		96(%rdi),%ymm7
vmovdqa		128(%rdi),%ymm8
vmovdqa		160(%rdi),%ymm9
vmovdqa		192(%rdi),%ymm10
vmovdqa		224(%rdi),%ymm11

shuffle8	4,8,3,8
shuffle8	5,9,4,9
shuffle8	6,10,5,10
shuffle8	7,11,6,11

shuffle4	3,5,7,5
shuffle4	8,10,3,10
shuffle4	4,6,8,6
shuffle4	9,11,4,11

shuffle2	7,8,9,8
shuffle2	5,6,7,6
shuffle2	3,4,5,4
shuffle2	10,11,3,11

shuffle1	9,5,10,5
shuffle1	8,4,9,4
shuffle1	7,3,8,3
shuffle1	6,11,7,11

#store
vmovdqa		%ymm10,(%rdi)
vmovdqa		%ymm5,32(%rdi)
vmovdqa		%ymm9,64(%rdi)
vmovdqa		%ymm4,96(%rdi)
vmovdqa		%ymm8,128(%rdi)
vmovdqa		%ymm3,160(%rdi)
vmovdqa		%ymm7,192(%rdi)
vmovdqa		%ymm11,224(%rdi)

ret

.global cdecl(nttunpack_avx)
cdecl(nttunpack_avx):
call		nttunpack128_avx
add		$256,%rdi
call		nttunpack128_avx
ret

ntttobytes128_avx:
#load
vmovdqa		(%rsi),%ymm5
vmovdqa		32(%rsi),%ymm6
vmovdqa		64(%rsi),%ymm7
vmovdqa		96(%rsi),%ymm8
vmovdqa		128(%rsi),%ymm9
vmovdqa		160(%rsi),%ymm10
vmovdqa		192(%rsi),%ymm11
vmovdqa		224(%rsi),%ymm12

#csubq
csubq		5,13
csubq		6,13
csubq		7,13
csubq		8,13
csubq		9,13
csubq		10,13
csubq		11,13
csubq		12,13

#bitpack
vpsllw		$12,%ymm6,%ymm4
vpor		%ymm4,%ymm5,%ymm4

vpsrlw		$4,%ymm6,%ymm5
vpsllw		$8,%ymm7,%ymm6
vpor		%ymm5,%ymm6,%ymm5

vpsrlw		$8,%ymm7,%ymm6
vpsllw		$4,%ymm8,%ymm7
vpor		%ymm6,%ymm7,%ymm6

vpsllw		$12,%ymm10,%ymm7
vpor		%ymm7,%ymm9,%ymm7

vpsrlw		$4,%ymm10,%ymm8
vpsllw		$8,%ymm11,%ymm9
vpor		%ymm8,%ymm9,%ymm8

vpsrlw		$8,%ymm11,%ymm9
vpsllw		$4,%ymm12,%ymm10
vpor		%ymm9,%ymm10,%ymm9

shuffle1	4,5,3,5
shuffle1	6,7,4,7
shuffle1	8,9,6,9

shuffle2	3,4,8,4
shuffle2	6,5,3,5
shuffle2	7,9,6,9

shuffle4	8,3,7,3
shuffle4	6,4,8,4
shuffle4	5,9,6,9

shuffle8	7,8,5,8
shuffle8	6,3,7,3
shuffle8	4,9,6,9

#store
vmovdqu		%ymm5,(%rdi)
vmovdqu		%ymm7,32(%rdi)
vmovdqu		%ymm6,64(%rdi)
vmovdqu		%ymm8,96(%rdi)
vmovdqu		%ymm3,128(%rdi)
vmovdqu		%ymm9,160(%rdi)

ret

.global cdecl(ntttobytes_avx)
cdecl(ntttobytes_avx):
#consts
vmovdqa		_16XQ*2(%rdx),%ymm0
call		ntttobytes128_avx
add		$256,%rsi
add		$192,%rdi
call		ntttobytes128_avx
ret

nttfrombytes128_avx:
#load
vmovdqu		(%rsi),%ymm4
vmovdqu		32(%rsi),%ymm5
vmovdqu		64(%rsi),%ymm6
vmovdqu		96(%rsi),%ymm7
vmovdqu		128(%rsi),%ymm8
vmovdqu		160(%rsi),%ymm9

shuffle8	4,7,3,7
shuffle8	5,8,4,8
shuffle8	6,9,5,9

shuffle4	3,8,6,8
shuffle4	7,5,3,5
shuffle4	4,9,7,9

shuffle2	6,5,4,5
shuffle2	8,7,6,7
shuffle2	3,9,8,9

shuffle1	4,7,10,7
shuffle1	5,8,4,8
shuffle1	6,9,5,9

#bitunpack
vpsrlw		$12,%ymm10,%ymm11
vpsllw		$4,%ymm7,%ymm12
vpor		%ymm11,%ymm12,%ymm11
vpand		%ymm0,%ymm10,%ymm10
vpand		%ymm0,%ymm11,%ymm11

vpsrlw		$8,%ymm7,%ymm12
vpsllw		$8,%ymm4,%ymm13
vpor		%ymm12,%ymm13,%ymm12
vpand		%ymm0,%ymm12,%ymm12

vpsrlw		$4,%ymm4,%ymm13
vpand		%ymm0,%ymm13,%ymm13

vpsrlw		$12,%ymm8,%ymm14
vpsllw		$4,%ymm5,%ymm15
vpor		%ymm14,%ymm15,%ymm14
vpand		%ymm0,%ymm8,%ymm8
vpand		%ymm0,%ymm14,%ymm14

vpsrlw		$8,%ymm5,%ymm15
vpsllw		$8,%ymm9,%ymm1
vpor		%ymm15,%ymm1,%ymm15
vpand		%ymm0,%ymm15,%ymm15

vpsrlw		$4,%ymm9,%ymm1
vpand		%ymm0,%ymm1,%ymm1

#store
vmovdqa		%ymm10,(%rdi)
vmovdqa		%ymm11,32(%rdi)
vmovdqa		%ymm12,64(%rdi)
vmovdqa		%ymm13,96(%rdi)
vmovdqa		%ymm8,128(%rdi)
vmovdqa		%ymm14,160(%rdi)
vmovdqa		%ymm15,192(%rdi)
vmovdqa		%ymm1,224(%rdi)

ret

.global cdecl(nttfrombytes_avx)
cdecl(nttfrombytes_avx):
#consts
vmovdqa		_16XMASK*2(%rdx),%ymm0
call		nttfrombytes128_avx
add		$256,%rdi
add		$192,%rsi
call		nttfrombytes128_avx
ret
