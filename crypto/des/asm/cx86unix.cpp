
#define TYPE(a,b)	.type	a,b
#define SIZE(a,b)	.size	a,b

#ifdef OUT
#define OK		1
#define des_SPtrans	_des_SPtrans
#define fcrypt_body	_fcrypt_body
#define ALIGN		4
#endif

#ifdef BSDI
#define OK		1
#define des_SPtrans	_des_SPtrans
#define fcrypt_body	_fcrypt_body
#define ALIGN		4
#undef SIZE
#undef TYPE
#endif

#if defined(ELF) || defined(SOL)
#define OK		1
#define ALIGN		16
#endif

#ifndef OK
You need to define one of
ELF - elf systems - linux-elf, NetBSD and DG-UX
OUT - a.out systems - linux-a.out and FreeBSD
SOL - solaris systems, which are elf with strange comment lines
BSDI - a.out with a very primative version of as.
#endif

#include "cx86-cpp.s" 

