
#define TYPE(a,b)	.type	a,b
#define SIZE(a,b)	.size	a,b

#ifdef OUT
#define OK		1
#define des_SPtrans	_des_SPtrans
#define des_encrypt	_des_encrypt
#define des_encrypt2	_des_encrypt2
#define des_encrypt3	_des_encrypt3
#define des_decrypt3	_des_decrypt3
#define ALIGN		4
#endif

#ifdef BSDI
#define OK		1
#define des_SPtrans	_des_SPtrans
#define des_encrypt	_des_encrypt
#define des_encrypt2	_des_encrypt2
#define des_encrypt3	_des_encrypt3
#define des_decrypt3	_des_decrypt3
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

#include "dx86-cpp.s" 

