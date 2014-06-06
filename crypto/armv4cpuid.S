#include "arm_arch.h"

.text
.code	32

.align	5
.global	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	.byte	0xf0,0x01,0x60,0xf2	@ vorr	q8,q8,q8
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv7_neon_probe,.-_armv7_neon_probe

.global	_armv7_tick
.type	_armv7_tick,%function
_armv7_tick:
	mrrc	p15,1,r0,r1,c14		@ CNTVCT
#if __ARM_ARCH__>=5
	bx	lr
#else
	.word	0xe12fff1e		@ bx	lr
#endif
.size	_armv7_tick,.-_armv7_tick

.global	_armv8_aes_probe
.type	_armv8_aes_probe,%function
_armv8_aes_probe:
	.byte	0x00,0x03,0xb0,0xf3	@ aese.8	q0,q0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv8_aes_probe,.-_armv8_aes_probe

.global	_armv8_sha1_probe
.type	_armv8_sha1_probe,%function
_armv8_sha1_probe:
	.byte	0x40,0x0c,0x00,0xf2	@ sha1c.32	q0,q0,q0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv8_sha1_probe,.-_armv8_sha1_probe

.global	_armv8_sha256_probe
.type	_armv8_sha256_probe,%function
_armv8_sha256_probe:
	.byte	0x40,0x0c,0x00,0xf3	@ sha256h.32	q0,q0,q0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx lr
.size	_armv8_sha256_probe,.-_armv8_sha256_probe
.global	_armv8_pmull_probe
.type	_armv8_pmull_probe,%function
_armv8_pmull_probe:
	.byte	0x00,0x0e,0xa0,0xf2	@ vmull.p64	q0,d0,d0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv8_pmull_probe,.-_armv8_pmull_probe

.align	5
.global	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,%function
OPENSSL_atomic_add:
#if __ARM_ARCH__>=6
.Ladd:	ldrex	r2,[r0]
	add	r3,r2,r1
	strex	r2,r3,[r0]
	cmp	r2,#0
	bne	.Ladd
	mov	r0,r3
	bx	lr
#else
	stmdb	sp!,{r4-r6,lr}
	ldr	r2,.Lspinlock
	adr	r3,.Lspinlock
	mov	r4,r0
	mov	r5,r1
	add	r6,r3,r2	@ &spinlock
	b	.+8
.Lspin:	bl	sched_yield
	mov	r0,#-1
	swp	r0,r0,[r6]
	cmp	r0,#0
	bne	.Lspin

	ldr	r2,[r4]
	add	r2,r2,r5
	str	r2,[r4]
	str	r0,[r6]		@ release spinlock
	ldmia	sp!,{r4-r6,lr}
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_atomic_add,.-OPENSSL_atomic_add

.global	OPENSSL_cleanse
.type	OPENSSL_cleanse,%function
OPENSSL_cleanse:
	eor	ip,ip,ip
	cmp	r1,#7
	subhs	r1,r1,#4
	bhs	.Lot
	cmp	r1,#0
	beq	.Lcleanse_done
.Little:
	strb	ip,[r0],#1
	subs	r1,r1,#1
	bhi	.Little
	b	.Lcleanse_done

.Lot:	tst	r0,#3
	beq	.Laligned
	strb	ip,[r0],#1
	sub	r1,r1,#1
	b	.Lot
.Laligned:
	str	ip,[r0],#4
	subs	r1,r1,#4
	bhs	.Laligned
	adds	r1,r1,#4
	bne	.Little
.Lcleanse_done:
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_cleanse,.-OPENSSL_cleanse

.global	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,%function
OPENSSL_wipe_cpu:
	ldr	r0,.LOPENSSL_armcap
	adr	r1,.LOPENSSL_armcap
	ldr	r0,[r1,r0]
	eor	r2,r2,r2
	eor	r3,r3,r3
	eor	ip,ip,ip
	tst	r0,#1
	beq	.Lwipe_done
	.byte	0x50,0x01,0x00,0xf3	@ veor	q0, q0, q0
	.byte	0x52,0x21,0x02,0xf3	@ veor	q1, q1, q1
	.byte	0x54,0x41,0x04,0xf3	@ veor	q2, q2, q2
	.byte	0x56,0x61,0x06,0xf3	@ veor	q3, q3, q3
	.byte	0xf0,0x01,0x40,0xf3	@ veor	q8, q8, q8
	.byte	0xf2,0x21,0x42,0xf3	@ veor	q9, q9, q9
	.byte	0xf4,0x41,0x44,0xf3	@ veor	q10, q10, q10
	.byte	0xf6,0x61,0x46,0xf3	@ veor	q11, q11, q11
	.byte	0xf8,0x81,0x48,0xf3	@ veor	q12, q12, q12
	.byte	0xfa,0xa1,0x4a,0xf3	@ veor	q13, q13, q13
	.byte	0xfc,0xc1,0x4c,0xf3	@ veor	q14, q14, q14
	.byte	0xfe,0xe1,0x4e,0xf3	@ veor	q14, q14, q14
.Lwipe_done:
	mov	r0,sp
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu

.global	OPENSSL_instrument_bus
.type	OPENSSL_instrument_bus,%function
OPENSSL_instrument_bus:
	eor	r0,r0,r0
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_instrument_bus,.-OPENSSL_instrument_bus

.global	OPENSSL_instrument_bus2
.type	OPENSSL_instrument_bus2,%function
OPENSSL_instrument_bus2:
	eor	r0,r0,r0
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
	.word	0xe12fff1e	@ bx	lr
#endif
.size	OPENSSL_instrument_bus2,.-OPENSSL_instrument_bus2

.align	5
.LOPENSSL_armcap:
.word	OPENSSL_armcap_P-.LOPENSSL_armcap
#if __ARM_ARCH__>=6
.align	5
#else
.Lspinlock:
.word	atomic_add_spinlock-.Lspinlock
.align	5

.data
.align	2
atomic_add_spinlock:
.word	0
#endif

.comm	OPENSSL_armcap_P,4,4
.hidden	OPENSSL_armcap_P
