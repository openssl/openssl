.text

.globl	OPENSSL_s390x_facilities
.type	OPENSSL_s390x_facilities,@function
.align	16
OPENSSL_s390x_facilities:
	lghi	%r0,0
	larl	%r2,OPENSSL_s390xcap_P
	stg	%r0,8(%r2)
	.long	0xb2b02000	# stfle	0(%r2)
	brc	8,.Ldone
	lghi	%r0,1
	.long	0xb2b02000	# stfle 0(%r2)
.Ldone:
	lg	%r2,0(%r2)
	br	%r14
.size	OPENSSL_s390x_facilities,.-OPENSSL_s390x_facilities

.globl	OPENSSL_rdtsc
.type	OPENSSL_rdtsc,@function
.align	16
OPENSSL_rdtsc:
	stck	16(%r15)
	lg	%r2,16(%r15)
	br	%r14
.size	OPENSSL_rdtsc,.-OPENSSL_rdtsc

.globl	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,@function
.align	16
OPENSSL_atomic_add:
	l	%r1,0(%r2)
.Lspin:	lr	%r0,%r1
	ar	%r0,%r3
	cs	%r1,%r0,0(%r2)
	brc	4,.Lspin
	lgfr	%r2,%r0		# OpenSSL expects the new value
	br	%r14
.size	OPENSSL_atomic_add,.-OPENSSL_atomic_add

.globl	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,@function
.align	16
OPENSSL_wipe_cpu:
	xgr	%r0,%r0
	xgr	%r1,%r1
	lgr	%r2,%r15
	xgr	%r3,%r3
	xgr	%r4,%r4
	lzdr	%f0
	lzdr	%f1
	lzdr	%f2
	lzdr	%f3
	lzdr	%f4
	lzdr	%f5
	lzdr	%f6
	lzdr	%f7
	br	%r14
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu

.globl	OPENSSL_instrument_bus
.type	OPENSSL_instrument_bus,@function
.align	16
OPENSSL_instrument_bus:
	lghi	%r2,0
	br	%r14
.size	OPENSSL_instrument_bus,.-OPENSSL_instrument_bus

.globl	OPENSSL_instrument_bus2
.type	OPENSSL_instrument_bus2,@function
.align	16
OPENSSL_instrument_bus2:
	lghi	%r2,0
	br	%r14
.size	OPENSSL_instrument_bus2,.-OPENSSL_instrument_bus2

.section	.init
	brasl	%r14,OPENSSL_cpuid_setup

.comm	OPENSSL_s390xcap_P,16,8
