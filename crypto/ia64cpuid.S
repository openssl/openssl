// Works on all IA-64 platforms: Linux, HP-UX, Win64i...
// On Win64i compile with ias.exe.
.text
.global	OPENSSL_rdtsc#
.proc	OPENSSL_rdtsc#
OPENSSL_rdtsc:
	mov	r8=ar.itc
	br.ret	b0
.endp   OPENSSL_rdtsc#
