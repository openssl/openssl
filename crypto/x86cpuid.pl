#!/usr/bin/env perl

push(@INC,"perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],"x86cpuid");

&function_begin("OPENSSL_ia32_cpuid");
	&xor	("edx","edx");
	&pushf	();
	&pop	("eax");
	&mov	("ecx","eax");
	&xor	("eax",1<<21);
	&push	("eax");
	&popf	();
	&pushf	();
	&pop	("eax");
	&xor	("ecx","eax");
	&bt	("ecx",21);
	&jnc	(&label("nocpuid"));
	&mov	("eax",1);
	&cpuid	();
&set_label("nocpuid");
	&mov	("eax","edx");
	&mov	("edx","ecx");
&function_end("OPENSSL_ia32_cpuid");

&external_label("OPENSSL_ia32cap_P");

&function_begin_B("OPENSSL_rdtsc","EXTRN\t_OPENSSL_ia32cap_P:DWORD");
	&xor	("eax","eax");
	&xor	("edx","edx");
	&picmeup("ecx","OPENSSL_ia32cap_P");
	&bt	(&DWP(0,"ecx"),4);
	&jnc	(&label("notsc"));
	&rdtsc	();
&set_label("notsc");
	&ret	();
&function_end_B("OPENSSL_rdtsc");

# This works in Ring 0 only [read DJGPP+MS-DOS+privileged DPMI host],
# but it's safe to call it on any [supported] 32-bit platform...
# Just check for [non-]zero return value...
&function_begin_B("OPENSSL_instrument_halt","EXTRN\t_OPENSSL_ia32cap_P:DWORD");
	&picmeup("ecx","OPENSSL_ia32cap_P");
	&bt	(&DWP(0,"ecx"),4);
	&jnc	(&label("nohalt"));	# no TSC

	&data_word(0x9058900e);		# push %cs; pop %eax
	&and	("eax",3);
	&jnz	(&label("nohalt"));	# not enough privileges

	&pushf	();
	&pop	("eax")
	&bt	("eax",9);
	&jnc	(&label("nohalt"));	# interrupts are disabled

	&rdtsc	();
	&push	("edx");
	&push	("eax");
	&halt	();
	&rdtsc	();

	&sub	("eax",&DWP(0,"esp"));
	&sbb	("edx",&DWP(4,"esp"));
	&add	("esp",8);
	&ret	();

&set_label("nohalt");
	&xor	("eax","eax");
	&xor	("edx","edx");
	&ret	();
&function_end_B("OPENSSL_instrument_halt");

&initseg("OPENSSL_cpuid_setup");

&asm_finish();
