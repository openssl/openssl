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

&external_label("OPENSSL_ia32cap");

&function_begin_B("OPENSSL_rdtsc");
	&xor	("eax","eax");
	&xor	("edx","edx");
	&picmeup("ecx","OPENSSL_ia32cap");
	&bt	(&DWP(0,"ecx"),4);
	&jnc	(&label("notsc"));
	&rdtsc	();
&set_label("notsc");
	&ret	();
&function_end_B("OPENSSL_rdtsc");

&initseg("OPENSSL_cpuid_setup") if ($main'elf);

&asm_finish();
