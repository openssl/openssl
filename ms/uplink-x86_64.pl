#!/usr/bin/env perl

$output=shift;
$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
open STDOUT,"| $^X ${dir}../crypto/perlasm/x86_64-xlate.pl $output";
push(@INC,"${dir}.");

require "uplink-common.pl";

$prefix="_lazy";

print <<___;
.text
.extern	OPENSSL_Uplink
___
for ($i=1;$i<=$N;$i++) {
print <<___;
.type	$prefix${i},\@abi-omnipotent
.align	16
$prefix${i}:
	.byte	0x48,0x83,0xEC,0x28	# sub rsp,40
	mov	%rcx,48(%rsp)
	mov	%rdx,56(%rsp)
	mov	%r8,64(%rsp)
	mov	%r9,72(%rsp)
	lea	OPENSSL_UplinkTable(%rip),%rcx
	mov	\$$i,%rdx
	call	OPENSSL_Uplink
	mov	48(%rsp),%rcx
	mov	56(%rsp),%rdx
	mov	64(%rsp),%r8
	mov	72(%rsp),%r9
	add	\$40,%rsp
	lea	OPENSSL_UplinkTable(%rip),%rax
	jmp	*8*$i(%rax)
$prefix${i}_end:
.size	$prefix${i},.-$prefix${i}
___
}
print <<___;
.data
.globl  OPENSSL_UplinkTable
OPENSSL_UplinkTable:
        .quad   $N
___
for ($i=1;$i<=$N;$i++) {   print "      .quad   $prefix$i\n";   }
print <<___;
.section	.pdata
___
for ($i=1;$i<=$N;$i++) {
print <<___;
	.long	$prefix${i}
	.long	$prefix${i}_end
	.long	${prefix}_unwind_info
___
}
print <<___;
.section	.xdata
${prefix}_unwind_info:
	.byte	0x01,0x04,0x01,0x00
	.byte	0x04,0x42,0x00,0x00
___
