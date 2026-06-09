#! /usr/bin/env perl
# Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# Ascetic x86_64 AT&T to MASM/NASM assembler translator by <@dot-asm>.
#
# Why AT&T to MASM and not vice versa? Several reasons. Because AT&T
# format is way easier to parse. Because it's simpler to "gear" from
# Unix ABI to Windows one [see cross-reference "card" at the end of
# file]. Because Linux targets were available first...
#
# In addition the script also "distills" code suitable for GNU
# assembler, so that it can be compiled with more rigid assemblers,
# such as Solaris /usr/ccs/bin/as.
#
# This translator is not designed to convert *arbitrary* assembler
# code from AT&T format to MASM one. It's designed to convert just
# enough to provide for dual-ABI OpenSSL modules development...
# There *are* limitations and you might have to modify your assembler
# code or this script to achieve the desired result...
#
# Currently recognized limitations:
#
# - can't use multiple ops per line;
#
# Dual-ABI styling rules.
#
# 1. Adhere to Unix register and stack layout [see cross-reference
#    ABI "card" at the end for explanation].
# 2. Forget about "red zone," stick to more traditional blended
#    stack frame allocation. If volatile storage is actually required
#    that is. If not, just leave the stack as is.
# 3. Functions tagged with ".type name,@function" get crafted with
#    unified Win64 prologue and epilogue automatically. If you want
#    to take care of ABI differences yourself, tag functions as
#    ".type name,@abi-omnipotent" instead.
# 4. To optimize the Win64 prologue you can specify number of input
#    arguments as ".type name,@function,N." Keep in mind that if N is
#    larger than 6, then you *have to* write "abi-omnipotent" code,
#    because >6 cases can't be addressed with unified prologue.
# 5. Name local labels as .L*, do *not* use dynamic labels such as 1:
#    (sorry about latter).
# 6. Don't use [or hand-code with .byte] "rep ret." "ret" mnemonic is
#    required to identify the spots, where to inject Win64 epilogue!
#    But on the pros, it's then prefixed with rep automatically:-)
# 7. Stick to explicit ip-relative addressing. If you have to use
#    GOTPCREL addressing, stick to mov symbol@GOTPCREL(%rip),%r??.
#    Both are recognized and translated to proper Win64 addressing
#    modes.
#
# 8. In order to provide for structured exception handling unified
#    Win64 prologue copies %rsp value to %rax. For further details
#    see SEH paragraph at the end.
# 9. .init segment is allowed to contain calls to functions only.
# a. If function accepts more than 4 arguments *and* >4th argument
#    is declared as non 64-bit value, do clear its upper part.


use strict;

my $flavour = shift;
my $output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

open STDOUT,">$output" || die "can't open $output: $!"
	if (defined($output));

my $gas=1;	$gas=0 if ($output =~ /\.asm$/);
my $elf=1;	$elf=0 if (!$gas);
my $win64=0;
my $prefix="";
my $decor=".L";

my $masmref=8 + 50727*2**-32;	# 8.00.50727 shipped with VS2005
my $masm=0;
my $PTR=" PTR";

my $nasmref=2.03;
my $nasm=0;

# GNU as indicator, as opposed to $gas, which indicates acceptable
# syntax
my $gnuas=0;

if    ($flavour eq "mingw64")	{ $gas=1; $elf=0; $win64=1;
				  $prefix=`echo __USER_LABEL_PREFIX__ | $ENV{CC} -E -P -`;
				  $prefix =~ s|\R$||; # Better chomp
				}
elsif ($flavour eq "macosx")	{ $gas=1; $elf=0; $prefix="_"; $decor="L\$"; }
elsif ($flavour eq "masm")	{ $gas=0; $elf=0; $masm=$masmref; $win64=1; $decor="\$L\$"; }
elsif ($flavour eq "nasm")	{ $gas=0; $elf=0; $nasm=$nasmref; $win64=1; $decor="\$L\$"; $PTR=""; }
elsif (!$gas)
{   if ($ENV{ASM} =~ m/nasm/ && `nasm -v` =~ m/version ([0-9]+)\.([0-9]+)/i)
    {	$nasm = $1 + $2*0.01; $PTR="";  }
    elsif (`ml64 2>&1` =~ m/Version ([0-9]+)\.([0-9]+)(\.([0-9]+))?/)
    {	$masm = $1 + $2*2**-16 + $4*2**-32;   }
    die "no assembler found on %PATH%" if (!($nasm || $masm));
    $win64=1;
    $elf=0;
    $decor="\$L\$";
}
# Find out if we're using GNU as
elsif (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/)
{
    $gnuas=1;
}
elsif (`$ENV{CC} --version 2>/dev/null`
		=~ /(clang .*|Intel.*oneAPI .*)/)
{
    $gnuas=1;
}
elsif (`$ENV{CC} -V 2>/dev/null`
		=~ /nvc .*/)
{
    $gnuas=1;
}

my $comment_ch = $masm || $nasm ? ';' : '#';

my $cet_property;
if ($flavour =~ /elf/) {
	# Always generate .note.gnu.property section for ELF outputs to
	# mark Intel CET support since all input files must be marked
	# with Intel CET support in order for linker to mark output with
	# Intel CET support.
	my $p2align=3; $p2align=2 if ($flavour eq "elf32");
	my $section='.note.gnu.property, #alloc';
	$section='".note.gnu.property", "a"' if $gnuas;
	$cet_property = <<_____;
	.section $section
	.p2align $p2align
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	# "GNU" encoded with .byte, since .asciz isn't supported
	# on Solaris.
	.byte 0x47
	.byte 0x4e
	.byte 0x55
	.byte 0
1:
	.p2align $p2align
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align $p2align
4:
_____
}

my $current_segment;
#
# I could not find equivalent of .previous directive for MASM (Microsoft
# assembler ML). Using of .previous got introduced to .pl files with
# placing of various constants into .rodata sections (segments).
# Each .rodata section is terminated by .previous directive which
# restores the preceding section to .rodata:
#
# .text
# 	; this is is the text section/segment
# .rodata
#	; constant definitions go here
# .previous
#	; the .text section which precedes .rodata got restored here
#
# The equivalent form for masm reads as follows:
#
# .text$	SEGMENT ALIGN(256) 'CODE'
# 	; this is is the text section/segment
# .text$	ENDS
# .rdata	SEGMENT READONLY ALIGN(64)
#	; constant definitions go here
# .rdata$	ENDS
# .text$	SEGMENT ALIGN(256) 'CODE'
#	; text section follows
# .text$	ENDS
#
# The .previous directive typically terminates .roadata segments/sections which
# hold definitions of constants. In order to place constants into .rdata
# segments when using masm we need to introduce a segment_stack array so we can
# emit proper ENDS directive whenever we see .previous.
#
# The code is tailored to work current set of .pl/asm files. There are some
# inconsistencies. For example .text section is the first section in all those
# files except ecp_nistz256. So we need to take that into account.
#
#	; stack is empty
# .text
#	; push '.text ' section twice, the stack looks as
#	; follows:
#	;	('.text', '.text')
# .rodata
#	; pop() so we can generate proper 'ENDS' for masm.
#	; stack looks like:
#	; 	('.text')
#	; push '.rodata', so we can create corresponding ENDS for masm.
#	; stack looks like:
#	;	('.rodata', '.text')
# .previous
#	; pop() '.rodata' from stack, so we create '.rodata ENDS'
#	; in masm flavour. For nasm flavour we just pop() because
#	; nasm does not use .rodata ENDS to close the current section
#	; the stack content is like this:
#	;	('.text', '.text')
#	; pop() again to find a previous section we need to restore.
#	; Depending on flavour we either generate .section .text
#	; or .text SEGMENT. The stack looks like:
#	; ('.text')
#
my @segment_stack = ();
my $current_function;
my $cfi_state; # value: undef, 'prologue', 'body', 'endproc'
my %globals;

{ package vex_prefix;	# pick up vex prefixes, example: {vex} vpmadd52luq m256, %ymm, %ymm
    sub re {
	my ($class, $line) = @_;
	my $self = {};
	my $ret;

	if ($$line =~ /(^\{vex\})/) {
	    bless $self,$class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;
	}
	$ret;
	}
    sub out {
	my $self = shift;
	$self->{value};
	}
}
{ package opcode;	# pick up opcodes
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /^([a-z][a-z0-9]*)/i) {
	    bless $self,$class;
	    $self->{op} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    undef $self->{sz};
	    if ($self->{op} =~ /^(movz)x?([bw]).*/) {	# movz is pain...
		$self->{op} = $1;
		$self->{sz} = $2;
	    } elsif ($self->{op} =~ /call|jmp/) {
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /^p/ && $' !~ /^(ush|op|insrw)/) { # SSEn
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /^[vk]/) { # VEX or k* such as kmov
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /mov[dq]/ && $$line =~ /%xmm/) {
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /([a-z]{3,})([qlwb])$/) {
		$self->{op} = $1;
		$self->{sz} = $2;
	    }
	}
	$ret;
    }
    sub size {
	my ($self, $sz) = @_;
	$self->{sz} = $sz if (defined($sz) && !defined($self->{sz}));
	$self->{sz};
    }
    sub out {
	my $self = shift;
	if ($gas) {
	    if ($self->{op} eq "movz") {	# movz is pain...
		sprintf "%s%s%s",$self->{op},$self->{sz},shift;
	    } elsif ($self->{op} =~ /^set/) {
		"$self->{op}";
	    } elsif ($self->{op} eq "ret") {
		my $epilogue = "";
		if ($win64 && $current_function->{abi} eq "svr4") {
		    $epilogue = "movq	8(%rsp),%rdi\n\t" .
				"movq	16(%rsp),%rsi\n\t";
		}
	    	$epilogue . ".byte	0xf3,0xc3";
	    } elsif ($self->{op} eq "call" && !$elf && $current_segment eq ".init") {
		".p2align\t3\n\t.quad";
	    } else {
		"$self->{op}$self->{sz}";
	    }
	} else {
	    $self->{op} =~ s/^movz/movzx/;
	    if ($self->{op} eq "ret") {
		$self->{op} = "";
		if ($win64 && $current_function->{abi} eq "svr4") {
		    $self->{op} = "mov	rdi,QWORD$PTR\[8+rsp\]\t;WIN64 epilogue\n\t".
				  "mov	rsi,QWORD$PTR\[16+rsp\]\n\t";
	    	}
		$self->{op} .= "DB\t0F3h,0C3h\t\t;repret";
	    } elsif ($self->{op} =~ /^(pop|push)f/) {
		$self->{op} .= $self->{sz};
	    } elsif ($self->{op} eq "call" && $current_segment eq ".CRT\$XCU") {
		$self->{op} = "\tDQ";
	    }
	    $self->{op};
	}
    }
    sub mnemonic {
	my ($self, $op) = @_;
	$self->{op}=$op if (defined($op));
	$self->{op};
    }
}
{ package const;	# pick up constants, which start with $
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /^\$([^,]+)/) {
	    bless $self, $class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;
	}
	$ret;
    }
    sub out {
    	my $self = shift;

	$self->{value} =~ s/\b(0b[0-1]+)/oct($1)/eig;
	if ($gas) {
	    # Solaris /usr/ccs/bin/as can't handle multiplications
	    # in $self->{value}
	    my $value = $self->{value};
	    no warnings;    # oct might complain about overflow, ignore here...
	    $value =~ s/(?<![\w\$\.])(0x?[0-9a-f]+)/oct($1)/egi;
	    if ($value =~ s/([0-9]+\s*[\*\/\%]\s*[0-9]+)/eval($1)/eg) {
		$self->{value} = $value;
	    }
	    sprintf "\$%s",$self->{value};
	} else {
	    my $value = $self->{value};
	    $value =~ s/0x([0-9a-f]+)/0$1h/ig if ($masm);
	    sprintf "%s",$value;
	}
    }
}
{ package ea;		# pick up effective addresses: expr(%reg,%reg,scale)

    my %szmap = (	b=>"BYTE$PTR",    w=>"WORD$PTR",
			l=>"DWORD$PTR",   d=>"DWORD$PTR",
			q=>"QWORD$PTR",   o=>"OWORD$PTR",
			x=>"XMMWORD$PTR", y=>"YMMWORD$PTR",
			z=>"ZMMWORD$PTR" ) if (!$gas);

    sub re {
	my	($class, $line, $opcode) = @_;
	my	$self = {};
	my	$ret;

	# optional * ----vvv--- appears in indirect jmp/call
	if ($$line =~ /^(\*?)([^\(,]*)\(([%\w,]+)\)((?:{[^}]+})*)/) {
	    bless $self, $class;
	    $self->{asterisk} = $1;
	    $self->{label} = $2;
	    ($self->{base},$self->{index},$self->{scale})=split(/,/,$3);
	    $self->{scale} = 1 if (!defined($self->{scale}));
	    $self->{opmask} = $4;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    if ($win64 && $self->{label} =~ s/\@GOTPCREL//) {
		die if ($opcode->mnemonic() ne "mov");
		$opcode->mnemonic("lea");
	    }
	    $self->{base}  =~ s/^%//;
	    $self->{index} =~ s/^%// if (defined($self->{index}));
	    $self->{opcode} = $opcode;
	}
	$ret;
    }
    sub size {}
    sub out {
	my ($self, $sz) = @_;

	$self->{label} =~ s/([_a-z][_a-z0-9]*)/$globals{$1} or $1/gei;
	$self->{label} =~ s/\.L/$decor/g;

	# Silently convert all EAs to 64-bit. This is required for
	# elder GNU assembler and results in more compact code,
	# *but* most importantly AES module depends on this feature!
	$self->{index} =~ s/^[er](.?[0-9xpi])[d]?$/r\1/;
	$self->{base}  =~ s/^[er](.?[0-9xpi])[d]?$/r\1/;

	# Solaris /usr/ccs/bin/as can't handle multiplications
	# in $self->{label}...
	use integer;
	$self->{label} =~ s/(?<![\w\$\.])(0x?[0-9a-f]+)/oct($1)/egi;
	$self->{label} =~ s/\b([0-9]+\s*[\*\/\%]\s*[0-9]+)\b/eval($1)/eg;

	# Some assemblers insist on signed presentation of 32-bit
	# offsets, but sign extension is a tricky business in perl...
	if ((1<<31)<<1) {
	    $self->{label} =~ s/\b([0-9]+)\b/$1<<32>>32/eg;
	} else {
	    $self->{label} =~ s/\b([0-9]+)\b/$1>>0/eg;
	}

	# if base register is %rbp or %r13, see if it's possible to
	# flip base and index registers [for better performance]
	if (!$self->{label} && $self->{index} && $self->{scale}==1 &&
	    $self->{base} =~ /(rbp|r13)/) {
		$self->{base} = $self->{index}; $self->{index} = $1;
	}

	if ($gas) {
	    $self->{label} =~ s/^___imp_/__imp__/   if ($flavour eq "mingw64");

	    if (defined($self->{index})) {
		sprintf "%s%s(%s,%%%s,%d)%s",
					$self->{asterisk},$self->{label},
					$self->{base}?"%$self->{base}":"",
					$self->{index},$self->{scale},
					$self->{opmask};
	    } else {
		sprintf "%s%s(%%%s)%s",	$self->{asterisk},$self->{label},
					$self->{base},$self->{opmask};
	    }
	} else {
	    $self->{label} =~ s/\./\$/g;
	    $self->{label} =~ s/(?<![\w\$\.])0x([0-9a-f]+)/0$1h/ig;
	    $self->{label} = "($self->{label})" if ($self->{label} =~ /[\*\+\-\/]/);

	    my $mnemonic = $self->{opcode}->mnemonic();
	    ($self->{asterisk})				&& ($sz="q") ||
	    ($mnemonic =~ /^v?mov([qd])$/)		&& ($sz=$1)  ||
	    ($mnemonic =~ /^v?pinsr([qdwb])$/)		&& ($sz=$1)  ||
	    ($mnemonic =~ /^vbroadcasti32x4$/)		&& ($sz="x") ||
	    ($mnemonic =~ /^vpbroadcast([qdwb])$/)	&& ($sz=$1)  ||
	    ($mnemonic =~ /^v(?!perm)[a-z]+[fi]128$/)	&& ($sz="x");

	    $self->{opmask}  =~ s/%(k[0-7])/$1/;

	    if (defined($self->{index})) {
		sprintf "%s[%s%s*%d%s]%s",$szmap{$sz},
					$self->{label}?"$self->{label}+":"",
					$self->{index},$self->{scale},
					$self->{base}?"+$self->{base}":"",
					$self->{opmask};
	    } elsif ($self->{base} eq "rip") {
		sprintf "%s[%s]",$szmap{$sz},$self->{label};
	    } else {
		sprintf "%s[%s%s]%s",	$szmap{$sz},
					$self->{label}?"$self->{label}+":"",
					$self->{base},$self->{opmask};
	    }
	}
    }
}
{ package register;	# pick up registers, which start with %.
    sub re {
	my	($class, $line, $opcode) = @_;
	my	$self = {};
	my	$ret;

	# optional * ----vvv--- appears in indirect jmp/call
	if ($$line =~ /^(\*?)%(\w+)((?:{[^}]+})*)/) {
	    bless $self,$class;
	    $self->{asterisk} = $1;
	    $self->{value} = $2;
	    $self->{opmask} = $3;
	    $opcode->size($self->size());
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;
	}
	$ret;
    }
    sub size {
	my	$self = shift;
	my	$ret;

	if    ($self->{value} =~ /^r[\d]+b$/i)	{ $ret="b"; }
	elsif ($self->{value} =~ /^r[\d]+w$/i)	{ $ret="w"; }
	elsif ($self->{value} =~ /^r[\d]+d$/i)	{ $ret="l"; }
	elsif ($self->{value} =~ /^r[\w]+$/i)	{ $ret="q"; }
	elsif ($self->{value} =~ /^[a-d][hl]$/i){ $ret="b"; }
	elsif ($self->{value} =~ /^[\w]{2}l$/i)	{ $ret="b"; }
	elsif ($self->{value} =~ /^[\w]{2}$/i)	{ $ret="w"; }
	elsif ($self->{value} =~ /^e[a-z]{2}$/i){ $ret="l"; }

	$ret;
    }
    sub out {
    	my $self = shift;
	if ($gas)	{ sprintf "%s%%%s%s",	$self->{asterisk},
						$self->{value},
						$self->{opmask}; }
	else		{ $self->{opmask} =~ s/%(k[0-7])/$1/;
			  $self->{value}.$self->{opmask}; }
    }
}
{ package label;	# pick up labels, which end with :
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /(^[\.\w]+)\:/) {
	    bless $self,$class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    $self->{value} =~ s/^\.L/$decor/;
	}
	$ret;
    }
    sub out {
	my $self = shift;

	if ($gas) {
	    my $func;
	    if ($win64	&& $current_function->{name} eq $self->{value}
			&& $current_function->{abi} eq "svr4") {
		$cfi_state = 'prologue'; # indicate that we've already emitted SEH64_PROC_FRAME.
		$func  = 'SEH64_PROC_FRAME ' . ($globals{$self->{value}} or $self->{value}) . "\n";
		$func .= "	movq	%rdi,8(%rsp)\n";
		$func .= "SEH64_SAVEREG rdi, 8\n";
		$func .= "	movq	%rsi,16(%rsp)\n";
		$func .= "SEH64_SAVEREG rsi, 16\n";
		$func .= "	movq	%rsp,%rax\n";
		my $narg = $current_function->{narg};
		$narg=6 if (!defined($narg));
		$func .= "	movq	%rcx,%rdi\n" if ($narg>0);
		$func .= "	movq	%rdx,%rsi\n" if ($narg>1);
		$func .= "	movq	%r8,%rdx\n"  if ($narg>2);
		$func .= "	movq	%r9,%rcx\n"  if ($narg>3);
		$func .= "	movq	40(%rsp),%r8\n" if ($narg>4);
		$func .= "	movq	48(%rsp),%r9\n" if ($narg>5);
	    } else {
		$func = ($globals{$self->{value}} or $self->{value}) . ":";
	    }
	    $func;
	} elsif ($self->{value} ne "$current_function->{name}") {
	    # Make all labels in masm global.
	    $self->{value} .= ":" if ($masm);
	    $self->{value} . ":";
	} elsif ($win64 && $current_function->{abi} eq "svr4") {
	    die "unexpected cfi state for proc label: $cfi_state" if (defined($cfi_state));
            $cfi_state = 'prologue'; # indicate that we've already emitted SEH64_PROC_FRAME.
            my $func = "SEH64_PROC_FRAME $current_function->{name},$current_function->{scope}\n";
	    $func .= "	mov	QWORD$PTR\[8+rsp\],rdi\t;WIN64 prologue\n";
	    $func .= "SEH64_SAVEREG rdi, 8\n";
	    $func .= "	mov	QWORD$PTR\[16+rsp\],rsi\n";
	    $func .= "SEH64_SAVEREG rsi, 16\n";
	    $func .= "	mov	rax,rsp\n";
	    my $narg = $current_function->{narg};
	    $narg=6 if (!defined($narg));
	    $func .= "	mov	rdi,rcx\n" if ($narg>0);
	    $func .= "	mov	rsi,rdx\n" if ($narg>1);
	    $func .= "	mov	rdx,r8\n"  if ($narg>2);
	    $func .= "	mov	rcx,r9\n"  if ($narg>3);
	    $func .= "	mov	r8,QWORD$PTR\[40+rsp\]\n" if ($narg>4);
	    $func .= "	mov	r9,QWORD$PTR\[48+rsp\]\n" if ($narg>5);
	    $func .= "\n";
	} else {
	    die "unexpected cfi state for proc label: $cfi_state" if (defined($cfi_state));
	    $cfi_state = 'prologue'; # indicate that we've already emitted PROC_FRAME.
	    "SEH64_PROC_FRAME $current_function->{name},$current_function->{scope}";
	}
    }
}
{ package expr;		# pick up expressions
    sub re {
	my	($class, $line, $opcode) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /(^[^,]+)/) {
	    bless $self,$class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    $self->{value} =~ s/\@PLT// if (!$elf);
	    $self->{value} =~ s/([_a-z][_a-z0-9]*)/$globals{$1} or $1/gei;
	    $self->{value} =~ s/\.L/$decor/g;
	    $self->{opcode} = $opcode;
	}
	$ret;
    }
    sub out {
	my $self = shift;
	if ($nasm && $self->{opcode}->mnemonic()=~m/^j(?![re]cxz)/) {
	    "NEAR ".$self->{value};
	} else {
	    $self->{value};
	}
    }
}
{ package cfi_directive;
    # CFI directives annotate instructions that are significant for
    # stack unwinding procedure compliant with DWARF specification,
    # see http://dwarfstd.org/. Besides naturally expected for this
    # script platform-specific filtering function, this module adds
    # three auxiliary synthetic directives not recognized by [GNU]
    # assembler:
    #
    # - .cfi_push to annotate push instructions in prologue, which
    #   translates to .cfi_adjust_cfa_offset (if needed) and
    #   .cfi_offset;
    # - .cfi_pop to annotate pop instructions in epilogue, which
    #   translates to .cfi_adjust_cfa_offset (if needed) and
    #   .cfi_restore;
    # - [and most notably] .cfi_cfa_expression which encodes
    #   DW_CFA_def_cfa_expression and passes it to .cfi_escape as
    #   byte vector;
    #
    # CFA expressions were introduced in DWARF specification version
    # 3 and describe how to deduce CFA, Canonical Frame Address. This
    # becomes handy if your stack frame is variable and you can't
    # spare register for [previous] frame pointer. Suggested directive
    # syntax is made-up mix of DWARF operator suffixes [subset of]
    # and references to registers with optional bias. Following example
    # describes offloaded *original* stack pointer at specific offset
    # from *current* stack pointer:
    #
    #   .cfi_cfa_expression     %rsp+40,deref,+8
    #
    # Final +8 has everything to do with the fact that CFA is defined
    # as reference to top of caller's stack, and on x86_64 call to
    # subroutine pushes 8-byte return address. In other words original
    # stack pointer upon entry to a subroutine is 8 bytes off from CFA.

    # Below constants are taken from "DWARF Expressions" section of the
    # DWARF specification, section is numbered 7.7 in versions 3 and 4.
    my %DW_OP_simple = (	# no-arg operators, mapped directly
	deref	=> 0x06,	dup	=> 0x12,
	drop	=> 0x13,	over	=> 0x14,
	pick	=> 0x15,	swap	=> 0x16,
	rot	=> 0x17,	xderef	=> 0x18,

	abs	=> 0x19,	and	=> 0x1a,
	div	=> 0x1b,	minus	=> 0x1c,
	mod	=> 0x1d,	mul	=> 0x1e,
	neg	=> 0x1f,	not	=> 0x20,
	or	=> 0x21,	plus	=> 0x22,
	shl	=> 0x24,	shr	=> 0x25,
	shra	=> 0x26,	xor	=> 0x27,
	);

    my %DW_OP_complex = (	# used in specific subroutines
	constu		=> 0x10,	# uleb128
	consts		=> 0x11,	# sleb128
	plus_uconst	=> 0x23,	# uleb128
	lit0 		=> 0x30,	# add 0-31 to opcode
	reg0		=> 0x50,	# add 0-31 to opcode
	breg0		=> 0x70,	# add 0-31 to opcole, sleb128
	regx		=> 0x90,	# uleb28
	fbreg		=> 0x91,	# sleb128
	bregx		=> 0x92,	# uleb128, sleb128
	piece		=> 0x93,	# uleb128
	);

    # Following constants are defined in x86_64 ABI supplement, for
    # example available at https://gitlab.com/x86-psABIs/x86-64-ABI.
    my %DW_reg_idx = (
	"%rax"=>0,  "%rdx"=>1,  "%rcx"=>2,  "%rbx"=>3,
	"%rsi"=>4,  "%rdi"=>5,  "%rbp"=>6,  "%rsp"=>7,
	"%r8" =>8,  "%r9" =>9,  "%r10"=>10, "%r11"=>11,
	"%r12"=>12, "%r13"=>13, "%r14"=>14, "%r15"=>15
	);

    my ($cfa_reg, $cfa_reg_offset, $cfa_rsp, $last_cfa_expression);
    my @cfa_stack;

    # [us]leb128 format is variable-length integer representation base
    # 2^128, with most significant bit of each byte being 0 denoting
    # *last* most significant digit. See "Variable Length Data" in the
    # DWARF specification, numbered 7.6 at least in versions 3 and 4.
    sub sleb128 {
	use integer;	# get right shift extend sign

	my $val = shift;
	my $sign = ($val < 0) ? -1 : 0;
	my @ret = ();

	while(1) {
	    push @ret, $val&0x7f;

	    # see if remaining bits are same and equal to most
	    # significant bit of the current digit, if so, it's
	    # last digit...
	    last if (($val>>6) == $sign);

	    @ret[-1] |= 0x80;
	    $val >>= 7;
	}

	return @ret;
    }
    sub uleb128 {
	my $val = shift;
	my @ret = ();

	while(1) {
	    push @ret, $val&0x7f;

	    # see if it's last significant digit...
	    last if (($val >>= 7) == 0);

	    @ret[-1] |= 0x80;
	}

	return @ret;
    }
    sub const {
	my $val = shift;

	if ($val >= 0 && $val < 32) {
            return ($DW_OP_complex{lit0}+$val);
	}
	return ($DW_OP_complex{consts}, sleb128($val));
    }
    sub reg {
	my $val = shift;

	return if ($val !~ m/^(%r\w+)(?:([\+\-])((?:0x)?[0-9a-f]+))?/);

	my $reg = $DW_reg_idx{$1};
	my $off = eval ("0 $2 $3");

	return (($DW_OP_complex{breg0} + $reg), sleb128($off));
	# Yes, we use DW_OP_bregX+0 to push register value and not
	# DW_OP_regX, because latter would require even DW_OP_piece,
	# which would be a waste under the circumstances. If you have
	# to use DWP_OP_reg, use "regx:N"...
    }
    sub cfa_expression {
	my $line = shift;
	my @ret;

	foreach my $token (split(/,\s*/,$line)) {
	    if ($token =~ /^%r/) {
		push @ret,reg($token);
	    } elsif ($token =~ /((?:0x)?[0-9a-f]+)\((%r\w+)\)/) {
		push @ret,reg("$2+$1");
	    } elsif ($token =~ /(\w+):(\-?(?:0x)?[0-9a-f]+)(U?)/i) {
		my $i = 1*eval($2);
		push @ret,$DW_OP_complex{$1}, ($3 ? uleb128($i) : sleb128($i));
	    } elsif (my $i = 1*eval($token) or $token eq "0") {
		if ($token =~ /^\+/) {
		    push @ret,$DW_OP_complex{plus_uconst},uleb128($i);
		} else {
		    push @ret,const($i);
		}
	    } else {
		push @ret,$DW_OP_simple{$token};
	    }
	}

	# Finally we return DW_CFA_def_cfa_expression, 15, followed by
	# length of the expression and of course the expression itself.
	return (15,scalar(@ret),@ret);
    }
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ s/^\s*\.cfi_(\w+)\s*//) {
	    bless $self,$class;
	    $ret = $self;
            if ($win64) {
                $self->{value} = "";	# default: drop it.
            } else {
                undef $self->{value};	# default: pass through.
            }
	    my $dir = $1;

	    SWITCH: for ($dir) {
	    # What is $cfa_rsp? Effectively it's difference between %rsp
	    # value and current CFA, Canonical Frame Address, which is
	    # why it starts with -8. Recall that CFA is top of caller's
	    # stack...
	    /startproc/	&& do {	($cfa_reg, $cfa_reg_offset, $cfa_rsp) = ("%rsp", 8, -8);
				if (defined($cfi_state) && $cfi_state ne 'prologue' && (!$elf || $cfi_state ne 'endproc')) {
				    die "invalid cfi state for cfi_startproc: $cfi_state";
				}
			        if ($win64 && !defined($cfi_state)) {
				    $self->{value} = "SEH64_PROC_FRAME\t$current_function->{name},$current_function->{scope}";
				}
				$cfi_state = 'prologue';
				last;
			      };
	    /endproc/	&& do {	($cfa_reg, $cfa_rsp, $cfa_reg_offset) = ("%rsp", 0, 0);
				# .cfi_remember_state directives that are not
				# matched with .cfi_restore_state are
				# unnecessary.
				die "unpaired .cfi_remember_state" if (@cfa_stack);
				die ".cfi_endproc without .cfi_endprolog in $current_function->{name}" if ($cfi_state eq 'prologue');
				die "bogus .cfi_endproc (state: $cfi_state)" if ($cfi_state ne 'body');
                                $self->{value} = "SEH64_ENDPROC_FRAME\t$current_function->{name}" if ($win64);
				$cfi_state = 'endproc';
				last;
			      };
	    /def_cfa_register/
			&& do { $cfa_reg = $$line;
				$last_cfa_expression = undef;
				last;
			      };
	    /def_cfa_offset/
			&& do { $cfa_reg_offset = 1*eval($$line);
				$cfa_rsp = -$cfa_reg_offset if ($cfa_reg eq "%rsp");
				$last_cfa_expression = undef;
				die "TODO: .cfi_$dir" if ($win64 && $cfi_state eq 'prologue');
				last;
			      };
	    /adjust_cfa_offset/
			&& do {	my $diff = 1*eval($$line);
				$cfa_reg_offset += $diff;
				$cfa_rsp -= $diff if ($cfa_reg eq "%rsp");
				$last_cfa_expression = undef;
				if ($win64 && $cfi_state eq 'prologue' && $cfa_reg eq '%rsp') {
				    $self->{value} = "SEH64_ALLOCSTACK $diff";
				}
				last;
			      };
	    /stackalloc/	# win64: .cfi_stackalloc nbytes - adjusts $cfa_rsp;
			&& do {	#        same as .cfi_adjust_cfa_offset if $cfa_reg is %rsp.
				die ".cfi_$dir $$line" if (!($$line =~ /^([-0-9a-fA-FxX+*]+)$/));
				die ".cfi_$dir following .cfi_cfa_expression" if (defined($last_cfa_expression));
				my $adj = 0 + eval($1);
				$cfa_rsp -= $adj;
				$cfa_reg_offset += $adj if ($cfa_reg eq '%rsp');
				if ($win64 && $cfi_state eq 'prologue') {
				    $self->{value} = "SEH64_ALLOCSTACK $adj";
				}
				last;
			      };
	    /^def_cfa$/	&& do {	if ($$line =~ /(%r\w+)\s*,\s*(.+)/) {
				    die "TODO: .cfi_$dir $1,$2" if ($1 ne '%rsp' && $win64 && $cfi_state eq 'prologue');
				    $cfa_reg = $1;
				    $cfa_reg_offset = 1*eval($$line);
				    $cfa_rsp = -$cfa_reg_offset if ($cfa_reg eq "%rsp");
				}
				$last_cfa_expression = undef;
				last;
			      };
	    /push/	&& do { die ".cfi_push outside the prologue: $cfi_state" if ($cfi_state ne 'prologue');
				$cfa_rsp -= 8;
				$cfa_reg_offset += 8 if ($cfa_reg eq "%rsp");
                                if ($win64) {
				    $self->{value}  = "SEH64_PUSHREG\t" . substr($$line, 1) . "\t"
						    . "$comment_ch cfa_rsp,cfa_reg_offset => $cfa_rsp,$cfa_reg_offset cfa_reg=$cfa_reg";
                                } else {
				    if ($cfa_reg eq "%rsp") {
				        $self->{value} = ".cfi_adjust_cfa_offset\t8\n";
				    }
				    $self->{value} .= ".cfi_offset\t$$line,$cfa_rsp";
                                }
				last;
			      };
	    /pop/	&& do { $cfa_rsp += 8;
				$cfa_reg_offset += 8 if ($cfa_reg eq "%rsp");
				last if ($win64);
				if ($cfa_reg eq "%rsp") {
				    $self->{value} = ".cfi_adjust_cfa_offset\t-8\n";
				}
				$self->{value} .= ".cfi_restore\t$$line";
				last;
			      };
	    /cfa_expression/
			&& do { $last_cfa_expression = $$line; # For win64
				$cfa_reg_offset = undef;
				if (!$win64) {
				    $self->{value} = ".cfi_escape\t" .
					    join(",", map(sprintf("0x%02x", $_),
							  cfa_expression($$line)));
				}
				last;
			      };
	    /remember_state/   	# Pseudo directive. Unused (doesn't work for win64).
			&& do {	push @cfa_stack, [$cfa_reg, $cfa_reg_offset, $cfa_rsp];
				last;
			      };
	    /restore_state/	# Pseudo directive. Unused.
			&& do {	($cfa_reg, $cfa_reg_offset, $cfa_rsp) = @{pop @cfa_stack};
				last;
			      };
	    /^sp_offset$/	# Pseudo directive. Translated using $cfa_rsp to .cfi_offset.
			&& do { die "malformed: $dir $$line" if (!($$line =~ /(%\w+)\s*,\s*(.+)/));
				die ".cfi_sp_offset cannot follow .cfi_cfa_expression " if (defined($last_cfa_expression));
				my $off = eval($2) + $cfa_rsp;
				$$line = "$1, $off";
				$dir = "offset";
			      };
	    /^rel_offset$/
			&& do { last if (!$win64 || $cfi_state ne 'prologue');
				# win64: Convert to .cfi_offset to avoid code duplication.
				die "malformed: .cfi_$dir $$line"  if (!($$line =~ /(%\w+)\s*,\s*(.+)/));
				die ".cfi_$dir: undefined cfa offset " if (!defined($cfa_reg_offset));
				die ".cfi_$dir: cfa_reg=$cfa_reg" if ($cfa_reg ne '%rsp');
				my $off = -($cfa_reg_offset - eval($2));
				$$line = "$1, $off";
				$dir = 'offset';
			      };
	    /^offset$/  && do { # win64: Need to convert these to SEH64_SAVEXXX.
				if ($win64 && $cfi_state eq 'prologue') {
				    if ($$line =~ /^%(\w+)\s*,\s*(.+)$/) {
					# The offset is relative to the preceived RSP for win64.
					my $w64_off_rsp = -$cfa_rsp + eval($2);
					if (rindex($1,'xmm') == 0) {
					    $self->{value} = "SEH64_SAVEXMM128 $1, $w64_off_rsp";
					} else {
					    $self->{value} = "SEH64_SAVEREG $1, $w64_off_rsp";
					}
					$self->{value} .= "\t$comment_ch .cfi_$dir $1, $2 cfa_reg_offset=$cfa_reg_offset cfa_rsp=$cfa_rsp";
				    } else {
					die "line: .cfi_$dir $$line";
				    }
				}
				last;
			      };
	    /^endprolog$/	# win64: .cfi_endprolog - marks the end of the prolog (fake directive).
			&& do { die ".cfi_endprolog without .cfi_startproc" if ($cfi_state ne 'prologue');
				$cfi_state = 'body';
				if ($win64) {
				    if (defined($last_cfa_expression)) {
					if (   ($last_cfa_expression =~ m/^\s*(0[Xx][0-9a-fA-F]+|\d+)\(%rsp\)\s*,\s*deref\s*,\s*([^,]*)$/)
					    || ($last_cfa_expression =~ m/^\s*%rsp\s*\+\s*(0[Xx][0-9a-fA-F]+|\d+),\s*deref\s*,\s*([^,]*)$/) ) {
					    my $rsp_off   = eval($1) + 0;
					    my $adj       = eval($2) + 0;
					    my $frame_off = -($cfa_rsp + $adj);
					    die $frame_off if ($frame_off & 7);
					    $self->{value}  = "$comment_ch Hack using rax to load saved CFA expression: $last_cfa_expression\n";
					    if ($frame_off & 15) {
						$self->{value} .= "SEH64_ALLOCSTACK 8";
						$self->{value} .= "\t$comment_ch Make frame reg offset multiple of 16.\n";
						$frame_off += 8;
					    }
					    $self->{value} .= "SEH64_SETFRAME rax, $frame_off\t"
							    . "$comment_ch Unwind basically does: rsp = rax - offset\n";
					    $self->{value} .= "SEH64_PUSHREG rax    \t"
							    . "$comment_ch Unwind will load deref'ed value into volatile reg for SET_FRAME above.\n";
					    if ($rsp_off != 0) {
						$self->{value} .= "SEH64_ALLOCSTACK $rsp_off\t";
						$self->{value} .= "$comment_ch Can only deref by .PUSHREG, so adjust RSP by feigning stack alloc.\n";
					    }
					} else {
					    ## @todo define CFA
					    die "TODO CFA: $last_cfa_expression";
					}
				    } elsif ($cfa_reg eq "%rsp") {
					$self->{value} = "\t$comment_ch cfa_rsp=$cfa_rsp\n";
				    } elsif (index("%rbp%rax%r11%r9", $cfa_reg) >= 0) { # Make sure to check the code properly...
					die ".cfi_$dir: cfa_reg=$cfa_reg" if ($cfa_reg eq "%rsp"); # If we're using RSP, then assume no frame pointer reg.
					my $off_rsp_to_fpreg = -$cfa_rsp - $cfa_reg_offset;
					if (($off_rsp_to_fpreg & 7) || $off_rsp_to_fpreg < 0 || $off_rsp_to_fpreg > 240) {
					    die "bad fpreg off: $off_rsp_to_fpreg (0..240, 8 byte aligned)";
					}
					die "$off_rsp_to_fpreg" if ($off_rsp_to_fpreg & 7);
					if ($off_rsp_to_fpreg & 15) {
					    $self->{value} = "SEH64_ALLOCSTACK 8\n";
					    $off_rsp_to_fpreg += 8;
					}
					$self->{value} .= 'SEH64_SETFRAME ' . substr($cfa_reg, 1) . ", $off_rsp_to_fpreg\n";
				    } else {
					die "TODO: CFA cfa_reg=$cfa_reg cfa_rsp=$cfa_rsp";
				    }
				    $self->{value} .= "SEH64_ENDPROLOG";
				    $self->{value} .= " $current_function->{name}" if ($gas);
				    $self->{value} .= "\t$comment_ch cfa_reg=$cfa_reg cfa_reg_offset=$cfa_reg_offset cfa_rsp=$cfa_rsp";
				} else {
				    $self->{value} = "# .cfi_endprolog";
				}
				last;
			      };
	       die "unknown cfi prolog directive: .cfi_$dir" if ($win64 && $cfi_state eq 'prologue');
	    }

	    $self->{value} = ".cfi_$dir\t$$line" if (!defined($self->{value}));

	    $$line = "";
	}

	return $ret;
    }
    sub out {
	my $self = shift;
	return ($elf || $win64 ? $self->{value} : undef);
    }
}
{ package directive;	# pick up directives, which start with .
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;
	my	$dir;

	# chain-call to cfi_directive
	$ret = cfi_directive->re($line) and return $ret;

	if ($$line =~ /^\s*(\.\w+)/) {
	    bless $self,$class;
	    $dir = $1;
	    $ret = $self;
	    undef $self->{value};
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    SWITCH: for ($dir) {
		/\.global|\.globl|\.extern/
			    && do { $globals{$$line} = $prefix . $$line;
				    $$line = $globals{$$line} if ($prefix);
				    last;
				  };
		/\.type/    && do { my ($sym,$type,$narg) = split(',',$$line);
				    if ($type eq "\@function") {
					undef $current_function;
					$current_function->{name} = $sym;
					$current_function->{abi}  = "svr4";
					$current_function->{narg} = $narg;
					$current_function->{scope} = defined($globals{$sym})?"PUBLIC":"PRIVATE";
				    } elsif ($type eq "\@abi-omnipotent") {
					undef $current_function;
					$current_function->{name} = $sym;
					$current_function->{scope} = defined($globals{$sym})?"PUBLIC":"PRIVATE";
				    }
				    $$line =~ s/\@abi\-omnipotent/\@function/;
				    $$line =~ s/\@function.*/\@function/;
				    last;
				  };
		/\.asciz/   && do { if ($$line =~ /^"(.*)"$/) {
					$dir  = ".byte";
					$$line = join(",",unpack("C*",$1),0);
				    }
				    last;
				  };
		/\.rva|\.long|\.quad|\.byte/
			    && do { $$line =~ s/([_a-z][_a-z0-9]*)/$globals{$1} or $1/gei;
				    $$line =~ s/\.L/$decor/g;
				    last;
				  };
	    }

	    if ($gas) {
		$self->{value} = $dir . "\t" . $$line;

		if ($dir =~ /\.extern/) {
		    $self->{value} = ""; # swallow extern
		} elsif (!$elf && $dir =~ /\.type/) {
		    $self->{value} = "";
		    $self->{value} = ".def\t" . ($globals{$1} or $1) . ";\t" .
				(defined($globals{$1})?".scl 2;":".scl 3;") .
				"\t.type 32;\t.endef"
				if ($win64 && $$line =~ /([^,]+),\@function/);
		} elsif (!$elf && $dir =~ /\.size/) {
		    $self->{value} = "";
		    if (defined($current_function)) {
			$self->{value} .= "${decor}SEH_end_$current_function->{name}:"
				if ($win64 && $current_function->{abi} eq "svr4");
			undef $current_function;
			undef $cfi_state;
		    }
		} elsif (!$elf && $dir =~ /\.align/) {
		    $self->{value} = ".p2align\t" . (log($$line)/log(2));
		} elsif ($dir eq ".section") {
		    #
		    # get rid off align option, it's not supported/tolerated
		    # by gcc. openssl project introduced the option as an aid
		    # to deal with nasm/masm assembly.
		    #
		    $self->{value} =~ s/(.+)\s+align\s*=.*$/$1/;
                    $current_segment = pop(@segment_stack);
                    if (not $current_segment) {
                        # if no previous section is defined, then assume .text
                        # so code does not land in .data section by accident.
                        # this deals with inconsistency of perl-assembly files.
                        push(@segment_stack, ".text");
                    }
		    #
		    # $$line may still contains align= option. We do care
		    # about section type here.
		    #
		    $current_segment = $$line;
		    $current_segment =~ s/([^\s]+).*$/$1/;
                    push(@segment_stack, $current_segment);
		    if (!$elf && $current_segment eq ".rodata") {
			if	($flavour eq "macosx") { $self->{value} = ".section\t__DATA,__const"; }
			elsif	($flavour eq "mingw64")	{ $self->{value} = ".section\t.rodata"; }
		    }
		    if (!$elf && $current_segment eq ".init") {
			if	($flavour eq "macosx")	{ $self->{value} = ".mod_init_func"; }
			elsif	($flavour eq "mingw64")	{ $self->{value} = ".section\t.ctors"; }
		    }
		} elsif ($dir =~ /\.(text|data)/) {
                    $current_segment = pop(@segment_stack);
                    if (not $current_segment) {
                        # if no previous section is defined, then assume .text
                        # so code does not land in .data section by accident.
                        # this deals with inconsistency of perl-assembly files.
                        push(@segment_stack, ".text");
                    }
		    $current_segment=".$1";
		    push(@segment_stack, $current_segment);
		} elsif ($dir =~ /\.hidden/) {
		    if    ($flavour eq "macosx")  { $self->{value} = ".private_extern\t$prefix$$line"; }
		    elsif ($flavour eq "mingw64") { $self->{value} = ""; }
		} elsif ($dir =~ /\.comm/) {
		    $self->{value} = "$dir\t$prefix$$line";
		    $self->{value} =~ s|,([0-9]+),([0-9]+)$|",$1,".log($2)/log(2)|e if ($flavour eq "macosx");
		} elsif ($dir =~ /\.previous/) {
                    pop(@segment_stack); #pop ourselves
                    # just peek at the top of the stack here
                    $current_segment = @segment_stack[0];
                    if (not $current_segment) {
                        # if no previous segment was defined assume .text so
                        # the code does not accidentally land in .data section.
                        $current_segment = ".text";
                        push(@segment_stack, $current_segment);
                    }
                    if ($flavour eq "mingw64" || $flavour eq "macosx") {
		        $self->{value} = $current_segment;
                    }
		}
		$$line = "";
		return $self;
	    }

	    # non-gas case or nasm/masm
	    SWITCH: for ($dir) {
		/\.text/    && do { my $v=undef;
				    if ($nasm) {
					$current_segment = pop(@segment_stack);
					if (not $current_segment) {
					    push(@segment_stack, ".text");
				        }
					$v="section	.text code align=64\n";
					$current_segment = ".text";
					push(@segment_stack, $current_segment);
				    } else {
					$current_segment = pop(@segment_stack);
					if (not $current_segment) {
					    push(@segment_stack, ".text\$");
				        }
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = ".text\$";
					push(@segment_stack, $current_segment);
					$v.="$current_segment\tSEGMENT ";
					$v.=$masm>=$masmref ? "ALIGN(256)" : "PAGE";
					$v.=" 'CODE'";
				    }
				    $self->{value} = $v;
				    last;
				  };
		/\.data/    && do { my $v=undef;
				    if ($nasm) {
					$v="section	.data data align=8\n";
				    } else {
					$current_segment = pop(@segment_stack);
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = "_DATA";
					push(@segment_stack, $current_segment);
					$v.="$current_segment\tSEGMENT";
				    }
				    $self->{value} = $v;
				    last;
				  };
		/\.section/ && do { my $v=undef;
				    my $align=undef;
				    #
				    # $$line may currently contain something like this
				    #	.rodata align = 64
				    # align part is optional
				    #
				    $align = $$line;
				    $align =~ s/(.*)(align\s*=\s*\d+$)/$2/;
				    $$line =~ s/(.*)(\s+align\s*=\s*\d+$)/$1/;
				    $$line =~ s/,.*//;
				    $$line = ".CRT\$XCU" if ($$line eq ".init");
				    $$line = ".rdata" if ($$line eq ".rodata");
				    if ($nasm) {
					$current_segment = pop(@segment_stack);
					if (not $current_segment) {
					    #
					    # This is a hack which deals with ecp_nistz256-x86_64.pl,
					    # The precomputed curve is stored in the first section
					    # in .asm file. Pushing extra .text section here
					    # allows our poor man's solution to stick to assumption
					    # .text section is always the first.
					    #
					    push(@segment_stack, ".text");
					}
					$v="section	$$line";
					if ($$line=~/\.([prx])data/) {
					    if ($align =~ /align\s*=\s*(\d+)/) {
						$v.= " rdata align=$1" ;
					    } else {
						$v.=" rdata align=";
						$v.=$1 eq "p"? 4 : 8;
					    }
					} elsif ($$line=~/\.CRT\$/i) {
					    $v.=" rdata align=8";
					}
				    } else {
					$current_segment = pop(@segment_stack);
					if (not $current_segment) {
					    #
					    # same hack for masm to keep ecp_nistz256-x86_64.pl
					    # happy.
					    #
					    push(@segment_stack, ".text\$");
				        }
					$v="$current_segment\tENDS\n" if ($current_segment);
					$v.="$$line\tSEGMENT";
					if ($$line=~/\.([prx])data/) {
					    $v.=" READONLY";
					    if ($align =~ /align\s*=\s*(\d+)$/) {
						$v.=" ALIGN($1)" if ($masm>=$masmref);
					    } else {
						$v.=" ALIGN(".($1 eq "p" ? 4 : 8).")" if ($masm>=$masmref);
					    }
					} elsif ($$line=~/\.CRT\$/i) {
					    $v.=" READONLY ";
					    $v.=$masm>=$masmref ? "ALIGN(8)" : "DWORD";
					}
				    }
				    $current_segment = $$line;
				    push(@segment_stack, $$line);
				    $self->{value} = $v;
				    last;
				  };
		/\.extern/  && do { $self->{value}  = "EXTERN\t".$$line;
				    $self->{value} .= ":NEAR" if ($masm);
				    last;
				  };
		/\.globl|.global/
			    && do { $self->{value}  = $masm?"PUBLIC":"global";
				    $self->{value} .= "\t".$$line;
				    last;
				  };
		/\.size/    && do { if (defined($current_function)) {
					undef $self->{value};
					if ($current_function->{abi} eq "svr4") {
					    $self->{value}="${decor}SEH_end_$current_function->{name}:";
					    $self->{value}.=":\n" if($masm);
					}
					$self->{value}.="$current_function->{name}\tENDP" if($masm && $current_function->{name} && $cfi_state ne 'endproc');
					undef $current_function;
					undef $cfi_state;
				    }
				    last;
				  };
		/\.align/   && do { my $max = ($masm && $masm>=$masmref) ? 256 : 4096;
				    $self->{value} = "ALIGN\t".($$line>$max?$max:$$line);
				    last;
				  };
		/\.(value|long|rva|quad)/
			    && do { my $sz  = substr($1,0,1);
				    my @arr = split(/,\s*/,$$line);
				    my $last = pop(@arr);
				    my $conv = sub  {	my $var=shift;
							$var=~s/^(0b[0-1]+)/oct($1)/eig;
							$var=~s/^0x([0-9a-f]+)/0$1h/ig if ($masm);
							if ($sz eq "D" && ($current_segment=~/.[px]data/ || $dir eq ".rva"))
							{ $var=~s/^([_a-z\$\@][_a-z0-9\$\@]*)/$nasm?"$1 wrt ..imagebase":"imagerel $1"/egi; }
							$var;
						    };

				    $sz =~ tr/bvlrq/BWDDQ/;
				    $self->{value} = "\tD$sz\t";
				    for (@arr) { $self->{value} .= &$conv($_).","; }
				    $self->{value} .= &$conv($last);
				    last;
				  };
		/\.byte/    && do { my @str=split(/,\s*/,$$line);
				    map(s/(0b[0-1]+)/oct($1)/eig,@str);
				    map(s/0x([0-9a-f]+)/0$1h/ig,@str) if ($masm);
				    while ($#str>15) {
					$self->{value}.="DB\t"
						.join(",",@str[0..15])."\n";
					foreach (0..15) { shift @str; }
				    }
				    $self->{value}.="DB\t"
						.join(",",@str) if (@str);
				    last;
				  };
		/\.comm/    && do { my @str=split(/,\s*/,$$line);
				    my $v=undef;
				    if ($nasm) {
					$v.="common	$prefix@str[0] @str[1]";
				    } else {
					$current_segment = pop(@segment_stack);;
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = "_DATA";
					push(@segment_stack, $current_segment);
					$v.="$current_segment\tSEGMENT\n";
					$v.="COMM	@str[0]:DWORD:".@str[1]/4;
				    }
				    $self->{value} = $v;
				    last;
				  };
		/^.previous/ && do {
				    my $v=undef;
				    if ($nasm) {
					pop(@segment_stack); # pop ourselves, we don't need to emit END directive
					# pop section so we can emit proper .section name.
					$current_segment = pop(@segment_stack);
					$v="section $current_segment";
					# Hack again:
					# push section/segment to stack. The .previous is currently paired
					# with .rodata only. We have to keep extra '.text' on stack for
					# situation where there is for example .pdata section 'terminated'
					# by new '.text' section.
					#
					push(@segment_stack, $current_segment);
				    } else {
					$current_segment = pop(@segment_stack);
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = pop(@segment_stack);
					if ($current_segment =~ /\.text\$/) {
					    $v.="$current_segment\tSEGMENT ";
					    $v.=$masm>=$masmref ? "ALIGN(256)" : "PAGE";
					    $v.=" 'CODE'";
					    push(@segment_stack, $current_segment);
					}
				    }
				    $self->{value} = $v;
				    last;
				    };
	    }
	    $$line = "";
	}

	$ret;
    }
    sub out {
	my $self = shift;
	$self->{value};
    }
}

# Upon initial x86_64 introduction SSE>2 extensions were not introduced
# yet. In order not to be bothered by tracing exact assembler versions,
# but at the same time to provide a bare security minimum of AES-NI, we
# hard-code some instructions. Extensions past AES-NI on the other hand
# are traced by examining assembler version in individual perlasm
# modules...

my %regrm = (	"%eax"=>0, "%ecx"=>1, "%edx"=>2, "%ebx"=>3,
		"%esp"=>4, "%ebp"=>5, "%esi"=>6, "%edi"=>7	);

sub rex {
 my $opcode=shift;
 my ($dst,$src,$rex)=@_;

   $rex|=0x04 if($dst>=8);
   $rex|=0x01 if($src>=8);
   push @$opcode,($rex|0x40) if ($rex);
}

my $movq = sub {	# elderly gas can't handle inter-register movq
  my $arg = shift;
  my @opcode=(0x66);
    if ($arg =~ /%xmm([0-9]+),\s*%r(\w+)/) {
	my ($src,$dst)=($1,$2);
	if ($dst !~ /[0-9]+/)	{ $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,$src,$dst,0x8);
	push @opcode,0x0f,0x7e;
	push @opcode,0xc0|(($src&7)<<3)|($dst&7);	# ModR/M
	@opcode;
    } elsif ($arg =~ /%r(\w+),\s*%xmm([0-9]+)/) {
	my ($src,$dst)=($2,$1);
	if ($dst !~ /[0-9]+/)	{ $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,$src,$dst,0x8);
	push @opcode,0x0f,0x6e;
	push @opcode,0xc0|(($src&7)<<3)|($dst&7);	# ModR/M
	@opcode;
    } else {
	();
    }
};

my $pextrd = sub {
    if (shift =~ /\$([0-9]+),\s*%xmm([0-9]+),\s*(%\w+)/) {
      my @opcode=(0x66);
	my $imm=$1;
	my $src=$2;
	my $dst=$3;
	if ($dst =~ /%r([0-9]+)d/)	{ $dst = $1; }
	elsif ($dst =~ /%e/)		{ $dst = $regrm{$dst}; }
	rex(\@opcode,$src,$dst);
	push @opcode,0x0f,0x3a,0x16;
	push @opcode,0xc0|(($src&7)<<3)|($dst&7);	# ModR/M
	push @opcode,$imm;
	@opcode;
    } else {
	();
    }
};

my $pinsrd = sub {
    if (shift =~ /\$([0-9]+),\s*(%\w+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	my $imm=$1;
	my $src=$2;
	my $dst=$3;
	if ($src =~ /%r([0-9]+)/)	{ $src = $1; }
	elsif ($src =~ /%e/)		{ $src = $regrm{$src}; }
	rex(\@opcode,$dst,$src);
	push @opcode,0x0f,0x3a,0x22;
	push @opcode,0xc0|(($dst&7)<<3)|($src&7);	# ModR/M
	push @opcode,$imm;
	@opcode;
    } else {
	();
    }
};

my $pshufb = sub {
    if (shift =~ /%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	rex(\@opcode,$2,$1);
	push @opcode,0x0f,0x38,0x00;
	push @opcode,0xc0|($1&7)|(($2&7)<<3);		# ModR/M
	@opcode;
    } else {
	();
    }
};

my $palignr = sub {
    if (shift =~ /\$([0-9]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x3a,0x0f;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	push @opcode,$1;
	@opcode;
    } else {
	();
    }
};

my $pclmulqdq = sub {
    if (shift =~ /\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x3a,0x44;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	@opcode;
    } else {
	();
    }
};

my $rdrand = sub {
    if (shift =~ /%[er](\w+)/) {
      my @opcode=();
      my $dst=$1;
	if ($dst !~ /[0-9]+/) { $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,0,$dst,8);
	push @opcode,0x0f,0xc7,0xf0|($dst&7);
	@opcode;
    } else {
	();
    }
};

my $rdseed = sub {
    if (shift =~ /%[er](\w+)/) {
      my @opcode=();
      my $dst=$1;
	if ($dst !~ /[0-9]+/) { $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,0,$dst,8);
	push @opcode,0x0f,0xc7,0xf8|($dst&7);
	@opcode;
    } else {
	();
    }
};

# Not all AVX-capable assemblers recognize AMD XOP extension. Since we
# are using only two instructions hand-code them in order to be excused
# from chasing assembler versions...

sub rxb {
 my $opcode=shift;
 my ($dst,$src1,$src2,$rxb)=@_;

   $rxb|=0x7<<5;
   $rxb&=~(0x04<<5) if($dst>=8);
   $rxb&=~(0x01<<5) if($src1>=8);
   $rxb&=~(0x02<<5) if($src2>=8);
   push @$opcode,$rxb;
}

my $vprotd = sub {
    if (shift =~ /\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x8f);
	rxb(\@opcode,$3,$2,-1,0x08);
	push @opcode,0x78,0xc2;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	@opcode;
    } else {
	();
    }
};

my $vprotq = sub {
    if (shift =~ /\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x8f);
	rxb(\@opcode,$3,$2,-1,0x08);
	push @opcode,0x78,0xc3;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	@opcode;
    } else {
	();
    }
};

# Intel Control-flow Enforcement Technology extension. All functions and
# indirect branch targets will have to start with this instruction...

my $endbranch = sub {
    (0xf3,0x0f,0x1e,0xfa);
};

########################################################################

if ($nasm) {
    print <<___;
default	rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
___
    if ($win64) {
        print <<___;
;; For concatenation.
%define SEH64_CONCAT(a,b) a %+ b

%ifndef __YASM_MAJOR__
 ;; \@name Register numbers.
 ;; \@{
 %define SEH64_PE_GREG_rax     0
 %define SEH64_PE_GREG_rcx     1
 %define SEH64_PE_GREG_rdx     2
 %define SEH64_PE_GREG_rbx     3
 %define SEH64_PE_GREG_rsp     4
 %define SEH64_PE_GREG_rbp     5
 %define SEH64_PE_GREG_rsi     6
 %define SEH64_PE_GREG_rdi     7
 %define SEH64_PE_GREG_r8      8
 %define SEH64_PE_GREG_r9      9
 %define SEH64_PE_GREG_r10     10
 %define SEH64_PE_GREG_r11     11
 %define SEH64_PE_GREG_r12     12
 %define SEH64_PE_GREG_r13     13
 %define SEH64_PE_GREG_r14     14
 %define SEH64_PE_GREG_r15     15

 %define SEH64_PE_XREG_xmm0     0
 %define SEH64_PE_XREG_xmm1     1
 %define SEH64_PE_XREG_xmm2     2
 %define SEH64_PE_XREG_xmm3     3
 %define SEH64_PE_XREG_xmm4     4
 %define SEH64_PE_XREG_xmm5     5
 %define SEH64_PE_XREG_xmm6     6
 %define SEH64_PE_XREG_xmm7     7
 %define SEH64_PE_XREG_xmm8     8
 %define SEH64_PE_XREG_xmm9     9
 %define SEH64_PE_XREG_xmm10    10
 %define SEH64_PE_XREG_xmm11    11
 %define SEH64_PE_XREG_xmm12    12
 %define SEH64_PE_XREG_xmm13    13
 %define SEH64_PE_XREG_xmm14    14
 %define SEH64_PE_XREG_xmm15    15
 ;; \@}

 ;; \@name PE unwind operations.
 ;; \@{
 %define SEH64_PE_PUSH_NONVOL      0
 %define SEH64_PE_ALLOC_LARGE      1
 %define SEH64_PE_ALLOC_SMALL      2
 %define SEH64_PE_SET_FPREG        3
 %define SEH64_PE_SAVE_NONVOL      4
 %define SEH64_PE_SAVE_NONVOL_FAR  5
 %define SEH64_PE_SAVE_XMM128      8
 %define SEH64_PE_SAVE_XMM128_FAR  9
 ;; \@}

 ;; We keep the unwind bytes in the seh64_slot_bytes (x)define, in reverse order as per spec.
 %macro SEH64_APPEND_SLOT_PAIR 2
  %ifdef seh64_slot_bytes
   %xdefine seh64_slot_bytes %1, %2, seh64_slot_bytes
  %else
   %xdefine seh64_slot_bytes %1, %2
  %endif
 %endmacro

 ;; For multi-slot unwind info.
 %macro SEH64_APPEND_SLOT_BYTES 2+
  %rep %0
   %rotate -1
   %ifdef seh64_slot_bytes
    %xdefine seh64_slot_bytes %1, seh64_slot_bytes
   %else
    %xdefine seh64_slot_bytes %1
   %endif
  %endrep
 %endmacro

 ;; For generating labels.
 %define SEH64_OP_LABEL(a_idx) asm_seh64_proc %+ .seh64_op_label %+ a_idx
%endif ; !__YASM__

;; For producing proper .labels despite .Lxxxx labels messing up the prefixing.
%define SEH64_DOT_LABEL(a_DotLabel) SEH64_CONCAT(asm_seh64_proc,a_DotLabel)

%macro SEH64_PROC_FRAME 2
 %define asm_seh64_proc %1
 %ifdef __YASM_MAJOR__
        proc_frame %1
 %else
  %assign seh64_idxOps   0
  ;%assign seh64_FrameReg SEH64_PE_GREG_rsp
  %assign seh64_FrameReg 0
  %assign seh64_offFrame 0
  %undef  seh64_slot_bytes
%1:
.start_of_prologue:
 %endif
%endmacro

%macro SEH64_ENDPROC_FRAME 1
SEH64_DOT_LABEL(.end_proc):
 %ifdef __YASM_MAJOR__
	[endproc_frame]
 %else
        ; Emit the RUNTIME_FUNCTION entry.  The linker is picky here, no label.
  %ifndef ASM_DEFINED_PDATA_SECTION
   %define ASM_DEFINED_PDATA_SECTION
        section .pdata rdata align=4
  %else
        section .pdata
  %endif
        dd      %1                              wrt ..imagebase
        dd      SEH64_DOT_LABEL(.end_proc)      wrt ..imagebase
        dd      SEH64_DOT_LABEL(.unwind_info)   wrt ..imagebase

        ; Restore code section.
        section .text
 %endif
%endmacro

%macro SEH64_ENDPROLOG 0
SEH64_DOT_LABEL(.end_of_prologue):
 %ifdef __YASM_MAJOR__
        [endprolog]
 %else
        ; Emit the unwind info now.
  %ifndef ASM_DEFINED_XDATA_SECTION
   %define ASM_DEFINED_XDATA_SECTION
        section .xdata rdata align=4
  %else
        section .xdata
        align   4, db 0
  %endif
SEH64_DOT_LABEL(.unwind_info):
        db      1                       ; version 1 (3 bit), no flags (5 bits)
        db      SEH64_DOT_LABEL(.end_of_prologue) - SEH64_DOT_LABEL(.start_of_prologue)

        db      (SEH64_DOT_LABEL(.unwind_info_array_end) - SEH64_DOT_LABEL(.unwind_info_array)) / 2
        db      seh64_FrameReg | (seh64_offFrame & 0xf0) ; framereg and offset/16.
SEH64_DOT_LABEL(.unwind_info_array):
   %ifdef seh64_slot_bytes
        db      seh64_slot_bytes
    %undef seh64_slot_bytes
   %endif
SEH64_DOT_LABEL(.unwind_info_array_end):

        ; Reset the segment
        section .text
 %endif
%endmacro

%macro SEH64_ALLOCSTACK 1
 %ifdef __YASM_MAJOR__
        [allocstack %1]
 %else
SEH64_OP_LABEL(seh64_idxOps):
  %if (%1) & 7
   %error "SEH64_ALLOCSTACK must be a multiple of 8"
  %endif
  %if (%1) < 8
   %error "SEH64_ALLOCSTACK must have an argument that's 8 or higher."
  %elif (%1) <= 128
   SEH64_APPEND_SLOT_PAIR \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
        SEH64_PE_ALLOC_SMALL | ((((%1) / 8) - 1) << 4)
  %elif (%1) < 512
   SEH64_APPEND_SLOT_BYTES \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
	SEH64_PE_ALLOC_LARGE | 0, \\
	((%1) / 8) & 0xff, ((%1) / 8) >> 8
  %else
   SEH64_APPEND_SLOT_BYTES \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
	SEH64_PE_ALLOC_LARGE | 1, \\
	(%1) & 0xff, ((%1) >> 8) & 0xff, ((%1) >> 16) & 0xff, ((%1) >> 24) & 0xff
  %endif
  %assign seh64_idxOps seh64_idxOps + 1
 %endif
%endmacro

%macro SEH64_PUSHREG 1
 %ifdef __YASM_MAJOR__
        [pushreg %1]
 %else
SEH64_OP_LABEL(seh64_idxOps):
  SEH64_APPEND_SLOT_PAIR \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
	SEH64_PE_PUSH_NONVOL | (SEH64_PE_GREG_ %+ %1 << 4)
  %assign seh64_idxOps seh64_idxOps + 1
 %endif
%endmacro

%macro SEH64_SAVEREG 2
 %ifdef __YASM_MAJOR__
        [savereg %1, %2]
 %else
  %if (%2) & 7
   %error "SEH64_SAVEREG offset must be a multiple of 8"
  %endif
  %if (%2) <= (65535*8)
SEH64_OP_LABEL(seh64_idxOps):
   SEH64_APPEND_SLOT_BYTES \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
	SEH64_PE_SAVE_NONVOL | (SEH64_PE_GREG_ %+ %1 << 4), \\
	((%2) / 8) & 0xff, \\
	((%2) / 8) >> 8
  %else
   %error "SEH64_SAVEREG implement far offsets"
  %endif
  %assign seh64_idxOps seh64_idxOps + 1
 %endif
%endmacro

%macro SEH64_SAVEXMM128 2
 %ifdef __YASM_MAJOR__
        [savexmm128 %1, %2]
 %else
SEH64_OP_LABEL(seh64_idxOps):
  %if (%2) & 15
   %error "SEH64_SAVE_XMM128 offset must be a multiple of 16"
  %endif
  %if (%2) <= (65535*16)
   SEH64_APPEND_SLOT_BYTES \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
        SEH64_PE_SAVE_XMM128 | (SEH64_PE_XREG_ %+ %1 << 4), \\
        ((%2) / 16) & 0xff, \\
        ((%2) / 16) >> 8
  %else
   %error "SEH64_SAVE_XMM128 implement far offsets"
  %endif
  %assign seh64_idxOps seh64_idxOps + 1
 %endif
%endmacro

%macro SEH64_SETFRAME 2
 %ifdef __YASM_MAJOR__
        [setframe %1, %2]
 %else
SEH64_OP_LABEL(seh64_idxOps):
  SEH64_APPEND_SLOT_PAIR \\
	SEH64_OP_LABEL(seh64_idxOps) - SEH64_DOT_LABEL(.start_of_prologue), \\
        SEH64_PE_SET_FPREG | 0
  %assign seh64_FrameReg SEH64_PE_GREG_ %+ %1
  %assign seh64_offFrame %2
  %assign seh64_idxOps seh64_idxOps + 1
 %endif
%endmacro
___
    }
} elsif ($masm) {
    print <<___;
OPTION	DOTNAME
___
    if ($win64) {
        print <<___;
SEH64_PROC_FRAME MACRO a_Name, a_Scope
    a_Name PROC a_Scope FRAME
ENDM
SEH64_ENDPROC_FRAME MACRO a_Name
    a_Name ENDP
ENDM
SEH64_ENDPROLOG MACRO
    .ENDPROLOG
ENDM
SEH64_ALLOCSTACK MACRO a_Size
    .ALLOCSTACK a_Size
ENDM
SEH64_PUSHREG MACRO a_Reg
    .PUSHREG a_Reg
ENDM
SEH64_SAVEREG MACRO a_Reg, a_Offset
    .SAVEREG a_Reg, a_Offset
ENDM
SEH64_SAVEXMM128 MACRO a_XReg, a_Offset
    .SAVEXMM128 a_XReg, a_Offset
ENDM
SEH64_SETFRAME MACRO a_Reg, a_Offset
    .SETFRAME a_Reg, a_Offset
ENDM
___
    }
} elsif ($gas) {
    print <<___ if ($win64);
# Converting register names to constants.
.equ seh64_greg_rax,	0
.equ seh64_greg_rcx,	1
.equ seh64_greg_rdx,	2
.equ seh64_greg_rbx,	3
.equ seh64_greg_rsp,	4
.equ seh64_greg_rbp,	5
.equ seh64_greg_rsi,	6
.equ seh64_greg_rdi,	7
.equ seh64_greg_r8,	8
.equ seh64_greg_r9,	9
.equ seh64_greg_r10,	10
.equ seh64_greg_r11,	11
.equ seh64_greg_r12,	12
.equ seh64_greg_r13,	13
.equ seh64_greg_r14,	14
.equ seh64_greg_r15,	15
.equ seh64_greg_shl4_rax,	0  << 4
.equ seh64_greg_shl4_rcx,	1  << 4
.equ seh64_greg_shl4_rdx,	2  << 4
.equ seh64_greg_shl4_rbx,	3  << 4
.equ seh64_greg_shl4_rsp,	4  << 4
.equ seh64_greg_shl4_rbp,	5  << 4
.equ seh64_greg_shl4_rsi,	6  << 4
.equ seh64_greg_shl4_rdi,	7  << 4
.equ seh64_greg_shl4_r8,	8  << 4
.equ seh64_greg_shl4_r9,	9  << 4
.equ seh64_greg_shl4_r10,	10 << 4
.equ seh64_greg_shl4_r11,	11 << 4
.equ seh64_greg_shl4_r12,	12 << 4
.equ seh64_greg_shl4_r13,	13 << 4
.equ seh64_greg_shl4_r14,	14 << 4
.equ seh64_greg_shl4_r15,	15 << 4
.equ seh64_xreg_shl4_xmm0,	0  << 4
.equ seh64_xreg_shl4_xmm1,	1  << 4
.equ seh64_xreg_shl4_xmm2,	2  << 4
.equ seh64_xreg_shl4_xmm3,	3  << 4
.equ seh64_xreg_shl4_xmm4,	4  << 4
.equ seh64_xreg_shl4_xmm5,	5  << 4
.equ seh64_xreg_shl4_xmm6,	6  << 4
.equ seh64_xreg_shl4_xmm7,	7  << 4
.equ seh64_xreg_shl4_xmm8,	8  << 4
.equ seh64_xreg_shl4_xmm9,	9  << 4
.equ seh64_xreg_shl4_xmm10,	10 << 4
.equ seh64_xreg_shl4_xmm11,	11 << 4
.equ seh64_xreg_shl4_xmm12,	12 << 4
.equ seh64_xreg_shl4_xmm13,	13 << 4
.equ seh64_xreg_shl4_xmm14,	14 << 4
.equ seh64_xreg_shl4_xmm15,	15 << 4

# FP register tracking... not sure if this works...
.equ seh64_fpreg_no_and_offset, 0

# The current .xdata subsection index.  We work in reverse order (decrementing),
# since the unwind opcodes must be stored in reverse order.
.equ seh64_sec_no, 999999
# Define the .xdata section (unwind info).
.section .xdata, "r0"
# Define the .pdata section (function table).
.section .pdata, "r2"
# Back to the .text section.
.section .text

.macro SEH64_PROC_FRAME a_Name, a_Scope
\\a_Name:
\\a_Name\\().start_of_prologue:
9:

# Define end of the unwind info array (opcode):
.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
\\a_Name\\().unwind_info_array_end:
# Back to the .text section.
.section .text

.endm

.macro SEH64_ENDPROC_FRAME a_Name
\\a_Name\\().end_proc:

# Emit the RUNTIME_FUNCTION entry.  The linker is picky here, no label.
.section .pdata
	.rva	\\a_Name
	.rva	\\a_Name\\().end_proc
	.rva	\\a_Name\\().unwind_info
# Back to the .text section.
.section .text

.endm

.macro SEH64_ENDPROLOG a_Name
\\a_Name\\().end_of_prologue:

.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
\\a_Name\\().unwind_info:
	.byte	1                       # version 1 (3 bit), no flags (5 bits)
	.byte	\\a_Name\\().end_of_prologue - \\a_Name\\().start_of_prologue
	.byte	(\\a_Name\\().unwind_info_array_end - \\a_Name\\().unwind_info_array) / 2
	.byte	seh64_fpreg_no_and_offset # framereg and offset/16.
\\a_Name\\().unwind_info_array:

# Back to the .text section.
.section .text
.endm

.macro SEH64_ALLOCSTACK a_Size
# Local post-instruction label.
8:

# Switch to the current opcode subsection of .xdata and emit the unwind code.
.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
	# The prolog offset.
	.byte	8b - 9b
	# The opcode and associated data.
.if \\a_Size < 8
 .error "SEH64_ALLOCSTACK must have an argument that's 8 or higher."
.elseif (\\a_Size) <= 128
	.byte	2 | ((((\\a_Size) / 8) - 1) << 4)       # 2 = SEH64_PE_ALLOC_SMALL
.elseif (\\a_Size) < 512
	.byte	1 | (0 << 4)                            # 1 = SEH64_PE_ALLOC_LARGE
	.byte	(\\a_Size / 8) & 0xff, ((\\a_Size) / 8) >> 8
.else
	.byte	1 | (1 << 4)                            # 1 = SEH64_PE_ALLOC_LARGE
	.byte	(\\a_Size) & 0xff, ((\\a_Size) >> 8) & 0xff, ((\\a_Size) >> 16) & 0xff, ((\\a_Size) >> 24) & 0xff
.endif

# Back to the .text section.
.section .text
.endm

.macro SEH64_PUSHREG a_Reg
# Local post-instruction label.
8:

# Switch to the current opcode subsection of .xdata and emit the unwind code.
.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
	# The prolog offset.
	.byte	8b - 9b
	# The opcode and associated data.
	.byte	0 + seh64_greg_shl4_\\()\\a_Reg         # 0 = SEH64_PE_PUSH_NONVOL

# Back to the .text section.
.section .text
.endm

.macro SEH64_SAVEREG a_Reg, a_Offset
# Local post-instruction label.
8:

# Switch to the current opcode subsection of .xdata and emit the unwind code.
.if (\\a_Offset) & 7
 .error "SEH64_SAVEREG: Offset must be a multiple of 8."
.endif
.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
	# The prolog offset.
	.byte	8b - 9b
.if (\\a_Offset) < (65535*8)
	# The opcode and associated data.
	.byte	4 + (seh64_greg_shl4_\\()\\a_Reg)        # 4 = SEH64_PE_SAVE_NONVOL
	.byte	((\\a_Offset) / 8) & 0xff
	.byte	((\\a_Offset) / 8) >> 8
.else
 .error "SEH64_SAVEREG: Implement SEH64_PE_SAVE_NONVOL_FAR"
.endif

# Back to the .text section.
.section .text
.endm

.macro SEH64_SAVEXMM128 a_XReg, a_Offset
# Local post-instruction label.
8:

# Switch to the current opcode subsection of .xdata and emit the unwind code.
.if (\\a_Offset) & 15
 .error "SEH64_SAVEXMM128: Offset must be a multiple of 16."
.endif
.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
	# The prolog offset.
	.byte	8b - 9b
.if (\\a_Offset) < (65535*8)
	# The opcode and associated data.
	.byte	8 + seh64_xreg_shl4_\\()\\a_XReg        # 8 = SEH64_PE_SAVE_XMM128
	.byte	((\\a_Offset) / 16) & 0xff
	.byte	((\\a_Offset) / 16) >> 8
.else
 .error "SEH64_SAVEXMM128: Implement SEH64_PE_SAVE_XMM128_FAR"
.endif

# Back to the .text section.
.section .text
.endm

.macro SEH64_SETFRAME a_Reg, a_Offset
.if (\\a_Offset & 15) || (\\a_Offset > 240) # (\\a_Offset < 8)
 .error "SEH64_SETFRAME offset is out of range or misaligned: \\a_Offset"
.endif
.equ seh64_fpreg_no_and_offset, seh64_greg_\\()\\a_Reg + \\a_Offset

# Local post-instruction label.
8:

# Switch to the current opcode subsection of .xdata and emit the unwind code.
.equ seh64_sec_no, (seh64_sec_no - 1)
.section .xdata, seh64_sec_no
	# The prolog offset.
	.byte	8b - 9b
	# The opcode and associated data.
	.byte	3                                       # 3 = SEH64_PE_SET_FPREG

# Back to the .text section.
.section .text
.endm
___
}
while(defined(my $line=<>)) {

    $line =~ s|\R$||;           # Better chomp

    $line =~ s|[#!].*$||;	# get rid of asm-style comments...
    $line =~ s|/\*.*\*/||;	# ... and C-style comments...
    $line =~ s|^\s+||;		# ... and skip whitespaces in beginning
    $line =~ s|\s+$||;		# ... and at the end

    if (my $label=label->re(\$line))	{ print $label->out(); }

    if (my $directive=directive->re(\$line)) {
	printf "%s",$directive->out();
    } else {
	if (my $vex_prefix=vex_prefix->re(\$line)) {
	printf "%s",$vex_prefix->out();
	}
	if (my $opcode=opcode->re(\$line)) {
	my $asm = eval("\$".$opcode->mnemonic());

	if ((ref($asm) eq 'CODE') && scalar(my @bytes=&$asm($line))) {
	    print $gas?".byte\t":"DB\t",join(',',@bytes),"\n";
	    next;
	}

	my @args;
	ARGUMENT: while (1) {
	    my $arg;

	    ($arg=register->re(\$line, $opcode))||
	    ($arg=const->re(\$line))		||
	    ($arg=ea->re(\$line, $opcode))	||
	    ($arg=expr->re(\$line, $opcode))	||
	    last ARGUMENT;

	    push @args,$arg;

	    last ARGUMENT if ($line !~ /^,/);

	    $line =~ s/^,\s*//;
	} # ARGUMENT:

	if ($#args>=0) {
	    my $insn;
	    my $sz=$opcode->size();

	    if ($gas) {
		$insn = $opcode->out($#args>=1?$args[$#args]->size():$sz);
		@args = map($_->out($sz),@args);
		printf "\t%s\t%s",$insn,join(",",@args);
	    } else {
		$insn = $opcode->out();
		foreach (@args) {
		    my $arg = $_->out();
		    # $insn.=$sz compensates for movq, pinsrw, ...
		    if ($arg =~ /^xmm[0-9]+$/) { $insn.=$sz; $sz="x" if(!$sz); last; }
		    if ($arg =~ /^ymm[0-9]+$/) { $insn.=$sz; $sz="y" if(!$sz); last; }
		    if ($arg =~ /^zmm[0-9]+$/) { $insn.=$sz; $sz="z" if(!$sz); last; }
		    if ($arg =~ /^mm[0-9]+$/)  { $insn.=$sz; $sz="q" if(!$sz); last; }
		}
		@args = reverse(@args);
		undef $sz if ($nasm && $opcode->mnemonic() eq "lea");
		printf "\t%s\t%s",$insn,join(",",map($_->out($sz),@args));
	    }
	} else {
	    printf "\t%s",$opcode->out();
	}
	}
    }

    print $line,"\n";
}

print "$cet_property"			if ($cet_property);
print "\n$current_segment\tENDS\n"	if ($current_segment && $masm);
print "END\n"				if ($masm);

close STDOUT or die "error closing STDOUT: $!;"

#################################################
# Cross-reference x86_64 ABI "card"
#
# 		Unix		Win64
# %rax		*		*
# %rbx		-		-
# %rcx		#4		#1
# %rdx		#3		#2
# %rsi		#2		-
# %rdi		#1		-
# %rbp		-		-
# %rsp		-		-
# %r8		#5		#3
# %r9		#6		#4
# %r10		*		*
# %r11		*		*
# %r12		-		-
# %r13		-		-
# %r14		-		-
# %r15		-		-
#
# (*)	volatile register
# (-)	preserved by callee
# (#)	Nth argument, volatile
#
# In Unix terms top of stack is argument transfer area for arguments
# which could not be accommodated in registers. Or in other words 7th
# [integer] argument resides at 8(%rsp) upon function entry point.
# 128 bytes above %rsp constitute a "red zone" which is not touched
# by signal handlers and can be used as temporal storage without
# allocating a frame.
#
# In Win64 terms N*8 bytes on top of stack is argument transfer area,
# which belongs to/can be overwritten by callee. N is the number of
# arguments passed to callee, *but* not less than 4! This means that
# upon function entry point 5th argument resides at 40(%rsp), as well
# as that 32 bytes from 8(%rsp) can always be used as temporal
# storage [without allocating a frame]. One can actually argue that
# one can assume a "red zone" above stack pointer under Win64 as well.
# Point is that at apparently no occasion Windows kernel would alter
# the area above user stack pointer in true asynchronous manner...
#
# All the above means that if assembler programmer adheres to Unix
# register and stack layout, but disregards the "red zone" existence,
# it's possible to use following prologue and epilogue to "gear" from
# Unix to Win64 ABI in leaf functions with not more than 6 arguments.
#
# omnipotent_function:
# ifdef WIN64
#	movq	%rdi,8(%rsp)
#	movq	%rsi,16(%rsp)
#	movq	%rcx,%rdi	; if 1st argument is actually present
#	movq	%rdx,%rsi	; if 2nd argument is actually ...
#	movq	%r8,%rdx	; if 3rd argument is ...
#	movq	%r9,%rcx	; if 4th argument ...
#	movq	40(%rsp),%r8	; if 5th ...
#	movq	48(%rsp),%r9	; if 6th ...
# endif
#	...
# ifdef WIN64
#	movq	8(%rsp),%rdi
#	movq	16(%rsp),%rsi
# endif
#	ret
#
#################################################
# Win64 Unwind Instructions
#
# Unlike on Unix systems(*) lack of Win64 stack unwinding information
# has undesired side-effect at run-time: if an exception is raised in
# assembler subroutine such as those in question (basically we're
# referring to segmentation violations caused by malformed input
# parameters), the application is briskly terminated without invoking
# any exception handlers, most notably without generating memory dump
# or any user notification whatsoever. This poses a problem. This was
# previously dealth with using custom exception handlers, which were
# difficult to maintain and offered zero help in a debugger. These days,
# Win64 piggy backs on the dwarf unwind directives (.cfi_startproc,
# .cfi_cfa_expression, .cfi_offset, ..., .cfi_endproc).
#
# The Windows x86_64 unwind information is very basic and inflexible
# compared to DWARF.  For starters, it only covers the prologue and
# just assumes RtlVirtualUnwind and others will figure out how to
# unwind the epilogue.  A requirement is that the end of the prologue
# is marked.  Since DWARF/gas doesn't have an .cfi_ directive for this
# we have introduced our own pseudo directive .cfi_endprolog.
#
# .cfi_endprolog: Marks the end of the prologue, i.e. where a reliable
# stack frame has been established.  For Win64 the frame register and
# offset is established with this directive rather than when any of
# the .cfa_def_cfa* directives was used earlier in the prologue.  This
# is different from the way DWARF works and must be kept in mind.
#
# Any function with a .cfi_startproc must have both a .cfi_endprolog
# as well as a .cfi_endproc directive. The .cfi_endproc directive must
# be followed by a .size directive.
#
# .cfi_stackalloc <bytes>: This pseudo directive indicates that %rsp
# has been adjusted, irrespective of whether it is the register for
# the frame or not.  If %rsp is defined as the CFA register, it will
# also update the CFA offset.
#
# Since the CFA register is only established at .cfi_endprolog in the
# Win64 unwind instructions, this directive is necessary to keep
# track of %rsp changes as these are always relevant to unwinding on
# Win64 before that point.
#
# .cfi_sp_offset <reg>,<offset>: Same as .cfi_offset, only it is
# relative to the current %rsp rather than the CFA.  This can be a
# lot simpler to use when the instruction doing the register saving
# is using %rsp for addressing.
#
# For an exact reference of the x86_64 Windows unwind handling, wine's
# implementation of RtlVirtualUnwind2 can be very helpful, see:
# https://gitlab.winehq.org/wine/wine/-/blob/b9f5aa42b1532a80963583cabeaeec2a4b479d9f/dlls/ntdll/unwind.c#L2053
#
#
#################################################
# HISTORICAL - Win64 SEH, Structured Exception Handling
# This is left here for explaining the %rax=%rsp coding pattern.
#
# It's possible to address it by registering custom language-specific
# handler that would restore processor context to the state at
# subroutine entry point and return "exception is not handled, keep
# unwinding" code. Writing such handler can be a challenge... But it's
# doable, though requires certain coding convention. Consider following
# snippet:
#
# .type	function,@function
# function:
#	movq	%rsp,%rax	# copy rsp to volatile register
#	pushq	%r15		# save non-volatile registers
#	pushq	%rbx
#	pushq	%rbp
#	movq	%rsp,%r11
#	subq	%rdi,%r11	# prepare [variable] stack frame
#	andq	$-64,%r11
#	movq	%rax,0(%r11)	# check for exceptions
#	movq	%r11,%rsp	# allocate [variable] stack frame
#	movq	%rax,0(%rsp)	# save original rsp value
# magic_point:
#	...
#	movq	0(%rsp),%rcx	# pull original rsp value
#	movq	-24(%rcx),%rbp	# restore non-volatile registers
#	movq	-16(%rcx),%rbx
#	movq	-8(%rcx),%r15
#	movq	%rcx,%rsp	# restore original rsp
# magic_epilogue:
#	ret
# .size function,.-function
#
# The key is that up to magic_point copy of original rsp value remains
# in chosen volatile register and no non-volatile register, except for
# rsp, is modified. While past magic_point rsp remains constant till
# the very end of the function. In this case custom language-specific
# exception handler would look like this:
#
# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
# {	ULONG64 *rsp = (ULONG64 *)context->Rax;
#	ULONG64  rip = context->Rip;
#
#	if (rip >= magic_point)
#	{   rsp = (ULONG64 *)context->Rsp;
#	    if (rip < magic_epilogue)
#	    {	rsp = (ULONG64 *)rsp[0];
#		context->Rbp = rsp[-3];
#		context->Rbx = rsp[-2];
#		context->R15 = rsp[-1];
#	    }
#	}
#	context->Rsp = (ULONG64)rsp;
#	context->Rdi = rsp[1];
#	context->Rsi = rsp[2];
#
#	memcpy (disp->ContextRecord,context,sizeof(CONTEXT));
#	RtlVirtualUnwind(UNW_FLAG_NHANDLER,disp->ImageBase,
#		dips->ControlPc,disp->FunctionEntry,disp->ContextRecord,
#		&disp->HandlerData,&disp->EstablisherFrame,NULL);
#	return ExceptionContinueSearch;
# }
#
# It's appropriate to implement this handler in assembler, directly in
# function's module. In order to do that one has to know members'
# offsets in CONTEXT and DISPATCHER_CONTEXT structures and some constant
# values. Here they are:
#
#	CONTEXT.Rax				120
#	CONTEXT.Rcx				128
#	CONTEXT.Rdx				136
#	CONTEXT.Rbx				144
#	CONTEXT.Rsp				152
#	CONTEXT.Rbp				160
#	CONTEXT.Rsi				168
#	CONTEXT.Rdi				176
#	CONTEXT.R8				184
#	CONTEXT.R9				192
#	CONTEXT.R10				200
#	CONTEXT.R11				208
#	CONTEXT.R12				216
#	CONTEXT.R13				224
#	CONTEXT.R14				232
#	CONTEXT.R15				240
#	CONTEXT.Rip				248
#	CONTEXT.Xmm6				512
#	sizeof(CONTEXT)				1232
#	DISPATCHER_CONTEXT.ControlPc		0
#	DISPATCHER_CONTEXT.ImageBase		8
#	DISPATCHER_CONTEXT.FunctionEntry	16
#	DISPATCHER_CONTEXT.EstablisherFrame	24
#	DISPATCHER_CONTEXT.TargetIp		32
#	DISPATCHER_CONTEXT.ContextRecord	40
#	DISPATCHER_CONTEXT.LanguageHandler	48
#	DISPATCHER_CONTEXT.HandlerData		56
#	UNW_FLAG_NHANDLER			0
#	ExceptionContinueSearch			1
#
# In order to tie the handler to the function one has to compose
# couple of structures: one for .xdata segment and one for .pdata.
#
# UNWIND_INFO structure for .xdata segment would be
#
# function_unwind_info:
#	.byte	9,0,0,0
#	.rva	handler
#
# This structure designates exception handler for a function with
# zero-length prologue, no stack frame or frame register.
#
# To facilitate composing of .pdata structures, auto-generated "gear"
# prologue copies rsp value to rax and denotes next instruction with
# .LSEH_begin_{function_name} label. This essentially defines the SEH
# styling rule mentioned in the beginning. Position of this label is
# chosen in such manner that possible exceptions raised in the "gear"
# prologue would be accounted to caller and unwound from latter's frame.
# End of function is marked with respective .LSEH_end_{function_name}
# label. To summarize, .pdata segment would contain
#
#	.rva	.LSEH_begin_function
#	.rva	.LSEH_end_function
#	.rva	function_unwind_info
#
# Reference to function_unwind_info from .xdata segment is the anchor.
# In case you wonder why references are 32-bit .rvas and not 64-bit
# .quads. References put into these two segments are required to be
# *relative* to the base address of the current binary module, a.k.a.
# image base. No Win64 module, be it .exe or .dll, can be larger than
# 2GB and thus such relative references can be and are accommodated in
# 32 bits.
#
# Having reviewed the example function code, one can argue that "movq
# %rsp,%rax" above is redundant. It is not! Keep in mind that on Unix
# rax would contain an undefined value. If this "offends" you, use
# another register and refrain from modifying rax till magic_point is
# reached, i.e. as if it was a non-volatile register. If more registers
# are required prior [variable] frame setup is completed, note that
# nobody says that you can have only one "magic point." You can
# "liberate" non-volatile registers by denoting last stack off-load
# instruction and reflecting it in finer grade unwind logic in handler.
# After all, isn't it why it's called *language-specific* handler...
#
# SE handlers are also involved in unwinding stack when executable is
# profiled or debugged. Profiling implies additional limitations that
# are too subtle to discuss here. For now it's sufficient to say that
# in order to simplify handlers one should either a) offload original
# %rsp to stack (like discussed above); or b) if you have a register to
# spare for frame pointer, choose volatile one.
#
# (*)	Note that we're talking about run-time, not debug-time. Lack of
#	unwind information makes debugging hard on both Windows and
#	Unix. "Unlike" refers to the fact that on Unix signal handler
#	will always be invoked, core dumped and appropriate exit code
#	returned to parent (for user notification).
#
# HISTORICAL END
