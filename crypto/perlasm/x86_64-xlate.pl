#!/usr/bin/env perl

# Ascetic x86_64 AT&T to MASM assembler translator by <appro>.
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
# - indirect calls and jumps are not supported;
#
# Dual-ABI styling rules.
#
# 1. Adhere to Unix register and stack layout [see the end for
#    explanation].
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
# 7. Due to MASM limitations [and certain general counter-intuitivity
#    of ip-relative addressing] generation of position-independent
#    code is assisted by synthetic directive, .picmeup, which puts
#    address of the *next* instruction into target register.
#
#    Example 1:
#		.picmeup	%rax
#		lea		.Label-.(%rax),%rax
#    Example 2:
#		.picmeup	%rcx
#	.Lpic_point:
#		...
#		lea		.Label-.Lpic_point(%rcx),%rbp

my $output = shift;

{ my ($stddev,$stdino,@junk)=stat(STDOUT);
  my ($outdev,$outino,@junk)=stat($output);

    open STDOUT,">$output" || die "can't open $output: $!"
	if ($stddev!=$outdev || $stdino!=$outino);
}

my $win64=1 if ($output =~ /\.asm/);

my $masmref=8 + 50727*2**-32;	# 8.00.50727 shipped with VS2005
my $masm=$masmref;
my $PTR=" PTR";

my $nasm=0;

if ($win64)
{   if ($ENV{ASM} =~ m/nasm/)
    {	$nasm = 1; $PTR="";   }
    elsif (`ml64 2>&1` =~ m/Version ([0-9]+)\.([0-9]+)(\.([0-9]+))?/)
    {	$masm = $1 + $2*2**-16 + $4*2**-32;   }
}

my $current_segment;
my $current_function;

{ package opcode;	# pick up opcodes
    sub re {
	my	$self = shift;	# single instance in enough...
	local	*line = shift;
	undef	$ret;

	if ($line =~ /^([a-z][a-z0-9]*)/i) {
	    $self->{op} = $1;
	    $ret = $self;
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;

	    undef $self->{sz};
	    if ($self->{op} =~ /^(movz)b.*/) {	# movz is pain...
		$self->{op} = $1;
		$self->{sz} = "b";
	    } elsif ($self->{op} =~ /call/) {
		$self->{sz} = ""
	    } elsif ($self->{op} =~ /([a-z]{3,})([qlwb])$/) {
		$self->{op} = $1;
		$self->{sz} = $2;
	    }
	}
	$ret;
    }
    sub size {
	my $self = shift;
	my $sz   = shift;
	$self->{sz} = $sz if (defined($sz) && !defined($self->{sz}));
	$self->{sz};
    }
    sub out {
	my $self = shift;
	if (!$win64) {
	    if ($self->{op} eq "movz") {	# movz is pain...
		sprintf "%s%s%s",$self->{op},$self->{sz},shift;
	    } elsif ($self->{op} =~ /^set/) { 
		"$self->{op}";
	    } elsif ($self->{op} eq "ret") {
	    	".byte	0xf3,0xc3";
	    } else {
		"$self->{op}$self->{sz}";
	    }
	} else {
	    $self->{op} =~ s/^movz/movzx/;
	    if ($self->{op} eq "ret") {
		$self->{op} = "";
		if ($current_function->{abi} eq "svr4") {
		    $self->{op} = "mov	rdi,QWORD${PTR}[8+rsp]\t;WIN64 epilogue\n\t".
				  "mov	rsi,QWORD${PTR}[16+rsp]\n\t";
	    	}
		$self->{op} .= "DB\t0F3h,0C3h\t\t;repret";
	    } elsif ($self->{op} =~ /^j/ && $nasm) {
		$self->{op} .= " NEAR";
	    }
	    $self->{op};
	}
    }
    sub mnemonic { shift->{op}; }
}
{ package const;	# pick up constants, which start with $
    sub re {
	my	$self = shift;	# single instance in enough...
	local	*line = shift;
	undef	$ret;

	if ($line =~ /^\$([^,]+)/) {
	    $self->{value} = $1;
	    $ret = $self;
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;
	}
	$ret;
    }
    sub out {
    	my $self = shift;

	if (!$win64) {
	    # Solaris /usr/ccs/bin/as can't handle multiplications
	    # in $self->{value}
	    $self->{value} =~ s/(?<![0-9a-f])(0[x0-9a-f]+)/oct($1)/egi;
	    $self->{value} =~ s/([0-9]+\s*[\*\/\%]\s*[0-9]+)/eval($1)/eg;
	    sprintf "\$%s",$self->{value};
	} else {
	    $self->{value} =~ s/0x([0-9a-f]+)/0$1h/ig;
	    sprintf "%s",$self->{value};
	}
    }
}
{ package ea;		# pick up effective addresses: expr(%reg,%reg,scale)
    sub re {
	my	$self = shift;	# single instance in enough...
	local	*line = shift;
	undef	$ret;

	if ($line =~ /^([^\(,]*)\(([%\w,]+)\)/) {
	    $self->{label} = $1;
	    ($self->{base},$self->{index},$self->{scale})=split(/,/,$2);
	    $self->{scale} = 1 if (!defined($self->{scale}));
	    $ret = $self;
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;

	    $self->{base}  =~ s/^%//;
	    $self->{index} =~ s/^%// if (defined($self->{index}));
	}
	$ret;
    }
    sub size {}
    sub out {
    	my $self = shift;
	my $sz = shift;

	# Silently convert all EAs to 64-bit. This is required for
	# elder GNU assembler and results in more compact code,
	# *but* most importantly AES module depends on this feature!
	$self->{index} =~ s/^[er](.?[0-9xpi])[d]?$/r\1/;
	$self->{base}  =~ s/^[er](.?[0-9xpi])[d]?$/r\1/;

	if (!$win64) {
	    # Solaris /usr/ccs/bin/as can't handle multiplications
	    # in $self->{label}
	    $self->{label} =~ s/(?<![0-9a-f])(0[x0-9a-f]+)/oct($1)/egi;
	    $self->{label} =~ s/([0-9]+\s*[\*\/\%]\s*[0-9]+)/eval($1)/eg;

	    if (defined($self->{index})) {
		sprintf "%s(%%%s,%%%s,%d)",
					$self->{label},$self->{base},
					$self->{index},$self->{scale};
	    } else {
		sprintf "%s(%%%s)",	$self->{label},$self->{base};
	    }
	} else {
	    %szmap = ( b=>"BYTE$PTR", w=>"WORD$PTR", l=>"DWORD$PTR", q=>"QWORD$PTR" );

	    $self->{label} =~ s/\./\$/g;
	    $self->{label} =~ s/0x([0-9a-f]+)/0$1h/ig;
	    $self->{label} = "($self->{label})" if ($self->{label} =~ /[\*\+\-\/]/);

	    if (defined($self->{index})) {
		sprintf "%s[%s%s*%d+%s]",$szmap{$sz},
					$self->{label}?"$self->{label}+":"",
					$self->{index},$self->{scale},
					$self->{base};
	    } elsif ($self->{base} eq "rip") {
		sprintf "%s[%s]",$szmap{$sz},$self->{label};
	    } else {
		sprintf "%s[%s%s]",$szmap{$sz},
					$self->{label}?"$self->{label}+":"",
					$self->{base};
	    }
	}
    }
}
{ package register;	# pick up registers, which start with %.
    sub re {
	my	$class = shift;	# muliple instances...
	my	$self = {};
	local	*line = shift;
	undef	$ret;

	if ($line =~ /^%(\w+)/) {
	    bless $self,$class;
	    $self->{value} = $1;
	    $ret = $self;
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;
	}
	$ret;
    }
    sub size {
	my	$self = shift;
	undef	$ret;

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
	sprintf $win64?"%s":"%%%s",$self->{value};
    }
}
{ package label;	# pick up labels, which end with :
    sub re {
	my	$self = shift;	# single instance is enough...
	local	*line = shift;
	undef	$ret;

	if ($line =~ /(^[\.\w]+\:)/) {
	    $self->{value} = $1;
	    $ret = $self;
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;

	    $self->{value} =~ s/\.L/\$L/ if ($win64);
	}
	$ret;
    }
    sub out {
	my $self = shift;

	if (!$win64) {
	    $self->{value};
	} elsif ($self->{value} ne "$current_function->{name}:") {
	    $self->{value};
	} elsif ($current_function->{abi} eq "svr4") {
	    my $func =	"$current_function->{name}".($nasm?":":"\tPROC")."\n".
			"	mov	QWORD${PTR}[8+rsp],rdi\t;WIN64 prologue\n".
			"	mov	QWORD${PTR}[16+rsp],rsi\n";
	    my $narg = $current_function->{narg};
	    $narg=6 if (!defined($narg));
	    $func .= "	mov	rdi,rcx\n" if ($narg>0);
	    $func .= "	mov	rsi,rdx\n" if ($narg>1);
	    $func .= "	mov	rdx,r8\n"  if ($narg>2);
	    $func .= "	mov	rcx,r9\n"  if ($narg>3);
	    $func .= "	mov	r8,QWORD${PTR}[40+rsp]\n" if ($narg>4);
	    $func .= "	mov	r9,QWORD${PTR}[48+rsp]\n" if ($narg>5);
	    $func .= "\n";
	} else {
	   "$current_function->{name}".($nasm?":":"\tPROC");
	}
    }
}
{ package expr;		# pick up expressioins
    sub re {
	my	$self = shift;	# single instance is enough...
	local	*line = shift;
	undef	$ret;

	if ($line =~ /(^[^,]+)/) {
	    $self->{value} = $1;
	    $ret = $self;
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;

	    $self->{value} =~ s/\.L/\$L/g if ($win64);
	}
	$ret;
    }
    sub out {
	my $self = shift;
	$self->{value};
    }
}
{ package directive;	# pick up directives, which start with .
    sub re {
	my	$self = shift;	# single instance is enough...
	local	*line = shift;
	undef	$ret;
	my	$dir;
	my	%opcode =	# lea 2f-1f(%rip),%dst; 1: nop; 2:
		(	"%rax"=>0x01058d48,	"%rcx"=>0x010d8d48,
			"%rdx"=>0x01158d48,	"%rbx"=>0x011d8d48,
			"%rsp"=>0x01258d48,	"%rbp"=>0x012d8d48,
			"%rsi"=>0x01358d48,	"%rdi"=>0x013d8d48,
			"%r8" =>0x01058d4c,	"%r9" =>0x010d8d4c,
			"%r10"=>0x01158d4c,	"%r11"=>0x011d8d4c,
			"%r12"=>0x01258d4c,	"%r13"=>0x012d8d4c,
			"%r14"=>0x01358d4c,	"%r15"=>0x013d8d4c	);

	if ($line =~ /^\s*(\.\w+)/) {
	    if (!$win64) {
		$self->{value} = $1;
		$line =~ s/\@abi\-omnipotent/\@function/;
		$line =~ s/\@function.*/\@function/;
		if ($line =~ /\.picmeup\s+(%r[\w]+)/i) {
		    $self->{value} = sprintf "\t.long\t0x%x,0x90000000",$opcode{$1};
		} elsif ($line =~ /\.asciz\s+"(.*)"$/) {
		    $self->{value} = ".byte\t".join(",",unpack("C*",$1),0);
		} elsif ($line =~ /\.extern/) {
		    $self->{value} = ""; # swallow extern
		} else {
		    $self->{value} = $line;
		}
		$line = "";
		return $self;
	    }

	    $dir = $1;
	    $ret = $self;
	    undef $self->{value};
	    $line = substr($line,@+[0]); $line =~ s/^\s+//;
	    SWITCH: for ($dir) {
		/\.(text)/
			    && do { my $v=undef;
				    if ($nasm) {
					$v ="section	.$1 code align=64\n";
					$v.="default	rel\n";
					$v.="%define	PUBLIC global";
				    } else {
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = "_$1\$";
					$current_segment =~ tr/[a-z]/[A-Z]/;
					$v.="$current_segment\tSEGMENT ";
					$v.=$masm>=$masmref ? "ALIGN(64)" : "PAGE";
					$v.=" 'CODE'";
				    }
				    $self->{value} = $v;
				    last;
				  };
		/\.extern/  && do { $self->{value}  = "EXTERN\t".$line;
				    $self->{value} .= ":BYTE" if (!$nasm);
				    last;
				  };
		/\.globl/   && do { $self->{value} = "PUBLIC\t".$line; last; };
		/\.type/    && do { ($sym,$type,$narg) = split(',',$line);
				    if ($type eq "\@function") {
					undef $current_function;
					$current_function->{name} = $sym;
					$current_function->{abi}  = "svr4";
					$current_function->{narg} = $narg;
				    } elsif ($type eq "\@abi-omnipotent") {
					undef $current_function;
					$current_function->{name} = $sym;
				    }
				    last;
				  };
		/\.size/    && do { if (defined($current_function)) {
					$self->{value}="$current_function->{name}\tENDP" if(!$nasm);
					undef $current_function;
				    }
				    last;
				  };
		/\.align/   && do { $self->{value} = "ALIGN\t".$line; last; };
		/\.(byte|value|long|quad)/
			    && do { my @arr = split(',',$line);
				    my $sz  = substr($1,0,1);
				    my $last = pop(@arr);
				    my $conv = sub  {	my $var=shift;
							if ($var=~s/0x([0-9a-f]+)/0$1h/i) { $var; }
							else { sprintf"0%Xh",$var; }
						    };  

				    $sz =~ tr/bvlq/BWDQ/;
				    $self->{value} = "\tD$sz\t";
				    for (@arr) { $self->{value} .= &$conv($_).","; }
				    $self->{value} .= &$conv($last);
				    last;
				  };
		/\.picmeup/ && do { $self->{value} = sprintf"\tDD\t0%Xh,090000000h",$opcode{$line};
				    last;
				  };
		/\.asciz/   && do { if ($line =~ /^"(.*)"$/) {
					my @str=unpack("C*",$1);
					push @str,0;
					while ($#str>15) {
					    $self->{value}.="DB\t"
						.join(",",@str[0..15])."\n";
					    foreach (0..15) { shift @str; }
					}
					$self->{value}.="DB\t"
						.join(",",@str) if (@str);
				    }
				    last;
				  };
	    }
	    $line = "";
	}

	$ret;
    }
    sub out {
	my $self = shift;
	$self->{value};
    }
}

while($line=<>) {

    chomp($line);

    $line =~ s|[#!].*$||;	# get rid of asm-style comments...
    $line =~ s|/\*.*\*/||;	# ... and C-style comments...
    $line =~ s|^\s+||;		# ... and skip white spaces in beginning

    undef $label;
    undef $opcode;
    undef $dst;
    undef $src;
    undef $sz;

    if ($label=label->re(\$line))	{ print $label->out(); }

    if (directive->re(\$line)) {
	printf "%s",directive->out();
    } elsif ($opcode=opcode->re(\$line)) { ARGUMENT: {

	if ($src=register->re(\$line))	{ opcode->size($src->size()); }
	elsif ($src=const->re(\$line))	{ }
	elsif ($src=ea->re(\$line))	{ }
	elsif ($src=expr->re(\$line))	{ }

	last ARGUMENT if ($line !~ /^,/);

	$line = substr($line,1); $line =~ s/^\s+//;

	if ($dst=register->re(\$line))	{ opcode->size($dst->size()); }
	elsif ($dst=const->re(\$line))	{ }
	elsif ($dst=ea->re(\$line))	{ }

	} # ARGUMENT:

	$sz=opcode->size();

	if (defined($dst)) {
	    if (!$win64) {
		printf "\t%s\t%s,%s",	$opcode->out($dst->size()),
					$src->out($sz),$dst->out($sz);
	    } else {
		undef $sz if ($nasm && $opcode->mnemonic() eq "lea");
		printf "\t%s\t%s,%s",	$opcode->out(),
					$dst->out($sz),$src->out($sz);
	    }
	} elsif (defined($src)) {
	    printf "\t%s\t%s",$opcode->out(),$src->out($sz);
	} else {
	    printf "\t%s",$opcode->out();
	}
    }

    print $line,"\n";
}

print "\n$current_segment\tENDS\nEND\n" if ($current_segment);

close STDOUT;

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
# which could not be accomodated in registers. Or in other words 7th
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
# register and stack layout, but disregards the "red zone" existense,
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
# Unlike on Unix systems(*) lack of Win64 stack unwinding information
# has undesired side-effect at run-time: if an exception is raised in
# assembler subroutine such as those in question (basically we're
# referring to segmentation violations caused by malformed input
# parameters), the application is briskly terminated without invoking
# any exception handlers, most notably without generating memory dump
# or any user notification whatsoever. This poses a problem. It's
# possible to address it by registering custom language-specific
# handler that would restore processor context to the state at
# subroutine entry point and return "exception is not handled, keep
# unwinding" code. Writing such handler can be a challenge... But it's
# doable, though requires certain coding convention. Consider following
# snippet:
#
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
#	ret
#
# The key is that up to magic_point copy of original rsp value remains
# in chosen volatile register and no non-volatile register, except for
# rsp, is modified. While past magic_point rsp remains constant till
# the very end of the function. In this case custom language-specific
# exception handler would look like this:
#
# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
# {	ULONG64 *rsp;
#	if (context->Rip<magic_point)
#	    rsp = (ULONG64 *)context->Rax;
#	else
#	{   rsp = ((ULONG64 **)context->Rsp)[0];
#	    context->Rbp = rsp[-3];
#	    context->Rbx = rsp[-2];
#	    context->R15 = rsp[-1];
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
# UNWIND_INFO structure for .xdata segment would be
#	DB	9,0,0,0
#	DD	imagerel handler
# denoting exception handler for a function with zero-length prologue,
# no stack frame or frame register.
#
# P.S.	Attentive reader can notice that effectively no exceptions are
#	expected in "gear" prologue and epilogue [discussed in "ABI
#	cross-reference" above]. No, there are not. This is because if
#	memory area used by them was subject to segmentation violation,
#	then exception would be raised upon call to our function and be
#	accounted to caller and unwound from its frame, which is not a
#	problem.
#
# (*)	Note that we're talking about run-time, not debug-time. Lack of
#	unwind information makes debugging hard on both Windows and
#	Unix. "Unlike" referes to the fact that on Unix signal handler
#	will always be invoked, core dumped and appropriate exit code
#	returned to parent (for user notification).
