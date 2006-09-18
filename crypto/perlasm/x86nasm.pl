#!/usr/bin/env perl

package x86nasm;

*out=\@::out;

$lprfx="\@L";
$label="000";
$under=($::netware)?'':'_';

sub ::generic
{ my $opcode=shift;
  my $tmp;

    if (!$::mwerks)
    {   if    ($opcode =~ m/^j/o && $#_==0) # optimize jumps
	{   $_[0] = "NEAR $_[0]";   	}
	elsif ($opcode eq "lea" && $#_==1)# wipe storage qualifier from lea
	{   $_[1] =~ s/^[^\[]*\[/\[/o;	}
    }
    &::emit($opcode,@_);
  1;
}
#
# opcodes not covered by ::generic above, mostly inconsistent namings...
#
sub ::movz	{ &::movzx(@_);		}
sub ::pushf	{ &::pushfd;		}
sub ::popf	{ &::popfd;		}

sub ::call	{ &::emit("call",(&islabel($_[0]) or "$under$_[0]")); }
sub ::call_ptr	{ &::emit("call",@_);	}
sub ::jmp_ptr	{ &::emit("jmp",@_);	}

# chosen SSE instructions
sub ::movq
{ my($p1,$p2,$optimize)=@_;

    if ($optimize && $p1=~/^mm[0-7]$/ && $p2=~/^mm[0-7]$/)
    # movq between mmx registers can sink Intel CPUs
    {	&::pshufw($p1,$p2,0xe4);		}
    else
    {	&::emit("movq",@_);			}
}
sub ::pshufw { &::emit("pshufw",@_); }

sub get_mem
{ my($size,$addr,$reg1,$reg2,$idx)=@_;
  my($post,$ret);

    if ($size ne "")
    {	$ret .= "$size";
	$ret .= " PTR" if ($::mwerks);
	$ret .= " ";
    }
    $ret .= "[";

    $addr =~ s/^\s+//;
    # prepend global references with optional underscore
    $addr =~ s/^([^\+\-0-9][^\+\-]*)/islabel($1) or "$under$1"/ige;
    # put address arithmetic expression in parenthesis
    $addr="($addr)" if ($addr =~ /^.+[\-\+].+$/);

    if (($addr ne "") && ($addr ne 0))
    {	if ($addr !~ /^-/)	{ $ret .= "$addr+"; }
	else			{ $post=$addr;      }
    }

    if ($reg2 ne "")
    {	$idx!=0 or $idx=1;
	$ret .= "$reg2*$idx";
	$ret .= "+$reg1" if ($reg1 ne "");
    }
    else
    {	$ret .= "$reg1";   }

    $ret .= "$post]";
    $ret =~ s/\+\]/]/; # in case $addr was the only argument

  $ret;
}
sub ::BP	{ &get_mem("BYTE",@_);  }
sub ::DWP	{ &get_mem("DWORD",@_); }
sub ::QWP	{ &get_mem("QWORD",@_); }
sub ::BC	{ (($::mwerks)?"":"BYTE ")."@_";  }
sub ::DWC	{ (($::mwerks)?"":"DWORD ")."@_"; }

sub ::file
{   if ($::mwerks)	{ push(@out,".section\t.text\n"); }
    else
    { my $tmp=<<___;
%ifdef __omf__
section	code	use32 class=code align=64
%else
section	.text	code align=64
%endif
___
	push(@out,$tmp);
    }
}

sub ::function_begin_B
{ my $func=$under.shift;
  my $tmp=<<___;
global	$func
align	16
$func:
___
    push(@out,$tmp);
    $::stack=4;
}
sub ::function_end_B
{ my $i;
    foreach $i (%label) { undef $label{$i} if ($label{$i} =~ /^$prfx/);  }
    $::stack=0;
}

sub ::file_end
{   # try to detect if SSE2 or MMX extensions were used on Win32...
    if ($::win32 && grep {/\s+[x]*mm[0-7]/i} @out)
    {	# One can argue that it's wasteful to craft every
	# SSE/MMX module with this snippet... Well, it's 72
	# bytes long and for the moment we have two modules.
	# Let's argue when we have 7 modules or so...
	#
	# $1<<10 sets a reserved bit to signal that variable
	# was initialized already...
	my $tmp=<<___;
align	16
${lprfx}OPENSSL_ia32cap_init:
	lea	edx,[${under}OPENSSL_ia32cap_P]
	cmp	DWORD [edx],0
	jne	NEAR ${lprfx}nocpuid
	mov	DWORD [edx],1<<10
	pushfd
	pop	eax
	mov	ecx,eax
	xor	eax,1<<21
	push	eax
	popfd
	pushfd
	pop	eax
	xor	eax,ecx
	bt	eax,21
	jnc	NEAR ${lprfx}nocpuid
	push	edi
	push	ebx
	mov	edi,edx
	mov	eax,1
	cpuid
	or	edx,1<<10
	mov	DWORD [edi],edx
	pop	ebx
	pop	edi
${lprfx}nocpuid:
	ret

segment	.CRT\$XCU rdata align=4
dd	${lprfx}OPENSSL_ia32cap_init
segment	.bss
common	${under}OPENSSL_ia32cap_P 4
___
	push (@out,$tmp);		
    }
}

sub ::comment {   foreach (@_) { push(@out,"\t; $_\n"); }   }

sub islabel	# see is argument is known label
{ my $i;
    foreach $i (%label) { return $label{$i} if ($label{$i} eq $_[0]); }
  undef;
}

sub ::external_label
{   push(@labels,@_);
    foreach (@_)
    {	push(@out,".") if ($::mwerks);
	push(@out, "extern\t${under}$_\n");
    }
}

sub ::public_label
{   $label{$_[0]}="${under}${_[0]}" if (!defined($label{$_[0]}));
    push(@out,"global\t$label{$_[0]}\n");
}

sub ::label
{   if (!defined($label{$_[0]}))
    {	$label{$_[0]}="${lprfx}${label}${_[0]}"; $label++;   }
  $label{$_[0]};
}

sub ::set_label
{ my $label=&::label($_[0]);
    &::align($_[1]) if ($_[1]>1);
    push(@out,"$label{$_[0]}:\n");
}

sub ::data_byte
{   push(@out,(($::mwerks)?".byte\t":"db\t").join(',',@_)."\n");	}

sub ::data_word
{   push(@out,(($::mwerks)?".long\t":"dd\t").join(',',@_)."\n");	}

sub ::align
{   push(@out,".") if ($::mwerks); push(@out,"align\t$_[0]\n");	}

sub ::picmeup
{ my($dst,$sym)=@_;
    &::lea($dst,&::DWP($sym));
}

sub ::initseg
{ my($f)=$under.shift;
    if ($::win32)
    { my($tmp)=<<___;
segment	.CRT\$XCU rdata align=4
extern	$f
dd	$f
___
	push(@out,$tmp);
    }
}

1;
