#!/usr/bin/env perl

package x86unix;	# GAS actually...

*out=\@::out;

$label="L000";
$const="";
$constl=0;

$align=($::aout)?"4":"16";
$under=($::aout or $::coff)?"_":"";
$dot=($::aout)?"":".";
$com_start="#" if ($::aout or $::coff);

sub opsize()
{ my $reg=shift;
    if    ($reg =~ m/^%e/o)		{ "l"; }
    elsif ($reg =~ m/^%[a-d][hl]$/o)	{ "b"; }
    elsif ($reg =~ m/^%[xm]/o)		{ undef; }
    else				{ "w"; }
}

# swap arguments;
# expand opcode with size suffix;
# prefix numeric constants with $;
sub ::generic
{ my($opcode,$dst,$src)=@_;
  my($tmp,$suffix,@arg);

    if (defined($src))
    {	$src =~ s/^(e?[a-dsixphl]{2})$/%$1/o;
	$src =~ s/^(x?mm[0-7])$/%$1/o;
	$src =~ s/^(\-?[0-9]+)$/\$$1/o;
	$src =~ s/^(\-?0x[0-9a-f]+)$/\$$1/o;
	push(@arg,$src);
    }
    if (defined($dst))
    {	$dst =~ s/^(\*?)(e?[a-dsixphl]{2})$/$1%$2/o;
	$dst =~ s/^(x?mm[0-7])$/%$1/o;
	$dst =~ s/^(\-?[0-9]+)$/\$$1/o		if(!defined($src));
	$dst =~ s/^(\-?0x[0-9a-f]+)$/\$$1/o	if(!defined($src));
	push(@arg,$dst);
    }

    if    ($dst =~ m/^%/o)	{ $suffix=&opsize($dst); }
    elsif ($src =~ m/^%/o)	{ $suffix=&opsize($src); }
    else			{ $suffix="l";           }
    undef $suffix if ($dst =~ m/^%[xm]/o || $src =~ m/^%[xm]/o);

    if ($#_==0)				{ &::emit($opcode);		}
    elsif ($opcode =~ m/^j/o && $#_==1)	{ &::emit($opcode,@arg);	}
    elsif ($opcode eq "call" && $#_==1)	{ &::emit($opcode,@arg);	}
    else				{ &::emit($opcode.$suffix,@arg);}

  1;
}
#
# opcodes not covered by ::generic above, mostly inconsistent namings...
#
sub ::movz	{ &::movzb(@_);			}
sub ::pushf	{ &::pushfl;			}
sub ::popf	{ &::popfl;			}
sub ::cpuid	{ &::emit(".byte\t0x0f,0xa2");	}
sub ::rdtsc	{ &::emit(".byte\t0x0f,0x31");	}

sub ::call	{ &::emit("call",(&islabel($_[0]) or "$under$_[0]")); }
sub ::call_ptr	{ &::generic("call","*$_[0]");	}
sub ::jmp_ptr	{ &::generic("jmp","*$_[0]");	}

*::bswap = sub	{ &::emit("bswap","%$_[0]");	} if (!$::i386);

# chosen SSE instructions
sub ::movq
{ my($p1,$p2,$optimize)=@_;
    if ($optimize && $p1=~/^mm[0-7]$/ && $p2=~/^mm[0-7]$/)
    # movq between mmx registers can sink Intel CPUs
    {	&::pshufw($p1,$p2,0xe4);	}
    else
    {	&::generic("movq",@_);	}
}
sub ::pshufw
{ my($dst,$src,$magic)=@_;
    &::emit("pshufw","\$$magic","%$src","%$dst");
}

sub ::DWP
{ my($addr,$reg1,$reg2,$idx)=@_;
  my $ret="";

    $addr =~ s/^\s+//;
    # prepend global references with optional underscore
    $addr =~ s/^([^\+\-0-9][^\+\-]*)/islabel($1) or "$under$1"/ige;

    $reg1 = "%$reg1" if ($reg1);
    $reg2 = "%$reg2" if ($reg2);

    $ret .= $addr if (($addr ne "") && ($addr ne 0));

    if ($reg2)
    {	$idx!= 0 or $idx=1;
	$ret .= "($reg1,$reg2,$idx)";
    }
    elsif ($reg1)
    {	$ret .= "($reg1)";	}

  $ret;
}
sub ::QWP	{ &::DWP(@_);	}
sub ::BP	{ &::DWP(@_);	}
sub ::BC	{ @_;		}
sub ::DWC	{ @_;		}

sub ::file
{   push(@out,".file\t\"$_[0].s\"\n");	}

sub ::function_begin_B
{ my($func,$extra)=@_;
  my $tmp;

    &::external_label($func);
    $func=$under.$func;

    push(@out,".text\n.globl\t$func\n");
    if ($::coff)
    {	push(@out,".def\t$func;\t.scl\t2;\t.type\t32;\t.endef\n"); }
    elsif ($::aout and !$::pic)
    { }
    else
    {	push(@out,".type	$func,\@function\n"); }
    push(@out,".align\t$align\n");
    push(@out,"$func:\n");
    $::stack=4;
}

sub ::function_end_B
{ my($func)=@_;

    $func=$under.$func;
    push(@out,"${dot}L_${func}_end:\n");
    if ($::elf)
    {	push(@out,".size\t$func,${dot}L_${func}_end-$func\n"); }
    $::stack=0;
    %label=();
}

sub ::comment
	{
	if (!defined($com_start) or $::elf)
		{	# Regarding $::elf above...
			# GNU and SVR4 as'es use different comment delimiters,
		push(@out,"\n");	# so we just skip ELF comments...
		return;
		}
	foreach (@_)
		{
		if (/^\s*$/)
			{ push(@out,"\n"); }
		else
			{ push(@out,"\t$com_start $_ $com_end\n"); }
		}
	}

sub islabel	# see is argument is a known label
{ my $i;
    foreach $i (%label) { return $label{$i} if ($label{$i} eq $_[0]); }
  undef;
}

sub ::external_label { push(@labels,@_); }

sub ::public_label
{   $label{$_[0]}="${under}${_[0]}"	if (!defined($label{$_[0]}));
    push(@out,".globl\t$label{$_[0]}\n");
}

sub ::label
{   if (!defined($label{$_[0]}))
    {	$label{$_[0]}="${dot}${label}${_[0]}"; $label++;   }
  $label{$_[0]};
}

sub ::set_label
{ my $label=&::label($_[0]);
    &::align($_[1]) if ($_[1]>1);
    push(@out,"$label:\n");
}

sub ::file_end
{   # try to detect if SSE2 or MMX extensions were used on ELF platform...
    if ($::elf && grep {/%[x]?mm[0-7]/i} @out){
	my $tmp;

	push (@out,"\n.section\t.bss\n");
	push (@out,".comm\t${under}OPENSSL_ia32cap_P,4,4\n");

	push (@out,".section\t.init\n");
	# One can argue that it's wasteful to craft every
	# SSE/MMX module with this snippet... Well, it's 72
	# bytes long and for the moment we have two modules.
	# Let's argue when we have 7 modules or so...
	#
	# $1<<10 sets a reserved bit to signal that variable
	# was initialized already...
	&::picmeup("edx","OPENSSL_ia32cap_P");
	$tmp=<<___;
	cmpl	\$0,(%edx)
	jne	1f
	movl	\$1<<10,(%edx)
	pushf
	popl	%eax
	movl	%eax,%ecx
	xorl	\$1<<21,%eax
	pushl	%eax
	popf
	pushf
	popl	%eax
	xorl	%ecx,%eax
	btl	\$21,%eax
	jnc	1f
	pushl	%edi
	pushl	%ebx
	movl	%edx,%edi
	movl	\$1,%eax
	.byte	0x0f,0xa2
	orl	\$1<<10,%edx
	movl	%edx,0(%edi)
	popl	%ebx
	popl	%edi
	jmp	1f
	.align	$align
	1:
___
	push (@out,$tmp);
    }

    if ($const ne "")
    {	push(@out,".section .rodata\n");
	push(@out,$const);
	$const="";
    }
}

sub ::data_byte	{   push(@out,".byte\t".join(',',@_)."\n");   }
sub ::data_word {   push(@out,".long\t".join(',',@_)."\n");   }

sub ::align
{ my $val=$_[0],$p2,$i;
    if ($::aout)
    {	for ($p2=0;$val!=0;$val>>=1) { $p2++; }
	$val=$p2-1;
	$val.=",0x90";
    }
    push(@out,".align\t$val\n");
}

sub ::picmeup
{ my($dst,$sym,$base,$reflabel)=@_;

    if ($::pic && ($::elf || $::aout))
    {	if (!defined($base))
	{   &::call(&::label("PIC_me_up"));
	    &::set_label("PIC_me_up");
	    &::blindpop($dst);
	    &::add($dst,"\$${under}_GLOBAL_OFFSET_TABLE_+[.-".
			    &::label("PIC_me_up") . "]");
	}
	else
	{   &::lea($dst,&::DWP("${under}_GLOBAL_OFFSET_TABLE_+[.-$reflabel]",
			    $base));
	}
	&::mov($dst,&::DWP($under.$sym."\@GOT",$dst));
    }
    else
    {	&::lea($dst,&::DWP($sym));	}
}

sub ::initseg
{ my($f)=@_;
  my($tmp,$ctor);

    if ($::elf)
    {	$tmp=<<___;
.section	.init
	call	$under$f
	jmp	.Linitalign
.align	$align
.Linitalign:
___
    }
    elsif ($::coff)
    {   $tmp=<<___;	# applies to both Cygwin and Mingw
.section	.ctors
.long	$under$f
___
    }
    elsif ($::aout)
    {	$ctor="${under}_GLOBAL_\$I\$$f";
	$tmp=".text\n";
	$tmp.=".type	$ctor,\@function\n" if ($::pic);
	$tmp.=<<___;	# OpenBSD way...
.globl	$ctor
.align	2
$ctor:
	jmp	$under$f
___
    }
    push(@out,$tmp) if ($tmp);
}

1;
