#!/usr/local/bin/perl

package x86unix;

$label="L000";

$align=($main'aout)?"4":"16";
$under=($main'aout)?"_":"";
$com_start=($main'sol)?"/":"#";

sub main'asm_init_output { @out=(); }
sub main'asm_get_output { return(@out); }
sub main'get_labels { return(@labels); }
sub main'external_label { push(@labels,@_); }

if ($main'cpp)
	{
	$align="ALIGN";
	$under="";
	$com_start='/*';
	$com_end='*/';
	}

%lb=(	'eax',	'%al',
	'ebx',	'%bl',
	'ecx',	'%cl',
	'edx',	'%dl',
	'ax',	'%al',
	'bx',	'%bl',
	'cx',	'%cl',
	'dx',	'%dl',
	);

%hb=(	'eax',	'%ah',
	'ebx',	'%bh',
	'ecx',	'%ch',
	'edx',	'%dh',
	'ax',	'%ah',
	'bx',	'%bh',
	'cx',	'%ch',
	'dx',	'%dh',
	);

%regs=(	'eax',	'%eax',
	'ebx',	'%ebx',
	'ecx',	'%ecx',
	'edx',	'%edx',
	'esi',	'%esi',
	'edi',	'%edi',
	'ebp',	'%ebp',
	'esp',	'%esp',
	);

%reg_val=(
	'eax',	0x00,
	'ebx',	0x03,
	'ecx',	0x01,
	'edx',	0x02,
	'esi',	0x06,
	'edi',	0x07,
	'ebp',	0x05,
	'esp',	0x04,
	);

sub main'LB
	{
	(defined($lb{$_[0]})) || die "$_[0] does not have a 'low byte'\n";
	return($lb{$_[0]});
	}

sub main'HB
	{
	(defined($hb{$_[0]})) || die "$_[0] does not have a 'high byte'\n";
	return($hb{$_[0]});
	}

sub main'DWP
	{
	local($addr,$reg1,$reg2,$idx)=@_;

	$ret="";
	$addr =~ s/(^|[+ \t])([A-Za-z_]+)($|[+ \t])/$1$under$2$3/;
	$reg1="$regs{$reg1}" if defined($regs{$reg1});
	$reg2="$regs{$reg2}" if defined($regs{$reg2});
	$ret.=$addr if ($addr ne "") && ($addr ne 0);
	if ($reg2 ne "")
		{
		if($idx ne "")
		    { $ret.="($reg1,$reg2,$idx)"; }
		else
		    { $ret.="($reg1,$reg2)"; }
	        }
	else
		{ $ret.="($reg1)" }
	return($ret);
	}

sub main'BP
	{
	return(&main'DWP(@_));
	}

sub main'BC
	{
	return @_;
	}

sub main'DWC
	{
	return @_;
	}

#sub main'BP
#	{
#	local($addr,$reg1,$reg2,$idx)=@_;
#
#	$ret="";
#
#	$addr =~ s/(^|[+ \t])([A-Za-z_]+)($|[+ \t])/$1$under$2$3/;
#	$reg1="$regs{$reg1}" if defined($regs{$reg1});
#	$reg2="$regs{$reg2}" if defined($regs{$reg2});
#	$ret.=$addr if ($addr ne "") && ($addr ne 0);
#	if ($reg2 ne "")
#		{ $ret.="($reg1,$reg2,$idx)"; }
#	else
#		{ $ret.="($reg1)" }
#	return($ret);
#	}

sub main'mov	{ &out2("movl",@_); }
sub main'movb	{ &out2("movb",@_); }
sub main'and	{ &out2("andl",@_); }
sub main'or	{ &out2("orl",@_); }
sub main'shl	{ &out2("sall",@_); }
sub main'shr	{ &out2("shrl",@_); }
sub main'xor	{ &out2("xorl",@_); }
sub main'xorb	{ &out2("xorb",@_); }
sub main'add	{ &out2("addl",@_); }
sub main'adc	{ &out2("adcl",@_); }
sub main'sub	{ &out2("subl",@_); }
sub main'rotl	{ &out2("roll",@_); }
sub main'rotr	{ &out2("rorl",@_); }
sub main'exch	{ &out2("xchg",@_); }
sub main'cmp	{ &out2("cmpl",@_); }
sub main'lea	{ &out2("leal",@_); }
sub main'mul	{ &out1("mull",@_); }
sub main'div	{ &out1("divl",@_); }
sub main'jmp	{ &out1("jmp",@_); }
sub main'jmp_ptr { &out1p("jmp",@_); }
sub main'je	{ &out1("je",@_); }
sub main'jle	{ &out1("jle",@_); }
sub main'jne	{ &out1("jne",@_); }
sub main'jnz	{ &out1("jnz",@_); }
sub main'jz	{ &out1("jz",@_); }
sub main'jge	{ &out1("jge",@_); }
sub main'jl	{ &out1("jl",@_); }
sub main'jb	{ &out1("jb",@_); }
sub main'jc	{ &out1("jc",@_); }
sub main'jnc	{ &out1("jnc",@_); }
sub main'jno	{ &out1("jno",@_); }
sub main'dec	{ &out1("decl",@_); }
sub main'inc	{ &out1("incl",@_); }
sub main'push	{ &out1("pushl",@_); $stack+=4; }
sub main'pop	{ &out1("popl",@_); $stack-=4; }
sub main'not	{ &out1("notl",@_); }
sub main'call	{ &out1("call",$under.$_[0]); }
sub main'ret	{ &out0("ret"); }
sub main'nop	{ &out0("nop"); }

# The bswapl instruction is new for the 486. Emulate if i386.
sub main'bswap
	{
	if ($main'i386)
		{
		&main'comment("bswapl @_");
		&main'exch(main'HB(@_),main'LB(@_));
		&main'rotr(@_,16);
		&main'exch(main'HB(@_),main'LB(@_));
		}
	else
		{
		&out1("bswapl",@_);
		}
	}

sub out2
	{
	local($name,$p1,$p2)=@_;
	local($l,$ll,$t);
	local(%special)=(	"roll",0xD1C0,"rorl",0xD1C8,
				"rcll",0xD1D0,"rcrl",0xD1D8,
				"shll",0xD1E0,"shrl",0xD1E8,
				"sarl",0xD1F8);
	
	if ((defined($special{$name})) && defined($regs{$p1}) && ($p2 == 1))
		{
		$op=$special{$name}|$reg_val{$p1};
		$tmp1=sprintf(".byte %d\n",($op>>8)&0xff);
		$tmp2=sprintf(".byte %d\t",$op     &0xff);
		push(@out,$tmp1);
		push(@out,$tmp2);

		$p2=&conv($p2);
		$p1=&conv($p1);
		&main'comment("$name $p2 $p1");
		return;
		}

	push(@out,"\t$name\t");
	$t=&conv($p2).",";
	$l=length($t);
	push(@out,$t);
	$ll=4-($l+9)/8;
	$tmp1=sprintf("\t" x $ll);
	push(@out,$tmp1);
	push(@out,&conv($p1)."\n");
	}

sub out1
	{
	local($name,$p1)=@_;
	local($l,$t);
	local(%special)=("bswapl",0x0FC8);

	if ((defined($special{$name})) && defined($regs{$p1}))
		{
		$op=$special{$name}|$reg_val{$p1};
		$tmp1=sprintf(".byte %d\n",($op>>8)&0xff);
		$tmp2=sprintf(".byte %d\t",$op     &0xff);
		push(@out,$tmp1);
		push(@out,$tmp2);

		$p2=&conv($p2);
		$p1=&conv($p1);
		&main'comment("$name $p2 $p1");
		return;
		}

	push(@out,"\t$name\t".&conv($p1)."\n");
	}

sub out1p
	{
	local($name,$p1)=@_;
	local($l,$t);

	push(@out,"\t$name\t*".&conv($p1)."\n");
	}

sub out0
	{
	push(@out,"\t$_[0]\n");
	}

sub conv
	{
	local($p)=@_;

#	$p =~ s/0x([0-9A-Fa-f]+)/0$1h/;

	$p=$regs{$p} if (defined($regs{$p}));

	$p =~ s/^(-{0,1}[0-9A-Fa-f]+)$/\$$1/;
	$p =~ s/^(0x[0-9A-Fa-f]+)$/\$$1/;
	return $p;
	}

sub main'file
	{
	local($file)=@_;

	local($tmp)=<<"EOF";
	.file	"$file.s"
	.version	"01.01"
gcc2_compiled.:
EOF
	push(@out,$tmp);
	}

sub main'function_begin
	{
	local($func)=@_;

	&main'external_label($func);
	$func=$under.$func;

	local($tmp)=<<"EOF";
.text
	.align $align
.globl $func
EOF
	push(@out,$tmp);
	if ($main'cpp)
		{ $tmp=push(@out,"\tTYPE($func,\@function)\n"); }
	else	{ $tmp=push(@out,"\t.type\t$func,\@function\n"); }
	push(@out,"$func:\n");
	$tmp=<<"EOF";
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

EOF
	push(@out,$tmp);
	$stack=20;
	}

sub main'function_begin_B
	{
	local($func,$extra)=@_;

	&main'external_label($func);
	$func=$under.$func;

	local($tmp)=<<"EOF";
.text
	.align $align
.globl $func
EOF
	push(@out,$tmp);
	if ($main'cpp)
		{ push(@out,"\tTYPE($func,\@function)\n"); }
	else	{ push(@out,"\t.type	$func,\@function\n"); }
	push(@out,"$func:\n");
	$stack=4;
	}

sub main'function_end
	{
	local($func)=@_;

	$func=$under.$func;

	local($tmp)=<<"EOF";
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.${func}_end:
EOF
	push(@out,$tmp);
	if ($main'cpp)
		{ push(@out,"\tSIZE($func,.${func}_end-$func)\n"); }
	else	{ push(@out,"\t.size\t$func,.${func}_end-$func\n"); }
	push(@out,".ident	\"$func\"\n");
	$stack=0;
	%label=();
	}

sub main'function_end_A
	{
	local($func)=@_;

	local($tmp)=<<"EOF";
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
EOF
	push(@out,$tmp);
	}

sub main'function_end_B
	{
	local($func)=@_;

	$func=$under.$func;

	push(@out,".${func}_end:\n");
	if ($main'cpp)
		{ push(@out,"\tSIZE($func,.${func}_end-$func)\n"); }
	else	{ push(@out,"\t.size\t$func,.${func}_end-$func\n"); }
	push(@out,".ident	\"desasm.pl\"\n");
	$stack=0;
	%label=();
	}

sub main'wparam
	{
	local($num)=@_;

	return(&main'DWP($stack+$num*4,"esp","",0));
	}

sub main'stack_push
	{
	local($num)=@_;
	$stack+=$num*4;
	&main'sub("esp",$num*4);
	}

sub main'stack_pop
	{
	local($num)=@_;
	$stack-=$num*4;
	&main'add("esp",$num*4);
	}

sub main'swtmp
	{
	return(&main'DWP($_[0]*4,"esp","",0));
	}

# Should use swtmp, which is above esp.  Linix can trash the stack above esp
#sub main'wtmp
#	{
#	local($num)=@_;
#
#	return(&main'DWP(-($num+1)*4,"esp","",0));
#	}

sub main'comment
	{
	foreach (@_)
		{
		if (/^\s*$/)
			{ push(@out,"\n"); }
		else
			{ push(@out,"\t$com_start $_ $com_end\n"); }
		}
	}

sub main'label
	{
	if (!defined($label{$_[0]}))
		{
		$label{$_[0]}=".${label}${_[0]}";
		$label++;
		}
	return($label{$_[0]});
	}

sub main'set_label
	{
	if (!defined($label{$_[0]}))
		{
		$label{$_[0]}=".${label}${_[0]}";
		$label++;
		}
	push(@out,".align $align\n") if ($_[1] != 0);
	push(@out,"$label{$_[0]}:\n");
	}

sub main'file_end
	{
	}

sub main'data_word
	{
	push(@out,"\t.long $_[0]\n");
	}
