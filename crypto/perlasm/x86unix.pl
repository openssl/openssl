#!/usr/local/bin/perl

package x86ms;

$label="L000";

$align=($main'aout)?"4":"16";
$under=($main'aout)?"_":"";
$com_start=($main'sol)?"/":"#";

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
		$ret.="($reg1,$reg2,$idx)";
		}
	else
		{
		$ret.="($reg1)"
		}
	return($ret);
	}

sub main'BP
	{
	local($addr,$reg1,$reg2,$idx)=@_;


	$ret="";

	$addr =~ s/(^|[+ \t])([A-Za-z_]+)($|[+ \t])/$1$under$2$3/;

	$reg1="$regs{$reg1}" if defined($regs{$reg1});
	$reg2="$regs{$reg2}" if defined($regs{$reg2});
	$ret.=$addr if ($addr ne "") && ($addr ne 0);
	if ($reg2 ne "")
		{
		$ret.="($reg1,$reg2,$idx)";
		}
	else
		{
		$ret.="($reg1)"
		}
	return($ret);
	}

sub main'mov	{ &out2("movl",@_); }
sub main'movb	{ &out2("movb",@_); }
sub main'and	{ &out2("andl",@_); }
sub main'or	{ &out2("orl",@_); }
sub main'shl	{ &out2("sall",@_); }
sub main'shr	{ &out2("shrl",@_); }
sub main'xor	{ &out2("xorl",@_); }
sub main'add	{ &out2("addl",@_); }
sub main'sub	{ &out2("subl",@_); }
sub main'rotl	{ &out2("roll",@_); }
sub main'rotr	{ &out2("rorl",@_); }
sub main'exch	{ &out2("xchg",@_); }
sub main'cmp	{ &out2("cmpl",@_); }
sub main'jmp	{ &out1("jmp",@_); }
sub main'je	{ &out1("je",@_); }
sub main'jne	{ &out1("jne",@_); }
sub main'jnz	{ &out1("jnz",@_); }
sub main'jz	{ &out1("jz",@_); }
sub main'dec	{ &out1("decl",@_); }
sub main'push	{ &out1("pushl",@_); }
sub main'call	{ &out1("call",$under.$_[0]); }


sub out2
	{
	local($name,$p1,$p2)=@_;
	local($l,$ll,$t);

	print "\t$name\t";
	$t=&conv($p2).",";
	$l=length($t);
	print $t;
	$ll=4-($l+9)/8;
	print "\t" x $ll;
	print &conv($p1);
	print "\n";
	}

sub out1
	{
	local($name,$p1)=@_;
	local($l,$t);

	print "\t$name\t";
	print &conv($p1);
	print "\n";
	}

sub conv
	{
	local($p)=@_;

#	$p =~ s/0x([0-9A-Fa-f]+)/0$1h/;

	$p=$regs{$p} if (defined($regs{$p}));

	$p =~ s/^([0-9A-Fa-f]+)$/\$$1/;
	$p =~ s/^(0x[0-9A-Fa-f]+)$/\$$1/;
	return $p;
	}

sub main'file
	{
	local($file)=@_;

	print <<"EOF";
	.file	"$file.s"
	.version	"01.01"
gcc2_compiled.:
EOF
	}

sub main'function_begin
	{
	local($func,$num)=@_;

	$params=$num*4;

	$func=$under.$func;

	print <<"EOF";
.text
	.align $align
.globl $func
EOF
	if ($main'cpp)
		{ printf("\tTYPE($func,\@function)\n"); }
	else	{ printf("\t.type	$func,\@function\n"); }
	print <<"EOF";
$func:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

EOF
	$stack=20;
	}

sub main'function_end
	{
	local($func)=@_;

	$func=$under.$func;

	print <<"EOF";
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.${func}_end:
EOF
	if ($main'cpp)
		{ printf("\tSIZE($func,.${func}_end-$func)\n"); }
	else	{ printf("\t.size\t$func,.${func}_end-$func\n"); }
	print ".ident	\"desasm.pl\"\n";
	$stack=0;
	%label=();
	}

sub main'function_end_A
	{
	local($func)=@_;

	print <<"EOF";
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
EOF
	}

sub main'function_end_B
	{
	local($func)=@_;

	$func=$under.$func;

	print <<"EOF";
.${func}_end:
EOF
	if ($main'cpp)
		{ printf("\tSIZE($func,.${func}_end-$func)\n"); }
	else	{ printf("\t.size\t$func,.${func}_end-$func\n"); }
	print ".ident	\"desasm.pl\"\n";
	$stack=0;
	%label=();
	}

sub main'wparam
	{
	local($num)=@_;

	return(&main'DWP($stack+$num*4,"esp","",0));
	}

sub main'wtmp_b
	{
	local($num,$b)=@_;

	return(&main'BP(-(($num+1)*4)+$b,"esp","",0));
	}

sub main'wtmp
	{
	local($num)=@_;

	return(&main'DWP(-($num+1)*4,"esp","",0));
	}

sub main'comment
	{
	foreach (@_)
		{
		if (/^\s*$/)
			{ print "\n"; }
		else
			{ print "\t$com_start $_ $com_end\n"; }
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
	print ".align $align\n";
	print "$label{$_[0]}:\n";
	}

sub main'file_end
	{
	}
