#!/usr/local/bin/perl

package x86ms;

$label="L000";

%lb=(	'eax',	'al',
	'ebx',	'bl',
	'ecx',	'cl',
	'edx',	'dl',
	'ax',	'al',
	'bx',	'bl',
	'cx',	'cl',
	'dx',	'dl',
	);

%hb=(	'eax',	'ah',
	'ebx',	'bh',
	'ecx',	'ch',
	'edx',	'dh',
	'ax',	'ah',
	'bx',	'bh',
	'cx',	'ch',
	'dx',	'dh',
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
	local($t);
	local($ret)="DWORD PTR ";

	$addr =~ s/^\s+//;
	if ($addr =~ /^(.+)\+(.+)$/)
		{
		$reg2=&conv($1);
		$addr="_$2";
		}
	elsif ($addr =~ /^[_a-zA-Z]/)
		{
		$addr="_$addr";
		}

	$reg1="$regs{$reg1}" if defined($regs{$reg1});
	$reg2="$regs{$reg2}" if defined($regs{$reg2});
	$ret.=$addr if ($addr ne "") && ($addr ne 0);
	if ($reg2 ne "")
		{
		$t="";
		$t="*$idx" if ($idx != 0);
		$ret.="[$reg2$t+$reg1]";
		}
	else
		{
		$ret.="[$reg1]"
		}
	return($ret);
	}

sub main'mov	{ &out2("mov",@_); }
sub main'movb	{ &out2("mov",@_); }
sub main'and	{ &out2("and",@_); }
sub main'or	{ &out2("or",@_); }
sub main'shl	{ &out2("shl",@_); }
sub main'shr	{ &out2("shr",@_); }
sub main'xor	{ &out2("xor",@_); }
sub main'add	{ &out2("add",@_); }
sub main'sub	{ &out2("sub",@_); }
sub main'rotl	{ &out2("rol",@_); }
sub main'rotr	{ &out2("ror",@_); }
sub main'exch	{ &out2("xchg",@_); }
sub main'cmp	{ &out2("cmp",@_); }
sub main'dec	{ &out1("dec",@_); }
sub main'jmp	{ &out1("jmp",@_); }
sub main'je	{ &out1("je",@_); }
sub main'jz	{ &out1("jz",@_); }
sub main'jnz	{ &out1("jnz",@_); }
sub main'push	{ &out1("push",@_); }
sub main'call	{ &out1("call",'_'.$_[0]); }


sub out2
	{
	local($name,$p1,$p2)=@_;
	local($l,$t);

	print "\t$name\t";
	$t=&conv($p1).",";
	$l=length($t);
	print $t;
	$l=4-($l+9)/8;
	print "\t" x $l;
	print &conv($p2);
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

	$p =~ s/0x([0-9A-Fa-f]+)/0$1h/;
	return $p;
	}

sub main'file
	{
	local($file)=@_;

	print <<"EOF";
	TITLE	$file.asm
        .386
.model FLAT
EOF
	}

sub main'function_begin
	{
	local($func,$num,$extra)=@_;

	$params=$num*4;

	print <<"EOF";
_TEXT	SEGMENT
PUBLIC	_$func
$extra
_$func PROC NEAR
	push	ebp
	push	ebx
	push	esi
	push	edi
EOF
	$stack=20;
	}

sub main'function_end
	{
	local($func)=@_;

	print <<"EOF";
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
_$func ENDP
_TEXT	ENDS
EOF
	$stack=0;
	%label=();
	}

sub main'function_end_A
	{
	local($func)=@_;

	print <<"EOF";
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
EOF
	}

sub main'function_end_B
	{
	local($func)=@_;

	print <<"EOF";
_$func ENDP
_TEXT	ENDS
EOF
	$stack=0;
	%label=();
	}

sub main'file_end
	{
	print "END\n"
	}

sub main'wparam
	{
	local($num)=@_;

	return(&main'DWP($stack+$num*4,"esp","",0));
	}

sub main'wtmp
	{
	local($num)=@_;

	return(&main'DWP($stack+$params+$num*4,"esp","",0));
	}

sub main'comment
	{
	foreach (@_)
		{
		print "\t; $_\n";
		}
	}

sub main'label
	{
	if (!defined($label{$_[0]}))
		{
		$label{$_[0]}="\$${label}${_[0]}";
		$label++;
		}
	return($label{$_[0]});
	}

sub main'set_label
	{
	if (!defined($label{$_[0]}))
		{
		$label{$_[0]}="${label}${_[0]}";
		$label++;
		}
	print "$label{$_[0]}:\n";
	}

sub main'file_end
        {
	print "END\n";
        }
