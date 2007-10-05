#!/usr/bin/env perl

# require 'x86asm.pl';
# &asm_init(<flavor>,"des-586.pl"[,$i386only]);
# &function_begin("foo");
# ...
# &function_end("foo");
# &asm_finish

# AUTOLOAD is this context has quite unpleasant side effect, namely
# that typos in function calls effectively go to assembler output,
# but on the pros side we don't have to implement one subroutine per
# each opcode...
sub ::AUTOLOAD
{ my $opcode = $AUTOLOAD;

    die "more than 2 arguments passed to $opcode" if ($#_>1);

    $opcode =~ s/.*:://;
    if    ($opcode =~ /^push/) { $stack+=4; }
    elsif ($opcode =~ /^pop/)  { $stack-=4; }

    &generic($opcode,@_) or die "undefined subroutine \&$AUTOLOAD";
}

$out=();
$i386=0;

sub ::emit
{ my $opcode=shift;

    if ($#_==-1)    { push(@out,"\t$opcode\n");				}
    else            { push(@out,"\t$opcode\t".join(',',@_)."\n");	}
}

sub ::LB
{   $_[0] =~ m/^e?([a-d])x$/o or die "$_[0] does not have a 'low byte'";
  $1."l";
}
sub ::HB
{   $_[0] =~ m/^e?([a-d])x$/o or die "$_[0] does not have a 'high byte'";
  $1."h";
}
sub ::stack_push{ my $num=$_[0]*4; $stack+=$num; &sub("esp",$num);	}
sub ::stack_pop	{ my $num=$_[0]*4; $stack-=$num; &add("esp",$num);	}
sub ::blindpop	{ &pop($_[0]); $stack+=4;				}
sub ::wparam	{ &DWP($stack+4*$_[0],"esp");				}
sub ::swtmp	{ &DWP(4*$_[0],"esp");					}

sub ::bswap
{   if ($i386)	# emulate bswap for i386
    {	&comment("bswap @_");
	&xchg(&HB(@_),&LB(@_));
	&ror (@_,16);
	&xchg(&HB(@_),&LB(@_));
    }
    else
    {	&generic("bswap",@_);	}
}
# These are made-up opcodes introduced over the years essentially
# by ignorance, just alias them to real ones...
sub ::movb	{ &mov(@_);	}
sub ::xorb	{ &xor(@_);	}
sub ::rotl	{ &rol(@_);	}
sub ::rotr	{ &ror(@_);	}
sub ::exch	{ &xchg(@_);	}
sub ::halt	{ &hlt;		}

sub ::function_begin
{   &function_begin_B(@_);
    $stack=4;
    &push("ebp");
    &push("ebx");
    &push("esi");
    &push("edi");
}

sub ::function_end
{   &pop("edi");
    &pop("esi");
    &pop("ebx");
    &pop("ebp");
    &ret();
    $stack=0;
    &function_end_B(@_);
}

sub ::function_end_A
{   &pop("edi");
    &pop("esi");
    &pop("ebx");
    &pop("ebp");
    &ret();
    $stack+=16;	# readjust esp as if we didn't pop anything
}

sub ::asciz {   foreach (@_) { &data_byte(unpack("C*",$_),0); }   }

sub ::asm_finish
{   &file_end();
    print @out;
}

sub ::asm_init
{ my ($type,$fn,$cpu)=@_;

    $filename=$fn;
    $i386=$cpu;

    $elf=$cpp=$coff=$aout=$win32=$netware=$mwerks=0;
    if    (($type eq "elf"))
    {	$elf=1;			require "x86unix.pl";	}
    elsif (($type eq "a\.out"))
    {	$aout=1;		require "x86unix.pl";	}
    elsif (($type eq "coff" or $type eq "gaswin"))
    {	$coff=1;		require "x86unix.pl";	}
    elsif (($type eq "win32n"))
    {	$win32=1;		require "x86nasm.pl";	}
    elsif (($type eq "nw-nasm"))
    {	$netware=1;		require "x86nasm.pl";	}
    elsif (($type eq "nw-mwasm"))
    {	$netware=1; $mwerks=1;	require "x86nasm.pl";	}
    else
    {	print STDERR <<"EOF";
Pick one target type from
	elf	- Linux, FreeBSD, Solaris x86, etc.
	a.out	- DJGPP, elder OpenBSD, etc.
	coff	- GAS/COFF such as Win32 targets
	win32n	- Windows 95/Windows NT NASM format
	nw-nasm - NetWare NASM format
	nw-mwasm- NetWare Metrowerks Assembler
EOF
	exit(1);
    }

    $pic=0;
    for (@ARGV) { $pic=1 if (/\-[fK]PIC/i); }

    $filename =~ s/\.pl$//;
    &file($filename);
}

1;
