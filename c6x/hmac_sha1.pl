#!/usr/bin/env perl
#
# Copyright (c) 2011 The OpenSSL Project.
#
######################################################################
#
# SHA1 and HMAC in Perl by <appro@openssl.org>.
#
{ package SHA1;
  use integer;

    {
    ################################### SHA1 block code generator
    my @V = ('$A','$B','$C','$D','$E');
    my $i;

    sub XUpdate {
      my $ret;
	$ret="(\$T=\$W[($i-16)%16]^\$W[($i-14)%16]^\$W[($i-8)%16]^\$W[($i-3)%16],\n\t";
	if ((1<<31)<<1) {
	    $ret.="    \$W[$i%16]=((\$T<<1)|(\$T>>31))&0xffffffff)\n\t  ";
	} else {
	    $ret.="    \$W[$i%16]=(\$T<<1)|((\$T>>31)&1))\n\t  ";
	}
    }
    sub tail {
      my ($a,$b,$c,$d,$e)=@V;
      my $ret;
	if ((1<<31)<<1) {
	    $ret.="(($a<<5)|($a>>27));\n\t";
	    $ret.="$b=($b<<30)|($b>>2);	$e&=0xffffffff;	#$b&=0xffffffff;\n\t";
	} else {
	    $ret.="(($a<<5)|($a>>27)&0x1f);\n\t";
	    $ret.="$b=($b<<30)|($b>>2)&0x3fffffff;\n\t";
	}
      $ret;
    }
    sub BODY_00_15 {
	my ($a,$b,$c,$d,$e)=@V;
	"$e+=\$W[$i]+0x5a827999+((($c^$d)&$b)^$d)+".tail();
    }
    sub BODY_16_19 {
	my ($a,$b,$c,$d,$e)=@V;
	"$e+=".XUpdate()."+0x5a827999+((($c^$d)&$b)^$d)+".tail();
    }
    sub BODY_20_39 {
	my ($a,$b,$c,$d,$e)=@V;
	"$e+=".XUpdate()."+0x6ed9eba1+($b^$c^$d)+".tail();
    }
    sub BODY_40_59 {
	my ($a,$b,$c,$d,$e)=@V;
	"$e+=".XUpdate()."+0x8f1bbcdc+(($b&$c)|(($b|$c)&$d))+".tail();
    }
    sub BODY_60_79 {
	my ($a,$b,$c,$d,$e)=@V;
	"$e+=".XUpdate()."+0xca62c1d6+($b^$c^$d)+".tail();
    }

    my $sha1_impl =
    'sub block {
	my $self = @_[0];
	my @W    = unpack("N16",@_[1]);
	my ($A,$B,$C,$D,$E,$T) = @{$self->{H}};
	';

	$sha1_impl.='
	$A &= 0xffffffff;
	$B &= 0xffffffff;
	' if ((1<<31)<<1);

	for($i=0;$i<16;$i++){ $sha1_impl.=BODY_00_15(); unshift(@V,pop(@V)); }
	for(;$i<20;$i++)    { $sha1_impl.=BODY_16_19(); unshift(@V,pop(@V)); }
	for(;$i<40;$i++)    { $sha1_impl.=BODY_20_39(); unshift(@V,pop(@V)); }
	for(;$i<60;$i++)    { $sha1_impl.=BODY_40_59(); unshift(@V,pop(@V)); }
	for(;$i<80;$i++)    { $sha1_impl.=BODY_60_79(); unshift(@V,pop(@V)); }

	$sha1_impl.='
	$self->{H}[0]+=$A;	$self->{H}[1]+=$B;	$self->{H}[2]+=$C;
	$self->{H}[3]+=$D;	$self->{H}[4]+=$E;	}';

    #print $sha1_impl,"\n";
    eval($sha1_impl);		# generate code
    }

    sub Init {
	my $class = shift;	# multiple instances...
	my $self  = {};

	bless $self,$class;
	$self->{H} = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];
	$self->{N} = 0;
	return $self;
    }

    sub Update {
	my $self = shift;
	my $msg;

	foreach $msg (@_) {
	    my $len  = length($msg);
	    my $num  = length($self->{buf});
	    my $off  = 0;

	    $self->{N} += $len;

	    if (($num+$len)<64)
	    {	$self->{buf} .= $msg; next;	}
	    elsif ($num)
	    {	$self->{buf} .= substr($msg,0,($off=64-$num));
		$self->block($self->{buf});
	    }

	    while(($off+64) <= $len)
	    {	$self->block(substr($msg,$off,64));
		$off += 64;
	    }

	    $self->{buf} = substr($msg,$off);
	}
	return $self;
    }

    sub Final {
	my $self = shift;
	my $num  = length($self->{buf});

	$self->{buf} .= chr(0x80); $num++;
	if ($num>56)
	{   $self->{buf} .= chr(0)x(64-$num);
	    $self->block($self->{buf});
	    $self->{buf}=undef;
	    $num=0;
	}
	$self->{buf} .= chr(0)x(56-$num);
	$self->{buf} .= pack("N2",($self->{N}>>29)&0x7,$self->{N}<<3);
	$self->block($self->{buf});

	return pack("N*",@{$self->{H}});
    }

    sub Selftest {
	my $hash;

	$hash=SHA1->Init()->Update('abc')->Final();
	die "SHA1 test#1" if (unpack("H*",$hash) ne 'a9993e364706816aba3e25717850c26c9cd0d89d');

	$hash=SHA1->Init()->Update('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')->Final();
	die "SHA1 test#2" if (unpack("H*",$hash) ne '84983e441c3bd26ebaae4aa1f95129e5e54670f1');

	#$hash=SHA1->Init()->Update('a'x1000000)->Final();
	#die "SHA1 test#3" if (unpack("H*",$hash) ne '34aa973cd4c4daa4f61eeb2bdbad27316534016f');
    }
}

{ package HMAC;

    sub Init {
	my $class = shift;
	my $key   = shift;
	my $self  = {};

	bless $self,$class;

	if (length($key)>64) {
	    $key = SHA1->Init()->Update($key)->Final();
	}
	$key .= chr(0x00)x(64-length($key));

	my @ikey = map($_^=0x36,unpack("C*",$key));
	($self->{hash} = SHA1->Init())->Update(pack("C*",@ikey));
	 $self->{okey} = pack("C*",map($_^=0x36^0x5c,@ikey));

	return $self;
    }

    sub Update {
	my $self = shift;
	$self->{hash}->Update(@_);
	return $self;
    }

    sub Final {
	my $self  = shift;
	my $ihash = $self->{hash}->Final();
	return SHA1->Init()->Update($self->{okey},$ihash)->Final();
    }

    sub Selftest {
	my $hmac;

	$hmac = HMAC->Init('0123456789:;<=>?@ABC')->Update('Sample #2')->Final();
	die "HMAC test" if (unpack("H*",$hmac) ne '0922d3405faa3d194f82a45830737d5cc6c75d24');
    }
}

1;
