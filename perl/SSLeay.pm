package SSLeay;

use Exporter;
use DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();

$VERSION='0.82';
$VERSION='0.82';
bootstrap SSLeay;

@SSLeay::BN::ISA=	qw(SSLeay::ERR);
@SSLeay::MD::ISA=	qw(SSLeay::ERR);
@SSLeay::Cipher::ISA=	qw(SSLeay::ERR);
@SSLeay::SSL::CTX::ISA=	qw(SSLeay::ERR);
@SSLeay::BIO::ISA=	qw(SSLeay::ERR);
@SSLeay::SSL::ISA=	qw(SSLeay::ERR);

@BN::ISA=	qw(SSLeay::BN);
@MD::ISA=	qw(SSLeay::MD);
@Cipher::ISA=	qw(SSLeay::Cipher);
@SSL::ISA=	qw(SSLeay::SSL);
@SSL::CTX::ISA=	qw(SSLeay::SSL::CTX);
@BIO::ISA=	qw(SSLeay::BIO);


@SSLeay::MD::names=qw(md2 md5 sha sha1 ripemd160 mdc2);

@SSLeay::Cipher::names=qw(
	des-ecb des-cfb des-ofb des-cbc
	des-ede des-ede-cfb des-ede-ofb des-ede-cbc
	des-ede3 des-ede3-cfb des-ede3-ofb des-ede3-cbc
	desx-cbc rc4 rc4-40
	idea-ecb idea-cfb idea-ofb idea-cbc
	rc2-ecb rc2-cbc rc2-40-cbc rc2-cfb rc2-ofb
	bf-ecb bf-cfb bf-ofb bf-cbc
	cast5-ecb cast5-cfb cast5-ofb cast5-cbc
	rc5-ecb rc5-cfb rc5-ofb rc5-cbc
	);

sub SSLeay::SSL::CTX::new_ssl { SSLeay::SSL::new($_[0]); }

sub SSLeay::ERR::error
	{
	my($o)=@_;
	my($s,$ret);

	while (($s=$o->get_error()) != 0)
		{
		$ret.=$s."\n";
		}
	return($ret);
	}

@SSLeay::Cipher::aliases=qw(des desx des3 idea rc2 bf cast);

package SSLeay::BN;

sub bnfix { (ref($_[0]) ne "SSLeay::BN")?SSLeay::BN::dec2bn($_[0]):$_[0]; }
use overload
"="  => sub { dup($_[0]); },
"+"  => sub { add($_[0],$_[1]); },
"-"  => sub {	($_[1],$_[0])=($_[0],$_[1]) if $_[2];
		SSLeay::BN::sub($_[0],$_[1]); },
"*"  => sub { mul($_[0],$_[1]); },
"/"  => sub {  ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; (div($_[0],$_[1]))[0]; },
"%"  => sub {  ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; mod($_[0],$_[1]); },
"**" => sub { ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; exp($_[0],$_[1]); },
"<<" => sub { lshift($_[0],$_[1]); },
">>" => sub { rshift($_[0],$_[1]); },
"<=>" => sub { SSLeay::BN::cmp($_[0],$_[1]); },
'""' => sub { bn2dec($_[0]); },
'0+' => sub { dec2bn($_[0]); },
"bool" => sub { ref($_[0]) eq "SSLeay::BN"; };

sub SSLeay::BIO::do_accept { SSLeay::BIO::do_handshake(@_); }
1;
