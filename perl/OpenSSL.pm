##
##  OpenSSL.pm
##

package OpenSSL;

require 5.000;
use Exporter;
use DynaLoader;

@ISA    = qw(Exporter DynaLoader);
@EXPORT = qw();

$VERSION = '0.94';
bootstrap OpenSSL;

@OpenSSL::BN::ISA        = qw(OpenSSL::ERR);
@OpenSSL::MD::ISA        = qw(OpenSSL::ERR);
@OpenSSL::Cipher::ISA    = qw(OpenSSL::ERR);
@OpenSSL::SSL::CTX::ISA  = qw(OpenSSL::ERR);
@OpenSSL::BIO::ISA       = qw(OpenSSL::ERR);
@OpenSSL::SSL::ISA       = qw(OpenSSL::ERR);

@BN::ISA                 = qw(OpenSSL::BN);
@MD::ISA                 = qw(OpenSSL::MD);
@Cipher::ISA             = qw(OpenSSL::Cipher);
@SSL::ISA                = qw(OpenSSL::SSL);
@SSL::CTX::ISA           = qw(OpenSSL::SSL::CTX);
@BIO::ISA                = qw(OpenSSL::BIO);

@OpenSSL::MD::names = qw(
    md2 md5 sha sha1 ripemd160 mdc2
);

@OpenSSL::Cipher::names = qw(
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

sub OpenSSL::SSL::CTX::new_ssl { 
    OpenSSL::SSL::new($_[0]);
}

sub OpenSSL::ERR::error {
    my($o) = @_;
    my($s, $ret);

    while (($s = $o->get_error()) != 0) {
        $ret.=$s."\n";
    }
    return($ret);
}

@OpenSSL::Cipher::aliases = qw(
    des desx des3 idea rc2 bf cast
);

package OpenSSL::BN;

sub bnfix { 
    (ref($_[0]) ne "OpenSSL::BN") ? OpenSSL::BN::dec2bn($_[0]) : $_[0]; 
}

use overload
"="    => sub { dup($_[0]); },
"+"    => sub { add($_[0],$_[1]); },
"-"    => sub { ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; OpenSSL::BN::sub($_[0],$_[1]); },
"*"    => sub { mul($_[0],$_[1]); },
"**"   => sub { ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; OpenSSL::BN::exp($_[0],$_[1]); },
"/"    => sub { ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; (div($_[0],$_[1]))[0]; },
"%"    => sub { ($_[1],$_[0])=($_[0],$_[1]) if $_[2]; mod($_[0],$_[1]); },
"<<"   => sub { lshift($_[0],$_[1]); },
">>"   => sub { rshift($_[0],$_[1]); },
"<=>"  => sub { OpenSSL::BN::cmp($_[0],$_[1]); },
'""'   => sub { bn2dec($_[0]); },
'0+'   => sub { dec2bn($_[0]); },
"bool" => sub { ref($_[0]) eq "OpenSSL::BN"; };

sub OpenSSL::BIO::do_accept { 
    OpenSSL::BIO::do_handshake(@_);
}

1;
