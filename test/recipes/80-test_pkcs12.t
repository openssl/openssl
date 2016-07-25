use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use Encode;

setup("test_pkcs12");

plan tests => 1;

my $pass = "σύνθημα γνώρισμα";

my $savedcp;
if (eval { require Win32::Console; 1; }) {
    # Trouble is that Win32 perl uses CreateProcessA, which
    # makes it problematic to pass non-ASCII arguments. The only
    # feasible option is to pick one language, set corresponding
    # code page and reencode the problematic string...

    $savedcp = Win32::Console::OutputCP();
    Win32::Console::OutputCP(1253);
    $pass = Encode::encode("cp1253",Encode::decode("utf-8",$pass));
}

# just see that we can read shibboleth.pfx protected with $pass
ok(run(app(["openssl", "pkcs12", "-noout",
            "-password", "pass:$pass",
            "-in", srctop_file("test", "shibboleth.pfx")])),
   "test_pkcs12");

Win32::Console::OutputCP($savedcp) if (defined($savedcp));
