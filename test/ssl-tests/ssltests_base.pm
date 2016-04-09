# -*- mode: perl; -*-

## SSL test configurations

package ssltests;

my $dir_sep = $^O ne "VMS" ? "/" : "";

our %base_server = (
    "Certificate" => "\${ENV::TEST_CERTS_DIR}${dir_sep}servercert.pem",
    "PrivateKey"  => "\${ENV::TEST_CERTS_DIR}${dir_sep}serverkey.pem",
    "CipherString" => "DEFAULT",
);

our %base_client = (
    "VerifyCAFile" => "\${ENV::TEST_CERTS_DIR}${dir_sep}rootcert.pem",
    "VerifyMode" => "Peer",
    "CipherString" => "DEFAULT",
);
