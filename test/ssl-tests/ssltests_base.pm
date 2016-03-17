# -*- mode: perl; -*-

## SSL test configurations

package ssltests;

our %base_server = (
    "Certificate" => "\${ENV::TEST_CERTS_DIR}/servercert.pem",
    "PrivateKey"  => "\${ENV::TEST_CERTS_DIR}/serverkey.pem",
    "CipherString" => "DEFAULT",
);

our %base_client = (
    "VerifyCAFile" => "\${ENV::TEST_CERTS_DIR}/rootcert.pem",
    "VerifyMode" => "Peer",
    "CipherString" => "DEFAULT",
);
