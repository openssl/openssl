# OQS-OpenSSL Interoperability Testing

This directory contains tests of interoperability between OQS-OpenSSL and OQS-BoringSSL. **We only guarantee the tests work on Ubuntu 18.04 (Bionic) and above**. This README only describes the nature of the tests. For the steps to run them, consult the `${PROJECT_ROOT}/.circleci/config.yml` file.

There are two types of tests:

- The "basic" TLS test suite: This first sets the server signature algorithm to `dilithium2` and establishes a TLS connection for each key-exchange algorithm, and next sets the server key-exchange algorithm to `frodo640aes` and establishes a TLS connection for each signature algorithm.

- The "full" TLS test suite, which tests TLS connections for all possible pairs of signature and key-exchange algorithms.

For each of these test types, the `--client-type` argument must be specified. This argument can take values `ossl` (denoting OpenSSL) and `bssl` (denoting BoringSSL). The client and server programs are then automatically selected.

If the client is an OpenSSL one, a BoringSSL server will be started and vice versa. Furthermore, if the server is an OpenSSL one, a CA and server certificate are generated and verified by the BoringSSL client. On the other hand, if the server is a BoringSSL one, only a single self-signed certificate is sent to the OpenSSL client, and no certificate verification takes place (this is due to the way the BoringSSL server is written).
