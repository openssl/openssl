OQS-OpenSSL Integration Testing
===============================

This directory contains test suites for all the OQS-added algorithms. The [README.md file for OQS-OpenSSL fork](https://github.com/open-quantum-safe/openssl#supported-algorithms) lists all supported OQS key exchange and authentication mechanisms.

**We can only guarantee the tests work on UNIX-like systems**. We regularly run these tests on macOS 10.14, Debian 10 (Buster) and Ubuntu 18.04 (Bionic).

1. First make sure you have **the necessary dependencies**:


- On **Ubuntu**

```
sudo apt install python3 python3-pytest python3-pytest-xdist python3-psutil
```

- On **macOS**

```
brew install python3
pip3 install --user pytest pytest-xdist psutil
```

2. From the project root directory, the following test suites can be executed:

- The "basic" TLS test suite: This first sets the server signature algorithm to `dilithium2` and establishes a TLS connection for each key-exchange algorithm, and then sets the server key-exchange algorithm to `frodo640aes` and establishes a TLS connection for each signature algorithm. This can be run by executing the following command:

```
python3 -m pytest oqs-test/test_tls_basic.py
```

- The "full" TLS test suite, which tests TLS connections for all possible pairs of signature and key-exchange algorithms and can be run by executing the following command:

```
python3 -m pytest oqs-test/test_tls_full.py
```

- A CMS test suite, which tests the CMS functionality for all signature algorithms and can be run by executing the following command:

```
python3 -m pytest oqs-test/test_cms.py
```

Note that all the above test suites can be parallelized using `pytest-xdist`'s `--numprocesses` option.

## Running using CircleCI

You can locally run any of the integration tests that CircleCI runs.  First, you need to install CircleCI's local command line interface as indicated in the [installation instructions](https://circleci.com/docs/2.0/local-cli/). Then:

	circleci local execute --job <jobname>

where `<jobname>` is one of the following:

- `debian_buster-shared_oqs-static_ossl`
- `macOS-shared_oqs-shared_ossl`
- `macOS-static_oqs-static_ossl`
- `ubuntu_bionic-shared_oqs-shared_ossl`
- `ubuntu_bionic-static_oqs-static_ossl`

By default, these jobs will use the current GitHub versions of liboqs and OQS-OpenSSL.  You can override these by passing environment variables to CircleCI:

	circleci local execute --job <jobname> --env <NAME>=<VALUE> --env <NAME>=<VALUE> ...

where `<NAME>` is one of the following:

- `LIBOQS_REPO`: which repo to check out from, default `https://github.com/open-quantum-safe/liboqs.git`
- `LIBOQS_BRANCH`: which branch to check out, default `main`

Note that as of April 13, 2019, CircleCI has a bug which causes it to fail when trying to locally run with a repository with a large number of files, such as OpenSSL.  A work-around is available by editing `.circleci/config.yml` as indicated by the comments in that file.
