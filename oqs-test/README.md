OQS-OpenSSL Integration Testing
===============================

[![CircleCI](https://circleci.com/gh/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable)

---

This directory contains scripts for testing the OQS fork of OpenSSL with liboqs, using all supported algorithms. The [README.md file for the OQS-OpenSSL fork](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README.md) describes the various key exchange and authentication mechanisms supported.

First make sure you have **installed the dependencies** for the target OS as indicated in the [top-level testing README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README.md).

Testing on Linux and macOS
--------------------------

The scripts have been tested on macOS 10.14, Debian 10 (Buster) and Ubuntu 18.04 (Bionic).

### Running directly

Run:

	cd oqs_test
	./run.sh

Alternatively, to log the run.sh output while following live, try:

    ./run.sh | tee `date "+%Y%m%d-%Hh%Mm%Ss-openssl.log.txt"`
	
### Running using CircleCI

You can locally run any of the integration tests that CircleCI runs.  First, you need to install CircleCI's local command line interface as indicated in the [installation instructions](https://circleci.com/docs/2.0/local-cli/).  Then:

	circleci local execute --job <jobname>

where `<jobname>` is one of the following:

- `debian-buster-amd64`
- `ubuntu-bionic-x86_64`
- `ubuntu-bionic-x86_64-shared`

By default, these jobs will use the current Github versions of liboqs and OQS-OpenSSL.  You can override these by passing environment variables to CircleCI:

	circleci local execute --job <jobname> --env <NAME>=<VALUE> --env <NAME>=<VALUE> ...

where `<NAME>` is one of the following:

- `LIBOQS_REPO`: which repo to check out from, default `https://github.com/open-quantum-safe/liboqs.git`
- `LIBOQS_BRANCH`: which branch to check out, default `master`

Note that as of April 13, 2019, CircleCI has a bug which causes it to fail when trying to locally run with a repository with a large number of files, such as OpenSSL.  A work-around is available by editing `.circleci/config.yml` as indicated by the comments in that file.
