Running external test suites with OpenSSL
=========================================

It is possible to integrate external test suites into OpenSSL's `make test`.
This capability is considered a developer option and does not work on all
platforms.

Python PYCA/Cryptography test suite
===================================

This python test suite runs cryptographic tests with a local OpenSSL build as
the implementation.

First checkout the `PYCA/Cryptography` module into `./pyca-cryptography` using:

    $ git submodule update --init

Then configure/build OpenSSL compatible with the python module:

    $ ./config enable-external-tests
    $ make

The tests will run in a python virtual environment which requires virtualenv
to be installed.

    $ make test VERBOSE=1 TESTS=test_external_pyca

Test failures and suppressions
------------------------------

Some tests target older (<=1.0.2) versions so will not run. Other tests target
other crypto implementations so are not relevant. Currently no tests fail.

krb5 test suite
===============

Much like the PYCA/Cryptography test suite, this builds and runs the krb5
tests against the local OpenSSL build.

You will need a git checkout of krb5 at the top level:

    $ git clone https://github.com/krb5/krb5

krb5's master has to pass this same CI, but a known-good version is
krb5-1.15.1-final if you want to be sure.

    $ cd krb5
    $ git checkout krb5-1.15.1-final
    $ cd ..

OpenSSL must be built with external tests enabled:

    $ ./config enable-external-tests
    $ make

krb5's tests will then be run as part of the rest of the suite, or can be
explicitly run (with more debugging):

    $ VERBOSE=1 make TESTS=test_external_krb5 test

Test-failures suppressions
--------------------------

krb5 will automatically adapt its test suite to account for the configuration
of your system.  Certain tests may require more installed packages to run.  No
tests are expected to fail.

GOST engine test suite
======================

Much like the PYCA/Cryptography test suite, this builds and runs the GOST engine
tests against the local OpenSSL build.

You will need a git checkout of gost-engine at the top level:

    $ git submodule update --init

Then configure/build OpenSSL enabling external tests:

    $ ./config enable-external-tests
    $ make

GOST engine requires CMake for the build process.

GOST engine tests will then be run as part of the rest of the suite, or can be
explicitly run (with more debugging):

    $ make test VERBOSE=1 TESTS=test_external_gost_engine

OQSprovider test suite
======================

Much like the PYCA/Cryptography test suite, this builds and runs the OQS
(OpenQuantumSafe -- www.openquantumsafe.org) provider tests against the
local OpenSSL build.

You will need a git checkout of oqsprovider at the top level:

    $ git submodule update --init

Then configure/build OpenSSL enabling external tests:

    $ ./config enable-external-tests
    $ make

oqsprovider requires CMake for the build process.

OQSprovider tests will then be run as part of the rest of the suite, or can be
explicitly run (with more debugging):

    $ make test VERBOSE=1 TESTS=test_external_oqsprovider

The names of all supported quantum-safe algorithms are available at
<https://github.com/open-quantum-safe/oqs-provider#algorithms>.

Please note specific limitations of oqsprovider operations dependent on specific
openssl versions as documented at
<https://github.com/open-quantum-safe/oqs-provider#note-on-openssl-versions>.

pkcs11-provider test suite
==========================

This builds and runs pkcs11-provider tests against the local OpenSSL build.

You will need a git checkout of pkcs11-provider at the top level:

    $ git submodule update --init

Then configure/build OpenSSL enabling external tests:

    $ ./config enable-external-tests
    $ make

pkcs11-provider requires meson for the build process. Moreover, it requires
softhsm and nss softokn tokens and certtool, certutil, pkcs11-tool and expect
to run the tests.

Tests will then be run as part of the rest of the suite, or can be
explicitly run (with more debugging):

    $ make test VERBOSE=1 TESTS=test_external_pkcs11_provider

Test failures and suppressions
------------------------------

There are tests for different software tokens - softhsm, nss-softokn and kryoptic.
Kryoptic tests will not run at this point. Currently no test fails.

The BoringSSL test suite
========================

In order to run the BoringSSL tests with OpenSSL, first checkout the BoringSSL
source code into an appropriate directory. This can be done in two ways:

1) Separately from the OpenSSL checkout using:

   $ `git clone https://boringssl.googlesource.com/boringssl boringssl`

 The BoringSSL tests are only confirmed to work at a specific commit in the
 BoringSSL repository. Later commits may or may not pass the test suite.
 Use the command below in the root of the OpenSSL source tree to determine the
 current commit hash:

   $ git submodule status

   $ cd boringssl
   $ git checkout `<boringssl_hash>`

2) Using the already configured submodule settings in OpenSSL:

   $ git submodule update --init

The BoringSSL tests use C++ 17 functions, so either CXX should be defined
for your configuration, or you set it when running configure. In addition
CXXFLAGS should include `-std=c++17`. Configure the OpenSSL source code to
enable the external tests:

   $ cd ../openssl
   $ CXX="g++" CXXFLAGS="-std=c++17" ./config enable-weak-ssl-ciphers \
       enable-external-tests

Note that using other config options than those given above may cause the tests
to fail.

Run the OpenSSL tests by providing the path to the BoringSSL test runner in the
`BORING_RUNNER_DIR` environment variable:

   $ BORING_RUNNER_DIR=/path/to/boringssl/ssl/test/runner make \
       TESTS="test_external_boringssl" test

Note that the test suite may change directory while running so the path provided
should be absolute and not relative to the current working directory.

To see more detailed output you can run just the BoringSSL tests with the
verbose option:

   $ VERBOSE=1 BORING_RUNNER_DIR=/path/to/boringssl/ssl/test/runner make \
       TESTS="test_external_boringssl" test

Test failures and suppressions
------------------------------

A large number of the BoringSSL tests are known to fail. A test could fail
because of many possible reasons. For example:

- A bug in OpenSSL
- Different interpretations of standards
- Assumptions about the way BoringSSL works that do not apply to OpenSSL
- The test uses APIs added to BoringSSL that are not present in OpenSSL
- etc

In order to provide a "clean" baseline run with all the tests passing a config
file has been provided that suppresses the running of tests that are known to
fail. These suppressions are held in the file "test/ossl_shim/ossl_config.json"
within the OpenSSL source code.

The community is encouraged to contribute patches which reduce the number of
suppressions that are currently present.

Updating test suites
====================

To update the commit for any of the above test suites:

- Make sure the submodules are cloned locally:

    $ git submodule update --init --recursive

- Enter subdirectory and pull from the repository (use a specific branch/tag if required):

    $ cd `<submodule-dir>`
    $ git pull origin master

- Go to root directory, there should be a new git status:

    $ cd ../
    $ git status
      ...
      #       modified:   `<submodule-dir>` (new commits)
      ...

- Add/commit/push the update

    $ git add `<submodule-dir>`
    $ git commit -m `"Updated <submodule> to latest commit"`
    $ git push
