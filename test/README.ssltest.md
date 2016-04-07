# SSL tests

SSL testcases are configured in the `ssl-tests` directory.

Each `ssl_*.conf.in` file contains a number of test configurations. These files
are used to generate testcases in the OpenSSL CONF format.

The precise test output can be dependent on the library configuration. The test
harness generates the output files on the fly.

However, for verification, we also include checked-in configuration outputs
corresponding to the default configuration. These testcases live in
`test/ssl-tests/*.conf` files. Therefore, whenever you're adding or updating a
generated test, you should run

```
$ ./config
$ cd test
$ TOP=.. perl -I testlib/ generate_ssl_tests.pl ssl-tests/my.conf.in \
  > ssl-tests/my.conf
```

where `my.conf.in` is your test input file.

For example, to generate the test cases in `ssl-tests/01-simple.conf.in`, do

```
$ TOP=.. perl generate_ssl_tests.pl ssl-tests/01-simple.conf.in > ssl-tests/01-simple.conf
```

For more details, see `ssl-tests/01-simple.conf.in` for an example.

## Configuring the test

First, give your test a name. The names do not have to be unique.

An example test input looks like this:

```
    {
        name => "test-default",
        server => { "CipherString" => "DEFAULT" },
        client => { "CipherString" => "DEFAULT" },
        test   => { "ExpectedResult" => "Success" },
    }
```

The test section supports the following options:

* ExpectedResult - expected handshake outcome. One of
  - Success - handshake success
  - ServerFail - serverside handshake failure
  - ClientFail - clientside handshake failure
  - InternalError - some other error

* ClientAlert, ServerAlert - expected alert. See `ssl_test_ctx.c` for known
  values.

* Protocol - expected negotiated protocol. One of
  SSLv3, TLSv1, TLSv1.1, TLSv1.2.

* ClientVerifyCallback - the client's custom certificate verify callback.
  Used to test callback behaviour. One of
  - AcceptAll - accepts all certificates.
  - RejectAll - rejects all certificates.

## Configuring the client and server

The client and server configurations can be any valid `SSL_CTX`
configurations. For details, see the manpages for `SSL_CONF_cmd`.

Give your configurations as a dictionary of CONF commands, e.g.

```
server => {
    "CipherString" => "DEFAULT",
    "MinProtocol" => "TLSv1",
}
```

### Default server and client configurations

The default server certificate and CA files are added to the configurations
automatically. Server certificate verification is requested by default.

You can override these options by redefining them:

```
client => {
    "VerifyCAFile" => "/path/to/custom/file"
}
```

or by deleting them

```
client => {
    "VerifyCAFile" => undef
}
```

## Adding a test to the test harness

Add your configuration file to `test/recipes/80-test_ssl_new.t`.

## Running the tests with the test harness

```
HARNESS_VERBOSE=yes make TESTS=test_ssl_new test
```

## Running a test manually

These steps are only needed during development. End users should run `make test`
or follow the instructions above to run the SSL test suite.

To run an SSL test manually from the command line, the `TEST_CERTS_DIR`
environment variable to point to the location of the certs. E.g., from the root
OpenSSL directory, do

```
$ TEST_CERTS_DIR=test/certs test/ssl_test test/ssl-tests/01-simple.conf
```

or for shared builds

```
$ TEST_CERTS_DIR=test/certs util/shlib_wrap.sh test/ssl_test \
  test/ssl-tests/01-simple.conf
```

Note that the test expectations sometimes depend on the Configure settings. For
example, the negotiated protocol depends on the set of available (enabled)
protocols: a build with `enable-ssl3` has different test expectations than a
build with `no-ssl3`.

The Perl test harness automatically generates expected outputs, so users who
just run `make test` do not need any extra steps.

However, when running a test manually, keep in mind that the repository version
of the generated `test/ssl-tests/*.conf` correspond to expected outputs in with
the default Configure options. To run `ssl_test` manually from the command line
in a build with a different configuration, you may need to generate the right
`*.conf` file from the `*.conf.in` input first.
