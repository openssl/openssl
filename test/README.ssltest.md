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
$ TOP=.. perl generate_ssl_tests.pl ssl-tests/my.conf.in > ssl-tests/my.conf
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
  
* ClientAlert, ServerAlert - expected alert. One of
  - UnknownCA

* Protocol - expected negotiated protocol. One of
  SSLv3, TLSv1, TLSv1.1, TLSv1.2.

## Configuring the client and server

The client and server configurations can be any valid `SSL_CTX`
configurations. For details, see the manpages for `SSL_CONF_cmd`.

Give your configurations as a dictionary of CONF commands, e.g.

```
server => {
    "CipherString = DEFAULT",
    "MinProtocol = TLSv1",
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

Set the `TEST_CERTS_DIR` environment variable to point to the location of the
certs. E.g., from the root OpenSSL directory, do

```
$ TEST_CERTS_DIR=test/certs test/ssl_test test/ssl-tests/01-simple.conf
```

Note that the `test/ssl-tests/*.conf` files correspond to expected outputs in
the default configuration. To run tests manually in a different configuration,
you may need to generate the right file from the `*.conf.in` input first.
