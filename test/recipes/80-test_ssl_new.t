#! /usr/bin/perl

use strict;
use warnings;

use File::Compare qw/compare_text/;

use OpenSSL::Test qw/:DEFAULT srctop_dir srctop_file/;
use OpenSSL::Test::Utils qw/disabled alldisabled available_protocols/;

setup("test_ssl_new");

$ENV{TEST_CERTS_DIR} = srctop_dir("test", "certs");

plan tests => 2;

# 02-protocol-version.conf test results depend on the configuration of enabled
# protocols. We only verify generated sources in the default configuration.
my $is_default = (disabled("ssl3") && !disabled("tls1") &&
                  !disabled("tls1_1") && !disabled("tls1_2"));

# [file, check_source]
my @conf_files = (["01-simple.conf", 1],
                  ["02-protocol-version.conf", $is_default]);

foreach my $conf (@conf_files) {
    subtest "Test configuration $conf->[0]" => sub {
        test_conf(@$conf);
    }
}

sub test_conf {
    plan tests => 3;

    my ($conf, $check_source) = @_;

    my $conf_file = srctop_file("test", "ssl-tests", $conf);
    my $tmp_file = srctop_file("test", "ssl-tests", "${conf}.tmp");
    my $run_test = 1;

  SKIP: {
      # "Test" 1. Generate the source.
      my $input_file = $conf_file . ".in";

      skip 'failure', 2 unless
        ok(run(perltest(["generate_ssl_tests.pl", $input_file],
                        stdout => $tmp_file)),
           "Getting output from generate_ssl_tests.pl.");

    SKIP: {
        # Test 2. Compare against existing output in test/ssl_tests.conf.
        skip "Skipping generated source test for $conf", 1
          if !$check_source;

        $run_test = is(cmp_text($tmp_file, $conf_file), 0,
                       "Comparing generated sources.");
      }

      # Test 3. Run the test.
      my $no_tls = alldisabled(available_protocols("tls"));
      skip "No TLS tests available; skipping tests", 1 if $no_tls;
      skip "Stale sources; skipping tests", 1 if !$run_test;
      
      ok(run(test(["ssl_test", $tmp_file])), "running ssl_test $conf");
    }

    unlink glob $tmp_file;
}

sub cmp_text {
    return compare_text(@_, sub {
        $_[0] =~ s/\R//g;
        $_[1] =~ s/\R//g;
        return $_[0] ne $_[1];
    });
}
