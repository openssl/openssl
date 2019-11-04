#! /usr/bin/env perl
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at

# Set some Perl variables for use by util/dofile.pl when processing
# POD files (mainly man1).

# Verify options
$OpenSSL::safe::opt_v_synopsis = ""
. "[B<-attime> I<timestamp>]\n"
. "[B<-check_ss_sig>]\n"
. "[B<-crl_check>]\n"
. "[B<-crl_check_all>]\n"
. "[B<-explicit_policy>]\n"
. "[B<-extended_crl>]\n"
. "[B<-ignore_critical>]\n"
. "[B<-inhibit_any>]\n"
. "[B<-inhibit_map>]\n"
. "[B<-partial_chain>]\n"
. "[B<-policy> I<arg>]\n"
. "[B<-policy_check>]\n"
. "[B<-policy_print>]\n"
. "[B<-purpose> I<purpose>]\n"
. "[B<-suiteB_128>]\n"
. "[B<-suiteB_128_only>]\n"
. "[B<-suiteB_192>]\n"
. "[B<-trusted_first>]\n"
. "[B<-no_alt_chains>]\n"
. "[B<-use_deltas>]\n"
. "[B<-auth_level> I<num>]\n"
. "[B<-verify_depth> I<num>]\n"
. "[B<-verify_email> I<email>]\n"
. "[B<-verify_hostname> I<hostname>]\n"
. "[B<-verify_ip> I<ip>]\n"
. "[B<-verify_name> I<name>]\n"
. "[B<-x509_strict>]\n"
. "[B<-certfile> I<file>]";
$OpenSSL::safe::opt_v_item = ""
. "=item B<-attime>, B<-check_ss_sig>, B<-crl_check>, B<-crl_check_all>,\n"
. "B<-explicit_policy>, B<-extended_crl>, B<-ignore_critical>, B<-inhibit_any>,\n"
. "B<-inhibit_map>, B<-no_alt_chains>, B<-partial_chain>, B<-policy>,\n"
. "B<-policy_check>, B<-policy_print>, B<-purpose>, B<-suiteB_128>,\n"
. "B<-suiteB_128_only>, B<-suiteB_192>, B<-trusted_first>, B<-use_deltas>,\n"
. "B<-auth_level>, B<-verify_depth>, B<-verify_email>, B<-verify_hostname>,\n"
. "B<-verify_ip>, B<-verify_name>, B<-x509_strict>\n"
. "\n"
. "Set various options of certificate chain verification.\n"
. "See L<openssl(1)/Verification Options> for details.";


# Extended validation options.
$OpenSSL::safe::opt_x_synopsis = ""
. "[B<-xkey>] I<infile>\n"
. "[B<-xcert> I<file>]\n"
. "[B<-xchain>] I<file>\n"
. "[B<-xchain_build>] I<file>\n"
. "[B<-xcertform> B<DER>|B<PEM>]>\n"
. "[B<-xkeyform> B<DER>|B<PEM>]>";
$OpenSSL::safe::opt_x_item = ""
. "=item B<xkey> I<infile>, B<-xcert> I<file>, B<-xchain> I<file>,\n"
. "B<-xchain_build> I<file>, B<-xcertform> B<DER>|B<PEM>,\n"
. "B<-xkeyform> B<DER>|B<PEM>>\n"
. "\n"
. "Set extended certificate verification options.\n"
. "See L<openssl(1)/Extended Verification Options> for details.";


# Random State Options
$OpenSSL::safe::opt_r_synopsis = ""
. "[B<-rand> I<files>]\n"
. "[B<-writerand> I<file>]";
$OpenSSL::safe::opt_r_item = ""
. "=item B<-rand> I<files>, B<-writerand> I<file>\n"
. "\n"
. "See L<openssl(1)/Random State Options> for details.";

# Trusted certs options
$OpenSSL::safe::opt_trust_synopsis = ""
. "[B<-CAfile> I<file>]\n"
. "[B<-no-CAfile>]\n"
. "[B<-CApath> I<dir>]\n"
. "[B<-no-CApath>]\n"
. "[B<-CAstore> I<uri>]\n"
. "[B<-no-CAstore>]";
$OpenSSL::safe::opt_trust_item = ""
. "=item B<-CAfile> I<file>, B<-no-CAfile>, B<-CApath> I<dir>, B<-no-CApath>,\n"
. "B<-CAstore> I<uri>, B<-no-CAstore>\n"
. "\n"
. "See L<openssl(1)/Trusted Certificate Options> for details.";

# SSL connection options.
# TODO(3.0) Not currently used.  The refactoring needs to be done, and
# the options will probably be re-ordered.
$OpenSSL::safe::opt_s_synopsis = ""
. "[B<-bugs>]\n"
. "[B<-no_comp>]\n"
. "[B<-no_ticket>]\n"
. "[B<-serverpref>]\n"
. "[B<-legacy_renegotiation>]\n"
. "[B<-no_renegotiation>]\n"
. "[B<-legacy_server_connect>]\n"
. "[B<-no_resumption_on_reneg>]\n"
. "[B<-no_legacy_server_connect>]\n"
. "[B<-allow_no_dhe_kex>]\n"
. "[B<-prioritize_chacha>]\n"
. "[B<-strict>]\n"
. "[B<-sigalgs> I<algs>]\n"
. "[B<-client_sigalgs> I<algs>]\n"
. "[B<-groups> I<groups>]\n"
. "[B<-curves> I<curves>]\n"
. "[B<-named_curve> I<curves>]\n"
. "[B<-cipher> I<ciphers>]\n"
. "[B<-ciphersuites> I<1.3ciphers>]\n"
. "[B<-min_protocol> I<minprot>]\n"
. "[B<-max_protocol> I<maxprot>]\n"
. "[B<-record_padding> I<padding>]\n"
. "[B<-debug_broken_protocol>]\n"
. "[B<-no_middlebox>]";
$OpenSSL::safe::opt_s_item = ""
. "=item B<-bugs>, B<-no_comp>, B<-no_ticket>, B<-serverpref>,"
. "B<-legacy_renegotiation>, B<-no_renegotiation>, B<-legacy_server_connect>,\n"
. "B<-no_resumption_on_reneg>, B<-no_legacy_server_connect>,\n"
. "B<-allow_no_dhe_kex>, B<-prioritize_chacha>, B<-strict>, B<-sigalgs>\n"
. "I<algs>, B<-client_sigalgs> I<algs>, B<-groups> I<groups>, B<-curves>\n"
. "I<curves>, B<-named_curve> I<curves>, B<-cipher> I<ciphers>, B<-ciphersuites>\n"
. "I<1.3ciphers>, B<-min_protocol> I<minprot>, B<-max_protocol> I<maxprot>,\n"
. "B<-record_padding> I<padding>, B<-debug_broken_protocol>, B<-no_middlebox>\n"
. "\n"
. "See L<SSL_CONF_cmd(3)/SUPPORTED COMMAND LINE COMMANDS> for details.";
