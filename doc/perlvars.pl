# Variables for common options.

$OpenSSL::safe::do_not_edit =
"=begin comment\n"
. join("  \n", @autowarntext)
. "\n=end";


$OpenSSL::safe::opt_v_synopsis =
"[B<-attime> I<timestamp>]\n"
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
$OpenSSL::safe::opt_v_item =
"=item B<-attime>, B<-check_ss_sig>, B<-crl_check>, B<-crl_check_all>,\n"
. "B<-explicit_policy>, B<-extended_crl>, B<-ignore_critical>, B<-inhibit_any>,\n"
. "B<-inhibit_map>, B<-no_alt_chains>, B<-partial_chain>, B<-policy>,\n"
. "B<-policy_check>, B<-policy_print>, B<-purpose>, B<-suiteB_128>,\n"
. "B<-suiteB_128_only>, B<-suiteB_192>, B<-trusted_first>, B<-use_deltas>,\n"
. "B<-auth_level>, B<-verify_depth>, B<-verify_email>, B<-verify_hostname>,\n"
. "B<-verify_ip>, B<-verify_name>, B<-x509_strict>\n"
. "\n"
. "Set various options of certificate chain verification. See\n"
. "L<openssl-verify(1)> manual page for details.";
