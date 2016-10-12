/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef HEADER_TEST_CONFIG
#define HEADER_TEST_CONFIG

#include <string>
#include <vector>


struct TestConfig {
  int port = 0;
  bool is_server = false;
  bool is_dtls = false;
  int resume_count = 0;
  bool fallback_scsv = false;
  std::string digest_prefs;
  std::vector<int> signing_prefs;
  std::string key_file;
  std::string cert_file;
  std::string expected_server_name;
  std::string expected_certificate_types;
  bool require_any_client_certificate = false;
  std::string advertise_npn;
  std::string expected_next_proto;
  bool false_start = false;
  std::string select_next_proto;
  bool async = false;
  bool write_different_record_sizes = false;
  bool cbc_record_splitting = false;
  bool partial_write = false;
  bool no_tls13 = false;
  bool no_tls12 = false;
  bool no_tls11 = false;
  bool no_tls1 = false;
  bool no_ssl3 = false;
  std::string expected_channel_id;
  bool enable_channel_id = false;
  std::string send_channel_id;
  bool shim_writes_first = false;
  std::string host_name;
  std::string advertise_alpn;
  std::string expected_alpn;
  std::string expected_advertised_alpn;
  std::string select_alpn;
  bool decline_alpn = false;
  bool expect_session_miss = false;
  bool expect_extended_master_secret = false;
  std::string psk;
  std::string psk_identity;
  std::string srtp_profiles;
  bool enable_ocsp_stapling = false;
  std::string expected_ocsp_response;
  bool enable_signed_cert_timestamps = false;
  std::string expected_signed_cert_timestamps;
  int min_version = 0;
  int max_version = 0;
  int mtu = 0;
  bool implicit_handshake = false;
  bool use_early_callback = false;
  bool fail_early_callback = false;
  bool install_ddos_callback = false;
  bool fail_ddos_callback = false;
  bool fail_second_ddos_callback = false;
  std::string cipher;
  std::string cipher_tls10;
  std::string cipher_tls11;
  bool handshake_never_done = false;
  int export_keying_material = 0;
  std::string export_label;
  std::string export_context;
  bool use_export_context = false;
  bool tls_unique = false;
  bool expect_ticket_renewal = false;
  bool expect_no_session = false;
  bool use_ticket_callback = false;
  bool renew_ticket = false;
  bool enable_client_custom_extension = false;
  bool enable_server_custom_extension = false;
  bool custom_extension_skip = false;
  bool custom_extension_fail_add = false;
  std::string ocsp_response;
  bool check_close_notify = false;
  bool shim_shuts_down = false;
  bool verify_fail = false;
  bool verify_peer = false;
  bool expect_verify_result = false;
  std::string signed_cert_timestamps;
  int expect_total_renegotiations = 0;
  bool renegotiate_once = false;
  bool renegotiate_freely = false;
  bool renegotiate_ignore = false;
  bool disable_npn = false;
  int expect_peer_signature_algorithm = 0;
  bool p384_only = false;
  bool enable_all_curves = false;
  bool use_sparse_dh_prime = false;
  int expect_curve_id = 0;
  int expect_dhe_group_size = 0;
  bool use_old_client_cert_callback = false;
  int initial_timeout_duration_ms = 0;
  bool use_null_client_ca_list = false;
  bool send_alert = false;
  bool peek_then_read = false;
  bool enable_grease = false;
  int max_cert_list = 0;
};

bool ParseConfig(int argc, char **argv, TestConfig *out_config);


#endif  // HEADER_TEST_CONFIG
