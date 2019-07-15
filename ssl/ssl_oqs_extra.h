/* Extra OQS content for the ssl integration */

/* Returns the OQS KEM NID from a given alg name, or 0 if there is no match */
static int OQS_nid_from_string(const char *value) {
  int nid = 0;
  int len = strlen(value);
  if (strncmp(value,"oqs_kem_default", len) == 0) {
    nid = NID_OQS_KEM_DEFAULT;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_START
  } else if (strncmp(value, "frodo640aes", len) == 0) {
    nid = NID_OQS_frodo640aes;
  } else if (strncmp(value, "frodo640shake", len) == 0) {
    nid = NID_OQS_frodo640shake;
  } else if (strncmp(value, "frodo976aes", len) == 0) {
    nid = NID_OQS_frodo976aes;
  } else if (strncmp(value, "frodo976shake", len) == 0) {
    nid = NID_OQS_frodo976shake;
  } else if (strncmp(value, "frodo1344aes", len) == 0) {
    nid = NID_OQS_frodo1344aes;
  } else if (strncmp(value, "frodo1344shake", len) == 0) {
    nid = NID_OQS_frodo1344shake;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_END
  /* hybrid algs */
  } else if (strncmp(value,"p256-oqs_kem_default", len) == 0) {
    nid = NID_OQS_p256_KEM_DEFAULT;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_HYBRID_START
  } else if (strncmp(value, "p256-frodo640aes", len) == 0) {
    nid = NID_OQS_p256_frodo640aes;
  } else if (strncmp(value, "p256-frodo640shake", len) == 0) {
    nid = NID_OQS_p256_frodo640shake;
  } else if (strncmp(value, "p256-frodo976aes", len) == 0) {
    nid = NID_OQS_p256_frodo976aes;
  } else if (strncmp(value, "p256-frodo976shake", len) == 0) {
    nid = NID_OQS_p256_frodo976shake;
  } else if (strncmp(value, "p256-frodo1344aes", len) == 0) {
    nid = NID_OQS_p256_frodo1344aes;
  } else if (strncmp(value, "p256-frodo1344shake", len) == 0) {
    nid = NID_OQS_p256_frodo1344shake;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_HYBRID_END
  }
  return nid;
}
