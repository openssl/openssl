/* Extra OQS content for the ssl integration */

/* Returns the OQS NID from a given alg name, or 0 if there is no match */
static int OQS_nid_from_string(const char *value) {
  int nid = 0;
  int len = strlen(value);
  if (memcmp(value,"frodo", len) == 0) {
    nid = NID_OQS_Frodo;
  } else if (memcmp(value,"sike503", len) == 0) {
    nid = NID_OQS_SIKE_503;
  } else if (memcmp(value,"sike751", len) == 0) {
    nid = NID_OQS_SIKE_751;
  } else if (memcmp(value,"newhope", len) == 0) {
    nid = NID_OQS_Newhope;
  } else if (memcmp(value,"ntru", len) == 0) {
    nid = NID_OQS_NTRU;
  }
  /* hybrid algs */
  else  if (memcmp(value,"p256-frodo", len) == 0) {
    nid = NID_OQS_p256_Frodo;
  } else if (memcmp(value,"p256-sike503", len) == 0) {
    nid = NID_OQS_p256_SIKE_503;
  } else if (memcmp(value,"p256-sike751", len) == 0) {
    nid = NID_OQS_p256_SIKE_751;
  } else if (memcmp(value,"p256-newhope", len) == 0) {
    nid = NID_OQS_p256_Newhope;
  } else if (memcmp(value,"p256-ntru", len) == 0) {
    nid = NID_OQS_p256_NTRU;
  }

  return nid;
}
