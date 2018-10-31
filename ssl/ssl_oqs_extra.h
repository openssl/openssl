/* Extra OQS content for the ssl integration */

/* Returns the OQS KEM NID from a given alg name, or 0 if there is no match */
static int OQS_nid_from_string(const char *value) {
  int nid = 0;
  int len = strlen(value);
  if (memcmp(value,"sike503", len) == 0) {
    nid = NID_OQS_SIKE_503;
  } else if (memcmp(value,"sike751", len) == 0) {
    nid = NID_OQS_SIKE_751;
#if !defined(OQS_NIST_BRANCH)
  } else if (memcmp(value,"sidh503", len) == 0) {
    nid = NID_OQS_SIDH_503;
  } else if (memcmp(value,"sidh751", len) == 0) {
    nid = NID_OQS_SIDH_751;
#endif
  } else if (memcmp(value,"frodo640aes", len) == 0) {
    nid = NID_OQS_Frodo_640_AES;
  } else if (memcmp(value,"frodo640cshake", len) == 0) {
    nid = NID_OQS_Frodo_640_cshake;
  } else if (memcmp(value,"frodo976aes", len) == 0) {
    nid = NID_OQS_Frodo_976_AES;
  } else if (memcmp(value,"frodo976cshake", len) == 0) {
    nid = NID_OQS_Frodo_976_cshake;
  } else if (memcmp(value,"bike1l1", len) == 0) {
    nid = NID_OQS_BIKE1_L1;
  } else if (memcmp(value,"bike1l3", len) == 0) {
    nid = NID_OQS_BIKE1_L3;
  } else if (memcmp(value,"bike1l5", len) == 0) {
    nid = NID_OQS_BIKE1_L5;
  } else if (memcmp(value,"bike2l1", len) == 0) {
    nid = NID_OQS_BIKE2_L1;
  } else if (memcmp(value,"bike2l3", len) == 0) {
    nid = NID_OQS_BIKE2_L3;
  } else if (memcmp(value,"bike2l5", len) == 0) {
    nid = NID_OQS_BIKE2_L5;
  } else if (memcmp(value,"bike3l1", len) == 0) {
    nid = NID_OQS_BIKE3_L1;
  } else if (memcmp(value,"bike3l3", len) == 0) {
    nid = NID_OQS_BIKE3_L3;
  } else if (memcmp(value,"bike3l5", len) == 0) {
    nid = NID_OQS_BIKE3_L5;
  } else if (memcmp(value,"newhope512cca", len) == 0) {
    nid = NID_OQS_NEWHOPE_512_CCA;
  } else if (memcmp(value,"newhope1024cca", len) == 0) {
    nid = NID_OQS_NEWHOPE_1024_CCA;
  /* ADD_MORE_OQS_KEM_HERE */
  /* hybrid algs */
  } else if (memcmp(value,"p256-sike503", len) == 0) {
    nid = NID_OQS_p256_SIKE_503;
#if !defined(OQS_NIST_BRANCH)
  } else if (memcmp(value,"p256-sidh503", len) == 0) {
    nid = NID_OQS_p256_SIDH_503;
#endif
  } else if (memcmp(value,"p256-frodo640aes", len) == 0) {
    nid = NID_OQS_p256_Frodo_640_AES;
  } else if (memcmp(value,"p256-frodo640cshake", len) == 0) {
    nid = NID_OQS_p256_Frodo_640_cshake;
  } else if (memcmp(value,"p256-bike1l1", len) == 0) {
    nid = NID_OQS_p256_BIKE1_L1;
  } else if (memcmp(value,"p256-bike2l1", len) == 0) {
    nid = NID_OQS_p256_BIKE2_L1;
  } else if (memcmp(value,"p256-bike3l1", len) == 0) {
    nid = NID_OQS_p256_BIKE3_L1;
  } else if (memcmp(value,"p256-newhope512cca", len) == 0) {
    nid = NID_OQS_p256_NEWHOPE_512_CCA;
  }
  /* ADD_MORE_OQS_KEM_HERE (L1 schemes) */
  return nid;
}
