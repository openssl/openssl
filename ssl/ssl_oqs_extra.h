/* Extra OQS content for the ssl integration */

/* Returns the OQS KEM NID from a given alg name, or 0 if there is no match */
static int OQS_nid_from_string(const char *value) {
  int nid = 0;
  int len = strlen(value);
  if (strncmp(value,"oqs_kem_default", len) == 0) {
    nid = NID_OQS_KEM_DEFAULT;
  } else if (strncmp(value,"sike503", len) == 0) {
    nid = NID_OQS_SIKE_503;
  } else if (strncmp(value,"sike751", len) == 0) {
    nid = NID_OQS_SIKE_751;
#if !defined(OQS_NIST_BRANCH)
  } else if (strncmp(value,"sidh503", len) == 0) {
    nid = NID_OQS_SIDH_503;
  } else if (strncmp(value,"sidh751", len) == 0) {
    nid = NID_OQS_SIDH_751;
#endif
  } else if (strncmp(value,"frodo640aes", len) == 0) {
    nid = NID_OQS_Frodo_640_AES;
  } else if (strncmp(value,"frodo640cshake", len) == 0) {
    nid = NID_OQS_Frodo_640_cshake;
  } else if (strncmp(value,"frodo976aes", len) == 0) {
    nid = NID_OQS_Frodo_976_AES;
  } else if (strncmp(value,"frodo976cshake", len) == 0) {
    nid = NID_OQS_Frodo_976_cshake;
  } else if (strncmp(value,"bike1l1", len) == 0) {
    nid = NID_OQS_BIKE1_L1;
  } else if (strncmp(value,"bike1l3", len) == 0) {
    nid = NID_OQS_BIKE1_L3;
  } else if (strncmp(value,"bike1l5", len) == 0) {
    nid = NID_OQS_BIKE1_L5;
  } else if (strncmp(value,"bike2l1", len) == 0) {
    nid = NID_OQS_BIKE2_L1;
  } else if (strncmp(value,"bike2l3", len) == 0) {
    nid = NID_OQS_BIKE2_L3;
  } else if (strncmp(value,"bike2l5", len) == 0) {
    nid = NID_OQS_BIKE2_L5;
  } else if (strncmp(value,"bike3l1", len) == 0) {
    nid = NID_OQS_BIKE3_L1;
  } else if (strncmp(value,"bike3l3", len) == 0) {
    nid = NID_OQS_BIKE3_L3;
  } else if (strncmp(value,"bike3l5", len) == 0) {
    nid = NID_OQS_BIKE3_L5;
  } else if (strncmp(value,"newhope512cca", len) == 0) {
    nid = NID_OQS_NEWHOPE_512_CCA;
  } else if (strncmp(value,"newhope1024cca", len) == 0) {
    nid = NID_OQS_NEWHOPE_1024_CCA;
#if defined(OQS_NIST_BRANCH)
    /* some schemes are disabled because their keys/ciphertext are too big for TLS */
  } else if (strncmp(value,"kyber512", len) == 0) {
    nid = NID_OQS_kyber512;
  } else if (strncmp(value,"kyber768", len) == 0) {
    nid = NID_OQS_kyber768;
  } else if (strncmp(value,"kyber1024", len) == 0) {
    nid = NID_OQS_kyber1024;
  } else if (strncmp(value,"ledakem_C1_N02", len) == 0) {
    nid = NID_OQS_ledakem_C1_N02;
  } else if (strncmp(value,"ledakem_C1_N03", len) == 0) {
    nid = NID_OQS_ledakem_C1_N03;
  } else if (strncmp(value,"ledakem_C1_N04", len) == 0) {
    nid = NID_OQS_ledakem_C1_N04;
  } else if (strncmp(value,"ledakem_C3_N02", len) == 0) {
    nid = NID_OQS_ledakem_C3_N02;
  } else if (strncmp(value,"ledakem_C3_N03", len) == 0) {
    nid = NID_OQS_ledakem_C3_N03;
  } else if (strncmp(value,"ledakem_C3_N04", len) == 0) {
    nid = NID_OQS_ledakem_C3_N04;
  } else if (strncmp(value,"ledakem_C5_N02", len) == 0) {
    nid = NID_OQS_ledakem_C5_N02;
    /*
  } else if (strncmp(value,"ledakem_C5_N03", len) == 0) {
    nid = NID_OQS_ledakem_C5_N03;
  } else if (strncmp(value,"ledakem_C5_N04", len) == 0) {
    nid = NID_OQS_ledakem_C5_N04;
    */
  } else if (strncmp(value,"saber_light_saber", len) == 0) {
    nid = NID_OQS_saber_light_saber;
  } else if (strncmp(value,"saber_saber", len) == 0) {
    nid = NID_OQS_saber_saber;
  } else if (strncmp(value,"saber_fire_saber", len) == 0) {
    nid = NID_OQS_saber_fire_saber;
#endif
  /* ADD_MORE_OQS_KEM_HERE */
  /* hybrid algs */
  } else if (strncmp(value,"p256-oqs_kem_default", len) == 0) {
    nid = NID_OQS_p256_KEM_DEFAULT;
  } else if (strncmp(value,"p256-sike503", len) == 0) {
    nid = NID_OQS_p256_SIKE_503;
#if !defined(OQS_NIST_BRANCH)
  } else if (strncmp(value,"p256-sidh503", len) == 0) {
    nid = NID_OQS_p256_SIDH_503;
#endif
  } else if (strncmp(value,"p256-frodo640aes", len) == 0) {
    nid = NID_OQS_p256_Frodo_640_AES;
  } else if (strncmp(value,"p256-frodo640cshake", len) == 0) {
    nid = NID_OQS_p256_Frodo_640_cshake;
  } else if (strncmp(value,"p256-bike1l1", len) == 0) {
    nid = NID_OQS_p256_BIKE1_L1;
  } else if (strncmp(value,"p256-bike2l1", len) == 0) {
    nid = NID_OQS_p256_BIKE2_L1;
  } else if (strncmp(value,"p256-bike3l1", len) == 0) {
    nid = NID_OQS_p256_BIKE3_L1;
  } else if (strncmp(value,"p256-newhope512cca", len) == 0) {
    nid = NID_OQS_p256_NEWHOPE_512_CCA;
#if defined(OQS_NIST_BRANCH)
  } else if (strncmp(value,"p256-kyber512", len) == 0) {
    nid = NID_OQS_p256_kyber512;
  } else if (strncmp(value,"p256-ledakem_C1_N02", len) == 0) {
    nid = NID_OQS_p256_ledakem_C1_N02;
  } else if (strncmp(value,"p256-ledakem_C1_N03", len) == 0) {
    nid = NID_OQS_p256_ledakem_C1_N03;
  } else if (strncmp(value,"p256-ledakem_C1_N04", len) == 0) {
    nid = NID_OQS_p256_ledakem_C1_N04;
    /*
  } else if (strncmp(value,"p256-saber_light_saber", len) == 0) {
    nid = NID_OQS_p256_saber_light_saber;
    */
#endif
  }
  /* ADD_MORE_OQS_KEM_HERE (L1 schemes) */
  return nid;
}
