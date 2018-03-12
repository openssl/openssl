/*! @file example.c
 *  @brief This is an example program to demonstrate how to use the
 *  Picnic signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "picnic.h"
#include <inttypes.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#define MSG_LEN 500

int picnicExample(picnic_params_t parameters) {
  picnic_publickey_t pk;
  picnic_privatekey_t sk;

  printf("Picnic example with parameter set: %s\n", picnic_get_param_name(parameters));

  fprintf(stdout, "Generating key... ");
  fflush(stdout);
  int ret = picnic_keygen(parameters, &pk, &sk);

  if (ret != 0) {
    printf("picnic_keygen failed\n");
    exit(-1);
  }
  printf(" success\n");

  uint8_t message[MSG_LEN];
  memset(message, 0x01, sizeof(message));
  uint8_t* signature = NULL;

  size_t signature_len = picnic_signature_size(parameters);
  signature            = (uint8_t*)malloc(signature_len);
  if (signature == NULL) {
    printf("failed to allocate signature\n");
    exit(-1);
  }
  fprintf(stdout, "Max signature length %" PRIuPTR " bytes\n", signature_len);

  fprintf(stdout, "Signing a %d byte message... ", MSG_LEN);
  fflush(stdout);

  ret = picnic_sign(&sk, message, sizeof(message), signature, &signature_len);
  if (ret != 0) {
    printf("picnic_sign failed\n");
    exit(-1);
  }
  printf(" success, signature is %d bytes\n", (int)signature_len);

  /* signature_len has the exact number of bytes used */
  if (signature_len < picnic_signature_size(parameters)) {
    uint8_t* newsig = realloc(signature, signature_len);
    if (newsig == NULL) {
      printf("failed to re-size signature\n");
      /* Not an error, we can continue with signature */
    } else {
      signature = newsig;
    }
  }

  fprintf(stdout, "Verifying signature... ");
  fflush(stdout);

  ret = picnic_verify(&pk, message, sizeof(message), signature, signature_len);
  if (ret != 0) {
    printf("picnic_verify failed\n");
    exit(-1);
  }
  printf(" success\n");

  printf("Testing public key serialization... ");
  uint8_t pk_buf[PICNIC_MAX_PUBLICKEY_SIZE + 1];
  ret = picnic_write_public_key(&pk, pk_buf, sizeof(pk_buf));
  if (ret <= 0) {
    printf("Failed to serialize public key\n");
    exit(-1);
  }

  memset(&pk, 0x00, sizeof(picnic_publickey_t));

  ret = picnic_read_public_key(&pk, pk_buf, sizeof(pk_buf));
  if (ret != 0) {
    printf("Failed to read public key\n");
    exit(-1);
  }

  ret = picnic_verify(&pk, message, sizeof(message), signature, signature_len);
  if (ret != 0) {
    printf("picnic_verify failed after de-serializing public key\n");
    exit(-1);
  }
  printf(" success\n");

  printf("Testing private key serialization... ");
  uint8_t sk_buf[PICNIC_MAX_PRIVATEKEY_SIZE + 1];
  ret = picnic_write_private_key(&sk, sk_buf, sizeof(sk_buf));
  if (ret <= 0) {
    printf("Failed to write private key\n");
    exit(-1);
  }

  memset(&sk, 0x00, sizeof(picnic_privatekey_t));
  ret = picnic_read_private_key(&sk, sk_buf, sizeof(sk_buf));
  if (ret != 0) {
    printf("Failed to read private key\n");
    exit(-1);
  }

  ret = picnic_validate_keypair(&sk, &pk);
  if (ret != 0) {
    printf("Keypair invalid after deserializing private key\n");
    exit(-1);
  }
  printf(" success\n\n");

  free(signature);

  return 0;
}

int main(void) {
  for (picnic_params_t params = 1; params < PARAMETER_SET_MAX_INDEX; params++) {
    picnicExample(params);
  }
}
