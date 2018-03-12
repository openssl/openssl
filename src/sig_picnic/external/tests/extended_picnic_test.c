#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "picnic.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int picnic_test_with_read_write(picnic_params_t parameters) {
  picnic_publickey_t pk;
  picnic_privatekey_t sk;

  int ret = picnic_keygen(parameters, &pk, &sk);
  if (ret) {
    return ret;
  }

  uint8_t message[256];
  memset(message, 0x12, sizeof(message));

  size_t signature_len = picnic_signature_size(parameters);
  uint8_t* signature   = malloc(signature_len);
  if (!signature) {
    return -1;
  }

  ret = picnic_sign(&sk, message, sizeof(message), signature, &signature_len);
  if (ret) {
    return ret;
  }

  ret = picnic_verify(&pk, message, sizeof(message), signature, signature_len);
  if (ret) {
    return ret;
  }

  uint8_t pk_buf[PICNIC_MAX_PUBLICKEY_SIZE + 1];
  ret = picnic_write_public_key(&pk, pk_buf, sizeof(pk_buf));
  if (ret <= 0) {
    return ret;
  }

  memset(&pk, 0x00, sizeof(picnic_publickey_t));

  ret = picnic_read_public_key(&pk, pk_buf, sizeof(pk_buf));
  if (ret) {
    return ret;
  }

  ret = picnic_verify(&pk, message, sizeof(message), signature, signature_len);
  if (ret) {
    return ret;
  }

  uint8_t sk_buf[PICNIC_MAX_PRIVATEKEY_SIZE + 1];
  ret = picnic_write_private_key(&sk, sk_buf, sizeof(sk_buf));
  if (ret <= 0) {
    return ret;
  }

  memset(&sk, 0x00, sizeof(picnic_privatekey_t));
  ret = picnic_read_private_key(&sk, sk_buf, sizeof(sk_buf));
  if (ret) {
    return ret;
  }

  ret = picnic_validate_keypair(&sk, &pk);
  if (ret) {
    return ret;
  }

  free(signature);
  return 0;
}

int main(void) {
  int ret = 0;
  for (picnic_params_t params = 1; params < PARAMETER_SET_MAX_INDEX; params++) {
    if (picnic_test_with_read_write(params)) {
      ret = -1;
    }
  }
  return ret;
}
