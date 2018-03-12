/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "picnic.h"

#include <stdlib.h>
#include <string.h>

#include "io.h"
#include "lowmc.h"
#include "picnic_impl.h"
#include <oqs/rand.h>

const picnic_instance_t* picnic_instance_get(picnic_params_t param) {
  return oqs_sig_picnic_get_instance(param);
}

size_t PICNIC_CALLING_CONVENTION picnic_signature_size(picnic_params_t param) {
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return 0;
  }

  return instance->max_signature_size;
}

size_t PICNIC_CALLING_CONVENTION picnic_get_private_key_size(picnic_params_t param) {
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return 0;
  }

  return 1 + instance->input_size + instance->output_size;
}

size_t PICNIC_CALLING_CONVENTION picnic_get_public_key_size(picnic_params_t param) {
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return 0;
  }

  return 1 + (instance->output_size << 1);
}

int PICNIC_CALLING_CONVENTION picnic_keygen(picnic_params_t param, picnic_publickey_t* pk,
                                            picnic_privatekey_t* sk, OQS_RAND* rand) {

  if (!pk || !sk) {
    return -1;
  }

  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t input_size  = instance->input_size;
  const size_t output_size = instance->output_size;

  uint8_t* sk_sk = &sk->data[1];
  uint8_t* pk_pt = &sk->data[1 + input_size];
  uint8_t* sk_c  = &sk->data[1 + input_size + output_size];

  // generate private key
  sk->data[0] = param;
  // random secret key
  OQS_RAND_n(rand, sk_sk, input_size);
  // random plain text
  OQS_RAND_n(rand, pk_pt, output_size);
  // encrypt plaintext under secret key
  if (picnic_sk_to_pk(sk, pk)) {
    return -1;
  }
  // copy ciphertext to secret key
  memcpy(sk_c, &pk->data[1 + output_size], output_size);
  return 0;
}

int PICNIC_CALLING_CONVENTION picnic_sk_to_pk(const picnic_privatekey_t* sk,
                                              picnic_publickey_t* pk) {
  if (!sk || !pk) {
    return -1;
  }

  const picnic_params_t param       = sk->data[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t input_size  = instance->input_size;
  const size_t output_size = instance->output_size;

  const uint8_t* sk_sk = &sk->data[1];
  uint8_t* pk_c        = &pk->data[1 + output_size];
  uint8_t* pk_pt       = &pk->data[1];
  const uint8_t* sk_pt = &sk->data[1 + input_size];

  mzd_local_t* plaintext = oqs_sig_picnic_mzd_local_init_ex(1, instance->lowmc.n, false);
  mzd_local_t* privkey   = oqs_sig_picnic_mzd_local_init_ex(1, instance->lowmc.k, false);

  oqs_sig_picnic_mzd_from_char_array(plaintext, sk_pt, output_size);
  oqs_sig_picnic_mzd_from_char_array(privkey, sk_sk, input_size);

  // compute public key
  mzd_local_t* ciphertext = oqs_sig_picnic_lowmc_call(&instance->lowmc, privkey, plaintext);

  pk->data[0] = param;
  memcpy(pk_pt, sk_pt, output_size);
  oqs_sig_picnic_mzd_to_char_array(pk_c, ciphertext, output_size);

  oqs_sig_picnic_mzd_local_free(ciphertext);
  oqs_sig_picnic_mzd_local_free(privkey);
  oqs_sig_picnic_mzd_local_free(plaintext);

  return 0;
}

int PICNIC_CALLING_CONVENTION picnic_validate_keypair(const picnic_privatekey_t* sk,
                                                      const picnic_publickey_t* pk) {
  if (!sk || !pk) {
    return -1;
  }

  const picnic_params_t param       = sk->data[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t input_size  = instance->input_size;
  const size_t output_size = instance->output_size;
  const uint8_t* sk_sk     = &sk->data[1];
  const uint8_t* sk_pt     = &sk->data[1 + input_size];
  const uint8_t* sk_c      = &sk->data[1 + input_size + output_size];
  const uint8_t* pk_pt     = &pk->data[1];
  const uint8_t* pk_c      = &pk->data[1 + output_size];

  // check param and plaintext
  if (param != pk->data[0] || memcmp(sk_pt, pk_pt, output_size) != 0 ||
      memcmp(sk_c, pk_c, output_size) != 0) {
    return -1;
  }

  mzd_local_t* plaintext = oqs_sig_picnic_mzd_local_init_ex(1, instance->lowmc.n, false);
  mzd_local_t* privkey   = oqs_sig_picnic_mzd_local_init_ex(1, instance->lowmc.k, false);

  oqs_sig_picnic_mzd_from_char_array(plaintext, sk_pt, instance->output_size);
  oqs_sig_picnic_mzd_from_char_array(privkey, sk_sk, instance->input_size);

  // compute public key
  mzd_local_t* ciphertext = oqs_sig_picnic_lowmc_call(&instance->lowmc, privkey, plaintext);

  uint8_t buffer[MAX_LOWMC_BLOCK_SIZE];
  oqs_sig_picnic_mzd_to_char_array(buffer, ciphertext, output_size);

  oqs_sig_picnic_mzd_local_free(ciphertext);
  oqs_sig_picnic_mzd_local_free(privkey);
  oqs_sig_picnic_mzd_local_free(plaintext);

  return memcmp(buffer, pk_c, output_size);
}

int PICNIC_CALLING_CONVENTION picnic_sign(const picnic_privatekey_t* sk, const uint8_t* message,
                                          size_t message_len, uint8_t* signature,
                                          size_t* signature_len) {
  if (!sk || !signature || !signature_len) {
    return -1;
  }

  const picnic_params_t param       = sk->data[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t output_size = instance->output_size;
  const size_t input_size  = instance->input_size;

  const uint8_t* sk_sk = &sk->data[1];
  const uint8_t* sk_c  = &sk->data[1 + input_size + output_size];
  const uint8_t* sk_pt = &sk->data[1 + input_size];

  return oqs_sig_picnic_fis_sign(instance, sk_pt, sk_sk, sk_c, message, message_len, signature, signature_len)
             ? 0
             : -1;
}

int PICNIC_CALLING_CONVENTION picnic_verify(const picnic_publickey_t* pk, const uint8_t* message,
                                            size_t message_len, const uint8_t* signature,
                                            size_t signature_len) {
  if (!pk || !signature || !signature_len) {
    return -1;
  }

  const picnic_params_t param       = pk->data[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return false;
  }

  const size_t output_size = instance->output_size;

  const uint8_t* pk_c  = &pk->data[1 + output_size];
  const uint8_t* pk_pt = &pk->data[1];

  return oqs_sig_picnic_fis_verify(instance, pk_pt, pk_c, message, message_len, signature, signature_len) ? 0 : -1;
}

void picnic_visualize(FILE* out, const uint8_t* public_key, size_t public_key_size,
                      const uint8_t* msg, size_t msglen, const uint8_t* sig, size_t siglen) {
  if (!public_key || !public_key_size) {
    return;
  }

  const picnic_params_t param       = public_key[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return;
  }

  oqs_sig_picnic_visualize_signature(out, instance, msg, msglen, sig, siglen);
}

const char* PICNIC_CALLING_CONVENTION picnic_get_param_name(picnic_params_t parameters) {
  switch (parameters) {
  case Picnic_L1_FS:
    return "Picnic_L1_FS";
  case Picnic_L1_UR:
    return "Picnic_L1_UR";
  case Picnic_L3_FS:
    return "Picnic_L3_FS";
  case Picnic_L3_UR:
    return "Picnic_L3_UR";
  case Picnic_L5_FS:
    return "Picnic_L5_FS";
  case Picnic_L5_UR:
    return "Picnic_L5_UR";
  default:
    return "Unknown parameter set";
  }
}

int PICNIC_CALLING_CONVENTION picnic_write_public_key(const picnic_publickey_t* key, uint8_t* buf,
                                                      size_t buflen) {
  if (!key || !buf) {
    return -1;
  }

  const picnic_params_t param       = key->data[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t output_size    = instance->output_size;
  const size_t bytes_required = 1 + 2 * output_size;
  if (buflen < bytes_required) {
    return -1;
  }

  memcpy(buf, key->data, bytes_required);
  return (int)bytes_required;
}

int PICNIC_CALLING_CONVENTION picnic_read_public_key(picnic_publickey_t* key, const uint8_t* buf,
                                                     size_t buflen) {
  if (!key || !buf || buflen < 1) {
    return -1;
  }

  const picnic_params_t param       = buf[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t output_size    = instance->output_size;
  const size_t bytes_required = 1 + 2 * output_size;
  if (buflen < bytes_required) {
    return -1;
  }

  memcpy(key->data, buf, bytes_required);
  return 0;
}

int PICNIC_CALLING_CONVENTION picnic_write_private_key(const picnic_privatekey_t* key, uint8_t* buf,
                                                       size_t buflen) {
  if (!key || !buf) {
    return -1;
  }

  const picnic_params_t param       = key->data[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t input_size     = instance->input_size;
  const size_t output_size    = instance->output_size;
  const size_t bytes_required = 1 + input_size + 2 * output_size;
  if (buflen < bytes_required) {
    return -1;
  }

  memcpy(buf, &key->data, bytes_required);
  return (int)bytes_required;
}

int PICNIC_CALLING_CONVENTION picnic_read_private_key(picnic_privatekey_t* key, const uint8_t* buf,
                                                      size_t buflen) {
  if (!key || !buf || buflen < 1) {
    return -1;
  }

  const picnic_params_t param       = buf[0];
  const picnic_instance_t* instance = picnic_instance_get(param);
  if (!instance) {
    return -1;
  }

  const size_t input_size     = instance->input_size;
  const size_t output_size    = instance->output_size;
  const size_t bytes_required = 1 + input_size + 2 * output_size;
  if (buflen < bytes_required) {
    return -1;
  }

  memcpy(key->data, buf, bytes_required);
  return 0;
}
