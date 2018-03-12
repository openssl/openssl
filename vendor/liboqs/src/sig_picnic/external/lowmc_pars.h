/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef LOWMC_PARS_H
#define LOWMC_PARS_H

#include <stddef.h>

#include "mzd_additional.h"

typedef mzd_local_t lowmc_key_t;

typedef struct {
  mzd_local_t* x0;
  mzd_local_t* x1;
  mzd_local_t* x2;
  mzd_local_t* mask;
  uint64_t x0i;
  uint64_t x1i;
  uint64_t x2i;
  uint64_t maski;
} mask_t;

typedef struct {
#if !defined(REDUCED_LINEAR_LAYER)
  const mzd_local_t* k_matrix;
#endif
  const mzd_local_t* l_matrix;
  const mzd_local_t* constant;

#if !defined(REDUCED_LINEAR_LAYER)
  mzd_local_t* k_lookup;
#endif
  mzd_local_t* l_lookup;
} lowmc_round_t;

/**
 * Represents the LowMC parameters as in https://bitbucket.org/malb/lowmc-helib/src,
 * with the difference that key in a separate struct
 */
typedef struct {
  unsigned int m;
  unsigned int n;
  unsigned int r;
  unsigned int k;

  mask_t mask;

  const mzd_local_t* k0_matrix; // K_0 or K_0 + precomputed if reduced_linear_layer is set
  mzd_local_t* k0_lookup;
  lowmc_round_t* rounds;

  const mzd_local_t* precomputed_non_linear_part_matrix;
  mzd_local_t* precomputed_non_linear_part_lookup;

  bool needs_free;
} lowmc_t;

/**
 * Generates a new LowMC instance (also including a key)
 *
 * \param m the number of sboxes
 * \param n the blocksize
 * \param r the number of rounds
 * \param k the keysize
 *
 * \return parameters defining a LowMC instance (including a key)
 */
bool oqs_sig_picnic_lowmc_init(lowmc_t* lowmc, unsigned int m, unsigned int n, unsigned int r, unsigned int k);

/**
 * Clears the allocated LowMC parameters
 *
 * \param lowmc the LowMC parameters to be cleared
 */
void oqs_sig_picnic_lowmc_clear(lowmc_t* lowmc);

bool oqs_sig_picnic_lowmc_read_file(lowmc_t* lowmc, unsigned int m, unsigned int n, unsigned int r,
                     unsigned int k);

#endif
