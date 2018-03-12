/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef LOWMC_H
#define LOWMC_H

#include "lowmc_pars.h"

/**
 * Implements LowMC encryption
 *
 * \param  lowmc the lowmc parameters
 * \param  p     the plaintext
 * \return       the ciphertext
 */
mzd_local_t* oqs_sig_picnic_lowmc_call(lowmc_t const* lowmc, lowmc_key_t const* lowmc_key, mzd_local_t const* p);

#endif
