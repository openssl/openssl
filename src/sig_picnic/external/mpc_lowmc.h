/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include <stdbool.h>

#include "lowmc_pars.h"
#include "mpc.h"

typedef mzd_local_t* mpc_lowmc_key_t;

typedef struct { mzd_local_t* s[SC_PROOF]; } in_out_shares_t;

typedef void (*lowmc_implementation_f)(lowmc_t const*, mpc_lowmc_key_t*, mzd_local_t const*,
                                       view_t*, in_out_shares_t*, rvec_t*);
typedef void (*lowmc_verify_implementation_f)(lowmc_t const*, mzd_local_t const*, view_t*,
                                              in_out_shares_t*, rvec_t*, unsigned int);

lowmc_implementation_f oqs_sig_picnic_get_lowmc_implementation(const lowmc_t* lowmc);
lowmc_verify_implementation_f oqs_sig_picnic_get_lowmc_verify_implementation(const lowmc_t* lowmc);

#endif
