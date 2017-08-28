#ifndef SHARED_KEY_H
#define SHARED_KEY_H

#include "sidh_private_key.h"
#include "sidh_public_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generates the shared-key.
 * @param shared_key the generated shared-key
 * @param public_key other's public-key
 * @param private_key own private-key
 * @param params own parameters
 */
void oqs_sidh_iqc_ref_shared_key_generate(fp2_element_t shared_key,
                                          const public_key_t public_key,
                                          const private_key_t private_key,
                                          const public_params_t params);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_KEY_H */
