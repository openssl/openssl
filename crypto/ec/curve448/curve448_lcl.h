#include "curve448utils.h"

int X448(uint8_t out_shared_key[56], const uint8_t private_key[56],
         const uint8_t peer_public_value[56]);

void X448_public_from_private(uint8_t out_public_value[56],
                              const uint8_t private_key[56]);
