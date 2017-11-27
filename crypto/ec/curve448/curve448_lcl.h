#include "curve448utils.h"

int X448(uint8_t out_shared_key[56], const uint8_t private_key[56],
         const uint8_t peer_public_value[56]);

void X448_public_from_private(uint8_t out_public_value[56],
                              const uint8_t private_key[56]);

int ED448_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
               const uint8_t public_key[56], const uint8_t private_key[56],
               const uint8_t *context, size_t context_len);

int ED448_verify(const uint8_t *message, size_t message_len,
                 const uint8_t signature[112], const uint8_t public_key[56],
                 const uint8_t *context, size_t context_len);

int ED448ph_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
                 const uint8_t public_key[56], const uint8_t private_key[56],
                 const uint8_t *context, size_t context_len);


int ED448ph_verify(const uint8_t *message, size_t message_len,
                   const uint8_t signature[112], const uint8_t public_key[56],
                   const uint8_t *context, size_t context_len);

void ED448_public_from_private(uint8_t out_public_key[56],
                               const uint8_t private_key[56]);
