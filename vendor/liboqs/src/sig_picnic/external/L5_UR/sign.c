#ifdef SUPERCOP
#include "crypto_sign.h"
#else
#include "api.h"
#endif

#define PICNIC_INSTANCE Picnic_L5_UR
#include "sign.c.template"
