#include "openssl/rd_fst.h"

#define RIJNDAEL_MAX_IV		16

typedef struct
    {
    word8 keySched[RIJNDAEL_MAXROUNDS+1][4][4];
    int rounds;
    word8 iv[RIJNDAEL_MAX_IV];
    int enc;
    } RIJNDAEL_KEY;
