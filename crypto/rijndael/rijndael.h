#include "openssl/rd_fst.h"

typedef struct
    {
    u32 rd_key[4 *(MAXNR + 1)];
    int rounds;
    } RIJNDAEL_KEY;
