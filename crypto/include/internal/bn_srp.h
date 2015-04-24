
#ifndef OPENSSL_NO_SRP

extern const BIGNUM bn_group_1024;

extern const BIGNUM bn_group_1536;

extern const BIGNUM bn_group_2048;

extern const BIGNUM bn_group_3072;

extern const BIGNUM bn_group_4096;

extern const BIGNUM bn_group_6144;

extern const BIGNUM bn_group_8192;

extern const BIGNUM bn_generator_19;

extern const BIGNUM bn_generator_5;

extern const BIGNUM bn_generator_2;

static SRP_gN knowngN[] = {
    {"8192", (BIGNUM *)&bn_generator_19, (BIGNUM *)&bn_group_8192},
    {"6144", (BIGNUM *)&bn_generator_5, (BIGNUM *)&bn_group_6144},
    {"4096", (BIGNUM *)&bn_generator_5, (BIGNUM *)&bn_group_4096},
    {"3072", (BIGNUM *)&bn_generator_5, (BIGNUM *)&bn_group_3072},
    {"2048", (BIGNUM *)&bn_generator_2, (BIGNUM *)&bn_group_2048},
    {"1536", (BIGNUM *)&bn_generator_2, (BIGNUM *)&bn_group_1536},
    {"1024", (BIGNUM *)&bn_generator_2, (BIGNUM *)&bn_group_1024},
};

# define KNOWN_GN_NUMBER sizeof(knowngN) / sizeof(SRP_gN)

#endif
