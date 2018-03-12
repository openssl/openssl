#include <stdint.h>
#include "params.h"

uint8_t mask1[32] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
uint32_t vrshiftsx8[8] = {0,1,2,3,4,5,6,7};
uint32_t maskffff[8] = {0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff};
uint16_t maskff[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};

double q8[4] = {PARAM_Q, PARAM_Q, PARAM_Q, PARAM_Q};
uint32_t q8x[8] = {PARAM_Q, PARAM_Q, PARAM_Q, PARAM_Q, PARAM_Q, PARAM_Q, PARAM_Q, PARAM_Q};
uint32_t v1x8[8] = {1,1,1,1,1,1,1,1};
uint32_t v3x8[8] = {3,3,3,3,3,3,3,3};
uint32_t v2730x8[8] = {2730,2730,2730,2730,2730,2730,2730,2730};


double qinv16[4] = {.00008137358613394092,.00008137358613394092,.00008137358613394092,.00008137358613394092};
double neg2[4] = {1.,-1.,1.,-1.};
double neg4[4] = {1.,1.,-1.,-1.};

