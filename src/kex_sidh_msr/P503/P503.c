/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P503
*********************************************************************************************/

#include "P503_api.h"
#include "P503_internal.h"

// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located at the leftmost position (i.e., little endian format).
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {a, b}, with a in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position.
// Internally, the number of digits used to represent all these elements is obtained by approximating the number of bits to the immediately greater multiple of 32.
// For example, a 503-bit field element is represented with Ceil(503 / 64) = 8 64-bit digits or Ceil(503 / 32) = 16 32-bit digits.

//
// Curve isogeny system "SIDHp503". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p503^2), where A=0, B=1, C=1 and p503 = 2^250*3^159-1
//

const uint64_t p503[NWORDS64_FIELD] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xABFFFFFFFFFFFFFF,
                                       0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E};
const uint64_t p503p1[NWORDS64_FIELD] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xAC00000000000000,
                                         0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E};
const uint64_t p503x2[NWORDS64_FIELD] = {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x57FFFFFFFFFFFFFF,
                                         0x2610B7B44423CF41, 0x3737ED90F6FCFB5E, 0xC08B8D7BB4EF49A0, 0x0080CDEA83023C3C};
// Order of Alice's subgroup
static const uint64_t Alice_order[NWORDS64_ORDER] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0400000000000000};
// Order of Bob's subgroup
static const uint64_t Bob_order[NWORDS64_ORDER] = {0xC216F6888479E82B, 0xE6FDB21EDF9F6BC4, 0x1171AF769DE93406, 0x1019BD5060478798};
// Alice's generator values {XPA0 + XPA1*i, XQA0, XRA0 + XRA1*i} in GF(p503^2), expressed in Montgomery representation
static const uint64_t A_gen[5 * NWORDS64_FIELD] = {0xE7EF4AA786D855AF, 0xED5758F03EB34D3B, 0x09AE172535A86AA9, 0x237B9CC07D622723,
                                                   0xE3A284CBA4E7932D, 0x27481D9176C5E63F, 0x6A323FF55C6E71BF, 0x002ECC31A6FB8773, // XPA0
                                                   0x64D02E4E90A620B8, 0xDAB8128537D4B9F1, 0x4BADF77B8A228F98, 0x0F5DBDF9D1FB7D1B,
                                                   0xBEC4DB288E1A0DCC, 0xE76A8665E80675DB, 0x6D6F252E12929463, 0x003188BD1463FACC, // XPA1
                                                   0xB79D41025DE85D56, 0x0B867DA9DF169686, 0x740E5368021C827D, 0x20615D72157BF25C,
                                                   0xFF1590013C9B9F5B, 0xC884DCADE8C16CEA, 0xEBD05E53BF724E01, 0x0032FEF8FDA5748C, // XQA0
                                                   0x12E2E849AA0A8006, 0x41CF47008635A1E8, 0x9CD720A70798AED7, 0x42A820B42FCF04CF,
                                                   0x7BF9BAD32AAE88B1, 0xF619127A54090BBE, 0x1CB10D8F56408EAA, 0x001D6B54C3C0EDEB, // XRA0
                                                   0x34DB54931CBAAC36, 0x420A18CB8DD5F0C4, 0x32008C1A48C0F44D, 0x3B3BA772B1CFD44D,
                                                   0xA74B058FDAF13515, 0x095FC9CA7EEC17B4, 0x448E829D28F120F8, 0x00261EC3ED16A489}; // XRA1
// Bob's generator values {XPB0 + XPB1*i, XQB0, XRB0 + XRB1*i} in GF(p503^2), expressed in Montgomery representation
static const uint64_t B_gen[5 * NWORDS64_FIELD] = {0x7EDE37F4FA0BC727, 0xF7F8EC5C8598941C, 0xD15519B516B5F5C8, 0xF6D5AC9B87A36282,
                                                   0x7B19F105B30E952E, 0x13BD8B2025B4EBEE, 0x7B96D27F4EC579A2, 0x00140850CAB7E5DE, // XPB0
                                                   0x7764909DAE7B7B2D, 0x578ABB16284911AB, 0x76E2BFD146A6BF4D, 0x4824044B23AA02F0,
                                                   0x1105048912A321F3, 0xB8A2E482CF0F10C1, 0x42FF7D0BE2152085, 0x0018E599C5223352, // XPB1
                                                   0x4256C520FB388820, 0x744FD7C3BAAF0A13, 0x4B6A2DDDB12CBCB8, 0xE46826E27F427DF8,
                                                   0xFE4A663CD505A61B, 0xD6B3A1BAF025C695, 0x7C3BB62B8FCC00BD, 0x003AFDDE4A35746C, // XQB0
                                                   0x75601CD1E6C0DFCB, 0x1A9007239B58F93E, 0xC1F1BE80C62107AC, 0x7F513B898F29FF08,
                                                   0xEA0BEDFF43E1F7B2, 0x2C6D94018CBAE6D0, 0x3A430D31BCD84672, 0x000D26892ECCFE83, // XRB0
                                                   0x1119D62AEA3007A1, 0xE3702AA4E04BAE1B, 0x9AB96F7D59F990E7, 0xF58440E8B43319C0,
                                                   0xAF8134BEE1489775, 0xE7F7774E905192AA, 0xF54AE09308E98039, 0x001EF7A041A86112}; // XRB1
// Montgomery constant Montgomery_R2 = (2^512)^2 mod p503
static const uint64_t Montgomery_R2[NWORDS64_FIELD] = {0x5289A0CF641D011F, 0x9B88257189FED2B9, 0xA3B365D58DC8F17A, 0x5BC57AB6EFF168EC,
                                                       0x9E51998BD84D4423, 0xBF8999CBAC3B5695, 0x46E9127BCE14CDB6, 0x003F6CFCE8B81771};
// Value one in Montgomery representation
static const uint64_t Montgomery_one[NWORDS64_FIELD] = {0x00000000000003F9, 0x0000000000000000, 0x0000000000000000, 0xB400000000000000,
                                                        0x63CB1A6EA6DED2B4, 0x51689D8D667EB37D, 0x8ACD77C71AB24142, 0x0026FBAEC60F5953};
// Value (2^256)^2 mod 3^159
static const uint64_t Montgomery_Rprime[NWORDS64_ORDER] = {0x0C2615CA3C5BAA99, 0x5A4FF3072AB6AA6A, 0xA6AFD4B039AD6AA2, 0x010DA06A26DD05CB};
// Value -(3^159)^-1 mod 2^256
static const uint64_t Montgomery_rprime[NWORDS64_ORDER] = {0x49C8A87190C0697D, 0x2EB7968EA0F0A558, 0x944257B696777FA2, 0xBAA4DDCD6139D2B3};
// Value order_Bob/3 mod p503
static const uint64_t Border_div3[NWORDS_ORDER] = {0xEB5CFCD82C28A2B9, 0x4CFF3B5F9FDFCE96, 0xB07B3A7CDF4DBC02, 0x055DE9C5756D2D32};

// Fixed parameters for isogeny tree computation
static const unsigned int strat_Alice[MAX_Alice - 1] = {
    61, 32, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1,
    4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1,
    1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 29, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1,
    1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 13, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2,
    1, 1, 2, 1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1};

static const unsigned int strat_Bob[MAX_Bob - 1] = {
    71, 38, 21, 13, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 5, 4, 2, 1, 1, 2, 1,
    1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 17, 9,
    5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1,
    1, 4, 2, 1, 1, 2, 1, 1, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1,
    2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1, 2,
    1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1};

// Setting up macro defines and including GF(p), GF(p^2), curve, isogeny and kex functions
#define fpcopy fpcopy503
#define fpzero fpzero503
#define fpadd fpadd503
#define fpsub fpsub503
#define fpneg fpneg503
#define fpdiv2 fpdiv2_503
#define fpcorrection fpcorrection503
#define fpmul_mont fpmul503_mont
#define fpsqr_mont fpsqr503_mont
#define fpinv_mont fpinv503_mont
#define fpinv_chain_mont fpinv503_chain_mont
#define fpinv_mont_bingcd fpinv503_mont_bingcd
#define fp2copy fp2copy503
#define fp2zero fp2zero503
#define fp2add fp2add503
#define fp2sub fp2sub503
#define fp2neg fp2neg503
#define fp2div2 fp2div2_503
#define fp2correction fp2correction503
#define fp2mul_mont fp2mul503_mont
#define fp2sqr_mont fp2sqr503_mont
#define fp2inv_mont fp2inv503_mont
#define fp2inv_mont_bingcd fp2inv503_mont_bingcd
#define fpequal_non_constant_time fpequal503_non_constant_time
#define mp_add_asm mp_add503_asm
#define mp_addx2_asm mp_add503x2_asm
#define mp_subx2_asm mp_sub503x2_asm
#define crypto_kem_keypair crypto_kem_keypair_SIKEp503
#define crypto_kem_enc crypto_kem_enc_SIKEp503
#define crypto_kem_dec crypto_kem_dec_SIKEp503
#define random_mod_order_A random_mod_order_A_SIDHp503
#define random_mod_order_B random_mod_order_B_SIDHp503
#define EphemeralKeyGeneration_A EphemeralKeyGeneration_A_SIDHp503
#define EphemeralKeyGeneration_B EphemeralKeyGeneration_B_SIDHp503
#define EphemeralSecretAgreement_A EphemeralSecretAgreement_A_SIDHp503
#define EphemeralSecretAgreement_B EphemeralSecretAgreement_B_SIDHp503

#if defined(X86_64)
#include "AMD64/fp_x64.c"
#include "AMD64/fp_x64_asm.S"
#elif defined(ARM64)
#include "ARM64/fp_arm64.c"
#else
#include "generic/fp_generic.c"
#endif
#include "../fpx.c"
#include "../ec_isogeny.c"
#include "../sidh.c"
#include "../sike.c"
