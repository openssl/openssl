/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P751
*********************************************************************************************/

#include "P751_api.h"
#include "P751_internal.h"

// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located at the leftmost position (i.e., little endian format).
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {a, b}, with a in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position.
// Internally, the number of digits used to represent all these elements is obtained by approximating the number of bits to the immediately greater multiple of 32.
// For example, a 751-bit field element is represented with Ceil(751 / 64) = 12 64-bit digits or Ceil(751 / 32) = 24 32-bit digits.

//
// Curve isogeny system "SIDHp751". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p751^2), where A=0, B=1, C=1 and p751 = 2^372*3^239-1
//

const uint64_t p751[NWORDS64_FIELD] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEEAFFFFFFFFFFFFF,
                                       0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C};
const uint64_t p751p1[NWORDS64_FIELD] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xEEB0000000000000,
                                         0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C};
const uint64_t p751x2[NWORDS64_FIELD] = {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xDD5FFFFFFFFFFFFF,
                                         0xC7D92D0A93F0F151, 0xB52B363427EF98ED, 0x109D30CFADD7D0ED, 0x0AC56A08B964AE90, 0x1C25213F2F75B8CD, 0x0000DFCBAA83EE38};
// Order of Alice's subgroup
static const uint64_t Alice_order[NWORDS64_ORDER] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0010000000000000};
// Order of Bob's subgroup
static const uint64_t Bob_order[NWORDS64_ORDER] = {0xC968549F878A8EEB, 0x59B1A13F7CC76E3E, 0xE9867D6EBE876DA9, 0x2B5045CB25748084, 0x2909F97BADC66856, 0x06FE5D541F71C0E1};
// Alice's generator values {XPA0 + XPA1*i, XQA0, XRA0 + XRA1*i} in GF(p751^2), expressed in Montgomery representation
static const uint64_t A_gen[5 * NWORDS64_FIELD] = {0xC2FC08CEAB50AD8B, 0x1D7D710F55E457B1, 0xE8738D92953DCD6E, 0xBAA7EBEE8A3418AA, 0xC9A288345F03F46F, 0xC8D18D167CFE2616,
                                                   0x02043761F6B1C045, 0xAA1975E13180E7E9, 0x9E13D3FDC6690DE6, 0x3A024640A3A3BB4F, 0x4E5AD44E6ACBBDAE, 0x0000544BEB561DAD, // XPA0
                                                   0xE6CC41D21582E411, 0x07C2ECB7C5DF400A, 0xE8E34B521432AEC4, 0x50761E2AB085167D, 0x032CFBCAA6094B3C, 0x6C522F5FDF9DDD71,
                                                   0x1319217DC3A1887D, 0xDC4FB25803353A86, 0x362C8D7B63A6AB09, 0x39DCDFBCE47EA488, 0x4C27C99A2C28D409, 0x00003CB0075527C4, // XPA1
                                                   0xD56FE52627914862, 0x1FAD60DC96B5BAEA, 0x01E137D0BF07AB91, 0x404D3E9252161964, 0x3C5385E4CD09A337, 0x4476426769E4AF73,
                                                   0x9790C6DB989DFE33, 0xE06E1C04D2AA8B5E, 0x38C08185EDEA73B9, 0xAA41F678A4396CA6, 0x92B9259B2229E9A0, 0x00002F9326818BE0, // XQA0
                                                   0x0BB84441DFFD19B3, 0x84B4DEA99B48C18E, 0x692DE648AD313805, 0xE6D72761B6DFAEE0, 0x223975C672C3058D, 0xA0FDE0C3CBA26FDC,
                                                   0xA5326132A922A3CA, 0xCA5E7F5D5EA96FA4, 0x127C7EFE33FFA8C6, 0x4749B1567E2A23C4, 0x2B7DF5B4AF413BFA, 0x0000656595B9623C, // XRA0
                                                   0xED78C17F1EC71BE8, 0xF824D6DF753859B1, 0x33A10839B2A8529F, 0xFC03E9E25FDEA796, 0xC4708A8054DF1762, 0x4034F2EC034C6467,
                                                   0xABFB70FBF06ECC79, 0xDABE96636EC108B7, 0x49CBCFB090605FD3, 0x20B89711819A45A7, 0xFB8E1590B2B0F63E, 0x0000556A5F964AB2}; // XRA1
// Bob's generator values {XPB0 + XPB1*i, XQB0, XRB0 + XRB1*i} in GF(p751^2), expressed in Montgomery representation
static const uint64_t B_gen[5 * NWORDS64_FIELD] = {0xCFB6D71EF867AB0B, 0x4A5FDD76E9A45C76, 0x38B1EE69194B1F03, 0xF6E7B18A7761F3F0, 0xFCF01A486A52C84C, 0xCBE2F63F5AA75466,
                                                   0x6487BCE837B5E4D6, 0x7747F5A8C622E9B8, 0x4CBFE1E4EE6AEBBA, 0x8A8616A13FA91512, 0x53DB980E1579E0A5, 0x000058FEBFF3BE69, // XPB0
                                                   0xA492034E7C075CC3, 0x677BAF00B04AA430, 0x3AAE0C9A755C94C8, 0x1DC4B064E9EBB08B, 0x3684EDD04E826C66, 0x9BAA6CB661F01B22,
                                                   0x20285A00AD2EFE35, 0xDCE95ABD0497065F, 0x16C7FBB3778E3794, 0x26B3AC29CEF25AAF, 0xFB3C28A31A30AC1D, 0x000046ED190624EE, // XPB1
                                                   0xF1A8C9ED7B96C4AB, 0x299429DA5178486E, 0xEF4926F20CD5C2F4, 0x683B2E2858B4716A, 0xDDA2FBCC3CAC3EEB, 0xEC055F9F3A600460,
                                                   0xD5A5A17A58C3848B, 0x4652D836F42EAED5, 0x2F2E71ED78B3A3B3, 0xA771C057180ADD1D, 0xC780A5D2D835F512, 0x0000114EA3B55AC1, // XQB0
                                                   0x1C0D6733769D0F31, 0xF084C3086E2659D1, 0xE23D5DA27BCBD133, 0xF38EC9A8D5864025, 0x6426DC781B3B645B, 0x4B24E8E3C9FB03EE,
                                                   0x6432792F9D2CEA30, 0x7CC8E8B1AE76E857, 0x7F32BFB626BB8963, 0xB9F05995B48D7B74, 0x4D71200A7D67E042, 0x0000228457AF0637, // XRB0
                                                   0x4AE37E7D8F72BD95, 0xDD2D504B3E993488, 0x5D14E7FA1ECB3C3E, 0x127610CEB75D6350, 0x255B4B4CAC446B11, 0x9EA12336C1F70CAF,
                                                   0x79FA68A2147BC2F8, 0x11E895CFDADBBC49, 0xE4B9D3C4D6356C18, 0x44B25856A67F951C, 0x5851541F61308D0B, 0x00002FFD994F7E4C}; // XRB1
// Montgomery constant Montgomery_R2 = (2^768)^2 mod p751
static const uint64_t Montgomery_R2[NWORDS64_FIELD] = {0x233046449DAD4058, 0xDB010161A696452A, 0x5E36941472E3FD8E, 0xF40BFE2082A2E706, 0x4932CCA8904F8751, 0x1F735F1F1EE7FC81,
                                                       0xA24F4D80C1048E18, 0xB56C383CCDB607C5, 0x441DD47B735F9C90, 0x5673ED2C6A6AC82A, 0x06C905261132294B, 0x000041AD830F1F35};
// Value one in Montgomery representation
static const uint64_t Montgomery_one[NWORDS64_FIELD] = {0x00000000000249ad, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
                                                        0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2};
// Value (2^384)^2 mod 3^239
static const uint64_t Montgomery_Rprime[NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C};
// Value -(3^239)^-1 mod 2^384
static const uint64_t Montgomery_rprime[NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5};
// Value order_Bob/3 mod p751
static const uint64_t Border_div3[NWORDS_ORDER] = {0xEDCD718A828384F9, 0x733B35BFD4427A14, 0xF88229CF94D7CF38, 0x63C56C990C7C2AD6, 0xB858A87E8F4222C7, 0x0254C9C6B525EAF5};

// Fixed parameters for isogeny tree computation
static const unsigned int strat_Alice[MAX_Alice - 1] = {
    80, 48, 27, 15, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1,
    1, 3, 2, 1, 1, 1, 1, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1,
    1, 1, 2, 1, 1, 1, 21, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1,
    1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1,
    33, 20, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1,
    1, 1, 8, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1,
    1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1};

static const unsigned int strat_Bob[MAX_Bob - 1] = {
    112, 63, 32, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1,
    1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 31, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2,
    1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 15, 8, 4, 2, 1, 1, 2, 1, 1, 4,
    2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 49, 31, 16, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1,
    15, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1,
    1, 1, 1, 21, 12, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 5, 3, 2, 1, 1, 1, 1,
    2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1};

// Setting up macro defines and including GF(p), GF(p^2), curve, isogeny and kex functions
#define fpcopy fpcopy751
#define fpzero fpzero751
#define fpadd fpadd751
#define fpsub fpsub751
#define fpneg fpneg751
#define fpdiv2 fpdiv2_751
#define fpcorrection fpcorrection751
#define fpmul_mont fpmul751_mont
#define fpsqr_mont fpsqr751_mont
#define fpinv_mont fpinv751_mont
#define fpinv_chain_mont fpinv751_chain_mont
#define fpinv_mont_bingcd fpinv751_mont_bingcd
#define fp2copy fp2copy751
#define fp2zero fp2zero751
#define fp2add fp2add751
#define fp2sub fp2sub751
#define fp2neg fp2neg751
#define fp2div2 fp2div2_751
#define fp2correction fp2correction751
#define fp2mul_mont fp2mul751_mont
#define fp2sqr_mont fp2sqr751_mont
#define fp2inv_mont fp2inv751_mont
#define fp2inv_mont_bingcd fp2inv751_mont_bingcd
#define fpequal_non_constant_time fpequal751_non_constant_time
#define mp_add_asm mp_add751_asm
#define mp_addx2_asm mp_add751x2_asm
#define mp_subx2_asm mp_sub751x2_asm
#define crypto_kem_keypair crypto_kem_keypair_SIKEp751
#define crypto_kem_enc crypto_kem_enc_SIKEp751
#define crypto_kem_dec crypto_kem_dec_SIKEp751
#define random_mod_order_A random_mod_order_A_SIDHp751
#define random_mod_order_B random_mod_order_B_SIDHp751
#define EphemeralKeyGeneration_A EphemeralKeyGeneration_A_SIDHp751
#define EphemeralKeyGeneration_B EphemeralKeyGeneration_B_SIDHp751
#define EphemeralSecretAgreement_A EphemeralSecretAgreement_A_SIDHp751
#define EphemeralSecretAgreement_B EphemeralSecretAgreement_B_SIDHp751

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
