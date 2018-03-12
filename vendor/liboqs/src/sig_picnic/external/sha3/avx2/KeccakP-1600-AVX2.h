/*
Implementation by Vladimir Sedach, hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakP_1600_AVX2_h_
#define _KeccakP_1600_AVX2_h_

#include <stddef.h>

typedef unsigned char UINT8;

#ifdef __cplusplus
extern "C" {
#endif

void KeccakP1600_StaticInitialize       (void);
void KeccakP1600_Initialize             (void *state);
void KeccakP1600_AddByte                (void *state, UINT8 byte, size_t offset);
void KeccakP1600_AddBytes               (void *state, const UINT8 *data, size_t offset, size_t length);
void KeccakP1600_OverwriteBytes         (void *state, const UINT8 *data, size_t offset, size_t length);
void KeccakP1600_OverwriteWithZeroes    (void *state, size_t byteCount);
void KeccakP1600_Permute_Nrounds        (void *state, unsigned int nrounds);
void KeccakP1600_Permute_24rounds       (void *state);
void KeccakP1600_Permute_12rounds       (void *state);
void KeccakP1600_ExtractBytes           (const void *state, UINT8 *data, size_t offset, size_t length);
void KeccakP1600_ExtractAndAddBytes     (const void *state, const UINT8 *input, UINT8 *output, size_t offset, size_t length);

size_t KeccakF1600_FastLoop_Absorb      (void *state, size_t laneCount, const UINT8 *data, size_t dataByteLen);

#ifdef __cplusplus
}
#endif

#endif /* _KeccakP_1600_AVX2_h_ */
