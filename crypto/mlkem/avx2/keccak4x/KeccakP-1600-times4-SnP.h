/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakP_1600_times4_SnP_h_
#define _KeccakP_1600_times4_SnP_h_

/** For the documentation, see PlSnP-documentation.h.
 */

#include "KeccakP-SIMD256-config.h"
#include "../fips202x4.h"

#define KeccakP1600times4_implementation        "256-bit SIMD implementation (" KeccakP1600times4_implementation_config ")"
#define KeccakP1600times4_statesSizeInBytes     800
#define KeccakP1600times4_statesAlignment       32
#define KeccakF1600times4_FastLoop_supported
#define KeccakP1600times4_12rounds_FastLoop_supported

#include <stddef.h>

#define KeccakP1600times4_StaticInitialize()
#define KeccakP1600times4_InitializeAll FIPS202X4_NAMESPACE(KeccakP1600times4_InitializeAll)
void KeccakP1600times4_InitializeAll(void *states);
#define KeccakP1600times4_AddByte(states, instanceIndex, byte, offset) \
    ((unsigned char*)(states))[(instanceIndex)*8 + ((offset)/8)*4*8 + (offset)%8] ^= (byte)
#define KeccakP1600times4_AddBytes FIPS202X4_NAMESPACE(KeccakP1600times4_AddBytes)
void KeccakP1600times4_AddBytes(void *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
#define KeccakP1600times4_AddLanesAll FIPS202X4_NAMESPACE(KeccakP1600times4_AddLanesAll)
void KeccakP1600times4_AddLanesAll(void *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
#define KeccakP1600times4_OverwriteBytes FIPS202X4_NAMESPACE(KeccakP1600times4_OverwriteBytes)
void KeccakP1600times4_OverwriteBytes(void *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
#define KeccakP1600times4_OverwriteLanesAll FIPS202X4_NAMESPACE(KeccakP1600times4_OverwriteLanesAll)
void KeccakP1600times4_OverwriteLanesAll(void *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
#define KeccakP1600times4_OverwriteWithZeroes FIPS202X4_NAMESPACE(KeccakP1600times4_OverwriteWithZeroes)
void KeccakP1600times4_OverwriteWithZeroes(void *states, unsigned int instanceIndex, unsigned int byteCount);
#define KeccakP1600times4_PermuteAll_12rounds FIPS202X4_NAMESPACE(KeccakP1600times4_PermuteAll_12rounds)
void KeccakP1600times4_PermuteAll_12rounds(void *states);
#define KeccakP1600times4_PermuteAll_24rounds FIPS202X4_NAMESPACE(KeccakP1600times4_PermuteAll_24rounds)
void KeccakP1600times4_PermuteAll_24rounds(void *states);
#define KeccakP1600times4_ExtractBytes FIPS202X4_NAMESPACE(KeccakP1600times4_ExtractBytes)
void KeccakP1600times4_ExtractBytes(const void *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
#define KeccakP1600times4_ExtractLanesAll FIPS202X4_NAMESPACE(KeccakP1600times4_ExtractLanesAll)
void KeccakP1600times4_ExtractLanesAll(const void *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
#define KeccakP1600times4_ExtractAndAddBytes FIPS202X4_NAMESPACE(KeccakP1600times4_ExtractAndAddBytes)
void KeccakP1600times4_ExtractAndAddBytes(const void *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
#define KeccakP1600times4_ExtractAndAddLanesAll FIPS202X4_NAMESPACE(KeccakP1600times4_ExtractAndAddLanesAll)
void KeccakP1600times4_ExtractAndAddLanesAll(const void *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);
#define KeccakF1600times4_FastLoop_Absorb FIPS202X4_NAMESPACE(KeccakF1600times4_FastLoop_Absorb)
size_t KeccakF1600times4_FastLoop_Absorb(void *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen);
#define KeccakP1600times4_12rounds_FastLoop_Absorb FIPS202X4_NAMESPACE(KeccakP1600times4_12rounds_FastLoop_Absorb)
size_t KeccakP1600times4_12rounds_FastLoop_Absorb(void *states, unsigned int laneCount, unsigned int laneOffsetParallel, unsigned int laneOffsetSerial, const unsigned char *data, size_t dataByteLen);

#endif
