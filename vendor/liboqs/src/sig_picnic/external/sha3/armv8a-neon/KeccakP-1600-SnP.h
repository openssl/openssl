#ifndef _KeccakP_1600_SnP_h_
#define _KeccakP_1600_SnP_h_

/** For the documentation, see SnP-documentation.h.
 */

#define KeccakP1600_implementation      "64-bit optimized ARMv8a assembler implementation"
#define KeccakP1600_stateSizeInBytes    200
#define KeccakP1600_stateAlignment      64

#define KeccakP1600_StaticInitialize()
void KeccakP1600_Initialize(void *state);
void KeccakP1600_AddByte(void *state, unsigned char data, unsigned int offset);
void KeccakP1600_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteWithZeroes(void *state, unsigned int byteCount);
void KeccakP1600_Permute_Nrounds(void *state, unsigned int nrounds);
void KeccakP1600_Permute_12rounds(void *state);
void KeccakP1600_Permute_24rounds(void *state);
void KeccakP1600_ExtractBytes(const void *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_ExtractAndAddBytes(const void *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);

#endif
