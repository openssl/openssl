#ifndef __SPARC_ARCH_H__
#define __SPARC_ARCH_H__

#if !__ASSEMBLER__
extern unsigned int OPENSSL_sparcv9cap_P[];
#endif

#define SPARCV9_TICK_PRIVILEGED	(1<<0)
#define SPARCV9_PREFER_FPU	(1<<1)
#define SPARCV9_VIS1		(1<<2)
#define SPARCV9_VIS2		(1<<3)	/* reserved */
#define SPARCV9_FMADD		(1<<4)	/* reserved for SPARC64 V */
#define SPARCV9_BLK		(1<<5)	/* VIS1 block copy */
#define SPARCV9_VIS3		(1<<6)
#define SPARCV9_RANDOM		(1<<7)

/*
 * OPENSSL_sparcv9cap_P[1] is copy of Compatibility Feature Register,
 * %asr26, SPARC-T4 and later. There is no SPARCV9_CFR bit in
 * OPENSSL_sparcv9cap_P[0], as %cfr copy is sufficient...
 */
#define CFR_AES		0x00000001 /* Supports AES opcodes     */
#define CFR_DES		0x00000002 /* Supports DES opcodes     */
#define CFR_KASUMI	0x00000004 /* Supports KASUMI opcodes  */
#define CFR_CAMELLIA	0x00000008 /* Supports CAMELLIA opcodes*/
#define CFR_MD5		0x00000010 /* Supports MD5 opcodes     */
#define CFR_SHA1	0x00000020 /* Supports SHA1 opcodes    */
#define CFR_SHA256	0x00000040 /* Supports SHA256 opcodes  */
#define CFR_SHA512	0x00000080 /* Supports SHA512 opcodes  */
#define CFR_MPMUL	0x00000100 /* Supports MPMUL opcodes   */
#define CFR_MONTMUL	0x00000200 /* Supports MONTMUL opcodes */
#define CFR_MONTSQR	0x00000400 /* Supports MONTSQR opcodes */
#define CFR_CRC32C	0x00000800 /* Supports CRC32C opcodes  */

#endif
