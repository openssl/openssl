/*
 * rijndael-alg-fst.h   v2.4   April '2000
 *
 * Optimised ANSI C code
 *
 * #define INTERMEDIATE_VALUE_KAT to generate the Intermediate Value Known Answer Test.
 */

#ifndef __RIJNDAEL_ALG_FST_H
#define __RIJNDAEL_ALG_FST_H

#define RIJNDAEL_MAXKC		(256/32)
#define RIJNDAEL_MAXROUNDS	14

#ifndef USUAL_TYPES
#define USUAL_TYPES
typedef unsigned char	byte;
typedef unsigned char	word8;	
typedef unsigned short	word16;	
typedef unsigned int	word32;
#endif /* USUAL_TYPES */

int rijndaelKeySched(const word8 k[RIJNDAEL_MAXKC][4],
		     word8 rk[RIJNDAEL_MAXROUNDS+1][4][4],
		     int ROUNDS);

int rijndaelKeyEncToDec(word8 W[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS);

int rijndaelEncrypt(const word8 a[16],word8 b[16],
		    word8 rk[RIJNDAEL_MAXROUNDS+1][4][4],
		    int ROUNDS);

#ifdef INTERMEDIATE_VALUE_KAT
int rijndaelEncryptRound(word8 a[4][4],word8 rk[RIJNDAEL_MAXROUNDS+1][4][4],
			 int ROUNDS, int rounds);
#endif /* INTERMEDIATE_VALUE_KAT */

int rijndaelDecrypt(const word8 a[16], word8 b[16],
		    word8 rk[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS);

#ifdef INTERMEDIATE_VALUE_KAT
int rijndaelDecryptRound(word8 a[4][4], word8 rk[RIJNDAEL_MAXROUNDS+1][4][4],
			 int ROUNDS, int rounds);
#endif /* INTERMEDIATE_VALUE_KAT */

#endif /* __RIJNDAEL_ALG_FST_H */
