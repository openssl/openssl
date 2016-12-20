/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: supersingular elliptic curve isogeny parameters
*
*********************************************************************************************/

#include "SIDH_internal.h"


// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located
// at the leftmost position (i.e., little endian format).
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {b, a}, with b
// in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position.

//
// Curve isogeny system "SIDHp751". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p751^2), where A=0, B=1 and C=1
//

CurveIsogenyStaticData CurveIsogeny_SIDHp751 = {
	"SIDHp751", 768, 384,         // Curve isogeny system ID, smallest multiple of 32 larger than the prime bitlength and smallest multiple of 32 larger than the order bitlength
	751,                          // Bitlength of the prime
	// Prime p751 = 2^372*3^239-1
	{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEEAFFFFFFFFFFFFF,
		0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C
	},
	// Base curve parameter "A"
	{ 0 },
	// Base curve parameter "C"
	{ 1 },
	// Order bitlength for Alice
	372,
	// Order of Alice's subgroup
	{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0010000000000000 },
	// Order bitlength for Bob
	379,
	// Power of Bob's subgroup order
	239,
	// Order of Bob's subgroup
	{ 0xC968549F878A8EEB, 0x59B1A13F7CC76E3E, 0xE9867D6EBE876DA9, 0x2B5045CB25748084, 0x2909F97BADC66856, 0x06FE5D541F71C0E1 },
	// Alice's generator PA = (XPA,YPA), where XPA and YPA are defined over GF(p751)
	{
		0x4B0346F5CCE233E9, 0x632646086CE3ACD5, 0x5661D14AB7347693, 0xA58A20449AF1F133, 0xB9AC2F40C56D6FA4, 0x8E561E008FA0E3F3,
		0x6CAE096D5DB822C9, 0x83FDB7A4AD3E83E8, 0xB1317AD904386217, 0x3FA23F89F6BE06D2, 0x429C8D36FF46BCC9, 0x00003E82027A38E9,
		0x12E0D620BFB341D5, 0x0F8EEA7370893430, 0x5A99EBEC3B5B8B00, 0x236C7FAC9E69F7FD, 0x0F147EF3BD0CFEC5, 0x8ED5950D80325A8D,
		0x1E911F50BF3F721A, 0x163A7421DFA8378D, 0xC331B043DA010E6A, 0x5E15915A755883B7, 0xB6236F5F598D56EB, 0x00003BBF8DCD4E7E
	},
	// Bob's generator PB = (XPB,YPB), where XPB and YPB are defined over GF(p751)
	{
		0x76ED2325DCC93103, 0xD9E1DF566C1D26D3, 0x76AECB94B919AEED, 0xD3785AAAA4D646C5, 0xCB610E30288A7770, 0x9BD3778659023B9E,
		0xD5E69CF26DF23742, 0xA3AD8E17B9F9238C, 0xE145FE2D525160E0, 0xF8D5BCE859ED725D, 0x960A01AB8FF409A2, 0x00002F1D80EF06EF,
		0x91479226A0687894, 0xBBC6BAF5F6BA40BB, 0x15B529122CFE3CA6, 0x7D12754F00E898A3, 0x76EBA0C8419745E9, 0x0A94F06CDFB3EADE,
		0x399A6EDB2EEB2F9B, 0xE302C5129C049EEB, 0xC35892123951D4B6, 0x15445287ED1CC55D, 0x1ACAF351F09AB55A, 0x00000127A46D082A
	},
	// BigMont's curve parameter A24 = (A+2)/4
	156113,
	// BigMont's order, where BigMont is defined by y^2=x^3+A*x^2+x
	{
		0xA59B73D250E58055, 0xCB063593D0BE10E1, 0xF6515CCB5D076CBB, 0x66880747EDDF5E20, 0xBA515248A6BFD4AB, 0x3B8EF00DDDDC789D,
		0xB8FB25A1527E1E2A, 0xB6A566C684FDF31D, 0x0213A619F5BAFA1D, 0xA158AD41172C95D2, 0x0384A427E5EEB719, 0x00001BF975507DC7
	},
	// Montgomery constant Montgomery_R2 = (2^768)^2 mod p751
	{
		0x233046449DAD4058, 0xDB010161A696452A, 0x5E36941472E3FD8E, 0xF40BFE2082A2E706, 0x4932CCA8904F8751 , 0x1F735F1F1EE7FC81,
		0xA24F4D80C1048E18, 0xB56C383CCDB607C5, 0x441DD47B735F9C90, 0x5673ED2C6A6AC82A, 0x06C905261132294B, 0x000041AD830F1F35
	},
	// Montgomery constant -p751^-1 mod 2^768
	{
		0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xEEB0000000000000,
		0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x258C28E5D541F71C
	},
	// Value one in Montgomery representation
	{
		0x00000000000249ad, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
		0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2
	}
};


// Fixed parameters for isogeny tree computation

const unsigned int splits_Alice[SIDH_MAX_Alice] = {
	0, 1, 1, 2, 2, 2, 3, 4, 4, 4, 4, 5, 5, 6, 7, 8, 8, 9, 9, 9, 9, 9, 9, 9, 12,
	11, 12, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 17, 17, 18, 18, 17, 21, 17,
	18, 21, 20, 21, 21, 21, 21, 21, 22, 25, 25, 25, 26, 27, 28, 28, 29, 30, 31,
	32, 32, 32, 32, 32, 32, 32, 33, 33, 33, 35, 36, 36, 33, 36, 35, 36, 36, 35,
	36, 36, 37, 38, 38, 39, 40, 41, 42, 38, 39, 40, 41, 42, 40, 46, 42, 43, 46,
	46, 46, 46, 48, 48, 48, 48, 49, 49, 48, 53, 54, 51, 52, 53, 54, 55, 56, 57,
	58, 59, 59, 60, 62, 62, 63, 64, 64, 64, 64, 64, 64, 64, 64, 65, 65, 65, 65,
	65, 66, 67, 65, 66, 67, 66, 69, 70, 66, 67, 66, 69, 70, 69, 70, 70, 71, 72,
	71, 72, 72, 74, 74, 75, 72, 72, 74, 74, 75, 72, 72, 74, 75, 75, 72, 72, 74,
	75, 75, 77, 77, 79, 80, 80, 82
};

const unsigned int splits_Bob[SIDH_MAX_Bob] = {
	0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 6, 7, 8, 8, 8, 8, 9, 9, 9, 9, 9,
	10, 12, 12, 12, 12, 12, 12, 13, 14, 14, 15, 16, 16, 16, 16, 16, 17, 16, 16,
	17, 19, 19, 20, 21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 24, 24, 25, 27,
	27, 28, 28, 29, 28, 29, 28, 28, 28, 30, 28, 28, 28, 29, 30, 33, 33, 33, 33,
	34, 35, 37, 37, 37, 37, 38, 38, 37, 38, 38, 38, 38, 38, 39, 43, 38, 38, 38,
	38, 43, 40, 41, 42, 43, 48, 45, 46, 47, 47, 48, 49, 49, 49, 50, 51, 50, 49,
	49, 49, 49, 51, 49, 53, 50, 51, 50, 51, 51, 51, 52, 55, 55, 55, 56, 56, 56,
	56, 56, 58, 58, 61, 61, 61, 63, 63, 63, 64, 65, 65, 65, 65, 66, 66, 65, 65,
	66, 66, 66, 66, 66, 66, 66, 71, 66, 73, 66, 66, 71, 66, 73, 66, 66, 71, 66,
	73, 68, 68, 71, 71, 73, 73, 73, 75, 75, 78, 78, 78, 80, 80, 80, 81, 81, 82,
	83, 84, 85, 86, 86, 86, 86, 86, 87, 86, 88, 86, 86, 86, 86, 88, 86, 88, 86,
	86, 86, 88, 88, 86, 86, 86, 93, 90, 90, 92, 92, 92, 93, 93, 93, 93, 93, 97,
	97, 97, 97, 97, 97
};
