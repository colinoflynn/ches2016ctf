/*

Based on AES-RSI implementation by N.V.


*/

#include "aes-challenge.h"
#include <avr/eeprom.h>

uint8_t _stored_key[16]; // all round keys
uint8_t _stored_ct[16];

uint8_t Round_Key[11][16] = {0,};

uint8_t seed, loop;

uint8_t state[16];
uint8_t SV[11] = {0,};
uint8_t mask, mask_a, mmask[4] = {0,}, mmask_a[4] = {0,}, mmask_t[4] = {0,};
uint8_t m_a_to_mmask[4] = {0,};
uint8_t mmask_a_to_m[4] = {0,};
uint8_t m_sbox1[256] = {0,};
unsigned int CC = 0;

#define do_delay() seed = (seed << 2) | ( ((seed >> 6)) ^ ((seed >> 6) & 1) ^ ((seed >> 5) & 1) ^ ((seed >> 4) & 1) ); for (loop=0;loop< (seed&0x0b) ;loop++) state[0] ^ 1;

#define ONE_ARRAY_SBOX	1
#define TWO_ARRAY_SBOX	2

const unsigned char SBox1[256]= 
{
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

const unsigned char SBox2[16][16] = 
{
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

/*
 * 2 x Sbox
 */
const unsigned char two_time_SBox[256] = 
{ 0xC6, 0xF8, 0xEE, 0xF6, 0xFF, 0xD6, 0xDE, 0x91, 0x60, 0x02, 0xCE, 0x56, 0xE7, 0xB5, 0x4D, 0xEC,
0x8F, 0x1F, 0x89, 0xFA, 0xEF, 0xB2, 0x8E, 0xFB, 0x41, 0xB3, 0x5F, 0x45, 0x23, 0x53, 0xE4, 0x9B,
0x75, 0xE1, 0x3D, 0x4C, 0x6C, 0x7E, 0xF5, 0x83, 0x68, 0x51, 0xD1, 0xF9, 0xE2, 0xAB, 0x62, 0x2A,
0x08, 0x95, 0x46, 0x9D, 0x30, 0x37, 0x0A, 0x2F, 0x0E, 0x24, 0x1B, 0xDF, 0xCD, 0x4E, 0x7F, 0xEA,
0x12, 0x1D, 0x58, 0x34, 0x36, 0xDC, 0xB4, 0x5B, 0xA4, 0x76, 0xB7, 0x7D, 0x52, 0xDD, 0x5E, 0x13,
0xA6, 0xB9, 0x00, 0xC1, 0x40, 0xE3, 0x79, 0xB6, 0xD4, 0x8D, 0x67, 0x72, 0x94, 0x98, 0xB0, 0x85,
0xBB, 0xC5, 0x4F, 0xED, 0x86, 0x9A, 0x66, 0x11, 0x8A, 0xE9, 0x04, 0xFE, 0xA0, 0x78, 0x25, 0x4B,
0xA2, 0x5D, 0x80, 0x05, 0x3F, 0x21, 0x70, 0xF1, 0x63, 0x77, 0xAF, 0x42, 0x20, 0xE5, 0xFD, 0xBF,
0x81, 0x18, 0x26, 0xC3, 0xBE, 0x35, 0x88, 0x2E, 0x93, 0x55, 0xFC, 0x7A, 0xC8, 0xBA, 0x32, 0xE6,
0xC0, 0x19, 0x9E, 0xA3, 0x44, 0x54, 0x3B, 0x0B, 0x8C, 0xC7, 0x6B, 0x28, 0xA7, 0xBC, 0x16, 0xAD,
0xDB, 0x64, 0x74, 0x14, 0x92, 0x0C, 0x48, 0xB8, 0x9F, 0xBD, 0x43, 0xC4, 0x39, 0x31, 0xD3, 0xF2,
0xD5, 0x8B, 0x6E, 0xDA, 0x01, 0xB1, 0x9C, 0x49, 0xD8, 0xAC, 0xF3, 0xCF, 0xCA, 0xF4, 0x47, 0x10,
0x6F, 0xF0, 0x4A, 0x5C, 0x38, 0x57, 0x73, 0x97, 0xCB, 0xA1, 0xE8, 0x3E, 0x96, 0x61, 0x0D, 0x0F,
0xE0, 0x7C, 0x71, 0xCC, 0x90, 0x06, 0xF7, 0x1C, 0xC2, 0x6A, 0xAE, 0x69, 0x17, 0x99, 0x3A, 0x27,
0xD9, 0xEB, 0x2B, 0x22, 0xD2, 0xA9, 0x07, 0x33, 0x2D, 0x3C, 0x15, 0xC9, 0x87, 0xAA, 0x50, 0xA5,
0x03, 0x59, 0x09, 0x1A, 0x65, 0xD7, 0x84, 0xD0, 0x82, 0x29, 0x5A, 0x1E, 0x7B, 0xA8, 0x6D, 0x2C};

/*
 * 3 x Sbox
 */
const unsigned char three_time_SBox[256] = 
{0xA5, 0x84, 0x99, 0x8D, 0x0D, 0xBD, 0xB1, 0x54, 0x50, 0x03, 0xA9, 0x7D, 0x19, 0x62, 0xE6, 0x9A, 
0x45, 0x9D, 0x40, 0x87, 0x15, 0xEB, 0xC9, 0x0B, 0xEC, 0x67, 0xFD, 0xEA, 0xBF, 0xF7, 0x96, 0x5B, 
0xC2, 0x1C, 0xAE, 0x6A, 0x5A, 0x41, 0x02, 0x4F, 0x5C, 0xF4, 0x34, 0x08, 0x93, 0x73, 0x53, 0x3F, 
0x0C, 0x52, 0x65, 0x5E, 0x28, 0xA1, 0x0F, 0xB5, 0x09, 0x36, 0x9B, 0x3D, 0x26, 0x69, 0xCD, 0x9F, 
0x1B, 0x9E, 0x74, 0x2E, 0x2D, 0xB2, 0xEE, 0xFB, 0xF6, 0x4D, 0x61, 0xCE, 0x7B, 0x3E, 0x71, 0x97,
0xF5, 0x68, 0x00, 0x2C, 0x60, 0x1F, 0xC8, 0xED, 0xBE, 0x46, 0xD9, 0x4B, 0xDE, 0xD4, 0xE8, 0x4A, 
0x6B, 0x2A, 0xE5, 0x16, 0xC5, 0xD7, 0x55, 0x94, 0xCF, 0x10, 0x06, 0x81, 0xF0, 0x44, 0xBA, 0xE3, 
0xF3, 0xFE, 0xC0, 0x8A, 0xAD, 0xBC, 0x48, 0x04, 0xDF, 0xC1, 0x75, 0x63, 0x30, 0x1A, 0x0E, 0x6D, 
0x4C, 0x14, 0x35, 0x2F, 0xE1, 0xA2, 0xCC, 0x39, 0x57, 0xF2, 0x82, 0x47, 0xAC, 0xE7, 0x2B, 0x95, 
0xA0, 0x98, 0xD1, 0x7F, 0x66, 0x7E, 0xAB, 0x83, 0xCA, 0x29, 0xD3, 0x3C, 0x79, 0xE2, 0x1D, 0x76,
0x3B, 0x56, 0x4E, 0x1E, 0xDB, 0x0A, 0x6C, 0xE4, 0x5D, 0x6E, 0xEF, 0xA6, 0xA8, 0xA4, 0x37, 0x8B, 
0x32, 0x43, 0x59, 0xB7, 0x8C, 0x64, 0xD2, 0xE0, 0xB4, 0xFA, 0x07, 0x25, 0xAF, 0x8E, 0xE9, 0x18, 
0xD5, 0x88, 0x6F, 0x72, 0x24, 0xF1, 0xC7, 0x51, 0x23, 0x7C, 0x9C, 0x21, 0xDD, 0xDC, 0x86, 0x85, 
0x90, 0x42, 0xC4, 0xAA, 0xD8, 0x05, 0x01, 0x12, 0xA3, 0x5F, 0xF9, 0xD0, 0x91, 0x58, 0x27, 0xB9, 
0x38, 0x13, 0xB3, 0x33, 0xBB, 0x70, 0x89, 0xA7, 0xB6, 0x22, 0x92, 0x20, 0x49, 0xFF, 0x78, 0x7A,
0x8F, 0xF8, 0x80, 0x17, 0xDA, 0x31, 0xC6, 0xB8, 0xC3, 0xB0, 0x77, 0x11, 0xCB, 0xFC, 0xD6, 0x3A};

const unsigned char Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void AES_Key_Gen(unsigned char RKey[11][16], unsigned char MKey[16])
{
	unsigned char cnt_i;

	for(cnt_i = 0;cnt_i < 16; cnt_i++)
		RKey[0][cnt_i] = MKey[cnt_i];

	for(cnt_i = 1; cnt_i < 11; cnt_i++)
	{
		RKey[cnt_i][0]=SBox1[RKey[cnt_i-1][13]]^Rcon[cnt_i-1]^RKey[cnt_i-1][0];
		RKey[cnt_i][1]=SBox1[RKey[cnt_i-1][14]]^RKey[cnt_i-1][1];
		RKey[cnt_i][2]=SBox1[RKey[cnt_i-1][15]]^RKey[cnt_i-1][2];
		RKey[cnt_i][3]=SBox1[RKey[cnt_i-1][12]]^RKey[cnt_i-1][3];
		RKey[cnt_i][4] = RKey[cnt_i-1][4] ^ RKey[cnt_i][0];
		RKey[cnt_i][5] = RKey[cnt_i-1][5] ^ RKey[cnt_i][1];
		RKey[cnt_i][6] = RKey[cnt_i-1][6] ^ RKey[cnt_i][2];
		RKey[cnt_i][7] = RKey[cnt_i-1][7] ^ RKey[cnt_i][3];
		RKey[cnt_i][8] = RKey[cnt_i-1][8] ^ RKey[cnt_i][4];
		RKey[cnt_i][9] = RKey[cnt_i-1][9] ^ RKey[cnt_i][5];
		RKey[cnt_i][10] = RKey[cnt_i-1][10] ^ RKey[cnt_i][6];
		RKey[cnt_i][11] = RKey[cnt_i-1][11] ^ RKey[cnt_i][7];
		RKey[cnt_i][12] = RKey[cnt_i-1][12] ^ RKey[cnt_i][8];
		RKey[cnt_i][13] = RKey[cnt_i-1][13] ^ RKey[cnt_i][9];
		RKey[cnt_i][14] = RKey[cnt_i-1][14] ^ RKey[cnt_i][10];
		RKey[cnt_i][15] = RKey[cnt_i-1][15] ^ RKey[cnt_i][11];
	}
}

void add_RKey(unsigned char data[], unsigned char RKey[])
{
	unsigned char cnt_i;
	do_delay()

	for(cnt_i = 0; cnt_i < 16; cnt_i++){
		data[cnt_i] ^= RKey[cnt_i];
		do_delay()
	}
}

#define add_RKey_Macro(data, RKey)	\
{	do_delay()				\
	(data)[0] ^= (RKey)[0];	\
	do_delay()				\
	(data)[1] ^= (RKey)[1];	\
	do_delay()				\
	(data)[2] ^= (RKey)[2];	\
	do_delay()				\
	(data)[3] ^= (RKey)[3];	\
	do_delay()				\
	(data)[4] ^= (RKey)[4];	\
	do_delay()				\
	(data)[5] ^= (RKey)[5];	\
	do_delay()				\
	(data)[6] ^= (RKey)[6];	\
	do_delay()				\
	(data)[7] ^= (RKey)[7];	\
	do_delay()				\
	(data)[8] ^= (RKey)[8];	\
	do_delay()				\
	(data)[9] ^= (RKey)[9];	\
	do_delay()				\
	(data)[10] ^= (RKey)[10];	\
	do_delay()				\
	(data)[11] ^= (RKey)[11];	\
	do_delay()				\
	(data)[12] ^= (RKey)[12];	\
	do_delay()				\
	(data)[13] ^= (RKey)[13];	\
	do_delay()				\
	(data)[14] ^= (RKey)[14];	\
	do_delay()				\
	(data)[15] ^= (RKey)[15];	\
	do_delay()				\
}


void sub_Bytes(unsigned char data[], unsigned int option)
{
	unsigned char cnt_i;
	do_delay()
	if(option == ONE_ARRAY_SBOX)
	{
		for(cnt_i = 0;cnt_i < 16; cnt_i++){
			data[cnt_i] = SBox1[data[cnt_i]]; 
			do_delay()
		}
	}
	else if(option == TWO_ARRAY_SBOX)
	{
		for(cnt_i = 0;cnt_i < 16; cnt_i++){
			data[cnt_i] = SBox2[data[cnt_i] >> 4][data[cnt_i] & 0x0F]; 
			do_delay()
		}
	}
}

void m_sub_Bytes(unsigned char data[], unsigned int option)
{
	unsigned char cnt_i;
	do_delay()
	if(option == ONE_ARRAY_SBOX)
	{
		for(cnt_i = 0;cnt_i < 16; cnt_i++){
			data[cnt_i] = m_sbox1[data[cnt_i]]; 
			do_delay()
		}
	}
}

#define sub_Bytes1_Macro(data)			\
{	do_delay()							\
	(data)[0] = (SBox1[(data)[0]]);		\
	do_delay()				\
	(data)[1] = (SBox1[(data)[1]]);		\
	do_delay()				\
	(data)[2] = (SBox1[(data)[2]]);		\
	do_delay()							\
	(data)[3] = (SBox1[(data)[3]]);		\
	do_delay()							\
	(data)[4] = (SBox1[(data)[4]]);		\
	do_delay()							\
	(data)[5] = (SBox1[(data)[5]]);		\
	do_delay()							\
	(data)[6] = (SBox1[(data)[6]]);		\
	do_delay()							\
	(data)[7] = (SBox1[(data)[7]]);		\
	do_delay()							\
	(data)[8] = (SBox1[(data)[8]]);		\
	do_delay()							\
	(data)[9] = (SBox1[(data)[9]]);		\
	do_delay()							\
	(data)[10] = (SBox1[(data)[10]]);	\
	do_delay()							\
	(data)[11] = (SBox1[(data)[11]]);	\
	do_delay()							\
	(data)[12] = (SBox1[(data)[12]]);	\
	do_delay()							\
	(data)[13] = (SBox1[(data)[13]]);	\
	do_delay()							\
	(data)[14] = (SBox1[(data)[14]]);	\
	do_delay()							\
	(data)[15] = (SBox1[(data)[15]]);	\
	do_delay()                         \
}

#define m_sub_Bytes1_Macro(data)			\
{	do_delay()							\
	(data)[0] = (m_sbox1[(data)[0]]);\
	do_delay()				\
	(data)[1] = (m_sbox1[(data)[1]]);		\
	do_delay()				\
	(data)[2] = (m_sbox1[(data)[2]]);		\
	do_delay()							\
	(data)[3] = (m_sbox1[(data)[3]]);		\
	do_delay()							\
	(data)[4] = (m_sbox1[(data)[4]]);		\
	do_delay()							\
	(data)[5] = (m_sbox1[(data)[5]]);		\
	do_delay()							\
	(data)[6] = (m_sbox1[(data)[6]]);		\
	do_delay()							\
	(data)[7] = (m_sbox1[(data)[7]]);		\
	do_delay()							\
	(data)[8] = (m_sbox1[(data)[8]]);		\
	do_delay()							\
	(data)[9] = (m_sbox1[(data)[9]]);		\
	do_delay()							\
	(data)[10] = (m_sbox1[(data)[10]]);	\
	do_delay()							\
	(data)[11] = (m_sbox1[(data)[11]]);	\
	do_delay()							\
	(data)[12] = (m_sbox1[(data)[12]]);	\
	do_delay()							\
	(data)[13] = (m_sbox1[(data)[13]]);	\
	do_delay()							\
	(data)[14] = (m_sbox1[(data)[14]]);	\
	do_delay()							\
	(data)[15] = (m_sbox1[(data)[15]]);	\
	do_delay()                         \
}

#define sub_Bytes2_Macro(data)			\
{	do_delay()												\
	(data)[0] = (SBox2[(data)[0]>>4][(data)[0]&0x0f]);		\
	do_delay()												\
	(data)[1] = (SBox2[(data)[1]>>4][(data)[1]&0x0f]);		\
	do_delay()												\
	(data)[2] = (SBox2[(data)[2]>>4][(data)[2]&0x0f]);		\
	do_delay()												\
	(data)[3] = (SBox2[(data)[3]>>4][(data)[3]&0x0f]);		\
	do_delay()												\
	(data)[4] = (SBox2[(data)[4]>>4][(data)[4]&0x0f]);		\
	do_delay()												\
	(data)[5] = (SBox2[(data)[5]>>4][(data)[5]&0x0f]);		\
	do_delay()												\
	(data)[6] = (SBox2[(data)[6]>>4][(data)[6]&0x0f]);		\
	do_delay()												\
	(data)[7] = (SBox2[(data)[7]>>4][(data)[7]&0x0f]);		\
	do_delay()												\
	(data)[8] = (SBox2[(data)[8]>>4][(data)[8]&0x0f]);		\
	do_delay()												\
	(data)[9] = (SBox2[(data)[9]>>4][(data)[9]&0x0f]);		\
	do_delay()												\
	(data)[10] = (SBox2[(data)[10]>>4][(data)[10]&0x0f]);	\
	do_delay()												\
	(data)[11] = (SBox2[(data)[11]>>4][(data)[11]&0x0f]);	\
	do_delay()												\
	(data)[12] = (SBox2[(data)[12]>>4][(data)[12]&0x0f]);	\
	do_delay()												\
	(data)[13] = (SBox2[(data)[13]>>4][(data)[13]&0x0f]);	\
	do_delay()												\
	(data)[14] = (SBox2[(data)[14]>>4][(data)[14]&0x0f]);	\
	do_delay()												\
	(data)[15] = (SBox2[(data)[15]>>4][(data)[15]&0x0f]);	\
	do_delay()                                             \
}

void shift_Rows(unsigned char data[])
{
	unsigned char temp;
	do_delay()
	temp = data[1];
	data[1] = data[5];
	data[5] = data[9];
	data[9] = data[13];
	data[13] = temp;
	do_delay()
	temp = data[2];
	data[2] = data[10];
	data[10] = temp;
	temp = data[6];
	data[6] = data[14];
	data[14] = temp;
	do_delay()
	temp = data[3];
	data[3] = data[15];
	data[15] = data[11];
	data[11] = data[7];
	data[7] = temp;
}

#define shift_Rows_Macro(data, temp)	\
{	do_delay()					\
	(temp) = (data)[1];			\
	(data)[1] = (data)[5];		\
	(data)[5] = (data)[9];		\
	(data)[9] = (data)[13];		\
	(data)[13] = (temp);		\
	do_delay()					\
	(temp) = (data)[2];			\
	(data)[2] = (data)[10];		\
	(data)[10] = (temp);		\
	(temp) = (data)[6];			\
	(data)[6] = (data)[14];		\
	(data)[14] = (temp);		\
	do_delay()					\
	(temp) = (data)[3];			\
	(data)[3] = (data)[15];		\
	(data)[15] = (data)[11];	\
	(data)[11] = (data)[7];		\
	(data)[7] = (temp);			\
}

void shift_Rows_bertoni(unsigned char data[])
{
	unsigned char temp;
	do_delay()
	temp = data[4];
	data[4] = data[5];
	data[5] = data[6];
	data[6] = data[7];
	data[7] = temp;
	do_delay()
	temp = data[8];
	data[8] = data[10];
	data[10] = temp;
	temp = data[9];
	data[9] = data[11];
	data[11] = temp;
	do_delay()
	temp = data[12];
	data[12] = data[15];
	data[15] = data[14];
	data[14] = data[13];
	data[13] = temp;
}

#define shift_Rows_bertoni_Macro(data, temp)	\
{	do_delay()									\
	(temp) = (data)[4];							\
	(data)[4] = (data)[5];						\
	(data)[5] = (data)[6];						\
	(data)[6] = (data)[7];						\
	(data)[7] = (temp);							\
	do_delay()									\
	(temp) = (data)[8];							\
	(data)[8] = (data)[10];						\
	(data)[10] = (temp);						\
	(temp) = (data)[9];							\
	(data)[9] = (data)[11];						\
	(data)[11] = (temp);						\
	do_delay()								\
	(temp) = (data)[12];						\
	(data)[12] = (data)[15];					\
	(data)[15] = (data)[14];					\
	(data)[14] = (data)[13];					\
	(data)[13] = (temp);						\
}

unsigned char xtime(unsigned char data)
{
	if(data & 0x80)
		return (data << 1) ^ 0x1b;
	else
		return data << 1;
}

#define xtime_Macro(data)	(((data) << 1) ^ ((((data) >> 7) & 1) * 0x1b))

void mix_Columns(unsigned char data[])
{
	unsigned char cnt_i = 0;
	unsigned char St[16], Mc[16];

	for(cnt_i = 0; cnt_i < 16; cnt_i++) 
	{
		do_delay()
		St[cnt_i] = data[cnt_i];
		Mc[cnt_i] = xtime(data[cnt_i]);
	}

	for(cnt_i = 0; cnt_i < 16; cnt_i += 4) 
	{
		do_delay()
		data[cnt_i] = (Mc[cnt_i])^((Mc[cnt_i+1])^St[cnt_i+1])^St[cnt_i+2]^St[cnt_i+3];
		data[cnt_i+1] = St[cnt_i]^(Mc[cnt_i+1])^((Mc[cnt_i+2])^St[cnt_i+2])^St[cnt_i+3];
		data[cnt_i+2] = St[cnt_i]^St[cnt_i+1]^(Mc[cnt_i+2])^((Mc[cnt_i+3])^St[cnt_i+3]);
		data[cnt_i+3] = ((Mc[cnt_i])^St[cnt_i])^St[cnt_i+1]^St[cnt_i+2]^(Mc[cnt_i+3]);
	}
}

void m_mix_Columns(unsigned char data[])
{
	unsigned char cnt_i = 0;
	unsigned char St[16], Mc[16];

	for(cnt_i = 0; cnt_i < 16; cnt_i++) 
	{
		do_delay()
		St[cnt_i] = data[cnt_i]^m_a_to_mmask[cnt_i & 0x03];
		Mc[cnt_i] = xtime(St[cnt_i]);
	}

	for(cnt_i = 0; cnt_i < 16; cnt_i += 4) 
	{
		do_delay()
		data[cnt_i] = (Mc[cnt_i])^((Mc[cnt_i+1])^St[cnt_i+1])^St[cnt_i+2]^St[cnt_i+3];
		data[cnt_i+1] = St[cnt_i]^(Mc[cnt_i+1])^((Mc[cnt_i+2])^St[cnt_i+2])^St[cnt_i+3];
		data[cnt_i+2] = St[cnt_i]^St[cnt_i+1]^(Mc[cnt_i+2])^((Mc[cnt_i+3])^St[cnt_i+3]);
		data[cnt_i+3] = ((Mc[cnt_i])^St[cnt_i])^St[cnt_i+1]^St[cnt_i+2]^(Mc[cnt_i+3]);
	}

	for(cnt_i = 0; cnt_i < 16; cnt_i++)
	{
		data[cnt_i] ^= mmask_a_to_m[cnt_i & 0x03];
	}
}

#define DM_mix_Columns_Macro(data, St, Mc)	\
{	do_delay()									\
	(St)[0] = (data)[0];				\
	(Mc)[0] = (xtime)(data[0]);			\
	do_delay()\
	(St)[1] = (data)[1];				\
	(Mc)[1] = (xtime)(data[1]);			\
	do_delay()\
	(St)[2] = (data)[2];				\
	(Mc)[2] = (xtime)(data[2]);			\
	do_delay()\
	(St)[3] = (data)[3];				\
	(Mc)[3] = (xtime)(data[3]);			\
	do_delay()\
	(St)[4] = (data)[4];				\
	(Mc)[4] = (xtime)(data[4]);			\
	do_delay()\
	(St)[5] = (data)[5];				\
	(Mc)[5] = (xtime)(data[5]);			\
	do_delay()\
	(St)[6] = (data)[6];				\
	(Mc)[6] = (xtime)(data[6]);			\
	do_delay()\
	(St)[7] = (data)[7];				\
	(Mc)[7] = (xtime)(data[7]);			\
	do_delay()\
	(St)[8] = (data)[8];				\
	(Mc)[8] = (xtime)(data[8]);			\
	do_delay()\
	(St)[9] = (data)[9];				\
	(Mc)[9] = (xtime)(data[9]);			\
	do_delay()\
	(St)[10] = (data)[10];				\
	(Mc)[10] = (xtime)(data[10]);			\
	do_delay()\
	(St)[11] = (data)[11];				\
	(Mc)[11] = (xtime)(data[11]);			\
	do_delay()\
	(St)[12] = (data)[12];				\
	(Mc)[12] = (xtime)(data[12]);			\
	do_delay()\
	(St)[13] = (data)[13];				\
	(Mc)[13] = (xtime)(data[13]);			\
	do_delay()\
	(St)[14] = (data)[14];				\
	(Mc)[14] = (xtime)(data[14]);			\
	do_delay()\
	(St)[15] = (data)[15];				\
	(Mc)[15] = (xtime)(data[15]);			\
}

#define mix_Columns_Macro(data, St, Mc)	\
{	do_delay()\
	(St)[0] = (data)[0];				\
	(Mc)[0] = (xtime)(data[0]);			\
	do_delay()\
	(St)[1] = (data)[1];				\
	(Mc)[1] = (xtime)(data[1]);			\
	do_delay()\
	(St)[2] = (data)[2];				\
	(Mc)[2] = (xtime)(data[2]);			\
	do_delay()\
	(St)[3] = (data)[3];				\
	(Mc)[3] = (xtime)(data[3]);			\
	do_delay()\
	(St)[4] = (data)[4];				\
	(Mc)[4] = (xtime)(data[4]);			\
	do_delay()\
	(St)[5] = (data)[5];				\
	(Mc)[5] = (xtime)(data[5]);			\
	do_delay()\
	(St)[6] = (data)[6];				\
	(Mc)[6] = (xtime)(data[6]);			\
	do_delay()\
	(St)[7] = (data)[7];				\
	(Mc)[7] = (xtime)(data[7]);			\
	do_delay()\
	(St)[8] = (data)[8];				\
	(Mc)[8] = (xtime)(data[8]);			\
	do_delay()\
	(St)[9] = (data)[9];				\
	(Mc)[9] = (xtime)(data[9]);			\
	do_delay()\
	(St)[10] = (data)[10];				\
	(Mc)[10] = (xtime)(data[10]);			\
	do_delay()\
	(St)[11] = (data)[11];				\
	(Mc)[11] = (xtime)(data[11]);			\
	do_delay()\
	(St)[12] = (data)[12];				\
	(Mc)[12] = (xtime)(data[12]);			\
	do_delay()\
	(St)[13] = (data)[13];				\
	(Mc)[13] = (xtime)(data[13]);			\
	do_delay()\
	(St)[14] = (data)[14];				\
	(Mc)[14] = (xtime)(data[14]);			\
	do_delay()\
	(St)[15] = (data)[15];				\
	(Mc)[15] = (xtime)(data[15]);			\
	do_delay()														\
	(data)[0] = ((Mc)[0])^(((Mc)[1])^(St)[1])^(St)[2]^(St)[3];		\
	(data)[1] = (St)[0]^((Mc)[1])^(((Mc)[2])^(St)[2])^(St)[3];		\
	(data)[2] = (St)[0]^(St)[1]^((Mc)[2])^(((Mc)[3])^(St)[3]);		\
	(data)[3] = (((Mc)[0])^(St)[0])^(St)[1]^(St)[2]^((Mc)[3]);		\
	do_delay()													\
	(data)[4] = ((Mc)[4])^(((Mc)[5])^(St)[5])^(St)[6]^(St)[7];		\
	(data)[5] = (St)[4]^((Mc)[5])^(((Mc)[6])^(St)[6])^(St)[7];		\
	(data)[6] = (St)[4]^(St)[5]^((Mc)[6])^(((Mc)[7])^(St)[7]);		\
	(data)[7] = (((Mc)[4])^(St)[4])^(St)[5]^(St)[6]^((Mc)[7]);		\
	do_delay()														\
	(data)[8] = ((Mc)[8])^(((Mc)[9])^(St)[9])^(St)[10]^(St)[11];		\
	(data)[9] = (St)[8]^((Mc)[9])^(((Mc)[10])^(St)[10])^(St)[11];		\
	(data)[10] = (St)[8]^(St)[9]^((Mc)[10])^(((Mc)[11])^(St)[11]);		\
	(data)[11] = (((Mc)[8])^(St)[8])^(St)[9]^(St)[10]^((Mc)[11]);		\
	do_delay()															\
	(data)[12] = ((Mc)[12])^(((Mc)[13])^(St)[13])^(St)[14]^(St)[15];		\
	(data)[13] = (St)[12]^((Mc)[13])^(((Mc)[14])^(St)[14])^(St)[15];		\
	(data)[14] = (St)[12]^(St)[13]^((Mc)[14])^(((Mc)[15])^(St)[15]);		\
	(data)[15] = (((Mc)[12])^(St)[12])^(St)[13]^(St)[14]^((Mc)[15]);		\
}

#define m_mix_Columns_Macro(data, St, Mc)	\
{	do_delay()\
	(St)[0] = (data)[0]^m_a_to_mmask[0];				\
	(Mc)[0] = (xtime)((data)[0]^m_a_to_mmask[0]);			\
	do_delay()\
	(St)[1] = (data)[1]^m_a_to_mmask[1];				\
	(Mc)[1] = (xtime)((data)[1]^m_a_to_mmask[1]);			\
	do_delay()\
	(St)[2] = (data)[2]^m_a_to_mmask[2]; 			\
	(Mc)[2] = (xtime)((data)[2]^m_a_to_mmask[2]);			\
	do_delay()\
	(St)[3] = (data)[3]^m_a_to_mmask[3];				\
	(Mc)[3] = (xtime)((data)[3]^m_a_to_mmask[3]);			\
	do_delay()\
	(St)[4] = (data)[4]^m_a_to_mmask[0];				\
	(Mc)[4] = (xtime)((data)[4]^m_a_to_mmask[0]);			\
	do_delay()\
	(St)[5] = (data)[5]^m_a_to_mmask[1];				\
	(Mc)[5] = (xtime)((data)[5]^m_a_to_mmask[1]);			\
	do_delay()\
	(St)[6] = (data)[6]^m_a_to_mmask[2];				\
	(Mc)[6] = (xtime)((data)[6]^m_a_to_mmask[2]);			\
	do_delay()\
	(St)[7] = (data)[7]^m_a_to_mmask[3];				\
	(Mc)[7] = (xtime)((data)[7]^m_a_to_mmask[3]);			\
	do_delay()\
	(St)[8] = (data)[8]^m_a_to_mmask[0];				\
	(Mc)[8] = (xtime)((data)[8]^m_a_to_mmask[0]);			\
	do_delay()\
	(St)[9] = (data)[9]^m_a_to_mmask[1];				\
	(Mc)[9] = (xtime)((data)[9]^m_a_to_mmask[1]);			\
	do_delay()\
	(St)[10] = (data)[10]^m_a_to_mmask[2];				\
	(Mc)[10] = (xtime)((data)[10]^m_a_to_mmask[2]);			\
	do_delay()\
	(St)[11] = (data)[11]^m_a_to_mmask[3];				\
	(Mc)[11] = (xtime)((data)[11]^m_a_to_mmask[3]);			\
	do_delay()\
	(St)[12] = (data)[12]^m_a_to_mmask[0];				\
	(Mc)[12] = (xtime)((data)[12]^m_a_to_mmask[0]);			\
	do_delay()\
	(St)[13] = (data)[13]^m_a_to_mmask[1];				\
	(Mc)[13] = (xtime)((data)[13]^m_a_to_mmask[1]);			\
	do_delay()\
	(St)[14] = (data)[14]^m_a_to_mmask[2];				\
	(Mc)[14] = (xtime)((data)[14]^m_a_to_mmask[2]);			\
	do_delay()\
	(St)[15] = (data)[15]^m_a_to_mmask[3];				\
	(Mc)[15] = (xtime)((data)[15]^m_a_to_mmask[3]);			\
	do_delay()														\
	(data)[0] = ((Mc)[0])^(((Mc)[1])^(St)[1])^(St)[2]^(St)[3];		\
	(data)[1] = (St)[0]^((Mc)[1])^(((Mc)[2])^(St)[2])^(St)[3];		\
	(data)[2] = (St)[0]^(St)[1]^((Mc)[2])^(((Mc)[3])^(St)[3]);		\
	(data)[3] = (((Mc)[0])^(St)[0])^(St)[1]^(St)[2]^((Mc)[3]);		\
	do_delay()													\
	(data)[4] = ((Mc)[4])^(((Mc)[5])^(St)[5])^(St)[6]^(St)[7];		\
	(data)[5] = (St)[4]^((Mc)[5])^(((Mc)[6])^(St)[6])^(St)[7];		\
	(data)[6] = (St)[4]^(St)[5]^((Mc)[6])^(((Mc)[7])^(St)[7]);		\
	(data)[7] = (((Mc)[4])^(St)[4])^(St)[5]^(St)[6]^((Mc)[7]);		\
	do_delay()														\
	(data)[8] = ((Mc)[8])^(((Mc)[9])^(St)[9])^(St)[10]^(St)[11];		\
	(data)[9] = (St)[8]^((Mc)[9])^(((Mc)[10])^(St)[10])^(St)[11];		\
	(data)[10] = (St)[8]^(St)[9]^((Mc)[10])^(((Mc)[11])^(St)[11]);		\
	(data)[11] = (((Mc)[8])^(St)[8])^(St)[9]^(St)[10]^((Mc)[11]);		\
	do_delay()															\
	(data)[12] = ((Mc)[12])^(((Mc)[13])^(St)[13])^(St)[14]^(St)[15];		\
	(data)[13] = (St)[12]^((Mc)[13])^(((Mc)[14])^(St)[14])^(St)[15];		\
	(data)[14] = (St)[12]^(St)[13]^((Mc)[14])^(((Mc)[15])^(St)[15]);		\
	(data)[15] = (((Mc)[12])^(St)[12])^(St)[13]^(St)[14]^((Mc)[15]);		\
}

void mix_Columns_bertoni(unsigned char data[])
{
	unsigned char cnt_i = 0;
	unsigned char temp[16] = {0x00, };
	unsigned char temp2[4] = {0x00, };

	temp[0] = data[4]^data[8]^data[12];
	temp[1] = data[5]^data[9]^data[13];
	temp[2] = data[6]^data[10]^data[14];
	temp[3] = data[7]^data[11]^data[15];

	temp[4] = data[0]^data[8]^data[12];
	temp[5] = data[1]^data[9]^data[13];
	temp[6] = data[2]^data[10]^data[14];
	temp[7] = data[3]^data[11]^data[15];

	temp[8] = data[0]^data[4]^data[12];
	temp[9] = data[1]^data[5]^data[13];
	temp[10] = data[2]^data[6]^data[14];
	temp[11] = data[3]^data[7]^data[15];

	temp[12] = data[0]^data[4]^data[8];
	temp[13] = data[1]^data[5]^data[9];
	temp[14] = data[2]^data[6]^data[10];
	temp[15] = data[3]^data[7]^data[11];

	for(cnt_i = 0; cnt_i < 16; cnt_i++)
	{
		data[cnt_i] = xtime(data[cnt_i]);
	}

	temp2[0] = data[0];
	temp2[1] = data[1];
	temp2[2] = data[2];
	temp2[3] = data[3];
	do_delay()
	data[0] = data[0]^data[4]^temp[0];
	data[1] = data[1]^data[5]^temp[1];
	data[2] = data[2]^data[6]^temp[2];
	data[3] = data[3]^data[7]^temp[3];
	do_delay()
	data[4] = data[4]^data[8]^temp[4];
	data[5] = data[5]^data[9]^temp[5];
	data[6] = data[6]^data[10]^temp[6];
	data[7] = data[7]^data[11]^temp[7];
	do_delay()
	data[8] = data[8]^data[12]^temp[8];
	data[9] = data[9]^data[13]^temp[9];
	data[10] = data[10]^data[14]^temp[10];
	data[11] = data[11]^data[15]^temp[11];
	do_delay()
	data[12] = data[12]^temp2[0]^temp[12];
	data[13] = data[13]^temp2[1]^temp[13];
	data[14] = data[14]^temp2[2]^temp[14];
	data[15] = data[15]^temp2[3]^temp[15];
}

void m_mix_Columns_bertoni(unsigned char data[])
{
	unsigned char cnt_i = 0;
	unsigned char St[16], Mc[16];

	for(cnt_i = 0; cnt_i < 16; cnt_i++) 
	{	do_delay()
		St[cnt_i] = data[cnt_i]^m_a_to_mmask[cnt_i >> 2];
		Mc[cnt_i] = xtime(St[cnt_i]);
	}

	do_delay()
	data[0] = (Mc[0])^((Mc[4])^St[4])^St[8]^St[12];
	data[1] = St[9]^(Mc[1])^((Mc[5])^St[5])^St[13];
	data[2] = St[10]^St[14]^(Mc[2])^((Mc[6])^St[6]);
	data[3] = ((Mc[7])^St[7])^St[11]^St[15]^(Mc[3]);
	do_delay()
	data[4] = (Mc[4])^((Mc[8])^St[8])^St[0]^St[12];
	data[5] = St[1]^(Mc[5])^((Mc[9])^St[9])^St[13];
	data[6] = St[2]^St[10]^(Mc[6])^((Mc[10])^St[14]);
	data[7] = ((Mc[7])^St[3])^St[11]^St[15]^(Mc[11]);
	do_delay()
	data[8] = (Mc[8])^((Mc[12])^St[0])^St[4]^St[12];
	data[9] = St[1]^(Mc[9])^((Mc[13])^St[5])^St[13];
	data[10] = St[2]^St[6]^(Mc[10])^((Mc[14])^St[14]);
	data[11] = ((Mc[11])^St[3])^St[7]^St[15]^(Mc[15]);
	do_delay()
	data[12] = (Mc[12])^((Mc[0])^St[0])^St[4]^St[8];
	data[13] = St[1]^(Mc[13])^((Mc[1])^St[5])^St[9];
	data[14] = St[2]^St[6]^(Mc[14])^((Mc[2])^St[10]);
	data[15] = ((Mc[15])^St[3])^St[7]^St[11]^(Mc[3]);
}

#define mix_Columns_bertoni_Macro(data, temp, temp2)	\
{														\
	(temp)[0] = (data)[4]^(data)[8]^(data)[12];			\
	(temp)[1] = (data)[5]^(data)[9]^(data)[13];			\
	(temp)[2] = (data)[6]^(data)[10]^(data)[14];		\
	(temp)[3] = (data)[7]^(data)[11]^(data)[15];		\
	(temp)[4] = (data)[0]^(data)[8]^(data)[12];			\
	(temp)[5] = (data)[1]^(data)[9]^(data)[13];			\
	(temp)[6] = (data)[2]^(data)[10]^(data)[14];		\
	(temp)[7] = (data)[3]^(data)[11]^(data)[15];		\
	(temp)[8] = (data)[0]^(data)[4]^(data)[12];			\
	(temp)[9] = (data)[1]^(data)[5]^(data)[13];			\
	(temp)[10] = (data)[2]^(data)[6]^(data)[14];		\
	(temp)[11] = (data)[3]^(data)[7]^(data)[15];		\
	(temp)[12] = (data)[0]^(data)[4]^(data)[8];			\
	(temp)[13] = (data)[1]^(data)[5]^(data)[9];			\
	(temp)[14] = (data)[2]^(data)[6]^(data)[10];		\
	(temp)[15] = (data)[3]^(data)[7]^(data)[11];		\
	(data)[0] = xtime_Macro((data)[0]);					\
	(data)[1] = xtime_Macro((data)[1]);					\
	(data)[2] = xtime_Macro((data)[2]);					\
	(data)[3] = xtime_Macro((data)[3]);					\
	(data)[4] = xtime_Macro((data)[4]);					\
	(data)[5] = xtime_Macro((data)[5]);					\
	(data)[6] = xtime_Macro((data)[6]);					\
	(data)[7] = xtime_Macro((data)[7]);					\
	(data)[8] = xtime_Macro((data)[8]);					\
	(data)[9] = xtime_Macro((data)[9]);					\
	(data)[10] = xtime_Macro((data)[10]);				\
	(data)[11] = xtime_Macro((data)[11]);				\
	(data)[12] = xtime_Macro((data)[12]);				\
	(data)[13] = xtime_Macro((data)[13]);				\
	(data)[14] = xtime_Macro((data)[14]);				\
	(data)[15] = xtime_Macro((data)[15]);				\
	(temp2)[0] = (data)[0];								\
	(temp2)[1] = (data)[1];								\
	(temp2)[2] = (data)[2];								\
	(temp2)[3] = (data)[3];								\
	do_delay()											\
	(data)[0] = (data)[0]^(data)[4]^(temp)[0];			\
	(data)[1] = (data)[1]^(data)[5]^(temp)[1];			\
	(data)[2] = (data)[2]^(data)[6]^(temp)[2];			\
	(data)[3] = (data)[3]^(data)[7]^(temp)[3];			\
	do_delay()											\
	(data)[4] = (data)[4]^(data)[8]^(temp)[4];			\
	(data)[5] = (data)[5]^(data)[9]^(temp)[5];			\
	(data)[6] = (data)[6]^(data)[10]^(temp)[6];			\
	(data)[7] = (data)[7]^(data)[11]^(temp)[7];			\
	do_delay()											\
	(data)[8] = (data)[8]^(data)[12]^(temp)[8];			\
	(data)[9] = (data)[9]^(data)[13]^(temp)[9];			\
	(data)[10] = (data)[10]^(data)[14]^(temp)[10];		\
	(data)[11] = (data)[11]^(data)[15]^(temp)[11];		\
	do_delay()											\
	(data)[12] = (data)[12]^(temp2)[0]^(temp)[12];		\
	(data)[13] = (data)[13]^(temp2)[1]^(temp)[13];		\
	(data)[14] = (data)[14]^(temp2)[2]^(temp)[14];		\
	(data)[15] = (data)[15]^(temp2)[3]^(temp)[15];		\
}

#define m_mix_Columns_bertoni_Macro(data, St, Mc)	\
{	do_delay() \	
    (St)[0] = (data)[0]^m_a_to_mmask[0];				\
	(Mc)[0] = (xtime)((data)[0]^m_a_to_mmask[0]);			\
	do_delay() \
	(St)[1] = (data)[1]^m_a_to_mmask[0];				\
	(Mc)[1] = (xtime)((data)[1]^m_a_to_mmask[0]);			\
	do_delay() \
	(St)[2] = (data)[2]^m_a_to_mmask[0]; 			\
	(Mc)[2] = (xtime)((data)[2]^m_a_to_mmask[0]);			\
	do_delay() \
	(St)[3] = (data)[3]^m_a_to_mmask[0];				\
	(Mc)[3] = (xtime)((data)[3]^m_a_to_mmask[0]);			\
	do_delay() \
	(St)[4] = (data)[4]^m_a_to_mmask[1];				\
	(Mc)[4] = (xtime)((data)[4]^m_a_to_mmask[1]);			\
	do_delay() \
	(St)[5] = (data)[5]^m_a_to_mmask[1];				\
	(Mc)[5] = (xtime)((data)[5]^m_a_to_mmask[1]);			\
	do_delay() \
	(St)[6] = (data)[6]^m_a_to_mmask[1];				\
	(Mc)[6] = (xtime)((data)[6]^m_a_to_mmask[1]);			\
	do_delay() \
	(St)[7] = (data)[7]^m_a_to_mmask[1];				\
	(Mc)[7] = (xtime)((data)[7]^m_a_to_mmask[1]);			\
	do_delay() \
	(St)[8] = (data)[8]^m_a_to_mmask[2];				\
	(Mc)[8] = (xtime)((data)[8]^m_a_to_mmask[2]);			\
	do_delay() \
	(St)[9] = (data)[9]^m_a_to_mmask[2];				\
	(Mc)[9] = (xtime)((data)[9]^m_a_to_mmask[2]);			\
	do_delay() \
	(St)[10] = (data)[10]^m_a_to_mmask[2];				\
	(Mc)[10] = (xtime)((data)[10]^m_a_to_mmask[2]);			\
	do_delay() \
	(St)[11] = (data)[11]^m_a_to_mmask[2];				\
	(Mc)[11] = (xtime)((data)[11]^m_a_to_mmask[2]);			\
	do_delay() \
	(St)[12] = (data)[12]^m_a_to_mmask[3];				\
	(Mc)[12] = (xtime)((data)[12]^m_a_to_mmask[3]);			\
	do_delay() \
	(St)[13] = (data)[13]^m_a_to_mmask[3];				\
	(Mc)[13] = (xtime)((data)[13]^m_a_to_mmask[3]);			\
	do_delay() \
	(St)[14] = (data)[14]^m_a_to_mmask[3];				\
	(Mc)[14] = (xtime)((data)[14]^m_a_to_mmask[3]);			\
	do_delay() \
	(St)[15] = (data)[15]^m_a_to_mmask[3];				\
	(Mc)[15] = (xtime)((data)[15]^m_a_to_mmask[3]);			\
	do_delay() \
	data[0] = (Mc[0])^((Mc[4])^St[4])^St[8]^St[12]; \
	data[1] = St[9]^(Mc[1])^((Mc[5])^St[5])^St[13]; \
	data[2] = St[10]^St[14]^(Mc[2])^((Mc[6])^St[6]); \
	data[3] = ((Mc[7])^St[7])^St[11]^St[15]^(Mc[3]); \
	do_delay() \
	data[4] = (Mc[4])^((Mc[8])^St[8])^St[0]^St[12]; \
	data[5] = St[1]^(Mc[5])^((Mc[9])^St[9])^St[13]; \
	data[6] = St[2]^St[10]^(Mc[6])^((Mc[10])^St[14]); \
	data[7] = ((Mc[7])^St[3])^St[11]^St[15]^(Mc[11]); \
	do_delay() \
	data[8] = (Mc[8])^((Mc[12])^St[0])^St[4]^St[12]; \
	data[9] = St[1]^(Mc[9])^((Mc[13])^St[5])^St[13]; \
	data[10] = St[2]^St[6]^(Mc[10])^((Mc[14])^St[14]); \
	data[11] = ((Mc[11])^St[3])^St[7]^St[15]^(Mc[15]); \
	do_delay() \
	data[12] = (Mc[12])^((Mc[0])^St[0])^St[4]^St[8]; \
	data[13] = St[1]^(Mc[13])^((Mc[1])^St[5])^St[9]; \
	data[14] = St[2]^St[6]^(Mc[14])^((Mc[2])^St[10]); \
	data[15] = ((Mc[15])^St[3])^St[7]^St[11]^(Mc[3]); \
}

void transpose(unsigned char data[])
{
	unsigned char temp;

	temp = data[1];
	data[1] = data[4];
	data[4] = temp;

	temp = data[2];
	data[2] = data[8];
	data[8] = temp;

	temp = data[3];
	data[3] = data[12];
	data[12] = temp;

	temp = data[6];
	data[6] = data[9];
	data[9] = temp;

	temp = data[7];
	data[7] = data[13];
	data[13] = temp;

	temp = data[11];
	data[11] = data[14];
	data[14] = temp;
}

#define transpose_Macro(data, temp)	\
{									\
	(temp) = (data)[1];				\
	(data)[1] = (data)[4];			\
	(data)[4] = (temp);				\
	(temp) = (data)[2];				\
	(data)[2] = (data)[8];			\
	(data)[8] = (temp);				\
	(temp) = (data)[3];				\
	(data)[3] = (data)[12];			\
	(data)[12] = (temp);			\
	(temp) = (data)[6];				\
	(data)[6] = (data)[9];			\
	(data)[9] = (temp);				\
	(temp) = (data)[7];				\
	(data)[7] = (data)[13];			\
	(data)[13] = (temp);			\
	(temp) = (data)[11];			\
	(data)[11] = (data)[14];		\
	(data)[14] = (temp);			\
}

void round_function(unsigned char T[], unsigned char CT[])
{
	do_delay()
	T[0] = two_time_SBox[CT[0]]^three_time_SBox[CT[5]]^SBox1[CT[10]]^SBox1[CT[15]];
	T[1] = SBox1[CT[0]]^two_time_SBox[CT[5]]^three_time_SBox[CT[10]]^SBox1[CT[15]];
	T[2] = SBox1[CT[0]]^SBox1[CT[5]]^two_time_SBox[CT[10]]^three_time_SBox[CT[15]];
	T[3] = three_time_SBox[CT[0]]^SBox1[CT[5]]^SBox1[CT[10]]^two_time_SBox[CT[15]];
	do_delay()
	T[4] = two_time_SBox[CT[4]]^three_time_SBox[CT[9]]^SBox1[CT[14]]^SBox1[CT[3]];
	T[5] = SBox1[CT[4]]^two_time_SBox[CT[9]]^three_time_SBox[CT[14]]^SBox1[CT[3]];
	T[6] = SBox1[CT[4]]^SBox1[CT[9]]^two_time_SBox[CT[14]]^three_time_SBox[CT[3]];
	T[7] = three_time_SBox[CT[4]]^SBox1[CT[9]]^SBox1[CT[14]]^two_time_SBox[CT[3]];
	do_delay()
	T[8] = two_time_SBox[CT[8]]^three_time_SBox[CT[13]]^SBox1[CT[2]]^SBox1[CT[7]];
	T[9] = SBox1[CT[8]]^two_time_SBox[CT[13]]^three_time_SBox[CT[2]]^SBox1[CT[7]];
	T[10] = SBox1[CT[8]]^SBox1[CT[13]]^two_time_SBox[CT[2]]^three_time_SBox[CT[7]];
	T[11] = three_time_SBox[CT[8]]^SBox1[CT[13]]^SBox1[CT[2]]^two_time_SBox[CT[7]];
	do_delay()
	T[12] = two_time_SBox[CT[12]]^three_time_SBox[CT[1]]^SBox1[CT[6]]^SBox1[CT[11]];
	T[13] = SBox1[CT[12]]^two_time_SBox[CT[1]]^three_time_SBox[CT[6]]^SBox1[CT[11]];
	T[14] = SBox1[CT[12]]^SBox1[CT[1]]^two_time_SBox[CT[6]]^three_time_SBox[CT[11]];
	T[15] = three_time_SBox[CT[12]]^SBox1[CT[1]]^SBox1[CT[6]]^two_time_SBox[CT[11]];
}

#define round_function_Macro(T, CT)														\
{	do_delay()																			\
	(T)[0] = two_time_SBox[(CT)[0]]^three_time_SBox[(CT)[5]]^SBox1[(CT)[10]]^SBox1[(CT)[15]];		\
	(T)[1] = SBox1[(CT)[0]]^two_time_SBox[(CT)[5]]^three_time_SBox[(CT)[10]]^SBox1[(CT)[15]];		\
	(T)[2] = SBox1[(CT)[0]]^SBox1[(CT)[5]]^two_time_SBox[(CT)[10]]^three_time_SBox[(CT)[15]];		\
	(T)[3] = three_time_SBox[(CT)[0]]^SBox1[(CT)[5]]^SBox1[(CT)[10]]^two_time_SBox[(CT)[15]];		\
	do_delay()																						\
	(T)[4] = two_time_SBox[(CT)[4]]^three_time_SBox[(CT)[9]]^SBox1[(CT)[14]]^SBox1[(CT)[3]];		\
	(T)[5] = SBox1[(CT)[4]]^two_time_SBox[(CT)[9]]^three_time_SBox[(CT)[14]]^SBox1[(CT)[3]];		\
	(T)[6] = SBox1[(CT)[4]]^SBox1[(CT)[9]]^two_time_SBox[(CT)[14]]^three_time_SBox[(CT)[3]];		\
	(T)[7] = three_time_SBox[(CT)[4]]^SBox1[(CT)[9]]^SBox1[(CT)[14]]^two_time_SBox[(CT)[3]];		\
	do_delay()																						\
	(T)[8] = two_time_SBox[(CT)[8]]^three_time_SBox[(CT)[13]]^SBox1[(CT)[2]]^SBox1[(CT)[7]];		\
	(T)[9] = SBox1[(CT)[8]]^two_time_SBox[(CT)[13]]^three_time_SBox[(CT)[2]]^SBox1[(CT)[7]];		\
	(T)[10] = SBox1[(CT)[8]]^SBox1[(CT)[13]]^two_time_SBox[(CT)[2]]^three_time_SBox[(CT)[7]];		\
	(T)[11] = three_time_SBox[(CT)[8]]^SBox1[(CT)[13]]^SBox1[(CT)[2]]^two_time_SBox[(CT)[7]];		\
	do_delay()																					\
	(T)[12] = two_time_SBox[(CT)[12]]^three_time_SBox[(CT)[1]]^SBox1[(CT)[6]]^SBox1[(CT)[11]];	\
	(T)[13] = SBox1[(CT)[12]]^two_time_SBox[(CT)[1]]^three_time_SBox[(CT)[6]]^SBox1[(CT)[11]];	\
	(T)[14] = SBox1[(CT)[12]]^SBox1[(CT)[1]]^two_time_SBox[(CT)[6]]^three_time_SBox[(CT)[11]];	\
	(T)[15] = three_time_SBox[(CT)[12]]^SBox1[(CT)[1]]^SBox1[(CT)[6]]^two_time_SBox[(CT)[11]];	\
}

void AES_encrypt_original1(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{	
	unsigned int cnt_i;
	
	switch(RN)
	{
	case 0:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		add_RKey(CT, RKey[0]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		break;
	case 10:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		m_sub_Bytes(CT, ONE_ARRAY_SBOX);
		shift_Rows(CT);
		add_RKey(CT, RKey[10]); 
			for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask_a;
	}
		break;
	default:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		m_sub_Bytes(CT, ONE_ARRAY_SBOX);
		shift_Rows(CT);
		m_mix_Columns(CT);
		add_RKey(CT, RKey[RN]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_original1_Macro(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned char temp;
	unsigned char St[16], Mc[16];
	unsigned int cnt_i;

	switch(RN)
	{
	case 0:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		add_RKey_Macro(CT, RKey[0]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		break;
	case 10:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		m_sub_Bytes1_Macro(CT);
		shift_Rows_Macro(CT, temp);
		add_RKey_Macro(CT, RKey[10]); 
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask_a;
	}
		break;
	default:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		m_sub_Bytes1_Macro(CT);
		shift_Rows_Macro(CT, temp);
		m_mix_Columns_Macro(CT, St, Mc);
		for(cnt_i = 0; cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mmask_a_to_m[cnt_i & 0x03];
	}
		add_RKey_Macro(CT, RKey[RN]); 
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_original2(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned int cnt_i;

	switch(RN)
	{
	case 0:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		add_RKey(CT, RKey[0]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		break;
	case 10:
		sub_Bytes(CT, TWO_ARRAY_SBOX);
		shift_Rows(CT);
		add_RKey(CT, RKey[10]); 
		break;
	default:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		sub_Bytes(CT, TWO_ARRAY_SBOX);
		shift_Rows(CT);
		mix_Columns(CT);
		for(cnt_i = 0; cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mmask_a_to_m[cnt_i & 0x03];
	}
		add_RKey(CT, RKey[RN]); 
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_original2_Macro(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned char temp;
	unsigned int cnt_i;
	unsigned char St[16], Mc[16];

	switch(RN)
	{
	case 0:
    for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		add_RKey_Macro(CT, RKey[0]);
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		break;
	case 10:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		sub_Bytes2_Macro(CT);
		shift_Rows_Macro(CT, temp);
		add_RKey_Macro(CT, RKey[10]); 
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		break;
	default:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		sub_Bytes2_Macro(CT);
		shift_Rows_Macro(CT, temp);
		mix_Columns_Macro(CT, St, Mc);
	for(cnt_i = 0; cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mmask_a_to_m[cnt_i & 0x03];
	}
		add_RKey_Macro(CT, RKey[RN]);
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_Ttable(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned char cnt_i, cnt_j;
	unsigned char T[16] = {0x00, };
	unsigned char St[16] = {0,}, Mc[16] = {0,};

	switch(RN)
	{
	case 0:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		add_RKey(CT, RKey[0]);
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		break;
	case 10:
		sub_Bytes(CT, ONE_ARRAY_SBOX);
		shift_Rows(CT);
		add_RKey(CT, RKey[10]); 
		break;
	default:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		m_sub_Bytes(DM, ONE_ARRAY_SBOX);
		shift_Rows(DM);
	for(cnt_i = 0; cnt_i < 16; cnt_i++) 
	{	do_delay()
		St[cnt_i] = DM[cnt_i]^m_a_to_mmask[cnt_i & 0x03];
		Mc[cnt_i] = xtime(St[cnt_i]);
	}
		round_function(T, CT);
		for(cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			CT[cnt_j] = T[cnt_j];
		}
		add_RKey(CT, RKey[RN]);
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_Ttable_Macro(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned char cnt_j, cnt_i;
	unsigned char T[16] = {0x00, };
	unsigned char St[16], Mc[16];

	switch(RN)
	{
	case 0:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		add_RKey_Macro(CT, RKey[0]);
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		break;
	case 10:
		sub_Bytes1_Macro(CT);
		shift_Rows_Macro(CT, T[0]);
		add_RKey_Macro(CT, RKey[10]); 
		break;
	default:
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
		sub_Bytes1_Macro(DM);
		shift_Rows_Macro(DM, T[0]);
		DM_mix_Columns_Macro(DM, St, Mc);
		round_function_Macro(T, CT);

		for(cnt_j = 0; cnt_j < 16; cnt_j++)
		{
			CT[cnt_j] = T[cnt_j];
		}
		add_RKey_Macro(CT, RKey[RN]);
	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		DM[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_bertoni(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned char cnt_i;

	switch(RN)
	{
	case 0:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		transpose(CT);
		transpose(RKey[0]);
		add_RKey(CT, RKey[0]);
		transpose(CT);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		break;
	case 10:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		transpose(CT);
		m_sub_Bytes(CT, ONE_ARRAY_SBOX);
		shift_Rows_bertoni(CT);
		transpose(RKey[10]); 
		add_RKey(CT, RKey[10]); 
		transpose(CT);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask_a;
	}
		break;
	default:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		transpose(CT);
		m_sub_Bytes(CT, ONE_ARRAY_SBOX);
		shift_Rows_bertoni(CT);
		m_mix_Columns_bertoni(CT);
		for(cnt_i = 0; cnt_i < 16; cnt_i++)
		{
			CT[cnt_i] = CT[cnt_i] ^ mmask_a_to_m[cnt_i >> 2];
		}
		transpose(RKey[RN]);
		add_RKey(CT, RKey[RN]);
		transpose(CT);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_bertoni_Macro(unsigned char CT[], unsigned char RKey[][16], unsigned char RN, unsigned char *DM)
{
	unsigned int cnt_i;
	unsigned char temp[16], temp2[16];

	switch(RN)
	{
	case 0:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		transpose_Macro(CT, temp[0]);
		transpose_Macro(RKey[0], temp[0]);
		add_RKey_Macro(CT, RKey[0]);
		transpose_Macro(CT, temp[0]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		break;
	case 10:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		transpose_Macro(CT, temp[0]);
		m_sub_Bytes1_Macro(CT);
		shift_Rows_bertoni_Macro(CT, temp[0]);
		transpose_Macro(RKey[10], temp[0]); 
		add_RKey_Macro(CT, RKey[10]); 
		transpose_Macro(CT, temp[0]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask_a;
	}
		break;
	default:
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
		transpose_Macro(CT, temp[0]);
		m_sub_Bytes1_Macro(CT);
		shift_Rows_bertoni_Macro(CT, temp[0]);
		m_mix_Columns_bertoni_Macro(CT, temp, temp2);
		for(cnt_i = 0; cnt_i < 16; cnt_i++)
		{
			CT[cnt_i] = CT[cnt_i] ^ mmask_a_to_m[cnt_i >> 2];
		}
		transpose_Macro(RKey[RN], temp[0]);
		add_RKey_Macro(CT, RKey[RN]);
		transpose_Macro(CT, temp[0]);
		for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] ^= mask;
	}
	}
}

void AES_encrypt_shuffle(unsigned char *PT,unsigned char *RKey[16],unsigned char *CT, unsigned char *SFF)
{
	int cnt_i;
	unsigned char shuffle;
	unsigned char RN;
	unsigned char DM[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

	for(cnt_i = 0;cnt_i < 16; cnt_i++)
	{
		CT[cnt_i] = PT[cnt_i];
	}
	for(RN=0;RN<11;RN++)
	{
		shuffle = SFF[RN];
		shuffle = CC % 8;
		switch (shuffle)
		{
		case 0 : 
			AES_encrypt_original1(CT, RKey, RN, DM);
			break;
		case 1 : 
			AES_encrypt_original2(CT, RKey, RN, DM);
			break;
		case 2 : 
			AES_encrypt_Ttable(CT, RKey, RN, DM);
			break;
		case 3 : 
			AES_encrypt_bertoni(CT, RKey, RN, DM);
			break;
		case 4 : 
			AES_encrypt_original1_Macro(CT, RKey, RN, DM);
			break;
		case 5 : 
			AES_encrypt_original2_Macro(CT, RKey, RN, DM);
			break;
		case 6 : 
			AES_encrypt_Ttable_Macro(CT, RKey, RN, DM);
			break;
		default : 
			AES_encrypt_bertoni_Macro(CT, RKey, RN, DM);
		}
	}
	CC++;
}

void aes_indep_init(void){
    //Get existing seed
	
    seed = eeprom_read_byte(0);
	srand(seed);
	seed = random();
	eeprom_write_byte(0, seed);
	srand(0);
}

void aes_indep_key(uint8_t * key){
	// init key here
	unsigned int i;

    for (i = 0; i < 16; i++){
        _stored_key[i] = key[i];
    }
    
  	AES_Key_Gen(Round_Key, _stored_key);
		
		for(i=0;i<11;i++)
	{
		SV[i] = random() % 8;
	}

	mask = random() & 0xff;
	mask_a = random() & 0xff;

	for(i=0;i<256;i++)
	{
		m_sbox1[i^mask] = SBox1[i]^mask_a;
	}

	for(i=0;i<4;i++)
	{
		mmask[i] = random() & 0xff;
		mmask_t[i] = xtime(mmask[i]);
		m_a_to_mmask[i] = mmask[i] ^ mask_a;
	}
	
	mmask_a[0] = (mmask_t[0])^((mmask_t[1])^mmask[1])^mmask[2]^mmask[3];
	mmask_a[1] = mmask[0]^(mmask_t[1])^((mmask_t[2])^mmask[2])^mmask[3];
	mmask_a[2] = mmask[0]^mmask[1]^(mmask_t[2])^((mmask_t[3])^mmask[3]);
	mmask_a[3] = ((mmask_t[0])^mmask[0])^mmask[1]^mmask[2]^(mmask_t[3]);

	for(i=0;i<4;i++)
	{
		mmask_a_to_m[i] = mmask_a[i] ^ mask;
	}
}

void aes_indep_enc(uint8_t * pt){
		unsigned int i;
	
	AES_encrypt_shuffle(pt,Round_Key,_stored_ct,SV);
    
    for (i = 0; i < 16; i++){
        pt[i] = _stored_ct[i];
    }
}

