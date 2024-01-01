#include <Windows.h>
#include <bcrypt.h> 
#include <stdio.h>
#include <stdlib.h> 
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define SUCCESS 1 
#define FAIL 0

#define PrivateKeyBLOB_Size 283

#define PRINT_PLAINTEXT 1
#define PRINT_CIPHERTEXT 2

BYTE ciphertext[128] = { 0x19, 0xE2, 0xE8, 0x98, 0xEA, 0x72, 0x92, 0x76, 0xD8, 0x1B, 0x3E, 0x15,
	0x39, 0x9D, 0xF9, 0xEF, 0xC7, 0xB2, 0xD0, 0xF2, 0xFC, 0x13, 0x8B, 0x9D,
	0x05, 0xE2, 0xF2, 0xF1, 0xB1, 0xB1, 0xF9, 0xA9, 0x9F, 0xA4, 0x7E, 0x75,
	0xBD, 0x2F, 0x21, 0x3F, 0xEA, 0x7D, 0xAB, 0x77, 0x01, 0xEF, 0x36, 0xF3,
	0x5A, 0xDC, 0x47, 0x48, 0xE4, 0x1F, 0x96, 0xD0, 0x02, 0x23, 0x13, 0x4A,
	0x60, 0x61, 0x62, 0xC7, 0x8A, 0x56, 0xF7, 0x1D, 0x47, 0x64, 0xC2, 0xB3,
	0xD3, 0x3B, 0x27, 0x10, 0x5C, 0x0A, 0x15, 0x3F, 0x0E, 0x46, 0xEC, 0xD7,
	0xE1, 0x59, 0xBE, 0xD0, 0xF8, 0x36, 0x1C, 0x6A, 0x80, 0x2E, 0xEF, 0xB7,
	0x46, 0x9D, 0xFF, 0xF5, 0xDB, 0xBB, 0x17, 0xA7, 0x3F, 0x2E, 0x01, 0x7A,
	0x5B, 0xD7, 0x65, 0x6B, 0x7D, 0xE8, 0xFF, 0x5A, 0x91, 0x57, 0x75, 0x93,
	0x38, 0xCE, 0x0C, 0x03, 0x40, 0xA1, 0xF8, 0xE6 };

PBYTE plaintext = NULL;
DWORD plaintextLength = 0;

BYTE e[3] = { 0x01, 0x00, 0x01 };
BYTE n[128] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x4F, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFE, 0xFF,
	0xFF, 0xFF, 0xF3, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4C, 0x41,
	0x00, 0x00, 0x00, 0x03, 0xE3, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xDF, 0xFF, 0xC1, 0xC4, 0x00, 0x00, 0x00, 0xB3,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xC7,
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xD4, 0x4D, 0x5F };

BYTE p[64] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xF0, 0x71 };

BYTE q[64] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0xCF };


typedef struct _PrivateKey_BLOB {
	ULONG Magic;                // Magic number of RSAKEY 
	ULONG BitLength;            // The size(bit) of the modulus N  
	ULONG cbPublicExp;          // The size(byte) of the Public exponent e
	ULONG cbModulus;            // The size(byte) of the modulus N 
	ULONG cbPrime1;             // The size(byte) of the p 
	ULONG cbPrime2;             // The size(byte) of the q 
	BYTE PublicExponent[3];     // Array of Public Exponent e; e = 65537 = 0x01, 0x00, 0x01
	BYTE Modulus[128];          // Array of Modulus n; In RSA-4096, n = 4096-bit = 512-byte
	BYTE p[64];                // Array of Prime p
	BYTE q[64];                // Array of Prime q
} PrivateKey_BLOB;

void PRINT(BYTE* arr, DWORD size, int flag)
{
	if (flag == PRINT_PLAINTEXT) {
		printf("\nplaintext : ");
		for (int i = 0; i < size; i++) {
			if (i % 16 == 0) printf("\n");
			printf("0x%02x\t", arr[i]);
		}
		printf("\n");
	}

	if (flag == PRINT_CIPHERTEXT) {
		printf("\nciphertext : ");
		for (int i = 0; i < size; i++) {
			if (i % 16 == 0) printf("\n");
			printf("0x%02x\t", arr[i]);
		}
		printf("\n");
	}
}

void GET_ALG_HANDLE(BCRYPT_ALG_HANDLE* handle)
{
	NTSTATUS status = BCryptOpenAlgorithmProvider(
		handle,                 // Algorithm Handle pointer 
		BCRYPT_RSA_ALGORITHM,   // Cryptographic Algorithm name 
		NULL,                   // 
		0);                     // Flags 

	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptOpenAlgorithmProvider fail\n", status);
		return;
	}

	return;
}


int SettingPrivateKeyBLOB(PrivateKey_BLOB** BLOB)
{
	*BLOB = (PrivateKey_BLOB*)(malloc)(sizeof(PrivateKey_BLOB));
	if (*BLOB == NULL) return FAIL;

	(*BLOB)->Magic = BCRYPT_RSAPRIVATE_MAGIC;
	(*BLOB)->BitLength = 1024;
	(*BLOB)->cbPublicExp = 3;
	(*BLOB)->cbModulus = 128;
	(*BLOB)->cbPrime1 = 64;
	(*BLOB)->cbPrime2 = 64;
	memcpy((*BLOB)->PublicExponent, e, 3);
	memcpy((*BLOB)->Modulus, n, 128);
	memcpy((*BLOB)->p, p, 64);
	memcpy((*BLOB)->q, q, 64);

	return SUCCESS;
}


void FreePrivateKeyBLOB(PrivateKey_BLOB** BLOB)
{
	if ((*BLOB) == NULL) return;

	free(*BLOB);
	return;
}


void RSA_4096_Test(BCRYPT_ALG_HANDLE ALG_HANDLE)                // RSA4096/PKCS1
{
	NTSTATUS status = 0;
	DWORD bufferSize = 0;
	BCRYPT_KEY_HANDLE PRIVATEKEY_HANDLE = NULL;

	PrivateKey_BLOB* RSA_PRIVATEKEY = NULL;                       // PrivateKeyBLOB Setting         
	if (!SettingPrivateKeyBLOB(&RSA_PRIVATEKEY)) {
		printf("Memory Allocation Fail...\n");
		FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
		return;
	}

	status = BCryptImportKeyPair(
		ALG_HANDLE,                        // CNG Algorithm Handle 
		NULL,                              // Not use 
		BCRYPT_RSAPRIVATE_BLOB,            // Type of blob
		&PRIVATEKEY_HANDLE,                // A pointer to Key Handle
		(PBYTE)&RSA_PRIVATEKEY->Magic,     // Address of a buffer that contains the key blob
		PrivateKeyBLOB_Size,               // Size of the buffer that contains the key blob 
		BCRYPT_NO_KEY_VALIDATION);         // Flags 
	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptImportKeyPair fail\n", status);
		BCryptDestroyKey(PRIVATEKEY_HANDLE);
		FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
		return;
	}


	status = BCryptDecrypt(                         // Calculate plaintext length
		PRIVATEKEY_HANDLE,       // KEY HANDLE
		ciphertext,              // Address of the buffer that contains the ciphertext 
		sizeof(ciphertext),      // Size of the buffer that contains the ciphertext 
		NULL,                    // A pointer to padding info used with asymetric; OEAP
		NULL,                    // Address of the buffer that contains the Initial Vector 
		0,                       // Size of the buffer that contains the Initial Vector
		NULL,                    // Address of the buffer that receives the plaintext. 
		0,                       // Size of the buffer that receives the plaintext
		&plaintextLength,        // Variable that receives number of bytes copied to plaintext buffer
		BCRYPT_PAD_PKCS1);       // Flags : Padding 
	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptDecrypt fail(Calculate plaintextLength)\n", status);
		BCryptDestroyKey(PRIVATEKEY_HANDLE);
		FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
		return;
	}
	else
	{
		plaintext = (PBYTE)calloc(plaintextLength, sizeof(BYTE));
		if (plaintext == NULL)
		{
			printf("Memory Allocation(plaintext) Fail...\n");
			BCryptDestroyKey(PRIVATEKEY_HANDLE);
			FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
			return;
		}
	}


	status = BCryptDecrypt(                         // Decrypt data
		PRIVATEKEY_HANDLE,       // KEY HANDLE
		ciphertext,              // Address of the buffer that contains the ciphertext 
		sizeof(ciphertext),      // Size of the buffer that contains the ciphertext 
		NULL,                    // A pointer to padding info used with asymetric; OAEP
		NULL,                    // Address of the buffer that contains the Initial Vector 
		0,                       // Size of the buffer that contains the Initial Vector
		plaintext,               // Address of the buffer that receives the plaintext. 
		plaintextLength,         // Size of the buffer that receives the plaintext
		&plaintextLength,        // Variable that receives number of bytes copied to plaintext buffer
		BCRYPT_PAD_PKCS1);       // Flags : Padding 
	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptDecrypt fail\n", status);
		free(plaintext);
		BCryptDestroyKey(PRIVATEKEY_HANDLE);
		FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
		return;
	}

	PRINT(plaintext, plaintextLength, PRINT_PLAINTEXT);
	PRINT(ciphertext, sizeof(ciphertext), PRINT_CIPHERTEXT);

	free(plaintext);
	BCryptDestroyKey(PRIVATEKEY_HANDLE);
	plaintextLength = 0;
	FreePrivateKeyBLOB(&RSA_PRIVATEKEY);

	return;
}


int main()
{
	BCRYPT_ALG_HANDLE RSA_ALG = NULL;
	GET_ALG_HANDLE(&RSA_ALG);
	RSA_4096_Test(RSA_ALG);                         // RSA4096/PKCS1
	BCryptCloseAlgorithmProvider(RSA_ALG, 0);
	return 0;
}