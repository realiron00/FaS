/*
	Win API: Cryptography Next Generation (CNG)
	This code is test code for sha256 hash function.

	Created by: Jincheol Park from Kookmin Univ.
	(Thanks to: YongJin Lee)
	Date: 2024.01.07
*/

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

BYTE plain_h[8] = {0x20, 0x19, 0x22, 0x33, 0x20, 0x19, 0x22, 0x33};

void PrintHex(unsigned char* buffer, size_t bufferSize) {
	for (size_t i = 0; i < bufferSize; ++i) {
		printf("%02x", buffer[i]);
	}
	printf("\n");
}

void sha256_test()
{
	BCRYPT_ALG_HANDLE hAlg = NULL;		// Algorithm handle
	BCRYPT_HASH_HANDLE hHash = NULL;	// Hash handle
	DWORD cbData = 0, hashlenth = 0;	// Size of the data to be hashed, Size of the hash
	PBYTE hashtext = NULL;				// A pointer to a buffer that receives the hash
	NTSTATUS status = 0;				// Status of the function

	status = BCryptOpenAlgorithmProvider(
		&hAlg,						// Algorithm handle pointer
		BCRYPT_SHA256_ALGORITHM,	// Algorithm identifier
		NULL,						//
		0);							// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptOpenAlgorithmProvider failed\n");
		return;
	}

	status = BCryptCreateHash(
		hAlg,		// Algorithm handle
		&hHash,		// Hash handle pointer
		NULL,		//
		0,			//
		NULL,		// 
		0,			// Size of the hash secret
		0);			// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptCreateHash failed\n");
		goto Cleanup;
	}

	status = BCryptHashData(
		hHash,				// Hash handle
		plain_h,			// Data to be hashed
		sizeof(plain_h),	// Size of the Data
		0);					// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptHashData failed\n");
		goto Cleanup;
	}

	status = BCryptGetProperty(		// Get the length of the hash
		hHash,						// Algorithm provider handle
		BCRYPT_HASH_LENGTH,			// Property name
		(PBYTE)&hashlenth,			// Buffer to receive the length of the hash
		sizeof(DWORD),				// Size of the buffer
		&cbData,					// Number of bytes copied to the buffer
		0);							// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptGetProperty failed\n");
		goto Cleanup;
	}

	hashtext = (PBYTE)malloc(hashlenth); // Allocate the hash buffer
	if (hashtext == NULL) {
		printf("Memory allocation failed\n");
		goto Cleanup;
	}

	status = BCryptFinishHash(	// Finish the hash
		hHash,					// Hash handle
		hashtext,				// Buffer that receives the hash
		hashlenth,				// Size of the hash buffer
		0);						// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptFinishHash failed\n");
		goto Cleanup;
	}

	PrintHex(hashtext, hashlenth);

Cleanup: // if error, clean the memory
	if (hHash) 
		BCryptDestroyHash(hHash);
	
	if (hAlg) 
		BCryptCloseAlgorithmProvider(hAlg, 0);

	if (hashtext)
		free(hashtext);
}

int main() {
	sha256_test();
	return 0;
}
