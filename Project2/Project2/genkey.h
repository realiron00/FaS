#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

void key_print(unsigned char* key, int size)
{
	for (int i = 0; i < size; i++) {
		printf("%02x ", key[i]);
	}
	printf("\n");
}

/************************************************************************************
 * sha256_hash : Hashes the data using SHA256
 * 
 * input: 
 * data - data to be hashed
 * data_len - length of the data
 * hash_out - buffer to store the hash
 * *********************************************************************************/
void sha256_hash(const unsigned char* data, int data_len, unsigned char* hash_out) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE pbHashObject = NULL;
	
	// Open the algorithm provider for SHA256
	NTSTATUS status = BCryptOpenAlgorithmProvider(
		&hAlg, 						// Algorithm handle pointer
		BCRYPT_SHA256_ALGORITHM, 	// Cryptographic algorithm name
		NULL,  						//
		0); 						// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptOpenAlgorithmProvider failed with error code 0x%x\n", status);
		return;
	}

	// Get the length of the hash
	status = BCryptGetProperty(
		hAlg,  					// Algorithm provider handle
		BCRYPT_OBJECT_LENGTH, 	// Property name
		(PBYTE)&cbHashObject, 	// Buffer to receive the object size
		sizeof(DWORD),  		// Size of the buffer
		&cbData,  				// Number of bytes copied to the buffer
		0); 					// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptGetProperty failed with error code 0x%x\n", status);
		return;
	}

	// Allocate the hash object
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (pbHashObject == NULL) {
		printf("Memory allocation failed\n");
		return;
	}

	// Create a hash object
	status = BCryptCreateHash(
		hAlg, 			// Algorithm provider handle
		&hHash, 		// Hash handle pointer
		pbHashObject,  	// Hash object buffer
		cbHashObject, 	// Size of the hash object buffer
		NULL,  			// Hash secret
		0, 				// Size of the hash secret
		0); 			// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptCreateHash failed with error code 0x%x\n", status);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Hash the data
	status = BCryptHashData(
		hHash, 			// Hash handle
		(PBYTE)data, 	// Data to be hashed
		data_len, 		// Length of the data
		0); 			// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptHashData failed with error code 0x%x\n", status);
		BCryptDestroyHash(hHash);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Get the length of the hash
	status = BCryptGetProperty(
		hAlg, 					// Algorithm  provider handle
		BCRYPT_HASH_LENGTH, 	// Property name
		(PBYTE)&cbHash, 		// Buffer to receive the length of the hash
		sizeof(DWORD), 			// Size of the buffer
		&cbData, 				// Number of bytes copied to the buffer
		0); 					// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptGetProperty failed with error code 0x%x\n", status);
		BCryptDestroyHash(hHash);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Finish the hash and retrieve the hash value
	status = BCryptFinishHash(
		hHash, 		// Hash handle
		hash_out, 	// Buffer to receive the hash value
		cbHash, 	// Size of the hash value buffer
		0); 		// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptFinishHash failed with error code 0x%x\n", status);
		BCryptDestroyHash(hHash);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Clean up resources
	BCryptDestroyHash(hHash);
	HeapFree(GetProcessHeap(), 0, pbHashObject);
}

/************************************************************************************
 * sha512_hash : Hashes the data using SHA512
 * 
 * input: 
 * data - data to be hashed
 * data_len - length of the data
 * hash_out - buffer to store the hash
 * *********************************************************************************/
void sha512_hash(const unsigned char* data, int data_len, unsigned char* hash_out) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE pbHashObject = NULL;

	// Open the algorithm provider for SHA512
	NTSTATUS status = BCryptOpenAlgorithmProvider(
		&hAlg,  					// Algorithm handle pointer
		BCRYPT_SHA512_ALGORITHM,  	// Cryptographic algorithm name
		NULL,  						//
		0); 						// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptOpenAlgorithmProvider failed with error code 0x%x\n", status);
		return;
	}

	// Get the length of the hash
	status = BCryptGetProperty(
		hAlg, 					// Algorithm provider handle
		BCRYPT_OBJECT_LENGTH, 	// Property name
		(PBYTE)&cbHashObject, 	// Buffer to receive the object size
		sizeof(DWORD), 			// Size of the buffer
		&cbData, 				// Number of bytes copied to the buffer
		0); 					// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptGetProperty failed with error code 0x%x\n", status);
		return;
	}

	// Allocate the hash object
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (pbHashObject == NULL) {
		printf("Memory allocation failed\n");
		return;
	}

	// Create a hash object
	status = BCryptCreateHash(
		hAlg, 			// Algorithm provider handle
		&hHash, 		// Hash handle pointer
		pbHashObject, 	// Hash object buffer
		cbHashObject, 	// Size of the hash object buffer
		NULL, 			// Hash secret
		0, 				// Size of the hash secret
		0);				// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptCreateHash failed with error code 0x%x\n", status);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Hash the data
	status = BCryptHashData(
		hHash, 			// Hash handle
		(PBYTE)data, 	// Data to be hashed
		data_len, 		// Length of the data
		0);				// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptHashData failed with error code 0x%x\n", status);
		BCryptDestroyHash(hHash);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Get the length of the hash
	status = BCryptGetProperty(
		hAlg, 					// Algorithm provider handle
		BCRYPT_HASH_LENGTH, 	// Property name
		(PBYTE)&cbHash, 		// Buffer to receive the length of the hash
		sizeof(DWORD), 			// Size of the buffer
		&cbData, 				// Number of bytes copied to the buffer
		0);						// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptGetProperty failed with error code 0x%x\n", status);
		BCryptDestroyHash(hHash);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Finish the hash and retrieve the hash value
	status = BCryptFinishHash(
		hHash, 		// Hash handle
		hash_out, 	// Buffer to receive the hash value
		cbHash, 	// Size of the hash value buffer
		0);			// Flags
	if (!NT_SUCCESS(status)) {
		printf("BCryptFinishHash failed with error code 0x%x\n", status);
		BCryptDestroyHash(hHash);
		HeapFree(GetProcessHeap(), 0, pbHashObject);
		return;
	}

	// Clean up resources
	BCryptDestroyHash(hHash);
	HeapFree(GetProcessHeap(), 0, pbHashObject);
}

/************************************************************************************
 * gen_key : Generates a 256/512 key by hashing a random number
 * 
 * input:
 * key_out - buffer to store the key
 * key_len - key length
 * *********************************************************************************/
void gen_key(unsigned char* key_out, int key_len) {
	unsigned char key[40]; 					// Buffer to store the randomly generated number
	BCRYPT_ALG_HANDLE alg_handle = NULL; 	// Bcrypt algorithm handle for random number generation
	
	// Open the algorithm provider for random number generation
	NTSTATUS status = BCryptOpenAlgorithmProvider(
		&alg_handle,			// Algorithm handle pointer
		BCRYPT_RNG_ALGORITHM, 	// Cryptographic algorithm name
		NULL, 					//
		0); 					// Flags
	if (!NT_SUCCESS(status)) {
		printf("Error Code : %x \n BCryptOpenAlgorithmProvider fail\n", status);
		return;
	}

	// Generate a random number
	status = BCryptGenRandom(
		alg_handle, 	// Algorithm provider handle
		key, 			// Buffer that receives the random number
		sizeof(key), 	// Size of the buffer that receives the random number
		0); 			// Flags; Additional entropy for the random number
	BCryptCloseAlgorithmProvider(alg_handle, 0);
	if (!NT_SUCCESS(status)) {
		printf("Error Code : %x \n BCryptGenRandom fail\n", status);
		return;
	}

	// Hash the random number to generate the key
	if (key_len == 256)
		sha256_hash(key, sizeof(key), key_out);	// Hash the key using SHA256
	else if (key_len == 512)
		sha512_hash(key, sizeof(key), key_out); // Hash the key using SHA512
	else
		printf("wrong key length!\n"); 			// Invalid key length provided
}