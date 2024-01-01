#pragma once
#include <Windows.h>
#include <bcrypt.h> 
#include <stdio.h>
#include <stdlib.h> 
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define SUCCESS 1 
#define FAIL 0

#define PulbicKeyBLOB_Size 155

DWORD ciphertextLength = 0;

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

typedef struct _PublicKey_BLOB {
	ULONG Magic;                // Magic number of RSAKEY 
	ULONG BitLength;            // The size(bit) of the modulus N  
	ULONG cbPublicExp;          // The size(byte) of the Public exponent e;
	ULONG cbModulus;            // The size(byte) of the modulus N; 
	ULONG cbPrime1;             // The size(byte) of the p; 
	ULONG cbPrime2;             // The size(byte) of the q; 
	BYTE PublicExponent[3];     // Array of Public Exponent e; e = 65537 = 0x01, 0x00, 0x01
	BYTE Modulus[128];          // Array of Modulus n; In RSA-4096, n = 4096-bit = 512-byte
} PublicKey_BLOB;

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


int SettingPublicKeyBLOB(PublicKey_BLOB** BLOB)
{
	*BLOB = (PublicKey_BLOB*)(malloc)(sizeof(PublicKey_BLOB));
	if (*BLOB == NULL) return FAIL;

	(*BLOB)->Magic = BCRYPT_RSAPUBLIC_MAGIC;
	(*BLOB)->BitLength = 1024;
	(*BLOB)->cbPublicExp = 3;
	(*BLOB)->cbModulus = 128;
	(*BLOB)->cbPrime1 = 0;
	(*BLOB)->cbPrime2 = 0;
	memcpy((*BLOB)->PublicExponent, e, 3);
	memcpy((*BLOB)->Modulus, n, 128);

	return SUCCESS;
}


void FreePublicKeyBLOB(PublicKey_BLOB** BLOB)
{
	if ((*BLOB) == NULL) return;

	free(*BLOB);
	return;
}

void rsa_1024_enc(BCRYPT_ALG_HANDLE ALG_HANDLE, unsigned char* plain, unsigned char* cipher)
{
	PBYTE ciphertext = NULL;
	NTSTATUS status = 0;
	DWORD bufferSize = 0;
	BCRYPT_KEY_HANDLE PUBLICKEY_HANDLE = NULL;

	PublicKey_BLOB* RSA_PUBLICKEY = NULL;                       // PulicKeyBLOB Setting         
	if (!SettingPublicKeyBLOB(&RSA_PUBLICKEY)) {
		printf("Memory Allocation Fail...\n");
		FreePublicKeyBLOB(&RSA_PUBLICKEY);
		return;
	}

	status = BCryptImportKeyPair(
		ALG_HANDLE,                    // CNG Algorithm Handle 
		NULL,                          // Not use 
		BCRYPT_RSAPUBLIC_BLOB,         // Type of blob
		&PUBLICKEY_HANDLE,             // A pointer to Key Handle
		(PBYTE)&RSA_PUBLICKEY->Magic,  // Address of a buffer that contains the key blob
		PulbicKeyBLOB_Size,            // Size of the buffer that contains the key blob 
		BCRYPT_NO_KEY_VALIDATION);     // Flags 
	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptImportKeyPair fail\n", status);
		BCryptDestroyKey(PUBLICKEY_HANDLE);
		FreePublicKeyBLOB(&RSA_PUBLICKEY);
		return;
	}


	status = BCryptEncrypt(                         // Calculate ciphertext length
		PUBLICKEY_HANDLE,        // KEY HANDLE
		plain,               // Address of the buffer that contains the plaintext 
		sizeof(plain),       // Size of the buffer that contains the plaintext 
		NULL,                    // A pointer to padding info used with asymetric; OAEP
		NULL,                    // Address of the buffer that contains the Initial Vector 
		0,                       // Size of the buffer that contains the Initial Vector
		NULL,                    // Address of the buffer that receives the ciphertext. 
		0,                       // Size of the buffer that receives the ciphertext
		&ciphertextLength,       // Variable that receives number of bytes copied to ciphertext buffer
		BCRYPT_PAD_PKCS1);       // Flags : Padding 
	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptEncrypt fail(Calculate ciphertextLength)\n", status);
		BCryptDestroyKey(PUBLICKEY_HANDLE);
		FreePublicKeyBLOB(&RSA_PUBLICKEY);
		return;
	}
	else
	{
		ciphertext = (PBYTE)calloc(ciphertextLength, sizeof(BYTE));
		if (ciphertext == NULL)
		{
			printf("Memory Allocation(ciphertext) Fail...\n");
			BCryptDestroyKey(PUBLICKEY_HANDLE);
			FreePublicKeyBLOB(&RSA_PUBLICKEY);
			return;
		}
	}

	status = BCryptEncrypt(                         // Encrypt data
		PUBLICKEY_HANDLE,        // KEY HANDLE
		plain,               // Address of the buffer that contains the plaintext 
		sizeof(plain),       // Size of the buffer that contains the plaintext 
		NULL,                    // A pointer to padding info used with asymetric; OAEP
		NULL,                    // Address of the buffer that contains the Initial Vector 
		0,                       // Size of the buffer that contains the Initial Vector
		ciphertext,              // Address of the buffer that receives the ciphertext. 
		ciphertextLength,        // Size of the buffer that receives the ciphertext
		&bufferSize,             // Variable that receives number of bytes copied to ciphertext buffer
		BCRYPT_PAD_PKCS1);       // Flags : Padding 
	if (!NT_SUCCESS(status))
	{
		printf("Error Code : %x \n BCryptEncrypt fail\n", status);
		free(ciphertext);
		BCryptDestroyKey(PUBLICKEY_HANDLE);
		FreePublicKeyBLOB(&RSA_PUBLICKEY);
		return;
	}
	printf("%d\n\n", sizeof(ciphertext));
	memcpy(cipher, ciphertext, 128);
	free(ciphertext);
	BCryptDestroyKey(PUBLICKEY_HANDLE);
	ciphertextLength = 0;
	FreePublicKeyBLOB(&RSA_PUBLICKEY);
}

void r_enc(unsigned char* key, unsigned char* key_out)
{
	BCRYPT_ALG_HANDLE RSA_ALG = NULL;
	GET_ALG_HANDLE(&RSA_ALG);
	rsa_1024_enc(RSA_ALG, key, key_out);
	BCryptCloseAlgorithmProvider(RSA_ALG, 0);
}




#define PrivateKeyBLOB_Size 283
DWORD plaintextLength = 0;

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

void rsa_1024_dec(BCRYPT_ALG_HANDLE ALG_HANDLE, unsigned char* cipher, unsigned char* dec)
{
	PBYTE plaintext = NULL;
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
		cipher,              // Address of the buffer that contains the ciphertext 
		sizeof(cipher),      // Size of the buffer that contains the ciphertext 
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
		cipher,              // Address of the buffer that contains the ciphertext 
		sizeof(cipher),      // Size of the buffer that contains the ciphertext 
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
	memcpy(dec, plaintext, 32);
	free(plaintext);
	BCryptDestroyKey(PRIVATEKEY_HANDLE);
	plaintextLength = 0;
	FreePrivateKeyBLOB(&RSA_PRIVATEKEY);
}
void r_dec(unsigned char* key, unsigned char* key_out)
{
	BCRYPT_ALG_HANDLE RSA_ALG = NULL;
	GET_ALG_HANDLE(&RSA_ALG);
	rsa_1024_dec(RSA_ALG, key, key_out);
}