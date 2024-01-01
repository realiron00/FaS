//#include <Windows.h>
//#include <bcrypt.h> 
//#include <stdio.h>
//#include <stdlib.h> 
//#pragma comment(lib, "bcrypt.lib")
//
//#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
//#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
//
//#define PRINT_PLAINTEXT 1
//#define PRINT_CIPHERTEXT 2
//
//#define SUCCESS 1 
//#define FAIL 0
//
//#define PulbicKeyBLOB_Size 155
//
//BYTE plaintext[32] = { 0x05, 0xC6, 0x80, 0x8B, 0x75, 0xB6, 0x93, 0x15, 0x09, 0xE7, 0x70, 0x49,
//	0xA0, 0x23, 0xE7, 0xCF, 0xF4, 0x29, 0xD7, 0x88, 0x53, 0x35, 0xC2, 0xFB,
//	0x49, 0x3A, 0xC4, 0x9A, 0x2A, 0xA9, 0x81, 0xE9 };
//
//PBYTE ciphertext = NULL;
//DWORD ciphertextLength = 0;
//
//BYTE e[3] = { 0x01, 0x00, 0x01 };
//BYTE n[128] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x4F, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFE, 0xFF,
//	0xFF, 0xFF, 0xF3, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00,
//	0x00, 0x00, 0x00, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4C, 0x41,
//	0x00, 0x00, 0x00, 0x03, 0xE3, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xFF, 0xFF, 0xFF, 0xDF, 0xFF, 0xC1, 0xC4, 0x00, 0x00, 0x00, 0xB3,
//	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xC7,
//	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xD4, 0x4D, 0x5F };
//
//typedef struct _PublicKey_BLOB {
//	ULONG Magic;                // Magic number of RSAKEY 
//	ULONG BitLength;            // The size(bit) of the modulus N  
//	ULONG cbPublicExp;          // The size(byte) of the Public exponent e;
//	ULONG cbModulus;            // The size(byte) of the modulus N; 
//	ULONG cbPrime1;             // The size(byte) of the p; 
//	ULONG cbPrime2;             // The size(byte) of the q; 
//	BYTE PublicExponent[3];     // Array of Public Exponent e; e = 65537 = 0x01, 0x00, 0x01
//	BYTE Modulus[128];          // Array of Modulus n; In RSA-4096, n = 4096-bit = 512-byte
//} PublicKey_BLOB;
//
//
//void PRINT(BYTE* arr, DWORD size, int flag)
//{
//	if (flag == PRINT_PLAINTEXT) {
//		printf("\nplaintext : ");
//		for (int i = 0; i < size; i++) {
//			if (i % 16 == 0) printf("\n");
//			printf("0x%02x\t", arr[i]);
//		}
//		printf("\n");
//	}
//
//	if (flag == PRINT_CIPHERTEXT) {
//		printf("\nciphertext : ");
//		for (int i = 0; i < size; i++) {
//			if (i % 16 == 0) printf("\n");
//			printf("%02x ", arr[i]);
//		}
//		printf("\n");
//	}
//}
//
//
//void GET_ALG_HANDLE(BCRYPT_ALG_HANDLE* handle)
//{
//	NTSTATUS status = BCryptOpenAlgorithmProvider(
//		handle,                 // Algorithm Handle pointer 
//		BCRYPT_RSA_ALGORITHM,   // Cryptographic Algorithm name 
//		NULL,                   // 
//		0);                     // Flags 
//
//	if (!NT_SUCCESS(status))
//	{
//		printf("Error Code : %x \n BCryptOpenAlgorithmProvider fail\n", status);
//		return;
//	}
//
//	return;
//}
//
//
//int SettingPublicKeyBLOB(PublicKey_BLOB** BLOB)
//{
//	*BLOB = (PublicKey_BLOB*)(malloc)(sizeof(PublicKey_BLOB));
//	if (*BLOB == NULL) return FAIL;
//
//	(*BLOB)->Magic = BCRYPT_RSAPUBLIC_MAGIC;
//	(*BLOB)->BitLength = 1024;
//	(*BLOB)->cbPublicExp = 3;
//	(*BLOB)->cbModulus = 128;
//	(*BLOB)->cbPrime1 = 0;
//	(*BLOB)->cbPrime2 = 0;
//	memcpy((*BLOB)->PublicExponent, e, 3);
//	memcpy((*BLOB)->Modulus, n, 128);
//
//	return SUCCESS;
//}
//
//
//void FreePublicKeyBLOB(PublicKey_BLOB** BLOB)
//{
//	if ((*BLOB) == NULL) return;
//
//	free(*BLOB);
//	return;
//}
//
//
//void RSA_4096_Test(BCRYPT_ALG_HANDLE ALG_HANDLE)                // RSA4096/PKCS1
//{
//	NTSTATUS status = 0;
//	DWORD bufferSize = 0;
//	BCRYPT_KEY_HANDLE PUBLICKEY_HANDLE = NULL;
//
//	PublicKey_BLOB* RSA_PUBLICKEY = NULL;                       // PulicKeyBLOB Setting         
//	if (!SettingPublicKeyBLOB(&RSA_PUBLICKEY)) {
//		printf("Memory Allocation Fail...\n");
//		FreePublicKeyBLOB(&RSA_PUBLICKEY);
//		return;
//	}
//
//	status = BCryptImportKeyPair(
//		ALG_HANDLE,                    // CNG Algorithm Handle 
//		NULL,                          // Not use 
//		BCRYPT_RSAPUBLIC_BLOB,         // Type of blob
//		&PUBLICKEY_HANDLE,             // A pointer to Key Handle
//		(PBYTE)&RSA_PUBLICKEY->Magic,  // Address of a buffer that contains the key blob
//		PulbicKeyBLOB_Size,            // Size of the buffer that contains the key blob 
//		BCRYPT_NO_KEY_VALIDATION);     // Flags 
//	if (!NT_SUCCESS(status))
//	{
//		printf("Error Code : %x \n BCryptImportKeyPair fail\n", status);
//		BCryptDestroyKey(PUBLICKEY_HANDLE);
//		FreePublicKeyBLOB(&RSA_PUBLICKEY);
//		return;
//	}
//
//
//	status = BCryptEncrypt(                         // Calculate ciphertext length
//		PUBLICKEY_HANDLE,        // KEY HANDLE
//		plaintext,               // Address of the buffer that contains the plaintext 
//		sizeof(plaintext),       // Size of the buffer that contains the plaintext 
//		NULL,                    // A pointer to padding info used with asymetric; OAEP
//		NULL,                    // Address of the buffer that contains the Initial Vector 
//		0,                       // Size of the buffer that contains the Initial Vector
//		NULL,                    // Address of the buffer that receives the ciphertext. 
//		0,                       // Size of the buffer that receives the ciphertext
//		&ciphertextLength,       // Variable that receives number of bytes copied to ciphertext buffer
//		BCRYPT_PAD_PKCS1);       // Flags : Padding 
//	if (!NT_SUCCESS(status))
//	{
//		printf("Error Code : %x \n BCryptEncrypt fail(Calculate ciphertextLength)\n", status);
//		BCryptDestroyKey(PUBLICKEY_HANDLE);
//		FreePublicKeyBLOB(&RSA_PUBLICKEY);
//		return;
//	}
//	else
//	{
//		ciphertext = (PBYTE)calloc(ciphertextLength, sizeof(BYTE));
//		if (ciphertext == NULL)
//		{
//			printf("Memory Allocation(ciphertext) Fail...\n");
//			BCryptDestroyKey(PUBLICKEY_HANDLE);
//			FreePublicKeyBLOB(&RSA_PUBLICKEY);
//			return;
//		}
//	}
//
//
//	status = BCryptEncrypt(                         // Encrypt data
//		PUBLICKEY_HANDLE,        // KEY HANDLE
//		plaintext,               // Address of the buffer that contains the plaintext 
//		sizeof(plaintext),       // Size of the buffer that contains the plaintext 
//		NULL,                    // A pointer to padding info used with asymetric; OAEP
//		NULL,                    // Address of the buffer that contains the Initial Vector 
//		0,                       // Size of the buffer that contains the Initial Vector
//		ciphertext,              // Address of the buffer that receives the ciphertext. 
//		ciphertextLength,        // Size of the buffer that receives the ciphertext
//		&bufferSize,             // Variable that receives number of bytes copied to ciphertext buffer
//		BCRYPT_PAD_PKCS1);       // Flags : Padding 
//	if (!NT_SUCCESS(status))
//	{
//		printf("Error Code : %x \n BCryptEncrypt fail\n", status);
//		free(ciphertext);
//		BCryptDestroyKey(PUBLICKEY_HANDLE);
//		FreePublicKeyBLOB(&RSA_PUBLICKEY);
//		return;
//	}
//
//	PRINT(plaintext, sizeof(plaintext), PRINT_PLAINTEXT);
//	PRINT(ciphertext, ciphertextLength, PRINT_CIPHERTEXT);
//
//	free(ciphertext);
//	BCryptDestroyKey(PUBLICKEY_HANDLE);
//	ciphertextLength = 0;
//	FreePublicKeyBLOB(&RSA_PUBLICKEY);
//
//	return;
//}
//
//
//int main()
//{
//	BCRYPT_ALG_HANDLE RSA_ALG = NULL;
//	GET_ALG_HANDLE(&RSA_ALG);
//	RSA_4096_Test(RSA_ALG);                         // RSA4096/PKCS1
//	BCryptCloseAlgorithmProvider(RSA_ALG, 0);
//	return 0;
//}