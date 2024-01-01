#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#define BLOCK_SIZE 16 // AES block size in bytes
#define AES_KEY_SIZE 32 // AES-256 key size in bytes

NTSTATUS GetAlgHandle(BCRYPT_ALG_HANDLE* handle) {
	NTSTATUS status = BCryptOpenAlgorithmProvider(
		handle,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0);

	return status;
}

void file_enc(const char* filename, int number, unsigned char* key, unsigned char* iv) {

	const char* ext = strrchr(filename, '.');
	if (ext == NULL) {
		printf("No file extension found.\n");
		return;
	}

	size_t extIndex = ext - filename;
	size_t newFilenameSize = extIndex + 6 + strlen(filename) + 1; // 숫자 길이, 파일명 길이, NULL 문자
	char* newFilename = (char*)malloc(newFilenameSize);
	if (newFilename == NULL) {
		printf("Memory allocation for new filename failed.\n");
		return;
	}

	snprintf(newFilename, newFilenameSize, "%d_%s.pjc", number, filename);

	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		printf("Failed to open file.\n");
		free(newFilename);
		return;
	}

	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);

	BYTE* fileData = (BYTE*)malloc(fileSize);
	if (fileData == NULL) {
		printf("Memory allocation failed.\n");
		fclose(file);
		free(newFilename);
		return;
	}

	size_t bytesRead = fread(fileData, 1, fileSize, file);
	fclose(file);

	if (bytesRead != fileSize) {
		printf("Error reading file.\n");
		free(fileData);
		free(newFilename);
		return;
	}

	DWORD paddingSize = BLOCK_SIZE - (fileSize % BLOCK_SIZE); // Calculate required padding
	DWORD paddedSize = fileSize + paddingSize;

	BYTE* paddedData = (BYTE*)malloc(paddedSize);
	if (paddedData == NULL) {
		printf("Memory allocation for padded data failed.\n");
		free(fileData);
		free(newFilename);
		return;
	}

	memcpy(paddedData, fileData, fileSize); // Copy original data to padded buffer
	memset(paddedData + fileSize, (BYTE)paddingSize, paddingSize); // Add PKCS#7 padding

	BCRYPT_ALG_HANDLE algHandle;
	NTSTATUS status = GetAlgHandle(&algHandle);
	if (!NT_SUCCESS(status)) {
		printf("Error getting algorithm handle.\n");
		free(fileData);
		free(paddedData);
		free(newFilename);
		return;
	}

	BCRYPT_KEY_HANDLE keyHandle;
	status = BCryptGenerateSymmetricKey(
		algHandle,
		&keyHandle,
		NULL,
		0,
		key,
		AES_KEY_SIZE,
		0);

	if (!NT_SUCCESS(status)) {
		printf("Error generating symmetric key.\n");
		free(fileData);
		free(paddedData);
		free(newFilename);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		return;
	}

	DWORD encryptedSize = 0;
	status = BCryptEncrypt(
		keyHandle,
		paddedData,
		paddedSize,
		NULL,
		iv,
		BLOCK_SIZE,
		NULL,
		0,
		&encryptedSize,
		0);

	if (!NT_SUCCESS(status)) {
		printf("Error calculating encrypted size.\n");
		free(fileData);
		free(paddedData);
		free(newFilename);
		BCryptDestroyKey(keyHandle);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		return;
	}

	BYTE* encryptedData = (BYTE*)malloc(encryptedSize);
	if (encryptedData == NULL) {
		printf("Memory allocation for encrypted data failed.\n");
		free(fileData);
		free(paddedData);
		free(newFilename);
		BCryptDestroyKey(keyHandle);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		return;
	}

	status = BCryptEncrypt(
		keyHandle,
		paddedData,
		paddedSize,
		NULL,
		iv,
		BLOCK_SIZE,
		encryptedData,
		encryptedSize,
		&encryptedSize,
		0);

	if (!NT_SUCCESS(status)) {
		printf("Error encrypting file.\n");
		free(fileData);
		free(paddedData);
		free(encryptedData);
		free(newFilename);
		BCryptDestroyKey(keyHandle);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		return;
	}

	FILE* encryptedFile = fopen(newFilename, "wb");
	if (encryptedFile == NULL) {
		printf("Failed to create encrypted file.\n");
		free(fileData);
		free(paddedData);
		free(encryptedData);
		free(newFilename);
		BCryptDestroyKey(keyHandle);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		return;
	}

	fwrite(encryptedData, 1, encryptedSize, encryptedFile);
	fclose(encryptedFile);

	//printf("File encrypted successfully. Encrypted file: %s\n", newFilename);

	free(fileData);
	free(paddedData);
	free(encryptedData);
	free(newFilename);
	BCryptDestroyKey(keyHandle);
	BCryptCloseAlgorithmProvider(algHandle, 0);
}