#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>

const char *extensions[] = { "txt", "pdf", "jpg", "pptx", "ppt", "bmp", "png" }; // List of extensions to search 
int numExtensions = sizeof(extensions) / sizeof(extensions[0]); // Number of extensions to search

/************************************************************************************
 * f_search : Searches for files with the given extensions in the current directory
 * 
 * input: 
 * filenames - buffer to store the filenames
 * filecount - number of files found
 * *********************************************************************************/
void f_search(char filenames[][MAX_PATH], int* filecount)
{
	char directory[4096]; // Current directory
	_getcwd(directory, 4096);

	WIN32_FIND_DATA finddata;
	HANDLE hfind;

	char path[MAX_PATH];

	// Search for files with the given extensions
	for (int i = 0; i < numExtensions; ++i) {
		sprintf(path, "%s\\*.%s", directory, extensions[i]); // Create the search path

		hfind = FindFirstFile((LPCSTR)path, &finddata);
		if (hfind != INVALID_HANDLE_VALUE) {
			// Store the filenames
			do {
				strcpy(filenames[*filecount], finddata.cFileName);
				(*filecount)++;
			} while (FindNextFile(hfind, &finddata) && (*filecount < 100)); // Limit the number of files to 100

			FindClose(hfind);
		}
	}
}