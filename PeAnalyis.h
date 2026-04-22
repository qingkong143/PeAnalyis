#pragma once
#include<iostream>
#include<Windows.h>
#define ERR int
#define CreateFileError 0x1
#define GetFileSizeError 0x2
#define ReadFileError 0x3


class PeAnalyis {
public:
	PeAnalyis(const char* path);
	~PeAnalyis();
	bool loadfile();
	bool analyisfile();
	void errorcheck();

private:
	ERR ErrorCode = 0;
    const char* path;
	char* buff{ nullptr };
	HANDLE hfile{ INVALID_HANDLE_VALUE };
	DWORD filesize{ 0 };
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectory;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory;
	PIMAGE_BASE_RELOCATION pBaseRelocation;
	bool parseMust();
	bool parseExportTable();
	bool parseImportTable();
	bool parseRedirectTable();
	DWORD RvaToFoa(DWORD Rva);
};