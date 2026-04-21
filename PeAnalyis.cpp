#include <iomanip>
#include "PeAnalyis.h"

PeAnalyis::PeAnalyis(const char* path)
{
    this->path = path;
	hfile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfile == INVALID_HANDLE_VALUE) {
		ErrorCode = CreateFileError;
		return;
	}

	filesize = GetFileSize(hfile, NULL);
	if (filesize == INVALID_FILE_SIZE || filesize == 0) {
		CloseHandle(hfile);
		hfile = INVALID_HANDLE_VALUE;
		ErrorCode = GetFileSizeError;
		return;
	}

	buff = new char[filesize] {0};
}

PeAnalyis::~PeAnalyis()
{
    if (buff) delete[] buff;
	if (hfile != INVALID_HANDLE_VALUE) CloseHandle(hfile);
}

void PeAnalyis::errorcheck()
{
	if (ErrorCode == CreateFileError) std::cout << "Create File Error" << std::endl;
	else if (ErrorCode == GetFileSizeError) std::cout << "Get File Size Error " << std::endl;
	else if (ErrorCode == ReadFileError) std::cout << "Read File Error" << std::endl;
}

bool PeAnalyis::loadfile()
{
	//可能有问题
    if (hfile == INVALID_HANDLE_VALUE || buff == nullptr || filesize == 0) return FALSE;
	DWORD read = 0;
	if (!ReadFile(hfile, buff, filesize, &read, NULL) || read != filesize) {
		ErrorCode = ReadFileError;
		return FALSE;
	}
	return TRUE;
}

//pe头,nt头,区段头和数据表解析
bool PeAnalyis::parseMust()
{
	if (buff == nullptr) return FALSE;
	pDosHeader = (PIMAGE_DOS_HEADER)buff;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)buff + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pOptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	std::cout << "pNtHeaders->FileHeader.Machine: " << pNtHeaders->FileHeader.Machine << std::endl;
	std::cout << "pNtHeaders->FileHeader.NumberOfSections: " << pNtHeaders->FileHeader.NumberOfSections << std::endl;
	if (pNtHeaders->FileHeader.SizeOfOptionalHeader == 0xE0) {
		std::cout << "This pe file should be run on a X86 system." << std::endl;
	}
	else {
		std::cout << "This pe file should be run on a X64 system." << std::endl;
	}
	std::cout << "\n==================== PE头解析 ====================\n\n";
	std::cout << "pNtHeaders->FileHeader.Characteristics: " << pNtHeaders->FileHeader.Characteristics << std::endl;
	std::cout << "pNtHeaders->OptionalHeader.AddressOfEntryPoint: " << pNtHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;
	std::cout << "pNtHeaders->FileHeader.NumberOfRvaAndSizes: " << pNtHeaders->OptionalHeader.NumberOfRvaAndSizes << std::endl;
	std::cout << "\n=====================================================\n\n";
	std::cout << "\n==================== 区段头解析 ====================\n\n";
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		char SectionName[9]{ 0 };
		memcpy_s(SectionName, 9, pSectionHeader[i].Name, 8);
		std::cout << "\033[33m[ " << SectionName << " ]\033[0m"<< "  Characteristics: " << pSectionHeader[i].Characteristics << "\n";
	}
	std::cout << "\n=====================================================\n\n";
	std::cout << std::endl;

	//表解析
	pDataDirectory = pOptionalHeader->DataDirectory;
	return true;
}

//内存地址转成文件地址
DWORD PeAnalyis::RvaToFoa(DWORD Rva)
{
	if (!pNtHeaders || !pSectionHeader) return 0;

	const WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	for (WORD i = 0; i < nSections; ++i) {
		DWORD va = pSectionHeader[i].VirtualAddress;
		DWORD rawPtr = pSectionHeader[i].PointerToRawData;
		DWORD rawSize = pSectionHeader[i].SizeOfRawData;
		DWORD virtSize = pSectionHeader[i].Misc.VirtualSize;
		DWORD span = virtSize ? virtSize : rawSize; // 使用 virtSize；若为0则使用 rawSize
		if (span == 0) continue;
		if (Rva >= va && Rva < va + span && rawPtr) {
			return (Rva - va) + rawPtr;
		}
	}
	return 0;
}

//导出表解析
bool PeAnalyis::parseExportTable()
{
	
	if (!pDataDirectory[0].Size || !pDataDirectory[0].VirtualAddress) {
		std::cout << "This file has not any exporttable." << std::endl;
		return FALSE;
	}
	DWORD Foa = RvaToFoa(pDataDirectory[0].VirtualAddress);
	if (!Foa) {
		std::cout << "This file has a empty exporttable" << std::endl;
		return FALSE;
	}
	else {
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(Foa + (BYTE*)buff);
		char* name = (char*)(RvaToFoa(pExportDirectory->Name) + (BYTE*)buff);
		std::cout << "pExportDirectory->Name: " << name << std::endl;
		std::cout << "pExportDirectory->NumberOfFunctions: " << pExportDirectory->NumberOfFunctions << std::endl;
		PDWORD pAddressOfFunctions = (PDWORD)(RvaToFoa(pExportDirectory->AddressOfFunctions) + (BYTE*)buff);
		PWORD pAddressOfNameOrdinals = (PWORD)(RvaToFoa(pExportDirectory->AddressOfNameOrdinals) + (BYTE*)buff);
		PDWORD pAddressOfNames = (PDWORD)(RvaToFoa(pExportDirectory->AddressOfNames) + (BYTE*)buff);
		std::cout << std::endl;
		std::cout << "\n==================== 导出表解析 ====================\n";
		std::cout << std::left
			<< std::setw(10) << "Order"
			<< std::setw(35) << "FuncName"
			<< std::hex << "FuncAddr"
			<< std::dec
			<< std::endl;
		std::cout << std::endl;
		for (WORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
			char* FuncName = (char*)(RvaToFoa(pAddressOfNames[i]) + (BYTE*)buff);
			WORD FuncOrdinal = pAddressOfNameOrdinals[i];
			DWORD FuncAddr = pAddressOfFunctions[FuncOrdinal];
			std::cout << std::left
				<< std::setw(10) << FuncOrdinal
				<< std::setw(35) << FuncName
				<< std::hex << FuncAddr
				<< std::dec
				<< std::endl;
		}
		std::cout << "\n=====================================================\n\n";
		std::cout << std::endl;
	}
	return TRUE;
}

// 导入表解析
bool PeAnalyis::parseImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory =
		(PIMAGE_IMPORT_DESCRIPTOR)(RvaToFoa(pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) + (BYTE*)buff);
    if (!pImportDirectory) {
        std::cout << "无导入表\n";
        return false;
    }
	//判段是否绑定导入
	std::cout << "\n==================== 导入表解析 ====================\n\n";
	if (pImportDirectory->TimeDateStamp) {
		char* name = (char*)(RvaToFoa(pImportDirectory->Name) + (BYTE*)buff);
		std::cout << "Dll.name:  " << name << std::endl;
		PIMAGE_THUNK_DATA pImportAddress = (PIMAGE_THUNK_DATA)(RvaToFoa(pImportDirectory->FirstThunk) + (BYTE*)buff);
		int i = 0;
		while (pImportAddress[i].u1.Function) {
			ULONGLONG FuncOffset = pImportAddress[i].u1.Function;
			std::cout << "         Function Offset:   " << FuncOffset << std::endl;
			i++;
		}
	}
	else {
		int dllIndex = 1;
		while (pImportDirectory->OriginalFirstThunk || pImportDirectory->FirstThunk)
		{
			char* dllName = (char*)(RvaToFoa(pImportDirectory->Name) + (BYTE*)buff);
			std::cout << "\n[" << dllIndex << "] \033[32m" << dllName << "\033[0m\n";
			dllIndex++;
			PIMAGE_THUNK_DATA pImportNames =
				(PIMAGE_THUNK_DATA)(RvaToFoa(pImportDirectory->OriginalFirstThunk) + (BYTE*)buff);
			if (!pImportNames) {
				pImportDirectory++;
				continue;
			}
			int funcIndex = 1;
			while (pImportNames->u1.Function)
			{
				// 判断：按序号导入 还是 按名称导入
				if (pImportNames->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				{
					DWORD ord = pImportNames->u1.Ordinal & 0xFFFF;
					std::cout << "     \033[33m[" << funcIndex << "]\033[0m 序号: #" << ord << " (无函数名)\n";
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pImportByName =
						(PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pImportNames->u1.AddressOfData) + (BYTE*)buff);
					std::cout << "     \033[33m[" << funcIndex << "]\033[0m " << pImportByName->Name << "\n";
				}
				funcIndex++;
				pImportNames++;
			}
			pImportDirectory++;
		}
	}
    std::cout << "\n=====================================================\n\n";
    return true;
}

//重定位表解析
bool PeAnalyis::parseRedirectTable()
{
	if (pDataDirectory[5].VirtualAddress == 0 || pDataDirectory[5].Size == 0) {
		std::cout << "该文件无重定位表\n";
		return FALSE;
	}
	try
	{
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)(
			RvaToFoa(pDataDirectory[5].VirtualAddress) + (BYTE*)buff
			);
		if (!pBaseRelocation)
		{
			std::cerr << "重定位表地址无效！" << std::endl;
			return FALSE;
		}
		std::cout << "\n==================== 重定位表解析 ====================\n\n";
		std::cout << "\033[33m[fDataAddr" << "]\033[0m           DataAddr" << "\n\n";
		while (pBaseRelocation->VirtualAddress && pBaseRelocation->SizeOfBlock)
		{
			if (pBaseRelocation->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
			{
				std::cerr << "非法重定位块，跳过..." << std::endl;
				break;
			}
			int NumberOfOffset = (pBaseRelocation->SizeOfBlock - 8) / 2;
			if (NumberOfOffset <= 0 || NumberOfOffset > 0x1000)
			{
				std::cerr << "重定位项数量无效，跳过..." << std::endl;
				break;
			}
			PWORD TypeOffset = (PWORD)(pBaseRelocation + 1);
			
			for (int ordinal = 0; ordinal < NumberOfOffset; ordinal++)
			{
				WORD Item = TypeOffset[ordinal];
				int type = Item >> 12;
				WORD offset = Item & 0xFFF;

				if (type == 3 || type == 0xA)
				{
					DWORD fOffset = RvaToFoa(pBaseRelocation->VirtualAddress + offset);
					if (fOffset >= this->filesize)
					{
						std::cout << "地址越界，跳过..." << std::endl;
						continue;
					}
					PDWORD fDataAddr = (PDWORD)(buff + fOffset);
					DWORD Data = *fDataAddr;
					std::cout << "\033[33m[" << fDataAddr << "]\033[0m   0x" << Data << "\n";
				}
			}
			pBaseRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)pBaseRelocation + pBaseRelocation->SizeOfBlock);
		}
		std::cout << "\n=====================================================\n\n";
		return TRUE;
	}
	catch (...)
	{
		std::cerr << "\n重定位表解析发生异常！文件可能被篡改或损坏！\n";
		return FALSE;
	}
}

//必要步骤执行
bool PeAnalyis::analyisfile()
{	
	if (buff == nullptr) return FALSE;
	if (!loadfile()) return FALSE;
	if (!parseMust()) return FALSE;

	if (!parseExportTable()) {
		std::cout << "Error: parseExportTable failed" << std::endl;
	}
	if (!parseImportTable()) {
		std::cout << "Error: parseImportTable failed" << std::endl;
	}
	if (!parseRedirectTable()) {
		std::cout << "Error: parseRedirectTable failed" << std::endl;
	}
	return TRUE;
}




