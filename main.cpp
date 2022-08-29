#include <string>
#include <windows.h>

#define MessageBoxA_hash  0x92b4d

uint32_t hash_function(std::string_view s)
{
    uint32_t ret = 0;
    static uint32_t PRIME_BASE = 17;
    static uint32_t PRIME_MOD = 1001369;

    for (size_t i = 0; i < s.size(); i++)
    {
        ret *= PRIME_BASE; 
        ret += s[i];
        ret %= PRIME_MOD;
    }
    return ret;
}

template<typename T>
T* get_func_by_hash(LPCSTR module_name, uint32_t func_hash)
{
	HMODULE lib_base = LoadLibraryA(module_name);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)lib_base;
	PIMAGE_NT_HEADERS image_NT_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)lib_base + dos_header->e_lfanew);

	DWORD_PTR export_directory_rva = image_NT_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lib_base + export_directory_rva);

	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)lib_base + image_export_directory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)lib_base + image_export_directory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)lib_base + image_export_directory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < image_export_directory->NumberOfFunctions; ++i)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)lib_base + functionNameRVA;

		DWORD_PTR functionAddressRVA = 0;

		if (hash_function((char*)functionNameVA) == func_hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			return (T*)((DWORD_PTR)lib_base + functionAddressRVA);
		}
	}

    return nullptr;
}

int main()
{ 
	// Calling MessageBoxA using function hash
    auto MsgBox = get_func_by_hash<decltype(MessageBoxA)>("user32.dll", MessageBoxA_hash);
	
	if (MsgBox) 
	{
		MsgBox(0, "Text", "Caption", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);
	}

	return 0;
}
