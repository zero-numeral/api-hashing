#include <concepts>
#include <windows.h>
#include <winternl.h>
#include <string_view>

uint32_t hash_function(std::string_view s)
{
	uint32_t ret = 0;
	static uint32_t PRIME_BASE = 17;
	static uint32_t PRIME_MOD = 1001369;

	for (size_t i = 0; i < s.size(); ++i)
	{
		ret *= PRIME_BASE;
		ret += s[i];
		ret %= PRIME_MOD;
	}
	return ret;
}

template <typename T>
T get_function_by_hash(uint32_t func_hash)
	requires std::is_pointer_v<T>
{
	/*
		The LDR_MODULE structure is a undocumented version of the LDR_DATA_TABLE_ENTRY struct,
		which is used in WindowsNT internal processes.

		http://undocumented.ntinternals.net/index.html?page=UserMode/Structures/LDR_MODULE.html
	*/
	typedef struct _LDR_MODULE
	{

		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID BaseAddress;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashTableEntry;
		ULONG TimeDateStamp;

	} LDR_MODULE, *PLDR_MODULE;

	PTEB teb = NtCurrentTeb();
	PPEB peb = teb->ProcessEnvironmentBlock;
	PPEB_LDR_DATA ldr = peb->Ldr;

	/*
		Each Flink and Blink are pointers to LDR_DATA_TABLE_ENTRY struct, like MSDN says.
		https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data

		But they don't point to the start of struct. Instead, they point to the InMemoryOrderLinks field,
		so to obtain the beginning of the structure, we need to subtract a specific offset, and for that,
		the CONTAINING_RECORD macro is used."
	*/

	PLIST_ENTRY head_entry = &ldr->InMemoryOrderModuleList, next_entry;
	for (next_entry = head_entry->Flink; next_entry != head_entry; next_entry = next_entry->Flink)
	{
		PLDR_MODULE ldr_module_entry = reinterpret_cast<PLDR_MODULE>(CONTAINING_RECORD(next_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		PVOID module_base = ldr_module_entry->BaseAddress;
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
		PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)module_base + dos_header->e_lfanew);

		ULONG_PTR export_directory_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((ULONG_PTR)module_base + export_directory_rva);

		PULONG address_of_names = reinterpret_cast<PULONG>((ULONG_PTR)module_base + export_directory->AddressOfNames);
		PULONG address_of_functions = reinterpret_cast<PULONG>((ULONG_PTR)module_base + export_directory->AddressOfFunctions);
		PWORD address_of_name_ordinals = reinterpret_cast<PWORD>((ULONG_PTR)module_base + export_directory->AddressOfNameOrdinals);

		for (auto i = 0; i < export_directory->NumberOfFunctions; ++i)
		{
			ULONG_PTR function_name_rva = address_of_names[i];
			const char* function_name = reinterpret_cast<char*>((ULONG_PTR)module_base + function_name_rva);

			__try
			{
				if (hash_function(function_name) == func_hash)
				{
					WORD function_index = address_of_name_ordinals[i];
					ULONG_PTR function_rva = address_of_functions[function_index];
					return reinterpret_cast<T>((ULONG_PTR)module_base + function_rva);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				// access violation handler
			}
		}
	}

	return nullptr;
}

int main()
{
	constexpr uint32_t MessageBoxA_hash = 0x92b4d;
	/*
		Make sure that library where our function located is already loaded.
	*/
	LoadLibrary("user32.dll");

	auto MsgBox = get_function_by_hash<decltype(MessageBoxA)*>(MessageBoxA_hash);
	if (MsgBox) {
		MsgBox(0, "Hello", "Circumventing the direct import!", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);
	}
	return 0;
}
