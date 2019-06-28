//Microsoft (R) C/C++ Optimizing Compiler Version 19.00.23506 for x86

#include <vector>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <windows.h>
#include <psapi.h>

std::vector<const void*> scan_memory(void* address_low, std::size_t nbytes,
	const std::vector<BYTE>& bytes_to_find)
{
	std::vector<const void*> addresses_found;

	// all readable pages: adjust this as required
	const DWORD pmask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE |
		PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

	::MEMORY_BASIC_INFORMATION mbi{};

	BYTE* address = static_cast<BYTE*>(address_low);
	BYTE* address_high = address + nbytes;

	while (address < address_high && ::VirtualQuery(address, std::addressof(mbi), sizeof(mbi)))
	{
		// committed memory, readable, wont raise exception guard page
		// if( (mbi.State==MEM_COMMIT) && (mbi.Protect|pmask) && !(mbi.Protect&PAGE_GUARD) )
		if ((mbi.State == MEM_COMMIT) && (mbi.Protect & pmask) && !(mbi.Protect & PAGE_GUARD))
		{
			const BYTE* begin = static_cast<const BYTE*>(mbi.BaseAddress);
			const BYTE* end = begin + mbi.RegionSize;

			const BYTE* found = std::search(begin, end, bytes_to_find.begin(), bytes_to_find.end());
			while (found != end)
			{
				addresses_found.push_back(found);
				found = std::search(found + 1, end, bytes_to_find.begin(), bytes_to_find.end());
			}
		}

		address += mbi.RegionSize;
		mbi = {};
	}

	return addresses_found;
}

std::vector<const void*> scan_memory(std::string module_name, const std::vector<BYTE>& bytes_to_find)
{
	auto base = ::GetModuleHandleA(module_name.c_str());
	if (base == nullptr) return {};

	MODULEINFO minfo{};
	::GetModuleInformation(GetCurrentProcess(), base, std::addressof(minfo), sizeof(minfo));
	return scan_memory(base, minfo.SizeOfImage, bytes_to_find);
}

int main()
{
	const std::vector<BYTE> bytes_to_find(32U, 0xff); // look for 32 consecutive bytes containing 0xff
	const std::vector<const void*> addresses_found = scan_memory("kernel32.dll", bytes_to_find);

	std::cout << "found at " << addresses_found.size() << " addresses\ngithub.com/Latencyx\n\n";
	for (const void* p : addresses_found) std::cout << p << '\n';
}
