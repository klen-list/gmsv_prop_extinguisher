#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/FactoryLoader.hpp>

#include <scanning/symbolfinder.hpp>

#include <dbg.h>

static SourceSDK::ModuleLoader server("server");

#ifdef SYSTEM_WINDOWS

#include <windows.h>

#ifdef ARCHITECTURE_X86

// mov     al, byte ptr[ebp+var_34]
// test    al, 40h
// jnz     short loc_102F0A9A
// test    al, 8
// jnz     short loc_102F0A9A
static const std::string pattern = "\x8A\x45\xCC\xA8\x40\x75\x77\xA8\x08\x75\x73\xDD\xD8\xA8\x02\x0F\x84****\x8B\x06\x8B\xCE\x6A\x0A\x8B\x40\x5C\xFF\xD0\x84\xC0\x0F\x84";

#elif ARCHITECTURE_X86_64

// todo

#endif

void Initialize()
{
	SymbolFinder symbolfinder;

	if (!server.IsValid())
	{
		Warning("[prop_extinguisher] ModuleLoader failed!\n");
		return;
	}

	void* ptr = symbolfinder.FindPattern(
		server.GetModule(),
		reinterpret_cast<const uint8_t*>(pattern.c_str()),
		pattern.length()
	);

	if (ptr == nullptr)
	{
		Warning("[prop_extinguisher] Pattern resolve failed!\n");
		return;
	}

	DWORD oldProt;
	BOOL succ = VirtualProtect(
		(LPVOID)ptr,
		pattern.length(),
		PAGE_EXECUTE_READWRITE,
		&oldProt
	);

	if (succ == 0)
	{
		Warning("[prop_extinguisher] VirtualProtect failed!\n");
		return;
	}

	uint8_t* buff = (uint8_t*)ptr;
	// jump through this shit
	buff[0] = 0xEB; buff[1] = 0x09; // jmp short +9

	VirtualProtect(
		(LPVOID)ptr,
		pattern.length(),
		oldProt,
		&oldProt
	);
}

#elif SYSTEM_LINUX

#include <unistd.h>
#include <sys/mman.h>

#ifdef ARCHITECTURE_X86

// mov     eax, [ebp+var_3C]
// test    al, 40h
// jnz     loc_DB1A78
// test    al, 8
// jnz     loc_DB1A78
static const std::string pattern = "\x8B\x45\xC4\xA8\x40\x0F\x85****\xA8\x08\x0F\x85****\xA8\x02\x0F\x84****\x8B\x07\xC7\x44\x24*****\x89\x3C\x24";

#elif ARCHITECTURE_X86_64

// todo

#endif

void Initialize()
{
	SymbolFinder symbolfinder;

	if (!server.IsValid())
	{
		Warning("[prop_extinguisher] ModuleLoader failed!\n");
		return;
	}

	void* ptr = symbolfinder.FindPattern(
		server.GetModule(),
		reinterpret_cast<const uint8_t*>(pattern.c_str()),
		pattern.length()
	);

	if (ptr == nullptr)
	{
		Warning("[prop_extinguisher] Pattern resolve failed!\n");
		return;
	}

	uintptr_t addr = (uintptr_t)ptr;

	if (mprotect((void*)(addr - addr % sysconf(_SC_PAGESIZE)), pattern.length(), PROT_READ | PROT_WRITE | PROT_EXEC))
	{
		Warning("[prop_extinguisher] mprotect failed!\n");
		return;
	}

	uint8_t* buff = (uint8_t*)ptr;
	// jump through this shit
	buff[0] = 0xEB; buff[1] = 0x11; // jmp short +11
}

#endif

GMOD_MODULE_OPEN()
{
	Initialize();
	return 0;
}

GMOD_MODULE_CLOSE()
{
	return 0;
}