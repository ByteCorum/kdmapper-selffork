#include "kdmapper.hpp"
#include <Windows.h>
#include <iostream>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"
#include "logger.hpp"
#include <sstream>

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log::Fine("Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped");
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log::Fine("StackCookie not defined, fix cookie skipped");
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log::Error("StackCookie already fixed!? this probably wrong", false);
		return false;
	}

	Log::Fine("Fixing stack cookie");

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool ResolveImports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		std::ostringstream ss;

		if (!Module) 
		{
			ss << "Dependency " << current_import.module_name << " wasn't found";
			Log::Error(ss.str(), false);
			ss.clear();

			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = intel_driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {

						ss << "Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")";
						Log::Error(ss.str(), false);
						ss.clear();

						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

ULONG64 kdmapper::MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);
	std::ostringstream ss;

	if (!nt_headers) {
		Log::Error("Invalid format of PE image", false);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log::Error("Image is not 64 bit", false);
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = 0;
	if (mode == AllocationMode::AllocateIndependentPages)
	{
		kernel_image_base = intel_driver::MmAllocateIndependentPagesEx(image_size);
	}
	else { // AllocatePool by default
		kernel_image_base = intel_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, image_size);
	}

	if (!kernel_image_base) {
		Log::Error("Failed to allocate remote image in kernel", false);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do
	{
		ss << "Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base);
		Log::Fine(ss.str());
		ss.clear();

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader)
		{
			kernel_image_base -= TotalVirtualHeaderSize;
			ss << "Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header";
			Log::Fine(ss.str());
			ss.clear();
		}

		// Resolve relocs and imports
		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!FixSecurityCookie(local_image_base, kernel_image_base ))
		{
			Log::Error("Failed to fix cookie", false);
			return 0;
		}

		if (!ResolveImports(portable_executable::GetImports(local_image_base)))
		{
			Log::Error("Failed to resolve imports", false);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel
		if (!intel_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) 
		{
			Log::Error("Failed to write local image to remote image", false);
			kernel_image_base = realBase;
			break;
		}

		if (mode == AllocationMode::AllocateIndependentPages)
		{
			auto ProtectionToString = [](ULONG prot) -> const char* {
				switch (prot)
				{
				case PAGE_NOACCESS: return "NOACCESS";
				case PAGE_READONLY: return "READONLY";
				case PAGE_READWRITE: return "READWRITE";
				case PAGE_EXECUTE: return "EXECUTE";
				case PAGE_EXECUTE_READ: return "EXECUTE_READ";
				case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
				default: return "UNKNOWN";
				}
				};

			for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				auto sec = &IMAGE_FIRST_SECTION(nt_headers)[i];
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize <= 0) 
				{
					ss << L"Skipping empty section: " << (char*)sec->Name;
					Log::Info(ss.str());
					ss.clear();
					continue;
				}

				ULONG prot = PAGE_READONLY;

				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
						PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
					prot = PAGE_READWRITE;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
					prot = PAGE_READONLY;
				}

				ss << "Setting protection for section: "
					<< (char*)sec->Name
					<< L" Base: 0x" << std::hex << secAddr
					<< L" Size: 0x" << secSize
					<< L" Prot: " << ProtectionToString(prot)
					<< std::dec;
				Log::Fine(ss.str());
				ss.clear();

				if (!intel_driver::MmSetPageProtection(secAddr, secSize, prot))
				{
					ss << "Failed to set protection for section: " << (char*)sec->Name;
					Log::Error(ss.str(), false);
					ss.clear();
				}
			}
		}

		// Call driver entry point
		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		ss << "Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point);
		Log::Info(ss.str());
		ss.clear();

		if (callback)
		{
			if (!callback(&param1, &param2, realBase, image_size))
			{
				Log::Error("Callback returns false, failed", false);
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (!intel_driver::CallKernelFunction(&status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2))
		{
			Log::Error("Failed to call DragonBurn kernel entry", false);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		ss << "DriverEntry returned 0x" << std::hex << status;
		Log::Fine(ss.str());
		ss.clear();

		// Free memory
		if (free)
		{
			Log::Info("Freeing memory...");
			bool free_status = false;

			if (mode == AllocationMode::AllocateIndependentPages)
				free_status = intel_driver::MmFreeIndependentPages(realBase, image_size);
			else
				free_status = intel_driver::FreePool(realBase);

			Log::PreviousLine();
			if (free_status)
				Log::Fine("Memory has been released");
			else
				Log::Warning("Failed to free memory");
		}



		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	Log::Info("Freeing memory...");
	bool free_status = false;

	if (mode == AllocationMode::AllocateIndependentPages)
		free_status = intel_driver::MmFreeIndependentPages(kernel_image_base, image_size);
	else
		free_status = intel_driver::FreePool(kernel_image_base);

	Log::PreviousLine();
	if (free_status)
		Log::Fine("Memory has been released");
	else
		Log::Warning("Failed to free memory");

	return 0;
}


