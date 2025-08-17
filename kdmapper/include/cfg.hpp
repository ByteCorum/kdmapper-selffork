#pragma once
namespace cfg 
{
	static std::string version = "3.0.0.0";
	static bool free = false; // Automatically frees mapped memory after execution	Dangerous unless the driver finishes instantly
	static bool indPagesMode = false; // Maps the driver into non-contiguous, separate memory pages	Better for stealth, but more complex
	static bool copyHeader = false; // Ensures the PE headers are copied into memory	Needed for drivers that inspect their own image
	static bool passAllocationPtr = false; // Passes allocated memory pointer as first param to entry point	Used by custom loaders or shellcode-style drivers

	static std::vector<uint8_t> image = { 0 };
}