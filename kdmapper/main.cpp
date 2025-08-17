#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "kdmapper.hpp"
#include "utils.hpp"
#include "intel_driver.hpp"
#include "cfg.hpp"
#include "web_api.hpp"

HANDLE iqvw64e_device_handle;


LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	Log("[+] Callback example called" << std::endl);
	
	/*
	This callback occurs before call driver entry and
	can be useful to pass more customized params in 
	the last step of the mapping procedure since you 
	know now the mapping address and other things
	*/
	return true;
}

DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	printf(R"LOGO(______                            ______                  
|  _  \                           | ___ \                 
| | | |_ __ __ _  __ _  ___  _ __ | |_/ /_   _ _ __ _ __  
| | | | '__/ _` |/ _` |/ _ \| '_ \| ___ \ | | | '__| '_ \ 
| |/ /| | | (_| | (_| | (_) | | | | |_/ / |_| | |  | | | |
|___/ |_|  \__,_|\__, |\___/|_| |_\____/ \__,_|_|  |_| |_|
                  __/ |                                   
                 |___/                                    

https://discord.gg/5WcvdzFybD
https://github.com/ByteCorum/DragonBurn

)LOGO");

	const std::string curVersionUrl = "https://raw.githubusercontent.com/ByteCorum/DragonBurn/data/version";
	std::string supportedVersions;

	Log(L"[<] Checking mapper version..." << std::endl);
	if (!Web::CheckConnection())
	{
		Log(L"[-] Bad internet connection" << std::endl);
		system("pause");
		return -1;
	}
	if (!Web::Get(curVersionUrl, supportedVersions))
	{
		Log(L"[-] Failed to get currently supported versions" << std::endl);
		system("pause");
		return -1;
	}
	if (supportedVersions.find(cfg::version) != std::string::npos)
		std::cout << "[+] Your mapper version is up to date and supported"<< std::endl;
	else 
	{
		Log(L"[-] Your mapper version is out of support" << std::endl);
		system("pause");
		return -1;
	}

	if (cfg::free)
		Log(L"[+] Free pool memory after usage enabled" << std::endl);
	if (cfg::indPagesMode)
		Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);// Log(L"[-] Can't use --free and --indPages at the same time" << std::endl);
	if (cfg::passAllocationPtr)
		Log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	if (cfg::copyHeader)
		Log(L"[+] Copying driver header enabled" << std::endl);

	iqvw64e_device_handle = intel_driver::Load();

	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE) {
		system("pause");
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;

	if (cfg::indPagesMode) {
		mode = kdmapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(iqvw64e_device_handle, cfg::image.data(), 0, 0, free, !cfg::copyHeader, mode, cfg::passAllocationPtr, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map DragonBurn driver"<< std::endl);
		intel_driver::Unload(iqvw64e_device_handle);
		system("pause");
		return -1;
	}

	if (!intel_driver::Unload(iqvw64e_device_handle)) {
		Log(L"[-] Warning failed to fully unload vulnerable driver" << std::endl);
		system("pause");
	}
	Log(L"[+] success" << std::endl);
	system("pause");
	return 0;
}