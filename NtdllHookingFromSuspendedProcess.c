#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <string.h>
#include <TlHelp32.h>
#include <tchar.h>

PVOID FetchNtdllAddress() {
#ifdef _WIN64
    PPEB PEB = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB PEB = (PPEB)__readfsdword(0x30);
#endif

    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)PEB->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}

SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {
    PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
    if (DosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pNtdllModule + DosHdr->e_lfanew);
    if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return pImgNtHdr->OptionalHeader.SizeOfImage;
}

BOOL ReadNtdllFromSuspendedProcess(IN LPCWSTR processname, OUT PVOID* pNtdllBuff) {
    WCHAR winPath[MAX_PATH / 2] = { 0 };
    WCHAR procPath[MAX_PATH] = { 0 };

    PVOID pNtdllModule = FetchNtdllAddress();
    PBYTE pNtdllBuffer = NULL;
    SIZE_T sNtdllSize = 0, sNumberOfBytes = 0;

    STARTUPINFOW Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    Si.cb = sizeof(STARTUPINFOW);

    if (GetWindowsDirectoryW(winPath, sizeof(winPath) / sizeof(WCHAR)) == 0) {
        wprintf(L"[!] Failed to Retrieve Windows Directory [!]\n");
        wprintf(L"[!] Error: %lu\n", GetLastError());
        return FALSE;
    }

    wsprintfW(procPath, L"%s\\System32\\%s", winPath, processname);
    wprintf(L"[+] Running Suspended Process %s [+]\n", procPath);

    if (!CreateProcessW(NULL, procPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        wprintf(L"[!] Error in Creating Process [!]\n");
        wprintf(L"[!] Error: %lu\n", GetLastError());
        return FALSE;
    }

    wprintf(L"[+] DONE\n");
    wprintf(L"[i] Suspended Process Created With PID: %d\n", Pi.dwProcessId);

    sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
    if (!sNtdllSize) {
        wprintf(L"[!] Failed to Get Ntdll Size\n");
        goto _EndOfFunc;
    }

    pNtdllBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
    if (!pNtdllBuffer) {
        wprintf(L"[!] Heap Allocation Failed\n");
        goto _EndOfFunc;
    }

    if (!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytes) || sNumberOfBytes != sNtdllSize) {
        wprintf(L"[!] Error in Reading Process Memory [!]\n");
        wprintf(L"[!] Error: %lu\n", GetLastError());
        wprintf(L"[i] Read %zu of %zu Bytes\n", sNumberOfBytes, sNtdllSize);
        goto _EndOfFunc;
    }

    *pNtdllBuff = pNtdllBuffer;

    wprintf(L"[#] Press <Enter> To Terminate The Child Process ... ");
    getchar();

    TerminateProcess(Pi.hProcess, 0);
    wprintf(L"[+] Process Successfully Terminated [+]\n");
    return TRUE;

_EndOfFunc:
    if (Pi.hProcess) CloseHandle(Pi.hProcess);
    if (Pi.hThread) CloseHandle(Pi.hThread);
    if (*pNtdllBuff == NULL && pNtdllBuffer) HeapFree(GetProcessHeap(), 0, pNtdllBuffer);
    return FALSE;
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
    PVOID pLocalNtdll = FetchNtdllAddress();

    printf("\t[i] 'Hooked' Ntdll Base Address: 0x%p\n\t[i] 'Unhooked' Ntdll Base Address: 0x%p\n", pLocalNtdll, pUnhookedNtdll);
    printf("[#] Press <Enter> To Continue ... ");
    getchar();

    PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (!pLocalDosHdr || pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS Header Signature\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
    if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT Header Signature\n");
        return FALSE;
    }

    PVOID pLocalNtdllTxt = NULL, pRemoteNtdllTxt = NULL;
    SIZE_T sNtdllTxtSize = 0;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);
    for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    printf("\t[i] 'Hooked' Ntdll Text Section Address: 0x%p\n\t[i] 'Unhooked' Ntdll Text Section Address: 0x%p\n\t[i] Text Section Size: %zu\n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
    printf("[#] Press <Enter> To Continue ... ");
    getchar();

    if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize) {
        printf("[!] Invalid Text Section Information\n");
        return FALSE;
    }

    if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
        printf("[!] Text Section Mismatch\n");
        return FALSE;
    }

    printf("[i] Replacing The Text Section ... ");
    DWORD dwOldProtection = 0;

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        printf("[!] VirtualProtect [1] Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        printf("[!] VirtualProtect [2] Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE!\n");
    return TRUE;
}

DWORD GetPID(LPCWSTR processname) {
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD PID = 0;

    if (hSnapShot == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Error in Retrieve Snapshot [!]\n");
        return 0;
    }

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapShot, &pe)) {
        wprintf(L"[!] Error in Process32First [!]\n");
        wprintf(L"[!] Error Code: %lu\n", GetLastError());
        CloseHandle(hSnapShot);
        return 0;
    }

    do {
        wprintf(L"Checking process: %s\n", pe.szExeFile);

        if (wcscmp(pe.szExeFile, processname) == 0) {
            PID = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapShot, &pe));

    CloseHandle(hSnapShot);
    if (PID == 0) {
        wprintf(L"[!] Error: Process %s not found.\n", processname);
    }
    return PID;
}

int wmain(int argc, wchar_t* argv[]) {
    PVOID pNtdll = NULL;
    DWORD PID;

    if (argc < 2) {
        wprintf(L"Usage: SuspendedProcessUnhooking.exe <processname>\n");
        return -1;
    }

    LPCWSTR processname = argv[1];
    PID = GetPID(processname);

    if (PID == 0) {
        wprintf(L"[!] Error: Process not found.\n");
        return -1;
    }

    wprintf(L"[i] Fetching A New \"ntdll.dll\" File From A Suspended Process\n");

    if (!ReadNtdllFromSuspendedProcess(processname, &pNtdll)) {
        return -1;
    }

    if (!ReplaceNtdllTxtSection(pNtdll)) {
        return -1;
    }

    if (pNtdll) {
        HeapFree(GetProcessHeap(), 0, pNtdll);
    }

    wprintf(L"[+] Ntdll Unhooked Successfully\n");

    wprintf(L"[#] Press <Enter> To Quit ...");
    getchar();

    return 0;
}
