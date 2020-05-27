// VBSFix - AMD Ryzen Master VBS check patcher

#include <Windows.h>
#include <wchar.h>
#include <winternl.h>

typedef unsigned long long QWORD;

typedef NTSTATUS
(NTAPI
    * _NtQueryInformationProcess)(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL
        );

const char* Pattern = "\x39\x7D\x90\x0F\x84\x00\x00\x00\x00\x33\xD2\x48\x8D\x4C\x24\x60";
const char* Mask = "xxxxx????xxxxxxx";
#define SearchLength 0x20000

const char* Patch = "\xE9\xE9\x00\x00\x00\x90";
SIZE_T PatchLen = 0x6;
QWORD PatchOffset = 0x3;

LPCWSTR Module = L"AMD Ryzen Master.exe";
LPCWSTR BackupPath = L"C:\\Program Files\\AMD\\RyzenMaster\\bin\\AMD Ryzen Master.exe";

_NtQueryInformationProcess Imp_NtQueryInformationProcess;

bool Compare(const char* pData, const char* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
        {
            return 0;
        }
    }

    return (*szMask) == NULL;
}

LPVOID FindPattern(QWORD qwAddress, DWORD dwLen, const char* bMask, const char* szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
    {
        if (Compare((char*)(qwAddress + i), bMask, szMask))
        {
            return (LPVOID)(qwAddress + i);
        }
    }

    return 0;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    PROCESS_INFORMATION processInformation;
    STARTUPINFO startupInfo = { sizeof(startupInfo) };
    PROCESS_BASIC_INFORMATION processBasicInformation;
    DWORD dwBytesRead;
    SIZE_T szBytesRead;
    NTSTATUS status;
    PEB peb;
    LPVOID buffer, patternPtr;
    QWORD offset;

    Imp_NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

    if (!Imp_NtQueryInformationProcess)
    {
        wprintf(L"NtQueryInformationProcess linkage failed.\n");
        return -1;
    }

    // Standalone mode: Launch program.
    if (!argv[1] || !lstrlenW(argv[1]))
    {
#ifdef _DEBUG
        wprintf(L"Standalone mode\n");
#endif

        if (!CreateProcessW(BackupPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInformation))
        {
            wprintf(L"CreateProcessW failed, %d.\n", GetLastError());
            return -2;
        }
    }
    else
    {
        // Image File Execution Options mode: Target name is argv[1].
#ifdef _DEBUG
        wprintf(L"Executing %s\n", argv[1]);
#endif

        // Check we aren't executing ourselves again.
        if (!wcsstr(argv[1], Module))
        {
#ifdef _DEBUG
            wprintf(L"Avoiding loop behaviour.\n", argv[1]);
#endif
            return 0;
        }

        if (!CreateProcessW(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInformation))
        {
            wprintf(L"CreateProcessW failed.\n");
            return -2;
        }
    }

    // Since we started suspended module information is not yet available, we just use the PEB
    status = Imp_NtQueryInformationProcess(processInformation.hProcess, ProcessBasicInformation, &processBasicInformation, sizeof(processBasicInformation), &dwBytesRead);

    if (!NT_SUCCESS(status))
    {
        wprintf(L"NtQueryInformationProcess failed, 0x%X.\n", status);
        TerminateProcess(processInformation.hProcess, 0);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        return -3;
    }

#ifdef _DEBUG
    wprintf(L"PEB Base: 0x%p.\n", processBasicInformation.PebBaseAddress);
#endif

    if (!ReadProcessMemory(processInformation.hProcess, processBasicInformation.PebBaseAddress, &peb, sizeof(peb), &szBytesRead))
    {
        wprintf(L"ReadProcessMemory[1] failed, %d.\n", GetLastError());
        TerminateProcess(processInformation.hProcess, 0);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        return -4;
    }

#ifdef _DEBUG
    wprintf(L"ImageBaseAddress: 0x%p.\n", peb.Reserved3[1]);
#endif

    // Allocate buffer to read into
    buffer = VirtualAlloc(NULL, SearchLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!buffer)
    {
        wprintf(L"VirtualAlloc failed, %d.\n", GetLastError());
        TerminateProcess(processInformation.hProcess, 0);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        return -5;
    }

    // Read text section into buffer
    if (!ReadProcessMemory(processInformation.hProcess, peb.Reserved3[1], buffer, SearchLength, &szBytesRead))
    {
        wprintf(L"ReadProcessMemory[2] failed, %d.\n", GetLastError());
        TerminateProcess(processInformation.hProcess, 0);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -6;
    }

    // Find pattern in buffer
    patternPtr = FindPattern((QWORD)buffer, SearchLength, Pattern, Mask);

    if (!patternPtr)
    {
        wprintf(L"FindPattern failed.\n");
        TerminateProcess(processInformation.hProcess, 0);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -7;
    }

    // Get relative offset
    offset = (QWORD)patternPtr - (QWORD)buffer;

#ifdef _DEBUG
    wprintf(L"Offset: 0x%p.\n", offset);
#endif

    // Write patch
    if (!WriteProcessMemory(processInformation.hProcess, (LPVOID)((QWORD)peb.Reserved3[1] + offset + PatchOffset), Patch, PatchLen, &szBytesRead))
    {
        wprintf(L"WriteProcessMemory failed, %d.\n", GetLastError());
        TerminateProcess(processInformation.hProcess, 0);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -8;
    }

    // Resume process
    ResumeThread(processInformation.hThread);

    // Free buffer
    VirtualFree(buffer, 0, MEM_RELEASE);

    // Close handles
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    return 0;
}