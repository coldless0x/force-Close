#include "hooks.h"
#include <stdio.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

typedef NTSTATUS (NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
typedef NTSTATUS (NTAPI* pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI* pNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(ULONG, void*, ULONG, ULONG*);
typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pNtFreeVirtualMemory)(HANDLE, void**, SIZE_T*, ULONG);

static pNtOpenProcess NtOpenProcess;
static pNtClose NtClose;
static pNtDuplicateObject NtDuplicateObject;
static pNtQuerySystemInformation NtQuerySystemInformation;
static pNtAllocateVirtualMemory NtAllocateVirtualMemory;
static pNtFreeVirtualMemory NtFreeVirtualMemory;

static int InitNtApis(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return 0;

    NtOpenProcess = (pNtOpenProcess)GetProcAddress(nt, "NtOpenProcess");
    NtClose = (pNtClose)GetProcAddress(nt, "NtClose");
    NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(nt, "NtDuplicateObject");
    NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
    NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(nt, "NtAllocateVirtualMemory");
    NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddress(nt, "NtFreeVirtualMemory");

    return NtOpenProcess && NtClose && NtDuplicateObject &&
           NtQuerySystemInformation && NtAllocateVirtualMemory && NtFreeVirtualMemory;
}

static DWORD FindNotepad(void) {
    SIZE_T size = 0x100000;
    void* buffer = NULL;

    if (NtAllocateVirtualMemory(GetCurrentProcess(), &buffer, 0,
        &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0)
        return 0;

    ULONG ret;
    if (NtQuerySystemInformation(SystemProcessInformation, buffer, (ULONG)size, &ret) < 0) {
        NtFreeVirtualMemory(GetCurrentProcess(), &buffer, &size, MEM_RELEASE);
        return 0;
    }

    SYSTEM_PROCESS_INFO* cur = (SYSTEM_PROCESS_INFO*)buffer;
    DWORD pid = 0;

    while (1) {
        if (cur->ImageName.Buffer && cur->ImageName.Length >= 16) {
            int len = cur->ImageName.Length / 2;
            wchar_t* p = cur->ImageName.Buffer + len;
            while (p > cur->ImageName.Buffer && p[-1] != L'\\') p--;
            if (_wcsicmp(p, L"notepad.exe") == 0) {
                pid = (DWORD)(ULONG_PTR)cur->UniqueProcessId;
                break;
            }
        }
        if (!cur->NextEntryOffset) break;
        cur = (SYSTEM_PROCESS_INFO*)((BYTE*)cur + cur->NextEntryOffset);
    }

    NtFreeVirtualMemory(GetCurrentProcess(), &buffer, &size, MEM_RELEASE);
    return pid;
}

static void* g_handleBuffer = NULL;
static SIZE_T g_bufferSize = 0;

static HANDLE_INFO_EX* GetHandles(void) {
    if (!g_handleBuffer) {
        g_bufferSize = 0x200000;
        if (NtAllocateVirtualMemory(GetCurrentProcess(), &g_handleBuffer, 0,
            &g_bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0)
            return NULL;
    }

    while (1) {
        ULONG ret;
        NTSTATUS s = NtQuerySystemInformation(
            SystemExtendedHandleInformation, g_handleBuffer, (ULONG)g_bufferSize, &ret);
        if (s >= 0) return (HANDLE_INFO_EX*)g_handleBuffer;

        if (s != STATUS_INFO_LENGTH_MISMATCH) return NULL;

        SIZE_T newSize = g_bufferSize * 2;
        void* newBuf = NULL;
        if (NtAllocateVirtualMemory(GetCurrentProcess(), &newBuf, 0,
            &newSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0)
            return NULL;
        NtFreeVirtualMemory(GetCurrentProcess(), &g_handleBuffer, &g_bufferSize, MEM_RELEASE);
        g_handleBuffer = newBuf;
        g_bufferSize = newSize;
    }
}

static USHORT FindProcessTypeIndex(DWORD selfPid) {
    HANDLE selfHandle;
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)selfPid;
    cid.UniqueThread = NULL;

    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, 0 };

    if (NtOpenProcess(&selfHandle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid) < 0)
        return 7;

    HANDLE_INFO_EX* info = GetHandles();
    USHORT typeIndex = 7;
    if (info) {
        for (ULONG_PTR i = 0; i < info->Count; i++) {
            if ((ULONG_PTR)info->Handles[i].UniqueProcessId == selfPid &&
                info->Handles[i].HandleValue == selfHandle) {
                typeIndex = info->Handles[i].ObjectTypeIndex;
                break;
            }
        }
    }

    NtClose(selfHandle);
    return typeIndex;
}

int main(void) {
    if (!InitNtApis()) {
        printf("[-] Failed to initialize ntdll functions\n");
        return 1;
    }

    timeBeginPeriod(1);
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    DWORD targetPid = FindNotepad();
    if (!targetPid) {
        printf("[-] Notepad not found\n");
        return 1;
    }
    printf("[+] Protecting Notepad (PID: %lu)\n", targetPid);

    HANDLE notepad;
    OBJECT_ATTRIBUTES noa = { sizeof(noa), 0, 0, 0, 0, 0 };
    CLIENT_ID ncid = { (HANDLE)(ULONG_PTR)targetPid, 0 };

    if (NtOpenProcess(&notepad, PROCESS_QUERY_LIMITED_INFORMATION, &noa, &ncid) < 0) {
        printf("[-] Failed to open Notepad\n");
        return 1;
    }

    DWORD selfPid = GetCurrentProcessId();
    USHORT processTypeIndex = FindProcessTypeIndex(selfPid);
    printf("[+] Process type index: %hu\n", processTypeIndex);

    void* targetObject = NULL;
    HANDLE_INFO_EX* info = GetHandles();
    if (info) {
        for (ULONG_PTR i = 0; i < info->Count; i++) {
            if ((ULONG_PTR)info->Handles[i].UniqueProcessId == selfPid &&
                info->Handles[i].HandleValue == notepad) {
                targetObject = info->Handles[i].Object;
                break;
            }
        }
    }
    NtClose(notepad);

    if (!targetObject) {
        printf("[-] Could not find target object address\n");
        return 1;
    }
    printf("[+] Target object: %p\n", targetObject);

    printf("[+] Entering handle-closing loop (realtime priority)\n");

    while (1) {
        info = GetHandles();
        if (!info) { continue; }

        HANDLE currentPid = NULL;
        HANDLE srcHandle = NULL;

        for (ULONG_PTR i = 0; i < info->Count; i++) {
            HANDLE_ENTRY_EX* e = &info->Handles[i];

            if (e->ObjectTypeIndex != processTypeIndex) continue;
            if (e->Object != targetObject) continue;
            if ((ULONG_PTR)e->UniqueProcessId == selfPid) continue;
            if ((ULONG_PTR)e->UniqueProcessId == targetPid) continue;
            if (!e->HandleValue) continue;

            if (e->UniqueProcessId != currentPid) {
                if (srcHandle) NtClose(srcHandle);
                currentPid = e->UniqueProcessId;
                CLIENT_ID cid = { currentPid, 0 };
                OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, 0 };
                if (NtOpenProcess(&srcHandle, PROCESS_DUP_HANDLE, &oa, &cid) < 0)
                    srcHandle = NULL;
            }

            if (srcHandle) {
                NtDuplicateObject(srcHandle, e->HandleValue, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
            }
        }

        if (srcHandle) NtClose(srcHandle);
    }
}
