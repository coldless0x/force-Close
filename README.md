# syscall NoRead

A proof-of-concept **userspace-only** handle-closing loop that protects a target process (Notepad) from being opened and read by other processes — with no driver, no hooks, no DLL injection, and no DACL manipulation.

## How it works

1. **Find the target** — enumerates processes via `NtQuerySystemInformation` to locate `notepad.exe`
2. **Learn the EPROCESS** — opens a handle to Notepad, then scans the system handle table to find the `Object` field (kernel EPROCESS address) associated with it
3. **Spin loop** — at `REALTIME_PRIORITY_CLASS`, iterates the system handle table continuously:
   - For every **Process**-type handle whose `Object` matches the target EPROCESS address
   - Opens the source process with `PROCESS_DUP_HANDLE` and calls `NtDuplicateObject` with `DUPLICATE_CLOSE_SOURCE`
   - Handles from the same source process are batched (one `NtOpenProcess` per PID)

## Key design choices

| Choice | Why |
|---|---|
| **`Object` pointer comparison** | Avoids expensive `NtDuplicateObject` → `NtQueryInformationProcess` verification per handle — one pointer compare instead |
| **Batched by source PID** | Opens each source process once, closes all matching handles, then closes the process |
| **Reusable query buffer** | Eliminates `NtAllocateVirtualMemory`/`NtFreeVirtualMemory` per loop iteration |
| **No Sleep, no yield** | Spins at 100% of one core for maximum responsiveness |
| **`NtOpenProcess` instead of syscall stubs** | All NT APIs resolved via `GetProcAddress` — no hand-written syscall stubs, no MASM |

## Limitations

- **Cannot block open+read in a single scheduler timeslice.** A caller that issues `NtOpenProcess` → `NtReadVirtualMemory` back-to-back in user mode will complete both before the scanning loop can react. The handle is closed, but the read already happened.
- **Userspace-only.** True interception of cross-process syscalls requires a kernel driver with `ObRegisterCallbacks`.
- **One core pinned.** The spin loop keeps one logical processor at 100%.

## Build

```
Open x64 Native Tools Command Prompt
msbuild /p:Configuration=Release /p:Platform=x64
```

Run **before** launching the test tool.

## Discord

`0x283`

---

**Project for educational purposes.** Works within the hard limits of userspace — a demonstration of how far you can get without going ring0.
