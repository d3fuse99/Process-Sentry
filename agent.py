import ctypes
from ctypes import wintypes
import socket
import time
import subprocess
import hashlib
import threading
import json

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = -1

kernel32 = ctypes.windll.kernel32

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_void_p),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260)
    ]

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL

wintrust = ctypes.windll.wintrust

class WINTRUST_FILE_INFO(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p)
    ]

class WINTRUST_DATA(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p)
    ]

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8)
    ]

wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
wintrust.WinVerifyTrust.restype = wintypes.LONG

action_guid = GUID()
action_guid.Data1 = 0x00AAC56B
action_guid.Data2 = 0xCD44
action_guid.Data3 = 0x11D0
action_guid.Data4 = (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)

def get_process_name_by_pid(pid):
    hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnapshot == INVALID_HANDLE_VALUE:
        return "unknown"
    
    pe32 = PROCESSENTRY32W()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    
    name = "unknown"
    if kernel32.Process32FirstW(hSnapshot, ctypes.byref(pe32)):
        while True:
            if pe32.th32ProcessID == pid:
                name = pe32.szExeFile
                break
            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe32)):
                break
                
    kernel32.CloseHandle(hSnapshot)
    return name

def is_signed(file_path):
    if not file_path:
        return 0
    path_lower = file_path.lower()
    if "c:\\windows\\system32" in path_lower or "c:\\windows\\syswow64" in path_lower:
        return 1
    try:
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2
        trust_data.fdwRevocationChecks = 0
        trust_data.dwUnionChoice = 1
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = 1
        trust_data.dwProvFlags = 0x10

        ret = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(trust_data))

        trust_data.dwStateAction = 2
        wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(trust_data))

        return 1 if ret == 0 else 0
    except Exception:
        return 0

def calculate_sha256(file_path):
    if not file_path:
        return ""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return ""

def terminate_process(pid):
    hProcess = kernel32.OpenProcess(0x0001, False, pid)
    if hProcess:
        kernel32.TerminateProcess(hProcess, 0)
        kernel32.CloseHandle(hProcess)
        print(f"[Agent] Successfully terminated malicious process PID: {pid}")

def socket_receiver(sock):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            pid_str = data.decode("utf-8").strip()
            if pid_str.isdigit():
                print(f"[Agent] Received termination command for process PID: {pid_str}")
                terminate_process(int(pid_str))
        except Exception as e:
            print(f"[Agent] Error receiving termination command: {e}")
            break

def main():
    print("[Agent] Initializing EDR agent...")
    server_ip = "127.0.0.1"
    server_port = 5006

    sock = None
    while True:
        try:
            print(f"[Agent] Connecting to server {server_ip}:{server_port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, server_port))
            print("[Agent] Connection established successfully!")
            break
        except Exception as e:
            print(f"[Agent] Server unavailable ({e}). Retrying in 3 seconds...")
            time.sleep(3)

    receiver_thread = threading.Thread(target=socket_receiver, args=(sock,), daemon=True)
    receiver_thread.start()

    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        "$ErrorActionPreference = 'Stop'; "
        "$q = \"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'\"; "
        "Register-CimIndicationEvent -Query $q -SourceIdentifier 'P'; "
        "while ($true) { "
        "  $e = Wait-Event -SourceIdentifier 'P'; "
        "  $t = $e.SourceEventArgs.NewEvent.TargetInstance; "
        "  [PSCustomObject]@{PPID=$t.ParentProcessId;Name=$t.Name;PID=$t.ProcessId;Path=$t.ExecutablePath;Cmd=$t.CommandLine} | ConvertTo-Json -Compress; "
        "  Remove-Event -SourceIdentifier 'P' "
        "}"
    ]

    print("[Agent] Starting background WMI process event subscription via PowerShell...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    
    while True:
        line = proc.stdout.readline()
        if not line:
            err = proc.stderr.read().strip()
            if err:
                print(f"[Agent] CRITICAL POWERSHELL ERROR: {err}")
                print("[Agent] Please ensure the agent is running with ADMINISTRATOR privileges!")
            else:
                print("[Agent] PowerShell event loop exited unexpectedly.")
            break
            
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            parent_pid = int(event["PPID"]) if event["PPID"] else 0
            child_name = event["Name"]
            child_pid = int(event["PID"]) if event["PID"] else 0
            child_path = event["Path"] if event["Path"] else ""
            command_line = event["Cmd"] if event["Cmd"] else ""

            print(f"[Agent] Intercepted process: {child_name} (PID: {child_pid})")

            parent_name = get_process_name_by_pid(parent_pid)
            sha256_val = calculate_sha256(child_path)
            is_signed_val = is_signed(child_path)

            payload = {
                "parent_name": parent_name,
                "child_name": child_name,
                "pid": child_pid,
                "is_signed": is_signed_val,
                "sha256": sha256_val,
                "command_line": command_line
            }
            
            message = json.dumps(payload) + "\n"
            sock.sendall(message.encode('utf-8'))
        except Exception as ex:
            print(f"[Agent] Event processing error: {ex}")

if __name__ == "__main__":
    main()