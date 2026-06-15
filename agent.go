package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	TH32CS_SNAPPROCESS  = 0x00000002
	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x00000010
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procTerminateProcess           = kernel32.NewProc("TerminateProcess")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot   = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = kernel32.NewProc("Process32FirstW")
	procProcess32NextW             = kernel32.NewProc("Process32NextW")
	procModule32FirstW             = kernel32.NewProc("Module32FirstW")
	procModule32NextW              = kernel32.NewProc("Module32NextW")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")

	wintrust           = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

type PROCESSENTRY32W struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

type MODULEENTRY32W struct {
	DwSize        uint32
	Th32ModuleID  uint32
	Th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	ModBaseAddr   uintptr
	ModBaseSize   uint32
	HModule       uintptr
	SzModule      [256]uint16
	SzExePath     [260]uint16
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          uintptr
	PgKnownSubject uintptr
}

type WINTRUST_DATA struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSIPClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               uintptr
	DwStateAction       uint32
	HWVTStateData       uintptr
	PwszURLReference    uintptr
	DwProvFlags         uint32
	DwUIContext         uint32
	PSignatureSettings  uintptr
}

type WMIPayload struct {
	PPID int    `json:"PPID"`
	Name string `json:"Name"`
	PID  int    `json:"PID"`
	Path string `json:"Path"`
	Cmd  string `json:"Cmd"`
}

type ServerPayload struct {
	ParentName     string   `json:"parent_name"`
	ParentPID      int      `json:"parent_pid"`
	ChildName      string   `json:"child_name"`
	ChildPath      string   `json:"child_path"`
	PID            int      `json:"pid"`
	IsSigned       int      `json:"is_signed"`
	SHA256         string   `json:"sha256"`
	CommandLine    string   `json:"command_line"`
	SuspiciousDLLs []string `json:"suspicious_dlls"`
}

func getProcessNameByPID(pid uint32) string {
	hProcess, _, _ := procOpenProcess.Call(0x1000, 0, uintptr(pid))
	if hProcess == 0 {
		return getProcessNameBySnapshot(pid)
	}
	defer procCloseHandle.Call(hProcess)

	var size uint32 = 1024
	buf := make([]uint16, size)
	ret, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return getProcessNameBySnapshot(pid)
	}
	fullPath := syscall.UTF16ToString(buf[:size])
	parts := strings.Split(fullPath, "\\")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

func getProcessNameBySnapshot(pid uint32) string {
	hSnapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if syscall.Handle(hSnapshot) == syscall.InvalidHandle {
		return "unknown"
	}
	defer procCloseHandle.Call(hSnapshot)

	var pe32 PROCESSENTRY32W
	pe32.DwSize = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32FirstW.Call(hSnapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return "unknown"
	}

	for {
		if pe32.Th32ProcessID == pid {
			return syscall.UTF16ToString(pe32.SzExeFile[:])
		}
		ret, _, _ = procProcess32NextW.Call(hSnapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}
	return "unknown"
}

func isSigned(filePath string) int {
	if filePath == "" {
		return 0
	}

	filePathUTF16, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return 0
	}

	var fileInfo WINTRUST_FILE_INFO
	fileInfo.CbStruct = uint32(unsafe.Sizeof(fileInfo))
	fileInfo.PcwszFilePath = filePathUTF16

	var trustData WINTRUST_DATA
	trustData.CbStruct = uint32(unsafe.Sizeof(trustData))
	trustData.DwUIChoice = 2
	trustData.FdwRevocationChecks = 0
	trustData.DwUnionChoice = 1
	trustData.PFile = uintptr(unsafe.Pointer(&fileInfo))
	trustData.DwStateAction = 1
	trustData.DwProvFlags = 0x10

	actionGUID := GUID{
		Data1: 0x00AAC56B,
		Data2: 0xCD44,
		Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
	}

	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	trustData.DwStateAction = 2
	procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	if int32(ret) == 0 {
		return 1
	}
	return 0
}

func checkDLLSideloading(pid uint32) []string {
	time.Sleep(50 * time.Millisecond)

	hSnapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, uintptr(pid))
	if syscall.Handle(hSnapshot) == syscall.InvalidHandle {
		return nil
	}
	defer procCloseHandle.Call(hSnapshot)

	var me32 MODULEENTRY32W
	me32.DwSize = uint32(unsafe.Sizeof(me32))

	ret, _, _ := procModule32FirstW.Call(hSnapshot, uintptr(unsafe.Pointer(&me32)))
	if ret == 0 {
		return nil
	}

	var suspiciousDLLs []string
	for {
		dllPath := syscall.UTF16ToString(me32.SzExePath[:])
		if dllPath != "" {
			dllPathLower := strings.ToLower(dllPath)
			isUserWritable := strings.Contains(dllPathLower, "\\users\\") ||
				strings.Contains(dllPathLower, "\\temp\\") ||
				strings.Contains(dllPathLower, "\\downloads\\") ||
				strings.Contains(dllPathLower, "\\appdata\\") ||
				strings.Contains(dllPathLower, "\\programdata\\")

			if isUserWritable {
				if isSigned(dllPath) == 0 {
					suspiciousDLLs = append(suspiciousDLLs, dllPath)
				}
			}
		}
		ret, _, _ = procModule32NextW.Call(hSnapshot, uintptr(unsafe.Pointer(&me32)))
		if ret == 0 {
			break
		}
	}
	return suspiciousDLLs
}

func calculateSHA256(filePath string) string {
	if filePath == "" {
		return ""
	}
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Sync()
}

func quarantineFile(filePath string) {
	if filePath == "" {
		return
	}
	os.MkdirAll("C:\\ProgramData\\ProcessSentry\\Quarantine", 0755)
	parts := strings.Split(filePath, "\\")
	fileName := parts[len(parts)-1]
	destPath := "C:\\ProgramData\\ProcessSentry\\Quarantine\\" + fileName + ".vir"
	err := os.Rename(filePath, destPath)
	if err != nil {
		copyFile(filePath, destPath)
		os.Remove(filePath)
	}
	println("[Agent] Successfully quarantined malicious file to:", destPath)
}

func isolateNetwork() {
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=ProcessSentry_Isolate", "dir=out", "action=block").Run()
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=ProcessSentry_Isolate", "dir=in", "action=block").Run()
	println("[Agent] HOST NETWORK ISOLATED: Firewall rules applied.")
}

func restoreNetwork() {
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ProcessSentry_Isolate").Run()
	println("[Agent] HOST NETWORK RESTORED: Isolation rules cleared.")
}

func terminateProcess(pid uint32) {
	hProcess, _, _ := procOpenProcess.Call(0x0001, 0, uintptr(pid))
	if hProcess != 0 {
		procTerminateProcess.Call(hProcess, 0)
		procCloseHandle.Call(hProcess)
		println("[Agent] Successfully terminated malicious process PID:", pid)
	}
}

func socketReceiver(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			println("[Agent] Connection to server lost. Auto-restoring network for safety...")
			restoreNetwork()
			break
		}
		line = strings.TrimSpace(line)
		if line == "ISOLATE" {
			isolateNetwork()
		} else if line == "RESTORE" {
			restoreNetwork()
		} else if strings.HasPrefix(line, "QUARANTINE:") {
			path := strings.TrimPrefix(line, "QUARANTINE:")
			quarantineFile(path)
		} else if pid, err := strconv.Atoi(line); err == nil {
			println("[Agent] Received termination command for process PID:", pid)
			terminateProcess(uint32(pid))
		}
	}
}

func main() {
	restoreNetwork()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sigs
		println("[Agent] Intercepted exit signal. Restoring network before shutdown...")
		restoreNetwork()
		os.Exit(0)
	}()

	println("[Agent] Initializing EDR agent in Go...")
	serverIP := "127.0.0.1"
	serverPort := "5006"

	var conn net.Conn
	var err error

	for {
		println("[Agent] Connecting to server " + serverIP + ":" + serverPort + "...")
		conn, err = net.Dial("tcp", serverIP+":"+serverPort)
		if err == nil {
			println("[Agent] Connection established successfully!")
			break
		}
		println("[Agent] Server unavailable. Retrying in 3 seconds...")
		time.Sleep(3 * time.Second)
	}

	go socketReceiver(conn)

	cmdText := "$ErrorActionPreference = 'Stop'; $q = \"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'\"; Register-CimIndicationEvent -Query $q -SourceIdentifier 'P'; while ($true) { $e = Wait-Event -SourceIdentifier 'P'; $t = $e.SourceEventArgs.NewEvent.TargetInstance; [PSCustomObject]@{PPID=$t.ParentProcessId;Name=$t.Name;PID=$t.ProcessId;Path=$t.ExecutablePath;Cmd=$t.CommandLine} | ConvertTo-Json -Compress; Remove-Event -SourceIdentifier 'P' }"

	println("[Agent] Starting background WMI process event subscription via PowerShell...")
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmdText)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		println("[Agent] Error getting stdout pipe:", err.Error())
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		println("[Agent] Error getting stderr pipe:", err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		println("[Agent] Error starting PowerShell monitor:", err.Error())
		return
	}

	go func() {
		errReader := bufio.NewReader(stderr)
		for {
			errLine, err := errReader.ReadString('\n')
			if err != nil {
				break
			}
			errLine = strings.TrimSpace(errLine)
			if len(errLine) > 0 {
				println("[Agent] CRITICAL POWERSHELL ERROR:", errLine)
				println("[Agent] Please ensure the agent is running with ADMINISTRATOR privileges!")
			}
		}
	}()

	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			println("[Agent] PowerShell event loop exited unexpectedly.")
			break
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var wmi WMIPayload
		if err := json.Unmarshal([]byte(line), &wmi); err != nil {
			continue
		}

		parentName := getProcessNameByPID(uint32(wmi.PPID))
		sha256Val := calculateSHA256(wmi.Path)
		isSignedVal := isSigned(wmi.Path)
		suspiciousDLLs := checkDLLSideloading(uint32(wmi.PID))

		println("[Agent] Intercepted process:", wmi.Name, "(PID:", wmi.PID, ")")

		payload := ServerPayload{
			ParentName:     parentName,
			ParentPID:      wmi.PPID,
			ChildName:      wmi.Name,
			ChildPath:      wmi.Path,
			PID:            wmi.PID,
			IsSigned:       isSignedVal,
			SHA256:         sha256Val,
			CommandLine:    wmi.Cmd,
			SuspiciousDLLs: suspiciousDLLs,
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		_, err = conn.Write(append(jsonData, '\n'))
		if err != nil {
			println("[Agent] Connection lost. Reconnecting...")
			conn.Close()
			for {
				conn, err = net.Dial("tcp", serverIP+":"+serverPort)
				if err == nil {
					println("[Agent] Connection re-established!")
					go socketReceiver(conn)
					break
				}
				time.Sleep(3 * time.Second)
			}
		}
	}
}
