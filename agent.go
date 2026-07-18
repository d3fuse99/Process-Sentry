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

	"github.com/secDre4mer/etw"
	"golang.org/x/sys/windows"
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procTerminateProcess            = kernel32.NewProc("TerminateProcess")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot   = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = kernel32.NewProc("Process32FirstW")
	procProcess32NextW             = kernel32.NewProc("Process32NextW")
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

type AgentConfig struct {
	SecretToken string `json:"SECRET_TOKEN"`
}

type ServerPayload struct {
	Token       string `json:"token"`
	ParentName  string `json:"parent_name"`
	ParentPID   int    `json:"parent_pid"`
	ChildName   string `json:"child_name"`
	ChildPath   string `json:"child_path"`
	PID         int    `json:"pid"`
	IsSigned    int    `json:"is_signed"`
	SHA256      string `json:"sha256"`
	CommandLine string `json:"command_line"`
}

func loadAgentConfig() string {
	file, err := os.Open("config.json")
	if err != nil {
		return "ProcessSentrySecretToken2026"
	}
	defer file.Close()

	var config AgentConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return "ProcessSentrySecretToken2026"
	}
	return config.SecretToken
}

func getProcessNameByPID(pid uint32) string {
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

func getProcessPath(pid uint32) string {
	hProcess, _, _ := procOpenProcess.Call(0x1000, 0, uintptr(pid))
	if hProcess == 0 {
		return ""
	}
	defer procCloseHandle.Call(hProcess)

	var size uint32 = 1024
	buf := make([]uint16, size)
	ret, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret != 0 {
		return syscall.UTF16ToString(buf[:size])
	}
	return ""
}

func getProcessNameFromPath(path string) string {
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "\\")
	return parts[len(parts)-1]
}

func normalizeDevicePath(devicePath string) string {
	if devicePath == "" {
		return ""
	}
	if strings.HasPrefix(devicePath, "\\Device\\HarddiskVolume") {
		parts := strings.SplitN(devicePath, "\\", 4)
		if len(parts) >= 4 {
			return "C:\\" + parts[3]
		}
	}
	return devicePath
}

func isSigned(filePath string) int {
	if filePath == "" {
		return 0
	}
	pathLower := strings.ToLower(filePath)
	pathLower = strings.ReplaceAll(pathLower, "/", "\\")
	if strings.Contains(pathLower, "c:\\windows\\system32") || strings.Contains(pathLower, "c:\\windows\\syswow64") {
		return 1
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

func isWhitelisted(pid uint32, name string) bool {
	if pid == 0 || pid == 4 {
		return true
	}
	nameLower := strings.ToLower(name)
	whitelist := []string{
		"system", "idle", "csrss.exe", "lsass.exe",
		"smss.exe", "services.exe", "wininit.exe", "winlogon.exe",
	}
	for _, w := range whitelist {
		if nameLower == w {
			return true
		}
	}
	return false
}

func terminateProcess(pid uint32) {
	name := getProcessNameByPID(pid)
	if isWhitelisted(pid, name) {
		println("[Agent] Refusing to terminate critical system process:", name, " (PID:", pid, ")")
		return
	}
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
	signal.Notify(sigs, os.Interrupt)
	go func() {
		<-sigs
		println("[Agent] Intercepted exit signal. Restoring network before shutdown...")
		restoreNetwork()
		os.Exit(0)
	}()

	secretToken := loadAgentConfig()
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
		println("[Agent] Server unavailable (" + err.Error() + "). Retrying in 3 seconds...")
		time.Sleep(3 * time.Second)
	}

	go socketReceiver(conn)

	println("[Agent] Starting background WMI-free ETW Kernel-Process session...")
	guid, err := windows.GUIDFromString("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}")
	if err != nil {
		println("[Agent] Error parsing GUID:", err.Error())
		return
	}

	session, err := etw.NewSession()
	if err != nil {
		println("[Agent] Error creating ETW session:", err.Error())
		return
	}
	defer session.Close()

	if err := session.AddProvider(guid); err != nil {
		println("[Agent] Error adding ETW provider:", err.Error())
		return
	}

	cb := func(e *etw.Event) {
		if e.Header.ID == 1 {
			data, err := e.EventProperties()
			if err != nil {
				return
			}

			var childPid uint32
			if pidVal, ok := data["ProcessID"]; ok {
				switch v := pidVal.(type) {
				case uint32:
					childPid = v
				case int32:
					childPid = uint32(v)
				case int:
					childPid = uint32(v)
				case float64:
					childPid = uint32(v)
				}
			}
			if childPid == 0 {
				return
			}

			var parentPid uint32
			if ppidVal, ok := data["ParentProcessID"]; ok {
				switch v := ppidVal.(type) {
				case uint32:
					parentPid = v
				case int32:
					parentPid = uint32(v)
				case int:
					parentPid = uint32(v)
				case float64:
					parentPid = uint32(v)
				}
			} else if ppidVal, ok := data["ParentProcessId"]; ok {
				switch v := ppidVal.(type) {
				case uint32:
					parentPid = v
				case int32:
					parentPid = uint32(v)
				case int:
					parentPid = uint32(v)
				case float64:
					parentPid = uint32(v)
				}
			}

			var childPath string
			if pathVal, ok := data["ImageName"]; ok {
				if s, ok := pathVal.(string); ok {
					childPath = normalizeDevicePath(s)
				}
			}
			if childPath == "" {
				childPath = getProcessPath(childPid)
			}

			childName := getProcessNameFromPath(childPath)
			if childName == "" {
				childName = getProcessNameByPID(childPid)
			}

			var commandLine string
			if cmdVal, ok := data["CommandLine"]; ok {
				if s, ok := cmdVal.(string); ok {
					commandLine = s
				}
			}