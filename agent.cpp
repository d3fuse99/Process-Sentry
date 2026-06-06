#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

std::string ConvertWStringToString(const WCHAR* wstr) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string str(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], size, nullptr, nullptr);
    return str;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(5006);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    std::set<DWORD> prevPids;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                prevPids.insert(pe.th32ProcessID);
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    while (true) {
        std::map<DWORD, std::pair<std::string, DWORD>> currentProcesses;
        std::set<DWORD> currentPids;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    currentProcesses[pe.th32ProcessID] = { ConvertWStringToString(pe.szExeFile), pe.th32ParentProcessID };
                    currentPids.insert(pe.th32ProcessID);
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }

        for (DWORD pid : currentPids) {
            if (prevPids.find(pid) == prevPids.end()) {
                std::string childName = currentProcesses[pid].first;
                DWORD ppid = currentProcesses[pid].second;
                std::string parentName = "unknown";

                if (currentProcesses.find(ppid) != currentProcesses.end()) {
                    parentName = currentProcesses[ppid].first;
                }

                std::stringstream ss;
                ss << parentName << ";" << childName << ";" << pid << "\n";
                std::string msg = ss.str();
                send(sock, msg.c_str(), static_cast<int>(msg.length()), 0);
            }
        }

        prevPids = currentPids;

        char buffer[128];
        int bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::stringstream ss(buffer);
            DWORD targetPid;
            while (ss >> targetPid) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
                if (hProcess != NULL) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        }

        Sleep(300);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}