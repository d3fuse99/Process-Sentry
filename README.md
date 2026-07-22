<img width="2546" height="1316" alt="изображение" src="https://github.com/user-attachments/assets/57977a0b-fef2-4db3-b622-b4cc3abc7d4d" />


Process-Sentry
==============

Local Endpoint Detection and Response (EDR) solution designed for process activity monitoring, network socket correlation, and automated threat mitigation on Windows operating systems.

Features
--------
* Hybrid Telemetry Monitoring: Intercepts process spawn events using ETW (Event Tracing for Windows) alongside a resilient Toolhelp32 snapshot polling mechanism.
* Network Activity Tracking: Collects and maps established network socket connections (destination IP and ports) directly to their spawning process PIDs.
* VirusTotal Threat Intelligence: Automatically queries file SHA256 hashes against VirusTotal reputation databases.
* Path Masquerading & DLL Sideloading Detection: Detects and blocks critical system binaries launching from non-standard or user-writable directories.
* Local Allowlisting: Bypasses security detection checks for trusted file paths and hash signatures configured in the policy.
* Automated Remediation: Instantly terminates blocked processes and isolates host network interfaces upon triggering security threshold alerts.

System Requirements
-------------------
* Windows 10 / 11 Operating System
* Python 3.x
* Go Compiler (only required if modifying the agent source code)

Quick Start
-----------
To deploy and launch the entire infrastructure, run:

start.bat

The script will automatically request administrator privileges (required for ETW events and Windows Firewall network isolation rules), host the EDR dashboard on port 3000, and launch the background telemetry agent.

<img width="573" height="504" alt="изображение" src="https://github.com/user-attachments/assets/2adae09e-0f55-4708-a7e9-5f88319160d1" />
