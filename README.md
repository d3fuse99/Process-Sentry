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

Project File Structure
----------------------
* dist - Directory containing compiled static frontend dashboard assets.
* agent.exe - Compiled telemetry monitoring agent.
* agent.go - Go source code for the monitoring agent.
* server.py - Core Python backend serving REST APIs, SSE, and managing the SQLite database.
* config.json - Security policy configuration, threat rules, allowlists, and VirusTotal API tokens.
* start.bat - Self-elevating system launcher script.
* stop.bat - Cleanup script to terminate active processes and restore network connectivity.
* process_sentry.db - SQLite database containing event telemetry histories (generated dynamically on first launch).
