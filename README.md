# Process-Sentry 🛡️
<img width="2546" height="1316" alt="image" src="https://github.com/user-attachments/assets/a6884bf2-a8f0-4fd8-847f-1b754601c393" />

Advanced event-driven EDR (Endpoint Detection & Response) & automated exploit mitigation suite for Windows.

Status: **Beta v1.2** | License: **GPLv3** | Platform: **Windows**

Process-Sentry is a lightweight, high-performance event-driven Endpoint Detection and Response (EDR) tool designed to identify, visualize, and neutralize zero-day exploits in real-time. Instead of relying on outdated static file signatures, it monitors the **behavioral process tree** and loaded modules of the operating system to intercept unauthorized execution patterns, such as suspicious shell spawning, LOLBAS attacks, DLL sideloading, and untrusted binaries execution.

## Advanced Incident Response Capabilities
<img width="573" height="504" alt="image" src="https://github.com/user-attachments/assets/684f6afe-4309-4bf5-ab37-39feaafe21b0" />

* **Zero-Polling Event Auditing**: Subscribes directly to Windows Management Instrumentation (WMI) process creation events. It acts as a passive listener, consuming 0% CPU at idle while capturing even ultra-short-lived processes instantly.
* **Active Response Engine**: Features an automated incident response loop that instantly terminates dangerous process branches on detection using native Win32 `TerminateProcess` API.
* **Heuristic Command Line Engine**: Analyzes raw process execution arguments (e.g., PowerShell execution policy bypass, base64-encoded payloads, or network download strings) to stop script-based evasion.
* **Static Analysis Hashing**: Instantly calculates the SHA-256 cryptographic hash of every newly launched process binary for reputation lookups.
* **Authenticode Signature Check**: Interrogates the Win32 `WinVerifyTrust` subsystem to detect unsigned critical binaries and enforce security catalog trust rules.
* **DLL Sideloading Detection (New)**: Leverages lightweight Win32 module snapshots to identify unsigned, unauthorized DLLs loaded by signed system binaries from user-writable directories (e.g., `AppData`, `Temp`, `Downloads`).
* **VirusTotal API Integration (New)**: Automated cloud reputation verification that queries process SHA-256 hashes against VirusTotal threat intelligence. Includes a thread-safe local cache to minimize external network requests.
* **High-Performance Process Querying (New)**: Obtains process identity directly through Win32 handles using `QueryFullProcessImageNameW`, reducing CPU consumption to near-zero levels during process spawning bursts.
* **Async Threaded Telemetry Logging (New)**: Implements SQLite Write-Ahead Logging (WAL) combined with a thread-safe transaction queue, preventing concurrent database lockups under high telemetry load.
* **Interactive Forensic HUD**: Cyberpunk-inspired interactive web dashboard built with React and Tailwind CSS v4 for live telemetry streaming and alerts.
* **Host Network Isolation**: Instantly isolate compromised hosts on-demand directly from the dashboard. Activating this feature deploys strict inbound/outbound Windows Firewall rules that immediately cut off all public internet and local network access to prevent lateral movement, while safely preserving the local loopback telemetry stream.
* **Persistent Incident Database**: Integrated local SQLite database to log and retrieve historical security incidents, accessible via the `Incident History` tab.
* **Threat Quarantine**: Automated mitigation that moves malicious binaries to a locked quarantine folder (`C:\ProgramData\ProcessSentry\Quarantine\`) with safe extensions (`.vir`) to prevent execution.
* **External Rules Engine**: Load process rules, suspicious parents, and dangerous keywords dynamically from an external `config.json` file.

## Threat Detection Matrix

| Detection Layer | Mechanics & Subsystems | Targeted Threats & Attacks |
| :--- | :--- | :--- |
| **LOLBAS (Behavioral)** | Monitors parent-child relationships. Triggers if protected applications (browsers, MS Office, Explorer) attempt to spawn command shells (cmd, powershell, mshta, cscript). | Initial access execution, privilege escalation, malicious macros, browser-based stagers. |
| **Command Line Heuristics** | Performs string-heuristics on raw execution arguments, scanning for obfuscation, bypass flags, or network download parameters. | PowerShell execution policy bypass, Base64 encoded payloads (`-enc`), network stagers (`DownloadString`, `iex`). |
| **Authenticode Verification** | Validates process signatures via `WinVerifyTrust`. Triggers if critical system binaries (svchost, lsass, conhost) are executed without a valid Microsoft signature. | Masquerading (malware renaming itself to svchost.exe), payload dropping in user-writable directories. |
| **DLL Sideloading Detection** | Scans memory maps of signed binaries using Win32 Toolhelp snapshots (`Module32FirstW`/`Module32NextW`) to flag mapped unsigned modules in writable paths. | Hijacking trusted processes to execute unsigned malicious DLLs. |
| **Threat Intelligence & Cloud Rep** | Performs reputation lookups of SHA-256 hashes against a local threat database and VirusTotal API. | Known malware campaigns, ransomware, stealers, and dual-use tools (e.g., Mimikatz). |

## Interactive Forensic Capabilities

* **Real-Time Search**: Use the `[ SEARCH TELEMETRY... ]` input bar to filter active processes, PIDs, hashes, or live alert feeds on the fly.
* **One-Click Clipboard Copy**: Forensic analysts can instantly copy command-line strings and SHA-256 hashes directly from the feed or the detail modals for rapid external lookups (e.g., VirusTotal, Google).
* **Detailed Process Inspection**: Clicking on any process node in the active process map opens a detailed view of its execution context.
* **Manual Incident Response**: Analysts can manually terminate any running process on demand directly from the detail modal via the `Terminate Process` action.

## Threat Simulation & Testing

To test and demonstrate the real-time active defense capabilities of Process-Sentry:

1. Open a standard command prompt (`cmd.exe`) or run dialog (`Win + R`).
2. Execute a typical obfuscated PowerShell bypass command:

   ```cmd
   powershell.exe -ep bypass -command Write-Host "Threat Simulation"
   ```

3. **Expected Result**: The PowerShell window will open and instantly vanish. The process is terminated before it can execute its payload. The Process-Sentry console logs the termination, and the HUD instantly locks into a red alarm modal displaying the blocked command line and SHA-256 hash of the process.

> ⚠️ **Important Note on Host Isolation**: Activating the **ISOLATE HOST** feature instantly drops all public internet and local network access for the target machine. This is designed to halt lateral movement and command-and-control (C2) communications immediately. Only the local EDR console communication (on `127.0.0.1`) remains active. Clicking **RESTORE HOST** will immediately restore normal network operations.

## How to run

1. **Prerequisites**: Ensure you have Python 3.10+, Go (Golang) 1.20+, and Node.js installed on your Windows system.
2. **Install Dependencies**: Run `npm.cmd install` in the project root to fetch frontend libraries.
3. **Build Frontend**: Execute `npm.cmd run build` to compile the dashboard into the static production folder.
4. **Build Go Agent**: Execute `go build agent.go` in your terminal to compile the high-performance agent executable (`agent.exe`).
5. **Configuration**: If you want to enable cloud reputation, add your VirusTotal API key in `config.json` inside the `"VT_API_KEY"` property.
6. **One-Click Launch**: Open your VS Code editor, navigate to `package.json`, hover over the `"sentry"` script, and click **Run Script** (or simply run `npm.cmd run sentry` in the terminal). This will automatically launch all three components with full Administrator privileges and open your default browser to `http://localhost:3000`.

## Tech stack

* **Go (Golang)**: High-performance, lightweight native Windows agent utilizing Win32 APIs for signature validation, module analysis, and active process termination.
* **Python**: Heuristic rule engine, cloud reputation database client, SQLite logging, and multi-threaded socket/SSE web server.
* **React / Vite**: Fast, modern, responsive frontend architecture.
* **Tailwind CSS v4**: Modern, high-performance cyber-ops styling engine.

## License

This project is licensed under the **GNU General Public License v3 (GPLv3)** - see the LICENSE file for details.
