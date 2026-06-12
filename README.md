<h1>Process-Sentry 🛡️</h1>

<p align="center">
  <strong>Advanced event-driven EDR (Endpoint Detection & Response) & automated exploit mitigation suite for Windows.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Beta%20v1.1.0-orange" alt="Status" />
  <img src="https://img.shields.io/badge/License-GPLv3-green" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform" />
</p>

<p align="center">
  <img src="assets/hud_normal.png" alt="PROCESS-SENTRY Telemetry Map" width="800" />
</p>

<p><strong>Note:</strong> This project is currently in the active Beta v1.1.0 phase. We are continually expanding the heuristic signatures, threat intelligence database, and automated mitigation capabilities.</p>

<p align="center">
  <img src="assets/hud_alert.png" alt="PROCESS-SENTRY Incident Alert" width="600" />
</p>

<p>Process-Sentry is a lightweight, high-performance event-driven Endpoint Detection and Response (EDR) tool designed to identify, visualize, and neutralize zero-day exploits in real-time. Instead of relying on outdated static file signatures, it monitors the <strong>behavioral process tree</strong> of the operating system to intercept unauthorized execution patterns, such as suspicious shell spawning, LOLBAS attacks, and untrusted binaries execution.</p>

<h2>Advanced Incident Response Capabilities</h2>

<ul>
  <li><strong>Zero-Polling Event Auditing:</strong> Subscribes directly to Windows Management Instrumentation (WMI) process creation events. It acts as a passive listener, consuming 0% CPU at idle while capturing even ultra-short-lived processes instantly.</li>
  <li><strong>Active Response Engine:</strong> Features an automated incident response loop that instantly terminates dangerous process branches on detection using native Win32 <code>TerminateProcess</code> API.</li>
  <li><strong>Heuristic Command Line Engine:</strong> Analyzes raw process execution arguments (e.g., PowerShell execution policy bypass, base64-encoded payloads, or network download strings) to stop script-based evasion.</li>
  <li><strong>Static Analysis Hashing:</strong> Instantly calculates the SHA-256 cryptographic hash of every newly launched process binary for reputation lookups.</li>
  <li><strong>Authenticode Signature Check:</strong> Interrogates the Win32 <code>WinVerifyTrust</code> subsystem to detect unsigned critical binaries and enforce security catalog trust rules.</li>
  <li><strong>Interactive Forensic HUD:</strong> Cyberpunk-inspired interactive web dashboard built with React and Tailwind CSS v4 for live telemetry streaming and alerts.</li>
  <li><strong>Host Network Isolation (New):</strong> Instantly isolate compromised hosts on-demand directly from the dashboard via Windows Firewall block rules, while preserving the EDR telemetry socket connection.</li>
  <li><strong>Persistent Incident Database (New):</strong> Integrated local SQLite database to log and retrieve historical security incidents, accessible via the <code>Incident History</code> tab.</li>
  <li><strong>Threat Quarantine (New):</strong> Automated mitigation that moves malicious binaries to a locked quarantine folder (<code>C:\ProgramData\ProcessSentry\Quarantine\</code>) with safe extensions (<code>.vir</code>) to prevent execution.</li>
  <li><strong>External Rules Engine (New):</strong> Load process rules, suspicious parents, and dangerous keywords dynamically from an external <code>config.json</code> file.</li>
</ul>

<h2>Threat Detection Matrix</h2>

<table border="1" cellpadding="5">
  <thead>
    <tr>
      <th>Detection Layer</th>
      <th>Mechanics & Subsystems</th>
      <th>Targeted Threats & Attacks</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>LOLBAS (Behavioral)</strong></td>
      <td>Monitors parent-child relationships. Triggers if protected applications (browsers, MS Office, Explorer) attempt to spawn command shells (cmd, powershell, mshta, cscript).</td>
      <td>Initial access execution, privilege escalation, malicious macros, browser-based stagers.</td>
    </tr>
    <tr>
      <td><strong>Command Line Heuristics</strong></td>
      <td>Performs string-heuristics on raw execution arguments, scanning for obfuscation, bypass flags, or network download parameters.</td>
      <td>PowerShell execution policy bypass, Base64 encoded payloads (<code>-enc</code>), network stagers (<code>DownloadString</code>, <code>iex</code>).</td>
    </tr>
    <tr>
      <td><strong>Authenticode Verification</strong></td>
      <td>Validates process signatures via <code>WinVerifyTrust</code>. Triggers if critical system binaries (svchost, lsass, conhost) are executed without a valid Microsoft signature.</td>
      <td>Masquerading (malware renaming itself to svchost.exe), payload dropping in user-writable directories.</td>
    </tr>
    <tr>
      <td><strong>Threat Intelligence</strong></td>
      <td>Performs reputation lookups of SHA-256 hashes against a customizable local threat database.</td>
      <td>Known malware campaigns, ransomware, stealers, and dual-use tools (e.g., Mimikatz).</td>
    </tr>
  </tbody>
</table>

<h2>Interactive Forensic Capabilities</h2>

<ul>
  <li><strong>Real-Time Search:</strong> Use the <code>[ SEARCH TELEMETRY... ]</code> input bar to filter active processes, PIDs, hashes, or live alert feeds on the fly.</li>
  <li><strong>One-Click Clipboard Copy:</strong> Forensic analysts can instantly copy command-line strings and SHA-256 hashes directly from the feed or the detail modals for rapid external lookups (e.g., VirusTotal, Google).</li>
  <li><strong>Detailed Process Inspection:</strong> Clicking on any process node in the active process map opens a detailed view of its execution context.</li>
  <li><strong>Manual Incident Response:</strong> Analysts can manually terminate any running process on demand directly from the detail modal via the <code>Terminate Process</code> action.</li>
</ul>

<h2>Threat Simulation & Testing</h2>

<p>To test and demonstrate the real-time active defense capabilities of Process-Sentry:</p>

<ol>
  <li>Open a standard command prompt (<code>cmd.exe</code>) or run dialog (<code>Win + R</code>).</li>
  <li>Execute a typical obfuscated PowerShell bypass command:
    <pre>powershell.exe -ep bypass -command Write-Host "Threat Simulation"</pre>
  </li>
  <li><strong>Expected Result:</strong> The PowerShell window will open and instantly vanish. The process is terminated before it can execute its payload. The Process-Sentry console logs the termination, and the HUD instantly locks into a red alarm modal displaying the blocked command line and SHA-256 hash of the process.</li>
</ol>

<h2>How to run</h2>

<ol>
  <li><strong>Prerequisites:</strong> Ensure you have Python 3.10+, Go (Golang) 1.20+, and Node.js installed on your Windows system.</li>
  <li><strong>Install Dependencies:</strong> Run <code>npm.cmd install</code> in the project root to fetch frontend libraries.</li>
  <li><strong>Build Frontend:</strong> Execute <code>npm.cmd run build</code> to compile the dashboard into the static production folder.</li>
  <li><strong>Build Go Agent:</strong> Execute <code>go build agent.go</code> in your terminal to compile the high-performance agent executable (<code>agent.exe</code>).</li>
  <li><strong>One-Click Launch:</strong> Open your VS Code editor, navigate to <code>package.json</code>, hover over the <code>"sentry"</code> script, and click <strong>Run Script</strong> (or simply run <code>npm.cmd run sentry</code> in the terminal). This will automatically launch all three components with full Administrator privileges and open your default browser to <code>http://localhost:3000</code>.</li>
</ol>

<h2>Tech stack</h2>

<ul>
  <li><strong>Go (Golang):</strong> High-performance, lightweight native Windows agent utilizing Win32 APIs for signature validation and active process termination.</li>
  <li><strong>Python:</strong> Heuristic rule engine, reputation database, SQLite logging, and multi-threaded socket/SSE web server.</li>
  <li><strong>React / Vite:</strong> Fast, modern, responsive frontend architecture.</li>
  <li><strong>Tailwind CSS v4:</strong> Modern, high-performance cyber-ops styling engine.</li>
</ul>

<h2>License</h2>

<p>This project is licensed under the <strong>GNU General Public License v3 (GPLv3)</strong> - see the LICENSE file for details.</p>
