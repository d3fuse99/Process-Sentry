<h1>Process-Sentry 🛡️</h1>

<p align="center">
  <strong>Advanced event-driven behavioral EDR engine and automated exploit mitigation system for Windows.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-In%20Development-orange" alt="Status" />
  <img src="https://img.shields.io/badge/License-MIT-purple" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform" />
</p>

<p align="center">
  <img src="assets/hud_normal.png" alt="PROCESS-SENTRY HUD" width="800" />
</p>

<p><strong>Note:</strong> This project is in active development. We are continually refining the detection logic, expanding active response capabilities, and updating telemetry maps.</p>

<p align="center">
  <img src="assets/hud_alert.png" alt="PROCESS-SENTRY Critical Alert" width="600" />
</p>

<p>Process-Sentry is a lightweight, high-performance event-driven Endpoint Detection and Response (EDR) tool designed to identify and neutralize zero-day exploits in real-time. Instead of relying on outdated static file signatures, it monitors the <strong>behavioral process tree</strong> of the operating system to intercept unauthorized execution patterns, such as suspicious shell spawning, LOLBAS attacks, and untrusted binaries execution.</p>

<h2>How It Works: System Internals</h2>

<p>Process-Sentry is designed on a zero-polling event-driven architecture that achieves enterprise-grade monitoring with minimal host footprint. Here is how the security pipeline operates:</p>

<ol>
  <li><strong>The Go Agent (agent.exe):</strong> Subscribes directly to Windows Management Instrumentation (WMI) process creation events. It acts as a passive listener, consuming 0% CPU at idle. It intercepts the new PID, Parent PID, execution path, and raw Command Line arguments.</li>
  <li><strong>Security Verification:</strong> The agent immediately queries the Win32 <code>WinVerifyTrust</code> subsystem to verify the digital signature of the newly launched process and calculates its cryptographic SHA-256 hash.</li>
  <li><strong>Telemetry Streaming:</strong> The agent packages this enriched metadata into a secure JSON payload and streams it via a local TCP socket to the Python Backend Server.</li>
  <li><strong>Decision Engine:</strong> The Python Server processes the JSON payload against behavioral rules, command-line heuristics, and a threat intelligence blacklist.</li>
  <li><strong>Active Response Loop:</strong> If an exploit or policy violation is detected, the server immediately sends a termination command with the target PID back to the Go Agent. The agent opens a process handle with <code>PROCESS_TERMINATE</code> rights and calls <code>TerminateProcess</code> to neutralize the threat in a fraction of a second.</li>
  <li><strong>HUD Display:</strong> Concurrently, the server broadcasts the telemetry update via Server-Sent Events (SSE) to the React-based frontend dashboard.</li>
</ol>

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
</table >

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
  <li><strong>Prerequisites:</strong> Ensure you have Python 3.10+ and Node.js installed on your Windows system.</li>
  <li><strong>Install Dependencies:</strong> Run <code>npm.cmd install</code> in the project root to fetch frontend libraries.</li>
  <li><strong>Build Frontend:</strong> Execute <code>npm.cmd run build</code> to compile the dashboard into the static production folder.</li>
  <li><strong>Initialize System:</strong> Double-click the <code>start.bat</code> file. It will automatically elevate itself to Administrator privileges to handle WMI event subscriptions and active process termination.</li>
  <li><strong>Access Dashboard:</strong> Open your browser and navigate to <code>http://localhost:3000</code>.</li>
</ol>

<h2>Tech stack</h2>

<ul>
  <li><strong>Go (Golang):</strong> High-performance, lightweight native Windows agent utilizing Win32 APIs for signature validation and active process termination.</li>
  <li><strong>Python:</strong> Heuristic rule engine, reputation database, and multi-threaded socket/SSE web server.</li>
  <li><strong>React / Vite:</strong> Fast, modern, responsive frontend architecture.</li>
  <li><strong>Tailwind CSS v4:</strong> Modern, high-performance cyber-ops styling engine.</li>
</ul>

<h2>License</h2>

<p>This project is licensed under the MIT License - see the LICENSE file for details.</p>
