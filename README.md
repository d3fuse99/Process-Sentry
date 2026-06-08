<h1>Process-Sentry </h1>

<p align="center">
  <strong>Advanced event-driven behavioral EDR engine and automated exploit mitigation system for Windows.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-In%20Development-orange" alt="Status" />
  <img src="https://img.shields.io/badge/License-MIT-purple" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform" />
</p>

<hr />

<p><strong>Note:</strong> This project is in active development. We are continually refining the detection logic, expanding active response capabilities, and updating telemetry maps.</p>
<img width="1905" height="979" alt="image" src="https://github.com/user-attachments/assets/8eb3f99c-b231-4c92-a6f6-fcfe59c01e54" />

<p>Process-Sentry is a lightweight, high-performance event-driven Endpoint Detection and Response (EDR) tool designed to identify and neutralize zero-day exploits in real-time. Instead of relying on outdated static file signatures, it monitors the <strong>behavioral process tree</strong> of the operating system to intercept unauthorized execution patterns, such as suspicious shell spawning, LOLBAS attacks, and untrusted binaries execution.</p>

<h2>Features</h2>

<ul>
  <li><strong>Zero-Polling Event Auditing:</strong> Subscribes directly to Windows Management Instrumentation (WMI) process creation events, achieving 0% idle CPU overhead while capturing even ultra-short-lived processes instantly.</li>
  <li><strong>Active Response & Mitigation:</strong> Features an automated incident response loop that instantly terminates dangerous process branches on detection using native Win32 <code>TerminateProcess</code> API.</li>
  <li><strong>Heuristic Command Line Engine:</strong> Analyzes raw process execution arguments (e.g., PowerShell execution policy bypass, base64-encoded payloads, or network download strings) to stop script-based evasion.</li>
  <li><strong>Static Analysis Hashing:</strong> Instantly calculates the SHA-256 cryptographic hash of every newly launched process binary for reputation lookups.</li>
  <li><strong>Authenticode Signature Check:</strong> Interrogates the Win32 <code>WinVerifyTrust</code> subsystem to detect unsigned critical binaries and enforce security catalog trust rules.</li>
  <li><strong>Real-time HUD Interface:</strong> Cyberpunk-inspired interactive web dashboard built with React and Tailwind CSS v4 for live telemetry streaming and alerts.</li>
</ul>

<h2>Architecture</h2>

<pre>
[Process Creation] ---> [WMI Subsystem] ---> [Python Agent (agent.py)] ---> [Python Server (server.py)] ---> [React Web HUD]
       |                                              |                                |                          |
  (Kernel/OS)                                   (SHA256 & Trust)                  (TCP Socket)                (SSE Stream)
</pre>

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
  <li><strong>Python:</strong> Heuristic rule engine, SHA-256 calculation, and multi-threaded socket/SSE server.</li>
  <li><strong>React / Vite:</strong> Fast, modern, responsive frontend architecture.</li>
  <li><strong>Tailwind CSS v4:</strong> Modern, high-performance cyber-ops styling engine.</li>
  <li><strong>WMI & Win32 API (via ctypes):</strong> Native Windows subsystems for event subscription, digital signature checks, and process management.</li>
</ul>

<h2>License</h2>

<p>This project is licensed under the MIT License - see the LICENSE file for details.</p>
