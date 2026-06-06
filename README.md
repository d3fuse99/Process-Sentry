<h1 align="center">Process-Sentry 🛡️</h1>

<p align="center">
  <strong>Advanced behavioral EDR engine and automated exploit mitigation system for Windows.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-In_Development-orange" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-magenta" alt="License MIT">
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform Windows">
</p>

<hr>

<blockquote>
  <strong>Note:</strong> This project is currently in active development. We are still refining the heuristic engine and expanding the process map features. Expect frequent updates.
</blockquote>

<p>
  Process-Sentry is a lightweight, high-performance Endpoint Detection and Response (EDR) tool designed to identify and neutralize zero-day exploits in real-time. Instead of relying on outdated file signatures, it monitors the <strong>behavioral process tree</strong> of the operating system to intercept unauthorized execution patterns, such as suspicious shell spawning from trusted applications.
</p>

<hr>

<h2>Features</h2>

<ul>
  <li><strong>Parent-Child Chain Audit:</strong> Continuously monitors system-wide process lifecycles using low-level Windows API snapshots to detect anomalous execution flows.</li>
  <li><strong>Zero-Day Mitigation:</strong> Identifies and blocks common exploit vectors (LOLBAS) where trusted apps (Word, Chrome, Acrobat) attempt to launch restricted system binaries.</li>
  <li><strong>Active Countermeasures:</strong> Features an automated incident response system that instantly terminates malicious process branches upon detection.</li>
  <li><strong>Real-time HUD Interface:</strong> Interactive, cyberpunk-inspired web dashboard built with React and Tailwind CSS v4 for live telemetry visualization.</li>
  <li><strong>Multi-threaded Backend:</strong> High-speed Python server handling concurrent TCP socket streams from the agent and SSE events for the frontend.</li>
  <li><strong>Low System Footprint:</strong> Optimized C++ agent designed for minimal CPU and memory impact during continuous system auditing.</li>
</ul>

<hr>

<h2>Architecture</h2>

<pre>
[Process Creation] ---> [C++ System Agent] ---> [Python Logic Core] ---> [React Web HUD]
          |                      |                       |                      |
    (Win32 API)           (TCP Sockets)            (SSE Stream)           (Live Alerts)
</pre>

<hr>

<h2>How to run</h2>

<ol>
  <li><strong>Prerequisites:</strong> Ensure you have Python 3.10+ and Node.js installed on your system.</li>
  <li><strong>Install Dependencies:</strong> Run <code>npm install</code> in the project root to fetch frontend libraries.</li>
  <li><strong>Build Frontend:</strong> Execute <code>npm run build</code> to compile the dashboard.</li>
  <li><strong>Initialize System:</strong> Run the <strong>start.bat</strong> file. This will launch the Python server and the C++ agent simultaneously.</li>
  <li><strong>Access Dashboard:</strong> Open your browser and navigate to <code>http://localhost:3000</code>.</li>
</ol>

<hr>

<h2>Tech stack</h2>

<ul>
  <li><strong>C++ / Win32 API:</strong> Low-level system interrogation and process management.</li>
  <li><strong>Python:</strong> Heuristic rule engine and multi-threaded socket server.</li>
  <li><strong>React / Vite:</strong> Fast, responsive frontend architecture.</li>
  <li><strong>Tailwind CSS v4:</strong> Modern, high-performance styling engine.</li>
  <li><strong>Lucide React:</strong> Vector-based security iconography.</li>
</ul>

<hr>

<h2>License</h2>
This project is licensed under the MIT License - see the LICENSE file for details.
