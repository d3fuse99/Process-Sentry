import socket
import threading
import queue
import json
import os
import sqlite3
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

sse_clients = []
clients_lock = threading.Lock()
agent_socket_lock = threading.Lock()
active_agent_socket = None

SUSPICIOUS_PARENTS = ["winword.exe", "excel.exe", "chrome.exe", "msedge.exe", "acrord32.exe", "explorer.exe"]
SUSPICIOUS_CHILDREN = ["cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe"]
CRITICAL_SYSTEM_BINARIES = ["svchost.exe", "explorer.exe", "services.exe", "taskhostw.exe", "conhost.exe", "lsass.exe"]
DANGEROUS_KEYWORDS = ["downloadstring", "downloadfile", "iex", "-enc", "-encodedcommand", "-ep bypass", "executionpolicy bypass", "bypass", "invoke-expression"]

MALICIOUS_HASHES = {}

def load_config():
    global SUSPICIOUS_PARENTS, SUSPICIOUS_CHILDREN, CRITICAL_SYSTEM_BINARIES, DANGEROUS_KEYWORDS
    config_path = "config.json"
    if not os.path.exists(config_path):
        default_config = {
            "SUSPICIOUS_PARENTS": SUSPICIOUS_PARENTS,
            "SUSPICIOUS_CHILDREN": SUSPICIOUS_CHILDREN,
            "CRITICAL_SYSTEM_BINARIES": CRITICAL_SYSTEM_BINARIES,
            "DANGEROUS_KEYWORDS": DANGEROUS_KEYWORDS
        }
        try:
            with open(config_path, "w") as f:
                json.dump(default_config, f, indent=4)
        except Exception:
            pass
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            SUSPICIOUS_PARENTS = config.get("SUSPICIOUS_PARENTS", SUSPICIOUS_PARENTS)
            SUSPICIOUS_CHILDREN = config.get("SUSPICIOUS_CHILDREN", SUSPICIOUS_CHILDREN)
            CRITICAL_SYSTEM_BINARIES = config.get("CRITICAL_SYSTEM_BINARIES", CRITICAL_SYSTEM_BINARIES)
            DANGEROUS_KEYWORDS = config.get("DANGEROUS_KEYWORDS", DANGEROUS_KEYWORDS)
    except Exception:
        pass

def init_db():
    try:
        conn = sqlite3.connect("process_sentry.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent TEXT,
                parent_pid INTEGER,
                child TEXT,
                pid INTEGER,
                is_signed INTEGER,
                sha256 TEXT,
                command_line TEXT,
                status TEXT,
                reason TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass

def save_event_to_db(event_data):
    try:
        conn = sqlite3.connect("process_sentry.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (parent, parent_pid, child, pid, is_signed, sha256, command_line, status, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data["parent"],
            event_data["parent_pid"],
            event_data["child"],
            event_data["pid"],
            1 if event_data["is_signed"] else 0,
            event_data["sha256"],
            event_data["command_line"],
            event_data["status"],
            event_data["reason"],
            event_data["timestamp"]
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Server] Database insertion error: {e}")

def check_heuristics(child_name, command_line):
    cmd_lower = command_line.lower()
    if child_name.lower() in ["powershell.exe", "cmd.exe"]:
        for kw in DANGEROUS_KEYWORDS:
            if kw in cmd_lower:
                return True
    return False

def broadcast_event(event_data):
    with clients_lock:
        for q in sse_clients:
            q.put(event_data)

def tcp_socket_thread():
    global active_agent_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 5006))
    server_socket.listen(5)
    
    while True:
        client_socket, addr = server_socket.accept()
        with agent_socket_lock:
            active_agent_socket = client_socket
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                decoded_data = data.decode("utf-8").strip()
                if not decoded_data:
                    continue
                for line in decoded_data.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        parent_name = event.get("parent_name", "unknown")
                        parent_pid = event.get("parent_pid", 0)
                        child_name = event.get("child_name", "unknown")
                        pid = event.get("pid", 0)
                        
                        is_signed_raw = event.get("is_signed", 0)
                        is_signed = True if is_signed_raw in [1, "1", True] else False
                        
                        sha256 = event.get("sha256", "")
                        command_line = event.get("command_line", "")
                        child_path = event.get("child_path", "")
                        
                        parent_lower = parent_name.lower()
                        child_lower = child_name.lower()
                        
                        is_exploit = False
                        reason = ""
                        
                        if parent_lower in SUSPICIOUS_PARENTS and child_lower in SUSPICIOUS_CHILDREN:
                            is_exploit = True
                            reason = "LOLBAS (Suspicious Parent-Child Link)"
                        elif child_lower in CRITICAL_SYSTEM_BINARIES and not is_signed and sha256 != "":
                            is_exploit = True
                            reason = "Unsigned Critical System Binary"
                        elif check_heuristics(child_lower, command_line):
                            is_exploit = True
                            reason = "Heuristics (Suspicious Command Line arguments)"
                        elif sha256 in MALICIOUS_HASHES:
                            is_exploit = True
                            reason = f"Threat Intel ({MALICIOUS_HASHES[sha256]})"
                        
                        event_data = {
                            "parent": parent_name,
                            "parent_pid": parent_pid,
                            "child": child_name,
                            "pid": pid,
                            "is_signed": is_signed,
                            "sha256": sha256,
                            "command_line": command_line,
                            "status": "BLOCKED" if is_exploit else "SAFE",
                            "reason": reason,
                            "timestamp": ""
                        }
                        
                        import datetime
                        event_data["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S")
                        save_event_to_db(event_data)
                        broadcast_event(event_data)
                        
                        if is_exploit:
                            print(f"[!!! EXPLOIT BLOCKED !!!] {parent_name} -> {child_name} (PID: {pid}) - Reason: {reason}")
                            client_socket.sendall((str(pid) + "\n").encode("utf-8"))
                            if child_path:
                                client_socket.sendall(("QUARANTINE:" + child_path + "\n").encode("utf-8"))
                        else:
                            print(f"[SAFE] {parent_name} -> {child_name} (PID: {pid})")
                    except Exception as e:
                        print(f"[Server] Error processing event line: {e}")
        except Exception as ex:
            print(f"[Server] Socket connection error: {ex}")
        finally:
            with agent_socket_lock:
                active_agent_socket = None
            client_socket.close()

class EDRHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        global active_agent_socket
        if self.path == "/api/kill":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode("utf-8"))
                pid = payload.get("pid")
                if pid:
                    with agent_socket_lock:
                        if active_agent_socket:
                            active_agent_socket.sendall((str(pid) + "\n").encode("utf-8"))
                            print(f"[Server] Sent manual termination command for PID: {pid}")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
                    return
            except Exception as e:
                print(f"[Server] Error handling manual kill POST: {e}")
            
            self.send_response(500)
            self.end_headers()

        elif self.path == "/api/isolate":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode("utf-8"))
                isolate_state = payload.get("isolate", False)
                command = "ISOLATE" if isolate_state else "RESTORE"
                with agent_socket_lock:
                    if active_agent_socket:
                        active_agent_socket.sendall((command + "\n").encode("utf-8"))
                        print(f"[Server] Sent network isolation command: {command}")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
                return
            except Exception as e:
                print(f"[Server] Error handling isolation POST: {e}")
            
            self.send_response(500)
            self.end_headers()

    def do_GET(self):
        if self.path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            q = queue.Queue()
            with clients_lock:
                sse_clients.append(q)

            try:
                while True:
                    try:
                        event = q.get(timeout=1.0)
                        sse_data = f"data: {json.dumps(event)}\n\n"
                        self.wfile.write(sse_data.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
            except Exception:
                pass
            finally:
                with clients_lock:
                    sse_clients.remove(q)

        elif self.path == "/api/history":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                conn = sqlite3.connect("process_sentry.db")
                cursor = conn.cursor()
                cursor.execute("SELECT parent, parent_pid, child, pid, is_signed, sha256, command_line, status, reason, timestamp FROM events ORDER BY id DESC LIMIT 100")
                rows = cursor.fetchall()
                conn.close()
                history = []
                for r in rows:
                    history.append({
                        "parent": r[0],
                        "parent_pid": r[1],
                        "child": r[2],
                        "pid": r[3],
                        "is_signed": r[4] == 1,
                        "sha256": r[5],
                        "command_line": r[6],
                        "status": r[7],
                        "reason": r[8],
                        "timestamp": r[9]
                    })
                self.wfile.write(json.dumps(history).encode("utf-8"))
            except Exception:
                self.wfile.write(json.dumps([]).encode("utf-8"))
            return
        else:
            if self.path == "/" or self.path == "":
                self.path = "/index.html"
            super().do_GET()

    def translate_path(self, path):
        root = os.path.abspath(os.path.join(os.getcwd(), "dist"))
        path = path.split('?', 1)[0]
        path = path.split(chr(35), 1)[0]
        target_path = os.path.abspath(os.path.join(root, path.lstrip('/')))
        if not target_path.startswith(root):
            return os.path.join(root, "index.html")
        return target_path

def run_http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 3000), EDRHandler)
    print("EDR Dashboard running at http://localhost:3000")
    server.serve_forever()

def main():
    load_config()
    init_db()
    t_tcp = threading.Thread(target=tcp_socket_thread, daemon=True)
    t_tcp.start()
    run_http_server()

if __name__ == "__main__":
    main()