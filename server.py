import socket
import threading
import queue
import json
import os
import sqlite3
import urllib.request
import urllib.error
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
VT_API_KEY = ""
VT_MIN_DETECTIONS = 5
VT_CACHE = {}

ALLOWLIST_HASHES = []
ALLOWLIST_PATHS = []

SCORE_UNSIGNED_SYSTEM = 30
SCORE_SUSPICIOUS_LINK = 40
SCORE_HEURISTIC_KEYWORD = 40
SCORE_MALICIOUS_HASH = 100
SCORE_DLL_SIDELOADING = 80
SCORE_BLOCK_THRESHOLD = 70

db_queue = queue.Queue()

def load_config():
    global SUSPICIOUS_PARENTS, SUSPICIOUS_CHILDREN, CRITICAL_SYSTEM_BINARIES, DANGEROUS_KEYWORDS, VT_API_KEY, VT_MIN_DETECTIONS
    global ALLOWLIST_HASHES, ALLOWLIST_PATHS, SCORE_UNSIGNED_SYSTEM, SCORE_SUSPICIOUS_LINK, SCORE_HEURISTIC_KEYWORD, SCORE_MALICIOUS_HASH, SCORE_DLL_SIDELOADING, SCORE_BLOCK_THRESHOLD
    config_path = "config.json"
    if not os.path.exists(config_path):
        default_config = {
            "SUSPICIOUS_PARENTS": SUSPICIOUS_PARENTS,
            "SUSPICIOUS_CHILDREN": SUSPICIOUS_CHILDREN,
            "CRITICAL_SYSTEM_BINARIES": CRITICAL_SYSTEM_BINARIES,
            "DANGEROUS_KEYWORDS": DANGEROUS_KEYWORDS,
            "VT_API_KEY": "",
            "VT_MIN_DETECTIONS": 5,
            "ALLOWLIST_HASHES": [],
            "ALLOWLIST_PATHS": [],
            "SCORE_UNSIGNED_SYSTEM": 30,
            "SCORE_SUSPICIOUS_LINK": 40,
            "SCORE_HEURISTIC_KEYWORD": 40,
            "SCORE_MALICIOUS_HASH": 100,
            "SCORE_DLL_SIDELOADING": 80,
            "SCORE_BLOCK_THRESHOLD": 70
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
            VT_API_KEY = config.get("VT_API_KEY", "")
            VT_MIN_DETECTIONS = int(config.get("VT_MIN_DETECTIONS", 5))
            ALLOWLIST_HASHES = [h.lower() for h in config.get("ALLOWLIST_HASHES", [])]
            ALLOWLIST_PATHS = [p.lower().replace("/", "\\") for p in config.get("ALLOWLIST_PATHS", [])]
            SCORE_UNSIGNED_SYSTEM = int(config.get("SCORE_UNSIGNED_SYSTEM", 30))
            SCORE_SUSPICIOUS_LINK = int(config.get("SCORE_SUSPICIOUS_LINK", 40))
            SCORE_HEURISTIC_KEYWORD = int(config.get("SCORE_HEURISTIC_KEYWORD", 40))
            SCORE_MALICIOUS_HASH = int(config.get("SCORE_MALICIOUS_HASH", 100))
            SCORE_DLL_SIDELOADING = int(config.get("SCORE_DLL_SIDELOADING", 80))
            SCORE_BLOCK_THRESHOLD = int(config.get("SCORE_BLOCK_THRESHOLD", 70))
    except Exception:
        pass

def init_db():
    try:
        conn = sqlite3.connect("process_sentry.db", timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
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
    except Exception as e:
        print(f"[Server] Database initialization error: {e}")

def db_writer_worker():
    conn = sqlite3.connect("process_sentry.db", timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    cursor = conn.cursor()
    while True:
        event_data = db_queue.get()
        if event_data is None:
            break
        try:
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
        except Exception as e:
            print(f"[Server] Async database write error: {e}")
        finally:
            db_queue.task_done()
    conn.close()

def check_heuristics(child_name, command_line):
    cmd_lower = command_line.lower()
    if child_name.lower() in ["powershell.exe", "cmd.exe"]:
        for kw in DANGEROUS_KEYWORDS:
            if kw in cmd_lower:
                return True
    return False

def check_virustotal(sha256_hash):
    global VT_API_KEY, VT_CACHE, VT_MIN_DETECTIONS
    if not VT_API_KEY or not sha256_hash:
        return False, ""
    
    if sha256_hash in VT_CACHE:
        return VT_CACHE[sha256_hash]
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", VT_API_KEY)
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                is_malicious = malicious >= VT_MIN_DETECTIONS
                reason = f"VirusTotal detection score: {malicious}"
                VT_CACHE[sha256_hash] = (is_malicious, reason)
                return is_malicious, reason
    except urllib.error.HTTPError as e:
        if e.code == 404:
            VT_CACHE[sha256_hash] = (False, "")
            return False, ""
        print(f"[Server] VirusTotal returned status code: {e.code}")
    except Exception as e:
        print(f"[Server] VirusTotal verification connection failure: {e}")
        
    return False, ""

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
            rfile = client_socket.makefile('r', encoding='utf-8')
            for line in rfile:
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
                    
                    sha256 = event.get("sha256", "").lower()
                    command_line = event.get("command_line", "")
                    child_path = event.get("child_path", "")
                    suspicious_dlls = event.get("suspicious_dlls", [])
                    
                    parent_lower = parent_name.lower()
                    child_lower = child_name.lower()
                    child_path_clean = child_path.lower().replace("/", "\\")
                    
                    is_exploit = False
                    reason = ""
                    score = 0
                    triggers = []
                    
                    is_allowlisted = (sha256 in ALLOWLIST_HASHES) or (child_path_clean in ALLOWLIST_PATHS)
                    
                    if not is_allowlisted and "agent" not in parent_lower and parent_lower != "unknown":
                        if sha256 in MALICIOUS_HASHES:
                            score += SCORE_MALICIOUS_HASH
                            triggers.append("Malicious Hash (Local)")
                        
                        if is_signed and suspicious_dlls:
                            score += SCORE_DLL_SIDELOADING
                            triggers.append(f"Unsigned DLLs: {len(suspicious_dlls)}")
                            
                        if parent_lower in SUSPICIOUS_PARENTS and child_lower in SUSPICIOUS_CHILDREN:
                            score += SCORE_SUSPICIOUS_LINK
                            triggers.append("Suspicious Parent-Child Link")
                            
                        if child_lower in CRITICAL_SYSTEM_BINARIES and not is_signed and sha256 != "":
                            score += SCORE_UNSIGNED_SYSTEM
                            triggers.append("Unsigned System Binary")
                            
                        if check_heuristics(child_lower, command_line):
                            score += SCORE_HEURISTIC_KEYWORD
                            triggers.append("Suspicious Heuristics Keyword")
                            
                        is_vt_malicious, vt_reason = check_virustotal(sha256)
                        if is_vt_malicious:
                            score += SCORE_MALICIOUS_HASH
                            triggers.append(vt_reason)
                            
                        if score >= SCORE_BLOCK_THRESHOLD:
                            is_exploit = True
                            reason = f"Threat Level: {score} ({', '.join(triggers)})"
                        elif score > 0:
                            reason = f"Suspicious Activity Score: {score} ({', '.join(triggers)})"
                    
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
                        "timestamp": "",
                        "suspicious_dlls": suspicious_dlls,
                        "score": score
                    }
                    
                    import datetime
                    event_data["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S")
                    
                    db_queue.put(event_data)
                    broadcast_event(event_data)
                    
                    if is_exploit:
                        print(f"[!!! EXPLOIT BLOCKED !!!] {parent_name} -> {child_name} (PID: {pid}) - Reason: {reason}")
                        client_socket.sendall((str(pid) + "\n").encode("utf-8"))
                        if child_path:
                            quarantine_cmd = f"QUARANTINE:{child_path};{pid};{sha256}\n"
                            client_socket.sendall(quarantine_cmd.encode("utf-8"))
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
                conn = sqlite3.connect("process_sentry.db", timeout=10)
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
    server = ThreadingHTTPServer(("127.0.0.1", 5007), EDRHandler)
    print("EDR API Server running at http://localhost:5007")
    server.serve_forever()

def main():
    load_config()
    init_db()
    
    t_db = threading.Thread(target=db_writer_worker, daemon=True)
    t_db.start()
    
    t_tcp = threading.Thread(target=tcp_socket_thread, daemon=True)
    t_tcp.start()
    
    run_http_server()

if __name__ == "__main__":
    main()