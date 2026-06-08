import socket
import threading
import queue
import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

sse_clients = []
clients_lock = threading.Lock()

SUSPICIOUS_PARENTS = ["winword.exe", "excel.exe", "chrome.exe", "msedge.exe", "acrord32.exe", "explorer.exe"]
SUSPICIOUS_CHILDREN = ["cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe"]
CRITICAL_SYSTEM_BINARIES = ["svchost.exe", "explorer.exe", "services.exe", "taskhostw.exe", "conhost.exe", "lsass.exe"]

DANGEROUS_KEYWORDS = ["downloadstring", "downloadfile", "iex", "-enc", "-encodedcommand", "-ep bypass", "executionpolicy bypass", "bypass", "invoke-expression"]

MALICIOUS_HASHES = {}

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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 5006))
    server_socket.listen(5)
    
    while True:
        client_socket, addr = server_socket.accept()
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
                        child_name = event.get("child_name", "unknown")
                        pid = event.get("pid", 0)
                        
                        is_signed_raw = event.get("is_signed", 0)
                        is_signed = True if is_signed_raw in [1, "1", True] else False
                        
                        sha256 = event.get("sha256", "")
                        command_line = event.get("command_line", "")
                        
                        is_exploit = False
                        reason = ""
                        
                        if parent_name in SUSPICIOUS_PARENTS and child_name in SUSPICIOUS_CHILDREN:
                            is_exploit = True
                            reason = "LOLBAS (Suspicious Parent-Child Link)"
                        elif child_name in CRITICAL_SYSTEM_BINARIES and not is_signed:
                            is_exploit = True
                            reason = "Unsigned Critical System Binary"
                        elif check_heuristics(child_name, command_line):
                            is_exploit = True
                            reason = "Heuristics (Suspicious Command Line arguments)"
                        elif sha256 in MALICIOUS_HASHES:
                            is_exploit = True
                            reason = f"Threat Intel ({MALICIOUS_HASHES[sha256]})"
                        
                        event_data = {
                            "parent": parent_name,
                            "child": child_name,
                            "pid": pid,
                            "is_signed": is_signed,
                            "sha256": sha256,
                            "command_line": command_line,
                            "status": "BLOCKED" if is_exploit else "SAFE",
                            "reason": reason
                        }
                        broadcast_event(event_data)
                        
                        if is_exploit:
                            print(f"[!!! EXPLOIT BLOCKED !!!] {parent_name} -> {child_name} (PID: {pid}) - Reason: {reason}")
                            client_socket.sendall(str(pid).encode("utf-8"))
                        else:
                            print(f"[SAFE] {parent_name} -> {child_name} (PID: {pid})")
                    except Exception as e:
                        print(f"[Server] Error processing event line: {e}")
        except Exception as ex:
            print(f"[Server] Socket connection error: {ex}")
        finally:
            client_socket.close()

class EDRHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

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
        else:
            if self.path == "/" or self.path == "":
                self.path = "/index.html"
            super().do_GET()

    def translate_path(self, path):
        root = os.path.join(os.getcwd(), 'dist')
        path = path.split('?', 1)[0]
        path = path.split(chr(35), 1)[0]
        return os.path.join(root, path.lstrip('/'))

def run_http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 3000), EDRHandler)
    print("EDR Dashboard running at http://localhost:3000")
    server.serve_forever()

def main():
    t_tcp = threading.Thread(target=tcp_socket_thread, daemon=True)
    t_tcp.start()
    run_http_server()

if __name__ == "__main__":
    main()