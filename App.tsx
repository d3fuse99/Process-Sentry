import React, { useState, useEffect, useRef } from "react";
import { Shield, ShieldAlert, Cpu, Activity, Terminal } from "lucide-react";

interface ProcessEvent {
  parent: string;
  child: string;
  pid: string;
  status: "SAFE" | "BLOCKED";
  time?: string;
}

export default function App() {
  const [events, setEvents] = useState<ProcessEvent[]>([]);
  const [stats, setStats] = useState({ total: 0, blocked: 0, safe: 0 });
  const [activeExploit, setActiveExploit] = useState<ProcessEvent | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const eventSource = new EventSource("/api/events");

    eventSource.onmessage = (event) => {
      try {
        const parsed: ProcessEvent = JSON.parse(event.data);
        const timestamp = new Date().toLocaleTimeString();
        const newEvent = { ...parsed, time: timestamp };

        setEvents((prev) => [...prev, newEvent]);
        setStats((prev) => {
          const isBlocked = parsed.status === "BLOCKED";
          return {
            total: prev.total + 1,
            blocked: isBlocked ? prev.blocked + 1 : prev.blocked,
            safe: !isBlocked ? prev.safe + 1 : prev.safe,
          };
        });

        if (parsed.status === "BLOCKED") {
          setActiveExploit(newEvent);
        }
      } catch (e) {
        console.error("Error parsing event", e);
      }
    };

    return () => {
      eventSource.close();
    };
  }, []);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events]);

  const clearLogs = () => {
    setEvents([]);
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-cyan-400 font-mono p-6 flex flex-col gap-6 relative overflow-hidden">
      {activeExploit && (
        <div className="absolute inset-0 bg-red-950/90 z-50 flex flex-col items-center justify-center gap-4 animate-pulse border-4 border-red-500">
          <ShieldAlert className="w-24 h-24 text-red-500 animate-bounce" />
          <h1 className="text-4xl font-extrabold text-red-500 tracking-wider">CRITICAL EXPLOIT DETECTED</h1>
          <div className="bg-black/80 border border-red-500 p-6 rounded-lg text-center max-w-lg">
            <p className="text-xl text-white mb-2">
              <span className="text-red-500 font-bold">{activeExploit.parent}</span> tried to spawn
              <span className="text-red-500 font-bold"> {activeExploit.child}</span> (PID: {activeExploit.pid})
            </p>
            <p className="text-green-500 text-lg font-bold mb-4">COUNTERMEASURE: Process Terminated & Isolated</p>
            <button
              onClick={() => setActiveExploit(null)}
              className="text-sm text-red-500 border-2 border-red-500 hover:bg-red-500 hover:text-black px-6 py-2 font-bold transition-all shadow-[0_0_15px_rgba(239,68,68,0.4)] cursor-pointer"
            >
              RESOLVE & DISMISS ALERT
            </button>
          </div>
        </div>
      )}

      <header className="flex justify-between items-center border-b-2 border-pink-600 pb-4 shadow-[0_0_15px_rgba(219,39,119,0.3)]">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-pink-600 animate-pulse" />
          <h1 className="text-2xl font-extrabold tracking-widest text-pink-600 drop-shadow-[0_0_8px_rgba(219,39,119,0.8)]">
            PROCESS-SENTRY HUD
          </h1>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-zinc-900 border border-cyan-500/30 p-4 flex items-center gap-4 shadow-[0_0_15px_rgba(6,182,212,0.1)]">
          <div className="bg-cyan-950/50 p-3 border border-cyan-500/50">
            <Activity className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Total Scanned</p>
            <p className="text-2xl font-bold text-cyan-300">{stats.total}</p>
          </div>
        </div>
        <div className="bg-zinc-900 border border-pink-500/30 p-4 flex items-center gap-4 shadow-[0_0_15px_rgba(236,72,153,0.1)]">
          <div className="bg-pink-950/50 p-3 border border-pink-500/50">
            <ShieldAlert className="w-6 h-6 text-pink-500" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Exploits Blocked</p>
            <p className="text-2xl font-bold text-pink-500">{stats.blocked}</p>
          </div>
        </div>
        <div className="bg-zinc-900 border border-emerald-500/30 p-4 flex items-center gap-4 shadow-[0_0_15px_rgba(16,185,129,0.1)]">
          <div className="bg-emerald-950/50 p-3 border border-emerald-500/50">
            <Cpu className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Clean Events</p>
            <p className="text-2xl font-bold text-emerald-400">{stats.safe}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-grow">
        <div className="bg-zinc-900 border border-cyan-500/30 flex flex-col h-[500px]">
          <div className="bg-cyan-950/30 border-b border-cyan-500/30 px-4 py-3 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-bold tracking-wider uppercase">Live Threat Intelligence Feed</span>
            </div>
            <button
              onClick={clearLogs}
              className="text-xs text-cyan-400 border border-cyan-400/50 hover:bg-cyan-400 hover:text-black px-2 py-1 transition-all"
            >
              CLEAR
            </button>
          </div>
          <div className="p-4 flex-grow overflow-y-auto space-y-3 flex flex-col">
            {events.length === 0 ? (
              <div className="text-gray-600 text-sm italic my-auto text-center font-bold">Awaiting process stream from C++ Agent...</div>
            ) : (
              events.map((ev, i) => (
                <div
                  key={i}
                  className={`p-3 border-l-4 text-xs ${
                    ev.status === "BLOCKED"
                      ? "bg-pink-950/20 border-pink-500 text-pink-300 animate-pulse"
                      : "bg-cyan-950/10 border-cyan-500 text-cyan-200"
                  }`}
                >
                  <div className="flex justify-between font-bold mb-1">
                    <span>{ev.status === "BLOCKED" ? "THREAT BLOCKED" : "PROCESS DETECTED"}</span>
                    <span className="text-gray-500">{ev.time}</span>
                  </div>
                  <p>
                    Parent: <span className="font-bold text-white">{ev.parent}</span> - Child:{" "}
                    <span className="font-bold text-white">{ev.child}</span> (PID: {ev.pid})
                  </p>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>

        <div className="bg-zinc-900 border border-cyan-500/30 flex flex-col h-[500px]">
          <div className="bg-cyan-950/30 border-b border-cyan-500/30 px-4 py-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-bold tracking-wider uppercase">Active Process Map</span>
          </div>
          <div className="p-4 flex-grow overflow-y-auto space-y-2">
            {events.length === 0 ? (
              <div className="text-gray-600 text-sm h-full flex items-center justify-center font-bold">No active process nodes</div>
            ) : (
              [...events].reverse().map((ev, i) => (
                <div
                  key={i}
                  className="flex justify-between items-center p-2.5 bg-zinc-950 border border-cyan-500/20 rounded hover:border-cyan-500/50 transition-all"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`w-2 h-2 rounded-full ${ev.status === "BLOCKED" ? "bg-pink-500 animate-ping" : "bg-emerald-400"}`}
                    ></span>
                    <span className="text-sm font-bold text-white">{ev.child}</span>
                    <span className="text-xs text-gray-500">PID: {ev.pid}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500">Parent: {ev.parent}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                        ev.status === "BLOCKED" ? "bg-pink-950 text-pink-400" : "bg-emerald-950 text-emerald-400"
                      }`}
                    >
                      {ev.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}