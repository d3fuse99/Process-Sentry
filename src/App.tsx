import React, { useState, useEffect } from 'react';

interface ProcessEvent {
  parent: string;
  parent_pid: number;
  child: string;
  pid: number;
  is_signed: boolean;
  sha256: string;
  command_line: string;
  status: string;
  reason: string;
  timestamp: string;
}

export default function App() {
  const [events, setEvents] = useState<ProcessEvent[]>([]);
  const [activeProcesses, setActiveProcesses] = useState<{ [key: number]: ProcessEvent }>({});
  const [scannedCount, setScannedCount] = useState<number>(0);
  const [blockedCount, setBlockedCount] = useState<number>(0);
  const [cleanCount, setCleanCount] = useState<number>(0);
  const [activeAlert, setActiveAlert] = useState<ProcessEvent | null>(null);
  const [selectedProcess, setSelectedProcess] = useState<ProcessEvent | null>(null);

  useEffect(() => {
    const eventSource = new EventSource('/api/events');

    eventSource.onmessage = (event) => {
      try {
        const newEvent: ProcessEvent = JSON.parse(event.data);
        newEvent.timestamp = new Date().toLocaleTimeString();

        setEvents((prev) => [newEvent, ...prev].slice(0, 50));
        setScannedCount((prev) => prev + 1);

        if (newEvent.status === 'BLOCKED') {
          setBlockedCount((prev) => prev + 1);
          setActiveAlert(newEvent);
        } else {
          setCleanCount((prev) => prev + 1);
        }

        setActiveProcesses((prev) => {
          const updated = { ...prev };
          updated[newEvent.pid] = newEvent;
          return updated;
        });
      } catch (e) {
        console.error(e);
      }
    };

    return () => {
      eventSource.close();
    };
  }, []);

  const handleKill = async (pid: number) => {
    try {
      await fetch('/api/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      setSelectedProcess(null);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-mono p-6 flex flex-col gap-6 selection:bg-red-500 selection:text-black">
      
      <header className="border border-red-900/30 bg-zinc-900/40 p-4 rounded backdrop-blur flex justify-between items-center shadow-[0_0_15px_rgba(153,27,27,0.1)]">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 bg-red-600 rounded-full animate-pulse" />
          <h1 className="text-xl tracking-widest text-red-500 font-bold">PROCESS-SENTRY HUD</h1>
        </div>
        <div className="text-xs text-zinc-500">SYSTEM AGENT: ACTIVE (WMI EVENT ROUTER)</div>
      </header>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="border border-zinc-800 bg-zinc-900/20 p-4 rounded flex items-center justify-between">
          <div>
            <div className="text-xs text-zinc-500 uppercase">Total Scanned</div>
            <div className="text-3xl font-bold mt-1 text-zinc-200">{scannedCount}</div>
          </div>
          <svg className="w-8 h-8 text-zinc-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
          </svg>
        </div>

        <div className="border border-red-900/20 bg-red-950/5 p-4 rounded flex items-center justify-between">
          <div>
            <div className="text-xs text-red-500 uppercase">Exploits Blocked</div>
            <div className="text-3xl font-bold mt-1 text-red-500">{blockedCount}</div>
          </div>
          <svg className="w-8 h-8 text-red-900/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </div>

        <div className="border border-emerald-900/20 bg-emerald-950/5 p-4 rounded flex items-center justify-between">
          <div>
            <div className="text-xs text-emerald-500 uppercase">Clean Events</div>
            <div className="text-3xl font-bold mt-1 text-emerald-500">{cleanCount}</div>
          </div>
          <svg className="w-8 h-8 text-emerald-900/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1 min-h-0">
        
        <div className="border border-zinc-800 bg-zinc-900/10 rounded flex flex-col min-h-0">
          <div className="border-b border-zinc-800 p-3 bg-zinc-900/30 flex justify-between items-center">
            <h2 className="text-sm tracking-wider font-bold text-zinc-400">LIVE THREAT FEED</h2>
            <button onClick={() => setEvents([])} className="text-[10px] text-zinc-600 hover:text-zinc-400 uppercase tracking-widest cursor-pointer">Clear Log</button>
          </div>
          <div className="p-4 flex-1 overflow-y-auto flex flex-col gap-3 min-h-0">
            {events.length === 0 ? (
              <div className="text-center text-zinc-600 text-xs py-8">Awaiting process stream from agent...</div>
            ) : (
              events.map((ev, i) => (
                <div key={i} onClick={() => setSelectedProcess(ev)} className={`p-3 rounded border text-xs flex flex-col gap-2 cursor-pointer hover:border-zinc-700 transition-all ${ev.status === 'BLOCKED' ? 'border-red-900/50 bg-red-950/10' : 'border-zinc-800/80 bg-zinc-900/10'}`}>
                  <div className="flex justify-between items-center">
                    <span className={`font-bold ${ev.status === 'BLOCKED' ? 'text-red-500' : 'text-emerald-500'}`}>
                      {ev.status === 'BLOCKED' ? 'THREAT BLOCKED' : 'PROCESS DETECTED'}
                    </span>
                    <span className="text-[10px] text-zinc-600">{ev.timestamp}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Parent: </span>
                    <span className="text-zinc-300 font-bold">{ev.parent}</span>
                    <span className="text-zinc-600"> &rarr; </span>
                    <span className="text-zinc-500">Child: </span>
                    <span className={`font-bold ${ev.status === 'BLOCKED' ? 'text-red-400' : 'text-zinc-200'}`}>{ev.child}</span>
                    <span className="text-zinc-600"> (PID: {ev.pid})</span>
                  </div>
                  {ev.command_line && (
                    <div className="bg-black/30 p-2 rounded text-[11px] text-zinc-400 font-mono break-all border border-zinc-900">
                      <span className="text-zinc-600 font-bold">CMD: </span>{ev.command_line}
                    </div>
                  )}
                  {ev.sha256 && (
                    <div className="text-[10px] text-zinc-600 flex justify-between">
                      <span>SHA256: {ev.sha256.substring(0, 32)}...</span>
                      <span>Signature: {ev.is_signed ? 'Verified' : 'Unsigned'}</span>
                    </div>
                  )}
                  {ev.status === 'BLOCKED' && ev.reason && (
                    <div className="text-[11px] text-red-500 font-bold">
                      Reason: {ev.reason}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="border border-zinc-800 bg-zinc-900/10 rounded flex flex-col min-h-0">
          <div className="border-b border-zinc-800 p-3 bg-zinc-900/30">
            <h2 className="text-sm tracking-wider font-bold text-zinc-400">ACTIVE PROCESS MAP</h2>
          </div>
          <div className="p-4 flex-1 overflow-y-auto flex flex-col gap-2 min-h-0">
            {Object.keys(activeProcesses).length === 0 ? (
              <div className="text-center text-zinc-600 text-xs py-8">No active process nodes tracked.</div>
            ) : (
              Object.values(activeProcesses).map((proc, i) => (
                <div key={i} onClick={() => setSelectedProcess(proc)} className="border border-zinc-900 bg-zinc-900/20 p-2.5 rounded text-xs flex justify-between items-center cursor-pointer hover:border-zinc-700 transition-all">
                  <div className="flex flex-col gap-0.5">
                    <span className="font-bold text-zinc-300">{proc.child}</span>
                    <span className="text-[10px] text-zinc-600">Parent: {proc.parent} | PID: {proc.pid}</span>
                  </div>
                  <div className="flex gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold ${proc.is_signed ? 'border-emerald-950 text-emerald-500 bg-emerald-950/20' : 'border-zinc-800 text-zinc-500 bg-zinc-900/50'}`}>
                      {proc.is_signed ? 'Signed' : 'Unsigned'}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold ${proc.status === 'BLOCKED' ? 'border-red-950 text-red-500 bg-red-950/20' : 'border-emerald-950 text-emerald-500 bg-emerald-950/20'}`}>
                      {proc.status === 'BLOCKED' ? 'Blocked' : 'Safe'}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      {activeAlert && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="border-2 border-red-600 bg-zinc-950 p-6 rounded max-w-xl w-full flex flex-col items-center text-center gap-4 shadow-[0_0_50px_rgba(239,68,68,0.25)]">
            <div className="w-16 h-16 rounded-full bg-red-950/30 border-2 border-red-500 flex items-center justify-center animate-bounce">
              <svg className="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            
            <h3 className="text-xl tracking-widest text-red-500 font-bold uppercase">CRITICAL EXPLOIT DETECTED</h3>
            
            <div className="text-sm text-zinc-300">
              <span className="text-red-400 font-bold">{activeAlert.parent}</span> tried to spawn <span className="text-red-400 font-bold">{activeAlert.child}</span>
              <div className="text-zinc-600 text-xs mt-1">Process Identification ID (PID): {activeAlert.pid}</div>
            </div>

            {activeAlert.reason && (
              <div className="border border-red-900/50 bg-red-950/10 p-2.5 rounded text-xs text-red-400 font-bold">
                ALERT REASON: {activeAlert.reason}
              </div>
            )}

            {activeAlert.command_line && (
              <div className="w-full text-left bg-black/40 p-3 rounded text-[11px] font-mono break-all border border-zinc-900 flex flex-col gap-1">
                <span className="text-zinc-600 font-bold">SUSPICIOUS COMMAND LINE:</span>
                <span className="text-zinc-400">{activeAlert.command_line}</span>
              </div>
            )}

            {activeAlert.sha256 && (
              <div className="text-[10px] text-zinc-600 w-full text-left font-mono truncate">
                FILE SHA256: {activeAlert.sha256}
              </div>
            )}

            <div className="text-xs text-emerald-500 font-bold tracking-widest">
              COUNTERMEASURE: Process Terminated & Isolated
            </div>

            <button 
              onClick={() => setActiveAlert(null)}
              className="mt-2 w-full bg-red-600 hover:bg-red-700 text-zinc-100 font-bold py-2.5 px-4 rounded text-xs uppercase tracking-widest cursor-pointer transition-all active:scale-[0.98]"
            >
              Resolve & Dismiss Alert
            </button>
          </div>
        </div>
      )}

      {selectedProcess && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-40">
          <div className="border border-zinc-800 bg-zinc-950 p-6 rounded max-w-lg w-full flex flex-col gap-4 shadow-[0_0_30px_rgba(255,255,255,0.05)]">
            <div className="flex justify-between items-center border-b border-zinc-900 pb-3">
              <h3 className="text-base font-bold text-zinc-300">PROCESS DETAILS</h3>
              <button onClick={() => setSelectedProcess(null)} className="text-zinc-600 hover:text-zinc-400 cursor-pointer text-xs uppercase tracking-widest">Close</button>
            </div>
            
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-zinc-600 uppercase font-bold block">Process Name</span>
                <span className="text-zinc-200 font-bold">{selectedProcess.child}</span>
              </div>
              <div>
                <span className="text-zinc-600 uppercase font-bold block">Process ID</span>
                <span className="text-zinc-200">{selectedProcess.pid}</span>
              </div>
              <div>
                <span className="text-zinc-600 uppercase font-bold block">Parent Process</span>
                <span className="text-zinc-300">{selectedProcess.parent}</span>
              </div>
              <div>
                <span className="text-zinc-600 uppercase font-bold block">Signature Status</span>
                <span className={selectedProcess.is_signed ? "text-emerald-500 font-bold" : "text-zinc-500"}>
                  {selectedProcess.is_signed ? "Verified" : "Unsigned"}
                </span>
              </div>
            </div>

            {selectedProcess.command_line && (
              <div className="bg-black/40 p-3 rounded text-[11px] font-mono break-all border border-zinc-900 flex flex-col gap-1">
                <span className="text-zinc-600 font-bold uppercase">Command Line Arguments</span>
                <span className="text-zinc-400">{selectedProcess.command_line}</span>
              </div>
            )}

            {selectedProcess.sha256 && (
              <div className="bg-black/40 p-3 rounded text-[11px] font-mono break-all border border-zinc-900 flex flex-col gap-1">
                <span className="text-zinc-600 font-bold uppercase">SHA256 Hash</span>
                <span className="text-zinc-400">{selectedProcess.sha256}</span>
              </div>
            )}

            {selectedProcess.status === "BLOCKED" && selectedProcess.reason && (
              <div className="border border-red-900/50 bg-red-950/10 p-2.5 rounded text-xs text-red-400 font-bold">
                BLOCKED REASON: {selectedProcess.reason}
              </div>
            )}

            <div className="border-t border-zinc-900 pt-3 flex gap-3">
              <button 
                onClick={() => handleKill(selectedProcess.pid)}
                className="flex-1 bg-red-600 hover:bg-red-700 text-zinc-100 font-bold py-2 px-4 rounded text-xs uppercase tracking-widest cursor-pointer transition-all active:scale-[0.98]"
              >
                Terminate Process
              </button>
              <button 
                onClick={() => setSelectedProcess(null)}
                className="border border-zinc-800 hover:border-zinc-700 text-zinc-400 font-bold py-2 px-4 rounded text-xs uppercase tracking-widest cursor-pointer transition-all"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}