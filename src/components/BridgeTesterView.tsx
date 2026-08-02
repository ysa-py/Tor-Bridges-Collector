import React, { useState } from 'react';
import { 
  Terminal, 
  Send, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Wifi, 
  Cpu, 
  Copy, 
  Check,
  Zap,
  HelpCircle
} from 'lucide-react';
import { ProbeTestResult } from '../types';

export const BridgeTesterView: React.FC = () => {
  const [inputLine, setInputLine] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<ProbeTestResult | null>(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [copied, setCopied] = useState(false);

  const sampleBridges = [
    'snowflake 192.0.2.3:80 2B280B2E58D7E004B2A2FA35540D304D8C4773A6',
    'webtunnel 109.104.14.213:443 3F94891578E8ED8E693F5C2B0442846C617D1B91 url=https://example.com/wt',
    'obfs4 185.132.41.102:443 4FBCA9FC7A7882D6DF090B89AEEECA8FC3E05D6C cert=xyZ... iat-mode=0',
    '108.175.13.9:80 F9A4DE8B36FA492A05277FAD58F93F5EFEA1E926'
  ];

  const handleTest = async (line: string = inputLine) => {
    if (!line.trim()) {
      setErrorMsg('Please enter a bridge line to test.');
      return;
    }

    setErrorMsg('');
    setIsTesting(true);
    setTestResult(null);

    try {
      const res = await fetch('/api/test-bridge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bridge_line: line.trim() })
      });

      const data = await res.json();
      if (res.ok) {
        setTestResult(data);
      } else {
        setErrorMsg(data.error || 'Failed to probe bridge');
      }
    } catch (err: any) {
      setErrorMsg('Error connecting to backend probe tool');
    } finally {
      setIsTesting(false);
    }
  };

  const handleCopyResult = () => {
    if (!testResult) return;
    navigator.clipboard.writeText(testResult.bridge_line);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">
              Live Bridge Probe & DPI Validator
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Test any custom Tor bridge line against Iranian DPI signatures, NIN reachability, and protocol syntax.
            </p>
          </div>
        </div>
      </div>

      {/* Main Input Box */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Bridge Line
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              placeholder="Paste bridge line (e.g. snowflake 192.0.2.3:80 ... or obfs4 IP:PORT ...)"
              value={inputLine}
              onChange={(e) => setInputLine(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleTest()}
              className="flex-1 px-4 py-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
            <button
              onClick={() => handleTest()}
              disabled={isTesting}
              className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Send className={`w-4 h-4 ${isTesting ? 'animate-spin' : ''}`} />
              <span>{isTesting ? 'Probing...' : 'Run Probe'}</span>
            </button>
          </div>
          {errorMsg && (
            <p className="text-xs text-rose-400 mt-2 font-medium flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>{errorMsg}</span>
            </p>
          )}
        </div>

        {/* Quick Sample Preset Buttons */}
        <div>
          <span className="text-[11px] font-medium text-slate-400 block mb-2">
            Or test a preset sample bridge line:
          </span>
          <div className="flex flex-wrap gap-2">
            {sampleBridges.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setInputLine(sample);
                  handleTest(sample);
                }}
                className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 transition-all truncate max-w-xs cursor-pointer"
              >
                {sample}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Test Results Output Display */}
      {testResult && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-6 shadow-2xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              {testResult.status === 'reachable' ? (
                <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
              ) : testResult.status === 'blocked' ? (
                <div className="p-2 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <XCircle className="w-6 h-6" />
                </div>
              ) : (
                <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <AlertTriangle className="w-6 h-6" />
                </div>
              )}

              <div>
                <h3 className="text-lg font-bold text-white capitalize flex items-center gap-2">
                  <span>Probe Status: {testResult.status}</span>
                  {testResult.nin_bypass_capable && (
                    <span className="px-2 py-0.5 text-xs font-semibold bg-purple-500/10 text-purple-300 border border-purple-500/20 rounded-full">
                      NIN PASS-THROUGH
                    </span>
                  )}
                </h3>
                <p className="text-xs text-slate-400">
                  Tested at {new Date(testResult.checked_at).toLocaleTimeString()}
                </p>
              </div>
            </div>

            <button
              onClick={handleCopyResult}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400 font-bold">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-400" />
                  <span>Copy Line</span>
                </>
              )}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-500 block">Detected Transport</span>
              <span className="text-base font-bold font-mono text-cyan-400 capitalize mt-1 block">
                {testResult.transport_detected}
              </span>
            </div>

            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-500 block">Latency Estimate</span>
              <span className="text-base font-bold font-mono text-emerald-400 mt-1 block">
                {testResult.latency_ms ? `${testResult.latency_ms} ms` : 'N/A'}
              </span>
            </div>

            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-500 block">DPI Resistance Verdict</span>
              <span className="text-sm font-bold text-slate-200 mt-1 block">
                {testResult.dpi_verdict}
              </span>
            </div>
          </div>

          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs font-bold text-slate-300">Probe Diagnostics Note:</div>
            <p className="text-xs font-mono text-slate-400 leading-relaxed">
              {testResult.notes}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
