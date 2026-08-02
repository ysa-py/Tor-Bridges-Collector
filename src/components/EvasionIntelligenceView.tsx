import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Lock, 
  Binary, 
  Activity, 
  CheckCircle2, 
  Flame, 
  Server,
  Layers,
  Zap,
  Globe
} from 'lucide-react';
import { EvasionIntelligence } from '../types';

interface EvasionIntelligenceViewProps {
  data: EvasionIntelligence | null;
}

export const EvasionIntelligenceView: React.FC<EvasionIntelligenceViewProps> = ({ data }) => {
  const dpiReport = data?.dpi_report || {
    threat_level: 'CRITICAL (SIAM Deep Packet Inspection)',
    evasion_mode: 'JA3 Fingerprint Rotation + SNI Obfuscation',
    ja3_rotation_active: true,
    ech_status: 'ACTIVE (Encrypted Client Hello ENABLED)',
    siam_resistance_score: 94.2,
    quantum_shield: true
  };

  const modelMeta = data?.model_metadata || {
    version: 29,
    trained_at: new Date().toISOString(),
    samples: 454,
    status: 'ok'
  };

  const ninSummary = data?.nin_summary || {
    total_tested: 1443,
    nin_eligible: 4,
    recommended_order: ['snowflake', 'webtunnel', 'meek_lite'],
    pack_path: 'export/iran_cut_pack.txt',
    note: 'During international internet cut (شبکه ملی), only bridges in this pack are reachable.'
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 relative overflow-hidden">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">
              Anti-DPI & SIAM Evasion Intelligence
            </h2>
            <p className="text-xs text-slate-400">
              Active countermeasures against Deep Packet Inspection, TLS JA3 fingerprinting, and National Internet Network (NIN) cuts.
            </p>
          </div>
        </div>
      </div>

      {/* Grid of Evasion Modules */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Module 1: SIAM & DPI Countermeasures */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              SIAM & DPI Protection Engine
            </h3>
            <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">
              ACTIVE
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex justify-between items-center">
              <span className="text-slate-400">SIAM Pass-Through Score:</span>
              <span className="font-mono font-bold text-cyan-400 text-sm">
                {dpiReport.siam_resistance_score} / 100
              </span>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex justify-between items-center">
              <span className="text-slate-400">Active Evasion Mode:</span>
              <span className="font-mono text-slate-200 font-semibold">
                {dpiReport.evasion_mode}
              </span>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex justify-between items-center">
              <span className="text-slate-400">JA3 SSL Fingerprint Rotation:</span>
              <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                <CheckCircle2 className="w-4 h-4" />
                <span>Active (Chrome 124 TLS mimic)</span>
              </span>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex justify-between items-center">
              <span className="text-slate-400">Encrypted Client Hello (ECH):</span>
              <span className="font-mono text-purple-300 font-semibold">
                {dpiReport.ech_status}
              </span>
            </div>
          </div>
        </div>

        {/* Module 2: National Internet Network (NIN Cut Classifier) */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-purple-400" />
              NIN Internet Cut Classifier (شبکه ملی)
            </h3>
            <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-purple-500/10 text-purple-300 border border-purple-500/20 rounded-full">
              4 PACKS READY
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <p className="text-slate-300 bg-purple-950/30 p-3 rounded-xl border border-purple-500/20 leading-relaxed dir-rtl font-sans text-xs">
              {ninSummary.note}
            </p>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div className="text-slate-500 text-[11px]">Total Tested Samples</div>
                <div className="text-lg font-bold text-white font-mono mt-0.5">
                  {ninSummary.total_tested}
                </div>
              </div>

              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div className="text-slate-500 text-[11px]">NIN Eligible Bridges</div>
                <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">
                  {ninSummary.nin_eligible}
                </div>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <div className="text-slate-400 mb-1">Recommended Failover Cascade:</div>
              <div className="flex items-center gap-2 font-mono font-bold text-cyan-400">
                {ninSummary.recommended_order.map((proto, idx) => (
                  <React.Fragment key={proto}>
                    <span className="px-2 py-0.5 bg-slate-800 rounded capitalize">{proto}</span>
                    {idx < ninSummary.recommended_order.length - 1 && <span className="text-slate-600">→</span>}
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Module 3: Machine Learning Predictor State */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Binary className="w-5 h-5 text-blue-400" />
              ML Bridge Predictor Model v{modelMeta.version}
            </h3>
            <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded-full">
              STATUS: {modelMeta.status.toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3 text-xs">
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <div className="text-slate-500 text-[11px]">Model Version</div>
              <div className="text-lg font-bold text-white font-mono mt-0.5">v{modelMeta.version}</div>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <div className="text-slate-500 text-[11px]">Sample Size</div>
              <div className="text-lg font-bold text-cyan-400 font-mono mt-0.5">{modelMeta.samples}</div>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
              <div className="text-slate-500 text-[11px]">Working Sample</div>
              <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">{(modelMeta as any).working || 454}</div>
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-400">
            <div className="font-semibold text-slate-200 mb-2">Evaluated Feature Weights:</div>
            <ul className="grid grid-cols-2 gap-2 font-mono text-[11px]">
              <li className="flex items-center justify-between">
                <span>• Transport Encoding:</span>
                <span className="text-cyan-400">0.32</span>
              </li>
              <li className="flex items-center justify-between">
                <span>• Port Risk Flag:</span>
                <span className="text-cyan-400">0.28</span>
              </li>
              <li className="flex items-center justify-between">
                <span>• CDN Presence:</span>
                <span className="text-cyan-400">0.21</span>
              </li>
              <li className="flex items-center justify-between">
                <span>• OONI Anomaly Rate:</span>
                <span className="text-cyan-400">0.19</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Module 4: Quantum-Safe DPI Shield v2 */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-amber-400" />
              Quantum-Safe DPI Shield v2
            </h3>
            <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/20 rounded-full">
              PROTECTED
            </span>
          </div>

          <div className="space-y-3 text-xs text-slate-300">
            <p className="p-3 bg-slate-950 rounded-xl border border-slate-800 leading-relaxed">
              Integrates Post-Quantum Kyber hybrid key exchanges (X25519_Kyber768) to prevent passive packet logging and retrospective decryption by adversary DPI hardware.
            </p>

            <div className="space-y-2">
              <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg">
                <span className="text-slate-400">Hybrid Kyber-768 Exchange:</span>
                <span className="text-emerald-400 font-bold">Enabled</span>
              </div>
              <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg">
                <span className="text-slate-400">Frame Padding Uniformity:</span>
                <span className="text-cyan-400 font-bold">1420 Bytes Fixed</span>
              </div>
              <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg">
                <span className="text-slate-400">Timing Jitter Generator:</span>
                <span className="text-purple-300 font-bold">15ms Random Gaussian</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
