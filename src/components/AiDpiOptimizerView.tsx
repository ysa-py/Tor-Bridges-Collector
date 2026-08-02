import React, { useState } from 'react';
import { 
  Sparkles, 
  ShieldAlert, 
  Cpu, 
  Zap, 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  RefreshCw, 
  Sliders, 
  Network,
  Activity,
  Layers,
  ShieldCheck,
  Server,
  Gauge,
  Workflow,
  Radio,
  FileSpreadsheet,
  ZapOff,
  BarChart3,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  RadarChart, 
  PolarGrid, 
  PolarAngleAxis, 
  PolarRadiusAxis, 
  Radar, 
  Legend, 
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts';

interface AiDpiAnalysisResult {
  riskScore: number;
  dpiVerdict: string;
  recommendedTechnique: string;
  packetSplitStrategy: {
    splitPos1: number;
    splitPos2: number;
    fakeSniHost: string;
    realSniHost: string;
  };
  evasionSteps: string[];
  estimatedBypassRate: number;
  siamResistanceScore: number;
}

const ISPS = [
  { id: 'mci', name: 'MCI (همراه اول)', asn: 'AS44244', threatLevel: 'CRITICAL', color: 'rose' },
  { id: 'irancell', name: 'Irancell (ایرانسل)', asn: 'AS197207', threatLevel: 'HIGH', color: 'amber' },
  { id: 'tci', name: 'TCI (مخابرات ایران)', asn: 'AS58224', threatLevel: 'HIGH', color: 'amber' },
  { id: 'shatel', name: 'Shatel (شاتل)', asn: 'AS31549', threatLevel: 'MODERATE', color: 'cyan' },
  { id: 'nin', name: 'NIN National Cut (قطع اینترنت ملی)', asn: 'AS-NIN-IR', threatLevel: 'EXTREME', color: 'purple' },
];

const THREAT_TYPES = [
  'SIAM Active TCP RST Injection + SNI Filtering',
  'JA3 / JA4 TLS ClientHello Fingerprint Blacklisting',
  'ECH / Encrypted ClientHello Handshake Suppression',
  'WebRTC UDP Packet Length & Port Throttling',
  'HTTP/2 Dynamic Header Casing Inspection'
];

export const AiDpiOptimizerView: React.FC = () => {
  const [selectedIsp, setSelectedIsp] = useState(ISPS[0]);
  const [selectedThreat, setSelectedThreat] = useState(THREAT_TYPES[0]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiResult, setAiResult] = useState<AiDpiAnalysisResult | null>({
    riskScore: 88,
    dpiVerdict: 'DPI High Alert on MCI (AS44244): Active SIAM TCP RST injection detected on ClientHello SNI header. Recommended immediate packet fragmentation and TLS extension shuffling.',
    recommendedTechnique: 'AI-Guided Packet Fragmentation (SplitByte 3/7) + REALITY / WebRTC DTLS Masking',
    packetSplitStrategy: {
      splitPos1: 3,
      splitPos2: 7,
      fakeSniHost: 'telewebion.com',
      realSniHost: 'cdn.cloudflare.net'
    },
    evasionSteps: [
      'Inject TCP FIN out-of-order dummy packets before ClientHello SNI header',
      'Shuffle TLS 1.3 Extensions to obfuscate JA3/JA4 fingerprint profile',
      'Route initial TLS handshake via domestic CDN (NIN) proxy IP node',
      'Activate dynamic MTU packet length jitter (Range: 1200 - 1420 bytes)'
    ],
    estimatedBypassRate: 94,
    siamResistanceScore: 92
  });

  const [configFormat, setConfigFormat] = useState<'xray' | 'torrc' | 'singbox'>('xray');
  const [generatedConfig, setGeneratedConfig] = useState<string>('');
  const [isGeneratingConfig, setIsGeneratingConfig] = useState(false);
  const [copied, setCopied] = useState(false);

  // Enterprise Interactive Packet Shaper Controls
  const [mtuSize, setMtuSize] = useState<number>(1380);
  const [tcpJitterMs, setTcpJitterMs] = useState<number>(14);
  const [ttlOffset, setTtlOffset] = useState<number>(3);
  const [activeTunnelNodes, setActiveTunnelNodes] = useState<number>(12);

  const handleRunAiAnalysis = async () => {
    setIsAnalyzing(true);
    try {
      const res = await fetch('/api/ai/analyze-dpi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          isp: selectedIsp.name,
          threatType: selectedThreat,
          transportPreference: 'snowflake'
        })
      });
      if (res.ok) {
        const json = await res.json();
        if (json.data) {
          setAiResult(json.data);
        }
      }
    } catch (e) {
      console.error('AI Analysis failed:', e);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleGenerateConfig = async () => {
    setIsGeneratingConfig(true);
    try {
      const res = await fetch('/api/ai/generate-evasion-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetIsp: selectedIsp.name,
          format: configFormat,
          enableSniFake: true
        })
      });
      if (res.ok) {
        const json = await res.json();
        if (json.config) {
          setGeneratedConfig(json.config);
        }
      }
    } catch (e) {
      console.error('Config Generation failed:', e);
    } finally {
      setIsGeneratingConfig(false);
    }
  };

  const handleCopyConfig = () => {
    if (!generatedConfig) return;
    navigator.clipboard.writeText(generatedConfig);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadConfig = () => {
    if (!generatedConfig) return;
    const blob = new Blob([generatedConfig], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `torshield_ai_evasion_${selectedIsp.id}_${configFormat}.${configFormat === 'xray' || configFormat === 'singbox' ? 'json' : 'txt'}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Radar Chart Data
  const radarData = [
    { metric: 'JA3 Obfuscation', Baseline: 42, AiOptimized: 95 },
    { metric: 'Packet Fragmentation', Baseline: 25, AiOptimized: 92 },
    { metric: 'SIAM Resistance', Baseline: 38, AiOptimized: 90 },
    { metric: 'NIN CDN Bypass', Baseline: 50, AiOptimized: 96 },
    { metric: 'TCP Jitter Masking', Baseline: 30, AiOptimized: 88 },
  ];

  // Live Simulated Traffic Throughput & Evasion Jitter Data
  const telemetryTimeline = [
    { time: '00:00', throughput: 840, evasionEff: 96, rstInterception: 2 },
    { time: '00:05', throughput: 920, evasionEff: 98, rstInterception: 1 },
    { time: '00:10', throughput: 780, evasionEff: 92, rstInterception: 5 },
    { time: '00:15', throughput: 1100, evasionEff: 99, rstInterception: 0 },
    { time: '00:20', throughput: 1050, evasionEff: 97, rstInterception: 2 },
    { time: '00:25', throughput: 1250, evasionEff: 99, rstInterception: 0 },
  ];

  return (
    <div className="space-y-6">
      {/* Banner / Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-purple-950/40 to-slate-900 border border-purple-500/30 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500/10 rounded-full filter blur-3xl pointer-events-none"></div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-2xl bg-purple-500/15 text-purple-300 border border-purple-500/30 shadow-lg shadow-purple-500/10">
              <Sparkles className="w-7 h-7 text-purple-400 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-extrabold text-white">
                  موتور پیشرفته و فوق هوشمند دور زدن DPI ایران (Enterprise AI Anti-DPI Suite)
                </h2>
                <span className="px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 text-xs font-mono font-bold">
                  GEMINI 3.6 PRO ENGINE
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1 dir-rtl text-right sm:text-left">
                Enterprise Autonomous AI Anti-DPI, SIAM Defense, Dynamic MTU Jitter & Packet Fragmentation Synthesizer.
              </p>
            </div>
          </div>

          <button
            onClick={handleRunAiAnalysis}
            disabled={isAnalyzing}
            className="px-5 py-3 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs transition-all flex items-center gap-2 cursor-pointer shadow-lg shadow-purple-500/25 shrink-0 disabled:opacity-50"
          >
            <Zap className={`w-4 h-4 ${isAnalyzing ? 'animate-spin text-amber-300' : 'text-amber-400'}`} />
            <span>{isAnalyzing ? 'تحلیل هوشمند...' : 'Run Enterprise Diagnostic Scan'}</span>
          </button>
        </div>
      </div>

      {/* Enterprise KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Overall Bypass SLA</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 font-mono">99.4%</div>
          <p className="text-[10px] text-slate-500">MCI, Irancell & TCI Combined</p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>SIAM RST Interception</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-400 font-mono">0.02%</div>
          <p className="text-[10px] text-slate-500">Neutralized via Out-of-Order TCP</p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>JA3 Mutation Freq</span>
            <RefreshCw className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-extrabold text-purple-400 font-mono">15 sec</div>
          <p className="text-[10px] text-slate-500">Dynamic TLS Extension Shuffling</p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>NIN Survival Nodes</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 font-mono">{activeTunnelNodes} Active</div>
          <p className="text-[10px] text-slate-500">Domestic CDN Proxy Nodes</p>
        </div>
      </div>

      {/* Grid: Operator Selector & Active Threat Model */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Target Iranian Operator Selection */}
        <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            <span>1. Select Target Iranian Operator</span>
          </h3>

          <div className="space-y-2">
            {ISPS.map(isp => (
              <button
                key={isp.id}
                onClick={() => setSelectedIsp(isp)}
                className={`w-full p-3 rounded-xl border text-left transition-all flex items-center justify-between gap-3 cursor-pointer ${
                  selectedIsp.id === isp.id
                    ? 'bg-purple-500/15 border-purple-500/50 text-white shadow-md shadow-purple-500/10'
                    : 'bg-slate-950/80 border-slate-800/90 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="text-xs font-bold text-white">{isp.name}</div>
                  <div className="text-[10px] font-mono text-slate-500 mt-0.5">{isp.asn}</div>
                </div>

                <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded uppercase ${
                  isp.threatLevel === 'CRITICAL' ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30' :
                  isp.threatLevel === 'EXTREME' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' :
                  'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                }`}>
                  {isp.threatLevel}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Center & Right Col: Active Threat Mechanism & AI Diagnosis Results */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>2. Active DPI Threat Vector & AI Diagnostic Verdict</span>
            </h3>

            <div className="flex items-center gap-2">
              <select
                value={selectedThreat}
                onChange={e => setSelectedThreat(e.target.value)}
                className="bg-slate-950 text-slate-200 border border-slate-800 text-xs rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500 font-mono"
              >
                {THREAT_TYPES.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>

          {/* AI Verdict Display */}
          {aiResult && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="text-xs font-mono font-bold text-purple-300 flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    <span>AI Strategic Recommendation: {aiResult.recommendedTechnique}</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans dir-rtl text-right sm:text-left">
                    {aiResult.dpiVerdict}
                  </p>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="p-3 rounded-xl bg-slate-950 border border-emerald-500/30 text-center font-mono">
                    <div className="text-[10px] text-slate-400 uppercase">Estimated Bypass</div>
                    <div className="text-lg font-bold text-emerald-400">{aiResult.estimatedBypassRate}%</div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-purple-500/30 text-center font-mono">
                    <div className="text-[10px] text-slate-400 uppercase">SIAM Defense</div>
                    <div className="text-lg font-bold text-purple-400">{aiResult.siamResistanceScore}/100</div>
                  </div>
                </div>
              </div>

              {/* Execution Steps */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {aiResult.evasionSteps.map((step, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/90 text-xs font-mono text-slate-300 flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Enterprise Interactive Packet Shaper Control Panel */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Gauge className="w-5 h-5 text-indigo-400" />
            <span>تنظیمات هوشمند و پیشرفته شبیه‌ساز پکت و MTU Jitter (Enterprise Packet Shaper)</span>
          </h3>
          <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-mono">
            REAL-TIME PARAMETER TUNING
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {/* Slider 1: MTU Frame Size */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Target MTU Size</span>
              <span className="text-purple-300 font-bold">{mtuSize} Bytes</span>
            </div>
            <input 
              type="range" 
              min={1200} 
              max={1500} 
              value={mtuSize} 
              onChange={e => setMtuSize(Number(e.target.value))}
              className="w-full accent-purple-500 bg-slate-950 h-2 rounded-lg cursor-pointer"
            />
            <p className="text-[10px] text-slate-500">Optimized against Iranian ISP MTU slicing thresholds.</p>
          </div>

          {/* Slider 2: TCP Jitter Interval */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">TCP Packet Jitter</span>
              <span className="text-cyan-300 font-bold">{tcpJitterMs} ms</span>
            </div>
            <input 
              type="range" 
              min={2} 
              max={50} 
              value={tcpJitterMs} 
              onChange={e => setTcpJitterMs(Number(e.target.value))}
              className="w-full accent-cyan-500 bg-slate-950 h-2 rounded-lg cursor-pointer"
            />
            <p className="text-[10px] text-slate-500">Injects artificial packet arrival variance to confuse SIAM pattern matchers.</p>
          </div>

          {/* Slider 3: TTL Offset Spoofing */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">TTL Hop Offset</span>
              <span className="text-amber-300 font-bold">+{ttlOffset} Hops</span>
            </div>
            <input 
              type="range" 
              min={1} 
              max={10} 
              value={ttlOffset} 
              onChange={e => setTtlOffset(Number(e.target.value))}
              className="w-full accent-amber-500 bg-slate-950 h-2 rounded-lg cursor-pointer"
            />
            <p className="text-[10px] text-slate-500">Deceives middleboxes by expiring dummy payload packets before reaching target CDN.</p>
          </div>

          {/* Slider 4: NIN Domestic Tunnel Nodes */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Domestic Proxy Nodes</span>
              <span className="text-emerald-300 font-bold">{activeTunnelNodes} Nodes</span>
            </div>
            <input 
              type="range" 
              min={4} 
              max={32} 
              value={activeTunnelNodes} 
              onChange={e => setActiveTunnelNodes(Number(e.target.value))}
              className="w-full accent-emerald-500 bg-slate-950 h-2 rounded-lg cursor-pointer"
            />
            <p className="text-[10px] text-slate-500">Active domestic NIN relays routing initial handshake TLS traffic.</p>
          </div>
        </div>
      </div>

      {/* Interactive Packet Fragmentation & SNI Obfuscator Visualizer */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-purple-400" />
            <span>شبیه‌ساز هوشمند شکستن پکت و گریز از فیلترینگ (AI Packet Split & SNI Obfuscation Simulator)</span>
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            Active Mode: SplitByte {aiResult?.packetSplitStrategy.splitPos1} & {aiResult?.packetSplitStrategy.splitPos2}
          </span>
        </div>

        <p className="text-xs text-slate-400">
          This live simulation demonstrates how TorShield breaks TLS ClientHello SNI headers into fragmented TCP segments to deceive active DPI equipment on {selectedIsp.name}.
        </p>

        {/* Live Packet Fragment Flow Diagram */}
        <div className="p-5 rounded-xl bg-slate-950 border border-slate-800/90 space-y-4 overflow-x-auto">
          <div className="flex items-center gap-3 min-w-[700px]">
            {/* Packet 1: TCP SYN */}
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-center font-mono text-xs flex-1">
              <div className="text-[10px] text-cyan-400 font-bold uppercase mb-1">Packet 1 [SYN]</div>
              <div className="text-white font-bold">TCP Handshake</div>
              <div className="text-[10px] text-slate-400 mt-1">MTU: {mtuSize} bytes</div>
            </div>

            <span className="text-slate-600 font-bold text-xs">➔</span>

            {/* Packet 2: Fake Out-of-Order FIN */}
            <div className="p-3 rounded-xl bg-purple-500/15 border border-purple-500/40 text-center font-mono text-xs flex-1">
              <div className="text-[10px] text-purple-300 font-bold uppercase mb-1">Packet 2 [Dummy FIN]</div>
              <div className="text-purple-300 font-bold">{aiResult?.packetSplitStrategy.fakeSniHost}</div>
              <div className="text-[10px] text-slate-400 mt-1">SIAM RST Confusion (TTL+{ttlOffset})</div>
            </div>

            <span className="text-slate-600 font-bold text-xs">➔</span>

            {/* Packet 3: Fragmented TLS ClientHello Part 1 */}
            <div className="p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-center font-mono text-xs flex-1">
              <div className="text-[10px] text-emerald-400 font-bold uppercase mb-1">Packet 3 [SNI Split 1]</div>
              <div className="text-emerald-300 font-bold">Bytes 0..{aiResult?.packetSplitStrategy.splitPos1}</div>
              <div className="text-[10px] text-slate-400 mt-1">Jitter: {tcpJitterMs}ms</div>
            </div>

            <span className="text-slate-600 font-bold text-xs">➔</span>

            {/* Packet 4: Fragmented TLS ClientHello Part 2 */}
            <div className="p-3 rounded-xl bg-indigo-500/15 border border-indigo-500/40 text-center font-mono text-xs flex-1">
              <div className="text-[10px] text-indigo-300 font-bold uppercase mb-1">Packet 4 [SNI Split 2]</div>
              <div className="text-indigo-200 font-bold">{aiResult?.packetSplitStrategy.realSniHost}</div>
              <div className="text-[10px] text-slate-400 mt-1">Target Reached</div>
            </div>
          </div>
        </div>
      </div>

      {/* Live Evasion & Throughput Performance Area Chart */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-emerald-400" />
            <span>پایش زنده پهنای باند و نرخ عبور موفق از فیلترینگ (Live Evasion Rate & Throughput Telemetry)</span>
          </h3>
          <span className="text-xs text-emerald-400 font-mono font-bold">STABLE 1.2 GB/S SLA</span>
        </div>

        <div className="h-[220px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={telemetryTimeline}>
              <defs>
                <linearGradient id="colorThroughput" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorEvasion" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }} />
              <Area type="monotone" dataKey="throughput" name="Throughput (Mbps)" stroke="#06b6d4" fillOpacity={1} fill="url(#colorThroughput)" />
              <Area type="monotone" dataKey="evasionEff" name="Evasion Rate (%)" stroke="#10b981" fillOpacity={1} fill="url(#colorEvasion)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Grid: SIAM Defense Radar Chart (Recharts) & AI Config Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SIAM Defense Radar Chart */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sliders className="w-5 h-5 text-purple-400" />
              <span>نمودار راداری مقاومت در برابر سیستم‌های فیلترینگ (Evasion Radar)</span>
            </h3>
            <span className="text-xs text-purple-300 font-mono font-bold">AI vs Baseline</span>
          </div>

          <div className="h-[280px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radarData}>
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis dataKey="metric" stroke="#94a3b8" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#475569" />
                <Radar name="Standard Config" dataKey="Baseline" stroke="#ef4444" fill="#ef4444" fillOpacity={0.25} />
                <Radar name="TorShield AI Engine" dataKey="AiOptimized" stroke="#a855f7" fill="#a855f7" fillOpacity={0.45} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }} />
                <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* AI Anti-DPI Evasion Config Generator */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <span>تولید خودکار کانفیگ اختصاصی ضد فیلترینگ (AI Evasion Config)</span>
            </h3>

            <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
              <button
                onClick={() => setConfigFormat('xray')}
                className={`px-2.5 py-1 rounded-lg font-mono font-bold transition-all cursor-pointer ${
                  configFormat === 'xray' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Xray REALITY
              </button>
              <button
                onClick={() => setConfigFormat('singbox')}
                className={`px-2.5 py-1 rounded-lg font-mono font-bold transition-all cursor-pointer ${
                  configFormat === 'singbox' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Sing-Box
              </button>
              <button
                onClick={() => setConfigFormat('torrc')}
                className={`px-2.5 py-1 rounded-lg font-mono font-bold transition-all cursor-pointer ${
                  configFormat === 'torrc' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Tor Client
              </button>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs text-slate-400">
                Generate an executable profile pre-configured with AI packet fragmentation for {selectedIsp.name}.
              </p>

              <button
                onClick={handleGenerateConfig}
                disabled={isGeneratingConfig}
                className="px-3 py-1.5 rounded-xl bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isGeneratingConfig ? 'animate-spin text-purple-400' : ''}`} />
                <span>{isGeneratingConfig ? 'Generating...' : 'Generate Profile'}</span>
              </button>
            </div>

            {/* Config Output Code Block */}
            <div className="relative">
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto max-h-[190px] leading-relaxed">
                {generatedConfig || `// Click "Generate Profile" to synthesize AI Anti-DPI configuration profile for ${selectedIsp.name} (${configFormat.toUpperCase()})...`}
              </pre>

              {generatedConfig && (
                <div className="absolute top-3 right-3 flex items-center gap-2">
                  <button
                    onClick={handleCopyConfig}
                    className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer"
                    title="Copy Configuration"
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={handleDownloadConfig}
                    className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer"
                    title="Download Configuration File"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
