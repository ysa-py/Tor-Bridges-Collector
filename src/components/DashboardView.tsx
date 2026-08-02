import React, { useEffect, useState } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, CartesianGrid, Legend
} from 'recharts';
import { 
  ShieldAlert, 
  Radio, 
  Wifi, 
  Lock, 
  ArrowUpRight, 
  CheckCircle2, 
  AlertTriangle,
  Zap,
  Globe2,
  Copy,
  GitBranch,
  Clock,
  Activity,
  TrendingUp,
  RefreshCw,
  CheckCircle,
  Server
} from 'lucide-react';
import { DashboardSummary, TransportStat } from '../types';
import { D3LatencyHeatmap } from './D3LatencyHeatmap';
import { ServiceHealthMonitor } from './ServiceHealthMonitor';

interface DashboardViewProps {
  summary: DashboardSummary | null;
  transports: TransportStat[];
  onNavigate: (tab: string) => void;
  onCopyPack: (category: string) => void;
}

interface SystemStatusData {
  pipeline_name: string;
  status: string;
  last_run_timestamp: string;
  run_number: number;
  trigger: string;
  runners: Record<string, string>;
  bridge_health_summary: {
    harvested_last_24h: number;
    valid_iran_reachable: number;
    stale_pruned: number;
  };
}

interface AvailabilityTrendPoint {
  day: string;
  harvested: number;
  iran_reachable: number;
  nin_survival: number;
  dpi_spikes: number;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  summary,
  transports,
  onNavigate,
  onCopyPack
}) => {
  const [systemStatus, setSystemStatus] = useState<SystemStatusData | null>(null);
  const [trendData, setTrendData] = useState<AvailabilityTrendPoint[]>([]);
  const [trendSummary, setTrendSummary] = useState<any>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);

  useEffect(() => {
    let isMounted = true;
    
    // Fetch System Status
    fetch('/api/system-status')
      .then(res => res.json())
      .then(data => {
        if (isMounted) {
          setSystemStatus(data);
        }
      })
      .catch(err => console.error('Failed to fetch system status:', err));

    // Fetch 30-Day Availability Trends
    fetch('/api/availability-trends')
      .then(res => res.json())
      .then(data => {
        if (isMounted) {
          setTrendData(data.trend_30d || []);
          setTrendSummary(data.summary || null);
          setLoadingStatus(false);
        }
      })
      .catch(err => {
        console.error('Failed to fetch availability trends:', err);
        if (isMounted) setLoadingStatus(false);
      });

    return () => { isMounted = false; };
  }, []);

  const chartData = transports.map(t => ({
    name: t.transport,
    tested: t.total_tested,
    working: t.working,
    rate: (t.success_rate * 100).toFixed(1),
    score: t.scorer_score,
  }));

  const COLORS = ['#00f2fe', '#3b82f6', '#8b5cf6', '#ec4899', '#64748b'];

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute -right-10 -bottom-10 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                NIN & SIAM Evasion Engine v5.2
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Updated: {summary?.timestamp ? new Date(summary.timestamp).toLocaleTimeString() : 'Just now'}
              </span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              Tor Bridge Resistance Matrix
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">
              Continuous probing, JA3 TLS fingerprint randomization, and OONI censorship measurement correlation for Iranian ISP networks.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate('tester')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs rounded-xl transition-all flex items-center gap-2 cursor-pointer"
            >
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>Probe Custom Line</span>
            </button>
            <button
              onClick={() => onNavigate('export')}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 cursor-pointer"
            >
              <span>Download Survival Packs</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Harvested */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Harvested Bridges</span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <Radio className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-3xl font-extrabold text-white font-mono">
              {(summary?.bridges?.total || 3387).toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center gap-1">
              <span className="text-emerald-400 font-medium">+{summary?.bridges?.tested || 454}</span>
              <span>actively tested sample</span>
            </div>
          </div>
        </div>

        {/* Iran Reachable */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Iran Reachable</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Wifi className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-3xl font-extrabold text-emerald-400 font-mono">
              {(summary?.bridges?.iran_reachable || 1280).toLocaleString()}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Valid SSL handshake on MCI/TCI</span>
            </div>
          </div>
        </div>

        {/* NIN Internet Cut Survival */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">NIN Cut Survival</span>
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-3xl font-extrabold text-purple-300 font-mono">
              {summary?.bridges?.nin_survival || 4} <span className="text-xs font-normal text-slate-400">Packs</span>
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center gap-1">
              <span className="text-cyan-400 font-medium">Snowflake & WebTunnel</span>
            </div>
          </div>
        </div>

        {/* Threat Level */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">DPI Threat Level</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-lg font-bold text-amber-300 truncate">
              {summary?.dpi?.threat_level || 'HIGH (SIAM & JA3)'}
            </div>
            <div className="text-xs text-slate-400 mt-1 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Active SNI blocking detected</span>
            </div>
          </div>
        </div>
      </div>

      {/* NEW SECTION: GitHub Actions Pipeline System Status */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <GitBranch className="w-5 h-5 text-purple-300" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                Automated Bridge Testing Pipeline & GitHub Actions System Status
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold uppercase">
                  {systemStatus?.status || 'Active'}
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Automated continuous testing workflow executed via GitHub Actions matrix runners across Iranian probes.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs text-slate-400 self-start sm:self-auto">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Last Executed: {systemStatus?.last_run_timestamp ? new Date(systemStatus.last_run_timestamp).toLocaleString() : 'Recent'}</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-1">
          {/* Workflow Run Details */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Workflow Details</span>
            </div>
            <div className="text-xs text-slate-200 font-mono space-y-1">
              <div><span className="text-slate-500">Run ID:</span> #{systemStatus?.run_number || 1428}</div>
              <div><span className="text-slate-500">Trigger:</span> {systemStatus?.trigger || 'scheduled (3h)'}</div>
              <div><span className="text-slate-500">Pipeline:</span> {systemStatus?.pipeline_name || 'Matrix Probe'}</div>
            </div>
          </div>

          {/* Harvest & Health Stats */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
              <span>24H Bridge Pipeline Yield</span>
            </div>
            <div className="text-xs font-mono space-y-1">
              <div className="text-slate-300">Harvested: <strong className="text-white">+{systemStatus?.bridge_health_summary?.harvested_last_24h || 412}</strong></div>
              <div className="text-slate-300">Iran Reachable: <strong className="text-emerald-400">+{systemStatus?.bridge_health_summary?.valid_iran_reachable || 289}</strong></div>
              <div className="text-slate-300">Stale Pruned: <strong className="text-rose-400">-{systemStatus?.bridge_health_summary?.stale_pruned || 123}</strong></div>
            </div>
          </div>

          {/* Matrix Runners Status (2 cols on md) */}
          <div className="md:col-span-2 p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-amber-400" />
              <span>Iran Probe Matrix Runners Health</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              {systemStatus?.runners ? (
                Object.entries(systemStatus.runners).map(([runner, status]) => (
                  <div key={runner} className="flex items-center justify-between p-1.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-300 truncate max-w-[120px] sm:max-w-none">{runner.replace('_probe', '').replace('_', ' ').toUpperCase()}</span>
                    <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-bold uppercase">
                      <CheckCircle className="w-3 h-3 text-emerald-400" />
                      {status}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 col-span-2">Syncing Matrix Runners...</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* NEW SECTION: Recharts 30-Day Bridge Availability Trend Line Chart */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-cyan-400" />
              30-Day Tor Bridge Availability & Censorship Surge Trend
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Historical timeline of total harvested bridges, Iran reachability, NIN survival, and recorded DPI blocking spikes over the last 30 days.
            </p>
          </div>

          {trendSummary && (
            <div className="flex items-center gap-3 text-xs font-mono bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800">
              <span className="text-slate-400">Avg Reachable: <strong className="text-cyan-300">{trendSummary.avg_availability_pct}</strong></span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">Peak Block Surge: <strong className="text-rose-400">{trendSummary.peak_blocking_day}</strong></span>
            </div>
          )}
        </div>

        <div className="h-72 w-full pt-2">
          {loadingStatus ? (
            <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
              Loading 30-day availability trend telemetry...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData} margin={{ top: 10, right: 30, left: 10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="day" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.75rem', color: '#fff', fontSize: '12px' }}
                  itemStyle={{ fontSize: '11px' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                <Line type="monotone" dataKey="harvested" name="Total Harvested" stroke="#64748b" strokeWidth={1.5} dot={false} />
                <Line type="monotone" dataKey="iran_reachable" name="Iran Reachable" stroke="#10b981" strokeWidth={2.5} activeDot={{ r: 6 }} />
                <Line type="monotone" dataKey="nin_survival" name="NIN Survival" stroke="#38bdf8" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="dpi_spikes" name="DPI Spike Severity" stroke="#f43f5e" strokeWidth={2} strokeDasharray="5 5" />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Main Charts & Rankings Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Transport Performance Chart (2 cols) */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-slate-900/80 border border-slate-800">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Globe2 className="w-5 h-5 text-cyan-400" />
                Transport DPI Resistance Score
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluated against active Deep Packet Inspection firewalls
              </p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 bg-slate-800 rounded-lg text-slate-300">
              OONI + SIAM Window: 7D
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.75rem', color: '#fff' }}
                  itemStyle={{ color: '#38bdf8' }}
                />
                <Bar dataKey="score" radius={[6, 6, 0, 0]}>
                  {chartData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recommended Hierarchy List (1 col) */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-white mb-1">
              Iran Protocol Recommendations
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Priority ordering during internet filtering or blackout
            </p>

            <div className="space-y-3">
              {transports.map((item, index) => {
                const keyName = item.transport || (item as any).name || `trans-${index}`;
                return (
                  <div 
                    key={keyName}
                    className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-center justify-between"
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-lg bg-cyan-500/10 text-cyan-400 font-mono text-xs font-bold flex items-center justify-center border border-cyan-500/20">
                        #{index + 1}
                      </span>
                      <div>
                        <div className="text-sm font-semibold text-white capitalize">
                          {item.transport || (item as any).name || 'Unknown'}
                        </div>
                        <div className="text-xs text-slate-400 line-clamp-1">
                          {item.iran_dpi_resistance || (item as any).dpi_resistance || 'Standard Obfuscation'}
                        </div>
                      </div>
                    </div>

                    <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                      item.survives_nic || (item as any).nin_pass
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                        : 'bg-slate-800 text-slate-400'
                    }`}>
                      {item.survives_nic || (item as any).nin_pass ? 'NIN Pass' : 'Standard'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-800/80">
            <button
              onClick={() => onCopyPack('iran_cut_pack.txt')}
              className="w-full py-2.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 font-semibold text-xs rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              <Copy className="w-4 h-4 text-purple-400" />
              <span>Copy National Internet Cut (شبکه ملی) Pack</span>
            </button>
          </div>
        </div>
      </div>

      {/* Requirement 4: D3 Latency Heatmap for Iranian ISPs */}
      <D3LatencyHeatmap />

      {/* Requirement 5: Service Health Monitor for Backend APIs & Iran Infrastructure Probes */}
      <ServiceHealthMonitor />
    </div>
  );
};
