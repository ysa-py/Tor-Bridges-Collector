import React, { useState, useEffect } from 'react';
import { 
  Server, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Activity, 
  Wifi, 
  Globe2, 
  Cpu, 
  Zap,
  Radio,
  Check
} from 'lucide-react';

interface EndpointHealth {
  id: string;
  name: string;
  endpoint: string;
  status: 'UP' | 'DEGRADED' | 'DOWN';
  latencyMs: number;
  httpStatus: number;
  lastChecked: string;
}

interface ProbeNodeHealth {
  id: string;
  location: string;
  isp: string;
  ipAddress: string;
  status: 'ONLINE' | 'ACTIVE_PROBING' | 'OFFLINE';
  pingMs: number;
  dpiBlockRate: number;
}

const INITIAL_ENDPOINTS: EndpointHealth[] = [
  { id: '1', name: 'Dashboard Core API', endpoint: '/api/dashboard', status: 'UP', latencyMs: 14, httpStatus: 200, lastChecked: 'Just now' },
  { id: '2', name: 'Bridge Inventory Engine', endpoint: '/api/bridges', status: 'UP', latencyMs: 18, httpStatus: 200, lastChecked: 'Just now' },
  { id: '3', name: 'DPI Telemetry Streamer', endpoint: '/api/telemetry', status: 'UP', latencyMs: 22, httpStatus: 200, lastChecked: 'Just now' },
  { id: '4', name: 'CI/CD Pipeline Monitor', endpoint: '/api/system-status', status: 'UP', latencyMs: 12, httpStatus: 200, lastChecked: 'Just now' },
  { id: '5', name: 'Bridge Pack Exporter', endpoint: '/api/export-packs', status: 'UP', latencyMs: 16, httpStatus: 200, lastChecked: 'Just now' },
  { id: '6', name: 'DPI Event Threat Stream', endpoint: '/api/dpi-events', status: 'UP', latencyMs: 15, httpStatus: 200, lastChecked: 'Just now' },
];

const INITIAL_PROBES: ProbeNodeHealth[] = [
  { id: 'p1', location: 'Tehran Hub', isp: 'MCI (Hamrah Aval)', ipAddress: '185.143.232.12', status: 'ONLINE', pingMs: 28, dpiBlockRate: 4.2 },
  { id: 'p2', location: 'Isfahan Center', isp: 'Irancell (MTN)', ipAddress: '5.160.128.44', status: 'ONLINE', pingMs: 34, dpiBlockRate: 3.8 },
  { id: 'p3', location: 'Shiraz South', isp: 'TCI (Mokhaberat)', ipAddress: '2.180.16.89', status: 'ONLINE', pingMs: 42, dpiBlockRate: 1.1 },
  { id: 'p4', location: 'Tabriz North-West', isp: 'Shatel DSL', ipAddress: '85.185.0.22', status: 'ONLINE', pingMs: 31, dpiBlockRate: 0.5 },
];

export const ServiceHealthMonitor: React.FC = () => {
  const [endpoints, setEndpoints] = useState<EndpointHealth[]>(INITIAL_ENDPOINTS);
  const [probes, setProbes] = useState<ProbeNodeHealth[]>(INITIAL_PROBES);
  const [isPinging, setIsPinging] = useState<boolean>(false);
  const [lastPingTime, setLastPingTime] = useState<string>(new Date().toLocaleTimeString());

  const handlePingAll = async () => {
    setIsPinging(true);

    const updatedEndpoints = await Promise.all(
      endpoints.map(async (ep) => {
        const start = performance.now();
        try {
          const res = await fetch(ep.endpoint);
          const duration = Math.round(performance.now() - start);
          return {
            ...ep,
            status: res.ok ? 'UP' as const : 'DEGRADED' as const,
            latencyMs: duration,
            httpStatus: res.status,
            lastChecked: new Date().toLocaleTimeString()
          };
        } catch {
          return {
            ...ep,
            status: 'DOWN' as const,
            latencyMs: 999,
            httpStatus: 500,
            lastChecked: new Date().toLocaleTimeString()
          };
        }
      })
    );

    // Simulate probing response to Iran infrastructure nodes
    const updatedProbes = probes.map(probe => {
      const pingDelta = Math.floor(Math.random() * 9) - 4;
      return {
        ...probe,
        pingMs: Math.max(15, probe.pingMs + pingDelta)
      };
    });

    setEndpoints(updatedEndpoints);
    setProbes(updatedProbes);
    setLastPingTime(new Date().toLocaleTimeString());
    setIsPinging(false);
  };

  const totalUp = endpoints.filter(e => e.status === 'UP').length;
  const overallPercentage = Math.round((totalUp / endpoints.length) * 100);

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">
              Service Health Monitor & Infrastructure Probes
            </h3>
            <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-xs font-mono font-bold">
              {overallPercentage}% OPERATIONAL
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time status of backend API routes and active probe connection latency to Iranian network infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500 font-mono hidden md:inline">
            Last Ping: {lastPingTime}
          </span>

          <button
            onClick={handlePingAll}
            disabled={isPinging}
            className="px-3.5 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-md shadow-cyan-500/20 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isPinging ? 'animate-spin' : ''}`} />
            <span>{isPinging ? 'Pinging...' : 'Re-Ping All Services'}</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* API Endpoints Health Table */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center justify-between">
            <span>Core Backend API Endpoints</span>
            <span className="text-emerald-400">{totalUp} / {endpoints.length} Healthy</span>
          </h4>

          <div className="space-y-2">
            {endpoints.map(ep => (
              <div 
                key={ep.id}
                className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/90 flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-2.5">
                  <span className={`w-2 h-2 rounded-full ${
                    ep.status === 'UP' ? 'bg-emerald-400 shadow-sm shadow-emerald-400' : 'bg-rose-500'
                  }`} />
                  <div>
                    <div className="text-xs font-bold text-white flex items-center gap-2">
                      <span>{ep.name}</span>
                      <span className="text-[10px] font-mono text-slate-500">{ep.endpoint}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                      HTTP {ep.httpStatus} • Latency: <span className="text-cyan-300 font-bold">{ep.latencyMs}ms</span>
                    </div>
                  </div>
                </div>

                <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded uppercase ${
                  ep.status === 'UP' 
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                }`}>
                  {ep.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Iran Infrastructure Probes */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center justify-between">
            <span>Iran Infrastructure Probes</span>
            <span className="text-cyan-400">4 Active Nodes</span>
          </h4>

          <div className="space-y-2">
            {probes.map(probe => (
              <div 
                key={probe.id}
                className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90 flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    <Radio className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white flex items-center gap-2">
                      <span>{probe.location}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                        {probe.isp}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                      IP: {probe.ipAddress} • Ping: <span className="text-emerald-400 font-bold">{probe.pingMs}ms</span>
                    </div>
                  </div>
                </div>

                <div className="text-right font-mono">
                  <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 uppercase">
                    ONLINE
                  </span>
                  <div className="text-[10px] text-slate-500 mt-1">
                    DPI Block: {probe.dpiBlockRate}%
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
