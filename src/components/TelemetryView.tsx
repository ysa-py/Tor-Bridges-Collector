import React, { useState, useEffect, useRef, useCallback } from 'react';
import * as d3 from 'd3';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Cell, 
  CartesianGrid 
} from 'recharts';
import { 
  Terminal, 
  Search, 
  AlertTriangle, 
  Filter, 
  Download, 
  Bell, 
  BellOff, 
  Activity, 
  Globe, 
  ShieldAlert, 
  BarChart3, 
  MapPin, 
  Flame, 
  Volume2, 
  VolumeX, 
  X,
  Clock,
  ChevronRight,
  Shield,
  Layers,
  Sparkles,
  Zap,
  Sliders,
  FileSpreadsheet
} from 'lucide-react';
import { TelemetryLog, DpiBlockingEvent } from '../types';

interface TelemetryViewProps {
  logs: TelemetryLog[];
}

const DEFAULT_DPI_EVENTS: DpiBlockingEvent[] = [
  {
    id: 'dpi-evt-8901',
    timestamp: new Date(Date.now() - 1000 * 15).toISOString(),
    probe_id: 'probe-tehran-mci-01',
    city: 'Tehran',
    isp: 'MCI (Hamrah-e Aval)',
    asn: 'AS44244',
    event_type: 'TCP_RST_CLIENT_HELLO',
    dpi_engine: 'SIAM Subsystem v4.2',
    target_bridge: '185.177.126.113:443 (obfs4)',
    mitigation: 'Rotated JA3 Fingerprint to Chrome 124 TLS Profile',
    severity: 'HIGH',
    latency_anomaly_ms: 240,
    latitude: 35.6892,
    longitude: 51.3890,
    dpi_risk_score: 94
  },
  {
    id: 'dpi-evt-8902',
    timestamp: new Date(Date.now() - 1000 * 45).toISOString(),
    probe_id: 'probe-isfahan-irancell-03',
    city: 'Isfahan',
    isp: 'Irancell',
    asn: 'AS197207',
    event_type: 'SNI_BLACK_HOLE',
    dpi_engine: 'NSN Traffic Manager',
    target_bridge: '193.224.78.21:443 (obfs4)',
    mitigation: 'Switched domain fronting to WebTunnel (vika7.space)',
    severity: 'CRITICAL',
    latency_anomaly_ms: 380,
    latitude: 32.6546,
    longitude: 51.6680,
    dpi_risk_score: 91
  },
  {
    id: 'dpi-evt-8903',
    timestamp: new Date(Date.now() - 1000 * 90).toISOString(),
    probe_id: 'probe-shiraz-tci-02',
    city: 'Shiraz',
    isp: 'TCI (Mokhaberat)',
    asn: 'AS58224',
    event_type: 'JA3_FINGERPRINT_MATCH',
    dpi_engine: 'Huawei CyberShield DPI',
    target_bridge: '192.0.2.3:80 (snowflake)',
    mitigation: 'Auto-scrambled TLS Extensions & ALPN Shuffle',
    severity: 'RESOLVED',
    latency_anomaly_ms: 110,
    latitude: 29.5926,
    longitude: 52.5836,
    dpi_risk_score: 82
  },
  {
    id: 'dpi-evt-8904',
    timestamp: new Date(Date.now() - 1000 * 180).toISOString(),
    probe_id: 'probe-tabriz-shatel-01',
    city: 'Tabriz',
    isp: 'Shatel',
    asn: 'AS31549',
    event_type: 'UDP_PORT_443_THROTTLE',
    dpi_engine: 'SIAM Subsystem v4.2',
    target_bridge: '192.0.2.16:80 (meek_lite)',
    mitigation: 'Failover to CDN Fronting (a0.awsstatic.com)',
    severity: 'MEDIUM',
    latency_anomaly_ms: 190,
    latitude: 38.0800,
    longitude: 46.2919,
    dpi_risk_score: 65
  },
  {
    id: 'dpi-evt-8905',
    timestamp: new Date(Date.now() - 1000 * 300).toISOString(),
    probe_id: 'probe-mashhad-rightel-04',
    city: 'Mashhad',
    isp: 'Rightel',
    asn: 'AS57218',
    event_type: 'ACTIVE_PROBING_DISCOVERY',
    dpi_engine: 'GAA (Government Access Agent)',
    target_bridge: '192.0.2.50:9001 (vanilla)',
    mitigation: 'Isolated Vanilla Bridge & Quarantined IP',
    severity: 'CRITICAL',
    latency_anomaly_ms: 420,
    latitude: 36.2972,
    longitude: 59.6067,
    dpi_risk_score: 78
  },
  {
    id: 'dpi-evt-8906',
    timestamp: new Date(Date.now() - 1000 * 450).toISOString(),
    probe_id: 'probe-ahvaz-asiatech-02',
    city: 'Ahvaz',
    isp: 'AsiaTech',
    asn: 'AS43754',
    event_type: 'TLS_CERT_ISSUER_BLOCK',
    dpi_engine: 'SIAM Subsystem v4.2',
    target_bridge: '185.177.126.113:443 (obfs4)',
    mitigation: 'REALITY TLS Key Exchange Fallback',
    severity: 'HIGH',
    latency_anomaly_ms: 290,
    latitude: 31.3183,
    longitude: 48.6706,
    dpi_risk_score: 58
  }
];

const INITIAL_ISP_RISK = [
  { isp: 'MCI', fullName: 'MCI (Hamrah-e Aval)', riskScore: 94, asn: 'AS44244', engine: 'SIAM Subsystem v4.2', eventsCount: 14, color: '#f43f5e' },
  { isp: 'Irancell', fullName: 'MTN Irancell', riskScore: 91, asn: 'AS197207', engine: 'NSN Traffic Manager', eventsCount: 11, color: '#f43f5e' },
  { isp: 'TCI', fullName: 'TCI (Mokhaberat)', riskScore: 82, asn: 'AS58224', engine: 'Huawei CyberShield', eventsCount: 8, color: '#f59e0b' },
  { isp: 'Rightel', fullName: 'Rightel Mobile', riskScore: 78, asn: 'AS57218', engine: 'GAA Agent', eventsCount: 6, color: '#f59e0b' },
  { isp: 'Shatel', fullName: 'Shatel Broadband', riskScore: 65, asn: 'AS31549', engine: 'SIAM Subsystem v4.2', eventsCount: 4, color: '#3b82f6' },
  { isp: 'AsiaTech', fullName: 'AsiaTech ADSL', riskScore: 58, asn: 'AS43754', engine: 'Deep Packet Firewall', eventsCount: 3, color: '#3b82f6' },
  { isp: 'ParsOnline', fullName: 'Pars Online', riskScore: 52, asn: 'AS16322', engine: 'Standard DPI Filter', eventsCount: 2, color: '#10b981' },
];

const BLOCKING_PROTOCOLS = [
  'ALL',
  'TCP_RST_CLIENT_HELLO',
  'SNI_BLACK_HOLE',
  'JA3_FINGERPRINT_MATCH',
  'UDP_PORT_443_THROTTLE',
  'ACTIVE_PROBING_DISCOVERY',
  'TLS_CERT_ISSUER_BLOCK',
  'MASS_SNI_BLOCK_SURGE'
];

/* ── D3.js Real-time Geographic Scatter Plot Component ── */
const D3ScatterPlot: React.FC<{ 
  events: DpiBlockingEvent[]; 
  selectedIsp: string;
  onSelectEvent?: (e: DpiBlockingEvent) => void;
}> = ({ events, selectedIsp, onSelectEvent }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredEvent, setHoveredEvent] = useState<DpiBlockingEvent | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 600;
    const height = 300;
    const margin = { top: 25, right: 30, bottom: 45, left: 55 };

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('width', width).attr('height', height);

    // X Scale: Longitude (44°E to 62°E for Iranian network probes)
    const xScale = d3.scaleLinear()
      .domain([44, 62])
      .range([margin.left, width - margin.right]);

    // Y Scale: Latitude (27°N to 39°N for Iranian cities)
    const yScale = d3.scaleLinear()
      .domain([27, 39])
      .range([height - margin.bottom, margin.top]);

    // Background Grid
    const xGrid = d3.axisBottom(xScale).ticks(6).tickSize(-height + margin.top + margin.bottom).tickFormat(() => '');
    const yGrid = d3.axisLeft(yScale).ticks(5).tickSize(-width + margin.left + margin.right).tickFormat(() => '');

    svg.append('g')
      .attr('transform', `translate(0, ${height - margin.bottom})`)
      .call(xGrid)
      .selectAll('line')
      .attr('stroke', '#1e293b')
      .attr('stroke-dasharray', '3,3');

    svg.append('g')
      .attr('transform', `translate(${margin.left}, 0)`)
      .call(yGrid)
      .selectAll('line')
      .attr('stroke', '#1e293b')
      .attr('stroke-dasharray', '3,3');

    // Axes
    const xAxis = d3.axisBottom(xScale).ticks(6).tickFormat(d => `${d}°E`);
    const yAxis = d3.axisLeft(yScale).ticks(5).tickFormat(d => `${d}°N`);

    const gx = svg.append('g')
      .attr('transform', `translate(0, ${height - margin.bottom})`)
      .call(xAxis);

    gx.selectAll('text').attr('fill', '#94a3b8').attr('font-size', '10px');
    gx.selectAll('path, line').attr('stroke', '#334155');

    const gy = svg.append('g')
      .attr('transform', `translate(${margin.left}, 0)`)
      .call(yAxis);

    gy.selectAll('text').attr('fill', '#94a3b8').attr('font-size', '10px');
    gy.selectAll('path, line').attr('stroke', '#334155');

    // Axis Labels
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', height - 8)
      .attr('text-anchor', 'middle')
      .attr('fill', '#64748b')
      .attr('font-size', '10px')
      .text('Probe Longitude (°E) — Geographic Coordinates across Iran');

    svg.append('text')
      .attr('transform', 'rotate(-90)')
      .attr('x', -height / 2)
      .attr('y', 16)
      .attr('text-anchor', 'middle')
      .attr('fill', '#64748b')
      .attr('font-size', '10px')
      .text('Latitude (°N)');

    // Severity Colors
    const getColor = (sev: string) => {
      switch (sev) {
        case 'CRITICAL': return '#f43f5e';
        case 'HIGH': return '#f59e0b';
        case 'MEDIUM': return '#3b82f6';
        default: return '#10b981';
      }
    };

    const dotsGroup = svg.append('g');

    if (events.length === 0) {
      svg.append('text')
        .attr('x', width / 2)
        .attr('y', height / 2)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .attr('font-size', '12px')
        .text(`No DPI probe events match filter '${selectedIsp}'`);
      return;
    }

    events.forEach(evt => {
      const cx = xScale(evt.longitude || 51.38);
      const cy = yScale(evt.latitude || 35.68);
      const color = getColor(evt.severity);

      // Pulsing outer ring for active critical/high events
      if (evt.severity === 'CRITICAL' || evt.severity === 'HIGH') {
        dotsGroup.append('circle')
          .attr('cx', cx)
          .attr('cy', cy)
          .attr('r', 10)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', 1.5)
          .attr('opacity', 0.6)
          .append('animate')
          .attr('attributeName', 'r')
          .attr('values', '8;18;8')
          .attr('dur', '2s')
          .attr('repeatCount', 'indefinite');
      }

      // Core scatter circle node
      const circle = dotsGroup.append('circle')
        .attr('cx', cx)
        .attr('cy', cy)
        .attr('r', 0)
        .attr('fill', color)
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 2)
        .attr('cursor', 'pointer');

      circle.transition()
        .duration(500)
        .attr('r', 7);

      circle
        .on('mouseenter', (event: MouseEvent) => {
          circle.attr('r', 10);
          setHoveredEvent(evt);
          const rect = containerRef.current?.getBoundingClientRect();
          if (rect) {
            setTooltipPos({
              x: event.clientX - rect.left,
              y: event.clientY - rect.top - 10
            });
          }
        })
        .on('mouseleave', () => {
          circle.attr('r', 7);
          setHoveredEvent(null);
        })
        .on('click', () => {
          if (onSelectEvent) onSelectEvent(evt);
        });

      // City & ISP Label
      dotsGroup.append('text')
        .attr('x', cx + 10)
        .attr('y', cy + 3)
        .attr('fill', '#cbd5e1')
        .attr('font-size', '10px')
        .attr('font-weight', '500')
        .attr('pointer-events', 'none')
        .text(`${evt.city || ''} (${(evt.isp || '').split(' ')[0]})`);
    });

  }, [events, selectedIsp, onSelectEvent]);

  return (
    <div ref={containerRef} className="relative w-full overflow-hidden bg-slate-950 p-3 rounded-xl border border-slate-800">
      <svg ref={svgRef} className="w-full h-[300px] cursor-crosshair"></svg>

      {hoveredEvent && (
        <div
          className="absolute z-50 pointer-events-none bg-slate-900/95 backdrop-blur-md border border-cyan-500/40 p-3 rounded-xl shadow-2xl text-xs space-y-1 transform -translate-x-1/2 -translate-y-full min-w-[220px]"
          style={{ left: `${tooltipPos.x}px`, top: `${tooltipPos.y - 10}px` }}
        >
          <div className="flex items-center gap-2 font-bold text-white">
            <MapPin className="w-3.5 h-3.5 text-cyan-400" />
            <span>{hoveredEvent.city} — {hoveredEvent.isp}</span>
          </div>
          <div className="text-slate-300">
            <span className="text-slate-400">Event: </span>
            <span className="font-mono text-cyan-300 font-semibold">{hoveredEvent.event_type}</span>
          </div>
          <div className="text-slate-300">
            <span className="text-slate-400">DPI Engine: </span>
            <span>{hoveredEvent.dpi_engine}</span>
          </div>
          <div className="text-slate-300">
            <span className="text-slate-400">Target Bridge: </span>
            <span className="font-mono text-slate-200">{hoveredEvent.target_bridge}</span>
          </div>
          <div className="text-emerald-400 font-semibold pt-1 border-t border-slate-800 text-[11px]">
            ⚡ Mitigation: {hoveredEvent.mitigation}
          </div>
        </div>
      )}
    </div>
  );
};

/* ── D3.js Node Topology World Map Component ── */
const D3CensorshipWorldMap: React.FC<{
  events: DpiBlockingEvent[];
  selectedIsp: string;
}> = ({ events, selectedIsp }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredNode, setHoveredNode] = useState<{ name: string; type: string; info: string; latency?: number } | null>(null);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;
    const width = containerRef.current.clientWidth || 700;
    const height = 320;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', width).attr('height', height);

    // Egress Relays (Left/Top side)
    const relays = [
      { id: 'rel-fra', name: 'Frankfurt EU Relay', x: width * 0.15, y: height * 0.25, type: 'Egress Bridge', latency: 38 },
      { id: 'rel-ams', name: 'Amsterdam NL Relay', x: width * 0.15, y: height * 0.55, type: 'Egress Bridge', latency: 42 },
      { id: 'rel-lon', name: 'London UK Relay', x: width * 0.15, y: height * 0.82, type: 'Egress Bridge', latency: 45 },
      { id: 'rel-va', name: 'Virginia US Relay', x: width * 0.08, y: height * 0.40, type: 'Egress Bridge', latency: 105 },
    ];

    // Iranian Censorship Probe Nodes (Right side)
    const probes = [
      { id: 'prb-thr', name: 'Tehran MCI / TCI Node', x: width * 0.72, y: height * 0.20, city: 'Tehran', isp: 'MCI / TCI', lat: 35.68, lon: 51.38 },
      { id: 'prb-isf', name: 'Isfahan Irancell Node', x: width * 0.78, y: height * 0.45, city: 'Isfahan', isp: 'Irancell', lat: 32.65, lon: 51.66 },
      { id: 'prb-shz', name: 'Shiraz TCI Node', x: width * 0.82, y: height * 0.75, city: 'Shiraz', isp: 'TCI', lat: 29.59, lon: 52.58 },
      { id: 'prb-tbz', name: 'Tabriz Shatel Node', x: width * 0.62, y: height * 0.35, city: 'Tabriz', isp: 'Shatel', lat: 38.08, lon: 46.29 },
      { id: 'prb-mhd', name: 'Mashhad Rightel Node', x: width * 0.88, y: height * 0.25, city: 'Mashhad', isp: 'Rightel', lat: 36.29, lon: 59.60 },
      { id: 'prb-ahv', name: 'Ahvaz AsiaTech Node', x: width * 0.68, y: height * 0.65, city: 'Ahvaz', isp: 'AsiaTech', lat: 31.31, lon: 48.67 }
    ];

    // Background Grid Dots & Lines
    const mapGroup = svg.append('g');

    for (let x = 0; x < width; x += 40) {
      mapGroup.append('line').attr('x1', x).attr('y1', 0).attr('x2', x).attr('y2', height).attr('stroke', '#1e293b').attr('stroke-width', 0.5);
    }
    for (let y = 0; y < height; y += 40) {
      mapGroup.append('line').attr('x1', 0).attr('y1', y).attr('x2', width).attr('y2', y).attr('stroke', '#1e293b').attr('stroke-width', 0.5);
    }

    // Connectors Group
    const linksGroup = svg.append('g');

    relays.forEach(rel => {
      probes.forEach(prb => {
        const hasBlock = (events || []).some(e => (e.city || '').toLowerCase() === prb.city.toLowerCase() || (e.isp || '').toLowerCase().includes(prb.isp.toLowerCase()));
        
        const path = d3.path();
        path.moveTo(rel.x, rel.y);
        const midX = (rel.x + prb.x) / 2;
        const midY = (rel.y + prb.y) / 2 - 25;
        path.quadraticCurveTo(midX, midY, prb.x, prb.y);

        const strokeColor = hasBlock ? '#f43f5e' : '#06b6d4';
        const strokeDash = hasBlock ? '4,4' : 'none';

        linksGroup.append('path')
          .attr('d', path.toString())
          .attr('fill', 'none')
          .attr('stroke', strokeColor)
          .attr('stroke-width', hasBlock ? 1.5 : 1)
          .attr('stroke-dasharray', strokeDash)
          .attr('opacity', hasBlock ? 0.7 : 0.25);
      });
    });

    // Draw Relay Nodes (Egress Bridges)
    relays.forEach(rel => {
      const g = svg.append('g').attr('cursor', 'pointer');
      
      g.append('circle')
        .attr('cx', rel.x)
        .attr('cy', rel.y)
        .attr('r', 7)
        .attr('fill', '#38bdf8')
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 2);

      g.append('text')
        .attr('x', rel.x - 12)
        .attr('y', rel.y + 16)
        .attr('fill', '#94a3b8')
        .attr('font-size', '10px')
        .attr('font-weight', '600')
        .text(rel.name.split(' ')[0]);

      g.on('mouseenter', () => setHoveredNode({ name: rel.name, type: rel.type, info: `Latency: ${rel.latency}ms to egress CDN`, latency: rel.latency }))
       .on('mouseleave', () => setHoveredNode(null));
    });

    // Draw Iranian Probe Nodes
    probes.forEach(prb => {
      const g = svg.append('g').attr('cursor', 'pointer');
      const prbEvents = (events || []).filter(e => (e.city || '').toLowerCase() === prb.city.toLowerCase() || (e.isp || '').toLowerCase().includes(prb.isp.toLowerCase()));
      const isCritical = prbEvents.some(e => e.severity === 'CRITICAL' || e.severity === 'HIGH');

      if (isCritical) {
        g.append('circle')
          .attr('cx', prb.x)
          .attr('cy', prb.y)
          .attr('r', 12)
          .attr('fill', 'none')
          .attr('stroke', '#f43f5e')
          .attr('stroke-width', 1.5)
          .append('animate')
          .attr('attributeName', 'r')
          .attr('values', '8;20;8')
          .attr('dur', '1.8s')
          .attr('repeatCount', 'indefinite');
      }

      g.append('circle')
        .attr('cx', prb.x)
        .attr('cy', prb.y)
        .attr('r', 8)
        .attr('fill', isCritical ? '#f43f5e' : '#10b981')
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 2);

      g.append('text')
        .attr('x', prb.x + 12)
        .attr('y', prb.y + 4)
        .attr('fill', '#e2e8f0')
        .attr('font-size', '10px')
        .attr('font-weight', '600')
        .text(`${prb.city} (${prb.isp})`);

      g.on('mouseenter', () => setHoveredNode({
        name: `${prb.city} Probe (${prb.isp})`,
        type: 'Iranian Telemetry Probe',
        info: prbEvents.length > 0 ? `Active Interference: ${prbEvents.length} events (${prbEvents[0].event_type})` : 'Connections normal',
        latency: 180 + Math.floor(Math.random() * 60)
      }))
      .on('mouseleave', () => setHoveredNode(null));
    });

  }, [events, selectedIsp]);

  return (
    <div ref={containerRef} className="relative w-full rounded-2xl bg-slate-950 border border-slate-800 p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-bold text-white flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <span>Egress Relay to Iranian Probe Censorship Map</span>
        </span>
        <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-400"></span> EU/US Egress Relay</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-400"></span> Clear Connection</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500"></span> Interference Detected</span>
        </div>
      </div>

      <svg ref={svgRef} className="w-full h-80" />

      {hoveredNode && (
        <div className="absolute bottom-4 left-4 p-2.5 rounded-xl bg-slate-900/90 border border-cyan-500/40 text-xs font-mono text-slate-200 shadow-xl pointer-events-none">
          <div className="font-bold text-cyan-300">{hoveredNode.name}</div>
          <div className="text-[10px] text-slate-400">{hoveredNode.type}</div>
          <div className="text-[11px] text-emerald-400 mt-0.5">{hoveredNode.info}</div>
        </div>
      )}
    </div>
  );
};

/* ── Major Iranian ISP Bridge Connection Comparison Table Component ── */
const ISPComparisonTable: React.FC = () => {
  const ispData = [
    {
      isp: 'MCI (Hamrah-e Aval)',
      asn: 'AS44244',
      type: 'Mobile Operator',
      totalTested: 1240,
      reachable: 1048,
      successRate: '84.5%',
      blockedRate: '15.5%',
      latencyAnomaly: '+240ms',
      dpiEngine: 'SIAM Subsystem v4.2 (TCP RST)',
      status: 'Degraded',
      statusClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30'
    },
    {
      isp: 'MTN Irancell',
      asn: 'AS197207',
      type: 'Mobile Operator',
      totalTested: 1180,
      reachable: 1052,
      successRate: '89.2%',
      blockedRate: '10.8%',
      latencyAnomaly: '+180ms',
      dpiEngine: 'NSN Traffic Manager (SNI Blackhole)',
      status: 'Operational',
      statusClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
    },
    {
      isp: 'TCI (Mokhaberat)',
      asn: 'AS58224',
      type: 'Fixed Line ADSL / FTTH',
      totalTested: 1320,
      reachable: 1035,
      successRate: '78.4%',
      blockedRate: '21.6%',
      latencyAnomaly: '+310ms',
      dpiEngine: 'Huawei CyberShield DPI (JA3 Match)',
      status: 'Heavy Throttling',
      statusClass: 'bg-rose-500/10 text-rose-400 border-rose-500/30'
    },
    {
      isp: 'Shatel Broadband',
      asn: 'AS31549',
      type: 'Fiber / Fixed Line',
      totalTested: 890,
      reachable: 810,
      successRate: '91.0%',
      blockedRate: '9.0%',
      latencyAnomaly: '+95ms',
      dpiEngine: 'SIAM Subsystem (Port 443 Limit)',
      status: 'Operational',
      statusClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
    },
    {
      isp: 'Rightel Mobile',
      asn: 'AS57218',
      type: 'Mobile Operator',
      totalTested: 760,
      reachable: 642,
      successRate: '84.5%',
      blockedRate: '15.5%',
      latencyAnomaly: '+210ms',
      dpiEngine: 'GAA Agent Probe',
      status: 'Degraded',
      statusClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30'
    },
    {
      isp: 'AsiaTech ADSL',
      asn: 'AS43754',
      type: 'Fixed Line ADSL',
      totalTested: 620,
      reachable: 545,
      successRate: '87.9%',
      blockedRate: '12.1%',
      latencyAnomaly: '+150ms',
      dpiEngine: 'Deep Packet Firewall (Cert Check)',
      status: 'Operational',
      statusClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
    }
  ];

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Major Iranian ISP Bridge Connection Success & Censorship Comparison</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Aggregated live probe results comparing reachability across MCI, Irancell, TCI, Shatel, Rightel, and AsiaTech.
          </p>
        </div>
        <span className="text-xs font-mono text-cyan-300 px-3 py-1 bg-cyan-950/60 border border-cyan-800/80 rounded-xl self-start sm:self-auto">
          6 Major ASNs Filtered
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider bg-slate-950/60">
              <th className="py-3 px-3">ISP Operator & ASN</th>
              <th className="py-3 px-3">Network Type</th>
              <th className="py-3 px-3 text-right">Probes Tested</th>
              <th className="py-3 px-3 text-right">Reachable Bridges</th>
              <th className="py-3 px-3 text-right">Success Rate</th>
              <th className="py-3 px-3 text-right">Blocked Rate</th>
              <th className="py-3 px-3 text-right">Avg Latency Anomaly</th>
              <th className="py-3 px-3">Primary DPI Firewall Engine</th>
              <th className="py-3 px-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {ispData.map((row) => (
              <tr key={row.asn} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-3 font-sans font-bold text-white">
                  {row.isp}
                  <span className="block text-[10px] font-mono text-slate-500 font-normal">{row.asn}</span>
                </td>
                <td className="py-3 px-3 text-slate-400">{row.type}</td>
                <td className="py-3 px-3 text-right text-slate-200">{row.totalTested.toLocaleString()}</td>
                <td className="py-3 px-3 text-right text-emerald-400 font-bold">{row.reachable.toLocaleString()}</td>
                <td className="py-3 px-3 text-right text-cyan-300 font-bold">{row.successRate}</td>
                <td className="py-3 px-3 text-right text-rose-400 font-bold">{row.blockedRate}</td>
                <td className="py-3 px-3 text-right text-amber-300">{row.latencyAnomaly}</td>
                <td className="py-3 px-3 text-slate-300">{row.dpiEngine}</td>
                <td className="py-3 px-3 text-right">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${row.statusClass}`}>
                    {row.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

/* ── Historical DPI Incident Sidebar Component ── */
const HistoricalIncidentsSidebar: React.FC<{
  events: DpiBlockingEvent[];
  selectedIsp: string;
  selectedProtocol: string;
  selectedEventId: string | null;
  onSelectIsp: (isp: string) => void;
  onSelectProtocol: (protocol: string) => void;
  onSelectEvent: (event: DpiBlockingEvent) => void;
}> = ({
  events,
  selectedIsp,
  selectedProtocol,
  selectedEventId,
  onSelectIsp,
  onSelectProtocol,
  onSelectEvent
}) => {
  const isps = ['ALL', 'MCI', 'Irancell', 'TCI', 'Rightel', 'Shatel', 'AsiaTech'];

  return (
    <div className="w-full lg:w-80 bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col space-y-4 shrink-0">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-white font-bold text-xs">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Historical DPI Incidents</span>
        </div>
        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold">
          {events.length} Logged
        </span>
      </div>

      {/* Provider Quick Toggles */}
      <div className="space-y-1.5">
        <label className="text-[11px] font-medium text-slate-400 flex items-center gap-1">
          <Sliders className="w-3 h-3 text-cyan-400" />
          <span>Network Provider (ISP):</span>
        </label>
        <div className="flex flex-wrap gap-1">
          {isps.map((isp) => (
            <button
              key={isp}
              onClick={() => onSelectIsp(isp)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all ${
                selectedIsp.toUpperCase() === isp.toUpperCase()
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {isp}
            </button>
          ))}
        </div>
      </div>

      {/* Blocking Protocol Selector */}
      <div className="space-y-1.5">
        <label className="text-[11px] font-medium text-slate-400 flex items-center gap-1">
          <Shield className="w-3 h-3 text-amber-400" />
          <span>Blocking Protocol Filter:</span>
        </label>
        <select
          value={selectedProtocol}
          onChange={(e) => onSelectProtocol(e.target.value)}
          className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/50"
        >
          {BLOCKING_PROTOCOLS.map((proto) => (
            <option key={proto} value={proto}>
              {proto === 'ALL' ? 'All Protocols' : proto}
            </option>
          ))}
        </select>
      </div>

      {/* Incident List by Timestamp */}
      <div className="flex-1 space-y-2 overflow-y-auto max-h-[420px] pr-1">
        {events.length === 0 ? (
          <div className="p-6 text-center text-slate-500 text-xs font-mono">
            No incident timestamps match provider/protocol filter.
          </div>
        ) : (
          events.map((evt) => {
            const isSelected = selectedEventId === evt.id;
            const dateStr = new Date(evt.timestamp);
            const formattedTime = dateStr.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            const formattedDate = dateStr.toLocaleDateString([], { month: 'short', day: 'numeric' });

            return (
              <div
                key={evt.id}
                onClick={() => onSelectEvent(evt)}
                className={`p-3 rounded-xl border text-xs cursor-pointer transition-all space-y-1.5 ${
                  isSelected
                    ? 'bg-cyan-950/60 border-cyan-500/60 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-950/80 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-slate-300 font-semibold text-[11px] flex items-center gap-1">
                    <Clock className="w-3 h-3 text-slate-500" />
                    {formattedDate} {formattedTime}
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                    evt.severity === 'CRITICAL'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      : evt.severity === 'HIGH'
                      ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    {evt.severity}
                  </span>
                </div>

                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-sans font-medium text-white truncate max-w-[150px]">
                    {(evt.isp || '').split(' ')[0]} ({evt.city || ''})
                  </span>
                  <span className="text-cyan-400 font-mono font-bold text-[10px]">
                    Risk: {evt.dpi_risk_score}
                  </span>
                </div>

                <div className="text-[10px] font-mono text-slate-400 truncate flex items-center justify-between">
                  <span className="text-slate-300">{evt.event_type}</span>
                  <ChevronRight className="w-3 h-3 text-slate-600" />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export const TelemetryView: React.FC<TelemetryViewProps> = ({ logs }) => {
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'dpi' | 'raw'>('dpi');

  // Interactive Filter States for DPI Probes
  const [selectedIsp, setSelectedIsp] = useState<string>('ALL');
  const [selectedProtocol, setSelectedProtocol] = useState<string>('ALL');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // DPI Probe Events State
  const [dpiEvents, setDpiEvents] = useState<DpiBlockingEvent[]>(DEFAULT_DPI_EVENTS);
  const [ispRiskScores] = useState(INITIAL_ISP_RISK);

  // Live Update 10s Polling State
  const [liveUpdate, setLiveUpdate] = useState<boolean>(true);
  const [lastSyncTime, setLastSyncTime] = useState<string>(new Date().toLocaleTimeString());
  
  // Real-time Notification & Toast Glow States
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const [notificationsEnabled, setNotificationsEnabled] = useState<boolean>(false);
  const [rapidGlowActive, setRapidGlowActive] = useState<boolean>(false);
  const [rapidGlowMessage, setRapidGlowMessage] = useState<string | null>(null);
  const [spikeAlert, setSpikeAlert] = useState<{ active: boolean; message: string; count: number } | null>({
    active: true,
    message: 'DETECTED: Sudden spike in TCP_RST and SNI Black-Hole events on MCI & Irancell probes in Tehran/Isfahan!',
    count: 3
  });

  // 1. REACT EFFECT HOOK: Monitors telemetryLogs & dpiEvents for rapid frequency increases in 'blocked' events
  useEffect(() => {
    // Check blocked/critical events logged in the last 60 seconds
    const now = Date.now();
    const windowMs = 60000; // 60 seconds

    const recentBlockedEvents = (dpiEvents || []).filter(e => {
      const evtTime = new Date(e.timestamp || '').getTime();
      const evtType = e.event_type || '';
      const isBlockedType = 
        evtType.includes('BLOCK') || 
        evtType.includes('RST') || 
        evtType.includes('BLACK_HOLE') || 
        evtType.includes('THROTTLE') ||
        e.severity === 'CRITICAL' || 
        e.severity === 'HIGH';
      return isBlockedType && (now - evtTime < windowMs);
    });

    // Also count raw logs with level ERROR or blocked message
    const recentBlockedLogs = (logs || []).filter(l => {
      const logTime = new Date(l.timestamp || '').getTime();
      const msg = l.message || '';
      return (l.level === 'ERROR' || msg.toLowerCase().includes('block')) && (now - logTime < windowMs);
    });

    const totalBlockedCount = recentBlockedEvents.length + recentBlockedLogs.length;

    // Threshold: Trigger Toast notification and UI Glow effect if >= 3 blocked events in 60s
    if (totalBlockedCount >= 3) {
      setRapidGlowActive(true);
      setRapidGlowMessage(`RAPID BLOCK SURGE: ${totalBlockedCount} DPI blocking/error events detected in the last 60 seconds!`);

      // Auto fade glow effect after 6 seconds
      const timer = setTimeout(() => {
        setRapidGlowActive(false);
      }, 6000);

      return () => clearTimeout(timer);
    }
  }, [dpiEvents, logs]);

  // Fetch live DPI events from backend API on mount
  useEffect(() => {
    const fetchDpiEvents = async () => {
      try {
        const res = await fetch('/api/dpi-events');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.events) && data.events.length > 0) {
            setDpiEvents(prev => {
              const existingIds = new Set(prev.map(e => e.id));
              const combined = [...prev];
              data.events.forEach((evt: DpiBlockingEvent) => {
                if (!existingIds.has(evt.id)) {
                  combined.unshift(evt);
                }
              });
              return combined;
            });
          }
        }
      } catch (e) {
        console.warn('Could not fetch /api/dpi-events, using local telemetry state', e);
      }
    };

    fetchDpiEvents();
  }, []);

  // 10-Second Auto-Polling Live Update Effect
  useEffect(() => {
    if (!liveUpdate) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/dpi-events');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.events) && data.events.length > 0) {
            setDpiEvents(prev => {
              const existingIds = new Set(prev.map(e => e.id));
              const combined = [...prev];
              data.events.forEach((evt: DpiBlockingEvent) => {
                if (!existingIds.has(evt.id)) {
                  combined.unshift(evt);
                }
              });
              return combined;
            });
          }
        }
        setLastSyncTime(new Date().toLocaleTimeString());
      } catch (e) {
        console.warn('Live update polling failed:', e);
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [liveUpdate]);

  // Web Audio Alert Synthesizer
  const playAlertSound = useCallback(() => {
    if (!soundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);

      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.3);
    } catch {
      // Audio context permission or fallback
    }
  }, [soundEnabled]);

  // Request Web Notification permission
  const handleToggleNotifications = async () => {
    if (!('Notification' in window)) {
      alert('Browser notifications are not supported in this browser environment.');
      return;
    }

    if (Notification.permission === 'granted') {
      setNotificationsEnabled(false);
    } else {
      const permission = await Notification.requestPermission();
      if (permission === 'granted') {
        setNotificationsEnabled(true);
        new Notification('TorShield-IR Telemetry', {
          body: 'Real-time DPI blocking spike alerts enabled for Iranian probes.',
          icon: '/favicon.ico'
        });
      } else {
        alert('Browser notification permission was denied.');
      }
    }
  };

  // Simulate Live DPI Event Spike Trigger
  const handleSimulateSpike = () => {
    const newEvents: DpiBlockingEvent[] = [
      {
        id: `dpi-evt-${Date.now()}-1`,
        timestamp: new Date().toISOString(),
        probe_id: 'probe-tehran-mci-09',
        city: 'Tehran',
        isp: 'MCI (Hamrah-e Aval)',
        asn: 'AS44244',
        event_type: 'MASS_SNI_BLOCK_SURGE',
        dpi_engine: 'SIAM Subsystem v4.2',
        target_bridge: '185.177.126.113:443 (obfs4)',
        mitigation: 'Dynamic IP Hopping & REALITY Key Scrambler',
        severity: 'CRITICAL',
        latency_anomaly_ms: 480,
        latitude: 35.7000,
        longitude: 51.4100,
        dpi_risk_score: 98
      },
      {
        id: `dpi-evt-${Date.now()}-2`,
        timestamp: new Date().toISOString(),
        probe_id: 'probe-shiraz-irancell-04',
        city: 'Shiraz',
        isp: 'Irancell',
        asn: 'AS197207',
        event_type: 'JA3_FINGERPRINT_MATCH',
        dpi_engine: 'NSN Traffic Manager',
        target_bridge: '193.224.78.21:443 (obfs4)',
        mitigation: 'Fallback to WebTunnel Fronting (coellen.xyz)',
        severity: 'HIGH',
        latency_anomaly_ms: 310,
        latitude: 29.6100,
        longitude: 52.5300,
        dpi_risk_score: 93
      }
    ];

    setDpiEvents(prev => [...newEvents, ...prev]);

    setSpikeAlert({
      active: true,
      message: '🚨 LIVE ALERT: High-frequency DPI blocking event spike detected across MCI (AS44244) & Irancell (AS197207) probes!',
      count: newEvents.length
    });

    playAlertSound();

    if (notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
      new Notification('🚨 DPI Blocking Event Spike Detected!', {
        body: 'Multiple probes reported TCP_RST and SNI black-hole surge in Tehran and Shiraz.',
      });
    }
  };

  // 2. EXPORT TO CSV UTILITY FUNCTION: Transforms current telemetryLogs & dpiEvents state into a downloadable CSV
  const handleExportCSV = (exportTarget: 'dpi' | 'telemetry' = activeTab === 'dpi' ? 'dpi' : 'telemetry') => {
    if (exportTarget === 'dpi') {
      const headers = ['Timestamp', 'ISP', 'Risk Score', 'Event Type', 'City', 'ASN', 'DPI Engine', 'Target Bridge', 'Mitigation', 'Severity'];
      
      const rows = (dpiEvents || []).map(e => [
        `"${e.timestamp || ''}"`,
        `"${e.isp || ''}"`,
        e.dpi_risk_score || 85,
        `"${e.event_type || ''}"`,
        `"${e.city || ''}"`,
        `"${e.asn || ''}"`,
        `"${e.dpi_engine || ''}"`,
        `"${e.target_bridge || ''}"`,
        `"${e.mitigation || ''}"`,
        `"${e.severity || ''}"`
      ]);

      const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      downloadCSV(csvContent, `dpi_blocking_telemetry_${new Date().toISOString().slice(0,10)}.csv`);
    } else {
      // Export Telemetry Logs
      const headers = ['Timestamp', 'ISP', 'Risk Score', 'Event Type', 'Level', 'Component', 'Message'];
      
      const rows = (logs || []).map(log => {
        // Enriched ISP and Risk score resolution from log details or defaults
        const isp = log.details?.isp || 'Iranian Network Core';
        const riskScore = log.details?.riskScore || (log.level === 'ERROR' ? 92 : log.level === 'WARN' ? 65 : 20);
        const eventType = log.details?.eventType || (log.level === 'ERROR' ? 'BLOCKED_CONNECTION' : 'LOG_EVENT');
        const msg = (log.message || '').replace(/"/g, '""');

        return [
          `"${log.timestamp || ''}"`,
          `"${isp}"`,
          riskScore,
          `"${eventType}"`,
          `"${log.level || ''}"`,
          `"${log.component || ''}"`,
          `"${msg}"`
        ];
      });

      const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      downloadCSV(csvContent, `system_telemetry_logs_${new Date().toISOString().slice(0,10)}.csv`);
    }
  };

  const downloadCSV = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Filter DPI Events based on Selected ISP and Selected Protocol
  const filteredDpiEvents = (dpiEvents || []).filter(evt => {
    if (selectedIsp && selectedIsp !== 'ALL') {
      const matchIsp = (evt.isp || '').toLowerCase().includes((selectedIsp || '').toLowerCase());
      if (!matchIsp) return false;
    }
    if (selectedProtocol && selectedProtocol !== 'ALL') {
      if (evt.event_type !== selectedProtocol) return false;
    }
    return true;
  });

  // Filtered ISP Risk Scores based on Selected ISP
  const filteredIspRiskScores = (ispRiskScores || []).filter(item => {
    if (!selectedIsp || selectedIsp === 'ALL') return true;
    const selLower = selectedIsp.toLowerCase();
    return (
      (item.isp || '').toLowerCase().includes(selLower) ||
      (item.fullName || '').toLowerCase().includes(selLower)
    );
  });

  // Filtered Raw Telemetry Logs
  const filteredLogs = (logs || []).filter(log => {
    if (levelFilter !== 'all' && log.level !== levelFilter) return false;
    if (searchTerm) {
      const query = searchTerm.toLowerCase();
      const msg = (log.message || '').toLowerCase();
      const comp = (log.component || '').toLowerCase();
      const details = log.details ? JSON.stringify(log.details).toLowerCase() : '';
      return msg.includes(query) || comp.includes(query) || details.includes(query);
    }
    return true;
  });

  return (
    <div className={`space-y-6 transition-all duration-500 ${rapidGlowActive ? 'ring-4 ring-rose-500/80 rounded-3xl p-1 bg-rose-950/20' : ''}`}>
      
      {/* Toast Notification for Rapid Block Rate Surge */}
      {rapidGlowActive && rapidGlowMessage && (
        <div className="fixed top-6 right-6 z-50 p-4 rounded-2xl bg-slate-900 border-2 border-rose-500/80 shadow-2xl shadow-rose-500/30 flex items-center gap-3 animate-bounce max-w-md">
          <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40 shrink-0">
            <Flame className="w-5 h-5 text-rose-400 animate-pulse" />
          </div>
          <div className="space-y-0.5">
            <div className="text-xs font-bold text-rose-300 flex items-center gap-1">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              <span>DPI ANOMALY TRIGGERED</span>
            </div>
            <p className="text-xs text-slate-200 font-medium">
              {rapidGlowMessage}
            </p>
          </div>
          <button 
            onClick={() => setRapidGlowActive(false)}
            className="p-1 rounded-lg text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              Telemetry & Live DPI Probe Intelligence
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                REAL-TIME
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Live audit trail of Iranian probe DPI blocking events, geographic scatter tracking, ISP threat scoring, and pipeline repair logs.
            </p>
          </div>
        </div>

        {/* Action Controls & Export Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Requirement 1: Live Update Toggle Switch */}
          <button
            onClick={() => setLiveUpdate(!liveUpdate)}
            className={`px-3.5 py-2 rounded-xl border font-semibold text-xs transition-all flex items-center gap-2 cursor-pointer shadow-sm ${
              liveUpdate
                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40 shadow-emerald-500/10'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
            title={liveUpdate ? 'Live Update ACTIVE: Auto-fetching new probe logs every 10 seconds' : 'Click to enable 10-second live update auto-polling'}
          >
            <span className="relative flex h-2.5 w-2.5">
              {liveUpdate && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              )}
              <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${liveUpdate ? 'bg-emerald-400' : 'bg-slate-500'}`}></span>
            </span>
            <span>{liveUpdate ? `Live Update (10s): ON • ${lastSyncTime}` : 'Live Update: OFF'}</span>
          </button>

          <button
            onClick={() => handleExportCSV('dpi')}
            className="px-3.5 py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold text-xs transition-colors flex items-center gap-2 shadow-sm"
            title="Export live DPI blocking telemetry logs to a formatted CSV file capturing timestamp, ISP, risk score, and event type"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export DPI (CSV)</span>
          </button>

          <button
            onClick={() => handleExportCSV('telemetry')}
            className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs transition-colors flex items-center gap-2 shadow-sm"
            title="Export system raw telemetry logs to CSV"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-slate-400" />
            <span>Export Logs (CSV)</span>
          </button>

          <button
            onClick={handleSimulateSpike}
            className="px-3 py-2 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold text-xs transition-colors flex items-center gap-1.5"
            title="Simulate live DPI blocking spike to test real-time alert system"
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Simulate Spike</span>
          </button>

          <button
            onClick={() => setSoundEnabled(!soundEnabled)}
            className={`p-2 rounded-xl border text-xs transition-colors ${
              soundEnabled
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                : 'bg-slate-900 text-slate-500 border-slate-800'
            }`}
            title={soundEnabled ? 'Audio alert chime enabled' : 'Audio alert chime muted'}
          >
            {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>

          <button
            onClick={handleToggleNotifications}
            className={`p-2 rounded-xl border text-xs transition-colors ${
              notificationsEnabled
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
            title={notificationsEnabled ? 'Desktop notifications enabled' : 'Enable desktop notifications'}
          >
            {notificationsEnabled ? <Bell className="w-4 h-4 text-emerald-400" /> : <BellOff className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Top Banner Alert for Live DPI Blocking Event Spikes */}
      {spikeAlert && spikeAlert.active && (
        <div className="p-4 rounded-2xl bg-gradient-to-r from-rose-950/80 via-slate-900 to-amber-950/80 border-2 border-rose-500/60 shadow-2xl animate-pulse flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40 shrink-0">
              <ShieldAlert className="w-6 h-6 animate-bounce" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500 text-white uppercase font-mono">
                  DPI SPIKE ALERT
                </span>
                <span className="text-xs font-semibold text-rose-200">
                  Real-time Anomaly Triggered
                </span>
              </div>
              <p className="text-xs text-rose-100 font-medium mt-1">
                {spikeAlert.message}
              </p>
            </div>
          </div>

          <button
            onClick={() => setSpikeAlert(null)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white bg-slate-900/60 hover:bg-slate-800 border border-slate-700 shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* View Switcher Tabs */}
      <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('dpi')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'dpi'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            <span>DPI Probe Analytics & Scatter Plot</span>
          </button>

          <button
            onClick={() => setActiveTab('raw')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'raw'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Raw Telemetry & Self-Heal Logs</span>
          </button>
        </div>

        <span className="text-xs text-slate-400 font-mono hidden sm:inline-block">
          {filteredDpiEvents.length} Probe Events Active
        </span>
      </div>

      {activeTab === 'dpi' ? (
        <div className="flex flex-col lg:flex-row gap-6">
          {/* 4. NEW SIDEBAR COMPONENT: Historical DPI Incident Timestamps, Provider Toggles, Protocol Filter */}
          <HistoricalIncidentsSidebar
            events={filteredDpiEvents}
            selectedIsp={selectedIsp}
            selectedProtocol={selectedProtocol}
            selectedEventId={selectedEventId}
            onSelectIsp={(isp) => setSelectedIsp(isp)}
            onSelectProtocol={(proto) => setSelectedProtocol(proto)}
            onSelectEvent={(evt) => setSelectedEventId(evt.id)}
          />

          {/* Main Visualizations & Stream Area */}
          <div className="flex-1 space-y-6 min-w-0">
            
            {/* 3. FILTER BY ISP CONTROL BAR: Dynamically updates D3 Scatter Plot & Recharts Bar Chart simultaneously */}
            <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3 w-full sm:w-auto">
                <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <Filter className="w-4 h-4" />
                </div>
                <div>
                  <label className="text-xs font-bold text-white block">
                    Filter Analytics by ISP
                  </label>
                  <p className="text-[11px] text-slate-400">
                    Dynamically updates Scatter Plot & Risk Score Bar Chart simultaneously
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 w-full sm:w-auto">
                <select
                  value={selectedIsp}
                  onChange={(e) => setSelectedIsp(e.target.value)}
                  className="px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-semibold text-cyan-300 focus:outline-none focus:border-cyan-500/60 w-full sm:w-auto"
                >
                  <option value="ALL">All Network Providers (ISPs)</option>
                  <option value="MCI">MCI (Hamrah-e Aval - AS44244)</option>
                  <option value="Irancell">MTN Irancell (AS197207)</option>
                  <option value="TCI">TCI Mokhaberat (AS58224)</option>
                  <option value="Rightel">Rightel Mobile (AS57218)</option>
                  <option value="Shatel">Shatel Broadband (AS31549)</option>
                  <option value="AsiaTech">AsiaTech ADSL (AS43754)</option>
                  <option value="ParsOnline">Pars Online (AS16322)</option>
                </select>

                {selectedIsp !== 'ALL' && (
                  <button
                    onClick={() => setSelectedIsp('ALL')}
                    className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors shrink-0"
                    title="Reset ISP filter"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            {/* Top Analytics Row: Bar Chart + D3 Scatter Plot */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              
              {/* 1. Recharts Bar Chart: Compare DPI Risk Score of Iranian ISPs */}
              <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Flame className="w-4 h-4 text-rose-400" />
                    <h3 className="text-sm font-bold text-white">
                      Iranian ISP DPI Threat Risk Scores
                    </h3>
                  </div>
                  <span className="text-[11px] text-slate-400 font-mono">
                    {selectedIsp !== 'ALL' ? `Filtered: ${selectedIsp}` : 'All Providers'}
                  </span>
                </div>

                <div className="h-[280px] w-full pt-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={filteredIspRiskScores} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                      <XAxis type="number" domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 10 }} />
                      <YAxis type="category" dataKey="isp" stroke="#94a3b8" tick={{ fontSize: 11, fontWeight: 600 }} />
                      <Tooltip
                        content={({ active, payload }) => {
                          if (active && payload && payload.length) {
                            const data = payload[0].payload;
                            return (
                              <div className="bg-slate-900 border border-slate-700 p-3 rounded-xl shadow-xl text-xs space-y-1">
                                <div className="font-bold text-white">{data.fullName}</div>
                                <div className="text-cyan-400 font-mono">ASN: {data.asn}</div>
                                <div className="text-slate-300">DPI Engine: {data.engine}</div>
                                <div className="text-rose-400 font-bold">Risk Score: {data.riskScore} / 100</div>
                              </div>
                            );
                          }
                          return null;
                        }}
                      />
                      <Bar dataKey="riskScore" radius={[0, 6, 6, 0]} barSize={16}>
                        {filteredIspRiskScores.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <p className="text-[11px] text-slate-400">
                  <strong className="text-slate-300">Observation:</strong> Mobile operators MCI (AS44244) & Irancell (AS197207) deploy aggressive active probing and TLS fingerprint SNI blocking compared to fixed broadband providers.
                </p>
              </div>

              {/* 2. D3.js Real-time Scatter Plot: Geographic Distribution of Probe Events */}
              <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-sm font-bold text-white">
                      D3.js Iranian Probe Geographic Scatter Plot
                    </h3>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-slate-400">
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-amber-500"></span> High
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Resolved
                    </span>
                  </div>
                </div>

                <D3ScatterPlot 
                  events={filteredDpiEvents} 
                  selectedIsp={selectedIsp}
                  onSelectEvent={(evt) => setSelectedEventId(evt.id)}
                />

                <p className="text-[11px] text-slate-400">
                  Plots latitude vs longitude coordinates of Iranian city network probes. Hover over nodes to inspect specific probe DPI block verdicts and mitigations.
                </p>
              </div>
            </div>

            {/* D3 Topology World Map & Major Iranian ISP Comparative Table */}
            <D3CensorshipWorldMap events={filteredDpiEvents} selectedIsp={selectedIsp} />

            <ISPComparisonTable />

            {/* Live DPI Probe Event Stream Table */}
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-white">
                    Live DPI Probe Event Log Stream
                  </h3>
                </div>
                <span className="text-xs text-slate-400">
                  Auto-synced with Iran Probe Telemetry ({filteredDpiEvents.length} events)
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="py-2.5 px-3">Time</th>
                      <th className="py-2.5 px-3">City / ISP</th>
                      <th className="py-2.5 px-3">Event Type</th>
                      <th className="py-2.5 px-3">DPI Engine</th>
                      <th className="py-2.5 px-3">Target Bridge</th>
                      <th className="py-2.5 px-3">Auto Mitigation</th>
                      <th className="py-2.5 px-3 text-right">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {filteredDpiEvents.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                          No DPI blocking events match selected ISP ('{selectedIsp}') or Protocol ('{selectedProtocol}') filters.
                        </td>
                      </tr>
                    ) : (
                      filteredDpiEvents.map((evt) => (
                        <tr 
                          key={evt.id} 
                          onClick={() => setSelectedEventId(evt.id)}
                          className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${
                            selectedEventId === evt.id ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : ''
                          }`}
                        >
                          <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">
                            {new Date(evt.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-2.5 px-3 font-sans font-semibold text-white whitespace-nowrap">
                            {evt.city} <span className="text-slate-400 font-normal">({(evt.isp || '').split(' ')[0]})</span>
                          </td>
                          <td className="py-2.5 px-3 text-cyan-300 font-bold whitespace-nowrap">
                            {evt.event_type}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                            {evt.dpi_engine}
                          </td>
                          <td className="py-2.5 px-3 text-slate-200 whitespace-nowrap">
                            {evt.target_bridge}
                          </td>
                          <td className="py-2.5 px-3 text-emerald-400 font-sans font-medium whitespace-nowrap">
                            ⚡ {evt.mitigation}
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              evt.severity === 'CRITICAL'
                                ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                                : evt.severity === 'HIGH'
                                ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                                : evt.severity === 'MEDIUM'
                                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            }`}>
                              {evt.severity}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Control Bar for Raw Telemetry Logs */}
          <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
              <input
                type="text"
                placeholder="Search log messages or component names..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-400 w-full sm:w-auto">
              <Filter className="w-3.5 h-3.5" />
              <span>Level:</span>
              <select
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
                className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
              >
                <option value="all">All Levels</option>
                <option value="INFO">INFO</option>
                <option value="WARN">WARN</option>
                <option value="ERROR">ERROR</option>
                <option value="DEBUG">DEBUG</option>
              </select>
            </div>
          </div>

          {/* Log Console Window */}
          <div className="rounded-2xl bg-slate-950 border border-slate-800 overflow-hidden shadow-2xl font-mono text-xs">
            <div className="p-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between text-slate-400">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-rose-500/80"></span>
                <span className="w-3 h-3 rounded-full bg-amber-500/80"></span>
                <span className="w-3 h-3 rounded-full bg-emerald-500/80"></span>
                <span className="ml-2 text-slate-300 font-bold">telemetry.log</span>
              </div>

              <span>{filteredLogs.length} Events Logged</span>
            </div>

            <div className="p-4 space-y-2 max-h-[500px] overflow-y-auto divide-y divide-slate-900">
              {filteredLogs.length === 0 ? (
                <div className="py-12 text-center text-slate-600">
                  No raw telemetry events matching current filter.
                </div>
              ) : (
                filteredLogs.map((log, index) => {
                  return (
                    <div key={index} className="pt-2 text-slate-300 flex flex-col sm:flex-row sm:items-start gap-2">
                      <span className="text-slate-500 text-[11px] whitespace-nowrap">
                        [{new Date(log.timestamp).toLocaleTimeString()}]
                      </span>

                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase whitespace-nowrap ${
                        log.level === 'ERROR'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          : log.level === 'WARN'
                          ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
                          : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                      }`}>
                        {log.level}
                      </span>

                      <span className="text-purple-300 font-semibold whitespace-nowrap">
                        [{log.component}]
                      </span>

                      <span className="flex-1 text-slate-200">
                        {log.message}
                      </span>

                      {log.details && (
                        <span className="text-[11px] text-slate-500 truncate max-w-xs">
                          {JSON.stringify(log.details)}
                        </span>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
