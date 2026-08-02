import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Activity, Flame, RefreshCw, Sliders } from 'lucide-react';

interface HeatmapCell {
  isp: string;
  region: string;
  latencyMs: number;
  jitterMs: number;
  packetLossPct: number;
  status: 'OPTIMAL' | 'MODERATE' | 'CONGESTED' | 'THROTTLED';
}

const ISPS = ['MCI (Hamrah Aval)', 'Irancell (MTN)', 'TCI (Mokhaberat)', 'Shatel', 'Rightel', 'AsiaTech'];
const REGIONS = ['Tehran', 'Isfahan', 'Shiraz', 'Tabriz', 'Mashhad', 'Ahvaz'];

// Seed realistic real-time latency matrix data for Iranian ISPs
const INITIAL_HEATMAP_DATA: HeatmapCell[] = [
  { isp: 'MCI (Hamrah Aval)', region: 'Tehran', latencyMs: 320, jitterMs: 45, packetLossPct: 12.4, status: 'THROTTLED' },
  { isp: 'MCI (Hamrah Aval)', region: 'Isfahan', latencyMs: 290, jitterMs: 38, packetLossPct: 8.5, status: 'CONGESTED' },
  { isp: 'MCI (Hamrah Aval)', region: 'Shiraz', latencyMs: 210, jitterMs: 18, packetLossPct: 2.1, status: 'MODERATE' },
  { isp: 'MCI (Hamrah Aval)', region: 'Tabriz', latencyMs: 185, jitterMs: 12, packetLossPct: 1.0, status: 'MODERATE' },
  { isp: 'MCI (Hamrah Aval)', region: 'Mashhad', latencyMs: 340, jitterMs: 52, packetLossPct: 14.2, status: 'THROTTLED' },
  { isp: 'MCI (Hamrah Aval)', region: 'Ahvaz', latencyMs: 270, jitterMs: 30, packetLossPct: 6.8, status: 'CONGESTED' },

  { isp: 'Irancell (MTN)', region: 'Tehran', latencyMs: 310, jitterMs: 42, packetLossPct: 11.0, status: 'THROTTLED' },
  { isp: 'Irancell (MTN)', region: 'Isfahan', latencyMs: 240, jitterMs: 22, packetLossPct: 4.5, status: 'CONGESTED' },
  { isp: 'Irancell (MTN)', region: 'Shiraz', latencyMs: 165, jitterMs: 10, packetLossPct: 0.8, status: 'OPTIMAL' },
  { isp: 'Irancell (MTN)', region: 'Tabriz', latencyMs: 155, jitterMs: 8, packetLossPct: 0.5, status: 'OPTIMAL' },
  { isp: 'Irancell (MTN)', region: 'Mashhad', latencyMs: 295, jitterMs: 36, packetLossPct: 9.1, status: 'CONGESTED' },
  { isp: 'Irancell (MTN)', region: 'Ahvaz', latencyMs: 250, jitterMs: 25, packetLossPct: 5.2, status: 'CONGESTED' },

  { isp: 'TCI (Mokhaberat)', region: 'Tehran', latencyMs: 220, jitterMs: 20, packetLossPct: 3.2, status: 'MODERATE' },
  { isp: 'TCI (Mokhaberat)', region: 'Isfahan', latencyMs: 195, jitterMs: 15, packetLossPct: 1.8, status: 'MODERATE' },
  { isp: 'TCI (Mokhaberat)', region: 'Shiraz', latencyMs: 140, jitterMs: 6, packetLossPct: 0.2, status: 'OPTIMAL' },
  { isp: 'TCI (Mokhaberat)', region: 'Tabriz', latencyMs: 135, jitterMs: 5, packetLossPct: 0.1, status: 'OPTIMAL' },
  { isp: 'TCI (Mokhaberat)', region: 'Mashhad', latencyMs: 230, jitterMs: 21, packetLossPct: 3.8, status: 'MODERATE' },
  { isp: 'TCI (Mokhaberat)', region: 'Ahvaz', latencyMs: 190, jitterMs: 14, packetLossPct: 1.5, status: 'MODERATE' },

  { isp: 'Shatel', region: 'Tehran', latencyMs: 145, jitterMs: 7, packetLossPct: 0.4, status: 'OPTIMAL' },
  { isp: 'Shatel', region: 'Isfahan', latencyMs: 138, jitterMs: 6, packetLossPct: 0.2, status: 'OPTIMAL' },
  { isp: 'Shatel', region: 'Shiraz', latencyMs: 125, jitterMs: 4, packetLossPct: 0.1, status: 'OPTIMAL' },
  { isp: 'Shatel', region: 'Tabriz', latencyMs: 120, jitterMs: 4, packetLossPct: 0.0, status: 'OPTIMAL' },
  { isp: 'Shatel', region: 'Mashhad', latencyMs: 160, jitterMs: 9, packetLossPct: 0.7, status: 'OPTIMAL' },
  { isp: 'Shatel', region: 'Ahvaz', latencyMs: 150, jitterMs: 8, packetLossPct: 0.5, status: 'OPTIMAL' },

  { isp: 'Rightel', region: 'Tehran', latencyMs: 260, jitterMs: 28, packetLossPct: 5.8, status: 'CONGESTED' },
  { isp: 'Rightel', region: 'Isfahan', latencyMs: 210, jitterMs: 19, packetLossPct: 2.4, status: 'MODERATE' },
  { isp: 'Rightel', region: 'Shiraz', latencyMs: 175, jitterMs: 11, packetLossPct: 1.1, status: 'MODERATE' },
  { isp: 'Rightel', region: 'Tabriz', latencyMs: 168, jitterMs: 10, packetLossPct: 0.9, status: 'OPTIMAL' },
  { isp: 'Rightel', region: 'Mashhad', latencyMs: 280, jitterMs: 32, packetLossPct: 7.2, status: 'CONGESTED' },
  { isp: 'Rightel', region: 'Ahvaz', latencyMs: 235, jitterMs: 22, packetLossPct: 4.0, status: 'MODERATE' },

  { isp: 'AsiaTech', region: 'Tehran', latencyMs: 150, jitterMs: 8, packetLossPct: 0.5, status: 'OPTIMAL' },
  { isp: 'AsiaTech', region: 'Isfahan', latencyMs: 142, jitterMs: 7, packetLossPct: 0.3, status: 'OPTIMAL' },
  { isp: 'AsiaTech', region: 'Shiraz', latencyMs: 130, jitterMs: 5, packetLossPct: 0.1, status: 'OPTIMAL' },
  { isp: 'AsiaTech', region: 'Tabriz', latencyMs: 128, jitterMs: 5, packetLossPct: 0.1, status: 'OPTIMAL' },
  { isp: 'AsiaTech', region: 'Mashhad', latencyMs: 165, jitterMs: 10, packetLossPct: 0.8, status: 'OPTIMAL' },
  { isp: 'AsiaTech', region: 'Ahvaz', latencyMs: 155, jitterMs: 8, packetLossPct: 0.6, status: 'OPTIMAL' },
];

export const D3LatencyHeatmap: React.FC = () => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [data, setData] = useState<HeatmapCell[]>(INITIAL_HEATMAP_DATA);
  const [selectedCell, setSelectedCell] = useState<HeatmapCell | null>(null);
  const [hoveredCell, setHoveredCell] = useState<HeatmapCell | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      // Slightly fluctuate latencies to simulate real-time Iranian probe ping jitter
      setData(prev =>
        prev.map(cell => {
          const delta = Math.floor(Math.random() * 21) - 10;
          const newLatency = Math.max(90, Math.min(420, cell.latencyMs + delta));
          let newStatus: HeatmapCell['status'] = 'OPTIMAL';
          if (newLatency >= 300) newStatus = 'THROTTLED';
          else if (newLatency >= 240) newStatus = 'CONGESTED';
          else if (newLatency >= 180) newStatus = 'MODERATE';

          return {
            ...cell,
            latencyMs: newLatency,
            status: newStatus,
            packetLossPct: Number((Math.max(0, (newLatency - 150) * 0.05)).toFixed(1))
          };
        })
      );
      setIsRefreshing(false);
    }, 600);
  };

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 700;
    const height = 320;
    const margin = { top: 40, right: 20, bottom: 60, left: 140 };

    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // X Scale (Regions)
    const xScale = d3
      .scaleBand()
      .range([0, innerWidth])
      .domain(REGIONS)
      .padding(0.08);

    // Y Scale (ISPs)
    const yScale = d3
      .scaleBand()
      .range([0, innerHeight])
      .domain(ISPS)
      .padding(0.08);

    // Color Scale: Green (low ms) -> Cyan -> Yellow -> Red (high ms)
    const colorScale = d3
      .scaleSequential<string>()
      .domain([100, 350])
      .interpolator(d3.interpolateRgbBasis(['#10b981', '#06b6d4', '#f59e0b', '#ef4444']));

    // Render X Axis (Regions)
    g.append('g')
      .attr('transform', `translate(0, -8)`)
      .call(d3.axisTop(xScale).tickSize(0))
      .call(g => g.select('.domain').remove())
      .selectAll('text')
      .attr('fill', '#94a3b8')
      .style('font-size', '11px')
      .style('font-weight', '600')
      .style('font-family', 'monospace');

    // Render Y Axis (ISPs)
    g.append('g')
      .call(d3.axisLeft(yScale).tickSize(0))
      .call(g => g.select('.domain').remove())
      .selectAll('text')
      .attr('fill', '#cbd5e1')
      .style('font-size', '11px')
      .style('font-weight', '600');

    // Render Heatmap Rectangles
    g.selectAll('rect.heatmap-cell')
      .data(data)
      .enter()
      .append('rect')
      .attr('class', 'heatmap-cell')
      .attr('x', d => xScale(d.region) || 0)
      .attr('y', d => yScale(d.isp) || 0)
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('rx', 6)
      .attr('ry', 6)
      .attr('fill', d => colorScale(d.latencyMs))
      .attr('opacity', 0.88)
      .attr('stroke', d => (hoveredCell?.isp === d.isp && hoveredCell?.region === d.region ? '#38bdf8' : '#0f172a'))
      .attr('stroke-width', d => (hoveredCell?.isp === d.isp && hoveredCell?.region === d.region ? 2.5 : 1.5))
      .style('cursor', 'pointer')
      .style('transition', 'all 0.2s ease')
      .on('mouseenter', (event, d) => {
        setHoveredCell(d);
      })
      .on('mouseleave', () => {
        setHoveredCell(null);
      })
      .on('click', (event, d) => {
        setSelectedCell(d);
      });

    // Render Latency Values inside Cells
    g.selectAll('text.cell-label')
      .data(data)
      .enter()
      .append('text')
      .attr('class', 'cell-label')
      .attr('x', d => (xScale(d.region) || 0) + xScale.bandwidth() / 2)
      .attr('y', d => (yScale(d.isp) || 0) + yScale.bandwidth() / 2 + 4)
      .attr('text-anchor', 'middle')
      .attr('fill', '#ffffff')
      .style('font-size', '10px')
      .style('font-weight', '700')
      .style('font-family', 'monospace')
      .style('pointer-events', 'none')
      .text(d => `${d.latencyMs}ms`);

  }, [data, hoveredCell]);

  const congestedCount = data.filter(d => d.status === 'CONGESTED' || d.status === 'THROTTLED').length;

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Iranian ISP Connection Latency Heatmap</span>
            {congestedCount > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-300 border border-rose-500/20 text-xs font-mono font-bold flex items-center gap-1">
                <Flame className="w-3 h-3 text-rose-400" />
                <span>{congestedCount} Hotspots</span>
              </span>
            )}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            D3-rendered real-time latency matrix measuring bridge probe response across major Iranian ISPs and metropolitan hubs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs rounded-xl transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Refresh Probes</span>
          </button>
        </div>
      </div>

      {/* D3 Heatmap SVG Container */}
      <div ref={containerRef} className="w-full overflow-x-auto relative">
        <svg ref={svgRef} className="w-full min-w-[640px]"></svg>
      </div>

      {/* Heatmap Legend & Hover Detail Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pt-2 border-t border-slate-800/80 text-xs text-slate-400">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="font-semibold text-slate-300">Latency Legend:</span>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-emerald-500 inline-block"></span>
            <span>Optimal (&lt;180ms)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-cyan-500 inline-block"></span>
            <span>Moderate (180-240ms)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-amber-500 inline-block"></span>
            <span>Congested (240-300ms)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-rose-500 inline-block"></span>
            <span>Throttled / DPI (&gt;300ms)</span>
          </div>
        </div>

        {hoveredCell ? (
          <div className="p-2 px-3 rounded-lg bg-slate-950 border border-cyan-500/40 text-cyan-300 font-mono text-xs flex items-center gap-3 animate-fade-in">
            <span><strong>{hoveredCell.isp}</strong> [{hoveredCell.region}]</span>
            <span>•</span>
            <span>Latency: <strong>{hoveredCell.latencyMs}ms</strong></span>
            <span>•</span>
            <span>Loss: <strong>{hoveredCell.packetLossPct}%</strong></span>
            <span>•</span>
            <span className={`font-bold ${hoveredCell.status === 'OPTIMAL' ? 'text-emerald-400' : hoveredCell.status === 'THROTTLED' ? 'text-rose-400' : 'text-amber-400'}`}>
              {hoveredCell.status}
            </span>
          </div>
        ) : (
          <span className="text-slate-500 italic">Hover over any ISP cell to inspect detailed loss & jitter metrics</span>
        )}
      </div>
    </div>
  );
};
