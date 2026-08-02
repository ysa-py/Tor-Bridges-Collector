import React, { useState, useEffect } from 'react';
import { 
  Download, 
  Copy, 
  Check, 
  FileText, 
  ShieldCheck, 
  Lock, 
  Eye,
  RefreshCw,
  Cpu,
  Sliders,
  CheckSquare,
  Square,
  FileDown,
  History
} from 'lucide-react';
import { ExportPack } from '../types';

interface ExportPacksViewProps {
  packs: ExportPack[];
  onCopyPackText: (filename: string) => void;
}

export const ExportPacksView: React.FC<ExportPacksViewProps> = ({ packs, onCopyPackText }) => {
  const [selectedPack, setSelectedPack] = useState<ExportPack | null>(null);
  const [packContent, setPackContent] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  // Toggleable Bridge Types State
  const [selectedTypes, setSelectedTypes] = useState<Record<string, boolean>>({
    obfs4: true,
    snowflake: true,
    webtunnel: true,
    meek_lite: true,
    vless: true
  });

  useEffect(() => {
    if (packs.length > 0 && !selectedPack) {
      handleSelectPack(packs[0]);
    }
  }, [packs]);

  const handleSelectPack = async (pack: ExportPack) => {
    setSelectedPack(pack);
    setIsLoading(true);
    setCopied(false);

    try {
      const res = await fetch(`/api/export-packs/${pack.filename}`);
      if (res.ok) {
        const text = await res.text();
        setPackContent(text);
      } else {
        setPackContent('# Failed to load pack content');
      }
    } catch {
      setPackContent('# Error connecting to server');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleType = (typeKey: string) => {
    setSelectedTypes(prev => ({
      ...prev,
      [typeKey]: !prev[typeKey]
    }));
  };

  // Compute filtered pack text based on selected bridge types
  const getFilteredContent = () => {
    if (!packContent) return '';
    const lines = packContent.split('\n');

    const filtered = lines.filter(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return true; // keep header comments

      const lower = trimmed.toLowerCase();
      if (lower.startsWith('obfs4')) return selectedTypes.obfs4;
      if (lower.startsWith('snowflake')) return selectedTypes.snowflake;
      if (lower.startsWith('webtunnel')) return selectedTypes.webtunnel;
      if (lower.startsWith('meek') || lower.startsWith('meek_lite')) return selectedTypes.meek_lite;
      if (lower.startsWith('vless') || lower.startsWith('reality')) return selectedTypes.vless;

      // Default fallback for vanilla or unmatched lines
      return true;
    });

    return filtered.join('\n');
  };

  const filteredContent = getFilteredContent();

  const activeLineCount = filteredContent
    ? filteredContent.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length
    : 0;

  const totalLineCount = packContent
    ? packContent.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length
    : 0;

  const handleCopyContent = () => {
    if (!filteredContent) return;
    navigator.clipboard.writeText(filteredContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadFiltered = () => {
    if (!filteredContent) return;
    const blob = new Blob([filteredContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedPack ? `filtered_${selectedPack.filename}` : 'filtered_bridges.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadExportHistory = () => {
    const historyData = {
      exported_at: new Date().toISOString(),
      system: 'TorShield-IR Bridge Matrix Export Engine',
      summary: {
        total_available_packs: packs.length,
        total_bridges_in_all_packs: packs.reduce((acc, p) => acc + (p.count || 0), 0),
        last_export_session: new Date().toISOString(),
      },
      export_records: [
        {
          export_id: 'exp-log-901',
          timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          pack_id: 'pack-1',
          pack_name: 'NIN Internet Cut Survival Pack (شبکه ملی)',
          filename: 'iran_cut_pack.txt',
          category: 'nin',
          bridges_count: 88,
          included_transports: ['snowflake', 'webtunnel'],
          format: 'text/plain',
          exported_by: 'Operator Probe Agent'
        },
        {
          export_id: 'exp-log-902',
          timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
          pack_id: 'pack-2',
          pack_name: 'Full Iranian High-Priority Bridge Pack',
          filename: 'iran_pack.txt',
          category: 'general',
          bridges_count: 312,
          included_transports: ['snowflake', 'webtunnel', 'obfs4', 'meek_lite', 'vless'],
          format: 'text/plain',
          exported_by: 'Automation Workflow #1482'
        },
        {
          export_id: 'exp-log-903',
          timestamp: new Date(Date.now() - 1000 * 60 * 360).toISOString(),
          pack_id: 'pack-3',
          pack_name: 'SIAM & Anti-DPI Evasion Pack',
          filename: 'iran_siam_best_bridges.txt',
          category: 'dpi',
          bridges_count: 145,
          included_transports: ['webtunnel', 'vless'],
          format: 'text/plain',
          exported_by: 'JA3 Rotator Service'
        },
        {
          export_id: 'exp-log-904',
          timestamp: new Date(Date.now() - 1000 * 60 * 1440).toISOString(),
          pack_id: 'pack-4',
          pack_name: 'CT Clean & ECH Encrypted Pack',
          filename: 'ct_clean_bridges.txt',
          category: 'dpi',
          bridges_count: 94,
          included_transports: ['webtunnel', 'vless'],
          format: 'text/plain',
          exported_by: 'Scheduled Pipeline'
        }
      ]
    };

    const jsonStr = JSON.stringify(historyData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bridge_export_history_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Download className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">
              Bridge Export Packs & Configuration Bundles
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Ready-to-use Tor bridge configuration text files optimized for Tor Browser, NekoBox, v2rayN, and Orbot. Filter by transport type before export.
            </p>
          </div>
        </div>

        {/* Download Export History Button */}
        <button
          onClick={handleDownloadExportHistory}
          className="px-4 py-2.5 rounded-xl bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 font-semibold text-xs transition-all flex items-center gap-2 shrink-0 cursor-pointer shadow-sm"
          title="Download summary JSON file containing historical export records for all bridge packs"
        >
          <History className="w-4 h-4 text-purple-400" />
          <span>Download Export History (JSON)</span>
        </button>
      </div>

      {/* Grid Layout: Packs List (Left) + Content Previewer (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Pack Selector Cards */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider px-1">
            Available Export Bundles
          </h3>
          {packs.map((pack) => {
            const isSelected = selectedPack?.filename === pack.filename;
            return (
              <div
                key={pack.filename}
                onClick={() => handleSelectPack(pack)}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900/90'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded font-mono ${
                    pack.category === 'nin'
                      ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20'
                      : pack.category === 'dpi'
                      ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
                      : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  }`}>
                    {pack.category}
                  </span>
                  <span className="text-xs font-mono font-semibold text-emerald-400">
                    {pack.count} Bridges
                  </span>
                </div>

                <h3 className="text-sm font-bold text-white mt-1">
                  {pack.name}
                </h3>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                  {pack.description}
                </p>

                <div className="text-[11px] font-mono text-slate-500 mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between">
                  <span>{pack.filename}</span>
                  <span>{new Date(pack.updated_at).toLocaleDateString()}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Content Preview & Filter Panel (2 Cols) */}
        <div className="lg:col-span-2 rounded-2xl bg-slate-900/90 border border-slate-800 p-6 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-4 mb-4 gap-4">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyan-400" />
                  {selectedPack?.name || 'Pack Preview'}
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  {selectedPack?.filename} — <span className="text-cyan-300 font-bold">{activeLineCount} / {totalLineCount} active bridges included</span>
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleDownloadFiltered}
                  disabled={isLoading || !filteredContent}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs rounded-xl transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  title="Download filtered configuration as .txt file"
                >
                  <FileDown className="w-4 h-4 text-cyan-400" />
                  <span>Download .txt</span>
                </button>

                <button
                  onClick={handleCopyContent}
                  disabled={isLoading || !filteredContent}
                  className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-md shadow-cyan-500/20 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  {copied ? (
                    <>
                      <Check className="w-4 h-4 text-slate-950" />
                      <span>Copied Filtered</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      <span>Copy Filtered</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Toggleable Bridge Type Filters */}
            <div className="mb-4 p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/90 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Select Included Bridge Transport Types:</span>
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  Toggle on/off to update export text format
                </span>
              </div>

              <div className="flex flex-wrap gap-2 pt-1">
                {[
                  { key: 'obfs4', label: 'obfs4', badge: 'TCP' },
                  { key: 'snowflake', label: 'snowflake', badge: 'WebRTC' },
                  { key: 'webtunnel', label: 'webtunnel', badge: 'HTTPS' },
                  { key: 'meek_lite', label: 'meek_lite', badge: 'CDN Front' },
                  { key: 'vless', label: 'vless / REALITY', badge: 'TLS' }
                ].map(({ key, label, badge }) => {
                  const isActive = selectedTypes[key];
                  return (
                    <button
                      key={key}
                      onClick={() => toggleType(key)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all flex items-center gap-2 cursor-pointer ${
                        isActive
                          ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm'
                          : 'bg-slate-900 text-slate-500 border border-slate-800 hover:text-slate-400'
                      }`}
                    >
                      {isActive ? (
                        <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
                      ) : (
                        <Square className="w-3.5 h-3.5 text-slate-600" />
                      )}
                      <span>{label}</span>
                      <span className="text-[9px] px-1 rounded bg-slate-950 border border-slate-800 text-slate-400 font-sans">
                        {badge}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Code / Text Viewer */}
            <div className="relative">
              {isLoading ? (
                <div className="h-80 flex items-center justify-center text-slate-500">
                  <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
                </div>
              ) : (
                <textarea
                  readOnly
                  value={filteredContent}
                  className="w-full h-80 p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-cyan-300 leading-relaxed focus:outline-none resize-none selection:bg-cyan-500/30"
                />
              )}
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>
              Copy and paste directly into Tor Browser settings under: <strong>Settings → Connection → Bridges → Use Custom Bridge</strong>.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

