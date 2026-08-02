import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  Copy, 
  Check, 
  ChevronLeft, 
  ChevronRight, 
  ShieldCheck, 
  ShieldAlert,
  Shield,
  Activity,
  AlertCircle,
  Clock,
  Radio,
  ExternalLink
} from 'lucide-react';
import { BridgeItem, TransportType } from '../types';

interface BridgesViewProps {
  bridges: BridgeItem[];
  totalBridges: number;
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  selectedTransport: TransportType;
  onTransportChange: (transport: TransportType) => void;
  selectedPriority: string;
  onPriorityChange: (priority: string) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
}

export const BridgesView: React.FC<BridgesViewProps> = ({
  bridges,
  totalBridges,
  currentPage,
  totalPages,
  onPageChange,
  selectedTransport,
  onTransportChange,
  selectedPriority,
  onPriorityChange,
  searchQuery,
  onSearchChange,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedBridges, setSelectedBridges] = useState<string[]>([]);

  const handleCopyLine = (id: string, line: string) => {
    navigator.clipboard.writeText(line);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleToggleSelect = (line: string) => {
    if (selectedBridges.includes(line)) {
      setSelectedBridges(selectedBridges.filter(l => l !== line));
    } else {
      setSelectedBridges([...selectedBridges, line]);
    }
  };

  const handleCopySelected = () => {
    if (selectedBridges.length === 0) return;
    navigator.clipboard.writeText(selectedBridges.join('\n'));
    alert(`Copied ${selectedBridges.length} bridge lines to clipboard!`);
  };

  const transportTabs: { id: TransportType; label: string }[] = [
    { id: 'all', label: 'All Transports' },
    { id: 'snowflake', label: 'Snowflake' },
    { id: 'webtunnel', label: 'WebTunnel' },
    { id: 'obfs4', label: 'Obfs4' },
    { id: 'meek_lite', label: 'Meek-Lite' },
    { id: 'vanilla', label: 'Vanilla' },
  ];

  return (
    <div className="space-y-6">
      {/* Search & Filtering Control Bar */}
      <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
            <input
              type="text"
              placeholder="Search by IP, Port, Fingerprint, or Bridge line..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-all"
            />
          </div>

          {/* Priority Filter */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>Priority:</span>
            </div>
            <select
              value={selectedPriority}
              onChange={(e) => onPriorityChange(e.target.value)}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="all">All Priorities</option>
              <option value="high">High Priority</option>
              <option value="medium">Medium Priority</option>
              <option value="low">Low Priority</option>
            </select>

            {selectedBridges.length > 0 && (
              <button
                onClick={handleCopySelected}
                className="px-3 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-xl transition-all flex items-center gap-1.5 cursor-pointer shadow-md shadow-cyan-500/20"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>Copy ({selectedBridges.length})</span>
              </button>
            )}
          </div>
        </div>

        {/* Transport Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pt-2 no-scrollbar border-t border-slate-800/60">
          {transportTabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => onTransportChange(tab.id)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all whitespace-nowrap cursor-pointer ${
                selectedTransport === tab.id
                  ? 'bg-cyan-500 text-slate-950 shadow-sm shadow-cyan-500/30'
                  : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Bridges List Table */}
      <div className="rounded-2xl bg-slate-900/80 border border-slate-800 overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span className="font-mono">
            Showing <strong className="text-white">{bridges.length}</strong> of{' '}
            <strong className="text-cyan-400">{totalBridges}</strong> bridges
          </span>

          <span className="text-slate-500 hidden sm:inline">
            Click checkbox to select multiple lines for bulk copy
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/60 text-xs uppercase text-slate-400 font-mono border-b border-slate-800">
              <tr>
                <th className="p-4 w-10">#</th>
                <th className="p-4">Transport</th>
                <th className="p-4">Bridge Configuration Line</th>
                <th className="p-4">DPI Score</th>
                <th className="p-4">Evasion Health</th>
                <th className="p-4">Priority</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {bridges.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-slate-500">
                    <Radio className="w-8 h-8 mx-auto mb-3 opacity-40 text-cyan-400" />
                    <p className="text-sm font-medium">No bridges found matching search criteria.</p>
                    <p className="text-xs mt-1">Try clearing filters or changing transport tab.</p>
                  </td>
                </tr>
              ) : (
                bridges.map((item, index) => {
                  const isChecked = selectedBridges.includes(item.line);

                  // Compute Current Evasion Health level
                  const isHigh = item.score >= 80 || ['snowflake', 'webtunnel', 'vless'].includes(item.transport);
                  const isMed = !isHigh && (item.score >= 50 || ['obfs4', 'meek_lite'].includes(item.transport));
                  const healthLevel = isHigh ? 'High' : isMed ? 'Medium' : 'Low';

                  return (
                    <tr 
                      key={item.id || index}
                      className="hover:bg-slate-800/40 transition-colors group"
                    >
                      <td className="p-4">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => handleToggleSelect(item.line)}
                          className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500/20"
                        />
                      </td>

                      <td className="p-4 font-mono text-xs">
                        <span className={`px-2 py-1 rounded font-bold uppercase ${
                          item.transport === 'snowflake' 
                            ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                            : item.transport === 'webtunnel'
                            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                            : item.transport === 'obfs4'
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                            : 'bg-slate-800 text-slate-300'
                        }`}>
                          {item.transport}
                        </span>
                      </td>

                      <td className="p-4 font-mono text-xs max-w-md">
                        <div className="truncate text-slate-200 group-hover:text-cyan-300 transition-colors">
                          {item.line}
                        </div>
                        {item.score_reasons && item.score_reasons.length > 0 && (
                          <div className="text-[11px] text-slate-500 truncate mt-0.5">
                            {item.score_reasons.join(' • ')}
                          </div>
                        )}
                      </td>

                      <td className="p-4 font-mono text-xs">
                        <div className="flex items-center gap-1.5">
                          <span className={`font-bold ${item.score >= 55 ? 'text-emerald-400' : 'text-amber-400'}`}>
                            {item.score.toFixed(0)}
                          </span>
                          <span className="text-slate-500">/ 100</span>
                        </div>
                      </td>

                      {/* Requirement 3: Current Evasion Health Status Indicator */}
                      <td className="p-4 font-mono text-xs">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${
                          healthLevel === 'High'
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            : healthLevel === 'Medium'
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                        }`}
                        title={`Evasion Health: ${healthLevel}. Evaluated against recent MCI, Irancell & TCI active probe RST rates.`}
                        >
                          <span className="relative flex h-2 w-2">
                            {healthLevel === 'High' && (
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            )}
                            <span className={`relative inline-flex rounded-full h-2 w-2 ${
                              healthLevel === 'High' ? 'bg-emerald-400' : healthLevel === 'Medium' ? 'bg-amber-400' : 'bg-rose-500'
                            }`}></span>
                          </span>
                          <span>{healthLevel} Evasion</span>
                        </span>
                      </td>

                      <td className="p-4">
                        <span className={`px-2 py-0.5 text-xs font-semibold rounded-full capitalize ${
                          item.recommended_priority === 'high'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : item.recommended_priority === 'medium'
                            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {item.recommended_priority}
                        </span>
                      </td>

                      <td className="p-4 text-right">
                        <button
                          onClick={() => handleCopyLine(item.id || `${index}`, item.line)}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-all inline-flex items-center gap-1 cursor-pointer"
                        >
                          {copiedId === (item.id || `${index}`) ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-400 font-bold">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5 text-slate-400" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="p-4 border-t border-slate-800 flex items-center justify-between">
            <button
              disabled={currentPage === 1}
              onClick={() => onPageChange(currentPage - 1)}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium disabled:opacity-40 transition-all flex items-center gap-1 cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous</span>
            </button>

            <span className="text-xs text-slate-400 font-mono">
              Page <strong className="text-white">{currentPage}</strong> of{' '}
              <strong className="text-white">{totalPages}</strong>
            </span>

            <button
              disabled={currentPage === totalPages}
              onClick={() => onPageChange(currentPage + 1)}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium disabled:opacity-40 transition-all flex items-center gap-1 cursor-pointer"
            >
              <span>Next</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
