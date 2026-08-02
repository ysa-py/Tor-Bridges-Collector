import React from 'react';
import { 
  ShieldCheck, 
  Radio, 
  Activity, 
  Terminal, 
  Download, 
  Cpu, 
  RefreshCw,
  Globe,
  Wifi,
  Sparkles
} from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRefresh: () => void;
  isScanning: boolean;
  iranReachableCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onRefresh,
  isScanning,
  iranReachableCount = 1280
}) => {
  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'ai-dpi', label: 'موتور ضد DPI (AI Engine)', icon: Sparkles },
    { id: 'bridges', label: 'Bridges Explorer', icon: Radio },
    { id: 'evasion', label: 'Anti-DPI Intelligence', icon: Cpu },
    { id: 'tester', label: 'Bridge Tester', icon: Terminal },
    { id: 'export', label: 'Export Packs', icon: Download },
    { id: 'telemetry', label: 'Telemetry Logs', icon: Globe },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & App Title */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-tr from-cyan-500 to-blue-600 rounded-lg text-slate-950 shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-6 h-6 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold text-white tracking-wide">
                  Tor Bridges Collector
                </h1>
                <span className="px-2 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  LIVE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Anti-DPI & NIN Survival Matrix
              </p>
            </div>
          </div>

          {/* Status Badge & Scan Trigger */}
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-3 px-3 py-1.5 bg-slate-800/60 border border-slate-700/60 rounded-lg text-xs">
              <div className="flex items-center gap-1.5 text-cyan-400">
                <Wifi className="w-3.5 h-3.5" />
                <span className="font-mono">{iranReachableCount} Reachable</span>
              </div>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">JA3 Rotation: <span className="text-emerald-400 font-medium">Active</span></span>
            </div>

            <button
              onClick={onRefresh}
              disabled={isScanning}
              className="flex items-center gap-2 px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Scanning...' : 'Sync Bridges'}</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-1 overflow-x-auto py-2 no-scrollbar border-t border-slate-800/60">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg whitespace-nowrap transition-all cursor-pointer ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
