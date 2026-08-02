import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { BridgesView } from './components/BridgesView';
import { EvasionIntelligenceView } from './components/EvasionIntelligenceView';
import { BridgeTesterView } from './components/BridgeTesterView';
import { ExportPacksView } from './components/ExportPacksView';
import { TelemetryView } from './components/TelemetryView';
import { AiDpiOptimizerView } from './components/AiDpiOptimizerView';
import { 
  DashboardSummary, 
  TransportStat, 
  BridgeItem, 
  EvasionIntelligence, 
  TelemetryLog, 
  ExportPack,
  TransportType 
} from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Data States
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [transports, setTransports] = useState<TransportStat[]>([]);
  const [bridges, setBridges] = useState<BridgeItem[]>([]);
  const [totalBridges, setTotalBridges] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [selectedTransport, setSelectedTransport] = useState<TransportType>('all');
  const [selectedPriority, setSelectedPriority] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [evasionData, setEvasionData] = useState<EvasionIntelligence | null>(null);
  const [telemetryLogs, setTelemetryLogs] = useState<TelemetryLog[]>([]);
  const [exportPacks, setExportPacks] = useState<ExportPack[]>([]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  // Fetch Dashboard & Transports
  const fetchDashboardData = async () => {
    try {
      const [dashRes, transRes] = await Promise.all([
        fetch('/api/dashboard'),
        fetch('/api/transports')
      ]);
      if (dashRes.ok) {
        const dData = await dashRes.json();
        setDashboardSummary(dData);
      }
      if (transRes.ok) {
        const tData = await transRes.json();
        setTransports(tData.transports || []);
      }
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    }
  };

  // Fetch Bridges list with filters
  const fetchBridges = async () => {
    try {
      const params = new URLSearchParams({
        page: currentPage.toString(),
        limit: '50',
        transport: selectedTransport,
        priority: selectedPriority,
        q: searchQuery
      });
      const res = await fetch(`/api/bridges?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setBridges(data.bridges || []);
        setTotalBridges(data.total || 0);
        setTotalPages(data.totalPages || 1);
      }
    } catch (err) {
      console.error('Error fetching bridges:', err);
    }
  };

  // Fetch Evasion Intelligence & Telemetry & Export Packs
  const fetchOtherData = async () => {
    try {
      const [evRes, telRes, packRes] = await Promise.all([
        fetch('/api/evasion'),
        fetch('/api/telemetry'),
        fetch('/api/export-packs')
      ]);
      if (evRes.ok) {
        const eData = await evRes.json();
        setEvasionData(eData);
      }
      if (telRes.ok) {
        const tLogs = await telRes.json();
        setTelemetryLogs(tLogs.logs || []);
      }
      if (packRes.ok) {
        const pData = await packRes.json();
        setExportPacks(pData.packs || []);
      }
    } catch (err) {
      console.error('Error fetching additional data:', err);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    fetchOtherData();
  }, []);

  useEffect(() => {
    fetchBridges();
  }, [currentPage, selectedTransport, selectedPriority, searchQuery]);

  // Handle Quick Scan Refresh
  const handleRefresh = async () => {
    setIsScanning(true);
    try {
      const res = await fetch('/api/quick-scan', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        showToast(data.message || 'Bridge matrix re-scanned');
        await Promise.all([
          fetchDashboardData(),
          fetchBridges(),
          fetchOtherData()
        ]);
      }
    } catch (err) {
      showToast('Scan refresh failed');
    } finally {
      setIsScanning(false);
    }
  };

  const handleCopyPack = async (filename: string) => {
    try {
      const res = await fetch(`/api/export-packs/${filename}`);
      if (res.ok) {
        const text = await res.text();
        await navigator.clipboard.writeText(text);
        showToast(`Copied ${filename} contents to clipboard!`);
      }
    } catch {
      showToast('Failed to copy pack');
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30">
      {/* Top Fixed Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRefresh={handleRefresh}
        isScanning={isScanning}
        iranReachableCount={dashboardSummary?.bridges.iran_reachable}
      />

      {/* Main View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && (
          <DashboardView
            summary={dashboardSummary}
            transports={transports}
            onNavigate={setActiveTab}
            onCopyPack={handleCopyPack}
          />
        )}

        {activeTab === 'ai-dpi' && (
          <AiDpiOptimizerView />
        )}

        {activeTab === 'bridges' && (
          <BridgesView
            bridges={bridges}
            totalBridges={totalBridges}
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={setCurrentPage}
            selectedTransport={selectedTransport}
            onTransportChange={(t) => {
              setSelectedTransport(t);
              setCurrentPage(1);
            }}
            selectedPriority={selectedPriority}
            onPriorityChange={(p) => {
              setSelectedPriority(p);
              setCurrentPage(1);
            }}
            searchQuery={searchQuery}
            onSearchChange={(q) => {
              setSearchQuery(q);
              setCurrentPage(1);
            }}
          />
        )}

        {activeTab === 'evasion' && (
          <EvasionIntelligenceView data={evasionData} />
        )}

        {activeTab === 'tester' && (
          <BridgeTesterView />
        )}

        {activeTab === 'export' && (
          <ExportPacksView
            packs={exportPacks}
            onCopyPackText={handleCopyPack}
          />
        )}

        {activeTab === 'telemetry' && (
          <TelemetryView logs={telemetryLogs} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-xs text-slate-500 text-center font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Tor Bridges Collector & Intelligence Matrix • Anti-DPI & NIN Survival Engine</span>
          <span>Targeting MCI, Irancell, Shatel, TCI, RighTel & AsiaTech Networks</span>
        </div>
      </footer>

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 px-4 py-3 bg-cyan-500 text-slate-950 font-bold text-xs rounded-xl shadow-2xl animate-bounce">
          {toastMessage}
        </div>
      )}
    </div>
  );
}
