import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { ScanLauncher } from './components/ScanLauncher';
import { MetricsOverview } from './components/MetricsOverview';
import { FindingsTable } from './components/FindingsTable';
import { FindingDetailModal } from './components/FindingDetailModal';
import { RulesCatalog } from './components/RulesCatalog';
import type { ScanReport, Finding, RuleMetadata } from './types/scan';
import { checkBackendHealth, triggerLocalScan, fetchRules } from './services/api';
import { AlertCircle, RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'scanner' | 'rules'>('scanner');
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [rules, setRules] = useState<RuleMetadata[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Initial load check
  useEffect(() => {
    async function init() {
      const connected = await checkBackendHealth();
      setIsBackendConnected(connected);
      if (connected) {
        const rulesList = await fetchRules();
        setRules(rulesList);
        
        // Auto-run initial scan on ./examples/vulnerable for instant demonstration
        try {
          setIsLoading(true);
          const initialReport = await triggerLocalScan('./examples/vulnerable');
          setScanReport(initialReport);
        } catch {
          // Ignore auto-scan error on boot
        } finally {
          setIsLoading(false);
        }
      }
    }
    init();
  }, []);

  const handleRunScan = async (targetPath: string, language?: string) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const report = await triggerLocalScan(targetPath, language);
      setScanReport(report);
      setIsBackendConnected(true);
    } catch (err: any) {
      setErrorMessage(err.message || 'Scan execution failed');
      const connected = await checkBackendHealth();
      setIsBackendConnected(connected);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      
      {/* Header */}
      <Header
        isBackendConnected={isBackendConnected}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        rulesCount={rules.length}
      />

      {/* Main Content Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Backend Disconnected Warning */}
        {!isBackendConnected && (
          <div className="bg-rose-950/40 border border-rose-800 text-rose-200 p-4 rounded-xl flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
              <div className="text-sm">
                <span className="font-semibold">Backend Engine Offline:</span> Ensure the FastAPI backend server is running locally at <code className="bg-rose-950 px-1.5 py-0.5 rounded text-rose-300 font-mono">http://localhost:8000</code>.
              </div>
            </div>
            <button
              onClick={async () => {
                const connected = await checkBackendHealth();
                setIsBackendConnected(connected);
                if (connected) {
                  const rulesList = await fetchRules();
                  setRules(rulesList);
                }
              }}
              className="px-3 py-1 bg-rose-900 hover:bg-rose-800 text-rose-100 text-xs font-semibold rounded-lg transition-colors flex items-center space-x-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Connection</span>
            </button>
          </div>
        )}

        {/* Error Banner */}
        {errorMessage && (
          <div className="bg-amber-950/40 border border-amber-800 text-amber-200 p-4 rounded-xl flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <AlertCircle className="w-5 h-5 text-amber-400 shrink-0" />
              <span className="text-sm font-medium">{errorMessage}</span>
            </div>
            <button onClick={() => setErrorMessage(null)} className="text-xs text-amber-400 hover:underline">
              Dismiss
            </button>
          </div>
        )}

        {/* Tab 1: Project Scanner */}
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            <ScanLauncher onRunScan={handleRunScan} isLoading={isLoading} />
            <MetricsOverview summary={scanReport?.summary || null} />
            <FindingsTable
              findings={scanReport?.findings || []}
              onSelectFinding={(finding) => setSelectedFinding(finding)}
            />
          </div>
        )}

        {/* Tab 2: Rules Catalog */}
        {activeTab === 'rules' && <RulesCatalog rules={rules} />}

      </main>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500 font-mono">
        FORGE — AI-Powered Security Code Review & Analysis Platform (B.Tech Academic Project)
      </footer>

    </div>
  );
};

export default App;
