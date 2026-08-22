import React from 'react';
import { Shield, Cpu, Terminal, CheckCircle2, XCircle } from 'lucide-react';

interface HeaderProps {
  isBackendConnected: boolean;
  activeTab: 'scanner' | 'rules';
  setActiveTab: (tab: 'scanner' | 'rules') => void;
  rulesCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  isBackendConnected,
  activeTab,
  setActiveTab,
  rulesCount,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Title */}
          <div className="flex items-center space-x-3">
          <div className="relative flex items-center justify-center">
            <img src="/logo.png" alt="Forge Security Logo" className="w-9 h-9 object-contain rounded-lg shadow-lg shadow-cyan-500/20 border border-cyan-500/30" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-bold tracking-tight text-white font-mono">FORGE</h1>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono font-semibold">
                SECURITY AI
              </span>
            </div>
            <p className="text-xs text-slate-400">AI-Assisted Security Code Review & Vulnerability Platform</p>
          </div>
        </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex space-x-1">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === 'scanner'
                  ? 'bg-slate-800 text-white shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Project Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === 'rules'
                  ? 'bg-slate-800 text-white shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Shield className="w-4 h-4 text-blue-400" />
              <span>Rules Catalog</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 font-mono">
                {rulesCount}
              </span>
            </button>
          </nav>

          {/* Backend Status Indicator */}
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
              <Cpu className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">Security Engine:</span>
              {isBackendConnected ? (
                <span className="flex items-center text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> Ready
                </span>
              ) : (
                <span className="flex items-center text-rose-400 font-medium">
                  <XCircle className="w-3.5 h-3.5 mr-1" /> Disconnected
                </span>
              )}
            </div>
          </div>

        </div>
      </div>
    </header>
  );
};
