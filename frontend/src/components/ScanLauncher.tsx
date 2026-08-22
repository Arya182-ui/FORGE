import React, { useState } from 'react';
import { Play, Folder, Filter, Loader2, Sparkles, FolderGit2 } from 'lucide-react';

interface ScanLauncherProps {
  onRunScan: (targetPath: string, language?: string) => Promise<void>;
  isLoading: boolean;
}

export const ScanLauncher: React.FC<ScanLauncherProps> = ({ onRunScan, isLoading }) => {
  const [targetPath, setTargetPath] = useState('./examples/vulnerable');
  const [language, setLanguage] = useState('all');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetPath.trim()) {
      onRunScan(targetPath.trim(), language);
    }
  };

  const handleQuickPreset = (path: string) => {
    setTargetPath(path);
    onRunScan(path, language);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
      {/* Decorative accent background glow */}
      <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
        
        {/* Title & Description */}
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <FolderGit2 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">Local Project Scanner</h2>
          </div>
          <p className="text-sm text-slate-400">
            Scan your codebase directly from disk using AST parsing rules. No GitHub connection required.
          </p>
        </div>

        {/* Scan Trigger Form */}
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          
          {/* Path Input */}
          <div className="relative flex-1 min-w-[280px]">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Folder className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="e.g. ./my-project or C:\path\to\code"
              className="w-full pl-9 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
            />
          </div>

          {/* Language Selector */}
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Filter className="w-3.5 h-3.5" />
            </div>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="pl-8 pr-8 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-200 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 appearance-none cursor-pointer font-medium"
            >
              <option value="all">All Languages</option>
              <option value="python">Python Only</option>
              <option value="javascript">JavaScript Only</option>
            </select>
          </div>

          {/* Launch Button */}
          <button
            type="submit"
            disabled={isLoading || !targetPath.trim()}
            className="flex items-center justify-center space-x-2 px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold rounded-xl transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shrink-0"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Run Scan</span>
              </>
            )}
          </button>

        </form>
      </div>

      {/* Quick Presets */}
      <div className="mt-4 pt-4 border-t border-slate-800/60 flex items-center space-x-3 text-xs">
        <span className="text-slate-400 flex items-center">
          <Sparkles className="w-3.5 h-3.5 mr-1 text-cyan-400" /> Quick Presets:
        </span>
        <button
          type="button"
          onClick={() => handleQuickPreset('./examples/vulnerable')}
          className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 font-mono transition-colors"
        >
          ./examples/vulnerable
        </button>
        <button
          type="button"
          onClick={() => handleQuickPreset('./examples/secure')}
          className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 font-mono transition-colors"
        >
          ./examples/secure
        </button>
      </div>
    </div>
  );
};
