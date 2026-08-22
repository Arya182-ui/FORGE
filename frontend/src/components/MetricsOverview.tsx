import React from 'react';
import type { ScanSummary } from '../types/scan';
import { FileText, Code2, AlertTriangle, Flame, ShieldAlert, Clock } from 'lucide-react';

interface MetricsOverviewProps {
  summary: ScanSummary | null;
}

export const MetricsOverview: React.FC<MetricsOverviewProps> = ({ summary }) => {
  if (!summary) return null;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
      
      {/* Files Scanned */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-medium">Files Scanned</span>
          <FileText className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-2xl font-bold text-white font-mono">{summary.scanned_files_count}</div>
      </div>

      {/* Lines Scanned */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-medium">Lines Analyzed</span>
          <Code2 className="w-4 h-4 text-blue-400" />
        </div>
        <div className="text-2xl font-bold text-white font-mono">{summary.scanned_lines_count}</div>
      </div>

      {/* Total Issues */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-medium">Total Issues</span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="text-2xl font-bold text-white font-mono">{summary.total_findings_count}</div>
      </div>

      {/* Critical Count */}
      <div className="bg-rose-950/20 border border-rose-900/50 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-rose-400 mb-2">
          <span className="text-xs font-medium">Critical</span>
          <Flame className="w-4 h-4" />
        </div>
        <div className="text-2xl font-bold text-rose-400 font-mono">{summary.critical_count}</div>
      </div>

      {/* High Count */}
      <div className="bg-orange-950/20 border border-orange-900/50 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-orange-400 mb-2">
          <span className="text-xs font-medium">High</span>
          <ShieldAlert className="w-4 h-4" />
        </div>
        <div className="text-2xl font-bold text-orange-400 font-mono">{summary.high_count}</div>
      </div>

      {/* Scan Time */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-medium">Duration</span>
          <Clock className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-2xl font-bold text-emerald-400 font-mono">{summary.duration_ms.toFixed(1)}ms</div>
      </div>

    </div>
  );
};
