import React, { useState, useMemo } from 'react';
import type { Finding, SeverityLevel } from '../types/scan';
import { Search, ChevronRight, FileCode, ShieldAlert, AlertCircle, Info, Flame } from 'lucide-react';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings, onSelectFinding }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      // Severity filter
      if (selectedSeverity !== 'ALL' && finding.severity !== selectedSeverity) {
        return false;
      }

      // Search query filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesTitle = finding.title.toLowerCase().includes(query);
        const matchesRule = finding.rule_id.toLowerCase().includes(query);
        const matchesFile = finding.file_path.toLowerCase().includes(query);
        const matchesOwasp = finding.owasp_category.toLowerCase().includes(query);
        return matchesTitle || matchesRule || matchesFile || matchesOwasp;
      }

      return true;
    });
  }, [findings, searchQuery, selectedSeverity]);

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/60 font-mono">
            <Flame className="w-3 h-3 mr-1" /> CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold bg-orange-950/80 text-orange-400 border border-orange-800/60 font-mono">
            <ShieldAlert className="w-3 h-3 mr-1" /> HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold bg-amber-950/80 text-amber-400 border border-amber-800/60 font-mono">
            <AlertCircle className="w-3 h-3 mr-1" /> MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold bg-blue-950/80 text-blue-400 border border-blue-800/60 font-mono">
            <Info className="w-3 h-3 mr-1" /> LOW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold bg-slate-800 text-slate-300 font-mono">
            INFO
          </span>
        );
    }
  };

  const getFilenameFromPath = (fullPath: string) => {
    const parts = fullPath.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1];
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
      
      {/* Table Header Controls */}
      <div className="p-4 sm:p-6 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        
        {/* Search Bar */}
        <div className="relative flex-1 max-w-md">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter findings by rule, file, or OWASP category..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-all"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                selectedSeverity === sev
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950/60 text-xs text-slate-400 font-mono border-b border-slate-800">
            <tr>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Finding Title & Rule</th>
              <th className="px-6 py-3">File Location</th>
              <th className="px-6 py-3">OWASP Category</th>
              <th className="px-6 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                  No security findings matched the current criteria.
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => (
                <tr
                  key={finding.fingerprint || `${finding.rule_id}-${finding.file_path}-${finding.line_number}`}
                  onClick={() => onSelectFinding(finding)}
                  className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                >
                  {/* Severity */}
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getSeverityBadge(finding.severity)}
                  </td>

                  {/* Title & Rule ID */}
                  <td className="px-6 py-4">
                    <div className="font-semibold text-white group-hover:text-cyan-400 transition-colors">
                      {finding.title}
                    </div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">
                      {finding.rule_id} • {finding.language.toUpperCase()}
                    </div>
                  </td>

                  {/* File Location */}
                  <td className="px-6 py-4 font-mono text-xs">
                    <div className="flex items-center text-slate-200">
                      <FileCode className="w-3.5 h-3.5 mr-1.5 text-cyan-400 shrink-0" />
                      <span>{getFilenameFromPath(finding.file_path)}</span>
                    </div>
                    <div className="text-slate-400 mt-0.5">
                      Line {finding.line_number}
                    </div>
                  </td>

                  {/* OWASP Category */}
                  <td className="px-6 py-4 text-xs">
                    <span className="inline-block px-2.5 py-1 rounded bg-slate-950 text-slate-300 border border-slate-800 font-mono">
                      {finding.owasp_category}
                    </span>
                  </td>

                  {/* Action Button */}
                  <td className="px-6 py-4 text-right whitespace-nowrap">
                    <button className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium group-hover:translate-x-1 transition-all">
                      <span>View Details</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
};
