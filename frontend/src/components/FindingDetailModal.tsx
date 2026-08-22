import React from 'react';
import type { Finding } from '../types/scan';
import { X, ShieldAlert, FileCode, ExternalLink, Lightbulb, Sparkles, Info, Layers } from 'lucide-react';
import { fetchSimilarPatterns } from '../services/api';
import type { RelatedPattern } from '../services/api';



interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  targetPath?: string;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({ finding, onClose, targetPath = './examples/vulnerable' }) => {
  const [relatedPatterns, setRelatedPatterns] = React.useState<RelatedPattern[]>([]);

  React.useEffect(() => {
    if (finding && finding.code_snippet) {
      fetchSimilarPatterns(targetPath, finding.code_snippet, finding.file_path).then(setRelatedPatterns);
    } else {
      setRelatedPatterns([]);
    }
  }, [finding, targetPath]);

  if (!finding) return null;


  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-900 border border-slate-800 w-full max-w-3xl max-h-[90vh] rounded-2xl shadow-2xl flex flex-col overflow-hidden relative">
        
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-950/40">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <span className="px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-rose-950 text-rose-400 border border-rose-800">
                {finding.severity}
              </span>
              <span className="px-2.5 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300">
                {finding.rule_id}
              </span>
              <span className="px-2.5 py-0.5 rounded text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                {finding.owasp_category}
              </span>
            </div>
            <h3 className="text-xl font-bold text-white">{finding.title}</h3>
          </div>

          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          
          {/* File Location */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex items-center space-x-3 text-sm font-mono">
            <FileCode className="w-5 h-5 text-cyan-400 shrink-0" />
            <div className="overflow-x-auto">
              <span className="text-slate-400">File: </span>
              <span className="text-white font-semibold">{finding.file_path}</span>
              <span className="text-slate-400 ml-2">Line: {finding.line_number}</span>
            </div>
          </div>

          {/* Evidence Code Snippet */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center">
              <ShieldAlert className="w-4 h-4 mr-1.5 text-rose-400" /> Evidence Code Snippet
            </h4>
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-sm overflow-x-auto">
              <div className="text-xs text-slate-500 border-b border-slate-800/80 pb-2 mb-2">
                Line {finding.line_number}
              </div>
              <pre className="text-rose-300 whitespace-pre-wrap">{finding.code_snippet || 'Snippet unavailable'}</pre>
            </div>
          </div>

          {/* AI Explanation Header / Offline Notice */}
          {finding.ai_explanation && (
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-semibold text-white">
                    {finding.ai_explanation.provider_name} ({finding.ai_explanation.model_name})
                  </span>
                </div>
                {finding.ai_explanation.is_ai_generated ? (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">
                    LLM Enriched
                  </span>
                ) : (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                    AI Unavailable • Rule Analysis
                  </span>
                )}
              </div>

              <div className="text-sm text-slate-200">
                {finding.ai_explanation.summary}
              </div>
            </div>
          )}

          {!finding.ai_explanation?.is_ai_generated && (
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3 text-xs text-slate-400 flex items-center space-x-2">
              <Info className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>AI explanation unavailable. Showing rule-based security analysis.</span>
            </div>
          )}

          {/* Issue Analysis / Root Cause */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center">
              <Lightbulb className="w-4 h-4 mr-1.5 text-amber-400" /> Root Cause & Risk Analysis
            </h4>
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 text-sm text-slate-200 space-y-2">
              <p><strong className="text-white">Root Cause:</strong> {finding.ai_explanation?.root_cause || finding.message}</p>
              {finding.ai_explanation?.why_dangerous && (
                <p><strong className="text-white">Why Dangerous:</strong> {finding.ai_explanation.why_dangerous}</p>
              )}
              {finding.ai_explanation?.potential_impact && (
                <p><strong className="text-white">Potential Impact:</strong> {finding.ai_explanation.potential_impact}</p>
              )}
            </div>
          </div>

          {/* Related Code Patterns */}
          {relatedPatterns.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center">
                <Layers className="w-4 h-4 mr-1.5 text-blue-400" /> Related Code Patterns Across Repository
              </h4>
              <div className="space-y-2">
                {relatedPatterns.map((rel, idx) => (
                  <div key={idx} className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-slate-300 font-semibold">{rel.file_path} : line {rel.line_number}</span>
                      <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800 text-[10px]">
                        {rel.label} ({Math.round(rel.similarity_score * 100)}% match)
                      </span>
                    </div>
                    <div className="text-slate-400 overflow-x-auto bg-slate-900/60 p-2 rounded">
                      <code>{rel.code_snippet}</code>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}



          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                External Security References
              </h4>
              <div className="space-y-1">
                {finding.references.map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center text-xs text-cyan-400 hover:underline mr-4"
                  >
                    <span>{ref}</span>
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </a>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl text-sm transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
