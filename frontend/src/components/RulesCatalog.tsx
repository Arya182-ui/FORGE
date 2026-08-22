import React from 'react';
import type { RuleMetadata } from '../types/scan';
import { Shield, BookOpen, ExternalLink } from 'lucide-react';

interface RulesCatalogProps {
  rules: RuleMetadata[];
}

export const RulesCatalog: React.FC<RulesCatalogProps> = ({ rules }) => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center">
            <Shield className="w-5 h-5 text-cyan-400 mr-2" /> Registered Security Rules Catalog
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Active AST rules enforced by Forge for Python and JavaScript source code analysis.
          </p>
        </div>
        <span className="px-3 py-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-cyan-400">
          Total Rules: {rules.length}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => (
          <div
            key={rule.rule_id}
            className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                  {rule.rule_id}
                </span>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-slate-400 uppercase">
                    {rule.language}
                  </span>
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-900/60">
                    {rule.severity}
                  </span>
                </div>
              </div>

              <h3 className="text-base font-bold text-white mb-2">{rule.name}</h3>
              <p className="text-xs text-slate-300 mb-3">{rule.description}</p>
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400 flex items-center">
                <BookOpen className="w-3.5 h-3.5 mr-1 text-blue-400" /> {rule.owasp_category}
              </span>
              {rule.references && rule.references.length > 0 && (
                <a
                  href={rule.references[0]}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:underline inline-flex items-center"
                >
                  OWASP Ref <ExternalLink className="w-3 h-3 ml-1" />
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
