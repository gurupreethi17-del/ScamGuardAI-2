import React, { useState } from 'react';
import { INCIDENT_PLAYBOOK } from '../lib/incidentPlaybook.ts';
import { UserInteractionChoice } from '../types/index.ts';
import {
  ShieldAlert,
  AlertTriangle,
  Lock,
  PhoneCall,
  CheckCircle,
  ExternalLink,
} from 'lucide-react';

export const IncidentPlaybookView: React.FC<{ onNavigateToAnalyzer: () => void }> = ({
  onNavigateToAnalyzer,
}) => {
  const [selectedKey, setSelectedKey] = useState<UserInteractionChoice>('entered_password');

  const playbookList = Object.values(INCIDENT_PLAYBOOK);
  const current = INCIDENT_PLAYBOOK[selectedKey];

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-rose-400 text-xs font-mono uppercase tracking-wider mb-1">
            <ShieldAlert className="h-4 w-4" />
            Emergency Remediation Protocols
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Cyber Incident Response Playbook
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Step-by-step containment and recovery actions based on how you interacted with the threat.
          </p>
        </div>

        <button
          onClick={onNavigateToAnalyzer}
          className="px-3.5 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded transition-colors whitespace-nowrap cursor-pointer"
        >
          Inspect Suspicious Message
        </button>
      </div>

      {/* Scenario Selector Chips */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
        {playbookList.map((item) => {
          const isSelected = selectedKey === item.key;
          return (
            <button
              key={item.key}
              onClick={() => setSelectedKey(item.key)}
              className={`p-3 rounded-lg border text-left text-xs transition-colors cursor-pointer flex flex-col justify-between ${
                isSelected
                  ? 'border-cyan-400 bg-cyan-950/40 text-cyan-200 font-semibold shadow-md'
                  : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700'
              }`}
            >
              <span>{item.title}</span>
              <span
                className={`mt-2 text-[10px] font-mono px-1.5 py-0.2 rounded w-fit border ${
                  item.severity === 'CRITICAL'
                    ? 'border-rose-500/30 text-rose-300 bg-rose-950/40'
                    : item.severity === 'URGENT'
                    ? 'border-amber-500/30 text-amber-300 bg-amber-950/40'
                    : 'border-slate-700 text-slate-400 bg-slate-950'
                }`}
              >
                {item.severity}
              </span>
            </button>
          );
        })}
      </div>

      {/* Detailed Protocol Action Center */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-6 shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              Selected Scenario: {current.title}
            </div>
            <h2 className="text-lg font-bold text-slate-100 mt-0.5">
              {current.headline}
            </h2>
          </div>
          <span
            className={`text-xs font-mono px-2.5 py-1 rounded border self-start sm:self-center ${
              current.severity === 'CRITICAL'
                ? 'border-rose-500/40 text-rose-300 bg-rose-950/40'
                : current.severity === 'URGENT'
                ? 'border-amber-500/40 text-amber-300 bg-amber-950/40'
                : 'border-slate-700 text-slate-300 bg-slate-950'
            }`}
          >
            {current.severity} ALERT LEVEL
          </span>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/70 p-3.5 rounded border border-slate-800">
          {current.summary}
        </p>

        {/* Immediate Priority Steps */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-rose-300 flex items-center gap-1.5">
            <AlertTriangle className="h-4 w-4" />
            Phase 1: Immediate Containment Actions
          </h3>
          <div className="grid grid-cols-1 gap-2.5">
            {current.immediateSteps.map((step, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 text-xs text-slate-200 bg-slate-950 p-3 rounded border border-slate-800"
              >
                <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-950 text-cyan-400 font-mono text-[11px] font-bold border border-cyan-800 mt-0.5">
                  {idx + 1}
                </div>
                <div className="flex-1 leading-relaxed">{step}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Phase 2: Secondary Hardening */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
            <Lock className="h-4 w-4" />
            Phase 2: Account Hardening & Investigation
          </h3>
          <div className="grid grid-cols-1 gap-2">
            {current.followUpSteps.map((step, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2.5 text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded border border-slate-800/80"
              >
                <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <span className="flex-1">{step}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Official Channels */}
        <div className="space-y-2 pt-2 border-t border-slate-800">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Official Incident Reporting Channels
          </h3>
          <div className="flex flex-wrap gap-2">
            {current.reportingChannels.map((c, idx) => (
              <div
                key={idx}
                className="text-xs px-3 py-1.5 rounded bg-slate-950 text-cyan-300 border border-slate-800 font-mono"
              >
                {c}
              </div>
            ))}
          </div>
        </div>

        {/* Warning Notice */}
        <div className="p-3 bg-amber-950/20 border border-amber-500/30 rounded text-xs text-amber-200">
          <span className="font-semibold block text-amber-100">Advisory:</span>
          {current.warningNotice}
        </div>
      </div>
    </div>
  );
};
