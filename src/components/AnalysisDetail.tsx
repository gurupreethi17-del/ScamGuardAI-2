import React, { useState } from 'react';
import { ThreatAnalysis, UserInteractionChoice } from '../types/index.ts';
import { INCIDENT_PLAYBOOK } from '../lib/incidentPlaybook.ts';
import { api } from '../lib/api.ts';
import { RiskGauge } from './RiskGauge.tsx';
import {
  ShieldAlert,
  AlertOctagon,
  CheckCircle,
  HelpCircle,
  Printer,
  Terminal,
  ChevronDown,
  ChevronUp,
  FileText,
  Clock,
  Tag,
  Share2,
  Lock,
  ArrowLeft,
  Info,
  Download,
  AlertTriangle,
  ExternalLink,
} from 'lucide-react';

interface AnalysisDetailProps {
  analysis: ThreatAnalysis;
  onBack: () => void;
  onOpenCopilotWithContext: (analysis: ThreatAnalysis) => void;
  onAnalysisUpdated: (updated: ThreatAnalysis) => void;
}

export const AnalysisDetail: React.FC<AnalysisDetailProps> = ({
  analysis,
  onBack,
  onOpenCopilotWithContext,
  onAnalysisUpdated,
}) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(true);
  const [selectedInteraction, setSelectedInteraction] = useState<UserInteractionChoice>(
    (analysis.incidentInteraction as UserInteractionChoice) || 'viewed_only'
  );
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [incidentSuccess, setIncidentSuccess] = useState(false);

  // Label & Notes inline editing
  const [isEditingMeta, setIsEditingMeta] = useState(false);
  const [labelInput, setLabelInput] = useState(analysis.label || '');
  const [notesInput, setNotesInput] = useState(analysis.notes || '');
  const [savingMeta, setSavingMeta] = useState(false);

  // Handle interaction choice submission
  const handleInteractionChange = async (choice: UserInteractionChoice) => {
    setSelectedInteraction(choice);
    setIncidentLoading(true);
    setIncidentSuccess(false);

    try {
      const res = await api.analyses.submitIncident(analysis.id, choice);
      onAnalysisUpdated(res.analysis);
      setIncidentSuccess(true);
      setTimeout(() => setIncidentSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to update incident response choice:', err);
    } finally {
      setIncidentLoading(false);
    }
  };

  const handleSaveMeta = async () => {
    setSavingMeta(true);
    try {
      const updated = await api.analyses.update(analysis.id, {
        label: labelInput.trim(),
        notes: notesInput.trim(),
      });
      onAnalysisUpdated(updated);
      setIsEditingMeta(false);
    } catch (err) {
      console.error('Failed to update analysis notes:', err);
    } finally {
      setSavingMeta(false);
    }
  };

  const currentPlaybook = INCIDENT_PLAYBOOK[selectedInteraction];

  const handlePrint = () => {
    window.print();
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'HIGH':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 print:max-w-none print:m-0">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800 print:hidden">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to History</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onOpenCopilotWithContext(analysis)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 rounded border border-cyan-500/40 transition-colors cursor-pointer"
          >
            <Terminal className="h-3.5 w-3.5 text-cyan-400" />
            <span>Consult Copilot</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 rounded border border-slate-700 transition-colors cursor-pointer"
          >
            <Printer className="h-3.5 w-3.5 text-slate-400" />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* Main Threat Header Card */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-5 sm:p-6 shadow-xl space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-5 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-500 mb-1">
              <span className="uppercase text-cyan-400 font-semibold">{analysis.type} ANALYSIS</span>
              <span>·</span>
              <span className="tabular-nums">
                {new Date(analysis.createdAt).toLocaleDateString()} {new Date(analysis.createdAt).toLocaleTimeString()}
              </span>
              <span>·</span>
              <span className="truncate max-w-[140px] text-slate-400">ID: {analysis.id}</span>
            </div>

            <h1 className="text-xl font-bold text-slate-100 tracking-tight">
              {analysis.title}
            </h1>
            <div className={`mt-1 text-sm font-semibold flex items-center gap-2 ${
              analysis.riskLevel === 'CRITICAL' || analysis.riskLevel === 'HIGH'
                ? 'text-rose-300'
                : analysis.riskLevel === 'MEDIUM'
                  ? 'text-yellow-300'
                  : 'text-emerald-300'
            }`}>
              <ShieldAlert className="h-4 w-4" />
              <span>{analysis.threatType}</span>
              <span className="text-[10px] font-mono rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-slate-300">
                {analysis.classification || (analysis.riskScore >= 50 ? 'SCAM' : analysis.riskScore >= 25 ? 'SUSPICIOUS' : 'SAFE')}
              </span>
            </div>
          </div>

          {/* Visual Risk Gauge */}
          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 shrink-0">
            <RiskGauge
              score={analysis.riskScore}
              level={analysis.riskLevel}
              confidence={analysis.confidence}
              size="lg"
            />
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-2">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Threat Intelligence Summary
          </h3>
          <p className="text-sm text-slate-200 leading-relaxed">
            {analysis.summary}
          </p>
        </div>

        {/* Direct Safety Warning Notice */}
        {analysis.userSafetyWarning && (
          <div className="rounded border border-amber-500/30 bg-amber-950/20 p-3.5 text-xs text-amber-200 flex items-start gap-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <span className="font-semibold block text-amber-100">Safety note:</span>
              {analysis.userSafetyWarning}
            </div>
          </div>
        )}
      </div>

      {/* Evidence-based explanation and signals */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 sm:p-6 shadow-md space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100">
              Why This Result Was Assigned
            </h2>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Plain Language Breakdown</span>
        </div>

        <div className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded border border-slate-800/80">
          {analysis.explanation}
        </div>

        {/* Indicators List */}
        <div className="space-y-3 pt-2">
          <h3 className="text-xs font-semibold text-slate-200">
            Observed Evidence ({analysis.indicators.length})
          </h3>
          <div className="grid grid-cols-1 gap-2.5">
            {analysis.indicators.map((ind, i) => (
              <div
                key={i}
                className="rounded border border-slate-800 bg-slate-950/70 p-3 flex flex-col sm:flex-row sm:items-start justify-between gap-2"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-200">{ind.name}</span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${getSeverityBadge(
                        ind.severity
                      )}`}
                    >
                      {ind.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-normal">{ind.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Expandable Technical Signals & Manipulation Tactics */}
        <div className="pt-2 border-t border-slate-800/80">
          <button
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            className="flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer"
          >
            {showTechnicalDetails ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            <span>{showTechnicalDetails ? 'Hide' : 'Show'} In-Depth Technical Signals & Social Engineering Analysis</span>
          </button>

          {showTechnicalDetails && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Social Engineering Tactics */}
              <div className="rounded border border-slate-800 bg-slate-950 p-4 space-y-2">
                <span className="text-xs font-semibold text-slate-200 block">
                  Psychological & Manipulation Tactics
                </span>
                <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
                  {analysis.socialEngineeringTactics.map((t, idx) => (
                    <li key={idx} className="text-slate-300">{t}</li>
                  ))}
                  {analysis.socialEngineeringTactics.length === 0 && (
                    <li className="text-slate-500 italic">No overt psychological coercion identified</li>
                  )}
                </ul>
              </div>

              {/* Technical Telemetry Signals */}
              <div className="rounded border border-slate-800 bg-slate-950 p-4 space-y-2">
                <span className="text-xs font-semibold text-slate-200 block">
                  Technical Signals & Telemetry Clues
                </span>
                <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
                  {analysis.technicalSignals.map((s, idx) => (
                    <li key={idx} className="text-slate-300 font-mono text-[11px]">{s}</li>
                  ))}
                  {analysis.technicalSignals.length === 0 && (
                    <li className="text-slate-500 italic">No network anomaly flags observed</li>
                  )}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* SECTION 6: SITUATION-SPECIFIC INCIDENT RESPONSE (CRITICAL REQUIREMENT) */}
      <div className="rounded-lg border border-cyan-500/30 bg-slate-900/90 p-5 sm:p-6 shadow-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase tracking-wider">
              <ShieldAlert className="h-4 w-4" />
              Incident Response Triage
            </div>
            <h2 className="text-base font-bold text-slate-100 mt-0.5">
              Have you already interacted with this content?
            </h2>
          </div>
          {incidentSuccess && (
            <span className="text-xs text-emerald-400 flex items-center gap-1 font-mono">
              <CheckCircle className="h-3.5 w-3.5" /> Protocol Saved
            </span>
          )}
        </div>

        {/* 9 Choice Buttons as per Section 6 Specification */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {(
            [
              ['viewed_only', 'I only viewed it'],
              ['clicked_link', 'I clicked the link'],
              ['entered_password', 'I entered my password'],
              ['shared_otp', 'I shared an OTP'],
              ['bank_details', 'I entered card/bank info'],
              ['transferred_money', 'I transferred money'],
              ['downloaded_file', 'I downloaded a file'],
              ['personal_info', 'I shared personal info'],
              ['unsure', "I'm not sure"],
            ] as const
          ).map(([key, label]) => {
            const isSelected = selectedInteraction === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => handleInteractionChange(key as UserInteractionChoice)}
                disabled={incidentLoading}
                className={`p-2.5 text-xs text-left rounded border transition-colors cursor-pointer ${
                  isSelected
                    ? 'border-cyan-400 bg-cyan-950/40 text-cyan-200 font-semibold shadow-sm'
                    : 'border-slate-800 bg-slate-950 hover:border-slate-700 text-slate-300'
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Selected Guidance Playbook Display */}
        {currentPlaybook && (
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 sm:p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
                  Tailored Action Protocol: {currentPlaybook.title}
                </span>
                <h3 className="text-sm font-bold text-slate-100 mt-0.5">
                  {currentPlaybook.headline}
                </h3>
              </div>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  currentPlaybook.severity === 'CRITICAL'
                    ? 'border-rose-500 text-rose-300 bg-rose-950/40'
                    : currentPlaybook.severity === 'URGENT'
                    ? 'border-amber-500 text-amber-300 bg-amber-950/40'
                    : 'border-slate-700 text-slate-300 bg-slate-900'
                }`}
              >
                {currentPlaybook.severity} PROTOCOL
              </span>
            </div>

            <p className="text-xs text-slate-300">
              {currentPlaybook.summary}
            </p>

            {/* Immediate Action Steps */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-rose-300 uppercase tracking-wide block">
                Immediate Actions Required:
              </span>
              <div className="space-y-2">
                {currentPlaybook.immediateSteps.map((step, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-2.5 text-xs text-slate-200 bg-slate-900/90 p-2.5 rounded border border-slate-800"
                  >
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-950 text-cyan-400 text-[11px] font-mono font-bold border border-cyan-800">
                      {idx + 1}
                    </span>
                    <span className="flex-1 mt-0.5">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Secondary Follow-up Steps */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wide block">
                Follow-up & Hardening:
              </span>
              <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                {currentPlaybook.followUpSteps.map((f, idx) => (
                  <li key={idx} className="text-slate-300">{f}</li>
                ))}
              </ul>
            </div>

            {/* Official Reporting Channels */}
            <div className="pt-2 border-t border-slate-800">
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">
                Official Reporting & Recovery Portals:
              </span>
              <div className="flex flex-wrap gap-2">
                {currentPlaybook.reportingChannels.map((c, idx) => (
                  <div
                    key={idx}
                    className="text-[11px] px-2.5 py-1 rounded bg-slate-900 text-cyan-300 border border-slate-800 font-mono"
                  >
                    {c}
                  </div>
                ))}
              </div>
            </div>

            {/* Important Disclaimer Notice */}
            <div className="text-[11px] text-slate-500 italic border-t border-slate-800/80 pt-2">
              {currentPlaybook.warningNotice}
            </div>
          </div>
        )}
      </div>

      {/* Actionable Recommendations & Prevention Tips */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
            <CheckCircle className="h-4 w-4" />
            Recommended Actions
          </h3>
          <ul className="space-y-2 text-xs text-slate-300">
            {analysis.recommendedActions.map((act, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-cyan-400 mt-0.5">•</span>
                <span>{act}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
            <Lock className="h-4 w-4" />
            Long-Term Prevention Habits
          </h3>
          <ul className="space-y-2 text-xs text-slate-300">
            {analysis.preventionTips.map((tip, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-emerald-400 mt-0.5">•</span>
                <span>{tip}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Original Content / Evidence Box */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Inspected Digital Evidence (Untrusted Data)
          </h3>
          <span className="text-[11px] text-slate-500 font-mono">
            Type: {analysis.type}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-950 p-3.5 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap break-all">
          {analysis.content}
        </div>

        {analysis.metadata?.url && (
          <div className="text-xs text-slate-400 font-mono">
            Destination URL: <span className="text-cyan-300">{analysis.metadata.url}</span>
          </div>
        )}
      </div>

      {/* Notes & Label Metadata Drawer */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-slate-300">
            Internal Analyst Notes & Labels
          </h3>
          {!isEditingMeta ? (
            <button
              onClick={() => setIsEditingMeta(true)}
              className="text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
            >
              Edit
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setIsEditingMeta(false)}
                className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveMeta}
                disabled={savingMeta}
                className="px-2 py-0.5 text-xs bg-cyan-600 text-slate-100 rounded hover:bg-cyan-500 cursor-pointer"
              >
                Save
              </button>
            </div>
          )}
        </div>

        {isEditingMeta ? (
          <div className="space-y-3">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Custom Label</label>
              <input
                type="text"
                value={labelInput}
                onChange={(e) => setLabelInput(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Analyst Notes</label>
              <textarea
                rows={2}
                value={notesInput}
                onChange={(e) => setNotesInput(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200"
              />
            </div>
          </div>
        ) : (
          <div className="text-xs text-slate-400 space-y-1">
            <div>
              <span className="text-slate-500">Label: </span>
              <span className="text-slate-200">{analysis.label || 'None'}</span>
            </div>
            <div>
              <span className="text-slate-500">Notes: </span>
              <span className="text-slate-300">{analysis.notes || 'No private notes added.'}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
