import React from 'react';
import {
  ShieldAlert,
  ArrowRight,
  Terminal,
  Lock,
  Search,
  CheckCircle2,
  FileCheck,
  AlertOctagon,
  Scan,
} from 'lucide-react';

interface LandingHeroProps {
  onStartAnalyze: () => void;
  onOpenCopilot: () => void;
}

export const LandingHero: React.FC<LandingHeroProps> = ({
  onStartAnalyze,
  onOpenCopilot,
}) => {
  return (
    <div className="w-full space-y-16 py-4">
      {/* Hero Section */}
      <div className="relative rounded-2xl border border-slate-800 bg-slate-900/60 p-6 sm:p-12 overflow-hidden shadow-2xl">
        <div className="relative z-10 max-w-2xl space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full bg-cyan-950/80 border border-cyan-500/40 px-3 py-1 text-xs text-cyan-300 font-mono">
            <ShieldAlert className="h-3.5 w-3.5 text-cyan-400" />
            Next-Generation Digital Safety Intelligence
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-slate-100 leading-tight">
            SCAMGUARD AI
          </h1>

          <p className="text-lg sm:text-xl font-medium text-cyan-300">
            "Detect threats. Understand the risk. Stay protected."
          </p>

          <p className="text-sm text-slate-300 leading-relaxed max-w-xl">
            Analyze suspicious messages, emails, links, screenshots, and QR codes with evidence-based checks. Optional Gemini analysis can add context when configured; ScamGuard does not perform live domain-reputation lookups.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              onClick={onStartAnalyze}
              className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 shadow-lg transition-colors cursor-pointer"
            >
              <span>Analyze a Threat Now</span>
              <ArrowRight className="h-4 w-4" />
            </button>

            <button
              onClick={onOpenCopilot}
              className="px-5 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-slate-700 transition-colors cursor-pointer"
            >
              <Terminal className="h-4 w-4 text-cyan-400" />
              <span>Explore Security Copilot</span>
            </button>
          </div>
        </div>

        {/* Ambient Hero Graphic */}
        <div className="absolute right-0 top-0 bottom-0 w-full sm:w-1/2 opacity-25 sm:opacity-40 pointer-events-none overflow-hidden">
          <img
            src="/src/assets/images/hero_scamguard_shield_1791367696430.jpg"
            alt="Illustration of a cybersecurity shield"
            referrerPolicy="no-referrer"
            className="w-full h-full object-cover object-center mix-blend-screen"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-slate-900 via-transparent to-transparent" />
        </div>
      </div>

      {/* 4-Step Intelligence Workflow */}
      <div className="space-y-6">
        <div className="text-center space-y-1">
          <span className="text-xs font-mono uppercase tracking-widest text-cyan-400">
            End-To-End Security Pipeline
          </span>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100">
            How ScamGuard Protects You
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          {/* Step 1 */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-2">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-slate-800 text-cyan-400 font-mono text-xs font-bold">
              01
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Submit Content</h3>
            <p className="text-xs text-slate-400 leading-normal">
              Paste SMS, email text, enter URLs, upload screenshots, or scan physical QR codes safely without triggering payload execution.
            </p>
          </div>

          {/* Step 2 */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-2">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-slate-800 text-cyan-400 font-mono text-xs font-bold">
              02
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Evidence-Based Threat Analysis</h3>
            <p className="text-xs text-slate-400 leading-normal">
              Deterministic signals calculate risk from the submitted message and URL. Gemini can add contextual analysis when configured.
            </p>
          </div>

          {/* Step 3 */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-2">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-slate-800 text-cyan-400 font-mono text-xs font-bold">
              03
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Understand the Risk</h3>
            <p className="text-xs text-slate-400 leading-normal">
              Explainable AI details WHY the content is risky in plain English, pinpointing psychological pressure tactics and technical indicators.
            </p>
          </div>

          {/* Step 4 */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-2">
            <div className="flex h-8 w-8 items-center justify-center rounded bg-slate-800 text-cyan-400 font-mono text-xs font-bold">
              04
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Remediate & Protect</h3>
            <p className="text-xs text-slate-400 leading-normal">
              Activate situational incident playbooks if you entered passwords or OTPs, with emergency bank lockouts and official FTC reporting.
            </p>
          </div>
        </div>
      </div>

      {/* Feature Showcase Bento Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden flex flex-col justify-between">
          <div className="p-6 space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase">
              <Scan className="h-4 w-4" />
              Isolated QR Scanner
            </div>
            <h3 className="text-base font-bold text-slate-100">
              Quishing Defense & Safe QR Decoupling
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Never blindly scan public parking meters or sticker codes. ScamGuard decodes the destination string offline, previews it safely, and checks for payment redirection traps before your phone touches it.
            </p>
          </div>
          <div className="h-44 w-full overflow-hidden bg-slate-950">
            <img
              src="/src/assets/images/feature_qr_scan_1791367709116.jpg"
              alt="Safe QR Scanning Visualization"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover opacity-80"
            />
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden flex flex-col justify-between">
          <div className="p-6 space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase">
              <AlertOctagon className="h-4 w-4" />
              Multimodal Phishing Analysis
            </div>
            <h3 className="text-base font-bold text-slate-100">
              Visual Screenshot & Fake Login Inspector
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Upload screenshots of suspicious text messages, spoofed login forms, or fake delivery tracking pages. The multimodal vision model inspects deceptive logos and simulated urgency layouts.
            </p>
          </div>
          <div className="h-44 w-full overflow-hidden bg-slate-950">
            <img
              src="/src/assets/images/feature_phishing_inspect_1791367722828.jpg"
              alt="Message Stream Threat Inspector"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover opacity-80"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
