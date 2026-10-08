import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext.tsx';
import { Navbar } from './components/Navbar.tsx';
import { Analyzer } from './components/Analyzer.tsx';
import { AnalysisDetail } from './components/AnalysisDetail.tsx';
import { History } from './components/History.tsx';
import { Copilot } from './components/Copilot.tsx';
import { IncidentPlaybookView } from './components/IncidentPlaybookView.tsx';
import { LandingHero } from './components/LandingHero.tsx';
import { AuthModal } from './components/AuthModal.tsx';
import { ThreatAnalysis } from './types/index.ts';
import { Shield } from 'lucide-react';

function ScamGuardApp() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'analyzer' | 'history' | 'playbook' | 'copilot'>('analyzer');
  const [selectedAnalysis, setSelectedAnalysis] = useState<ThreatAnalysis | null>(null);
  const [copilotContextAnalysis, setCopilotContextAnalysis] = useState<ThreatAnalysis | null>(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [showLandingBanner, setShowLandingBanner] = useState(true);

  // When an analysis completes in Analyzer
  const handleAnalysisComplete = (analysis: ThreatAnalysis) => {
    setSelectedAnalysis(analysis);
  };

  // When user opens Copilot with an active threat report
  const handleOpenCopilotWithContext = (analysis: ThreatAnalysis) => {
    setCopilotContextAnalysis(analysis);
    setActiveTab('copilot');
    setSelectedAnalysis(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Bar adhering to Top Bar Contract */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          setSelectedAnalysis(null);
        }}
        onOpenAuth={() => setAuthModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 py-6 sm:py-8">
        {selectedAnalysis ? (
          <AnalysisDetail
            analysis={selectedAnalysis}
            onBack={() => setSelectedAnalysis(null)}
            onOpenCopilotWithContext={handleOpenCopilotWithContext}
            onAnalysisUpdated={(updated) => setSelectedAnalysis(updated)}
          />
        ) : (
          <>
            {activeTab === 'analyzer' && (
              <div className="space-y-12">
                {/* Landing overview on first arrival */}
                {showLandingBanner && !user && (
                  <LandingHero
                    onStartAnalyze={() => setShowLandingBanner(false)}
                    onOpenCopilot={() => {
                      setActiveTab('copilot');
                      setShowLandingBanner(false);
                    }}
                  />
                )}

                <Analyzer
                  user={user}
                  onAnalysisComplete={handleAnalysisComplete}
                  onOpenAuth={() => setAuthModalOpen(true)}
                />
              </div>
            )}

            {activeTab === 'history' && (
              <History
                onSelectAnalysis={(item) => setSelectedAnalysis(item)}
                onAnalysisUpdated={(_item) => {
                  // updated in history
                }}
              />
            )}

            {activeTab === 'playbook' && (
              <IncidentPlaybookView
                onNavigateToAnalyzer={() => setActiveTab('analyzer')}
              />
            )}

            {activeTab === 'copilot' && (
              <Copilot
                initialAnalysis={copilotContextAnalysis}
                onClearContext={() => setCopilotContextAnalysis(null)}
              />
            )}
          </>
        )}
      </main>

      {/* Clean Footer (Anti-slop: No fake telemetry tickers) */}
      <footer className="w-full border-t border-slate-900 bg-slate-950/90 py-6 text-xs text-slate-500 print:hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="h-5 w-5 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Shield className="h-3 w-3" />
            </div>
            <span className="font-semibold text-slate-300">ScamGuard AI</span>
            <span>·</span>
            <span className="text-slate-400">Digital Safety & Threat Intelligence Platform</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] text-slate-400">
            <span>Deterministic scoring · Gemini optional</span>
            <span>·</span>
            <span>Adversarial Prompt Guard</span>
            <span>·</span>
            <span>© 2026 ScamGuard AI</span>
          </div>
        </div>
      </footer>

      {/* Auth Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
      />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ScamGuardApp />
    </AuthProvider>
  );
}
