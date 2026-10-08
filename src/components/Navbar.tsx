import React from 'react';
import { useAuth } from '../context/AuthContext.tsx';
import { Shield, User, LogOut, Terminal, Lock } from 'lucide-react';

interface NavbarProps {
  activeTab: 'analyzer' | 'history' | 'playbook' | 'copilot';
  setActiveTab: (tab: 'analyzer' | 'history' | 'playbook' | 'copilot') => void;
  onOpenAuth: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, onOpenAuth }) => {
  const { user, logout } = useAuth();

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6">
        {/* Zone 1: Single text element wordmark */}
        <button
          onClick={() => setActiveTab('analyzer')}
          className="flex items-center gap-2 text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 rounded cursor-pointer"
        >
          <div className="flex h-7 w-7 items-center justify-center rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <Shield className="h-4 w-4" />
          </div>
          <span className="text-base font-bold tracking-tight text-slate-100 hover:text-cyan-400 transition-colors">
            ScamGuard AI
          </span>
        </button>

        {/* Zone 2: 4-6 clean text navigation links */}
        <nav className="hidden md:flex items-center gap-7 text-xs font-medium text-slate-400">
          <button
            onClick={() => setActiveTab('analyzer')}
            className={`transition-colors hover:text-slate-100 ${
              activeTab === 'analyzer' ? 'text-cyan-400 font-semibold' : ''
            }`}
          >
            Threat Analyzer
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`transition-colors hover:text-slate-100 ${
              activeTab === 'history' ? 'text-cyan-400 font-semibold' : ''
            }`}
          >
            Analysis History
          </button>
          <button
            onClick={() => setActiveTab('playbook')}
            className={`transition-colors hover:text-slate-100 ${
              activeTab === 'playbook' ? 'text-cyan-400 font-semibold' : ''
            }`}
          >
            Incident Playbook
          </button>
          <button
            onClick={() => setActiveTab('copilot')}
            className={`transition-colors hover:text-slate-100 flex items-center gap-1.5 ${
              activeTab === 'copilot' ? 'text-cyan-400 font-semibold' : ''
            }`}
          >
            <Terminal className="h-3 w-3" />
            Security Copilot
          </button>
        </nav>

        {/* Zone 3: 1-2 primary actions */}
        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-3">
              <div className="hidden sm:flex flex-col text-right">
                <span className="text-xs font-medium text-slate-200 truncate max-w-[130px]">
                  {user.name}
                </span>
                <span className="text-[10px] text-slate-500 font-mono truncate max-w-[130px]">
                  {user.email}
                </span>
              </div>
              <button
                onClick={logout}
                title="Sign Out"
                className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded border border-slate-800 transition-colors"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuth}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-cyan-600 hover:bg-cyan-500 rounded border border-cyan-400/40 shadow-sm transition-colors whitespace-nowrap cursor-pointer"
            >
              <Lock className="h-3.5 w-3.5" />
              Sign In / Register
            </button>
          )}
        </div>
      </div>

      {/* Mobile subnav */}
      <div className="flex md:hidden overflow-x-auto border-t border-slate-800/60 px-4 py-2 gap-4 text-xs font-medium text-slate-400 no-scrollbar">
        <button
          onClick={() => setActiveTab('analyzer')}
          className={`whitespace-nowrap ${activeTab === 'analyzer' ? 'text-cyan-400' : ''}`}
        >
          Analyzer
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`whitespace-nowrap ${activeTab === 'history' ? 'text-cyan-400' : ''}`}
        >
          History
        </button>
        <button
          onClick={() => setActiveTab('playbook')}
          className={`whitespace-nowrap ${activeTab === 'playbook' ? 'text-cyan-400' : ''}`}
        >
          Playbook
        </button>
        <button
          onClick={() => setActiveTab('copilot')}
          className={`whitespace-nowrap ${activeTab === 'copilot' ? 'text-cyan-400' : ''}`}
        >
          Copilot
        </button>
      </div>
    </header>
  );
};
