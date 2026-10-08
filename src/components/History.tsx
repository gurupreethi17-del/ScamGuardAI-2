import React, { useState, useEffect } from 'react';
import { api } from '../lib/api.ts';
import { ThreatAnalysis, RiskLevel, AnalysisType } from '../types/index.ts';
import {
  Search,
  Filter,
  ArrowUpDown,
  Archive,
  RotateCcw,
  Trash2,
  Eye,
  Edit2,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  X,
  Check,
} from 'lucide-react';

interface HistoryProps {
  onSelectAnalysis: (analysis: ThreatAnalysis) => void;
  onAnalysisUpdated: (analysis: ThreatAnalysis) => void;
}

export const History: React.FC<HistoryProps> = ({ onSelectAnalysis, onAnalysisUpdated }) => {
  const [analyses, setAnalyses] = useState<ThreatAnalysis[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [riskLevel, setRiskLevel] = useState('ALL');
  const [analysisType, setAnalysisType] = useState('ALL');
  const [status, setStatus] = useState<'active' | 'archived' | 'all'>('active');
  const [sort, setSort] = useState<'newest' | 'oldest' | 'highest_risk' | 'lowest_risk'>('newest');

  // Delete confirmation modal state
  const [deleteTarget, setDeleteTarget] = useState<ThreatAnalysis | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Quick edit label modal
  const [editTarget, setEditTarget] = useState<ThreatAnalysis | null>(null);
  const [editLabel, setEditLabel] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [savingEdit, setSavingEdit] = useState(false);

  const fetchAnalyses = async () => {
    try {
      setLoading(true);
      const res = await api.analyses.list({
        search: search.trim() || undefined,
        riskLevel: riskLevel !== 'ALL' ? riskLevel : undefined,
        analysisType: analysisType !== 'ALL' ? analysisType : undefined,
        status: status !== 'all' ? status : undefined,
        sort,
        page,
        limit: 10,
      });
      setAnalyses(res.items);
      setTotal(res.total);
      setTotalPages(res.totalPages);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, [search, riskLevel, analysisType, status, sort, page]);

  const handleArchiveToggle = async (item: ThreatAnalysis, e: React.MouseEvent) => {
    e.stopPropagation();
    const newStatus = item.status === 'archived' ? 'active' : 'archived';
    try {
      const updated = await api.analyses.update(item.id, { status: newStatus });
      onAnalysisUpdated(updated);
      fetchAnalyses();
    } catch (err) {
      console.error('Failed to toggle archive status:', err);
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.analyses.delete(deleteTarget.id);
      setDeleteTarget(null);
      fetchAnalyses();
    } catch (err) {
      console.error('Failed to delete analysis:', err);
    } finally {
      setDeleting(false);
    }
  };

  const handleOpenEdit = (item: ThreatAnalysis, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditTarget(item);
    setEditLabel(item.label || '');
    setEditNotes(item.notes || '');
  };

  const handleSaveEdit = async () => {
    if (!editTarget) return;
    setSavingEdit(true);
    try {
      const updated = await api.analyses.update(editTarget.id, {
        label: editLabel.trim(),
        notes: editNotes.trim(),
      });
      onAnalysisUpdated(updated);
      setEditTarget(null);
      fetchAnalyses();
    } catch (err) {
      console.error('Failed to update notes:', err);
    } finally {
      setSavingEdit(false);
    }
  };

  const getRiskBadge = (level: RiskLevel) => {
    switch (level) {
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
    <div className="w-full max-w-5xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Threat Analysis History
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit trail of all digital content inspected and remediated in your workspace.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-slate-100 font-semibold">{analyses.length}</span> of{' '}
          <span className="text-slate-100 font-semibold">{total}</span> records
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 bg-slate-900/80 p-3 rounded-lg border border-slate-800">
        {/* Search */}
        <div className="relative lg:col-span-2">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search keywords, URLs, threat types..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        {/* Risk Level Filter */}
        <div>
          <select
            value={riskLevel}
            onChange={(e) => { setRiskLevel(e.target.value); setPage(1); }}
            className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="CRITICAL">Critical (75-100)</option>
            <option value="HIGH">High (50-74)</option>
            <option value="MEDIUM">Medium (25-49)</option>
            <option value="LOW">Low (0-24)</option>
          </select>
        </div>

        {/* Analysis Type Filter */}
        <div>
          <select
            value={analysisType}
            onChange={(e) => { setAnalysisType(e.target.value); setPage(1); }}
            className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="ALL">All Media Types</option>
            <option value="message">Messages (SMS/Chat)</option>
            <option value="email">Emails</option>
            <option value="url">Websites / URLs</option>
            <option value="screenshot">Screenshots</option>
            <option value="qr">QR Codes</option>
          </select>
        </div>

        {/* Sort */}
        <div>
          <select
            value={sort}
            onChange={(e) => { setSort(e.target.value as any); setPage(1); }}
            className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 px-2.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="newest">Sort: Newest First</option>
            <option value="oldest">Sort: Oldest First</option>
            <option value="highest_risk">Sort: Highest Risk</option>
            <option value="lowest_risk">Sort: Lowest Risk</option>
          </select>
        </div>
      </div>

      {/* Active vs Archived Segmented Control */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => { setStatus('active'); setPage(1); }}
          className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
            status === 'active'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Active Records
        </button>
        <button
          onClick={() => { setStatus('archived'); setPage(1); }}
          className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
            status === 'archived'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Archived Records
        </button>
      </div>

      {/* History Table Container */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
              <tr>
                <th className="py-3 px-4">Threat Summary</th>
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3">Risk Level</th>
                <th className="py-3 px-3 text-right">Score</th>
                <th className="py-3 px-3">Date</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Loading your analysis history...
                  </td>
                </tr>
              ) : analyses.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center space-y-2">
                    <p className="text-sm font-semibold text-slate-200">
                      {total === 0 && !search && riskLevel === 'ALL' && analysisType === 'ALL' && status === 'active'
                        ? 'No analyses yet'
                        : 'No threat analyses found matching your filters.'}
                    </p>
                    <p className="text-xs text-slate-400 max-w-sm mx-auto">
                      {total === 0 && !search && riskLevel === 'ALL' && analysisType === 'ALL' && status === 'active'
                        ? 'Analyze your first suspicious message, link, email, screenshot or QR code.'
                        : 'Try adjusting or clearing your search filters above.'}
                    </p>
                  </td>
                </tr>
              ) : (
                analyses.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => onSelectAnalysis(item)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4 max-w-xs sm:max-w-md">
                      <div className="font-semibold text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                        {item.title}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        <span className="text-slate-300 font-medium">{item.threatType}</span>
                        {item.label && item.label !== item.threatType && (
                          <span className="ml-2 text-cyan-400/90 font-mono text-[10px] bg-slate-950 px-1.5 py-0.2 rounded border border-slate-800">
                            {item.label}
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-950 text-slate-300 uppercase border border-slate-800">
                        {item.type}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <span
                        className={`font-mono text-[10px] px-2 py-0.5 rounded border ${getRiskBadge(
                          item.riskLevel
                        )}`}
                      >
                        {item.riskLevel}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-right font-mono font-bold tabular-nums text-slate-200">
                      {item.riskScore}
                    </td>

                    <td className="py-3 px-3 text-[11px] text-slate-400 font-mono whitespace-nowrap">
                      {new Date(item.createdAt).toLocaleDateString()}
                    </td>

                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={(e) => handleOpenEdit(item, e)}
                          title="Edit Label & Notes"
                          className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </button>

                        <button
                          onClick={(e) => handleArchiveToggle(item, e)}
                          title={item.status === 'archived' ? 'Restore record' : 'Archive record'}
                          className="p-1.5 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition-colors"
                        >
                          {item.status === 'archived' ? (
                            <RotateCcw className="h-3.5 w-3.5" />
                          ) : (
                            <Archive className="h-3.5 w-3.5" />
                          )}
                        </button>

                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setDeleteTarget(item);
                          }}
                          title="Delete record"
                          className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between p-3 border-t border-slate-800 text-xs text-slate-400">
            <span>
              Page <span className="font-semibold text-slate-200 font-mono">{page}</span> of{' '}
              <span className="font-semibold text-slate-200 font-mono">{totalPages}</span>
            </span>

            <div className="flex items-center gap-1.5">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="p-1.5 rounded border border-slate-700 bg-slate-950 hover:bg-slate-800 disabled:opacity-40 transition-colors"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
                className="p-1.5 rounded border border-slate-700 bg-slate-950 hover:bg-slate-800 disabled:opacity-40 transition-colors"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Delete Confirmation Dialog Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-lg border border-slate-800 bg-slate-900 p-5 shadow-2xl space-y-4">
            <div className="flex items-center gap-2 text-rose-400">
              <AlertTriangle className="h-5 w-5" />
              <h3 className="text-sm font-bold text-slate-100">Delete Analysis Record?</h3>
            </div>
            <p className="text-xs text-slate-300">
              Are you sure you want to permanently delete this report for{' '}
              <span className="font-semibold text-slate-100">"{deleteTarget.title}"</span>? This action cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setDeleteTarget(null)}
                className="px-3 py-1.5 text-xs text-slate-300 hover:text-slate-100 rounded border border-slate-700 bg-slate-950"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                disabled={deleting}
                className="px-3 py-1.5 text-xs text-white bg-rose-600 hover:bg-rose-500 rounded font-medium disabled:opacity-50"
              >
                {deleting ? 'Deleting...' : 'Delete Record'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Quick Edit Label & Notes Modal */}
      {editTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-slate-800 bg-slate-900 p-5 shadow-2xl space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Update Record Label & Notes
              </h3>
              <button onClick={() => setEditTarget(null)} className="text-slate-400 hover:text-slate-200">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Custom Label</label>
              <input
                type="text"
                value={editLabel}
                onChange={(e) => setEditLabel(e.target.value)}
                placeholder="e.g. CEO Fraud, Smishing Campaign"
                className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 px-3 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Analyst Private Notes</label>
              <textarea
                rows={3}
                value={editNotes}
                onChange={(e) => setEditNotes(e.target.value)}
                placeholder="Enter incident context or follow-up notes..."
                className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 px-3 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none resize-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setEditTarget(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                disabled={savingEdit}
                className="px-3 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded"
              >
                {savingEdit ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
