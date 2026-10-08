import React, { useState, useEffect, useRef } from 'react';
import { api } from '../lib/api.ts';
import { ThreatAnalysis, CopilotConversation, CopilotMessage } from '../types/index.ts';
import {
  Terminal,
  Send,
  Sparkles,
  Plus,
  RefreshCw,
  User,
  AlertTriangle,
  RotateCcw,
  MessageSquare,
  StopCircle,
} from 'lucide-react';

interface CopilotProps {
  initialAnalysis?: ThreatAnalysis | null;
  onClearContext?: () => void;
}

const QUICK_ACTIONS = [
  'What should I do right now?',
  'I entered my OTP — how to freeze access?',
  'I gave them my debit/credit card info',
  'Is this lookalike link dangerous?',
  'How do I file an official report with the FTC/IC3?',
  'Can they hack my phone if I only opened the message?',
];

const TIMEOUT_MS = 20000; // 20 seconds max

export const Copilot: React.FC<CopilotProps> = ({ initialAnalysis, onClearContext }) => {
  const [conversations, setConversations] = useState<CopilotConversation[]>([]);
  const [currentConvoId, setCurrentConvoId] = useState<string | null>(null);
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [statusFeedback, setStatusFeedback] = useState<string>('');
  const [activeAnalysis, setActiveAnalysis] = useState<ThreatAnalysis | null>(initialAnalysis || null);
  const [lastFailedMessage, setLastFailedMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const timeoutIdRef = useRef<NodeJS.Timeout | null>(null);

  // Sync initialAnalysis prop if it changes
  useEffect(() => {
    if (initialAnalysis) {
      setActiveAnalysis(initialAnalysis);
    }
  }, [initialAnalysis]);

  // Clean up any pending abort controllers or timers on unmount
  useEffect(() => {
    return () => {
      if (timeoutIdRef.current) clearTimeout(timeoutIdRef.current);
      if (abortControllerRef.current) abortControllerRef.current.abort();
    };
  }, []);

  // Load conversations on mount
  useEffect(() => {
    const loadConversations = async () => {
      try {
        const convos = await api.copilot.getConversations();
        setConversations(convos);
        if (convos.length > 0) {
          setCurrentConvoId(convos[0].id);
        }
      } catch (err) {
        console.error('Failed to load conversations:', err);
      }
    };
    loadConversations();
  }, []);

  // Load messages whenever conversation changes
  useEffect(() => {
    const loadMessages = async () => {
      if (!currentConvoId) {
        setMessages([]);
        return;
      }
      try {
        const msgs = await api.copilot.getMessages(currentConvoId);
        setMessages(msgs);
      } catch (err) {
        console.error('Failed to load messages:', err);
      }
    };
    loadMessages();
  }, [currentConvoId]);

  // Scroll to bottom on message update
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, sending, statusFeedback]);

  const handleStartNewChat = async () => {
    try {
      if (sending && abortControllerRef.current) {
        abortControllerRef.current.abort();
        setSending(false);
      }
      setErrorMessage(null);
      setLastFailedMessage(null);
      const newConvo = await api.copilot.createConversation('New Incident Session');
      setConversations((prev) => [newConvo, ...prev]);
      setCurrentConvoId(newConvo.id);
      setMessages([]);
    } catch (err) {
      console.error('Failed to create new conversation:', err);
    }
  };

  const handleAbort = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    if (timeoutIdRef.current) {
      clearTimeout(timeoutIdRef.current);
    }
    setSending(false);
    setStatusFeedback('');
  };

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || input).trim();
    if (!text || sending) return;

    setInput('');
    setSending(true);
    setErrorMessage(null);
    setLastFailedMessage(null);
    setStatusFeedback('Connecting to Security Copilot...');

    // Optimistically append user message
    const tempUserMsgId = 'temp_usr_' + Date.now();
    const tempUserMsg: CopilotMessage = {
      id: tempUserMsgId,
      conversationId: currentConvoId || '',
      role: 'user',
      content: text,
      createdAt: new Date().toISOString(),
      relatedAnalysisId: activeAnalysis?.id,
    };

    // Optimistic streaming placeholder for assistant
    const tempAssistantMsgId = 'temp_ast_' + Date.now();
    const tempAssistantMsg: CopilotMessage = {
      id: tempAssistantMsgId,
      conversationId: currentConvoId || '',
      role: 'assistant',
      content: '',
      createdAt: new Date().toISOString(),
      relatedAnalysisId: activeAnalysis?.id,
    };

    setMessages((prev) => [...prev, tempUserMsg, tempAssistantMsg]);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    let didTimeout = false;
    timeoutIdRef.current = setTimeout(() => {
      didTimeout = true;
      abortController.abort();
    }, TIMEOUT_MS);

    try {
      let streamedAny = false;

      const result = await api.copilot.streamMessage(
        text,
        currentConvoId || undefined,
        activeAnalysis?.id,
        (_chunk, fullText) => {
          streamedAny = true;
          setStatusFeedback('');
          setMessages((prev) =>
            prev.map((m) => (m.id === tempAssistantMsgId ? { ...m, content: fullText } : m))
          );
        },
        abortController.signal
      );

      if (timeoutIdRef.current) clearTimeout(timeoutIdRef.current);

      if (!currentConvoId && result.conversationId) {
        setCurrentConvoId(result.conversationId);
        const convos = await api.copilot.getConversations();
        setConversations(convos);
      }

      // Replace temporary messages with confirmed stored records
      setMessages((prev) => {
        const filtered = prev.filter((m) => m.id !== tempUserMsgId && m.id !== tempAssistantMsgId);
        const userM = result.userMessage || tempUserMsg;
        const asstM = result.assistantMessage || {
          ...tempAssistantMsg,
          content: result.text || 'I analyzed your request. Please exercise immediate caution.',
        };
        return [...filtered, userM, asstM];
      });

      setErrorMessage(null);
      setLastFailedMessage(null);
    } catch (err: any) {
      if (timeoutIdRef.current) clearTimeout(timeoutIdRef.current);
      console.error('Error in Copilot chat:', err);

      // Clean out the empty assistant placeholder if nothing was streamed
      setMessages((prev) => prev.filter((m) => m.id !== tempAssistantMsgId));

      setLastFailedMessage(text);

      if (didTimeout || err.name === 'AbortError') {
        setErrorMessage('ScamGuard Security Copilot is taking longer than expected. Please try again.');
      } else {
        setErrorMessage(
          err.message || 'ScamGuard Security Copilot is taking longer than expected. Please try again.'
        );
      }
    } finally {
      setSending(false);
      setStatusFeedback('');
      abortControllerRef.current = null;
    }
  };

  const handleRetry = () => {
    if (lastFailedMessage) {
      handleSendMessage(lastFailedMessage);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-4 h-[720px]">
      {/* Sidebar: Conversation Sessions & Context */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 flex flex-col justify-between hidden md:flex">
        <div className="space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5 text-cyan-400" />
              Triage Sessions
            </span>
            <button
              onClick={handleStartNewChat}
              title="New Chat Session"
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer"
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Conversation List */}
          <div className="space-y-1 overflow-y-auto max-h-[380px]">
            {conversations.map((c) => (
              <button
                key={c.id}
                onClick={() => {
                  setCurrentConvoId(c.id);
                  setErrorMessage(null);
                  setLastFailedMessage(null);
                }}
                className={`w-full text-left p-2 rounded text-xs transition-colors flex items-center gap-2 truncate cursor-pointer ${
                  currentConvoId === c.id
                    ? 'bg-cyan-950/40 text-cyan-300 border border-cyan-800/60 font-medium'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                <MessageSquare className="h-3 w-3 shrink-0" />
                <span className="truncate">{c.title || 'Incident Session'}</span>
              </button>
            ))}

            {conversations.length === 0 && (
              <div className="text-[11px] text-slate-500 italic p-2">
                No past sessions. Send a message to start.
              </div>
            )}
          </div>
        </div>

        {/* Active Threat Context Badge */}
        {activeAnalysis && (
          <div className="p-2.5 rounded border border-cyan-500/30 bg-cyan-950/20 text-xs space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-cyan-400 uppercase font-semibold">
                Grounded Context
              </span>
              <button
                onClick={() => {
                  setActiveAnalysis(null);
                  if (onClearContext) onClearContext();
                }}
                className="text-[10px] text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                Clear
              </button>
            </div>
            <div className="font-medium text-slate-200 truncate">
              {activeAnalysis.title}
            </div>
            <div className="text-[10px] text-rose-300">
              Risk: {activeAnalysis.riskScore}/100 ({activeAnalysis.riskLevel})
            </div>
          </div>
        )}
      </div>

      {/* Main Chat Area */}
      <div className="md:col-span-3 rounded-lg border border-slate-800 bg-slate-900/60 flex flex-col h-full overflow-hidden shadow-xl">
        {/* Chat Header */}
        <div className="p-3.5 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Terminal className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                <span>ScamGuard Security Copilot</span>
                <span className="text-[10px] font-mono text-cyan-400 border border-cyan-500/30 px-1 py-0.2 rounded bg-cyan-950/40">
                  Real-Time Streaming
                </span>
              </h2>
              <p className="text-[10px] text-slate-400">
                Triage guidance, phishing defense, credential recovery, official cybercrime reporting
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {sending && (
              <button
                onClick={handleAbort}
                title="Stop response"
                className="text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 cursor-pointer px-2 py-1 rounded bg-rose-950/40 border border-rose-800/40"
              >
                <StopCircle className="h-3 w-3" />
                <span>Stop</span>
              </button>
            )}
            <button
              onClick={handleStartNewChat}
              className="md:hidden text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
            >
              New Chat
            </button>
          </div>
        </div>

        {/* Message Thread Scroll View */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-4">
              <div className="h-12 w-12 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Sparkles className="h-6 w-6" />
              </div>
              <div className="max-w-md space-y-1">
                <h3 className="text-sm font-semibold text-slate-100">
                  How can Security Copilot assist you?
                </h3>
                <p className="text-xs text-slate-400">
                  Ask immediate questions about suspicious communications, emergency account lockouts, or fund recovery procedures.
                </p>
              </div>

              {/* Quick Actions Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full max-w-lg pt-2">
                {QUICK_ACTIONS.map((action, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendMessage(action)}
                    className="p-2.5 text-xs text-left rounded border border-slate-800 bg-slate-950/80 hover:border-cyan-500/40 hover:bg-slate-900 text-slate-300 hover:text-cyan-200 transition-colors cursor-pointer"
                  >
                    {action}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m) => (
              <div
                key={m.id}
                className={`flex gap-3 text-xs leading-relaxed ${
                  m.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {m.role === 'assistant' && (
                  <div className="h-7 w-7 rounded bg-cyan-950 border border-cyan-700/50 flex items-center justify-center text-cyan-400 shrink-0 mt-0.5">
                    <Terminal className="h-3.5 w-3.5" />
                  </div>
                )}

                <div
                  className={`max-w-[85%] rounded-lg p-3.5 space-y-2 ${
                    m.role === 'user'
                      ? 'bg-cyan-600 text-slate-100 font-medium'
                      : 'bg-slate-950 border border-slate-800 text-slate-200 whitespace-pre-wrap'
                  }`}
                >
                  {m.content ? (
                    m.content
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-cyan-400 font-mono text-xs">
                      <RefreshCw className="h-3 w-3 animate-spin" />
                      <span>Copilot generating response...</span>
                    </span>
                  )}
                </div>

                {m.role === 'user' && (
                  <div className="h-7 w-7 rounded bg-slate-800 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                    <User className="h-3.5 w-3.5" />
                  </div>
                )}
              </div>
            ))
          )}

          {/* Initial feedback while waiting for first stream token */}
          {sending && statusFeedback && (
            <div className="flex gap-3 text-xs items-center text-slate-400">
              <div className="h-7 w-7 rounded bg-cyan-950 border border-cyan-700/50 flex items-center justify-center text-cyan-400 shrink-0">
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              </div>
              <div className="bg-slate-950 border border-slate-800 py-2 px-3 rounded-lg text-slate-400 text-xs flex items-center gap-2">
                <span>{statusFeedback}</span>
              </div>
            </div>
          )}

          {/* Error & Timeout banner with Retry button */}
          {errorMessage && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 p-3.5 text-xs text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                <span>{errorMessage}</span>
              </div>
              {lastFailedMessage && (
                <button
                  onClick={handleRetry}
                  className="px-3 py-1.5 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold text-xs flex items-center justify-center gap-1.5 transition-colors cursor-pointer shrink-0"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>Retry</span>
                </button>
              )}
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Form Bar */}
        <div className="p-3 bg-slate-950 border-t border-slate-800 space-y-2">
          {/* Quick Prompts Toolbar */}
          {messages.length > 0 && (
            <div className="flex gap-1.5 overflow-x-auto pb-1 text-[11px] text-slate-400 no-scrollbar">
              <span className="shrink-0 text-slate-500 font-mono py-1">Quick Actions:</span>
              <button
                onClick={() => handleSendMessage('What should I do right now?')}
                className="shrink-0 px-2 py-1 rounded bg-slate-900 border border-slate-800 hover:text-cyan-300 hover:border-slate-700 transition-colors whitespace-nowrap cursor-pointer"
              >
                Immediate steps
              </button>
              <button
                onClick={() => handleSendMessage('I shared my OTP code')}
                className="shrink-0 px-2 py-1 rounded bg-slate-900 border border-slate-800 hover:text-cyan-300 hover:border-slate-700 transition-colors whitespace-nowrap cursor-pointer"
              >
                OTP Shared
              </button>
              <button
                onClick={() => handleSendMessage('I entered my bank card details')}
                className="shrink-0 px-2 py-1 rounded bg-slate-900 border border-slate-800 hover:text-cyan-300 hover:border-slate-700 transition-colors whitespace-nowrap cursor-pointer"
              >
                Bank Details Entered
              </button>
              <button
                onClick={() => handleSendMessage('How do I report this officially?')}
                className="shrink-0 px-2 py-1 rounded bg-slate-900 border border-slate-800 hover:text-cyan-300 hover:border-slate-700 transition-colors whitespace-nowrap cursor-pointer"
              >
                Official Reporting
              </button>
            </div>
          )}

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask Copilot (e.g. 'I clicked the link and entered my password, what do I do?')..."
              className="flex-1 rounded border border-slate-700 bg-slate-900 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={sending || !input.trim()}
              className="p-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 transition-colors cursor-pointer"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
