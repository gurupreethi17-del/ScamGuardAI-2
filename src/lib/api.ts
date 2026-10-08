import {
  AuthResponse,
  ThreatAnalysis,
  CopilotConversation,
  CopilotMessage,
  UserInteractionChoice,
  IncidentPlaybookItem,
} from '../types/index.ts';

const TOKEN_KEY = 'scamguard_auth_token';

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string | null) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

async function fetchWithAuth(url: string, options: RequestInit = {}) {
  const token = getStoredToken();
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    let errMsg = `Request failed (${res.status})`;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        const errJson = await res.json();
        if (errJson.error) errMsg = errJson.error;
      } catch {
        // fallback
      }
    } else {
      if (res.status === 401) {
        errMsg = 'Authentication required. Please sign in to view this content.';
      } else if (res.status === 403) {
        errMsg = 'Access denied. You do not have permission to view this resource.';
      } else if (res.status === 404) {
        errMsg = 'Endpoint not found (404). The API service could not be reached.';
      } else if (res.status >= 500) {
        errMsg = 'Internal server error (500). Please try again shortly.';
      }
    }
    throw new Error(errMsg);
  }
  return res.json();
}

export const api = {
  auth: {
    async register(email: string, password: string, name: string): Promise<AuthResponse> {
      const data = await fetchWithAuth('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password, name }),
      });
      setStoredToken(data.token);
      return data;
    },
    async login(email: string, password: string): Promise<AuthResponse> {
      const data = await fetchWithAuth('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      setStoredToken(data.token);
      return data;
    },
    async me(): Promise<{ user: any }> {
      return fetchWithAuth('/api/auth/me');
    },
    logout() {
      setStoredToken(null);
    },
  },

  analyses: {
    async analyze(payload: {
      type: 'message' | 'email' | 'url' | 'screenshot' | 'qr';
      content?: string;
      metadata?: any;
    }): Promise<ThreatAnalysis> {
      return fetchWithAuth('/api/analyze', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
    },

    async list(params: {
      search?: string;
      riskLevel?: string;
      threatType?: string;
      analysisType?: string;
      status?: string;
      sort?: string;
      page?: number;
      limit?: number;
    } = {}): Promise<{ items: ThreatAnalysis[]; total: number; page: number; totalPages: number }> {
      const query = new URLSearchParams();
      if (params.search) query.set('search', params.search);
      if (params.riskLevel) query.set('riskLevel', params.riskLevel);
      if (params.threatType) query.set('threatType', params.threatType);
      if (params.analysisType) query.set('analysisType', params.analysisType);
      if (params.status) query.set('status', params.status);
      if (params.sort) query.set('sort', params.sort);
      if (params.page) query.set('page', String(params.page));
      if (params.limit) query.set('limit', String(params.limit));

      return fetchWithAuth(`/api/analyses?${query.toString()}`);
    },

    async get(id: string): Promise<ThreatAnalysis> {
      return fetchWithAuth(`/api/analyses/${id}`);
    },

    async update(
      id: string,
      updates: Partial<Pick<ThreatAnalysis, 'label' | 'notes' | 'status' | 'incidentInteraction' | 'incidentResponseActions'>>
    ): Promise<ThreatAnalysis> {
      return fetchWithAuth(`/api/analyses/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      });
    },

    async delete(id: string): Promise<{ success: boolean }> {
      return fetchWithAuth(`/api/analyses/${id}`, {
        method: 'DELETE',
      });
    },

    async submitIncident(
      id: string,
      interaction: UserInteractionChoice,
      customActions?: string[]
    ): Promise<{ analysis: ThreatAnalysis; playbook: IncidentPlaybookItem }> {
      return fetchWithAuth(`/api/analyses/${id}/incident-response`, {
        method: 'POST',
        body: JSON.stringify({ interaction, customActions }),
      });
    },
  },

  copilot: {
    async getConversations(): Promise<CopilotConversation[]> {
      return fetchWithAuth('/api/copilot/conversations');
    },
    async createConversation(title?: string): Promise<CopilotConversation> {
      return fetchWithAuth('/api/copilot/conversations', {
        method: 'POST',
        body: JSON.stringify({ title }),
      });
    },
    async getMessages(conversationId: string): Promise<CopilotMessage[]> {
      return fetchWithAuth(`/api/copilot/conversations/${conversationId}/messages`);
    },
    async sendMessage(
      message: string,
      conversationId?: string,
      relatedAnalysisId?: string,
      signal?: AbortSignal
    ): Promise<{ conversationId: string; userMessage: CopilotMessage; assistantMessage: CopilotMessage }> {
      return fetchWithAuth('/api/copilot/chat', {
        method: 'POST',
        body: JSON.stringify({ message, conversationId, relatedAnalysisId }),
        signal,
      });
    },

    async streamMessage(
      message: string,
      conversationId: string | undefined,
      relatedAnalysisId: string | undefined,
      onChunk: (chunk: string, fullText: string) => void,
      signal?: AbortSignal
    ): Promise<{ conversationId: string; userMessage?: CopilotMessage; assistantMessage?: CopilotMessage; text: string }> {
      const token = getStoredToken();
      const headers = new Headers();
      headers.set('Content-Type', 'application/json');
      if (token) {
        headers.set('Authorization', `Bearer ${token}`);
      }

      const res = await fetch('/api/copilot/chat/stream', {
        method: 'POST',
        headers,
        body: JSON.stringify({ message, conversationId, relatedAnalysisId }),
        signal,
      });

      if (!res.ok) {
        let errMessage = `Server error (${res.status})`;
        try {
          const errData = await res.json();
          if (errData.error) errMessage = errData.error;
        } catch {
          // fallback
        }
        throw new Error(errMessage);
      }

      const reader = res.body?.getReader();
      if (!reader) {
        throw new Error('Streaming response body is unavailable.');
      }

      const decoder = new TextDecoder();
      let accumulatedText = '';
      let resultConvoId = conversationId || '';
      let userMsg: CopilotMessage | undefined;
      let assistantMsg: CopilotMessage | undefined;
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data: ')) continue;
          const jsonStr = trimmed.slice(6).trim();
          if (!jsonStr) continue;

          try {
            const data = JSON.parse(jsonStr);
            if (data.type === 'start') {
              resultConvoId = data.conversationId;
              userMsg = data.userMessage;
            } else if (data.type === 'chunk') {
              accumulatedText += data.text;
              onChunk(data.text, accumulatedText);
            } else if (data.type === 'done') {
              resultConvoId = data.conversationId;
              assistantMsg = data.assistantMessage;
              userMsg = data.userMessage;
            } else if (data.type === 'error') {
              throw new Error(data.error || 'Stream error occurred.');
            }
          } catch (pErr) {
            console.warn('Error parsing SSE event:', pErr);
          }
        }
      }

      return {
        conversationId: resultConvoId,
        userMessage: userMsg,
        assistantMessage: assistantMsg,
        text: accumulatedText,
      };
    },
  },
};
