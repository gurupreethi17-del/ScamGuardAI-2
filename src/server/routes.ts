import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { dbStore, UserRecord } from './db/store.ts';
import { analyzeThreatWithGemini, askSecurityCopilot, streamSecurityCopilot, AnalyzeInput } from './ai/gemini.ts';
import { INCIDENT_PLAYBOOK } from '../lib/incidentPlaybook.ts';
import { UserInteractionChoice } from '../types/index.ts';

export const apiRouter = Router();

const TOKEN_SECRET = process.env.AUTH_SECRET || 'scamguard_auth_token_key_2026';

function generateToken(userId: string): string {
  const payload = Buffer.from(JSON.stringify({ userId, exp: Date.now() + 7 * 86400000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifyToken(token: string): string | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payload, signature] = parts;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
    if (signature !== expected) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    if (data.exp && data.exp < Date.now()) return null;
    return data.userId;
  } catch {
    return null;
  }
}

export interface AuthenticatedRequest extends Request {
  user?: UserRecord;
}

// Authentication middleware
function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid authentication token.' });
  }

  const token = authHeader.substring(7).trim();
  const userId = verifyToken(token);
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized: Session expired or invalid token.' });
  }

  const user = dbStore.findUserById(userId);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: User not found.' });
  }

  req.user = user;
  next();
}

// --- Health ---
apiRouter.get('/health', (_req, res) => {
  const geminiAvailable = Boolean(process.env.GEMINI_API_KEY);
  res.json({
    status: 'ok',
    service: 'ScamGuard AI Threat Engine',
    timestamp: new Date().toISOString(),
    analysisEngine: geminiAvailable ? 'deterministic+gemini-3.8-flash' : 'deterministic',
    geminiAvailable,
  });
});

// --- Auth Routes ---
apiRouter.post('/auth/register', (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const user = dbStore.createUser(email, password, name || 'User');
    const token = generateToken(user.id);
    res.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Registration failed.' });
  }
});

apiRouter.post('/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = dbStore.verifyUser(email, password);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = generateToken(user.id);
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Login failed.' });
  }
});

apiRouter.get('/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  const u = req.user!;
  res.json({
    user: {
      id: u.id,
      email: u.email,
      name: u.name,
      role: u.role,
      createdAt: u.createdAt,
    },
  });
});

// --- Threat Analysis Route ---
apiRouter.post('/analyze', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { type, content, metadata } = req.body as {
      type: 'message' | 'email' | 'url' | 'screenshot' | 'qr';
      content?: string;
      metadata?: any;
    };

    if (!type || !['message', 'email', 'url', 'screenshot', 'qr'].includes(type)) {
      return res.status(400).json({ error: 'Invalid analysis type. Must be message, email, url, screenshot, or qr.' });
    }

    if (type !== 'screenshot' && (typeof content !== 'string' || !content.trim())) {
      return res.status(400).json({ error: 'Content is required for threat inspection.' });
    }

    if (type === 'screenshot' && !metadata?.imageDataBase64) {
      return res.status(400).json({ error: 'Image file data is required for screenshot inspection.' });
    }
    if (typeof content === 'string' && content.length > 30_000) {
      return res.status(413).json({ error: 'Content exceeds the 30,000 character analysis limit.' });
    }
    if (type === 'screenshot') {
      if (typeof metadata.imageDataBase64 !== 'string' || metadata.imageDataBase64.length > 14_000_000) {
        return res.status(413).json({ error: 'Screenshot data is invalid or exceeds the 10MB image limit.' });
      }
      if (!['image/png', 'image/jpeg', 'image/webp'].includes(metadata.imageMimeType)) {
        return res.status(400).json({ error: 'Screenshot must be a PNG, JPEG, or WEBP image.' });
      }
    }
    for (const field of ['sender', 'subject', 'url', 'qrDecodedText'] as const) {
      if (metadata?.[field] !== undefined && typeof metadata[field] !== 'string') {
        return res.status(400).json({ error: `Invalid ${field} metadata.` });
      }
    }
    const metadataLimits = { sender: 500, subject: 500, url: 2_000, qrDecodedText: 30_000 };
    for (const [field, limit] of Object.entries(metadataLimits)) {
      if (metadata?.[field] && metadata[field].length > limit) {
        return res.status(413).json({ error: `${field} metadata exceeds the ${limit} character limit.` });
      }
    }

    const input: AnalyzeInput = {
      type,
      content: content?.trim() || 'Uploaded visual screenshot asset',
      metadata,
    };

    // Run AI Risk Assessment through Gemini
    const aiResult = await analyzeThreatWithGemini(input);

    // Compute title for the analysis
    let title = `${type.toUpperCase()} Analysis`;
    if (type === 'message') {
      title = (content || '').slice(0, 48).trim() || 'Suspicious Message';
    } else if (type === 'email') {
      title = metadata?.subject ? `Email: ${metadata.subject.slice(0, 40)}` : 'Suspicious Email';
    } else if (type === 'url') {
      try {
        const u = new URL(content!.startsWith('http') ? content! : `https://${content}`);
        title = `URL: ${u.hostname}`;
      } catch {
        title = `URL: ${content?.slice(0, 36)}`;
      }
    } else if (type === 'qr') {
      title = metadata?.qrDecodedText ? `QR Code: ${metadata.qrDecodedText.slice(0, 36)}` : 'Decoded QR Threat';
    } else if (type === 'screenshot') {
      title = aiResult.threatType ? `Screenshot: ${aiResult.threatType}` : 'Visual Threat Inspection';
    }

    // Persist to user's isolated record
    const saved = dbStore.saveAnalysis(req.user!.id, {
      title,
      type,
      content: content || 'Visual image inspect',
      metadata: {
        sender: metadata?.sender,
        subject: metadata?.subject,
        url: metadata?.url || (type === 'url' ? content : undefined),
        qrDecodedText: metadata?.qrDecodedText || (type === 'qr' ? content : undefined),
        extractedLinks: metadata?.extractedLinks,
      },
      riskScore: aiResult.riskScore,
      riskLevel: aiResult.riskLevel,
      classification: aiResult.classification,
      threatType: aiResult.threatType,
      confidence: aiResult.confidence,
      summary: aiResult.summary,
      explanation: aiResult.explanation,
      indicators: aiResult.indicators,
      socialEngineeringTactics: aiResult.socialEngineeringTactics,
      technicalSignals: aiResult.technicalSignals,
      recommendedActions: aiResult.recommendedActions,
      preventionTips: aiResult.preventionTips,
      userSafetyWarning: aiResult.userSafetyWarning,
      incidentInteraction: undefined,
      incidentResponseActions: [],
      notes: '',
      label: aiResult.threatType,
    });

    res.status(201).json(saved);
  } catch (err: any) {
    console.error('Error analyzing content:', err);
    const message = err.message || 'Unable to analyze this content right now. Please try again.';
    res.status(/requires GEMINI_API_KEY|Gemini was unavailable|Gemini API key/i.test(message) ? 503 : 500).json({ error: message });
  }
});

// --- Analyses History & CRUD ---
apiRouter.get('/analyses', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const { search, riskLevel, threatType, analysisType, status, sort, page, limit } = req.query as any;

    const result = dbStore.getAnalyses(req.user!.id, {
      search,
      riskLevel,
      threatType,
      analysisType,
      status,
      sort,
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 10,
    });

    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to retrieve analyses.' });
  }
});

apiRouter.get('/analyses/:id', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const analysis = dbStore.getAnalysisById(req.user!.id, req.params.id);
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis report not found.' });
    }
    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch analysis.' });
  }
});

apiRouter.patch('/analyses/:id', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const { label, notes, status, incidentInteraction, incidentResponseActions } = req.body;
    const updated = dbStore.updateAnalysis(req.user!.id, req.params.id, {
      label,
      notes,
      status,
      incidentInteraction,
      incidentResponseActions,
    });

    if (!updated) {
      return res.status(404).json({ error: 'Analysis report not found.' });
    }

    res.json(updated);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to update analysis.' });
  }
});

apiRouter.delete('/analyses/:id', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const deleted = dbStore.deleteAnalysis(req.user!.id, req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: 'Analysis not found or unauthorized.' });
    }
    res.json({ success: true, message: 'Analysis deleted successfully.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to delete analysis.' });
  }
});

// --- Incident Response Submission ---
apiRouter.post('/analyses/:id/incident-response', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const { interaction, customActions } = req.body as {
      interaction: UserInteractionChoice;
      customActions?: string[];
    };

    if (!interaction || !INCIDENT_PLAYBOOK[interaction]) {
      return res.status(400).json({ error: 'Invalid interaction choice.' });
    }

    const playbook = INCIDENT_PLAYBOOK[interaction];
    const actions = customActions || playbook.immediateSteps;

    const updated = dbStore.updateAnalysis(req.user!.id, req.params.id, {
      incidentInteraction: interaction,
      incidentResponseActions: actions,
    });

    if (!updated) {
      return res.status(404).json({ error: 'Analysis not found.' });
    }

    res.json({
      analysis: updated,
      playbook,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to record incident response.' });
  }
});

// --- Dashboard Real Statistics ---
apiRouter.get('/dashboard/stats', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const stats = dbStore.getDashboardStats(req.user!.id);
    res.json(stats);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to calculate dashboard statistics.' });
  }
});

// --- Security Copilot Chat ---
apiRouter.get('/copilot/conversations', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const convos = dbStore.getCopilotConversations(req.user!.id);
    res.json(convos);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load conversations.' });
  }
});

apiRouter.post('/copilot/conversations', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const { title } = req.body;
    const convo = dbStore.getOrCreateCopilotConversation(req.user!.id, undefined, title);
    res.status(201).json(convo);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to create conversation.' });
  }
});

apiRouter.get('/copilot/conversations/:id/messages', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const messages = dbStore.getCopilotMessages(req.user!.id, req.params.id);
    res.json(messages);
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to load messages.' });
  }
});

// --- Streaming Security Copilot Chat (SSE) ---
apiRouter.post('/copilot/chat/stream', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { conversationId, message, relatedAnalysisId } = req.body as {
      conversationId?: string;
      message: string;
      relatedAnalysisId?: string;
    };

    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    const convo = dbStore.getOrCreateCopilotConversation(req.user!.id, conversationId, message.slice(0, 32));

    // Save user's question
    const userMsg = dbStore.addCopilotMessage(req.user!.id, convo.id, 'user', message.trim(), relatedAnalysisId);

    // Fetch conversation history for context (exclude current message)
    const allMessages = dbStore.getCopilotMessages(req.user!.id, convo.id);
    const history = allMessages
      .filter((m) => m.id !== userMsg.id)
      .slice(-8)
      .map((m) => ({
        role: m.role as 'user' | 'assistant',
        content: m.content,
      }));

    // Fetch related analysis context if provided
    let analysisContext = null;
    if (relatedAnalysisId) {
      analysisContext = dbStore.getAnalysisById(req.user!.id, relatedAnalysisId);
    }

    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    // Send initial ack event with message info
    res.write(`data: ${JSON.stringify({ type: 'start', conversationId: convo.id, userMessage: userMsg })}\n\n`);

    let fullAssistantText = '';
    let isAborted = false;

    req.on('close', () => {
      isAborted = true;
    });

    try {
      const generator = streamSecurityCopilot(history, message.trim(), analysisContext);
      for await (const chunk of generator) {
        if (isAborted) break;
        fullAssistantText += chunk;
        res.write(`data: ${JSON.stringify({ type: 'chunk', text: chunk })}\n\n`);
      }

      if (!isAborted) {
        const finalText = fullAssistantText.trim() || 'I have analyzed your situation. Please exercise immediate caution.';
        const assistantMsg = dbStore.addCopilotMessage(req.user!.id, convo.id, 'assistant', finalText, relatedAnalysisId);
        res.write(
          `data: ${JSON.stringify({
            type: 'done',
            conversationId: convo.id,
            assistantMessage: assistantMsg,
            userMessage: userMsg,
          })}\n\n`
        );
      }
    } catch (streamErr: any) {
      console.error('Error in streaming copilot response:', streamErr);
      if (!isAborted) {
        res.write(`data: ${JSON.stringify({ type: 'error', error: streamErr.message || 'Error generating response' })}\n\n`);
      }
    } finally {
      res.end();
    }
  } catch (err: any) {
    console.error('Error starting Security Copilot stream:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: err.message || 'Security Copilot is temporarily unavailable.' });
    } else {
      res.end();
    }
  }
});

apiRouter.post('/copilot/chat', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { conversationId, message, relatedAnalysisId } = req.body as {
      conversationId?: string;
      message: string;
      relatedAnalysisId?: string;
    };

    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    const convo = dbStore.getOrCreateCopilotConversation(req.user!.id, conversationId, message.slice(0, 32));

    // Save user's question
    const userMsg = dbStore.addCopilotMessage(req.user!.id, convo.id, 'user', message.trim(), relatedAnalysisId);

    // Fetch conversation history for context
    const allMessages = dbStore.getCopilotMessages(req.user!.id, convo.id);
    const history = allMessages
      .filter((m) => m.id !== userMsg.id)
      .slice(-8)
      .map((m) => ({
        role: m.role as 'user' | 'assistant',
        content: m.content,
      }));

    // Fetch related analysis context if provided
    let analysisContext = null;
    if (relatedAnalysisId) {
      analysisContext = dbStore.getAnalysisById(req.user!.id, relatedAnalysisId);
    }

    // Call Gemini Copilot with 20-second timeout guard
    const timeoutPromise = new Promise<string>((_, reject) =>
      setTimeout(() => reject(new Error('Security Copilot request timed out.')), 20000)
    );
    const assistantReply = await Promise.race([
      askSecurityCopilot(history, message.trim(), analysisContext),
      timeoutPromise,
    ]);

    // Save assistant reply
    const assistantMsg = dbStore.addCopilotMessage(req.user!.id, convo.id, 'assistant', assistantReply, relatedAnalysisId);

    res.json({
      conversationId: convo.id,
      userMessage: userMsg,
      assistantMessage: assistantMsg,
    });
  } catch (err: any) {
    console.error('Error in Security Copilot chat:', err);
    res.status(500).json({ error: err.message || 'Security Copilot is temporarily unavailable.' });
  }
});
