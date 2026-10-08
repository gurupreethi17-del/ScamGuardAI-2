import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ThreatAnalysis, DashboardStats, CopilotConversation, CopilotMessage } from '../../types/index.ts';

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  role: string;
  createdAt: string;
}

interface DatabaseStructure {
  users: UserRecord[];
  analyses: ThreatAnalysis[];
  copilotConversations: CopilotConversation[];
  copilotMessages: CopilotMessage[];
}

function resolveDataPaths() {
  const isVercel = Boolean(process.env.VERCEL);
  const rootDataDir = path.resolve(process.cwd(), '.data');
  const targetDir = isVercel ? path.join('/tmp', '.data') : rootDataDir;
  const targetFile = path.join(targetDir, 'scamguard_db.json');
  const sourceFile = path.join(rootDataDir, 'scamguard_db.json');
  return { targetDir, targetFile, sourceFile, isVercel };
}

function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password + 'sg_salt_2026').digest('hex');
}

export class DataStore {
  private data: DatabaseStructure = {
    users: [],
    analyses: [],
    copilotConversations: [],
    copilotMessages: [],
  };

  constructor() {
    this.init();
  }

  private init() {
    try {
      const { targetDir, targetFile, sourceFile, isVercel } = resolveDataPaths();
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }

      // On Vercel, copy seed database if present in source and not yet in /tmp
      if (isVercel && !fs.existsSync(targetFile) && fs.existsSync(sourceFile)) {
        try {
          fs.copyFileSync(sourceFile, targetFile);
        } catch {
          // ignore copy error
        }
      }

      const fileToRead = fs.existsSync(targetFile)
        ? targetFile
        : (fs.existsSync(sourceFile) ? sourceFile : null);

      if (fileToRead) {
        const raw = fs.readFileSync(fileToRead, 'utf-8');
        const loaded = JSON.parse(raw);
        this.data = {
          users: Array.isArray(loaded.users) ? loaded.users : [],
          analyses: Array.isArray(loaded.analyses) ? loaded.analyses : [],
          copilotConversations: Array.isArray(loaded.copilotConversations) ? loaded.copilotConversations : [],
          copilotMessages: Array.isArray(loaded.copilotMessages) ? loaded.copilotMessages : [],
        };
        this.data.analyses = this.data.analyses.map((analysis) => ({
          ...analysis,
          classification: analysis.classification || (
            Number(analysis.riskScore) >= 50 ? 'SCAM' :
              Number(analysis.riskScore) >= 25 ? 'SUSPICIOUS' : 'SAFE'
          ),
        }));
      } else {
        this.data = {
          users: [],
          analyses: [],
          copilotConversations: [],
          copilotMessages: [],
        };
        this.persist();
      }
    } catch (err) {
      console.warn('Initializing in-memory database fallback:', err);
      this.data = {
        users: [],
        analyses: [],
        copilotConversations: [],
        copilotMessages: [],
      };
    }
  }

  private persist() {
    try {
      const { targetDir, targetFile } = resolveDataPaths();
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }
      fs.writeFileSync(targetFile, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (err) {
      console.error('Error persisting database:', err);
    }
  }

  // --- Users ---
  public createUser(email: string, password: string, name: string): UserRecord {
    const existing = this.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      throw new Error('User already exists with this email address.');
    }

    const newUser: UserRecord = {
      id: `usr_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      email: email.toLowerCase().trim(),
      passwordHash: hashPassword(password),
      name: name.trim() || 'User',
      role: 'user',
      createdAt: new Date().toISOString(),
    };

    this.data.users.push(newUser);
    this.persist();
    return newUser;
  }

  public verifyUser(email: string, password: string): UserRecord | null {
    const user = this.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase().trim());
    if (!user) return null;
    if (user.passwordHash !== hashPassword(password)) return null;
    return user;
  }

  public findUserById(id: string): UserRecord | null {
    return this.data.users.find((u) => u.id === id) || null;
  }

  public findUserByEmail(email: string): UserRecord | null {
    return this.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase().trim()) || null;
  }

  // --- Analyses (Isolated by userId) ---
  public saveAnalysis(userId: string, analysisData: Omit<ThreatAnalysis, 'id' | 'userId' | 'createdAt' | 'status'>): ThreatAnalysis {
    const newAnalysis: ThreatAnalysis = {
      ...analysisData,
      id: `ana_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      userId,
      createdAt: new Date().toISOString(),
      status: 'active',
      notes: analysisData.notes || '',
      label: analysisData.label || analysisData.threatType || 'Analysis',
    };

    this.data.analyses.unshift(newAnalysis);
    this.persist();
    return newAnalysis;
  }

  public getAnalyses(
    userId: string,
    filters: {
      search?: string;
      riskLevel?: string;
      threatType?: string;
      analysisType?: string;
      status?: string;
      sort?: 'newest' | 'oldest' | 'highest_risk' | 'lowest_risk';
      page?: number;
      limit?: number;
    } = {}
  ): { items: ThreatAnalysis[]; total: number; page: number; totalPages: number } {
    let items = this.data.analyses.filter((a) => a.userId === userId);

    // Status filter (active vs archived, default active)
    if (filters.status && filters.status !== 'all') {
      items = items.filter((a) => a.status === filters.status);
    } else if (!filters.status) {
      items = items.filter((a) => a.status !== 'archived');
    }

    // Risk level filter
    if (filters.riskLevel && filters.riskLevel !== 'ALL') {
      items = items.filter((a) => a.riskLevel.toUpperCase() === filters.riskLevel?.toUpperCase());
    }

    // Analysis type filter
    if (filters.analysisType && filters.analysisType !== 'ALL') {
      items = items.filter((a) => a.type.toLowerCase() === filters.analysisType?.toLowerCase());
    }

    // Threat type filter
    if (filters.threatType && filters.threatType !== 'ALL') {
      items = items.filter((a) => a.threatType.toLowerCase().includes(filters.threatType!.toLowerCase()));
    }

    // Search query
    if (filters.search && filters.search.trim()) {
      const q = filters.search.toLowerCase().trim();
      items = items.filter(
        (a) =>
          a.title.toLowerCase().includes(q) ||
          a.summary.toLowerCase().includes(q) ||
          a.threatType.toLowerCase().includes(q) ||
          a.content.toLowerCase().includes(q) ||
          (a.label && a.label.toLowerCase().includes(q))
      );
    }

    // Sort
    const sort = filters.sort || 'newest';
    if (sort === 'newest') {
      items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    } else if (sort === 'oldest') {
      items.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
    } else if (sort === 'highest_risk') {
      items.sort((a, b) => b.riskScore - a.riskScore);
    } else if (sort === 'lowest_risk') {
      items.sort((a, b) => a.riskScore - b.riskScore);
    }

    const total = items.length;
    const page = Math.max(1, filters.page || 1);
    const limit = Math.max(1, filters.limit || 10);
    const totalPages = Math.ceil(total / limit) || 1;
    const paginatedItems = items.slice((page - 1) * limit, page * limit);

    return {
      items: paginatedItems,
      total,
      page,
      totalPages,
    };
  }

  public getAnalysisById(userId: string, id: string): ThreatAnalysis | null {
    const analysis = this.data.analyses.find((a) => a.id === id && a.userId === userId);
    return analysis || null;
  }

  public updateAnalysis(
    userId: string,
    id: string,
    updates: Partial<Pick<ThreatAnalysis, 'label' | 'notes' | 'status' | 'incidentInteraction' | 'incidentResponseActions'>>
  ): ThreatAnalysis | null {
    const index = this.data.analyses.findIndex((a) => a.id === id && a.userId === userId);
    if (index === -1) return null;

    this.data.analyses[index] = {
      ...this.data.analyses[index],
      ...updates,
    };

    this.persist();
    return this.data.analyses[index];
  }

  public deleteAnalysis(userId: string, id: string): boolean {
    const initialLen = this.data.analyses.length;
    this.data.analyses = this.data.analyses.filter((a) => !(a.id === id && a.userId === userId));
    const deleted = this.data.analyses.length < initialLen;
    if (deleted) this.persist();
    return deleted;
  }

  // --- Real Dashboard Statistics (Calculated strictly from user's data) ---
  public getDashboardStats(userId: string): DashboardStats {
    const userAnalyses = this.data.analyses.filter((a) => a.userId === userId && a.status !== 'archived');
    const totalAnalyses = userAnalyses.length;

    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    const oneWeekAgo = Date.now() - 7 * 86400000;
    let thisWeekCount = 0;

    const typeCounts: Record<string, number> = {};

    for (const a of userAnalyses) {
      if (a.riskLevel === 'CRITICAL') criticalCount++;
      else if (a.riskLevel === 'HIGH') highCount++;
      else if (a.riskLevel === 'MEDIUM') mediumCount++;
      else lowCount++;

      if (new Date(a.createdAt).getTime() >= oneWeekAgo) {
        thisWeekCount++;
      }

      const t = a.threatType || 'Unclassified Threat';
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    }

    const threatTypeBreakdown = Object.entries(typeCounts)
      .map(([type, count]) => ({
        type,
        count,
        percentage: totalAnalyses > 0 ? Math.round((count / totalAnalyses) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);

    const recentAnalyses = [...userAnalyses]
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 5);

    return {
      totalAnalyses,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      thisWeekCount,
      threatTypeBreakdown,
      recentAnalyses,
    };
  }

  // --- Security Copilot Chat History ---
  public getCopilotConversations(userId: string): CopilotConversation[] {
    return this.data.copilotConversations
      .filter((c) => c.userId === userId)
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
  }

  public getOrCreateCopilotConversation(userId: string, conversationId?: string, title?: string): CopilotConversation {
    if (conversationId) {
      const existing = this.data.copilotConversations.find((c) => c.id === conversationId && c.userId === userId);
      if (existing) return existing;
    }

    const newConvo: CopilotConversation = {
      id: `conv_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      userId,
      title: title || 'New Security Triage Session',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this.data.copilotConversations.unshift(newConvo);
    this.persist();
    return newConvo;
  }

  public getCopilotMessages(userId: string, conversationId: string): CopilotMessage[] {
    const convo = this.data.copilotConversations.find((c) => c.id === conversationId && c.userId === userId);
    if (!convo) return [];

    return this.data.copilotMessages
      .filter((m) => m.conversationId === conversationId)
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  }

  public addCopilotMessage(
    userId: string,
    conversationId: string,
    role: 'user' | 'assistant',
    content: string,
    relatedAnalysisId?: string
  ): CopilotMessage {
    const convo = this.data.copilotConversations.find((c) => c.id === conversationId && c.userId === userId);
    if (!convo) {
      throw new Error('Conversation not found or unauthorized.');
    }

    const message: CopilotMessage = {
      id: `msg_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      conversationId,
      role,
      content,
      createdAt: new Date().toISOString(),
      relatedAnalysisId,
    };

    this.data.copilotMessages.push(message);
    convo.updatedAt = message.createdAt;
    this.persist();
    return message;
  }
}

export const dbStore = new DataStore();
