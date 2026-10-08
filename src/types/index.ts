export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatClassification = 'SAFE' | 'SUSPICIOUS' | 'SCAM';

export type AnalysisType = 'message' | 'email' | 'url' | 'screenshot' | 'qr';

export type UserInteractionChoice =
  | 'viewed_only'
  | 'clicked_link'
  | 'entered_password'
  | 'shared_otp'
  | 'bank_details'
  | 'transferred_money'
  | 'downloaded_file'
  | 'personal_info'
  | 'unsure';

export interface ThreatIndicator {
  name: string;
  severity: RiskLevel;
  description: string;
}

export interface ThreatAnalysis {
  id: string;
  userId: string;
  createdAt: string;
  title: string;
  type: AnalysisType;
  content: string;
  metadata?: {
    sender?: string;
    subject?: string;
    url?: string;
    qrDecodedText?: string;
    imageMimeType?: string;
    extractedLinks?: string[];
  };
  riskScore: number; // 0 - 100
  riskLevel: RiskLevel;
  /** Optional for compatibility with analysis records saved before classification was added. */
  classification?: ThreatClassification;
  threatType: string;
  confidence: number; // 0 - 100
  summary: string;
  explanation: string;
  indicators: ThreatIndicator[];
  socialEngineeringTactics: string[];
  technicalSignals: string[];
  recommendedActions: string[];
  preventionTips: string[];
  userSafetyWarning: string;
  incidentInteraction?: UserInteractionChoice;
  incidentResponseActions?: string[];
  status: 'active' | 'archived';
  notes?: string;
  label?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  role?: string;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export interface DashboardStats {
  totalAnalyses: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  thisWeekCount: number;
  threatTypeBreakdown: Array<{
    type: string;
    count: number;
    percentage: number;
  }>;
  recentAnalyses: ThreatAnalysis[];
}

export interface CopilotMessage {
  id: string;
  conversationId: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
  relatedAnalysisId?: string;
}

export interface CopilotConversation {
  id: string;
  userId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentPlaybookItem {
  key: UserInteractionChoice;
  title: string;
  severity: 'MILD' | 'ELEVATED' | 'URGENT' | 'CRITICAL';
  headline: string;
  summary: string;
  immediateSteps: string[];
  followUpSteps: string[];
  reportingChannels: string[];
  warningNotice: string;
}
