/**
 * ScamGuard AI Database Schema
 * PostgreSQL / Drizzle ORM representation
 */
export interface DbUser {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  role: string;
  createdAt: string;
}

export interface DbAnalysis {
  id: string;
  userId: string;
  createdAt: string;
  title: string;
  type: string;
  content: string;
  metadataJson: string; // JSON string
  riskScore: number;
  riskLevel: string;
  classification: string;
  threatType: string;
  confidence: number;
  summary: string;
  explanation: string;
  indicatorsJson: string; // JSON string
  socialEngineeringTacticsJson: string; // JSON string
  technicalSignalsJson: string; // JSON string
  recommendedActionsJson: string; // JSON string
  preventionTipsJson: string; // JSON string
  userSafetyWarning: string;
  incidentInteraction: string | null;
  incidentResponseActionsJson: string; // JSON string
  status: string; // 'active' | 'archived'
  notes: string;
  label: string;
}

export interface DbCopilotConversation {
  id: string;
  userId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
}

export interface DbCopilotMessage {
  id: string;
  conversationId: string;
  userId: string;
  role: string;
  content: string;
  createdAt: string;
  relatedAnalysisId: string | null;
}
