export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type IncidentStatus = 'ACTIVE' | 'TRIAGING' | 'CONTAINED' | 'MITIGATED' | 'CLOSED';

export type ActionStatus = 'PENDING' | 'EXECUTING' | 'COMPLETED' | 'FAILED';

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  sourceIp: string;
  destinationIp: string;
  host: string;
  user: string;
  timestamp: string;
  mitreTactic: string;
  mitreTechnique: string;
  techniqueId: string;
  status: AlertStatus;
  incidentId?: string;
  confidenceScore: number;
  rawLog?: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  relativeTime: string;
  tactic: string;
  technique: string;
  techniqueId: string;
  title: string;
  description: string;
  source: string;
  target: string;
  severity: Severity;
  command?: string;
  ioc?: {
    type: 'IP' | 'DOMAIN' | 'HASH' | 'REGISTRY' | 'PAYLOAD';
    value: string;
  };
  evidenceConfidence: number;
  phaseOrder: number;
}

export interface RecommendedAction {
  id: string;
  title: string;
  description: string;
  type: 'CONTAINMENT' | 'ERADICATION' | 'RECOVERY' | 'HARDENING';
  status: ActionStatus;
  target: string;
  riskLevel: 'LOW' | 'MED' | 'HIGH';
  executedAt?: string;
  executedBy?: string;
  playbookId?: string;
}

export interface RootCause {
  vector: string;
  cveId?: string;
  cveScore?: number;
  entryPoint: string;
  compromisedAccount: string;
  c2Server: string;
  c2Location: string;
  vulnerabilityDetails: string;
  detectionMechanism: string;
  initialPayload: string;
  firstObserved: string;
  primary?: string;
  confidence?: number;
  confidence_status?: string;
  confidenceStatus?: string;
  requires_analyst_verification?: boolean;
  requiresAnalystVerification?: boolean;
  reasoning?: string;
  contributingFactors?: string[];
}

export interface AffectedAsset {
  id: string;
  name: string;
  ip: string;
  os: string;
  role: 'Domain Controller' | 'Production DB' | 'API Gateway' | 'Dev Workstation' | 'Cloud IAM' | 'K8s Cluster';
  status: 'COMPROMISED' | 'ISOLATED' | 'MONITORED' | 'CLEAN';
  criticality: 'TIER 0' | 'TIER 1' | 'TIER 2';
}

export interface AiAnalysisResult {
  analyzedAt: string;
  confidenceScore: number;
  threatClassification: string;
  mitreCoverage: string[];
  keyFindings: string[];
  killChainStage: string;
  blastRadius: string;
  urgency: 'IMMEDIATE' | 'HIGH' | 'ELEVATED';
  suggestedContainmentSteps: string[];
  summary: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  threatActor: string;
  threatActorOrigin?: string;
  detectedAt: string;
  updatedAt: string;
  leadAnalyst: string;
  impactSummary: string;
  affectedAssets: AffectedAsset[];
  rootCause: RootCause;
  recommendedActions: RecommendedAction[];
  timelineEvents: TimelineEvent[];
  aiAnalysis?: AiAnalysisResult;
  associatedAlertCount: number;
  riskScore?: number;
  riskLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  riskBreakdown?: {
    criticalAlert?: boolean;
    privilegeEscalation?: boolean;
    dataAccess?: boolean;
    multipleDevices?: boolean;
    multipleIps?: boolean;
  };
  mlFeatures?: {
    alertCount: number;
    criticalAlerts: number;
    uniqueDevices: number;
    uniqueIps: number;
    powershellPresent: boolean;
    privilegePresent: boolean;
    phishingPresent: boolean;
    dataAccessPresent: boolean;
    severityNumeric?: number;
  };
}

export interface KpiMetrics {
  activeIncidents: number;
  criticalAlerts: number;
  mttdMinutes: number;
  mttrMinutes: number;
  threatLevel: 'DEFCON 1' | 'DEFCON 2' | 'DEFCON 3' | 'DEFCON 4';
  compromisedAssets: number;
  blockedAttacks24h: number;
}

export interface UserSession {
  id: string;
  name: string;
  email: string;
  callsign: string;
  role: 'Tier 3 Lead Threat Hunter' | 'Tier 2 Incident Responder' | 'Tier 1 Triage Analyst' | 'SOC Commander';
  clearance: 'TOP SECRET // NOFORN' | 'SECRET // DEF' | 'CONFIDENTIAL';
  token: string;
  avatarUrl?: string;
}

export interface RestApiLog {
  id: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  endpoint: string;
  status: number;
  latencyMs: number;
  timestamp: string;
  requestBody?: any;
  responsePreview?: any;
}
