export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface UserProfile {
  id: string;
  email: string;
  displayName: string;
  photoURL?: string;
  role: UserRole;
  createdAt: string;
  updatedAt?: string;
}

export type AssessmentType = 'passive' | 'active' | 'mixed';
export type AssessmentStatus =
  | 'draft'
  | 'queued'
  | 'validating'
  | 'running'
  | 'partially_completed'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface ScopeRule {
  rootDomain: string;
  approvedHostnames?: string[];
  approvedIpsAndCidrs?: string[];
  permittedPorts?: string[];
  startDate?: string;
  endDate?: string;
  authorizationConfirmed: boolean;
  authReference?: string;
  authorizedBy?: string;
  allowedSubdomains?: boolean;
  ipRanges?: string[];
  exclusions?: string[];
  allowActiveProbing?: boolean;
  allowPortScanning?: boolean;
}

export interface ToolConfig {
  subfinder: boolean;
  amass?: boolean;
  dnsx: boolean;
  httpx: boolean;
  nmap: boolean;
  whatweb: boolean;
  concurrency?: number;
  rateLimit?: number;
  rateLimitRps?: number;
  timeoutSeconds: number;
  dnsRecordTypes?: string[];
  nmapProfile?: 'quick' | 'top100' | 'top1000' | 'custom' | 'service_detection';
  executionEnvironment?: 'in_browser_doh' | 'local_cli_agent' | 'lab_simulation';
}

export interface AssessmentStats {
  totalAssets?: number;
  assetsCount?: number;
  subdomainsCount: number;
  ipAddressesCount?: number;
  ipsCount?: number;
  dnsRecordsCount?: number;
  liveEndpointsCount?: number;
  endpointsCount?: number;
  openPortsCount?: number;
  servicesCount?: number;
  technologiesCount?: number;
  findingsCount: number;
  relationshipsCount?: number;
  potentiallyExposedCount?: number;
}

export interface Assessment {
  id: string;
  name: string;
  clientName: string;
  description: string;
  ownerId: string;
  ownerEmail: string;
  type: AssessmentType;
  status: AssessmentStatus;
  scope: ScopeRule;
  toolConfig: ToolConfig;
  stats: AssessmentStats;
  isDemo?: boolean;
  createdAt: string;
  updatedAt: string;
}

export type AssetType =
  | 'root_domain'
  | 'subdomain'
  | 'ip_address'
  | 'port'
  | 'endpoint'
  | 'service'
  | 'technology';

export interface Asset {
  id: string;
  assessmentId: string;
  ownerId: string;
  canonicalName: string;
  assetValue?: string;
  normalizedValue?: string;
  assetType: AssetType;
  discoverySource: string;
  sources?: string[];
  status: 'active' | 'resolved' | 'unresponsive' | 'observed';
  firstSeen: string;
  lastSeen: string;
  ipAddress?: string;
  parentHostname?: string;
  confidenceScore?: number;
  isPotentiallyExposed?: boolean;
  isExposedRisk?: boolean;
  riskReason?: string;
  exposureReasons?: string[];
  riskLevel?: FindingSeverity;
  openPorts?: number[];
  detectedServices?: string[];
  detectedTechnologies?: string[];
  associatedDomains?: string[];
  metadata?: Record<string, any>;
}

export type RelationshipType =
  | 'HAS_SUBDOMAIN'
  | 'RESOLVES_TO'
  | 'EXPOSES_PORT'
  | 'RUNS_SERVICE'
  | 'SERVES_ENDPOINT'
  | 'USES_TECHNOLOGY'
  | 'CNAME_TO';

export interface AssetEvidence {
  id: string;
  assessmentId: string;
  ownerId: string;
  assetId: string;
  sourceTool: string;
  rawOutputReference: string;
  discoveredAt: string;
}

export interface AssetRelationship {
  id: string;
  assessmentId: string;
  ownerId: string;
  sourceAssetId: string;
  sourceAssetName: string;
  sourceAssetType: AssetType;
  sourceName?: string;
  sourceType?: AssetType;
  targetAssetId: string;
  targetAssetName: string;
  targetAssetType: AssetType;
  targetName?: string;
  targetType?: AssetType;
  relationshipType: RelationshipType;
  confidenceScore: number;
  evidenceId: string;
  evidenceSummary: string;
  evidenceSnippet?: string;
  sourceTool: string;
  isSuspicious?: boolean;
  suspicionReason?: string;
  discoveredAt: string;
}

export interface CorrelationAnomaly {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  affectedAssets: string[];
  sourceTools: string[];
  sourceTool?: string;
  confidenceScore: number;
  evidence: string;
}

export interface AssetCorrelation {
  id: string;
  assessmentId: string;
  ownerId: string;
  normalizedAssetsCount: number;
  duplicatesMergedCount: number;
  relationshipsCount: number;
  suspiciousRelationshipsCount: number;
  potentiallyExposedCount: number;
  totalAssets: number;
  uniqueDomains: number;
  uniqueSubdomains: number;
  uniqueIps: number;
  openPortsCount: number;
  detectedServicesCount: number;
  detectedTechnologiesCount: number;
  correlatedRelationshipsCount: number;
  potentiallyExposedAssetsCount: number;
  anomalies: CorrelationAnomaly[];
  createdAt: string;
  generatedAt: string;
}

export interface SnapshotAssetDigest {
  stableId: string;
  canonicalName: string;
  normalizedValue: string;
  assetType: AssetType;
  status: string;
  discoverySource: string;
  ipAddress?: string;
  ports?: number[];
  services?: string[];
  technologies?: string[];
  statusCode?: number;
  dnsRecords?: string[];
  version?: string;
  metadataHash: string;
}

export interface AssessmentSnapshot {
  id: string;
  assessmentId: string;
  assessmentName: string;
  rootDomain: string;
  ownerId: string;
  snapshotTimestamp: string;
  completionStatus: AssessmentStatus;
  assetCount: number;
  relationshipCount: number;
  subdomainsCount: number;
  ipCount: number;
  openPortsCount: number;
  servicesCount: number;
  endpointsCount: number;
  technologiesCount: number;
  findingsCount: number;
  assetDigests: SnapshotAssetDigest[];
  assetMap: Record<string, SnapshotAssetDigest>;
  countsByType: Record<string, number>;
}

export type AssetChangeType = 'NEW' | 'NOT_OBSERVED' | 'MODIFIED';

export interface AssetChange {
  id: string;
  assessmentId: string;
  previousAssessmentId: string;
  ownerId: string;
  assetId: string;
  assetName: string;
  canonicalName: string;
  normalizedValue: string;
  assetType: AssetType;
  changeType: AssetChangeType;
  changeCategory: string;
  changeDescription: string;
  observationNote: string;
  previousValue?: string;
  newValue?: string;
  previousState?: Record<string, any>;
  currentState?: Record<string, any>;
  detectedAt: string;
  evidenceReference: string;
  sourceTool: string;
  confidenceNote?: string;
}

export interface AIAnalysis {
  id: string;
  assessmentId: string;
  ownerId: string;
  provider: 'gemini_ai' | 'deterministic_fallback';
  mode: 'ai_gemini' | 'deterministic_fallback';
  modelUsed: string;
  executiveSummary: string;
  relationshipInsights: string[];
  unusualExposurePatterns: string[];
  riskyConfigurations: string[];
  prioritizedReviewList: Array<{
    rank: number;
    priority: FindingSeverity;
    assetName: string;
    assetType: string;
    reason: string;
    rationale: string;
    safeInvestigationStep: string;
    confidenceScore: number;
    authorizedNextSteps: string[];
  }>;
  generatedAt: string;
}

export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT' | 'SOA' | 'PTR';

export interface DnsRecord {
  id: string;
  assessmentId: string;
  ownerId: string;
  hostname: string;
  recordType: DnsRecordType;
  value: string;
  ttl?: number;
  source: string;
  timestamp: string;
}

export interface WebEndpoint {
  id: string;
  assessmentId: string;
  ownerId: string;
  url: string;
  hostname: string;
  port: number;
  protocol: 'http' | 'https';
  statusCode: number;
  title: string;
  ip: string;
  technologies: string[];
  tlsInfo?: {
    valid?: boolean;
    issuer?: string;
    subject?: string;
    expires?: string;
  };
  headers?: Record<string, string>;
  timestamp: string;
}

export interface NetworkService {
  id: string;
  assessmentId: string;
  ownerId: string;
  host: string;
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered' | 'unknown';
  serviceName: string;
  version?: string;
  toolSource: string;
  timestamp: string;
}

export type FindingSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type FindingConfidence = 'tentative' | 'firm' | 'certain';
export type VerificationStatus = 'observed_fact' | 'potential_risk' | 'verified';

export interface Finding {
  id: string;
  assessmentId: string;
  ownerId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  category: string;
  assetRef: string;
  evidence: string;
  sourceTool: string;
  remediation: string;
  verificationStatus: VerificationStatus;
  firstSeen: string;
  lastSeen: string;
}

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScanJob {
  id: string;
  assessmentId: string;
  ownerId: string;
  toolName: 'Subfinder' | 'Amass' | 'dnsx' | 'httpx' | 'Nmap' | 'WhatWeb';
  status: JobStatus;
  durationMs: number;
  returnCode: number;
  logs: string[];
  errorSummary?: string;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  assessmentId?: string;
  ownerId: string;
  actorEmail: string;
  action: string;
  details: string;
  timestamp: string;
}

export interface ToolDiagnosticInfo {
  toolName: string;
  displayName: string;
  category: 'Passive Recon' | 'DNS Resolution' | 'HTTP Prober' | 'Port & Service' | 'Fingerprinter';
  status: 'Ready' | 'Not installed' | 'External Host' | 'Lab Emulated';
  version: string;
  supportedFormats: string[];
  lastTest: string;
  requiredPermissions: string;
  integrationGuide: string;
  commandExample: string;
}
