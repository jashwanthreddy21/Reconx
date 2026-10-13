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
  approvedHostnames: string[];
  approvedIpsAndCidrs: string[];
  permittedPorts: string[];
  startDate: string;
  endDate: string;
  authorizationConfirmed: boolean;
  authReference?: string;
  authorizedBy?: string;
}

export interface ToolConfig {
  subfinder: boolean;
  dnsx: boolean;
  httpx: boolean;
  nmap: boolean;
  whatweb: boolean;
  concurrency: number;
  rateLimit: number;
  timeoutSeconds: number;
  dnsRecordTypes: string[];
  nmapProfile: 'quick' | 'top100' | 'top1000' | 'custom';
  executionEnvironment: 'in_browser_doh' | 'local_cli_agent' | 'lab_simulation';
}

export interface AssessmentStats {
  assetsCount: number;
  subdomainsCount: number;
  dnsRecordsCount: number;
  endpointsCount: number;
  servicesCount: number;
  technologiesCount: number;
  findingsCount: number;
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
  | 'endpoint'
  | 'service'
  | 'technology';

export interface Asset {
  id: string;
  assessmentId: string;
  ownerId: string;
  canonicalName: string;
  assetType: AssetType;
  discoverySource: string;
  status: 'active' | 'resolved' | 'unresponsive' | 'observed';
  firstSeen: string;
  lastSeen: string;
  ipAddress?: string;
  parentHostname?: string;
  metadata?: Record<string, any>;
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
  toolName: 'Subfinder' | 'dnsx' | 'httpx' | 'Nmap' | 'WhatWeb';
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
