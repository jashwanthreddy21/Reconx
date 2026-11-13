import express from 'express';
import dns from 'dns/promises';
import net from 'net';
import tls from 'tls';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';
import type {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  AssetRelationship,
  AssetEvidence,
  AssetCorrelation,
  AssessmentSnapshot,
  AssetChange,
  AIAnalysis,
  IpGeoLocation,
} from './src/types/index.ts';
import {
  runAssetCorrelationEngine,
  generateDeterministicAIAnalysis,
} from './src/services/assetCorrelationEngine.ts';
import {
  createAssessmentSnapshot,
  compareAssessmentSnapshots,
} from './src/services/changeDetectionEngine.ts';
import {
  isValidIpv4,
  isPrivateOrNonRoutableIp,
  mapCountryToGeoRegion,
  classifyReservedOrRirFallback,
} from './src/services/ipGeolocationService.ts';

export const app = express();
app.use(express.json({ limit: '10mb' }));

const DEFAULT_APP_PORT = 3000;

// ============================================================================
// IN-MEMORY INTELLIGENCE STORE (Pre-seeded with Baseline & Latest Assessments)
// ============================================================================

interface StoredAssessmentBundle {
  assessment: Assessment;
  rawAssets: Asset[];
  dnsRecords: DnsRecord[];
  endpoints: WebEndpoint[];
  services: NetworkService[];
  findings: Finding[];
  correlatedAssets: Asset[];
  relationships: AssetRelationship[];
  evidences: AssetEvidence[];
  correlation: AssetCorrelation;
  snapshot: AssessmentSnapshot;
  aiAnalysis: AIAnalysis;
}

const assessmentStore = new Map<string, StoredAssessmentBundle>();
let latestChangesCache: AssetChange[] = [];

function initializeSeedAssessments() {
  const baselineAssessment: Assessment = {
    id: 'asm_baseline_01',
    name: 'Q1 Baseline External Perimeter Scan',
    clientName: 'ACME Corp Security Operations',
    description: 'Initial baseline external perimeter reconnaissance assessment.',
    ownerId: 'system',
    ownerEmail: 'secops@acme-corp.io',
    type: 'mixed',
    status: 'completed',
    scope: {
      rootDomain: 'acme-corp.io',
      authorizationConfirmed: true,
      authorizedBy: 'secops@acme-corp.io',
      authReference: 'ROE-2026-01',
      allowedSubdomains: true,
      allowActiveProbing: true,
      allowPortScanning: true,
    },
    toolConfig: {
      subfinder: true,
      amass: true,
      dnsx: true,
      httpx: true,
      nmap: true,
      whatweb: true,
      timeoutSeconds: 60,
    },
    stats: {
      subdomainsCount: 3,
      ipsCount: 2,
      openPortsCount: 1,
      endpointsCount: 1,
      technologiesCount: 2,
      findingsCount: 0,
    },
    createdAt: '2026-09-01T10:00:00.000Z',
    updatedAt: '2026-09-01T10:05:00.000Z',
  };

  const baselineRawAssets: Asset[] = [
    {
      id: 'ast_base_legacy',
      assessmentId: 'asm_baseline_01',
      ownerId: 'system',
      canonicalName: 'legacy-vpn.acme-corp.io',
      assetType: 'subdomain',
      discoverySource: 'Subfinder',
      status: 'active',
      firstSeen: '2026-09-01T10:01:00.000Z',
      lastSeen: '2026-09-01T10:04:00.000Z',
    },
  ];

  const baselineDns: DnsRecord[] = [
    {
      id: 'dns_b1',
      assessmentId: 'asm_baseline_01',
      ownerId: 'system',
      hostname: 'api.acme-corp.io',
      recordType: 'A',
      value: '203.0.113.10',
      ttl: 300,
      source: 'dnsx',
      timestamp: '2026-09-01T10:01:00.000Z',
    },
    {
      id: 'dns_b2',
      assessmentId: 'asm_baseline_01',
      ownerId: 'system',
      hostname: 'legacy-vpn.acme-corp.io',
      recordType: 'A',
      value: '203.0.113.55',
      ttl: 300,
      source: 'dnsx',
      timestamp: '2026-09-01T10:01:30.000Z',
    },
  ];

  const baselineEndpoints: WebEndpoint[] = [
    {
      id: 'ep_b1',
      assessmentId: 'asm_baseline_01',
      ownerId: 'system',
      url: 'https://api.acme-corp.io',
      hostname: 'api.acme-corp.io',
      port: 443,
      protocol: 'https',
      statusCode: 200,
      title: 'ACME Core API Gateway',
      ip: '203.0.113.10',
      technologies: ['Nginx', 'Node.js'],
      timestamp: '2026-09-01T10:02:00.000Z',
    },
  ];

  const baselineServices: NetworkService[] = [
    {
      id: 'svc_b1',
      assessmentId: 'asm_baseline_01',
      ownerId: 'system',
      host: 'api.acme-corp.io',
      ip: '203.0.113.10',
      port: 443,
      protocol: 'tcp',
      state: 'open',
      serviceName: 'https',
      version: 'nginx 1.24.0',
      toolSource: 'Nmap',
      timestamp: '2026-09-01T10:03:00.000Z',
    },
  ];

  const baselineCorrelated = runAssetCorrelationEngine(
    baselineAssessment,
    baselineRawAssets,
    baselineDns,
    baselineEndpoints,
    baselineServices,
    []
  );

  const baselineSnapshot = createAssessmentSnapshot(
    baselineAssessment,
    baselineCorrelated.normalizedAssets,
    baselineCorrelated.relationships,
    baselineDns,
    baselineEndpoints,
    baselineServices
  );

  const baselineAI = generateDeterministicAIAnalysis(
    baselineAssessment,
    baselineCorrelated.normalizedAssets,
    baselineCorrelated.relationships,
    baselineCorrelated.correlationSummary,
    []
  );

  assessmentStore.set(baselineAssessment.id, {
    assessment: baselineAssessment,
    rawAssets: baselineRawAssets,
    dnsRecords: baselineDns,
    endpoints: baselineEndpoints,
    services: baselineServices,
    findings: [],
    correlatedAssets: baselineCorrelated.normalizedAssets,
    relationships: baselineCorrelated.relationships,
    evidences: baselineCorrelated.evidences,
    correlation: baselineCorrelated.correlationSummary,
    snapshot: baselineSnapshot,
    aiAnalysis: baselineAI,
  });

  // Latest Assessment
  const latestAssessment: Assessment = {
    id: 'asm_latest_02',
    name: 'Q2 Continuous Attack Surface Verification',
    clientName: 'ACME Corp Security Operations',
    description: 'Follow-up perimeter verification assessment.',
    ownerId: 'system',
    ownerEmail: 'secops@acme-corp.io',
    type: 'mixed',
    status: 'completed',
    scope: {
      rootDomain: 'acme-corp.io',
      authorizationConfirmed: true,
      authorizedBy: 'secops@acme-corp.io',
      authReference: 'ROE-2026-02',
      allowedSubdomains: true,
      allowActiveProbing: true,
      allowPortScanning: true,
    },
    toolConfig: {
      subfinder: true,
      amass: true,
      dnsx: true,
      httpx: true,
      nmap: true,
      whatweb: true,
      timeoutSeconds: 60,
    },
    stats: {
      subdomainsCount: 4,
      ipsCount: 2,
      openPortsCount: 3,
      endpointsCount: 2,
      technologiesCount: 4,
      findingsCount: 1,
    },
    createdAt: '2026-10-01T14:00:00.000Z',
    updatedAt: '2026-10-01T14:06:00.000Z',
  };

  const latestRawAssets: Asset[] = [
    {
      id: 'ast_lat_api_subfinder',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      canonicalName: 'api.acme-corp.io',
      assetType: 'subdomain',
      discoverySource: 'Subfinder',
      status: 'active',
      firstSeen: '2026-09-01T10:01:00.000Z',
      lastSeen: '2026-10-01T14:05:00.000Z',
    },
    {
      id: 'ast_lat_api_amass',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      canonicalName: 'API.ACME-CORP.IO.',
      assetType: 'subdomain',
      discoverySource: 'Amass',
      status: 'active',
      firstSeen: '2026-09-01T10:01:00.000Z',
      lastSeen: '2026-10-01T14:05:00.000Z',
    },
    {
      id: 'ast_lat_staging',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      canonicalName: 'staging-admin.acme-corp.io',
      assetType: 'subdomain',
      discoverySource: 'Subfinder, dnsx',
      status: 'active',
      firstSeen: '2026-10-01T14:01:00.000Z',
      lastSeen: '2026-10-01T14:05:00.000Z',
    },
  ];

  const latestDns: DnsRecord[] = [
    {
      id: 'dns_l1',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      hostname: 'api.acme-corp.io',
      recordType: 'A',
      value: '203.0.113.25',
      ttl: 300,
      source: 'dnsx',
      timestamp: '2026-10-01T14:02:00.000Z',
    },
    {
      id: 'dns_l2',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      hostname: 'staging-admin.acme-corp.io',
      recordType: 'A',
      value: '203.0.113.99',
      ttl: 60,
      source: 'dnsx',
      timestamp: '2026-10-01T14:02:10.000Z',
    },
  ];

  const latestEndpoints: WebEndpoint[] = [
    {
      id: 'ep_l1',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      url: 'https://api.acme-corp.io',
      hostname: 'api.acme-corp.io',
      port: 443,
      protocol: 'https',
      statusCode: 200,
      title: 'ACME Core API Gateway v2',
      ip: '203.0.113.25',
      technologies: ['Nginx', 'Node.js', 'Express'],
      timestamp: '2026-10-01T14:03:00.000Z',
    },
    {
      id: 'ep_l2',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      url: 'https://staging-admin.acme-corp.io:8443',
      hostname: 'staging-admin.acme-corp.io',
      port: 8443,
      protocol: 'https',
      statusCode: 200,
      title: 'ACME Staging Administration Portal',
      ip: '203.0.113.99',
      technologies: ['Apache', 'React'],
      timestamp: '2026-10-01T14:03:20.000Z',
    },
  ];

  const latestServices: NetworkService[] = [
    {
      id: 'svc_l1',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      host: 'api.acme-corp.io',
      ip: '203.0.113.25',
      port: 443,
      protocol: 'tcp',
      state: 'open',
      serviceName: 'https',
      version: 'nginx 1.25.3',
      toolSource: 'Nmap',
      timestamp: '2026-10-01T14:04:00.000Z',
    },
    {
      id: 'svc_l2',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      host: 'staging-admin.acme-corp.io',
      ip: '203.0.113.99',
      port: 6379,
      protocol: 'tcp',
      state: 'open',
      serviceName: 'redis',
      version: '7.0.11',
      toolSource: 'Nmap',
      timestamp: '2026-10-01T14:04:15.000Z',
    },
    {
      id: 'svc_l3',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      host: 'staging-admin.acme-corp.io',
      ip: '203.0.113.99',
      port: 22,
      protocol: 'tcp',
      state: 'open',
      serviceName: 'ssh',
      version: 'OpenSSH 8.9p1',
      toolSource: 'Nmap',
      timestamp: '2026-10-01T14:04:20.000Z',
    },
  ];

  const latestFindings: Finding[] = [
    {
      id: 'fnd_l1',
      assessmentId: 'asm_latest_02',
      ownerId: 'system',
      title: 'Exposed Redis Service on Public Perimeter (Port 6379)',
      description: 'Port 6379 (Redis) is directly reachable on 203.0.113.99 backing staging-admin.acme-corp.io.',
      severity: 'critical',
      confidence: 'certain',
      category: 'Exposed Database Service',
      assetRef: '203.0.113.99:6379',
      evidence: 'TCP 203.0.113.99:6379 OPEN -> Redis 7.0.11 banner verified by Nmap',
      sourceTool: 'Nmap',
      remediation: 'Restrict port 6379 to internal VPC subnets and enforce Redis ACL authentication.',
      verificationStatus: 'verified',
      firstSeen: '2026-10-01T14:04:15.000Z',
      lastSeen: '2026-10-01T14:05:00.000Z',
    },
  ];

  const latestCorrelated = runAssetCorrelationEngine(
    latestAssessment,
    latestRawAssets,
    latestDns,
    latestEndpoints,
    latestServices,
    latestFindings
  );

  const latestSnapshot = createAssessmentSnapshot(
    latestAssessment,
    latestCorrelated.normalizedAssets,
    latestCorrelated.relationships,
    latestDns,
    latestEndpoints,
    latestServices
  );

  const comparison = compareAssessmentSnapshots(
    baselineSnapshot,
    latestSnapshot,
    baselineAssessment,
    latestAssessment
  );
  latestChangesCache = comparison.changes;

  const latestAI = generateDeterministicAIAnalysis(
    latestAssessment,
    latestCorrelated.normalizedAssets,
    latestCorrelated.relationships,
    latestCorrelated.correlationSummary,
    latestFindings
  );

  assessmentStore.set(latestAssessment.id, {
    assessment: latestAssessment,
    rawAssets: latestRawAssets,
    dnsRecords: latestDns,
    endpoints: latestEndpoints,
    services: latestServices,
    findings: latestFindings,
    correlatedAssets: latestCorrelated.normalizedAssets,
    relationships: latestCorrelated.relationships,
    evidences: latestCorrelated.evidences,
    correlation: latestCorrelated.correlationSummary,
    snapshot: latestSnapshot,
    aiAnalysis: latestAI,
  });
}

initializeSeedAssessments();

// ============================================================================
// SAFETY & SCOPE VALIDATION HELPERS
// ============================================================================

function isPrivateOrReservedIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return false;
  if (parts[0] === 127) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 0) return true;
  return false;
}

function cleanDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (domain === 'localhost' || domain.endsWith('.local') || domain.endsWith('.internal')) return false;
  const domainRegex = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
  return domainRegex.test(domain);
}

// ============================================================================
// MODULE 2, 3, 4 & 5 REST API ENDPOINTS
// ============================================================================

// GET /api/assets
app.get('/api/assets', (req, res) => {
  const assessmentId = (req.query.assessmentId as string) || 'asm_latest_02';
  const category = (req.query.category || req.query.type) as string | undefined;
  const search = ((req.query.search as string) || '').toLowerCase();

  const bundle = assessmentStore.get(assessmentId) || assessmentStore.get('asm_latest_02')!;
  let assets = bundle.correlatedAssets;

  if (category && category !== 'all') {
    assets = assets.filter((a) => a.assetType === category);
  }
  if (search) {
    assets = assets.filter(
      (a) =>
        a.canonicalName.toLowerCase().includes(search) ||
        a.discoverySource.toLowerCase().includes(search)
    );
  }

  res.json({
    assessmentId: bundle.assessment.id,
    total: assets.length,
    assets,
  });
});

// GET /api/assets/correlation
app.get('/api/assets/correlation', (req, res) => {
  const assessmentId = (req.query.assessmentId as string) || 'asm_latest_02';
  const bundle = assessmentStore.get(assessmentId) || assessmentStore.get('asm_latest_02')!;

  res.json({
    assessmentId: bundle.assessment.id,
    correlation: bundle.correlation,
    assets: bundle.correlatedAssets,
    relationships: bundle.relationships,
    evidences: bundle.evidences,
  });
});

// GET /api/assets/relationships
app.get('/api/assets/relationships', (req, res) => {
  const assessmentId = (req.query.assessmentId as string) || 'asm_latest_02';
  const bundle = assessmentStore.get(assessmentId) || assessmentStore.get('asm_latest_02')!;
  res.json({
    assessmentId: bundle.assessment.id,
    total: bundle.relationships.length,
    relationships: bundle.relationships,
  });
});

// GET /api/assets/:id
app.get('/api/assets/:id', (req, res) => {
  const { id } = req.params;
  for (const bundle of assessmentStore.values()) {
    const asset = bundle.correlatedAssets.find((a) => a.id === id);
    if (asset) {
      const relationships = bundle.relationships.filter(
        (r) => r.sourceAssetId === id || r.targetAssetId === id
      );
      const evidences = bundle.evidences.filter((e) => e.assetId === id);
      return res.json({
        asset,
        relationships,
        evidences,
      });
    }
  }
  return res.status(404).json({ error: `Asset with id '${id}' not found.` });
});

// GET /api/attack-surface/graph
app.get('/api/attack-surface/graph', (req, res) => {
  const assessmentId = (req.query.assessmentId as string) || 'asm_latest_02';
  const categoryFilter = (req.query.category || req.query.type) as string | undefined;
  const riskyOnly = req.query.riskyOnly === 'true';

  const bundle = assessmentStore.get(assessmentId) || assessmentStore.get('asm_latest_02')!;
  let nodes = bundle.correlatedAssets;

  if (categoryFilter && categoryFilter !== 'all') {
    nodes = nodes.filter((n) => n.assetType === categoryFilter);
  }
  if (riskyOnly) {
    nodes = nodes.filter(
      (n) =>
        n.isExposedRisk ||
        n.isPotentiallyExposed ||
        n.riskLevel === 'critical' ||
        n.riskLevel === 'high'
    );
  }

  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = bundle.relationships.filter(
    (r) => nodeIds.has(r.sourceAssetId) && nodeIds.has(r.targetAssetId)
  );

  res.json({
    assessmentId: bundle.assessment.id,
    rootDomain: bundle.assessment.scope.rootDomain,
    nodes,
    edges,
    evidences: bundle.evidences,
  });
});

// GET /api/assessments/history
app.get('/api/assessments/history', (_req, res) => {
  const assessments = Array.from(assessmentStore.values()).map((b) => ({
    assessment: b.assessment,
    snapshot: b.snapshot,
  }));
  res.json({ assessments });
});

// GET /api/assessments/compare
app.get('/api/assessments/compare', (req, res) => {
  const previousId = (req.query.previousAssessmentId as string) || 'asm_baseline_01';
  const latestId = (req.query.latestAssessmentId as string) || 'asm_latest_02';
  const changeTypeFilter = req.query.changeType as string | undefined;

  const prevBundle = assessmentStore.get(previousId);
  const latestBundle = assessmentStore.get(latestId);

  if (!prevBundle || !latestBundle) {
    return res
      .status(404)
      .json({ error: 'Specified assessment snapshot not found for comparison.' });
  }

  const comparison = compareAssessmentSnapshots(
    prevBundle.snapshot,
    latestBundle.snapshot,
    prevBundle.assessment,
    latestBundle.assessment
  );
  let changes = comparison.changes;

  if (changeTypeFilter && changeTypeFilter !== 'ALL') {
    changes = changes.filter((c) => c.changeType === changeTypeFilter);
  }

  return res.json({
    previousAssessmentId: previousId,
    latestAssessmentId: latestId,
    summary: comparison.summary,
    changes,
  });
});

// GET /api/assessments/:id/snapshot
app.get('/api/assessments/:id/snapshot', (req, res) => {
  const bundle = assessmentStore.get(req.params.id);
  if (!bundle) {
    return res.status(404).json({ error: `Assessment '${req.params.id}' not found.` });
  }
  return res.json(bundle.snapshot);
});

// GET /api/changes
app.get('/api/changes', (req, res) => {
  const changeType = req.query.changeType as string | undefined;
  let changes = [...latestChangesCache];
  if (changeType && changeType !== 'ALL') {
    changes = changes.filter((c) => c.changeType === changeType);
  }
  res.json({
    total: changes.length,
    changes,
  });
});

// GET /api/ai/asset-insights
app.get('/api/ai/asset-insights', (req, res) => {
  const assessmentId = (req.query.assessmentId as string) || 'asm_latest_02';
  const bundle = assessmentStore.get(assessmentId) || assessmentStore.get('asm_latest_02')!;
  res.json(bundle.aiAnalysis);
});

// POST /api/ai/analyze-assets
app.post('/api/ai/analyze-assets', async (req, res) => {
  try {
    const body = req.body || {};
    const {
      assessment: bodyAssessment,
      assets: bodyAssets,
      relationships: bodyRelationships,
      correlation: bodyCorrelation,
      findings: bodyFindings,
      assessmentId,
    } = body;

    if (!bodyAssessment && !assessmentId && (!Array.isArray(bodyAssets) || bodyAssets.length === 0)) {
      return res.status(400).json({
        error: 'Invalid request payload: assessment or assets array is required.',
      });
    }

    const bundle = assessmentStore.get(assessmentId || bodyAssessment?.id || 'asm_latest_02');
    const targetAssessment: Assessment = bodyAssessment || bundle?.assessment;
    const targetAssets: Asset[] = Array.isArray(bodyAssets) ? bodyAssets : bundle?.correlatedAssets || [];
    const targetRelationships: AssetRelationship[] = Array.isArray(bodyRelationships)
      ? bodyRelationships
      : bundle?.relationships || [];
    const targetCorrelation: AssetCorrelation = bodyCorrelation || bundle?.correlation;
    const targetFindings: Finding[] = Array.isArray(bodyFindings) ? bodyFindings : bundle?.findings || [];

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      const fallback = generateDeterministicAIAnalysis(
        targetAssessment,
        targetAssets,
        targetRelationships,
        targetCorrelation,
        targetFindings
      );
      return res.json(fallback);
    }

    try {
      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: { headers: { 'User-Agent': 'aistudio-build' } },
      });

      const prompt = `You are a Principal Attack Surface Intelligence Analyst for ReconX.
Analyze ONLY the verified reconnaissance evidence below for target "${targetAssessment?.scope?.rootDomain || 'authorized-target'}".
STRICT RULES:
1. NEVER invent, fabricate, or hallucinate any assets, ports, CVEs, IP addresses, or technologies not explicitly present in the provided JSON evidence.
2. Every conclusion MUST cite the exact canonicalName and evidence from the input.

Correlated Assets (${targetAssets.length}):
${JSON.stringify(
  targetAssets.slice(0, 40).map((a) => ({
    name: a.canonicalName,
    type: a.assetType,
    sources: a.discoverySource,
    confidence: a.confidenceScore,
    exposed: a.isExposedRisk,
    reason: a.riskReason,
  }))
)}

Correlated Relationships (${targetRelationships.length}):
${JSON.stringify(
  targetRelationships.slice(0, 40).map((r) => ({
    source: r.sourceAssetName,
    type: r.relationshipType,
    target: r.targetAssetName,
    evidence: r.evidenceSummary,
  }))
)}`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              executiveSummary: { type: Type.STRING },
              relationshipInsights: { type: Type.ARRAY, items: { type: Type.STRING } },
              unusualExposurePatterns: { type: Type.ARRAY, items: { type: Type.STRING } },
              riskyConfigurations: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: [
              'executiveSummary',
              'relationshipInsights',
              'unusualExposurePatterns',
              'riskyConfigurations',
            ],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}');
      const baseFallback = generateDeterministicAIAnalysis(
        targetAssessment,
        targetAssets,
        targetRelationships,
        targetCorrelation,
        targetFindings
      );

      const aiResult: AIAnalysis = {
        ...baseFallback,
        provider: 'gemini_ai',
        mode: 'ai_gemini',
        modelUsed: 'gemini-3.8-flash',
        executiveSummary: parsed.executiveSummary || baseFallback.executiveSummary,
        relationshipInsights:
          parsed.relationshipInsights?.length > 0
            ? parsed.relationshipInsights
            : baseFallback.relationshipInsights,
        unusualExposurePatterns:
          parsed.unusualExposurePatterns?.length > 0
            ? parsed.unusualExposurePatterns
            : baseFallback.unusualExposurePatterns,
        riskyConfigurations:
          parsed.riskyConfigurations?.length > 0
            ? parsed.riskyConfigurations
            : baseFallback.riskyConfigurations,
        generatedAt: new Date().toISOString(),
      };
      return res.json(aiResult);
    } catch {
      const fallback = generateDeterministicAIAnalysis(
        targetAssessment,
        targetAssets,
        targetRelationships,
        targetCorrelation,
        targetFindings
      );
      return res.json(fallback);
    }
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to analyze assets' });
  }
});

// ============================================================================
// REAL RECONNAISSANCE ENGINE ENDPOINT (/api/recon/execute)
// ============================================================================

async function discoverSubdomainsCRT(domain: string): Promise<string[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ReconX-ASM-Scanner/2.0 (Authorized-Assessment)' },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as Array<{ name_value?: string }>;
    const found = new Set<string>();
    found.add(domain);
    for (const entry of data.slice(0, 200)) {
      if (!entry.name_value) continue;
      const names = entry.name_value.split('\n');
      for (let name of names) {
        name = name.trim().toLowerCase().replace(/^\*\./, '');
        if ((name === domain || name.endsWith(`.${domain}`)) && isValidDomain(name)) {
          found.add(name);
        }
      }
      if (found.size >= 25) break;
    }
    return Array.from(found);
  } catch {
    return [domain];
  } finally {
    clearTimeout(timeout);
  }
}

async function enumerateCommonSubdomains(domain: string): Promise<string[]> {
  const prefixes = ['www', 'api', 'mail', 'dev', 'staging', 'app', 'portal', 'cdn', 'docs', 'status', 'auth', 'admin'];
  const discovered: string[] = [domain];

  await Promise.all(
    prefixes.map(async (sub) => {
      const candidate = `${sub}.${domain}`;
      try {
        const ips = await dns.resolve4(candidate);
        if (ips && ips.length > 0) {
          discovered.push(candidate);
        }
      } catch {
        // Not resolved
      }
    })
  );
  return discovered;
}

function checkTcpPort(ip: string, port: number, timeoutMs = 1500): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let resolved = false;

    const finish = (open: boolean) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({ open, banner: banner.trim() });
      }
    };

    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      setTimeout(() => finish(true), 250);
    });
    socket.on('data', (chunk) => {
      banner += chunk.toString('utf8').slice(0, 200);
      finish(true);
    });
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));

    socket.connect(port, ip);
  });
}

function inspectTlsCertificate(host: string, port = 443, timeoutMs = 3000): Promise<{
  valid: boolean;
  issuer: string;
  subject: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
} | null> {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (val: any) => {
      if (!resolved) {
        resolved = true;
        resolve(val);
      }
    };

    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || 'TLS';
          const authorized = socket.authorized;
          socket.end();
          if (!cert || !cert.valid_to) {
            return done(null);
          }
          const expiryDate = new Date(cert.valid_to);
          const daysRemaining = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          done({
            valid: authorized && daysRemaining > 0,
            issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown Issuer',
            subject: cert.subject?.CN || host,
            validTo: expiryDate.toISOString(),
            daysRemaining,
            protocol,
          });
        } catch {
          socket.destroy();
          done(null);
        }
      }
    );

    socket.on('error', () => {
      socket.destroy();
      done(null);
    });
    socket.on('timeout', () => {
      socket.destroy();
      done(null);
    });
  });
}

app.post('/api/recon/execute', async (req, res) => {
  try {
    const { domain: rawDomain, authorizationConfirmed, scope = {} } = req.body;

    if (!authorizationConfirmed) {
      return res.status(403).json({
        error: 'Explicit target authorization confirmation is required before running reconnaissance.',
      });
    }

    const rootDomain = cleanDomain(rawDomain || '');
    if (!isValidDomain(rootDomain)) {
      return res.status(400).json({
        error: 'Invalid or restricted domain target. Private networks, localhost, and malformed domains are blocked.',
      });
    }

    const crtSubs = await discoverSubdomainsCRT(rootDomain);
    const dnsSubs = await enumerateCommonSubdomains(rootDomain);
    const allSubdomains = Array.from(new Set([rootDomain, ...crtSubs, ...dnsSubs])).slice(0, 18);

    const dnsRecords: Array<{
      name: string;
      type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT';
      value: string;
      ttl: number;
    }> = [];

    const subdomainToIps: Record<string, string[]> = {};
    const uniqueIps = new Set<string>();

    for (const sub of allSubdomains) {
      try {
        const aRecords = await dns.resolve4(sub);
        const safeIps = aRecords.filter((ip) => !isPrivateOrReservedIP(ip));
        subdomainToIps[sub] = safeIps;
        safeIps.forEach((ip) => {
          uniqueIps.add(ip);
          dnsRecords.push({ name: sub, type: 'A', value: ip, ttl: 300 });
        });
      } catch {}

      try {
        const cnameRecords = await dns.resolveCname(sub);
        cnameRecords.forEach((cname) => {
          dnsRecords.push({ name: sub, type: 'CNAME', value: cname, ttl: 300 });
        });
      } catch {}
    }

    const services: Array<{
      ip: string;
      port: number;
      protocol: 'tcp';
      state: 'open';
      serviceName: string;
      product: string;
      version: string;
      banner: string;
      isRisky: boolean;
      riskReason?: string;
    }> = [];

    const portMap: Record<number, { name: string; risky: boolean; reason?: string }> = {
      21: { name: 'ftp', risky: true, reason: 'Unencrypted file transfer port exposed' },
      22: { name: 'ssh', risky: true, reason: 'Direct SSH administrative service exposed to internet' },
      80: { name: 'http', risky: false },
      443: { name: 'https', risky: false },
      3306: { name: 'mysql', risky: true, reason: 'Database service port 3306 exposed publicly' },
      5432: { name: 'postgresql', risky: true, reason: 'PostgreSQL port 5432 exposed publicly' },
      6379: { name: 'redis', risky: true, reason: 'Redis key-value store port 6379 exposed publicly' },
      8080: { name: 'http-alt', risky: true, reason: 'Secondary/Staging HTTP service port 8080 exposed' },
      8443: { name: 'https-alt', risky: false },
    };

    if (scope.activePortScan !== false && !scope.passiveOnly) {
      const ipsToScan = Array.from(uniqueIps).slice(0, 6);
      const portsToCheck = [80, 443, 22, 8080, 8443, 21, 3306, 5432, 6379];

      for (const ip of ipsToScan) {
        await Promise.all(
          portsToCheck.map(async (port) => {
            const resPort = await checkTcpPort(ip, port, 1200);
            if (resPort.open) {
              const meta = portMap[port] || { name: 'unknown', risky: false };
              services.push({
                ip,
                port,
                protocol: 'tcp',
                state: 'open',
                serviceName: meta.name,
                product: meta.name.toUpperCase(),
                version: '',
                banner: resPort.banner || `TCP/${port} OPEN`,
                isRisky: meta.risky,
                riskReason: meta.reason,
              });
            }
          })
        );
      }
    }

    const webEndpoints: Array<{
      subdomain: string;
      url: string;
      statusCode: number;
      title: string;
      serverHeader: string;
      contentType: string;
      responseTimeMs: number;
      technologies: string[];
      tlsValid: boolean;
      tlsIssuer: string;
      tlsExpiry: string;
      tlsDaysRemaining: number;
      headers: Record<string, string>;
    }> = [];

    const subsToProbe = allSubdomains.slice(0, 8);
    await Promise.all(
      subsToProbe.map(async (sub) => {
        const start = Date.now();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4500);
        try {
          const url = `https://${sub}`;
          const resp = await fetch(url, {
            method: 'GET',
            redirect: 'follow',
            signal: controller.signal,
            headers: { 'User-Agent': 'ReconX-ASM-Scanner/2.0' },
          });
          const elapsed = Date.now() - start;
          const html = await resp.text();
          const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
          const title = titleMatch ? titleMatch[1].trim().slice(0, 120) : sub;

          const headersObj: Record<string, string> = {};
          resp.headers.forEach((val, key) => {
            headersObj[key.toLowerCase()] = val;
          });

          const serverHeader = headersObj['server'] || 'Unknown';
          const poweredBy = headersObj['x-powered-by'] || '';
          const techs = new Set<string>();
          if (serverHeader !== 'Unknown') techs.add(serverHeader.split('/')[0]);
          if (poweredBy) techs.add(poweredBy);
          if (headersObj['cf-ray']) techs.add('Cloudflare');
          if (headersObj['x-vercel-id']) techs.add('Vercel');
          if (headersObj['x-amz-cf-id']) techs.add('AWS CloudFront');

          let tlsInfo = null;
          if (scope.sslInspection !== false) {
            tlsInfo = await inspectTlsCertificate(sub, 443, 2500);
          }

          webEndpoints.push({
            subdomain: sub,
            url,
            statusCode: resp.status,
            title,
            serverHeader,
            contentType: headersObj['content-type'] || 'text/html',
            responseTimeMs: elapsed,
            technologies: Array.from(techs),
            tlsValid: tlsInfo ? tlsInfo.valid : true,
            tlsIssuer: tlsInfo ? tlsInfo.issuer : 'Verified CA',
            tlsExpiry: tlsInfo ? tlsInfo.validTo : new Date(Date.now() + 90 * 86400000).toISOString(),
            tlsDaysRemaining: tlsInfo ? tlsInfo.daysRemaining : 90,
            headers: headersObj,
          });
        } catch {
          // Unreachable over HTTPS
        } finally {
          clearTimeout(timer);
        }
      })
    );

    return res.json({
      rootDomain,
      scannedAt: new Date().toISOString(),
      subdomains: allSubdomains,
      subdomainToIps,
      ips: Array.from(uniqueIps),
      dnsRecords,
      services,
      webEndpoints,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Internal reconnaissance execution error' });
  }
});

// ============================================================================
// AUTOMATED SLACK WEBHOOK NOTIFICATION ENDPOINT (/api/notifications/slack)
// ============================================================================

function isBlockedWebhookHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (
    lower === 'localhost' ||
    lower === '0.0.0.0' ||
    lower === '::1' ||
    lower === '[::1]' ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal')
  ) {
    return true;
  }
  return isPrivateOrReservedIP(lower);
}

app.post('/api/notifications/slack', async (req, res) => {
  try {
    const {
      webhookUrl,
      channelName,
      assessmentName,
      rootDomain,
      alertedCount = 0,
      isTest = false,
      payload,
    } = req.body || {};

    if (!webhookUrl || typeof webhookUrl !== 'string') {
      return res.status(400).json({
        ok: false,
        error: 'A valid Slack Incoming Webhook URL is required.',
      });
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(webhookUrl.trim());
    } catch {
      return res.status(400).json({
        ok: false,
        error: 'Malformed webhook URL.',
      });
    }

    const isTestMode = process.env.RECONX_TEST_MODE === 'true';
    if (!isTestMode) {
      if (parsedUrl.protocol !== 'https:') {
        return res.status(400).json({
          ok: false,
          error: 'Slack webhook URLs must use HTTPS.',
        });
      }
      if (isBlockedWebhookHost(parsedUrl.hostname)) {
        return res.status(400).json({
          ok: false,
          error: 'Private, loopback, and internal network webhook targets are blocked.',
        });
      }
    } else if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      return res.status(400).json({
        ok: false,
        error: 'Unsupported webhook protocol.',
      });
    }

    const slackBody =
      payload && typeof payload === 'object' && (payload.text || Array.isArray(payload.blocks))
        ? payload
        : {
            text: `[ReconX] ${isTest ? 'Test Alert' : 'High-Severity Security Alert'} for ${
              rootDomain || assessmentName || 'Assessment'
            }${channelName ? ` (${channelName})` : ''}`,
          };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      const upstream = await fetch(parsedUrl.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(slackBody),
        signal: controller.signal,
      });

      const responseText = await upstream.text().catch(() => '');
      if (!upstream.ok) {
        return res.status(502).json({
          ok: false,
          statusCode: upstream.status,
          error: `Slack webhook rejected request (HTTP ${upstream.status}${
            responseText ? `: ${responseText.slice(0, 120)}` : ''
          })`,
        });
      }

      return res.json({
        ok: true,
        statusCode: upstream.status,
        alertedCount,
        isTest: Boolean(isTest),
        channelName: channelName || '#security-alerts',
        deliveredAt: new Date().toISOString(),
        message: isTest
          ? `Test webhook notification delivered to ${channelName || 'Slack'}.`
          : `Dispatched ${alertedCount} high-severity alert(s) to ${channelName || 'Slack'}.`,
      });
    } catch (fetchErr: any) {
      return res.status(502).json({
        ok: false,
        statusCode: 502,
        error:
          fetchErr?.name === 'AbortError'
            ? 'Slack webhook request timed out after 8s.'
            : fetchErr?.message || 'Failed to reach Slack webhook endpoint.',
      });
    } finally {
      clearTimeout(timer);
    }
  } catch (err: any) {
    return res.status(500).json({
      ok: false,
      error: err?.message || 'Internal webhook notification error.',
    });
  }
});

// ============================================================================
// IP GEOLOCATION SERVICE ENDPOINTS (/api/geo/ip-lookup & /api/geo/ip/:ip)
// ============================================================================

const GEO_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const serverGeoCache = new Map<string, { expiresAt: number; data: IpGeoLocation }>();

async function resolveBatchIpGeolocations(ips: string[]): Promise<Record<string, IpGeoLocation>> {
  const uniqueIps = Array.from(
    new Set(ips.map((ip) => (ip || '').trim()).filter((ip) => isValidIpv4(ip)))
  ).slice(0, 100);

  const results: Record<string, IpGeoLocation> = {};
  const externalToFetch: string[] = [];
  const now = Date.now();

  for (const ip of uniqueIps) {
    const cached = serverGeoCache.get(ip);
    if (cached && cached.expiresAt > now) {
      results[ip] = cached.data;
      continue;
    }

    if (isPrivateOrNonRoutableIp(ip)) {
      const localGeo = classifyReservedOrRirFallback(ip);
      serverGeoCache.set(ip, { expiresAt: now + GEO_CACHE_TTL_MS, data: localGeo });
      results[ip] = localGeo;
      continue;
    }

    externalToFetch.push(ip);
  }

  if (externalToFetch.length > 0) {
    // Primary batch lookup via ip-api.com (no API key required, up to 100 IPs per POST)
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      try {
        const resp = await fetch(
          'http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,continent,isp,org,as,lat,lon,query',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(externalToFetch),
            signal: controller.signal,
          }
        );

        if (resp.ok) {
          const batchData = (await resp.json()) as Array<Record<string, any>>;
          if (Array.isArray(batchData)) {
            for (const entry of batchData) {
              const queryIp = String(entry?.query || '').trim();
              if (!queryIp || entry?.status !== 'success') continue;
              const mappedRegion = mapCountryToGeoRegion(entry.countryCode, entry.continent);
              const geoRecord: IpGeoLocation = {
                ip: queryIp,
                isExternal: true,
                country: entry.country || 'Unknown',
                countryCode: entry.countryCode || 'UN',
                regionName: entry.regionName || undefined,
                city: entry.city || undefined,
                continent: entry.continent || 'Unknown',
                geoRegionId: mappedRegion.id,
                geoRegionLabel: mappedRegion.label,
                isp: entry.isp || entry.org || undefined,
                asn: entry.as || undefined,
                lat: typeof entry.lat === 'number' ? entry.lat : undefined,
                lon: typeof entry.lon === 'number' ? entry.lon : undefined,
                source: 'ip-api',
                resolvedAt: new Date().toISOString(),
              };
              serverGeoCache.set(queryIp, { expiresAt: now + GEO_CACHE_TTL_MS, data: geoRecord });
              results[queryIp] = geoRecord;
            }
          }
        }
      } finally {
        clearTimeout(timer);
      }
    } catch {
      // Proceed to secondary provider & RIR fallback below
    }

    // Secondary single-IP fallback via ipwho.is for any still-unresolved external IPs (cap 8 concurrent)
    const remaining = externalToFetch.filter((ip) => !results[ip]).slice(0, 8);
    if (remaining.length > 0) {
      await Promise.all(
        remaining.map(async (ip) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 3500);
          try {
            const resp = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
              signal: controller.signal,
              headers: { 'User-Agent': 'ReconX-ASM-GeoIP/1.0' },
            });
            if (resp.ok) {
              const data = (await resp.json()) as Record<string, any>;
              if (data?.success && data?.country) {
                const mappedRegion = mapCountryToGeoRegion(data.country_code, data.continent);
                const geoRecord: IpGeoLocation = {
                  ip,
                  isExternal: true,
                  country: data.country,
                  countryCode: data.country_code || 'UN',
                  regionName: data.region || undefined,
                  city: data.city || undefined,
                  continent: data.continent || 'Unknown',
                  geoRegionId: mappedRegion.id,
                  geoRegionLabel: mappedRegion.label,
                  isp: data.connection?.isp || data.connection?.org || undefined,
                  asn: data.connection?.asn ? `AS${data.connection.asn}` : undefined,
                  lat: typeof data.latitude === 'number' ? data.latitude : undefined,
                  lon: typeof data.longitude === 'number' ? data.longitude : undefined,
                  source: 'ipwho.is',
                  resolvedAt: new Date().toISOString(),
                };
                serverGeoCache.set(ip, { expiresAt: now + GEO_CACHE_TTL_MS, data: geoRecord });
                results[ip] = geoRecord;
                return;
              }
            }
          } catch {
            // Fall through to RIR fallback
          } finally {
            clearTimeout(timer);
          }
        })
      );
    }

    // Final deterministic fallback for reserved documentation ranges (e.g. 203.0.113.x) or offline mode
    for (const ip of externalToFetch) {
      if (!results[ip]) {
        const fallback = classifyReservedOrRirFallback(ip);
        serverGeoCache.set(ip, { expiresAt: now + GEO_CACHE_TTL_MS, data: fallback });
        results[ip] = fallback;
      }
    }
  }

  return results;
}

app.post('/api/geo/ip-lookup', async (req, res) => {
  try {
    const ips = req.body?.ips;
    if (!Array.isArray(ips)) {
      return res.status(400).json({
        ok: false,
        error: 'Request body must include an ips string array.',
      });
    }

    const validIps = ips.filter((ip) => typeof ip === 'string' && isValidIpv4(ip.trim()));
    if (ips.length > 0 && validIps.length === 0) {
      return res.status(400).json({
        ok: false,
        error: 'No valid IPv4 addresses provided in request.',
      });
    }

    const results = await resolveBatchIpGeolocations(validIps);
    return res.json({
      ok: true,
      count: Object.keys(results).length,
      results,
    });
  } catch (err: any) {
    return res.status(500).json({
      ok: false,
      error: err?.message || 'IP geolocation lookup error',
    });
  }
});

app.get('/api/geo/ip/:ip', async (req, res) => {
  const ip = (req.params.ip || '').trim();
  if (!isValidIpv4(ip)) {
    return res.status(400).json({
      ok: false,
      error: `Invalid IPv4 address '${ip}'.`,
    });
  }
  const results = await resolveBatchIpGeolocations([ip]);
  return res.json({
    ok: true,
    geo: results[ip],
  });
});

// ============================================================================
// VITE DEV SERVER OR PRODUCTION STATIC SERVING
// ============================================================================

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, status: 'healthy' });
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const distDir = path.resolve(__dirname, 'dist');
  const runningUnderTsx = process.execArgv.some((arg) => arg.includes('tsx'));
  const isProd =
    process.env.NODE_ENV === 'production' ||
    (process.env.NODE_ENV !== 'development' &&
      !runningUnderTsx &&
      fs.existsSync(path.join(distDir, 'index.html')));
  const port = isProd && process.env.PORT ? Number(process.env.PORT) : DEFAULT_APP_PORT;

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api/')) return next();
      return res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`ReconX Platform Server listening on http://0.0.0.0:${port}`);
  });
}

if (process.env.RECONX_TEST_MODE !== 'true') {
  startServer().catch((err) => {
    console.error('Failed to start server:', err);
  });
}
