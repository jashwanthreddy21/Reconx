import {
  Assessment,
  AssessmentRiskProfile,
  Asset,
  AssetRiskBreakdown,
  Finding,
  FindingSeverity,
  NetworkService,
  RiskFactorAttribution,
  RiskScoreWeights,
  WebEndpoint,
} from '../types';

export const DEFAULT_RISK_WEIGHTS: RiskScoreWeights = {
  openPorts: 0.25,
  exposedServices: 0.25,
  vulnerabilities: 0.5,
};

interface PortRiskSpec {
  weight: number;
  severity: FindingSeverity;
  label: string;
}

const PORT_RISK_CATALOG: Record<number, PortRiskSpec> = {
  23: { weight: 30, severity: 'critical', label: 'Telnet Cleartext Remote Shell' },
  445: { weight: 28, severity: 'critical', label: 'SMB / NetBIOS File Sharing' },
  3389: { weight: 26, severity: 'critical', label: 'Remote Desktop Protocol (RDP)' },
  6379: { weight: 28, severity: 'critical', label: 'Redis In-Memory Store' },
  27017: { weight: 28, severity: 'critical', label: 'MongoDB Database Listener' },
  9200: { weight: 26, severity: 'critical', label: 'Elasticsearch HTTP API' },
  1433: { weight: 24, severity: 'high', label: 'Microsoft SQL Server' },
  1521: { weight: 24, severity: 'high', label: 'Oracle Database Listener' },
  3306: { weight: 22, severity: 'high', label: 'MySQL Database Port' },
  5432: { weight: 22, severity: 'high', label: 'PostgreSQL Database Port' },
  21: { weight: 20, severity: 'high', label: 'FTP Control Port' },
  22: { weight: 14, severity: 'medium', label: 'SSH Administrative Access' },
  25: { weight: 14, severity: 'medium', label: 'SMTP Mail Transfer' },
  8080: { weight: 12, severity: 'medium', label: 'Alternate HTTP / Proxy / Admin Console' },
  8443: { weight: 10, severity: 'medium', label: 'Alternate HTTPS / Management Console' },
  53: { weight: 7, severity: 'low', label: 'DNS Resolver Service' },
  80: { weight: 8, severity: 'low', label: 'Cleartext HTTP Listener' },
  443: { weight: 4, severity: 'informational', label: 'Standard HTTPS Listener' },
};

const VULN_SEVERITY_POINTS: Record<FindingSeverity, number> = {
  critical: 34,
  high: 20,
  medium: 10,
  low: 4,
  informational: 1.5,
};

const CONFIDENCE_MULTIPLIER: Record<string, number> = {
  certain: 1.0,
  firm: 0.85,
  tentative: 0.65,
};

const VERIFICATION_MULTIPLIER: Record<string, number> = {
  verified: 1.15,
  potential_risk: 1.0,
  observed_fact: 0.8,
};

const CLEARTEXT_OR_RISKY_SERVICES = new Set([
  'telnet',
  'ftp',
  'smb',
  'microsoft-ds',
  'ms-wbt-server',
  'rdp',
  'redis',
  'mongodb',
  'elasticsearch',
  'mysql',
  'postgresql',
  'ms-sql-s',
  'oracle',
  'vnc',
  'http-proxy',
]);

const SENSITIVE_HOSTNAME_PATTERN =
  /\b(admin|internal|staging|dev|jenkins|gitlab|grafana|kibana|vpn|bastion|db|redis|manage|console)\b/i;

export function scoreToSeverityTier(score: number): FindingSeverity {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  if (score >= 15) return 'low';
  return 'informational';
}

function normalizeWeights(custom?: Partial<RiskScoreWeights>): RiskScoreWeights {
  const raw: RiskScoreWeights = {
    openPorts: Math.max(0, custom?.openPorts ?? DEFAULT_RISK_WEIGHTS.openPorts),
    exposedServices: Math.max(0, custom?.exposedServices ?? DEFAULT_RISK_WEIGHTS.exposedServices),
    vulnerabilities: Math.max(0, custom?.vulnerabilities ?? DEFAULT_RISK_WEIGHTS.vulnerabilities),
  };
  const sum = raw.openPorts + raw.exposedServices + raw.vulnerabilities;
  if (sum <= 0) return { ...DEFAULT_RISK_WEIGHTS };
  return {
    openPorts: Number((raw.openPorts / sum).toFixed(4)),
    exposedServices: Number((raw.exposedServices / sum).toFixed(4)),
    vulnerabilities: Number((raw.vulnerabilities / sum).toFixed(4)),
  };
}

function saturateScore(rawPoints: number, scale: number): number {
  if (rawPoints <= 0) return 0;
  const val = 100 * (1 - Math.exp(-rawPoints / scale));
  return Math.min(100, Math.max(0, Math.round(val)));
}

export interface CalculateRiskScoreInput {
  assessment?: Assessment | null;
  assets?: Asset[];
  services?: NetworkService[];
  endpoints?: WebEndpoint[];
  findings?: Finding[];
  weights?: Partial<RiskScoreWeights>;
}

/**
 * Weighted Risk-Scoring Engine
 * Computes an aggregate 0-100 severity score and full attribution across:
 *   1. Open Ports (default 25%)
 *   2. Exposed Services & Attack Surface (default 25%)
 *   3. Discovered Vulnerabilities / Findings (default 50%)
 */
export function calculateAssessmentRiskScore({
  assets = [],
  services = [],
  endpoints = [],
  findings = [],
  weights: customWeights,
}: CalculateRiskScoreInput): AssessmentRiskProfile {
  const weights = normalizeWeights(customWeights);
  const factors: RiskFactorAttribution[] = [];

  // Map to track per-host breakdown
  const hostMap = new Map<
    string,
    {
      assetKey: string;
      assetType: Asset['assetType'] | 'host';
      openPorts: Set<number>;
      portRawPoints: number;
      serviceRawPoints: number;
      vulnRawPoints: number;
      exposedServicesCount: number;
      findingsCount: number;
      topReason: string;
      topReasonWeight: number;
    }
  >();

  const ensureHost = (key: string, assetType: Asset['assetType'] | 'host' = 'subdomain') => {
    const clean = (key || 'unknown-host').trim().toLowerCase();
    let entry = hostMap.get(clean);
    if (!entry) {
      entry = {
        assetKey: clean,
        assetType,
        openPorts: new Set<number>(),
        portRawPoints: 0,
        serviceRawPoints: 0,
        vulnRawPoints: 0,
        exposedServicesCount: 0,
        findingsCount: 0,
        topReason: 'Observed surface host',
        topReasonWeight: 0,
      };
      hostMap.set(clean, entry);
    }
    return entry;
  };

  // Seed host entries from assets
  for (const a of assets) {
    if (a.assetType === 'root_domain' || a.assetType === 'subdomain' || a.assetType === 'ip_address') {
      ensureHost(a.canonicalName, a.assetType);
    }
  }

  // ---------------------------------------------------------------------------
  // PILLAR 1: OPEN PORTS EXPOSURE
  // ---------------------------------------------------------------------------
  const openNetworkServices = services.filter((s) => s.state === 'open');
  const seenHostPorts = new Set<string>();
  let openPortsRawPoints = 0;
  let highRiskPortsCount = 0;

  for (const svc of openNetworkServices) {
    const hostKey = (svc.host || svc.ip || 'unknown').toLowerCase();
    const dedupeKey = `${hostKey}:${svc.port}/${svc.protocol}`;
    if (seenHostPorts.has(dedupeKey)) continue;
    seenHostPorts.add(dedupeKey);

    const spec = PORT_RISK_CATALOG[svc.port] || {
      weight: svc.port < 1024 ? 10 : 7,
      severity: svc.port < 1024 ? ('medium' as FindingSeverity) : ('low' as FindingSeverity),
      label: `Open ${svc.protocol.toUpperCase()} Port ${svc.port}`,
    };

    if (spec.severity === 'critical' || spec.severity === 'high') {
      highRiskPortsCount += 1;
    }

    openPortsRawPoints += spec.weight;

    const hostEntry = ensureHost(hostKey, 'subdomain');
    hostEntry.openPorts.add(svc.port);
    hostEntry.portRawPoints += spec.weight;
    if (spec.weight > hostEntry.topReasonWeight) {
      hostEntry.topReasonWeight = spec.weight;
      hostEntry.topReason = `Open port ${svc.port}/${svc.protocol} (${spec.label})`;
    }

    factors.push({
      id: `port_${hostKey}_${svc.port}`,
      pillar: 'open_ports',
      label: `${spec.label} (Port ${svc.port})`,
      evidence: `${hostKey} · ${svc.ip}:${svc.port}/${svc.protocol} (${svc.serviceName})`,
      severity: spec.severity,
      rawPoints: spec.weight,
      weightedContribution: 0, // populated after sub-scores are normalized
    });
  }

  // Also include open ports attached to asset objects if service list omitted them
  for (const asset of assets) {
    if (!asset.openPorts || asset.openPorts.length === 0) continue;
    const hostKey = asset.canonicalName.toLowerCase();
    for (const port of asset.openPorts) {
      const dedupeTcp = `${hostKey}:${port}/tcp`;
      const dedupeUdp = `${hostKey}:${port}/udp`;
      if (seenHostPorts.has(dedupeTcp) || seenHostPorts.has(dedupeUdp)) continue;
      seenHostPorts.add(dedupeTcp);

      const spec = PORT_RISK_CATALOG[port] || {
        weight: 8,
        severity: 'low' as FindingSeverity,
        label: `Open Port ${port}`,
      };
      if (spec.severity === 'critical' || spec.severity === 'high') {
        highRiskPortsCount += 1;
      }
      openPortsRawPoints += spec.weight;

      const hostEntry = ensureHost(hostKey, asset.assetType);
      hostEntry.openPorts.add(port);
      hostEntry.portRawPoints += spec.weight;
    }
  }

  const openPortsTotal = seenHostPorts.size;
  const openPortsScore = saturateScore(openPortsRawPoints, 55);

  // ---------------------------------------------------------------------------
  // PILLAR 2: EXPOSED SERVICES & ATTACK SURFACE FOOTPRINT
  // ---------------------------------------------------------------------------
  let exposedServicesRawPoints = 0;
  let cleartextOrVersionExposedCount = 0;

  for (const svc of openNetworkServices) {
    const hostKey = (svc.host || svc.ip || 'unknown').toLowerCase();
    const svcNameLower = (svc.serviceName || '').toLowerCase();
    const versionStr = (svc.version || '').trim();
    const hasBannerVersion =
      versionStr.length > 0 && !/concealed|unknown|n\/a/i.test(versionStr);
    const isRiskyService = CLEARTEXT_OR_RISKY_SERVICES.has(svcNameLower);

    let pts = 4; // baseline exposed service footprint
    let reason = `Service ${svc.serviceName} exposed on port ${svc.port}`;
    let sev: FindingSeverity = 'low';

    if (isRiskyService) {
      pts += 14;
      sev = 'high';
      cleartextOrVersionExposedCount += 1;
      reason = `Sensitive/cleartext service "${svc.serviceName}" exposed externally`;
    }
    if (hasBannerVersion) {
      pts += 6;
      if (sev === 'low') sev = 'medium';
      cleartextOrVersionExposedCount += 1;
      reason = `${reason} (banner: ${versionStr})`;
    }

    exposedServicesRawPoints += pts;

    const hostEntry = ensureHost(hostKey, 'subdomain');
    hostEntry.exposedServicesCount += 1;
    hostEntry.serviceRawPoints += pts;
    if (pts > hostEntry.topReasonWeight) {
      hostEntry.topReasonWeight = pts;
      hostEntry.topReason = reason;
    }

    if (isRiskyService || hasBannerVersion) {
      factors.push({
        id: `svc_${hostKey}_${svc.port}_${svc.serviceName}`,
        pillar: 'exposed_services',
        label: `Exposed Service: ${svc.serviceName}${hasBannerVersion ? ` (${versionStr})` : ''}`,
        evidence: `${hostKey}:${svc.port} · ${reason}`,
        severity: sev,
        rawPoints: pts,
        weightedContribution: 0,
      });
    }
  }

  // Evaluate exposed HTTP endpoints & sensitive non-production hostnames
  for (const ep of endpoints) {
    const hostKey = (ep.hostname || '').toLowerCase();
    let pts = 2;
    let sev: FindingSeverity = 'informational';
    let label = `Live Web Endpoint (${ep.statusCode})`;

    if (ep.protocol === 'http') {
      pts += 8;
      sev = 'medium';
      cleartextOrVersionExposedCount += 1;
      label = 'Unencrypted Cleartext HTTP Endpoint';
    }
    if (ep.tlsInfo && ep.tlsInfo.valid === false) {
      pts += 12;
      sev = 'high';
      label = 'Invalid / Misconfigured TLS Certificate';
    }
    if (SENSITIVE_HOSTNAME_PATTERN.test(hostKey) && ep.statusCode < 404) {
      pts += 10;
      sev = sev === 'high' ? 'high' : 'medium';
      label = `Sensitive Control-Plane Endpoint Exposed (${ep.url})`;
    }

    exposedServicesRawPoints += pts;
    const hostEntry = ensureHost(hostKey, 'subdomain');
    hostEntry.exposedServicesCount += 1;
    hostEntry.serviceRawPoints += pts;

    if (pts >= 8) {
      factors.push({
        id: `ep_${ep.id}`,
        pillar: 'exposed_services',
        label,
        evidence: `${ep.url} (HTTP ${ep.statusCode})`,
        severity: sev,
        rawPoints: pts,
        weightedContribution: 0,
      });
    }
  }

  // Check assets with sensitive hostnames not already covered by endpoints
  for (const asset of assets) {
    if (
      (asset.assetType === 'subdomain' || asset.assetType === 'root_domain') &&
      SENSITIVE_HOSTNAME_PATTERN.test(asset.canonicalName)
    ) {
      const hasEndpoint = endpoints.some(
        (ep) => ep.hostname.toLowerCase() === asset.canonicalName.toLowerCase()
      );
      if (!hasEndpoint) {
        exposedServicesRawPoints += 7;
        const hostEntry = ensureHost(asset.canonicalName, asset.assetType);
        hostEntry.serviceRawPoints += 7;
        factors.push({
          id: `host_${asset.id}`,
          pillar: 'exposed_services',
          label: `Non-Production / Administrative Hostname Resolvable`,
          evidence: `${asset.canonicalName} discovered via ${asset.discoverySource}`,
          severity: 'medium',
          rawPoints: 7,
          weightedContribution: 0,
        });
      }
    }
  }

  const exposedServicesTotal = openNetworkServices.length + endpoints.length;
  const exposedServicesScore = saturateScore(exposedServicesRawPoints, 65);

  // ---------------------------------------------------------------------------
  // PILLAR 3: DISCOVERED VULNERABILITIES & SECURITY FINDINGS
  // ---------------------------------------------------------------------------
  const findingsBySeverity: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  let vulnerabilitiesRawPoints = 0;

  for (const f of findings) {
    const sev: FindingSeverity = f.severity || 'informational';
    findingsBySeverity[sev] = (findingsBySeverity[sev] || 0) + 1;

    const basePts = VULN_SEVERITY_POINTS[sev] || 1.5;
    const confMult = CONFIDENCE_MULTIPLIER[f.confidence || 'firm'] ?? 0.85;
    const verifMult = VERIFICATION_MULTIPLIER[f.verificationStatus || 'observed_fact'] ?? 1.0;
    const pts = Number((basePts * confMult * verifMult).toFixed(2));
    vulnerabilitiesRawPoints += pts;

    // Attribute finding back to its host
    const cleanRef = (f.assetRef || 'root')
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .split(':')[0]
      .toLowerCase();
    const hostEntry = ensureHost(cleanRef || 'root', 'subdomain');
    hostEntry.findingsCount += 1;
    hostEntry.vulnRawPoints += pts;
    if (pts > hostEntry.topReasonWeight) {
      hostEntry.topReasonWeight = pts;
      hostEntry.topReason = f.title;
    }

    factors.push({
      id: `vuln_${f.id}`,
      pillar: 'vulnerabilities',
      label: f.title,
      evidence: `${f.assetRef} · ${f.sourceTool} (${f.verificationStatus.replace('_', ' ')})`,
      severity: sev,
      rawPoints: pts,
      weightedContribution: 0,
    });
  }

  const vulnerabilitiesScore = saturateScore(vulnerabilitiesRawPoints, 60);

  // ---------------------------------------------------------------------------
  // WEIGHTED AGGREGATION (0 - 100)
  // ---------------------------------------------------------------------------
  const openPortsPoints = Number((openPortsScore * weights.openPorts).toFixed(1));
  const exposedServicesPoints = Number(
    (exposedServicesScore * weights.exposedServices).toFixed(1)
  );
  const vulnerabilitiesPoints = Number(
    (vulnerabilitiesScore * weights.vulnerabilities).toFixed(1)
  );

  let aggregateScore = Math.round(
    openPortsPoints + exposedServicesPoints + vulnerabilitiesPoints
  );

  // Guardrails: verified critical findings should ensure at least Medium-High elevation
  if (findingsBySeverity.critical > 0 && aggregateScore < 65) {
    aggregateScore = Math.max(aggregateScore, 65);
  }
  aggregateScore = Math.min(100, Math.max(0, aggregateScore));

  // Attribute proportional weighted points to each factor for explainability
  const totalPillarRaw = {
    open_ports: Math.max(1, openPortsRawPoints),
    exposed_services: Math.max(1, exposedServicesRawPoints),
    vulnerabilities: Math.max(1, vulnerabilitiesRawPoints),
  };
  const totalPillarContrib = {
    open_ports: openPortsPoints,
    exposed_services: exposedServicesPoints,
    vulnerabilities: vulnerabilitiesPoints,
  };

  for (const factor of factors) {
    const share = factor.rawPoints / totalPillarRaw[factor.pillar];
    factor.weightedContribution = Number(
      (share * totalPillarContrib[factor.pillar]).toFixed(1)
    );
  }

  const topFactors = factors
    .sort((a, b) => b.weightedContribution - a.weightedContribution || b.rawPoints - a.rawPoints)
    .slice(0, 12);

  // Per-host breakdown sorted descending
  const highestRiskAssets: AssetRiskBreakdown[] = Array.from(hostMap.values())
    .map((h) => {
      const pScore = saturateScore(h.portRawPoints, 35);
      const sScore = saturateScore(h.serviceRawPoints, 40);
      const vScore = saturateScore(h.vulnRawPoints, 35);
      const hostScore = Math.min(
        100,
        Math.round(
          pScore * weights.openPorts +
            sScore * weights.exposedServices +
            vScore * weights.vulnerabilities
        )
      );
      return {
        assetKey: h.assetKey,
        assetType: h.assetType,
        score: hostScore,
        severity: scoreToSeverityTier(hostScore),
        openPorts: Array.from(h.openPorts).sort((a, b) => a - b),
        exposedServicesCount: h.exposedServicesCount,
        findingsCount: h.findingsCount,
        topReason: h.topReason,
      };
    })
    .filter((h) => h.score > 0 || h.openPorts.length > 0 || h.findingsCount > 0)
    .sort((a, b) => b.score - a.score || b.findingsCount - a.findingsCount)
    .slice(0, 10);

  return {
    aggregateScore,
    severityTier: scoreToSeverityTier(aggregateScore),
    weights,
    subScores: {
      openPortsScore,
      exposedServicesScore,
      vulnerabilitiesScore,
    },
    weightedContributions: {
      openPortsPoints,
      exposedServicesPoints,
      vulnerabilitiesPoints,
    },
    metrics: {
      openPortsTotal,
      highRiskPortsCount,
      exposedServicesTotal,
      cleartextOrVersionExposedCount,
      findingsTotal: findings.length,
      findingsBySeverity,
    },
    topFactors,
    highestRiskAssets,
    computedAt: new Date().toISOString(),
  };
}
