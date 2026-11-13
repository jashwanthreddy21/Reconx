import type {
  Assessment,
  Asset,
  AssetType,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  AssetRelationship,
  AssetEvidence,
  AssetCorrelation,
  CorrelationAnomaly,
  AIAnalysis,
  FindingSeverity,
} from '../types/index.ts';

/**
 * Normalizes raw asset values into a canonical, deterministic format
 * so duplicate discoveries across Subfinder, Amass, dnsx, httpx, Nmap, and WhatWeb merge cleanly.
 */
export function normalizeAssetValue(value: string, type: AssetType): string {
  if (!value) return '';
  let cleaned = value.trim().toLowerCase();

  if (type === 'root_domain' || type === 'subdomain') {
    cleaned = cleaned.replace(/^\*\./, '').replace(/\.+$/, '');
    cleaned = cleaned.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    return cleaned;
  }

  if (type === 'ip_address') {
    return cleaned.replace(/^\[|\]$/g, '').split('/')[0];
  }

  if (type === 'port') {
    return cleaned.replace(/\s+/g, '');
  }

  if (type === 'endpoint') {
    try {
      const url = new URL(cleaned.startsWith('http') ? cleaned : `https://${cleaned}`);
      const isDefaultPort =
        (url.protocol === 'https:' && (url.port === '' || url.port === '443')) ||
        (url.protocol === 'http:' && (url.port === '' || url.port === '80'));
      const portPart = isDefaultPort || !url.port ? '' : `:${url.port}`;
      const pathPart = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
      return `${url.protocol}//${url.hostname}${portPart}${pathPart}`;
    } catch {
      return cleaned.replace(/\/$/, '');
    }
  }

  if (type === 'service') {
    return cleaned.replace(/\s+/g, ' ');
  }

  if (type === 'technology') {
    return cleaned.replace(/\s+/g, ' ');
  }

  return cleaned;
}

/**
 * Generates a deterministic, stable asset identifier across assessments for a given type and value.
 */
export function generateStableAssetId(type: AssetType, normalizedValue: string): string {
  const safe = normalizedValue.replace(/[^a-z0-9]/gi, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
  return `ast_${type}_${safe.slice(0, 90)}`;
}

/**
 * Calculates a deterministic confidence score (0 - 100) based on:
 * - Number of distinct corroborating reconnaissance tools
 * - Direct active verification vs passive observation
 * - Presence of concrete network/DNS/HTTP evidence
 * Supports both object and positional argument invocation.
 */
export function calculateConfidenceScore(
  paramsOrTools:
    | {
        sourceTools: string[];
        hasDnsResolution?: boolean;
        hasActiveProbe?: boolean;
        isSimulated?: boolean;
      }
    | string[],
  hasDnsResolutionArg?: boolean,
  hasActiveProbeArg?: boolean
): number {
  const sourceTools = Array.isArray(paramsOrTools)
    ? paramsOrTools
    : paramsOrTools?.sourceTools || [];
  const hasDnsResolution = Array.isArray(paramsOrTools)
    ? Boolean(hasDnsResolutionArg)
    : Boolean(paramsOrTools?.hasDnsResolution);
  const hasActiveProbe = Array.isArray(paramsOrTools)
    ? Boolean(hasActiveProbeArg)
    : Boolean(paramsOrTools?.hasActiveProbe);

  const uniqueTools = Array.from(
    new Set(
      sourceTools
        .flatMap((s) => String(s || '').split(/[,/]/))
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    )
  );

  let score = 68;
  if (uniqueTools.length >= 3) {
    score += 24;
  } else if (uniqueTools.length === 2) {
    score += 16;
  } else if (uniqueTools.length === 1) {
    score += 6;
  }

  if (hasDnsResolution) score += 5;
  if (hasActiveProbe) score += 5;

  return Math.min(99, Math.max(40, score));
}

export interface CorrelationEngineOutput {
  normalizedAssets: Asset[];
  relationships: AssetRelationship[];
  evidences: AssetEvidence[];
  correlationSummary: AssetCorrelation;
}

export interface CorrelationParams {
  assessment: Assessment;
  rawAssets: Asset[];
  dnsRecords?: DnsRecord[];
  endpoints?: WebEndpoint[];
  services?: NetworkService[];
  findings?: Finding[];
}

const HIGH_RISK_PORTS = new Set([21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]);

/**
 * Core Asset Correlation Engine
 * Supports both object parameter `{ assessment, rawAssets, dnsRecords, endpoints, services, findings }`
 * and positional parameters `(assessment, rawAssets, dnsRecords, endpoints, services, findings)`.
 */
export function runAssetCorrelationEngine(
  paramsOrAssessment: CorrelationParams | Assessment,
  rawAssetsArg: Asset[] = [],
  dnsRecordsArg: DnsRecord[] = [],
  endpointsArg: WebEndpoint[] = [],
  servicesArg: NetworkService[] = [],
  findingsArg: Finding[] = []
): CorrelationEngineOutput {
  const isParamsObj =
    paramsOrAssessment &&
    typeof paramsOrAssessment === 'object' &&
    'assessment' in paramsOrAssessment &&
    paramsOrAssessment.assessment !== undefined;

  const assessment: Assessment = isParamsObj
    ? (paramsOrAssessment as CorrelationParams).assessment
    : (paramsOrAssessment as Assessment);

  const rawAssets: Asset[] = isParamsObj
    ? (paramsOrAssessment as CorrelationParams).rawAssets || []
    : rawAssetsArg || [];
  const dnsRecords: DnsRecord[] = isParamsObj
    ? (paramsOrAssessment as CorrelationParams).dnsRecords || []
    : dnsRecordsArg || [];
  const endpoints: WebEndpoint[] = isParamsObj
    ? (paramsOrAssessment as CorrelationParams).endpoints || []
    : endpointsArg || [];
  const services: NetworkService[] = isParamsObj
    ? (paramsOrAssessment as CorrelationParams).services || []
    : servicesArg || [];
  const findings: Finding[] = isParamsObj
    ? (paramsOrAssessment as CorrelationParams).findings || []
    : findingsArg || [];

  const now = new Date().toISOString();
  const safeAssessmentId = assessment?.id || 'asm_default';
  const safeOwnerId = assessment?.ownerId || 'operator';
  const rawRootDomain = assessment?.scope?.rootDomain || 'example.com';
  const rootDomain = normalizeAssetValue(rawRootDomain, 'root_domain') || 'example.com';

  const assetMap = new Map<string, Asset>();
  const evidences: AssetEvidence[] = [];
  const relationshipsMap = new Map<string, AssetRelationship>();
  let duplicatesMergedCount = 0;

  const registerEvidence = (assetId: string, sourceTool: string, rawRef: string, timestamp?: string): AssetEvidence => {
    const evId = `ev_${safeAssessmentId}_${assetId}_${sourceTool.replace(/[^a-z0-9]/gi, '_')}_${evidences.length}`.slice(0, 120);
    const ev: AssetEvidence = {
      id: evId,
      assessmentId: safeAssessmentId,
      ownerId: safeOwnerId,
      assetId,
      sourceTool,
      rawOutputReference: rawRef,
      discoveredAt: timestamp || now,
    };
    evidences.push(ev);
    return ev;
  };

  const upsertAsset = (candidate: {
    canonicalName: string;
    assetType: AssetType;
    discoverySource: string;
    status: Asset['status'];
    firstSeen?: string;
    lastSeen?: string;
    ipAddress?: string;
    parentHostname?: string;
    metadata?: Record<string, any>;
    rawEvidence: string;
  }): Asset => {
    const norm = normalizeAssetValue(candidate.canonicalName, candidate.assetType);
    const key = `${candidate.assetType}::${norm}`;
    const existing = assetMap.get(key);

    const incomingSources = (candidate.discoverySource || 'ReconX')
      .split(/[,+]/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (existing) {
      duplicatesMergedCount++;
      const mergedSources = Array.from(new Set([...(existing.sources || [existing.discoverySource]), ...incomingSources]));
      existing.sources = mergedSources;
      existing.discoverySource = mergedSources.join(', ');
      if (candidate.firstSeen && candidate.firstSeen < existing.firstSeen) {
        existing.firstSeen = candidate.firstSeen;
      }
      if (candidate.lastSeen && candidate.lastSeen > existing.lastSeen) {
        existing.lastSeen = candidate.lastSeen;
      }
      if (candidate.ipAddress && !existing.ipAddress) {
        existing.ipAddress = candidate.ipAddress;
      }
      if (candidate.parentHostname && !existing.parentHostname) {
        existing.parentHostname = candidate.parentHostname;
      }
      existing.metadata = { ...(existing.metadata || {}), ...(candidate.metadata || {}) };
      existing.confidenceScore = calculateConfidenceScore({
        sourceTools: mergedSources,
        hasDnsResolution: Boolean(existing.ipAddress),
        hasActiveProbe: existing.status === 'active',
      });
      registerEvidence(existing.id, candidate.discoverySource, candidate.rawEvidence, candidate.lastSeen);
      return existing;
    }

    const stableId = `${safeAssessmentId}_${generateStableAssetId(candidate.assetType, norm)}`.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120);
    const created: Asset = {
      id: stableId,
      assessmentId: safeAssessmentId,
      ownerId: safeOwnerId,
      canonicalName: candidate.assetType === 'subdomain' || candidate.assetType === 'root_domain' ? norm : candidate.canonicalName.trim(),
      assetValue: candidate.canonicalName.trim(),
      normalizedValue: norm,
      assetType: candidate.assetType,
      discoverySource: incomingSources.join(', ') || 'ReconX',
      sources: incomingSources,
      status: candidate.status,
      firstSeen: candidate.firstSeen || now,
      lastSeen: candidate.lastSeen || now,
      ipAddress: candidate.ipAddress,
      parentHostname: candidate.parentHostname,
      openPorts: [],
      detectedServices: [],
      detectedTechnologies: [],
      associatedDomains: [],
      isPotentiallyExposed: false,
      isExposedRisk: false,
      exposureReasons: [],
      riskLevel: 'informational',
      confidenceScore: calculateConfidenceScore({
        sourceTools: incomingSources,
        hasDnsResolution: Boolean(candidate.ipAddress),
        hasActiveProbe: candidate.status === 'active',
      }),
      metadata: candidate.metadata || {},
    };

    assetMap.set(key, created);
    registerEvidence(created.id, created.discoverySource, candidate.rawEvidence, created.firstSeen);
    return created;
  };

  const markExposed = (asset: Asset, reason: string, level: FindingSeverity = 'medium') => {
    asset.isPotentiallyExposed = true;
    asset.isExposedRisk = true;
    asset.riskLevel = level;
    if (!asset.exposureReasons?.includes(reason)) {
      asset.exposureReasons = [...(asset.exposureReasons || []), reason];
    }
    asset.riskReason = asset.exposureReasons.join('; ');
  };

  // 1. Ensure Root Domain exists
  const rootAsset = upsertAsset({
    canonicalName: rootDomain,
    assetType: 'root_domain',
    discoverySource: 'Scope Definition',
    status: 'active',
    rawEvidence: `Authorized root domain scope: ${rootDomain}`,
    metadata: { validatedScope: true },
  });

  // 2. Process all raw assets
  for (const raw of rawAssets) {
    if (!raw || !raw.canonicalName) continue;
    upsertAsset({
      canonicalName: raw.canonicalName,
      assetType: raw.assetType,
      discoverySource: raw.discoverySource || 'Subfinder',
      status: raw.status || 'observed',
      firstSeen: raw.firstSeen,
      lastSeen: raw.lastSeen,
      ipAddress: raw.ipAddress,
      parentHostname: raw.parentHostname,
      metadata: raw.metadata,
      rawEvidence: `Asset cataloged by ${raw.discoverySource}: ${raw.canonicalName}`,
    });
  }

  // 3. Process DNS records (dnsx)
  for (const dns of dnsRecords) {
    const hostNorm = normalizeAssetValue(dns.hostname, dns.hostname === rootDomain ? 'root_domain' : 'subdomain');
    const hostType: AssetType = hostNorm === rootDomain ? 'root_domain' : 'subdomain';
    const hostAsset = upsertAsset({
      canonicalName: hostNorm,
      assetType: hostType,
      discoverySource: dns.source || 'dnsx',
      status: 'resolved',
      firstSeen: dns.timestamp,
      lastSeen: dns.timestamp,
      parentHostname: hostType === 'subdomain' ? rootDomain : undefined,
      rawEvidence: `DNS ${dns.recordType} query for ${dns.hostname} -> ${dns.value} (TTL ${dns.ttl ?? 300})`,
    });

    if (dns.recordType === 'A' || dns.recordType === 'AAAA') {
      const ipVal = dns.value.trim();
      hostAsset.ipAddress = ipVal;
      const ipAsset = upsertAsset({
        canonicalName: ipVal,
        assetType: 'ip_address',
        discoverySource: dns.source || 'dnsx',
        status: 'resolved',
        firstSeen: dns.timestamp,
        lastSeen: dns.timestamp,
        ipAddress: ipVal,
        rawEvidence: `${dns.hostname} IN ${dns.recordType} ${ipVal}`,
        metadata: { ttl: dns.ttl, recordType: dns.recordType },
      });

      if (!ipAsset.associatedDomains?.includes(hostAsset.canonicalName)) {
        ipAsset.associatedDomains = [...(ipAsset.associatedDomains || []), hostAsset.canonicalName];
      }

      const isPrivateIp = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)/.test(ipVal);
      const isLabScope = rootDomain.endsWith('.internal') || rootDomain.endsWith('.local') || Boolean(assessment?.isDemo);
      const isSuspiciousDns = isPrivateIp && !isLabScope;

      addRelationship({
        source: hostAsset,
        target: ipAsset,
        type: 'RESOLVES_TO',
        sourceTool: dns.source || 'dnsx',
        evidenceSummary: `DNS ${dns.recordType} record maps ${hostAsset.canonicalName} -> ${ipVal} (TTL: ${dns.ttl ?? 300}s)`,
        confidenceScore: 95,
        isSuspicious: isSuspiciousDns,
        suspicionReason: isSuspiciousDns ? 'Public hostname resolves to internal RFC1918 private IP address (potential DNS split-horizon leak)' : undefined,
      });
    } else if (dns.recordType === 'CNAME') {
      const cnameTarget = normalizeAssetValue(dns.value, 'subdomain');
      const isExternalCname = !cnameTarget.endsWith(rootDomain);
      const targetSubAsset = upsertAsset({
        canonicalName: cnameTarget,
        assetType: 'subdomain',
        discoverySource: dns.source || 'dnsx',
        status: 'observed',
        firstSeen: dns.timestamp,
        lastSeen: dns.timestamp,
        rawEvidence: `${dns.hostname} IN CNAME ${cnameTarget}`,
        metadata: { externalAlias: isExternalCname },
      });

      addRelationship({
        source: hostAsset,
        target: targetSubAsset,
        type: 'CNAME_TO',
        sourceTool: dns.source || 'dnsx',
        evidenceSummary: `DNS CNAME alias ${hostAsset.canonicalName} -> ${cnameTarget}`,
        confidenceScore: 92,
        isSuspicious: isExternalCname,
        suspicionReason: isExternalCname
          ? `CNAME points to external domain (${cnameTarget}) — verify target registration to prevent subdomain takeover`
          : undefined,
      });
    }
  }

  // 4. Connect all Subdomains -> Root Domain (HAS_SUBDOMAIN)
  for (const asset of assetMap.values()) {
    if (asset.assetType === 'subdomain') {
      if (asset.normalizedValue?.endsWith(rootDomain)) {
        if (!asset.associatedDomains?.includes(rootDomain)) {
          asset.associatedDomains = [...(asset.associatedDomains || []), rootDomain];
        }
        addRelationship({
          source: rootAsset,
          target: asset,
          type: 'HAS_SUBDOMAIN',
          sourceTool: asset.discoverySource,
          evidenceSummary: `Subdomain ${asset.canonicalName} discovered under root scope ${rootDomain} via ${asset.discoverySource}`,
          confidenceScore: asset.confidenceScore || 90,
        });
      }
    }
  }

  // 5. Process Network Services & Ports (Nmap)
  for (const svc of services) {
    if (svc.state === 'closed') continue;

    const ipVal = svc.ip || '0.0.0.0';
    const ipAsset = upsertAsset({
      canonicalName: ipVal,
      assetType: 'ip_address',
      discoverySource: svc.toolSource || 'Nmap',
      status: 'active',
      firstSeen: svc.timestamp,
      lastSeen: svc.timestamp,
      ipAddress: ipVal,
      rawEvidence: `Nmap host discovery on ${ipVal} (${svc.host})`,
    });

    if (svc.host) {
      const hostNorm = normalizeAssetValue(svc.host, svc.host === rootDomain ? 'root_domain' : 'subdomain');
      const hostAsset = upsertAsset({
        canonicalName: hostNorm,
        assetType: hostNorm === rootDomain ? 'root_domain' : 'subdomain',
        discoverySource: svc.toolSource || 'Nmap',
        status: 'active',
        ipAddress: ipVal,
        rawEvidence: `Host ${svc.host} scanned by Nmap (${ipVal})`,
      });
      if (!hostAsset.openPorts?.includes(svc.port)) {
        hostAsset.openPorts = [...(hostAsset.openPorts || []), svc.port];
      }
      if (!hostAsset.detectedServices?.includes(svc.serviceName)) {
        hostAsset.detectedServices = [...(hostAsset.detectedServices || []), `${svc.serviceName}${svc.version ? ` (${svc.version})` : ''}`];
      }
      addRelationship({
        source: hostAsset,
        target: ipAsset,
        type: 'RESOLVES_TO',
        sourceTool: svc.toolSource || 'Nmap',
        evidenceSummary: `Host ${hostAsset.canonicalName} resolved to ${ipVal} during port scan`,
        confidenceScore: 94,
      });
    }

    if (!ipAsset.openPorts?.includes(svc.port)) {
      ipAsset.openPorts = [...(ipAsset.openPorts || []), svc.port];
    }

    const portCanonical = `${ipVal}:${svc.port}/${svc.protocol}`;
    const isHighRiskPort = HIGH_RISK_PORTS.has(svc.port) && ![80, 443].includes(svc.port);
    const portAsset = upsertAsset({
      canonicalName: portCanonical,
      assetType: 'port',
      discoverySource: svc.toolSource || 'Nmap',
      status: svc.state === 'open' ? 'active' : 'observed',
      firstSeen: svc.timestamp,
      lastSeen: svc.timestamp,
      ipAddress: ipVal,
      parentHostname: svc.host,
      rawEvidence: `Port ${svc.port}/${svc.protocol} state=${svc.state} on ${ipVal}`,
      metadata: {
        port: svc.port,
        protocol: svc.protocol,
        state: svc.state,
        host: svc.host,
      },
    });
    portAsset.openPorts = [svc.port];
    if (isHighRiskPort) {
      markExposed(
        portAsset,
        `Administrative or database port ${svc.port}/${svc.protocol} (${svc.serviceName}) reachable externally`,
        [3306, 5432, 6379, 27017, 9200].includes(svc.port) ? 'high' : 'medium'
      );
    }

    addRelationship({
      source: ipAsset,
      target: portAsset,
      type: 'EXPOSES_PORT',
      sourceTool: svc.toolSource || 'Nmap',
      evidenceSummary: `${ipVal} exposes port ${svc.port}/${svc.protocol} (${svc.state.toUpperCase()})`,
      confidenceScore: svc.state === 'open' ? 96 : 78,
      isSuspicious: isHighRiskPort,
      suspicionReason: isHighRiskPort
        ? `Sensitive port ${svc.port}/${svc.protocol} (${svc.serviceName}) exposed on ${ipVal}`
        : undefined,
    });

    const serviceLabel = `${svc.serviceName}${svc.version ? ` ${svc.version}` : ''} (${svc.host}:${svc.port})`;
    const svcAsset = upsertAsset({
      canonicalName: serviceLabel,
      assetType: 'service',
      discoverySource: svc.toolSource || 'Nmap',
      status: 'active',
      firstSeen: svc.timestamp,
      lastSeen: svc.timestamp,
      ipAddress: ipVal,
      parentHostname: svc.host,
      rawEvidence: `Service fingerprint on ${ipVal}:${svc.port} -> ${svc.serviceName} ${svc.version || ''}`,
      metadata: {
        port: svc.port,
        protocol: svc.protocol,
        serviceName: svc.serviceName,
        version: svc.version,
        state: svc.state,
        host: svc.host,
      },
    });
    if (isHighRiskPort) {
      markExposed(
        svcAsset,
        `Service ${svc.serviceName} listening on non-standard or sensitive port ${svc.port}`,
        portAsset.riskLevel || 'medium'
      );
    }
    if (!ipAsset.detectedServices?.includes(svc.serviceName)) {
      ipAsset.detectedServices = [...(ipAsset.detectedServices || []), `${svc.serviceName}${svc.version ? ` (${svc.version})` : ''}`];
    }

    addRelationship({
      source: portAsset,
      target: svcAsset,
      type: 'RUNS_SERVICE',
      sourceTool: svc.toolSource || 'Nmap',
      evidenceSummary: `Port ${svc.port}/${svc.protocol} runs ${svc.serviceName}${svc.version ? ` (${svc.version})` : ''}`,
      confidenceScore: svc.version ? 95 : 85,
    });
  }

  // 6. Process Web Endpoints (httpx) & Technologies (WhatWeb)
  for (const ep of endpoints) {
    const epAsset = upsertAsset({
      canonicalName: ep.url,
      assetType: 'endpoint',
      discoverySource: 'httpx',
      status: 'active',
      firstSeen: ep.timestamp,
      lastSeen: ep.timestamp,
      ipAddress: ep.ip,
      parentHostname: ep.hostname,
      rawEvidence: `HTTP probe ${ep.url} -> Status ${ep.statusCode} Title "${ep.title}"`,
      metadata: {
        statusCode: ep.statusCode,
        title: ep.title,
        port: ep.port,
        protocol: ep.protocol,
        tlsInfo: ep.tlsInfo,
        technologies: ep.technologies,
      },
    });
    epAsset.openPorts = [ep.port];
    epAsset.detectedTechnologies = ep.technologies || [];

    if (ep.protocol === 'http' && ep.statusCode === 200) {
      markExposed(epAsset, 'Unencrypted HTTP endpoint responds with 200 OK instead of redirecting to HTTPS', 'medium');
    }
    if ([401, 403, 500, 502, 503].includes(ep.statusCode) || ep.port === 8080 || ep.port === 8443) {
      markExposed(epAsset, `Endpoint on port ${ep.port} returned HTTP ${ep.statusCode} (${ep.title})`, 'medium');
    }

    const hostNorm = normalizeAssetValue(ep.hostname, ep.hostname === rootDomain ? 'root_domain' : 'subdomain');
    const hostAsset = upsertAsset({
      canonicalName: hostNorm,
      assetType: hostNorm === rootDomain ? 'root_domain' : 'subdomain',
      discoverySource: 'httpx',
      status: 'active',
      ipAddress: ep.ip,
      rawEvidence: `Host ${ep.hostname} serves web endpoint ${ep.url}`,
    });

    addRelationship({
      source: hostAsset,
      target: epAsset,
      type: 'SERVES_ENDPOINT',
      sourceTool: 'httpx',
      evidenceSummary: `${hostAsset.canonicalName} serves ${ep.url} [HTTP ${ep.statusCode}]`,
      confidenceScore: 97,
      isSuspicious: ep.protocol === 'http' && ep.statusCode === 200,
      suspicionReason: ep.protocol === 'http' && ep.statusCode === 200 ? 'Cleartext HTTP service without HTTPS redirect' : undefined,
    });

    for (const techName of ep.technologies || []) {
      const techAsset = upsertAsset({
        canonicalName: techName,
        assetType: 'technology',
        discoverySource: 'httpx, WhatWeb',
        status: 'observed',
        firstSeen: ep.timestamp,
        lastSeen: ep.timestamp,
        parentHostname: ep.hostname,
        rawEvidence: `Technology "${techName}" fingerprinted on ${ep.url}`,
        metadata: { name: techName, endpointUrl: ep.url },
      });

      if (!hostAsset.detectedTechnologies?.includes(techName)) {
        hostAsset.detectedTechnologies = [...(hostAsset.detectedTechnologies || []), techName];
      }

      addRelationship({
        source: epAsset,
        target: techAsset,
        type: 'USES_TECHNOLOGY',
        sourceTool: 'WhatWeb / httpx',
        evidenceSummary: `Endpoint ${ep.url} fingerprinted with technology ${techName}`,
        confidenceScore: 90,
      });
    }
  }

  const primaryEndpoint =
    Array.from(assetMap.values()).find((a) => a.assetType === 'endpoint' && a.canonicalName.startsWith('https://')) ||
    Array.from(assetMap.values()).find((a) => a.assetType === 'endpoint') ||
    rootAsset;

  for (const asset of assetMap.values()) {
    if (asset.assetType === 'technology') {
      const hasIncoming = Array.from(relationshipsMap.values()).some((r) => r.targetAssetId === asset.id);
      if (!hasIncoming && primaryEndpoint) {
        addRelationship({
          source: primaryEndpoint,
          target: asset,
          type: 'USES_TECHNOLOGY',
          sourceTool: asset.discoverySource || 'WhatWeb',
          evidenceSummary: `${primaryEndpoint.canonicalName} uses fingerprinted technology ${asset.canonicalName}`,
          confidenceScore: asset.confidenceScore || 88,
        });
      }
    }
  }

  // 7. Correlate Findings to mark potentially exposed assets
  for (const f of findings) {
    for (const asset of assetMap.values()) {
      if (
        f.assetRef &&
        (f.assetRef.toLowerCase().includes(asset.normalizedValue || asset.canonicalName.toLowerCase()) ||
          asset.canonicalName.toLowerCase().includes(f.assetRef.toLowerCase()))
      ) {
        if (f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium') {
          markExposed(asset, f.title, f.severity);
        }
      }
    }
  }

  function addRelationship(params: {
    source: Asset;
    target: Asset;
    type: AssetRelationship['relationshipType'];
    sourceTool: string;
    evidenceSummary: string;
    confidenceScore: number;
    isSuspicious?: boolean;
    suspicionReason?: string;
  }) {
    if (params.source.id === params.target.id) return;
    const relKey = `${params.source.id}__${params.type}__${params.target.id}`;
    const existing = relationshipsMap.get(relKey);
    if (existing) {
      if (!existing.sourceTool.includes(params.sourceTool)) {
        existing.sourceTool = `${existing.sourceTool}, ${params.sourceTool}`;
        existing.confidenceScore = Math.min(99, existing.confidenceScore + 4);
      }
      return;
    }

    const ev = registerEvidence(params.source.id, params.sourceTool, params.evidenceSummary, now);
    const relId = `rel_${safeAssessmentId}_${relationshipsMap.size + 1}`.replace(/[^a-zA-Z0-9_-]/g, '_');

    relationshipsMap.set(relKey, {
      id: relId,
      assessmentId: safeAssessmentId,
      ownerId: safeOwnerId,
      sourceAssetId: params.source.id,
      sourceAssetName: params.source.canonicalName,
      sourceAssetType: params.source.assetType,
      sourceName: params.source.canonicalName,
      sourceType: params.source.assetType,
      targetAssetId: params.target.id,
      targetAssetName: params.target.canonicalName,
      targetAssetType: params.target.assetType,
      targetName: params.target.canonicalName,
      targetType: params.target.assetType,
      relationshipType: params.type,
      confidenceScore: params.confidenceScore,
      evidenceId: ev.id,
      evidenceSummary: params.evidenceSummary,
      evidenceSnippet: params.evidenceSummary,
      sourceTool: params.sourceTool,
      isSuspicious: Boolean(params.isSuspicious),
      suspicionReason: params.suspicionReason,
      discoveredAt: now,
    });
  }

  // 8. Detect Correlation Anomalies & Suspicious Exposure Patterns
  const anomalies: CorrelationAnomaly[] = [];
  const allAssets = Array.from(assetMap.values());
  const allRelationships = Array.from(relationshipsMap.values());

  const exposedDbOrAdminPorts = allAssets.filter(
    (a) => a.assetType === 'port' && a.isPotentiallyExposed
  );
  if (exposedDbOrAdminPorts.length > 0) {
    anomalies.push({
      id: `anom_${safeAssessmentId}_exposed_ports`,
      title: 'Administrative or Database Services Exposed to Network Vantage Point',
      description: `Correlated Nmap and DNS data indicates ${exposedDbOrAdminPorts.length} sensitive port(s) (${exposedDbOrAdminPorts
        .map((p) => p.canonicalName)
        .join(', ')}) are reachable on infrastructure resolving to ${rootDomain}.`,
      severity: exposedDbOrAdminPorts.some((p) => p.riskLevel === 'high') ? 'high' : 'medium',
      affectedAssets: exposedDbOrAdminPorts.map((p) => p.canonicalName),
      sourceTools: ['Nmap', 'dnsx'],
      sourceTool: 'Nmap, dnsx',
      confidenceScore: 94,
      evidence: exposedDbOrAdminPorts.map((p) => p.exposureReasons?.[0] || p.canonicalName).join('; '),
    });
  }

  const unresolvedSubdomains = allAssets.filter(
    (a) =>
      a.assetType === 'subdomain' &&
      !allRelationships.some((r) => r.sourceAssetId === a.id && (r.relationshipType === 'RESOLVES_TO' || r.relationshipType === 'CNAME_TO'))
  );
  if (unresolvedSubdomains.length > 0) {
    anomalies.push({
      id: `anom_${safeAssessmentId}_unresolved_subs`,
      title: 'Unresolved or Dormant Subdomains in Certificate Transparency Logs',
      description: `${unresolvedSubdomains.length} subdomain(s) discovered via passive reconnaissance did not return active A/AAAA/CNAME records during dnsx resolution. Verify whether these are decommissioned hosts or dangling DNS entries.`,
      severity: 'low',
      affectedAssets: unresolvedSubdomains.map((s) => s.canonicalName),
      sourceTools: ['Subfinder', 'dnsx'],
      sourceTool: 'Subfinder, dnsx',
      confidenceScore: 86,
      evidence: `Subdomains present in passive inventory without active DNS resolution: ${unresolvedSubdomains
        .slice(0, 5)
        .map((s) => s.canonicalName)
        .join(', ')}`,
    });
  }

  const ipAssets = allAssets.filter((a) => a.assetType === 'ip_address');
  for (const ip of ipAssets) {
    const hostedDomains = ip.associatedDomains || [];
    const hasDevOrStaging = hostedDomains.some((d) => /^(dev|staging|test|uat)\./i.test(d));
    const hasProdOrAuth = hostedDomains.some((d) => /^(auth|api|portal|www)\./i.test(d) || d === rootDomain);
    if (hasDevOrStaging && hasProdOrAuth) {
      markExposed(
        ip,
        `Co-hosts non-production (${hostedDomains.filter((d) => /^(dev|staging)/i.test(d)).join(', ')}) and production services on ${ip.canonicalName}`,
        'medium'
      );
      anomalies.push({
        id: `anom_${safeAssessmentId}_shared_env_${ip.normalizedValue}`,
        title: 'Production and Development Environments Co-Hosted on Shared IP',
        description: `IP address ${ip.canonicalName} simultaneously resolves both development/staging hostnames and production/authentication services (${hostedDomains.join(
          ', '
        )}). A compromise in a less-hardened dev instance could enable lateral movement.`,
        severity: 'medium',
        affectedAssets: [ip.canonicalName, ...hostedDomains],
        sourceTools: ['Subfinder', 'dnsx', 'httpx'],
        sourceTool: 'Subfinder, dnsx, httpx',
        confidenceScore: 95,
        evidence: `DNS A records map [${hostedDomains.join(', ')}] -> ${ip.canonicalName}`,
      });
    }
  }

  const suspiciousRels = allRelationships.filter((r) => r.isSuspicious);
  for (const sr of suspiciousRels) {
    if (!anomalies.some((a) => a.affectedAssets.includes(sr.targetAssetName))) {
      anomalies.push({
        id: `anom_${safeAssessmentId}_rel_${sr.id}`,
        title: `Suspicious Asset Relationship: ${sr.sourceAssetName} → ${sr.targetAssetName}`,
        description: sr.suspicionReason || `Unusual relationship (${sr.relationshipType}) detected between ${sr.sourceAssetName} and ${sr.targetAssetName}.`,
        severity: 'medium',
        affectedAssets: [sr.sourceAssetName, sr.targetAssetName],
        sourceTools: [sr.sourceTool],
        sourceTool: sr.sourceTool,
        confidenceScore: sr.confidenceScore,
        evidence: sr.evidenceSummary,
      });
    }
  }

  const potentiallyExposedCount = allAssets.filter((a) => a.isPotentiallyExposed || a.isExposedRisk).length;
  const uniqueDomains = allAssets.filter((a) => a.assetType === 'root_domain').length;
  const uniqueSubdomains = allAssets.filter((a) => a.assetType === 'subdomain').length;
  const uniqueIps = allAssets.filter((a) => a.assetType === 'ip_address').length;
  const openPortsCount = allAssets.filter((a) => a.assetType === 'port').length;
  const detectedServicesCount = allAssets.filter((a) => a.assetType === 'service').length;
  const detectedTechnologiesCount = allAssets.filter((a) => a.assetType === 'technology').length;

  const correlationSummary: AssetCorrelation = {
    id: `corr_${safeAssessmentId}`,
    assessmentId: safeAssessmentId,
    ownerId: safeOwnerId,
    normalizedAssetsCount: allAssets.length,
    duplicatesMergedCount,
    relationshipsCount: allRelationships.length,
    suspiciousRelationshipsCount: suspiciousRels.length + anomalies.length,
    potentiallyExposedCount,
    totalAssets: allAssets.length,
    uniqueDomains,
    uniqueSubdomains,
    uniqueIps,
    openPortsCount,
    detectedServicesCount,
    detectedTechnologiesCount,
    correlatedRelationshipsCount: allRelationships.length,
    potentiallyExposedAssetsCount: potentiallyExposedCount,
    anomalies,
    createdAt: now,
    generatedAt: now,
  };

  return {
    normalizedAssets: allAssets,
    relationships: allRelationships,
    evidences,
    correlationSummary,
  };
}

export interface DeterministicAIParams {
  assessment: Assessment;
  assets: Asset[];
  relationships: AssetRelationship[];
  correlation: AssetCorrelation;
  findings?: Finding[];
}

/**
 * Deterministic Rule-Based AI Fallback Analysis Engine
 * Supports both object and positional parameter styles.
 */
export function generateDeterministicAIAnalysis(
  paramsOrAssessment: DeterministicAIParams | Assessment,
  assetsArg: Asset[] = [],
  relationshipsArg: AssetRelationship[] = [],
  correlationArg?: AssetCorrelation,
  findingsArg: Finding[] = []
): AIAnalysis {
  const isObj =
    paramsOrAssessment &&
    typeof paramsOrAssessment === 'object' &&
    'assessment' in paramsOrAssessment &&
    paramsOrAssessment.assessment !== undefined;

  const assessment: Assessment = isObj
    ? (paramsOrAssessment as DeterministicAIParams).assessment
    : (paramsOrAssessment as Assessment);
  const assets: Asset[] = isObj ? (paramsOrAssessment as DeterministicAIParams).assets || [] : assetsArg || [];
  const relationships: AssetRelationship[] = isObj
    ? (paramsOrAssessment as DeterministicAIParams).relationships || []
    : relationshipsArg || [];
  const correlation: AssetCorrelation = isObj
    ? (paramsOrAssessment as DeterministicAIParams).correlation
    : correlationArg!;
  const findings: Finding[] = isObj ? (paramsOrAssessment as DeterministicAIParams).findings || [] : findingsArg || [];

  const now = new Date().toISOString();
  const rootDomain = assessment?.scope?.rootDomain || 'example.com';

  const subdomains = assets.filter((a) => a.assetType === 'subdomain' || a.assetType === 'root_domain');
  const ips = assets.filter((a) => a.assetType === 'ip_address');
  const ports = assets.filter((a) => a.assetType === 'port');
  const services = assets.filter((a) => a.assetType === 'service');
  const endpoints = assets.filter((a) => a.assetType === 'endpoint');
  const technologies = assets.filter((a) => a.assetType === 'technology');
  const exposedAssets = assets.filter((a) => a.isPotentiallyExposed || a.isExposedRisk);
  const anomaliesList = correlation?.anomalies || [];

  const executiveSummary = `Deterministic correlation of authorized scope "${rootDomain}" (${assessment?.name || 'Assessment'}) synthesized ${assets.length} unique normalized assets and ${relationships.length} verified relationships across ${subdomains.length} hostnames, ${ips.length} IP addresses, ${ports.length} open/filtered ports, ${services.length} network services, ${endpoints.length} web endpoints, and ${technologies.length} fingerprinted technologies. ${exposedAssets.length} asset(s) and ${anomaliesList.length} structural correlation pattern(s) require prioritized security review.`;

  const relationshipInsights: string[] = [
    `Domain Hierarchy: Root domain ${rootDomain} branches into ${Math.max(0, subdomains.length - 1)} discovered subdomain(s) corroborated by passive CT logs and DNS resolution.`,
    `Network Topology: Hostnames resolve across ${ips.length} unique IP address(es), exposing ${ports.length} network port node(s) and ${services.length} fingerprinted service listener(s).`,
    `Application Stack: ${endpoints.length} active HTTP/HTTPS endpoint(s) utilize ${technologies.length} fingerprinted technologies (${
      technologies
        .slice(0, 5)
        .map((t) => t.canonicalName)
        .join(', ') || 'standard web stack'
    }).`,
  ];

  if ((correlation?.duplicatesMergedCount || 0) > 0) {
    relationshipInsights.push(
      `Cross-Tool Corroboration: Merged ${correlation.duplicatesMergedCount} overlapping tool observations into canonical asset records, increasing relationship confidence.`
    );
  }

  const unusualExposurePatterns: string[] = anomaliesList.map(
    (a) => `${a.title}: ${a.description} [Evidence: ${a.evidence}]`
  );

  if (unusualExposurePatterns.length === 0 && exposedAssets.length > 0) {
    unusualExposurePatterns.push(
      `Observed ${exposedAssets.length} asset(s) with non-standard ports or security findings attached: ${exposedAssets
        .map((e) => `${e.canonicalName} (${e.riskReason || e.exposureReasons?.join(', ') || 'flagged'})`)
        .join('; ')}`
    );
  }
  if (unusualExposurePatterns.length === 0) {
    unusualExposurePatterns.push(
      `All ${assets.length} discovered assets conform to standard perimeter patterns on ${rootDomain}.`
    );
  }

  const riskyConfigurations: string[] = findings.slice(0, 6).map(
    (f) => `${f.title} on ${f.assetRef}: ${f.description} (Remediation: ${f.remediation})`
  );
  if (riskyConfigurations.length === 0 && exposedAssets.length > 0) {
    exposedAssets.slice(0, 5).forEach((e) => {
      riskyConfigurations.push(
        `${e.canonicalName} (${e.assetType}): ${e.riskReason || e.exposureReasons?.join(', ') || 'Exposed surface requires review'}`
      );
    });
  }
  if (riskyConfigurations.length === 0) {
    riskyConfigurations.push(
      'No high-risk misconfigurations observed in current telemetry; continue enforcing TLS and firewall ACL baselines.'
    );
  }

  const scoredAssets = [...assets].sort((a, b) => {
    const scoreA = (a.isPotentiallyExposed || a.isExposedRisk ? 50 : 0) + (a.openPorts?.length || 0) * 10 + (a.confidenceScore || 50) * 0.2;
    const scoreB = (b.isPotentiallyExposed || b.isExposedRisk ? 50 : 0) + (b.openPorts?.length || 0) * 10 + (b.confidenceScore || 50) * 0.2;
    return scoreB - scoreA;
  });

  const prioritizedReviewList = scoredAssets.slice(0, 5).map((asset, idx) => {
    const reasonText =
      asset.exposureReasons && asset.exposureReasons.length > 0
        ? asset.exposureReasons.join('. ')
        : `Correlated across ${asset.discoverySource} with ${
            relationships.filter((r) => r.sourceAssetId === asset.id || r.targetAssetId === asset.id).length
          } connected infrastructure relationships.`;
    const stepText =
      asset.assetType === 'port' || asset.assetType === 'service'
        ? `Confirm firewall ACLs and service banner hardening on ${asset.canonicalName}.`
        : `Inspect HTTP security headers, TLS certificate chain, and authentication controls on ${asset.canonicalName}.`;
    const priority: FindingSeverity =
      asset.riskLevel && asset.riskLevel !== 'informational'
        ? asset.riskLevel
        : idx === 0
        ? 'high'
        : 'medium';

    return {
      rank: idx + 1,
      priority,
      assetName: asset.canonicalName,
      assetType: asset.assetType,
      reason: reasonText,
      rationale: reasonText,
      safeInvestigationStep: stepText,
      confidenceScore: asset.confidenceScore || 85,
      authorizedNextSteps: [
        `Verify scope authorization for ${asset.canonicalName} against ROE reference ${assessment?.scope?.authReference || 'N/A'}.`,
        stepText,
      ],
    };
  });

  return {
    id: `ai_analysis_${assessment?.id || 'default'}`,
    assessmentId: assessment?.id || 'default',
    ownerId: assessment?.ownerId || 'operator',
    provider: 'deterministic_fallback',
    mode: 'deterministic_fallback',
    modelUsed: 'ReconX Deterministic Rule Engine v2.0',
    executiveSummary,
    relationshipInsights,
    unusualExposurePatterns,
    riskyConfigurations,
    prioritizedReviewList,
    generatedAt: now,
  };
}
