import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  AssetRelationship,
  AssessmentSnapshot,
  SnapshotAssetDigest,
  AssetChange,
} from '../types';
import { normalizeAssetValue, generateStableAssetId } from './assetCorrelationEngine';

/**
 * Computes a deterministic string hash for asset metadata comparison across snapshots.
 */
function computeMetadataHash(digest: Omit<SnapshotAssetDigest, 'metadataHash'>): string {
  const payload = JSON.stringify({
    status: digest.status,
    ip: digest.ipAddress || '',
    ports: (digest.ports || []).slice().sort(),
    services: (digest.services || []).slice().sort(),
    tech: (digest.technologies || []).slice().sort(),
    statusCode: digest.statusCode || 0,
    dns: (digest.dnsRecords || []).slice().sort(),
    version: digest.version || '',
  });
  let hash = 0;
  for (let i = 0; i < payload.length; i++) {
    hash = (hash << 5) - hash + payload.charCodeAt(i);
    hash |= 0;
  }
  return `h_${Math.abs(hash).toString(16)}`;
}

export interface SnapshotCreateParams {
  assessment: Assessment;
  assets: Asset[];
  dnsRecords?: DnsRecord[];
  endpoints?: WebEndpoint[];
  services?: NetworkService[];
  relationships?: AssetRelationship[];
}

/**
 * Creates an immutable historical snapshot from an assessment and its correlated dataset.
 * Supports both object parameter `{ assessment, assets, dnsRecords, endpoints, services, relationships }`
 * and positional parameters `(assessment, assets, relationships, dnsRecords, endpoints, services)`.
 */
export function createAssessmentSnapshot(
  paramsOrAssessment: SnapshotCreateParams | Assessment,
  assetsArg: Asset[] = [],
  relationshipsArg: AssetRelationship[] = [],
  dnsRecordsArg: DnsRecord[] = [],
  endpointsArg: WebEndpoint[] = [],
  servicesArg: NetworkService[] = []
): AssessmentSnapshot {
  const isObj =
    paramsOrAssessment &&
    typeof paramsOrAssessment === 'object' &&
    'assessment' in paramsOrAssessment &&
    paramsOrAssessment.assessment !== undefined;

  const assessment: Assessment = isObj
    ? (paramsOrAssessment as SnapshotCreateParams).assessment
    : (paramsOrAssessment as Assessment);
  const assets: Asset[] = isObj ? (paramsOrAssessment as SnapshotCreateParams).assets || [] : assetsArg || [];
  const relationships: AssetRelationship[] = isObj
    ? (paramsOrAssessment as SnapshotCreateParams).relationships || []
    : relationshipsArg || [];
  const dnsRecords: DnsRecord[] = isObj
    ? (paramsOrAssessment as SnapshotCreateParams).dnsRecords || []
    : dnsRecordsArg || [];
  const endpoints: WebEndpoint[] = isObj
    ? (paramsOrAssessment as SnapshotCreateParams).endpoints || []
    : endpointsArg || [];
  const services: NetworkService[] = isObj
    ? (paramsOrAssessment as SnapshotCreateParams).services || []
    : servicesArg || [];

  const digestMap = new Map<string, SnapshotAssetDigest>();
  const assetMapObj: Record<string, SnapshotAssetDigest> = {};
  const countsByType: Record<string, number> = {
    root_domain: 0,
    subdomain: 0,
    ip_address: 0,
    port: 0,
    service: 0,
    endpoint: 0,
    technology: 0,
  };

  for (const a of assets) {
    const norm = a.normalizedValue || normalizeAssetValue(a.canonicalName, a.assetType);
    const stableId = generateStableAssetId(a.assetType, norm);

    const hostDns = dnsRecords
      .filter((d) => normalizeAssetValue(d.hostname, 'subdomain') === norm)
      .map((d) => `${d.recordType}:${d.value}`);

    const matchingEp = endpoints.find(
      (ep) => normalizeAssetValue(ep.url, 'endpoint') === norm || normalizeAssetValue(ep.hostname, 'subdomain') === norm
    );

    const matchingSvcs = services.filter(
      (s) =>
        normalizeAssetValue(s.host, 'subdomain') === norm ||
        s.ip === norm ||
        norm.includes(`${s.port}`)
    );

    const ports = Array.from(
      new Set([
        ...(a.openPorts || []),
        ...matchingSvcs.filter((s) => s.state === 'open' || s.state === 'filtered').map((s) => s.port),
      ])
    ).sort((x, y) => x - y);

    const svcNames = Array.from(
      new Set([
        ...(a.detectedServices || []),
        ...matchingSvcs.map((s) => `${s.serviceName}${s.version ? ` ${s.version}` : ''}`.trim()),
      ])
    );

    const techNames = Array.from(
      new Set([
        ...(a.detectedTechnologies || []),
        ...(matchingEp?.technologies || []),
      ])
    );

    const partialDigest: Omit<SnapshotAssetDigest, 'metadataHash'> = {
      stableId,
      canonicalName: a.canonicalName,
      normalizedValue: norm,
      assetType: a.assetType,
      status: a.status,
      discoverySource: a.discoverySource,
      ipAddress: a.ipAddress || matchingEp?.ip || matchingSvcs[0]?.ip,
      ports,
      services: svcNames,
      technologies: techNames,
      statusCode: a.metadata?.statusCode ?? matchingEp?.statusCode,
      dnsRecords: hostDns,
      version: a.metadata?.version || matchingSvcs[0]?.version,
    };

    const fullDigest: SnapshotAssetDigest = {
      ...partialDigest,
      metadataHash: computeMetadataHash(partialDigest),
    };

    digestMap.set(stableId, fullDigest);
    assetMapObj[stableId] = fullDigest;
    countsByType[a.assetType] = (countsByType[a.assetType] || 0) + 1;
  }

  const assetDigests = Array.from(digestMap.values());
  const openPortsSet = new Set<string>();
  services.forEach((s) => {
    if (s.state === 'open' || s.state === 'filtered') {
      openPortsSet.add(`${s.ip || s.host}:${s.port}`);
    }
  });
  assets.filter((a) => a.assetType === 'port').forEach((p) => openPortsSet.add(p.canonicalName));

  return {
    id: `snap_${assessment?.id || 'default'}`,
    assessmentId: assessment?.id || 'default',
    assessmentName: assessment?.name || 'Assessment',
    rootDomain: assessment?.scope?.rootDomain || 'example.com',
    ownerId: assessment?.ownerId || 'operator',
    snapshotTimestamp: assessment?.updatedAt || assessment?.createdAt || new Date().toISOString(),
    completionStatus: assessment?.status || 'completed',
    assetCount: assetDigests.length,
    relationshipCount: relationships.length,
    subdomainsCount: assetDigests.filter((d) => d.assetType === 'subdomain' || d.assetType === 'root_domain').length,
    ipCount: assetDigests.filter((d) => d.assetType === 'ip_address').length,
    openPortsCount: openPortsSet.size,
    servicesCount: assetDigests.filter((d) => d.assetType === 'service').length || services.length,
    endpointsCount: assetDigests.filter((d) => d.assetType === 'endpoint').length || endpoints.length,
    technologiesCount: assetDigests.filter((d) => d.assetType === 'technology').length,
    findingsCount: assessment?.stats?.findingsCount || 0,
    assetDigests,
    assetMap: assetMapObj,
    countsByType,
  };
}

export interface SnapshotComparisonResult {
  previousSnapshot: AssessmentSnapshot;
  latestSnapshot: AssessmentSnapshot;
  changes: AssetChange[];
  newAssets: AssetChange[];
  notObservedAssets: AssetChange[];
  modifiedAssets: AssetChange[];
  summary: {
    totalNew: number;
    totalNotObserved: number;
    totalModified: number;
    newAssetsCount: number;
    notObservedCount: number;
    modifiedAssetsCount: number;
    newlyExposedPortsCount: number;
    newlyDetectedServicesCount: number;
    technologyChangesCount: number;
    newSubdomains: number;
    newIps: number;
    newPorts: number;
    newServices: number;
    newEndpoints: number;
    newTechnologies: number;
    isLatestScanIncomplete: boolean;
    scanStatusWarning?: string;
  };
}

/**
 * Deterministic Historical Change Detection Engine
 * Compares a baseline AssessmentSnapshot against a latest AssessmentSnapshot.
 * Classifies changes into NEW, NOT_OBSERVED ("Not observed in latest scan"), and MODIFIED.
 */
export function compareAssessmentSnapshots(
  previousSnapshot: AssessmentSnapshot,
  latestSnapshot: AssessmentSnapshot,
  _previousAssessment?: Assessment,
  _latestAssessment?: Assessment
): SnapshotComparisonResult {
  const detectedAt = new Date().toISOString();
  const prevMap = new Map<string, SnapshotAssetDigest>();
  const latestMap = new Map<string, SnapshotAssetDigest>();

  for (const d of previousSnapshot.assetDigests || Object.values(previousSnapshot.assetMap || {})) {
    prevMap.set(d.stableId, d);
  }
  for (const d of latestSnapshot.assetDigests || Object.values(latestSnapshot.assetMap || {})) {
    latestMap.set(d.stableId, d);
  }

  const changesMap = new Map<string, AssetChange>();
  const isLatestScanIncomplete =
    latestSnapshot.completionStatus !== 'completed' ||
    (previousSnapshot.rootDomain || '').toLowerCase() !== (latestSnapshot.rootDomain || '').toLowerCase();

  const mapTypeToCategory = (t: SnapshotAssetDigest['assetType']): string => {
    switch (t) {
      case 'root_domain':
      case 'subdomain':
        return 'subdomain';
      case 'ip_address':
        return 'ip_address';
      case 'port':
        return 'port';
      case 'service':
        return 'service';
      case 'endpoint':
        return 'endpoint';
      case 'technology':
        return 'technology';
      default:
        return 'subdomain';
    }
  };

  // 1. Detect NEW and MODIFIED assets
  for (const [stableId, latestDigest] of latestMap.entries()) {
    const prevDigest = prevMap.get(stableId);

    if (!prevDigest) {
      const changeId = `chg_${latestSnapshot.assessmentId}_${previousSnapshot.assessmentId}_NEW_${stableId}`.slice(0, 120);
      const desc = `Newly discovered ${latestDigest.assetType.replace('_', ' ')} "${latestDigest.canonicalName}" via ${latestDigest.discoverySource}`;
      changesMap.set(changeId, {
        id: changeId,
        assessmentId: latestSnapshot.assessmentId,
        previousAssessmentId: previousSnapshot.assessmentId,
        ownerId: latestSnapshot.ownerId,
        assetId: stableId,
        assetName: latestDigest.canonicalName,
        canonicalName: latestDigest.canonicalName,
        normalizedValue: latestDigest.normalizedValue,
        assetType: latestDigest.assetType,
        changeType: 'NEW',
        changeCategory: mapTypeToCategory(latestDigest.assetType),
        changeDescription: desc,
        observationNote: desc,
        newValue: latestDigest.ipAddress || latestDigest.canonicalName,
        currentState: {
          ipAddress: latestDigest.ipAddress,
          statusCode: latestDigest.statusCode,
          ports: latestDigest.ports,
          services: latestDigest.services,
          technologies: latestDigest.technologies,
        },
        detectedAt,
        evidenceReference: `Observed by ${latestDigest.discoverySource} in "${latestSnapshot.assessmentName}" (${new Date(
          latestSnapshot.snapshotTimestamp
        ).toLocaleDateString()})`,
        sourceTool: latestDigest.discoverySource,
      });
    } else if (prevDigest.metadataHash !== latestDigest.metadataHash) {
      const modifications: string[] = [];
      let category = mapTypeToCategory(latestDigest.assetType);
      let prevVal = prevDigest.ipAddress || '';
      let newVal = latestDigest.ipAddress || '';

      if (prevDigest.ipAddress && latestDigest.ipAddress && prevDigest.ipAddress !== latestDigest.ipAddress) {
        modifications.push(`IP mapping changed from ${prevDigest.ipAddress} to ${latestDigest.ipAddress}`);
        category = 'dns_record';
        prevVal = prevDigest.ipAddress;
        newVal = latestDigest.ipAddress;
      }

      const prevDns = (prevDigest.dnsRecords || []).join(', ');
      const latestDns = (latestDigest.dnsRecords || []).join(', ');
      if (prevDns !== latestDns && (prevDns || latestDns)) {
        modifications.push(`DNS records updated: [${prevDns || 'none'}] → [${latestDns || 'none'}]`);
        category = 'dns_record';
        if (!prevVal) prevVal = prevDns;
        if (!newVal) newVal = latestDns;
      }

      if (
        prevDigest.statusCode !== undefined &&
        latestDigest.statusCode !== undefined &&
        prevDigest.statusCode !== latestDigest.statusCode
      ) {
        modifications.push(`HTTP status code changed from ${prevDigest.statusCode} to ${latestDigest.statusCode}`);
        category = 'endpoint';
        prevVal = `HTTP ${prevDigest.statusCode}`;
        newVal = `HTTP ${latestDigest.statusCode}`;
      }

      if (prevDigest.version !== latestDigest.version && (prevDigest.version || latestDigest.version)) {
        modifications.push(`Service/software version changed from "${prevDigest.version || 'unspecified'}" to "${latestDigest.version || 'unspecified'}"`);
        category = 'service';
        prevVal = prevDigest.version || 'unspecified';
        newVal = latestDigest.version || 'unspecified';
      }

      const prevPorts = (prevDigest.ports || []).join(',');
      const latestPorts = (latestDigest.ports || []).join(',');
      if (prevPorts !== latestPorts) {
        modifications.push(`Open ports changed from [${prevPorts || 'none'}] to [${latestPorts || 'none'}]`);
        category = 'port';
        prevVal = prevPorts;
        newVal = latestPorts;
      }

      const prevTech = (prevDigest.technologies || []).slice().sort().join(', ');
      const latestTech = (latestDigest.technologies || []).slice().sort().join(', ');
      if (prevTech !== latestTech) {
        modifications.push(`Technology fingerprint updated: [${prevTech || 'none'}] → [${latestTech || 'none'}]`);
        category = 'technology';
        prevVal = prevTech;
        newVal = latestTech;
      }

      if (modifications.length > 0) {
        const changeId = `chg_${latestSnapshot.assessmentId}_${previousSnapshot.assessmentId}_MOD_${stableId}`.slice(0, 120);
        const desc = modifications.join('; ');
        changesMap.set(changeId, {
          id: changeId,
          assessmentId: latestSnapshot.assessmentId,
          previousAssessmentId: previousSnapshot.assessmentId,
          ownerId: latestSnapshot.ownerId,
          assetId: stableId,
          assetName: latestDigest.canonicalName,
          canonicalName: latestDigest.canonicalName,
          normalizedValue: latestDigest.normalizedValue,
          assetType: latestDigest.assetType,
          changeType: 'MODIFIED',
          changeCategory: category,
          changeDescription: desc,
          observationNote: desc,
          previousValue: prevVal,
          newValue: newVal,
          previousState: {
            ipAddress: prevDigest.ipAddress,
            statusCode: prevDigest.statusCode,
            ports: prevDigest.ports,
            services: prevDigest.services,
            technologies: prevDigest.technologies,
            dnsRecords: prevDigest.dnsRecords,
            version: prevDigest.version,
          },
          currentState: {
            ipAddress: latestDigest.ipAddress,
            statusCode: latestDigest.statusCode,
            ports: latestDigest.ports,
            services: latestDigest.services,
            technologies: latestDigest.technologies,
            dnsRecords: latestDigest.dnsRecords,
            version: latestDigest.version,
          },
          detectedAt,
          evidenceReference: `Delta detected between "${previousSnapshot.assessmentName}" and "${latestSnapshot.assessmentName}" via ${latestDigest.discoverySource}`,
          sourceTool: latestDigest.discoverySource,
        });
      }
    }
  }

  // 2. Detect NOT_OBSERVED assets (present in baseline, absent in latest scan)
  for (const [stableId, prevDigest] of prevMap.entries()) {
    if (!latestMap.has(stableId)) {
      const changeId = `chg_${latestSnapshot.assessmentId}_${previousSnapshot.assessmentId}_UNOBS_${stableId}`.slice(0, 120);
      const confidenceNote =
        latestSnapshot.completionStatus !== 'completed'
          ? `Not observed in latest scan (status: "${latestSnapshot.completionStatus}"). Absence may be due to an incomplete scan or transient network timeout rather than permanent decommissioning.`
          : 'Not observed in latest scan. Verify whether asset was decommissioned, placed behind a firewall/VPN, or experienced transient DNS/probe timeout.';

      changesMap.set(changeId, {
        id: changeId,
        assessmentId: latestSnapshot.assessmentId,
        previousAssessmentId: previousSnapshot.assessmentId,
        ownerId: latestSnapshot.ownerId,
        assetId: stableId,
        assetName: prevDigest.canonicalName,
        canonicalName: prevDigest.canonicalName,
        normalizedValue: prevDigest.normalizedValue,
        assetType: prevDigest.assetType,
        changeType: 'NOT_OBSERVED',
        changeCategory: mapTypeToCategory(prevDigest.assetType),
        changeDescription: `Not observed in latest scan (previously discovered by ${prevDigest.discoverySource})`,
        observationNote: confidenceNote,
        previousValue: prevDigest.ipAddress || prevDigest.canonicalName,
        newValue: 'Not observed in latest scan',
        previousState: {
          ipAddress: prevDigest.ipAddress,
          statusCode: prevDigest.statusCode,
          ports: prevDigest.ports,
          services: prevDigest.services,
          technologies: prevDigest.technologies,
        },
        detectedAt,
        evidenceReference: `Previously recorded in "${previousSnapshot.assessmentName}" (${new Date(
          previousSnapshot.snapshotTimestamp
        ).toLocaleDateString()}) via ${prevDigest.discoverySource}`,
        sourceTool: prevDigest.discoverySource,
        confidenceNote,
      });
    }
  }

  const changes = Array.from(changesMap.values());
  const newAssets = changes.filter((c) => c.changeType === 'NEW');
  const notObservedAssets = changes.filter((c) => c.changeType === 'NOT_OBSERVED');
  const modifiedAssets = changes.filter((c) => c.changeType === 'MODIFIED');

  const newPortsCount = newAssets.filter((c) => c.assetType === 'port').length;
  const newServicesCount = newAssets.filter((c) => c.assetType === 'service').length;
  const techChangesCount = changes.filter(
    (c) => c.assetType === 'technology' || c.changeCategory === 'technology'
  ).length;

  return {
    previousSnapshot,
    latestSnapshot,
    changes,
    newAssets,
    notObservedAssets,
    modifiedAssets,
    summary: {
      totalNew: newAssets.length,
      totalNotObserved: notObservedAssets.length,
      totalModified: modifiedAssets.length,
      newAssetsCount: newAssets.length,
      notObservedCount: notObservedAssets.length,
      modifiedAssetsCount: modifiedAssets.length,
      newlyExposedPortsCount: newPortsCount,
      newlyDetectedServicesCount: newServicesCount,
      technologyChangesCount: techChangesCount,
      newSubdomains: newAssets.filter((c) => c.assetType === 'subdomain' || c.assetType === 'root_domain').length,
      newIps: newAssets.filter((c) => c.assetType === 'ip_address').length,
      newPorts: newPortsCount,
      newServices: newServicesCount,
      newEndpoints: newAssets.filter((c) => c.assetType === 'endpoint').length,
      newTechnologies: newAssets.filter((c) => c.assetType === 'technology').length,
      isLatestScanIncomplete,
      scanStatusWarning:
        latestSnapshot.completionStatus !== 'completed'
          ? `Note: Latest assessment "${latestSnapshot.assessmentName}" has status "${latestSnapshot.completionStatus}". Assets labeled "Not observed in latest scan" may reflect incomplete tool execution.`
          : (previousSnapshot.rootDomain || '').toLowerCase() !== (latestSnapshot.rootDomain || '').toLowerCase()
          ? `Note: Comparing assessments with different root domains (${previousSnapshot.rootDomain} vs ${latestSnapshot.rootDomain}).`
          : undefined,
    },
  };
}
