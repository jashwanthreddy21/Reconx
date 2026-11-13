import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import {
  Assessment,
  Asset,
  AssetType,
  Finding,
  FindingSeverity,
  IpGeoLocation,
} from '../../types';
import { firestoreService } from '../../services/firestoreService';
import {
  Globe,
  ShieldAlert,
  Layers,
  Server,
  ExternalLink,
  Filter,
  Loader2,
  Grid,
  CircleDot,
  X,
  MapPin,
  AlertTriangle,
} from 'lucide-react';

export interface GeoRegionDefinition {
  id: string;
  code: string;
  label: string;
  shortLabel: string;
  coordinates: string;
}

export const GEO_REGIONS: GeoRegionDefinition[] = [
  {
    id: 'us-east',
    code: 'US-EAST',
    label: 'North America East (Ashburn / IAD)',
    shortLabel: 'US East (Ashburn)',
    coordinates: '39.04°N, 77.49°W',
  },
  {
    id: 'us-west',
    code: 'US-WEST',
    label: 'North America West (Oregon / SJC)',
    shortLabel: 'US West (Oregon)',
    coordinates: '45.52°N, 122.68°W',
  },
  {
    id: 'eu-central',
    code: 'EU-CENT',
    label: 'Europe Central (Frankfurt / FRA)',
    shortLabel: 'EU Central (Frankfurt)',
    coordinates: '50.11°N, 8.68°E',
  },
  {
    id: 'eu-west',
    code: 'EU-WEST',
    label: 'Europe West (Dublin / London)',
    shortLabel: 'EU West (Dublin)',
    coordinates: '53.35°N, 6.26°W',
  },
  {
    id: 'ap-southeast',
    code: 'AP-SOUTH',
    label: 'Asia Pacific South (Singapore / SIN)',
    shortLabel: 'APAC South (Singapore)',
    coordinates: '1.35°N, 103.82°E',
  },
  {
    id: 'ap-northeast',
    code: 'AP-EAST',
    label: 'Asia Pacific East (Tokyo / NRT)',
    shortLabel: 'APAC East (Tokyo)',
    coordinates: '35.68°N, 139.77°E',
  },
  {
    id: 'global-edge',
    code: 'ANYCAST',
    label: 'Global Anycast CDN & Edge Network',
    shortLabel: 'Global Edge / CDN',
    coordinates: 'Multi-Region Edge',
  },
];

export const SEVERITY_COLUMNS: {
  key: FindingSeverity;
  label: string;
  shortLabel: string;
  weight: number;
  baseHex: string;
  badgeClass: string;
}[] = [
  {
    key: 'critical',
    label: 'Critical',
    shortLabel: 'CRIT',
    weight: 5,
    baseHex: '#f43f5e',
    badgeClass: 'text-rose-300 bg-rose-500/15 border-rose-500/30',
  },
  {
    key: 'high',
    label: 'High',
    shortLabel: 'HIGH',
    weight: 4,
    baseHex: '#f97316',
    badgeClass: 'text-orange-300 bg-orange-500/15 border-orange-500/30',
  },
  {
    key: 'medium',
    label: 'Medium',
    shortLabel: 'MED',
    weight: 3,
    baseHex: '#f59e0b',
    badgeClass: 'text-amber-300 bg-amber-500/15 border-amber-500/30',
  },
  {
    key: 'low',
    label: 'Low',
    shortLabel: 'LOW',
    weight: 2,
    baseHex: '#06b6d4',
    badgeClass: 'text-cyan-300 bg-cyan-500/15 border-cyan-500/30',
  },
  {
    key: 'informational',
    label: 'Informational',
    shortLabel: 'INFO',
    weight: 1,
    baseHex: '#64748b',
    badgeClass: 'text-slate-300 bg-slate-500/15 border-slate-500/30',
  },
];

const SENSITIVE_PORTS = new Set([
  21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017,
]);

export interface ClusteredAssetItem {
  id: string;
  canonicalName: string;
  assetType: AssetType;
  ipAddress?: string;
  openPorts: number[];
  regionId: string;
  regionLabel: string;
  regionCode: string;
  severity: FindingSeverity;
  riskReason: string;
  confidenceScore: number;
  assessmentId: string;
  assessmentName: string;
  rootDomain: string;
  discoverySource: string;
}

export interface HeatmapCellDatum {
  regionId: string;
  regionLabel: string;
  regionShortLabel: string;
  regionCode: string;
  severity: FindingSeverity;
  severityLabel: string;
  count: number;
  assets: ClusteredAssetItem[];
  weightedIntensity: number;
}

function fnv1aHash(input: string): number {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

/**
 * Resolves an asset's geographic cluster using explicit metadata, hostname geo-tokens/ccTLDs,
 * IPv4 RIR/Cloud prefix ranges, or deterministic hash fallback.
 */
export function resolveAssetGeoRegion(
  asset: Asset,
  assessment: Assessment,
  ipToRegionMap: Map<string, string>,
  resolvedGeo?: IpGeoLocation | null
): GeoRegionDefinition {
  if (resolvedGeo && resolvedGeo.isExternal) {
    if (resolvedGeo.geoRegionId === 'europe') {
      const ukOrWest = new Set(['GB', 'UK', 'IE', 'FR', 'NL', 'ES', 'PT', 'BE']);
      return ukOrWest.has(resolvedGeo.countryCode) ? GEO_REGIONS[3] : GEO_REGIONS[2];
    }
    if (resolvedGeo.geoRegionId === 'asia-pacific') {
      const eastAsia = new Set(['JP', 'KR', 'HK', 'TW', 'CN']);
      return eastAsia.has(resolvedGeo.countryCode) ? GEO_REGIONS[5] : GEO_REGIONS[4];
    }
    if (resolvedGeo.geoRegionId === 'north-america') {
      const regionText = `${resolvedGeo.regionName || ''} ${resolvedGeo.city || ''}`.toLowerCase();
      if (/(california|oregon|washington|nevada|san jose|seattle|los angeles|san francisco)/.test(regionText)) {
        return GEO_REGIONS[1];
      }
      return GEO_REGIONS[0];
    }
    if (resolvedGeo.geoRegionId === 'middle-east-africa') {
      return GEO_REGIONS[3];
    }
    if (resolvedGeo.geoRegionId === 'latin-america') {
      return GEO_REGIONS[0];
    }
  }

  const metaRegion = String(
    asset.metadata?.region || asset.metadata?.country || asset.metadata?.datacenter || ''
  ).toLowerCase();

  const name = (asset.canonicalName || asset.assetValue || '').toLowerCase();
  const ip = (
    asset.ipAddress ||
    (asset.assetType === 'ip_address' ? asset.canonicalName : '') ||
    ''
  ).trim();

  // 1. Check explicit metadata or hostname tokens
  const combinedText = `${metaRegion} ${name}`;
  if (
    /\b(us-east|useast|iad|ashburn|virginia|ny|nyc|atl|mia)\b/.test(combinedText)
  ) {
    return GEO_REGIONS[0];
  }
  if (
    /\b(us-west|uswest|sjc|pdx|lax|sea|oregon|california|sfo)\b/.test(combinedText)
  ) {
    return GEO_REGIONS[1];
  }
  if (
    /\b(eu-central|eucentral|fra|frankfurt|zurich|zrh|de|ber|munich)\b/.test(combinedText) ||
    /\.(de|ch|at|pl)(\/|$|:)/.test(name)
  ) {
    return GEO_REGIONS[2];
  }
  if (
    /\b(eu-west|euwest|dub|dublin|lon|lhr|london|ams|par|uk|nl|fr|ie)\b/.test(combinedText) ||
    /\.(uk|co\.uk|ie|fr|nl|eu)(\/|$|:)/.test(name)
  ) {
    return GEO_REGIONS[3];
  }
  if (
    /\b(ap-southeast|apsoutheast|sin|singapore|syd|sydney|sg|au|id|my|in|bom)\b/.test(
      combinedText
    ) ||
    /\.(sg|au|com\.au|in|co\.in|id)(\/|$|:)/.test(name)
  ) {
    return GEO_REGIONS[4];
  }
  if (
    /\b(ap-northeast|apnortheast|nrt|tokyo|icn|seoul|hnd|jp|kr|hk|tw)\b/.test(combinedText) ||
    /\.(jp|co\.jp|kr|hk|tw)(\/|$|:)/.test(name)
  ) {
    return GEO_REGIONS[5];
  }
  if (
    /\b(cdn|edge|anycast|cloudflare|akamai|fastly|cloudfront|waf|proxy|dns)\b/.test(combinedText)
  ) {
    return GEO_REGIONS[6];
  }

  // 2. Check IP address mapping
  if (ip) {
    const cached = ipToRegionMap.get(ip);
    if (cached) {
      const found = GEO_REGIONS.find((r) => r.id === cached);
      if (found) return found;
    }

    const octets = ip.split('.').map((n) => parseInt(n, 10));
    if (octets.length === 4 && octets.every((n) => !Number.isNaN(n))) {
      const [o1, o2] = octets;
      // Cloud / Anycast CDN ranges
      if (o1 === 104 || o1 === 172 || o1 === 198 || o1 === 1 && o2 === 1) {
        ipToRegionMap.set(ip, 'global-edge');
        return GEO_REGIONS[6];
      }
      // North America East
      if (o1 === 3 || o1 === 18 || o1 === 34 || o1 === 52 || o1 === 54 || o1 === 23) {
        const region = o2 % 2 === 0 ? GEO_REGIONS[0] : GEO_REGIONS[1];
        ipToRegionMap.set(ip, region.id);
        return region;
      }
      // Europe RIPE ranges
      if (o1 >= 77 && o1 <= 95 || o1 === 185 || o1 === 193 || o1 === 194 || o1 === 195) {
        const region = o2 % 2 === 0 ? GEO_REGIONS[2] : GEO_REGIONS[3];
        ipToRegionMap.set(ip, region.id);
        return region;
      }
      // APNIC ranges
      if (o1 >= 101 && o1 <= 126 || o1 === 133 || o1 === 150 || o1 === 153 || o1 === 202 || o1 === 203) {
        const region = o2 % 2 === 0 ? GEO_REGIONS[4] : GEO_REGIONS[5];
        ipToRegionMap.set(ip, region.id);
        return region;
      }
    }
  }

  // 3. Deterministic hash across canonicalName + rootDomain so related assets cluster consistently
  const seedKey = ip || asset.parentHostname || `${asset.canonicalName}:${assessment.scope?.rootDomain || ''}`;
  const hashIndex = fnv1aHash(seedKey) % GEO_REGIONS.length;
  const assigned = GEO_REGIONS[hashIndex];
  if (ip) {
    ipToRegionMap.set(ip, assigned.id);
  }
  return assigned;
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

/**
 * Resolves the effective risk severity of a discovered asset based on correlated findings,
 * explicit asset riskLevel, open sensitive ports, and exposure flags.
 */
export function resolveAssetSeverity(
  asset: Asset,
  findings: Finding[]
): { severity: FindingSeverity; reason: string } {
  let highest: FindingSeverity = asset.riskLevel || 'informational';
  let reason =
    asset.riskReason ||
    (asset.exposureReasons && asset.exposureReasons[0]) ||
    'Standard surface asset observed within authorized scope';

  const assetKey = (asset.canonicalName || '').toLowerCase();
  const assetIp = (asset.ipAddress || '').toLowerCase();

  // Correlate findings referencing this asset
  for (const f of findings) {
    const ref = (f.assetRef || '').toLowerCase();
    if (
      ref &&
      (ref === assetKey ||
        (assetIp && ref === assetIp) ||
        ref.includes(assetKey) ||
        assetKey.includes(ref))
    ) {
      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[highest]) {
        highest = f.severity;
        reason = f.title;
      }
    }
  }

  // Inspect open ports if severity is still low/informational
  const ports = asset.openPorts || [];
  const sensitiveOpen = ports.filter((p) => SENSITIVE_PORTS.has(p));
  if (sensitiveOpen.length > 0 && SEVERITY_RANK[highest] < SEVERITY_RANK.high) {
    if (sensitiveOpen.some((p) => [23, 445, 3389, 6379, 27017, 9200].includes(p))) {
      highest = 'critical';
      reason = `Exposed high-risk administrative/database port (${sensitiveOpen.join(', ')})`;
    } else {
      highest = 'high';
      reason = `Sensitive network service port exposed (${sensitiveOpen.join(', ')})`;
    }
  } else if (
    (asset.isPotentiallyExposed || asset.isExposedRisk) &&
    SEVERITY_RANK[highest] < SEVERITY_RANK.medium
  ) {
    highest = 'medium';
    reason = asset.riskReason || 'Potentially exposed external endpoint or service';
  } else if (ports.length > 0 && SEVERITY_RANK[highest] < SEVERITY_RANK.low) {
    highest = 'low';
    reason = `Active network listener on port ${ports.join(', ')}`;
  }

  // Check staging/dev/admin naming patterns
  const lowerName = asset.canonicalName.toLowerCase();
  if (
    /\b(admin|internal|staging|dev|jenkins|gitlab|Grafana|kibana|vpn|bastion|db|redis)\b/i.test(
      lowerName
    ) &&
    SEVERITY_RANK[highest] < SEVERITY_RANK.high
  ) {
    highest = 'high';
    reason = 'Administrative or non-production control plane hostname exposed';
  }

  return { severity: highest, reason };
}

interface Props {
  assessments: Assessment[];
  onSelectAssessment: (assessmentId: string) => void;
  preloadedClusteredAssets?: ClusteredAssetItem[];
  externalLoadingIntel?: boolean;
}

export const AssetDistributionHeatmap: React.FC<Props> = ({
  assessments,
  onSelectAssessment,
  preloadedClusteredAssets,
  externalLoadingIntel,
}) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>('all');
  const [selectedAssetType, setSelectedAssetType] = useState<string>('all');
  const [viewMode, setViewMode] = useState<'matrix' | 'bubble'>('matrix');
  const [internalLoadingIntel, setInternalLoadingIntel] = useState<boolean>(false);
  const [internalClusteredAssets, setInternalClusteredAssets] = useState<ClusteredAssetItem[]>([]);
  const [selectedCell, setSelectedCell] = useState<{
    regionId: string;
    severity: FindingSeverity;
  } | null>(null);
  const [hoveredTooltip, setHoveredTooltip] = useState<{
    x: number;
    y: number;
    title: string;
    subtitle: string;
    count: number;
    sharePct: string;
    severityLabel: string;
    severityHex: string;
    topAssets: string[];
  } | null>(null);

  const svgRef = useRef<SVGSVGElement | null>(null);
  const bubbleSvgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const intelCacheRef = useRef<
    Map<string, { updatedAt: string; items: ClusteredAssetItem[] }>
  >(new Map());

  // Reset selected assessment filter if it was deleted
  useEffect(() => {
    if (
      selectedAssessmentId !== 'all' &&
      !assessments.some((a) => a.id === selectedAssessmentId)
    ) {
      setSelectedAssessmentId('all');
    }
  }, [assessments, selectedAssessmentId]);

  const usesPreloaded = preloadedClusteredAssets !== undefined;
  const loadingIntel = usesPreloaded ? Boolean(externalLoadingIntel) : internalLoadingIntel;
  const clusteredAssets = usesPreloaded ? preloadedClusteredAssets : internalClusteredAssets;

  // Load and correlate assets across assessments when preloaded items are not provided
  useEffect(() => {
    if (usesPreloaded) return;
    let cancelled = false;

    async function loadAllAssets() {
      if (assessments.length === 0) {
        setInternalClusteredAssets([]);
        return;
      }

      setInternalLoadingIntel(true);
      const ipToRegionMap = new Map<string, string>();
      const aggregated: ClusteredAssetItem[] = [];

      for (const assessment of assessments) {
        const cacheEntry = intelCacheRef.current.get(assessment.id);
        if (cacheEntry && cacheEntry.updatedAt === assessment.updatedAt) {
          aggregated.push(...cacheEntry.items);
          continue;
        }

        try {
          const intel = await firestoreService.loadOrComputeAssessmentIntelligence(assessment);
          const items: ClusteredAssetItem[] = [];

          // Pass 1: register IP regions first so hostnames resolving to those IPs share the same region
          for (const asset of intel.assets) {
            if (asset.assetType === 'ip_address' || asset.ipAddress) {
              resolveAssetGeoRegion(asset, assessment, ipToRegionMap);
            }
          }

          // Pass 2: build clustered asset items
          for (const asset of intel.assets) {
            const geo = resolveAssetGeoRegion(asset, assessment, ipToRegionMap);
            const { severity, reason } = resolveAssetSeverity(asset, intel.findings);

            items.push({
              id: `${assessment.id}_${asset.id}`,
              canonicalName: asset.canonicalName,
              assetType: asset.assetType,
              ipAddress: asset.ipAddress,
              openPorts: asset.openPorts || [],
              regionId: geo.id,
              regionLabel: geo.label,
              regionCode: geo.code,
              severity,
              riskReason: reason,
              confidenceScore: asset.confidenceScore || 80,
              assessmentId: assessment.id,
              assessmentName: assessment.name,
              rootDomain: assessment.scope?.rootDomain || '',
              discoverySource: asset.discoverySource || 'Correlated Recon',
            });
          }

          intelCacheRef.current.set(assessment.id, {
            updatedAt: assessment.updatedAt,
            items,
          });
          aggregated.push(...items);
        } catch (err) {
          console.warn(`Heatmap intelligence load skipped for ${assessment.id}:`, err);
        }
      }

      if (!cancelled) {
        setInternalClusteredAssets(aggregated);
        setInternalLoadingIntel(false);
      }
    }

    loadAllAssets();
    return () => {
      cancelled = true;
    };
  }, [assessments, usesPreloaded]);

  // Filter clustered assets by selected assessment and asset type
  const filteredAssets = useMemo(() => {
    return clusteredAssets.filter((item) => {
      if (selectedAssessmentId !== 'all' && item.assessmentId !== selectedAssessmentId) {
        return false;
      }
      if (selectedAssetType !== 'all') {
        if (selectedAssetType === 'hosts') {
          return item.assetType === 'root_domain' || item.assetType === 'subdomain';
        }
        if (selectedAssetType === 'ips') {
          return item.assetType === 'ip_address';
        }
        if (selectedAssetType === 'endpoints') {
          return item.assetType === 'endpoint';
        }
        if (selectedAssetType === 'services') {
          return (
            item.assetType === 'port' ||
            item.assetType === 'service' ||
            item.assetType === 'technology'
          );
        }
      }
      return true;
    });
  }, [clusteredAssets, selectedAssessmentId, selectedAssetType]);

  // Build Matrix Heatmap data (7 Geo Regions x 5 Risk Severities = 35 cells)
  const { cells, regionTotals, severityTotals, maxCellCount } = useMemo(() => {
    const cellMap = new Map<string, HeatmapCellDatum>();
    const regTotals: Record<string, number> = {};
    const sevTotals: Record<FindingSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    for (const reg of GEO_REGIONS) {
      regTotals[reg.id] = 0;
      for (const sev of SEVERITY_COLUMNS) {
        const key = `${reg.id}__${sev.key}`;
        cellMap.set(key, {
          regionId: reg.id,
          regionLabel: reg.label,
          regionShortLabel: reg.shortLabel,
          regionCode: reg.code,
          severity: sev.key,
          severityLabel: sev.label,
          count: 0,
          assets: [],
          weightedIntensity: 0,
        });
      }
    }

    for (const item of filteredAssets) {
      const key = `${item.regionId}__${item.severity}`;
      const cell = cellMap.get(key);
      if (cell) {
        cell.count += 1;
        cell.assets.push(item);
        regTotals[item.regionId] = (regTotals[item.regionId] || 0) + 1;
        sevTotals[item.severity] = (sevTotals[item.severity] || 0) + 1;
      }
    }

    const allCells = Array.from(cellMap.values());
    const maxCount = d3.max(allCells, (d) => d.count) || 1;

    for (const c of allCells) {
      const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === c.severity);
      const sevWeight = sevMeta ? sevMeta.weight : 1;
      c.weightedIntensity =
        c.count === 0 ? 0 : (c.count / maxCount) * 0.7 + (sevWeight / 5) * 0.3;
    }

    return {
      cells: allCells,
      regionTotals: regTotals,
      severityTotals: sevTotals,
      maxCellCount: maxCount,
    };
  }, [filteredAssets]);

  // Selected Cell Drill-Down Assets
  const activeDrilldownCell = useMemo(() => {
    if (!selectedCell) return null;
    return (
      cells.find(
        (c) =>
          c.regionId === selectedCell.regionId && c.severity === selectedCell.severity
      ) || null
    );
  }, [cells, selectedCell]);

  // Render D3 Matrix Heatmap
  useEffect(() => {
    if (viewMode !== 'matrix' || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = 860;
    const height = 390;
    const margin = { top: 44, right: 86, bottom: 26, left: 195 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const g = svg
      .attr('viewBox', `0 0 ${width} ${height}`)
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const xDomain = SEVERITY_COLUMNS.map((s) => s.key);
    const yDomain = GEO_REGIONS.map((r) => r.id);

    const xScale = d3
      .scaleBand<FindingSeverity>()
      .domain(xDomain)
      .range([0, innerWidth])
      .paddingInner(0.08)
      .paddingOuter(0.02);

    const yScale = d3
      .scaleBand<string>()
      .domain(yDomain)
      .range([0, innerHeight])
      .paddingInner(0.12)
      .paddingOuter(0.02);

    // D3 Color scales per severity column so high-severity clusters glow warmer
    const getCellFill = (d: HeatmapCellDatum): string => {
      if (d.count === 0) return '#0f172a';
      const ratio = Math.min(1, Math.max(0.18, d.count / Math.max(1, maxCellCount)));
      const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === d.severity);
      const targetColor = sevMeta ? sevMeta.baseHex : '#38bdf8';
      return d3.interpolateRgb('#111827', targetColor)(0.22 + ratio * 0.68);
    };

    const getCellStroke = (d: HeatmapCellDatum): string => {
      const isSelected =
        selectedCell?.regionId === d.regionId && selectedCell?.severity === d.severity;
      if (isSelected) return '#38bdf8';
      if (d.count === 0) return '#1e293b';
      const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === d.severity);
      return d3.interpolateRgb('#334155', sevMeta?.baseHex || '#38bdf8')(0.55);
    };

    // Column Header Labels (Risk Severity)
    const colHeaders = g
      .selectAll('.col-header')
      .data(SEVERITY_COLUMNS)
      .enter()
      .append('g')
      .attr('class', 'col-header')
      .attr(
        'transform',
        (d) => `translate(${(xScale(d.key) || 0) + xScale.bandwidth() / 2}, -16)`
      );

    colHeaders
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('fill', (d) => d.baseHex)
      .attr('font-size', '11px')
      .attr('font-weight', '700')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .text((d) => `${d.label.toUpperCase()} (${severityTotals[d.key] || 0})`);

    // Row Labels (Geographic Regions)
    const rowHeaders = g
      .selectAll('.row-header')
      .data(GEO_REGIONS)
      .enter()
      .append('g')
      .attr('class', 'row-header')
      .attr(
        'transform',
        (d) => `translate(-12, ${(yScale(d.id) || 0) + yScale.bandwidth() / 2})`
      );

    rowHeaders
      .append('text')
      .attr('text-anchor', 'end')
      .attr('dominant-baseline', 'middle')
      .attr('fill', '#e2e8f0')
      .attr('font-size', '11.5px')
      .attr('font-weight', '600')
      .text((d) => d.shortLabel);

    // Region Totals on Right Column
    const rowTotals = g
      .selectAll('.row-total')
      .data(GEO_REGIONS)
      .enter()
      .append('g')
      .attr('class', 'row-total')
      .attr(
        'transform',
        (d) =>
          `translate(${innerWidth + 14}, ${(yScale(d.id) || 0) + yScale.bandwidth() / 2})`
      );

    rowTotals
      .append('text')
      .attr('text-anchor', 'start')
      .attr('dominant-baseline', 'middle')
      .attr('fill', (d) => ((regionTotals[d.id] || 0) > 0 ? '#94a3b8' : '#475569'))
      .attr('font-size', '11px')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .text((d) => `${regionTotals[d.id] || 0} assets`);

    // Heatmap Cells
    const cellGroups = g
      .selectAll('.heatmap-cell')
      .data(cells)
      .enter()
      .append('g')
      .attr('class', 'heatmap-cell')
      .attr(
        'transform',
        (d) => `translate(${xScale(d.severity) || 0}, ${yScale(d.regionId) || 0})`
      )
      .style('cursor', (d) => (d.count > 0 ? 'pointer' : 'default'));

    // Cell Background Rectangles
    cellGroups
      .append('rect')
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('rx', 8)
      .attr('ry', 8)
      .attr('fill', (d) => getCellFill(d))
      .attr('stroke', (d) => getCellStroke(d))
      .attr('stroke-width', (d) =>
        selectedCell?.regionId === d.regionId && selectedCell?.severity === d.severity
          ? 2.2
          : 1
      );

    // Count Label inside Cell
    cellGroups
      .append('text')
      .attr('x', 12)
      .attr('y', yScale.bandwidth() / 2 + 1)
      .attr('dominant-baseline', 'middle')
      .attr('fill', (d) => (d.count > 0 ? '#ffffff' : '#334155'))
      .attr('font-size', (d) => (d.count > 0 ? '14px' : '11px'))
      .attr('font-weight', (d) => (d.count > 0 ? '700' : '500'))
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .text((d) => d.count);

    // Visual Asset Cluster Nodes inside each populated cell (up to 8 mini nodes)
    cellGroups.each(function (d) {
      if (d.count <= 0) return;
      const group = d3.select(this);
      const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === d.severity);
      const dotColor = sevMeta ? sevMeta.baseHex : '#38bdf8';
      const maxDots = Math.min(8, d.count);
      const startX = xScale.bandwidth() - 14;
      const centerY = yScale.bandwidth() / 2;

      for (let i = 0; i < maxDots; i++) {
        const col = i % 4;
        const row = Math.floor(i / 4);
        const cx = startX - col * 9;
        const cy = maxDots > 4 ? centerY - 4 + row * 8 : centerY;
        group
          .append('circle')
          .attr('cx', cx)
          .attr('cy', cy)
          .attr('r', 3)
          .attr('fill', dotColor)
          .attr('stroke', '#0f172a')
          .attr('stroke-width', 1)
          .attr('opacity', 0.95);
      }
    });

    // Interactive Hover & Click Events
    cellGroups
      .on('mouseenter', function (event, d) {
        d3.select(this)
          .select('rect')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 2);

        if (containerRef.current) {
          const rect = containerRef.current.getBoundingClientRect();
          const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === d.severity);
          const total = Math.max(1, filteredAssets.length);
          const sharePct = ((d.count / total) * 100).toFixed(1);

          setHoveredTooltip({
            x: event.clientX - rect.left,
            y: event.clientY - rect.top,
            title: d.regionLabel,
            subtitle: `${d.severityLabel} Risk Severity Cluster`,
            count: d.count,
            sharePct,
            severityLabel: d.severityLabel,
            severityHex: sevMeta?.baseHex || '#38bdf8',
            topAssets: d.assets.slice(0, 4).map((a) => a.canonicalName),
          });
        }
      })
      .on('mousemove', function (event) {
        if (containerRef.current) {
          const rect = containerRef.current.getBoundingClientRect();
          setHoveredTooltip((prev) =>
            prev
              ? {
                  ...prev,
                  x: event.clientX - rect.left,
                  y: event.clientY - rect.top,
                }
              : null
          );
        }
      })
      .on('mouseleave', function (_event, d) {
        const isSelected =
          selectedCell?.regionId === d.regionId && selectedCell?.severity === d.severity;
        d3.select(this)
          .select('rect')
          .attr('stroke', getCellStroke(d))
          .attr('stroke-width', isSelected ? 2.2 : 1);
        setHoveredTooltip(null);
      })
      .on('click', function (_event, d) {
        if (d.count === 0) return;
        setSelectedCell((prev) =>
          prev?.regionId === d.regionId && prev?.severity === d.severity
            ? null
            : { regionId: d.regionId, severity: d.severity }
        );
      });
  }, [
    viewMode,
    cells,
    regionTotals,
    severityTotals,
    maxCellCount,
    selectedCell,
    filteredAssets.length,
  ]);

  // Render D3 Geocluster Bubble Pack View (when viewMode === 'bubble')
  useEffect(() => {
    if (viewMode !== 'bubble' || !bubbleSvgRef.current) return;

    const svg = d3.select(bubbleSvgRef.current);
    svg.selectAll('*').remove();

    const width = 860;
    const height = 390;

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    const colCount = 4;
    const cellW = width / colCount;
    const cellH = height / 2;

    GEO_REGIONS.forEach((region, idx) => {
      const col = idx % colCount;
      const row = Math.floor(idx / colCount);
      const centerX = col * cellW + cellW / 2;
      const centerY = row * cellH + cellH / 2 + 8;

      const regionAssets = filteredAssets.filter((a) => a.regionId === region.id);
      const group = svg.append('g').attr('transform', `translate(${centerX}, ${centerY})`);

      // Outer Regional Cluster Boundary
      const packDiameter = Math.min(cellW, cellH) - 42;
      const outerRadius = packDiameter / 2;

      group
        .append('circle')
        .attr('r', outerRadius)
        .attr('fill', regionAssets.length > 0 ? '#0f172a' : '#090d16')
        .attr('stroke', regionAssets.length > 0 ? '#334155' : '#1e293b')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', regionAssets.length > 0 ? 'none' : '4 3');

      // Region Label Above Cluster
      group
        .append('text')
        .attr('y', -outerRadius - 10)
        .attr('text-anchor', 'middle')
        .attr('fill', '#e2e8f0')
        .attr('font-size', '11px')
        .attr('font-weight', '600')
        .text(`${region.shortLabel} (${regionAssets.length})`);

      if (regionAssets.length === 0) {
        group
          .append('text')
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'middle')
          .attr('fill', '#475569')
          .attr('font-size', '10px')
          .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
          .text('0 assets');
        return;
      }

      // Use d3.pack to spatially cluster assets inside the geographic region circle
      const hierarchyData = {
        name: region.id,
        children: regionAssets.map((a) => {
          const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === a.severity);
          return {
            asset: a,
            value: (sevMeta?.weight || 1) * 10 + (a.openPorts.length || 1) * 3,
          };
        }),
      };

      const root = d3
        .hierarchy<any>(hierarchyData)
        .sum((d) => d.value || 1)
        .sort((a, b) => (b.value || 0) - (a.value || 0));

      const packLayout = d3.pack<any>().size([packDiameter - 12, packDiameter - 12]).padding(3);
      const packed = packLayout(root);

      const leaves = packed.leaves();

      const leafNodes = group
        .selectAll('.asset-bubble')
        .data(leaves)
        .enter()
        .append('g')
        .attr('class', 'asset-bubble')
        .attr(
          'transform',
          (d) => `translate(${d.x - (packDiameter - 12) / 2}, ${d.y - (packDiameter - 12) / 2})`
        )
        .style('cursor', 'pointer');

      leafNodes
        .append('circle')
        .attr('r', (d) => Math.max(4, d.r))
        .attr('fill', (d) => {
          const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === d.data.asset.severity);
          return sevMeta?.baseHex || '#64748b';
        })
        .attr('fill-opacity', 0.82)
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 1.2);

      leafNodes
        .filter((d) => d.r >= 16)
        .append('text')
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'middle')
        .attr('fill', '#ffffff')
        .attr('font-size', '8.5px')
        .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
        .attr('font-weight', '600')
        .text((d) => d.data.asset.canonicalName.slice(0, 10));

      leafNodes
        .on('mouseenter', function (event, d) {
          const asset: ClusteredAssetItem = d.data.asset;
          d3.select(this).select('circle').attr('stroke', '#ffffff').attr('stroke-width', 2);

          if (containerRef.current) {
            const rect = containerRef.current.getBoundingClientRect();
            const sevMeta = SEVERITY_COLUMNS.find((s) => s.key === asset.severity);
            setHoveredTooltip({
              x: event.clientX - rect.left,
              y: event.clientY - rect.top,
              title: asset.canonicalName,
              subtitle: `${asset.regionLabel} · ${asset.assetType.replace('_', ' ')}`,
              count: 1,
              sharePct: `${asset.confidenceScore}% conf`,
              severityLabel: sevMeta?.label || asset.severity,
              severityHex: sevMeta?.baseHex || '#38bdf8',
              topAssets: [
                asset.riskReason,
                asset.ipAddress ? `IP: ${asset.ipAddress}` : `Scope: ${asset.rootDomain}`,
              ],
            });
          }
        })
        .on('mouseleave', function () {
          d3.select(this).select('circle').attr('stroke', '#0f172a').attr('stroke-width', 1.2);
          setHoveredTooltip(null);
        })
        .on('click', function (_event, d) {
          const asset: ClusteredAssetItem = d.data.asset;
          setSelectedCell({ regionId: asset.regionId, severity: asset.severity });
        });
    });
  }, [viewMode, filteredAssets]);

  const highRiskTotal =
    (severityTotals.critical || 0) + (severityTotals.high || 0);
  const activeRegionCount = GEO_REGIONS.filter(
    (r) => (regionTotals[r.id] || 0) > 0
  ).length;

  return (
    <div
      ref={containerRef}
      className="bg-[#111827] rounded-xl border border-slate-800 shadow-lg overflow-hidden relative"
    >
      {/* Header Bar */}
      <div className="p-4 border-b border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
            <h3 className="text-sm font-semibold text-white">
              Asset Distribution Heatmap (Geography × Risk Severity)
            </h3>
            <span className="text-xs font-mono text-slate-400">
              · {filteredAssets.length} correlated assets across {activeRegionCount} regions
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            D3 spatial clustering of discovered attack surface assets by geographic edge region and correlated risk severity. Click any cluster cell to inspect underlying hosts.
          </p>
        </div>

        {/* Interactive Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Assessment Selector */}
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs">
            <Filter className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <select
              value={selectedAssessmentId}
              onChange={(e) => {
                setSelectedAssessmentId(e.target.value);
                setSelectedCell(null);
              }}
              aria-label="Filter heatmap by assessment"
              className="bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer max-w-[190px] truncate"
            >
              <option value="all" className="bg-slate-900 text-slate-200">
                All Assessments ({assessments.length})
              </option>
              {assessments.map((a) => (
                <option key={a.id} value={a.id} className="bg-slate-900 text-slate-200">
                  {a.name} ({a.scope?.rootDomain})
                </option>
              ))}
            </select>
          </div>

          {/* Asset Category Filter */}
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs">
            {[
              { key: 'all', label: 'All Assets' },
              { key: 'hosts', label: 'Hosts' },
              { key: 'ips', label: 'IPs' },
              { key: 'endpoints', label: 'Endpoints' },
              { key: 'services', label: 'Services' },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => {
                  setSelectedAssetType(tab.key);
                  setSelectedCell(null);
                }}
                className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  selectedAssetType === tab.key
                    ? 'bg-slate-800 text-white shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* D3 Visualization Mode Switcher */}
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs">
            <button
              onClick={() => setViewMode('matrix')}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'matrix'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="D3 Geography × Risk Severity Matrix Heatmap"
            >
              <Grid className="w-3.5 h-3.5" />
              <span>Matrix Heatmap</span>
            </button>
            <button
              onClick={() => setViewMode('bubble')}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'bubble'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="D3 Hierarchical Geocluster Bubble Pack"
            >
              <CircleDot className="w-3.5 h-3.5" />
              <span>Geo Bubble Pack</span>
            </button>
          </div>
        </div>
      </div>

      {/* Summary Telemetry Strip */}
      <div className="px-4 py-2.5 bg-slate-900/50 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-4 text-slate-400 font-mono tabular-nums">
          <span>
            Total Mapped: <strong className="text-white">{filteredAssets.length}</strong>
          </span>
          <span>·</span>
          <span>
            Active Geo Clusters: <strong className="text-cyan-400">{activeRegionCount} / {GEO_REGIONS.length}</strong>
          </span>
          <span>·</span>
          <span>
            Critical &amp; High Exposure:{' '}
            <strong className={highRiskTotal > 0 ? 'text-rose-400' : 'text-emerald-400'}>
              {highRiskTotal} assets
            </strong>
          </span>
        </div>

        {/* Severity Legend */}
        <div className="flex flex-wrap items-center gap-3 text-[11px]">
          {SEVERITY_COLUMNS.map((sev) => (
            <button
              key={sev.key}
              onClick={() => {
                // Find region with most assets of this severity
                const topCell = cells
                  .filter((c) => c.severity === sev.key && c.count > 0)
                  .sort((a, b) => b.count - a.count)[0];
                if (topCell) {
                  setSelectedCell({
                    regionId: topCell.regionId,
                    severity: topCell.severity,
                  });
                }
              }}
              className="inline-flex items-center gap-1.5 text-slate-300 hover:text-white transition-colors cursor-pointer font-mono tabular-nums"
              title={`Click to focus top ${sev.label} risk cluster`}
            >
              <span
                className="w-2.5 h-2.5 rounded-xs shrink-0"
                style={{ backgroundColor: sev.baseHex }}
              />
              <span>{sev.label}:</span>
              <span className="text-white font-semibold">
                {severityTotals[sev.key] || 0}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Main D3 Canvas + Optional Selected Cluster Drill-Down Panel */}
      {loadingIntel && clusteredAssets.length === 0 ? (
        <div className="p-12 flex flex-col items-center justify-center gap-2 text-slate-400 text-xs">
          <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
          <span>Correlating asset geography and risk severity across assessments...</span>
        </div>
      ) : filteredAssets.length === 0 ? (
        <div className="p-10 text-center flex flex-col items-center justify-center space-y-2">
          <MapPin className="w-6 h-6 text-slate-500" />
          <div className="text-sm font-semibold text-white">
            No Discovered Assets to Cluster
          </div>
          <p className="text-xs text-slate-400 max-w-md">
            Launch an assessment scan or load the Demo Lab fixture above to populate the D3 geographic and risk severity heatmap.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12">
          {/* D3 SVG Viewport */}
          <div
            className={`p-4 ${
              activeDrilldownCell && activeDrilldownCell.count > 0
                ? 'xl:col-span-8 border-b xl:border-b-0 xl:border-r border-slate-800'
                : 'xl:col-span-12'
            }`}
          >
            {viewMode === 'matrix' ? (
              <svg
                ref={svgRef}
                className="w-full h-auto max-h-[410px] select-none"
                role="img"
                aria-label="Asset Distribution Heatmap by Geography and Risk Severity"
              />
            ) : (
              <svg
                ref={bubbleSvgRef}
                className="w-full h-auto max-h-[410px] select-none"
                role="img"
                aria-label="Asset Geographic Bubble Cluster Pack"
              />
            )}
          </div>

          {/* Cluster Drill-Down Inspector Panel */}
          {activeDrilldownCell && activeDrilldownCell.count > 0 && (
            <div className="xl:col-span-4 bg-slate-950/60 p-4 flex flex-col justify-between max-h-[430px]">
              <div className="space-y-3 overflow-hidden flex flex-col h-full">
                <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-2.5">
                  <div>
                    <div className="text-[11px] font-mono text-cyan-400">
                      {activeDrilldownCell.regionCode} · {activeDrilldownCell.severityLabel.toUpperCase()} CLUSTER
                    </div>
                    <h4 className="text-sm font-semibold text-white mt-0.5">
                      {activeDrilldownCell.regionShortLabel}
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono tabular-nums">
                      {activeDrilldownCell.count} correlated asset
                      {activeDrilldownCell.count === 1 ? '' : 's'} in this cluster
                    </p>
                  </div>
                  <button
                    onClick={() => setSelectedCell(null)}
                    className="p-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 cursor-pointer"
                    title="Close cluster inspector"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-2 overflow-y-auto pr-1 flex-1">
                  {activeDrilldownCell.assets.map((asset) => {
                    const sevMeta = SEVERITY_COLUMNS.find(
                      (s) => s.key === asset.severity
                    );
                    return (
                      <div
                        key={asset.id}
                        onClick={() => onSelectAssessment(asset.assessmentId)}
                        className="p-2.5 rounded-lg bg-slate-900/90 hover:bg-slate-800/80 border border-slate-800 transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs font-semibold text-white group-hover:text-cyan-300 truncate">
                            {asset.canonicalName}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400 shrink-0 uppercase">
                            {asset.assetType.replace('_', ' ')}
                          </span>
                        </div>

                        <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                          {asset.riskReason}
                        </div>

                        <div className="flex flex-wrap items-center justify-between gap-2 mt-2 pt-1.5 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 tabular-nums">
                          <span>
                            {asset.ipAddress ? `IP: ${asset.ipAddress}` : asset.rootDomain}
                            {asset.openPorts.length > 0
                              ? ` · Ports: ${asset.openPorts.slice(0, 4).join(', ')}`
                              : ''}
                          </span>
                          <span
                            className="inline-flex items-center gap-1 font-semibold"
                            style={{ color: sevMeta?.baseHex || '#38bdf8' }}
                          >
                            Inspect <ExternalLink className="w-2.5 h-2.5" />
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Floating D3 Hover Tooltip */}
      {hoveredTooltip && (
        <div
          className="pointer-events-none absolute z-30 w-64 p-3 rounded-xl bg-slate-950/95 border border-slate-700 shadow-2xl text-xs space-y-1.5 backdrop-blur-md"
          style={{
            left: `${Math.min(Math.max(12, hoveredTooltip.x + 14), 560)}px`,
            top: `${Math.max(12, hoveredTooltip.y - 20)}px`,
          }}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-white truncate">
              {hoveredTooltip.title}
            </span>
            <span
              className="font-mono text-[10px] font-bold uppercase shrink-0"
              style={{ color: hoveredTooltip.severityHex }}
            >
              {hoveredTooltip.severityLabel}
            </span>
          </div>
          <div className="text-[11px] text-slate-400">{hoveredTooltip.subtitle}</div>
          <div className="flex items-center justify-between pt-1 border-t border-slate-800 font-mono text-[11px] tabular-nums">
            <span className="text-slate-300">
              Assets: <strong className="text-white">{hoveredTooltip.count}</strong>
            </span>
            <span className="text-cyan-400">{hoveredTooltip.sharePct}% of surface</span>
          </div>
          {hoveredTooltip.topAssets.length > 0 && (
            <div className="pt-1 border-t border-slate-800/80 space-y-0.5">
              <div className="text-[10px] font-mono text-slate-400">
                Sample Clustered Assets:
              </div>
              {hoveredTooltip.topAssets.map((name, i) => (
                <div
                  key={i}
                  className="text-[10px] font-mono text-slate-200 truncate"
                >
                  · {name}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
