import React, { useState, useEffect, useMemo } from 'react';
import {
  Assessment,
  Asset,
  DnsRecord,
  NetworkService,
  WebEndpoint,
  AssessmentSnapshot,
  AssetChange,
} from '../types';
import { firestoreService } from '../services/firestoreService';
import { compareAssessmentSnapshots } from '../services/changeDetectionEngine';
import {
  GitCompare,
  PlusCircle,
  MinusCircle,
  Globe,
  Cpu,
  ArrowLeft,
  ArrowRight,
  ArrowLeftRight,
  RefreshCw,
  Clock,
  ShieldAlert,
  Server,
  Layers,
  Search,
  Download,
  Filter,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

interface Props {
  assessments: Assessment[];
  onBack: () => void;
}

type DeltaFilterCategory =
  | 'all'
  | 'subdomains'
  | 'ports'
  | 'service_versions'
  | 'dns_ip'
  | 'not_observed';

interface PortDeltaItem {
  id: string;
  host: string;
  ip: string;
  port: number;
  protocol: string;
  deltaType: 'NEW_OPEN_PORT' | 'STATE_CHANGED' | 'NOT_OBSERVED_PORT';
  baselineState?: string;
  latestState?: string;
  serviceName: string;
  version?: string;
  toolSource: string;
  isHighRisk: boolean;
  timestamp: string;
}

interface SubdomainDeltaItem {
  id: string;
  hostname: string;
  deltaType: 'NEW_SUBDOMAIN' | 'IP_CHANGED' | 'NOT_OBSERVED_SUBDOMAIN';
  baselineIp?: string;
  latestIp?: string;
  discoverySource: string;
  confidenceScore: number;
  timestamp: string;
}

interface ServiceVersionDeltaItem {
  id: string;
  target: string;
  port: number;
  protocol: string;
  serviceName: string;
  deltaType: 'VERSION_MODIFIED' | 'SERVICE_CHANGED' | 'TECH_STACK_MODIFIED';
  baselineVersion: string;
  latestVersion: string;
  sourceTool: string;
  timestamp: string;
}

const SENSITIVE_PORTS = new Set([
  21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017,
]);

export const AssessmentComparison: React.FC<Props> = ({ assessments, onBack }) => {
  // Sort assessments chronologically so default Baseline = older, Latest = newer
  const sortedAssessments = useMemo(
    () =>
      [...assessments].sort(
        (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
      ),
    [assessments]
  );

  const [assessmentAId, setAssessmentAId] = useState<string>(
    sortedAssessments[Math.max(0, sortedAssessments.length - 2)]?.id || assessments[0]?.id || ''
  );
  const [assessmentBId, setAssessmentBId] = useState<string>(
    sortedAssessments[sortedAssessments.length - 1]?.id || assessments[1]?.id || assessments[0]?.id || ''
  );

  const [viewMode, setViewMode] = useState<'scan_delta' | 'classic_diff'>('scan_delta');
  const [deltaCategory, setDeltaCategory] = useState<DeltaFilterCategory>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const [assetsA, setAssetsA] = useState<Asset[]>([]);
  const [assetsB, setAssetsB] = useState<Asset[]>([]);
  const [dnsA, setDnsA] = useState<DnsRecord[]>([]);
  const [dnsB, setDnsB] = useState<DnsRecord[]>([]);
  const [servicesA, setServicesA] = useState<NetworkService[]>([]);
  const [servicesB, setServicesB] = useState<NetworkService[]>([]);
  const [endpointsA, setEndpointsA] = useState<WebEndpoint[]>([]);
  const [endpointsB, setEndpointsB] = useState<WebEndpoint[]>([]);
  const [snapshotA, setSnapshotA] = useState<AssessmentSnapshot | null>(null);
  const [snapshotB, setSnapshotB] = useState<AssessmentSnapshot | null>(null);

  const [loading, setLoading] = useState(false);

  const assessmentA = useMemo(
    () => assessments.find((a) => a.id === assessmentAId) || null,
    [assessments, assessmentAId]
  );
  const assessmentB = useMemo(
    () => assessments.find((a) => a.id === assessmentBId) || null,
    [assessments, assessmentBId]
  );

  useEffect(() => {
    if (assessments.length === 0) {
      setAssessmentAId('');
      setAssessmentBId('');
      return;
    }
    const validIds = new Set(assessments.map((a) => a.id));
    setAssessmentAId((prev) =>
      prev && validIds.has(prev)
        ? prev
        : sortedAssessments[Math.max(0, sortedAssessments.length - 2)]?.id || assessments[0].id
    );
    setAssessmentBId((prev) =>
      prev && validIds.has(prev)
        ? prev
        : sortedAssessments[sortedAssessments.length - 1]?.id ||
          assessments[1]?.id ||
          assessments[0].id
    );
  }, [assessments, sortedAssessments]);

  useEffect(() => {
    if (!assessmentA || !assessmentB) {
      setAssetsA([]);
      setAssetsB([]);
      setDnsA([]);
      setDnsB([]);
      setServicesA([]);
      setServicesB([]);
      setEndpointsA([]);
      setEndpointsB([]);
      setSnapshotA(null);
      setSnapshotB(null);
      return;
    }

    let mounted = true;
    const fetchDiffData = async () => {
      setLoading(true);
      try {
        const [intelA, intelB] = await Promise.all([
          firestoreService.loadOrComputeAssessmentIntelligence(assessmentA),
          firestoreService.loadOrComputeAssessmentIntelligence(assessmentB),
        ]);

        if (mounted) {
          setAssetsA(intelA.assets || []);
          setAssetsB(intelB.assets || []);
          setDnsA(intelA.dnsRecords || []);
          setDnsB(intelB.dnsRecords || []);
          setServicesA(intelA.services || []);
          setServicesB(intelB.services || []);
          setEndpointsA(intelA.endpoints || []);
          setEndpointsB(intelB.endpoints || []);
          setSnapshotA(intelA.snapshot);
          setSnapshotB(intelB.snapshot);
        }
      } catch (err) {
        console.error('Diff error:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    fetchDiffData();

    return () => {
      mounted = false;
    };
  }, [assessmentA, assessmentB]);

  const handleSwapRuns = () => {
    const temp = assessmentAId;
    setAssessmentAId(assessmentBId);
    setAssessmentBId(temp);
  };

  // Snapshot Comparison via Change Detection Engine
  const snapshotComparison = useMemo(() => {
    if (!snapshotA || !snapshotB || !assessmentA || !assessmentB) return null;
    return compareAssessmentSnapshots(snapshotA, snapshotB, assessmentA, assessmentB);
  }, [snapshotA, snapshotB, assessmentA, assessmentB]);

  // 1. Subdomain Deltas (New Subdomains, IP Resolution Shifts, Not Observed Subdomains)
  const subdomainDeltas = useMemo<SubdomainDeltaItem[]>(() => {
    const list: SubdomainDeltaItem[] = [];
    const subsA = assetsA.filter(
      (a) => a.assetType === 'subdomain' || a.assetType === 'root_domain'
    );
    const subsB = assetsB.filter(
      (a) => a.assetType === 'subdomain' || a.assetType === 'root_domain'
    );

    const resolveIpForHost = (host: string, asset: Asset | undefined, dnsList: DnsRecord[]) => {
      if (asset?.ipAddress) return asset.ipAddress;
      const aRec = dnsList.find(
        (d) =>
          d.hostname.toLowerCase() === host.toLowerCase() &&
          (d.recordType === 'A' || d.recordType === 'AAAA')
      );
      return aRec?.value;
    };

    const mapA = new Map(subsA.map((s) => [s.canonicalName.toLowerCase(), s]));
    const mapB = new Map(subsB.map((s) => [s.canonicalName.toLowerCase(), s]));

    // Check Latest (B) against Baseline (A)
    for (const [hostKey, subB] of mapB.entries()) {
      const subA = mapA.get(hostKey);
      const ipB = resolveIpForHost(hostKey, subB, dnsB);
      if (!subA) {
        list.push({
          id: `sub_new_${hostKey}`,
          hostname: subB.canonicalName,
          deltaType: 'NEW_SUBDOMAIN',
          latestIp: ipB || 'Unresolved',
          discoverySource: subB.discoverySource,
          confidenceScore: subB.confidenceScore ?? 85,
          timestamp: subB.lastSeen || assessmentB?.createdAt || new Date().toISOString(),
        });
      } else {
        const ipA = resolveIpForHost(hostKey, subA, dnsA);
        if (ipA && ipB && ipA !== ipB) {
          list.push({
            id: `sub_ip_${hostKey}`,
            hostname: subB.canonicalName,
            deltaType: 'IP_CHANGED',
            baselineIp: ipA,
            latestIp: ipB,
            discoverySource: subB.discoverySource,
            confidenceScore: subB.confidenceScore ?? 90,
            timestamp: subB.lastSeen || assessmentB?.createdAt || new Date().toISOString(),
          });
        }
      }
    }

    // Check Baseline (A) subdomains not observed in Latest (B)
    for (const [hostKey, subA] of mapA.entries()) {
      if (!mapB.has(hostKey)) {
        const ipA = resolveIpForHost(hostKey, subA, dnsA);
        list.push({
          id: `sub_unobs_${hostKey}`,
          hostname: subA.canonicalName,
          deltaType: 'NOT_OBSERVED_SUBDOMAIN',
          baselineIp: ipA || 'Unresolved',
          discoverySource: subA.discoverySource,
          confidenceScore: subA.confidenceScore ?? 80,
          timestamp: subA.lastSeen || assessmentA?.createdAt || new Date().toISOString(),
        });
      }
    }

    return list;
  }, [assetsA, assetsB, dnsA, dnsB, assessmentA, assessmentB]);

  // 2. Open Port Deltas (Newly Exposed Ports, Port State Changes, Unobserved Ports)
  const portDeltas = useMemo<PortDeltaItem[]>(() => {
    const list: PortDeltaItem[] = [];
    const keyForSvc = (s: NetworkService) =>
      `${(s.host || s.ip).toLowerCase()}:${s.port}/${s.protocol}`;

    const mapA = new Map(servicesA.map((s) => [keyForSvc(s), s]));
    const mapB = new Map(servicesB.map((s) => [keyForSvc(s), s]));

    for (const [key, svcB] of mapB.entries()) {
      const svcA = mapA.get(key);
      const isHighRisk = SENSITIVE_PORTS.has(svcB.port) && ![80, 443].includes(svcB.port);
      if (!svcA) {
        list.push({
          id: `port_new_${key}`,
          host: svcB.host || svcB.ip,
          ip: svcB.ip,
          port: svcB.port,
          protocol: svcB.protocol,
          deltaType: 'NEW_OPEN_PORT',
          latestState: svcB.state,
          serviceName: svcB.serviceName,
          version: svcB.version,
          toolSource: svcB.toolSource || 'Nmap',
          isHighRisk,
          timestamp: svcB.timestamp || assessmentB?.createdAt || new Date().toISOString(),
        });
      } else if (svcA.state !== svcB.state) {
        list.push({
          id: `port_state_${key}`,
          host: svcB.host || svcB.ip,
          ip: svcB.ip,
          port: svcB.port,
          protocol: svcB.protocol,
          deltaType: 'STATE_CHANGED',
          baselineState: svcA.state,
          latestState: svcB.state,
          serviceName: svcB.serviceName,
          version: svcB.version,
          toolSource: svcB.toolSource || 'Nmap',
          isHighRisk,
          timestamp: svcB.timestamp || assessmentB?.createdAt || new Date().toISOString(),
        });
      }
    }

    for (const [key, svcA] of mapA.entries()) {
      if (!mapB.has(key)) {
        const isHighRisk = SENSITIVE_PORTS.has(svcA.port) && ![80, 443].includes(svcA.port);
        list.push({
          id: `port_unobs_${key}`,
          host: svcA.host || svcA.ip,
          ip: svcA.ip,
          port: svcA.port,
          protocol: svcA.protocol,
          deltaType: 'NOT_OBSERVED_PORT',
          baselineState: svcA.state,
          serviceName: svcA.serviceName,
          version: svcA.version,
          toolSource: svcA.toolSource || 'Nmap',
          isHighRisk,
          timestamp: svcA.timestamp || assessmentA?.createdAt || new Date().toISOString(),
        });
      }
    }

    return list;
  }, [servicesA, servicesB, assessmentA, assessmentB]);

  // 3. Modified Service Versions & Tech Stack Drift
  const serviceVersionDeltas = useMemo<ServiceVersionDeltaItem[]>(() => {
    const list: ServiceVersionDeltaItem[] = [];
    const keyForSvc = (s: NetworkService) =>
      `${(s.host || s.ip).toLowerCase()}:${s.port}/${s.protocol}`;

    const mapA = new Map(servicesA.map((s) => [keyForSvc(s), s]));
    const mapB = new Map(servicesB.map((s) => [keyForSvc(s), s]));

    for (const [key, svcB] of mapB.entries()) {
      const svcA = mapA.get(key);
      if (!svcA) continue;

      const verA = (svcA.version || '').trim();
      const verB = (svcB.version || '').trim();
      const nameA = (svcA.serviceName || '').trim();
      const nameB = (svcB.serviceName || '').trim();

      if (nameA !== nameB) {
        list.push({
          id: `svc_chg_${key}`,
          target: svcB.host || svcB.ip,
          port: svcB.port,
          protocol: svcB.protocol,
          serviceName: nameB,
          deltaType: 'SERVICE_CHANGED',
          baselineVersion: `${nameA}${verA ? ` (${verA})` : ''}`,
          latestVersion: `${nameB}${verB ? ` (${verB})` : ''}`,
          sourceTool: svcB.toolSource || 'Nmap',
          timestamp: svcB.timestamp || assessmentB?.createdAt || new Date().toISOString(),
        });
      } else if (verA !== verB && (verA || verB)) {
        list.push({
          id: `ver_mod_${key}`,
          target: svcB.host || svcB.ip,
          port: svcB.port,
          protocol: svcB.protocol,
          serviceName: nameB,
          deltaType: 'VERSION_MODIFIED',
          baselineVersion: verA || 'Unspecified',
          latestVersion: verB || 'Unspecified',
          sourceTool: svcB.toolSource || 'Nmap',
          timestamp: svcB.timestamp || assessmentB?.createdAt || new Date().toISOString(),
        });
      }
    }

    // Also check Web Endpoints for Technology Stack or Server Version Drift
    const epMapA = new Map(endpointsA.map((e) => [e.url.toLowerCase(), e]));
    const epMapB = new Map(endpointsB.map((e) => [e.url.toLowerCase(), e]));

    for (const [urlKey, epB] of epMapB.entries()) {
      const epA = epMapA.get(urlKey);
      if (!epA) continue;
      const techA = (epA.technologies || []).slice().sort().join(', ');
      const techB = (epB.technologies || []).slice().sort().join(', ');
      if (techA !== techB) {
        list.push({
          id: `tech_mod_${urlKey}`,
          target: epB.hostname || epB.url,
          port: epB.port || 443,
          protocol: epB.protocol || 'https',
          serviceName: 'HTTP/Web Stack',
          deltaType: 'TECH_STACK_MODIFIED',
          baselineVersion: techA || 'None detected',
          latestVersion: techB || 'None detected',
          sourceTool: 'httpx / WhatWeb',
          timestamp: epB.timestamp || assessmentB?.createdAt || new Date().toISOString(),
        });
      }
    }

    return list;
  }, [servicesA, servicesB, endpointsA, endpointsB, assessmentB]);

  // Filtered Subdomain, Port, and Service Version Deltas based on search query
  const filteredSubdomainDeltas = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return subdomainDeltas.filter((item) => {
      if (deltaCategory === 'not_observed' && item.deltaType !== 'NOT_OBSERVED_SUBDOMAIN')
        return false;
      if (deltaCategory === 'dns_ip' && item.deltaType !== 'IP_CHANGED') return false;
      if (deltaCategory === 'subdomains' && item.deltaType !== 'NEW_SUBDOMAIN') return false;
      if (!q) return true;
      return (
        item.hostname.toLowerCase().includes(q) ||
        (item.latestIp || '').toLowerCase().includes(q) ||
        (item.baselineIp || '').toLowerCase().includes(q) ||
        item.discoverySource.toLowerCase().includes(q)
      );
    });
  }, [subdomainDeltas, deltaCategory, searchQuery]);

  const filteredPortDeltas = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return portDeltas.filter((item) => {
      if (deltaCategory === 'not_observed' && item.deltaType !== 'NOT_OBSERVED_PORT') return false;
      if (!q) return true;
      return (
        item.host.toLowerCase().includes(q) ||
        item.ip.toLowerCase().includes(q) ||
        String(item.port).includes(q) ||
        item.serviceName.toLowerCase().includes(q) ||
        (item.version || '').toLowerCase().includes(q)
      );
    });
  }, [portDeltas, deltaCategory, searchQuery]);

  const filteredServiceVersionDeltas = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return serviceVersionDeltas.filter((item) => {
      if (!q) return true;
      return (
        item.target.toLowerCase().includes(q) ||
        item.serviceName.toLowerCase().includes(q) ||
        item.baselineVersion.toLowerCase().includes(q) ||
        item.latestVersion.toLowerCase().includes(q)
      );
    });
  }, [serviceVersionDeltas, searchQuery]);

  // Classic Diff Calculations
  const namesA = new Set(assetsA.map((a) => a.canonicalName));
  const namesB = new Set(assetsB.map((a) => a.canonicalName));
  const newlyObservedAssets = assetsB.filter((b) => !namesA.has(b.canonicalName));
  const notObservedInLatest = assetsA.filter((a) => !namesB.has(a.canonicalName));
  const urlsA = new Set(endpointsA.map((e) => e.url));
  const newEndpoints = endpointsB.filter((e) => !urlsA.has(e.url));
  const portsA = new Set(servicesA.map((s) => `${s.host}:${s.port}`));
  const newPorts = servicesB.filter((s) => !portsA.has(`${s.host}:${s.port}`));

  const newSubdomainsOnlyCount = subdomainDeltas.filter(
    (s) => s.deltaType === 'NEW_SUBDOMAIN'
  ).length;
  const ipChangedSubdomainsCount = subdomainDeltas.filter(
    (s) => s.deltaType === 'IP_CHANGED'
  ).length;
  const newOpenPortsOnlyCount = portDeltas.filter(
    (p) => p.deltaType === 'NEW_OPEN_PORT'
  ).length;
  const notObservedTotalCount =
    subdomainDeltas.filter((s) => s.deltaType === 'NOT_OBSERVED_SUBDOMAIN').length +
    portDeltas.filter((p) => p.deltaType === 'NOT_OBSERVED_PORT').length;

  // Time delta calculation between the two runs
  const timeDeltaLabel = useMemo(() => {
    if (!assessmentA || !assessmentB) return '';
    const tA = new Date(assessmentA.createdAt).getTime();
    const tB = new Date(assessmentB.createdAt).getTime();
    const diffMs = Math.abs(tB - tA);
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays > 0) return `${diffDays} day(s), ${diffHours % 24} hr(s) between scans`;
    const diffMins = Math.max(1, Math.floor(diffMs / (1000 * 60)));
    return `${diffHours} hr(s), ${diffMins % 60} min(s) between scans`;
  }, [assessmentA, assessmentB]);

  const exportScanDeltaCsv = () => {
    const headers = [
      'DeltaCategory',
      'ChangeType',
      'TargetAssetOrHost',
      'BaselineValue',
      'LatestValue',
      'DiscoveryTool',
      'ObservedAt',
    ];
    const rows: string[][] = [];

    subdomainDeltas.forEach((s) => {
      rows.push([
        'Subdomain',
        s.deltaType,
        s.hostname,
        s.baselineIp || 'Absent in baseline',
        s.deltaType === 'NOT_OBSERVED_SUBDOMAIN'
          ? 'Not observed in latest scan'
          : s.latestIp || 'Observed',
        s.discoverySource,
        s.timestamp,
      ]);
    });

    portDeltas.forEach((p) => {
      rows.push([
        'OpenPort',
        p.deltaType,
        `${p.host}:${p.port}/${p.protocol}`,
        p.baselineState || 'Closed / Unobserved',
        p.deltaType === 'NOT_OBSERVED_PORT'
          ? 'Not observed in latest scan'
          : `${p.latestState || 'open'} (${p.serviceName}${p.version ? ` ${p.version}` : ''})`,
        p.toolSource,
        p.timestamp,
      ]);
    });

    serviceVersionDeltas.forEach((v) => {
      rows.push([
        'ServiceVersion',
        v.deltaType,
        `${v.target}:${v.port}/${v.protocol} (${v.serviceName})`,
        v.baselineVersion,
        v.latestVersion,
        v.sourceTool,
        v.timestamp,
      ]);
    });

    const csv = [
      headers.join(','),
      ...rows.map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `reconx-scan-delta-${assessmentA?.id || 'base'}-vs-${
      assessmentB?.id || 'latest'
    }.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (assessments.length < 2) {
    return (
      <div className="max-w-2xl mx-auto mt-8 p-8 bg-[#111827] border border-slate-800 rounded-2xl text-center space-y-4 shadow-xl">
        <GitCompare className="w-10 h-10 text-cyan-400 mx-auto" />
        <h3 className="text-base font-bold text-white">Not Enough Assessments to Compare</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Historical Scan Delta analysis requires at least two saved reconnaissance assessments. Run another scan or load a lab demo fixture to compare attack surface changes over time.
        </p>
        <button
          onClick={onBack}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Return to Dashboard
        </button>
      </div>
    );
  }

  const showSubdomainSection =
    deltaCategory === 'all' ||
    deltaCategory === 'subdomains' ||
    deltaCategory === 'dns_ip' ||
    deltaCategory === 'not_observed';

  const showPortsSection =
    deltaCategory === 'all' || deltaCategory === 'ports' || deltaCategory === 'not_observed';

  const showServiceVersionsSection =
    deltaCategory === 'all' || deltaCategory === 'service_versions';

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header & Time-Stamped Run Selectors */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl sm:rounded-2xl p-4 sm:p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <GitCompare className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                Assessment Comparison &amp; Scan Delta Intelligence
              </h2>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase font-bold rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                Time-Stamped Diff Engine
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Inspect exact attack surface drift between two time-stamped reconnaissance runs — highlighting newly exposed open ports, new subdomains, IP resolution shifts, and modified service versions.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* View Mode Switcher */}
            <div className="inline-flex p-1 bg-slate-950 border border-slate-800 rounded-xl">
              <button
                onClick={() => setViewMode('scan_delta')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                  viewMode === 'scan_delta'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5" />
                Scan Delta View
              </button>
              <button
                onClick={() => setViewMode('classic_diff')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                  viewMode === 'classic_diff'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                Asset Inventory Diff
              </button>
            </div>

            <button
              onClick={exportScanDeltaCsv}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700 cursor-pointer"
              title="Export complete Scan Delta ledger as CSV"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" /> Export Delta CSV
            </button>

            <button
              onClick={onBack}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs border border-slate-700 shrink-0 cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Dashboard
            </button>
          </div>
        </div>

        {/* Time-Stamped Assessment Selectors */}
        <div className="grid grid-cols-1 lg:grid-cols-11 gap-3 items-center mt-6 pt-5 border-t border-slate-800">
          {/* Baseline Assessment (Run A) */}
          <div className="lg:col-span-5 bg-slate-950/90 border border-slate-800 rounded-xl p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Baseline Run (Scan A)
              </span>
              {assessmentA && (
                <span className="text-[11px] font-mono text-cyan-400 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(assessmentA.createdAt).toLocaleString()}
                </span>
              )}
            </div>
            <select
              value={assessmentAId}
              onChange={(e) => setAssessmentAId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.scope?.rootDomain || 'N/A'}) —{' '}
                  {new Date(a.createdAt).toLocaleString()}
                </option>
              ))}
            </select>
            {assessmentA && (
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
                <span>Scope: {assessmentA.scope?.rootDomain}</span>
                <span>
                  Assets: {assetsA.length} • Ports: {servicesA.length}
                </span>
              </div>
            )}
          </div>

          {/* Swap & Time Elapsed Indicator */}
          <div className="lg:col-span-1 flex flex-col items-center justify-center gap-1.5 py-1">
            <button
              onClick={handleSwapRuns}
              className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-700 transition-colors cursor-pointer"
              title="Swap Baseline and Latest Assessment Runs"
            >
              <ArrowLeftRight className="w-4 h-4" />
            </button>
            {timeDeltaLabel && (
              <span className="text-[10px] font-mono text-slate-500 text-center leading-tight">
                {timeDeltaLabel}
              </span>
            )}
          </div>

          {/* Latest Assessment (Run B) */}
          <div className="lg:col-span-5 bg-slate-950/90 border border-cyan-500/30 rounded-xl p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-semibold">
                Target Comparison Run (Scan B)
              </span>
              {assessmentB && (
                <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(assessmentB.createdAt).toLocaleString()}
                </span>
              )}
            </div>
            <select
              value={assessmentBId}
              onChange={(e) => setAssessmentBId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.scope?.rootDomain || 'N/A'}) —{' '}
                  {new Date(a.createdAt).toLocaleString()}
                </option>
              ))}
            </select>
            {assessmentB && (
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
                <span>Scope: {assessmentB.scope?.rootDomain}</span>
                <span>
                  Assets: {assetsB.length} • Ports: {servicesB.length}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Warning if comparing identical run or incomplete scan */}
        {assessmentAId === assessmentBId && (
          <div className="mt-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            Baseline (Scan A) and Target (Scan B) are currently set to the same assessment run. Select two distinct time-stamped runs above to inspect infrastructure drift.
          </div>
        )}
        {snapshotComparison?.summary.scanStatusWarning && (
          <div className="mt-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {snapshotComparison.summary.scanStatusWarning}
          </div>
        )}
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-400 font-mono text-xs bg-[#111827] border border-slate-800 rounded-2xl">
          Computing time-stamped Scan Delta across subdomains, ports, and service versions...
        </div>
      ) : viewMode === 'scan_delta' ? (
        <div className="space-y-6">
          {/* Scan Delta KPI Summary Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            <button
              onClick={() => setDeltaCategory('subdomains')}
              className={`text-left p-4 rounded-xl border transition-all cursor-pointer ${
                deltaCategory === 'subdomains'
                  ? 'bg-emerald-500/20 border-emerald-400'
                  : 'bg-emerald-500/10 border-emerald-500/30 hover:border-emerald-500/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-emerald-400">New Subdomains</span>
                <Globe className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                +{newSubdomainsOnlyCount}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Newly discovered hostnames in Scan B
              </p>
            </button>

            <button
              onClick={() => setDeltaCategory('ports')}
              className={`text-left p-4 rounded-xl border transition-all cursor-pointer ${
                deltaCategory === 'ports'
                  ? 'bg-cyan-500/20 border-cyan-400'
                  : 'bg-cyan-500/10 border-cyan-500/30 hover:border-cyan-500/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-cyan-400">New Open Ports</span>
                <Server className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                +{newOpenPortsOnlyCount}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Newly reachable TCP/UDP listeners
              </p>
            </button>

            <button
              onClick={() => setDeltaCategory('service_versions')}
              className={`text-left p-4 rounded-xl border transition-all cursor-pointer ${
                deltaCategory === 'service_versions'
                  ? 'bg-purple-500/20 border-purple-400'
                  : 'bg-purple-500/10 border-purple-500/30 hover:border-purple-500/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-purple-400">
                  Modified Service Versions
                </span>
                <RefreshCw className="w-4 h-4 text-purple-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                {serviceVersionDeltas.length}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Version, banner, or tech stack changes
              </p>
            </button>

            <button
              onClick={() => setDeltaCategory('dns_ip')}
              className={`text-left p-4 rounded-xl border transition-all cursor-pointer ${
                deltaCategory === 'dns_ip'
                  ? 'bg-blue-500/20 border-blue-400'
                  : 'bg-blue-500/10 border-blue-500/30 hover:border-blue-500/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-blue-400">DNS / IP Shifts</span>
                <ArrowLeftRight className="w-4 h-4 text-blue-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                {ipChangedSubdomainsCount}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Hostnames remapped to new IP addresses
              </p>
            </button>

            <button
              onClick={() => setDeltaCategory('not_observed')}
              className={`text-left p-4 rounded-xl border transition-all cursor-pointer ${
                deltaCategory === 'not_observed'
                  ? 'bg-amber-500/20 border-amber-400'
                  : 'bg-amber-500/10 border-amber-500/30 hover:border-amber-500/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-amber-400">Not Observed</span>
                <MinusCircle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                {notObservedTotalCount}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Not observed in latest scan (Scan B)
              </p>
            </button>
          </div>

          {/* Filter & Search Bar */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <Filter className="w-4 h-4 text-slate-400 mr-1" />
              {(
                [
                  { id: 'all', label: 'All Scan Deltas' },
                  { id: 'ports', label: 'Open Port Changes' },
                  { id: 'subdomains', label: 'New Subdomains' },
                  { id: 'service_versions', label: 'Modified Service Versions' },
                  { id: 'dns_ip', label: 'DNS / IP Shifts' },
                  { id: 'not_observed', label: 'Not Observed in Latest' },
                ] as { id: DeltaFilterCategory; label: string }[]
              ).map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setDeltaCategory(tab.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                    deltaCategory === tab.id
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by hostname, IP, port, or version..."
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 w-64 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* SECTION A: OPEN PORT DELTAS */}
          {showPortsSection && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Open Port &amp; Listener Deltas ({filteredPortDeltas.length})
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  Compares Nmap / service port states between Scan A &amp; Scan B
                </span>
              </div>

              {filteredPortDeltas.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">
                  No open port deltas match the active filter between the selected runs.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/70 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-3">Delta Type</th>
                        <th className="px-4 py-3">Host / IP</th>
                        <th className="px-4 py-3">Port / Proto</th>
                        <th className="px-4 py-3">Baseline (Scan A)</th>
                        <th className="px-4 py-3">Latest (Scan B)</th>
                        <th className="px-4 py-3">Service &amp; Banner</th>
                        <th className="px-4 py-3">Source Tool</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {filteredPortDeltas.map((item) => (
                        <tr key={item.id} className="hover:bg-slate-800/30">
                          <td className="px-4 py-3">
                            {item.deltaType === 'NEW_OPEN_PORT' ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                + NEW OPEN PORT
                              </span>
                            ) : item.deltaType === 'STATE_CHANGED' ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                                Δ STATE CHANGED
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                                NOT OBSERVED
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 font-semibold text-white">
                            {item.host}
                            {item.ip && item.ip !== item.host ? (
                              <span className="text-slate-500 block text-[10px]">{item.ip}</span>
                            ) : null}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`font-bold ${
                                item.isHighRisk ? 'text-rose-400' : 'text-cyan-300'
                              }`}
                            >
                              {item.port}/{item.protocol.toUpperCase()}
                            </span>
                            {item.isHighRisk && (
                              <span className="ml-2 px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[9px] uppercase">
                                Sensitive Port
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-400">
                            {item.baselineState ? item.baselineState.toUpperCase() : 'UNOBSERVED'}
                          </td>
                          <td className="px-4 py-3">
                            {item.deltaType === 'NOT_OBSERVED_PORT' ? (
                              <span className="text-amber-300">Not observed in latest scan</span>
                            ) : (
                              <span className="text-emerald-400 font-bold uppercase">
                                {item.latestState || 'OPEN'}
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-200">
                            {item.serviceName}
                            {item.version ? (
                              <span className="text-cyan-300 ml-1">({item.version})</span>
                            ) : null}
                          </td>
                          <td className="px-4 py-3 text-slate-400">{item.toolSource}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* SECTION B: SUBDOMAIN & DNS / IP RESOLUTION DELTAS */}
          {showSubdomainSection && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Subdomain &amp; DNS Resolution Deltas ({filteredSubdomainDeltas.length})
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  Tracks newly discovered subdomains, IP remappings, and unobserved hosts
                </span>
              </div>

              {filteredSubdomainDeltas.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">
                  No subdomain or DNS resolution deltas match the active filter between the selected runs.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/70 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-3">Delta Classification</th>
                        <th className="px-4 py-3">Subdomain / Hostname</th>
                        <th className="px-4 py-3">Baseline IP (Scan A)</th>
                        <th className="px-4 py-3">Latest IP / Status (Scan B)</th>
                        <th className="px-4 py-3">Correlated Tools</th>
                        <th className="px-4 py-3">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {filteredSubdomainDeltas.map((sub) => (
                        <tr key={sub.id} className="hover:bg-slate-800/30">
                          <td className="px-4 py-3">
                            {sub.deltaType === 'NEW_SUBDOMAIN' ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                + NEW SUBDOMAIN
                              </span>
                            ) : sub.deltaType === 'IP_CHANGED' ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300 border border-blue-500/40">
                                Δ IP REMAPPED
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                                NOT OBSERVED
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 font-semibold text-white">{sub.hostname}</td>
                          <td className="px-4 py-3 text-slate-400">
                            {sub.baselineIp || 'Absent in Scan A'}
                          </td>
                          <td className="px-4 py-3">
                            {sub.deltaType === 'NOT_OBSERVED_SUBDOMAIN' ? (
                              <span className="text-amber-300">Not observed in latest scan</span>
                            ) : sub.deltaType === 'IP_CHANGED' ? (
                              <span className="inline-flex items-center gap-1.5 text-blue-300 font-semibold">
                                <span className="text-slate-500 line-through">{sub.baselineIp}</span>
                                <ArrowRight className="w-3 h-3 text-cyan-400" />
                                <span className="text-emerald-300">{sub.latestIp}</span>
                              </span>
                            ) : (
                              <span className="text-emerald-300 font-semibold">
                                {sub.latestIp || 'Active'}
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-cyan-400">{sub.discoverySource}</td>
                          <td className="px-4 py-3 text-emerald-400 font-bold">
                            {sub.confidenceScore}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* SECTION C: MODIFIED SERVICE VERSIONS & TECH STACK DRIFT */}
          {showServiceVersionsSection && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Modified Service Versions &amp; Technology Stack Drift ({filteredServiceVersionDeltas.length})
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  Highlights daemon upgrades, downgrades, or web framework changes
                </span>
              </div>

              {filteredServiceVersionDeltas.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">
                  No modified service versions or technology fingerprint changes detected between Scan A and Scan B.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/70 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-3">Change Type</th>
                        <th className="px-4 py-3">Target Host &amp; Port</th>
                        <th className="px-4 py-3">Service / Layer</th>
                        <th className="px-4 py-3">Baseline Version (Scan A)</th>
                        <th className="px-4 py-3">Latest Version (Scan B)</th>
                        <th className="px-4 py-3">Source Tool</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {filteredServiceVersionDeltas.map((v) => (
                        <tr key={v.id} className="hover:bg-slate-800/30">
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                              {v.deltaType.replace(/_/g, ' ')}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-semibold text-white">
                            {v.target}:{v.port}/{v.protocol}
                          </td>
                          <td className="px-4 py-3 text-cyan-300">{v.serviceName}</td>
                          <td className="px-4 py-3 text-rose-300/90">{v.baselineVersion}</td>
                          <td className="px-4 py-3">
                            <span className="inline-flex items-center gap-1.5 text-emerald-300 font-semibold">
                              <ArrowRight className="w-3.5 h-3.5 text-purple-400" />
                              {v.latestVersion}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-slate-400">{v.sourceTool}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        /* CLASSIC INVENTORY DIFF VIEW */
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-emerald-400">Newly Discovered Assets</span>
                <PlusCircle className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                +{newlyObservedAssets.length}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Observed in latest scan, absent in baseline
              </p>
            </div>

            <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-amber-400">Not Observed in Latest</span>
                <MinusCircle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                -{notObservedInLatest.length}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Present in baseline, not observed in latest run
              </p>
            </div>

            <div className="p-4 bg-purple-500/10 border border-purple-500/30 rounded-xl">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-purple-400">New Web Endpoints</span>
                <Globe className="w-4 h-4 text-purple-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                +{newEndpoints.length}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Newly probed HTTP/HTTPS application routes
              </p>
            </div>

            <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-xl">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-cyan-400">New Open Ports / Services</span>
                <Cpu className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                +{newPorts.length}
              </div>
              <p className="text-[10px] text-slate-400 mt-1">
                Newly reachable network service listeners
              </p>
            </div>
          </div>

          {/* Newly Discovered Assets Table */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="p-4 border-b border-slate-800 flex items-center gap-2">
              <PlusCircle className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">
                Newly Discovered Assets (Attack Surface Expansion)
              </h3>
            </div>
            {newlyObservedAssets.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No new assets were added between these two snapshots.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Canonical Asset</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Discovery Source</th>
                      <th className="px-4 py-3">Delta Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {newlyObservedAssets.map((a) => (
                      <tr key={a.id} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3 text-emerald-300 font-semibold">
                          {a.canonicalName}
                        </td>
                        <td className="px-4 py-3 uppercase text-slate-400">{a.assetType}</td>
                        <td className="px-4 py-3 text-slate-400">{a.discoverySource}</td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40">
                            + NEWLY OBSERVED
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Assets Not Observed Table */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="p-4 border-b border-slate-800 flex items-center gap-2">
              <MinusCircle className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-white">Assets Not Observed in Latest Run</h3>
            </div>
            {notObservedInLatest.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                All baseline assets were successfully confirmed in latest scan.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Canonical Asset</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Baseline Source</th>
                      <th className="px-4 py-3">Delta Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {notObservedInLatest.map((a) => (
                      <tr key={a.id} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3 text-amber-300 font-semibold">
                          {a.canonicalName}
                        </td>
                        <td className="px-4 py-3 uppercase text-slate-400">{a.assetType}</td>
                        <td className="px-4 py-3 text-slate-400">{a.discoverySource}</td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40">
                            Not observed in latest scan
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
