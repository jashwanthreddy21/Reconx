import React, { useState, useEffect } from 'react';
import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  ScanJob,
  AssetType,
  FindingSeverity
} from '../types';
import { scannerOrchestrator } from '../services/scannerEngine';
import { firestoreService } from '../services/firestoreService';
import { AttackSurfaceGraph } from '../components/graph/AttackSurfaceGraph';
import {
  Globe,
  Server,
  Layers,
  Cpu,
  Shield,
  Activity,
  Play,
  StopCircle,
  FileText,
  Download,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Terminal,
  ExternalLink,
  ChevronRight,
  Code,
  Lock,
  Printer,
  FileDown,
  Flame,
  LayoutGrid,
  List
} from 'lucide-react';
import { generateAssessmentSummaryPdf } from '../services/pdfReportGenerator';
import { SubdomainFindingsHeatmap } from '../components/heatmap/SubdomainFindingsHeatmap';

interface Props {
  assessment: Assessment;
  onUpdateAssessment: (updated: Assessment) => void;
  onBack: () => void;
}

export type DetailTab =
  | 'overview'
  | 'heatmap'
  | 'graph'
  | 'assets'
  | 'dns'
  | 'endpoints'
  | 'services'
  | 'technologies'
  | 'findings'
  | 'logs'
  | 'reports'
  | 'scope';

export const AssessmentDetail: React.FC<Props> = ({
  assessment,
  onUpdateAssessment,
  onBack,
}) => {
  const [activeTab, setActiveTab] = useState<DetailTab>('overview');
  const [findingsViewMode, setFindingsViewMode] = useState<'list' | 'heatmap'>('list');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [dnsRecords, setDnsRecords] = useState<DnsRecord[]>([]);
  const [endpoints, setEndpoints] = useState<WebEndpoint[]>([]);
  const [services, setServices] = useState<NetworkService[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [selectedLogJob, setSelectedLogJob] = useState<ScanJob | null>(null);

  const [loadingData, setLoadingData] = useState(true);
  const [isScanning, setIsScanning] = useState(false);

  // Filters for tables
  const [assetSearch, setAssetSearch] = useState('');
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>('all');
  const [dnsSearch, setDnsSearch] = useState('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>('all');

  // Load existing data from Firestore
  useEffect(() => {
    let mounted = true;
    const load = async () => {
      setLoadingData(true);
      try {
        const [aList, dList, eList, sList, fList, jList] = await Promise.all([
          firestoreService.getAssets(assessment.id),
          firestoreService.getDnsRecords(assessment.id),
          firestoreService.getWebEndpoints(assessment.id),
          firestoreService.getNetworkServices(assessment.id),
          firestoreService.getFindings(assessment.id),
          firestoreService.getScanJobs(assessment.id),
        ]);

        if (mounted) {
          setAssets(aList || []);
          setDnsRecords(dList || []);
          setEndpoints(eList || []);
          setServices(sList || []);
          setFindings(fList || []);
          setScanJobs(jList || []);

          // Auto-start scan if queued
          if (assessment.status === 'queued' && !isScanning) {
            handleStartScan();
          }
        }
      } catch (err) {
        console.error('Error loading assessment subcollections:', err);
      } finally {
        if (mounted) setLoadingData(false);
      }
    };
    load();

    return () => {
      mounted = false;
    };
  }, [assessment.id]);

  // Start or resume scan pipeline
  const handleStartScan = async () => {
    setIsScanning(true);
    const updatedStatus: Assessment = { ...assessment, status: 'running' };
    onUpdateAssessment(updatedStatus);
    await firestoreService.updateAssessment(assessment.id, { status: 'running' });

    try {
      const results = await scannerOrchestrator.executePipeline(assessment, {
        onJobUpdate: (job) => {
          setScanJobs((prev) => {
            const idx = prev.findIndex((j) => j.id === job.id);
            if (idx >= 0) {
              const copy = [...prev];
              copy[idx] = job;
              return copy;
            }
            return [...prev, job];
          });
          firestoreService.saveScanJob(job);
        },
        onLog: (tool, line) => {
          // Log streaming
        },
        onAssetsDiscovered: (newAssets) => {
          setAssets((prev) => {
            const map = new Map(prev.map((a) => [a.id, a]));
            newAssets.forEach((a) => map.set(a.id, a));
            return Array.from(map.values());
          });
          firestoreService.saveAssetsBatch(assessment.id, newAssets);
        },
        onDnsDiscovered: (newDns) => {
          setDnsRecords((prev) => {
            const map = new Map(prev.map((d) => [d.id, d]));
            newDns.forEach((d) => map.set(d.id, d));
            return Array.from(map.values());
          });
          firestoreService.saveDnsRecordsBatch(assessment.id, newDns);
        },
        onEndpointsDiscovered: (newEps) => {
          setEndpoints((prev) => {
            const map = new Map(prev.map((e) => [e.id, e]));
            newEps.forEach((e) => map.set(e.id, e));
            return Array.from(map.values());
          });
          firestoreService.saveEndpointsBatch(assessment.id, newEps);
        },
        onServicesDiscovered: (newSvcs) => {
          setServices((prev) => {
            const map = new Map(prev.map((s) => [s.id, s]));
            newSvcs.forEach((s) => map.set(s.id, s));
            return Array.from(map.values());
          });
          firestoreService.saveServicesBatch(assessment.id, newSvcs);
        },
        onFindingsGenerated: (newFindings) => {
          setFindings((prev) => {
            const map = new Map(prev.map((f) => [f.id, f]));
            newFindings.forEach((f) => map.set(f.id, f));
            return Array.from(map.values());
          });
          firestoreService.saveFindingsBatch(assessment.id, newFindings);
        },
      });

      // Update assessment stats
      const finalStats = {
        assetsCount: results.assets.length,
        subdomainsCount: results.assets.filter((a) => a.assetType === 'subdomain').length,
        dnsRecordsCount: results.dnsRecords.length,
        endpointsCount: results.endpoints.length,
        servicesCount: results.services.length,
        technologiesCount: results.assets.filter((a) => a.assetType === 'technology').length,
        findingsCount: results.findings.length,
      };

      const completedAssessment: Assessment = {
        ...assessment,
        status: 'completed',
        stats: finalStats,
        updatedAt: new Date().toISOString(),
      };
      onUpdateAssessment(completedAssessment);
      await firestoreService.updateAssessment(assessment.id, {
        status: 'completed',
        stats: finalStats,
      });
    } catch (err: any) {
      const isCancelled = err?.message?.includes('cancelled');
      const targetStatus = isCancelled ? 'cancelled' : 'failed';
      const updatedStatus: Assessment = { ...assessment, status: targetStatus };
      onUpdateAssessment(updatedStatus);
      await firestoreService.updateAssessment(assessment.id, { status: targetStatus });
    } finally {
      setIsScanning(false);
    }
  };

  const handleCancelScan = () => {
    scannerOrchestrator.cancelScan();
    setIsScanning(false);
  };

  // Export handlers
  const exportCsv = (type: 'assets' | 'dns' | 'endpoints' | 'services') => {
    let rows: any[] = [];
    let headers: string[] = [];

    if (type === 'assets') {
      headers = ['CanonicalName', 'AssetType', 'DiscoverySource', 'Status', 'FirstSeen', 'LastSeen'];
      rows = assets.map((a) => [a.canonicalName, a.assetType, a.discoverySource, a.status, a.firstSeen, a.lastSeen]);
    } else if (type === 'dns') {
      headers = ['Hostname', 'RecordType', 'Value', 'TTL', 'Source', 'Timestamp'];
      rows = dnsRecords.map((d) => [d.hostname, d.recordType, d.value, d.ttl || 300, d.source, d.timestamp]);
    } else if (type === 'endpoints') {
      headers = ['URL', 'Hostname', 'Protocol', 'Port', 'StatusCode', 'Title', 'IP'];
      rows = endpoints.map((e) => [e.url, e.hostname, e.protocol, e.port, e.statusCode, e.title, e.ip]);
    } else if (type === 'services') {
      headers = ['Host', 'IP', 'Port', 'Protocol', 'State', 'ServiceName', 'Version'];
      rows = services.map((s) => [s.host, s.ip, s.port, s.protocol, s.state, s.serviceName, s.version || '']);
    }

    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((e) => e.map((x: any) => `"${String(x).replace(/"/g, '""')}"`).join(','))].join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `reconx_${assessment.name}_${type}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const exportFullJson = () => {
    const fullPayload = {
      assessment,
      assets,
      dnsRecords,
      endpoints,
      services,
      findings,
      scanJobs,
      exportedAt: new Date().toISOString(),
      disclaimer: 'ReconX Authorized Security Reconnaissance Assessment Report Data',
    };
    const blob = new Blob([JSON.stringify(fullPayload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconx-assessment-${assessment.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadSummaryPdf = () => {
    generateAssessmentSummaryPdf({
      assessment,
      findings,
      totalFindingsCount: assessment.stats?.findingsCount || findings.length,
    });
  };

  const getSeverityBadge = (sev: FindingSeverity) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'low':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      case 'informational':
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header Card */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl sm:rounded-2xl p-4 sm:p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <button
                onClick={onBack}
                className="text-xs text-slate-400 hover:text-white flex items-center gap-1 hover:underline"
              >
                Assessments
              </button>
              <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
              <span className="text-xs font-mono text-cyan-400 font-medium">
                {assessment.scope.rootDomain}
              </span>
              {assessment.isDemo && (
                <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  DEMO LAB FIXTURE
                </span>
              )}
            </div>

            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex flex-wrap items-center gap-2 sm:gap-2.5">
              <span>{assessment.name}</span>
              <span
                className={`text-[11px] sm:text-xs px-2.5 py-0.5 rounded-full font-mono font-medium capitalize border ${
                  assessment.status === 'completed'
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : assessment.status === 'running'
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse'
                    : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
                }`}
              >
                ● {assessment.status}
              </span>
            </h1>

            <p className="text-[11px] sm:text-xs text-slate-400 mt-1 leading-relaxed">
              Target: <span className="text-slate-200 font-mono font-semibold">{assessment.scope.rootDomain}</span> • Client:{' '}
              <span className="text-slate-200">{assessment.clientName}</span> • Type:{' '}
              <span className="capitalize text-slate-200">{assessment.type}</span> • Started:{' '}
              {new Date(assessment.createdAt).toLocaleDateString()}
            </p>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
            {isScanning ? (
              <button
                onClick={handleCancelScan}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-rose-600/20 transition-all cursor-pointer"
              >
                <StopCircle className="w-4 h-4" /> Cancel Scan
              </button>
            ) : (
              <button
                onClick={handleStartScan}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all cursor-pointer"
              >
                <Play className="w-4 h-4" /> Re-Run Pipeline
              </button>
            )}

            <button
              onClick={handleDownloadSummaryPdf}
              className="flex items-center gap-1.5 px-3 sm:px-3.5 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-500/20 transition-all cursor-pointer"
              title="Generate summary PDF report with scope, tool configs, and findings count"
            >
              <FileDown className="w-4 h-4" /> Summary PDF Report
            </button>

            <button
              onClick={exportFullJson}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
              title="Download Full Raw Assessment JSON"
            >
              <Download className="w-4 h-4 text-cyan-400" /> JSON Export
            </button>
          </div>
        </div>

        {/* Tab Navigation Strip */}
        <div className="flex items-center gap-1 overflow-x-auto border-t border-slate-800/80 pt-4 mt-5 text-xs">
          {[
            { id: 'overview' as DetailTab, label: 'Overview', icon: Activity },
            { id: 'heatmap' as DetailTab, label: 'Subdomain Heatmap', icon: Flame, count: findings.length },
            { id: 'graph' as DetailTab, label: 'Attack Surface Graph', icon: Globe, count: assets.length },
            { id: 'assets' as DetailTab, label: 'Asset Inventory', icon: Server, count: assets.length },
            { id: 'dns' as DetailTab, label: 'DNS Explorer', icon: Layers, count: dnsRecords.length },
            { id: 'endpoints' as DetailTab, label: 'Web Endpoints', icon: Globe, count: endpoints.length },
            { id: 'services' as DetailTab, label: 'Network Services', icon: Cpu, count: services.length },
            {
              id: 'technologies' as DetailTab,
              label: 'Technologies',
              icon: Shield,
              count: assets.filter((a) => a.assetType === 'technology').length,
            },
            { id: 'findings' as DetailTab, label: 'Observations & Risks', icon: AlertTriangle, count: findings.length },
            { id: 'logs' as DetailTab, label: 'Tool Logs', icon: Terminal, count: scanJobs.length },
            { id: 'reports' as DetailTab, label: 'Report & Export', icon: FileText },
            { id: 'scope' as DetailTab, label: 'Scope & ROE', icon: Lock },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-cyan-400 border border-blue-500/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                      isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-500'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Quick Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {[
              { label: 'Total Assets', value: assets.length, icon: Server, color: 'text-cyan-400' },
              {
                label: 'Subdomains',
                value: assets.filter((a) => a.assetType === 'subdomain').length,
                icon: Globe,
                color: 'text-blue-400',
              },
              { label: 'DNS Answers', value: dnsRecords.length, icon: Layers, color: 'text-emerald-400' },
              { label: 'HTTP Endpoints', value: endpoints.length, icon: Globe, color: 'text-purple-400' },
              { label: 'Open Ports', value: services.length, icon: Cpu, color: 'text-amber-400' },
              { label: 'Key Findings', value: findings.length, icon: AlertTriangle, color: 'text-rose-400' },
            ].map((k, i) => (
              <div key={i} className="p-4 bg-[#111827] border border-slate-800 rounded-xl">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] text-slate-400">{k.label}</span>
                  <k.icon className={`w-3.5 h-3.5 ${k.color}`} />
                </div>
                <div className="text-xl font-bold font-mono text-white">{k.value}</div>
              </div>
            ))}
          </div>

          {/* Scanner Pipeline Status Cards */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Reconnaissance Scanner Pipeline
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
              {[
                { name: 'Subfinder', desc: 'Passive Subdomain Enumeration', enabled: assessment.toolConfig.subfinder },
                { name: 'dnsx', desc: 'DNS Record Multi-Resolver', enabled: assessment.toolConfig.dnsx },
                { name: 'httpx', desc: 'Web Service & Title Prober', enabled: assessment.toolConfig.httpx },
                { name: 'Nmap', desc: 'Port & Service Fingerprinting', enabled: assessment.toolConfig.nmap },
                { name: 'WhatWeb', desc: 'Observable Tech Fingerprinting', enabled: assessment.toolConfig.whatweb },
              ].map((tool) => {
                const job = scanJobs.find((j) => j.toolName === tool.name);
                const status = job ? job.status : tool.enabled ? (isScanning ? 'running' : 'completed') : 'disabled';

                return (
                  <div
                    key={tool.name}
                    className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-semibold text-xs text-white">{tool.name}</span>
                        <span
                          className={`text-[9px] px-1.5 py-0.5 rounded font-mono uppercase ${
                            status === 'completed'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : status === 'running'
                              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse'
                              : 'bg-slate-800 text-slate-500'
                          }`}
                        >
                          {status}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400">{tool.desc}</p>
                    </div>

                    {job && (
                      <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                        <span>{job.durationMs}ms</span>
                        <button
                          onClick={() => {
                            setSelectedLogJob(job);
                            setActiveTab('logs');
                          }}
                          className="text-cyan-400 hover:underline"
                        >
                          Logs ({job.logs.length})
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Graph Preview & Findings Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-white">Attack Surface Relationship Topology</h3>
                  <button
                    onClick={() => setActiveTab('graph')}
                    className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                  >
                    Interactive Canvas <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
                <p className="text-xs text-slate-400 mb-4">
                  Visual map linking root domain to subdomains, resolved IPs, HTTP endpoints, network services, and technology observations.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('graph')}
                className="h-56 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-center cursor-pointer hover:border-cyan-500/40 transition-all p-4 relative overflow-hidden group"
              >
                <div className="text-center space-y-2 z-10">
                  <Globe className="w-10 h-10 text-cyan-400 mx-auto group-hover:scale-110 transition-transform" />
                  <div className="text-xs font-semibold text-white">
                    {assets.length} Correlated Nodes &amp; Relationships
                  </div>
                  <span className="text-[10px] text-slate-400 block font-mono">
                    Click to launch full interactive visual graph
                  </span>
                </div>
              </div>
            </div>

            {/* Recent Findings Preview */}
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-white">Observations &amp; Risk Items</h3>
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                  >
                    View All ({findings.length}) <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
                <p className="text-xs text-slate-400 mb-4">
                  Prioritized findings based on verified network reconnaissance observations.
                </p>
              </div>

              <div className="space-y-2">
                {findings.slice(0, 3).map((f) => (
                  <div key={f.id} className="p-3 bg-slate-950 rounded-xl border border-slate-800/80">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-white truncate max-w-[280px]">
                        {f.title}
                      </span>
                      <span
                        className={`text-[9px] px-2 py-0.5 rounded font-mono uppercase border ${getSeverityBadge(
                          f.severity
                        )}`}
                      >
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-1">{f.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Subdomain Findings Heatmap Quick Card */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Flame className="w-5 h-5 text-rose-500" />
                <h3 className="text-sm font-semibold text-white">
                  Subdomain Risk &amp; Finding Severity Heatmap
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30">
                  D3.js Visualization
                </span>
              </div>
              <p className="text-xs text-slate-400 max-w-2xl">
                Matrix correlating vulnerability counts and severity tiers (Critical, High, Medium, Low, Informational) across all cataloged subdomains.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('heatmap')}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-rose-600/20 transition-all cursor-pointer whitespace-nowrap"
            >
              <Flame className="w-4 h-4" /> Open Interactive Heatmap
            </button>
          </div>
        </div>
      )}

      {/* TAB: SUBDOMAIN HEATMAP (D3.js) */}
      {activeTab === 'heatmap' && (
        <SubdomainFindingsHeatmap
          assessment={assessment}
          findings={findings}
          assets={assets}
          onSelectFinding={(f) => {
            setFindingSeverityFilter(f.severity);
            setFindingsViewMode('list');
            setActiveTab('findings');
          }}
        />
      )}

      {/* TAB 2: INTERACTIVE GRAPH */}
      {activeTab === 'graph' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-white">Interactive Attack Surface Graph</h3>
              <p className="text-xs text-slate-400">
                Pan, zoom, filter, and inspect relationships from root domains down to detected technologies.
              </p>
            </div>
          </div>
          <AttackSurfaceGraph
            assets={assets}
            dnsRecords={dnsRecords}
            endpoints={endpoints}
            services={services}
          />
        </div>
      )}

      {/* TAB 3: ASSET INVENTORY */}
      {activeTab === 'assets' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter assets by name..."
                  value={assetSearch}
                  onChange={(e) => setAssetSearch(e.target.value)}
                  className="pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-56"
                />
              </div>

              <select
                value={assetTypeFilter}
                onChange={(e) => setAssetTypeFilter(e.target.value)}
                className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-xl text-slate-300 focus:outline-none"
              >
                <option value="all">All Asset Types</option>
                <option value="root_domain">Root Domain</option>
                <option value="subdomain">Subdomain</option>
                <option value="ip_address">IP Address</option>
                <option value="endpoint">Web Endpoint</option>
                <option value="service">Network Service</option>
                <option value="technology">Technology</option>
              </select>
            </div>

            <button
              onClick={() => exportCsv('assets')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" /> Export CSV
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Canonical Identifier</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Discovery Tool</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">First Seen</th>
                  <th className="px-4 py-3">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
                {assets
                  .filter((a) => {
                    if (assetTypeFilter !== 'all' && a.assetType !== assetTypeFilter) return false;
                    if (assetSearch && !a.canonicalName.toLowerCase().includes(assetSearch.toLowerCase())) {
                      return false;
                    }
                    return true;
                  })
                  .map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 text-white font-medium break-all">{a.canonicalName}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 border border-slate-700">
                          {a.assetType}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400">{a.discoverySource}</td>
                      <td className="px-4 py-3 text-emerald-400 capitalize">{a.status}</td>
                      <td className="px-4 py-3 text-slate-500 text-[11px]">{new Date(a.firstSeen).toLocaleDateString()}</td>
                      <td className="px-4 py-3 text-slate-500 text-[11px]">{new Date(a.lastSeen).toLocaleDateString()}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: DNS EXPLORER */}
      {activeTab === 'dns' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filter hostname or answer..."
                value={dnsSearch}
                onChange={(e) => setDnsSearch(e.target.value)}
                className="pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-56"
              />
            </div>
            <button
              onClick={() => exportCsv('dns')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" /> Export CSV
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Hostname</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Answer / Value</th>
                  <th className="px-4 py-3">TTL</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {dnsRecords
                  .filter((d) => {
                    if (
                      dnsSearch &&
                      !d.hostname.toLowerCase().includes(dnsSearch.toLowerCase()) &&
                      !d.value.toLowerCase().includes(dnsSearch.toLowerCase())
                    ) {
                      return false;
                    }
                    return true;
                  })
                  .map((d) => (
                    <tr key={d.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 text-cyan-300">{d.hostname}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-blue-500/15 text-blue-300 font-bold border border-blue-500/30">
                          {d.recordType}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-white break-all">{d.value}</td>
                      <td className="px-4 py-3 text-slate-400">{d.ttl || 300}s</td>
                      <td className="px-4 py-3 text-slate-400">{d.source}</td>
                      <td className="px-4 py-3 text-slate-500 text-[11px]">{new Date(d.timestamp).toLocaleTimeString()}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 5: WEB ENDPOINTS */}
      {activeTab === 'endpoints' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Discovered HTTP/HTTPS Endpoints</h3>
            <button
              onClick={() => exportCsv('endpoints')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" /> Export CSV
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Target URL</th>
                  <th className="px-4 py-3">HTTP Status</th>
                  <th className="px-4 py-3">Page Title</th>
                  <th className="px-4 py-3">Resolved IP</th>
                  <th className="px-4 py-3">Detected Technologies</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {endpoints.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 text-cyan-300 font-semibold">{e.url}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          e.statusCode === 200
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : e.statusCode === 301 || e.statusCode === 302
                            ? 'bg-blue-500/20 text-blue-300'
                            : 'bg-amber-500/20 text-amber-300'
                        }`}
                      >
                        {e.statusCode}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-white font-sans">{e.title}</td>
                    <td className="px-4 py-3 text-slate-400">{e.ip}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {e.technologies?.map((t, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 6: NETWORK SERVICES (NMAP) */}
      {activeTab === 'services' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">Controlled Network Port &amp; Service Discovery (Nmap)</h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Ports probed according to authorized port profile. Open ports are observed facts, not confirmed exploits.
              </p>
            </div>
            <button
              onClick={() => exportCsv('services')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" /> Export CSV
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">Port</th>
                  <th className="px-4 py-3">Protocol</th>
                  <th className="px-4 py-3">State</th>
                  <th className="px-4 py-3">Service Name</th>
                  <th className="px-4 py-3">Product / Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {services.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 text-cyan-300">{s.host}</td>
                    <td className="px-4 py-3 text-slate-400">{s.ip}</td>
                    <td className="px-4 py-3 text-white font-bold">{s.port}</td>
                    <td className="px-4 py-3 uppercase text-slate-400">{s.protocol}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          s.state === 'open'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : s.state === 'filtered'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            : 'bg-slate-800 text-slate-500'
                        }`}
                      >
                        {s.state}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-blue-300 font-semibold">{s.serviceName}</td>
                    <td className="px-4 py-3 text-slate-300">{s.version || 'Version probe concealed'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 7: TECHNOLOGIES (WHATWEB) */}
      {activeTab === 'technologies' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div>
            <h3 className="text-base font-semibold text-white">Observable Website Technologies (WhatWeb)</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Passive and active web technology identification. Evidence extracted from headers and HTML signatures.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {assets
              .filter((a) => a.assetType === 'technology')
              .map((t) => (
                <div key={t.id} className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-sm text-cyan-400">{t.canonicalName}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      {t.metadata?.category || 'Framework'}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Confidence:</span>
                      <span className="text-emerald-400 capitalize">{t.metadata?.confidence || 'Firm'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Source:</span>
                      <span className="text-slate-300 font-mono">WhatWeb v0.5.5</span>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* TAB 8: FINDINGS & RISKS */}
      {activeTab === 'findings' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">Centralized Observations &amp; Risk Findings</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Facts vs potential risks. Transparent evidence, subdomain correlation, and remediation guides.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
                <button
                  onClick={() => setFindingsViewMode('list')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-medium transition-all ${
                    findingsViewMode === 'list'
                      ? 'bg-blue-600/30 text-cyan-300 font-semibold border border-blue-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <List className="w-3.5 h-3.5" /> List View
                </button>
                <button
                  onClick={() => setFindingsViewMode('heatmap')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-medium transition-all ${
                    findingsViewMode === 'heatmap'
                      ? 'bg-rose-600/30 text-rose-300 font-semibold border border-rose-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Flame className="w-3.5 h-3.5 text-rose-500" /> Subdomain Heatmap
                </button>
              </div>

              {findingsViewMode === 'list' && (
                <select
                  value={findingSeverityFilter}
                  onChange={(e) => setFindingSeverityFilter(e.target.value)}
                  className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-xl text-slate-300 focus:outline-none"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="informational">Informational</option>
                </select>
              )}
            </div>
          </div>

          {findingsViewMode === 'heatmap' ? (
            <SubdomainFindingsHeatmap
              assessment={assessment}
              findings={findings}
              assets={assets}
              onSelectFinding={(f) => {
                setFindingSeverityFilter(f.severity);
                setFindingsViewMode('list');
              }}
            />
          ) : (
            <div className="space-y-4">
              {findings
                .filter((f) => findingSeverityFilter === 'all' || f.severity === findingSeverityFilter)
                .map((f) => (
                  <div key={f.id} className="p-5 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className={`text-[10px] px-2.5 py-0.5 rounded font-mono font-bold uppercase border ${getSeverityBadge(
                              f.severity
                            )}`}
                          >
                            {f.severity}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                            {f.verificationStatus.replace('_', ' ')}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            Source: {f.sourceTool}
                          </span>
                        </div>
                        <h4 className="text-sm font-semibold text-white">{f.title}</h4>
                      </div>

                      <div className="text-xs font-mono text-cyan-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                        Asset: {f.assetRef}
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

                    <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800/80 space-y-2 text-xs">
                      <div>
                        <span className="text-[11px] font-semibold text-slate-400 block uppercase font-mono">
                          Evidence:
                        </span>
                        <p className="text-slate-300 font-mono text-[11px] mt-0.5">{f.evidence}</p>
                      </div>

                      <div className="pt-2 border-t border-slate-800">
                        <span className="text-[11px] font-semibold text-emerald-400 block uppercase font-mono">
                          Remediation &amp; Next Steps:
                        </span>
                        <p className="text-slate-300 text-[11px] mt-0.5">{f.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 9: TOOL LOGS */}
      {activeTab === 'logs' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-white">Scanner Tool Execution Logs</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Standard output, standard error, duration, and process return codes from adapter runs.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-1 space-y-2">
              {scanJobs.map((j) => (
                <button
                  key={j.id}
                  onClick={() => setSelectedLogJob(j)}
                  className={`w-full text-left p-3 rounded-xl border text-xs transition-all ${
                    (selectedLogJob?.id || scanJobs[0]?.id) === j.id
                      ? 'bg-blue-600/15 border-blue-500 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">{j.toolName}</span>
                    <span className="font-mono text-[10px] text-emerald-400">RC: {j.returnCode}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">
                    Duration: {j.durationMs}ms • {j.logs.length} lines
                  </div>
                </button>
              ))}
            </div>

            <div className="md:col-span-3 bg-slate-950 rounded-xl border border-slate-800 p-4 font-mono text-[11px] text-slate-300 max-h-[500px] overflow-y-auto">
              <div className="text-slate-500 pb-2 mb-2 border-b border-slate-800 flex justify-between">
                <span>
                  STREAM: {selectedLogJob?.toolName || scanJobs[0]?.toolName || 'Waiting'} (STDOUT / STDERR)
                </span>
                <span>STATUS: {selectedLogJob?.status || scanJobs[0]?.status}</span>
              </div>
              <div className="space-y-1">
                {(selectedLogJob?.logs || scanJobs[0]?.logs || ['No tool logs recorded yet.']).map((line, i) => (
                  <div
                    key={i}
                    className={`leading-relaxed ${
                      line.includes('[ERROR]')
                        ? 'text-rose-400'
                        : line.includes('[SUCCESS]')
                        ? 'text-emerald-400'
                        : line.includes('[CMD]')
                        ? 'text-cyan-400 font-bold'
                        : line.includes('[WARN]')
                        ? 'text-amber-400'
                        : 'text-slate-300'
                    }`}
                  >
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 10: REPORTS & EXPORT */}
      {activeTab === 'reports' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-base font-semibold text-white">Reconnaissance Assessment Report</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Executive summary, scope documentation, asset inventory, and prioritized observations.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleDownloadSummaryPdf}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-blue-600/20 cursor-pointer"
                title="Download formatted executive PDF report"
              >
                <FileDown className="w-4 h-4" /> Download Summary PDF
              </button>
              <button
                onClick={() => window.print()}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
              >
                <Printer className="w-4 h-4 text-cyan-400" /> Print Preview
              </button>
              <button
                onClick={exportFullJson}
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700"
              >
                <Download className="w-4 h-4 text-cyan-400" /> Export JSON
              </button>
            </div>
          </div>

          {/* Printable Report Document Body */}
          <div className="bg-slate-950 p-8 rounded-2xl border border-slate-800 text-slate-200 space-y-6 font-sans">
            <div className="border-b border-slate-800 pb-6 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-bold tracking-wider uppercase mb-1">
                  RECONX SECURITY ASSESSMENT REPORT
                </div>
                <h2 className="text-2xl font-bold text-white">{assessment.name}</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Target Domain: <span className="font-mono text-slate-200">{assessment.scope.rootDomain}</span> • Client:{' '}
                  {assessment.clientName}
                </p>
              </div>
              <div className="text-right text-xs text-slate-400 font-mono">
                <div>Report Date: {new Date().toLocaleDateString()}</div>
                <div>ID: {assessment.id}</div>
                <div>Auditor: {assessment.ownerEmail}</div>
              </div>
            </div>

            {/* Executive Summary Section */}
            <div className="space-y-2">
              <h4 className="text-sm font-semibold text-white uppercase tracking-wider font-mono text-cyan-300">
                1. Executive Summary
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                An authorized external attack surface mapping and reconnaissance evaluation was conducted against{' '}
                <strong className="text-white">{assessment.scope.rootDomain}</strong>. The assessment discovered{' '}
                <strong className="text-cyan-400 font-mono">{assets.length}</strong> canonical infrastructure assets, including{' '}
                <strong className="text-cyan-400 font-mono">{assets.filter((a) => a.assetType === 'subdomain').length}</strong>{' '}
                subdomains, <strong className="text-cyan-400 font-mono">{endpoints.length}</strong> active web endpoints, and{' '}
                <strong className="text-cyan-400 font-mono">{services.length}</strong> observable network services. A total of{' '}
                <strong className="text-amber-400 font-mono">{findings.length}</strong> observations and risk exposures were
                cataloged.
              </p>
            </div>

            {/* Scope & Authorization */}
            <div className="space-y-2">
              <h4 className="text-sm font-semibold text-white uppercase tracking-wider font-mono text-cyan-300">
                2. Scope &amp; Legal Authorization
              </h4>
              <div className="p-3 bg-slate-900 rounded-lg text-xs font-mono space-y-1">
                <div>Root Domain: {assessment.scope.rootDomain}</div>
                <div>Permitted Ports: {assessment.scope.permittedPorts.join(', ')}</div>
                <div>ROE Reference: {assessment.scope.authReference || 'Internal Ethical Hacking Coursework Lab'}</div>
                <div>Authorization Certified: TRUE</div>
              </div>
            </div>

            {/* Discovered Inventory Summary */}
            <div className="space-y-2">
              <h4 className="text-sm font-semibold text-white uppercase tracking-wider font-mono text-cyan-300">
                3. Asset Inventory Breakdown
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">SUBDOMAINS</span>
                  <span className="text-base font-bold text-white">
                    {assets.filter((a) => a.assetType === 'subdomain').length}
                  </span>
                </div>
                <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">DNS RECORDS</span>
                  <span className="text-base font-bold text-white">{dnsRecords.length}</span>
                </div>
                <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">WEB ENDPOINTS</span>
                  <span className="text-base font-bold text-white">{endpoints.length}</span>
                </div>
                <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">SERVICES / PORTS</span>
                  <span className="text-base font-bold text-white">{services.length}</span>
                </div>
              </div>
            </div>

            {/* Key Observations */}
            <div className="space-y-2">
              <h4 className="text-sm font-semibold text-white uppercase tracking-wider font-mono text-cyan-300">
                4. Key Reconnaissance Observations &amp; Next Steps
              </h4>
              <div className="space-y-2">
                {findings.map((f, idx) => (
                  <div key={idx} className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-white">{f.title}</span>
                      <span className="font-mono text-[10px] text-amber-400 uppercase">[{f.severity}]</span>
                    </div>
                    <p className="text-slate-400 text-[11px] mb-2">{f.description}</p>
                    <div className="text-[11px] text-emerald-400">
                      <strong>Remediation:</strong> {f.remediation}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Methodological Limitations */}
            <div className="space-y-2 border-t border-slate-800 pt-4 text-xs text-slate-400">
              <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono">
                5. Assessment Limitations &amp; Exclusions
              </h4>
              <p className="text-[11px] leading-relaxed">
                This reconnaissance mapping report represents passive and active observations collected at the time of execution. Passive sources reflect public data feeds and Certificate Transparency logs which may omit unindexed hosts. The absence of findings does not guarantee immunity from vulnerability. Destructive exploitation and automated attacks were strictly excluded.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 11: SCOPE & ROE */}
      {activeTab === 'scope' && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div>
            <h3 className="text-base font-semibold text-white">Rules of Engagement &amp; Authorized Scope Boundary</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Legal agreement parameters governing this reconnaissance assessment.
            </p>
          </div>

          <div className="bg-slate-950 rounded-xl border border-slate-800 p-5 space-y-3 text-xs">
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-500">Authorized Root Domain:</span>
              <span className="font-mono text-cyan-300 font-semibold">{assessment.scope.rootDomain}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-500">Permitted Ports:</span>
              <span className="font-mono text-slate-200">{assessment.scope.permittedPorts.join(', ')}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-500">Engagement Window:</span>
              <span className="font-mono text-slate-200">
                {assessment.scope.startDate} through {assessment.scope.endDate}
              </span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-500">ROE Reference Code:</span>
              <span className="font-mono text-slate-200">
                {assessment.scope.authReference || 'ROE-2026-INTERNAL-LAB'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Authorized Operator:</span>
              <span className="font-mono text-slate-200">{assessment.scope.authorizedBy || assessment.ownerEmail}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
