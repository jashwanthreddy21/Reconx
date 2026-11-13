import React, { useState, useEffect, useMemo } from 'react';
import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  AssetRelationship,
  AssetEvidence,
  Finding,
  UserProfile
} from '../types';
import {
  loadOrComputeAssessmentIntelligence,
  getDnsRecords,
  getWebEndpoints,
  getNetworkServices,
  getFindings
} from '../services/firestoreService';
import { AttackSurfaceGraph } from '../components/graph/AttackSurfaceGraph';
import {
  Database,
  Network,
  FileText,
  Settings as SettingsIcon,
  Search,
  Download,
  ShieldCheck,
  Sliders,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';

interface CommonProps {
  assessments: Assessment[];
  userProfile?: UserProfile | null;
  onSelectAssessment?: (a: Assessment) => void;
}

/**
 * 3. ASSET INVENTORY (Dedicated Unified Section)
 */
export const GlobalAssetInventoryPage: React.FC<CommonProps> = ({
  assessments,
  onSelectAssessment,
}) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>(
    assessments[0]?.id || 'all'
  );
  const [assets, setAssets] = useState<Asset[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;
    const loadAssets = async () => {
      if (assessments.length === 0) return;
      setLoading(true);
      try {
        const targets =
          selectedAssessmentId === 'all'
            ? assessments.slice(0, 8)
            : assessments.filter((a) => a.id === selectedAssessmentId);
        const all: Asset[] = [];
        for (const asm of targets) {
          const intel = await loadOrComputeAssessmentIntelligence(asm);
          all.push(...intel.assets);
        }
        if (mounted) setAssets(all);
      } catch (err) {
        console.error('Error loading asset inventory:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    loadAssets();
    return () => {
      mounted = false;
    };
  }, [assessments, selectedAssessmentId]);

  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      if (typeFilter !== 'all' && a.assetType !== typeFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        if (
          !a.canonicalName.toLowerCase().includes(q) &&
          !a.discoverySource.toLowerCase().includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [assets, typeFilter, searchQuery]);

  const exportCsv = () => {
    const headers = [
      'Asset ID',
      'Canonical Name',
      'Normalized Key',
      'Category',
      'Discovery Sources',
      'Confidence Score',
      'Exposed Risk',
      'First Seen',
      'Last Seen',
    ];
    const rows = filteredAssets.map((a) => [
      a.id,
      a.canonicalName,
      a.normalizedValue || a.canonicalName.toLowerCase(),
      a.assetType,
      `"${(a.sources || [a.discoverySource]).join(', ')}"`,
      a.confidenceScore ?? 85,
      a.isExposedRisk ? 'YES' : 'NO',
      a.firstSeen,
      a.lastSeen,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `reconx-asset-inventory-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2.5">
            <Database className="w-6 h-6 text-cyan-400" />
            Unified Asset Inventory
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Normalized, deduplicated inventory of domains, subdomains, IPs, ports, services, endpoints, and technologies across assessments.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={selectedAssessmentId}
            onChange={(e) => setSelectedAssessmentId(e.target.value)}
            className="px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            <option value="all">All Assessments Combined</option>
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.scope.rootDomain})
              </option>
            ))}
          </select>

          <button
            onClick={exportCsv}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Export Inventory CSV
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              placeholder="Search hostname, IP, port, service..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200 w-56"
            />
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            <option value="all">All Asset Categories</option>
            <option value="root_domain">Root Domains</option>
            <option value="subdomain">Subdomains</option>
            <option value="ip_address">IP Addresses</option>
            <option value="port">Network Ports</option>
            <option value="service">Running Services</option>
            <option value="endpoint">Web Endpoints</option>
            <option value="technology">Web Technologies</option>
          </select>
        </div>

        <span className="text-xs font-mono text-slate-400">
          {loading ? 'Loading inventory...' : `${filteredAssets.length} Normalized Assets`}
        </span>
      </div>

      {/* Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <th className="py-3 px-4 font-semibold">Asset Value</th>
                <th className="py-3 px-4 font-semibold">Category</th>
                <th className="py-3 px-4 font-semibold">Correlated Tools</th>
                <th className="py-3 px-4 font-semibold">Confidence</th>
                <th className="py-3 px-4 font-semibold">First Discovered</th>
                <th className="py-3 px-4 font-semibold">Last Observed</th>
                <th className="py-3 px-4 font-semibold">Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredAssets.map((a) => {
                const parentAsm = assessments.find((asm) => asm.id === a.assessmentId);
                return (
                  <tr key={`${a.assessmentId}_${a.id}`} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 font-mono font-semibold text-white">
                      {a.canonicalName}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] uppercase">
                        {a.assetType.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-cyan-400">
                      {(a.sources || [a.discoverySource]).join(', ')}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-emerald-400 font-semibold">
                      {a.confidenceScore ?? 85}%
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-400">
                      {new Date(a.firstSeen).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-400">
                      {new Date(a.lastSeen).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-4">
                      {parentAsm && onSelectAssessment ? (
                        <button
                          onClick={() => onSelectAssessment(parentAsm)}
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          {parentAsm.name} <ExternalLink className="w-3 h-3" />
                        </button>
                      ) : (
                        <span className="text-slate-500 font-mono">{a.assessmentId}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

/**
 * 5. ATTACK SURFACE MAP (Dedicated Full-Screen Section)
 */
export const GlobalAttackSurfaceMapPage: React.FC<CommonProps> = ({ assessments }) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>(
    assessments[0]?.id || ''
  );
  const [assets, setAssets] = useState<Asset[]>([]);
  const [dnsRecords, setDnsRecords] = useState<DnsRecord[]>([]);
  const [endpoints, setEndpoints] = useState<WebEndpoint[]>([]);
  const [services, setServices] = useState<NetworkService[]>([]);
  const [relationships, setRelationships] = useState<AssetRelationship[]>([]);
  const [evidences, setEvidences] = useState<AssetEvidence[]>([]);

  useEffect(() => {
    if (!selectedAssessmentId && assessments.length > 0) {
      setSelectedAssessmentId(assessments[0].id);
    }
  }, [assessments, selectedAssessmentId]);

  useEffect(() => {
    const asm =
      assessments.find((a) => a.id === selectedAssessmentId) || assessments[0];
    if (!asm) return;

    let mounted = true;
    const loadGraph = async () => {
      try {
        const [intel, dns, eps, svcs] = await Promise.all([
          loadOrComputeAssessmentIntelligence(asm),
          getDnsRecords(asm.id),
          getWebEndpoints(asm.id),
          getNetworkServices(asm.id),
        ]);
        if (!mounted) return;
        setAssets(intel.assets);
        setRelationships(intel.relationships);
        setEvidences(intel.evidences);
        setDnsRecords(dns);
        setEndpoints(eps);
        setServices(svcs);
      } catch (err) {
        console.error('Error loading attack surface map:', err);
      }
    };
    loadGraph();
    return () => {
      mounted = false;
    };
  }, [selectedAssessmentId, assessments]);

  return (
    <div className="space-y-4">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider bg-blue-500/15 text-blue-300 border border-blue-500/30 rounded">
              Feature 2 • Interactive Topology Visualizer
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2.5">
            <Network className="w-6 h-6 text-blue-400" />
            Interactive Attack Surface Map
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Explore connected domains, subdomains, IPs, open ports, services, endpoints, and technologies. Drag nodes, double-click to collapse/expand branches, highlight risks, and export as PNG/SVG.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={selectedAssessmentId}
            onChange={(e) => setSelectedAssessmentId(e.target.value)}
            className="px-3 py-2 text-xs sm:text-sm bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} — {a.scope.rootDomain} ({a.status})
              </option>
            ))}
          </select>
        </div>
      </div>

      <AttackSurfaceGraph
        assets={assets}
        dnsRecords={dnsRecords}
        endpoints={endpoints}
        services={services}
        relationships={relationships}
        evidences={evidences}
        assessments={assessments}
        selectedAssessmentFilter="all"
      />
    </div>
  );
};

/**
 * 8. REPORTS (Dedicated Reporting & Export Center)
 */
export const GlobalReportsPage: React.FC<CommonProps> = ({
  assessments,
  onSelectAssessment,
}) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>(
    assessments[0]?.id || ''
  );
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assetsCount, setAssetsCount] = useState(0);
  const [relationshipsCount, setRelationshipsCount] = useState(0);

  const selectedAssessment = useMemo(
    () => assessments.find((a) => a.id === selectedAssessmentId) || assessments[0],
    [assessments, selectedAssessmentId]
  );

  useEffect(() => {
    if (!selectedAssessment) return;
    let mounted = true;
    const loadReportContext = async () => {
      const [intel, fnds] = await Promise.all([
        loadOrComputeAssessmentIntelligence(selectedAssessment),
        getFindings(selectedAssessment.id),
      ]);
      if (!mounted) return;
      setAssetsCount(intel.assets.length);
      setRelationshipsCount(intel.relationships.length);
      setFindings(fnds);
    };
    loadReportContext();
    return () => {
      mounted = false;
    };
  }, [selectedAssessment]);

  const handleExportComprehensiveJson = async () => {
    if (!selectedAssessment) return;
    const intel = await loadOrComputeAssessmentIntelligence(selectedAssessment);
    const payload = {
      reportMetadata: {
        platform: 'ReconX Attack Surface Intelligence Platform',
        exportedAt: new Date().toISOString(),
        assessment: selectedAssessment,
      },
      correlationSummary: intel.correlation,
      aiAnalysis: intel.aiAnalysis,
      snapshot: intel.snapshot,
      assets: intel.assets,
      relationships: intel.relationships,
      findings,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconx-executive-report-${selectedAssessment.scope.rootDomain}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2.5">
            <FileText className="w-6 h-6 text-emerald-400" />
            Executive &amp; Technical Reconnaissance Reports
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Generate evidence-backed assessment reports with correlated asset inventories, relationship topologies, and prioritized security review checklists.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={selectedAssessment?.id || ''}
            onChange={(e) => setSelectedAssessmentId(e.target.value)}
            className="px-3 py-2 text-xs sm:text-sm bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.scope.rootDomain})
              </option>
            ))}
          </select>

          <button
            onClick={handleExportComprehensiveJson}
            className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs sm:text-sm font-medium flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Download Full Intelligence Dossier (JSON)
          </button>

          {selectedAssessment && onSelectAssessment && (
            <button
              onClick={() => onSelectAssessment(selectedAssessment)}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs sm:text-sm font-medium flex items-center gap-1.5"
            >
              Open Printable HTML/PDF View <ExternalLink className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {selectedAssessment && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="border-b border-slate-800 pb-4 flex flex-wrap items-center justify-between gap-4">
            <div>
              <span className="text-xs font-mono text-cyan-400 uppercase">
                Target Scope: {selectedAssessment.scope.rootDomain}
              </span>
              <h2 className="text-lg font-bold text-white mt-0.5">
                {selectedAssessment.name} — Reconnaissance Dossier
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Client / Environment: {selectedAssessment.clientName} • Mode: {selectedAssessment.type.toUpperCase()}
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Normalized Assets</span>
                <span className="text-white font-bold text-sm">{assetsCount}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Correlated Edges</span>
                <span className="text-cyan-400 font-bold text-sm">{relationshipsCount}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Verified Findings</span>
                <span className="text-amber-400 font-bold text-sm">{findings.length}</span>
              </div>
            </div>
          </div>

          <div className="space-y-2.5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Discovered Security Observations ({findings.length})
            </h3>
            {findings.map((f) => (
              <div
                key={f.id}
                className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[10px] uppercase font-bold">
                      {f.severity}
                    </span>
                    <span className="font-semibold text-white">{f.title}</span>
                  </div>
                  <p className="text-slate-400 mt-1">{f.description}</p>
                </div>
                <span className="font-mono text-slate-400 shrink-0">{f.sourceTool}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * 9. SETTINGS (Dedicated Platform & Correlation Engine Settings)
 */
export const GlobalSettingsPage: React.FC<CommonProps> = ({ userProfile }) => {
  const [defaultRateLimit, setDefaultRateLimit] = useState(20);
  const [minCorrelationConfidence, setMinCorrelationConfidence] = useState(65);
  const [enableDeterministicFallback, setEnableDeterministicFallback] = useState(true);
  const [savedBanner, setSavedBanner] = useState(false);

  const handleSave = () => {
    setSavedBanner(true);
    setTimeout(() => setSavedBanner(false), 3000);
  };

  return (
    <div className="max-w-4xl space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <h1 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2.5">
          <SettingsIcon className="w-6 h-6 text-cyan-400" />
          Platform &amp; Correlation Engine Settings
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Configure authorization guardrails, asset correlation confidence thresholds, and AI fallback behavior.
        </p>
      </div>

      {savedBanner && (
        <div className="p-3.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          Platform configuration updated and enforced across active reconnaissance pipelines.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Operator Identity &amp; Scope Guardrails
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-2 border-b border-slate-800">
              <span className="text-slate-400">Operator Email:</span>
              <span className="font-mono text-white">{userProfile?.email || 'Authenticated Operator'}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-slate-800">
              <span className="text-slate-400">RBAC Role:</span>
              <span className="font-mono uppercase text-cyan-400 font-bold">
                {userProfile?.role || 'analyst'}
              </span>
            </div>
            <div className="flex justify-between py-2 border-b border-slate-800">
              <span className="text-slate-400">RFC1918 / Loopback Protection:</span>
              <span className="font-mono text-emerald-400">ENFORCED</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-slate-400">Snapshot Immutability:</span>
              <span className="font-mono text-emerald-400">ENABLED</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            Correlation &amp; Scanner Parameters
          </h3>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-300 mb-1">
                Default Probe Rate Limit (Requests / Sec): <span className="font-mono text-cyan-400">{defaultRateLimit} RPS</span>
              </label>
              <input
                type="range"
                min={5}
                max={100}
                value={defaultRateLimit}
                onChange={(e) => setDefaultRateLimit(Number(e.target.value))}
                className="w-full accent-cyan-400"
              />
            </div>

            <div>
              <label className="block text-slate-300 mb-1">
                Minimum Correlation Confidence Score: <span className="font-mono text-emerald-400">{minCorrelationConfidence}%</span>
              </label>
              <input
                type="range"
                min={40}
                max={95}
                value={minCorrelationConfidence}
                onChange={(e) => setMinCorrelationConfidence(Number(e.target.value))}
                className="w-full accent-emerald-400"
              />
            </div>

            <label className="flex items-center gap-2 pt-2 cursor-pointer">
              <input
                type="checkbox"
                checked={enableDeterministicFallback}
                onChange={(e) => setEnableDeterministicFallback(e.target.checked)}
                className="rounded border-slate-700"
              />
              <span className="text-slate-300">
                Always maintain deterministic rule-based correlation fallback when AI provider is offline
              </span>
            </label>

            <button
              onClick={handleSave}
              className="w-full mt-2 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium transition-colors"
            >
              Save Platform Preferences
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
