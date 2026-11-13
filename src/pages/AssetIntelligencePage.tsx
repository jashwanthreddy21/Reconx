import React, { useState, useEffect, useMemo } from 'react';
import {
  Assessment,
  Asset,
  AssetRelationship,
  AssetEvidence,
  AssetCorrelation,
  AIAnalysis,
  AssetType
} from '../types';
import {
  loadOrComputeAssessmentIntelligence,
  saveAIAnalysis
} from '../services/firestoreService';
import { generateDeterministicAIAnalysis } from '../services/assetCorrelationEngine';
import {
  Brain,
  Network,
  Globe,
  Server,
  ShieldAlert,
  Cpu,
  Layers,
  Filter,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Lock,
  ExternalLink
} from 'lucide-react';

interface Props {
  assessments: Assessment[];
  initialAssessmentId?: string;
  onSelectAssessment?: (assessment: Assessment) => void;
}

export const AssetIntelligencePage: React.FC<Props> = ({
  assessments,
  initialAssessmentId,
  onSelectAssessment,
}) => {
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>(
    initialAssessmentId || assessments[0]?.id || ''
  );
  const [loading, setLoading] = useState(false);
  const [aiGenerating, setAiGenerating] = useState(false);

  // Correlated data state
  const [assets, setAssets] = useState<Asset[]>([]);
  const [relationships, setRelationships] = useState<AssetRelationship[]>([]);
  const [evidences, setEvidences] = useState<AssetEvidence[]>([]);
  const [correlation, setCorrelation] = useState<AssetCorrelation | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);

  // Filters required by Feature 1
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sourceToolFilter, setSourceToolFilter] = useState<string>('all');
  const [minConfidence, setMinConfidence] = useState<number>(50);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [activeSubTab, setActiveSubTab] = useState<'relationships' | 'assets' | 'anomalies'>('relationships');

  const currentAssessment = useMemo(
    () => assessments.find((a) => a.id === selectedAssessmentId) || assessments[0] || null,
    [assessments, selectedAssessmentId]
  );

  useEffect(() => {
    if (!selectedAssessmentId && assessments.length > 0) {
      setSelectedAssessmentId(assessments[0].id);
    }
  }, [assessments, selectedAssessmentId]);

  useEffect(() => {
    if (!currentAssessment) return;
    let mounted = true;
    const loadData = async () => {
      setLoading(true);
      try {
        const intel = await loadOrComputeAssessmentIntelligence(currentAssessment);
        if (!mounted) return;
        setAssets(intel.assets);
        setRelationships(intel.relationships);
        setEvidences(intel.evidences);
        setCorrelation(intel.correlation);
        setAiAnalysis(intel.aiAnalysis);
      } catch (err) {
        console.error('Failed to load asset intelligence:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    loadData();
    return () => {
      mounted = false;
    };
  }, [currentAssessment]);

  const handleRunLiveAIAnalysis = async () => {
    if (!currentAssessment || !correlation) return;
    setAiGenerating(true);
    try {
      const response = await fetch('/api/ai/analyze-assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          assessment: currentAssessment,
          assets: assets.slice(0, 80),
          relationships: relationships.slice(0, 100),
          correlation,
        }),
      });
      if (response.ok) {
        const result: AIAnalysis = await response.json();
        setAiAnalysis(result);
        try {
          await saveAIAnalysis(currentAssessment.id, result);
        } catch {
          // Ignore storage error if offline
        }
      } else {
        const fallback = generateDeterministicAIAnalysis(
          currentAssessment,
          assets,
          relationships,
          correlation
        );
        setAiAnalysis(fallback);
      }
    } catch {
      const fallback = generateDeterministicAIAnalysis(
        currentAssessment,
        assets,
        relationships,
        correlation
      );
      setAiAnalysis(fallback);
    } finally {
      setAiGenerating(false);
    }
  };

  // Filtered assets
  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      if (assetTypeFilter !== 'all' && a.assetType !== assetTypeFilter) return false;
      if (severityFilter === 'exposed' && !a.isExposedRisk) return false;
      if (severityFilter === 'standard' && a.isExposedRisk) return false;
      if (sourceToolFilter !== 'all') {
        const tools = (a.sources || [a.discoverySource]).join(' ').toLowerCase();
        if (!tools.includes(sourceToolFilter.toLowerCase())) return false;
      }
      if ((a.confidenceScore ?? 85) < minConfidence) return false;
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        if (
          !a.canonicalName.toLowerCase().includes(q) &&
          !a.discoverySource.toLowerCase().includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [assets, assetTypeFilter, severityFilter, sourceToolFilter, minConfidence, searchTerm]);

  // Filtered relationships
  const filteredRelationships = useMemo(() => {
    return relationships.filter((r) => {
      if (assetTypeFilter !== 'all') {
        if (r.sourceType !== assetTypeFilter && r.targetType !== assetTypeFilter) return false;
      }
      if (severityFilter === 'exposed' && !r.isSuspicious) return false;
      if (sourceToolFilter !== 'all') {
        if (!r.sourceTool.toLowerCase().includes(sourceToolFilter.toLowerCase())) return false;
      }
      if (r.confidenceScore < minConfidence) return false;
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        if (
          !(r.sourceName || '').toLowerCase().includes(q) &&
          !(r.targetName || '').toLowerCase().includes(q) &&
          !r.relationshipType.toLowerCase().includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [relationships, assetTypeFilter, severityFilter, sourceToolFilter, minConfidence, searchTerm]);

  // KPI metrics calculated from actual correlated data
  const metrics = useMemo(() => {
    if (correlation) {
      return {
        totalAssets: correlation.totalAssets,
        uniqueDomainsAndSubdomains:
          correlation.uniqueDomains + correlation.uniqueSubdomains,
        uniqueIps: correlation.uniqueIps,
        openPorts: correlation.openPortsCount,
        detectedServices: correlation.detectedServicesCount,
        detectedTechnologies: correlation.detectedTechnologiesCount,
        correlatedRelationships: correlation.correlatedRelationshipsCount,
        potentiallyExposedAssets: correlation.potentiallyExposedAssetsCount,
      };
    }
    return {
      totalAssets: assets.length,
      uniqueDomainsAndSubdomains: assets.filter(
        (a) => a.assetType === 'root_domain' || a.assetType === 'subdomain'
      ).length,
      uniqueIps: assets.filter((a) => a.assetType === 'ip_address').length,
      openPorts: assets.filter((a) => a.assetType === 'port').length,
      detectedServices: assets.filter((a) => a.assetType === 'service').length,
      detectedTechnologies: assets.filter((a) => a.assetType === 'technology').length,
      correlatedRelationships: relationships.length,
      potentiallyExposedAssets: assets.filter((a) => a.isExposedRisk).length,
    };
  }, [correlation, assets, relationships]);

  if (assessments.length === 0) {
    return (
      <div className="p-8 bg-slate-900/60 border border-slate-800 rounded-xl text-center">
        <Brain className="w-12 h-12 text-cyan-400 mx-auto mb-3 opacity-80" />
        <h3 className="text-lg font-semibold text-white mb-1">No Assessments Available</h3>
        <p className="text-sm text-slate-400">
          Run an authorized reconnaissance assessment first to correlate assets and generate intelligence.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Assessment Selector */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 rounded">
              Feature 1 • Multi-Scanner Correlation Engine
            </span>
            {aiAnalysis && (
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider bg-purple-500/15 text-purple-300 border border-purple-500/30 rounded">
                {aiAnalysis.provider === 'gemini_ai' ? 'Gemini AI Verified' : 'Deterministic Engine Active'}
              </span>
            )}
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2.5">
            <Brain className="w-6 h-6 text-cyan-400" />
            AI-Powered Asset Correlation & Intelligence
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Normalized entity deduplication, confidence-scored relationship graph, and automated exposure prioritization across Subfinder, Amass, dnsx, httpx, Nmap, and WhatWeb.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={selectedAssessmentId}
            onChange={(e) => setSelectedAssessmentId(e.target.value)}
            className="px-3 py-2 text-xs sm:text-sm bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} — {a.scope.rootDomain} ({a.status})
              </option>
            ))}
          </select>

          <button
            onClick={handleRunLiveAIAnalysis}
            disabled={aiGenerating || loading}
            className="px-3.5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white rounded-lg text-xs sm:text-sm font-medium flex items-center gap-2 shadow-lg shadow-cyan-950/50 transition-all"
          >
            {aiGenerating ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Sparkles className="w-4 h-4" />
            )}
            {aiGenerating ? 'Analyzing Attack Surface...' : 'Refresh AI Intelligence'}
          </button>

          {currentAssessment && onSelectAssessment && (
            <button
              onClick={() => onSelectAssessment(currentAssessment)}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs sm:text-sm font-medium flex items-center gap-1.5 border border-slate-700"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Workspace
            </button>
          )}
        </div>
      </div>

      {/* 8 KPI Cards Required by Feature 1 */}
      <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Total Assets</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-white font-mono">
            {metrics.totalAssets}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Normalized entities</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Domains / Subs</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-cyan-400 font-mono">
            {metrics.uniqueDomainsAndSubdomains}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Root + Subdomains</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Unique IPs</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-emerald-400 font-mono">
            {metrics.uniqueIps}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Resolved hosts</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Open Ports</span>
            <Lock className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-orange-400 font-mono">
            {metrics.openPorts}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Exposed TCP/UDP</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Services</span>
            <Cpu className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-amber-400 font-mono">
            {metrics.detectedServices}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Fingerprinted daemons</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Technologies</span>
            <Sparkles className="w-4 h-4 text-pink-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-pink-400 font-mono">
            {metrics.detectedTechnologies}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Web stacks</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Relationships</span>
            <Network className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-purple-400 font-mono">
            {metrics.correlatedRelationships}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Correlated edges</div>
        </div>

        <div className="bg-slate-900/80 border border-red-900/40 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-red-300 text-xs mb-1">
            <span>Exposed Assets</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold text-red-400 font-mono">
            {metrics.potentiallyExposedAssets}
          </div>
          <div className="text-[10px] text-red-400/70 mt-0.5">Priority review</div>
        </div>
      </div>

      {/* AI-Generated Intelligence Summary Section */}
      {aiAnalysis && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" />
                AI-Generated Attack Surface Intelligence Summary
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Evidence-backed synthesis — strictly derived from observed scan outputs without fabricated findings.
              </p>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Generated: {new Date(aiAnalysis.generatedAt).toLocaleString()}
            </span>
          </div>

          {/* Executive Summary */}
          <div className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800 text-xs sm:text-sm text-slate-200 leading-relaxed">
            {aiAnalysis.executiveSummary}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Discovered Relationship Insights */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/90">
              <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-2.5 flex items-center gap-1.5">
                <Network className="w-4 h-4" />
                Correlated Relationship Insights
              </h3>
              <ul className="space-y-2 text-xs text-slate-300">
                {aiAnalysis.relationshipInsights.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Unusual Exposure Patterns */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/90">
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2.5 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" />
                Unusual Exposure Patterns
              </h3>
              <ul className="space-y-2 text-xs text-slate-300">
                {aiAnalysis.unusualExposurePatterns.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0 mt-1.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Potentially Risky Configurations */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/90">
              <h3 className="text-xs font-bold uppercase tracking-wider text-red-400 mb-2.5 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                Potentially Risky Configurations
              </h3>
              <ul className="space-y-2 text-xs text-slate-300">
                {aiAnalysis.riskyConfigurations.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0 mt-1.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Prioritized Assets for Manual Security Review */}
          {aiAnalysis.prioritizedReviewList.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2.5">
                Prioritized Assets for Manual Security Review & Authorized Next Steps
              </h3>
              <div className="overflow-x-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-950 text-slate-400 border-b border-slate-800">
                      <th className="py-2.5 px-3 font-semibold">Priority</th>
                      <th className="py-2.5 px-3 font-semibold">Asset</th>
                      <th className="py-2.5 px-3 font-semibold">Category</th>
                      <th className="py-2.5 px-3 font-semibold">Exposure Rationale</th>
                      <th className="py-2.5 px-3 font-semibold">Safe Authorized Investigation Step</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {aiAnalysis.prioritizedReviewList.map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
                              item.priority === 'critical' || item.priority === 'high'
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {item.priority}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono font-semibold text-white">
                          {item.assetName}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400 uppercase">
                          {item.assetType.replace('_', ' ')}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">{item.reason}</td>
                        <td className="py-2.5 px-3 text-cyan-300 font-mono text-[11px]">
                          {item.safeInvestigationStep}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Filter Bar (Asset Type, Severity, Source Tool, Confidence Score, Search) */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 mr-1">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            Filters:
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <input
              type="text"
              placeholder="Search asset or relationship..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 w-44 sm:w-56"
            />
          </div>

          {/* Asset Type Filter */}
          <select
            value={assetTypeFilter}
            onChange={(e) => setAssetTypeFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            <option value="all">All Asset Types</option>
            <option value="root_domain">Root Domain</option>
            <option value="subdomain">Subdomain</option>
            <option value="ip_address">IP Address</option>
            <option value="port">Port</option>
            <option value="service">Service</option>
            <option value="endpoint">Web Endpoint</option>
            <option value="technology">Technology</option>
          </select>

          {/* Severity / Exposure Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            <option value="all">All Severity / Exposure</option>
            <option value="exposed">Exposed / Suspicious Risk Only</option>
            <option value="standard">Standard Observation Only</option>
          </select>

          {/* Source Tool Filter */}
          <select
            value={sourceToolFilter}
            onChange={(e) => setSourceToolFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            <option value="all">All Integrated Tools</option>
            <option value="Subfinder">Subfinder</option>
            <option value="Amass">Amass</option>
            <option value="dnsx">dnsx</option>
            <option value="httpx">httpx</option>
            <option value="Nmap">Nmap</option>
            <option value="WhatWeb">WhatWeb</option>
          </select>

          {/* Confidence Filter */}
          <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1">
            <span>Min Confidence:</span>
            <input
              type="range"
              min={0}
              max={95}
              step={5}
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="w-20 accent-cyan-400"
            />
            <span className="font-mono text-cyan-400 w-8">{minConfidence}%</span>
          </div>
        </div>

        {/* Sub-view switcher */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveSubTab('relationships')}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              activeSubTab === 'relationships'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Relationships ({filteredRelationships.length})
          </button>
          <button
            onClick={() => setActiveSubTab('assets')}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              activeSubTab === 'assets'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Normalized Assets ({filteredAssets.length})
          </button>
          <button
            onClick={() => setActiveSubTab('anomalies')}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              activeSubTab === 'anomalies'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Anomalies ({correlation?.anomalies.length || 0})
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {activeSubTab === 'relationships' && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <th className="py-3 px-4 font-semibold">Source Asset</th>
                  <th className="py-3 px-4 font-semibold">Relationship</th>
                  <th className="py-3 px-4 font-semibold">Target Asset</th>
                  <th className="py-3 px-4 font-semibold">Source Tool</th>
                  <th className="py-3 px-4 font-semibold">Confidence Score</th>
                  <th className="py-3 px-4 font-semibold">Preserved Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {filteredRelationships.map((rel) => (
                  <tr key={rel.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4">
                      <div className="font-mono font-semibold text-white">{rel.sourceName}</div>
                      <div className="text-[10px] font-mono uppercase text-slate-500">
                        {rel.sourceType?.replace('_', ' ')}
                      </div>
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[11px] font-semibold ${
                          rel.isSuspicious
                            ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                            : 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                        }`}
                      >
                        {rel.relationshipType}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <div className="font-mono font-semibold text-emerald-300">
                        {rel.targetName}
                      </div>
                      <div className="text-[10px] font-mono uppercase text-slate-500">
                        {rel.targetType?.replace('_', ' ')}
                      </div>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300">{rel.sourceTool}</td>
                    <td className="py-2.5 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-emerald-400 rounded-full"
                            style={{ width: `${rel.confidenceScore}%` }}
                          />
                        </div>
                        <span className="font-mono text-emerald-400 font-semibold">
                          {rel.confidenceScore}%
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                      {rel.evidenceSnippet}
                    </td>
                  </tr>
                ))}
                {filteredRelationships.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No correlated relationships match the current filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeSubTab === 'assets' && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <th className="py-3 px-4 font-semibold">Canonical Asset</th>
                  <th className="py-3 px-4 font-semibold">Normalized Key</th>
                  <th className="py-3 px-4 font-semibold">Category</th>
                  <th className="py-3 px-4 font-semibold">Correlated Tools</th>
                  <th className="py-3 px-4 font-semibold">Confidence</th>
                  <th className="py-3 px-4 font-semibold">Exposure Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 font-mono font-semibold text-white">
                      {asset.canonicalName}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-400">
                      {asset.normalizedValue || asset.canonicalName.toLowerCase()}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] uppercase">
                        {asset.assetType.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-cyan-400">
                      {(asset.sources || [asset.discoverySource]).join(', ')}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-emerald-400 font-semibold">
                      {asset.confidenceScore ?? 85}%
                    </td>
                    <td className="py-2.5 px-4">
                      {asset.isExposedRisk ? (
                        <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 text-[10px] font-semibold">
                          EXPOSED: {asset.riskReason || 'Review Required'}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px]">
                          Standard Observation
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeSubTab === 'anomalies' && (
        <div className="space-y-3">
          {(correlation?.anomalies || []).map((anom) => (
            <div
              key={anom.id}
              className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
                      anom.severity === 'high' || anom.severity === 'critical'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {anom.severity}
                  </span>
                  <h4 className="text-sm font-semibold text-white">{anom.title}</h4>
                </div>
                <p className="text-xs text-slate-300">{anom.description}</p>
                <p className="text-[11px] font-mono text-slate-400">
                  Evidence: {anom.evidence} (Source: {anom.sourceTool})
                </p>
              </div>
              <div className="text-right shrink-0">
                <span className="text-xs font-mono text-cyan-400">
                  Confidence: {anom.confidenceScore}%
                </span>
              </div>
            </div>
          ))}
          {(correlation?.anomalies || []).length === 0 && (
            <div className="p-8 text-center bg-slate-900/60 border border-slate-800 rounded-xl text-slate-400 text-sm">
              No suspicious or inconsistent asset relationships detected in this assessment.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
