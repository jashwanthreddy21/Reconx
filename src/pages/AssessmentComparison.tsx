import React, { useState, useEffect } from 'react';
import { Assessment, Asset, NetworkService, WebEndpoint } from '../types';
import { firestoreService } from '../services/firestoreService';
import {
  GitCompare,
  PlusCircle,
  MinusCircle,
  Globe,
  Cpu,
  ArrowLeft,
} from 'lucide-react';

interface Props {
  assessments: Assessment[];
  onBack: () => void;
}

export const AssessmentComparison: React.FC<Props> = ({ assessments, onBack }) => {
  const [assessmentAId, setAssessmentAId] = useState<string>(assessments[0]?.id || '');
  const [assessmentBId, setAssessmentBId] = useState<string>(assessments[1]?.id || assessments[0]?.id || '');

  const [assetsA, setAssetsA] = useState<Asset[]>([]);
  const [assetsB, setAssetsB] = useState<Asset[]>([]);
  const [servicesA, setServicesA] = useState<NetworkService[]>([]);
  const [servicesB, setServicesB] = useState<NetworkService[]>([]);
  const [endpointsA, setEndpointsA] = useState<WebEndpoint[]>([]);
  const [endpointsB, setEndpointsB] = useState<WebEndpoint[]>([]);

  const [loading, setLoading] = useState(false);

  // Sync default selections when assessments load asynchronously
  useEffect(() => {
    if (assessments.length === 0) {
      setAssessmentAId('');
      setAssessmentBId('');
      return;
    }
    const validIds = new Set(assessments.map((a) => a.id));
    setAssessmentAId((prev) => (prev && validIds.has(prev) ? prev : assessments[0].id));
    setAssessmentBId((prev) =>
      prev && validIds.has(prev) ? prev : assessments[1]?.id || assessments[0].id
    );
  }, [assessments]);

  useEffect(() => {
    if (!assessmentAId || !assessmentBId) {
      setAssetsA([]);
      setAssetsB([]);
      setServicesA([]);
      setServicesB([]);
      setEndpointsA([]);
      setEndpointsB([]);
      return;
    }

    let mounted = true;
    const fetchDiffData = async () => {
      setLoading(true);
      try {
        const [aA, aB, sA, sB, eA, eB] = await Promise.all([
          firestoreService.getAssets(assessmentAId),
          firestoreService.getAssets(assessmentBId),
          firestoreService.getNetworkServices(assessmentAId),
          firestoreService.getNetworkServices(assessmentBId),
          firestoreService.getWebEndpoints(assessmentAId),
          firestoreService.getWebEndpoints(assessmentBId),
        ]);

        if (mounted) {
          setAssetsA(aA || []);
          setAssetsB(aB || []);
          setServicesA(sA || []);
          setServicesB(sB || []);
          setEndpointsA(eA || []);
          setEndpointsB(eB || []);
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
  }, [assessmentAId, assessmentBId]);

  // Diff Calculations
  const namesA = new Set(assetsA.map((a) => a.canonicalName));
  const namesB = new Set(assetsB.map((a) => a.canonicalName));

  const newlyObservedAssets = assetsB.filter((b) => !namesA.has(b.canonicalName));
  const notObservedInLatest = assetsA.filter((a) => !namesB.has(a.canonicalName));

  // Web Endpoints Diff
  const urlsA = new Set(endpointsA.map((e) => e.url));
  const newEndpoints = endpointsB.filter((e) => !urlsA.has(e.url));

  // Service Ports Diff
  const portsA = new Set(servicesA.map((s) => `${s.host}:${s.port}`));
  const newPorts = servicesB.filter((s) => !portsA.has(`${s.host}:${s.port}`));

  if (assessments.length < 2) {
    return (
      <div className="max-w-2xl mx-auto mt-8 p-8 bg-[#111827] border border-slate-800 rounded-2xl text-center space-y-4 shadow-xl">
        <GitCompare className="w-10 h-10 text-cyan-400 mx-auto" />
        <h3 className="text-base font-bold text-white">Not Enough Assessments to Compare</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Historical diff analysis requires at least two saved reconnaissance assessments. Run another scan or load a lab demo fixture to compare attack surface changes over time.
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

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl sm:rounded-2xl p-4 sm:p-6 shadow-xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <GitCompare className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                Historical Assessment Diff &amp; Attack Surface Delta
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Compare two distinct reconnaissance runs across the same target scope to track newly exposed assets, decommissioned services, and configuration changes over time.
            </p>
          </div>
          <button
            onClick={onBack}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs border border-slate-700 shrink-0 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Dashboard
          </button>
        </div>

        {/* Assessment Selectors */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6 pt-4 border-t border-slate-800">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Baseline Assessment (Scan A)
            </label>
            <select
              value={assessmentAId}
              onChange={(e) => setAssessmentAId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-200 focus:outline-none"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.scope?.rootDomain || 'N/A'}) — {new Date(a.createdAt).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Latest Assessment (Scan B)
            </label>
            <select
              value={assessmentBId}
              onChange={(e) => setAssessmentBId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-200 focus:outline-none"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.scope?.rootDomain || 'N/A'}) — {new Date(a.createdAt).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-400 font-mono text-xs">
          Computing delta between assessment snapshots...
        </div>
      ) : (
        <div className="space-y-6">
          {/* Summary Delta Cards */}
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
              <h3 className="text-sm font-semibold text-white">Newly Discovered Assets (Attack Surface Expansion)</h3>
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
                        <td className="px-4 py-3 text-emerald-300 font-semibold">{a.canonicalName}</td>
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
                        <td className="px-4 py-3 text-amber-300 font-semibold">{a.canonicalName}</td>
                        <td className="px-4 py-3 uppercase text-slate-400">{a.assetType}</td>
                        <td className="px-4 py-3 text-slate-400">{a.discoverySource}</td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40">
                            UNOBSERVED IN LATEST RUN
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* New Open Ports / Services Table */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="p-4 border-b border-slate-800 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">New Open Ports &amp; Network Services</h3>
            </div>
            {newPorts.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No new network service ports detected between baseline and latest run.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Host</th>
                      <th className="px-4 py-3">Port / Proto</th>
                      <th className="px-4 py-3">Service</th>
                      <th className="px-4 py-3">State</th>
                      <th className="px-4 py-3">Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {newPorts.map((svc) => (
                      <tr key={svc.id} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3 text-cyan-300 font-semibold">{svc.host}</td>
                        <td className="px-4 py-3 text-amber-300 font-bold">
                          {svc.port}/{svc.protocol}
                        </td>
                        <td className="px-4 py-3 text-white">
                          {svc.serviceName}
                          {svc.version ? ` (${svc.version})` : ''}
                        </td>
                        <td className="px-4 py-3 uppercase text-emerald-400">{svc.state}</td>
                        <td className="px-4 py-3 text-slate-400">{svc.toolSource}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* New Web Endpoints Table */}
          <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="p-4 border-b border-slate-800 flex items-center gap-2">
              <Globe className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">New Web Endpoints</h3>
            </div>
            {newEndpoints.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No new HTTP/HTTPS web endpoints detected between baseline and latest run.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Endpoint URL</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Page Title</th>
                      <th className="px-4 py-3">Host IP</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {newEndpoints.map((ep) => (
                      <tr key={ep.id} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3 text-purple-300 font-semibold break-all">{ep.url}</td>
                        <td className="px-4 py-3 text-emerald-400 font-bold">{ep.statusCode}</td>
                        <td className="px-4 py-3 text-slate-200 font-sans">{ep.title || '—'}</td>
                        <td className="px-4 py-3 text-slate-400">{ep.ip || '—'}</td>
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
