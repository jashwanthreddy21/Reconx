import React, { useState, useEffect } from 'react';
import { Assessment, Asset, NetworkService, WebEndpoint } from '../types';
import { firestoreService } from '../services/firestoreService';
import {
  GitCompare,
  PlusCircle,
  MinusCircle,
  RefreshCw,
  Server,
  Globe,
  Cpu,
  Layers,
  ArrowRight,
  AlertCircle
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

  useEffect(() => {
    if (!assessmentAId || !assessmentBId) return;

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

  // Service Ports Diff
  const portsA = new Set(servicesA.map((s) => `${s.host}:${s.port}`));
  const newPorts = servicesB.filter((s) => !portsA.has(`${s.host}:${s.port}`));

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl sm:rounded-2xl p-4 sm:p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-1">
          <GitCompare className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
            Historical Assessment Diff &amp; Attack Surface Delta
          </h2>
        </div>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
          Compare two distinct reconnaissance runs across the same target scope to track newly exposed assets, decommissioned services, and configuration changes over time.
        </p>

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
                  {a.name} ({a.scope.rootDomain}) — {new Date(a.createdAt).toLocaleDateString()}
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
                  {a.name} ({a.scope.rootDomain}) — {new Date(a.createdAt).toLocaleDateString()}
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
        </div>
      )}
    </div>
  );
};
