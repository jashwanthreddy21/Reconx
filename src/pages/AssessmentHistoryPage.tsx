import React, { useState, useEffect, useMemo } from 'react';
import { Assessment, AssessmentSnapshot, AssetChange } from '../types';
import { loadOrComputeAssessmentIntelligence } from '../services/firestoreService';
import { compareAssessmentSnapshots } from '../services/changeDetectionEngine';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend
} from 'recharts';
import {
  History,
  Calendar,
  TrendingUp,
  PlusCircle,
  MinusCircle,
  RefreshCw,
  Lock,
  Cpu,
  Sparkles,
  Download,
  Clock,
  ExternalLink
} from 'lucide-react';

interface Props {
  assessments: Assessment[];
  onSelectAssessment?: (assessment: Assessment) => void;
  onNavigateToComparison?: () => void;
}

interface HistoricalPoint {
  assessmentId: string;
  name: string;
  rootDomain: string;
  timestamp: string;
  dateLabel: string;
  status: string;
  totalAssets: number;
  subdomains: number;
  ips: number;
  openPorts: number;
  services: number;
  technologies: number;
  newAssets: number;
  notObservedAssets: number;
  modifiedAssets: number;
  newlyExposedPorts: number;
  newlyDetectedServices: number;
  technologyChanges: number;
}

export const AssessmentHistoryPage: React.FC<Props> = ({
  assessments,
  onSelectAssessment,
  onNavigateToComparison,
}) => {
  const [dateRangeFilter, setDateRangeFilter] = useState<'all' | '7d' | '30d' | '90d'>('all');
  const [domainFilter, setDomainFilter] = useState<string>('all');
  const [loading, setLoading] = useState(false);
  const [historyPoints, setHistoryPoints] = useState<HistoricalPoint[]>([]);
  const [timelineChanges, setTimelineChanges] = useState<AssetChange[]>([]);

  const uniqueDomains = useMemo(
    () => Array.from(new Set(assessments.map((a) => a.scope.rootDomain).filter(Boolean))),
    [assessments]
  );

  useEffect(() => {
    let mounted = true;
    const buildHistory = async () => {
      if (assessments.length === 0) {
        setHistoryPoints([]);
        setTimelineChanges([]);
        return;
      }
      setLoading(true);
      try {
        // Sort assessments chronologically (oldest to newest)
        const sorted = [...assessments].sort(
          (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
        );

        const snapshotsById = new Map<string, AssessmentSnapshot>();
        for (const asm of sorted) {
          const intel = await loadOrComputeAssessmentIntelligence(asm);
          snapshotsById.set(asm.id, intel.snapshot);
        }

        if (!mounted) return;

        const points: HistoricalPoint[] = [];
        const allChanges: AssetChange[] = [];

        for (let i = 0; i < sorted.length; i++) {
          const current = sorted[i];
          const snap = snapshotsById.get(current.id)!;

          // Find previous assessment for same domain or immediately preceding assessment
          let prevAsm: Assessment | undefined;
          for (let j = i - 1; j >= 0; j--) {
            if (sorted[j].scope.rootDomain === current.scope.rootDomain) {
              prevAsm = sorted[j];
              break;
            }
          }
          if (!prevAsm && i > 0) {
            prevAsm = sorted[i - 1];
          }

          let newAssets = 0;
          let notObservedAssets = 0;
          let modifiedAssets = 0;
          let newlyExposedPorts = 0;
          let newlyDetectedServices = 0;
          let technologyChanges = 0;

          if (prevAsm) {
            const prevSnap = snapshotsById.get(prevAsm.id)!;
            const diff = compareAssessmentSnapshots(prevSnap, snap, prevAsm, current);
            newAssets = diff.summary.newAssetsCount;
            notObservedAssets = diff.summary.notObservedCount;
            modifiedAssets = diff.summary.modifiedAssetsCount;
            newlyExposedPorts = diff.summary.newlyExposedPortsCount;
            newlyDetectedServices = diff.summary.newlyDetectedServicesCount;
            technologyChanges = diff.summary.technologyChangesCount;
            allChanges.push(...diff.changes);
          }

          points.push({
            assessmentId: current.id,
            name: current.name,
            rootDomain: current.scope.rootDomain,
            timestamp: current.createdAt,
            dateLabel: new Date(current.createdAt).toLocaleDateString(undefined, {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            }),
            status: current.status,
            totalAssets: snap.assetCount,
            subdomains: snap.countsByType.subdomain || 0,
            ips: snap.countsByType.ip_address || 0,
            openPorts: snap.countsByType.port || 0,
            services: snap.countsByType.service || 0,
            technologies: snap.countsByType.technology || 0,
            newAssets,
            notObservedAssets,
            modifiedAssets,
            newlyExposedPorts,
            newlyDetectedServices,
            technologyChanges,
          });
        }

        setHistoryPoints(points);
        setTimelineChanges(
          allChanges.sort(
            (a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime()
          )
        );
      } catch (err) {
        console.error('Error building historical timeline:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    buildHistory();
    return () => {
      mounted = false;
    };
  }, [assessments]);

  const filteredPoints = useMemo(() => {
    const now = Date.now();
    return historyPoints.filter((pt) => {
      if (domainFilter !== 'all' && pt.rootDomain !== domainFilter) return false;
      if (dateRangeFilter !== 'all') {
        const days = dateRangeFilter === '7d' ? 7 : dateRangeFilter === '30d' ? 30 : 90;
        if (now - new Date(pt.timestamp).getTime() > days * 86400 * 1000) return false;
      }
      return true;
    });
  }, [historyPoints, domainFilter, dateRangeFilter]);

  const aggregateStats = useMemo(() => {
    const latest = filteredPoints[filteredPoints.length - 1];
    return {
      totalAssetsLatest: latest?.totalAssets || 0,
      totalNewDiscovered: filteredPoints.reduce((acc, p) => acc + p.newAssets, 0),
      totalNotObserved: filteredPoints.reduce((acc, p) => acc + p.notObservedAssets, 0),
      totalModified: filteredPoints.reduce((acc, p) => acc + p.modifiedAssets, 0),
      totalNewPorts: filteredPoints.reduce((acc, p) => acc + p.newlyExposedPorts, 0),
      totalNewServices: filteredPoints.reduce((acc, p) => acc + p.newlyDetectedServices, 0),
      totalTechChanges: filteredPoints.reduce((acc, p) => acc + p.technologyChanges, 0),
    };
  }, [filteredPoints]);

  const exportHistoryReport = () => {
    const report = {
      exportedAt: new Date().toISOString(),
      dateRangeFilter,
      domainFilter,
      aggregateStats,
      historicalSnapshots: filteredPoints,
      timelineChanges: timelineChanges.slice(0, 200),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconx-attack-surface-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header & Filters */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider bg-purple-500/15 text-purple-300 border border-purple-500/30 rounded">
              Feature 3 • Historical Attack Surface Analytics
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white flex items-center gap-2.5">
            <History className="w-6 h-6 text-purple-400" />
            Attack Surface History &amp; Evolution Timeline
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Track total assets over time, newly discovered exposures, assets not observed in recent scans, and infrastructure drift across assessments.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Domain Selector */}
          <select
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            className="px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
          >
            <option value="all">All Target Scopes</option>
            {uniqueDomains.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>

          {/* Date-Range Filter */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1 text-xs">
            {(['all', '7d', '30d', '90d'] as const).map((rng) => (
              <button
                key={rng}
                onClick={() => setDateRangeFilter(rng)}
                className={`px-2.5 py-1 rounded font-medium transition-colors ${
                  dateRangeFilter === rng
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {rng === 'all' ? 'All Time' : `Last ${rng}`}
              </button>
            ))}
          </div>

          {onNavigateToComparison && (
            <button
              onClick={onNavigateToComparison}
              className="px-3 py-2 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-medium"
            >
              Side-by-Side Diff
            </button>
          )}

          <button
            onClick={exportHistoryReport}
            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Export History Report
          </button>
        </div>
      </div>

      {/* 7 Historical KPI Cards Required by Feature 3 */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Total Assets</span>
            <TrendingUp className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white">
            {aggregateStats.totalAssetsLatest}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Latest snapshot</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-emerald-400 mb-1">
            <span>New Discovered</span>
            <PlusCircle className="w-4 h-4" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400">
            +{aggregateStats.totalNewDiscovered}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Cumulative additions</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-amber-400 mb-1">
            <span>Not Observed</span>
            <MinusCircle className="w-4 h-4" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">
            {aggregateStats.totalNotObserved}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Unobserved in latest</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-cyan-400 mb-1">
            <span>Modified Assets</span>
            <RefreshCw className="w-4 h-4" />
          </div>
          <div className="text-xl font-bold font-mono text-cyan-400">
            {aggregateStats.totalModified}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">DNS/IP/HTTP shifts</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-orange-400 mb-1">
            <span>Exposed Ports</span>
            <Lock className="w-4 h-4" />
          </div>
          <div className="text-xl font-bold font-mono text-orange-400">
            +{aggregateStats.totalNewPorts}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Newly opened</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-purple-400 mb-1">
            <span>New Services</span>
            <Cpu className="w-4 h-4" />
          </div>
          <div className="text-xl font-bold font-mono text-purple-400">
            +{aggregateStats.totalNewServices}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Newly detected</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between text-xs text-pink-400 mb-1">
            <span>Tech Changes</span>
            <Sparkles className="w-4 h-4" />
          </div>
          <div className="text-xl font-bold font-mono text-pink-400">
            {aggregateStats.totalTechChanges}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Stack evolution</div>
        </div>
      </div>

      {/* Interactive Recharts Historical Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Total Assets Over Time Area Chart */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">
            Total Attack Surface Assets Over Time
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Historical growth of total normalized assets, subdomains, open ports, and technologies across snapshots.
          </p>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={filteredPoints}>
                <defs>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorSubs" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22D3EE" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#22D3EE" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="dateLabel" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Area
                  type="monotone"
                  dataKey="totalAssets"
                  name="Total Assets"
                  stroke="#3B82F6"
                  fillOpacity={1}
                  fill="url(#colorTotal)"
                />
                <Area
                  type="monotone"
                  dataKey="subdomains"
                  name="Subdomains"
                  stroke="#22D3EE"
                  fillOpacity={1}
                  fill="url(#colorSubs)"
                />
                <Area
                  type="monotone"
                  dataKey="openPorts"
                  name="Open Ports"
                  stroke="#F97316"
                  fillOpacity={0.2}
                  fill="#F97316"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Delta Classification Bar Chart */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">
            Snapshot Change Velocity (New vs Not Observed vs Modified)
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Comparison of newly discovered assets, modified configurations, and assets not observed per scan.
          </p>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={filteredPoints}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="dateLabel" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="newAssets" name="New Assets" fill="#10B981" radius={[4, 4, 0, 0]} />
                <Bar
                  dataKey="modifiedAssets"
                  name="Modified Assets"
                  fill="#22D3EE"
                  radius={[4, 4, 0, 0]}
                />
                <Bar
                  dataKey="notObservedAssets"
                  name="Not Observed in Scan"
                  fill="#F59E0B"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Historical Assessment Snapshots Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Calendar className="w-4 h-4 text-cyan-400" />
            Immutable Assessment Snapshots
          </h3>
          <span className="text-xs font-mono text-slate-400">
            {filteredPoints.length} Snapshots Recorded
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <th className="py-3 px-4 font-semibold">Assessment</th>
                <th className="py-3 px-4 font-semibold">Root Scope</th>
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold">Total Assets</th>
                <th className="py-3 px-4 font-semibold">Delta (+New / ΔMod / -Unobs)</th>
                <th className="py-3 px-4 font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {[...filteredPoints].reverse().map((pt) => {
                const asm = assessments.find((a) => a.id === pt.assessmentId);
                return (
                  <tr key={pt.assessmentId} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-semibold text-white">{pt.name}</td>
                    <td className="py-3 px-4 font-mono text-cyan-400">{pt.rootDomain}</td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {new Date(pt.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] uppercase">
                        {pt.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-white">{pt.totalAssets}</td>
                    <td className="py-3 px-4 font-mono">
                      <span className="text-emerald-400 mr-2">+{pt.newAssets}</span>
                      <span className="text-cyan-400 mr-2">Δ{pt.modifiedAssets}</span>
                      <span className="text-amber-400">-{pt.notObservedAssets}</span>
                    </td>
                    <td className="py-3 px-4">
                      {asm && onSelectAssessment && (
                        <button
                          onClick={() => onSelectAssessment(asm)}
                          className="text-cyan-400 hover:underline flex items-center gap-1 font-medium"
                        >
                          Inspect <ExternalLink className="w-3 h-3" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Asset Change Timeline */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-4">
          <Clock className="w-4 h-4 text-purple-400" />
          Chronological Asset Change Audit Trail
        </h3>
        {timelineChanges.length === 0 ? (
          <p className="text-xs text-slate-500">
            Run multiple assessments over time to populate the chronological change detection timeline.
          </p>
        ) : (
          <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
            {timelineChanges.slice(0, 40).map((chg) => (
              <div
                key={chg.id}
                className="p-3 rounded-lg bg-slate-950/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
                        chg.changeType === 'NEW'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : chg.changeType === 'MODIFIED'
                          ? 'bg-cyan-500/20 text-cyan-300'
                          : 'bg-amber-500/20 text-amber-300'
                      }`}
                    >
                      {chg.changeType === 'NOT_OBSERVED'
                        ? 'NOT OBSERVED IN LATEST SCAN'
                        : chg.changeType}
                    </span>
                    <span className="font-mono font-bold text-white">{chg.assetName}</span>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">
                      ({chg.changeCategory})
                    </span>
                  </div>
                  <p className="text-slate-300">{chg.changeDescription}</p>
                  <p className="text-[10px] font-mono text-slate-500">
                    Evidence: {chg.evidenceReference}
                  </p>
                </div>
                <div className="text-[11px] font-mono text-slate-400 shrink-0">
                  {new Date(chg.detectedAt).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
