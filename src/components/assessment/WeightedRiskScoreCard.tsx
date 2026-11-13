import React, { useMemo, useState } from 'react';
import {
  Assessment,
  AssessmentRiskProfile,
  Asset,
  Finding,
  FindingSeverity,
  NetworkService,
  RiskScoreWeights,
  WebEndpoint,
} from '../../types';
import {
  calculateAssessmentRiskScore,
  DEFAULT_RISK_WEIGHTS,
} from '../../services/riskScoringEngine';
import {
  ShieldAlert,
  Cpu,
  Globe,
  AlertTriangle,
  Sliders,
  ArrowUpRight,
  Layers,
} from 'lucide-react';

interface Props {
  assessment: Assessment;
  assets: Asset[];
  services: NetworkService[];
  endpoints: WebEndpoint[];
  findings: Finding[];
  onNavigateTab?: (tab: 'services' | 'findings' | 'endpoints') => void;
}

type WeightPresetKey = 'balanced' | 'vuln_centric' | 'perimeter_exposure';

const WEIGHT_PRESETS: Record<
  WeightPresetKey,
  { label: string; weights: RiskScoreWeights }
> = {
  balanced: {
    label: 'Balanced (25 / 25 / 50)',
    weights: DEFAULT_RISK_WEIGHTS,
  },
  vuln_centric: {
    label: 'Vuln-Focused (15 / 15 / 70)',
    weights: { openPorts: 0.15, exposedServices: 0.15, vulnerabilities: 0.7 },
  },
  perimeter_exposure: {
    label: 'Perimeter (40 / 35 / 25)',
    weights: { openPorts: 0.4, exposedServices: 0.35, vulnerabilities: 0.25 },
  },
};

function getTierStyles(tier: FindingSeverity): {
  label: string;
  hex: string;
  textClass: string;
  borderClass: string;
  bgClass: string;
} {
  switch (tier) {
    case 'critical':
      return {
        label: 'CRITICAL',
        hex: '#f43f5e',
        textClass: 'text-rose-400',
        borderClass: 'border-rose-500/40',
        bgClass: 'bg-rose-500/10',
      };
    case 'high':
      return {
        label: 'HIGH',
        hex: '#f97316',
        textClass: 'text-orange-400',
        borderClass: 'border-orange-500/40',
        bgClass: 'bg-orange-500/10',
      };
    case 'medium':
      return {
        label: 'MEDIUM',
        hex: '#f59e0b',
        textClass: 'text-amber-400',
        borderClass: 'border-amber-500/40',
        bgClass: 'bg-amber-500/10',
      };
    case 'low':
      return {
        label: 'LOW',
        hex: '#06b6d4',
        textClass: 'text-cyan-400',
        borderClass: 'border-cyan-500/40',
        bgClass: 'bg-cyan-500/10',
      };
    case 'informational':
    default:
      return {
        label: 'INFORMATIONAL',
        hex: '#3b82f6',
        textClass: 'text-blue-400',
        borderClass: 'border-blue-500/40',
        bgClass: 'bg-blue-500/10',
      };
  }
}

export const WeightedRiskScoreCard: React.FC<Props> = ({
  assessment,
  assets,
  services,
  endpoints,
  findings,
  onNavigateTab,
}) => {
  const [preset, setPreset] = useState<WeightPresetKey>('balanced');

  const riskProfile: AssessmentRiskProfile = useMemo(() => {
    return calculateAssessmentRiskScore({
      assessment,
      assets,
      services,
      endpoints,
      findings,
      weights: WEIGHT_PRESETS[preset].weights,
    });
  }, [assessment, assets, services, endpoints, findings, preset]);

  const tierStyle = getTierStyles(riskProfile.severityTier);

  // SVG gauge geometry
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const strokeOffset =
    circumference - (riskProfile.aggregateScore / 100) * circumference;

  const pillars = [
    {
      key: 'openPorts',
      title: 'Open Ports Exposure',
      icon: Cpu,
      weightPct: Math.round(riskProfile.weights.openPorts * 100),
      subScore: riskProfile.subScores.openPortsScore,
      weightedPts: riskProfile.weightedContributions.openPortsPoints,
      detail: `${riskProfile.metrics.openPortsTotal} open ports (${riskProfile.metrics.highRiskPortsCount} high-risk)`,
      barColor: 'bg-amber-400',
      targetTab: 'services' as const,
    },
    {
      key: 'exposedServices',
      title: 'Exposed Services & Endpoints',
      icon: Globe,
      weightPct: Math.round(riskProfile.weights.exposedServices * 100),
      subScore: riskProfile.subScores.exposedServicesScore,
      weightedPts: riskProfile.weightedContributions.exposedServicesPoints,
      detail: `${riskProfile.metrics.exposedServicesTotal} services/endpoints (${riskProfile.metrics.cleartextOrVersionExposedCount} exposed banners/HTTP)`,
      barColor: 'bg-cyan-400',
      targetTab: 'endpoints' as const,
    },
    {
      key: 'vulnerabilities',
      title: 'Discovered Vulnerabilities',
      icon: AlertTriangle,
      weightPct: Math.round(riskProfile.weights.vulnerabilities * 100),
      subScore: riskProfile.subScores.vulnerabilitiesScore,
      weightedPts: riskProfile.weightedContributions.vulnerabilitiesPoints,
      detail: `${riskProfile.metrics.findingsTotal} findings (${riskProfile.metrics.findingsBySeverity.critical} crit, ${riskProfile.metrics.findingsBySeverity.high} high, ${riskProfile.metrics.findingsBySeverity.medium} med)`,
      barColor: 'bg-rose-400',
      targetTab: 'findings' as const,
    },
  ];

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl shadow-lg overflow-hidden">
      {/* Header Row */}
      <div className="p-4 sm:p-5 border-b border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0" />
            <h3 className="text-sm font-semibold text-white">
              Weighted Aggregate Risk-Scoring Engine
            </h3>
            <span className="text-xs font-mono text-slate-400">
              · {riskProfile.aggregateScore} / 100 ({tierStyle.label})
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Calculates an aggregate severity score weighted across open network ports, exposed service footprints, and verified vulnerability findings.
          </p>
        </div>

        {/* Weighting Profile Selector */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-slate-400 mr-1">
            <Sliders className="w-3.5 h-3.5 text-cyan-400" />
            Weighting Model:
          </span>
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            {(Object.keys(WEIGHT_PRESETS) as WeightPresetKey[]).map((key) => (
              <button
                key={key}
                onClick={() => setPreset(key)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  preset === key
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {WEIGHT_PRESETS[key].label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="p-4 sm:p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Left: Aggregate Score Gauge & Tier */}
        <div className="lg:col-span-4 bg-slate-950/70 border border-slate-800/90 rounded-xl p-5 flex flex-col items-center justify-center text-center space-y-3">
          <div className="relative w-32 h-32 flex items-center justify-center">
            <svg className="w-32 h-32 -rotate-90" viewBox="0 0 110 110">
              <circle
                cx="55"
                cy="55"
                r={radius}
                fill="none"
                stroke="#1e293b"
                strokeWidth="10"
              />
              <circle
                cx="55"
                cy="55"
                r={radius}
                fill="none"
                stroke={tierStyle.hex}
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeOffset}
                className="transition-all duration-300"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold font-mono tabular-nums text-white leading-none">
                {riskProfile.aggregateScore}
              </span>
              <span className="text-[10px] font-mono text-slate-400 mt-1">
                OUT OF 100
              </span>
            </div>
          </div>

          <div className="space-y-1">
            <div
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md border text-xs font-mono font-bold ${tierStyle.bgClass} ${tierStyle.borderClass} ${tierStyle.textClass}`}
            >
              SEVERITY TIER: {tierStyle.label}
            </div>
            <div className="text-[11px] font-mono text-slate-400 tabular-nums pt-1">
              Ports {riskProfile.weightedContributions.openPortsPoints} + Services{' '}
              {riskProfile.weightedContributions.exposedServicesPoints} + Vulns{' '}
              {riskProfile.weightedContributions.vulnerabilitiesPoints} pts
            </div>
          </div>
        </div>

        {/* Middle/Right: 3 Weighted Pillar Bars */}
        <div className="lg:col-span-8 flex flex-col justify-between space-y-3.5">
          {pillars.map((p) => {
            const Icon = p.icon;
            return (
              <div
                key={p.key}
                className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span className="text-xs font-semibold text-white">
                      {p.title}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      · Weight {p.weightPct}%
                    </span>
                  </div>

                  <div className="flex items-center gap-3 font-mono text-xs tabular-nums">
                    <span className="text-slate-400">
                      Sub-score: <strong className="text-white">{p.subScore}/100</strong>
                    </span>
                    <span className="text-cyan-400 font-semibold">
                      +{p.weightedPts} weighted pts
                    </span>
                    {onNavigateTab && (
                      <button
                        onClick={() => onNavigateTab(p.targetTab)}
                        className="text-[11px] text-slate-400 hover:text-cyan-300 inline-flex items-center gap-0.5 cursor-pointer"
                      >
                        Inspect <ArrowUpRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden border border-slate-800/80">
                  <div
                    className={`h-full ${p.barColor} transition-all duration-300 rounded-full`}
                    style={{ width: `${Math.min(100, Math.max(2, p.subScore))}%` }}
                  />
                </div>

                <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                  {p.detail}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom: Top Risk Drivers & Highest-Risk Hosts */}
      {(riskProfile.topFactors.length > 0 || riskProfile.highestRiskAssets.length > 0) && (
        <div className="px-4 sm:px-5 pb-5 grid grid-cols-1 lg:grid-cols-2 gap-4 border-t border-slate-800/80 pt-4">
          {/* Top Weighted Drivers */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold text-white flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Top Weighted Risk Drivers
              </h4>
              <span className="text-[11px] font-mono text-slate-400">
                Top {Math.min(5, riskProfile.topFactors.length)} factors
              </span>
            </div>

            <div className="divide-y divide-slate-800/70 bg-slate-950/60 border border-slate-800/80 rounded-xl overflow-hidden">
              {riskProfile.topFactors.slice(0, 5).map((factor) => {
                const fStyle = getTierStyles(factor.severity);
                return (
                  <div
                    key={factor.id}
                    className="px-3 py-2.5 flex items-center justify-between gap-3 text-xs"
                  >
                    <div className="min-w-0">
                      <div className="font-medium text-slate-200 truncate">
                        {factor.label}
                      </div>
                      <div className="text-[10px] font-mono text-slate-400 truncate mt-0.5">
                        {factor.evidence}
                      </div>
                    </div>
                    <div className="text-right shrink-0 font-mono tabular-nums">
                      <div className={`text-[10px] font-bold uppercase ${fStyle.textClass}`}>
                        {factor.severity}
                      </div>
                      <div className="text-[11px] text-white font-semibold">
                        +{factor.weightedContribution} pts
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Highest-Risk Hosts */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold text-white flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                Highest-Risk Target Hosts
              </h4>
              <span className="text-[11px] font-mono text-slate-400">
                Ranked by aggregate score
              </span>
            </div>

            <div className="overflow-x-auto bg-slate-950/60 border border-slate-800/80 rounded-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/60 text-slate-400 font-mono text-[10px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="px-3 py-2">Host / Target</th>
                    <th className="px-3 py-2">Ports</th>
                    <th className="px-3 py-2">Findings</th>
                    <th className="px-3 py-2 text-right">Host Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono tabular-nums">
                  {riskProfile.highestRiskAssets.slice(0, 5).map((host) => {
                    const hStyle = getTierStyles(host.severity);
                    return (
                      <tr key={host.assetKey} className="hover:bg-slate-900/50">
                        <td className="px-3 py-2 text-slate-200 truncate max-w-[180px]" title={host.topReason}>
                          {host.assetKey}
                        </td>
                        <td className="px-3 py-2 text-slate-400 text-[11px]">
                          {host.openPorts.length > 0 ? host.openPorts.slice(0, 4).join(', ') : '—'}
                        </td>
                        <td className="px-3 py-2 text-slate-300">
                          {host.findingsCount}
                        </td>
                        <td className="px-3 py-2 text-right font-bold">
                          <span className={hStyle.textClass}>
                            {host.score} · {host.severity.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
