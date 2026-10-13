import React, { useState, useRef, useEffect } from 'react';
import { Assessment, Finding } from '../types';
import {
  ShieldAlert,
  Server,
  Globe,
  Layers,
  Cpu,
  PlusCircle,
  FileText,
  AlertTriangle,
  Clock,
  CheckCircle2,
  XCircle,
  ArrowRight,
  ExternalLink,
  Beaker,
  Activity,
  FileDown,
  Download,
  FileSpreadsheet,
  Code,
  ChevronDown,
  Loader2
} from 'lucide-react';
import { generateAssessmentSummaryPdf } from '../services/pdfReportGenerator';
import { firestoreService } from '../services/firestoreService';
import {
  exportAssessmentsMetadataCsv,
  exportFindingsSummaryCsv,
  exportAssessmentsAndFindingsJson,
  exportSingleAssessmentCsv,
  exportSingleAssessmentJson,
} from '../services/exportService';

interface Props {
  assessments: Assessment[];
  onSelectAssessment: (id: string) => void;
  onCreateNew: () => void;
  onSeedDemoLab: () => void;
  loading: boolean;
}

export const Dashboard: React.FC<Props> = ({
  assessments,
  onSelectAssessment,
  onCreateNew,
  onSeedDemoLab,
  loading,
}) => {
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [activeRowMenuId, setActiveRowMenuId] = useState<string | null>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setShowExportMenu(false);
      }
      if (!(e.target as HTMLElement).closest('.row-export-menu-container')) {
        setActiveRowMenuId(null);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  // Aggregate statistics
  const totalAssessments = assessments.length;
  const totalAssets = assessments.reduce((acc, a) => acc + (a.stats?.assetsCount || 0), 0);
  const totalSubdomains = assessments.reduce((acc, a) => acc + (a.stats?.subdomainsCount || 0), 0);
  const totalEndpoints = assessments.reduce((acc, a) => acc + (a.stats?.endpointsCount || 0), 0);
  const totalServices = assessments.reduce((acc, a) => acc + (a.stats?.servicesCount || 0), 0);
  const totalFindings = assessments.reduce((acc, a) => acc + (a.stats?.findingsCount || 0), 0);

  const completedScans = assessments.filter((a) => a.status === 'completed').length;
  const failedScans = assessments.filter((a) => a.status === 'failed').length;

  const statCards = [
    {
      label: 'Total Assessments',
      value: totalAssessments,
      icon: FileText,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10 border-blue-500/20',
    },
    {
      label: 'Discovered Assets',
      value: totalAssets,
      icon: Server,
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/10 border-cyan-500/20',
    },
    {
      label: 'Subdomains Identified',
      value: totalSubdomains,
      icon: Globe,
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10 border-emerald-500/20',
    },
    {
      label: 'Active Web Endpoints',
      value: totalEndpoints,
      icon: Layers,
      color: 'text-purple-400',
      bg: 'bg-purple-500/10 border-purple-500/20',
    },
    {
      label: 'Open Ports & Services',
      value: totalServices,
      icon: Cpu,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10 border-amber-500/20',
    },
    {
      label: 'Attack Surface Findings',
      value: totalFindings,
      icon: ShieldAlert,
      color: 'text-rose-400',
      bg: 'bg-rose-500/10 border-rose-500/20',
    },
  ];

  const getStatusBadge = (status: Assessment['status']) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" /> Completed
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse">
            <Activity className="w-3 h-3" /> Scanning
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" /> Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <Clock className="w-3 h-3" /> {status}
          </span>
        );
    }
  };

  // Helper to fetch findings for all assessments
  const fetchAllFindingsMap = async (): Promise<Record<string, Finding[]>> => {
    const map: Record<string, Finding[]> = {};
    const promises = assessments.map(async (a) => {
      try {
        const list = await firestoreService.getFindings(a.id);
        map[a.id] = list || [];
      } catch (err) {
        console.warn(`Could not load findings for ${a.id}:`, err);
        map[a.id] = [];
      }
    });
    await Promise.all(promises);
    return map;
  };

  // Bulk Export Handlers
  const handleExportMetadataCsv = () => {
    setShowExportMenu(false);
    exportAssessmentsMetadataCsv(assessments);
  };

  const handleExportFindingsCsv = async () => {
    setShowExportMenu(false);
    setIsExporting(true);
    try {
      const findingsMap = await fetchAllFindingsMap();
      exportFindingsSummaryCsv(assessments, findingsMap);
    } catch (err) {
      console.error('Error exporting findings CSV:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportAllJson = async () => {
    setShowExportMenu(false);
    setIsExporting(true);
    try {
      const findingsMap = await fetchAllFindingsMap();
      exportAssessmentsAndFindingsJson(assessments, findingsMap);
    } catch (err) {
      console.error('Error exporting full JSON:', err);
    } finally {
      setIsExporting(false);
    }
  };

  // Row-Level Export Handlers
  const handleExportSingleCsv = async (assessment: Assessment) => {
    setActiveRowMenuId(null);
    setIsExporting(true);
    try {
      const findings = await firestoreService.getFindings(assessment.id);
      exportSingleAssessmentCsv(assessment, findings || []);
    } catch (err) {
      console.error('Error exporting assessment CSV:', err);
      exportSingleAssessmentCsv(assessment, []);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportSingleJson = async (assessment: Assessment) => {
    setActiveRowMenuId(null);
    setIsExporting(true);
    try {
      const findings = await firestoreService.getFindings(assessment.id);
      exportSingleAssessmentJson(assessment, findings || []);
    } catch (err) {
      console.error('Error exporting assessment JSON:', err);
      exportSingleAssessmentJson(assessment, []);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Hero Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-semibold">
              Reconnaissance Operations Center
            </span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Attack Surface Command Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Centralized orchestration across Subfinder, dnsx, httpx, Nmap, and WhatWeb. Validate authorized scope, correlate infrastructure assets, and map observable exposures.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* CSV / JSON Export Menu */}
          <div className="relative" ref={exportMenuRef}>
            <button
              onClick={() => setShowExportMenu(!showExportMenu)}
              disabled={assessments.length === 0 || isExporting}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-medium border transition-all shadow-sm ${
                assessments.length === 0 || isExporting
                  ? 'bg-slate-900 text-slate-600 border-slate-800 cursor-not-allowed'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700 cursor-pointer'
              }`}
              title="Download assessment metadata and findings summary in CSV or JSON format"
            >
              {isExporting ? (
                <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
              ) : (
                <Download className="w-4 h-4 text-cyan-400" />
              )}
              <span>{isExporting ? 'Exporting...' : 'Export Data'}</span>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {showExportMenu && (
              <div className="absolute right-0 mt-2 w-64 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl py-1.5 z-50 text-xs">
                <div className="px-3 py-1.5 text-[10px] font-mono text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  Export Metadata &amp; Findings
                </div>

                <button
                  onClick={handleExportMetadataCsv}
                  className="w-full text-left px-3.5 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <FileSpreadsheet className="w-4 h-4 text-emerald-400 shrink-0" />
                  <div>
                    <div className="font-semibold text-slate-200">Assessments Metadata (CSV)</div>
                    <div className="text-[10px] text-slate-500">Scopes, tool configs, and counts</div>
                  </div>
                </button>

                <button
                  onClick={handleExportFindingsCsv}
                  className="w-full text-left px-3.5 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <FileSpreadsheet className="w-4 h-4 text-amber-400 shrink-0" />
                  <div>
                    <div className="font-semibold text-slate-200">Findings Summary (CSV)</div>
                    <div className="text-[10px] text-slate-500">All observations &amp; remediation guides</div>
                  </div>
                </button>

                <div className="my-1 border-t border-slate-800" />

                <button
                  onClick={handleExportAllJson}
                  className="w-full text-left px-3.5 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Code className="w-4 h-4 text-cyan-400 shrink-0" />
                  <div>
                    <div className="font-semibold text-slate-200">Complete Dataset (JSON)</div>
                    <div className="text-[10px] text-slate-500">SIEM/SOAR compatible JSON export</div>
                  </div>
                </button>
              </div>
            )}
          </div>

          <button
            onClick={onSeedDemoLab}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700 transition-all shadow-sm cursor-pointer"
            title="Load an authorized OWASP Juice Shop lab fixture for coursework demonstration"
          >
            <Beaker className="w-4 h-4 text-cyan-400" />
            <span>Load Lab Demo Fixture</span>
          </button>

          <button
            onClick={onCreateNew}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all cursor-pointer"
          >
            <PlusCircle className="w-4 h-4" />
            <span>New Assessment</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        {statCards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className={`p-4 rounded-xl border ${card.bg} backdrop-blur flex flex-col justify-between`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-medium text-slate-400 leading-tight">
                  {card.label}
                </span>
                <Icon className={`w-4 h-4 ${card.color}`} />
              </div>
              <div className="text-2xl font-bold font-mono text-white">
                {loading ? '...' : card.value}
              </div>
            </div>
          );
        })}
      </div>

      {/* Assessment Table / Empty State */}
      <div className="bg-[#111827] rounded-xl border border-slate-800 overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-white">Recent Security Assessments</h3>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono">
              {assessments.length}
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500" /> {completedScans} Successful
            </span>
            {failedScans > 0 && (
              <span className="flex items-center gap-1 text-rose-400 ml-2">
                <span className="w-2 h-2 rounded-full bg-rose-500" /> {failedScans} Failed
              </span>
            )}
            {assessments.length > 0 && (
              <span className="text-[11px] text-slate-500 border-l border-slate-800 pl-3">
                Downloads enabled for CSV / JSON / PDF
              </span>
            )}
          </div>
        </div>

        {assessments.length === 0 ? (
          <div className="p-12 text-center flex flex-col items-center justify-center space-y-4">
            <div className="w-14 h-14 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
              <ShieldAlert className="w-7 h-7 text-blue-400" />
            </div>
            <div className="max-w-md">
              <h4 className="text-base font-semibold text-white">No Assessments Registered</h4>
              <p className="text-xs text-slate-400 mt-1">
                You haven't initiated any reconnaissance projects yet. Launch a new authorized assessment wizard or load a demonstration lab fixture to inspect attack surface mapping.
              </p>
            </div>
            <div className="flex items-center gap-3 pt-2">
              <button
                onClick={onCreateNew}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium shadow-md shadow-blue-500/20"
              >
                Launch Assessment Wizard
              </button>
              <button
                onClick={onSeedDemoLab}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700"
              >
                Load Demo Lab (Juice Shop)
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Assessment Name</th>
                  <th className="px-4 py-3">Target Scope</th>
                  <th className="px-4 py-3">Mode</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Discovered Assets</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3 text-right">Actions &amp; Export</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {assessments.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => onSelectAssessment(a.id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="px-4 py-3.5 font-medium text-white">
                      <div className="flex items-center gap-2">
                        <span className="group-hover:text-cyan-400 transition-colors">{a.name}</span>
                        {a.isDemo && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            DEMO LAB
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">{a.clientName || 'General Assessment'}</div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-cyan-300">
                      {a.scope.rootDomain}
                    </td>
                    <td className="px-4 py-3.5 capitalize">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {a.type}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      {getStatusBadge(a.status)}
                    </td>
                    <td className="px-4 py-3.5 font-mono">
                      <span className="text-white font-semibold">{a.stats?.assetsCount || 0}</span>
                      <span className="text-slate-500 text-[10px] ml-1">
                        ({a.stats?.subdomainsCount || 0} hosts, {a.stats?.endpointsCount || 0} eps)
                      </span>
                    </td>
                    <td className="px-4 py-3.5 font-mono">
                      <span className={`font-semibold ${a.stats?.findingsCount ? 'text-amber-400' : 'text-slate-500'}`}>
                        {a.stats?.findingsCount || 0}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 text-slate-400 text-[11px]">
                      {new Date(a.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        {/* PDF Download Button */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            generateAssessmentSummaryPdf({ assessment: a });
                          }}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 transition-all text-xs font-medium border border-slate-700 cursor-pointer"
                          title="Generate & Download Summary PDF Report"
                        >
                          <FileDown className="w-3.5 h-3.5" /> PDF
                        </button>

                        {/* CSV/JSON Download Dropdown for this Assessment */}
                        <div className="relative row-export-menu-container">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveRowMenuId(activeRowMenuId === a.id ? null : a.id);
                            }}
                            className="inline-flex items-center gap-0.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 hover:text-emerald-300 transition-all text-xs font-medium border border-slate-700 cursor-pointer"
                            title="Export metadata and findings as CSV or JSON"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <ChevronDown className="w-3 h-3 text-slate-400" />
                          </button>

                          {activeRowMenuId === a.id && (
                            <div className="absolute right-0 mt-1 w-44 bg-slate-900 border border-slate-700 rounded-lg shadow-xl py-1 z-50 text-left text-xs">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleExportSingleCsv(a);
                                }}
                                className="w-full text-left px-3 py-1.5 text-slate-200 hover:bg-slate-800 flex items-center gap-2"
                              >
                                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                                <span>Export CSV</span>
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleExportSingleJson(a);
                                }}
                                className="w-full text-left px-3 py-1.5 text-slate-200 hover:bg-slate-800 flex items-center gap-2"
                              >
                                <Code className="w-3.5 h-3.5 text-cyan-400" />
                                <span>Export JSON</span>
                              </button>
                            </div>
                          )}
                        </div>

                        {/* Inspect Button */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAssessment(a.id);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-blue-600 text-slate-300 hover:text-white transition-all text-xs font-medium cursor-pointer"
                        >
                          Inspect <ArrowRight className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Coursework & Methodological Disclaimers */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 flex items-start gap-3">
        <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">Ethical Reconnaissance Compliance:</span>{' '}
          All automated discovery routines operate exclusively within validated, pre-authorized root domains, IP allowlists, and designated port specifications. Real results are strictly distinguished from lab fixtures. ReconX does not perform destructive payloads or automated exploitation.
        </div>
      </div>
    </div>
  );
};
