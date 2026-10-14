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
  Loader2,
  Search,
  X,
  Trash2,
  Filter,
  CheckSquare,
  Square,
  AlertOctagon,
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
  searchQuery?: string;
  onClearSearch?: () => void;
  onSelectAssessment: (id: string) => void;
  onCreateNew: () => void;
  onSeedDemoLab: () => void;
  onDeleteAssessments?: (ids: string[]) => Promise<void> | void;
  loading: boolean;
}

export const Dashboard: React.FC<Props> = ({
  assessments,
  searchQuery,
  onClearSearch,
  onSelectAssessment,
  onCreateNew,
  onSeedDemoLab,
  onDeleteAssessments,
  loading,
}) => {
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [activeRowMenuId, setActiveRowMenuId] = useState<string | null>(null);
  const exportMenuRef = useRef<HTMLDivElement>(null);

  // Status Filter State: 'all' | 'queued' | 'running' | 'completed' | 'failed'
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Multi-select Checkbox State
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

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

  // Clear selections that no longer exist when assessments change
  useEffect(() => {
    setSelectedIds((prev) => {
      const existing = new Set(assessments.map((a) => a.id));
      const next = new Set<string>();
      prev.forEach((id) => {
        if (existing.has(id)) next.add(id);
      });
      return next;
    });
  }, [assessments]);

  // Compute status counts for filter chips
  const statusCounts = React.useMemo(() => {
    return {
      all: assessments.length,
      queued: assessments.filter((a) => a.status === 'queued').length,
      running: assessments.filter((a) => a.status === 'running').length,
      completed: assessments.filter((a) => a.status === 'completed').length,
      failed: assessments.filter((a) => a.status === 'failed').length,
    };
  }, [assessments]);

  // Filter assessments by status AND search query
  const filteredAssessments = React.useMemo(() => {
    return assessments.filter((a) => {
      // 1. Status Filter
      if (statusFilter !== 'all') {
        if (a.status !== statusFilter) return false;
      }
      // 2. Search Query Filter
      if (!searchQuery?.trim()) return true;
      const q = searchQuery.trim().toLowerCase();
      const clientMatch = a.clientName?.toLowerCase().includes(q);
      const domainMatch = a.scope?.rootDomain?.toLowerCase().includes(q);
      const nameMatch = a.name?.toLowerCase().includes(q);
      const hostnamesMatch = a.scope?.approvedHostnames?.some((h) =>
        h.toLowerCase().includes(q)
      );
      return clientMatch || domainMatch || nameMatch || hostnamesMatch;
    });
  }, [assessments, searchQuery, statusFilter]);

  // Multi-select handlers
  const isAllFilteredSelected =
    filteredAssessments.length > 0 &&
    filteredAssessments.every((a) => selectedIds.has(a.id));

  const isSomeFilteredSelected =
    filteredAssessments.some((a) => selectedIds.has(a.id)) && !isAllFilteredSelected;

  const toggleSelectAllFiltered = () => {
    if (isAllFilteredSelected) {
      // Unselect all currently filtered
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredAssessments.forEach((a) => next.delete(a.id));
        return next;
      });
    } else {
      // Select all currently filtered
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredAssessments.forEach((a) => next.add(a.id));
        return next;
      });
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const clearSelection = () => {
    setSelectedIds(new Set());
  };

  // Perform bulk delete
  const handleConfirmDelete = async () => {
    const idsToDelete = Array.from(selectedIds);
    if (idsToDelete.length === 0) return;
    setIsDeleting(true);
    try {
      if (onDeleteAssessments) {
        await onDeleteAssessments(idsToDelete);
      } else {
        await firestoreService.deleteAssessmentsBatch(idsToDelete);
      }
      setSelectedIds(new Set());
      setShowDeleteModal(false);
    } catch (err) {
      console.error('Failed to delete assessments:', err);
    } finally {
      setIsDeleting(false);
    }
  };

  const highlightMatch = (text: string, query?: string) => {
    const q = query?.trim();
    if (!q || !text) return text;
    const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escaped})`, 'gi');
    const parts = text.split(regex);
    return parts.map((part, i) =>
      part.toLowerCase() === q.toLowerCase() ? (
        <span key={i} className="bg-cyan-500/30 text-cyan-200 font-semibold rounded px-0.5">
          {part}
        </span>
      ) : (
        part
      )
    );
  };

  // Aggregate statistics
  const totalAssessments = assessments.length;
  const totalAssets = assessments.reduce((acc, a) => acc + (a.stats?.assetsCount || 0), 0);
  const totalSubdomains = assessments.reduce((acc, a) => acc + (a.stats?.subdomainsCount || 0), 0);
  const totalEndpoints = assessments.reduce((acc, a) => acc + (a.stats?.endpointsCount || 0), 0);
  const totalServices = assessments.reduce((acc, a) => acc + (a.stats?.servicesCount || 0), 0);
  const totalFindings = assessments.reduce((acc, a) => acc + (a.stats?.findingsCount || 0), 0);

  const completedScans = assessments.filter((a) => a.status === 'completed').length;
  const runningScans = assessments.filter((a) => a.status === 'running' || a.status === 'validating').length;
  const queuedScans = assessments.filter((a) => a.status === 'queued').length;
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

  // Visual status indicator dot for scans (Queued, Running, Completed, Failed, etc.)
  const renderStatusDot = (status: Assessment['status'], animated = true) => {
    switch (status) {
      case 'running':
      case 'validating':
        return (
          <span
            className="relative flex h-2.5 w-2.5 shrink-0"
            title={`Scan Status: ${status === 'running' ? 'Running / Scanning in progress' : 'Validating Scope'}`}
          >
            {animated && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
            )}
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.9)]" />
          </span>
        );
      case 'queued':
        return (
          <span
            className="relative flex h-2.5 w-2.5 shrink-0"
            title="Scan Status: Queued (Waiting to run)"
          >
            {animated && (
              <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-60" />
            )}
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.85)]" />
          </span>
        );
      case 'completed':
        return (
          <span
            className="inline-flex h-2.5 w-2.5 shrink-0 rounded-full bg-emerald-400 shadow-[0_0_7px_rgba(52,211,153,0.85)] ring-1 ring-emerald-500/40"
            title="Scan Status: Completed"
          />
        );
      case 'partially_completed':
        return (
          <span
            className="inline-flex h-2.5 w-2.5 shrink-0 rounded-full bg-teal-400 shadow-[0_0_6px_rgba(45,212,191,0.8)]"
            title="Scan Status: Partially Completed"
          />
        );
      case 'failed':
        return (
          <span
            className="inline-flex h-2.5 w-2.5 shrink-0 rounded-full bg-rose-500 shadow-[0_0_7px_rgba(244,63,94,0.85)] ring-1 ring-rose-500/40"
            title="Scan Status: Failed"
          />
        );
      case 'cancelled':
      case 'draft':
      default:
        return (
          <span
            className="inline-flex h-2.5 w-2.5 shrink-0 rounded-full bg-slate-500 ring-1 ring-slate-600/40"
            title={`Scan Status: ${status || 'Draft'}`}
          />
        );
    }
  };

  const getStatusBadge = (status: Assessment['status']) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_5px_rgba(52,211,153,0.9)] shrink-0" />
            <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
            <span>Completed</span>
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-xs">
            <span className="relative flex h-2 w-2 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
            </span>
            <Activity className="w-3 h-3 text-cyan-400 animate-pulse shrink-0" />
            <span>Running</span>
          </span>
        );
      case 'validating':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-blue-500/10 text-blue-300 border border-blue-500/30 shadow-xs">
            <span className="relative flex h-2 w-2 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-400" />
            </span>
            <Loader2 className="w-3 h-3 text-blue-400 animate-spin shrink-0" />
            <span>Validating</span>
          </span>
        );
      case 'queued':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-amber-500/10 text-amber-300 border border-amber-500/30 shadow-xs">
            <span className="relative flex h-2 w-2 shrink-0">
              <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-60" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-400 shadow-[0_0_4px_rgba(251,191,36,0.9)]" />
            </span>
            <Clock className="w-3 h-3 text-amber-400 shrink-0" />
            <span>Queued</span>
          </span>
        );
      case 'partially_completed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-teal-500/10 text-teal-300 border border-teal-500/30 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shrink-0" />
            <AlertTriangle className="w-3 h-3 text-teal-400 shrink-0" />
            <span>Partial</span>
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-300 border border-rose-500/30 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-[0_0_5px_rgba(244,63,94,0.9)] shrink-0" />
            <XCircle className="w-3 h-3 text-rose-400 shrink-0" />
            <span>Failed</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500 shrink-0" />
            <Clock className="w-3 h-3 shrink-0" />
            <span className="capitalize">{status}</span>
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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 p-4 sm:p-6 rounded-xl sm:rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-semibold">
              Reconnaissance Operations Center
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Attack Surface Command Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Centralized orchestration across Subfinder, dnsx, httpx, Nmap, and WhatWeb. Validate authorized scope, correlate infrastructure assets, and map observable exposures.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full md:w-auto">
          {/* CSV / JSON Export Menu */}
          <div className="relative" ref={exportMenuRef}>
            <button
              onClick={() => setShowExportMenu(!showExportMenu)}
              disabled={assessments.length === 0 || isExporting}
              className={`flex items-center gap-1.5 px-3 sm:px-3.5 py-2 rounded-xl text-xs font-medium border transition-all shadow-sm ${
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
              {searchQuery?.trim()
                ? `${filteredAssessments.length} of ${assessments.length}`
                : assessments.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.7)] shrink-0" />
              <span>{completedScans} Completed</span>
            </span>
            {runningScans > 0 && (
              <span className="flex items-center gap-1.5 text-cyan-300">
                <span className="relative flex h-2 w-2 shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
                </span>
                <span>{runningScans} Running</span>
              </span>
            )}
            {queuedScans > 0 && (
              <span className="flex items-center gap-1.5 text-amber-300">
                <span className="w-2 h-2 rounded-full bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.7)] shrink-0" />
                <span>{queuedScans} Queued</span>
              </span>
            )}
            {failedScans > 0 && (
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.7)] shrink-0" />
                <span>{failedScans} Failed</span>
              </span>
            )}
            {assessments.length > 0 && (
              <span className="text-[11px] text-slate-500 border-l border-slate-800 pl-3 hidden sm:inline">
                Color-coded indicators show scan progress
              </span>
            )}
          </div>
        </div>

        {/* Status Filter Chips Bar */}
        <div className="px-4 py-2.5 bg-slate-900/40 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <div className="flex items-center gap-1 text-[11px] font-mono text-slate-400 mr-1.5">
              <Filter className="w-3.5 h-3.5 text-cyan-400" />
              <span>Status Filter:</span>
            </div>

            {[
              { key: 'all', label: 'All', count: statusCounts.all, dot: null },
              { key: 'completed', label: 'Completed', count: statusCounts.completed, dot: 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]' },
              { key: 'running', label: 'Running', count: statusCounts.running, dot: 'bg-cyan-400 animate-ping' },
              { key: 'queued', label: 'Queued', count: statusCounts.queued, dot: 'bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.9)]' },
              { key: 'failed', label: 'Failed', count: statusCounts.failed, dot: 'bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.9)]' },
            ].map((chip) => {
              const active = statusFilter === chip.key;
              return (
                <button
                  key={chip.key}
                  onClick={() => setStatusFilter(chip.key)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    active
                      ? 'bg-blue-600/30 text-white border border-blue-500/60 shadow-sm'
                      : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-700/60'
                  }`}
                >
                  {chip.dot && <span className={`w-1.5 h-1.5 rounded-full ${chip.dot}`} />}
                  <span>{chip.label}</span>
                  <span
                    className={`text-[10px] font-mono px-1 rounded ${
                      active ? 'bg-blue-500/30 text-blue-200 font-semibold' : 'bg-slate-700/60 text-slate-400'
                    }`}
                  >
                    {chip.count}
                  </span>
                </button>
              );
            })}

            {statusFilter !== 'all' && (
              <button
                onClick={() => setStatusFilter('all')}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 hover:underline ml-1 cursor-pointer font-medium"
              >
                Reset Filter
              </button>
            )}
          </div>

          {/* Selection indicator if active */}
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2 text-xs">
              <span className="font-semibold text-cyan-300 font-mono">
                {selectedIds.size} selected
              </span>
              <button
                onClick={clearSelection}
                className="text-slate-400 hover:text-slate-200 text-[11px] hover:underline cursor-pointer"
              >
                Clear
              </button>
            </div>
          )}
        </div>

        {/* Bulk Selection Actions Floating/Sticky Bar */}
        {selectedIds.size > 0 && (
          <div className="mx-4 my-2.5 p-2.5 rounded-xl bg-blue-950/50 border border-blue-700/60 flex flex-wrap items-center justify-between gap-3 shadow-lg">
            <div className="flex items-center gap-2 text-xs text-blue-200">
              <CheckSquare className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong className="text-white">{selectedIds.size}</strong> assessment{selectedIds.size > 1 ? 's' : ''} selected
              </span>
              <span className="text-slate-400 text-[11px]">
                ({filteredAssessments.length} matching current filter)
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={toggleSelectAllFiltered}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs border border-slate-700 transition-colors cursor-pointer"
              >
                {isAllFilteredSelected ? 'Deselect All' : `Select All Shown (${filteredAssessments.length})`}
              </button>

              <button
                onClick={() => setShowDeleteModal(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-md shadow-rose-600/30 transition-all cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Delete Selected ({selectedIds.size})</span>
              </button>
            </div>
          </div>
        )}

        {/* Global Search Filter Active Notice */}
        {searchQuery?.trim() && (
          <div className="mx-4 mt-3 mb-1 px-3 py-2 rounded-lg bg-cyan-950/40 border border-cyan-800/60 flex items-center justify-between text-xs text-cyan-300">
            <div className="flex items-center gap-2">
              <Search className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>
                Filtered by client or domain: <strong className="text-white font-mono">"{searchQuery.trim()}"</strong> ({filteredAssessments.length} matching)
              </span>
            </div>
            {onClearSearch && (
              <button
                onClick={onClearSearch}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-200 hover:underline cursor-pointer"
              >
                <X className="w-3 h-3" /> Clear filter
              </button>
            )}
          </div>
        )}

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
        ) : filteredAssessments.length === 0 ? (
          <div className="p-12 text-center flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
              <Search className="w-6 h-6 text-cyan-400" />
            </div>
            <div className="max-w-md">
              <h4 className="text-sm font-semibold text-white">No Matching Assessments</h4>
              <p className="text-xs text-slate-400 mt-1">
                {statusFilter !== 'all' ? (
                  <>
                    No assessments with status <span className="text-cyan-400 font-mono capitalize">"{statusFilter}"</span>
                    {searchQuery?.trim() && <> and search query <span className="text-cyan-400 font-mono">"{searchQuery}"</span></>}.
                  </>
                ) : (
                  <>No assessments match query "<span className="text-cyan-400 font-mono">{searchQuery}</span>".</>
                )}
              </p>
            </div>
            <div className="flex items-center gap-2 pt-1">
              {statusFilter !== 'all' && (
                <button
                  onClick={() => setStatusFilter('all')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs rounded-lg border border-slate-700 font-medium transition-colors cursor-pointer"
                >
                  Show All Statuses
                </button>
              )}
              {onClearSearch && searchQuery?.trim() && (
                <button
                  onClick={onClearSearch}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700 font-medium transition-colors cursor-pointer"
                >
                  Reset Search Filter
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                <tr>
                  {/* Select All Checkbox Header */}
                  <th className="px-3 py-3 w-10 text-center">
                    <input
                      type="checkbox"
                      checked={isAllFilteredSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = isSomeFilteredSelected;
                      }}
                      onChange={toggleSelectAllFiltered}
                      className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 cursor-pointer accent-blue-600"
                      title={isAllFilteredSelected ? 'Deselect all' : 'Select all shown'}
                    />
                  </th>
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
                {filteredAssessments.map((a) => {
                  const isSelected = selectedIds.has(a.id);
                  return (
                    <tr
                      key={a.id}
                      onClick={() => onSelectAssessment(a.id)}
                      className={`transition-colors cursor-pointer group ${
                        isSelected
                          ? 'bg-blue-950/30 hover:bg-blue-950/40'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      {/* Row Checkbox */}
                      <td
                        className="px-3 py-3.5 text-center"
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleSelectOne(a.id);
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 cursor-pointer accent-blue-600"
                          aria-label={`Select assessment ${a.name}`}
                        />
                      </td>
                    <td className="px-4 py-3.5 font-medium text-white">
                      <div className="flex items-center gap-2.5">
                        {/* Visual Status Indicator Dot (Queued, Running, Completed, Failed) */}
                        {renderStatusDot(a.status)}
                        <span className="group-hover:text-cyan-400 transition-colors font-medium">
                          {highlightMatch(a.name, searchQuery)}
                        </span>
                        {a.isDemo && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30 shrink-0">
                            DEMO LAB
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5 pl-5">
                        {highlightMatch(a.clientName || 'General Assessment', searchQuery)}
                      </div>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-cyan-300">
                      {highlightMatch(a.scope.rootDomain, searchQuery)}
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
                );
              })}
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

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-[#111827] border border-slate-700 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-500/20 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
                <AlertOctagon className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-base font-bold text-white">Delete Selected Assessments?</h4>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Are you sure you want to delete <strong className="text-white">{selectedIds.size}</strong> selected assessment{selectedIds.size > 1 ? 's' : ''}?
                  This action will permanently delete all associated assets, discovered endpoints, and findings. This cannot be undone.
                </p>
              </div>
            </div>

            <div className="max-h-36 overflow-y-auto bg-slate-950/80 rounded-xl p-3 border border-slate-800 space-y-1.5 text-xs font-mono">
              {assessments
                .filter((a) => selectedIds.has(a.id))
                .map((a) => (
                  <div key={a.id} className="flex items-center justify-between text-slate-300">
                    <div className="flex items-center gap-2 truncate max-w-[240px]">
                      {renderStatusDot(a.status, false)}
                      <span className="truncate text-white">{a.name}</span>
                    </div>
                    <span className="text-slate-500 text-[11px]">{a.scope?.rootDomain}</span>
                  </div>
                ))}
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                disabled={isDeleting}
                onClick={() => setShowDeleteModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                disabled={isDeleting}
                onClick={handleConfirmDelete}
                className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold shadow-lg shadow-rose-600/30 transition-all flex items-center gap-2 cursor-pointer"
              >
                {isDeleting ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Deleting...</span>
                  </>
                ) : (
                  <>
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Confirm Delete ({selectedIds.size})</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
