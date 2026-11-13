import React, { useState, useRef, useEffect, useMemo } from 'react';
import { useAuth } from '../../context/AuthContext';
import {
  ShieldAlert,
  LayoutDashboard,
  PlusCircle,
  FolderKanban,
  GitCompare,
  Wrench,
  History,
  LogOut,
  ChevronLeft,
  ChevronRight,
  User as UserIcon,
  Terminal,
  Menu,
  X,
  ShieldCheck,
  Shield,
  Search,
  Globe,
  Building2,
  ArrowRight,
  CheckCircle2,
  Activity,
  XCircle,
  Clock,
  Bot,
  Loader2,
  Server,
} from 'lucide-react';
import { Assessment, AssessmentStatus } from '../../types';
import {
  getCachedSubdomainMap,
  loadGlobalSubdomainIndex,
  queryGlobalSearchIndex,
  SubdomainSearchEntry,
} from '../../services/globalSearchService';

export type ActivePage =
  | 'dashboard'
  | 'wizard'
  | 'detail'
  | 'comparison'
  | 'diagnostics'
  | 'audit'
  | 'ai-assistant';

interface AppShellProps {
  activePage: ActivePage;
  setActivePage: (page: ActivePage) => void;
  selectedAssessmentId: string | null;
  onSelectAssessment?: (id: string) => void;
  assessments?: Assessment[];
  searchQuery?: string;
  onSearchChange?: (query: string) => void;
  onOpenLogin?: () => void;
  onOpenSignup?: () => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  activePage,
  setActivePage,
  selectedAssessmentId,
  onSelectAssessment,
  assessments = [],
  searchQuery,
  onSearchChange,
  onOpenLogin,
  onOpenSignup,
  children,
}) => {
  const { user, profile, signInWithGoogle, signOut } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Global search input state
  const [localSearch, setLocalSearch] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchScopeTab, setSearchScopeTab] = useState<'all' | 'assessments' | 'subdomains'>('all');
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const [subdomainsByAssessment, setSubdomainsByAssessment] = useState<
    Record<string, SubdomainSearchEntry[]>
  >({});
  const [isIndexingSubdomains, setIsIndexingSubdomains] = useState(false);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const currentQuery = searchQuery !== undefined ? searchQuery : localSearch;

  const handleSearchChange = (val: string) => {
    setLocalSearch(val);
    onSearchChange?.(val);
  };

  // Keep instant synchronous cache snapshot synced whenever assessments update
  useEffect(() => {
    if (assessments.length === 0) {
      setSubdomainsByAssessment({});
      return;
    }
    setSubdomainsByAssessment(getCachedSubdomainMap(assessments));
  }, [assessments]);

  // Lazily index discovered subdomains from Firestore when user focuses or queries global search
  useEffect(() => {
    if ((!isSearchOpen && !currentQuery.trim()) || assessments.length === 0) {
      return;
    }
    let cancelled = false;
    setIsIndexingSubdomains(true);

    loadGlobalSubdomainIndex(assessments)
      .then((indexedMap) => {
        if (!cancelled) {
          setSubdomainsByAssessment(indexedMap);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsIndexingSubdomains(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [isSearchOpen, currentQuery, assessments]);

  const totalIndexedSubdomains = useMemo(() => {
    return Object.values(subdomainsByAssessment).reduce(
      (sum, list) => sum + list.length,
      0
    );
  }, [subdomainsByAssessment]);

  // Execute unified search across assessment names, clients, root domains, and discovered subdomains
  const searchResults = useMemo(() => {
    return queryGlobalSearchIndex(currentQuery, assessments, subdomainsByAssessment);
  }, [currentQuery, assessments, subdomainsByAssessment]);

  const visibleAssessmentHits = useMemo(() => {
    if (searchScopeTab === 'subdomains') return [];
    return searchResults.assessmentHits;
  }, [searchResults.assessmentHits, searchScopeTab]);

  const visibleSubdomainHits = useMemo(() => {
    if (searchScopeTab === 'assessments') return [];
    return searchResults.subdomainHits.slice(0, 25);
  }, [searchResults.subdomainHits, searchScopeTab]);

  const flatSelectableAssessmentIds = useMemo(() => {
    return [
      ...visibleAssessmentHits.map((h) => h.assessment.id),
      ...visibleSubdomainHits.map((h) => h.entry.assessmentId),
    ];
  }, [visibleAssessmentHits, visibleSubdomainHits]);

  // Click outside listener for search dropdown
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        searchContainerRef.current &&
        !searchContainerRef.current.contains(e.target as Node)
      ) {
        setIsSearchOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Global keyboard shortcut: Cmd+K / Ctrl+K or "/" to focus search
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        setIsSearchOpen(true);
      } else if (
        e.key === '/' &&
        document.activeElement !== searchInputRef.current &&
        !['INPUT', 'TEXTAREA', 'SELECT'].includes(
          (document.activeElement as HTMLElement)?.tagName
        )
      ) {
        e.preventDefault();
        searchInputRef.current?.focus();
        setIsSearchOpen(true);
      } else if (e.key === 'Escape' && isSearchOpen) {
        setIsSearchOpen(false);
        searchInputRef.current?.blur();
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, [isSearchOpen]);

  // Keyboard navigation inside search dropdown
  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!isSearchOpen || flatSelectableAssessmentIds.length === 0) {
      if (e.key === 'ArrowDown') {
        setIsSearchOpen(true);
      }
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightedIndex((prev) =>
        prev < flatSelectableAssessmentIds.length - 1 ? prev + 1 : 0
      );
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightedIndex((prev) =>
        prev > 0 ? prev - 1 : flatSelectableAssessmentIds.length - 1
      );
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const targetId =
        highlightedIndex >= 0
          ? flatSelectableAssessmentIds[highlightedIndex]
          : flatSelectableAssessmentIds[0];
      if (targetId) {
        handleSelectAssessment(targetId);
      }
    } else if (e.key === 'Escape') {
      setIsSearchOpen(false);
      searchInputRef.current?.blur();
    }
  };

  const handleSelectAssessment = (id: string) => {
    if (onSelectAssessment) {
      onSelectAssessment(id);
    }
    setActivePage('detail');
    setIsSearchOpen(false);
    setMobileMenuOpen(false);
  };

  const highlightMatch = (text: string, query: string) => {
    const trimmed = query.trim();
    if (!trimmed || !text) return text;
    const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escaped})`, 'gi');
    const parts = text.split(regex);
    return parts.map((part, i) =>
      part.toLowerCase() === trimmed.toLowerCase() ? (
        <span
          key={i}
          className="bg-cyan-500/30 text-cyan-200 font-semibold rounded px-0.5"
        >
          {part}
        </span>
      ) : (
        part
      )
    );
  };

  const getMiniStatusBadge = (status: AssessmentStatus) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_5px_rgba(52,211,153,0.9)] shrink-0" />
            <CheckCircle2 className="w-2.5 h-2.5 text-emerald-400 shrink-0" /> Done
          </span>
        );
      case 'running':
      case 'validating':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs">
            <span className="relative flex h-1.5 w-1.5 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-cyan-400" />
            </span>
            <Activity className="w-2.5 h-2.5 text-cyan-400 animate-pulse shrink-0" /> Scanning
          </span>
        );
      case 'queued':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30 shadow-xs">
            <span className="relative flex h-1.5 w-1.5 shrink-0">
              <span className="animate-pulse absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-60" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-amber-400 shadow-[0_0_4px_rgba(251,191,36,0.9)]" />
            </span>
            <Clock className="w-2.5 h-2.5 text-amber-400 shrink-0" /> Queued
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-rose-500/15 text-rose-300 border border-rose-500/30 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-[0_0_5px_rgba(244,63,94,0.9)] shrink-0" />
            <XCircle className="w-2.5 h-2.5 text-rose-400 shrink-0" /> Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500 shrink-0" />
            <Clock className="w-2.5 h-2.5 shrink-0" /> {status}
          </span>
        );
    }
  };

  // Identify operator role badge (admin, researcher/viewer, or security analyst)
  const isAdmin =
    user?.email?.toLowerCase() === 'cybersafe07@gmail.com' ||
    profile?.role === 'admin';
  const isViewer = !isAdmin && profile?.role === 'viewer';
  const roleDisplay = isAdmin
    ? 'ADMINISTRATOR'
    : isViewer
    ? 'SECURITY RESEARCHER'
    : 'SECURITY ANALYST';
  const roleDisplayShort = isAdmin ? 'ADMIN' : isViewer ? 'VIEWER' : 'ANALYST';

  const navItems = [
    { id: 'dashboard' as ActivePage, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'wizard' as ActivePage, label: 'New Assessment', icon: PlusCircle },
    {
      id: 'detail' as ActivePage,
      label: 'Active Workspace',
      icon: FolderKanban,
      disabled: !selectedAssessmentId,
      badge: selectedAssessmentId ? '1 Active' : undefined,
    },
    { id: 'comparison' as ActivePage, label: 'Historical Diff', icon: GitCompare },
    { id: 'diagnostics' as ActivePage, label: 'Tool Diagnostics', icon: Wrench },
    { id: 'audit' as ActivePage, label: 'Audit Trail', icon: History },
    { id: 'ai-assistant' as ActivePage, label: 'AI Recon Copilot', icon: Bot, badge: 'Gemini' },
  ];

  const handleNavClick = (pageId: ActivePage) => {
    setActivePage(pageId);
    setMobileMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#0B1020] text-slate-100 flex flex-col font-sans antialiased selection:bg-blue-600 selection:text-white">
      {/* Top Navbar */}
      <header className="h-14 bg-[#111827] border-b border-slate-800 flex items-center justify-between px-2.5 sm:px-4 sticky top-0 z-30 gap-2 sm:gap-4">
        {/* Left: Hamburger + Collapse + Brand Logo */}
        <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
          {/* Mobile Hamburger Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title="Toggle Menu"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          {/* Desktop Collapse Button */}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden md:flex p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>

          {/* Brand Logo */}
          <div
            onClick={() => handleNavClick('dashboard')}
            className="flex items-center gap-2 cursor-pointer group shrink-0"
          >
            <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:scale-105 transition-transform">
              <ShieldAlert className="w-4 h-4 sm:w-5 sm:h-5 text-white" />
            </div>
            <div className="hidden xs:block">
              <div className="flex items-center gap-1.5 sm:gap-2">
                <span className="font-bold tracking-wider text-xs sm:text-base text-white">
                  RECON<span className="text-cyan-400">X</span>
                </span>
                <span className="text-[9px] sm:text-[10px] uppercase font-mono px-1.5 py-0.2 bg-blue-500/20 text-blue-300 border border-blue-500/30 rounded hidden sm:inline-block">
                  SEC-OPS
                </span>
              </div>
              <p className="text-[10px] text-slate-400 leading-none hidden xl:block">
                Automated Reconnaissance &amp; Attack Surface Mapper
              </p>
            </div>
          </div>
        </div>

        {/* Center: Global Search Input */}
        <div
          ref={searchContainerRef}
          className="flex-1 max-w-xs sm:max-w-md lg:max-w-xl min-w-0 relative mx-1 sm:mx-2 md:mx-4"
        >
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-slate-400 absolute left-2.5 sm:left-3 pointer-events-none" />
            <input
              ref={searchInputRef}
              type="text"
              value={currentQuery}
              onChange={(e) => {
                handleSearchChange(e.target.value);
                setIsSearchOpen(true);
                setHighlightedIndex(-1);
              }}
              onFocus={() => {
                setIsSearchOpen(true);
              }}
              onKeyDown={handleInputKeyDown}
              placeholder="Search assessments, clients, or subdomains..."
              className="w-full pl-8 sm:pl-9 pr-12 sm:pr-20 py-1.5 text-xs bg-slate-900/90 hover:bg-slate-900 focus:bg-slate-950 border border-slate-700/80 focus:border-cyan-500/80 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/40 transition-all shadow-inner"
              aria-label="Global search across assessment names, clients, and discovered subdomains"
            />
            <div className="absolute right-1.5 sm:right-2 flex items-center gap-1">
              {currentQuery ? (
                <button
                  onClick={() => {
                    handleSearchChange('');
                    setHighlightedIndex(-1);
                    searchInputRef.current?.focus();
                  }}
                  className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors cursor-pointer"
                  title="Clear search query"
                >
                  <X className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                </button>
              ) : (
                <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[9px] font-mono text-slate-400 bg-slate-800 border border-slate-700 rounded shadow-xs select-none">
                  ⌘K
                </kbd>
              )}
            </div>
          </div>

          {/* Search Dropdown / Unified Global Search Flyout */}
          {isSearchOpen && (
            <div className="absolute left-0 right-0 sm:right-auto sm:w-[520px] lg:w-[600px] top-full mt-2 bg-[#111827] border border-slate-700/90 rounded-xl shadow-2xl shadow-black/90 z-50 overflow-hidden divide-y divide-slate-800 backdrop-blur-md">
              {/* Dropdown Header */}
              <div className="px-3.5 py-2.5 bg-slate-900/90 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                <div className="flex items-center gap-2 min-w-0">
                  {currentQuery.trim() ? (
                    <span className="font-medium text-slate-300 truncate">
                      Global matches for{' '}
                      <strong className="text-cyan-400 font-mono">
                        "{currentQuery.trim()}"
                      </strong>
                    </span>
                  ) : (
                    <span className="font-medium text-slate-300">
                      Global Recon Index
                    </span>
                  )}
                  {isIndexingSubdomains && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono text-cyan-400 shrink-0">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Indexing subdomains...
                    </span>
                  )}
                </div>
                <span className="font-mono tabular-nums text-[11px] text-slate-400 whitespace-nowrap shrink-0">
                  {currentQuery.trim()
                    ? `${searchResults.assessmentHits.length} assessments · ${searchResults.subdomainHits.length} subdomains`
                    : `${assessments.length} assessments · ${totalIndexedSubdomains} subdomains`}
                </span>
              </div>

              {/* Category Tabs when query is active */}
              {currentQuery.trim().length > 0 && (
                <div className="px-3.5 py-2 bg-slate-950/60 flex items-center gap-1.5">
                  {[
                    {
                      id: 'all' as const,
                      label: 'All Matches',
                      count: searchResults.totalHits,
                    },
                    {
                      id: 'assessments' as const,
                      label: 'Assessments & Clients',
                      count: searchResults.assessmentHits.length,
                    },
                    {
                      id: 'subdomains' as const,
                      label: 'Discovered Subdomains',
                      count: searchResults.subdomainHits.length,
                    },
                  ].map((tab) => {
                    const active = searchScopeTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => {
                          setSearchScopeTab(tab.id);
                          setHighlightedIndex(-1);
                        }}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          active
                            ? 'bg-slate-800 text-white border border-slate-600'
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                        }`}
                      >
                        <span>{tab.label}</span>
                        <span className="font-mono tabular-nums text-[10px] text-slate-400">
                          {tab.count}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Results List */}
              <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/60">
                {!currentQuery.trim() ? (
                  assessments.length > 0 ? (
                    <div>
                      <div className="px-3.5 py-1.5 bg-slate-950/40 text-[11px] font-mono text-slate-400">
                        Recent Assessments ({Math.min(assessments.length, 5)} of {assessments.length})
                      </div>
                      {assessments.slice(0, 5).map((a) => (
                        <div
                          key={a.id}
                          onClick={() => handleSelectAssessment(a.id)}
                          className="p-3 cursor-pointer hover:bg-slate-800/60 transition-colors flex items-center justify-between gap-3 group"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="text-xs font-semibold text-white truncate group-hover:text-cyan-300">
                              {a.name}
                            </div>
                            <div className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5 truncate">
                              <span className="font-mono text-cyan-300">
                                {a.scope?.rootDomain}
                              </span>
                              <span aria-hidden="true">·</span>
                              <span>{a.clientName || 'General Assessment'}</span>
                              <span aria-hidden="true">·</span>
                              <span className="font-mono tabular-nums">
                                {a.stats?.subdomainsCount || 0} subdomains
                              </span>
                            </div>
                          </div>
                          <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 shrink-0" />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-6 text-center space-y-1.5">
                      <Search className="w-5 h-5 text-slate-500 mx-auto" />
                      <p className="text-xs text-slate-300 font-medium">
                        No assessments in index yet
                      </p>
                      <p className="text-[11px] text-slate-500">
                        Create an assessment or load the Demo Lab fixture to index clients and subdomains.
                      </p>
                    </div>
                  )
                ) : visibleAssessmentHits.length > 0 || visibleSubdomainHits.length > 0 ? (
                  <>
                    {/* Section 1: Assessments & Clients */}
                    {visibleAssessmentHits.length > 0 && (
                      <div>
                        <div className="px-3.5 py-1.5 bg-slate-950/50 text-[11px] font-medium text-slate-400 flex items-center justify-between">
                          <span>Assessments &amp; Clients</span>
                          <span className="font-mono tabular-nums text-[10px]">
                            {visibleAssessmentHits.length}
                          </span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {visibleAssessmentHits.map((hit, idx) => {
                            const a = hit.assessment;
                            const isHighlighted = idx === highlightedIndex;
                            return (
                              <div
                                key={a.id}
                                onClick={() => handleSelectAssessment(a.id)}
                                onMouseEnter={() => setHighlightedIndex(idx)}
                                className={`p-3 cursor-pointer transition-colors flex items-center justify-between gap-3 group ${
                                  isHighlighted
                                    ? 'bg-slate-800/80'
                                    : 'hover:bg-slate-800/50'
                                }`}
                              >
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                                    <span className="font-semibold text-xs text-white truncate max-w-[260px] group-hover:text-cyan-300 transition-colors">
                                      {highlightMatch(a.name, currentQuery)}
                                    </span>
                                    {a.isDemo && (
                                      <span className="text-[10px] font-mono text-amber-300">
                                        · Demo Lab
                                      </span>
                                    )}
                                    {getMiniStatusBadge(a.status)}
                                  </div>

                                  <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
                                    <span className="inline-flex items-center gap-1 text-cyan-300 font-mono">
                                      <Globe className="w-3 h-3 text-cyan-400 shrink-0" />
                                      {highlightMatch(a.scope?.rootDomain || '', currentQuery)}
                                    </span>
                                    <span aria-hidden="true">·</span>
                                    <span className="inline-flex items-center gap-1 text-slate-300">
                                      <Building2 className="w-3 h-3 text-slate-500 shrink-0" />
                                      {highlightMatch(a.clientName || 'General Assessment', currentQuery)}
                                    </span>
                                  </div>

                                  <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-500 font-mono tabular-nums flex-wrap">
                                    <span>{a.stats?.assetsCount || 0} assets</span>
                                    <span aria-hidden="true">·</span>
                                    <span className={a.stats?.findingsCount ? 'text-amber-400' : ''}>
                                      {a.stats?.findingsCount || 0} findings
                                    </span>
                                    {hit.matchedSubdomainCount > 0 && (
                                      <>
                                        <span aria-hidden="true">·</span>
                                        <span className="text-cyan-400">
                                          {hit.matchedSubdomainCount} matching subdomain
                                          {hit.matchedSubdomainCount === 1 ? '' : 's'}
                                        </span>
                                      </>
                                    )}
                                  </div>
                                </div>

                                <div className="shrink-0 flex items-center gap-1 text-cyan-400 text-xs font-medium opacity-80 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                                  <span className="hidden sm:inline text-[11px]">Workspace</span>
                                  <ArrowRight className="w-3.5 h-3.5" />
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Section 2: Discovered Subdomains */}
                    {visibleSubdomainHits.length > 0 && (
                      <div>
                        <div className="px-3.5 py-1.5 bg-slate-950/50 text-[11px] font-medium text-slate-400 flex items-center justify-between">
                          <span>Discovered Subdomains</span>
                          <span className="font-mono tabular-nums text-[10px]">
                            {searchResults.subdomainHits.length > 25
                              ? `Showing 25 of ${searchResults.subdomainHits.length}`
                              : searchResults.subdomainHits.length}
                          </span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {visibleSubdomainHits.map((hit, subIdx) => {
                            const entry = hit.entry;
                            const flatIdx = visibleAssessmentHits.length + subIdx;
                            const isHighlighted = flatIdx === highlightedIndex;
                            return (
                              <div
                                key={entry.id}
                                onClick={() => handleSelectAssessment(entry.assessmentId)}
                                onMouseEnter={() => setHighlightedIndex(flatIdx)}
                                className={`p-3 cursor-pointer transition-colors flex items-center justify-between gap-3 group ${
                                  isHighlighted
                                    ? 'bg-slate-800/80'
                                    : 'hover:bg-slate-800/50'
                                }`}
                              >
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <Server className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                                    <span className="font-mono text-xs font-medium text-white truncate group-hover:text-cyan-300">
                                      {highlightMatch(entry.subdomain, currentQuery)}
                                    </span>
                                    {entry.isExposedRisk && (
                                      <span className="text-[10px] font-mono text-amber-400 shrink-0">
                                        · Exposed
                                      </span>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-2 mt-1 text-[11px] text-slate-400 flex-wrap">
                                    <span className="truncate max-w-[200px] text-slate-300">
                                      {highlightMatch(entry.assessmentName, currentQuery)}
                                    </span>
                                    <span aria-hidden="true">·</span>
                                    <span className="truncate max-w-[160px]">
                                      {highlightMatch(entry.clientName, currentQuery)}
                                    </span>
                                    <span aria-hidden="true">·</span>
                                    <span className="font-mono text-slate-500">
                                      {entry.discoverySource}
                                    </span>
                                    {entry.ipAddress && (
                                      <>
                                        <span aria-hidden="true">·</span>
                                        <span className="font-mono tabular-nums text-cyan-300">
                                          {entry.ipAddress}
                                        </span>
                                      </>
                                    )}
                                  </div>
                                </div>

                                <div className="shrink-0 flex items-center gap-1 text-cyan-400 text-xs font-medium opacity-80 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                                  <span className="hidden sm:inline text-[11px]">Inspect</span>
                                  <ArrowRight className="w-3.5 h-3.5" />
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="p-6 text-center space-y-2.5">
                    <Search className="w-6 h-6 text-slate-500 mx-auto" />
                    <p className="text-xs text-slate-300 font-medium">
                      No assessments, clients, or subdomains matching "{currentQuery.trim()}"
                    </p>
                    <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                      Global search checks assessment names, client organizations, root domains, and all discovered subdomains.
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        handleSearchChange('');
                        setSearchScopeTab('all');
                        searchInputRef.current?.focus();
                      }}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-medium cursor-pointer"
                    >
                      Clear Search
                    </button>
                  </div>
                )}
              </div>

              {/* Dropdown Footer Actions */}
              <div className="p-2 bg-slate-900/90 flex items-center justify-between text-[11px] text-slate-400 px-3">
                <button
                  type="button"
                  onClick={() => {
                    setActivePage('dashboard');
                    setIsSearchOpen(false);
                  }}
                  className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors cursor-pointer flex items-center gap-1 whitespace-nowrap"
                >
                  <span>Filter in Dashboard</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
                <div className="hidden sm:flex items-center gap-2 text-[10px] text-slate-500 font-mono whitespace-nowrap">
                  <span>↑↓ navigate</span>
                  <span>·</span>
                  <span>↵ open</span>
                  <span>·</span>
                  <span>esc close</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right side: Auth & Operator Badge */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {user ? (
            <div className="flex items-center gap-2 sm:gap-3">
              {/* Authenticated Role Indicator Badge */}
              <div
                className={`flex items-center gap-1.5 px-2 sm:px-2.5 py-1 text-[10px] sm:text-xs font-mono font-semibold rounded-md border ${
                  isAdmin
                    ? 'bg-rose-500/15 text-rose-300 border-rose-500/40 shadow-sm shadow-rose-900/30'
                    : isViewer
                    ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40 shadow-sm shadow-cyan-900/30'
                    : 'bg-blue-500/15 text-blue-300 border-blue-500/40 shadow-sm shadow-blue-900/30'
                }`}
                title={
                  isAdmin
                    ? `Verified Administrator (${user.email})`
                    : `${isViewer ? 'Security Researcher' : 'Security Analyst'} (${user.email})`
                }
              >
                {isAdmin ? (
                  <ShieldCheck className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                ) : (
                  <Shield className={`w-3.5 h-3.5 ${isViewer ? 'text-cyan-400' : 'text-blue-400'} shrink-0`} />
                )}
                <span className="hidden sm:inline">{roleDisplay}</span>
                <span className="sm:hidden">{roleDisplayShort}</span>
              </div>

              {/* User Avatar & Logout */}
              <div className="flex items-center gap-1.5 sm:gap-2 pl-1.5 sm:pl-2 border-l border-slate-800">
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || 'Operator'}
                    className="w-6 h-6 sm:w-7 sm:h-7 rounded-full border border-slate-700"
                  />
                ) : (
                  <div className="w-6 h-6 sm:w-7 sm:h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-medium text-slate-300">
                    <UserIcon className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                  </div>
                )}
                <div className="hidden lg:block text-left max-w-[130px]">
                  <div className="text-xs font-medium text-slate-200 leading-tight truncate">
                    {user.displayName || user.email?.split('@')[0]}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono truncate">
                    {user.email}
                  </div>
                </div>

                <button
                  onClick={() => signOut()}
                  className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={() => onOpenLogin ? onOpenLogin() : signInWithGoogle()}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-blue-500/20 transition-all cursor-pointer"
              >
                Sign In
              </button>
              {onOpenSignup && (
                <button
                  onClick={onOpenSignup}
                  className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 rounded-lg text-xs font-semibold transition-all cursor-pointer"
                >
                  Sign Up
                </button>
              )}
            </div>
          )}
        </div>
      </header>

      {/* Mobile Drawer Overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={() => setMobileMenuOpen(false)}
          />

          {/* Drawer Body */}
          <aside className="relative w-72 max-w-[80vw] bg-[#111827] border-r border-slate-800 h-full p-4 flex flex-col justify-between shadow-2xl z-10">
            <div>
              <div className="flex items-center justify-between pb-4 mb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center">
                    <ShieldAlert className="w-4 h-4 text-white" />
                  </div>
                  <span className="font-bold text-white text-sm">RECONX NAVIGATION</span>
                </div>
                <button
                  onClick={() => setMobileMenuOpen(false)}
                  className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-1.5">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = activePage === item.id;
                  const isDisabled = item.disabled;

                  return (
                    <button
                      key={item.id}
                      disabled={isDisabled}
                      onClick={() => handleNavClick(item.id)}
                      className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                        isActive
                          ? 'bg-blue-600/20 text-cyan-400 border border-blue-500/40 font-semibold'
                          : isDisabled
                          ? 'text-slate-600 cursor-not-allowed opacity-40'
                          : 'text-slate-300 hover:text-white hover:bg-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                        <span>{item.label}</span>
                      </div>
                      {item.badge && (
                        <span className="text-[9px] px-1.5 py-0.5 bg-cyan-500/20 text-cyan-300 rounded font-mono">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Mobile Drawer Footer */}
            <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-2">
              <div className="flex items-center justify-between">
                <span>Current Role:</span>
                <span
                  className={`font-mono font-bold ${
                    isAdmin ? 'text-rose-400' : isViewer ? 'text-cyan-400' : 'text-blue-400'
                  }`}
                >
                  {roleDisplay}
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-500 text-[10px]">
                <span>Engine Status:</span>
                <span className="text-emerald-400">● 100% Operational</span>
              </div>
            </div>
          </aside>
        </div>
      )}

      {/* Main Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Desktop Collapsible Sidebar */}
        <aside
          className={`hidden md:flex bg-[#111827] border-r border-slate-800 flex-col justify-between transition-all duration-200 ${
            collapsed ? 'w-16' : 'w-60'
          }`}
        >
          <div className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              const isDisabled = item.disabled;

              return (
                <button
                  key={item.id}
                  disabled={isDisabled}
                  onClick={() => handleNavClick(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                      : isDisabled
                      ? 'text-slate-600 cursor-not-allowed opacity-50'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                  title={item.label}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                  {!collapsed && (
                    <div className="flex items-center justify-between w-full">
                      <span className="truncate">{item.label}</span>
                      {item.badge && (
                        <span className="text-[9px] px-1.5 py-0.5 bg-cyan-500/20 text-cyan-300 rounded font-mono">
                          {item.badge}
                        </span>
                      )}
                    </div>
                  )}
                </button>
              );
            })}
          </div>

          {/* Desktop Sidebar footer */}
          <div className="p-3 border-t border-slate-800/80">
            {!collapsed ? (
              <div className="bg-slate-900/80 rounded-lg p-2.5 border border-slate-800 text-[11px]">
                <div className="flex items-center gap-1.5 text-cyan-400 font-semibold mb-1">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Adapter Engine</span>
                </div>
                <p className="text-slate-400 text-[10px] leading-relaxed">
                  Subfinder, dnsx, httpx, Nmap, WhatWeb
                </p>
                <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
                  <span>Engine State:</span>
                  <span className="text-emerald-400">● Active</span>
                </div>
              </div>
            ) : (
              <div className="flex justify-center text-emerald-400 text-xs" title="Engine: Active">
                ●
              </div>
            )}
          </div>
        </aside>

        {/* Content area with full-width responsive padding */}
        <main className="flex-1 overflow-y-auto p-3 sm:p-5 lg:p-8 bg-[#0B1020] w-full max-w-full">
          {children}
        </main>
      </div>
    </div>
  );
};
