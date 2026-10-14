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
  Sparkles,
} from 'lucide-react';
import { UserRole, Assessment, AssessmentStatus } from '../../types';

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
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const currentQuery = searchQuery !== undefined ? searchQuery : localSearch;

  const handleSearchChange = (val: string) => {
    setLocalSearch(val);
    onSearchChange?.(val);
  };

  // Filter assessments by client name or domain (rootDomain / approved hostnames) or name
  const filteredAssessments = useMemo(() => {
    const q = currentQuery.trim().toLowerCase();
    if (!q || !assessments || assessments.length === 0) return [];
    return assessments.filter((a) => {
      const clientMatch = a.clientName?.toLowerCase().includes(q);
      const domainMatch = a.scope?.rootDomain?.toLowerCase().includes(q);
      const nameMatch = a.name?.toLowerCase().includes(q);
      const hostnamesMatch = a.scope?.approvedHostnames?.some((h) =>
        h.toLowerCase().includes(q)
      );
      return clientMatch || domainMatch || nameMatch || hostnamesMatch;
    });
  }, [assessments, currentQuery]);

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
    if (!isSearchOpen || filteredAssessments.length === 0) {
      if (e.key === 'ArrowDown') {
        setIsSearchOpen(true);
      }
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightedIndex((prev) =>
        prev < filteredAssessments.length - 1 ? prev + 1 : 0
      );
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightedIndex((prev) =>
        prev > 0 ? prev - 1 : filteredAssessments.length - 1
      );
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const target =
        highlightedIndex >= 0
          ? filteredAssessments[highlightedIndex]
          : filteredAssessments[0];
      if (target) {
        handleSelectAssessment(target.id);
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

  // Strictly identify if the current credentials belong to Administrator
  const isAdmin = user?.email?.toLowerCase() === 'cybersafe07@gmail.com';
  const roleDisplay = isAdmin ? 'ADMINISTRATOR' : 'SECURITY ANALYST';
  const roleDisplayShort = isAdmin ? 'ADMIN' : 'ANALYST';

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
                if (currentQuery.trim()) {
                  setIsSearchOpen(true);
                }
              }}
              onKeyDown={handleInputKeyDown}
              placeholder="Search assessments by client or domain..."
              className="w-full pl-8 sm:pl-9 pr-12 sm:pr-20 py-1.5 text-xs bg-slate-900/90 hover:bg-slate-900 focus:bg-slate-950 border border-slate-700/80 focus:border-cyan-500/80 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/40 transition-all shadow-inner"
              aria-label="Filter assessments by client name or domain"
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

          {/* Search Dropdown / Live Results Flyout */}
          {isSearchOpen && currentQuery.trim().length > 0 && (
            <div className="absolute left-0 right-0 sm:right-auto sm:w-[480px] lg:w-[540px] top-full mt-2 bg-[#111827] border border-slate-700/90 rounded-xl shadow-2xl shadow-black/90 z-50 overflow-hidden divide-y divide-slate-800 backdrop-blur-md">
              {/* Dropdown Header */}
              <div className="px-3.5 py-2 bg-slate-900/90 flex items-center justify-between text-[11px] text-slate-400">
                <span className="font-medium text-slate-300">
                  Assessments matching <strong className="text-cyan-400 font-mono">"{currentQuery.trim()}"</strong>
                </span>
                <span className="font-mono text-[10px] px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded border border-slate-700">
                  {filteredAssessments.length} found
                </span>
              </div>

              {/* Results List */}
              <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
                {filteredAssessments.length > 0 ? (
                  filteredAssessments.map((a, idx) => {
                    const isHighlighted = idx === highlightedIndex;
                    return (
                      <div
                        key={a.id}
                        onClick={() => handleSelectAssessment(a.id)}
                        onMouseEnter={() => setHighlightedIndex(idx)}
                        className={`p-3 cursor-pointer transition-colors flex items-center justify-between gap-3 group ${
                          isHighlighted
                            ? 'bg-cyan-950/40 border-l-2 border-cyan-400'
                            : 'hover:bg-slate-800/60'
                        }`}
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <span className="font-semibold text-xs text-white truncate max-w-[200px] sm:max-w-[260px] group-hover:text-cyan-300 transition-colors">
                              {highlightMatch(a.name, currentQuery)}
                            </span>
                            {a.isDemo && (
                              <span className="px-1.5 py-0.2 text-[9px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded">
                                DEMO LAB
                              </span>
                            )}
                            {getMiniStatusBadge(a.status)}
                          </div>

                          <div className="flex items-center gap-3 text-[11px] text-slate-400 flex-wrap">
                            {/* Domain match */}
                            <div className="flex items-center gap-1 text-cyan-300 font-mono">
                              <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                              <span>{highlightMatch(a.scope?.rootDomain || '', currentQuery)}</span>
                            </div>

                            {/* Client match */}
                            <div className="flex items-center gap-1 text-slate-300">
                              <Building2 className="w-3 h-3 text-slate-500 shrink-0" />
                              <span>Client: {highlightMatch(a.clientName || 'General', currentQuery)}</span>
                            </div>
                          </div>

                          <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-500 font-mono">
                            <span>{a.stats?.assetsCount || 0} assets</span>
                            <span>•</span>
                            <span className={a.stats?.findingsCount ? 'text-amber-400 font-medium' : ''}>
                              {a.stats?.findingsCount || 0} findings
                            </span>
                            <span>•</span>
                            <span>{new Date(a.createdAt).toLocaleDateString()}</span>
                          </div>
                        </div>

                        <div className="shrink-0 flex items-center gap-1 text-cyan-400 text-xs font-medium opacity-80 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all">
                          <span className="hidden sm:inline text-[11px]">Workspace</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="p-6 text-center space-y-2">
                    <Search className="w-6 h-6 text-slate-500 mx-auto" />
                    <p className="text-xs text-slate-300 font-medium">
                      No assessments matching "{currentQuery.trim()}"
                    </p>
                    <p className="text-[11px] text-slate-500 max-w-xs mx-auto">
                      Search checks client names (e.g. Ethical Hacking) or target root domains (e.g. srux.in).
                    </p>
                  </div>
                )}
              </div>

              {/* Dropdown Footer Actions */}
              <div className="p-2 bg-slate-900/90 flex items-center justify-between text-[11px] text-slate-400 px-3">
                <button
                  onClick={() => {
                    setActivePage('dashboard');
                    setIsSearchOpen(false);
                  }}
                  className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors cursor-pointer flex items-center gap-1"
                >
                  <span>Filter in Dashboard</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
                <div className="hidden sm:flex items-center gap-2 text-[10px] text-slate-500 font-mono">
                  <span>↑↓ navigate</span>
                  <span>↵ select</span>
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
                    : 'bg-blue-500/15 text-blue-300 border-blue-500/40 shadow-sm shadow-blue-900/30'
                }`}
                title={
                  isAdmin
                    ? 'Verified Administrator (cybersafe07@gmail.com)'
                    : `Security Analyst (${user.email})`
                }
              >
                {isAdmin ? (
                  <ShieldCheck className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                ) : (
                  <Shield className="w-3.5 h-3.5 text-blue-400 shrink-0" />
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
                <span className={`font-mono font-bold ${isAdmin ? 'text-rose-400' : 'text-blue-400'}`}>
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
