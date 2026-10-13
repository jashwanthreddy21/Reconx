import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import {
  ShieldAlert,
  LayoutDashboard,
  PlusCircle,
  FolderKanban,
  GitCompare,
  Wrench,
  FileText,
  History,
  LogOut,
  ChevronLeft,
  ChevronRight,
  User as UserIcon,
  Sparkles,
  Terminal,
  ExternalLink
} from 'lucide-react';
import { UserRole } from '../../types';

export type ActivePage =
  | 'dashboard'
  | 'wizard'
  | 'detail'
  | 'comparison'
  | 'diagnostics'
  | 'audit'
  | 'profile';

interface AppShellProps {
  activePage: ActivePage;
  setActivePage: (page: ActivePage) => void;
  selectedAssessmentId: string | null;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  activePage,
  setActivePage,
  selectedAssessmentId,
  children,
}) => {
  const { user, profile, signInWithGoogle, signOut, updateRole } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [showRoleMenu, setShowRoleMenu] = useState(false);

  const navItems = [
    { id: 'dashboard' as ActivePage, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'wizard' as ActivePage, label: 'New Assessment', icon: PlusCircle, roleRequired: 'analyst' },
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
  ];

  const getRoleBadgeColor = (role?: UserRole) => {
    switch (role) {
      case 'admin':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'analyst':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'viewer':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="min-h-screen bg-[#0B1020] text-slate-100 flex flex-col font-sans antialiased selection:bg-blue-600 selection:text-white">
      {/* Top Navbar */}
      <header className="h-14 bg-[#111827] border-b border-slate-800 flex items-center justify-between px-4 sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>

          <div
            onClick={() => setActivePage('dashboard')}
            className="flex items-center gap-2 cursor-pointer group"
          >
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:scale-105 transition-transform">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-wider text-base text-white">RECON<span className="text-cyan-400">X</span></span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 bg-blue-500/20 text-blue-300 border border-blue-500/30 rounded">
                  v1.0-SEC
                </span>
              </div>
              <p className="text-[10px] text-slate-400 leading-none hidden sm:block">
                Automated Reconnaissance &amp; Attack Surface Mapper
              </p>
            </div>
          </div>
        </div>

        {/* Right side: Auth & Operator Badge */}
        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-3">
              {/* Role Indicator with RBAC Switcher */}
              <div className="relative">
                <button
                  onClick={() => setShowRoleMenu(!showRoleMenu)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium rounded-md border ${getRoleBadgeColor(
                    profile?.role
                  )} hover:opacity-90 transition-opacity`}
                  title="Click to switch role for RBAC testing"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
                  ROLE: {profile?.role?.toUpperCase() || 'ANALYST'}
                </button>

                {showRoleMenu && (
                  <div className="absolute right-0 mt-2 w-48 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl py-1 z-50 text-xs">
                    <div className="px-3 py-1.5 text-[10px] font-mono text-slate-400 uppercase border-b border-slate-800">
                      RBAC Simulation Role
                    </div>
                    {(['admin', 'analyst', 'viewer'] as UserRole[]).map((r) => (
                      <button
                        key={r}
                        onClick={() => {
                          updateRole(r);
                          setShowRoleMenu(false);
                        }}
                        className={`w-full text-left px-3 py-1.5 capitalize hover:bg-slate-800 flex items-center justify-between ${
                          profile?.role === r ? 'text-cyan-400 font-semibold bg-slate-800/60' : 'text-slate-300'
                        }`}
                      >
                        {r}
                        {profile?.role === r && <span className="text-[10px]">● Active</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* User Avatar & Logout */}
              <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || 'Operator'}
                    className="w-7 h-7 rounded-full border border-slate-700"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-medium text-slate-300">
                    <UserIcon className="w-3.5 h-3.5" />
                  </div>
                )}
                <div className="hidden md:block text-left">
                  <div className="text-xs font-medium text-slate-200 leading-tight">
                    {user.displayName || user.email?.split('@')[0]}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">
                    {user.email}
                  </div>
                </div>

                <button
                  onClick={() => signOut()}
                  className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition-colors ml-1"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={() => signInWithGoogle()}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium shadow-md shadow-blue-500/20 transition-all cursor-pointer"
            >
              Sign In with Google
            </button>
          )}
        </div>
      </header>

      {/* Main Body with Sidebar */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside
          className={`bg-[#111827] border-r border-slate-800 flex flex-col justify-between transition-all duration-200 ${
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
                  onClick={() => setActivePage(item.id)}
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

          {/* Sidebar footer */}
          <div className="p-3 border-t border-slate-800/80">
            {!collapsed ? (
              <div className="bg-slate-900/80 rounded-lg p-2.5 border border-slate-800 text-[11px]">
                <div className="flex items-center gap-1.5 text-cyan-400 font-semibold mb-1">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Adapter Runtime</span>
                </div>
                <p className="text-slate-400 text-[10px] leading-relaxed">
                  Subfinder, dnsx, httpx, Nmap, WhatWeb
                </p>
                <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
                  <span>Engine: Active</span>
                  <span className="text-emerald-400">● 100% Ready</span>
                </div>
              </div>
            ) : (
              <div className="flex justify-center text-emerald-400" title="Engine: Active">
                ●
              </div>
            )}
          </div>
        </aside>

        {/* Content area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-[#0B1020]">
          {children}
        </main>
      </div>
    </div>
  );
};
