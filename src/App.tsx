import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppShell, ActivePage } from './components/layout/AppShell';
import { Dashboard } from './pages/Dashboard';
import { AssessmentWizard } from './pages/AssessmentWizard';
import { AssessmentDetail } from './pages/AssessmentDetail';
import { AssessmentComparison } from './pages/AssessmentComparison';
import { ToolDiagnostics } from './pages/ToolDiagnostics';
import { AuditLogs } from './pages/AuditLogs';
import { LoginPage } from './pages/LoginPage';
import { SignupPage } from './pages/SignupPage';
import { AiAssistantPage } from './pages/AiAssistantPage';
import { GeminiChatbot } from './components/chat/GeminiChatbot';
import { firestoreService } from './services/firestoreService';
import { Assessment } from './types';
import { ShieldAlert, Shield, ArrowRight, Lock, CheckCircle2, UserPlus } from 'lucide-react';

const ReconXMain: React.FC = () => {
  const { user, profile, loading: authLoading, signInWithGoogle } = useAuth();
  const [activePage, setActivePage] = useState<ActivePage>('dashboard');
  const [authView, setAuthView] = useState<'landing' | 'login' | 'signup'>('landing');
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null);
  const [loadingAssessments, setLoadingAssessments] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch assessments when user is logged in
  useEffect(() => {
    let mounted = true;
    const fetchAssessments = async () => {
      if (!user) {
        setAssessments([]);
        return;
      }
      setLoadingAssessments(true);
      try {
        const list = await firestoreService.getAssessments(user.uid);
        if (mounted) {
          setAssessments(list);
          if (list.length > 0 && !selectedAssessmentId) {
            setSelectedAssessmentId(list[0].id);
          }
        }
      } catch (err) {
        console.error('Error fetching assessments:', err);
      } finally {
        if (mounted) setLoadingAssessments(false);
      }
    };
    fetchAssessments();

    return () => {
      mounted = false;
    };
  }, [user]);

  const handleAssessmentCreated = async (newAssessment: Assessment) => {
    try {
      await firestoreService.createAssessment(newAssessment);
      setAssessments((prev) => [newAssessment, ...prev]);
      setSelectedAssessmentId(newAssessment.id);
      setActivePage('detail');
    } catch (err) {
      console.error('Error creating assessment:', err);
    }
  };

  const handleUpdateAssessment = (updated: Assessment) => {
    setAssessments((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
  };

  // Seed authorized OWASP Juice Shop lab fixture for coursework demonstration
  const handleSeedDemoLab = async () => {
    const demoId = `demo_juiceshop_${Date.now()}`;
    const demoAssessment: Assessment = {
      id: demoId,
      name: 'OWASP Juice Shop — Coursework Lab Recon',
      clientName: 'Ethical Hacking Lab Environment',
      description: 'Authorized baseline reconnaissance for university course demonstration.',
      ownerId: user?.uid || 'guest_analyst',
      ownerEmail: user?.email || 'operator@reconx.local',
      type: 'mixed',
      status: 'queued',
      isDemo: true,
      scope: {
        rootDomain: 'juiceshop.lab.internal',
        approvedHostnames: [
          'api.juiceshop.lab.internal',
          'auth.juiceshop.lab.internal',
          'dev.juiceshop.lab.internal',
          'staging.juiceshop.lab.internal',
        ],
        approvedIpsAndCidrs: ['10.14.0.0/24'],
        permittedPorts: ['80', '443', '22', '3306', '8080'],
        startDate: '2026-10-01',
        endDate: '2026-11-01',
        authorizationConfirmed: true,
        authReference: 'COURSE-ETHICAL-HACK-LAB-01',
        authorizedBy: user?.email || 'Professor / Course Director',
      },
      toolConfig: {
        subfinder: true,
        dnsx: true,
        httpx: true,
        nmap: true,
        whatweb: true,
        concurrency: 10,
        rateLimit: 20,
        timeoutSeconds: 30,
        dnsRecordTypes: ['A', 'CNAME', 'MX', 'TXT'],
        nmapProfile: 'quick',
        executionEnvironment: 'lab_simulation',
      },
      stats: {
        assetsCount: 0,
        subdomainsCount: 0,
        dnsRecordsCount: 0,
        endpointsCount: 0,
        servicesCount: 0,
        technologiesCount: 0,
        findingsCount: 0,
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    if (user) {
      await firestoreService.createAssessment(demoAssessment);
    }
    setAssessments((prev) => [demoAssessment, ...prev]);
    setSelectedAssessmentId(demoAssessment.id);
    setActivePage('detail');
  };

  const handleDeleteAssessments = async (ids: string[]) => {
    if (user) {
      await firestoreService.deleteAssessmentsBatch(ids);
    }
    setAssessments((prev) => prev.filter((a) => !ids.includes(a.id)));
    if (selectedAssessmentId && ids.includes(selectedAssessmentId)) {
      setSelectedAssessmentId(null);
    }
  };

  const selectedAssessment = assessments.find((a) => a.id === selectedAssessmentId) || null;

  // Unauthenticated routing: Landing, Login, or Signup
  if (!user && !authLoading) {
    if (authView === 'login') {
      return (
        <LoginPage
          onNavigateToSignup={() => setAuthView('signup')}
          onNavigateToHome={() => setAuthView('landing')}
        />
      );
    }

    if (authView === 'signup') {
      return (
        <SignupPage
          onNavigateToLogin={() => setAuthView('login')}
          onNavigateToHome={() => setAuthView('landing')}
        />
      );
    }

    // Landing splash
    return (
      <div className="min-h-screen bg-[#0B1020] text-slate-100 flex flex-col justify-between selection:bg-blue-600 selection:text-white font-sans">
        <header className="h-16 border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between bg-[#111827]/80 backdrop-blur sticky top-0 z-20">
          <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => setAuthView('landing')}>
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold tracking-wider text-base text-white">
              RECON<span className="text-cyan-400">X</span>
            </span>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            <button
              onClick={() => setAuthView('login')}
              className="px-3 sm:px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-blue-500/20 transition-all cursor-pointer"
            >
              Sign In
            </button>
            <button
              onClick={() => setAuthView('signup')}
              className="px-3 sm:px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5"
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Create Account</span>
            </button>
          </div>
        </header>

        <div className="max-w-4xl mx-auto px-4 sm:px-6 py-10 sm:py-16 text-center space-y-5 sm:space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono max-w-full truncate">
            <Shield className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Ethical Hacking Coursework &amp; Reconnaissance Platform</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            Automated Reconnaissance &amp; <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-teal-300">
              Attack Surface Mapper
            </span>
          </h1>

          <p className="text-xs sm:text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Centralized orchestration across <strong className="text-slate-200">Subfinder</strong>,{' '}
            <strong className="text-slate-200">dnsx</strong>, <strong className="text-slate-200">httpx</strong>,{' '}
            <strong className="text-slate-200">Nmap</strong>, and <strong className="text-slate-200">WhatWeb</strong>.
            Safely discover hostnames, resolve DNS topologies, probe web endpoints, and visualize relationships on an interactive attack surface graph.
          </p>

          <div className="pt-2 sm:pt-4 flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4 w-full">
            <button
              onClick={() => setAuthView('login')}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs sm:text-sm font-semibold shadow-xl shadow-blue-600/25 transition-all cursor-pointer"
            >
              Sign In to Enter Console <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => setAuthView('signup')}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs sm:text-sm font-semibold shadow-xl shadow-cyan-600/20 transition-all cursor-pointer"
            >
              <UserPlus className="w-4 h-4" />
              <span>Create Operator Account</span>
            </button>
          </div>

          {/* Pillars preview */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-12 text-left">
            <div className="p-5 bg-[#111827] border border-slate-800 rounded-2xl">
              <div className="text-cyan-400 font-mono text-xs font-semibold mb-1">01. Centralized Tools</div>
              <h4 className="text-sm font-semibold text-white mb-1">Unified Multi-Scanner Pipeline</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Execute passive subdomain discovery, multi-threaded DNS resolution, HTTP probing, and service mapping.
              </p>
            </div>
            <div className="p-5 bg-[#111827] border border-slate-800 rounded-2xl">
              <div className="text-blue-400 font-mono text-xs font-semibold mb-1">02. Visual Topology</div>
              <h4 className="text-sm font-semibold text-white mb-1">Interactive Attack Surface Graph</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Connect domains, subdomains, IPs, web endpoints, ports, and detected technologies with zoom and inspect.
              </p>
            </div>
            <div className="p-5 bg-[#111827] border border-slate-800 rounded-2xl">
              <div className="text-emerald-400 font-mono text-xs font-semibold mb-1">03. Strict Governance</div>
              <h4 className="text-sm font-semibold text-white mb-1">Scope Validation &amp; Audit Trail</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Mandatory legal certification, out-of-scope rejection, and immutable cryptographic audit logging.
              </p>
            </div>
          </div>
        </div>

        <footer className="py-6 border-t border-slate-800/80 text-center text-xs text-slate-500 font-mono">
          ReconX • Discover. Map. Assess. Report. • Coursework Final Project
        </footer>
      </div>
    );
  }

  return (
    <AppShell
      activePage={activePage}
      setActivePage={setActivePage}
      selectedAssessmentId={selectedAssessmentId}
      onSelectAssessment={(id) => {
        setSelectedAssessmentId(id);
        setActivePage('detail');
      }}
      assessments={assessments}
      searchQuery={searchQuery}
      onSearchChange={setSearchQuery}
      onOpenLogin={() => setAuthView('login')}
      onOpenSignup={() => setAuthView('signup')}
    >
      {activePage === 'dashboard' && (
        <Dashboard
          assessments={assessments}
          searchQuery={searchQuery}
          onClearSearch={() => setSearchQuery('')}
          onSelectAssessment={(id) => {
            setSelectedAssessmentId(id);
            setActivePage('detail');
          }}
          onCreateNew={() => setActivePage('wizard')}
          onSeedDemoLab={handleSeedDemoLab}
          onDeleteAssessments={handleDeleteAssessments}
          loading={loadingAssessments}
        />
      )}

      {activePage === 'wizard' && (
        <AssessmentWizard
          onAssessmentCreated={handleAssessmentCreated}
          onCancel={() => setActivePage('dashboard')}
        />
      )}

      {activePage === 'detail' && selectedAssessment && (
        <AssessmentDetail
          assessment={selectedAssessment}
          onUpdateAssessment={handleUpdateAssessment}
          onBack={() => setActivePage('dashboard')}
        />
      )}

      {activePage === 'comparison' && (
        <AssessmentComparison
          assessments={assessments}
          onBack={() => setActivePage('dashboard')}
        />
      )}

      {activePage === 'diagnostics' && <ToolDiagnostics />}

      {activePage === 'audit' && <AuditLogs assessments={assessments} />}

      {activePage === 'ai-assistant' && (
        <AiAssistantPage
          currentAssessment={selectedAssessment}
          assessments={assessments}
          onSelectAssessment={(id) => {
            setSelectedAssessmentId(id);
            setActivePage('detail');
          }}
        />
      )}

      {/* Floating Gemini AI Copilot (visible across all non-full-page views) */}
      {activePage !== 'ai-assistant' && (
        <GeminiChatbot currentAssessment={selectedAssessment} />
      )}
    </AppShell>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <ReconXMain />
    </AuthProvider>
  );
}
