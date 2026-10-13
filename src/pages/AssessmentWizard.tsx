import React, { useState } from 'react';
import { Assessment, ScopeRule, ToolConfig, AssessmentType } from '../types';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Server,
  Globe,
  Sliders,
  Check,
  Terminal,
  FileCheck,
  Lock
} from 'lucide-react';

interface Props {
  onAssessmentCreated: (assessment: Assessment) => void;
  onCancel: () => void;
}

export const AssessmentWizard: React.FC<Props> = ({ onAssessmentCreated, onCancel }) => {
  const { user, profile } = useAuth();
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5>(1);

  // Form State
  const [name, setName] = useState('');
  const [clientName, setClientName] = useState('');
  const [description, setDescription] = useState('');
  const [type, setType] = useState<AssessmentType>('mixed');

  // Scope
  const [rootDomain, setRootDomain] = useState('');
  const [approvedHostnamesRaw, setApprovedHostnamesRaw] = useState('');
  const [approvedIpsRaw, setApprovedIpsRaw] = useState('');
  const [permittedPortsRaw, setPermittedPortsRaw] = useState('80, 443, 22, 53, 8080');
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [authReference, setAuthReference] = useState('');
  const [startDate, setStartDate] = useState(new Date().toISOString().split('T')[0]);
  const [endDate, setEndDate] = useState(
    new Date(Date.now() + 7 * 86400000).toISOString().split('T')[0]
  );

  // Tool Selection
  const [tools, setTools] = useState({
    subfinder: true,
    dnsx: true,
    httpx: true,
    nmap: true,
    whatweb: true,
  });

  // Scan Config
  const [concurrency, setConcurrency] = useState(10);
  const [rateLimit, setRateLimit] = useState(25);
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);
  const [dnsTypes, setDnsTypes] = useState<string[]>(['A', 'CNAME', 'MX', 'TXT', 'NS']);
  const [nmapProfile, setNmapProfile] = useState<'quick' | 'top100' | 'top1000'>('quick');
  const [executionEnvironment, setExecutionEnvironment] = useState<
    'in_browser_doh' | 'local_cli_agent' | 'lab_simulation'
  >('in_browser_doh');

  // Validation
  const [error, setError] = useState<string | null>(null);

  const handleNext = () => {
    setError(null);
    if (step === 1) {
      if (!name.trim()) {
        setError('Please provide an assessment project name.');
        return;
      }
      setStep(2);
    } else if (step === 2) {
      if (!rootDomain.trim()) {
        setError('Root domain is required (e.g. example.com or lab.internal).');
        return;
      }
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-._]{1,253}\.[a-zA-Z]{2,}$|^[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*\.local$|^[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*\.internal$/;
      if (!domainRegex.test(rootDomain.trim())) {
        setError('Please enter a valid FQDN or lab root domain name (e.g., inlanefreight.com, juiceshop.lab.internal).');
        return;
      }
      if (!authConfirmed) {
        setError('You must confirm explicit authorization and Rules of Engagement before scanning.');
        return;
      }
      setStep(3);
    } else if (step === 3) {
      if (!Object.values(tools).some(Boolean)) {
        setError('Please select at least one reconnaissance tool to execute.');
        return;
      }
      setStep(4);
    } else if (step === 4) {
      setStep(5);
    }
  };

  const handleLaunch = () => {
    if (!authConfirmed) {
      setError('Explicit authorization confirmation is mandatory.');
      return;
    }

    const approvedHostnames = approvedHostnamesRaw
      .split('\n')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    const approvedIpsAndCidrs = approvedIpsRaw
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    const permittedPorts = permittedPortsRaw
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    const newScope: ScopeRule = {
      rootDomain: rootDomain.trim().toLowerCase(),
      approvedHostnames,
      approvedIpsAndCidrs,
      permittedPorts,
      startDate,
      endDate,
      authorizationConfirmed: true,
      authReference: authReference.trim() || undefined,
      authorizedBy: user?.email || 'Authorized Security Analyst',
    };

    const newConfig: ToolConfig = {
      subfinder: tools.subfinder,
      dnsx: tools.dnsx,
      httpx: tools.httpx,
      nmap: tools.nmap,
      whatweb: tools.whatweb,
      concurrency,
      rateLimit,
      timeoutSeconds,
      dnsRecordTypes: dnsTypes,
      nmapProfile,
      executionEnvironment,
    };

    const newAssessment: Assessment = {
      id: `recon_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      name: name.trim(),
      clientName: clientName.trim() || 'Internal Target Assessment',
      description: description.trim(),
      ownerId: user?.uid || 'anon_operator',
      ownerEmail: user?.email || 'operator@reconx.local',
      type,
      status: 'queued',
      scope: newScope,
      toolConfig: newConfig,
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

    onAssessmentCreated(newAssessment);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Step Indicator Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-500" />
              Assessment Launch Wizard
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              5-step controlled authorization, scope boundary, and tool orchestration setup
            </p>
          </div>
          <button
            onClick={onCancel}
            className="text-xs text-slate-400 hover:text-white px-3 py-1.5 rounded-lg hover:bg-slate-800"
          >
            Cancel
          </button>
        </div>

        {/* Steps track */}
        <div className="grid grid-cols-5 gap-2">
          {[
            { stepNum: 1, title: 'Details' },
            { stepNum: 2, title: 'Scope & ROE' },
            { stepNum: 3, title: 'Tools' },
            { stepNum: 4, title: 'Execution' },
            { stepNum: 5, title: 'Review' },
          ].map((item) => (
            <div key={item.stepNum} className="space-y-1">
              <div
                className={`h-1.5 rounded-full transition-all ${
                  step === item.stepNum
                    ? 'bg-blue-500 shadow-sm shadow-blue-500/50'
                    : step > item.stepNum
                    ? 'bg-emerald-500'
                    : 'bg-slate-800'
                }`}
              />
              <span
                className={`text-[11px] block text-center font-mono ${
                  step === item.stepNum
                    ? 'text-white font-semibold'
                    : step > item.stepNum
                    ? 'text-emerald-400'
                    : 'text-slate-600'
                }`}
              >
                0{item.stepNum} {item.title}
              </span>
            </div>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Step 1: Details */}
      {step === 1 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div>
            <h3 className="text-base font-semibold text-white">Assessment Project Details</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Define the administrative reference and objectives for this reconnaissance session.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Assessment Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Q4 Attack Surface Review"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Target Organization / Lab Name
              </label>
              <input
                type="text"
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
                placeholder="e.g. Acme Corp / Internal Cyber Range"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Assessment Description &amp; Objectives
            </label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Outline the engagement scope, testing goals, or lab coursework requirements..."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-2">
              Reconnaissance Profile Mode
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {[
                {
                  id: 'passive' as AssessmentType,
                  title: 'Passive Only',
                  desc: 'Zero active probes. Harvests exclusively from CT logs, public DNS, and search caches.',
                },
                {
                  id: 'active' as AssessmentType,
                  title: 'Active Probing',
                  desc: 'Direct interaction including port scanning (Nmap) and HTTP probing (httpx).',
                },
                {
                  id: 'mixed' as AssessmentType,
                  title: 'Mixed / Comprehensive',
                  desc: 'Full workflow: Passive discovery + validated active port & tech mapping.',
                },
              ].map((m) => (
                <div
                  key={m.id}
                  onClick={() => setType(m.id)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    type === m.id
                      ? 'bg-blue-600/15 border-blue-500 text-white'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-xs text-slate-200">{m.title}</span>
                    {type === m.id && <Check className="w-3.5 h-3.5 text-blue-400" />}
                  </div>
                  <p className="text-[11px] leading-relaxed text-slate-400">{m.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Step 2: Scope & Authorization */}
      {step === 2 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div>
            <h3 className="text-base font-semibold text-white">Target Scope Boundaries &amp; Authorization</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Strict boundary enforcement. Any discovered host outside these specifications will be excluded.
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-xl border border-blue-500/30 text-xs text-slate-300 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold">
              <Lock className="w-4 h-4" />
              <span>Mandatory Authorization Notice</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Never treat possession of a domain name as proof of authorization. Performing unauthorized port scans or active probes against external systems violates cyber legislation. Only scan systems you own, have signed written consent to test, or designated coursework lab environments.
            </p>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Authorized Root Domain <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              value={rootDomain}
              onChange={(e) => setRootDomain(e.target.value)}
              placeholder="e.g. inlanefreight.com or juiceshop.lab.internal"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-cyan-300 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Approved Hostnames (One per line)
              </label>
              <textarea
                rows={3}
                value={approvedHostnamesRaw}
                onChange={(e) => setApprovedHostnamesRaw(e.target.value)}
                placeholder="api.target.com&#10;auth.target.com&#10;portal.target.com"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Approved IP Addresses / CIDR Ranges
              </label>
              <textarea
                rows={3}
                value={approvedIpsRaw}
                onChange={(e) => setApprovedIpsRaw(e.target.value)}
                placeholder="198.51.100.0/24&#10;203.0.113.15"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Permitted Ports
              </label>
              <input
                type="text"
                value={permittedPortsRaw}
                onChange={(e) => setPermittedPortsRaw(e.target.value)}
                placeholder="80, 443, 22, 53, 8080"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Rules of Engagement (ROE) Reference
              </label>
              <input
                type="text"
                value={authReference}
                onChange={(e) => setAuthReference(e.target.value)}
                placeholder="e.g. ROE-2026-ETHICAL-HACK"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Authorized Window (Dates)
              </label>
              <div className="flex items-center gap-1">
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="w-full px-2 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-[11px] text-slate-300"
                />
                <span className="text-slate-500 text-xs">to</span>
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="w-full px-2 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-[11px] text-slate-300"
                />
              </div>
            </div>
          </div>

          {/* Mandatory Checkbox */}
          <div className="pt-2">
            <label className="flex items-start gap-3 p-3.5 bg-blue-950/20 border border-blue-500/30 rounded-xl cursor-pointer">
              <input
                type="checkbox"
                checked={authConfirmed}
                onChange={(e) => setAuthConfirmed(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-xs text-slate-300 leading-relaxed">
                <strong className="text-white">Legal Scope Certification:</strong> I certify that I have explicit written authorization from the system owner, or this target is an authorized internal coursework laboratory. I acknowledge that all scans will be logged to an immutable security audit trail.
              </span>
            </label>
          </div>
        </div>
      )}

      {/* Step 3: Tool Selection */}
      {step === 3 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div>
            <h3 className="text-base font-semibold text-white">Reconnaissance Tool Adapter Selection</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Choose the security tools to invoke during this assessment pipeline.
            </p>
          </div>

          <div className="space-y-3">
            {[
              {
                id: 'subfinder' as const,
                name: 'Subfinder v2.6.4',
                cat: 'Passive Subdomain Discovery',
                desc: 'Harvests subdomains passively via Certificate Transparency logs and public DNS datasets.',
              },
              {
                id: 'dnsx' as const,
                name: 'dnsx v1.2.1',
                cat: 'DNS Resolution & Extraction',
                desc: 'Resolves A, AAAA, CNAME, MX, TXT, and NS records with DoH caching and wildcards filtering.',
              },
              {
                id: 'httpx' as const,
                name: 'ProjectDiscovery httpx v1.6.8',
                cat: 'HTTP/HTTPS Service Prober',
                desc: 'Probes HTTP status codes, web titles, SSL certificate chains, and server headers.',
              },
              {
                id: 'nmap' as const,
                name: 'Nmap v7.94SV',
                cat: 'Controlled Port & Service Discovery',
                desc: 'Identifies open ports, service banners, and protocol versions across permitted port profiles.',
              },
              {
                id: 'whatweb' as const,
                name: 'WhatWeb v0.5.5',
                cat: 'Technology Fingerprinter',
                desc: 'Detects content management systems, web frameworks, embedded scripts, and HTTP libraries.',
              },
            ].map((tool) => (
              <label
                key={tool.id}
                className={`flex items-start justify-between p-4 rounded-xl border cursor-pointer transition-all ${
                  tools[tool.id]
                    ? 'bg-blue-600/10 border-blue-500/40 text-white'
                    : 'bg-slate-950/40 border-slate-800 text-slate-500'
                }`}
              >
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    checked={tools[tool.id]}
                    onChange={(e) => setTools({ ...tools, [tool.id]: e.target.checked })}
                    className="mt-1 rounded border-slate-700 text-blue-600 focus:ring-blue-500"
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs text-white">{tool.name}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                        {tool.cat}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{tool.desc}</p>
                  </div>
                </div>
                <div className="text-[11px] font-mono text-emerald-400 shrink-0 ml-2">
                  ● Adapter Ready
                </div>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* Step 4: Scan Configuration */}
      {step === 4 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div>
            <h3 className="text-base font-semibold text-white">Scan Rate &amp; Profile Tuning</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Tune concurrency and timeouts to prevent network exhaustion or false positives.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Max Concurrency: {concurrency} workers
              </label>
              <input
                type="range"
                min="1"
                max="50"
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                className="w-full accent-blue-500"
              />
              <span className="text-[10px] text-slate-500">Conservative setting recommended</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Rate Limit: {rateLimit} req/sec
              </label>
              <input
                type="range"
                min="5"
                max="100"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                className="w-full accent-blue-500"
              />
              <span className="text-[10px] text-slate-500">Prevents WAF ban on target</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Probe Timeout: {timeoutSeconds}s
              </label>
              <input
                type="range"
                min="5"
                max="120"
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                className="w-full accent-blue-500"
              />
              <span className="text-[10px] text-slate-500">Graceful timeout cutoff</span>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Nmap Port Discovery Profile
            </label>
            <div className="grid grid-cols-3 gap-3">
              {[
                { id: 'quick', name: 'Quick Profile', desc: 'Standard ports: 80, 443, 22, 53, 8080' },
                { id: 'top100', name: 'Top 100 Profile', desc: 'Most common 100 TCP services' },
                { id: 'top1000', name: 'Top 1000 Profile', desc: 'Comprehensive TCP scan (extended)' },
              ].map((p) => (
                <div
                  key={p.id}
                  onClick={() => setNmapProfile(p.id as any)}
                  className={`p-3 rounded-xl border cursor-pointer text-xs ${
                    nmapProfile === p.id
                      ? 'bg-blue-600/15 border-blue-500 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400'
                  }`}
                >
                  <div className="font-semibold text-slate-200">{p.name}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{p.desc}</div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Execution Environment Mode
            </label>
            <div className="grid grid-cols-2 gap-3">
              <div
                onClick={() => setExecutionEnvironment('in_browser_doh')}
                className={`p-3 rounded-xl border cursor-pointer text-xs ${
                  executionEnvironment === 'in_browser_doh'
                    ? 'bg-blue-600/15 border-blue-500 text-white'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                <div className="font-semibold text-cyan-300">Live DoH &amp; Public CT Harvest</div>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  Queries live Cloudflare/Google DoH and Certificate Transparency logs for real targets.
                </div>
              </div>

              <div
                onClick={() => setExecutionEnvironment('lab_simulation')}
                className={`p-3 rounded-xl border cursor-pointer text-xs ${
                  executionEnvironment === 'lab_simulation'
                    ? 'bg-blue-600/15 border-blue-500 text-white'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                <div className="font-semibold text-amber-300">Authorized Lab Emulation Mode</div>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  Pre-configured OWASP Juice Shop lab fixture for coursework demonstration.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Step 5: Review & Launch */}
      {step === 5 && (
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
          <div>
            <h3 className="text-base font-semibold text-white">Engagement Scope Summary &amp; Review</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Carefully review the final authorized parameters before launching the reconnaissance pipeline.
            </p>
          </div>

          <div className="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3 text-xs">
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-500">Assessment Name:</span>
              <span className="font-semibold text-white">{name}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-500">Target Root Domain:</span>
              <span className="font-mono text-cyan-300 font-semibold">{rootDomain}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-500">Mode:</span>
              <span className="capitalize text-slate-200">{type}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-500">Selected Tools:</span>
              <span className="text-slate-200 font-mono">
                {Object.entries(tools)
                  .filter(([, v]) => v)
                  .map(([k]) => k)
                  .join(', ')}
              </span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-500">Execution Mode:</span>
              <span className="font-mono text-emerald-400">{executionEnvironment}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ROE Reference:</span>
              <span className="font-mono text-slate-300">{authReference || 'Internal Lab Authorized'}</span>
            </div>
          </div>

          <div className="p-3.5 bg-blue-950/20 border border-blue-500/30 rounded-xl text-xs text-slate-300">
            <span className="font-semibold text-blue-300">Auditing Notice:</span> Launching will write initial assessment parameters to the Firestore database and dispatch the scanner engine jobs.
          </div>
        </div>
      )}

      {/* Navigation Buttons */}
      <div className="flex items-center justify-between pt-2">
        {step > 1 ? (
          <button
            onClick={() => setStep((s) => (s - 1) as any)}
            className="flex items-center gap-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium transition-all"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back
          </button>
        ) : (
          <div />
        )}

        {step < 5 ? (
          <button
            onClick={handleNext}
            className="flex items-center gap-1.5 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all cursor-pointer"
          >
            Next Step <ArrowRight className="w-3.5 h-3.5" />
          </button>
        ) : (
          <button
            onClick={handleLaunch}
            className="flex items-center gap-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-emerald-600/20 transition-all cursor-pointer"
          >
            <FileCheck className="w-4 h-4" /> Launch Reconnaissance Scan
          </button>
        )}
      </div>
    </div>
  );
};
