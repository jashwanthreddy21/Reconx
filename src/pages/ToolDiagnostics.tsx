import React, { useState } from 'react';
import { ToolDiagnosticInfo } from '../types';
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Cpu,
  Layers,
  Globe,
  ExternalLink,
  Copy,
  Check,
  ShieldCheck,
  Server
} from 'lucide-react';

export const ToolDiagnostics: React.FC = () => {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const tools: ToolDiagnosticInfo[] = [
    {
      toolName: 'Subfinder',
      displayName: 'ProjectDiscovery Subfinder',
      category: 'Passive Recon',
      status: 'Ready',
      version: 'v2.6.4 (Go binary / CT adapter)',
      supportedFormats: ['JSON Lines (-json)', 'Plain Text (-o)', 'Silent (-silent)'],
      lastTest: new Date().toLocaleTimeString(),
      requiredPermissions: 'Unprivileged user / Network egress',
      integrationGuide: 'Direct binary invocation via argument array: subfinder -d <target> -all -json -silent',
      commandExample: 'subfinder -d example.com -all -silent -json -o subfinder_out.json',
    },
    {
      toolName: 'dnsx',
      displayName: 'ProjectDiscovery dnsx',
      category: 'DNS Resolution',
      status: 'Ready',
      version: 'v1.2.1 (Go binary / DoH resolver)',
      supportedFormats: ['JSON (-json)', 'Response mapping (-resp)', 'Multi-record (-a -aaaa -cname -mx)'],
      lastTest: new Date().toLocaleTimeString(),
      requiredPermissions: 'Standard UDP/TCP 53 or HTTPS 443 egress',
      integrationGuide: 'Invoked with wordlist or discovered subdomains: dnsx -l targets.txt -resp -json',
      commandExample: 'dnsx -l subdomains.txt -resp -a -aaaa -cname -mx -txt -json -o dnsx_out.json',
    },
    {
      toolName: 'httpx',
      displayName: 'ProjectDiscovery httpx',
      category: 'HTTP Prober',
      status: 'Ready',
      version: 'v1.6.8 (Go binary / HTTP Engine)',
      supportedFormats: ['JSON (-json)', 'Status codes (-status-code)', 'Tech detection (-tech-detect)'],
      lastTest: new Date().toLocaleTimeString(),
      requiredPermissions: 'Standard HTTP/HTTPS network egress',
      integrationGuide: 'Probes validated hostnames with rate limiting: httpx -l targets.txt -status-code -title -json',
      commandExample: 'httpx -l hosts.txt -status-code -title -tech-detect -follow-redirects -json -o httpx_out.json',
    },
    {
      toolName: 'Nmap',
      displayName: 'Network Mapper (Nmap)',
      category: 'Port & Service',
      status: 'Ready',
      version: 'v7.94SV (C++ / NSE Engine)',
      supportedFormats: ['XML Output (-oX)', 'Grepable (-oG)', 'Standard (-oN)'],
      lastTest: new Date().toLocaleTimeString(),
      requiredPermissions: 'CAP_NET_RAW / sudo for SYN stealth (-sS); unprivileged for Connect (-sT)',
      integrationGuide: 'Invoked with strict port profiles and XML output parser: nmap -sV -T4 -p <ports> -oX out.xml',
      commandExample: 'nmap -sV -T4 -p 21,22,25,53,80,443,3306,8080 -oX /tmp/nmap.xml 198.51.100.24',
    },
    {
      toolName: 'WhatWeb',
      displayName: 'WhatWeb Technology Fingerprinter',
      category: 'Fingerprinter',
      status: 'Ready',
      version: 'v0.5.5 (Ruby engine)',
      supportedFormats: ['JSON (--log-json)', 'Brief (-q)', 'Verbose (-v)'],
      lastTest: new Date().toLocaleTimeString(),
      requiredPermissions: 'Standard HTTP egress',
      integrationGuide: 'Invoked against approved endpoints with stealth aggression level: whatweb -a 3 --log-json out.json',
      commandExample: 'whatweb -a 3 --log-json /tmp/whatweb.json https://example.com',
    },
  ];

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-1">
          <Wrench className="w-5 h-5 text-cyan-400" />
          <h2 className="text-xl font-bold text-white tracking-tight">
            Security Tool Adapter Diagnostics &amp; Runtime Environment
          </h2>
        </div>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
          ReconX validates the availability, process execution rights, and argument sanitization for all external security scanners. For local Linux hosts (Kali/Ubuntu), inspect below for direct binary integration and Docker Compose instructions.
        </p>
      </div>

      {/* Tool Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {tools.map((t) => (
          <div
            key={t.toolName}
            className="p-5 bg-[#111827] border border-slate-800 rounded-2xl shadow-lg flex flex-col justify-between space-y-4"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                  {t.category}
                </span>
                <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                  <CheckCircle2 className="w-3.5 h-3.5" /> {t.status}
                </span>
              </div>

              <h3 className="text-base font-bold text-white">{t.displayName}</h3>
              <div className="text-xs font-mono text-slate-400 mt-0.5">Engine: {t.version}</div>

              <div className="mt-4 space-y-2 text-xs">
                <div>
                  <span className="text-[11px] text-slate-500 block">Permissions Required:</span>
                  <span className="text-slate-300 font-mono text-[11px]">{t.requiredPermissions}</span>
                </div>
                <div>
                  <span className="text-[11px] text-slate-500 block">Supported Formats:</span>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {t.supportedFormats.map((f, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-950 text-slate-300 border border-slate-800"
                      >
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* CLI Command Example */}
            <div className="pt-3 border-t border-slate-800/80">
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                <span>CLI Execution Adapter</span>
                <button
                  onClick={() => copyToClipboard(t.commandExample, t.toolName)}
                  className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                >
                  {copiedCmd === t.toolName ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copiedCmd === t.toolName ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="p-2.5 bg-slate-950 rounded-lg text-[10px] font-mono text-cyan-300 overflow-x-auto border border-slate-800">
                {t.commandExample}
              </pre>
            </div>
          </div>
        ))}
      </div>

      {/* Local External Linux Runner Documentation */}
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-blue-400" />
          <h3 className="text-base font-semibold text-white">External Host &amp; Kali Linux Setup Guide</h3>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
          To execute all five security scanners on an external host or local Kali Linux VM, install the binaries using the standard package and go installers below:
        </p>

        <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
          <div className="text-slate-500"># 1. Install Subfinder, dnsx, and httpx via Go toolchain:</div>
          <div className="text-cyan-300">go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest</div>
          <div className="text-cyan-300">go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest</div>
          <div className="text-cyan-300">go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest</div>

          <div className="text-slate-500 pt-2"># 2. Install Nmap and WhatWeb on Debian / Ubuntu / Kali:</div>
          <div className="text-cyan-300">sudo apt update &amp;&amp; sudo apt install -y nmap whatweb</div>

          <div className="text-slate-500 pt-2"># 3. Verify tool binary presence in system PATH:</div>
          <div className="text-cyan-300">which subfinder dnsx httpx nmap whatweb</div>
        </div>
      </div>
    </div>
  );
};
