import { jsPDF } from 'jspdf';
import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  AssetRelationship,
  AIAnalysis,
  AssessmentRiskProfile,
} from '../types';
import { calculateAssessmentRiskScore } from './riskScoringEngine';

export interface GeneratePdfOptions {
  assessment: Assessment;
  assets?: Asset[];
  dnsRecords?: DnsRecord[];
  endpoints?: WebEndpoint[];
  services?: NetworkService[];
  relationships?: AssetRelationship[];
  aiAnalysis?: AIAnalysis | null;
  findings?: Finding[];
  riskProfile?: AssessmentRiskProfile | null;
  totalFindingsCount?: number;
}

export function generateAssessmentSummaryPdf({
  assessment,
  assets = [],
  dnsRecords = [],
  endpoints = [],
  services = [],
  relationships = [],
  aiAnalysis = null,
  findings = [],
  riskProfile = null,
  totalFindingsCount,
}: GeneratePdfOptions): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 16;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const renderHeaderMini = () => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(140, 150, 165);
    doc.text('RECONX — STRUCTURED ASSET & FINDINGS ASSESSMENT REPORT', margin, margin - 4);
    doc.text(`ID: ${assessment.id}`, pageWidth - margin, margin - 4, { align: 'right' });
    doc.setDrawColor(220, 225, 235);
    doc.setLineWidth(0.3);
    doc.line(margin, margin - 2, pageWidth - margin, margin - 2);
  };

  const checkPageBreak = (requiredSpace: number) => {
    if (y + requiredSpace > pageHeight - margin - 12) {
      doc.addPage();
      y = margin + 4;
      renderHeaderMini();
    }
  };

  // --- TOP BANNER / COVER HEADER ---
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y, contentWidth, 34, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(255, 255, 255);
  doc.text('RECONX — ATTACK SURFACE MAPPER', margin + 8, y + 11.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(56, 189, 248);
  doc.text('STRUCTURED ASSET INVENTORY & SECURITY FINDINGS REPORT', margin + 8, y + 19.5);

  doc.setFontSize(7.5);
  doc.setTextColor(203, 213, 225);
  const clientLabel = `CONFIDENTIAL • PREPARED FOR: ${(assessment.clientName || 'Authorized Engagement').toUpperCase()}`;
  const splitClient = doc.splitTextToSize(clientLabel, contentWidth - 52);
  doc.text(splitClient[0] || clientLabel, margin + 8, y + 27);

  // Status badge
  const statusText = (assessment.status || 'draft').replace(/_/g, ' ').toUpperCase();
  const statusColor: [number, number, number] =
    assessment.status === 'failed' || assessment.status === 'cancelled'
      ? [248, 113, 113]
      : assessment.status === 'completed'
      ? [52, 211, 153]
      : assessment.status === 'queued' || assessment.status === 'partially_completed'
      ? [251, 191, 36]
      : [56, 189, 248];
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(pageWidth - margin - 42, y + 8, 36, 18, 2, 2, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text('STATUS', pageWidth - margin - 24, y + 14, { align: 'center' });
  doc.setFontSize(statusText.length > 10 ? 6.8 : 8);
  doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
  doc.text(statusText, pageWidth - margin - 24, y + 21, { align: 'center', maxWidth: 33 });

  y += 40;

  // --- METADATA STRIP ---
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  const nameLines = doc.splitTextToSize(assessment.name || 'Untitled Assessment', 62);
  const domainLines = doc.splitTextToSize(assessment.scope?.rootDomain || 'N/A', 52);
  const dateLines = doc.splitTextToSize(new Date().toLocaleString(), 46);
  const maxMetaLines = Math.max(nameLines.length, domainLines.length, dateLines.length, 1);
  const stripHeight = Math.max(17, 10 + maxMetaLines * 4);

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.rect(margin, y, contentWidth, stripHeight, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  doc.text('ASSESSMENT NAME:', margin + 4, y + 5.5);
  doc.text('TARGET DOMAIN:', margin + 70, y + 5.5);
  doc.text('REPORT GENERATED:', margin + 126, y + 5.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(15, 23, 42);
  doc.text(nameLines, margin + 4, y + 11);
  doc.text(domainLines, margin + 70, y + 11);
  doc.text(dateLines, margin + 126, y + 11);

  y += stripHeight + 6;

  // Compute inventory counts from provided arrays with fallback to assessment.stats
  const totalAssetsCount =
    assets.length > 0
      ? assets.length
      : assessment.stats?.totalAssets || assessment.stats?.assetsCount || 0;
  const subdomainsCount =
    assets.filter((a) => a.assetType === 'subdomain' || a.assetType === 'root_domain').length ||
    assessment.stats?.subdomainsCount ||
    0;
  const ipsCount =
    assets.filter((a) => a.assetType === 'ip_address').length ||
    assessment.stats?.ipsCount ||
    assessment.stats?.ipAddressesCount ||
    0;
  const endpointsCount =
    endpoints.length ||
    assets.filter((a) => a.assetType === 'endpoint').length ||
    assessment.stats?.endpointsCount ||
    assessment.stats?.liveEndpointsCount ||
    0;
  const servicesCount =
    services.length ||
    assets.filter((a) => a.assetType === 'service' || a.assetType === 'port').length ||
    assessment.stats?.servicesCount ||
    assessment.stats?.openPortsCount ||
    0;
  const technologiesCount =
    assets.filter((a) => a.assetType === 'technology').length ||
    assessment.stats?.technologiesCount ||
    0;
  const totalFindings =
    totalFindingsCount !== undefined
      ? totalFindingsCount
      : findings.length > 0
      ? findings.length
      : assessment.stats?.findingsCount || 0;

  // --- SECTION 1: EXECUTIVE OVERVIEW ---
  checkPageBreak(28);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('1. Executive Assessment Overview', margin, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(51, 65, 85);

  const overviewText =
    aiAnalysis?.executiveSummary ||
    `An authorized technical reconnaissance assessment was executed against primary root domain "${
      assessment.scope?.rootDomain || 'N/A'
    }" under engagement mode "${(
      assessment.type || 'mixed'
    ).toUpperCase()}". The automated reconnaissance and correlation pipeline synthesized ${totalAssetsCount} discovered assets across ${subdomainsCount} domains/subdomains, ${ipsCount} IP hosts, ${endpointsCount} active web endpoints, ${servicesCount} network services/ports, and ${technologiesCount} fingerprinted technologies, identifying ${totalFindings} security observations.`;

  const splitOverview = doc.splitTextToSize(overviewText, contentWidth);
  doc.text(splitOverview, margin, y);
  y += splitOverview.length * 4.2 + 4;

  // --- WEIGHTED AGGREGATE RISK SCORE PANEL ---
  const computedRisk =
    riskProfile ||
    calculateAssessmentRiskScore({
      assessment,
      assets,
      services,
      endpoints,
      findings,
    });

  checkPageBreak(24);
  doc.setFillColor(241, 245, 249);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(margin, y, contentWidth, 18, 2, 2, 'FD');

  const tierRgb: [number, number, number] =
    computedRisk.severityTier === 'critical'
      ? [225, 29, 72]
      : computedRisk.severityTier === 'high'
      ? [234, 88, 12]
      : computedRisk.severityTier === 'medium'
      ? [217, 119, 6]
      : [14, 116, 144];

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text('WEIGHTED AGGREGATE RISK SCORE:', margin + 4, y + 6.5);

  doc.setFontSize(11);
  doc.setTextColor(tierRgb[0], tierRgb[1], tierRgb[2]);
  doc.text(
    `${computedRisk.aggregateScore} / 100 (${computedRisk.severityTier.toUpperCase()})`,
    margin + 68,
    y + 6.5
  );

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.8);
  doc.setTextColor(71, 85, 105);
  doc.text(
    `Open Ports (${Math.round(computedRisk.weights.openPorts * 100)}%): ${computedRisk.subScores.openPortsScore}/100   |   Exposed Services (${Math.round(computedRisk.weights.exposedServices * 100)}%): ${computedRisk.subScores.exposedServicesScore}/100   |   Vulnerabilities (${Math.round(computedRisk.weights.vulnerabilities * 100)}%): ${computedRisk.subScores.vulnerabilitiesScore}/100`,
    margin + 4,
    y + 13.5
  );

  y += 23;

  // --- SECTION 2: AUTHORIZED SCOPE & ROE ---
  checkPageBreak(35);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('2. Authorized Scope Boundaries & Rules of Engagement', margin, y);
  y += 4.5;

  const scopeData: [string, string][] = [
    ['Root Domain Target:', assessment.scope?.rootDomain || 'N/A'],
    [
      'Approved Hostnames:',
      assessment.scope?.approvedHostnames?.length
        ? assessment.scope.approvedHostnames.join(', ')
        : 'All in-scope subdomains of root domain',
    ],
    [
      'Approved IP / CIDR Ranges:',
      assessment.scope?.approvedIpsAndCidrs?.length
        ? assessment.scope.approvedIpsAndCidrs.join(', ')
        : 'Restricted to resolved target infrastructure',
    ],
    [
      'Permitted Ports Profile:',
      assessment.scope?.permittedPorts?.length
        ? assessment.scope.permittedPorts.join(', ')
        : 'Standard Reconnaissance Profile (80, 443, 22, 53, 8080, 8443)',
    ],
    [
      'Authorization Window:',
      `${assessment.scope?.startDate || 'N/A'} through ${assessment.scope?.endDate || 'N/A'}`,
    ],
    [
      'Rules of Engagement (ROE) Ref:',
      assessment.scope?.authReference || 'ROE-ETHICAL-HACKING-COURSEWORK-2026',
    ],
    ['Authorization Certified By:', assessment.scope?.authorizedBy || assessment.ownerEmail || 'Authorized Operator'],
  ];

  scopeData.forEach(([label, value], i) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    const wrappedVal = doc.splitTextToSize(String(value || 'N/A'), contentWidth - 62);
    const rowHeight = Math.max(6, wrappedVal.length * 3.8 + 2.2);
    checkPageBreak(rowHeight);

    doc.setFillColor(i % 2 === 0 ? 248 : 255, i % 2 === 0 ? 250 : 255, i % 2 === 0 ? 252 : 255);
    doc.rect(margin, y, contentWidth, rowHeight, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.8);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 3, y + 4.2);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    doc.setTextColor(15, 23, 42);
    doc.text(wrappedVal, margin + 58, y + 4.2);

    y += rowHeight;
  });

  y += 6;

  // --- SECTION 3: TOOL CONFIGURATIONS ---
  checkPageBreak(32);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('3. Security Tool Configurations & Scanner Pipeline', margin, y);
  y += 4.5;

  const envLabel =
    assessment.toolConfig?.executionEnvironment === 'lab_simulation'
      ? 'Authorized Lab Emulation (OWASP Juice Shop)'
      : assessment.toolConfig?.executionEnvironment === 'local_cli_agent'
      ? 'Local CLI Runner Adapter'
      : 'Live DoH & Public CT Stream';

  const toolConfigs: [string, string][] = [
    [
      'Subfinder (Passive Subdomain Harvester)',
      assessment.toolConfig?.subfinder ? 'ACTIVE (Enabled)' : 'DISABLED',
    ],
    [
      'dnsx (Multi-Threaded DNS Resolver)',
      assessment.toolConfig?.dnsx ? 'ACTIVE (Enabled)' : 'DISABLED',
    ],
    [
      'httpx (Web Endpoint & Title Prober)',
      assessment.toolConfig?.httpx ? 'ACTIVE (Enabled)' : 'DISABLED',
    ],
    [
      'Nmap (Controlled Port & Service Discovery)',
      assessment.toolConfig?.nmap
        ? `ACTIVE (Profile: ${(assessment.toolConfig.nmapProfile || 'top100').toUpperCase()})`
        : 'DISABLED',
    ],
    [
      'WhatWeb (Technology Fingerprinter)',
      assessment.toolConfig?.whatweb ? 'ACTIVE (Enabled)' : 'DISABLED',
    ],
    [
      'Max Concurrency & Rate Limit:',
      `${assessment.toolConfig?.concurrency ?? 10} workers • ${
        assessment.toolConfig?.rateLimit ?? 25
      } req/sec`,
    ],
    ['Execution Runtime Environment:', envLabel],
  ];

  toolConfigs.forEach(([label, value], i) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    const wrappedVal = doc.splitTextToSize(String(value || 'N/A'), contentWidth - 76);
    const rowHeight = Math.max(6, wrappedVal.length * 3.8 + 2.2);
    checkPageBreak(rowHeight);

    doc.setFillColor(i % 2 === 0 ? 248 : 255, i % 2 === 0 ? 250 : 255, i % 2 === 0 ? 252 : 255);
    doc.rect(margin, y, contentWidth, rowHeight, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.8);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 3, y + 4.2);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    doc.setTextColor(
      value.includes('ACTIVE') ? 22 : 15,
      value.includes('ACTIVE') ? 101 : 23,
      value.includes('ACTIVE') ? 52 : 42
    );
    doc.text(wrappedVal, margin + 72, y + 4.2);

    y += rowHeight;
  });

  y += 6;

  // --- SECTION 4: DISCOVERED ASSET INVENTORY SUMMARY ---
  checkPageBreak(35);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`4. Discovered Asset Inventory Summary (${totalAssetsCount} Total Assets)`, margin, y);
  y += 4.5;

  // Asset KPI Summary Boxes
  const assetMetrics = [
    { label: 'SUBDOMAINS', value: subdomainsCount },
    { label: 'IP HOSTS', value: ipsCount },
    { label: 'WEB ENDPOINTS', value: endpointsCount },
    { label: 'SERVICES / PORTS', value: servicesCount },
    { label: 'TECHNOLOGIES', value: technologiesCount },
    { label: 'CORR. EDGES', value: relationships.length || assessment.stats?.relationshipsCount || 0 },
  ];

  const metricBoxWidth = (contentWidth - 10) / 6;
  checkPageBreak(16);
  assetMetrics.forEach((m, idx) => {
    const bx = margin + idx * (metricBoxWidth + 2);
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(203, 213, 225);
    doc.rect(bx, y, metricBoxWidth, 13, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(71, 85, 105);
    doc.text(m.label, bx + metricBoxWidth / 2, y + 4.5, { align: 'center' });

    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(String(m.value), bx + metricBoxWidth / 2, y + 10.8, { align: 'center' });
  });
  y += 17;

  // Detailed Asset Table (if assets are provided)
  if (assets.length > 0) {
    checkPageBreak(14);
    // Table Header
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y, contentWidth, 7, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.2);
    doc.setTextColor(255, 255, 255);
    doc.text('CANONICAL ASSET NAME', margin + 3, y + 4.8);
    doc.text('CATEGORY', margin + 78, y + 4.8);
    doc.text('DISCOVERY SOURCES', margin + 108, y + 4.8);
    doc.text('CONF.', margin + 150, y + 4.8);
    doc.text('STATUS', margin + 164, y + 4.8);
    y += 7;

    const sortedAssets = [...assets].sort((a, b) => {
      const riskOrder = (x: Asset) => (x.isExposedRisk || x.isPotentiallyExposed ? 0 : 1);
      return riskOrder(a) - riskOrder(b);
    });

    sortedAssets.slice(0, 60).forEach((asset, idx) => {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.2);
      const nameWrapped = doc.splitTextToSize(asset.canonicalName || 'N/A', 72);
      const sourcesText = (asset.sources || [asset.discoverySource || 'ReconX']).join(', ');
      const sourcesWrapped = doc.splitTextToSize(sourcesText, 39);
      const maxLines = Math.max(nameWrapped.length, sourcesWrapped.length, 1);
      const rowH = Math.max(6, maxLines * 3.6 + 2);

      checkPageBreak(rowH);

      const isExposed = Boolean(asset.isExposedRisk || asset.isPotentiallyExposed);
      if (isExposed) {
        doc.setFillColor(254, 242, 242);
      } else {
        doc.setFillColor(idx % 2 === 0 ? 248 : 255, idx % 2 === 0 ? 250 : 255, idx % 2 === 0 ? 252 : 255);
      }
      doc.rect(margin, y, contentWidth, rowH, 'F');

      doc.setFont('helvetica', isExposed ? 'bold' : 'normal');
      doc.setTextColor(isExposed ? 185 : 15, isExposed ? 28 : 23, isExposed ? 28 : 42);
      doc.text(nameWrapped, margin + 3, y + 4.2);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(71, 85, 105);
      doc.text((asset.assetType || 'asset').replace(/_/g, ' ').toUpperCase(), margin + 78, y + 4.2);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.text(sourcesWrapped, margin + 108, y + 4.2);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(16, 185, 129);
      doc.text(`${asset.confidenceScore ?? 85}%`, margin + 150, y + 4.2);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(isExposed ? 220 : 71, isExposed ? 38 : 85, isExposed ? 38 : 105);
      doc.text(isExposed ? 'EXPOSED' : (asset.status || 'active').toUpperCase(), margin + 164, y + 4.2);

      y += rowH;
    });

    if (assets.length > 60) {
      checkPageBreak(7);
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7.2);
      doc.setTextColor(100, 116, 139);
      doc.text(
        `Showing top 60 prioritized assets out of ${assets.length} total normalized assets. Export JSON/CSV for complete raw dump.`,
        margin + 2,
        y + 4.5
      );
      y += 6;
    }
    y += 4;
  }

  // Optional Network Services & Web Endpoints Highlight Table
  if (services.length > 0 || endpoints.length > 0 || dnsRecords.length > 0) {
    checkPageBreak(20);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(
      `4b. Active Network Services (${services.length}) & Web Endpoints (${endpoints.length})`,
      margin,
      y
    );
    y += 4;

    if (services.length > 0) {
      services.slice(0, 15).forEach((svc, i) => {
        const line = `• [PORT ${svc.port}/${svc.protocol.toUpperCase()} - ${svc.state.toUpperCase()}] Host: ${
          svc.host || svc.ip
        } (${svc.ip}) — Service: ${svc.serviceName} ${svc.version || ''} [Source: ${
          svc.toolSource || 'Nmap'
        }]`;
        const wrapped = doc.splitTextToSize(line, contentWidth - 4);
        const h = wrapped.length * 3.6 + 1.5;
        checkPageBreak(h);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.4);
        doc.setTextColor(i % 2 === 0 ? 30 : 51, 41, 59);
        doc.text(wrapped, margin + 2, y + 3.2);
        y += h;
      });
      y += 2;
    }

    if (endpoints.length > 0) {
      endpoints.slice(0, 12).forEach((ep) => {
        const line = `• [HTTP ${ep.statusCode}] ${ep.url} — Title: "${ep.title || 'N/A'}" — Tech: ${
          (ep.technologies || []).join(', ') || 'Standard Web'
        }`;
        const wrapped = doc.splitTextToSize(line, contentWidth - 4);
        const h = wrapped.length * 3.6 + 1.5;
        checkPageBreak(h);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.4);
        doc.setTextColor(30, 41, 59);
        doc.text(wrapped, margin + 2, y + 3.2);
        y += h;
      });
      y += 3;
    }
  }

  // --- SECTION 5: FINDINGS & OBSERVATIONS SUMMARY ---
  checkPageBreak(30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`5. Security Findings & Attack Surface Exposure (${totalFindings})`, margin, y);
  y += 5;

  const counts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    informational: findings.filter((f) => f.severity === 'informational').length,
  };

  checkPageBreak(18);
  const cardWidth = (contentWidth - 8) / 5;
  const sevCards = [
    { label: 'CRITICAL', count: counts.critical, color: [239, 68, 68] },
    { label: 'HIGH', count: counts.high, color: [249, 115, 22] },
    { label: 'MEDIUM', count: counts.medium, color: [245, 158, 11] },
    { label: 'LOW', count: counts.low, color: [16, 185, 129] },
    { label: 'INFO', count: counts.informational, color: [59, 130, 246] },
  ];

  sevCards.forEach((c, idx) => {
    const cardX = margin + idx * (cardWidth + 2);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.rect(cardX, y, cardWidth, 13, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(c.color[0], c.color[1], c.color[2]);
    doc.text(c.label, cardX + cardWidth / 2, y + 4.5, { align: 'center' });

    doc.setFontSize(10.5);
    doc.setTextColor(15, 23, 42);
    doc.text(String(c.count), cardX + cardWidth / 2, y + 10.8, { align: 'center' });
  });

  y += 17;

  if (findings.length > 0) {
    findings.forEach((f, idx) => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.2);
      const titleLines = doc.splitTextToSize(`${idx + 1}. ${f.title}`, contentWidth - 6);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.2);
      const metaText = `[${f.severity.toUpperCase()}] • ASSET: ${f.assetRef || 'N/A'} • TOOL: ${
        f.sourceTool || 'ReconX'
      } • STATUS: ${(f.verificationStatus || 'observed_fact').replace(/_/g, ' ').toUpperCase()}`;
      const metaLines = doc.splitTextToSize(metaText, contentWidth - 6);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.4);
      const descLines = f.description
        ? doc.splitTextToSize(f.description, contentWidth - 6)
        : [];

      const evidenceLines = f.evidence
        ? doc.splitTextToSize(`Evidence: ${f.evidence}`, contentWidth - 6)
        : [];

      const remediationText = f.remediation
        ? `Remediation: ${f.remediation}`
        : 'Remediation: Review asset configuration and enforce least-privilege exposure controls.';
      const remediationLines = doc.splitTextToSize(remediationText, contentWidth - 6);

      const boxHeight =
        4.5 +
        titleLines.length * 3.8 +
        metaLines.length * 3.5 +
        descLines.length * 3.5 +
        evidenceLines.length * 3.5 +
        remediationLines.length * 3.5 +
        3;

      checkPageBreak(boxHeight + 2);

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.rect(margin, y, contentWidth, boxHeight, 'FD');

      let innerY = y + 4.2;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.2);
      doc.setTextColor(15, 23, 42);
      doc.text(titleLines, margin + 3, innerY);
      innerY += titleLines.length * 3.8 + 0.4;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.2);
      const sevColor =
        f.severity === 'critical'
          ? [220, 38, 38]
          : f.severity === 'high'
          ? [234, 88, 12]
          : f.severity === 'medium'
          ? [217, 119, 6]
          : [71, 85, 105];
      doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
      doc.text(metaLines, margin + 3, innerY);
      innerY += metaLines.length * 3.5 + 0.4;

      if (descLines.length > 0) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.4);
        doc.setTextColor(51, 65, 85);
        doc.text(descLines, margin + 3, innerY);
        innerY += descLines.length * 3.5 + 0.4;
      }

      if (evidenceLines.length > 0) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.2);
        doc.setTextColor(71, 85, 105);
        doc.text(evidenceLines, margin + 3, innerY);
        innerY += evidenceLines.length * 3.5 + 0.4;
      }

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.3);
      doc.setTextColor(16, 120, 80);
      doc.text(remediationLines, margin + 3, innerY);

      y += boxHeight + 2.5;
    });
  } else {
    checkPageBreak(12);
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('No observation findings recorded for this assessment.', margin, y + 4);
    y += 10;
  }

  // --- FOOTER & COMPLIANCE DISCLAIMER ---
  checkPageBreak(24);
  y += 3;
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(0.4);
  doc.line(margin, y, pageWidth - margin, y);
  y += 4.5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(148, 163, 184);
  const disclaimerText =
    'METHODOLOGICAL DISCLAIMER: ReconX produces reconnaissance observations using authorized passive intelligence and non-destructive service discovery. Findings represent point-in-time surface mappings grounded strictly in collected telemetry. No automated exploitation or payload injections were conducted.';
  const splitDisclaimer = doc.splitTextToSize(disclaimerText, contentWidth);
  doc.text(splitDisclaimer, margin, y);

  // Add page numbers across all generated pages
  const pageCount = doc.getNumberOfPages();
  for (let p = 1; p <= pageCount; p++) {
    doc.setPage(p);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `ReconX Security Report • ${assessment.scope?.rootDomain || assessment.name} • Page ${p} of ${pageCount}`,
      pageWidth / 2,
      pageHeight - 7,
      { align: 'center' }
    );
  }

  const safeName = (assessment.name || 'Assessment').replace(/[^a-zA-Z0-9_-]/g, '_');
  doc.save(`ReconX_Assessment_Report_${safeName}.pdf`);
}
