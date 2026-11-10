import { jsPDF } from 'jspdf';
import { Assessment, Finding } from '../types';

export interface GeneratePdfOptions {
  assessment: Assessment;
  findings?: Finding[];
  totalFindingsCount?: number;
}

export function generateAssessmentSummaryPdf({
  assessment,
  findings = [],
  totalFindingsCount,
}: GeneratePdfOptions): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 18;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  // Helper function for page overflow
  const checkPageBreak = (requiredSpace: number) => {
    if (y + requiredSpace > pageHeight - margin - 10) {
      doc.addPage();
      y = margin + 5;
      renderHeaderMini();
    }
  };

  const renderHeaderMini = () => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(140, 150, 165);
    doc.text('RECONX SECURITY ASSESSMENT SUMMARY REPORT', margin, y - 5);
    doc.text(`ID: ${assessment.id}`, pageWidth - margin, y - 5, { align: 'right' });
    doc.setDrawColor(220, 225, 235);
    doc.setLineWidth(0.3);
    doc.line(margin, y - 3, pageWidth - margin, y - 3);
  };

  // --- TOP BANNER / COVER HEADER ---
  // Background bar
  doc.setFillColor(15, 23, 42); // Slate-900 / Navy
  doc.rect(margin, y, contentWidth, 34, 'F');

  // Title & Tagline
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('RECONX — ATTACK SURFACE MAPPER', margin + 8, y + 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(56, 189, 248); // Cyan-400
  doc.text('AUTOMATED RECONNAISSANCE & SCOPE ASSESSMENT SUMMARY', margin + 8, y + 20);

  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  const clientLabel = `CONFIDENTIAL • PREPARED FOR: ${(assessment.clientName || 'Authorized Engagement').toUpperCase()}`;
  const splitClient = doc.splitTextToSize(clientLabel, contentWidth - 52);
  doc.text(splitClient[0] || clientLabel, margin + 8, y + 27);

  // Top right badge
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
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text('STATUS', pageWidth - margin - 24, y + 14, { align: 'center' });
  doc.setFontSize(statusText.length > 10 ? 7 : 8.5);
  doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
  doc.text(statusText, pageWidth - margin - 24, y + 21, { align: 'center', maxWidth: 33 });

  y += 42;

  // --- METADATA STRIP ---
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  const nameLines = doc.splitTextToSize(assessment.name || 'Untitled Assessment', 60);
  const domainLines = doc.splitTextToSize(assessment.scope?.rootDomain || 'N/A', 50);
  const dateLines = doc.splitTextToSize(new Date().toLocaleString(), 44);
  const maxMetaLines = Math.max(nameLines.length, domainLines.length, dateLines.length, 1);
  const stripHeight = Math.max(18, 11 + maxMetaLines * 4.2);

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.rect(margin, y, contentWidth, stripHeight, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);

  doc.text('ASSESSMENT NAME:', margin + 4, y + 6);
  doc.text('TARGET DOMAIN:', margin + 68, y + 6);
  doc.text('REPORT GENERATED:', margin + 123, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);

  doc.text(nameLines, margin + 4, y + 12);
  doc.text(domainLines, margin + 68, y + 12);
  doc.text(dateLines, margin + 123, y + 12);

  y += stripHeight + 6;

  // --- SECTION 1: EXECUTIVE OVERVIEW ---
  checkPageBreak(30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('1. Executive Assessment Overview', margin, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(51, 65, 85);

  const totalFindings = totalFindingsCount !== undefined ? totalFindingsCount : (assessment.stats?.findingsCount || findings.length);
  const overviewText = `An authorized technical reconnaissance assessment was executed against primary root domain "${assessment.scope?.rootDomain || 'N/A'}" under engagement type "${(assessment.type || 'mixed').toUpperCase()}". The automated scan gathered observable assets across Certificate Transparency streams, public DNS records, HTTP web endpoints, and service ports. Total inventory contains ${assessment.stats?.assetsCount || 0} discovered assets, ${assessment.stats?.subdomainsCount || 0} subdomains, ${assessment.stats?.endpointsCount || 0} active web endpoints, and ${totalFindings} identified observation findings.`;

  const splitOverview = doc.splitTextToSize(overviewText, contentWidth);
  doc.text(splitOverview, margin, y);
  y += splitOverview.length * 4.5 + 4;

  // --- SECTION 2: AUTHORIZED SCOPE & ROE ---
  checkPageBreak(35);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('2. Authorized Scope Boundaries & Rules of Engagement', margin, y);
  y += 5;

  const scopeData: [string, string][] = [
    ['Root Domain Target:', assessment.scope?.rootDomain || 'N/A'],
    ['Explicit Approved Hostnames:', assessment.scope?.approvedHostnames?.length ? assessment.scope.approvedHostnames.join(', ') : 'All in-scope subdomains of root domain'],
    ['Approved IP / CIDR Ranges:', assessment.scope?.approvedIpsAndCidrs?.length ? assessment.scope.approvedIpsAndCidrs.join(', ') : 'Restricted to resolved target infrastructure'],
    ['Permitted Ports Profile:', assessment.scope?.permittedPorts?.length ? assessment.scope.permittedPorts.join(', ') : 'Standard Reconnaissance Profile (80, 443, 22, 53, 8080)'],
    ['Authorization Window:', `${assessment.scope?.startDate || 'N/A'} through ${assessment.scope?.endDate || 'N/A'}`],
    ['Rules of Engagement (ROE) Ref:', assessment.scope?.authReference || 'ROE-ETHICAL-HACKING-COURSEWORK-2026'],
    ['Authorization Certified By:', assessment.scope?.authorizedBy || assessment.ownerEmail],
  ];

  // Draw Scope Table with dynamic row wrapping and incremental Y tracking
  scopeData.forEach(([label, value], i) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    const wrappedVal = doc.splitTextToSize(String(value || 'N/A'), contentWidth - 64);
    const rowHeight = Math.max(6.5, wrappedVal.length * 4 + 2.5);
    checkPageBreak(rowHeight);

    doc.setFillColor(i % 2 === 0 ? 248 : 255, i % 2 === 0 ? 250 : 255, i % 2 === 0 ? 252 : 255);
    doc.rect(margin, y, contentWidth, rowHeight, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 3, y + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(wrappedVal, margin + 60, y + 4.5);

    y += rowHeight;
  });

  y += 8;

  // --- SECTION 3: TOOL CONFIGURATIONS ---
  checkPageBreak(35);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('3. Security Tool Configurations & Scanner Pipeline', margin, y);
  y += 5;

  const envLabel =
    assessment.toolConfig.executionEnvironment === 'lab_simulation'
      ? 'Authorized Lab Emulation (OWASP Juice Shop)'
      : assessment.toolConfig.executionEnvironment === 'local_cli_agent'
      ? 'Local CLI Runner Adapter'
      : 'Live DoH & Public CT Stream';

  const toolConfigs: [string, string][] = [
    ['Subfinder (Passive Subdomain Harvester)', assessment.toolConfig.subfinder ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['dnsx (Multi-Threaded DNS Resolver)', assessment.toolConfig.dnsx ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['httpx (Web Endpoint & Title Prober)', assessment.toolConfig.httpx ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['Nmap (Controlled Port & Service Discovery)', assessment.toolConfig.nmap ? `ACTIVE (Profile: ${assessment.toolConfig.nmapProfile.toUpperCase()})` : 'DISABLED'],
    ['WhatWeb (Technology Fingerprinter)', assessment.toolConfig.whatweb ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['Max Concurrency & Rate Limit:', `${assessment.toolConfig.concurrency} workers • ${assessment.toolConfig.rateLimit} req/sec`],
    ['Probe Timeout Cutoff:', `${assessment.toolConfig.timeoutSeconds} seconds`],
    ['DNS Query Types:', assessment.toolConfig.dnsRecordTypes?.join(', ') || 'A, CNAME, MX, TXT, NS'],
    ['Execution Runtime Environment:', envLabel],
  ];

  toolConfigs.forEach(([label, value], i) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    const wrappedVal = doc.splitTextToSize(String(value || 'N/A'), contentWidth - 79);
    const rowHeight = Math.max(6.5, wrappedVal.length * 4 + 2.5);
    checkPageBreak(rowHeight);

    doc.setFillColor(i % 2 === 0 ? 248 : 255, i % 2 === 0 ? 250 : 255, i % 2 === 0 ? 252 : 255);
    doc.rect(margin, y, contentWidth, rowHeight, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 3, y + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(value.includes('ACTIVE') ? 22 : 15, value.includes('ACTIVE') ? 101 : 23, value.includes('ACTIVE') ? 52 : 42);
    doc.text(wrappedVal, margin + 75, y + 4.5);

    y += rowHeight;
  });

  y += 8;

  // --- SECTION 4: FINDINGS & OBSERVATIONS SUMMARY ---
  checkPageBreak(30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(`4. Total Findings & Attack Surface Exposure (${totalFindings})`, margin, y);
  y += 5;

  // Severity count tally
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
    doc.rect(cardX, y, cardWidth, 14, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(c.color[0], c.color[1], c.color[2]);
    doc.text(c.label, cardX + cardWidth / 2, y + 4.5, { align: 'center' });

    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(String(c.count), cardX + cardWidth / 2, y + 11.5, { align: 'center' });
  });

  y += 18;

  // Render all findings with dynamic multi-line wrapping
  if (findings.length > 0) {
    findings.forEach((f, idx) => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      const titleLines = doc.splitTextToSize(`${idx + 1}. ${f.title}`, contentWidth - 6);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      const metaText = `[${f.severity.toUpperCase()}] • ASSET: ${f.assetRef || 'N/A'} • TOOL: ${f.sourceTool || 'ReconX'}`;
      const metaLines = doc.splitTextToSize(metaText, contentWidth - 6);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      const remediationText = f.remediation ? `Remediation: ${f.remediation}` : 'Remediation: Review asset configuration and enforce least-privilege exposure controls.';
      const remediationLines = doc.splitTextToSize(remediationText, contentWidth - 6);

      const boxHeight =
        4.5 +
        titleLines.length * 4 +
        metaLines.length * 3.8 +
        remediationLines.length * 3.8 +
        2.5;

      checkPageBreak(boxHeight + 2);

      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.rect(margin, y, contentWidth, boxHeight, 'FD');

      let innerY = y + 4.5;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      doc.text(titleLines, margin + 3, innerY);
      innerY += titleLines.length * 4 + 0.5;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
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
      innerY += metaLines.length * 3.8 + 0.5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text(remediationLines, margin + 3, innerY);

      y += boxHeight + 2.5;
    });
  } else {
    checkPageBreak(12);
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(
      totalFindings > 0
        ? 'Detailed finding records were omitted from this summary call; open the Assessment Detail console to inspect full evidence.'
        : 'No observation findings recorded for this assessment.',
      margin,
      y + 4
    );
    y += 10;
  }

  // --- FOOTER & COMPLIANCE DISCLAIMER ---
  checkPageBreak(25);
  y += 4;
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(0.4);
  doc.line(margin, y, pageWidth - margin, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  const disclaimerText = 'METHODOLOGICAL DISCLAIMER: ReconX produces reconnaissance observations using authorized passive intelligence and non-destructive service discovery. Findings represent point-in-time surface mappings. No automated exploitation or payload injections were conducted. This document is intended solely for authorized personnel and course evaluation.';
  const splitDisclaimer = doc.splitTextToSize(disclaimerText, contentWidth);
  doc.text(splitDisclaimer, margin, y);

  y += splitDisclaimer.length * 3.5 + 4;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  doc.text(`Generated by ReconX Platform • Operator: ${assessment.ownerEmail} • Cryptographic Audit Reference: OK`, margin, y);

  // Trigger browser download
  const safeName = assessment.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  doc.save(`ReconX_Summary_Report_${safeName}.pdf`);
}
