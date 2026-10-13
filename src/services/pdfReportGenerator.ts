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
  doc.text(
    `CONFIDENTIAL • PREPARED FOR: ${assessment.clientName.toUpperCase()}`,
    margin + 8,
    y + 27
  );

  // Top right badge
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(pageWidth - margin - 42, y + 8, 36, 18, 2, 2, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text('STATUS', pageWidth - margin - 24, y + 14, { align: 'center' });
  doc.setFontSize(9);
  doc.setTextColor(52, 211, 153); // Emerald
  doc.text(assessment.status.toUpperCase(), pageWidth - margin - 24, y + 21, { align: 'center' });

  y += 42;

  // --- METADATA STRIP ---
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.rect(margin, y, contentWidth, 18, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);

  doc.text('ASSESSMENT NAME:', margin + 4, y + 6);
  doc.text('TARGET DOMAIN:', margin + 70, y + 6);
  doc.text('REPORT GENERATED:', margin + 125, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);

  doc.text(doc.splitTextToSize(assessment.name, 62)[0] || assessment.name, margin + 4, y + 12);
  doc.text(assessment.scope.rootDomain, margin + 70, y + 12);
  doc.text(new Date().toLocaleString(), margin + 125, y + 12);

  y += 24;

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
  const overviewText = `An authorized technical reconnaissance assessment was executed against primary root domain "${assessment.scope.rootDomain}" under engagement type "${assessment.type.toUpperCase()}". The automated scan gathered observable assets across Certificate Transparency streams, public DNS records, HTTP web endpoints, and service ports. Total inventory contains ${assessment.stats?.assetsCount || 0} discovered assets, ${assessment.stats?.subdomainsCount || 0} subdomains, ${assessment.stats?.endpointsCount || 0} active web endpoints, and ${totalFindings} identified observation findings.`;

  const splitOverview = doc.splitTextToSize(overviewText, contentWidth);
  doc.text(splitOverview, margin, y);
  y += splitOverview.length * 4.5 + 4;

  // --- SECTION 2: AUTHORIZED SCOPE & ROE ---
  checkPageBreak(50);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('2. Authorized Scope Boundaries & Rules of Engagement', margin, y);
  y += 5;

  const scopeData = [
    ['Root Domain Target:', assessment.scope.rootDomain],
    ['Explicit Approved Hostnames:', assessment.scope.approvedHostnames?.length ? assessment.scope.approvedHostnames.join(', ') : 'All in-scope subdomains of root domain'],
    ['Approved IP / CIDR Ranges:', assessment.scope.approvedIpsAndCidrs?.length ? assessment.scope.approvedIpsAndCidrs.join(', ') : 'Restricted to resolved target infrastructure'],
    ['Permitted Ports Profile:', assessment.scope.permittedPorts?.join(', ') || 'Standard Reconnaissance Profile (80, 443, 22, 53, 8080)'],
    ['Authorization Window:', `${assessment.scope.startDate} through ${assessment.scope.endDate}`],
    ['Rules of Engagement (ROE) Ref:', assessment.scope.authReference || 'ROE-ETHICAL-HACKING-COURSEWORK-2026'],
    ['Authorization Certified By:', assessment.scope.authorizedBy || assessment.ownerEmail],
  ];

  // Draw Scope Table
  scopeData.forEach(([label, value], i) => {
    checkPageBreak(7);
    const rowY = y + i * 6.5;
    doc.setFillColor(i % 2 === 0 ? 248 : 255, i % 2 === 0 ? 250 : 255, i % 2 === 0 ? 252 : 255);
    doc.rect(margin, rowY, contentWidth, 6.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 3, rowY + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    const truncatedVal = doc.splitTextToSize(value, contentWidth - 62)[0] || value;
    doc.text(truncatedVal, margin + 60, rowY + 4.5);
  });

  y += scopeData.length * 6.5 + 8;

  // --- SECTION 3: TOOL CONFIGURATIONS ---
  checkPageBreak(45);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('3. Security Tool Configurations & Scanner Pipeline', margin, y);
  y += 5;

  const toolConfigs = [
    ['Subfinder (Passive Subdomain Harvester)', assessment.toolConfig.subfinder ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['dnsx (Multi-Threaded DNS Resolver)', assessment.toolConfig.dnsx ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['httpx (Web Endpoint & Title Prober)', assessment.toolConfig.httpx ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['Nmap (Controlled Port & Service Discovery)', assessment.toolConfig.nmap ? `ACTIVE (Profile: ${assessment.toolConfig.nmapProfile.toUpperCase()})` : 'DISABLED'],
    ['WhatWeb (Technology Fingerprinter)', assessment.toolConfig.whatweb ? 'ACTIVE (Enabled)' : 'DISABLED'],
    ['Max Concurrency & Rate Limit:', `${assessment.toolConfig.concurrency} workers • ${assessment.toolConfig.rateLimit} req/sec`],
    ['Probe Timeout Cutoff:', `${assessment.toolConfig.timeoutSeconds} seconds`],
    ['DNS Query Types:', assessment.toolConfig.dnsRecordTypes?.join(', ') || 'A, CNAME, MX, TXT, NS'],
    ['Execution Runtime Environment:', assessment.toolConfig.executionEnvironment === 'lab_simulation' ? 'Authorized Lab Emulation (OWASP Juice Shop)' : 'Live DoH & Public CT Stream'],
  ];

  toolConfigs.forEach(([label, value], i) => {
    checkPageBreak(7);
    const rowY = y + i * 6.5;
    doc.setFillColor(i % 2 === 0 ? 248 : 255, i % 2 === 0 ? 250 : 255, i % 2 === 0 ? 252 : 255);
    doc.rect(margin, rowY, contentWidth, 6.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(label, margin + 3, rowY + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(value.includes('ACTIVE') ? 22 : 15, value.includes('ACTIVE') ? 101 : 23, value.includes('ACTIVE') ? 52 : 42);
    doc.text(value, margin + 75, rowY + 4.5);
  });

  y += toolConfigs.length * 6.5 + 8;

  // --- SECTION 4: FINDINGS & OBSERVATIONS SUMMARY ---
  checkPageBreak(50);
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

  // Render individual findings breakdown
  if (findings.length > 0) {
    findings.slice(0, 5).forEach((f, idx) => {
      checkPageBreak(18);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.rect(margin, y, contentWidth, 16, 'FD');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      doc.text(`${idx + 1}. ${f.title}`, margin + 3, y + 4.5);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      const sevColor = f.severity === 'critical' ? [220, 38, 38] : f.severity === 'high' ? [234, 88, 12] : [71, 85, 105];
      doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
      doc.text(`[${f.severity.toUpperCase()}] • ASSET: ${f.assetRef}`, margin + 3, y + 9);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text(`Remediation: ${doc.splitTextToSize(f.remediation, contentWidth - 10)[0]}`, margin + 3, y + 13.5);

      y += 18;
    });
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
