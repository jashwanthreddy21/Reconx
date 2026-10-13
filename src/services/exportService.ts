import { Assessment, Finding } from '../types';

/**
 * Trigger browser file download for text/blob
 */
function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Escape string for CSV cell
 */
function escapeCsv(val: any): string {
  if (val === undefined || val === null) return '""';
  const str = String(val);
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Export Assessment Metadata to CSV
 */
export function exportAssessmentsMetadataCsv(assessments: Assessment[], filenamePrefix = 'reconx_assessments_metadata') {
  const headers = [
    'Assessment ID',
    'Assessment Name',
    'Client / Lab',
    'Root Domain',
    'Type',
    'Status',
    'ROE Reference',
    'Authorized By',
    'Start Date',
    'End Date',
    'Permitted Ports',
    'Subfinder',
    'dnsx',
    'httpx',
    'Nmap Profile',
    'WhatWeb',
    'Concurrency',
    'Rate Limit (req/s)',
    'Total Assets',
    'Subdomains Count',
    'DNS Records Count',
    'Endpoints Count',
    'Services Count',
    'Technologies Count',
    'Total Findings Count',
    'Created At',
    'Updated At',
  ];

  const rows = assessments.map((a) => [
    escapeCsv(a.id),
    escapeCsv(a.name),
    escapeCsv(a.clientName),
    escapeCsv(a.scope?.rootDomain),
    escapeCsv(a.type),
    escapeCsv(a.status),
    escapeCsv(a.scope?.authReference || 'N/A'),
    escapeCsv(a.scope?.authorizedBy || a.ownerEmail),
    escapeCsv(a.scope?.startDate),
    escapeCsv(a.scope?.endDate),
    escapeCsv(a.scope?.permittedPorts?.join(';') || ''),
    escapeCsv(a.toolConfig?.subfinder ? 'Yes' : 'No'),
    escapeCsv(a.toolConfig?.dnsx ? 'Yes' : 'No'),
    escapeCsv(a.toolConfig?.httpx ? 'Yes' : 'No'),
    escapeCsv(a.toolConfig?.nmap ? a.toolConfig.nmapProfile : 'No'),
    escapeCsv(a.toolConfig?.whatweb ? 'Yes' : 'No'),
    escapeCsv(a.toolConfig?.concurrency || 10),
    escapeCsv(a.toolConfig?.rateLimit || 25),
    escapeCsv(a.stats?.assetsCount || 0),
    escapeCsv(a.stats?.subdomainsCount || 0),
    escapeCsv(a.stats?.dnsRecordsCount || 0),
    escapeCsv(a.stats?.endpointsCount || 0),
    escapeCsv(a.stats?.servicesCount || 0),
    escapeCsv(a.stats?.technologiesCount || 0),
    escapeCsv(a.stats?.findingsCount || 0),
    escapeCsv(a.createdAt),
    escapeCsv(a.updatedAt),
  ]);

  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
  const filename = `${filenamePrefix}_${new Date().toISOString().split('T')[0]}.csv`;
  downloadFile(csvContent, filename, 'text/csv;charset=utf-8;');
}

/**
 * Export Findings Summary to CSV
 */
export function exportFindingsSummaryCsv(
  assessments: Assessment[],
  findingsMap: Record<string, Finding[]>,
  filenamePrefix = 'reconx_findings_summary'
) {
  const headers = [
    'Assessment ID',
    'Assessment Name',
    'Client / Lab',
    'Root Domain',
    'Finding ID',
    'Finding Title',
    'Severity',
    'Confidence',
    'Verification Status',
    'Category',
    'Affected Asset',
    'Source Tool',
    'Remediation',
    'Evidence Excerpt',
    'First Seen',
    'Last Seen',
  ];

  const rows: string[][] = [];

  assessments.forEach((a) => {
    const list = findingsMap[a.id] || [];
    list.forEach((f) => {
      rows.push([
        escapeCsv(a.id),
        escapeCsv(a.name),
        escapeCsv(a.clientName),
        escapeCsv(a.scope?.rootDomain),
        escapeCsv(f.id),
        escapeCsv(f.title),
        escapeCsv(f.severity),
        escapeCsv(f.confidence),
        escapeCsv(f.verificationStatus),
        escapeCsv(f.category || 'Reconnaissance Observation'),
        escapeCsv(f.assetRef),
        escapeCsv(f.sourceTool),
        escapeCsv(f.remediation),
        escapeCsv(f.evidence),
        escapeCsv(f.firstSeen),
        escapeCsv(f.lastSeen),
      ]);
    });
  });

  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
  const filename = `${filenamePrefix}_${new Date().toISOString().split('T')[0]}.csv`;
  downloadFile(csvContent, filename, 'text/csv;charset=utf-8;');
}

/**
 * Export Complete Assessments & Findings Dataset to JSON
 */
export function exportAssessmentsAndFindingsJson(
  assessments: Assessment[],
  findingsMap: Record<string, Finding[]>,
  filenamePrefix = 'reconx_assessments_export'
) {
  const exportPayload = {
    platform: 'ReconX — Automated Reconnaissance & Attack Surface Mapper',
    exportTimestamp: new Date().toISOString(),
    totalAssessments: assessments.length,
    totalFindings: Object.values(findingsMap).reduce((sum, fList) => sum + fList.length, 0),
    data: assessments.map((a) => ({
      metadata: {
        id: a.id,
        name: a.name,
        clientName: a.clientName,
        type: a.type,
        status: a.status,
        isDemo: a.isDemo || false,
        createdAt: a.createdAt,
        updatedAt: a.updatedAt,
      },
      scope: a.scope,
      toolConfig: a.toolConfig,
      stats: a.stats,
      findingsSummary: {
        count: (findingsMap[a.id] || []).length,
        severityBreakdown: {
          critical: (findingsMap[a.id] || []).filter((f) => f.severity === 'critical').length,
          high: (findingsMap[a.id] || []).filter((f) => f.severity === 'high').length,
          medium: (findingsMap[a.id] || []).filter((f) => f.severity === 'medium').length,
          low: (findingsMap[a.id] || []).filter((f) => f.severity === 'low').length,
          informational: (findingsMap[a.id] || []).filter((f) => f.severity === 'informational').length,
        },
        items: findingsMap[a.id] || [],
      },
    })),
  };

  const jsonString = JSON.stringify(exportPayload, null, 2);
  const filename = `${filenamePrefix}_${new Date().toISOString().split('T')[0]}.json`;
  downloadFile(jsonString, filename, 'application/json');
}

/**
 * Export Single Assessment Metadata + Findings to CSV
 */
export function exportSingleAssessmentCsv(assessment: Assessment, findings: Finding[] = []) {
  const metadataHeaders = ['Metric / Field', 'Value'];
  const metaRows = [
    ['Assessment ID', assessment.id],
    ['Assessment Name', assessment.name],
    ['Client / Lab', assessment.clientName],
    ['Root Domain Target', assessment.scope.rootDomain],
    ['Mode', assessment.type],
    ['Status', assessment.status],
    ['ROE Reference', assessment.scope.authReference || 'N/A'],
    ['Total Discovered Assets', String(assessment.stats?.assetsCount || 0)],
    ['Subdomains Count', String(assessment.stats?.subdomainsCount || 0)],
    ['Web Endpoints Count', String(assessment.stats?.endpointsCount || 0)],
    ['Network Services Count', String(assessment.stats?.servicesCount || 0)],
    ['Total Findings Count', String(findings.length || assessment.stats?.findingsCount || 0)],
    ['Execution Environment', assessment.toolConfig.executionEnvironment],
    ['Created Timestamp', assessment.createdAt],
  ].map(([k, v]) => `${escapeCsv(k)},${escapeCsv(v)}`);

  const findingHeaders = [
    'Finding ID',
    'Title',
    'Severity',
    'Verification Status',
    'Asset Reference',
    'Source Tool',
    'Remediation Guidance',
    'Evidence',
  ];
  const findingRows = findings.map((f) =>
    [
      escapeCsv(f.id),
      escapeCsv(f.title),
      escapeCsv(f.severity),
      escapeCsv(f.verificationStatus),
      escapeCsv(f.assetRef),
      escapeCsv(f.sourceTool),
      escapeCsv(f.remediation),
      escapeCsv(f.evidence),
    ].join(',')
  );

  const fullCsv = [
    '=== ASSESSMENT METADATA ===',
    metadataHeaders.join(','),
    ...metaRows,
    '',
    '=== FINDINGS SUMMARY ===',
    findingHeaders.join(','),
    ...findingRows,
  ].join('\r\n');

  const safeName = assessment.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  downloadFile(fullCsv, `reconx_${safeName}_summary.csv`, 'text/csv;charset=utf-8;');
}

/**
 * Export Single Assessment to JSON
 */
export function exportSingleAssessmentJson(assessment: Assessment, findings: Finding[] = []) {
  const payload = {
    platform: 'ReconX Attack Surface Mapper',
    exportedAt: new Date().toISOString(),
    assessment,
    findingsSummary: {
      total: findings.length || assessment.stats?.findingsCount || 0,
      breakdown: {
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        informational: findings.filter((f) => f.severity === 'informational').length,
      },
      items: findings,
    },
  };
  const safeName = assessment.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  downloadFile(JSON.stringify(payload, null, 2), `reconx_${safeName}_export.json`, 'application/json');
}
