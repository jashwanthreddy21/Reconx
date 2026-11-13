import assert from 'node:assert/strict';
import http from 'node:http';
import {
  normalizeAssetValue,
  calculateConfidenceScore,
  runAssetCorrelationEngine,
  generateDeterministicAIAnalysis
} from '../services/assetCorrelationEngine';
import {
  createAssessmentSnapshot,
  compareAssessmentSnapshots
} from '../services/changeDetectionEngine';
import { calculateAssessmentRiskScore } from '../services/riskScoringEngine';
import {
  filterAlertableFindings,
  buildSlackAlertPayload,
  isValidSlackWebhookUrl,
} from '../services/slackAlertService';
import {
  classifyReservedOrRirFallback,
  extractAssetIp,
  isExternalPublicIp,
  isPrivateOrNonRoutableIp,
  mapCountryToGeoRegion,
} from '../services/ipGeolocationService';
import {
  buildSubdomainSearchEntries,
  clearGlobalSearchCache,
  loadGlobalSubdomainIndex,
  queryGlobalSearchIndex,
} from '../services/globalSearchService';
import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  WebhookNotificationConfig,
} from '../types';

process.env.RECONX_TEST_MODE = 'true';

async function runAllTests() {
  console.log('==============================================================');
  console.log('RECONX — AUTOMATED VERIFICATION SUITE (14 REQUIRED SCENARIOS)');
  console.log('==============================================================\n');

  const dummyAssessment: Assessment = {
    id: 'test_asm_1',
    name: 'Test Recon Assessment',
    clientName: 'Cyber Defense Lab',
    description: 'Unit & Integration Test Suite',
    ownerId: 'analyst_01',
    ownerEmail: 'analyst@reconx.local',
    type: 'mixed',
    status: 'completed',
    scope: {
      rootDomain: 'Example.COM.',
      allowedSubdomains: true,
      ipRanges: ['93.184.216.0/24'],
      exclusions: [],
      allowActiveProbing: true,
      allowPortScanning: true,
      authorizationConfirmed: true,
    },
    toolConfig: {
      subfinder: true,
      dnsx: true,
      httpx: true,
      nmap: true,
      whatweb: true,
      nmapProfile: 'service_detection',
      rateLimitRps: 20,
      timeoutSeconds: 30,
    },
    stats: {
      totalAssets: 0,
      subdomainsCount: 0,
      ipAddressesCount: 0,
      liveEndpointsCount: 0,
      openPortsCount: 0,
      findingsCount: 0,
    },
    createdAt: '2026-10-01T00:00:00.000Z',
    updatedAt: '2026-10-01T00:10:00.000Z',
  };

  // 1. Asset Normalization
  {
    assert.equal(
      normalizeAssetValue('  API.Example.COM. ', 'subdomain'),
      'api.example.com',
      'Subdomain normalization should lowercase, trim, and strip trailing dot'
    );
    assert.equal(
      normalizeAssetValue('HTTPS://Portal.Example.com:443/', 'endpoint'),
      'https://portal.example.com',
      'Endpoint normalization should lowercase, strip default port 443, and strip trailing slash'
    );
    console.log('✅ 1. Asset normalization passed');
  }

  // 2. Duplicate Asset Detection
  {
    const duplicateAssets: Asset[] = [
      {
        id: 'dup_1',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        canonicalName: 'api.example.com',
        assetType: 'subdomain',
        discoverySource: 'Subfinder',
        status: 'active',
        firstSeen: '2026-10-01T01:00:00.000Z',
        lastSeen: '2026-10-01T01:00:00.000Z',
        metadata: { source: 'ct_logs' },
      },
      {
        id: 'dup_2',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        canonicalName: 'API.EXAMPLE.COM.',
        assetType: 'subdomain',
        discoverySource: 'Amass',
        status: 'resolved',
        firstSeen: '2026-10-01T00:30:00.000Z',
        lastSeen: '2026-10-01T02:00:00.000Z',
        metadata: { asn: 'AS15133' },
      },
    ];

    const corr = runAssetCorrelationEngine(dummyAssessment, duplicateAssets, [], [], []);
    const subs = corr.normalizedAssets.filter((a) => a.assetType === 'subdomain');
    assert.equal(subs.length, 1, 'Duplicate subdomains from Subfinder and Amass must merge into 1');
    assert.ok(
      subs[0].sources?.includes('Subfinder') && subs[0].sources?.includes('Amass'),
      'Merged asset must preserve both Subfinder and Amass sources'
    );
    assert.equal(subs[0].firstSeen, '2026-10-01T00:30:00.000Z', 'Should retain earliest firstSeen');
    assert.equal(subs[0].lastSeen, '2026-10-01T02:00:00.000Z', 'Should retain latest lastSeen');
    console.log('✅ 2. Duplicate asset detection & source merging passed');
  }

  // 3. Asset Relationship Correlation
  const sampleDns: DnsRecord[] = [
    {
      id: 'd1',
      assessmentId: dummyAssessment.id,
      ownerId: dummyAssessment.ownerId,
      hostname: 'api.example.com',
      recordType: 'A',
      value: '93.184.216.34',
      ttl: 300,
      source: 'dnsx',
      timestamp: '2026-10-01T01:00:00.000Z',
    },
  ];
  const sampleEps: WebEndpoint[] = [
    {
      id: 'e1',
      assessmentId: dummyAssessment.id,
      ownerId: dummyAssessment.ownerId,
      url: 'https://api.example.com',
      hostname: 'api.example.com',
      port: 443,
      protocol: 'https',
      statusCode: 200,
      title: 'API Gateway',
      ip: '93.184.216.34',
      technologies: ['Nginx', 'Express'],
      timestamp: '2026-10-01T01:00:00.000Z',
    },
  ];
  const sampleSvcs: NetworkService[] = [
    {
      id: 's1',
      assessmentId: dummyAssessment.id,
      ownerId: dummyAssessment.ownerId,
      host: 'api.example.com',
      ip: '93.184.216.34',
      port: 443,
      protocol: 'tcp',
      state: 'open',
      serviceName: 'https',
      version: 'nginx 1.24',
      toolSource: 'Nmap',
      timestamp: '2026-10-01T01:00:00.000Z',
    },
  ];

  const fullCorr = runAssetCorrelationEngine(
    dummyAssessment,
    [],
    sampleDns,
    sampleEps,
    sampleSvcs
  );
  {
    const relTypes = new Set(fullCorr.relationships.map((r) => r.relationshipType));
    assert.ok(relTypes.has('HAS_SUBDOMAIN'), 'Must correlate Root domain -> Subdomain');
    assert.ok(relTypes.has('RESOLVES_TO'), 'Must correlate Subdomain -> IP address');
    assert.ok(relTypes.has('EXPOSES_PORT'), 'Must correlate IP address -> Open port');
    assert.ok(relTypes.has('RUNS_SERVICE'), 'Must correlate Port -> Running service');
    assert.ok(relTypes.has('USES_TECHNOLOGY'), 'Must correlate Web endpoint -> Detected technology');
    console.log('✅ 3. Asset relationship correlation passed');
  }

  // 4. Confidence Score Calculation
  {
    const singleScore = calculateConfidenceScore(['Subfinder'], true, false);
    const multiScore = calculateConfidenceScore(['Subfinder', 'Amass', 'dnsx'], true, true);
    assert.ok(multiScore > singleScore, 'Multi-tool corroborated confidence must exceed single tool');
    assert.ok(multiScore <= 99 && singleScore >= 40, 'Confidence score must stay within valid bounds');
    console.log('✅ 4. Confidence score calculation passed');
  }

  // 5. Attack Surface Graph Generation & 6. Graph Filtering
  const { app } = await import('../../server');
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    // 5. Attack Surface Graph Generation
    const graphRes = await fetch(`${baseUrl}/api/attack-surface/graph?assessmentId=asm_latest_02`);
    assert.equal(graphRes.status, 200);
    const graphData = await graphRes.json();
    assert.ok(graphData.nodes.length > 0, 'Graph must contain correlated nodes');
    assert.ok(graphData.edges.length > 0, 'Graph must contain relationship edges');
    console.log('✅ 5. Attack surface graph generation passed');

    // 6. Graph Filtering
    const filteredGraphRes = await fetch(
      `${baseUrl}/api/attack-surface/graph?assessmentId=asm_latest_02&category=subdomain`
    );
    assert.equal(filteredGraphRes.status, 200);
    const filteredGraph = await filteredGraphRes.json();
    assert.ok(
      filteredGraph.nodes.every((n: Asset) => n.assetType === 'subdomain'),
      'Graph category filter must return only matching asset category'
    );
    console.log('✅ 6. Graph filtering passed');

    // 7. Historical Snapshot Creation
    const snap1 = createAssessmentSnapshot(
      dummyAssessment,
      fullCorr.normalizedAssets,
      fullCorr.relationships,
      sampleDns,
      sampleEps,
      sampleSvcs
    );
    assert.equal(snap1.assessmentId, dummyAssessment.id);
    assert.equal(snap1.assetCount, fullCorr.normalizedAssets.length);
    assert.ok(Object.keys(snap1.assetMap).length > 0, 'Snapshot must contain stable assetMap digests');
    console.log('✅ 7. Historical snapshot creation passed');

    // 8. New Asset Detection, 9. Missing Asset Detection, 10. Modified Asset Detection, 11. Assessment Comparison
    const latestAssessment: Assessment = {
      ...dummyAssessment,
      id: 'test_asm_2',
      createdAt: '2026-10-15T00:00:00.000Z',
    };
    const latestDns: DnsRecord[] = [
      // api.example.com changed IP from 93.184.216.34 -> 93.184.216.99 (MODIFIED)
      {
        id: 'd1_new',
        assessmentId: latestAssessment.id,
        ownerId: latestAssessment.ownerId,
        hostname: 'api.example.com',
        recordType: 'A',
        value: '93.184.216.99',
        ttl: 300,
        source: 'dnsx',
        timestamp: '2026-10-15T01:00:00.000Z',
      },
      // new.example.com is newly discovered (NEW)
      {
        id: 'd2_new',
        assessmentId: latestAssessment.id,
        ownerId: latestAssessment.ownerId,
        hostname: 'new.example.com',
        recordType: 'A',
        value: '93.184.216.99',
        ttl: 300,
        source: 'Subfinder',
        timestamp: '2026-10-15T01:00:00.000Z',
      },
    ];
    // Add an asset in baseline that won't be in latest to test NOT_OBSERVED
    const baselineExtraAsset: Asset = {
      id: 'legacy_sub',
      assessmentId: dummyAssessment.id,
      ownerId: dummyAssessment.ownerId,
      canonicalName: 'legacy.example.com',
      assetType: 'subdomain',
      discoverySource: 'Subfinder',
      status: 'active',
      firstSeen: '2026-10-01T00:00:00.000Z',
      lastSeen: '2026-10-01T00:00:00.000Z',
    };
    const baseCorrWithLegacy = runAssetCorrelationEngine(
      dummyAssessment,
      [baselineExtraAsset],
      sampleDns,
      sampleEps,
      sampleSvcs
    );
    const baseSnapWithLegacy = createAssessmentSnapshot(
      dummyAssessment,
      baseCorrWithLegacy.normalizedAssets,
      baseCorrWithLegacy.relationships,
      sampleDns,
      sampleEps,
      sampleSvcs
    );

    const latCorr = runAssetCorrelationEngine(latestAssessment, [], latestDns, [], []);
    const latSnap = createAssessmentSnapshot(
      latestAssessment,
      latCorr.normalizedAssets,
      latCorr.relationships,
      latestDns,
      [],
      []
    );

    const comparison = compareAssessmentSnapshots(
      baseSnapWithLegacy,
      latSnap,
      dummyAssessment,
      latestAssessment
    );

    const newChanges = comparison.changes.filter((c) => c.changeType === 'NEW');
    const notObservedChanges = comparison.changes.filter((c) => c.changeType === 'NOT_OBSERVED');
    const modifiedChanges = comparison.changes.filter((c) => c.changeType === 'MODIFIED');

    assert.ok(
      newChanges.some((c) => c.assetName === 'new.example.com'),
      'Must detect newly discovered subdomain as NEW'
    );
    console.log('✅ 8. New asset detection passed');

    const legacyMissing = notObservedChanges.find((c) => c.assetName === 'legacy.example.com');
    assert.ok(legacyMissing, 'Must detect missing baseline asset as NOT_OBSERVED');
    assert.ok(
      legacyMissing.observationNote.includes('Not observed in latest scan'),
      'Missing asset must be labeled "Not observed in latest scan"'
    );
    console.log('✅ 9. Missing asset detection ("Not observed in latest scan") passed');

    assert.ok(
      modifiedChanges.some((c) => c.assetName === 'api.example.com'),
      'Must detect changed DNS/IP mapping on api.example.com as MODIFIED'
    );
    console.log('✅ 10. Modified asset detection passed');

    const apiCompareRes = await fetch(
      `${baseUrl}/api/assessments/compare?previousAssessmentId=asm_baseline_01&latestAssessmentId=asm_latest_02`
    );
    assert.equal(apiCompareRes.status, 200);
    const apiCompareData = await apiCompareRes.json();
    assert.ok(apiCompareData.summary.newAssetsCount > 0, 'API compare must return summary counts');
    console.log('✅ 11. Assessment comparison API & engine passed');

    // 12. API Validation & Error Handling
    const badPostRes = await fetch(`${baseUrl}/api/ai/analyze-assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(badPostRes.status, 400, 'Invalid POST payload must return HTTP 400');

    const missingAssetRes = await fetch(`${baseUrl}/api/assets/non_existent_asset_999`);
    assert.equal(missingAssetRes.status, 404, 'Unknown asset ID must return HTTP 404');
    console.log('✅ 12. API input validation & error status checks passed');

    // 13. AI Fallback Behavior when AI is disabled or unavailable
    const savedKey = process.env.GEMINI_API_KEY;
    delete process.env.GEMINI_API_KEY;
    const fallbackRes = await fetch(`${baseUrl}/api/ai/analyze-assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        assessment: dummyAssessment,
        assets: fullCorr.normalizedAssets,
        relationships: fullCorr.relationships,
        correlation: fullCorr.correlationSummary,
      }),
    });
    if (savedKey) process.env.GEMINI_API_KEY = savedKey;
    assert.equal(fallbackRes.status, 200);
    const fallbackAnalysis = await fallbackRes.json();
    assert.equal(fallbackAnalysis.provider, 'deterministic_fallback');
    assert.ok(fallbackAnalysis.executiveSummary.length > 20);
    assert.ok(Array.isArray(fallbackAnalysis.relationshipInsights));
    console.log('✅ 13. AI fallback behavior (deterministic rule-based engine) passed');

    // 14. Performance with Large Asset Collections (1,200+ assets)
    const largeAssets: Asset[] = [];
    for (let i = 0; i < 1200; i++) {
      largeAssets.push({
        id: `perf_sub_${i}`,
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        canonicalName: `node-${i}.example.com`,
        assetType: 'subdomain',
        discoverySource: i % 2 === 0 ? 'Subfinder' : 'Amass',
        status: 'active',
        firstSeen: '2026-10-01T00:00:00.000Z',
        lastSeen: '2026-10-01T00:00:00.000Z',
      });
    }
    const t0 = performance.now();
    const perfCorr = runAssetCorrelationEngine(dummyAssessment, largeAssets, [], [], []);
    const elapsedMs = performance.now() - t0;
    assert.equal(perfCorr.normalizedAssets.length, 1201); // 1 root + 1200 subdomains
    assert.ok(
      elapsedMs < 1500,
      `Large collection correlation (1,200+ assets) must complete rapidly (took ${elapsedMs.toFixed(1)}ms)`
    );
    console.log(
      `✅ 14. Large asset collection performance passed (1,201 assets correlated in ${elapsedMs.toFixed(1)}ms)`
    );

    // 15. Weighted Risk-Scoring Engine
    const lowExposureRisk = calculateAssessmentRiskScore({
      assessment: dummyAssessment,
      assets: fullCorr.normalizedAssets,
      services: sampleSvcs, // only 443 HTTPS
      endpoints: sampleEps, // only HTTPS 200
      findings: [],
    });
    const highExposureFindings: Finding[] = [
      {
        id: 'rf_1',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        title: 'Critical Exposed Redis & Remote Code Surface',
        description: 'Unauthenticated Redis listener exposed externally.',
        severity: 'critical',
        confidence: 'certain',
        category: 'Database Security',
        assetRef: 'db.example.com:6379',
        evidence: 'Port 6379 open with banner',
        sourceTool: 'Nmap',
        remediation: 'Restrict access to private VPC',
        verificationStatus: 'verified',
        firstSeen: '2026-10-01T00:00:00.000Z',
        lastSeen: '2026-10-01T00:00:00.000Z',
      },
      {
        id: 'rf_2',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        title: 'Deprecated TLS 1.0 Cipher Suite',
        description: 'Weak cipher enabled.',
        severity: 'high',
        confidence: 'firm',
        category: 'TLS',
        assetRef: 'api.example.com',
        evidence: 'TLS 1.0 handshake',
        sourceTool: 'httpx',
        remediation: 'Upgrade to TLS 1.3',
        verificationStatus: 'potential_risk',
        firstSeen: '2026-10-01T00:00:00.000Z',
        lastSeen: '2026-10-01T00:00:00.000Z',
      },
    ];
    const highExposureServices: NetworkService[] = [
      ...sampleSvcs,
      {
        id: 's_redis',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        host: 'db.example.com',
        ip: '93.184.216.99',
        port: 6379,
        protocol: 'tcp',
        state: 'open',
        serviceName: 'redis',
        version: 'Redis 6.2.1',
        toolSource: 'Nmap',
        timestamp: '2026-10-01T01:00:00.000Z',
      },
    ];
    const highExposureRisk = calculateAssessmentRiskScore({
      assessment: dummyAssessment,
      assets: fullCorr.normalizedAssets,
      services: highExposureServices,
      endpoints: sampleEps,
      findings: highExposureFindings,
    });
    assert.ok(
      highExposureRisk.aggregateScore > lowExposureRisk.aggregateScore,
      'Aggregate risk score must increase significantly with critical ports, exposed services, and findings'
    );
    assert.ok(
      highExposureRisk.aggregateScore >= 65 && highExposureRisk.aggregateScore <= 100,
      'Critical finding + Redis exposure must yield High/Critical risk score within [65, 100]'
    );
    assert.ok(
      highExposureRisk.subScores.openPortsScore > lowExposureRisk.subScores.openPortsScore &&
        highExposureRisk.subScores.exposedServicesScore >
          lowExposureRisk.subScores.exposedServicesScore &&
        highExposureRisk.subScores.vulnerabilitiesScore > 0,
      'All three weighted risk pillars must reflect exposure increases'
    );
    console.log(
      `✅ 15. Weighted risk-scoring engine passed (Low=${lowExposureRisk.aggregateScore}/100 vs Critical=${highExposureRisk.aggregateScore}/100)`
    );

    // 16. Automated Slack Webhook Alerting (Filtering, Validation, Payload & HTTP Dispatch)
    const webhookConfig: WebhookNotificationConfig = {
      enabled: true,
      provider: 'slack',
      webhookUrl: 'https://hooks.slack.com/services/example-org/example-channel/example-token',
      channelName: '#secops-critical',
      minSeverity: 'high',
      notifyOnScanComplete: false,
    };

    const urlValidationValid = isValidSlackWebhookUrl(webhookConfig.webhookUrl);
    const urlValidationInvalid = isValidSlackWebhookUrl('http://hooks.slack.com/services/insecure');
    assert.equal(urlValidationValid.valid, true, 'Standard HTTPS Slack webhook URL must validate');
    assert.equal(urlValidationInvalid.valid, false, 'Non-HTTPS webhook URL must be rejected');

    const mixedFindings: Finding[] = [
      ...highExposureFindings, // critical + high
      {
        id: 'rf_low',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        title: 'Missing X-Content-Type-Options Header',
        description: 'Informational hardening note.',
        severity: 'low',
        confidence: 'firm',
        category: 'HTTP Headers',
        assetRef: 'https://api.example.com',
        evidence: 'Header absent',
        sourceTool: 'httpx',
        remediation: 'Add nosniff header',
        verificationStatus: 'observed_fact',
        firstSeen: '2026-10-01T00:00:00.000Z',
        lastSeen: '2026-10-01T00:00:00.000Z',
      },
    ];

    const alertable = filterAlertableFindings(mixedFindings, webhookConfig);
    assert.equal(alertable.length, 2, 'High threshold must filter out low severity findings');
    assert.equal(alertable[0].severity, 'critical', 'Critical findings must sort first in alerts');

    let receivedWebhookBody: any = null;
    const mockSlackServer = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk) => {
        raw += chunk;
      });
      req.on('end', () => {
        receivedWebhookBody = JSON.parse(raw);
        res.statusCode = 200;
        res.end('ok');
      });
    });
    await new Promise<void>((resolve) => mockSlackServer.listen(0, '127.0.0.1', resolve));
    const slackAddr = mockSlackServer.address() as { port: number };
    const mockWebhookUrl = `http://127.0.0.1:${slackAddr.port}/services/test/mock`;

    try {
      const payload = buildSlackAlertPayload({
        assessment: dummyAssessment,
        findings: alertable,
        webhookConfig,
        riskScore: highExposureRisk.aggregateScore,
        riskTier: highExposureRisk.severityTier,
      });

      const notifyRes = await fetch(`${baseUrl}/api/notifications/slack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          webhookUrl: mockWebhookUrl,
          channelName: webhookConfig.channelName,
          assessmentName: dummyAssessment.name,
          rootDomain: dummyAssessment.scope.rootDomain,
          alertedCount: alertable.length,
          payload,
        }),
      });
      assert.equal(notifyRes.status, 200, 'Slack proxy endpoint must deliver webhook payload');
      const notifyJson = await notifyRes.json();
      assert.equal(notifyJson.ok, true);
      assert.equal(notifyJson.alertedCount, 2);
      assert.ok(receivedWebhookBody?.blocks?.length >= 4, 'Slack Block Kit payload must be received');
      assert.ok(
        receivedWebhookBody.text.includes('Example.COM.'),
        'Slack notification text must include target domain'
      );

      // Verify bad payload returns HTTP 400
      const badNotifyRes = await fetch(`${baseUrl}/api/notifications/slack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ webhookUrl: 'not-a-url' }),
      });
      assert.equal(badNotifyRes.status, 400, 'Malformed webhook URL must return HTTP 400');
    } finally {
      mockSlackServer.close();
    }

    console.log('✅ 16. Automated Slack webhook alerting & /api/notifications/slack dispatch passed');

    // 17. External IP Geolocation Resolution, Asset IP Extraction & Geographic Region Filtering
    assert.equal(isPrivateOrNonRoutableIp('10.14.0.5'), true, 'RFC1918 10.x must be marked private/internal');
    assert.equal(isExternalPublicIp('10.14.0.5'), false, 'RFC1918 IP must not be flagged external');
    assert.equal(isExternalPublicIp('198.51.100.42'), true, 'Public IPv4 must be flagged external');

    assert.equal(mapCountryToGeoRegion('US', 'North America').id, 'north-america');
    assert.equal(mapCountryToGeoRegion('DE', 'Europe').id, 'europe');
    assert.equal(mapCountryToGeoRegion('SG', 'Asia').id, 'asia-pacific');
    assert.equal(mapCountryToGeoRegion('BR', 'South America').id, 'latin-america');
    assert.equal(mapCountryToGeoRegion('ZA', 'Africa').id, 'middle-east-africa');

    const dnsCorrelatedAsset: Asset = {
      id: 'geo_ast_1',
      assessmentId: dummyAssessment.id,
      ownerId: dummyAssessment.ownerId,
      assetType: 'subdomain',
      assetValue: 'edge.example.com',
      canonicalName: 'edge.example.com',
      normalizedValue: 'edge.example.com',
      discoverySource: 'dnsx',
      confidenceScore: 95,
      status: 'active',
      firstSeen: '2026-10-01T00:00:00.000Z',
      lastSeen: '2026-10-01T00:00:00.000Z',
    };
    const sampleDnsRecords: DnsRecord[] = [
      {
        id: 'dns_geo_1',
        assessmentId: dummyAssessment.id,
        ownerId: dummyAssessment.ownerId,
        hostname: 'edge.example.com',
        recordType: 'A',
        value: '198.51.100.42',
        ttl: 300,
        source: 'dnsx',
        timestamp: '2026-10-01T00:00:00.000Z',
      },
    ];
    assert.equal(
      extractAssetIp(dnsCorrelatedAsset, sampleDnsRecords, [], []),
      '198.51.100.42',
      'extractAssetIp must resolve IPv4 from correlated DNS A record'
    );

    assert.equal(classifyReservedOrRirFallback('198.51.100.42').countryCode, 'DE');
    assert.equal(classifyReservedOrRirFallback('198.51.100.42').geoRegionId, 'europe');
    assert.equal(classifyReservedOrRirFallback('203.0.113.99').countryCode, 'SG');
    assert.equal(classifyReservedOrRirFallback('203.0.113.99').geoRegionId, 'asia-pacific');

    const geoBatchRes = await fetch(`${baseUrl}/api/geo/ip-lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: ['10.14.0.5', '8.8.8.8', '198.51.100.42'] }),
    });
    assert.equal(geoBatchRes.status, 200, '/api/geo/ip-lookup must return HTTP 200');
    const geoBatchJson = await geoBatchRes.json();
    assert.equal(geoBatchJson.ok, true);
    assert.equal(geoBatchJson.results['10.14.0.5'].isExternal, false);
    assert.equal(geoBatchJson.results['10.14.0.5'].geoRegionId, 'internal');
    assert.equal(geoBatchJson.results['8.8.8.8'].isExternal, true);
    assert.equal(geoBatchJson.results['8.8.8.8'].countryCode, 'US');
    assert.equal(geoBatchJson.results['8.8.8.8'].geoRegionId, 'north-america');
    assert.equal(geoBatchJson.results['198.51.100.42'].isExternal, true);
    assert.ok(geoBatchJson.results['198.51.100.42'].country.length > 0);
    assert.notEqual(geoBatchJson.results['198.51.100.42'].geoRegionId, 'internal');

    const geoSingleRes = await fetch(`${baseUrl}/api/geo/ip/8.8.8.8`);
    assert.equal(geoSingleRes.status, 200, 'GET /api/geo/ip/:ip must return HTTP 200');
    const geoSingleJson = await geoSingleRes.json();
    assert.equal(geoSingleJson.geo.countryCode, 'US');

    const badGeoRes = await fetch(`${baseUrl}/api/geo/ip-lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: ['not-an-ip'] }),
    });
    assert.equal(badGeoRes.status, 400, 'Invalid IPs payload must return HTTP 400');

    console.log('✅ 17. IP geolocation resolution, asset IP extraction & geographic lookup API passed');

    // 18. AppShell Global Search across Assessment Names, Clients, and Discovered Subdomains
    clearGlobalSearchCache();
    const searchAsmA: Assessment = {
      ...dummyAssessment,
      id: 'search_asm_a',
      name: 'Payment Gateway Audit',
      clientName: 'Acme Financial Corp',
      scope: {
        ...dummyAssessment.scope,
        rootDomain: 'acme-pay.com',
        approvedHostnames: ['api.acme-pay.com'],
      },
      stats: { ...dummyAssessment.stats, subdomainsCount: 3, assetsCount: 4 },
      updatedAt: '2026-10-05T10:00:00.000Z',
    };
    const searchAsmB: Assessment = {
      ...dummyAssessment,
      id: 'search_asm_b',
      name: 'Perimeter Edge Discovery',
      clientName: 'Globex Logistics',
      scope: {
        ...dummyAssessment.scope,
        rootDomain: 'globex-logistics.io',
        approvedHostnames: ['portal.globex-logistics.io'],
      },
      stats: { ...dummyAssessment.stats, subdomainsCount: 2, assetsCount: 2 },
      updatedAt: '2026-10-06T10:00:00.000Z',
    };

    const mockDiscoveredAssets: Record<string, Asset[]> = {
      search_asm_a: [
        {
          id: 'sub_1',
          assessmentId: 'search_asm_a',
          ownerId: 'analyst_01',
          assetType: 'subdomain',
          assetValue: 'internal-vault.acme-pay.com',
          canonicalName: 'internal-vault.acme-pay.com',
          normalizedValue: 'internal-vault.acme-pay.com',
          discoverySource: 'Subfinder',
          confidenceScore: 96,
          status: 'active',
          firstSeen: '2026-10-05T10:00:00.000Z',
          lastSeen: '2026-10-05T10:00:00.000Z',
        },
        {
          id: 'sub_2',
          assessmentId: 'search_asm_a',
          ownerId: 'analyst_01',
          assetType: 'subdomain',
          assetValue: 'api.acme-pay.com',
          canonicalName: 'api.acme-pay.com',
          normalizedValue: 'api.acme-pay.com',
          discoverySource: 'dnsx',
          confidenceScore: 99,
          status: 'active',
          firstSeen: '2026-10-05T10:00:00.000Z',
          lastSeen: '2026-10-05T10:00:00.000Z',
        },
      ],
      search_asm_b: [
        {
          id: 'sub_3',
          assessmentId: 'search_asm_b',
          ownerId: 'analyst_01',
          assetType: 'subdomain',
          assetValue: 'tracking-vault.globex-logistics.io',
          canonicalName: 'tracking-vault.globex-logistics.io',
          normalizedValue: 'tracking-vault.globex-logistics.io',
          discoverySource: 'Subfinder',
          confidenceScore: 92,
          status: 'active',
          firstSeen: '2026-10-06T10:00:00.000Z',
          lastSeen: '2026-10-06T10:00:00.000Z',
        },
      ],
    };

    // Deduplication test between assets and scope hostnames
    const builtA = buildSubdomainSearchEntries(searchAsmA, mockDiscoveredAssets.search_asm_a);
    assert.equal(
      builtA.filter((e) => e.subdomain === 'api.acme-pay.com').length,
      1,
      'Subdomain search entries must deduplicate scope hostnames already in discovered assets'
    );

    let fetchCount = 0;
    const mockFetcher = async (id: string) => {
      fetchCount += 1;
      return mockDiscoveredAssets[id] || [];
    };

    const firstIndex = await loadGlobalSubdomainIndex([searchAsmA, searchAsmB], mockFetcher);
    assert.equal(fetchCount, 2, 'Initial global index build must fetch assets once per assessment');
    await loadGlobalSubdomainIndex([searchAsmA, searchAsmB], mockFetcher);
    assert.equal(fetchCount, 2, 'Cached global search index must avoid duplicate Firestore reads');

    // Query 1: Match Assessment Name
    const byName = queryGlobalSearchIndex('Payment Gateway', [searchAsmA, searchAsmB], firstIndex);
    assert.equal(byName.assessmentHits.length, 1);
    assert.equal(byName.assessmentHits[0].assessment.id, 'search_asm_a');
    assert.ok(byName.assessmentHits[0].matchedFields.includes('name'));

    // Query 2: Match Client Name
    const byClient = queryGlobalSearchIndex('Globex Logistics', [searchAsmA, searchAsmB], firstIndex);
    assert.equal(byClient.assessmentHits.length, 1);
    assert.equal(byClient.assessmentHits[0].assessment.id, 'search_asm_b');
    assert.ok(byClient.assessmentHits[0].matchedFields.includes('client'));

    // Query 3: Match Discovered Subdomain across multiple assessments
    const bySubdomain = queryGlobalSearchIndex('vault', [searchAsmA, searchAsmB], firstIndex);
    assert.equal(bySubdomain.subdomainHits.length, 2, 'Query must match discovered subdomains across all assessments');
    assert.equal(bySubdomain.assessmentHits.length, 2, 'Parent assessments containing matching subdomains must surface');

    const byExactSubdomain = queryGlobalSearchIndex('internal-vault', [searchAsmA, searchAsmB], firstIndex);
    assert.equal(byExactSubdomain.subdomainHits.length, 1);
    assert.equal(byExactSubdomain.subdomainHits[0].entry.subdomain, 'internal-vault.acme-pay.com');
    assert.equal(byExactSubdomain.subdomainHits[0].entry.assessmentId, 'search_asm_a');

    // Query 4: Non-matching query
    const noMatch = queryGlobalSearchIndex('nonexistent-xyz-target', [searchAsmA, searchAsmB], firstIndex);
    assert.equal(noMatch.totalHits, 0);

    console.log('✅ 18. Global search across assessment names, clients, and discovered subdomains passed');
  } finally {
    server.close();
  }

  console.log('\n🎉 ALL 18 AUTOMATED RECONX TEST SUITES PASSED SUCCESSFULLY!');
}

runAllTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
