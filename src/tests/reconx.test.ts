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
import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService
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
  } finally {
    server.close();
  }

  console.log('\n🎉 ALL 14 AUTOMATED RECONX TEST SUITES PASSED SUCCESSFULLY!');
}

runAllTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
