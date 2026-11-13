import { Assessment, AssessmentStatus, Asset } from '../types';
import { firestoreService } from './firestoreService';

export interface SubdomainSearchEntry {
  id: string;
  subdomain: string;
  assessmentId: string;
  assessmentName: string;
  clientName: string;
  rootDomain: string;
  discoverySource: string;
  ipAddress?: string;
  isExposedRisk?: boolean;
  confidenceScore?: number;
  status: AssessmentStatus;
}

export interface GlobalSearchAssessmentHit {
  kind: 'assessment';
  assessment: Assessment;
  matchedFields: Array<'name' | 'client' | 'domain' | 'subdomain'>;
  matchedSubdomainCount: number;
  score: number;
}

export interface GlobalSearchSubdomainHit {
  kind: 'subdomain';
  entry: SubdomainSearchEntry;
  score: number;
}

export interface GlobalSearchResults {
  query: string;
  assessmentHits: GlobalSearchAssessmentHit[];
  subdomainHits: GlobalSearchSubdomainHit[];
  totalHits: number;
}

interface CachedSubdomainBucket {
  cacheKey: string;
  entries: SubdomainSearchEntry[];
}

const subdomainCache = new Map<string, CachedSubdomainBucket>();

function makeCacheKey(assessment: Assessment): string {
  return `${assessment.id}::${assessment.updatedAt || ''}::${assessment.stats?.subdomainsCount || 0}::${assessment.stats?.assetsCount || 0}`;
}

export function clearGlobalSearchCache(): void {
  subdomainCache.clear();
}

export function buildSubdomainSearchEntries(
  assessment: Assessment,
  assets: Asset[] = []
): SubdomainSearchEntry[] {
  const seen = new Set<string>();
  const entries: SubdomainSearchEntry[] = [];
  const clientName = assessment.clientName || 'General Assessment';
  const rootDomain = assessment.scope?.rootDomain || '';

  for (const asset of assets) {
    if (asset.assetType !== 'subdomain' && asset.assetType !== 'root_domain') {
      continue;
    }
    const hostname = (asset.canonicalName || asset.assetValue || '').trim();
    if (!hostname) continue;
    const norm = hostname.toLowerCase().replace(/\.$/, '');
    if (seen.has(norm)) continue;
    seen.add(norm);

    entries.push({
      id: `${assessment.id}::${asset.id || norm}`,
      subdomain: hostname,
      assessmentId: assessment.id,
      assessmentName: assessment.name,
      clientName,
      rootDomain,
      discoverySource: asset.discoverySource || 'Subfinder / Correlated',
      ipAddress: asset.ipAddress,
      isExposedRisk: Boolean(asset.isExposedRisk || asset.isPotentiallyExposed),
      confidenceScore: asset.confidenceScore,
      status: assessment.status,
    });
  }

  // Ensure declared approved hostnames & root domain are also searchable even before/during a scan
  const scopeHosts = [
    ...(assessment.scope?.approvedHostnames || []),
    ...(rootDomain ? [rootDomain] : []),
  ];
  for (const host of scopeHosts) {
    const clean = (host || '').trim();
    if (!clean) continue;
    const norm = clean.toLowerCase().replace(/\.$/, '');
    if (seen.has(norm)) continue;
    seen.add(norm);

    entries.push({
      id: `${assessment.id}::scope::${norm}`,
      subdomain: clean,
      assessmentId: assessment.id,
      assessmentName: assessment.name,
      clientName,
      rootDomain,
      discoverySource: 'Authorized Scope',
      status: assessment.status,
    });
  }

  return entries;
}

export function seedSubdomainIndexForAssessment(
  assessment: Assessment,
  assets: Asset[]
): SubdomainSearchEntry[] {
  const entries = buildSubdomainSearchEntries(assessment, assets);
  subdomainCache.set(assessment.id, {
    cacheKey: makeCacheKey(assessment),
    entries,
  });
  return entries;
}

export function getCachedSubdomainMap(
  assessments: Assessment[]
): Record<string, SubdomainSearchEntry[]> {
  const map: Record<string, SubdomainSearchEntry[]> = {};
  for (const assessment of assessments) {
    const cached = subdomainCache.get(assessment.id);
    if (cached && cached.cacheKey === makeCacheKey(assessment)) {
      map[assessment.id] = cached.entries;
    } else {
      map[assessment.id] = buildSubdomainSearchEntries(assessment, []);
    }
  }
  return map;
}

export async function loadGlobalSubdomainIndex(
  assessments: Assessment[],
  fetchAssets: (assessmentId: string) => Promise<Asset[]> = (id) =>
    firestoreService.getAssets(id)
): Promise<Record<string, SubdomainSearchEntry[]>> {
  const map: Record<string, SubdomainSearchEntry[]> = {};
  const toFetch: Assessment[] = [];

  for (const assessment of assessments) {
    const expectedKey = makeCacheKey(assessment);
    const cached = subdomainCache.get(assessment.id);
    if (cached && cached.cacheKey === expectedKey) {
      map[assessment.id] = cached.entries;
    } else {
      toFetch.push(assessment);
    }
  }

  // Limit concurrent subcollection reads to respect client connection budgets
  const CONCURRENCY = 5;
  for (let i = 0; i < toFetch.length; i += CONCURRENCY) {
    const batch = toFetch.slice(i, i + CONCURRENCY);
    await Promise.all(
      batch.map(async (assessment) => {
        try {
          const assets = await fetchAssets(assessment.id);
          const entries = seedSubdomainSearchIndexInternal(assessment, assets);
          map[assessment.id] = entries;
        } catch {
          // Graceful fallback to scope-defined hostnames if subcollection unavailable
          map[assessment.id] = buildSubdomainSearchEntries(assessment, []);
        }
      })
    );
  }

  return map;
}

function seedSubdomainSearchIndexInternal(
  assessment: Assessment,
  assets: Asset[]
): SubdomainSearchEntry[] {
  const entries = buildSubdomainSearchEntries(assessment, assets);
  subdomainCache.set(assessment.id, {
    cacheKey: makeCacheKey(assessment),
    entries,
  });
  return entries;
}

function computeMatchScore(text: string, queryLower: string): number {
  const t = (text || '').toLowerCase();
  if (!t) return 0;
  if (t === queryLower) return 100;
  if (t.startsWith(queryLower)) return 80;
  if (t.includes(`.${queryLower}`) || t.includes(` ${queryLower}`)) return 65;
  if (t.includes(queryLower)) return 45;
  return 0;
}

export function queryGlobalSearchIndex(
  query: string,
  assessments: Assessment[],
  subdomainsByAssessment: Record<string, SubdomainSearchEntry[]> = {}
): GlobalSearchResults {
  const trimmed = (query || '').trim();
  const q = trimmed.toLowerCase();

  if (!q || assessments.length === 0) {
    return {
      query: trimmed,
      assessmentHits: [],
      subdomainHits: [],
      totalHits: 0,
    };
  }

  const assessmentHits: GlobalSearchAssessmentHit[] = [];
  const subdomainHits: GlobalSearchSubdomainHit[] = [];

  for (const assessment of assessments) {
    const nameScore = computeMatchScore(assessment.name || '', q);
    const clientScore = computeMatchScore(assessment.clientName || '', q);
    const domainScore = computeMatchScore(assessment.scope?.rootDomain || '', q);

    const subEntries =
      subdomainsByAssessment[assessment.id] ||
      buildSubdomainSearchEntries(assessment, []);

    const matchingSubs: GlobalSearchSubdomainHit[] = [];
    for (const entry of subEntries) {
      const subScore = computeMatchScore(entry.subdomain, q);
      if (subScore > 0) {
        const finalScore = subScore + (entry.discoverySource !== 'Authorized Scope' ? 10 : 0);
        matchingSubs.push({
          kind: 'subdomain',
          entry,
          score: finalScore,
        });
      }
    }

    subdomainHits.push(...matchingSubs);

    const matchedFields: Array<'name' | 'client' | 'domain' | 'subdomain'> = [];
    if (nameScore > 0) matchedFields.push('name');
    if (clientScore > 0) matchedFields.push('client');
    if (domainScore > 0) matchedFields.push('domain');
    if (matchingSubs.length > 0) matchedFields.push('subdomain');

    if (matchedFields.length > 0) {
      const maxSubScore = matchingSubs.reduce((m, s) => Math.max(m, s.score), 0);
      const bestScore = Math.max(nameScore + 15, clientScore + 10, domainScore + 8, maxSubScore);
      assessmentHits.push({
        kind: 'assessment',
        assessment,
        matchedFields,
        matchedSubdomainCount: matchingSubs.length,
        score: bestScore,
      });
    }
  }

  assessmentHits.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return (
      new Date(b.assessment.createdAt).getTime() -
      new Date(a.assessment.createdAt).getTime()
    );
  });

  subdomainHits.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.entry.subdomain.localeCompare(b.entry.subdomain);
  });

  return {
    query: trimmed,
    assessmentHits,
    subdomainHits,
    totalHits: assessmentHits.length + subdomainHits.length,
  };
}
