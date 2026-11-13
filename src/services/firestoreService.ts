import {
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  writeBatch,
  type DocumentReference,
} from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from '../lib/firebase';
import {
  Assessment,
  Asset,
  DnsRecord,
  WebEndpoint,
  NetworkService,
  Finding,
  ScanJob,
  AuditLog,
  UserProfile,
  AssetRelationship,
  AssetEvidence,
  AssetCorrelation,
  AssessmentSnapshot,
  AssetChange,
  AIAnalysis,
} from '../types';
import {
  runAssetCorrelationEngine,
  generateDeterministicAIAnalysis,
} from './assetCorrelationEngine';
import { createAssessmentSnapshot } from './changeDetectionEngine';

const BATCH_CHUNK_SIZE = 400;
const DELETABLE_SUBCOLLECTIONS = [
  'assets',
  'dns_records',
  'web_endpoints',
  'services',
  'findings',
  'scan_jobs',
  'relationships',
  'evidences',
  'snapshots',
  'asset_changes',
  'ai_analysis',
] as const;

function stripUndefined<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => stripUndefined(item)) as unknown as T;
  }
  if (value !== null && typeof value === 'object') {
    const cleaned: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v !== undefined) {
        cleaned[k] = stripUndefined(v);
      }
    }
    return cleaned as T;
  }
  return value;
}

async function commitSetBatch<T extends { id: string }>(
  assessmentId: string,
  subcollectionName: string,
  items: T[]
): Promise<void> {
  if (!items || items.length === 0) return;
  const path = `assessments/${assessmentId}/${subcollectionName}`;
  try {
    for (let i = 0; i < items.length; i += BATCH_CHUNK_SIZE) {
      const chunk = items.slice(i, i + BATCH_CHUNK_SIZE);
      const batch = writeBatch(db);
      for (const item of chunk) {
        const ref = doc(db, 'assessments', assessmentId, subcollectionName, item.id);
        batch.set(ref, stripUndefined(item), { merge: true });
      }
      await batch.commit();
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, path);
  }
}

async function deleteDocumentRefsInChunks(refs: DocumentReference[]): Promise<void> {
  for (let i = 0; i < refs.length; i += BATCH_CHUNK_SIZE) {
    const chunk = refs.slice(i, i + BATCH_CHUNK_SIZE);
    const batch = writeBatch(db);
    for (const ref of chunk) {
      batch.delete(ref);
    }
    await batch.commit();
  }
}

async function deleteAssessmentSubcollections(assessmentId: string): Promise<void> {
  const refsToDelete: DocumentReference[] = [];
  for (const sub of DELETABLE_SUBCOLLECTIONS) {
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, sub));
      snap.forEach((d) => refsToDelete.push(d.ref));
    } catch {
      // Ignore if subcollection doesn't exist
    }
  }
  if (refsToDelete.length > 0) {
    await deleteDocumentRefsInChunks(refsToDelete);
  }
}

export const firestoreService = {
  // ----------------------------------------------------
  // USER PROFILES
  // ----------------------------------------------------
  async getUserProfile(userId: string): Promise<UserProfile | null> {
    const path = `users/${userId}`;
    try {
      const snap = await getDoc(doc(db, 'users', userId));
      if (!snap.exists()) return null;
      return { id: snap.id, ...snap.data() } as UserProfile;
    } catch (err) {
      handleFirestoreError(err, OperationType.GET, path);
    }
  },

  async saveUserProfile(profile: UserProfile): Promise<void> {
    const path = `users/${profile.id}`;
    try {
      const dataToSave: Record<string, unknown> = {
        id: profile.id,
        email: profile.email,
        displayName: profile.displayName || '',
        role: profile.role,
        createdAt: profile.createdAt || new Date().toISOString(),
      };
      if (profile.photoURL) dataToSave.photoURL = profile.photoURL;
      if (profile.updatedAt) dataToSave.updatedAt = profile.updatedAt;

      await setDoc(doc(db, 'users', profile.id), dataToSave, { merge: true });
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
  },

  // ----------------------------------------------------
  // ASSESSMENTS
  // ----------------------------------------------------
  async getAssessments(userId: string): Promise<Assessment[]> {
    const path = 'assessments';
    try {
      const q = query(collection(db, path), where('ownerId', '==', userId));
      const snap = await getDocs(q);
      const results: Assessment[] = [];
      snap.forEach((d) => {
        results.push({ id: d.id, ...d.data() } as Assessment);
      });
      return results.sort(
        (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async getAssessment(assessmentId: string): Promise<Assessment | null> {
    const path = `assessments/${assessmentId}`;
    try {
      const snap = await getDoc(doc(db, 'assessments', assessmentId));
      if (!snap.exists()) return null;
      return { id: snap.id, ...snap.data() } as Assessment;
    } catch (err) {
      handleFirestoreError(err, OperationType.GET, path);
    }
  },

  async createAssessment(assessment: Assessment): Promise<void> {
    const path = `assessments/${assessment.id}`;
    try {
      await setDoc(doc(db, 'assessments', assessment.id), stripUndefined(assessment));
      await this.addAuditLog({
        id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        assessmentId: assessment.id,
        ownerId: assessment.ownerId,
        actorEmail: assessment.ownerEmail,
        action: 'ASSESSMENT_CREATED',
        details: `Created assessment "${assessment.name}" for target ${assessment.scope?.rootDomain} (${assessment.type})`,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, path);
    }
  },

  async updateAssessment(assessmentId: string, updates: Partial<Assessment>): Promise<void> {
    const path = `assessments/${assessmentId}`;
    try {
      await updateDoc(
        doc(db, 'assessments', assessmentId),
        stripUndefined({
          ...updates,
          updatedAt: new Date().toISOString(),
        })
      );
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, path);
    }
  },

  async deleteAssessment(assessmentId: string): Promise<void> {
    const path = `assessments/${assessmentId}`;
    try {
      await deleteAssessmentSubcollections(assessmentId);
      await deleteDoc(doc(db, 'assessments', assessmentId));
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, path);
    }
  },

  async deleteAssessmentsBatch(assessmentIds: string[]): Promise<void> {
    if (!assessmentIds || assessmentIds.length === 0) return;
    const path = `assessments (batch delete ${assessmentIds.length})`;
    try {
      for (const id of assessmentIds) {
        await deleteAssessmentSubcollections(id);
      }
      const docRefs = assessmentIds.map((id) => doc(db, 'assessments', id));
      await deleteDocumentRefsInChunks(docRefs);
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, path);
    }
  },

  // ----------------------------------------------------
  // ASSETS SUBCOLLECTION
  // ----------------------------------------------------
  async getAssets(assessmentId: string): Promise<Asset[]> {
    const path = `assessments/${assessmentId}/assets`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'assets'));
      const list: Asset[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as Asset));
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async saveAssetsBatch(assessmentId: string, assets: Asset[]): Promise<void> {
    return commitSetBatch(assessmentId, 'assets', assets);
  },

  // ----------------------------------------------------
  // DNS RECORDS
  // ----------------------------------------------------
  async getDnsRecords(assessmentId: string): Promise<DnsRecord[]> {
    const path = `assessments/${assessmentId}/dns_records`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'dns_records'));
      const list: DnsRecord[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as DnsRecord));
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async saveDnsRecordsBatch(assessmentId: string, records: DnsRecord[]): Promise<void> {
    return commitSetBatch(assessmentId, 'dns_records', records);
  },

  // ----------------------------------------------------
  // WEB ENDPOINTS
  // ----------------------------------------------------
  async getWebEndpoints(assessmentId: string): Promise<WebEndpoint[]> {
    const path = `assessments/${assessmentId}/web_endpoints`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'web_endpoints'));
      const list: WebEndpoint[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as WebEndpoint));
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async saveEndpointsBatch(assessmentId: string, endpoints: WebEndpoint[]): Promise<void> {
    return commitSetBatch(assessmentId, 'web_endpoints', endpoints);
  },

  // ----------------------------------------------------
  // NETWORK SERVICES
  // ----------------------------------------------------
  async getNetworkServices(assessmentId: string): Promise<NetworkService[]> {
    const path = `assessments/${assessmentId}/services`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'services'));
      const list: NetworkService[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as NetworkService));
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async saveServicesBatch(assessmentId: string, services: NetworkService[]): Promise<void> {
    return commitSetBatch(assessmentId, 'services', services);
  },

  // ----------------------------------------------------
  // FINDINGS
  // ----------------------------------------------------
  async getFindings(assessmentId: string): Promise<Finding[]> {
    const path = `assessments/${assessmentId}/findings`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'findings'));
      const list: Finding[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as Finding));
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async saveFindingsBatch(assessmentId: string, findings: Finding[]): Promise<void> {
    return commitSetBatch(assessmentId, 'findings', findings);
  },

  // ----------------------------------------------------
  // SCAN JOBS
  // ----------------------------------------------------
  async getScanJobs(assessmentId: string): Promise<ScanJob[]> {
    const path = `assessments/${assessmentId}/scan_jobs`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'scan_jobs'));
      const list: ScanJob[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as ScanJob));
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async saveScanJob(job: ScanJob): Promise<void> {
    const path = `assessments/${job.assessmentId}/scan_jobs/${job.id}`;
    try {
      await setDoc(
        doc(db, 'assessments', job.assessmentId, 'scan_jobs', job.id),
        stripUndefined(job),
        { merge: true }
      );
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
  },

  // ----------------------------------------------------
  // AUDIT LOGS
  // ----------------------------------------------------
  async getAuditLogs(assessmentId: string): Promise<AuditLog[]> {
    const path = `assessments/${assessmentId}/audit_logs`;
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'audit_logs'));
      const list: AuditLog[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as AuditLog));
      return list.sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async addAuditLog(log: AuditLog): Promise<void> {
    const path = log.assessmentId
      ? `assessments/${log.assessmentId}/audit_logs/${log.id}`
      : `audit_logs/${log.id}`;
    try {
      if (log.assessmentId) {
        await setDoc(
          doc(db, 'assessments', log.assessmentId, 'audit_logs', log.id),
          stripUndefined(log)
        );
      }
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
  },

  // ----------------------------------------------------
  // CORRELATION RELATIONSHIPS & EVIDENCES
  // ----------------------------------------------------
  async getRelationships(assessmentId: string): Promise<AssetRelationship[]> {
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'relationships'));
      const list: AssetRelationship[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as AssetRelationship));
      return list;
    } catch {
      return [];
    }
  },

  async saveRelationshipsBatch(
    assessmentId: string,
    relationships: AssetRelationship[]
  ): Promise<void> {
    return commitSetBatch(assessmentId, 'relationships', relationships);
  },

  async getEvidences(assessmentId: string): Promise<AssetEvidence[]> {
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'evidences'));
      const list: AssetEvidence[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as AssetEvidence));
      return list;
    } catch {
      return [];
    }
  },

  async saveEvidencesBatch(assessmentId: string, evidences: AssetEvidence[]): Promise<void> {
    return commitSetBatch(assessmentId, 'evidences', evidences);
  },

  // ----------------------------------------------------
  // SNAPSHOTS, ASSET CHANGES & AI ANALYSIS
  // ----------------------------------------------------
  async getSnapshot(assessmentId: string): Promise<AssessmentSnapshot | null> {
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'snapshots'));
      if (snap.empty) return null;
      const d = snap.docs[0];
      return { id: d.id, ...d.data() } as AssessmentSnapshot;
    } catch {
      return null;
    }
  },

  async saveSnapshot(assessmentId: string, snapshot: AssessmentSnapshot): Promise<void> {
    try {
      await setDoc(
        doc(db, 'assessments', assessmentId, 'snapshots', snapshot.id),
        stripUndefined(snapshot),
        { merge: true }
      );
    } catch {
      // Non-fatal fallback
    }
  },

  async getAssetChanges(assessmentId: string): Promise<AssetChange[]> {
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'asset_changes'));
      const list: AssetChange[] = [];
      snap.forEach((d) => list.push({ id: d.id, ...d.data() } as AssetChange));
      return list;
    } catch {
      return [];
    }
  },

  async saveAssetChanges(assessmentId: string, changes: AssetChange[]): Promise<void> {
    try {
      await commitSetBatch(assessmentId, 'asset_changes', changes);
    } catch {
      // Non-fatal fallback
    }
  },

  async getAIAnalysis(assessmentId: string): Promise<AIAnalysis | null> {
    try {
      const snap = await getDocs(collection(db, 'assessments', assessmentId, 'ai_analysis'));
      if (snap.empty) return null;
      const d = snap.docs[0];
      return { id: d.id, ...d.data() } as AIAnalysis;
    } catch {
      return null;
    }
  },

  async saveAIAnalysis(assessmentId: string, analysis: AIAnalysis): Promise<void> {
    try {
      await setDoc(
        doc(db, 'assessments', assessmentId, 'ai_analysis', analysis.id),
        stripUndefined(analysis),
        { merge: true }
      );
    } catch {
      // Non-fatal fallback
    }
  },

  async loadOrComputeAssessmentIntelligence(assessment: Assessment): Promise<{
    assets: Asset[];
    relationships: AssetRelationship[];
    evidences: AssetEvidence[];
    correlation: AssetCorrelation;
    snapshot: AssessmentSnapshot;
    aiAnalysis: AIAnalysis;
    dnsRecords: DnsRecord[];
    endpoints: WebEndpoint[];
    services: NetworkService[];
    findings: Finding[];
  }> {
    const [rawAssets, dnsRecords, endpoints, services, findings] = await Promise.all([
      this.getAssets(assessment.id),
      this.getDnsRecords(assessment.id),
      this.getWebEndpoints(assessment.id),
      this.getNetworkServices(assessment.id),
      this.getFindings(assessment.id),
    ]);

    const correlated = runAssetCorrelationEngine(
      assessment,
      rawAssets,
      dnsRecords,
      endpoints,
      services,
      findings
    );

    const snapshot = createAssessmentSnapshot(
      assessment,
      correlated.normalizedAssets,
      correlated.relationships,
      dnsRecords,
      endpoints,
      services
    );

    const existingAI = await this.getAIAnalysis(assessment.id);
    const aiAnalysis =
      existingAI ||
      generateDeterministicAIAnalysis(
        assessment,
        correlated.normalizedAssets,
        correlated.relationships,
        correlated.correlationSummary,
        findings
      );

    return {
      assets: correlated.normalizedAssets,
      relationships: correlated.relationships,
      evidences: correlated.evidences,
      correlation: correlated.correlationSummary,
      snapshot,
      aiAnalysis,
      dnsRecords,
      endpoints,
      services,
      findings,
    };
  },
};

export const loadOrComputeAssessmentIntelligence = (assessment: Assessment) =>
  firestoreService.loadOrComputeAssessmentIntelligence(assessment);

export const saveAIAnalysis = (assessmentId: string, analysis: AIAnalysis) =>
  firestoreService.saveAIAnalysis(assessmentId, analysis);

export const saveAssetChanges = (assessmentId: string, changes: AssetChange[]) =>
  firestoreService.saveAssetChanges(assessmentId, changes);

export const getDnsRecords = (assessmentId: string) =>
  firestoreService.getDnsRecords(assessmentId);

export const getWebEndpoints = (assessmentId: string) =>
  firestoreService.getWebEndpoints(assessmentId);

export const getNetworkServices = (assessmentId: string) =>
  firestoreService.getNetworkServices(assessmentId);

export const getFindings = (assessmentId: string) =>
  firestoreService.getFindings(assessmentId);
