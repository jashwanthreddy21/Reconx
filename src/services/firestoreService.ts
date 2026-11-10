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
  type DocumentReference
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
  UserProfile
} from '../types';

const BATCH_CHUNK_SIZE = 400;
const DELETABLE_SUBCOLLECTIONS = [
  'assets',
  'dns_records',
  'web_endpoints',
  'services',
  'findings',
  'scan_jobs',
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
    const snap = await getDocs(collection(db, 'assessments', assessmentId, sub));
    snap.forEach((d) => refsToDelete.push(d.ref));
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
      // Sort client-side by createdAt descending to avoid composite index requirement
      return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
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
        details: `Created assessment "${assessment.name}" for target ${assessment.scope.rootDomain} (${assessment.type})`,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, path);
    }
  },

  async updateAssessment(assessmentId: string, updates: Partial<Assessment>): Promise<void> {
    const path = `assessments/${assessmentId}`;
    try {
      await updateDoc(doc(db, 'assessments', assessmentId), stripUndefined({
        ...updates,
        updatedAt: new Date().toISOString(),
      }));
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
      await setDoc(doc(db, 'assessments', job.assessmentId, 'scan_jobs', job.id), stripUndefined(job), { merge: true });
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
      return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    } catch (err) {
      handleFirestoreError(err, OperationType.LIST, path);
    }
  },

  async addAuditLog(log: AuditLog): Promise<void> {
    const path = log.assessmentId ? `assessments/${log.assessmentId}/audit_logs/${log.id}` : `audit_logs/${log.id}`;
    try {
      if (log.assessmentId) {
        await setDoc(doc(db, 'assessments', log.assessmentId, 'audit_logs', log.id), stripUndefined(log));
      }
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
  },
};
