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
  orderBy,
  onSnapshot,
  writeBatch
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
      await setDoc(doc(db, 'users', profile.id), profile, { merge: true });
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
      await setDoc(doc(db, 'assessments', assessment.id), assessment);
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
      await updateDoc(doc(db, 'assessments', assessmentId), {
        ...updates,
        updatedAt: new Date().toISOString(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, path);
    }
  },

  async deleteAssessment(assessmentId: string): Promise<void> {
    const path = `assessments/${assessmentId}`;
    try {
      await deleteDoc(doc(db, 'assessments', assessmentId));
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
    const path = `assessments/${assessmentId}/assets`;
    try {
      const batch = writeBatch(db);
      for (const a of assets) {
        const ref = doc(db, 'assessments', assessmentId, 'assets', a.id);
        batch.set(ref, a, { merge: true });
      }
      await batch.commit();
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
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
    const path = `assessments/${assessmentId}/dns_records`;
    try {
      const batch = writeBatch(db);
      for (const r of records) {
        const ref = doc(db, 'assessments', assessmentId, 'dns_records', r.id);
        batch.set(ref, r, { merge: true });
      }
      await batch.commit();
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
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
    const path = `assessments/${assessmentId}/web_endpoints`;
    try {
      const batch = writeBatch(db);
      for (const ep of endpoints) {
        const ref = doc(db, 'assessments', assessmentId, 'web_endpoints', ep.id);
        batch.set(ref, ep, { merge: true });
      }
      await batch.commit();
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
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
    const path = `assessments/${assessmentId}/services`;
    try {
      const batch = writeBatch(db);
      for (const s of services) {
        const ref = doc(db, 'assessments', assessmentId, 'services', s.id);
        batch.set(ref, s, { merge: true });
      }
      await batch.commit();
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
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
    const path = `assessments/${assessmentId}/findings`;
    try {
      const batch = writeBatch(db);
      for (const f of findings) {
        const ref = doc(db, 'assessments', assessmentId, 'findings', f.id);
        batch.set(ref, f, { merge: true });
      }
      await batch.commit();
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
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
      await setDoc(doc(db, 'assessments', job.assessmentId, 'scan_jobs', job.id), job, { merge: true });
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
        await setDoc(doc(db, 'assessments', log.assessmentId, 'audit_logs', log.id), log);
      }
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, path);
    }
  },
};
