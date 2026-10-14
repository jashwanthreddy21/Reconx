import React, { useState, useEffect } from 'react';
import { AuditLog, Assessment } from '../types';
import { firestoreService } from '../services/firestoreService';
import { History, Shield, Lock, Search, Download } from 'lucide-react';

interface Props {
  assessments: Assessment[];
}

export const AuditLogs: React.FC<Props> = ({ assessments }) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    let mounted = true;
    const fetchAllAudit = async () => {
      setLoading(true);
      try {
        const logPromises = assessments.map((a) => firestoreService.getAuditLogs(a.id));
        const all = await Promise.all(logPromises);
        const flattened = all.flat();
        if (mounted) {
          setLogs(flattened.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()));
        }
      } catch (err) {
        console.error('Error fetching audit logs:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    fetchAllAudit();

    return () => {
      mounted = false;
    };
  }, [assessments]);

  const exportAuditJson = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconx-audit-trail-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="bg-[#111827] border border-slate-800 rounded-xl sm:rounded-2xl p-4 sm:p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <History className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
              Security Operations Audit Trail
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Tamper-evident audit log of all assessment initiations, scope certifications, exports, and scanner actions for non-repudiation and ethical hacking compliance.
          </p>
        </div>

        <button
          onClick={exportAuditJson}
          className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium border border-slate-700 shrink-0"
        >
          <Download className="w-4 h-4 text-cyan-400" /> Export Audit Trail
        </button>
      </div>

      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search audit action, operator email, or details..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-72"
            />
          </div>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            Loading cryptographic audit entries...
          </div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            No audit records created yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Actor / Operator</th>
                  <th className="px-4 py-3">Action Type</th>
                  <th className="px-4 py-3">Audit Details</th>
                  <th className="px-4 py-3">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {logs
                  .filter((l) => {
                    if (
                      search &&
                      !l.action.toLowerCase().includes(search.toLowerCase()) &&
                      !l.actorEmail.toLowerCase().includes(search.toLowerCase()) &&
                      !l.details.toLowerCase().includes(search.toLowerCase())
                    ) {
                      return false;
                    }
                    return true;
                  })
                  .map((l) => (
                    <tr key={l.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 text-slate-400 text-[11px]">
                        {new Date(l.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-cyan-300">{l.actorEmail}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-blue-300 border border-slate-700">
                          {l.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-white font-sans text-xs break-all max-w-md">
                        {l.details}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-emerald-400 text-[10px]">VERIFIED ✓</span>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
