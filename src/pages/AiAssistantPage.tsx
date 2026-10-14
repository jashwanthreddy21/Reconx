import React from 'react';
import { GeminiChatbot } from '../components/chat/GeminiChatbot';
import { Assessment } from '../types';
import { Bot, Sparkles, Shield, Cpu, Zap, Brain } from 'lucide-react';

interface AiAssistantPageProps {
  currentAssessment: Assessment | null;
  assessments: Assessment[];
  onSelectAssessment: (id: string) => void;
}

export const AiAssistantPage: React.FC<AiAssistantPageProps> = ({
  currentAssessment,
  assessments,
  onSelectAssessment,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-blue-950/60 via-slate-900 to-indigo-950/60 border border-slate-800 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-wide">
                ReconX AI Security Copilot
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Powered by Gemini
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Multi-turn defensive reconnaissance intelligence, port risk triage, and attack surface remediation planning.
            </p>
          </div>
        </div>

        {/* Assessment context selector */}
        {assessments.length > 0 && (
          <div className="flex items-center gap-2 text-xs bg-slate-900/90 border border-slate-800 p-2 rounded-xl">
            <span className="text-slate-400 text-[11px] whitespace-nowrap">Active Scope:</span>
            <select
              value={currentAssessment?.id || ''}
              onChange={(e) => onSelectAssessment(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.scope.rootDomain} ({a.name})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Embedded Chat Container */}
      <div className="h-[750px] max-h-[80vh] rounded-2xl border border-slate-800 overflow-hidden shadow-2xl relative">
        <GeminiChatbot
          currentAssessment={currentAssessment}
          isOpen={true}
          onClose={() => {}}
          isFloating={false}
        />
      </div>
    </div>
  );
};
