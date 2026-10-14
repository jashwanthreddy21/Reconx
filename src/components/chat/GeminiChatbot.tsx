import React, { useState, useRef, useEffect } from 'react';
import {
  MessageSquare,
  Bot,
  User,
  Send,
  Sparkles,
  Zap,
  Brain,
  Shield,
  X,
  Minimize2,
  Maximize2,
  Trash2,
  Copy,
  Check,
  ChevronDown,
  RefreshCw,
  ExternalLink,
  Target,
  Info,
} from 'lucide-react';
import { Assessment } from '../../types';

export type ChatRoleKey = 'security_analyst' | 'rapid_scout' | 'deep_threat_expert';

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  timestamp: string;
  model?: string;
  roleKey?: ChatRoleKey;
}

export interface ChatRoleDefinition {
  key: ChatRoleKey;
  name: string;
  badge: string;
  model: string;
  modelLabel: string;
  icon: React.ComponentType<{ className?: string }>;
  tagline: string;
  badgeColor: string;
}

export const CHAT_ROLES: ChatRoleDefinition[] = [
  {
    key: 'security_analyst',
    name: 'General Recon Analyst',
    badge: 'Standard',
    model: 'gemini-3.8-flash',
    modelLabel: 'Gemini 3.8 Flash',
    icon: Shield,
    tagline: 'Balanced attack surface posture, recon interpretation & remediation.',
    badgeColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
  },
  {
    key: 'rapid_scout',
    name: 'Fast Triage Scout',
    badge: 'Speed',
    model: 'gemini-3.1-flash-lite',
    modelLabel: 'Gemini 3.1 Flash Lite',
    icon: Zap,
    tagline: 'Instant lookups for ports, CLI syntax (nmap/subfinder), and CVE checks.',
    badgeColor: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  },
  {
    key: 'deep_threat_expert',
    name: 'Deep Threat Specialist',
    badge: 'Complex',
    model: 'gemini-4-argon',
    modelLabel: 'Gemini 4 Argon',
    icon: Brain,
    tagline: 'Advanced reasoning, multi-step attack chaining, and threat modeling.',
    badgeColor: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
  },
];

interface GeminiChatbotProps {
  currentAssessment?: Assessment | null;
  isOpen?: boolean;
  onClose?: () => void;
  isFloating?: boolean;
}

export const GeminiChatbot: React.FC<GeminiChatbotProps> = ({
  currentAssessment,
  isOpen,
  onClose,
  isFloating = true,
}) => {
  const [internalOpen, setInternalOpen] = useState(false);
  const effectiveOpen = isOpen !== undefined ? isOpen : internalOpen;
  const [selectedRoleKey, setSelectedRoleKey] = useState<ChatRoleKey>('security_analyst');
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    const saved = localStorage.getItem('reconx_gemini_chat_history');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        // Fallback to initial greeting
      }
    }
    return [
      {
        id: 'initial-greeting',
        role: 'model',
        text: `Hello Operator! I am your **ReconX Security Copilot** powered by Gemini.

I can assist with:
- **Scope & Attack Surface Analysis:** Reviewing targets, subdomains, and exposed endpoints.
- **Port & Service Triage:** Evaluating risks for open ports like 22, 80, 443, 3306, 8080.
- **Tool Automation Guidance:** Providing safe syntax for \`subfinder\`, \`nmap\`, \`dnsx\`, and \`httpx\`.
- **Prioritized Remediation:** Formulating defensive hardening actions based on CVSS & OWASP.

Select an operational role above or ask anything about your reconnaissance workflow!`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        model: 'gemini-3.8-flash',
        roleKey: 'security_analyst',
      },
    ];
  });

  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [includeContext, setIncludeContext] = useState(true);
  const [isExpanded, setIsExpanded] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const activeRole = CHAT_ROLES.find((r) => r.key === selectedRoleKey) || CHAT_ROLES[0];

  // Save conversation history to local storage
  useEffect(() => {
    localStorage.setItem('reconx_gemini_chat_history', JSON.stringify(messages));
  }, [messages]);

  // Scroll to bottom on new messages
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  // Focus textarea when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => textareaRef.current?.focus(), 150);
    }
  }, [isOpen]);

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleClearHistory = () => {
    const freshGreeting: ChatMessage = {
      id: `greeting-${Date.now()}`,
      role: 'model',
      text: `Chat history cleared. I'm ready for your next reconnaissance query in **${activeRole.name}** mode (\`${activeRole.model}\`).`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      model: activeRole.model,
      roleKey: activeRole.key,
    };
    setMessages([freshGreeting]);
  };

  const handleSendMessage = async (textToSend?: string) => {
    const rawText = textToSend || inputText;
    const trimmed = rawText.trim();
    if (!trimmed || loading) return;

    const userMessageId = `user-${Date.now()}`;
    const userMessage: ChatMessage = {
      id: userMessageId,
      role: 'user',
      text: trimmed,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const nextMessages = [...messages, userMessage];
    setMessages(nextMessages);
    setInputText('');
    setLoading(true);

    try {
      // Prepare payload
      const assessmentContext =
        includeContext && currentAssessment
          ? {
              name: currentAssessment.name,
              clientName: currentAssessment.clientName,
              rootDomain: currentAssessment.scope?.rootDomain,
              type: currentAssessment.type,
              status: currentAssessment.status,
              assetsCount: currentAssessment.stats?.assetsCount,
              subdomainsCount: currentAssessment.stats?.subdomainsCount,
              endpointsCount: currentAssessment.stats?.endpointsCount,
              servicesCount: currentAssessment.stats?.servicesCount,
              findingsCount: currentAssessment.stats?.findingsCount,
              approvedHostnames: currentAssessment.scope?.approvedHostnames,
              permittedPorts: currentAssessment.scope?.permittedPorts,
            }
          : undefined;

      const payload = {
        role: activeRole.key,
        model: activeRole.model,
        messages: nextMessages.map((m) => ({
          role: m.role,
          text: m.text,
        })),
        assessmentContext,
      };

      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok || data.error) {
        throw new Error(data.error || `HTTP ${res.status}: Server request failed`);
      }

      const botMessage: ChatMessage = {
        id: `model-${Date.now()}`,
        role: 'model',
        text: data.text || 'No response returned from the model.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        model: data.model || activeRole.model,
        roleKey: activeRole.key,
      };

      setMessages((prev) => [...prev, botMessage]);
    } catch (err: any) {
      console.error('Chat error:', err);
      const errorMessage: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'model',
        text: `⚠️ **Error generating response:** ${err.message || 'Unknown network error'}. Please verify that GEMINI_API_KEY is properly configured or try again.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        model: activeRole.model,
        roleKey: activeRole.key,
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Preset query shortcuts
  const samplePrompts = [
    {
      label: 'Exposed Port Risks',
      query: 'What are the main security risks and attack vectors when ports 80, 443, 22, and 3306 are discovered open on a target?',
    },
    {
      label: 'Nmap Stealth Flags',
      query: 'What are the recommended nmap flags for non-disruptive, polite scanning within authorized client scope?',
    },
    {
      label: 'Scope Triage Summary',
      query: currentAssessment
        ? `Review the target scope for ${currentAssessment.scope.rootDomain} and summarize the key reconnaissance risks and verification steps.`
        : 'How do you structure an authorized reconnaissance report for an enterprise client?',
    },
    {
      label: 'Subfinder & DNSX Workflow',
      query: 'Explain how subfinder piped into dnsx and httpx creates an efficient passive-to-active asset discovery pipeline.',
    },
  ];

  // Helper to format basic markdown-style text (bold, backticks, bullet lines)
  const renderFormattedContent = (content: string) => {
    const lines = content.split('\n');
    let inCodeBlock = false;
    let codeBlockContent: string[] = [];
    const elements: React.ReactNode[] = [];

    lines.forEach((line, lineIndex) => {
      if (line.startsWith('```')) {
        if (inCodeBlock) {
          // end code block
          inCodeBlock = false;
          const codeText = codeBlockContent.join('\n');
          elements.push(
            <div key={`codeblock-${lineIndex}`} className="my-2 rounded-lg bg-slate-950 border border-slate-800 p-2.5 font-mono text-xs text-cyan-300 overflow-x-auto relative group">
              <pre>{codeText}</pre>
            </div>
          );
          codeBlockContent = [];
        } else {
          // start code block
          inCodeBlock = true;
          codeBlockContent = [];
        }
        return;
      }

      if (inCodeBlock) {
        codeBlockContent.push(line);
        return;
      }

      // Format inline bold and code
      const formattedLine = line.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, i) => {
        if (part.startsWith('`') && part.endsWith('`')) {
          return (
            <code
              key={i}
              className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[11px] text-cyan-300"
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        if (part.startsWith('**') && part.endsWith('**')) {
          return (
            <strong key={i} className="font-semibold text-white">
              {part.slice(2, -2)}
            </strong>
          );
        }
        return part;
      });

      if (line.startsWith('- ') || line.startsWith('* ')) {
        elements.push(
          <div key={lineIndex} className="flex items-start gap-2 my-0.5 pl-1">
            <span className="text-cyan-400 mt-1 leading-none">•</span>
            <span className="text-slate-300 leading-relaxed text-xs">{formattedLine.slice(1)}</span>
          </div>
        );
      } else if (line.startsWith('### ')) {
        elements.push(
          <h4 key={lineIndex} className="font-semibold text-white text-xs mt-2 mb-1 text-cyan-300">
            {line.replace('### ', '')}
          </h4>
        );
      } else if (line.startsWith('## ')) {
        elements.push(
          <h3 key={lineIndex} className="font-bold text-white text-sm mt-2.5 mb-1 text-cyan-200">
            {line.replace('## ', '')}
          </h3>
        );
      } else if (line.trim() === '') {
        elements.push(<div key={lineIndex} className="h-2" />);
      } else {
        elements.push(
          <p key={lineIndex} className="text-slate-300 text-xs leading-relaxed my-0.5">
            {formattedLine}
          </p>
        );
      }
    });

    return elements;
  };

  const handleClose = () => {
    if (onClose) onClose();
    if (isOpen === undefined) setInternalOpen(false);
  };

  if (!effectiveOpen) {
    if (isFloating) {
      return (
        <button
          onClick={() => {
            if (isOpen === undefined) setInternalOpen(true);
            else onClose?.();
          }}
          className="fixed bottom-5 right-5 z-40 px-3.5 py-2.5 rounded-2xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-500 text-white shadow-xl shadow-blue-500/30 hover:scale-105 hover:shadow-cyan-500/40 active:scale-95 transition-all flex items-center gap-2.5 font-medium text-xs group cursor-pointer border border-cyan-400/30"
          aria-label="Open AI Recon Copilot"
        >
          <div className="relative">
            <Bot className="w-5 h-5 group-hover:rotate-12 transition-transform" />
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <span className="font-semibold tracking-wide">AI Copilot</span>
        </button>
      );
    }
    return null;
  }

  return (
    <div
      className={`fixed z-50 transition-all duration-200 flex flex-col shadow-2xl border border-slate-700/80 bg-[#0F172A] ${
        isFloating
          ? isExpanded
            ? 'bottom-4 right-4 w-[92vw] max-w-2xl h-[88vh] rounded-2xl'
            : 'bottom-4 right-4 w-[94vw] sm:w-[460px] h-[620px] max-h-[90vh] rounded-2xl'
          : 'w-full h-full rounded-none border-none'
      }`}
    >
      {/* Header */}
      <div className="p-3.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between shrink-0 rounded-t-2xl">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/20 shrink-0">
            <Bot className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold text-white tracking-wide truncate">
                ReconX Security Copilot
              </h3>
              <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-semibold ${activeRole.badgeColor}`}>
                {activeRole.badge}
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono truncate">
              {activeRole.modelLabel}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={handleClearHistory}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            title="Clear Chat History"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          {isFloating && (
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              title={isExpanded ? 'Restore Size' : 'Expand View'}
            >
              {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
            </button>
          )}
          <button
            onClick={handleClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
            title="Close Assistant"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Role Switcher Toolbar */}
      <div className="p-2 bg-slate-900/60 border-b border-slate-800/80 flex items-center gap-1.5 overflow-x-auto scrollbar-none shrink-0">
        <span className="text-[10px] uppercase font-mono text-slate-500 pl-1 shrink-0">Role:</span>
        {CHAT_ROLES.map((r) => {
          const Icon = r.icon;
          const isSelected = r.key === selectedRoleKey;
          return (
            <button
              key={r.key}
              onClick={() => setSelectedRoleKey(r.key)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium transition-all shrink-0 cursor-pointer ${
                isSelected
                  ? 'bg-blue-600/30 text-white border border-blue-500/50 shadow-sm'
                  : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-transparent'
              }`}
            >
              <Icon className="w-3 h-3 text-cyan-400" />
              <span>{r.name}</span>
            </button>
          );
        })}
      </div>

      {/* Target Assessment Context Bar (if assessment is present) */}
      {currentAssessment && (
        <div className="px-3 py-1.5 bg-cyan-950/30 border-b border-cyan-900/40 flex items-center justify-between text-[11px] shrink-0">
          <div className="flex items-center gap-1.5 text-cyan-300 truncate">
            <Target className="w-3 h-3 text-cyan-400 shrink-0" />
            <span className="truncate">
              Target: <strong className="font-mono text-white">{currentAssessment.scope.rootDomain}</strong>
            </span>
          </div>
          <button
            onClick={() => setIncludeContext(!includeContext)}
            className={`px-2 py-0.5 rounded text-[10px] font-mono transition-colors cursor-pointer ${
              includeContext
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'bg-slate-800 text-slate-400 border border-slate-700'
            }`}
            title="Toggle sending current assessment scope & findings to the assistant"
          >
            {includeContext ? 'Context Linked' : 'Context Ignored'}
          </button>
        </div>
      )}

      {/* Message Thread (Scrollable) */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((m) => {
          const isUser = m.role === 'user';
          return (
            <div
              key={m.id}
              className={`flex items-start gap-2.5 group ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
            >
              {/* Avatar */}
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 text-xs shadow-sm ${
                  isUser
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-slate-800 border border-slate-700 text-cyan-400'
                }`}
              >
                {isUser ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
              </div>

              {/* Message Bubble */}
              <div className={`max-w-[85%] rounded-xl px-3.5 py-2.5 shadow-sm text-xs relative ${
                isUser
                  ? 'bg-blue-600 text-white rounded-tr-none'
                  : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-none'
              }`}>
                {!isUser && (
                  <div className="flex items-center justify-between gap-2 mb-1.5 pb-1 border-b border-slate-800/60">
                    <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                      <Sparkles className="w-3 h-3 text-cyan-400" />
                      <span>{m.model || activeRole.model}</span>
                    </div>
                    <button
                      onClick={() => handleCopyText(m.text, m.id)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded text-slate-400 hover:text-white"
                      title="Copy response"
                    >
                      {copiedId === m.id ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                )}

                <div className="space-y-1">
                  {isUser ? (
                    <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
                  ) : (
                    renderFormattedContent(m.text)
                  )}
                </div>

                <div className={`text-[9px] mt-1.5 font-mono ${isUser ? 'text-blue-200 text-right' : 'text-slate-500 text-left'}`}>
                  {m.timestamp}
                </div>
              </div>
            </div>
          );
        })}

        {loading && (
          <div className="flex items-start gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 shrink-0">
              <Bot className="w-3.5 h-3.5 animate-pulse" />
            </div>
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl rounded-tl-none px-4 py-3 text-xs text-slate-400 flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
              <span className="font-mono text-[11px]">
                {activeRole.name} is analyzing... ({activeRole.model})
              </span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts (horizontal scroll) */}
      <div className="px-3 py-1.5 bg-slate-900/40 border-t border-slate-800/60 flex items-center gap-1.5 overflow-x-auto scrollbar-none shrink-0">
        <span className="text-[10px] text-slate-500 font-mono shrink-0">Quick Ask:</span>
        {samplePrompts.map((p, idx) => (
          <button
            key={idx}
            disabled={loading}
            onClick={() => handleSendMessage(p.query)}
            className="px-2 py-0.5 rounded-full bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-[10px] whitespace-nowrap transition-colors cursor-pointer shrink-0 disabled:opacity-50"
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <div className="p-3 bg-slate-900/90 border-t border-slate-800 shrink-0 rounded-b-2xl">
        <div className="flex items-end gap-2 bg-slate-950 border border-slate-700/80 rounded-xl p-1.5 focus-within:border-cyan-500/80 focus-within:ring-1 focus-within:ring-cyan-500/30 transition-all">
          <textarea
            ref={textareaRef}
            rows={1}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={`Ask ${activeRole.name} (${activeRole.model})...`}
            className="w-full bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none resize-none px-2 py-1 max-h-24 scrollbar-none"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={!inputText.trim() || loading}
            className="p-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white disabled:text-slate-500 transition-colors shrink-0 cursor-pointer shadow-md shadow-blue-500/20"
            title="Send Message (Enter)"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1.5 px-1 font-mono">
          <span>Shift+Enter for newline</span>
          <span>Role: {activeRole.name}</span>
        </div>
      </div>
    </div>
  );
};
