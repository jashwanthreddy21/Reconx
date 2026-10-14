import express from 'express';
import type { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const getPort = () => {
  // 1. Explicit CLI argument --port
  const portArgIndex = process.argv.indexOf('--port');
  if (portArgIndex !== -1 && process.argv[portArgIndex + 1]) {
    return parseInt(process.argv[portArgIndex + 1], 10);
  }
  // 2. Custom APP_PORT env var
  if (process.env.APP_PORT) {
    return parseInt(process.env.APP_PORT, 10);
  }
  // 3. AI Studio development environment has DEFAULT_APP_PORT=3000 while NGINX runs on 8080.
  // In dev, the app MUST bind to DEFAULT_APP_PORT (3000) so NGINX can proxy to it.
  if (process.env.NODE_ENV !== 'production' && process.env.DEFAULT_APP_PORT) {
    return parseInt(process.env.DEFAULT_APP_PORT, 10);
  }
  // 4. Cloud Run production sets PORT (e.g. 8080). When published, the container must bind to PORT.
  if (process.env.PORT) {
    return parseInt(process.env.PORT, 10);
  }
  // 5. Default fallback to port 3000
  return 3000;
};
const PORT = getPort();

app.use(express.json({ limit: '10mb' }));

// Initialize GoogleGenAI client
const getAiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
};

export interface ChatRoleConfig {
  roleName: string;
  defaultModel: string;
  description: string;
  prompt: string;
}

const SYSTEM_ROLES: Record<string, ChatRoleConfig> = {
  security_analyst: {
    roleName: 'General Recon Analyst',
    defaultModel: 'gemini-3.8-flash',
    description: 'Balanced recon analysis, attack surface posture, and remediation guidance.',
    prompt: `You are ReconX Security Copilot, an elite defensive cybersecurity reconnaissance and attack surface mapping specialist.
You assist security engineers, penetration testers, and analysts who have authorized scope to assess infrastructure.
Your expertise covers:
- Reconnaissance methodologies (Passive OSINT, Active scanning, DNS enumeration, Web fingerprinting, Port scanning)
- Analysis of open ports, services, TLS configurations, and DNS records
- Interpretation of attack surface findings and vulnerability severity (CVSS, OWASP Top 10)
- Actionable, prioritized remediation guidance
- Clear, professional security briefings and technical explanations

Guidelines:
- Maintain an authoritative yet helpful, professional cybersecurity expert tone.
- When explaining commands (such as nmap, subfinder, httpx, dnsx), provide safe, syntax-correct, and context-appropriate examples.
- Clearly emphasize authorization and ethical boundaries when discussing testing.
- Format responses cleanly with markdown headings, concise bullet points, and code blocks with syntax highlighting.`,
  },
  rapid_scout: {
    roleName: 'Fast Triage Scout',
    defaultModel: 'gemini-3.1-flash-lite',
    description: 'Ultra-rapid lookups for ports, CLI tool syntax, CVE summaries, and quick checks.',
    prompt: `You are ReconX Fast Scout, a rapid-fire cybersecurity assistant optimized for quick lookups and triage.
You provide instant, punchy answers:
- Quick port & protocol definitions (e.g., port 3306, 8080, 53, 22)
- Rapid CLI tool syntax (nmap flags, subfinder parameters, httpx options, dnsx record lookups)
- Rapid CVE identification and CVSS summaries
- Quick troubleshooting of recon errors or timeout issues

Be extremely concise, fast, and direct. Use bullet points and code snippets. Skip unnecessary preamble.`,
  },
  deep_threat_expert: {
    roleName: 'Deep Exploit & Attack Vector Specialist',
    defaultModel: 'gemini-4-argon',
    description: 'Advanced reasoning for multi-stage attack chaining and complex threat modeling.',
    prompt: `You are ReconX Deep Threat Specialist, an advanced reasoning engine for complex attack surface vectoring, vulnerability chaining, and threat modeling.
Your role:
- Reason in-depth through complex attack surfaces and potential vulnerability chains across discovered assets
- Correlate seemingly benign open services (e.g. exposed Redis + internal web panel) into multi-stage attack scenarios
- Provide rigorous threat models (STRIDE, MITRE ATT&CK mapping)
- Deliver in-depth architectural remediation and defense-in-depth hardening roadmaps

Provide thorough technical depth, logical chains of reasoning, and comprehensive mitigation steps.`,
  },
};

// API: Available models and roles info
app.get('/api/chat/roles', (_req: Request, res: Response) => {
  res.json({
    roles: Object.entries(SYSTEM_ROLES).map(([key, config]) => ({
      key,
      name: config.roleName,
      defaultModel: config.defaultModel,
      description: config.description,
    })),
  });
});

// POST /api/chat
app.post('/api/chat', async (req: Request, res: Response) => {
  try {
    const { messages, role = 'security_analyst', model, assessmentContext } = req.body;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Messages array is required' });
    }

    const ai = getAiClient();
    if (!ai) {
      return res.status(503).json({
        error: 'GEMINI_API_KEY is not configured on the server. Please check the Secrets panel in AI Studio.',
      });
    }

    const roleConfig = SYSTEM_ROLES[role] || SYSTEM_ROLES.security_analyst;
    const selectedModel = model || roleConfig.defaultModel;

    let systemInstruction = roleConfig.prompt;

    if (assessmentContext) {
      systemInstruction += `\n\n[CURRENT ASSESSMENT TARGET CONTEXT]\nProject: ${assessmentContext.name || 'Assessment'}\nClient: ${assessmentContext.clientName || 'General Target'}\nTarget Domain: ${assessmentContext.rootDomain || 'N/A'}\nMode: ${assessmentContext.type || 'N/A'}\nStatus: ${assessmentContext.status || 'N/A'}\nAssets Discovered: ${assessmentContext.assetsCount ?? 0}\nSubdomains: ${assessmentContext.subdomainsCount ?? 0}\nEndpoints: ${assessmentContext.endpointsCount ?? 0}\nOpen Services: ${assessmentContext.servicesCount ?? 0}\nFindings Count: ${assessmentContext.findingsCount ?? 0}`;

      if (Array.isArray(assessmentContext.approvedHostnames) && assessmentContext.approvedHostnames.length > 0) {
        systemInstruction += `\nApproved Hostnames: ${assessmentContext.approvedHostnames.slice(0, 15).join(', ')}`;
      }
      if (Array.isArray(assessmentContext.permittedPorts) && assessmentContext.permittedPorts.length > 0) {
        systemInstruction += `\nPermitted Ports: ${assessmentContext.permittedPorts.join(', ')}`;
      }
      if (Array.isArray(assessmentContext.topFindings) && assessmentContext.topFindings.length > 0) {
        systemInstruction += `\nRecent Findings in Scope:\n${assessmentContext.topFindings.map((f: any) => `- [${f.severity?.toUpperCase() || 'INFO'}] ${f.title}: ${f.description || ''}`).join('\n')}`;
      }
    }

    // Convert messages to GenAI contents format
    const contents = messages.map((m: { role: string; text: string }) => ({
      role: m.role === 'model' || m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.text }],
    }));

    const response = await ai.models.generateContent({
      model: selectedModel,
      contents,
      config: {
        systemInstruction,
      },
    });

    const replyText = response.text || 'No response generated.';

    return res.json({
      text: replyText,
      model: selectedModel,
      role,
      roleName: roleConfig.roleName,
    });
  } catch (err: any) {
    console.error('Error in /api/chat:', err);
    return res.status(500).json({
      error: err.message || 'Failed to generate response from Gemini API',
    });
  }
});

// GET /api/health
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    hasApiKey: Boolean(process.env.GEMINI_API_KEY),
  });
});

// Start dev or production server
async function startServer() {
  const isProduction =
    process.env.NODE_ENV === 'production' ||
    (!process.env.DEFAULT_APP_PORT && fs.existsSync(path.resolve(__dirname, 'dist', 'index.html')));

  if (isProduction) {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ReconX Server running on http://0.0.0.0:${PORT} (mode: ${isProduction ? 'production' : 'development'})`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
