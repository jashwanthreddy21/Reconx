# ReconX — Automated Reconnaissance & Attack Surface Mapper

ReconX is a full-stack security reconnaissance, attack surface visualization, and assessment reporting platform built for authorized security engagements and ethical hacking lab demonstrations.

## Features

- **Authorized Scope & Assessment Wizard** — Define root domains, approved hostnames, IP/CIDR ranges, permitted ports, assessment mode (`passive`, `active`, or `mixed`), and Rules of Engagement (ROE) metadata before launching scans (`src/pages/AssessmentWizard.tsx`).
- **Automated Recon Pipeline & Lab Simulation** — Multi-phase discovery modeling (`subfinder`, `dnsx`, `httpx`, `naabu`/`nmap`, and technology/risk correlation) alongside a built-in OWASP Juice Shop coursework lab fixture (`src/services/scannerEngine.ts`).
- **12-Tab Assessment Workspace** — Dedicated views in `src/pages/AssessmentDetail.tsx` covering **Overview**, **Subdomain Heatmap**, **Attack Surface Graph**, **Asset Inventory**, **DNS Explorer**, **Web Endpoints**, **Network Services**, **Technologies**, **Observations & Risks**, **Tool Logs**, **Report & Export**, and **Scope & ROE**.
- **Interactive D3 Attack Surface Graph & Risk Heatmap** — Force-directed asset/service/finding graph (`src/components/graph/AttackSurfaceGraph.tsx`) and subdomain severity matrix (`src/components/heatmap/SubdomainFindingsHeatmap.tsx`).
- **Assessment Comparison, Diagnostics & Audit Trail** — Diff posture across runs (`src/pages/AssessmentComparison.tsx`), inspect simulated tool readiness (`src/pages/ToolDiagnostics.tsx`), and track workspace events (`src/pages/AuditLogs.tsx`).
- **PDF, JSON & CSV Reporting** — Generate multi-section PDF executive/technical reports (`src/services/pdfReportGenerator.ts`) and structured JSON/CSV exports (`src/services/exportService.ts`).
- **Server-Side Gemini Security Copilot** — Express API proxy (`server.ts`) backed by `@google/genai` with three specialized analyst roles (`General Recon Analyst`, `Fast Triage Scout`, `Deep Exploit & Attack Vector Specialist`) and scope-aware prompt context (`src/components/chat/GeminiChatbot.tsx`, `src/pages/AiAssistantPage.tsx`).
- **Firebase Auth & Owner-Scoped Firestore Rules** — Email/password and Google sign-in (`src/context/AuthContext.tsx`) paired with least-privilege Firestore security rules (`firestore.rules`).

## Tech Stack

- **Frontend:** React 19, TypeScript, Vite 8, Tailwind CSS v4, Lucide Icons, Motion
- **Visualization & Reporting:** D3 v7, jsPDF
- **Backend & AI:** Node.js, Express 4, `tsx`, `@google/genai`
- **Auth & Database:** Firebase Auth & Cloud Firestore

## Project Structure

```text
.
├── server.ts                          # Express server (Vite dev middleware / static dist + /api routes)
├── firestore.rules                    # Owner-scoped & role-guarded Cloud Firestore rules
├── firebase-applet-config.json        # Firebase project configuration
├── firebase-blueprint.json            # Firestore data schema blueprint
├── index.html                         # SPA entry template
├── vite.config.ts                     # Vite + Tailwind v4 configuration
└── src/
    ├── App.tsx                        # Main application router & landing/auth gating
    ├── context/AuthContext.tsx        # Firebase authentication & user profile state
    ├── lib/firebase.ts                # Firebase/Firestore initialization & connectivity helper
    ├── components/
    │   ├── chat/GeminiChatbot.tsx     # Floating/embedded Gemini security copilot
    │   ├── graph/AttackSurfaceGraph.tsx
    │   ├── heatmap/SubdomainFindingsHeatmap.tsx
    │   └── layout/AppShell.tsx        # Sidebar navigation & global assessment search
    ├── pages/                         # Dashboard, Wizard, Detail, Comparison, Diagnostics, Audit, Auth, AI
    ├── services/
    │   ├── scannerEngine.ts           # Multi-stage recon pipeline & findings generator
    │   ├── firestoreService.ts        # Firestore CRUD & batch persistence
    │   ├── exportService.ts           # CSV/JSON download helpers
    │   └── pdfReportGenerator.ts      # jsPDF report builder
    └── types/index.ts                 # Shared TypeScript interfaces
```

## Prerequisites

- **Node.js** 20+ and **npm**
- A **Gemini API key** (`GEMINI_API_KEY`) if using the Security Copilot (`/api/chat`)
- A **Firebase project** matching `firebase-applet-config.json` with Authentication and Firestore enabled

## Environment Setup

Create a local `.env` file in the project root (ignored by git):

```env
GEMINI_API_KEY="your_gemini_api_key_here"
# Optional server port override (defaults to 3000 in dev)
APP_PORT=3000
```

> Do not commit `.env` or real API keys to version control.

## Getting Started

Install dependencies:

```bash
npm install
```

Run the development server (Express API + Vite HMR middleware on port `3000` by default):

```bash
npm run dev
```

Type-check, build, and run in production mode:

```bash
npm run lint
npm run build
npm start
```

You can also pass a custom port cleanly:

```bash
node server.ts --port 8080
```

## Available Scripts

| Script | Command | Description |
| --- | --- | --- |
| `npm run dev` | `tsx server.ts` | Starts the Express + Vite development server |
| `npm run build` | `vite build` | Bundles the frontend into `dist/` |
| `npm start` | `node server.ts` | Serves `dist/` and API endpoints in production mode |
| `npm run lint` | `tsc --noEmit` | Runs TypeScript type checking |
| `npm run clean` | `rm -rf dist server.js` | Removes build artifacts |

## Server API Endpoints

- `GET /api/health` — Returns server status, timestamp, and whether `GEMINI_API_KEY` is configured.
- `GET /api/chat/roles` — Lists available Security Copilot roles and default Gemini models.
- `POST /api/chat` — Normalizes chat turns and queries `@google/genai` with optional assessment context.

## Ethical Use Notice

ReconX is designed strictly for **authorized security assessments**, controlled coursework labs, and defensive attack surface analysis. Always obtain explicit written authorization before mapping or testing external systems.
