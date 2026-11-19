# ⚡ CORSCraft

> **Developer-First CORS & Preflight Simulator, Cross-Origin Linter, Security Header Auditor & Bento Grid Studio.**  
> Crafted with pride by **[Jatin Sharma](https://jatinsh.netlify.app/)** (`raghav1924`).

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-v18+-green.svg)](https://nodejs.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0_Runtime-emerald.svg)]()
[![Design System](https://img.shields.io/badge/Design_Patterns-Bento_Grid_%2312_%7C_Dark_Mode_%2320_%7C_Cybercore_%2324-cyan.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 The Developer Problem

Every web and API developer has run into the dreaded browser error:
```text
Access to fetch at 'https://api.example.com/data' from origin 'http://localhost:3000' 
has been blocked by CORS policy: Response to preflight request doesn't pass access 
control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.
```

Cross-Origin Resource Sharing (CORS) and HTTP security headers are notoriously tricky:
1. **The Credentials Trap (`CORS-001`)**: Setting `Access-Control-Allow-Origin: *` while `Access-Control-Allow-Credentials: true` is forbidden by the W3C/WHATWG Fetch Standard and crashes browser requests.
2. **Reflected Attacker Origins (`CORS-002`)**: Blindly reflecting incoming `Origin` headers exposes authenticated APIs to session hijacking and CSRF.
3. **CDN Cache Poisoning (`CORS-004`)**: Omitting `Vary: Origin` causes shared proxy caches and CDNs (Cloudflare, CloudFront) to cache one origin for all users, randomly breaking cross-origin requests worldwide.
4. **Preflight Latency Tax (`CORS-008`)**: Missing or sub-optimal `Access-Control-Max-Age` forces browsers to fire an extra `OPTIONS` preflight roundtrip for every request, adding 100–300ms latency to every client interaction.
5. **Local Development Gridlock**: Frontends running on `localhost:3000` or `localhost:5173` cannot communicate with backends or staging APIs without modifying server code.

**CORSCraft** solves this once and for all: an all-in-one developer CLI, browser preflight simulator, zero-config local CORS proxy, multi-framework config generator, and embedded **Bento Grid Web Studio**.

---

## 🎨 Master Design Patterns (from `DESIGN_INSPIRATION.md`)

CORSCraft features a bespoke visual studio designed with:
* **Pattern #12: Bento Grid**: Modular, asymmetric cards grouping health telemetry, interactive handshake timelines, origin matrices, and code generators.
* **Pattern #20: High-Contrast Dark Mode**: Deep obsidian canvas (`#070a12`), slate structural borders (`#1e293b`), and vibrant neon status tokens.
* **Pattern #24: Cybercore Telemetry HUD**: High-precision status indicators and browser-to-server request handshake tracers.
* **Pattern #10: Glassmorphism**: Translucent frosted panels with backdrop blur filters and crisp edge highlights.
* **Pattern #3: Swiss Design Discipline**: Clean typographic hierarchy, strict grid discipline, and asymmetric balance.

---

## ⚡ Features

* **🛡️ 14+ CORS & Security Header Heuristics**: Detects illegal wildcard credentials, null origins, missing `Vary: Origin`, HSTS gaps, MIME-sniffing risks, and CSP vulnerabilities.
* **🔄 Interactive Preflight Simulator**: Emulates browser preflight handshakes step-by-step (`Browser` $\leftrightarrow$ `Network` $\leftrightarrow$ `Server`), pinpointing the exact specification violation and browser console error.
* **🌐 Origin Access Matrix**: Tests 7 origin archetypes (Localhost, Vite dev, Production, Staging, Sandboxed `null`, Attacker spoofing, Third-party exploit).
* **🔌 Zero-Config CORS Development Proxy**: Instantly bridges local frontends and remote/local backends on port `9090`, resolving local development CORS blocks with zero code changes.
* **⚙️ Production-Hardened Config Generator**: One-click generation of hardened middleware for **Express**, **Next.js 14/15**, **Fastify**, **Nginx**, **Cloudflare Workers**, and **FastAPI**.
* **📊 Embedded Bento Grid Web Studio**: Interactive browser UI hosted on port `6565` with real-time SVG health gauges and remediation diffs.
* **🚀 Zero Runtime Dependencies**: Pure native Node.js (`http`, `https`, `url`, `crypto`, `fs`).

---

## 📦 Installation & Quickstart

```bash
# Run directly via npx
npx corscraft studio

# Or install globally
npm install -g corscraft
```

---

## 💻 CLI Commands

### 1. Audit Live URL or Static Header Set
```bash
# Audit any live API endpoint
corscraft audit https://api.github.com --origin https://myapp.com

# Run in CI mode (exits with code 1 if score < 70 or critical issue detected)
corscraft audit https://api.example.com --ci

# Output raw machine-readable JSON
corscraft audit https://api.example.com --json
```

### 2. Simulate Browser Preflight Handshake
```bash
corscraft simulate \
  --origin http://localhost:3000 \
  --target https://api.example.com/v1/checkout \
  --method POST \
  --credentials
```

### 3. Test Origin Access Matrix
```bash
corscraft matrix https://api.example.com
```

### 4. Zero-Config Local Development CORS Proxy
```bash
# Forwards localhost:9090 -> backend:8080 with automatic CORS headers injected
corscraft proxy --port 9090 --target http://localhost:8080
```

### 5. Generate Production Middleware
```bash
corscraft generate --framework express
corscraft generate --framework nextjs
corscraft generate --framework nginx
corscraft generate --framework cloudflare_workers
corscraft generate --framework fastapi
```

### 6. Launch Embedded Bento Grid Studio
```bash
corscraft studio --port 6565
```
Open `http://localhost:6565` in your browser.

---

## 🛠️ Programmatic TypeScript API

```typescript
import { 
  auditHeaders, 
  auditLiveUrl, 
  simulatePreflightHandshake, 
  generateFrameworkConfig 
} from 'corscraft';

// Audit an endpoint
const audit = await auditLiveUrl('https://api.example.com', 'https://myapp.com');
console.log(`Score: ${audit.score}/100, Grade: ${audit.grade}`);

// Simulate preflight
const sim = simulatePreflightHandshake({
  origin: 'http://localhost:3000',
  targetUrl: 'https://api.example.com/data',
  method: 'PUT',
  credentials: true
}, audit.headers);

console.log(`Allowed: ${sim.actualRequestAllowed}`);
```

---

## 🧪 Test Suite

```bash
npm test
```
All 16 unit and integration tests run in $<300\text{ms}$ with zero external testing dependencies using Node.js native test runner.

---

## 👤 Author

**Jatin Sharma (`raghav1924`)**
* Portfolio: [https://jatinsh.netlify.app/](https://jatinsh.netlify.app/)
* GitHub: [@raghav1924](https://github.com/raghav1924)
* Email: [raghavjatin245@gmail.com](mailto:raghavjatin245@gmail.com)

---

## 📄 License

MIT License © 2026 Jatin Sharma.
