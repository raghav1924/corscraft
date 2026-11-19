/**
 * CORSCraft Embedded Bento Grid Web Studio (Port 6565)
 * Patterns: Bento Grid (#12), Dark Mode (#20), Cybercore (#24), Glassmorphism (#10), Swiss Design (#3)
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import http from 'http';
import { URL } from 'url';
import { auditHeaders, auditLiveUrl } from '../core/auditor.js';
import { simulatePreflightHandshake } from '../simulator/preflight.js';
import { testOriginMatrix } from '../simulator/matrix.js';
import { generateFrameworkConfig } from '../generators/configGen.js';
import { computeHeaderDiff } from '../core/hardener.js';
import { FrameworkType } from '../types.js';

export function startStudioServer(port: number = 6565): http.Server {
  const server = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url || '/', `http://${req.headers.host}`);

    // API: Audit endpoint
    if (reqUrl.pathname === '/api/audit' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const payload = JSON.parse(body || '{}');
          const targetUrl = payload.targetUrl;
          const origin = payload.origin || 'https://app.example.com';
          
          let result;
          if (targetUrl && (targetUrl.startsWith('http://') || targetUrl.startsWith('https://'))) {
            result = await auditLiveUrl(targetUrl, origin);
          } else {
            const rawHeaders = payload.headers || {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
              'Access-Control-Max-Age': '300'
            };
            result = auditHeaders(rawHeaders, 'Custom Header Set', origin);
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    // API: Simulate preflight endpoint
    if (reqUrl.pathname === '/api/simulate' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const p = JSON.parse(body || '{}');
          const headers = p.headers || {
            'Access-Control-Allow-Origin': p.origin || 'https://app.example.com',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '7200'
          };
          const sim = simulatePreflightHandshake({
            origin: p.origin || 'https://app.example.com',
            targetUrl: p.targetUrl || 'http://localhost:8080/api/data',
            method: p.method || 'POST',
            requestHeaders: p.requestHeaders || ['Content-Type', 'Authorization'],
            credentials: Boolean(p.credentials)
          }, headers);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(sim));
        } catch (err: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    // API: Generate framework config
    if (reqUrl.pathname === '/api/generate' && req.method === 'GET') {
      const framework = (reqUrl.searchParams.get('framework') || 'express') as FrameworkType;
      const origins = reqUrl.searchParams.get('origins')?.split(',') || ['http://localhost:3000', 'https://app.example.com'];
      const creds = reqUrl.searchParams.get('credentials') === 'true';
      const config = generateFrameworkConfig(framework, { allowedOrigins: origins, allowCredentials: creds });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(config));
      return;
    }

    // Serve HTML Studio
    if (reqUrl.pathname === '/' || reqUrl.pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(renderStudioHtml(port));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  server.listen(port, () => {
    console.log(`\n⚡ CORSCraft Bento Grid Studio live at http://localhost:${port}`);
  });

  return server;
}

export function renderStudioHtml(port: number): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CORSCraft Studio | Developer-First Preflight & Security Studio</title>
  <style>
    :root {
      --bg: #070a12;
      --card-bg: rgba(15, 23, 42, 0.75);
      --card-border: #1e293b;
      --border-focus: #38bdf8;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #f43f5e;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      line-height: 1.5;
      padding: 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-logo {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, #0284c7, #38bdf8);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 20px;
      color: #fff;
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
    }
    .brand h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
    .brand p { font-size: 13px; color: var(--text-muted); }
    .author-badge {
      font-size: 13px;
      color: var(--accent);
      text-decoration: none;
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 6px 14px;
      border-radius: 20px;
      transition: all 0.2s;
    }
    .author-badge:hover { background: rgba(56, 189, 248, 0.2); }

    /* Bento Grid (Pattern #12) */
    .bento-grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 20px;
    }
    .bento-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }
    .col-4 { grid-column: span 4; }
    .col-6 { grid-column: span 6; }
    .col-8 { grid-column: span 8; }
    .col-12 { grid-column: span 12; }

    @media (max-width: 1024px) {
      .col-4, .col-6, .col-8 { grid-column: span 12; }
    }

    .card-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.8px;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Score Gauge */
    .score-container {
      display: flex;
      align-items: center;
      justify-content: space-around;
      padding: 10px 0;
    }
    .gauge-wrapper {
      position: relative;
      width: 130px;
      height: 130px;
    }
    .gauge-wrapper svg {
      transform: rotate(-90deg);
      width: 130px;
      height: 130px;
    }
    .gauge-bg {
      fill: none;
      stroke: #1e293b;
      stroke-width: 10;
    }
    .gauge-fill {
      fill: none;
      stroke: var(--accent);
      stroke-width: 10;
      stroke-linecap: round;
      stroke-dasharray: 339;
      stroke-dashoffset: 60;
      transition: stroke-dashoffset 1s ease;
    }
    .gauge-text {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .gauge-score { font-size: 32px; font-weight: 800; color: #fff; }
    .gauge-label { font-size: 12px; color: var(--text-muted); }
    .grade-badge {
      font-size: 42px;
      font-weight: 900;
      color: var(--success);
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      width: 80px;
      height: 80px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
    }

    /* Input Controls */
    .form-group { margin-bottom: 14px; }
    .form-group label {
      display: block;
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 6px;
      font-weight: 500;
    }
    input, select, textarea {
      width: 100%;
      padding: 10px 14px;
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      color: #fff;
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus, select:focus, textarea:focus { border-color: var(--border-focus); }
    .btn {
      background: var(--accent);
      color: #000;
      font-weight: 600;
      padding: 10px 18px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .btn:hover { background: #7dd3fc; box-shadow: 0 0 15px rgba(56, 189, 248, 0.4); }

    /* Handshake Timeline */
    .timeline { display: flex; flex-direction: column; gap: 12px; }
    .timeline-step {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      background: rgba(3, 7, 18, 0.6);
      padding: 12px;
      border-radius: 8px;
      border-left: 3px solid var(--card-border);
    }
    .timeline-step.SUCCESS { border-left-color: var(--success); }
    .timeline-step.FAILED { border-left-color: var(--danger); background: rgba(244, 63, 94, 0.08); }
    .timeline-step.SKIPPED { border-left-color: var(--warning); }
    .step-badge {
      background: #1e293b;
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 12px;
      white-space: nowrap;
    }
    .step-actor {
      font-size: 12px;
      font-weight: 700;
      color: var(--accent);
      text-transform: uppercase;
      margin-bottom: 2px;
    }
    .step-desc { font-size: 13px; color: #cbd5e1; }
    .step-detail { font-size: 12px; color: var(--text-muted); font-family: monospace; margin-top: 4px; word-break: break-all; }

    /* Matrix Table */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 10px; color: var(--text-muted); border-bottom: 1px solid var(--card-border); }
    td { padding: 10px; border-bottom: 1px solid rgba(30, 41, 59, 0.5); }
    .status-pill {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 10px;
      font-weight: 600;
      display: inline-block;
    }
    .status-pill.SAFE { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .status-pill.WARNING { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .status-pill.CRITICAL { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }

    /* Code Blocks */
    pre {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      overflow-x: auto;
      color: #e2e8f0;
    }

    /* Tabs */
    .tabs { display: flex; gap: 8px; margin-bottom: 14px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; }
    .tab-btn {
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 600;
      padding: 6px 12px;
      cursor: pointer;
      border-radius: 6px;
      transition: all 0.2s;
    }
    .tab-btn.active { color: var(--accent); background: rgba(56, 189, 248, 0.15); }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-logo">⚡</div>
      <div>
        <h1>CORSCraft Studio</h1>
        <p>Preflight Simulator, Cross-Origin Linter & Security Header Engine</p>
      </div>
    </div>
    <a href="https://jatinsh.netlify.app/" target="_blank" class="author-badge">Built by Jatin Sharma</a>
  </header>

  <div class="bento-grid">
    <!-- Card 1: Score & Grade -->
    <div class="bento-card col-4">
      <div class="card-title">Security & CORS Posture</div>
      <div class="score-container">
        <div class="gauge-wrapper">
          <svg>
            <circle class="gauge-bg" cx="65" cy="65" r="54"></circle>
            <circle class="gauge-fill" id="gauge-circle" cx="65" cy="65" r="54"></circle>
          </svg>
          <div class="gauge-text">
            <div class="gauge-score" id="score-val">92</div>
            <div class="gauge-label">SCORE</div>
          </div>
        </div>
        <div class="grade-badge" id="grade-val">A</div>
      </div>
      <div style="font-size: 12px; color: var(--text-muted); text-align: center; margin-top: 10px;" id="target-display">
        Target: https://api.example.com
      </div>
    </div>

    <!-- Card 2: Interactive Preflight Simulator -->
    <div class="bento-card col-8">
      <div class="card-title">
        <span>Cross-Origin Preflight Handshake Simulator</span>
        <span style="font-size: 11px; color: var(--accent); font-family: monospace;">W3C / WHATWG Spec</span>
      </div>
      <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 12px; margin-bottom: 14px;">
        <div class="form-group">
          <label>Requesting Origin</label>
          <input type="text" id="sim-origin" value="http://localhost:3000">
        </div>
        <div class="form-group">
          <label>HTTP Method</label>
          <select id="sim-method">
            <option value="POST">POST</option>
            <option value="GET">GET</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>
        </div>
        <div class="form-group">
          <label>Credentials Mode</label>
          <select id="sim-creds">
            <option value="false">same-origin (omitted)</option>
            <option value="true">include (cookies/auth)</option>
          </select>
        </div>
      </div>
      <button class="btn" onclick="runSimulation()">⚡ Simulate Browser Preflight</button>
    </div>

    <!-- Card 3: Handshake Execution Flow -->
    <div class="bento-card col-6">
      <div class="card-title">Browser ↔ Server Handshake Trace</div>
      <div class="timeline" id="handshake-timeline">
        <div class="timeline-step SUCCESS">
          <span class="step-badge">1</span>
          <div>
            <div class="step-actor">Browser</div>
            <div class="step-desc">Initiate Cross-Origin Fetch</div>
            <div class="step-detail">Client executes fetch("https://api.example.com/data", { method: "POST" })</div>
          </div>
        </div>
        <div class="timeline-step SUCCESS">
          <span class="step-badge">2</span>
          <div>
            <div class="step-actor">Network</div>
            <div class="step-desc">OPTIONS Preflight Handshake Dispatched</div>
            <div class="step-detail">Access-Control-Request-Method: POST | Access-Control-Request-Headers: Content-Type</div>
          </div>
        </div>
        <div class="timeline-step SUCCESS">
          <span class="step-badge">3</span>
          <div>
            <div class="step-actor">Server</div>
            <div class="step-desc">Preflight Handshake Verified (204 No Content)</div>
            <div class="step-detail">Access-Control-Allow-Origin: http://localhost:3000 | Access-Control-Max-Age: 7200</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Card 4: Origin Matrix -->
    <div class="bento-card col-6">
      <div class="card-title">Origin Access Matrix & Vulnerabilities</div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Origin</th>
              <th>Category</th>
              <th>Status</th>
              <th>Risk Level</th>
            </tr>
          </thead>
          <tbody id="matrix-body">
            <tr>
              <td><code>http://localhost:3000</code></td>
              <td>Localhost</td>
              <td><span class="status-pill SAFE">Allowed</span></td>
              <td><span class="status-pill SAFE">SAFE</span></td>
            </tr>
            <tr>
              <td><code>https://app.example.com</code></td>
              <td>Production</td>
              <td><span class="status-pill SAFE">Allowed</span></td>
              <td><span class="status-pill SAFE">SAFE</span></td>
            </tr>
            <tr>
              <td><code>null</code></td>
              <td>Sandboxed</td>
              <td><span class="status-pill SAFE">Blocked</span></td>
              <td><span class="status-pill SAFE">SAFE</span></td>
            </tr>
            <tr>
              <td><code>https://evil-attacker.com</code></td>
              <td>Attacker</td>
              <td><span class="status-pill SAFE">Blocked</span></td>
              <td><span class="status-pill SAFE">SAFE</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Card 5: Framework Config Generator -->
    <div class="bento-card col-12">
      <div class="card-title">
        <span>Production-Hardened Middleware Generator</span>
        <button class="btn" style="padding: 4px 12px; font-size: 12px;" onclick="copyCode()">Copy Code</button>
      </div>
      <div class="tabs">
        <button class="tab-btn active" onclick="switchFramework('express')">Express.js</button>
        <button class="tab-btn" onclick="switchFramework('nextjs')">Next.js</button>
        <button class="tab-btn" onclick="switchFramework('fastify')">Fastify</button>
        <button class="tab-btn" onclick="switchFramework('nginx')">Nginx</button>
        <button class="tab-btn" onclick="switchFramework('cloudflare_workers')">Cloudflare Workers</button>
        <button class="tab-btn" onclick="switchFramework('fastapi')">FastAPI (Python)</button>
      </div>
      <pre id="code-output">// Loading production configuration...</pre>
    </div>
  </div>

  <script>
    let currentFramework = 'express';

    async function switchFramework(fw) {
      currentFramework = fw;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      
      const res = await fetch('/api/generate?framework=' + fw);
      const data = await res.json();
      document.getElementById('code-output').textContent = data.code;
    }

    async function runSimulation() {
      const origin = document.getElementById('sim-origin').value;
      const method = document.getElementById('sim-method').value;
      const creds = document.getElementById('sim-creds').value === 'true';

      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ origin, method, credentials: creds })
      });
      const data = await res.json();

      const timeline = document.getElementById('handshake-timeline');
      timeline.innerHTML = '';
      data.handshakeSteps.forEach(s => {
        const div = document.createElement('div');
        div.className = 'timeline-step ' + s.status;
        div.innerHTML = \`
          <span class="step-badge">\${s.step}</span>
          <div>
            <div class="step-actor">\${s.actor}</div>
            <div class="step-desc">\${s.action}</div>
            <div class="step-detail">\${s.details}</div>
          </div>
        \`;
        timeline.appendChild(div);
      });
    }

    function copyCode() {
      const code = document.getElementById('code-output').textContent;
      navigator.clipboard.writeText(code);
      alert('Config copied to clipboard!');
    }

    // Initial load
    switchFramework('express');
  </script>
</body>
</html>`;
}
