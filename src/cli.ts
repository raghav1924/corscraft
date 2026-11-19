#!/usr/bin/env node
/**
 * CORSCraft Command Line Interface (CLI)
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import { auditLiveUrl, auditHeaders } from './core/auditor.js';
import { simulatePreflightHandshake } from './simulator/preflight.js';
import { testOriginMatrix } from './simulator/matrix.js';
import { startCorsProxy } from './proxy/corsProxy.js';
import { generateFrameworkConfig } from './generators/configGen.js';
import { startStudioServer } from './studio/server.js';
import { FrameworkType } from './types.js';

const VERSION = '1.0.0';

export async function run(args: string[]): Promise<void> {
  const command = args[0] || 'help';

  if (command === '--version' || command === '-v') {
    console.log(`corscraft v${VERSION} by Jatin Sharma (https://jatinsh.netlify.app/)`);
    return;
  }

  if (command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  switch (command) {
    case 'audit':
      await handleAudit(args.slice(1));
      break;
    case 'simulate':
      handleSimulate(args.slice(1));
      break;
    case 'matrix':
      await handleMatrix(args.slice(1));
      break;
    case 'proxy':
      handleProxy(args.slice(1));
      break;
    case 'generate':
      handleGenerate(args.slice(1));
      break;
    case 'studio':
      handleStudio(args.slice(1));
      break;
    default:
      console.error(`Unknown command: "${command}". Run "corscraft help" for usage.`);
      process.exit(1);
  }
}

function printHelp(): void {
  console.log(`
⚡ CORSCraft v${VERSION} — Developer-First CORS & Security Header Engine
Author: Jatin Sharma (https://jatinsh.netlify.app/)

Usage:
  corscraft <command> [options]

Commands:
  audit <url>           Audit live HTTP/HTTPS endpoint or headers for CORS & security issues
  simulate              Simulate browser cross-origin preflight handshake step-by-step
  matrix <url>          Test origin matrix (Localhost, Prod, Null, Attacker origins)
  proxy                 Start zero-config local CORS development proxy
  generate              Generate production-hardened CORS middleware (Express, Next.js, Fastify...)
  studio                Launch embedded Bento Grid Web Studio (Default port: 6565)
  help                  Show this help menu

Options:
  --origin <origin>     Specify client requesting origin (e.g. http://localhost:3000)
  --target <target>     Target server URL for simulation or proxy forwarding
  --method <method>     HTTP Method for preflight simulation (GET, POST, PUT, DELETE...)
  --credentials         Enable Access-Control-Allow-Credentials simulation
  --port <port>         Port number for Studio (6565) or Proxy (9090)
  --ci                  Exit with code 1 if audit score < 70 or CRITICAL issue found
  --json                Output audit or simulation results as JSON

Examples:
  corscraft audit https://api.github.com --origin https://myapp.com
  corscraft simulate --origin http://localhost:3000 --target https://api.example.com --method POST
  corscraft proxy --port 9090 --target https://api.example.com
  corscraft generate --framework express
  corscraft studio --port 6565
`);
}

async function handleAudit(args: string[]): Promise<void> {
  const target = args.find((a) => !a.startsWith('-')) || 'demo';
  const originIdx = args.indexOf('--origin');
  const origin = originIdx !== -1 ? args[originIdx + 1] : 'https://app.example.com';
  const isCi = args.includes('--ci');
  const isJson = args.includes('--json');

  let result;
  if (target === 'demo' || !target.startsWith('http')) {
    const demoHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true', // Triggers CORS-001
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Max-Age': '60'
    };
    result = auditHeaders(demoHeaders, 'Demo Insecure CORS Header Set', origin);
  } else {
    try {
      result = await auditLiveUrl(target, origin);
    } catch (e: any) {
      console.error(`Audit Error: ${e.message}`);
      process.exit(1);
    }
  }

  if (isJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printAuditTerminal(result);
  }

  if (isCi) {
    const hasCritical = result.issues.some((i) => i.severity === 'CRITICAL');
    if (result.score < 70 || hasCritical) {
      console.error(`\n✖ CI Check Failed: Audit score ${result.score}/100 below threshold or critical issue detected.`);
      process.exit(1);
    }
  }
}

function printAuditTerminal(r: any): void {
  const gradeColor = r.score >= 85 ? '\x1b[32m' : r.score >= 70 ? '\x1b[33m' : '\x1b[31m';
  console.log(`\n======================================================`);
  console.log(`⚡ CORSCraft Security & CORS Audit: ${r.target}`);
  console.log(`======================================================`);
  console.log(`Audit Score: ${gradeColor}${r.score}/100 (Grade: ${r.grade})\x1b[0m`);
  console.log(`CORS Configured: ${r.cors.hasCORS ? 'YES' : 'NO'}`);
  console.log(`Allowed Origin: ${r.cors.allowOrigin || 'None'}`);
  console.log(`Allow Credentials: ${r.cors.allowCredentials}`);
  console.log(`Preflight Max-Age: ${r.cors.maxAge !== null ? `${r.cors.maxAge}s` : 'None'}`);
  console.log(`Vary: Origin Declared: ${r.cors.hasVaryOrigin ? 'YES' : 'NO'}`);

  console.log(`\n--- Heuristics & Findings (${r.issues.length}) ---`);
  if (r.issues.length === 0) {
    console.log(`\x1b[32m✔ No vulnerabilities or misconfigurations detected. Clean posture!\x1b[0m`);
  } else {
    for (const iss of r.issues) {
      const col = iss.severity === 'CRITICAL' ? '\x1b[31m' : iss.severity === 'HIGH' ? '\x1b[35m' : '\x1b[33m';
      console.log(`\n${col}[${iss.severity}] ${iss.code}: ${iss.title}\x1b[0m`);
      console.log(`  Description: ${iss.description}`);
      console.log(`  Fix: \x1b[36m${iss.remediation}\x1b[0m`);
    }
  }
  console.log(`\n======================================================\n`);
}

function handleSimulate(args: string[]): void {
  const originIdx = args.indexOf('--origin');
  const targetIdx = args.indexOf('--target');
  const methodIdx = args.indexOf('--method');
  const creds = args.includes('--credentials');

  const origin = originIdx !== -1 ? args[originIdx + 1] : 'http://localhost:3000';
  const target = targetIdx !== -1 ? args[targetIdx + 1] : 'https://api.example.com/items';
  const method = methodIdx !== -1 ? args[methodIdx + 1] : 'POST';

  const simulatedServerHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:3000',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '7200'
  };

  const sim = simulatePreflightHandshake(
    { origin, targetUrl: target, method, credentials: creds },
    simulatedServerHeaders
  );

  console.log(`\n======================================================`);
  console.log(`⚡ Preflight Simulation: ${origin} -> ${method} ${target}`);
  console.log(`======================================================`);
  console.log(`Preflight Required: ${sim.preflightRequired ? 'YES' : 'NO (Simple Request)'}`);
  console.log(`Preflight Result: ${sim.preflightPassed ? '\x1b[32mPASSED\x1b[0m' : '\x1b[31mBLOCKED\x1b[0m'}`);
  console.log(`Actual Request: ${sim.actualRequestAllowed ? '\x1b[32mALLOWED\x1b[0m' : '\x1b[31mBLOCKED BY BROWSER\x1b[0m'}`);

  console.log(`\n--- Handshake Trace ---`);
  for (const s of sim.handshakeSteps) {
    const col = s.status === 'SUCCESS' ? '\x1b[32m✔' : s.status === 'FAILED' ? '\x1b[31m✖' : '\x1b[33m-';
    console.log(`Step ${s.step}: [${s.actor}] ${col} ${s.action}\x1b[0m`);
    console.log(`   ${s.details}`);
  }

  if (sim.browserConsoleError) {
    console.log(`\n\x1b[31mBrowser Console Error:\x1b[0m`);
    console.log(`  ${sim.browserConsoleError}`);
  }
  console.log(`\n======================================================\n`);
}

async function handleMatrix(args: string[]): Promise<void> {
  const target = args.find((a) => !a.startsWith('-')) || 'https://api.example.com';
  console.log(`\n⚡ Testing Origin Matrix against ${target}...`);

  const matrix = testOriginMatrix(target, (origin) => {
    // Dynamic mock origin validator for CLI preview
    if (origin.includes('localhost') || origin.includes('example.com')) {
      return { allowOrigin: origin, allowCredentials: true };
    }
    return { allowOrigin: null, allowCredentials: false };
  });

  console.log(`\nMatrix Evaluation Results:`);
  for (const item of matrix.results) {
    const col = item.risk === 'SAFE' ? '\x1b[32m' : item.risk === 'WARNING' ? '\x1b[33m' : '\x1b[31m';
    console.log(`${col}[${item.risk}] ${item.origin} (${item.category})\x1b[0m -> ${item.statusDescription}`);
  }
}

function handleProxy(args: string[]): void {
  const portIdx = args.indexOf('--port');
  const targetIdx = args.indexOf('--target');

  const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : 9090;
  const target = targetIdx !== -1 ? args[targetIdx + 1] : 'http://localhost:8080';

  startCorsProxy({ port, target });
}

function handleGenerate(args: string[]): void {
  const fwIdx = args.indexOf('--framework');
  const fw = (fwIdx !== -1 ? args[fwIdx + 1] : 'express') as FrameworkType;
  const config = generateFrameworkConfig(fw);

  console.log(`\n// ${config.title} (${config.filename})`);
  console.log(`// ${config.description}\n`);
  console.log(config.code);
}

function handleStudio(args: string[]): void {
  const portIdx = args.indexOf('--port');
  const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) : 6565;
  startStudioServer(port);
}

if (process.argv[1] && (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('corscraft'))) {
  run(process.argv.slice(2)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

