/**
 * CORSCraft Heuristics Engine
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import { AuditIssue } from '../types.js';

export interface EvaluationContext {
  headers: Record<string, string>;
  originProvided?: string;
  isHttps: boolean;
}

export function evaluateCORSHeuristics(ctx: EvaluationContext): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(ctx.headers)) {
    h[k.toLowerCase()] = v;
  }

  const allowOrigin = h['access-control-allow-origin']?.trim() ?? null;
  const allowCreds = h['access-control-allow-credentials']?.trim().toLowerCase() === 'true';
  const allowMethods = h['access-control-allow-methods']?.split(',').map((s) => s.trim()) ?? [];
  const allowHeaders = h['access-control-allow-headers']?.split(',').map((s) => s.trim()) ?? [];
  const exposeHeaders = h['access-control-expose-headers']?.split(',').map((s) => s.trim()) ?? [];
  const maxAgeStr = h['access-control-max-age']?.trim();
  const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : null;
  const vary = h['vary']?.toLowerCase() ?? '';

  // 1. CORS-001 (CRITICAL): Wildcard Origin with Credentials
  if (allowOrigin === '*' && allowCreds) {
    issues.push({
      code: 'CORS-001',
      title: 'Illegal Wildcard Origin with Credentials',
      description: 'Access-Control-Allow-Origin is set to wildcard "*" while Access-Control-Allow-Credentials is true. The Fetch Standard explicitly forbids this combination; all major browsers reject this response and abort client requests.',
      severity: 'CRITICAL',
      remediation: 'Specify explicit whitelist origins dynamically (e.g. "https://app.example.com") instead of wildcard "*" when credentials are required.',
      headersAffected: ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials']
    });
  }

  // 2. CORS-002 (CRITICAL): Reflected Untrusted Origin
  if (ctx.originProvided && allowOrigin === ctx.originProvided) {
    const isAttackerOrigin = ctx.originProvided.includes('evil.com') || ctx.originProvided.includes('attacker.local');
    if (isAttackerOrigin && allowCreds) {
      issues.push({
        code: 'CORS-002',
        title: 'Dangerous Reflected Untrusted Origin with Credentials',
        description: `Server blindly reflected untrusted origin "${ctx.originProvided}" into Access-Control-Allow-Origin with credentials enabled. This permits arbitrary websites to steal user sessions and perform authenticated API operations.`,
        severity: 'CRITICAL',
        remediation: 'Validate incoming Origin headers against an explicit, strict whitelist array before echoing into Access-Control-Allow-Origin.',
        headersAffected: ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials']
      });
    }
  }

  // 3. CORS-003 (HIGH): Null Origin Allowed
  if (allowOrigin === 'null' || allowOrigin === '"null"') {
    issues.push({
      code: 'CORS-003',
      title: 'Vulnerable Null Origin Permitted',
      description: 'Access-Control-Allow-Origin is configured to allow "null". Sandboxed iframes, file:// URLs, and data: URIs execute with origin "null", allowing untrusted scripts to bypass origin restrictions.',
      severity: 'HIGH',
      remediation: 'Remove "null" from allowed origins. Authenticate via explicit, verified domain origins only.',
      headersAffected: ['Access-Control-Allow-Origin']
    });
  }

  // 4. CORS-004 (HIGH): Missing Vary: Origin
  if (allowOrigin && allowOrigin !== '*' && !vary.includes('origin')) {
    issues.push({
      code: 'CORS-004',
      title: 'Missing "Vary: Origin" on Origin-Specific Response',
      description: 'Response returns a specific Access-Control-Allow-Origin header without declaring "Vary: Origin". Downstream HTTP caches (CDNs, Cloudflare, proxies) will cache this origin for other users, causing cross-origin breakage or cache poisoning.',
      severity: 'HIGH',
      remediation: 'Add "Vary: Origin" (or append to existing Vary header) on all CORS responses.',
      headersAffected: ['Vary', 'Access-Control-Allow-Origin']
    });
  }

  // 5. CORS-005 (HIGH): Missing CORS Headers on API Response
  if (!allowOrigin) {
    issues.push({
      code: 'CORS-005',
      title: 'Missing Cross-Origin Resource Sharing Headers',
      description: 'Endpoint does not return an Access-Control-Allow-Origin header. Web browsers will block client-side JavaScript applications from reading this response.',
      severity: 'HIGH',
      remediation: 'Configure CORS middleware to supply Access-Control-Allow-Origin matching your approved client applications.',
      headersAffected: ['Access-Control-Allow-Origin']
    });
  }

  // 6. CORS-006 (MEDIUM): Overly Broad Wildcard Headers
  if (allowHeaders.includes('*') && !allowHeaders.some(h => h.toLowerCase() === 'authorization')) {
    issues.push({
      code: 'CORS-006',
      title: 'Unrestricted Wildcard Allowed Headers',
      description: 'Access-Control-Allow-Headers is set to "*". While permissible in modern browsers without credentials, explicit header declarations ensure tighter attack surface control.',
      severity: 'MEDIUM',
      remediation: 'Enumerate explicitly permitted client headers: "Content-Type, Authorization, X-Requested-With".',
      headersAffected: ['Access-Control-Allow-Headers']
    });
  }

  // 7. CORS-007 (MEDIUM): Missing Expose Headers for Custom Attributes
  if (allowOrigin && exposeHeaders.length === 0) {
    issues.push({
      code: 'CORS-007',
      title: 'No Exposed Headers Declared (Access-Control-Expose-Headers)',
      description: 'Browser client fetch() calls will be unable to read custom headers such as "X-Total-Count", "Retry-After", "X-Request-Id", or pagination metadata.',
      severity: 'MEDIUM',
      remediation: 'Include "Access-Control-Expose-Headers: Content-Length, X-Request-Id, Retry-After" to make custom telemetry visible to frontend code.',
      headersAffected: ['Access-Control-Expose-Headers']
    });
  }

  // 8. CORS-008 (MEDIUM): Sub-optimal Preflight Cache
  if (allowOrigin && (maxAge === null || isNaN(maxAge) || maxAge < 600)) {
    issues.push({
      code: 'CORS-008',
      title: 'Missing or Sub-optimal Preflight Max-Age',
      description: `Access-Control-Max-Age is ${maxAge !== null ? `${maxAge}s (<600s)` : 'missing'}. Browsers will re-issue OPTIONS preflight handshakes frequently, adding 100-300ms latency to every request.`,
      severity: 'MEDIUM',
      remediation: 'Set "Access-Control-Max-Age: 86400" (or 7200 for Chromium maximum) to cache preflight handshakes efficiently.',
      headersAffected: ['Access-Control-Max-Age']
    });
  }

  // 9. CORS-009 (LOW): Excessive Max-Age
  if (maxAge !== null && maxAge > 86400) {
    issues.push({
      code: 'CORS-009',
      title: 'Preflight Max-Age Exceeds Browser Clamping Ceilings',
      description: `Access-Control-Max-Age (${maxAge}s) exceeds the maximum clamping value of modern browsers (Chrome caps at 7,200s; Firefox at 86,400s).`,
      severity: 'LOW',
      remediation: 'Use "Access-Control-Max-Age: 7200" to match standard browser constraints reliably.',
      headersAffected: ['Access-Control-Max-Age']
    });
  }

  // Security Headers Heuristics
  // SEC-001: HSTS
  const hsts = h['strict-transport-security'];
  if (ctx.isHttps && !hsts) {
    issues.push({
      code: 'SEC-001',
      title: 'Missing Strict-Transport-Security (HSTS)',
      description: 'HTTPS response lacks Strict-Transport-Security header, leaving connections vulnerable to SSL-stripping and man-in-the-middle downgrade attacks.',
      severity: 'HIGH',
      remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
      headersAffected: ['Strict-Transport-Security']
    });
  }

  // SEC-002: X-Content-Type-Options
  const nosniff = h['x-content-type-options'];
  if (!nosniff || nosniff.toLowerCase() !== 'nosniff') {
    issues.push({
      code: 'SEC-002',
      title: 'Missing X-Content-Type-Options: nosniff',
      description: 'Without "X-Content-Type-Options: nosniff", browsers may attempt MIME-type sniffing, transforming user-uploaded files into executable script vectors.',
      severity: 'HIGH',
      remediation: 'Add "X-Content-Type-Options: nosniff" to all HTTP responses.',
      headersAffected: ['X-Content-Type-Options']
    });
  }

  // SEC-003: X-Frame-Options
  const xfo = h['x-frame-options'];
  const csp = h['content-security-policy'] ?? '';
  const hasFrameAncestors = csp.toLowerCase().includes('frame-ancestors');
  if (!xfo && !hasFrameAncestors) {
    issues.push({
      code: 'SEC-003',
      title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
      description: 'No framing restrictions declared. Third-party sites can embed this page inside an iframe and orchestrate UI clickjacking attacks.',
      severity: 'MEDIUM',
      remediation: 'Add "X-Frame-Options: DENY" or CSP "frame-ancestors \'none\'".',
      headersAffected: ['X-Frame-Options', 'Content-Security-Policy']
    });
  }

  // SEC-004: CSP
  if (!csp) {
    issues.push({
      code: 'SEC-004',
      title: 'Missing Content-Security-Policy (CSP)',
      description: 'No Content-Security-Policy header defined. The application lacks defense-in-depth against Cross-Site Scripting (XSS) and data injection.',
      severity: 'HIGH',
      remediation: 'Deploy a strict CSP policy (e.g. "default-src \'self\'; script-src \'self\'; object-src \'none\'").',
      headersAffected: ['Content-Security-Policy']
    });
  } else if (csp.includes('unsafe-inline') && !csp.includes('nonce-') && !csp.includes('sha256-')) {
    issues.push({
      code: 'SEC-005',
      title: 'Permissive CSP with Unrestricted "unsafe-inline"',
      description: 'Content-Security-Policy contains "unsafe-inline" without cryptographic nonces or hashes, substantially degrading XSS protection.',
      severity: 'MEDIUM',
      remediation: 'Migrate to strict nonce-based or hash-based CSP scripts.',
      headersAffected: ['Content-Security-Policy']
    });
  }

  // SEC-006: Referrer-Policy
  const refPol = h['referrer-policy'];
  if (!refPol) {
    issues.push({
      code: 'SEC-006',
      title: 'Missing Referrer-Policy Header',
      description: 'Without an explicit Referrer-Policy, browsers may expose full URL paths containing private query parameters to third-party endpoints.',
      severity: 'LOW',
      remediation: 'Specify "Referrer-Policy: strict-origin-when-cross-origin".',
      headersAffected: ['Referrer-Policy']
    });
  }

  // SEC-007: Permissions-Policy
  const permPol = h['permissions-policy'];
  if (!permPol) {
    issues.push({
      code: 'SEC-007',
      title: 'Missing Permissions-Policy Header',
      description: 'Hardware and browser feature access (camera, microphone, geolocation) is unconstrained for embedded third-party contexts.',
      severity: 'LOW',
      remediation: 'Add "Permissions-Policy: camera=(), microphone=(), geolocation=()".',
      headersAffected: ['Permissions-Policy']
    });
  }

  return issues;
}
