/**
 * CORSCraft Core Auditor
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import http from 'http';
import https from 'https';
import { URL } from 'url';
import {
  AuditResult,
  AuditGrade,
  CORSHeadersSummary,
  SecurityHeaderAnalysis
} from '../types.js';
import { evaluateCORSHeuristics } from './heuristics.js';
import { generateHardenedHeaders } from './hardener.js';

export function calculateGrade(score: number): AuditGrade {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function parseCORSHeaders(headers: Record<string, string>): CORSHeadersSummary {
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    h[k.toLowerCase()] = v;
  }

  const allowOrigin = h['access-control-allow-origin']?.trim() ?? null;
  const allowCredentials = h['access-control-allow-credentials']?.trim().toLowerCase() === 'true';
  const allowMethods = h['access-control-allow-methods']?.split(',').map((s) => s.trim()) ?? [];
  const allowHeaders = h['access-control-allow-headers']?.split(',').map((s) => s.trim()) ?? [];
  const exposeHeaders = h['access-control-expose-headers']?.split(',').map((s) => s.trim()) ?? [];
  const maxAgeStr = h['access-control-max-age']?.trim();
  const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : null;
  const vary = h['vary']?.toLowerCase() ?? '';

  return {
    hasCORS: Boolean(allowOrigin),
    allowOrigin,
    allowCredentials,
    allowMethods,
    allowHeaders,
    exposeHeaders,
    maxAge: isNaN(maxAge as number) ? null : maxAge,
    hasVaryOrigin: vary.includes('origin')
  };
}

export function analyzeSecurityHeaders(
  headers: Record<string, string>,
  isHttps: boolean
): Record<string, SecurityHeaderAnalysis> {
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    h[k.toLowerCase()] = v;
  }

  return {
    'Strict-Transport-Security': {
      name: 'Strict-Transport-Security',
      present: Boolean(h['strict-transport-security']),
      value: h['strict-transport-security'] ?? null,
      valid: Boolean(h['strict-transport-security'] && h['strict-transport-security'].includes('max-age=')),
      recommendation: 'max-age=31536000; includeSubDomains; preload'
    },
    'X-Content-Type-Options': {
      name: 'X-Content-Type-Options',
      present: Boolean(h['x-content-type-options']),
      value: h['x-content-type-options'] ?? null,
      valid: h['x-content-type-options']?.toLowerCase() === 'nosniff',
      recommendation: 'nosniff'
    },
    'X-Frame-Options': {
      name: 'X-Frame-Options',
      present: Boolean(h['x-frame-options']),
      value: h['x-frame-options'] ?? null,
      valid: Boolean(h['x-frame-options'] && ['deny', 'sameorigin'].includes(h['x-frame-options'].toLowerCase())),
      recommendation: 'DENY'
    },
    'Content-Security-Policy': {
      name: 'Content-Security-Policy',
      present: Boolean(h['content-security-policy']),
      value: h['content-security-policy'] ?? null,
      valid: Boolean(h['content-security-policy'] && !h['content-security-policy'].includes('unsafe-inline')),
      recommendation: "default-src 'self'; frame-ancestors 'none'; object-src 'none';"
    },
    'Referrer-Policy': {
      name: 'Referrer-Policy',
      present: Boolean(h['referrer-policy']),
      value: h['referrer-policy'] ?? null,
      valid: Boolean(h['referrer-policy'] && ['strict-origin-when-cross-origin', 'no-referrer'].includes(h['referrer-policy'].toLowerCase())),
      recommendation: 'strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
      name: 'Permissions-Policy',
      present: Boolean(h['permissions-policy']),
      value: h['permissions-policy'] ?? null,
      valid: Boolean(h['permissions-policy']),
      recommendation: 'camera=(), microphone=(), geolocation=()'
    }
  };
}

export function auditHeaders(
  headers: Record<string, string>,
  targetLabel: string = 'Static Header Set',
  originProvided?: string,
  isHttps: boolean = true
): AuditResult {
  const issues = evaluateCORSHeuristics({
    headers,
    originProvided,
    isHttps
  });

  let penalty = 0;
  for (const iss of issues) {
    if (iss.severity === 'CRITICAL') penalty += 35;
    else if (iss.severity === 'HIGH') penalty += 18;
    else if (iss.severity === 'MEDIUM') penalty += 10;
    else if (iss.severity === 'LOW') penalty += 4;
  }

  const score = Math.max(0, Math.min(100, 100 - penalty));
  const grade = calculateGrade(score);
  const cors = parseCORSHeaders(headers);
  const securityHeaders = analyzeSecurityHeaders(headers, isHttps);
  const recommendedHardenedHeaders = generateHardenedHeaders(
    headers,
    originProvided || 'https://app.example.com',
    cors.allowCredentials
  );

  return {
    target: targetLabel,
    timestamp: new Date().toISOString(),
    score,
    grade,
    issues,
    headers,
    cors,
    securityHeaders,
    recommendedHardenedHeaders
  };
}

export async function auditLiveUrl(
  targetUrl: string,
  testOrigin: string = 'https://app.example.com'
): Promise<AuditResult> {
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const client = isHttps ? https : http;

  const headersToSend: Record<string, string> = {
    'User-Agent': 'CORSCraft/1.0.0 (https://github.com/raghav1924/corscraft)',
    'Origin': testOrigin,
    'Accept': '*/*'
  };

  return new Promise<AuditResult>((resolve, reject) => {
    const req = client.request(
      targetUrl,
      {
        method: 'GET',
        headers: headersToSend,
        timeout: 8000
      },
      (res) => {
        const receivedHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) {
            receivedHeaders[k] = v.join(', ');
          } else if (v !== undefined) {
            receivedHeaders[k] = v;
          }
        }
        res.resume(); // Discard body
        const result = auditHeaders(receivedHeaders, targetUrl, testOrigin, isHttps);
        resolve(result);
      }
    );

    req.on('error', (err) => {
      reject(new Error(`Failed to audit ${targetUrl}: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Connection timed out while auditing ${targetUrl}`));
    });

    req.end();
  });
}
