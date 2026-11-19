/**
 * CORSCraft Origin Matrix Tester
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import { OriginMatrixResult, OriginMatrixTestItem } from '../types.js';

export const STANDARD_TEST_ORIGINS: { origin: string; category: OriginMatrixTestItem['category'] }[] = [
  { origin: 'http://localhost:3000', category: 'Localhost' },
  { origin: 'http://127.0.0.1:5173', category: 'Localhost' },
  { origin: 'https://app.example.com', category: 'Production' },
  { origin: 'https://staging.example.com', category: 'Staging' },
  { origin: 'null', category: 'Null / Sandboxed' },
  { origin: 'https://evil-attacker.com', category: 'Untrusted / Attacker' },
  { origin: 'https://example.com.evil.com', category: 'Untrusted / Attacker' }
];

export function testOriginMatrix(
  targetUrl: string,
  corsChecker: (origin: string) => { allowOrigin: string | null; allowCredentials: boolean }
): OriginMatrixResult {
  const results: OriginMatrixTestItem[] = [];
  const vulnerabilities: string[] = [];

  for (const item of STANDARD_TEST_ORIGINS) {
    const check = corsChecker(item.origin);
    const allowOrigin = check.allowOrigin;
    const allowCreds = check.allowCredentials;

    let isAllowed = false;
    if (allowOrigin === '*') {
      isAllowed = !allowCreds; // * with creds is illegal and blocked
    } else if (allowOrigin === item.origin) {
      isAllowed = true;
    }

    let risk: OriginMatrixTestItem['risk'] = 'SAFE';
    let statusDesc = `Origin blocked safely.`;

    if (isAllowed) {
      if (item.category === 'Untrusted / Attacker') {
        risk = 'CRITICAL';
        statusDesc = `CRITICAL: Server permits untrusted attacker origin! ${allowCreds ? 'With credentials enabled (Severe CSRF/Data Theft Risk).' : 'Without credentials.'}`;
        vulnerabilities.push(`Permits untrusted attacker origin "${item.origin}"`);
      } else if (item.category === 'Null / Sandboxed') {
        risk = 'CRITICAL';
        statusDesc = 'CRITICAL: Null origin permitted. Sandboxed iframes and local file exploits can access API.';
        vulnerabilities.push('Null origin permitted');
      } else if (allowOrigin === '*' && allowCreds) {
        risk = 'CRITICAL';
        statusDesc = 'CRITICAL: Wildcard origin with credentials violates Fetch Standard.';
        vulnerabilities.push('Illegal wildcard origin with credentials');
      } else {
        risk = 'SAFE';
        statusDesc = `Authorized legitimate origin (${item.category}).`;
      }
    } else if (allowOrigin === '*' && allowCreds) {
      risk = 'CRITICAL';
      statusDesc = 'BLOCKED: Illegal wildcard + credentials configuration.';
      vulnerabilities.push('Illegal wildcard origin with credentials');
    } else if (item.category === 'Localhost' && !isAllowed) {
      risk = 'WARNING';
      statusDesc = 'Local development origin blocked. Developers will experience CORS errors locally.';
    }

    results.push({
      origin: item.origin,
      category: item.category,
      isAllowed,
      credentialsSupported: allowCreds,
      risk,
      statusDescription: statusDesc
    });
  }

  return {
    targetUrl,
    results,
    vulnerabilitiesDetected: Array.from(new Set(vulnerabilities))
  };
}
