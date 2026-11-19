/**
 * CORSCraft Automated Hardener & Remediation Diff Generator
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

export function generateHardenedHeaders(
  currentHeaders: Record<string, string>,
  targetOrigin: string = 'https://app.example.com',
  requireCredentials: boolean = false
): Record<string, string> {
  const hardened: Record<string, string> = { ...currentHeaders };

  // Case normalization map
  const lowerMap: Record<string, string> = {};
  for (const k of Object.keys(hardened)) {
    lowerMap[k.toLowerCase()] = k;
  }

  // 1. CORS headers
  if (requireCredentials) {
    hardened['Access-Control-Allow-Origin'] = targetOrigin;
    hardened['Access-Control-Allow-Credentials'] = 'true';
    hardened['Vary'] = hardened['Vary'] ? `${hardened['Vary']}, Origin` : 'Origin';
  } else {
    hardened['Access-Control-Allow-Origin'] = targetOrigin || '*';
    if (hardened['Access-Control-Allow-Origin'] !== '*') {
      hardened['Vary'] = hardened['Vary'] ? `${hardened['Vary']}, Origin` : 'Origin';
    }
  }

  hardened['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
  hardened['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-Request-ID';
  hardened['Access-Control-Expose-Headers'] = 'Content-Length, X-Request-ID, Retry-After';
  hardened['Access-Control-Max-Age'] = '7200';

  // 2. Core Security Headers
  hardened['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  hardened['X-Content-Type-Options'] = 'nosniff';
  hardened['X-Frame-Options'] = 'DENY';
  hardened['Referrer-Policy'] = 'strict-origin-when-cross-origin';
  hardened['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()';
  hardened['Cross-Origin-Opener-Policy'] = 'same-origin';
  hardened['Cross-Origin-Resource-Policy'] = 'same-site';

  if (!hardened['Content-Security-Policy']) {
    hardened['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'; object-src 'none';";
  }

  return hardened;
}

export interface HeaderDiffItem {
  header: string;
  status: 'UNCHANGED' | 'ADDED' | 'MODIFIED' | 'REMOVED';
  currentValue: string | null;
  hardenedValue: string;
}

export function computeHeaderDiff(
  current: Record<string, string>,
  hardened: Record<string, string>
): HeaderDiffItem[] {
  const diffs: HeaderDiffItem[] = [];
  const currLower: Record<string, { originalKey: string; val: string }> = {};
  for (const [k, v] of Object.entries(current)) {
    currLower[k.toLowerCase()] = { originalKey: k, val: v };
  }

  for (const [hKey, hVal] of Object.entries(hardened)) {
    const existing = currLower[hKey.toLowerCase()];
    if (!existing) {
      diffs.push({
        header: hKey,
        status: 'ADDED',
        currentValue: null,
        hardenedValue: hVal
      });
    } else if (existing.val.trim() !== hVal.trim()) {
      diffs.push({
        header: hKey,
        status: 'MODIFIED',
        currentValue: existing.val,
        hardenedValue: hVal
      });
    } else {
      diffs.push({
        header: hKey,
        status: 'UNCHANGED',
        currentValue: existing.val,
        hardenedValue: hVal
      });
    }
  }

  return diffs;
}
