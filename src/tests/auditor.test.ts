import { test } from 'node:test';
import assert from 'node:assert';
import { auditHeaders, calculateGrade, parseCORSHeaders } from '../core/auditor.js';
import { evaluateCORSHeuristics } from '../core/heuristics.js';
import { generateHardenedHeaders, computeHeaderDiff } from '../core/hardener.js';

test('calculateGrade assigns correct letter grades', () => {
  assert.strictEqual(calculateGrade(98), 'A+');
  assert.strictEqual(calculateGrade(88), 'A');
  assert.strictEqual(calculateGrade(75), 'B');
  assert.strictEqual(calculateGrade(60), 'C');
  assert.strictEqual(calculateGrade(45), 'D');
  assert.strictEqual(calculateGrade(20), 'F');
});

test('parseCORSHeaders parses complex header combinations', () => {
  const headers = {
    'Access-Control-Allow-Origin': 'https://app.example.com',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '7200',
    'Vary': 'Origin, Accept-Encoding'
  };

  const parsed = parseCORSHeaders(headers);
  assert.strictEqual(parsed.hasCORS, true);
  assert.strictEqual(parsed.allowOrigin, 'https://app.example.com');
  assert.strictEqual(parsed.allowCredentials, true);
  assert.strictEqual(parsed.maxAge, 7200);
  assert.strictEqual(parsed.hasVaryOrigin, true);
});

test('evaluateCORSHeuristics flags CORS-001 (Wildcard Origin with Credentials)', () => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true'
  };

  const issues = evaluateCORSHeuristics({ headers, isHttps: true });
  const cors001 = issues.find(i => i.code === 'CORS-001');
  assert.ok(cors001, 'Should detect CORS-001');
  assert.strictEqual(cors001?.severity, 'CRITICAL');
});

test('evaluateCORSHeuristics flags CORS-003 (Null Origin Allowed)', () => {
  const headers = {
    'Access-Control-Allow-Origin': 'null'
  };

  const issues = evaluateCORSHeuristics({ headers, isHttps: true });
  const cors003 = issues.find(i => i.code === 'CORS-003');
  assert.ok(cors003, 'Should detect CORS-003');
  assert.strictEqual(cors003?.severity, 'HIGH');
});

test('evaluateCORSHeuristics flags CORS-004 (Missing Vary: Origin on specific origin)', () => {
  const headers = {
    'Access-Control-Allow-Origin': 'https://app.example.com'
  };

  const issues = evaluateCORSHeuristics({ headers, isHttps: true });
  const cors004 = issues.find(i => i.code === 'CORS-004');
  assert.ok(cors004, 'Should detect CORS-004');
});

test('generateHardenedHeaders and computeHeaderDiff work seamlessly', () => {
  const initial = {
    'Access-Control-Allow-Origin': '*'
  };

  const hardened = generateHardenedHeaders(initial, 'https://app.example.com', true);
  assert.strictEqual(hardened['Access-Control-Allow-Origin'], 'https://app.example.com');
  assert.strictEqual(hardened['Access-Control-Allow-Credentials'], 'true');
  assert.ok(hardened['Strict-Transport-Security']);

  const diff = computeHeaderDiff(initial, hardened);
  assert.ok(diff.length > 0);
  const originDiff = diff.find(d => d.header === 'Access-Control-Allow-Origin');
  assert.strictEqual(originDiff?.status, 'MODIFIED');
});
