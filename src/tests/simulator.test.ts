import { test } from 'node:test';
import assert from 'node:assert';
import { isPreflightRequired, simulatePreflightHandshake } from '../simulator/preflight.js';
import { testOriginMatrix } from '../simulator/matrix.js';

test('isPreflightRequired identifies non-simple methods and headers', () => {
  assert.strictEqual(isPreflightRequired('GET', ['Accept']).required, false);
  assert.strictEqual(isPreflightRequired('POST', ['Content-Type'], 'text/plain').required, false);

  assert.strictEqual(isPreflightRequired('PUT', ['Accept']).required, true);
  assert.strictEqual(isPreflightRequired('DELETE', ['Accept']).required, true);
  assert.strictEqual(isPreflightRequired('POST', ['Authorization']).required, true);
  assert.strictEqual(isPreflightRequired('POST', ['Content-Type'], 'application/json').required, true);
});

test('simulatePreflightHandshake succeeds on valid CORS preflight response', () => {
  const req = {
    origin: 'http://localhost:3000',
    targetUrl: 'https://api.example.com/items',
    method: 'POST',
    requestHeaders: ['Content-Type', 'Authorization'],
    credentials: false
  };

  const serverHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:3000',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '7200'
  };

  const sim = simulatePreflightHandshake(req, serverHeaders, 204);
  assert.strictEqual(sim.preflightRequired, true);
  assert.strictEqual(sim.preflightPassed, true);
  assert.strictEqual(sim.actualRequestAllowed, true);
  assert.strictEqual(sim.browserConsoleError, undefined);
});

test('simulatePreflightHandshake rejects wildcard origin with credentials', () => {
  const req = {
    origin: 'http://localhost:3000',
    targetUrl: 'https://api.example.com/items',
    method: 'POST',
    requestHeaders: ['Content-Type'],
    credentials: true
  };

  const serverHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };

  const sim = simulatePreflightHandshake(req, serverHeaders, 204);
  assert.strictEqual(sim.preflightPassed, false);
  assert.strictEqual(sim.actualRequestAllowed, false);
  assert.ok(sim.browserConsoleError?.includes('wildcard'));
});

test('testOriginMatrix detects attacker origins correctly', () => {
  const matrix = testOriginMatrix('https://api.example.com', (origin) => {
    if (origin.includes('localhost') || origin.includes('example.com')) {
      return { allowOrigin: origin, allowCredentials: true };
    }
    return { allowOrigin: null, allowCredentials: false };
  });

  assert.strictEqual(matrix.targetUrl, 'https://api.example.com');
  const evil = matrix.results.find(r => r.origin === 'https://evil-attacker.com');
  assert.strictEqual(evil?.isAllowed, false);
  assert.strictEqual(evil?.risk, 'SAFE');
});
