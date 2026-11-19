import { test } from 'node:test';
import assert from 'node:assert';
import { generateFrameworkConfig } from '../generators/configGen.js';

test('generateFrameworkConfig generates valid Express configuration', () => {
  const config = generateFrameworkConfig('express', {
    allowedOrigins: ['https://myapp.com'],
    allowCredentials: true
  });

  assert.strictEqual(config.framework, 'express');
  assert.ok(config.code.includes('ALLOWED_ORIGINS'));
  assert.ok(config.code.includes('https://myapp.com'));
  assert.ok(config.code.includes('credentials: true'));
  assert.ok(config.code.includes('Strict-Transport-Security'));
});

test('generateFrameworkConfig generates valid Next.js configuration', () => {
  const config = generateFrameworkConfig('nextjs', {
    allowedOrigins: ['https://dashboard.company.com'],
    allowCredentials: true
  });

  assert.strictEqual(config.framework, 'nextjs');
  assert.ok(config.code.includes('nextConfig'));
  assert.ok(config.code.includes('Access-Control-Allow-Origin'));
  assert.ok(config.code.includes('https://dashboard.company.com'));
});

test('generateFrameworkConfig generates valid Nginx configuration', () => {
  const config = generateFrameworkConfig('nginx', {
    allowedOrigins: ['http://localhost:3000', 'https://myapp.com']
  });

  assert.strictEqual(config.framework, 'nginx');
  assert.ok(config.code.includes('map $http_origin $cors_origin'));
  assert.ok(config.code.includes('$request_method = \'OPTIONS\''));
  assert.ok(config.code.includes('return 204;'));
});

test('generateFrameworkConfig generates valid Cloudflare Workers configuration', () => {
  const config = generateFrameworkConfig('cloudflare_workers');
  assert.strictEqual(config.framework, 'cloudflare_workers');
  assert.ok(config.code.includes('export default {'));
  assert.ok(config.code.includes('request.method === \'OPTIONS\''));
});

test('generateFrameworkConfig generates valid FastAPI configuration', () => {
  const config = generateFrameworkConfig('fastapi');
  assert.strictEqual(config.framework, 'fastapi');
  assert.ok(config.code.includes('from fastapi.middleware.cors import CORSMiddleware'));
  assert.ok(config.code.includes('app.add_middleware'));
});
