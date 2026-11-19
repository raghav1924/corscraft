import { test } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import { startCorsProxy } from '../proxy/corsProxy.js';

test('startCorsProxy intercepts OPTIONS preflight and forwards requests', async () => {
  // 1. Start mock backend
  const backend = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Hello from Backend!' }));
  });

  await new Promise<void>((resolve) => backend.listen(8991, resolve));

  // 2. Start CORS Proxy
  const proxy = startCorsProxy({
    port: 8992,
    target: 'http://localhost:8991',
    onLog: () => {} // Silent
  });

  await new Promise<void>((resolve) => setTimeout(resolve, 150));

  // 3. Test OPTIONS preflight
  const optRes = await new Promise<{ statusCode?: number; headers: http.IncomingHttpHeaders }>((resolve) => {
    const req = http.request(
      'http://localhost:8992/test',
      { method: 'OPTIONS', headers: { Origin: 'http://localhost:3000' } },
      (res) => {
        resolve({ statusCode: res.statusCode, headers: res.headers });
      }
    );
    req.end();
  });

  assert.strictEqual(optRes.statusCode, 204);
  assert.strictEqual(optRes.headers['access-control-allow-origin'], 'http://localhost:3000');
  assert.ok(optRes.headers['access-control-allow-methods']);

  // 4. Test GET request forwarding
  const getRes = await new Promise<{ statusCode?: number; body: string; headers: http.IncomingHttpHeaders }>((resolve) => {
    const req = http.request(
      'http://localhost:8992/test',
      { method: 'GET', headers: { Origin: 'http://localhost:3000' } },
      (res) => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ statusCode: res.statusCode, body: b, headers: res.headers }));
      }
    );
    req.end();
  });

  assert.strictEqual(getRes.statusCode, 200);
  assert.strictEqual(getRes.headers['access-control-allow-origin'], 'http://localhost:3000');
  const data = JSON.parse(getRes.body);
  assert.strictEqual(data.message, 'Hello from Backend!');

  // Cleanup
  proxy.close();
  backend.close();
});
