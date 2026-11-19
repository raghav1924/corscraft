/**
 * CORSCraft Zero-Config CORS Development Proxy
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import http from 'http';
import https from 'https';
import { URL } from 'url';

export interface ProxyOptions {
  port: number;
  target: string;
  allowOrigin?: string;
  allowCredentials?: boolean;
  onLog?: (msg: string) => void;
}

export function startCorsProxy(options: ProxyOptions): http.Server {
  const targetUrl = new URL(options.target);
  const isHttps = targetUrl.protocol === 'https:';
  const client = isHttps ? https : http;
  const logger = options.onLog || ((msg) => console.log(msg));

  const server = http.createServer((clientReq, clientRes) => {
    const rawOrigin = clientReq.headers['origin'];
    const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : (rawOrigin || '*');
    const effectiveOrigin = options.allowOrigin === '*' ? '*' : (options.allowOrigin || origin);

    const rawReqHeaders = clientReq.headers['access-control-request-headers'];
    const reqHeadersStr = Array.isArray(rawReqHeaders)
      ? rawReqHeaders.join(', ')
      : (rawReqHeaders || 'Content-Type, Authorization, X-Requested-With, X-Request-ID, Accept');

    const corsHeaders: Record<string, string> = {
      'Access-Control-Allow-Origin': effectiveOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD',
      'Access-Control-Allow-Headers': reqHeadersStr,
      'Access-Control-Expose-Headers': 'Content-Length, X-Request-ID, Retry-After',
      'Access-Control-Max-Age': '7200'
    };

    if (options.allowCredentials) {
      corsHeaders['Access-Control-Allow-Credentials'] = 'true';
      if (effectiveOrigin === '*') {
        corsHeaders['Access-Control-Allow-Origin'] = origin !== '*' ? origin : 'http://localhost:3000';
      }
    }

    // Handle OPTIONS Preflight
    if (clientReq.method === 'OPTIONS') {
      logger(`[PROXY PREFLIGHT] OPTIONS ${clientReq.url} -> 204 No Content`);
      clientRes.writeHead(204, corsHeaders);
      clientRes.end();
      return;
    }

    // Forward actual request to target
    const proxyHeaders = { ...clientReq.headers };
    proxyHeaders['host'] = targetUrl.host;

    const proxyReq = client.request(
      {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttps ? 443 : 80),
        method: clientReq.method,
        path: clientReq.url,
        headers: proxyHeaders
      },
      (targetRes: http.IncomingMessage) => {
        const outHeaders: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(targetRes.headers)) {
          if (!k.toLowerCase().startsWith('access-control-') && v !== undefined && v !== null) {
            outHeaders[k] = v as string | string[];
          }
        }

        // Inject verified CORS headers
        for (const [ck, cv] of Object.entries(corsHeaders)) {
          outHeaders[ck] = cv;
        }

        logger(`[PROXY FORWARD] ${clientReq.method} ${clientReq.url} -> ${targetRes.statusCode}`);
        clientRes.writeHead(targetRes.statusCode || 200, outHeaders);
        targetRes.pipe(clientRes);
      }
    );

    proxyReq.on('error', (err) => {
      logger(`[PROXY ERROR] ${err.message}`);
      clientRes.writeHead(502, {
        'Content-Type': 'application/json',
        ...corsHeaders
      });
      clientRes.end(JSON.stringify({
        error: 'CORSCraft Proxy Gateway Error',
        message: err.message,
        target: options.target
      }));
    });

    clientReq.pipe(proxyReq);
  });

  server.listen(options.port, () => {
    logger(`✔ CORSCraft Proxy active on http://localhost:${options.port} -> forwarding to ${options.target}`);
  });

  return server;
}
