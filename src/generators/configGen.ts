/**
 * CORSCraft Multi-Framework Config Generator
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import { GeneratedConfig, FrameworkType } from '../types.js';

export interface GeneratorOptions {
  allowedOrigins?: string[];
  allowCredentials?: boolean;
  maxAge?: number;
}

export function generateFrameworkConfig(
  framework: FrameworkType,
  options: GeneratorOptions = {}
): GeneratedConfig {
  const origins = options.allowedOrigins?.length
    ? options.allowedOrigins
    : ['http://localhost:3000', 'https://app.example.com'];
  const creds = Boolean(options.allowCredentials);
  const maxAge = options.maxAge || 7200;

  switch (framework) {
    case 'express':
      return {
        framework: 'express',
        title: 'Express.js Hardened CORS & Helmet Middleware',
        filename: 'src/middleware/cors.ts',
        description: 'Production-ready Express middleware with strict origin whitelist validation and security headers.',
        code: `import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';

const ALLOWED_ORIGINS = new Set(${JSON.stringify(origins, null, 2)});

export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (e.g. server-to-server or curl)
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error(\`Origin \${origin} not allowed by CORS\`));
    }
  },
  credentials: ${creds},
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
  exposedHeaders: ['Content-Length', 'X-Request-ID', 'Retry-After'],
  maxAge: ${maxAge}
});

export const securityHeadersMiddleware = (req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; object-src 'none';");
  res.setHeader('Vary', 'Origin');
  next();
};
`
      };

    case 'nextjs':
      return {
        framework: 'nextjs',
        title: 'Next.js 14/15 Headers Configuration',
        filename: 'next.config.mjs',
        description: 'Global CORS and security headers configuration for Next.js App Router and API routes.',
        code: `/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Credentials', value: '${creds}' },
          { key: 'Access-Control-Allow-Origin', value: '${origins[0]}' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,POST,PUT,DELETE,PATCH,OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type, Authorization, X-Requested-With, X-Request-ID' },
          { key: 'Access-Control-Expose-Headers', value: 'Content-Length, X-Request-ID, Retry-After' },
          { key: 'Access-Control-Max-Age', value: '${maxAge}' },
          { key: 'Vary', value: 'Origin' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
        ]
      }
    ];
  }
};

export default nextConfig;
`
      };

    case 'fastify':
      return {
        framework: 'fastify',
        title: 'Fastify @fastify/cors Configuration',
        filename: 'src/plugins/cors.ts',
        description: 'High-performance Fastify plugin with dynamic origin lookup and preflight caching.',
        code: `import { FastifyPluginAsync } from 'fastify';
import fastifyCors from '@fastify/cors';

const ALLOWED_ORIGINS = new Set(${JSON.stringify(origins, null, 2)});

export const corsPlugin: FastifyPluginAsync = async (fastify) => {
  await fastify.register(fastifyCors, {
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.has(origin)) {
        cb(null, true);
        return;
      }
      cb(new Error('Cross-Origin Request Blocked'), false);
    },
    credentials: ${creds},
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
    exposedHeaders: ['Content-Length', 'X-Request-ID', 'Retry-After'],
    maxAge: ${maxAge},
    hook: 'preHandler'
  });
};
`
      };

    case 'nginx':
      return {
        framework: 'nginx',
        title: 'Nginx Whitelist & Preflight Directive',
        filename: 'cors.conf',
        description: 'Nginx map-based origin whitelist with OPTIONS preflight interceptor and CDN Vary caching.',
        code: `# Map allowed origins dynamically
map $http_origin $cors_origin {
  default "";
${origins.map(o => `  "${o}" "${o}";`).join('\n')}
}

server {
  listen 443 ssl http2;
  server_name api.example.com;

  location / {
    if ($request_method = 'OPTIONS') {
      add_header 'Access-Control-Allow-Origin' $cors_origin always;
      add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, PATCH, OPTIONS' always;
      add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization, X-Requested-With, X-Request-ID' always;
      add_header 'Access-Control-Allow-Credentials' '${creds}' always;
      add_header 'Access-Control-Max-Age' ${maxAge} always;
      add_header 'Content-Type' 'text/plain; charset=utf-8';
      add_header 'Content-Length' 0;
      return 204;
    }

    add_header 'Access-Control-Allow-Origin' $cors_origin always;
    add_header 'Access-Control-Allow-Credentials' '${creds}' always;
    add_header 'Access-Control-Expose-Headers' 'Content-Length, X-Request-ID, Retry-After' always;
    add_header 'Vary' 'Origin' always;
    add_header 'X-Content-Type-Options' 'nosniff' always;
    add_header 'X-Frame-Options' 'DENY' always;

    proxy_pass http://backend_upstream;
  }
}
`
      };

    case 'cloudflare_workers':
      return {
        framework: 'cloudflare_workers',
        title: 'Cloudflare Workers Edge CORS Handler',
        filename: 'worker.ts',
        description: 'Edge worker interceptor with instant OPTIONS preflight responses and zero-overhead origin validation.',
        code: `const ALLOWED_ORIGINS = new Set(${JSON.stringify(origins, null, 2)});

export default {
  async fetch(request: Request, env: any, ctx: any): Promise<Response> {
    const origin = request.headers.get('Origin') || '';
    const isAllowed = ALLOWED_ORIGINS.has(origin);

    const corsHeaders: Record<string, string> = {
      'Access-Control-Allow-Origin': isAllowed ? origin : '${origins[0]}',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Request-ID',
      'Access-Control-Expose-Headers': 'Content-Length, X-Request-ID, Retry-After',
      'Access-Control-Allow-Credentials': '${creds}',
      'Access-Control-Max-Age': '${maxAge}',
      'Vary': 'Origin'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const response = await fetch(request);
    const newHeaders = new Headers(response.headers);
    for (const [k, v] of Object.entries(corsHeaders)) {
      newHeaders.set(k, v);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
};
`
      };

    case 'fastapi':
      return {
        framework: 'fastapi',
        title: 'FastAPI (Python) CORSMiddleware',
        filename: 'main.py',
        description: 'Production FastAPI setup with typed CORS middleware and explicit header permissions.',
        code: `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Secure API")

origins = ${JSON.stringify(origins)}

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=${creds ? 'True' : 'False'},
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Request-ID"],
    expose_headers=["Content-Length", "X-Request-ID", "Retry-After"],
    max_age=${maxAge},
)
`
      };
  }
}
