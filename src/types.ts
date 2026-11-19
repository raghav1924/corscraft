/**
 * CORSCraft Type Definitions
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';

export type AuditGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface AuditIssue {
  code: string;
  title: string;
  description: string;
  severity: AuditSeverity;
  remediation: string;
  headersAffected: string[];
}

export interface CORSHeadersSummary {
  hasCORS: boolean;
  allowOrigin: string | null;
  allowCredentials: boolean;
  allowMethods: string[];
  allowHeaders: string[];
  exposeHeaders: string[];
  maxAge: number | null;
  hasVaryOrigin: boolean;
}

export interface SecurityHeaderAnalysis {
  name: string;
  present: boolean;
  value: string | null;
  valid: boolean;
  recommendation: string;
}

export interface AuditResult {
  target: string;
  timestamp: string;
  score: number;
  grade: AuditGrade;
  issues: AuditIssue[];
  headers: Record<string, string>;
  cors: CORSHeadersSummary;
  securityHeaders: Record<string, SecurityHeaderAnalysis>;
  recommendedHardenedHeaders: Record<string, string>;
}

export interface PreflightSimulationRequest {
  origin: string;
  targetUrl: string;
  method: string;
  requestHeaders?: string[];
  credentials?: boolean;
}

export interface HandshakeStep {
  step: number;
  actor: 'Browser' | 'Network' | 'Server';
  action: string;
  details: string;
  status: 'SUCCESS' | 'FAILED' | 'SKIPPED';
}

export interface PreflightSimulationResult {
  origin: string;
  targetUrl: string;
  method: string;
  preflightRequired: boolean;
  preflightPassed: boolean;
  actualRequestAllowed: boolean;
  browserConsoleError?: string;
  handshakeSteps: HandshakeStep[];
  responseHeaders: Record<string, string>;
}

export interface OriginMatrixTestItem {
  origin: string;
  category: 'Localhost' | 'Production' | 'Staging' | 'Wildcard' | 'Null / Sandboxed' | 'Untrusted / Attacker';
  isAllowed: boolean;
  credentialsSupported: boolean;
  risk: 'SAFE' | 'WARNING' | 'CRITICAL';
  statusDescription: string;
}

export interface OriginMatrixResult {
  targetUrl: string;
  results: OriginMatrixTestItem[];
  vulnerabilitiesDetected: string[];
}

export type FrameworkType = 'express' | 'nextjs' | 'fastify' | 'nginx' | 'cloudflare_workers' | 'fastapi';

export interface GeneratedConfig {
  framework: FrameworkType;
  title: string;
  filename: string;
  code: string;
  description: string;
}
