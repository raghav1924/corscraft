/**
 * CORSCraft Preflight & Browser Handshake Simulator
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import {
  PreflightSimulationRequest,
  PreflightSimulationResult,
  HandshakeStep
} from '../types.js';

const SIMPLE_METHODS = new Set(['GET', 'HEAD', 'POST']);
const SIMPLE_HEADERS = new Set(['accept', 'accept-language', 'content-language']);
const SIMPLE_CONTENT_TYPES = new Set([
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain'
]);

export function isPreflightRequired(
  method: string,
  headers: string[] = [],
  contentType?: string
): { required: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const upperMethod = method.toUpperCase();

  if (!SIMPLE_METHODS.has(upperMethod)) {
    reasons.push(`Method "${upperMethod}" is non-simple`);
  }

  for (const h of headers) {
    const lower = h.toLowerCase().trim();
    if (lower === 'content-type' && contentType) {
      const ctLower = contentType.toLowerCase().split(';')[0].trim();
      if (!SIMPLE_CONTENT_TYPES.has(ctLower)) {
        reasons.push(`Content-Type "${contentType}" is non-simple`);
      }
    } else if (!SIMPLE_HEADERS.has(lower)) {
      reasons.push(`Header "${h}" is non-simple`);
    }
  }

  return {
    required: reasons.length > 0,
    reasons
  };
}

export function simulatePreflightHandshake(
  req: PreflightSimulationRequest,
  serverHeaders: Record<string, string>,
  serverStatusCode: number = 204
): PreflightSimulationResult {
  const steps: HandshakeStep[] = [];
  let stepCount = 1;

  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(serverHeaders)) {
    h[k.toLowerCase()] = v;
  }

  const requestedMethod = req.method.toUpperCase();
  const requestedHeaders = req.requestHeaders ?? ['Content-Type'];
  const credentials = Boolean(req.credentials);

  const preflightCheck = isPreflightRequired(requestedMethod, requestedHeaders);
  const preflightRequired = preflightCheck.required;

  let preflightPassed = true;
  let actualRequestAllowed = true;
  let browserConsoleError: string | undefined;

  // Step 1: Client initiate
  steps.push({
    step: stepCount++,
    actor: 'Browser',
    action: 'Initiate Cross-Origin Fetch',
    details: `Client script on origin "${req.origin}" executes fetch("${req.targetUrl}", { method: "${requestedMethod}", credentials: "${credentials ? 'include' : 'same-origin'}" })`,
    status: 'SUCCESS'
  });

  // Step 2: Preflight determination
  if (preflightRequired) {
    steps.push({
      step: stepCount++,
      actor: 'Browser',
      action: 'Determine Preflight Requirement',
      details: `Preflight OPTIONS request required: ${preflightCheck.reasons.join(', ')}`,
      status: 'SUCCESS'
    });

    // Step 3: Send OPTIONS request
    steps.push({
      step: stepCount++,
      actor: 'Network',
      action: 'Dispatch OPTIONS Preflight Handshake',
      details: `OPTIONS ${req.targetUrl} HTTP/1.1 | Origin: ${req.origin} | Access-Control-Request-Method: ${requestedMethod} | Access-Control-Request-Headers: ${requestedHeaders.join(', ')}`,
      status: 'SUCCESS'
    });

    // Step 4: Evaluate Preflight Response Status
    if (serverStatusCode < 200 || serverStatusCode >= 300) {
      preflightPassed = false;
      actualRequestAllowed = false;
      browserConsoleError = `Response to preflight request doesn't pass access control check: It does not have HTTP ok status (${serverStatusCode}).`;
      steps.push({
        step: stepCount++,
        actor: 'Server',
        action: 'Preflight Response Status Code Failure',
        details: `Server returned HTTP ${serverStatusCode}. Browser requires 200-299 for preflight success.`,
        status: 'FAILED'
      });
    } else {
      steps.push({
        step: stepCount++,
        actor: 'Server',
        action: 'Preflight Response Received',
        details: `Server returned HTTP ${serverStatusCode} OK.`,
        status: 'SUCCESS'
      });
    }

    // Step 5: Validate Access-Control-Allow-Origin
    const allowOrigin = h['access-control-allow-origin']?.trim();
    const allowCreds = h['access-control-allow-credentials']?.trim().toLowerCase() === 'true';

    if (!allowOrigin) {
      preflightPassed = false;
      actualRequestAllowed = false;
      browserConsoleError = `Access to fetch at '${req.targetUrl}' from origin '${req.origin}' has been blocked by CORS policy: Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.`;
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Origin Header Verification Failed',
        details: 'No Access-Control-Allow-Origin header in server response.',
        status: 'FAILED'
      });
    } else if (allowOrigin === '*' && credentials) {
      preflightPassed = false;
      actualRequestAllowed = false;
      browserConsoleError = `Access to fetch at '${req.targetUrl}' from origin '${req.origin}' has been blocked by CORS policy: The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.`;
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Illegal Wildcard + Credentials Trap',
        details: 'Wildcard "*" origin cannot be combined with credentials mode "include".',
        status: 'FAILED'
      });
    } else if (allowOrigin !== '*' && allowOrigin !== req.origin) {
      preflightPassed = false;
      actualRequestAllowed = false;
      browserConsoleError = `Access to fetch at '${req.targetUrl}' from origin '${req.origin}' has been blocked by CORS policy: The 'Access-Control-Allow-Origin' header has a value '${allowOrigin}' that is not equal to the supplied origin.`;
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Origin Mismatch',
        details: `Server allowed "${allowOrigin}", but requesting origin was "${req.origin}".`,
        status: 'FAILED'
      });
    } else {
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Origin Verification Succeeded',
        details: `Origin "${req.origin}" matches Access-Control-Allow-Origin: ${allowOrigin}`,
        status: 'SUCCESS'
      });
    }

    // Step 6: Validate Access-Control-Allow-Methods
    const allowedMethods = (h['access-control-allow-methods'] ?? '')
      .split(',')
      .map((s) => s.trim().toUpperCase());
    if (preflightPassed && !allowedMethods.includes(requestedMethod) && !allowedMethods.includes('*')) {
      preflightPassed = false;
      actualRequestAllowed = false;
      browserConsoleError = `Access to fetch at '${req.targetUrl}' from origin '${req.origin}' has been blocked by CORS policy: Method ${requestedMethod} is not allowed by Access-Control-Allow-Methods in preflight response.`;
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Method Disallowed in Preflight',
        details: `Method "${requestedMethod}" missing from Access-Control-Allow-Methods (${allowedMethods.join(', ') || 'none'}).`,
        status: 'FAILED'
      });
    } else if (preflightPassed) {
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Method Verification Succeeded',
        details: `Method "${requestedMethod}" permitted by server.`,
        status: 'SUCCESS'
      });
    }

    // Step 7: Validate Access-Control-Allow-Headers
    const allowedHeaders = (h['access-control-allow-headers'] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase());
    const missingHeaders: string[] = [];

    if (preflightPassed && !allowedHeaders.includes('*')) {
      for (const reqH of requestedHeaders) {
        const lowerH = reqH.toLowerCase().trim();
        if (!SIMPLE_HEADERS.has(lowerH) && !allowedHeaders.includes(lowerH)) {
          missingHeaders.push(reqH);
        }
      }
    }

    if (preflightPassed && missingHeaders.length > 0) {
      preflightPassed = false;
      actualRequestAllowed = false;
      browserConsoleError = `Access to fetch at '${req.targetUrl}' from origin '${req.origin}' has been blocked by CORS policy: Request header field ${missingHeaders[0]} is not allowed by Access-Control-Allow-Headers in preflight response.`;
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Headers Disallowed in Preflight',
        details: `Headers not permitted: ${missingHeaders.join(', ')}`,
        status: 'FAILED'
      });
    } else if (preflightPassed) {
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Headers Verification Succeeded',
        details: `All non-simple headers (${requestedHeaders.join(', ')}) authorized.`,
        status: 'SUCCESS'
      });
    }
  } else {
    // Simple Request (No Preflight)
    steps.push({
      step: stepCount++,
      actor: 'Browser',
      action: 'Simple Request Assessment',
      details: 'Request uses simple method and headers. No OPTIONS preflight required; proceeding directly to actual request.',
      status: 'SKIPPED'
    });

    // Check simple response origin
    const allowOrigin = h['access-control-allow-origin']?.trim();
    if (!allowOrigin) {
      actualRequestAllowed = false;
      browserConsoleError = `Access to fetch at '${req.targetUrl}' from origin '${req.origin}' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.`;
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Response Origin Check Failed',
        details: 'No Access-Control-Allow-Origin emitted in actual response.',
        status: 'FAILED'
      });
    } else {
      steps.push({
        step: stepCount++,
        actor: 'Browser',
        action: 'Response Origin Check Succeeded',
        details: `Access-Control-Allow-Origin "${allowOrigin}" accepted.`,
        status: 'SUCCESS'
      });
    }
  }

  // Final step: Actual request delivery
  if (actualRequestAllowed) {
    steps.push({
      step: stepCount++,
      actor: 'Browser',
      action: 'Dispatch Actual Request',
      details: `${requestedMethod} ${req.targetUrl} executed successfully. Response payload readable by JavaScript client.`,
      status: 'SUCCESS'
    });
  } else {
    steps.push({
      step: stepCount++,
      actor: 'Browser',
      action: 'Request Blocked by Security Sandbox',
      details: 'Client execution aborted. TypeError: Failed to fetch thrown to JavaScript caller.',
      status: 'FAILED'
    });
  }

  return {
    origin: req.origin,
    targetUrl: req.targetUrl,
    method: requestedMethod,
    preflightRequired,
    preflightPassed,
    actualRequestAllowed,
    browserConsoleError,
    handshakeSteps: steps,
    responseHeaders: serverHeaders
  };
}
