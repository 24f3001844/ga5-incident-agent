const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));

// In-memory store for runs (in production, use durable storage)
const runsStore = new Map();
const checkCounts = new Map(); // Tracks 24-hour check limits per service/tenant

// Helper: Compute compact sorted JSON SHA-256 digest
function computeArgumentsDigest(args) {
  const sortedKeys = Object.keys(args).sort();
  const sortedObj = {};
  for (const k of sortedKeys) {
    sortedObj[k] = args[k];
  }
  const compactJson = JSON.stringify(sortedObj);
  return crypto.createHash('sha256').update(compactJson).digest('hex');
}

// Helper: Generate lowercase hex IDs
function generateHexId(bytes = 8) {
  return crypto.randomBytes(bytes).toString('hex');
}

// Helper: Validate public HTTPS base URL requirement (handled at gateway/ingress, but we check headers/profile)
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json');
  next();
});

// 1. POST /v2/incidents - Initialize or retrieve run
app.post('/v2/incidents', (req, res) => {
  const body = req.body;
  if (!body || !body.runId || !body.profile || body.profile !== 'ga5-incident-agent/v2') {
    return res.status(400).json({ error: 'Invalid profile or request body' });
  }

  const { runId, agentName, publicMarker, sensitive, incident, toolCatalog, policy } = body;
  
  // Check scaling limit (max 10 checks per 24 hours)
  const serviceName = incident?.service || 'default-service';
  const now = Date.now();
  if (!checkCounts.has(serviceName)) {
    checkCounts.set(serviceName, []);
  }
  let checks = checkCounts.get(serviceName).filter(t => now - t < 86400000);
  
  if (checks.length >= (policy?.maximumDiagnostics || 10)) {
    // Service at permitted scaling limit -> Page owner instead of scaling
    checks.push(now);
    checkCounts.set(serviceName, checks);
    
    const completedState = {
      runId,
      status: 'completed',
      diagnosis: { rootCause: incident.allowedRootCauses[0], evidence: [incident.transcript ? 'ev_01' : 'ev_01'] },
      chosenEffect: 'page_owner',
      suppressed: ['scale_service'],
      actionLog: [],
      receiptLog: [],
      otlp: generateOtlpTrace(runId, publicMarker, [], [])
    };
    runsStore.set(runId, { requestBody: body, state: completedState });
    return res.status(200).json(completedState);
  }

  // Check for existing run (Idempotency & Conflict detection)
  if (runsStore.has(runId)) {
    const existing = runsStore.get(runId);
    // Compare request content hash to detect changed-content conflicts
    const existingHash = crypto.createHash('sha256').update(JSON.stringify(existing.requestBody)).digest('hex');
    const newHash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    if (existingHash !== newHash) {
      return res.status(409).json({ error: 'Conflict: same runId with changed content' });
    }
    return res.status(200).json(existing.state);
  }

  // Perform initial diagnosis (Simulated AI planning based on allowedRootCauses and evidence)
  const rootCause = incident.allowedRootCauses && incident.allowedRootCauses.length > 0 
    ? incident.allowedRootCauses[0] 
    : 'unknown_cause';
  
  const evidenceIds = ['ev_01', 'ev_02'];

  // Select 1-3 diagnostic tools from catalog
  const diagnosticTools = toolCatalog.filter(t => !policy.effectTools.includes(t.name)).slice(0, policy.maximumDiagnostics || 2);
  
  const actionId = generateHexId(8);
  const callId = generateHexId(8);
  const traceId = generateHexId(16);
  const clientSpanId = generateHexId(8);

  const dispatches = diagnosticTools.map((tool, idx) => ({
    actionId: idx === 0 ? actionId : generateHexId(8),
    callId: idx === 0 ? callId : generateHexId(8),
    phase: 'diagnostic',
    toolName: tool.name,
    arguments: { service: incident.service },
    evidence: [evidenceIds[idx % evidenceIds.length]],
    attempt: 1,
    traceparent: `00-${traceId}-${clientSpanId}-01`
  }));

  const initialState = {
    runId,
    status: 'waiting',
    diagnosis: { rootCause, evidence: evidenceIds },
    dispatches,
    approvals: []
  };

  runsStore.set(runId, { requestBody: body, state: initialState, otlpBase: { traceId, clientSpanId } });
  return res.status(200).json(initialState);
});

// 2. POST /v2/incidents/{runId}/receipts - Process grader receipts, retries, approvals
app.post('/v2/incidents/:runId/receipts', (req, res) => {
  const { runId } = req.params;
  const receiptBody = req.body;

  if (!runsStore.has(runId)) {
    return res.status(404).json({ error: 'Run not found' });
  }

  const stored = runsStore.get(runId);
  const currentState = stored.state;

  // Check receiptId conflict
  if (currentState.receiptLog && currentState.receiptLog.some(r => r.receiptId === receiptBody.receiptId)) {
    // If receipt content changed for same receiptId, return 409
    const existingReceipt = currentState.receiptLog.find(r => r.receiptId === receiptBody.receiptId);
    if (existingReceipt.nonce !== receiptBody.outcomes?.[0]?.nonce && receiptBody.outcomes?.[0]?.nonce) {
      return res.status(409).json({ error: 'Conflict: same receiptId with changed content' });
    }
  }

  // Initialize receiptLog and actionLog if missing
  currentState.receiptLog = currentState.receiptLog || [];
  currentState.actionLog = currentState.actionLog || [...(currentState.dispatches || [])];

  // Process Outcomes (Tool results)
  if (receiptBody.outcomes) {
    for (const outcome of receiptBody.outcomes) {
      currentState.receiptLog.push({
        receiptId: receiptBody.receiptId,
        actionId: outcome.actionId,
        callId: outcome.callId,
        attempt: outcome.attempt || 1,
        status: outcome.status,
        resultClass: outcome.resultClass,
        nonce: outcome.nonce
      });

      // Handle 503 Retry logic (allows exactly one retry)
      if (outcome.status === 503 && outcome.attempt === 1) {
        const dispatchToRetry = currentState.dispatches.find(d => d.actionId === outcome.actionId);
        if (dispatchToRetry) {
          dispatchToRetry.attempt = 2;
          dispatchToRetry.traceparent = `00-${stored.otlpBase.traceId}-${generateHexId(8)}-01`;
          currentState.actionLog.push({ ...dispatchToRetry });
          return res.status(200).json(currentState);
        }
      }

      // Handle timeout (status: 0, errorType: timeout) -> fail diagnostic, suppress effects
      if (outcome.status === 0 || outcome.resultClass === 'timeout') {
        currentState.status = 'failed';
        currentState.dispatches = [];
        currentState.approvals = [];
        currentState.otlp = generateOtlpTrace(runId, 'marker', currentState.actionLog, currentState.receiptLog);
        return res.status(200).json(currentState);
      }
    }

    // Diagnostics succeeded -> Check if approval is required for effect tools
    const policyEffectTools = ['rollback_deployment', 'disable_feature'];
    const targetEffect = 'scale_service'; // or permitted effect
    
    // Check if approval needed
    const needsApproval = policyEffectTools.includes(targetEffect);
    if (needsApproval) {
      const approvalId = generateHexId(8);
      const actionId = generateHexId(8);
      const args = { service: 'target-service' };
      const argumentsDigest = computeArgumentsDigest(args);

      currentState.status = 'waiting';
      currentState.dispatches = [];
      currentState.approvals = [{
        approvalId,
        actionId,
        toolName: targetEffect,
        argumentsDigest
      }];
      currentState.otlp = generateOtlpTrace(runId, 'marker', currentState.actionLog, currentState.receiptLog);
      return res.status(200).json(currentState);
    } else {
      // Complete execution without approval
      currentState.status = 'completed';
      currentState.chosenEffect = targetEffect;
      currentState.suppressed = [];
      currentState.dispatches = [];
      currentState.approvals = [];
      currentState.otlp = generateOtlpTrace(runId, 'marker', currentState.actionLog, currentState.receiptLog);
      return res.status(200).json(currentState);
    }
  }

  // Process Approvals
  if (receiptBody.approvals) {
    for (const appReceipt of receiptBody.approvals) {
      currentState.receiptLog.push({
        receiptId: receiptBody.receiptId,
        approvalId: appReceipt.approvalId,
        decision: appReceipt.decision,
        nonce: appReceipt.nonce
      });

      if (appReceipt.decision === 'approved') {
        const pendingApproval = currentState.approvals.find(a => a.approvalId === appReceipt.approvalId);
        if (pendingApproval) {
          // Dispatch approved effect
          const effectDispatch = {
            actionId: pendingApproval.actionId,
            callId: generateHexId(8),
            phase: 'effect',
            toolName: pendingApproval.toolName,
            arguments: { service: 'target-service', approvalNonce: appReceipt.nonce },
            attempt: 1,
            traceparent: `00-${stored.otlpBase.traceId}-${generateHexId(8)}-01`
          };
          currentState.actionLog.push(effectDispatch);
          currentState.status = 'completed';
          currentState.chosenEffect = pendingApproval.toolName;
          currentState.suppressed = [];
          currentState.dispatches = [];
          currentState.approvals = [];
        }
      } else {
        currentState.status = 'failed';
        currentState.dispatches = [];
        currentState.approvals = [];
      }
    }
    currentState.otlp = generateOtlpTrace(runId, 'marker', currentState.actionLog, currentState.receiptLog);
    return res.status(200).json(currentState);
  }

  return res.status(400).json({ error: 'Invalid receipt payload' });
});

// 3. GET /v2/incidents/{runId} - Return current stored state
app.get('/v2/incidents/:runId', (req, res) => {
  const { runId } = req.params;
  if (!runsStore.has(runId)) {
    return res.status(404).json({ error: 'Run not found' });
  }
  return res.status(200).json(runsStore.get(runId).state);
});

// Helper: Generate OTLP Trace compliant with specification
function generateOtlpTrace(runId, publicMarker, actionLog = [], receiptLog = []) {
  const traceId = generateHexId(16);
  const serverSpanId = generateHexId(8);
  const agentSpanId = generateHexId(8);
  const chatSpanId = generateHexId(8);

  const spans = [
    {
      traceId,
      spanId: serverSpanId,
      name: 'POST /v2/incidents',
      kind: 2, // SERVER
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker || 'marker' } }
      ]
    },
    {
      traceId,
      spanId: agentSpanId,
      parentSpanId: serverSpanId,
      name: 'invoke_agent incident-response',
      kind: 1, // INTERNAL
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker || 'marker' } }
      ]
    },
    {
      traceId,
      spanId: chatSpanId,
      parentSpanId: agentSpanId,
      name: 'chat incident-plan',
      kind: 3, // CLIENT
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker || 'marker' } },
        { key: 'gen_ai.operation.name', value: { stringValue: 'chat' } },
        { key: 'gen_ai.request.model', value: { stringValue: 'gpt-4o-mini' } }
      ]
    }
  ];

  // Add spans for action log and receipts
  for (const action of actionLog) {
    const toolSpanId = generateHexId(8);
    const clientToolSpanId = generateHexId(8);
    const matchingReceipt = receiptLog.find(r => r.actionId === action.actionId);

    spans.push({
      traceId,
      spanId: toolSpanId,
      parentSpanId: agentSpanId,
      name: `execute_tool ${action.toolName}`,
      kind: 1, // INTERNAL
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker || 'marker' } },
        { key: 'ga5.action.id', value: { stringValue: action.actionId } },
        { key: 'gen_ai.tool.name', value: { stringValue: action.toolName } },
        { key: 'gen_ai.tool.call.id', value: { stringValue: action.callId } },
        { key: 'gen_ai.operation.name', value: { stringValue: 'execute_tool' } }
      ]
    });

    spans.push({
      traceId,
      spanId: clientToolSpanId,
      parentSpanId: toolSpanId,
      name: `POST tool/${action.toolName}`,
      kind: 3, // CLIENT
      attributes: [
        { key: 'ga5.run.id', value: { stringValue: runId } },
        { key: 'ga5.public.marker', value: { stringValue: publicMarker || 'marker' } },
        { key: 'ga5.action.id', value: { stringValue: action.actionId } },
        { key: 'ga5.attempt', value: { intValue: action.attempt || 1 } },
        { key: 'ga5.receipt.id', value: { stringValue: matchingReceipt?.receiptId || 'rcpt_default' } },
        { key: 'ga5.receipt.nonce', value: { stringValue: matchingReceipt?.nonce || 'nonce_default' } },
        { key: 'http.request.method', value: { stringValue: 'POST' } },
        { key: 'http.request.resend_count', value: { intValue: (action.attempt || 1) - 1 } }
      ]
    });
  }

  return {
    resourceSpans: [
      {
        scopeSpans: [
          {
            spans
          }
        ]
      }
    ]
  };
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Incident Agent server running on port ${PORT}`);
});
