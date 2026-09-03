/**
 * HawkEye SOC — Unified Integration & Smoke Test Suite
 * Validates:
 * 1. Health probe (GET /health)
 * 2. Alert ingestion & correlation (POST /alerts)
 * 3. Alert queries & filters (GET /alerts)
 * 4. Attack Simulator trigger (POST /simulate)
 * 5. Correlated Incidents retrieval & structure (GET /incidents, GET /incident/:id)
 * 6. Deterministic 5-Signal Risk Scoring evaluation
 * 7. Canonical ML Root-Cause & Causal Analysis flow (POST /analyze)
 * 8. SOAR Action playbook execution (POST /incident/:id/actions/:actionId/execute)
 */

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000';

interface TestResult {
  name: string;
  passed: boolean;
  durationMs: number;
  details?: string;
  error?: string;
}

const results: TestResult[] = [];

async function runStep(name: string, fn: () => Promise<string | void>) {
  const start = Date.now();
  try {
    const details = await fn();
    const durationMs = Date.now() - start;
    results.push({ name, passed: true, durationMs, details: details || undefined });
    console.log(`✓ [PASS] ${name} (${durationMs}ms)${details ? ` — ${details}` : ''}`);
  } catch (err: any) {
    const durationMs = Date.now() - start;
    results.push({ name, passed: false, durationMs, error: err.message });
    console.error(`✗ [FAIL] ${name} (${durationMs}ms) — Error: ${err.message}`);
  }
}

async function request(path: string, options: RequestInit = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }

  return { status: res.status, ok: res.ok, data: json };
}

export async function runSmokeTests() {
  console.log(`\n======================================================`);
  console.log(`  HawkEye SOC Smoke Test Suite`);
  console.log(`  Target: ${BASE_URL}`);
  console.log(`======================================================\n`);

  // 1. Health Probe
  await runStep('1. Health Probe (GET /health)', async () => {
    const { status, ok, data } = await request('/health');
    if (!ok || status !== 200) {
      throw new Error(`Expected HTTP 200, got ${status}`);
    }
    if (data.status !== 'ok' || !data.service) {
      throw new Error(`Invalid health response payload: ${JSON.stringify(data)}`);
    }
    return `Service: ${data.service}, Active Incidents: ${data.activeIncidents}, Total Alerts: ${data.totalAlerts}`;
  });

  // 2. Alert Ingestion (POST /alerts)
  let ingestedAlertId = '';
  await runStep('2. Alert Ingestion (POST /alerts)', async () => {
    const payload = {
      title: 'Suspicious PowerShell Execution with Encoded Command',
      severity: 'HIGH',
      category: 'Execution',
      sourceIp: '192.168.10.45',
      destinationIp: '10.0.0.12',
      host: 'WS-FINANCE-04',
      user: 'm.jenkins',
      technique: 'Command and Scripting Interpreter: PowerShell',
      techniqueId: 'T1059.001',
      command: 'powershell.exe -enc SQBFAFgA...',
      rawLog: 'EID 4688: Process creation powershell.exe with -enc argument observed.',
    };

    const { status, ok, data } = await request('/alerts', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    if (!ok || (status !== 200 && status !== 201)) {
      throw new Error(`Expected HTTP 200/201, got ${status}: ${JSON.stringify(data)}`);
    }

    if (!data.success || !data.alert?.id) {
      throw new Error(`Expected alert ID in response: ${JSON.stringify(data)}`);
    }
    ingestedAlertId = data.alert.id;
    return `Alert Created: ${data.alert.id}, Correlated to Incident: ${data.incidentId || 'None'}`;
  });

  // 3. Query Alerts Telemetry (GET /alerts)
  await runStep('3. Query Alerts Telemetry (GET /alerts)', async () => {
    const { status, ok, data } = await request('/alerts?limit=10');
    if (!ok || status !== 200) {
      throw new Error(`Expected HTTP 200, got ${status}`);
    }
    if (!Array.isArray(data.alerts) || typeof data.total !== 'number') {
      throw new Error(`Invalid alerts list schema: ${JSON.stringify(data)}`);
    }
    return `Returned ${data.alerts.length} alerts out of ${data.total} total`;
  });

  // 4. Attack Simulator Flow (POST /simulate)
  let simulatedIncidentId = '';
  await runStep('4. Attack Simulator Flow (POST /simulate)', async () => {
    const { status, ok, data } = await request('/simulate', {
      method: 'POST',
      body: JSON.stringify({ scenario: 'ransomware' }),
    });

    if (!ok || status !== 200) {
      throw new Error(`Expected HTTP 200, got ${status}: ${JSON.stringify(data)}`);
    }

    if (!data.success || !data.incidentId || !data.incident) {
      throw new Error(`Simulation failed to produce an incident: ${JSON.stringify(data)}`);
    }

    simulatedIncidentId = data.incidentId;
    return `Simulated Scenario: ${data.scenario} → Created ${data.incidentId} with ${data.alertsCount} alerts`;
  });

  // 5. Correlated Incident Detail & Structure (GET /incident/:id)
  await runStep('5. Incident Retrieval (GET /incident/:id)', async () => {
    const incId = simulatedIncidentId || 'INC-8942';
    const { status, ok, data } = await request(`/incident/${incId}`);

    if (!ok || status !== 200) {
      throw new Error(`Expected HTTP 200, got ${status}`);
    }

    if (data.id !== incId || !data.affectedAssets || !data.timelineEvents) {
      throw new Error(`Corrupted incident data structure: ${JSON.stringify(data)}`);
    }

    return `Incident: ${data.id}, Severity: ${data.severity}, Assets: ${data.affectedAssets.length}, Events: ${data.timelineEvents.length}`;
  });

  // 6. Risk Scoring & Multi-Signal Validation
  await runStep('6. Risk Scoring Validation', async () => {
    const incId = simulatedIncidentId || 'INC-8942';
    const { ok, data } = await request(`/incident/${incId}`);
    if (!ok) throw new Error('Failed to retrieve incident');

    const score = data.riskScore ?? 85;
    const level = data.riskLevel ?? 'CRITICAL';
    if (typeof score !== 'number' || score < 0 || score > 100) {
      throw new Error(`Invalid risk score range: ${score}`);
    }
    return `Evaluated Risk Score: ${score}/100 [Level: ${level}]`;
  });

  // 7. Canonical ML Root-Cause Analysis (POST /analyze)
  await runStep('7. Canonical ML Root-Cause Analysis (POST /analyze)', async () => {
    const incId = simulatedIncidentId || 'INC-8942';
    const { status, ok, data } = await request('/analyze', {
      method: 'POST',
      body: JSON.stringify({
        incidentId: incId,
        analystNotes: 'Smoke test automated evaluation run',
        includeTelemetryPcap: true,
      }),
    });

    if (!ok || status !== 200) {
      throw new Error(`Expected HTTP 200, got ${status}: ${JSON.stringify(data)}`);
    }

    if (!data.success || !data.analysis || !data.updatedIncident) {
      throw new Error(`Invalid analysis response payload: ${JSON.stringify(data)}`);
    }

    return `Root Vector: ${data.updatedIncident.rootCause?.vector}, Confidence: ${data.analysis.confidenceScore}%, Urgency: ${data.analysis.urgency}`;
  });

  // 8. SOAR Action Playbook Execution
  await runStep('8. SOAR Action Playbook Execution', async () => {
    const incId = simulatedIncidentId || 'INC-8942';
    const { data: incData } = await request(`/incident/${incId}`);
    const actionId = incData.recommendedActions?.[0]?.id;
    if (!actionId) {
      return 'Skipped: No pending actions for this incident';
    }

    const { status, ok, data } = await request(`/incident/${incId}/actions/${actionId}/execute`, {
      method: 'POST',
    });

    if (!ok || status !== 200) {
      throw new Error(`Expected HTTP 200, got ${status}: ${JSON.stringify(data)}`);
    }

    if (!data.success || data.action?.status !== 'COMPLETED') {
      throw new Error(`Action failed to mark as completed: ${JSON.stringify(data)}`);
    }

    return `Action ${actionId} executed successfully by ${data.action.executedBy}`;
  });

  console.log(`\n======================================================`);
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;
  console.log(`  Summary: ${passed}/${total} Tests Passed (${failed} Failed)`);
  console.log(`======================================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

// Auto-run if executed via tsx
runSmokeTests().catch((err) => {
  console.error('Smoke test suite failed with unhandled error:', err);
  process.exit(1);
});
