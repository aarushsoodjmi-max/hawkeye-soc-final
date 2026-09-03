import {
  Alert,
  Incident,
  KpiMetrics,
  RestApiLog,
  AiAnalysisResult,
  RecommendedAction,
  Severity,
  AlertStatus,
  IncidentStatus,
} from '../types';

// Real REST API transaction logger for the dashboard inspector
type ApiListener = (log: RestApiLog) => void;
const apiListeners: Set<ApiListener> = new Set();

export function subscribeToApiLogs(listener: ApiListener) {
  apiListeners.add(listener);
  return () => {
    apiListeners.delete(listener);
  };
}

function broadcastApiLog(log: RestApiLog) {
  apiListeners.forEach((fn) => fn(log));
}

// Relative path routes straight to backend in dev & preview
const API_BASE = '';

/**
 * Helper to log and execute real fetch calls
 */
async function fetchWithLogs<T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  endpoint: string,
  body?: any
): Promise<T> {
  const start = performance.now();
  const url = `${API_BASE}${endpoint}`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  let status = 0;
  let responseData: any = null;

  try {
    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    status = res.status;
    const text = await res.text();
    try {
      responseData = text ? JSON.parse(text) : {};
    } catch {
      responseData = { raw: text };
    }

    const duration = Math.max(1, Math.round(performance.now() - start));

    broadcastApiLog({
      id: `REQ-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      method,
      endpoint,
      status,
      latencyMs: duration,
      timestamp: new Date().toLocaleTimeString(),
      requestBody: body,
      responsePreview: responseData,
    });

    if (!res.ok) {
      const errDetail = responseData?.detail || responseData?.message || `HTTP ${status}`;
      throw new Error(errDetail);
    }

    return responseData as T;
  } catch (error: any) {
    const duration = Math.max(1, Math.round(performance.now() - start));
    if (status === 0) {
      broadcastApiLog({
        id: `REQ-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        method,
        endpoint,
        status: 503,
        latencyMs: duration,
        timestamp: new Date().toLocaleTimeString(),
        requestBody: body,
        responsePreview: { error: error.message },
      });
    }
    throw error;
  }
}

/**
 * HawkEye SOC Real REST Client connected directly to FastAPI Backend
 */
export const socApi = {
  /**
   * GET /alerts
   */
  async getAlerts(params?: {
    severity?: Severity | 'ALL';
    status?: AlertStatus | 'ALL';
    search?: string;
    incidentId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ alerts: Alert[]; total: number; timestamp: string }> {
    const searchParams = new URLSearchParams();
    if (params?.severity && params.severity !== 'ALL') {
      searchParams.set('severity', params.severity);
    }
    if (params?.status && params.status !== 'ALL') {
      searchParams.set('status', params.status);
    }
    if (params?.incidentId) {
      searchParams.set('incidentId', params.incidentId);
    }
    if (params?.search) {
      searchParams.set('search', params.search);
    }
    if (params?.limit) {
      searchParams.set('limit', String(params.limit));
    }
    if (params?.offset) {
      searchParams.set('offset', String(params.offset));
    }

    const queryString = searchParams.toString();
    const endpoint = `/alerts${queryString ? `?${queryString}` : ''}`;

    return await fetchWithLogs<{ alerts: Alert[]; total: number; timestamp: string }>(
      'GET',
      endpoint
    );
  },

  /**
   * GET /alerts/:id
   */
  async getAlertById(alertId: string): Promise<Alert> {
    return await fetchWithLogs<Alert>('GET', `/alerts/${alertId}`);
  },

  /**
   * Ingest Single Alert
   * POST /alerts
   */
  async ingestAlert(alertData: Partial<Alert>): Promise<{
    success: boolean;
    message: string;
    alert: Alert;
    correlatedIncidentId?: string;
    incidentId?: string;
  }> {
    return await fetchWithLogs<{
      success: boolean;
      message: string;
      alert: Alert;
      correlatedIncidentId?: string;
      incidentId?: string;
    }>('POST', '/alerts', alertData);
  },

  /**
   * GET /incidents
   */
  async getIncidents(): Promise<{ incidents: Incident[]; kpis: KpiMetrics; timestamp: string }> {
    return await fetchWithLogs<{ incidents: Incident[]; kpis: KpiMetrics; timestamp: string }>(
      'GET',
      '/incidents'
    );
  },

  /**
   * GET /incident/:id
   */
  async getIncidentById(id: string): Promise<Incident | null> {
    return await fetchWithLogs<Incident>('GET', `/incident/${id}`);
  },

  /**
   * POST /analyze
   */
  async analyzeIncident(payload: {
    incidentId: string;
    analystNotes?: string;
    includeTelemetryPcap?: boolean;
  }): Promise<{ success: boolean; analysis: AiAnalysisResult; updatedIncident: Incident }> {
    return await fetchWithLogs<{ success: boolean; analysis: AiAnalysisResult; updatedIncident: Incident }>(
      'POST',
      '/analyze',
      payload
    );
  },

  /**
   * Action Execution (SOAR trigger)
   * POST /incident/:incidentId/actions/:actionId/execute
   */
  async executeAction(incidentId: string, actionId: string): Promise<RecommendedAction> {
    const res = await fetchWithLogs<{ success: boolean; message: string; action: RecommendedAction }>(
      'POST',
      `/incident/${incidentId}/actions/${actionId}/execute`
    );
    return res.action;
  },

  /**
   * Toggle Asset Isolation
   * POST /incident/:incidentId/assets/:assetId/toggle-isolation
   */
  async toggleAssetIsolation(incidentId: string, assetId: string): Promise<Incident> {
    const res = await fetchWithLogs<{ success: boolean; message: string; incident: Incident }>(
      'POST',
      `/incident/${incidentId}/assets/${assetId}/toggle-isolation`
    );
    return res.incident;
  },

  /**
   * Update Alert Status
   * PUT /alerts/:alertId/status
   */
  async updateAlertStatus(alertId: string, status: AlertStatus): Promise<Alert> {
    const res = await fetchWithLogs<{ message: string; alert: Alert }>(
      'PUT',
      `/alerts/${alertId}/status`,
      { status }
    );
    return res.alert;
  },

  /**
   * Update Incident Status
   * PUT /incident/:incidentId/status
   */
  async updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<Incident> {
    const res = await fetchWithLogs<{ message: string; incident: Incident }>(
      'PUT',
      `/incident/${incidentId}/status`,
      { status }
    );
    return res.incident;
  },

  /**
   * Trigger Attack Simulation
   * POST /simulate
   */
  async simulateAttack(scenario: string = 'ransomware'): Promise<{
    success: boolean;
    scenario: string;
    alertsCount: number;
    incidentId?: string;
    incident?: Incident;
    alerts?: Alert[];
  }> {
    return await fetchWithLogs<{
      success: boolean;
      scenario: string;
      alertsCount: number;
      incidentId?: string;
      incident?: Incident;
      alerts?: Alert[];
    }>('POST', '/simulate', { scenario });
  },

  /**
   * Health Check
   * GET /health
   */
  async checkHealth(): Promise<{ status: string; service: string; version: string; activeIncidents?: number; totalAlerts?: number }> {
    return await fetchWithLogs<{ status: string; service: string; version: string; activeIncidents?: number; totalAlerts?: number }>(
      'GET',
      '/health'
    );
  },
};
