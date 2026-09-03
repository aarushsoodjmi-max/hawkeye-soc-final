/**
 * HawkEye SOC — Canonical Store Client Bridge
 * ==========================================
 * Deprecates in-memory mock engine in favor of the canonical FastAPI backend.
 * All operations route to socApi in api.ts.
 */
import { socApi } from './api';
import type {
  Alert,
  Incident,
  KpiMetrics,
  Severity,
  AlertStatus,
  IncidentStatus,
  RecommendedAction,
} from '../types';

export class SocStoreEngine {
  async getIncidents(): Promise<{ incidents: Incident[]; kpis: KpiMetrics }> {
    return socApi.getIncidents();
  }

  async getIncidentById(id: string): Promise<Incident | null> {
    return socApi.getIncidentById(id);
  }

  async getAlerts(filter?: {
    severity?: Severity;
    status?: AlertStatus;
    incidentId?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ alerts: Alert[]; total: number }> {
    return socApi.getAlerts(filter);
  }

  async getAlertById(id: string): Promise<Alert | null> {
    return socApi.getAlertById(id);
  }

  async updateAlertStatus(alertId: string, status: AlertStatus): Promise<Alert> {
    return socApi.updateAlertStatus(alertId, status);
  }

  async updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<Incident> {
    return socApi.updateIncidentStatus(incidentId, status);
  }

  async executeAction(incidentId: string, actionId: string): Promise<RecommendedAction> {
    return socApi.executeAction(incidentId, actionId);
  }

  async toggleAssetIsolation(incidentId: string, assetId: string): Promise<Incident> {
    return socApi.toggleAssetIsolation(incidentId, assetId);
  }

  async simulateAttack(scenario: string = 'ransomware') {
    return socApi.simulateAttack(scenario);
  }

  async runAiAnalysis(incidentId: string, analystNotes?: string, includePcap?: boolean) {
    return socApi.analyzeIncident({
      incidentId,
      analystNotes,
      includeTelemetryPcap: includePcap,
    });
  }
}

export const socStore = new SocStoreEngine();
