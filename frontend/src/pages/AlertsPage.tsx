import React, { useState, useEffect } from 'react';
import { Bell, RefreshCw, Radio, Shield, Filter, ArrowLeft } from 'lucide-react';
import { Alert, AlertStatus } from '../types';
import { AlertTable } from '../components/AlertTable';
import { socApi } from '../services/api';

interface AlertsPageProps {
  onNavigateToIncident: (incidentId: string) => void;
  onBackToDashboard: () => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({
  onNavigateToIncident,
  onBackToDashboard
}) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadAlerts = async () => {
    setIsLoading(true);
    try {
      const res = await socApi.getAlerts();
      setAlerts(res.alerts);
    } catch (err) {
      console.error('Failed to load alerts', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleUpdateStatus = async (alertId: string, newStatus: AlertStatus) => {
    try {
      const updated = await socApi.updateAlertStatus(alertId, newStatus);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    } catch (err) {
      console.error('Failed to update status', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#212634] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <button
              id="btn-alerts-back-dashboard"
              onClick={onBackToDashboard}
              className="flex items-center gap-1.5 rounded-lg border border-[#212634] bg-[#161b24] px-2.5 py-1.5 text-xs font-mono font-medium text-slate-300 hover:text-white hover:border-slate-600 transition cursor-pointer"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>DASHBOARD</span>
            </button>
            <div className="h-4 w-px bg-[#212634]" />
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-sans">
              SIEM / EDR Alert Telemetry
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Raw event telemetry and correlated threat alerts (GET /alerts)
          </p>
        </div>

        <button
          id="btn-refresh-alerts"
          onClick={loadAlerts}
          disabled={isLoading}
          className="flex items-center gap-1.5 rounded-lg border border-[#212634] bg-[#161b24] px-3.5 py-2 text-xs font-mono text-slate-200 hover:border-slate-600 hover:bg-[#1c2230] transition self-start md:self-center cursor-pointer shadow-xs"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin text-sky-400' : ''}`} />
          <span>QUERY GET /alerts</span>
        </button>
      </div>

      {/* Alert Table */}
      <AlertTable
        alerts={alerts}
        onSelectIncident={onNavigateToIncident}
        onUpdateStatus={handleUpdateStatus}
        isLoading={isLoading}
      />
    </div>
  );
};
