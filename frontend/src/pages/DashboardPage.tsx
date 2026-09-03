import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  Radio,
  RefreshCw,
  Clock,
  ArrowRight,
  Server,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Zap,
  Activity
} from 'lucide-react';
import { Alert, Incident, KpiMetrics, AlertStatus } from '../types';
import { KpiCards } from '../components/KpiCards';
import { AlertTable } from '../components/AlertTable';
import { SeverityBadge } from '../components/SeverityBadge';
import { socApi } from '../services/api';

interface DashboardPageProps {
  onNavigateToIncident: (incidentId: string) => void;
  onNavigateToTimeline: (incidentId?: string) => void;
  onNavigateToAlerts: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onNavigateToIncident,
  onNavigateToTimeline,
  onNavigateToAlerts
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [kpis, setKpis] = useState<KpiMetrics>({
    activeIncidents: 2,
    criticalAlerts: 3,
    mttdMinutes: 4.2,
    mttrMinutes: 18.5,
    threatLevel: 'DEFCON 2',
    compromisedAssets: 4,
    blockedAttacks24h: 1842
  });
  const [isLoading, setIsLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState('');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationMenuOpen, setSimulationMenuOpen] = useState(false);
  const [simulationBanner, setSimulationBanner] = useState<{
    incidentId: string;
    scenario: string;
    alertsCount: number;
    title: string;
  } | null>(null);

  // Live UTC Clock
  useEffect(() => {
    const updateUtc = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateUtc();
    const interval = setInterval(updateUtc, 1000);
    return () => clearInterval(interval);
  }, []);

  // Fetch initial data via simulated REST endpoints
  const fetchDashboardData = async () => {
    setIsLoading(true);
    try {
      const [incidentsRes, alertsRes] = await Promise.all([
        socApi.getIncidents(),
        socApi.getAlerts()
      ]);
      setIncidents(incidentsRes.incidents);
      setKpis(incidentsRes.kpis);
      setAlerts(alertsRes.alerts);
    } catch (err) {
      console.error('Failed to load dashboard data', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const handleSimulateScenario = async (scenarioKey: string) => {
    setSimulationMenuOpen(false);
    setIsSimulating(true);
    try {
      const res = await socApi.simulateAttack(scenarioKey);
      if (res.success && res.incident) {
        setSimulationBanner({
          incidentId: res.incident.id,
          scenario: res.scenario,
          alertsCount: res.alertsCount,
          title: res.incident.title,
        });
        // Refresh dashboard data
        await fetchDashboardData();
      }
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleUpdateAlertStatus = async (alertId: string, newStatus: AlertStatus) => {
    try {
      const updated = await socApi.updateAlertStatus(alertId, newStatus);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    } catch (err) {
      console.error('Failed to update alert', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Operational Posture Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#212634] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-sans">
              HawkEye Threat Overview
            </h1>
            <span className="flex items-center gap-1.5 rounded border border-rose-500/20 bg-rose-500/10 px-2.5 py-0.5 text-xs font-mono font-medium text-rose-300">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-400 animate-pulse" />
              DEFCON 2 : ELEVATED
            </span>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span>Autonomous ML Telemetry Correlator Online</span>
            <span>•</span>
            <span className="text-sky-400">Endpoint Coverage: 99.4% (8,412 sensors)</span>
          </p>
        </div>

        {/* Action Controls & Clock */}
        <div className="flex items-center gap-3 self-start md:self-center flex-wrap">
          <div className="hidden sm:flex items-center gap-2 rounded-lg border border-[#1c202a] bg-[#10131b] px-3 py-1.5 text-xs font-mono text-slate-300">
            <Clock className="h-3.5 w-3.5 text-red-400" />
            <span>{currentTime || 'SYNCHRONIZING UTC...'}</span>
          </div>

          {/* Attack Simulator Button with Dropdown */}
          <div className="relative">
            <button
              id="btn-simulate-attack-dropdown"
              onClick={() => setSimulationMenuOpen(!simulationMenuOpen)}
              disabled={isSimulating}
              className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 px-3.5 py-2 text-xs font-sans font-medium text-white shadow-[0_0_15px_rgba(255,0,51,0.3)] uppercase tracking-wider transition cursor-pointer"
            >
              <Zap className={`h-3.5 w-3.5 ${isSimulating ? 'animate-spin' : 'fill-white'}`} />
              <span>{isSimulating ? 'SIMULATING...' : 'SIMULATE ATTACK'}</span>
            </button>

            {simulationMenuOpen && (
              <div
                id="menu-simulation-scenarios"
                className="absolute right-0 mt-2 w-64 rounded-xl border border-red-500/30 bg-[#0f121a] shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95"
              >
                <div className="px-2 py-1.5 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-400 border-b border-[#1c202a] mb-1">
                  Inject Attack Scenario (POST /simulate)
                </div>
                {[
                  { key: 'ransomware', name: 'Ransomware Outbreak', desc: 'LockBit 3.0 & VSS Purge' },
                  { key: 'credential_theft', name: 'Credential Theft', desc: 'Pass-the-Hash & LSASS Dump' },
                  { key: 'phishing', name: 'Spearphishing Stager', desc: 'Malicious Macro & C2 Ingress' },
                  { key: 'malware', name: 'Malware Persistence', desc: 'DLL Sideloading & AMSI Bypass' },
                  { key: 'insider_threat', name: 'Insider Exfiltration', desc: 'Bulk Database S3 Scraping' },
                ].map((sc) => (
                  <button
                    key={sc.key}
                    id={`btn-simulate-${sc.key}`}
                    onClick={() => handleSimulateScenario(sc.key)}
                    className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-red-950/40 hover:text-white transition group cursor-pointer text-slate-300"
                  >
                    <div className="text-xs font-medium font-sans group-hover:text-red-300 flex items-center justify-between">
                      <span>{sc.name}</span>
                      <ChevronRight className="h-3 w-3 text-slate-500 group-hover:text-red-400 group-hover:translate-x-0.5 transition-transform" />
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 group-hover:text-slate-400">
                      {sc.desc}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          <button
            id="btn-refresh-dashboard"
            onClick={fetchDashboardData}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-[#232938] bg-[#12151e] px-3.5 py-2 text-xs font-mono font-medium text-slate-300 hover:border-red-500/40 hover:text-white transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin text-red-400' : 'text-slate-400'}`} />
            <span>REFETCH REST</span>
          </button>
        </div>
      </div>

      {/* Simulation Result Toast Banner */}
      {simulationBanner && (
        <div
          id="banner-simulation-success"
          className="rounded-xl border border-red-500/50 bg-red-950/30 p-4 shadow-[0_0_20px_rgba(255,0,51,0.2)] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 animate-in slide-in-from-top duration-300"
        >
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-red-600/20 border border-red-500/40 flex items-center justify-center shrink-0">
              <Zap className="h-5 w-5 text-red-400 fill-red-400" />
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-red-300 font-mono flex items-center gap-2">
                <span>Attack Pipeline Injected: {simulationBanner.scenario}</span>
                <span className="bg-red-500/20 px-2 py-0.5 rounded text-[10px] text-red-200">
                  {simulationBanner.alertsCount} Telemetry Alerts Generated
                </span>
              </div>
              <div className="text-sm font-medium text-slate-100 font-sans mt-0.5">
                {simulationBanner.title}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              id="btn-banner-triage"
              onClick={() => onNavigateToIncident(simulationBanner.incidentId)}
              className="flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-500 px-3.5 py-1.5 text-xs font-medium text-white transition shadow-sm cursor-pointer"
            >
              <span>Investigate Incident</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setSimulationBanner(null)}
              className="px-2.5 py-1.5 text-xs font-mono text-slate-400 hover:text-white transition cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* KPI Cards Component */}
      <KpiCards
        metrics={kpis}
        onNavigateToIncidents={() => onNavigateToIncident('INC-8942')}
        onNavigateToAlerts={onNavigateToAlerts}
      />

      {/* Priority Incident Spotlight Strip */}
      <div className="rounded-xl border border-red-500/30 bg-[#10131b] p-5 shadow-[0_0_15px_rgba(255,0,51,0.08)] relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="rounded px-2 py-0.5 text-[10px] font-mono font-medium bg-red-500/20 text-red-300 border border-red-500/40 uppercase tracking-wider">
                ACTIVE P1 INCIDENT
              </span>
              <span className="font-mono text-[10px] font-medium text-red-300 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/30">
                APT29 / Nobelium
              </span>
              <span className="font-mono text-xs text-slate-400">
                Detected: 2026-09-03 04:18:22 UTC
              </span>
            </div>

            <h2 className="text-lg font-bold text-slate-100 tracking-tight font-sans">
              INC-8942: Kerberoasting & Lateral Movement toward Primary Domain Controller
            </h2>

            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
              Unauthenticated Palo Alto VPN command injection (CVE-2024-3400) escalated into domain controller LSASS credential dumping. Attacker actively staging ransomware / exfiltration tunnel.
            </p>
          </div>

          <div className="flex items-center gap-2.5 shrink-0 self-start lg:self-center">
            <button
              id="btn-spotlight-investigate"
              onClick={() => onNavigateToIncident('INC-8942')}
              className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 px-4 py-2 text-xs font-sans font-medium text-white shadow-[0_0_12px_rgba(255,0,51,0.3)] uppercase tracking-wider transition cursor-pointer"
            >
              <span>INVESTIGATE ROOT CAUSE</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>

            <button
              id="btn-spotlight-timeline"
              onClick={() => onNavigateToTimeline('INC-8942')}
              className="flex items-center gap-1.5 rounded-lg border border-[#232938] bg-[#141822] hover:bg-[#1a202c] hover:border-red-500/30 px-3.5 py-2 text-xs font-sans font-medium text-slate-300 hover:text-white uppercase tracking-wider transition cursor-pointer"
            >
              <span>VIEW KILL-CHAIN</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Incidents Quick Cards Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="h-4 w-4 text-red-500" />
            <h3 className="text-xs font-semibold tracking-wider text-slate-400 uppercase font-sans">
              Assigned Security Incidents Queue (GET /incidents)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {incidents.length} Total Incidents Tracked
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
          {incidents.map((inc) => (
            <div
              key={inc.id}
              id={`incident-card-${inc.id}`}
              onClick={() => onNavigateToIncident(inc.id)}
              className="group rounded-xl border border-[#1c202a] bg-[#10131b] p-4 transition-all duration-150 hover:border-red-500/40 hover:bg-[#141722] hover:shadow-[0_0_12px_rgba(255,0,51,0.1)] cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-medium text-red-400 group-hover:text-red-300">
                    {inc.id}
                  </span>
                  <SeverityBadge severity={inc.severity} size="sm" />
                </div>

                <h4 className="text-xs font-medium text-slate-200 line-clamp-2 group-hover:text-white mb-2">
                  {inc.title}
                </h4>

                <div className="text-[11px] font-mono text-red-400/90 truncate mb-1">
                  Actor: {inc.threatActor}
                </div>

                <div className="flex items-center gap-1.5 text-[10px] font-mono my-2 flex-wrap">
                  <span className="bg-rose-950/50 border border-rose-500/40 text-rose-300 px-1.5 py-0.5 rounded font-semibold">
                    Risk: {inc.riskScore ?? 85}/100
                  </span>
                  <span className="bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 px-1.5 py-0.5 rounded">
                    ML: {((inc.rootCause.confidence || 0.92) * ((inc.rootCause.confidence || 0.92) <= 1 ? 100 : 1)).toFixed(0)}%
                  </span>
                  <span className="text-slate-400">
                    {inc.timelineEvents?.length || 0} evts
                  </span>
                </div>

                <div className="text-[10px] text-slate-400 line-clamp-2 mb-3">
                  {inc.impactSummary}
                </div>
              </div>

              <div className="border-t border-[#1c202a] pt-2.5 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-400">
                  {inc.affectedAssets.length} Assets Affected
                </span>
                <span className="text-red-400 group-hover:translate-x-0.5 transition-transform flex items-center gap-0.5 font-medium">
                  Triage <ChevronRight className="h-3 w-3" />
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Correlated Alert Table Component */}
      <div className="space-y-3 pt-2">
        <AlertTable
          alerts={alerts}
          onSelectIncident={onNavigateToIncident}
          onUpdateStatus={handleUpdateAlertStatus}
          isLoading={isLoading}
        />
      </div>
    </div>
  );
};
