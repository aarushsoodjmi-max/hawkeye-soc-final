import React, { useState, useEffect } from 'react';
import {
  Flame,
  Shield,
  ArrowLeft,
  Server,
  GitCommit,
  Radio,
  User,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Unlock,
  RotateCw,
  ExternalLink
} from 'lucide-react';
import { Incident, IncidentStatus, RecommendedAction, AiAnalysisResult } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { RootCauseCard } from '../components/RootCauseCard';
import { RecommendedActionPanel } from '../components/RecommendedActionPanel';
import { socApi } from '../services/api';

interface IncidentDetailsPageProps {
  incidentId: string;
  onBackToDashboard: () => void;
  onNavigateToTimeline: (incidentId: string) => void;
}

export const IncidentDetailsPage: React.FC<IncidentDetailsPageProps> = ({
  incidentId,
  onBackToDashboard,
  onNavigateToTimeline
}) => {
  const [incident, setIncident] = useState<Incident | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [isolatingAssetId, setIsolatingAssetId] = useState<string | null>(null);

  // Fetch Incident by ID: GET /incident/:id
  useEffect(() => {
    let isMounted = true;
    const loadIncident = async () => {
      setIsLoading(true);
      try {
        const data = await socApi.getIncidentById(incidentId);
        if (isMounted) setIncident(data);
      } catch (err) {
        console.error('Failed to load incident', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    loadIncident();
    return () => {
      isMounted = false;
    };
  }, [incidentId]);

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!incident) return;
    setIsUpdatingStatus(true);
    try {
      const updated = await socApi.updateIncidentStatus(incident.id, newStatus);
      setIncident(updated);
    } catch (err) {
      console.error('Failed to update status', err);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleActionExecuted = (updatedAction: RecommendedAction) => {
    if (!incident) return;
    setIncident((prev) => {
      if (!prev) return null;
      return {
        ...prev,
        recommendedActions: prev.recommendedActions.map((a) =>
          a.id === updatedAction.id ? updatedAction : a
        )
      };
    });
  };

  const handleAnalysisCompleted = (analysis: AiAnalysisResult, updated: Incident) => {
    setIncident(updated);
  };

  const handleToggleAssetIsolation = async (assetId: string) => {
    if (!incident) return;
    setIsolatingAssetId(assetId);
    try {
      const updated = await socApi.toggleAssetIsolation(incident.id, assetId);
      setIncident(updated);
    } catch (err) {
      console.error('Failed to isolate asset', err);
    } finally {
      setIsolatingAssetId(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <div className="h-7 w-7 animate-spin rounded-full border-2 border-red-500 border-t-transparent"></div>
        <span className="font-mono text-xs text-red-400">
          Querying GET /incident/{incidentId}...
        </span>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-8 text-center rounded-xl border border-[#1c202a] bg-[#10131b]">
        <AlertTriangle className="h-9 w-9 text-amber-400 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-slate-100">Incident {incidentId} Not Found</h3>
        <p className="text-xs font-mono text-slate-400 mt-1 mb-4">
          The requested incident record does not exist in the security database.
        </p>
        <button
          onClick={onBackToDashboard}
          className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-medium"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Navigation & Status Bar */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#1c202a] pb-5">
        <div className="flex items-center gap-3">
          <button
            id="btn-back-dashboard"
            onClick={onBackToDashboard}
            className="flex items-center gap-1.5 rounded-lg border border-[#232938] bg-[#12151e] px-3 py-1.5 text-xs font-mono font-medium text-slate-300 hover:text-white hover:border-red-500/40 transition cursor-pointer"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>DASHBOARD</span>
          </button>
          <div className="h-4 w-px bg-[#1c202a]" />
          <span className="font-mono text-xs text-red-400 font-medium tracking-wider">
            GET /incident/{incident.id}
          </span>
        </div>

        {/* View Attack Timeline Action */}
        <div className="flex items-center gap-2">
          <button
            id="btn-nav-timeline"
            onClick={() => onNavigateToTimeline(incident.id)}
            className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 px-3.5 py-2 text-xs font-sans font-medium text-white shadow-[0_0_12px_rgba(255,0,51,0.3)] uppercase tracking-wider transition cursor-pointer"
          >
            <GitCommit className="h-4 w-4 text-white" />
            <span>VIEW ATTACK TIMELINE</span>
            <ExternalLink className="h-3.5 w-3.5 text-white/80" />
          </button>
        </div>
      </div>

      {/* Incident Command Hero Header */}
      <div className="rounded-xl border border-[#1c202a] bg-[#10131b] p-5 shadow-[0_0_15px_rgba(0,0,0,0.5)]">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
          <div className="space-y-3 flex-1">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="font-mono text-sm font-semibold text-red-400">
                {incident.id}
              </span>
              <SeverityBadge severity={incident.severity} size="md" />
              <span className="font-mono text-xs text-rose-300 bg-rose-950/50 px-2.5 py-0.5 rounded border border-rose-500/40 font-semibold flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-rose-400" />
                RISK SCORE: {incident.riskScore ?? 85}/100 [{incident.riskLevel ?? 'CRITICAL'}]
              </span>
              <span className="font-mono text-xs text-emerald-300 bg-emerald-950/40 px-2.5 py-0.5 rounded border border-emerald-500/30 font-medium">
                ML CONFIDENCE: {((incident.rootCause.confidence || 0.92) * ((incident.rootCause.confidence || 0.92) <= 1 ? 100 : 1)).toFixed(1)}%
              </span>
              <span className="font-mono text-xs text-red-300 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/30 font-medium">
                Threat Actor: {incident.threatActor}
              </span>
              {incident.threatActorOrigin && (
                <span className="text-xs font-mono text-slate-400">
                  ({incident.threatActorOrigin})
                </span>
              )}
            </div>

            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 font-sans">
              {incident.title}
            </h1>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-4xl">
              {incident.impactSummary}
            </p>

            {/* Metadata pills */}
            <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 pt-2">
              <span className="flex items-center gap-1.5 text-slate-300">
                <User className="h-3.5 w-3.5 text-red-400" />
                Lead: {incident.leadAnalyst}
              </span>
              <span className="flex items-center gap-1.5 text-slate-400">
                <Clock className="h-3.5 w-3.5 text-slate-500" />
                Detected: {incident.detectedAt}
              </span>
              <span className="text-slate-400">Updated: {incident.updatedAt}</span>
            </div>
          </div>

          {/* Status Switcher Box */}
          <div className="rounded-xl border border-[#1c202a] bg-[#0c0e14] p-3.5 shrink-0 min-w-[200px]">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-2">
              Incident Triage Status:
            </span>
            <div className="grid grid-cols-1 gap-1.5">
              {(['ACTIVE', 'TRIAGING', 'CONTAINED', 'MITIGATED', 'CLOSED'] as IncidentStatus[]).map(
                (st) => (
                  <button
                    key={st}
                    id={`btn-incident-status-${st.toLowerCase()}`}
                    onClick={() => handleStatusChange(st)}
                    disabled={isUpdatingStatus}
                    className={`flex items-center justify-between px-3 py-1.5 rounded-lg text-xs font-mono border transition cursor-pointer ${
                      incident.status === st
                        ? 'bg-red-600 text-white border-red-500 font-semibold shadow-[0_0_10px_rgba(255,0,51,0.3)]'
                        : 'bg-[#10131b] text-slate-400 border-[#1c202a] hover:border-slate-600 hover:text-slate-200'
                    }`}
                  >
                    <span>{st}</span>
                    {incident.status === st && <CheckCircle2 className="h-3 w-3 text-white" />}
                  </button>
                )
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Root Cause Card Component */}
      <RootCauseCard rootCause={incident.rootCause} incidentId={incident.id} />

      {/* Recommended Action Panel Component */}
      <RecommendedActionPanel
        incident={incident}
        onActionExecuted={handleActionExecuted}
        onAnalysisCompleted={handleAnalysisCompleted}
      />

      {/* Affected Infrastructure / Fleet Assets Inventory */}
      <div className="rounded-xl border border-[#1c202a] bg-[#10131b] p-5 shadow-[0_0_15px_rgba(0,0,0,0.5)]">
        <div className="flex items-center justify-between border-b border-[#1c202a] pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-950/40 text-red-400">
              <Server className="h-4.5 w-4.5" />
            </div>
            <div>
              <h3 className="text-base font-bold tracking-tight text-slate-100 font-sans">
                Impacted Infrastructure Assets ({incident.affectedAssets.length})
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Endpoints, gateways, and identity scopes within adversary blast radius
              </p>
            </div>
          </div>
        </div>

        {/* Asset Cards Grid */}
        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
          {incident.affectedAssets.map((asset) => {
            const isIsolated = asset.status === 'ISOLATED';
            const isToggling = isolatingAssetId === asset.id;

            return (
              <div
                key={asset.id}
                id={`asset-card-${asset.id}`}
                className={`rounded-xl border p-4 flex flex-col justify-between transition ${
                  isIsolated
                    ? 'border-red-500/40 bg-red-950/20'
                    : 'border-[#1c202a] bg-[#0c0e14] hover:border-slate-600'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-semibold text-slate-200 truncate">
                      {asset.name}
                    </span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded border font-medium ${
                        asset.criticality === 'TIER 0'
                          ? 'bg-rose-500/10 text-rose-300 border-rose-500/20'
                          : 'bg-red-500/10 text-red-300 border-red-500/20'
                      }`}
                    >
                      {asset.criticality}
                    </span>
                  </div>

                  <div className="text-[11px] font-mono text-red-400 mb-1">{asset.ip}</div>
                  <div className="text-[10px] text-slate-400 font-mono mb-2 truncate">
                    {asset.os} • {asset.role}
                  </div>
                </div>

                <div className="border-t border-[#1c202a] pt-3 flex items-center justify-between">
                  <span
                    className={`text-[10px] font-mono uppercase font-medium px-2 py-0.5 rounded border ${
                      isIsolated
                        ? 'bg-red-500/10 text-red-300 border-red-500/20'
                        : asset.status === 'COMPROMISED'
                        ? 'bg-rose-500/10 text-rose-300 border-rose-500/20'
                        : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20'
                    }`}
                  >
                    {asset.status}
                  </span>

                  <button
                    id={`btn-isolate-${asset.id}`}
                    onClick={() => handleToggleAssetIsolation(asset.id)}
                    disabled={isToggling}
                    className={`flex items-center gap-1 text-[10px] font-mono font-medium px-2 py-1 rounded border transition cursor-pointer ${
                      isIsolated
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
                        : 'border-rose-500/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20'
                    }`}
                  >
                    {isToggling ? (
                      <RotateCw className="h-3 w-3 animate-spin" />
                    ) : isIsolated ? (
                      <>
                        <Unlock className="h-3 w-3" />
                        <span>Unisolate</span>
                      </>
                    ) : (
                      <>
                        <Lock className="h-3 w-3" />
                        <span>Isolate</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
