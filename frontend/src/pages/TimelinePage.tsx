import React, { useState, useEffect } from 'react';
import {
  GitCommit,
  Shield,
  ArrowLeft,
  ExternalLink,
  ChevronDown,
  Activity,
  Radio,
  FileCode,
  Layers
} from 'lucide-react';
import { Incident } from '../types';
import { AttackTimeline } from '../components/AttackTimeline';
import { SeverityBadge } from '../components/SeverityBadge';
import { socApi } from '../services/api';

interface TimelinePageProps {
  initialIncidentId?: string;
  onNavigateToIncident: (incidentId: string) => void;
  onBackToDashboard: () => void;
}

export const TimelinePage: React.FC<TimelinePageProps> = ({
  initialIncidentId = 'INC-8942',
  onNavigateToIncident,
  onBackToDashboard
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId);
  const [incidentsList, setIncidentsList] = useState<Incident[]>([]);
  const [currentIncident, setCurrentIncident] = useState<Incident | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load all incidents for selector
  useEffect(() => {
    const loadAll = async () => {
      try {
        const res = await socApi.getIncidents();
        setIncidentsList(res.incidents);
      } catch (err) {
        console.error('Failed to load incidents', err);
      }
    };
    loadAll();
  }, []);

  // Load current incident data: GET /incident/:id
  useEffect(() => {
    let isMounted = true;
    const loadCurrent = async () => {
      setIsLoading(true);
      try {
        const data = await socApi.getIncidentById(selectedIncidentId);
        if (isMounted) setCurrentIncident(data);
      } catch (err) {
        console.error('Failed to load incident timeline', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };
    loadCurrent();
    return () => {
      isMounted = false;
    };
  }, [selectedIncidentId]);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#1c202a] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <button
              id="btn-timeline-back-dashboard"
              onClick={onBackToDashboard}
              className="flex items-center gap-1.5 rounded-lg border border-[#232938] bg-[#12151e] px-3 py-1.5 text-xs font-mono font-medium text-slate-300 hover:text-white hover:border-red-500/40 transition cursor-pointer"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>DASHBOARD</span>
            </button>
            <div className="h-4 w-px bg-[#1c202a]" />
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-sans">
              Attack Kill-Chain Timeline
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Reconstructed forensic chronology mapped to MITRE ATT&CK framework tactics
          </p>
        </div>

        {/* Incident Switcher & Action */}
        <div className="flex items-center gap-3 self-start md:self-center">
          <div className="flex items-center gap-2 bg-[#0c0e14] border border-[#1c202a] rounded-lg px-3 py-1.5">
            <span className="text-xs font-mono text-slate-400">Incident:</span>
            <select
              id="timeline-incident-select"
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="bg-transparent text-xs font-mono font-medium text-red-400 focus:outline-hidden cursor-pointer"
            >
              {incidentsList.map((inc) => (
                <option key={inc.id} value={inc.id} className="bg-[#10131b] text-slate-200">
                  {inc.id}: {inc.title.substring(0, 32)}...
                </option>
              ))}
            </select>
          </div>

          {currentIncident && (
            <button
              id="btn-timeline-open-incident"
              onClick={() => onNavigateToIncident(currentIncident.id)}
              className="flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-500 px-3.5 py-2 text-xs font-sans font-medium text-white shadow-[0_0_12px_rgba(255,0,51,0.3)] uppercase tracking-wider transition cursor-pointer"
            >
              <span>Incident Details</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Incident Summary Banner */}
      {currentIncident && (
        <div className="rounded-xl border border-[#1c202a] bg-[#10131b] p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 shadow-[0_0_15px_rgba(0,0,0,0.5)]">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={currentIncident.severity} size="sm" />
            <div>
              <div className="font-semibold text-sm text-slate-200">{currentIncident.title}</div>
              <div className="text-xs font-mono text-slate-400 mt-0.5 flex flex-wrap items-center gap-2">
                <span>Threat Actor: <span className="text-red-300 font-medium">{currentIncident.threatActor}</span></span>
                <span>•</span>
                <span className="text-rose-400 font-semibold">Risk: {currentIncident.riskScore ?? 85}/100</span>
                <span>•</span>
                <span className="text-emerald-400 font-medium">
                  ML Cause: {currentIncident.rootCause?.primary || currentIncident.rootCause?.vector} ({((currentIncident.rootCause?.confidence || 0.92) * ((currentIncident.rootCause?.confidence || 0.92) <= 1 ? 100 : 1)).toFixed(0)}%)
                </span>
                <span>•</span>
                <span>{currentIncident.timelineEvents.length} Verified Attack Steps</span>
              </div>
            </div>
          </div>
          <span className="text-[11px] font-mono text-red-400 self-end sm:self-center">
            Detected: {currentIncident.detectedAt}
          </span>
        </div>
      )}

      {/* Loading or Timeline Component */}
      {isLoading ? (
        <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
          <div className="h-7 w-7 animate-spin rounded-full border-2 border-red-500 border-t-transparent"></div>
          <span className="font-mono text-xs text-red-400">
            Reconstructing Attack Chronology from telemetry events...
          </span>
        </div>
      ) : currentIncident ? (
        <AttackTimeline
          events={currentIncident.timelineEvents}
          incidentTitle={currentIncident.title}
          incidentId={currentIncident.id}
        />
      ) : (
        <div className="p-8 text-center text-slate-400 font-mono text-xs">
          No timeline events found for this incident.
        </div>
      )}
    </div>
  );
};
