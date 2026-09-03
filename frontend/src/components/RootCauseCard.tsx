import React, { useState } from 'react';
import {
  ShieldAlert,
  Bug,
  Server,
  UserX,
  Radio,
  Globe,
  Copy,
  Check,
  Code2,
  Lock,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle2
} from 'lucide-react';
import { RootCause } from '../types';

interface RootCauseCardProps {
  rootCause: RootCause;
  incidentId: string;
}

export const RootCauseCard: React.FC<RootCauseCardProps> = ({
  rootCause,
  incidentId
}) => {
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [isExpanded, setIsExpanded] = useState(true);

  const rawConfidence = rootCause.confidence !== undefined ? rootCause.confidence : 0.88;
  const confNormalized = rawConfidence <= 1.0 ? rawConfidence : rawConfidence / 100.0;
  const confPercent = (confNormalized * 100).toFixed(1);
  const isHighConfidence = confNormalized >= 0.70;
  const confidenceStatus =
    rootCause.confidence_status ||
    rootCause.confidenceStatus ||
    (isHighConfidence ? 'ML-supported root cause' : 'Low-confidence ML prediction');
  const requiresVerification =
    rootCause.requires_analyst_verification ??
    rootCause.requiresAnalystVerification ??
    !isHighConfidence;

  const handleCopyPayload = () => {
    navigator.clipboard.writeText(rootCause.initialPayload);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div
      id="root-cause-card"
      className="rounded-xl border border-[#1c202a] bg-[#10131b] p-5 shadow-[0_0_15px_rgba(0,0,0,0.5)] transition-all"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#1c202a] pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-950/40 text-red-400">
            <ShieldAlert className="h-4.5 w-4.5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-base font-bold text-slate-100 font-sans tracking-tight">
                Root Cause Analysis
              </h3>
              {rootCause.primary && (
                <span className="rounded border border-sky-500/30 bg-sky-950/40 px-2 py-0.5 text-[10px] font-mono font-medium text-sky-300">
                  ML: {rootCause.primary.replace('_', ' ')}
                </span>
              )}
              <span
                className={`rounded border px-2 py-0.5 text-[10px] font-mono font-medium flex items-center gap-1 ${
                  isHighConfidence
                    ? 'border-emerald-500/30 bg-emerald-950/40 text-emerald-300'
                    : 'border-amber-500/30 bg-amber-950/40 text-amber-300'
                }`}
              >
                {isHighConfidence ? (
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-3 w-3 text-amber-400" />
                )}
                {confPercent}% ({confidenceStatus})
              </span>
              {rootCause.cveId && (
                <span className="rounded border border-red-500/30 bg-red-950/40 px-2 py-0.5 text-[10px] font-mono font-medium text-red-300">
                  {rootCause.cveId} {rootCause.cveScore ? `(CVSS ${rootCause.cveScore.toFixed(1)})` : ''}
                </span>
              )}
            </div>
            <p className="text-xs font-mono text-slate-400 mt-0.5">
              Primary breach vector & compromised entry point telemetry
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-1.5 text-slate-400 hover:text-slate-200 transition cursor-pointer"
        >
          {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>
      </div>

      {requiresVerification && (
        <div className="mt-3.5 flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-950/30 px-3.5 py-2 text-xs font-mono text-amber-300">
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
          <span>
            <strong>Analyst Verification Required:</strong> Confidence ({confPercent}%) is below 70.0% threshold. Manual verification is required before initiating automated responses.
          </span>
        </div>
      )}

      {isExpanded && (
        <div className="mt-4 space-y-3.5">
          {/* Main Vector Description */}
          <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4">
            <div className="flex items-center gap-2 text-xs font-mono font-medium text-red-400 uppercase tracking-wider mb-1">
              <Bug className="h-3.5 w-3.5 text-red-400" />
              Infiltration Vector
            </div>
            <p className="text-sm font-semibold text-slate-200">{rootCause.vector}</p>
            <p className="mt-1 text-xs text-slate-300 leading-relaxed">
              {rootCause.vulnerabilityDetails}
            </p>
          </div>

          {/* Technical Telemetry 4-Cell Grid */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {/* Entry Point */}
            <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
              <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-slate-400 mb-1">
                <Server className="h-3.5 w-3.5 text-red-400" />
                Compromised Entry Point
              </div>
              <div className="text-xs font-mono font-medium text-slate-200 break-all">
                {rootCause.entryPoint}
              </div>
              <div className="mt-1 text-[11px] font-mono text-slate-400">
                First Observed: {rootCause.firstObserved}
              </div>
            </div>

            {/* Compromised Account */}
            <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
              <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-slate-400 mb-1">
                <UserX className="h-3.5 w-3.5 text-red-400" />
                Hijacked Identity / SPN
              </div>
              <div className="text-xs font-mono font-medium text-red-300 break-all">
                {rootCause.compromisedAccount}
              </div>
              <div className="mt-1 text-[11px] font-mono text-slate-400">
                Privilege Level: TIER 0 Service Principal
              </div>
            </div>

            {/* C2 Command & Control Node */}
            <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
              <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-slate-400 mb-1">
                <Radio className="h-3.5 w-3.5 text-rose-400" />
                C2 Ingress / Beacon Node
              </div>
              <div className="text-xs font-mono font-medium text-rose-300 break-all">
                {rootCause.c2Server}
              </div>
              <div className="mt-1 flex items-center gap-1 text-[11px] font-mono text-slate-400">
                <Globe className="h-3 w-3 text-slate-400" />
                {rootCause.c2Location}
              </div>
            </div>

            {/* Detection Trigger */}
            <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
              <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-slate-400 mb-1">
                <Lock className="h-3.5 w-3.5 text-emerald-400" />
                Primary EDR Heuristic Trigger
              </div>
              <div className="text-xs text-emerald-300 font-medium leading-tight">
                {rootCause.detectionMechanism}
              </div>
            </div>
          </div>

          {/* Initial Weaponized Payload Snippet */}
          <div className="rounded-lg border border-[#1c202a] bg-[#08090d] p-3.5">
            <div className="flex items-center justify-between mb-2">
              <span className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-slate-400">
                <Code2 className="h-3.5 w-3.5 text-red-400" />
                Extracted Ingress Exploit Command / Payload
              </span>
              <button
                id="btn-copy-root-payload"
                onClick={handleCopyPayload}
                className="flex items-center gap-1 text-[11px] font-mono text-red-400 hover:text-red-300 transition cursor-pointer"
              >
                {copiedPayload ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                {copiedPayload ? 'Copied' : 'Copy Payload'}
              </button>
            </div>
            <pre className="p-3 bg-[#0c0e14] border border-[#1c202a] rounded font-mono text-xs text-red-300 overflow-x-auto select-all break-all">
              <code>{rootCause.initialPayload}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
