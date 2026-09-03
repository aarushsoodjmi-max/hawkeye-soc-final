import React, { useState } from 'react';
import {
  Sparkles,
  ShieldCheck,
  Zap,
  Play,
  CheckCircle2,
  AlertOctagon,
  Clock,
  RotateCw,
  Cpu,
  Layers,
  ArrowRight
} from 'lucide-react';
import { Incident, RecommendedAction, AiAnalysisResult } from '../types';
import { socApi } from '../services/api';

interface RecommendedActionPanelProps {
  incident: Incident;
  onActionExecuted?: (updatedAction: RecommendedAction) => void;
  onAnalysisCompleted?: (analysis: AiAnalysisResult, updatedIncident: Incident) => void;
}

export const RecommendedActionPanel: React.FC<RecommendedActionPanelProps> = ({
  incident,
  onActionExecuted,
  onAnalysisCompleted
}) => {
  const [executingActionId, setExecutingActionId] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);

  // Handle single action execution
  const handleExecuteAction = async (action: RecommendedAction) => {
    if (action.status === 'COMPLETED' || executingActionId) return;

    try {
      setExecutingActionId(action.id);
      const updated = await socApi.executeAction(incident.id, action.id);
      onActionExecuted?.(updated);
    } catch (err) {
      console.error('Failed to execute action', err);
    } finally {
      setExecutingActionId(null);
    }
  };

  // Handle POST /analyze
  const handleRunAiAnalysis = async () => {
    if (isAnalyzing) return;
    setIsAnalyzing(true);
    setAnalysisProgress(15);

    const interval = setInterval(() => {
      setAnalysisProgress((prev) => {
        if (prev >= 85) {
          clearInterval(interval);
          return 85;
        }
        return prev + 18;
      });
    }, 150);

    try {
      const response = await socApi.analyzeIncident({
        incidentId: incident.id,
        analystNotes: 'Auto-triggered from SOC triage console',
        includeTelemetryPcap: true
      });

      setAnalysisProgress(100);
      setTimeout(() => {
        setIsAnalyzing(false);
        setAnalysisProgress(0);
        onAnalysisCompleted?.(response.analysis, response.updatedIncident);
      }, 300);
    } catch (err) {
      console.error('Analysis failed', err);
      setIsAnalyzing(false);
      setAnalysisProgress(0);
    }
  };

  const getRiskBadge = (risk: 'LOW' | 'MED' | 'HIGH') => {
    switch (risk) {
      case 'HIGH':
        return 'bg-rose-500/10 text-rose-300 border-rose-500/20';
      case 'MED':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/20';
      case 'LOW':
        return 'bg-red-500/10 text-red-300 border-red-500/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* AI Threat Engine Trigger & Result Block */}
      <div
        id="ai-analysis-engine"
        className="rounded-xl border border-red-500/30 bg-red-950/20 p-5 shadow-[0_0_15px_rgba(0,0,0,0.5)] relative overflow-hidden"
      >
        {/* Engine Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[#1c202a] pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-950/40 text-red-400">
              <Sparkles className="h-4.5 w-4.5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-100 font-sans tracking-tight">
                  Neural Attack Correlation Engine
                </h3>
                <span className="rounded bg-red-500/10 px-2 py-0.5 text-[10px] font-mono text-red-300 border border-red-500/20 font-medium">
                  POST /analyze
                </span>
              </div>
              <p className="text-xs font-mono text-slate-400">
                Automated multi-vector kill-chain correlation & blast radius synthesis
              </p>
            </div>
          </div>

          {/* Trigger Button */}
          <button
            id="btn-trigger-analyze"
            onClick={handleRunAiAnalysis}
            disabled={isAnalyzing}
            className="flex items-center justify-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 px-4 py-2 text-xs font-sans font-medium text-white shadow-[0_0_12px_rgba(255,0,51,0.3)] uppercase tracking-wider transition-all disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
          >
            {isAnalyzing ? (
              <>
                <RotateCw className="h-4 w-4 animate-spin" />
                <span>SYNTHESIZING TELEMETRY ({analysisProgress}%)...</span>
              </>
            ) : (
              <>
                <Cpu className="h-4 w-4" />
                <span>DISPATCH POST /analyze</span>
              </>
            )}
          </button>
        </div>

        {/* Analysis Loading Bar */}
        {isAnalyzing && (
          <div className="my-4">
            <div className="flex justify-between text-[11px] font-mono text-red-300 mb-1">
              <span>Correlating EDR beacons, Active Directory SPNs, and PCAP flows...</span>
              <span>{analysisProgress}%</span>
            </div>
            <div className="h-1.5 w-full bg-[#0c0e14] rounded-full overflow-hidden">
              <div
                className="h-full bg-red-500 transition-all duration-200"
                style={{ width: `${analysisProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* AI Analysis Findings Display */}
        {incident.aiAnalysis && (
          <div className="mt-4 space-y-3">
            {/* Top Analysis Metrics */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">
                  Neural Confidence
                </span>
                <span className="text-xl font-bold font-sans text-red-400">
                  {incident.aiAnalysis.confidenceScore.toFixed(1)}%
                </span>
                <span className="text-[10px] text-slate-400 block">Heuristic correlation threshold</span>
              </div>

              <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">
                  Kill-Chain Stage
                </span>
                <span className="text-sm font-semibold text-slate-100 block mt-0.5 truncate">
                  {incident.aiAnalysis.killChainStage}
                </span>
                <span className="text-[10px] text-amber-400 font-mono block">Urgency: {incident.aiAnalysis.urgency}</span>
              </div>

              <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-3.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">
                  Blast Radius Assessment
                </span>
                <span className="text-xs text-slate-300 font-medium line-clamp-2 mt-0.5">
                  {incident.aiAnalysis.blastRadius}
                </span>
              </div>
            </div>

            {/* Key Findings List */}
            <div className="rounded-lg border border-[#1c202a] bg-[#0c0e14] p-4">
              <div className="text-xs font-mono font-medium uppercase text-red-400 mb-2.5 flex items-center gap-1.5">
                <Layers className="h-3.5 w-3.5 text-red-400" />
                Correlated Threat Discoveries
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {incident.aiAnalysis.keyFindings.map((finding, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="mt-1 h-1.5 w-1.5 rounded-full bg-red-400 shrink-0" />
                    <span>{finding}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Recommended Action Playbook Panel */}
      <div
        id="recommended-action-panel"
        className="rounded-xl border border-[#1c202a] bg-[#10131b] p-5 shadow-[0_0_15px_rgba(0,0,0,0.5)]"
      >
        <div className="flex items-center justify-between border-b border-[#1c202a] pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-950/40 text-red-400">
              <ShieldCheck className="h-4.5 w-4.5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 font-sans tracking-tight">
                Recommended Response Playbooks
              </h3>
              <p className="text-xs font-mono text-slate-400">
                SOAR orchestrated response actions (Containment, Eradication, Hardening)
              </p>
            </div>
          </div>
          <span className="rounded bg-[#0c0e14] px-2.5 py-1 text-xs font-mono text-slate-300 border border-[#1c202a]">
            {incident.recommendedActions.filter((a) => a.status === 'COMPLETED').length} /{' '}
            {incident.recommendedActions.length} Executed
          </span>
        </div>

        {/* Action Cards List */}
        <div className="mt-4 space-y-3">
          {incident.recommendedActions.map((action) => {
            const isExecuting = executingActionId === action.id;
            const isCompleted = action.status === 'COMPLETED';

            return (
              <div
                key={action.id}
                id={`action-card-${action.id}`}
                className={`rounded-xl border p-4 transition-all ${
                  isCompleted
                    ? 'border-emerald-500/25 bg-emerald-500/5'
                    : 'border-[#1c202a] bg-[#0c0e14] hover:border-slate-600'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm text-slate-200">{action.title}</span>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-mono border font-medium ${getRiskBadge(
                          action.riskLevel
                        )}`}
                      >
                        {action.riskLevel} RISK
                      </span>
                      <span className="rounded bg-[#10131b] px-1.5 py-0.5 text-[10px] font-mono text-slate-400 border border-[#1c202a]">
                        {action.type}
                      </span>
                      <span className="text-[10px] font-mono text-red-400">
                        {action.playbookId}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                      {action.description}
                    </p>

                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 pt-1">
                      <span>Target: <strong className="text-slate-200 font-medium">{action.target}</strong></span>
                      {action.executedAt && (
                        <span className="text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" />
                          Executed at {action.executedAt}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Execution Action Button */}
                  <div className="sm:self-center shrink-0">
                    {isCompleted ? (
                      <div className="flex items-center gap-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 text-xs font-mono font-medium text-emerald-300">
                        <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        <span>CONTAINED</span>
                      </div>
                    ) : (
                      <button
                        id={`btn-exec-${action.id}`}
                        onClick={() => handleExecuteAction(action)}
                        disabled={isExecuting}
                        className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 px-3.5 py-2 text-xs font-mono font-medium text-white transition disabled:opacity-50 cursor-pointer uppercase tracking-wider shadow-[0_0_10px_rgba(255,0,51,0.3)]"
                      >
                        {isExecuting ? (
                          <>
                            <RotateCw className="h-3.5 w-3.5 animate-spin" />
                            <span>EXECUTING...</span>
                          </>
                        ) : (
                          <>
                            <Play className="h-3.5 w-3.5 fill-white" />
                            <span>EXECUTE PLAYBOOK</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
