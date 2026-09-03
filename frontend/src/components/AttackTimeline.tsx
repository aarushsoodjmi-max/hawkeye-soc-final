import React, { useState, useEffect } from 'react';
import {
  GitCommit,
  Clock,
  Terminal,
  Shield,
  Copy,
  Check,
  Play,
  Pause,
  RotateCcw,
  ChevronRight,
  Filter,
  CheckCircle,
  ExternalLink,
  Zap,
  Lock,
  Radio,
  Server
} from 'lucide-react';
import { TimelineEvent, Severity } from '../types';
import { SeverityBadge } from './SeverityBadge';

interface AttackTimelineProps {
  events: TimelineEvent[];
  incidentTitle?: string;
  incidentId?: string;
}

export const AttackTimeline: React.FC<AttackTimelineProps> = ({
  events,
  incidentTitle = 'Kerberoasting & Domain Compromise Attack Sequence',
  incidentId = 'INC-8942'
}) => {
  const [selectedTactic, setSelectedTactic] = useState<string>('ALL');
  const [expandedEventId, setExpandedEventId] = useState<string | null>(events[0]?.id || null);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);

  // Attack Replay simulation
  const [activePlaybackStep, setActivePlaybackStep] = useState<number | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    let timer: any;
    if (isPlaying) {
      timer = setInterval(() => {
        setActivePlaybackStep((prev) => {
          if (prev === null || prev >= events.length - 1) {
            setIsPlaying(false);
            return 0;
          }
          const next = prev + 1;
          setExpandedEventId(events[next].id);
          return next;
        });
      }, 1600);
    }
    return () => clearInterval(timer);
  }, [isPlaying, events]);

  const handleStartReplay = () => {
    setActivePlaybackStep(0);
    setExpandedEventId(events[0]?.id || null);
    setIsPlaying(true);
  };

  const handlePauseReplay = () => {
    setIsPlaying(false);
  };

  const handleResetReplay = () => {
    setIsPlaying(false);
    setActivePlaybackStep(null);
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIoc(id);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  // Tactics list for filter
  const tactics = ['ALL', ...Array.from(new Set(events.map((e) => e.tactic)))];

  const filteredEvents = selectedTactic === 'ALL'
    ? events
    : events.filter((e) => e.tactic === selectedTactic);

  return (
    <div className="space-y-5">
      {/* Top Banner & Attack Kill Chain Replay Bar */}
      <div className="rounded-xl border border-[#1c202a] bg-[#10131b] p-5 shadow-[0_0_15px_rgba(0,0,0,0.5)]">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-red-500/10 px-2 py-0.5 text-xs font-mono font-medium text-red-300 border border-red-500/20">
                {incidentId}
              </span>
              <h2 className="text-lg font-bold tracking-tight text-slate-100 font-sans">
                Interactive Attack Timeline & MITRE Kill-Chain
              </h2>
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1">
              Chronological forensic reconstruction from initial exploit to lateral staging
            </p>
          </div>

          {/* Kill Chain Playback Controller */}
          <div className="flex items-center gap-2 bg-[#0c0e14] border border-[#1c202a] rounded-lg p-1.5 self-start md:self-center">
            <span className="text-[11px] font-mono text-slate-400 px-2 uppercase">
              Replay Attack:
            </span>
            {isPlaying ? (
              <button
                id="btn-pause-replay"
                onClick={handlePauseReplay}
                className="flex items-center gap-1 px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white text-xs font-sans font-medium uppercase tracking-wider transition cursor-pointer"
              >
                <Pause className="h-3.5 w-3.5" />
                <span>Pause</span>
              </button>
            ) : (
              <button
                id="btn-start-replay"
                onClick={handleStartReplay}
                className="flex items-center gap-1 px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-sans font-medium uppercase tracking-wider transition cursor-pointer shadow-[0_0_10px_rgba(255,0,51,0.3)]"
              >
                <Play className="h-3.5 w-3.5 fill-white" />
                <span>Play Sequence</span>
              </button>
            )}

            <button
              id="btn-reset-replay"
              onClick={handleResetReplay}
              title="Reset Replay"
              className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-[#10131b] transition cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Step dots horizontal indicator */}
        <div className="mt-4 pt-3 border-t border-[#1c202a] overflow-x-auto pb-1">
          <div className="flex items-center justify-between min-w-[500px] gap-2">
            {events.map((ev, index) => {
              const isCurrent = activePlaybackStep === index || expandedEventId === ev.id;
              const isPassed = activePlaybackStep !== null && index < activePlaybackStep;
              return (
                <button
                  key={ev.id}
                  onClick={() => {
                    setExpandedEventId(ev.id);
                    setActivePlaybackStep(index);
                  }}
                  className={`group flex-1 flex flex-col items-center gap-1.5 text-center transition cursor-pointer`}
                >
                  <div className="flex items-center w-full">
                    <div
                      className={`h-0.5 flex-1 ${
                        index === 0 ? 'opacity-0' : isPassed ? 'bg-red-500' : 'bg-[#1c202a]'
                      }`}
                    />
                    <div
                      className={`h-6 w-6 rounded-full border flex items-center justify-center text-[10px] font-mono font-medium transition-all ${
                        isCurrent
                          ? 'border-red-400 bg-red-500/20 text-red-200 ring-2 ring-red-500/30'
                          : isPassed
                          ? 'border-red-500/50 bg-red-500/10 text-red-300'
                          : 'border-[#1c202a] bg-[#0c0e14] text-slate-400 group-hover:border-slate-600'
                      }`}
                    >
                      {index + 1}
                    </div>
                    <div
                      className={`h-0.5 flex-1 ${
                        index === events.length - 1
                          ? 'opacity-0'
                          : isPassed || isCurrent
                          ? 'bg-red-500/40'
                          : 'bg-[#1c202a]'
                      }`}
                    />
                  </div>
                  <span
                    className={`text-[10px] font-mono truncate max-w-[80px] ${
                      isCurrent ? 'text-red-300 font-medium' : 'text-slate-400'
                    }`}
                  >
                    {ev.tactic}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Filter by Tactic */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <Filter className="h-3.5 w-3.5 text-slate-400 shrink-0 ml-1" />
        <span className="text-xs font-mono text-slate-400 shrink-0">Filter Tactic:</span>
        {tactics.map((tac) => (
          <button
            key={tac}
            onClick={() => setSelectedTactic(tac)}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono border whitespace-nowrap transition cursor-pointer ${
              selectedTactic === tac
                ? 'bg-red-600 text-white border-red-500 font-medium shadow-[0_0_10px_rgba(255,0,51,0.3)]'
                : 'bg-[#0c0e14] text-slate-400 border-[#1c202a] hover:border-slate-600 hover:text-slate-200'
            }`}
          >
            {tac}
          </button>
        ))}
      </div>

      {/* Vertical Connective Timeline */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-[#1c202a]">
        {filteredEvents.map((evt, idx) => {
          const isExpanded = expandedEventId === evt.id;
          const isHighlighted = activePlaybackStep !== null && events[activePlaybackStep]?.id === evt.id;

          return (
            <div
              key={evt.id}
              id={`timeline-node-${evt.id}`}
              className={`relative rounded-xl border transition-all duration-200 ${
                isHighlighted
                  ? 'border-red-400 bg-[#10131b] shadow-[0_0_12px_rgba(255,0,51,0.3)]'
                  : isExpanded
                  ? 'border-red-500/40 bg-[#10131b] shadow-xs'
                  : 'border-[#1c202a] bg-[#10131b] hover:border-slate-600'
              }`}
            >
              {/* Node Marker on vertical line */}
              <div
                className={`absolute -left-[31px] top-4.5 flex h-5 w-5 items-center justify-center rounded-full border text-[9px] font-mono font-medium transition-all ${
                  isHighlighted
                    ? 'border-red-300 bg-red-500 text-white'
                    : isExpanded
                    ? 'border-red-400 bg-[#0c0e14] text-red-300 ring-2 ring-red-500/30'
                    : 'border-[#1c202a] bg-[#0c0e14] text-slate-400'
                }`}
              >
                {evt.phaseOrder}
              </div>

              {/* Event Header Card */}
              <div
                onClick={() => setExpandedEventId(isExpanded ? null : evt.id)}
                className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 p-4 cursor-pointer select-none"
              >
                <div className="flex items-start sm:items-center gap-3">
                  <SeverityBadge severity={evt.severity} size="sm" />
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm text-slate-100">{evt.title}</span>
                      <span className="rounded bg-red-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-red-300 border border-red-500/20">
                        {evt.techniqueId} : {evt.technique}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 mt-1">
                      <span className="flex items-center gap-1 text-slate-300">
                        <Clock className="h-3 w-3 text-red-400" />
                        {evt.timestamp} ({evt.relativeTime})
                      </span>
                      <span>Confidence: {evt.evidenceConfidence}%</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  <span className="rounded bg-[#0c0e14] px-2 py-0.5 text-[10px] font-mono text-slate-400 border border-[#1c202a]">
                    Phase {evt.phaseOrder}
                  </span>
                  <ChevronRight
                    className={`h-4 w-4 text-slate-400 transition-transform ${
                      isExpanded ? 'rotate-90' : ''
                    }`}
                  />
                </div>
              </div>

              {/* Expanded Forensic Details */}
              {isExpanded && (
                <div className="border-t border-[#1c202a] p-4 space-y-3 bg-[#0c0e14] rounded-b-xl">
                  {/* Description */}
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {evt.description}
                  </p>

                  {/* Flow Vector */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-[#10131b] border border-[#1c202a]">
                      <span className="text-[10px] uppercase text-slate-400 block">Threat Source</span>
                      <span className="text-rose-400 font-medium break-all">{evt.source}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#10131b] border border-[#1c202a]">
                      <span className="text-[10px] uppercase text-slate-400 block">Target Asset</span>
                      <span className="text-red-300 font-medium break-all">{evt.target}</span>
                    </div>
                  </div>

                  {/* Raw Command / Execution Payload */}
                  {evt.command && (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="flex items-center gap-1.5 text-[11px] font-mono uppercase text-slate-400">
                          <Terminal className="h-3 w-3 text-red-400" />
                          Forensic Command Artifact
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(evt.command!, `cmd-${evt.id}`);
                          }}
                          className="flex items-center gap-1 text-[10px] font-mono text-red-400 hover:text-red-300 cursor-pointer"
                        >
                          {copiedIoc === `cmd-${evt.id}` ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          <span>Copy</span>
                        </button>
                      </div>
                      <pre className="p-2.5 rounded-lg bg-[#08090d] border border-[#1c202a] font-mono text-[11px] text-red-300 whitespace-pre-wrap break-all select-all">
                        <code>{evt.command}</code>
                      </pre>
                    </div>
                  )}

                  {/* IOC Indicator Badge */}
                  {evt.ioc && (
                    <div className="flex items-center justify-between p-2 rounded-lg bg-red-500/5 border border-red-500/20">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[9px] font-mono text-red-200 font-medium">
                          IOC: {evt.ioc.type}
                        </span>
                        <span className="text-xs font-mono text-red-300 truncate max-w-sm sm:max-w-md">
                          {evt.ioc.value}
                        </span>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopy(evt.ioc!.value, `ioc-${evt.id}`);
                        }}
                        className="text-red-400 hover:text-red-200 p-1 cursor-pointer"
                        title="Copy IOC"
                      >
                        {copiedIoc === `ioc-${evt.id}` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
