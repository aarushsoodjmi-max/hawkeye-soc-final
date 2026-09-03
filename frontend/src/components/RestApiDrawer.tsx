import React, { useState } from 'react';
import { Terminal, X, Check, Trash2, ArrowUpRight, Copy } from 'lucide-react';
import { RestApiLog } from '../types';

interface RestApiDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  logs: RestApiLog[];
  onClearLogs: () => void;
}

export const RestApiDrawer: React.FC<RestApiDrawerProps> = ({
  isOpen,
  onClose,
  logs,
  onClearLogs
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (content: any, id: string) => {
    navigator.clipboard.writeText(JSON.stringify(content, null, 2));
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const getMethodBadge = (method: string) => {
    switch (method) {
      case 'GET':
        return 'bg-sky-500/10 text-sky-400 border-sky-500/20';
      case 'POST':
        return 'bg-sky-500/20 text-sky-300 border-sky-500/30';
      case 'PUT':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      default:
        return 'bg-[#121620] text-slate-300 border-[#212634]';
    }
  };

  return (
    <div
      id="rest-api-drawer"
      className="fixed bottom-0 right-0 z-50 w-full md:w-[480px] max-h-[85vh] h-[520px] rounded-tl-xl border-t border-l border-[#212634] bg-[#161b24] shadow-2xl flex flex-col animate-in slide-in-from-bottom duration-200"
    >
      {/* Drawer Header */}
      <div className="flex items-center justify-between border-b border-[#212634] p-4 bg-[#121620]">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-400">
            <Terminal className="h-4 w-4" />
          </div>
          <div>
            <span className="text-sm font-semibold tracking-tight text-slate-100 block font-sans">
              Live REST API Monitor
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              Assumed Endpoints: GET /alerts, GET /incidents, GET /incident/:id, POST /analyze
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={onClearLogs}
            title="Clear API Log History"
            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-[#1c2230] transition cursor-pointer"
          >
            <Trash2 className="h-4 w-4" />
          </button>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#1c2230] transition cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Logs Scroll List */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-2.5">
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs text-center p-6">
            <Terminal className="h-8 w-8 text-slate-600 mb-2" />
            <span>No REST transactions recorded yet.</span>
            <span className="text-[10px] text-slate-500 mt-1">
              Trigger actions or filters on the dashboard to view API telemetry.
            </span>
          </div>
        ) : (
          logs.map((log) => (
            <div
              key={log.id}
              className="rounded-lg border border-[#212634] bg-[#121620] p-3 text-xs font-mono space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-medium border ${getMethodBadge(
                      log.method
                    )}`}
                  >
                    {log.method}
                  </span>
                  <span className="text-slate-200 font-medium truncate max-w-[260px]">
                    {log.endpoint}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-medium text-[11px]">{log.status} OK</span>
                  <span className="text-slate-500 text-[10px]">{log.latencyMs}ms</span>
                </div>
              </div>

              {/* Request Payload preview if available */}
              {log.requestBody && (
                <div className="p-2 rounded bg-[#161b24] border border-[#212634] text-[10px] text-sky-300 overflow-x-auto">
                  <div className="text-slate-400 uppercase text-[9px] mb-0.5 font-medium">Payload Body:</div>
                  <pre>{JSON.stringify(log.requestBody, null, 2)}</pre>
                </div>
              )}

              {/* Response Preview */}
              {log.responsePreview && (
                <div className="flex items-center justify-between text-[10px] text-slate-400 pt-0.5">
                  <span className="truncate max-w-[320px]">
                    Response: {JSON.stringify(log.responsePreview)}
                  </span>
                  <button
                    onClick={() => handleCopy(log.responsePreview, log.id)}
                    className="flex items-center gap-0.5 text-sky-400 hover:text-sky-300 cursor-pointer"
                    title="Copy response JSON"
                  >
                    {copiedId === log.id ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  </button>
                </div>
              )}

              <div className="text-[9px] text-slate-500 text-right">{log.timestamp}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
