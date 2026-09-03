import React, { useState } from 'react';
import {
  Search,
  Filter,
  Eye,
  ExternalLink,
  Copy,
  Check,
  X,
  Radio,
  FileCode,
  ShieldCheck,
  AlertCircle
} from 'lucide-react';
import { Alert, AlertStatus, Severity } from '../types';
import { SeverityBadge } from './SeverityBadge';

interface AlertTableProps {
  alerts: Alert[];
  onSelectIncident?: (incidentId: string) => void;
  onUpdateStatus?: (alertId: string, newStatus: AlertStatus) => void;
  isLoading?: boolean;
}

export const AlertTable: React.FC<AlertTableProps> = ({
  alerts,
  onSelectIncident,
  onUpdateStatus,
  isLoading
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<AlertStatus | 'ALL'>('ALL');
  const [inspectAlert, setInspectAlert] = useState<Alert | null>(null);
  const [copiedLog, setCopiedLog] = useState(false);

  // Client-side filtering for immediate snappy responsiveness
  const filteredAlerts = alerts.filter((alert) => {
    const matchesSeverity = selectedSeverity === 'ALL' || alert.severity === selectedSeverity;
    const matchesStatus = selectedStatus === 'ALL' || alert.status === selectedStatus;
    const matchesSearch =
      !searchQuery ||
      alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.sourceIp.includes(searchQuery) ||
      alert.destinationIp.includes(searchQuery) ||
      alert.techniqueId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.category.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesSeverity && matchesStatus && matchesSearch;
  });

  const handleCopyLog = (text?: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedLog(true);
    setTimeout(() => setCopiedLog(false), 2000);
  };

  const getStatusPill = (status: AlertStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-red-500/15 text-red-300 border-red-500/30';
      case 'INVESTIGATING':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/20';
      case 'CONTAINED':
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20';
      case 'RESOLVED':
        return 'bg-slate-800 text-slate-300 border-slate-700/60';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800/50 text-slate-400 border-slate-700/40';
    }
  };

  return (
    <div className="rounded-xl border border-[#1c202a] bg-[#10131b] overflow-hidden shadow-[0_0_15px_rgba(0,0,0,0.5)]">
      {/* Table Toolbar */}
      <div className="border-b border-[#1c202a] px-5 py-3.5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-red-500/30 bg-red-950/40 text-red-400">
              <Radio className="h-4 w-4 animate-pulse" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2 font-sans">
                Alert Telemetry
                <span className="rounded bg-red-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-red-300 border border-red-500/20">
                  {filteredAlerts.length} Active Events
                </span>
              </h3>
              <p className="text-[11px] font-mono text-slate-400">
                Correlated SIEM & EDR telemetry stream (Endpoint, Network, IAM)
              </p>
            </div>
          </div>

          {/* Search & Filter Controls */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Search Input */}
            <div className="relative min-w-[220px] flex-1 sm:flex-none">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                id="alert-search-input"
                type="text"
                placeholder="Filter IP, host, CVE, user..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg border border-[#1c202a] bg-[#0c0e14] py-1.5 pl-9 pr-3 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-red-500 focus:outline-hidden focus:ring-1 focus:ring-red-500/20"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1.5 bg-[#0c0e14] border border-[#1c202a] rounded-lg px-2.5 py-1">
              <Filter className="h-3 w-3 text-slate-400" />
              <select
                id="filter-severity"
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value as any)}
                className="bg-transparent text-xs font-mono text-slate-300 focus:outline-hidden cursor-pointer"
              >
                <option value="ALL" className="bg-[#10131b] text-slate-200">Severity: All</option>
                <option value="CRITICAL" className="bg-[#10131b] text-rose-300">Critical Only</option>
                <option value="HIGH" className="bg-[#10131b] text-amber-300">High</option>
                <option value="MEDIUM" className="bg-[#10131b] text-red-300">Medium</option>
                <option value="LOW" className="bg-[#10131b] text-slate-300">Low</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1.5 bg-[#0c0e14] border border-[#1c202a] rounded-lg px-2.5 py-1">
              <select
                id="filter-status"
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value as any)}
                className="bg-transparent text-xs font-mono text-slate-300 focus:outline-hidden cursor-pointer"
              >
                <option value="ALL" className="bg-[#10131b] text-slate-200">Status: All</option>
                <option value="NEW" className="bg-[#10131b] text-red-300">New</option>
                <option value="INVESTIGATING" className="bg-[#10131b] text-amber-300">Investigating</option>
                <option value="CONTAINED" className="bg-[#10131b] text-emerald-300">Contained</option>
                <option value="RESOLVED" className="bg-[#10131b] text-slate-300">Resolved</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0c0e14] font-sans text-[10px] uppercase tracking-wider text-slate-400 font-semibold border-b border-[#1c202a]">
            <tr>
              <th className="py-3 px-5">Severity</th>
              <th className="py-3 px-5">Alert Details / MITRE</th>
              <th className="py-3 px-5">Target Host & User</th>
              <th className="py-3 px-5">Network Telemetry</th>
              <th className="py-3 px-5">Timestamp</th>
              <th className="py-3 px-5">Status</th>
              <th className="py-3 px-5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1c202a]">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <div className="h-6 w-6 animate-spin rounded-full border-2 border-red-500 border-t-transparent"></div>
                    <span className="font-mono text-xs text-red-400">Querying GET /alerts...</span>
                  </div>
                </td>
              </tr>
            ) : filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500">
                  <AlertCircle className="mx-auto h-8 w-8 text-slate-500 mb-2" />
                  <p className="font-mono text-xs">No correlated security alerts match the active filters.</p>
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alert) => (
                <tr
                  key={alert.id}
                  id={`alert-row-${alert.id}`}
                  className={`group transition-colors hover:bg-[#151924] border-l-2 ${
                    alert.severity === 'CRITICAL'
                      ? 'border-l-rose-500/80 bg-rose-500/5'
                      : 'border-l-transparent'
                  }`}
                >
                  {/* Severity Badge */}
                  <td className="py-3 px-5 whitespace-nowrap">
                    <SeverityBadge severity={alert.severity} size="sm" />
                  </td>

                  {/* Alert title & MITRE */}
                  <td className="py-3 px-5 max-w-sm">
                    <div className="font-medium text-slate-200 group-hover:text-white transition-colors">
                      {alert.title}
                    </div>
                    <div className="mt-1 flex items-center gap-2">
                      <span className="font-mono text-[10px] font-medium text-sky-300 bg-sky-500/10 px-1.5 py-0.5 rounded border border-sky-500/20">
                        {alert.techniqueId}
                      </span>
                      <span className="text-[11px] text-slate-400 truncate">
                        {alert.mitreTechnique}
                      </span>
                    </div>
                  </td>

                  {/* Host & User */}
                  <td className="py-3 px-5 whitespace-nowrap">
                    <div className="font-mono text-xs text-slate-200">{alert.host}</div>
                    <div className="text-[11px] text-slate-400 font-mono truncate">{alert.user}</div>
                  </td>

                  {/* Network flow */}
                  <td className="py-3 px-5 whitespace-nowrap font-mono text-[11px]">
                    <div className="text-slate-300">SRC: {alert.sourceIp}</div>
                    <div className="text-slate-400">DST: {alert.destinationIp}</div>
                  </td>

                  {/* Timestamp */}
                  <td className="py-3 px-5 whitespace-nowrap font-mono text-[11px] text-slate-400">
                    {alert.timestamp}
                  </td>

                  {/* Status Pill */}
                  <td className="py-3 px-5 whitespace-nowrap">
                    <span
                      className={`inline-block rounded border px-2 py-0.5 text-[10px] font-mono uppercase font-medium ${getStatusPill(
                        alert.status
                      )}`}
                    >
                      {alert.status}
                    </span>
                  </td>

                  {/* Actions */}
                  <td className="py-3 px-5 whitespace-nowrap text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        id={`btn-inspect-${alert.id}`}
                        onClick={() => setInspectAlert(alert)}
                        title="Inspect Raw EDR / Sysmon Log"
                        className="rounded-lg border border-slate-700/60 bg-[#121620] p-1.5 text-slate-400 hover:border-sky-500/40 hover:bg-[#1a202c] hover:text-sky-300 transition cursor-pointer"
                      >
                        <Eye className="h-3.5 w-3.5" />
                      </button>

                      {alert.incidentId && onSelectIncident && (
                        <button
                          id={`btn-view-incident-${alert.id}`}
                          onClick={() => onSelectIncident(alert.incidentId!)}
                          title={`Navigate to ${alert.incidentId}`}
                          className="flex items-center gap-1 rounded-lg border border-sky-500/25 bg-sky-500/10 px-2 py-1 text-[11px] font-mono font-medium text-sky-300 hover:bg-sky-500/20 hover:border-sky-400 transition cursor-pointer"
                        >
                          <span>{alert.incidentId}</span>
                          <ExternalLink className="h-3 w-3" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Raw Payload Inspection Modal */}
      {inspectAlert && (
        <div
          id="alert-inspect-modal"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
        >
          <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-[#070b14] shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 p-4">
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-indigo-500/30 bg-indigo-950/50 text-indigo-300">
                  <FileCode className="h-4 w-4" />
                </div>
                <div>
                  <h4 className="text-base font-bold text-white flex items-center gap-2 font-sans">
                    Raw Telemetry Inspection
                    <SeverityBadge severity={inspectAlert.severity} size="sm" />
                  </h4>
                  <p className="text-[11px] font-mono text-slate-500">
                    {inspectAlert.id} // {inspectAlert.category}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setInspectAlert(null)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 space-y-3 max-h-[70vh] overflow-y-auto">
              <div>
                <span className="text-xs font-mono uppercase text-slate-500 block mb-1">
                  Alert Title & Description
                </span>
                <p className="text-sm font-medium text-slate-200 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                  {inspectAlert.title}
                </p>
              </div>

              {/* Host & Network Details Grid */}
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Target Endpoint</span>
                  <span className="text-indigo-300 font-semibold">{inspectAlert.host}</span>
                  <div className="text-slate-400 text-[11px] mt-0.5">User: {inspectAlert.user}</div>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">MITRE ATT&CK</span>
                  <span className="text-indigo-300 font-semibold">{inspectAlert.techniqueId}</span>
                  <div className="text-slate-400 text-[11px] mt-0.5 truncate">{inspectAlert.mitreTechnique}</div>
                </div>
              </div>

              {/* Raw Sysmon / EDR Log payload */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono uppercase text-slate-500">
                    Raw EDR / SIEM Sysmon Record
                  </span>
                  <button
                    onClick={() => handleCopyLog(inspectAlert.rawLog)}
                    className="flex items-center gap-1 text-[11px] font-mono text-indigo-400 hover:text-indigo-300 cursor-pointer"
                  >
                    {copiedLog ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
                    {copiedLog ? 'Copied' : 'Copy Log'}
                  </button>
                </div>
                <pre className="p-3 bg-[#03060d] border border-slate-800 rounded-lg font-mono text-[11px] text-green-400/90 whitespace-pre-wrap break-all select-all overflow-x-auto">
                  {inspectAlert.rawLog || 'Raw telemetry payload not indexed.'}
                </pre>
              </div>

              {/* Quick Status Setter */}
              {onUpdateStatus && (
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-500">Update Alert Status:</span>
                  <div className="flex gap-1.5">
                    {(['INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'] as AlertStatus[]).map(
                      (st) => (
                        <button
                          key={st}
                          onClick={() => {
                            onUpdateStatus(inspectAlert.id, st);
                            setInspectAlert({ ...inspectAlert, status: st });
                          }}
                          className={`px-2 py-1 rounded text-[10px] font-mono border transition cursor-pointer ${
                            inspectAlert.status === st
                              ? 'bg-indigo-600 text-white border-indigo-500 font-bold'
                              : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200'
                          }`}
                        >
                          {st}
                        </button>
                      )
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="border-t border-slate-800 bg-slate-900/40 p-3 flex justify-between items-center">
              {inspectAlert.incidentId && onSelectIncident ? (
                <button
                  onClick={() => {
                    const incId = inspectAlert.incidentId!;
                    setInspectAlert(null);
                    onSelectIncident(incId);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono font-bold uppercase tracking-wider transition cursor-pointer"
                >
                  <span>Open Incident {inspectAlert.incidentId}</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </button>
              ) : (
                <span />
              )}
              <button
                onClick={() => setInspectAlert(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
