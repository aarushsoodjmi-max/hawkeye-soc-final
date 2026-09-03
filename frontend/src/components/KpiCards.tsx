import React from 'react';
import {
  AlertTriangle,
  Clock,
  Zap,
  Activity,
  ArrowUpRight,
  ArrowDownRight
} from 'lucide-react';
import { KpiMetrics } from '../types';

interface KpiCardsProps {
  metrics: KpiMetrics;
  onNavigateToIncidents?: () => void;
  onNavigateToAlerts?: () => void;
}

export const KpiCards: React.FC<KpiCardsProps> = ({
  metrics,
  onNavigateToIncidents,
  onNavigateToAlerts
}) => {
  const cards = [
    {
      id: 'kpi-active-incidents',
      title: 'Active Incidents',
      value: metrics.activeIncidents.toString(),
      valueColor: 'text-white',
      subValue: '1 Critical P1 • 1 High',
      change: '+1 escalation',
      isPositive: false,
      badgeText: 'CRITICAL',
      badgeClass: 'bg-rose-500/10 text-rose-300 border border-rose-500/20',
      action: onNavigateToIncidents,
      bars: [30, 45, 60, 85, 100, 75]
    },
    {
      id: 'kpi-critical-alerts',
      title: 'Critical Alerts (24h)',
      value: metrics.criticalAlerts.toString(),
      valueColor: 'text-slate-100',
      subValue: 'Requiring immediate triage',
      change: '+3 in last 2 hrs',
      isPositive: false,
      badgeText: 'P1 QUEUE',
      badgeClass: 'bg-amber-500/10 text-amber-300 border border-amber-500/20',
      action: onNavigateToAlerts,
      bars: [40, 60, 50, 80, 70, 90]
    },
    {
      id: 'kpi-mttd',
      title: 'Mean Time to Detect',
      value: `${metrics.mttdMinutes}m`,
      valueColor: 'text-slate-100',
      subValue: 'SLA target: < 15.0m',
      change: '-24% vs baseline',
      isPositive: true,
      badgeText: 'OPTIMAL',
      badgeClass: 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20',
      bars: [90, 75, 60, 45, 30, 20]
    },
    {
      id: 'kpi-mttr',
      title: 'Mean Time to Remediate',
      value: `${metrics.mttrMinutes}m`,
      valueColor: 'text-slate-100',
      subValue: 'Automated containment active',
      change: '-12% improvement',
      isPositive: true,
      badgeText: 'CONTAINED',
      badgeClass: 'bg-red-500/10 text-red-300 border border-red-500/20',
      bars: [80, 70, 65, 50, 40, 35]
    }
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => {
        return (
          <div
            key={card.id}
            id={card.id}
            onClick={card.action}
            className={`bg-[#10131b] border border-[#1c202a] rounded-xl p-5 flex flex-col justify-between hover:border-red-500/30 hover:bg-[#131722] transition-all duration-150 ${
              card.action ? 'cursor-pointer group' : ''
            }`}
          >
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                  {card.title}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-medium tracking-wider ${card.badgeClass}`}>
                  {card.badgeText}
                </span>
              </div>
              <div className="mt-2.5 flex items-baseline justify-between">
                <div className={`text-3xl font-bold font-sans tracking-tight ${card.valueColor}`}>
                  {card.value}
                </div>
                {/* Mini telemetry sparkline */}
                <div className="opacity-30 flex items-end space-x-1 h-5">
                  {card.bars.map((bar, i) => (
                    <div
                      key={i}
                      className="w-1 bg-red-400 rounded-t-xs"
                      style={{ height: `${bar}%` }}
                    />
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-[#1c202a] flex items-center justify-between text-xs">
              <span className="text-slate-400 text-[11px] truncate max-w-[130px]">
                {card.subValue}
              </span>
              <span
                className={`flex items-center gap-0.5 text-[11px] font-medium ${
                  card.isPositive ? 'text-emerald-400' : 'text-rose-400'
                }`}
              >
                {card.isPositive ? (
                  <ArrowDownRight className="h-3 w-3" />
                ) : (
                  <ArrowUpRight className="h-3 w-3" />
                )}
                {card.change}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
