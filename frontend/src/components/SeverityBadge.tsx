import React from 'react';
import { Severity } from '../types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showDot = true,
}) => {
  const configs: Record<
    Severity,
    {
      bg: string;
      text: string;
      border: string;
      dotBg: string;
      glowClass: string;
    }
  > = {
    CRITICAL: {
      bg: 'bg-rose-500/10',
      text: 'text-rose-300',
      border: 'border-rose-500/20',
      dotBg: 'bg-rose-400',
      glowClass: '',
    },
    HIGH: {
      bg: 'bg-amber-500/10',
      text: 'text-amber-300',
      border: 'border-amber-500/20',
      dotBg: 'bg-amber-400',
      glowClass: '',
    },
    MEDIUM: {
      bg: 'bg-sky-500/10',
      text: 'text-sky-300',
      border: 'border-sky-500/20',
      dotBg: 'bg-sky-400',
      glowClass: '',
    },
    LOW: {
      bg: 'bg-slate-800/80',
      text: 'text-slate-300',
      border: 'border-slate-700/60',
      dotBg: 'bg-slate-400',
      glowClass: '',
    },
    INFO: {
      bg: 'bg-slate-800/40',
      text: 'text-slate-400',
      border: 'border-slate-700/40',
      dotBg: 'bg-slate-500',
      glowClass: '',
    },
  };

  const current = configs[severity] || configs.INFO;

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 gap-1.5 font-medium',
    md: 'text-xs px-2.5 py-0.5 gap-1.5 font-medium',
    lg: 'text-sm px-3 py-1 gap-2 font-medium',
  };

  return (
    <span
      id={`severity-badge-${severity.toLowerCase()}`}
      className={`inline-flex items-center rounded border tracking-wider font-mono uppercase whitespace-nowrap transition-colors duration-150 ${current.bg} ${current.text} ${current.border} ${sizeClasses[size]}`}
    >
      {showDot && (
        <span
          className={`h-1.5 w-1.5 rounded-full shrink-0 ${current.dotBg}`}
        />
      )}
      {severity}
    </span>
  );
};
