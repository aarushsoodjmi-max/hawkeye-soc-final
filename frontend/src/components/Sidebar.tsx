import React from 'react';
import {
  LayoutDashboard,
  Flame,
  GitCommit,
  Bell,
  Terminal,
  LogOut,
  Radio,
  ChevronRight,
  UserCheck
} from 'lucide-react';
import { UserSession } from '../types';
import { HawkEyeLogo } from './HawkEyeLogo';

interface SidebarProps {
  currentPage: 'dashboard' | 'incident-details' | 'timeline' | 'alerts';
  onNavigate: (page: 'dashboard' | 'incident-details' | 'timeline' | 'alerts', incidentId?: string) => void;
  currentUser: UserSession | null;
  onLogout: () => void;
  onToggleApiDrawer: () => void;
  apiLogCount: number;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
  selectedIncidentId?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  currentUser,
  onLogout,
  onToggleApiDrawer,
  apiLogCount,
  isOpenMobile,
  onCloseMobile
}) => {
  const navItems = [
    {
      id: 'dashboard' as const,
      label: 'HawkEye Overview',
      description: 'Threat pulse & fleet status',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'incident-details' as const,
      label: 'Incident Details',
      description: 'Deep triage & root cause',
      icon: Flame,
      badge: 'INC-8942'
    },
    {
      id: 'timeline' as const,
      label: 'Attack Timeline',
      description: 'MITRE kill-chain breakdown',
      icon: GitCommit,
      badge: '7 Stages'
    },
    {
      id: 'alerts' as const,
      label: 'Alert Telemetry',
      description: 'Live SIEM / EDR stream',
      icon: Bell,
      badge: '10'
    }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          id="sidebar-mobile-backdrop"
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs lg:hidden"
        />
      )}

      <aside
        id="soc-sidebar"
        className={`fixed top-0 bottom-0 left-0 z-40 w-72 flex-col justify-between border-r border-[#1c202a] bg-[#0c0e14] transition-transform duration-200 lg:translate-x-0 ${
          isOpenMobile ? 'translate-x-0 flex' : '-translate-x-full lg:flex'
        }`}
      >
        {/* Top Header / HawkEye Branding */}
        <div className="p-4 border-b border-[#1c202a]">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 flex-shrink-0 rounded-lg bg-[#06070a] border border-red-500/30 p-1 flex items-center justify-center shadow-[0_0_12px_rgba(255,0,51,0.2)]">
              <HawkEyeLogo variant="sidebar" showText={false} className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-slate-100 font-sans">
                  HAWKEYE SOC
                </span>
                <span className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] font-mono font-medium text-red-400 border border-red-500/20">
                  v2.4
                </span>
              </div>
              <p className="text-[10px] text-slate-400 flex items-center gap-1.5 mt-0.5 font-mono">
                <span className="h-1.5 w-1.5 rounded-full bg-red-500 inline-block animate-pulse"></span>
                ACTIVE RADAR ONLINE
              </p>
            </div>
          </div>

          {/* Threat Level Status Pill */}
          <div className="mt-3.5 flex items-center justify-between rounded-lg border border-red-500/25 bg-red-950/30 px-3 py-1.5">
            <div className="flex items-center gap-2">
              <Radio className="h-3.5 w-3.5 text-red-400 animate-pulse" />
              <span className="text-[11px] font-mono font-semibold tracking-wider text-red-300 uppercase">
                DEFCON 2 : ELEVATED
              </span>
            </div>
            <span className="text-[10px] font-mono text-red-400 font-medium">P1 ACTIVE</span>
          </div>
        </div>

        {/* Navigation Menu */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          <div className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-widest text-slate-400 font-mono">
            OPERATIONS CONSOLE
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => {
                  onNavigate(item.id);
                  onCloseMobile?.();
                }}
                className={`group relative flex w-full items-center justify-between rounded-lg px-3 py-2 text-left transition-colors duration-150 cursor-pointer ${
                  isActive
                    ? 'bg-red-950/40 text-red-200 border-l-2 border-red-500 font-medium shadow-[inset_0_0_12px_rgba(255,0,51,0.15)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#141720]'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`flex h-7 w-7 items-center justify-center rounded transition-colors ${
                      isActive
                        ? 'text-red-400'
                        : 'text-slate-400 group-hover:text-slate-300'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                  <div>
                    <div className="text-sm tracking-tight">{item.label}</div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      {item.description}
                    </div>
                  </div>
                </div>

                {item.badge && (
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-medium ${
                      isActive
                        ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                        : 'bg-[#151924] text-slate-400 group-hover:text-slate-300 border border-[#232938]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}

          {/* Telemetry Launcher */}
          <div className="pt-4 px-1 space-y-2">
            <div className="px-1 pb-1 text-[10px] font-semibold uppercase tracking-widest text-slate-400 font-mono">
              SYSTEM CONTROLS
            </div>

            {/* REST API Inspector Launcher */}
            <button
              id="btn-toggle-rest-inspector"
              onClick={onToggleApiDrawer}
              className="flex w-full items-center justify-between rounded-lg border border-[#222836] bg-[#12151e] px-3 py-2 text-left transition hover:bg-[#181d28] hover:border-slate-600 text-slate-300 group cursor-pointer"
            >
              <div className="flex items-center gap-2.5">
                <Terminal className="h-4 w-4 text-red-400" />
                <div>
                  <span className="text-xs font-sans font-medium block text-slate-200">REST API Monitor</span>
                  <span className="text-[10px] text-slate-400 font-mono">Telemetry stream</span>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <span className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] font-mono text-red-300 font-medium border border-red-500/20">
                  {apiLogCount} reqs
                </span>
                <ChevronRight className="h-3.5 w-3.5 text-slate-400 transition-transform group-hover:translate-x-0.5" />
              </div>
            </button>
          </div>
        </div>

        {/* User Clearance / Footer */}
        <div className="border-t border-[#1c202a] p-4 bg-[#080a0f]">
          <div className="mb-3 flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-red-500/25 bg-red-950/40 text-red-300">
              <UserCheck className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-medium text-slate-200 font-mono">
                {currentUser?.callsign || 'SEC-OPERATOR'}
              </div>
              <div className="text-[10px] text-red-400/90 font-mono tracking-tight truncate">
                {currentUser?.clearance || 'TOP SECRET // NOFORN'}
              </div>
            </div>
          </div>

          <button
            id="btn-logout-sidebar"
            onClick={onLogout}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-[#222836] bg-[#12151e] py-1.5 text-xs font-mono font-medium text-slate-300 transition hover:border-red-500/40 hover:bg-red-950/20 hover:text-red-300 cursor-pointer"
          >
            <LogOut className="h-3.5 w-3.5" />
            TERMINATE SESSION
          </button>
        </div>
      </aside>
    </>
  );
};

