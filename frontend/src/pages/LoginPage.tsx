import React, { useState } from 'react';
import {
  KeyRound,
  Lock,
  UserCheck,
  ChevronRight,
  Shield,
  Terminal,
  Cpu,
  Radio
} from 'lucide-react';
import { UserSession } from '../types';
import { HawkEyeLogo } from '../components/HawkEyeLogo';

interface LoginPageProps {
  onLoginSuccess: (user: UserSession) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('a.reyes@cyberdefense.mil');
  const [password, setPassword] = useState('••••••••••••');
  const [mfaCode, setMfaCode] = useState('894-201');
  const [selectedRole, setSelectedRole] = useState<'L3' | 'L2' | 'L1'>('L3');
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  const demoAccounts: Record<'L3' | 'L2' | 'L1', UserSession> = {
    L3: {
      id: 'USR-01',
      name: 'Alexander Reyes',
      email: 'a.reyes@cyberdefense.mil',
      callsign: 'GHOST-LEAD (L3)',
      role: 'Tier 3 Lead Threat Hunter',
      clearance: 'TOP SECRET // NOFORN',
      token: 'simulated_session_token_tier3'
    },
    L2: {
      id: 'USR-02',
      name: 'Maya Chen',
      email: 'm.chen@cyberdefense.mil',
      callsign: 'SPECTRE-02 (L2)',
      role: 'Tier 2 Incident Responder',
      clearance: 'SECRET // DEF',
      token: 'simulated_session_token_tier2'
    },
    L1: {
      id: 'USR-03',
      name: 'Kellan Novak',
      email: 'k.novak@cyberdefense.mil',
      callsign: 'SENTINEL-04 (L1)',
      role: 'Tier 1 Triage Analyst',
      clearance: 'CONFIDENTIAL',
      token: 'simulated_session_token_tier1'
    }
  };

  const handleSelectDemo = (tier: 'L3' | 'L2' | 'L1') => {
    setSelectedRole(tier);
    const acc = demoAccounts[tier];
    setUsername(acc.email);
    setPassword('••••••••••••');
    setMfaCode(tier === 'L3' ? '894-201' : tier === 'L2' ? '552-198' : '330-812');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsAuthenticating(true);

    setTimeout(() => {
      setIsAuthenticating(false);
      onLoginSuccess(demoAccounts[selectedRole]);
    }, 600);
  };

  return (
    <div className="min-h-screen w-full bg-[#08090d] flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Crimson ambient glow */}
      <div className="absolute top-1/3 left-1/3 h-96 w-96 rounded-full bg-red-950/20 blur-3xl pointer-events-none" />

      {/* Main Login Card */}
      <div className="w-full max-w-md rounded-xl border border-[#1f2533] bg-[#10131b] p-8 shadow-[0_0_25px_rgba(0,0,0,0.8)] relative z-10">
        {/* Top HawkEye Brand Logo */}
        <div className="flex flex-col items-center text-center mb-5">
          <div className="w-full max-w-[280px] mb-2">
            <HawkEyeLogo variant="login" showText={true} />
          </div>
          <p className="text-[11px] font-mono text-red-400/90 tracking-tight flex items-center gap-1.5 mt-1">
            <Radio className="h-3 w-3 text-red-500 animate-pulse" />
            SECURITY OPERATIONS COMMAND // AUTH CONSOLE
          </p>
        </div>

        {/* Operational Security Notice */}
        <div className="mb-5 rounded-lg border border-red-500/20 bg-red-950/20 px-3 py-2 text-center">
          <p className="text-[10px] font-mono text-red-300 tracking-wide">
            OPERATIONAL DEFENSE ENVIRONMENT — Authenticated Session & Role-Based Access Control Active.
          </p>
        </div>

        {/* Security Clearance Quick Selector */}
        <div className="mb-6 space-y-2">
          <label className="text-[11px] font-mono uppercase text-slate-400 font-medium block">
            Select Analyst Profile (Quick Load):
          </label>
          <div className="grid grid-cols-3 gap-2">
            {(['L3', 'L2', 'L1'] as const).map((tier) => (
              <button
                key={tier}
                type="button"
                id={`btn-select-tier-${tier.toLowerCase()}`}
                onClick={() => handleSelectDemo(tier)}
                className={`py-2 px-1 rounded-lg text-center border font-mono transition cursor-pointer ${
                  selectedRole === tier
                    ? 'border-red-500 bg-red-950/40 text-red-200 ring-1 ring-red-500/40 font-medium shadow-[0_0_10px_rgba(255,0,51,0.2)]'
                    : 'border-[#1f2533] bg-[#0c0e14] text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                <div className="text-xs font-semibold">{tier} Lead</div>
                <div className="text-[9px] text-slate-400 truncate">
                  {tier === 'L3' ? 'Hunter' : tier === 'L2' ? 'Responder' : 'Triage'}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">
              Analyst Identity (CAC / PIV / Email)
            </label>
            <div className="relative">
              <UserCheck className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
              <input
                id="login-input-email"
                type="email"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-lg border border-[#1f2533] bg-[#0c0e14] py-2.5 pl-10 pr-3 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-red-500 focus:outline-hidden focus:ring-1 focus:ring-red-500"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">
              Cryptographic Passphrase
            </label>
            <div className="relative">
              <KeyRound className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
              <input
                id="login-input-password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg border border-[#1f2533] bg-[#0c0e14] py-2.5 pl-10 pr-3 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-red-500 focus:outline-hidden focus:ring-1 focus:ring-red-500"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-mono text-slate-300">
                FIDO2 / Hardware MFA Token
              </label>
              <span className="text-[10px] font-mono text-red-400">YubiKey Active</span>
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-4 w-4 text-slate-500" />
              <input
                id="login-input-mfa"
                type="text"
                required
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="w-full rounded-lg border border-[#1f2533] bg-[#0c0e14] py-2.5 pl-10 pr-3 text-xs font-mono text-red-300 focus:border-red-500 focus:outline-hidden focus:ring-1 focus:ring-red-500"
              />
            </div>
          </div>

          <button
            type="submit"
            id="btn-login-submit"
            disabled={isAuthenticating}
            className="w-full rounded-lg bg-red-600 hover:bg-red-500 py-2.5 text-xs font-sans font-medium tracking-wider text-white shadow-[0_0_15px_rgba(255,0,51,0.3)] uppercase transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-6"
          >
            {isAuthenticating ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                <span>VALIDATING CREDENTIALS & RBAC CLEARANCE...</span>
              </>
            ) : (
              <>
                <span>INITIALIZE SOC SESSION</span>
                <ChevronRight className="h-4 w-4" />
              </>
            )}
          </button>
        </form>

        {/* Security Warning Banner */}
        <div className="mt-6 border-t border-[#1f2533] pt-4 text-center">
          <p className="text-[10px] font-mono text-slate-400 leading-relaxed">
            RESTRICTED SYSTEM • ALL TELEMETRY & ACTIONS LOGGED UNDER 18 U.S.C. § 1030
          </p>
          <div className="mt-2 flex items-center justify-center gap-3 text-[10px] font-mono text-slate-400">
            <span>REST Endpoints: Connected</span>
            <span>•</span>
            <span className="text-red-400">Encrypted Tunnel: Active</span>
          </div>
        </div>
      </div>
    </div>
  );
};

