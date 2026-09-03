import React, { useState, useEffect } from 'react';
import { Menu, Terminal, Shield, Bell, Radio } from 'lucide-react';
import { UserSession, RestApiLog } from './types';
import { Sidebar } from './components/Sidebar';
import { RestApiDrawer } from './components/RestApiDrawer';
import { SplashScreen } from './components/SplashScreen';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { IncidentDetailsPage } from './pages/IncidentDetailsPage';
import { TimelinePage } from './pages/TimelinePage';
import { AlertsPage } from './pages/AlertsPage';
import { subscribeToApiLogs } from './services/api';

export default function App() {
  // Splash Screen State - displays upon initial load
  const [showSplashScreen, setShowSplashScreen] = useState<boolean>(true);

  // Default session initializes directly to operational state for instant preview
  const [currentUser, setCurrentUser] = useState<UserSession | null>({
    id: 'USR-01',
    name: 'Alexander Reyes',
    email: 'a.reyes@cyberdefense.mil',
    callsign: 'GHOST-LEAD (L3)',
    role: 'Tier 3 Lead Threat Hunter',
    clearance: 'TOP SECRET // NOFORN',
    token: 'simulated_session_token_tier3'
  });

  const [currentPage, setCurrentPage] = useState<
    'login' | 'dashboard' | 'incident-details' | 'timeline' | 'alerts'
  >('dashboard');

  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('INC-8942');
  const [isApiDrawerOpen, setIsApiDrawerOpen] = useState(false);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);
  const [apiLogs, setApiLogs] = useState<RestApiLog[]>([]);

  // Subscribe to real-time REST API events
  useEffect(() => {
    const unsubscribe = subscribeToApiLogs((newLog) => {
      setApiLogs((prev) => [newLog, ...prev.slice(0, 49)]); // Keep last 50 transactions
    });
    return unsubscribe;
  }, []);

  const handleLoginSuccess = (user: UserSession) => {
    setCurrentUser(user);
    setCurrentPage('dashboard');
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setCurrentPage('login');
  };

  const handleNavigate = (
    page: 'dashboard' | 'incident-details' | 'timeline' | 'alerts',
    incidentId?: string
  ) => {
    if (incidentId) {
      setSelectedIncidentId(incidentId);
    }
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // If on login page or unauthenticated
  if (currentPage === 'login' || !currentUser) {
    return (
      <>
        {showSplashScreen && (
          <SplashScreen onComplete={() => setShowSplashScreen(false)} />
        )}
        <LoginPage onLoginSuccess={handleLoginSuccess} />
      </>
    );
  }

  return (
    <div className="min-h-screen bg-[#08090d] text-slate-200 flex flex-col antialiased selection:bg-red-500/25 selection:text-red-200">
      {/* Animated Splash Screen - Plays automatically on initial load & reload */}
      {showSplashScreen && (
        <SplashScreen onComplete={() => setShowSplashScreen(false)} />
      )}

      {/* Sidebar Navigation - Strictly hidden while intro is playing */}
      {!showSplashScreen && (
        <Sidebar
          currentPage={currentPage}
          onNavigate={handleNavigate}
          currentUser={currentUser}
          onLogout={handleLogout}
          onToggleApiDrawer={() => setIsApiDrawerOpen(!isApiDrawerOpen)}
          apiLogCount={apiLogs.length}
          isOpenMobile={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
          selectedIncidentId={selectedIncidentId}
        />
      )}

      {/* Main Content Area */}
      <div className={`${!showSplashScreen ? 'lg:pl-72' : ''} flex-1 flex flex-col min-w-0`}>
        {/* Top Operational Bar */}
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#1c202a] bg-[#0e1017]/90 backdrop-blur-md px-4 sm:px-8">
          <div className="flex items-center gap-4">
            {/* Mobile menu hamburger */}
            <button
              id="btn-mobile-sidebar-toggle"
              onClick={() => setIsMobileSidebarOpen(true)}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-[#181d28] hover:text-white lg:hidden cursor-pointer"
            >
              <Menu className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-100 font-sans">
                HawkEye Security Operations Center
              </h1>
              <span className="hidden sm:inline-flex px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/20 uppercase tracking-wider">
                DEFCON 2 : ELEVATED
              </span>
            </div>
          </div>

          {/* Right Top Status & Tools */}
          <div className="flex items-center gap-3 sm:gap-5">
            {/* REST API Inspector Quick Trigger */}
            <button
              id="btn-topbar-api-monitor"
              onClick={() => setIsApiDrawerOpen(!isApiDrawerOpen)}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-mono transition cursor-pointer ${
                isApiDrawerOpen
                  ? 'border-red-500/40 bg-red-950/40 text-red-300 shadow-[0_0_10px_rgba(255,0,51,0.2)]'
                  : 'border-[#232938] bg-[#12151e] text-slate-300 hover:bg-[#181d28] hover:border-slate-600 hover:text-white'
              }`}
            >
              <Terminal className="h-3.5 w-3.5 text-red-400" />
              <span className="hidden sm:inline font-sans text-[11px] font-medium uppercase tracking-wider">REST Telemetry</span>
              <span className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] font-mono text-red-300 font-medium border border-red-500/20">
                {apiLogs.length}
              </span>
            </button>

            {/* Analyst Avatar Pill */}
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-full bg-red-950/50 border border-red-500/30 flex items-center justify-center text-xs font-semibold text-red-300">
                {currentUser.name
                  .split(' ')
                  .map((n) => n[0])
                  .join('')}
              </div>
              <div className="hidden sm:block text-left">
                <div className="text-xs font-medium text-slate-200 truncate max-w-[120px]">
                  {currentUser.name}
                </div>
                <div className="text-[10px] text-red-400 font-mono">
                  {currentUser.callsign.split(' ')[0]}
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Page Views */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {currentPage === 'dashboard' && (
            <DashboardPage
              onNavigateToIncident={(id) => handleNavigate('incident-details', id)}
              onNavigateToTimeline={(id) => handleNavigate('timeline', id)}
              onNavigateToAlerts={() => handleNavigate('alerts')}
            />
          )}

          {currentPage === 'incident-details' && (
            <IncidentDetailsPage
              incidentId={selectedIncidentId}
              onBackToDashboard={() => handleNavigate('dashboard')}
              onNavigateToTimeline={(id) => handleNavigate('timeline', id)}
            />
          )}

          {currentPage === 'timeline' && (
            <TimelinePage
              initialIncidentId={selectedIncidentId}
              onNavigateToIncident={(id) => handleNavigate('incident-details', id)}
              onBackToDashboard={() => handleNavigate('dashboard')}
            />
          )}

          {currentPage === 'alerts' && (
            <AlertsPage
              onNavigateToIncident={(id) => handleNavigate('incident-details', id)}
              onBackToDashboard={() => handleNavigate('dashboard')}
            />
          )}
        </main>
      </div>

      {/* Floating REST API Live Inspector Drawer */}
      <RestApiDrawer
        isOpen={isApiDrawerOpen}
        onClose={() => setIsApiDrawerOpen(false)}
        logs={apiLogs}
        onClearLogs={() => setApiLogs([])}
      />
    </div>
  );
}
