import React, { useState, useEffect } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, Loader2, Info, ArrowRight, Activity, Globe, LayoutDashboard, Target, FileText, Settings, Menu, BarChart3, Grid } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

type Vulnerability = {
  url: string;
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence?: 'High' | 'Medium' | 'Low';
  explanation: string;
  mitigation: string;
  poc?: string;
};

type ScanSession = {
  id: string;
  url: string;
  status: string;
  endpoints: any[];
  vulnerabilities: Vulnerability[];
  error?: string;
};

export default function App() {
  const [url, setUrl] = useState('');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [session, setSession] = useState<ScanSession | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [currentView, setCurrentView] = useState<'dashboard' | 'targets' | 'oob' | 'vulnerabilities' | 'analytics'>('dashboard');
  const [targets, setTargets] = useState<any[]>([]);
  const [oobHits, setOobHits] = useState<any[]>([]);
  const [allVulnerabilities, setAllVulnerabilities] = useState<any[]>([]);
  const [timeToFixStats, setTimeToFixStats] = useState<any[]>([]);
  const [trendStats, setTrendStats] = useState<{new: any[], resolved: any[]}>({new: [], resolved: []});
  const [severityConfidenceHeatmap, setSeverityConfidenceHeatmap] = useState<Record<string, Record<string, number>>>({});
  const [targetTypeHeatmap, setTargetTypeHeatmap] = useState<Record<string, Record<string, number>>>({});

  const fetchTargets = async () => {
    try {
      const res = await fetch('/api/targets');
      const data = await res.json();
      setTargets(data);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchOobHits = async () => {
    try {
      const res = await fetch('/api/oob-hits');
      const data = await res.json();
      setOobHits(data);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchAllVulnerabilities = async () => {
    try {
      const res = await fetch('/api/vulnerabilities');
      const data = await res.json();
      setAllVulnerabilities(data);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchAnalytics = async () => {
    try {
      const [ttfRes, trendsRes, scHeatmapRes, ttHeatmapRes] = await Promise.all([
        fetch('/api/analytics/time-to-fix'),
        fetch('/api/analytics/trends'),
        fetch('/api/analytics/heatmap/severity-confidence'),
        fetch('/api/analytics/heatmap/target-type')
      ]);
      setTimeToFixStats(await ttfRes.json());
      setTrendStats(await trendsRes.json());
      setSeverityConfidenceHeatmap(await scHeatmapRes.json());
      setTargetTypeHeatmap(await ttHeatmapRes.json());
    } catch (e) {
      console.error(e);
    }
  };

  const toggleVulnStatus = async (id: string, currentStatus: string) => {
    const newStatus = currentStatus === 'open' ? 'closed' : 'open';
    try {
      await fetch(`/api/vulnerabilities/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      fetchAllVulnerabilities();
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    if (currentView === 'targets') fetchTargets();
    if (currentView === 'oob') fetchOobHits();
    if (currentView === 'vulnerabilities') fetchAllVulnerabilities();
    if (currentView === 'analytics') fetchAnalytics();
  }, [currentView]);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsScanning(true);
    setSession(null);
    setSessionId(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (data.sessionId) {
        setSessionId(data.sessionId);
      } else {
        setIsScanning(false);
        alert('Failed to start scan');
      }
    } catch (error) {
      console.error(error);
      setIsScanning(false);
      alert('Error starting scan');
    }
  };

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (sessionId && isScanning) {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`/api/scan/${sessionId}`);
          const data = await res.json();
          setSession(data);
          if (data.status === 'Completed' || data.status === 'Failed') {
            setIsScanning(false);
            clearInterval(interval);
          }
        } catch (error) {
          console.error(error);
        }
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [sessionId, isScanning]);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'badge-critical';
      case 'High': return 'badge-high';
      case 'Medium': return 'badge-medium';
      case 'Low': return 'badge-low';
      default: return 'bg-gray-100 text-gray-600 border border-gray-200';
    }
  };

  const getConfidenceColor = (confidence?: string) => {
    switch (confidence) {
      case 'High': return 'text-[var(--color-emerald-800)]';
      case 'Medium': return 'text-[var(--color-turmeric)]';
      case 'Low': return 'text-[var(--color-indigo-900)] opacity-60';
      default: return 'text-gray-500';
    }
  };

  // Calculate progress for the mandala ring
  let progress = 0;
  if (session) {
    if (session.status === 'Completed') progress = 100;
    else if (session.status === 'Failed') progress = 100;
    else if (session.status.includes('Crawling')) progress = 30;
    else if (session.status.includes('Scanning')) progress = 60;
    else if (session.status.includes('Analyzing')) progress = 85;
    else progress = 10;
  }

  return (
    <div className="min-h-screen flex overflow-hidden selection:bg-[var(--color-saffron)] selection:text-white">
      
      {/* Sidebar */}
      <aside className={`motif-sidebar transition-all duration-300 ease-in-out ${sidebarOpen ? 'w-64' : 'w-20'} flex flex-col hidden md:flex`}>
        <div className="h-20 flex items-center justify-center border-b border-white/10 relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-white/10 flex items-center justify-center border border-white/20">
              <Shield className="w-6 h-6 text-[var(--color-saffron)]" />
            </div>
            {sidebarOpen && <h1 className="font-display font-bold text-2xl tracking-wide text-white">Aegis AI</h1>}
          </div>
        </div>
        
        <nav className="flex-1 py-8 px-4 space-y-2 relative z-10">
          <button onClick={() => setCurrentView('dashboard')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors ${currentView === 'dashboard' ? 'bg-white/10 text-white border border-white/10' : 'hover:bg-white/5 text-white/70 hover:text-white'}`}>
            <LayoutDashboard className={`w-5 h-5 ${currentView === 'dashboard' ? 'text-[var(--color-turmeric)]' : ''}`} />
            {sidebarOpen && <span className="font-medium">Dashboard</span>}
          </button>
          <button onClick={() => setCurrentView('targets')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors ${currentView === 'targets' ? 'bg-white/10 text-white border border-white/10' : 'hover:bg-white/5 text-white/70 hover:text-white'}`}>
            <Target className={`w-5 h-5 ${currentView === 'targets' ? 'text-[var(--color-turmeric)]' : ''}`} />
            {sidebarOpen && <span className="font-medium">Targets History</span>}
          </button>
          <button onClick={() => setCurrentView('vulnerabilities')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors ${currentView === 'vulnerabilities' ? 'bg-white/10 text-white border border-white/10' : 'hover:bg-white/5 text-white/70 hover:text-white'}`}>
            <FileText className={`w-5 h-5 ${currentView === 'vulnerabilities' ? 'text-[var(--color-turmeric)]' : ''}`} />
            {sidebarOpen && <span className="font-medium">Vulnerabilities</span>}
          </button>
          <button onClick={() => setCurrentView('oob')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors ${currentView === 'oob' ? 'bg-white/10 text-white border border-white/10' : 'hover:bg-white/5 text-white/70 hover:text-white'}`}>
            <Activity className={`w-5 h-5 ${currentView === 'oob' ? 'text-[var(--color-turmeric)]' : ''}`} />
            {sidebarOpen && <span className="font-medium">OOB Callbacks</span>}
          </button>
          <button onClick={() => setCurrentView('analytics')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors ${currentView === 'analytics' ? 'bg-white/10 text-white border border-white/10' : 'hover:bg-white/5 text-white/70 hover:text-white'}`}>
            <BarChart3 className={`w-5 h-5 ${currentView === 'analytics' ? 'text-[var(--color-turmeric)]' : ''}`} />
            {sidebarOpen && <span className="font-medium">Analytics</span>}
          </button>
        </nav>

        <div className="p-4 border-t border-white/10 relative z-10">
          <div className="flex items-center gap-3 px-4 py-2">
            <div className="w-2 h-2 rounded-full bg-[var(--color-turmeric)] animate-pulse"></div>
            {sidebarOpen && <span className="text-sm font-medium text-white/80">System Online</span>}
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-screen overflow-y-auto relative">
        {/* Header */}
        <header className="h-20 border-b border-[var(--color-indigo-900)]/10 bg-white/80 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between px-8">
          <div className="flex items-center gap-4">
            <button onClick={() => setSidebarOpen(!sidebarOpen)} className="p-2 rounded-lg hover:bg-[var(--color-indigo-900)]/5 text-[var(--color-indigo-900)] hidden md:block">
              <Menu className="w-5 h-5" />
            </button>
            <h2 className="font-display font-semibold text-xl text-[var(--color-indigo-900)]">Threat Intelligence</h2>
          </div>
          <div className="flex items-center gap-4">
             <div className="text-sm font-medium text-[var(--color-indigo-900)]/60 hidden sm:block">
               Elite AI-Powered Bug Bounty Platform
             </div>
          </div>
        </header>

        <div className="p-8 max-w-6xl mx-auto w-full">
          {currentView === 'dashboard' && (
            <>
              {/* Input Section */}
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="mb-12 bg-white rounded-2xl p-8 border border-[var(--color-indigo-900)]/10 shadow-sm relative overflow-hidden"
              >
            {/* Subtle background motif */}
            <div className="absolute top-0 right-0 w-64 h-64 opacity-5 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle, var(--color-indigo-900) 2px, transparent 2px)', backgroundSize: '20px 20px' }}></div>

            <div className="max-w-3xl relative z-10">
              <h2 className="text-3xl font-display font-bold text-[var(--color-indigo-900)] mb-3">Initiate Reconnaissance</h2>
              <p className="text-[var(--color-indigo-900)]/70 mb-8 text-lg">
                Deploy advanced LLM-augmented vulnerability scanning. Enter a target URL to begin the analysis pipeline.
              </p>

              <form onSubmit={startScan} className="relative flex items-center">
                <div className="absolute inset-y-0 left-5 flex items-center pointer-events-none">
                  <Globe className="w-6 h-6 text-[var(--color-indigo-900)]/40" />
                </div>
                <input
                  type="url"
                  required
                  placeholder="https://target-application.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={isScanning}
                  className="w-full bg-[var(--color-ivory)] border-2 border-[var(--color-indigo-900)]/10 rounded-xl py-5 pl-14 pr-40 text-[var(--color-indigo-900)] text-lg placeholder:text-[var(--color-indigo-900)]/40 focus:outline-none focus:border-[var(--color-saffron)] focus:ring-4 focus:ring-[var(--color-saffron)]/10 transition-all disabled:opacity-50 font-medium"
                />
                <button
                  type="submit"
                  disabled={isScanning || !url}
                  className="rangoli-btn absolute right-3 top-3 bottom-3 px-8 font-semibold text-lg flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed border border-[var(--color-indigo-900)]/20 shadow-sm"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Scanning
                    </>
                  ) : (
                    <>
                      Analyze
                      <ArrowRight className="w-5 h-5" />
                    </>
                  )}
                </button>
              </form>
            </div>
          </motion.div>

          {/* Dashboard / Progress */}
          <AnimatePresence mode="wait">
            {session && (
              <motion.div
                key="dashboard"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-8"
              >
                {/* Status Banner */}
                <div className="artisan-card p-8 flex flex-col md:flex-row items-center justify-between gap-8">
                  <div className="flex items-center gap-8">
                    {/* Mandala Progress */}
                    <div 
                      className="mandala-ring shrink-0" 
                      style={{ '--progress': `${progress}%` } as React.CSSProperties}
                    >
                      <div className="mandala-ring-inner">
                        {progress}%
                      </div>
                    </div>
                    
                    <div>
                      <h3 className="text-[var(--color-indigo-900)] font-display font-bold text-2xl mb-1">Scan Status</h3>
                      <p className="text-[var(--color-indigo-900)]/70 text-lg flex items-center gap-2">
                        {session.status === 'Completed' ? (
                          <CheckCircle className="w-5 h-5 text-[var(--color-emerald-800)]" />
                        ) : session.status === 'Failed' ? (
                          <AlertTriangle className="w-5 h-5 text-[var(--color-crimson)]" />
                        ) : (
                          <Activity className="w-5 h-5 text-[var(--color-saffron)] animate-pulse" />
                        )}
                        {session.status}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex gap-12 text-center md:text-right">
                    <div>
                      <div className="text-4xl font-display font-bold text-[var(--color-indigo-900)]">
                        {session.endpoints?.length || 0}
                      </div>
                      <div className="text-sm text-[var(--color-indigo-900)]/60 uppercase tracking-widest font-semibold mt-1">
                        Endpoints
                      </div>
                    </div>
                    {session.status === 'Completed' && (
                      <div>
                        <div className="text-4xl font-display font-bold text-[var(--color-rani)]">
                          {session.vulnerabilities.length}
                        </div>
                        <div className="text-sm text-[var(--color-indigo-900)]/60 uppercase tracking-widest font-semibold mt-1">
                          Findings
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Error State */}
                {session.error && (
                  <div className="bg-[var(--color-crimson)]/5 border border-[var(--color-crimson)]/20 rounded-xl p-6 text-[var(--color-crimson)] flex items-start gap-4">
                    <AlertTriangle className="w-6 h-6 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-display font-bold text-lg mb-1">Scan Failed</h4>
                      <p className="opacity-90">{session.error}</p>
                    </div>
                  </div>
                )}

                {/* Results */}
                {session.status === 'Completed' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between border-b border-[var(--color-indigo-900)]/10 pb-4">
                      <h3 className="text-2xl font-display font-bold text-[var(--color-indigo-900)]">Vulnerability Report</h3>
                      <div className="flex gap-3">
                        <span className="px-4 py-1.5 rounded-full badge-critical text-sm font-bold tracking-wide">
                          {session.vulnerabilities.filter(v => v.severity === 'Critical').length} Critical
                        </span>
                        <span className="px-4 py-1.5 rounded-full badge-high text-sm font-bold tracking-wide">
                          {session.vulnerabilities.filter(v => v.severity === 'High').length} High
                        </span>
                      </div>
                    </div>

                    {session.vulnerabilities.length === 0 ? (
                      <div className="artisan-card p-16 text-center">
                        <Shield className="w-16 h-16 text-[var(--color-emerald-800)] mx-auto mb-6 opacity-80" />
                        <h4 className="text-2xl font-display font-bold text-[var(--color-indigo-900)] mb-3">No Vulnerabilities Detected</h4>
                        <p className="text-[var(--color-indigo-900)]/70 text-lg max-w-lg mx-auto">The scan completed but did not find any obvious vulnerabilities in the discovered endpoints.</p>
                      </div>
                    ) : (
                      <div className="grid gap-6">
                        {session.vulnerabilities.map((vuln, idx) => (
                          <motion.div 
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.1 }}
                            key={idx} 
                            className="artisan-card p-8"
                          >
                            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-6">
                              <div>
                                <div className="flex flex-wrap items-center gap-3 mb-3">
                                  <span className={`px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${getSeverityBadge(vuln.severity)}`}>
                                    {vuln.severity}
                                  </span>
                                  {vuln.confidence && (
                                    <span className={`text-sm font-bold ${getConfidenceColor(vuln.confidence)} flex items-center gap-1.5 bg-gray-50 px-3 py-1 rounded-md border border-gray-100`}>
                                      <Shield className="w-4 h-4" />
                                      {vuln.confidence} Confidence
                                    </span>
                                  )}
                                </div>
                                <h4 className="text-xl font-display font-bold text-[var(--color-indigo-900)] mb-2">{vuln.type}</h4>
                                <div className="font-mono text-sm text-[var(--color-indigo-900)]/60 break-all bg-[var(--color-ivory)] px-3 py-2 rounded-lg border border-[var(--color-indigo-900)]/5 inline-block">
                                  {vuln.url}
                                </div>
                              </div>
                            </div>
                            
                            <div className="space-y-6">
                              <div className="bg-[var(--color-ivory)]/50 rounded-xl p-5 border border-[var(--color-indigo-900)]/5">
                                <h5 className="text-[var(--color-indigo-900)] font-bold mb-2 flex items-center gap-2">
                                  <Info className="w-5 h-5 text-[var(--color-saffron)]" />
                                  Analysis
                                </h5>
                                <p className="text-[var(--color-indigo-900)]/80 leading-relaxed">{vuln.explanation}</p>
                              </div>
                              
                              {vuln.poc && (
                                <div>
                                  <h5 className="text-[var(--color-indigo-900)] font-bold mb-2 px-1">Proof of Concept</h5>
                                  <div className="bg-[var(--color-indigo-900)] rounded-xl p-4 font-mono text-sm text-[var(--color-turmeric)] overflow-x-auto shadow-inner">
                                    {vuln.poc}
                                  </div>
                                </div>
                              )}

                              <div>
                                <h5 className="text-[var(--color-indigo-900)] font-bold mb-2 px-1">Remediation</h5>
                                <p className="text-[var(--color-indigo-900)]/80 leading-relaxed bg-[var(--color-emerald-800)]/5 p-4 rounded-xl border border-[var(--color-emerald-800)]/10">
                                  {vuln.mitigation}
                                </p>
                              </div>
                            </div>
                          </motion.div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
            </>
          )}

          {currentView === 'targets' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <h2 className="text-3xl font-display font-bold text-[var(--color-indigo-900)] mb-6">Scan History</h2>
              <div className="grid gap-4">
                {targets.map(target => (
                  <div key={target.id} className="artisan-card p-6 flex items-center justify-between">
                    <div>
                      <h3 className="text-xl font-bold text-[var(--color-indigo-900)]">{target.url}</h3>
                      <p className="text-sm text-[var(--color-indigo-900)]/60 mt-1">Last scanned: {new Date(target.last_scan_at).toLocaleString()}</p>
                      {target.waf_detected === 1 && (
                        <span className="inline-block mt-2 px-3 py-1 bg-[var(--color-saffron)]/10 text-[var(--color-saffron)] text-xs font-bold rounded-full">
                          WAF Detected: {target.waf_name || 'Unknown'}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                {targets.length === 0 && (
                  <div className="text-center p-12 text-[var(--color-indigo-900)]/50">No targets scanned yet.</div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'vulnerabilities' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <h2 className="text-3xl font-display font-bold text-[var(--color-indigo-900)] mb-6">All Vulnerabilities</h2>
              <div className="grid gap-4">
                {allVulnerabilities.map(vuln => (
                  <div key={vuln.id} className="artisan-card p-6">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className={`px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${getSeverityBadge(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                          <span className={`px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${vuln.status === 'open' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                            {vuln.status}
                          </span>
                        </div>
                        <h3 className="text-xl font-bold text-[var(--color-indigo-900)]">{vuln.type}</h3>
                      </div>
                      <div className="text-right">
                        <div className="text-sm text-[var(--color-indigo-900)]/60">First seen: {new Date(vuln.discovered_at).toLocaleDateString()}</div>
                        <div className="text-sm text-[var(--color-indigo-900)]/60">Last seen: {new Date(vuln.last_seen_at).toLocaleDateString()}</div>
                        {vuln.closed_at && (
                          <div className="text-sm text-green-700/80 font-medium mt-1">Closed: {new Date(vuln.closed_at).toLocaleDateString()}</div>
                        )}
                      </div>
                    </div>
                    <div className="font-mono text-sm bg-[var(--color-ivory)] p-3 rounded border border-[var(--color-indigo-900)]/10 mb-4 break-all">
                      {vuln.target_url}
                    </div>
                    <div className="flex justify-between items-end">
                      {vuln.fingerprint && (
                        <div className="text-xs text-[var(--color-indigo-900)]/40 font-mono mb-2">
                          Fingerprint: {vuln.fingerprint}
                        </div>
                      )}
                      <button 
                        onClick={() => toggleVulnStatus(vuln.id, vuln.status)}
                        className={`px-4 py-2 rounded-lg text-sm font-bold transition-colors ${vuln.status === 'open' ? 'bg-[var(--color-emerald-800)] text-white hover:bg-[var(--color-emerald-800)]/90' : 'bg-white border border-[var(--color-indigo-900)]/20 text-[var(--color-indigo-900)] hover:bg-gray-50'}`}
                      >
                        {vuln.status === 'open' ? 'Mark as Closed' : 'Reopen'}
                      </button>
                    </div>
                  </div>
                ))}
                {allVulnerabilities.length === 0 && (
                  <div className="text-center p-12 text-[var(--color-indigo-900)]/50">No vulnerabilities found.</div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'oob' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <h2 className="text-3xl font-display font-bold text-[var(--color-indigo-900)] mb-6">Out-of-Band (OOB) Callbacks</h2>
              <div className="grid gap-4">
                {oobHits.map(hit => (
                  <div key={hit.id} className="artisan-card p-6 border-l-4 border-[var(--color-crimson)]">
                    <div className="flex justify-between items-start mb-2">
                      <h3 className="text-lg font-bold text-[var(--color-indigo-900)]">{hit.vuln_type} Confirmed</h3>
                      <span className="text-xs text-[var(--color-indigo-900)]/50">{new Date(hit.hit_at).toLocaleString()}</span>
                    </div>
                    <div className="font-mono text-sm bg-[var(--color-ivory)] p-3 rounded border border-[var(--color-indigo-900)]/10 mb-2 break-all">
                      {hit.target_url}
                    </div>
                    <p className="text-sm text-[var(--color-indigo-900)]/70">
                      <strong>Parameter:</strong> {hit.parameter} <br/>
                      <strong>Source IP:</strong> {hit.source_ip}
                    </p>
                  </div>
                ))}
                {oobHits.length === 0 && (
                  <div className="text-center p-12 text-[var(--color-indigo-900)]/50">No OOB callbacks received yet.</div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'analytics' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
              <h2 className="text-3xl font-display font-bold text-[var(--color-indigo-900)] mb-6">Threat Intelligence Analytics</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Time to Fix Card */}
                <div className="artisan-card p-6">
                  <h3 className="text-xl font-bold text-[var(--color-indigo-900)] mb-4 flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-[var(--color-turmeric)]" />
                    Average Time to Fix (Days)
                  </h3>
                  <div className="space-y-4">
                    {timeToFixStats.length > 0 ? (
                      timeToFixStats.map(stat => (
                        <div key={stat.severity} className="flex items-center justify-between">
                          <span className={`px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${getSeverityBadge(stat.severity)}`}>
                            {stat.severity}
                          </span>
                          <div className="flex items-center gap-4">
                            <div className="w-32 h-2 bg-gray-100 rounded-full overflow-hidden">
                              <div 
                                className={`h-full ${stat.severity === 'Critical' ? 'bg-red-500' : stat.severity === 'High' ? 'bg-orange-500' : stat.severity === 'Medium' ? 'bg-yellow-500' : 'bg-blue-500'}`}
                                style={{ width: `${Math.min((stat.avg_days_to_fix / 30) * 100, 100)}%` }}
                              />
                            </div>
                            <span className="font-mono font-bold text-[var(--color-indigo-900)] w-12 text-right">
                              {Math.round(stat.avg_days_to_fix * 10) / 10}d
                            </span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-sm text-[var(--color-indigo-900)]/50 text-center py-4">
                        No closed vulnerabilities yet to calculate time-to-fix.
                      </div>
                    )}
                  </div>
                </div>

                {/* Trends Card */}
                <div className="artisan-card p-6">
                  <h3 className="text-xl font-bold text-[var(--color-indigo-900)] mb-4 flex items-center gap-2">
                    <Activity className="w-5 h-5 text-[var(--color-turmeric)]" />
                    Vulnerability Trends
                  </h3>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center border-b border-[var(--color-indigo-900)]/10 pb-2">
                      <span className="text-sm font-medium text-[var(--color-indigo-900)]/70">Month</span>
                      <div className="flex gap-4 text-sm font-bold">
                        <span className="text-red-600">New</span>
                        <span className="text-green-600">Resolved</span>
                      </div>
                    </div>
                    {trendStats.new.length > 0 || trendStats.resolved.length > 0 ? (
                      // Combine and sort months
                      Array.from(new Set([...trendStats.new.map(t => t.month), ...trendStats.resolved.map(t => t.month)])).sort().map(month => {
                        const newCount = trendStats.new.find(t => t.month === month)?.count || 0;
                        const resolvedCount = trendStats.resolved.find(t => t.month === month)?.count || 0;
                        return (
                          <div key={month} className="flex justify-between items-center">
                            <span className="font-mono text-sm text-[var(--color-indigo-900)]">{month}</span>
                            <div className="flex gap-4 font-mono text-sm">
                              <span className="text-red-600 w-8 text-right">{newCount}</span>
                              <span className="text-green-600 w-8 text-right">{resolvedCount}</span>
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <div className="text-sm text-[var(--color-indigo-900)]/50 text-center py-4">
                        Not enough data to show trends.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Heatmaps */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Severity x Confidence Heatmap */}
                <div className="artisan-card p-6">
                  <h3 className="text-xl font-bold text-[var(--color-indigo-900)] mb-4 flex items-center gap-2">
                    <Grid className="w-5 h-5 text-[var(--color-turmeric)]" />
                    Severity vs Confidence
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left">
                      <thead>
                        <tr>
                          <th className="p-2 border-b border-[var(--color-indigo-900)]/10 text-[var(--color-indigo-900)]/70 font-medium">Severity \ Confidence</th>
                          {['High', 'Medium', 'Low'].map(conf => (
                            <th key={conf} className="p-2 border-b border-[var(--color-indigo-900)]/10 text-center text-[var(--color-indigo-900)]/70 font-medium">{conf}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {['Critical', 'High', 'Medium', 'Low'].map(sev => (
                          <tr key={sev}>
                            <td className="p-2 border-b border-[var(--color-indigo-900)]/5 font-medium text-[var(--color-indigo-900)]">{sev}</td>
                            {['High', 'Medium', 'Low'].map(conf => {
                              const count = severityConfidenceHeatmap[sev]?.[conf] || 0;
                              // Calculate intensity based on count (max 10 for example)
                              const intensity = Math.min(count / 10, 1);
                              return (
                                <td key={conf} className="p-1 border-b border-[var(--color-indigo-900)]/5">
                                  <div 
                                    className="w-full h-10 rounded flex items-center justify-center font-mono text-xs transition-colors"
                                    style={{ 
                                      backgroundColor: count > 0 ? `rgba(220, 38, 38, ${0.1 + intensity * 0.9})` : 'rgba(0,0,0,0.02)',
                                      color: count > 5 ? 'white' : 'var(--color-indigo-900)',
                                      fontWeight: count > 0 ? 'bold' : 'normal'
                                    }}
                                  >
                                    {count > 0 ? count : '-'}
                                  </div>
                                </td>
                              );
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Target x Type Heatmap */}
                <div className="artisan-card p-6">
                  <h3 className="text-xl font-bold text-[var(--color-indigo-900)] mb-4 flex items-center gap-2">
                    <Grid className="w-5 h-5 text-[var(--color-turmeric)]" />
                    Target vs Vulnerability Type
                  </h3>
                  <div className="overflow-x-auto">
                    {Object.keys(targetTypeHeatmap).length > 0 ? (
                      <table className="w-full text-sm text-left">
                        <thead>
                          <tr>
                            <th className="p-2 border-b border-[var(--color-indigo-900)]/10 text-[var(--color-indigo-900)]/70 font-medium">Target</th>
                            {/* Extract all unique vulnerability types */}
                            {Array.from(new Set(Object.values(targetTypeHeatmap).flatMap(types => Object.keys(types)))).map(type => (
                              <th key={type} className="p-2 border-b border-[var(--color-indigo-900)]/10 text-center text-[var(--color-indigo-900)]/70 font-medium">{type}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {Object.keys(targetTypeHeatmap).map(target => {
                            const types = Array.from(new Set(Object.values(targetTypeHeatmap).flatMap(t => Object.keys(t))));
                            return (
                              <tr key={target}>
                                <td className="p-2 border-b border-[var(--color-indigo-900)]/5 font-mono text-xs text-[var(--color-indigo-900)] truncate max-w-[150px]" title={target}>
                                  {target.replace(/^https?:\/\//, '')}
                                </td>
                                {types.map(type => {
                                  const count = targetTypeHeatmap[target]?.[type] || 0;
                                  const intensity = Math.min(count / 10, 1);
                                  return (
                                    <td key={type} className="p-1 border-b border-[var(--color-indigo-900)]/5">
                                      <div 
                                        className="w-full h-10 rounded flex items-center justify-center font-mono text-xs transition-colors"
                                        style={{ 
                                          backgroundColor: count > 0 ? `rgba(242, 125, 38, ${0.1 + intensity * 0.9})` : 'rgba(0,0,0,0.02)',
                                          color: count > 5 ? 'white' : 'var(--color-indigo-900)',
                                          fontWeight: count > 0 ? 'bold' : 'normal'
                                        }}
                                      >
                                        {count > 0 ? count : '-'}
                                      </div>
                                    </td>
                                  );
                                })}
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    ) : (
                      <div className="text-sm text-[var(--color-indigo-900)]/50 text-center py-4">
                        No vulnerability data available for targets.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </main>
    </div>
  );
}
