import React, { useState, useEffect } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, Loader2, Info, ArrowRight, Activity, Globe, LayoutDashboard, Target, FileText, Settings, Menu, BarChart3, Grid } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { HeatmapWithWAF } from './components/HeatmapWithWAF';

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
      case 'High': return 'text-[var(--color-jade-green)]';
      case 'Medium': return 'text-[var(--color-marigold)]';
      case 'Low': return 'text-[var(--color-charcoal)] opacity-60';
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
    <div className="min-h-screen flex overflow-hidden selection:bg-[var(--color-fuchsia)] selection:text-white">
      
      {/* Sidebar */}
      <aside className={`motif-sidebar transition-all duration-300 ease-in-out ${sidebarOpen ? 'w-64' : 'w-20'} flex flex-col hidden md:flex`}>
        <div className="h-20 flex items-center justify-center border-b-2 border-[var(--color-marigold)]/30 relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-[var(--color-marigold)] flex items-center justify-center border-2 border-sand">
              <Shield className="w-7 h-7 text-[var(--color-peacock-blue)]" />
            </div>
            {sidebarOpen && <h1 className="font-display font-bold text-3xl tracking-wide text-sand">Aegis</h1>}
          </div>
        </div>
        
        <nav className="flex-1 py-8 px-4 space-y-3 relative z-10">
          <button onClick={() => setCurrentView('dashboard')} className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200 ${currentView === 'dashboard' ? 'bg-[var(--color-marigold)] text-[var(--color-peacock-blue)] shadow-lg' : 'hover:bg-sand/10 text-sand/80 hover:text-sand'}`}>
            <LayoutDashboard className={`w-6 h-6`} />
            {sidebarOpen && <span className="font-bold text-lg">Dashboard</span>}
          </button>
          <button onClick={() => setCurrentView('targets')} className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200 ${currentView === 'targets' ? 'bg-[var(--color-marigold)] text-[var(--color-peacock-blue)] shadow-lg' : 'hover:bg-sand/10 text-sand/80 hover:text-sand'}`}>
            <Target className={`w-6 h-6`} />
            {sidebarOpen && <span className="font-bold text-lg">Targets</span>}
          </button>
          <button onClick={() => setCurrentView('vulnerabilities')} className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200 ${currentView === 'vulnerabilities' ? 'bg-[var(--color-marigold)] text-[var(--color-peacock-blue)] shadow-lg' : 'hover:bg-sand/10 text-sand/80 hover:text-sand'}`}>
            <FileText className={`w-6 h-6`} />
            {sidebarOpen && <span className="font-bold text-lg">Vulnerabilities</span>}
          </button>
          <button onClick={() => setCurrentView('oob')} className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200 ${currentView === 'oob' ? 'bg-[var(--color-marigold)] text-[var(--color-peacock-blue)] shadow-lg' : 'hover:bg-sand/10 text-sand/80 hover:text-sand'}`}>
            <Activity className={`w-6 h-6`} />
            {sidebarOpen && <span className="font-bold text-lg">Callbacks</span>}
          </button>
          <button onClick={() => setCurrentView('analytics')} className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all duration-200 ${currentView === 'analytics' ? 'bg-[var(--color-marigold)] text-[var(--color-peacock-blue)] shadow-lg' : 'hover:bg-sand/10 text-sand/80 hover:text-sand'}`}>
            <BarChart3 className={`w-6 h-6`} />
            {sidebarOpen && <span className="font-bold text-lg">Analytics</span>}
          </button>
        </nav>

        <div className="p-4 border-t-2 border-[var(--color-marigold)]/30 relative z-10">
          <div className="flex items-center gap-4 px-4 py-2">
            <div className="w-3 h-3 rounded-full bg-[var(--color-jade-green)] animate-pulse shadow-lg"></div>
            {sidebarOpen && <span className="text-sm font-semibold text-sand/90">System Online</span>}
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-screen overflow-y-auto relative bg-sand">
        {/* Header */}
        <header className="h-20 border-b border-[var(--color-peacock-blue)]/10 bg-sand/80 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between px-8">
          <div className="flex items-center gap-4">
            <button onClick={() => setSidebarOpen(!sidebarOpen)} className="p-2 rounded-lg hover:bg-[var(--color-peacock-blue)]/10 text-[var(--color-peacock-blue)] hidden md:block">
              <Menu className="w-6 h-6" />
            </button>
            <h2 className="font-display font-bold text-2xl text-[var(--color-peacock-blue)]">Threat Intelligence Dashboard</h2>
          </div>
          <div className="flex items-center gap-4">
             <div className="text-md font-semibold text-[var(--color-charcoal)]/60 hidden sm:block">
               AI-Powered Security Orchestration
             </div>
          </div>
        </header>

        <div className="p-8 max-w-7xl mx-auto w-full">
          {currentView === 'dashboard' && (
            <>
              {/* Input Section */}
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="mb-12 bg-white/50 rounded-2xl p-10 border border-[var(--color-peacock-blue)]/20 shadow-xl relative overflow-hidden artisan-card"
              >

            <div className="max-w-4xl relative z-10">
              <h2 className="text-5xl font-display font-bold text-[var(--color-peacock-blue)] mb-4">Start a New Scan</h2>
              <p className="text-[var(--color-charcoal)]/70 mb-8 text-xl">
                Enter a URL to begin the advanced reconnaissance and vulnerability analysis process.
              </p>

              <form onSubmit={startScan} className="relative flex items-center">
                <div className="absolute inset-y-0 left-6 flex items-center pointer-events-none">
                  <Globe className="w-7 h-7 text-[var(--color-peacock-blue)]/50" />
                </div>
                <input
                  type="url"
                  required
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={isScanning}
                  className="w-full bg-sand border-2 border-[var(--color-peacock-blue)]/20 rounded-xl py-5 pl-16 pr-48 text-[var(--color-peacock-blue)] text-lg placeholder:text-[var(--color-peacock-blue)]/50 focus:outline-none focus:border-[var(--color-marigold)] focus:ring-4 focus:ring-[var(--color-marigold)]/20 transition-all disabled:opacity-50 font-semibold"
                />
                <button
                  type="submit"
                  disabled={isScanning || !url}
                  className="rangoli-btn absolute right-2 top-2 bottom-2 px-10 font-bold text-lg flex items-center gap-3 disabled:opacity-60 disabled:cursor-not-allowed shadow-lg"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-6 h-6 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      Launch Scan
                      <ArrowRight className="w-6 h-6" />
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
                      <h3 className="text-[var(--color-peacock-blue)] font-display font-bold text-3xl mb-1">Scan Progress</h3>
                      <p className="text-[var(--color-charcoal)]/80 text-xl font-semibold flex items-center gap-3">
                        {session.status === 'Completed' ? (
                          <CheckCircle className="w-6 h-6 text-[var(--color-jade-green)]" />
                        ) : session.status === 'Failed' ? (
                          <AlertTriangle className="w-6 h-6 text-[var(--color-terracotta)]" />
                        ) : (
                          <Activity className="w-6 h-6 text-[var(--color-marigold)] animate-pulse" />
                        )}
                        {session.status}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex gap-12 text-center md:text-right">
                    <div>
                      <div className="text-5xl font-display font-bold text-[var(--color-peacock-blue)]">
                        {session.endpoints?.length || 0}
                      </div>
                      <div className="text-md text-[var(--color-charcoal)]/60 uppercase tracking-widest font-bold mt-1">
                        Endpoints
                      </div>
                    </div>
                    {session.status === 'Completed' && (
                      <div>
                        <div className="text-5xl font-display font-bold text-[var(--color-fuchsia)]">
                          {session.vulnerabilities.length}
                        </div>
                        <div className="text-md text-[var(--color-charcoal)]/60 uppercase tracking-widest font-bold mt-1">
                          Findings
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Error State */}
                {session.error && (
                  <div className="bg-[var(--color-terracotta)]/10 border-2 border-[var(--color-terracotta)]/30 rounded-xl p-6 text-[var(--color-terracotta)] flex items-start gap-4">
                    <AlertTriangle className="w-8 h-8 shrink-0 mt-1" />
                    <div>
                      <h4 className="font-display font-bold text-xl mb-1 text-charcoal">Scan Failed</h4>
                      <p className="font-semibold opacity-90 text-charcoal/80">{session.error}</p>
                    </div>
                  </div>
                )}

                {/* Results */}
                {session.status === 'Completed' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between border-b-2 border-[var(--color-peacock-blue)]/10 pb-4">
                      <h3 className="text-3xl font-display font-bold text-[var(--color-peacock-blue)]">Vulnerability Analysis Report</h3>
                      <div className="flex gap-4">
                        <span className="px-5 py-2 rounded-full badge-critical text-md font-bold tracking-wide">
                          {session.vulnerabilities.filter(v => v.severity === 'Critical').length} Critical
                        </span>
                        <span className="px-5 py-2 rounded-full badge-high text-md font-bold tracking-wide">
                          {session.vulnerabilities.filter(v => v.severity === 'High').length} High
                        </span>
                      </div>
                    </div>

                    {session.vulnerabilities.length === 0 ? (
                      <div className="artisan-card p-16 text-center">
                        <CheckCircle className="w-20 h-20 text-[var(--color-jade-green)] mx-auto mb-6 opacity-80" />
                        <h4 className="text-3xl font-display font-bold text-[var(--color-peacock-blue)] mb-3">No Vulnerabilities Found</h4>
                        <p className="text-[var(--color-charcoal)]/70 text-lg max-w-lg mx-auto">The scan completed successfully without detecting any vulnerabilities.</p>
                      </div>
                    ) : (
                      <div className="grid gap-6">
                        {session.vulnerabilities.map((vuln, idx) => (
                          <motion.div 
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.05 }}
                            key={idx} 
                            className="artisan-card p-8"
                          >
                            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-6">
                              <div>
                                <div className="flex flex-wrap items-center gap-4 mb-4">
                                  <span className={`px-4 py-1.5 rounded-lg text-sm font-bold uppercase tracking-wider ${getSeverityBadge(vuln.severity)}`}>
                                    {vuln.severity}
                                  </span>
                                  {vuln.confidence && (
                                    <span className={`text-md font-bold ${getConfidenceColor(vuln.confidence)} flex items-center gap-2 bg-sand/80 px-4 py-1.5 rounded-lg border border-charcoal/10`}>
                                      <Shield className="w-5 h-5" />
                                      {vuln.confidence} Confidence
                                    </span>
                                  )}
                                </div>
                                <h4 className="text-2xl font-display font-bold text-[var(--color-peacock-blue)] mb-2">{vuln.type}</h4>
                                <div className="font-mono text-md text-[var(--color-charcoal)]/60 break-all bg-sand px-4 py-2 rounded-lg border border-peacock-blue/10 inline-block">
                                  {vuln.url}
                                </div>
                              </div>
                            </div>
                            
                            <div className="space-y-6">
                              <div className="bg-sand/70 rounded-xl p-5 border border-peacock-blue/10">
                                <h5 className="text-[var(--color-peacock-blue)] font-bold mb-2 flex items-center gap-3 text-lg">
                                  <Info className="w-6 h-6 text-[var(--color-marigold)]" />
                                  AI-Powered Analysis
                                </h5>
                                <p className="text-[var(--color-charcoal)]/80 leading-relaxed text-md">{vuln.explanation}</p>
                              </div>
                              
                              {vuln.poc && (
                                <div>
                                  <h5 className="text-[var(--color-peacock-blue)] font-bold mb-2 px-1 text-lg">Proof of Concept</h5>
                                  <div className="bg-[var(--color-charcoal)] rounded-xl p-4 font-mono text-md text-[var(--color-marigold)] overflow-x-auto shadow-inner">
                                    {vuln.poc}
                                  </div>
                                </div>
                              )}

                              <div>
                                <h5 className="text-[var(--color-peacock-blue)] font-bold mb-2 px-1 text-lg">Suggested Remediation</h5>
                                <p className="text-[var(--color-charcoal)]/90 leading-relaxed bg-[var(--color-jade-green)]/10 p-5 rounded-xl border border-[var(--color-jade-green)]/20">
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
              <h2 className="text-4xl font-display font-bold text-[var(--color-peacock-blue)] mb-6">Scan History</h2>
              <div className="grid gap-5">
                {targets.map(target => (
                  <div key={target.id} className="artisan-card p-6 flex items-center justify-between">
                    <div>
                      <h3 className="text-2xl font-bold font-mono text-[var(--color-peacock-blue)]">{target.url}</h3>
                      <p className="text-md text-[var(--color-charcoal)]/60 mt-1">Last scanned: {new Date(target.last_scan_at).toLocaleString()}</p>
                      {target.waf_detected === 1 && (
                        <span className="inline-block mt-3 px-4 py-1.5 bg-[var(--color-marigold)]/20 text-[var(--color-marigold)] text-sm font-bold rounded-full border border-[var(--color-marigold)]/30">
                          WAF Detected: {target.waf_name || 'Unknown'}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                {targets.length === 0 && (
                  <div className="text-center p-16 text-[var(--color-charcoal)]/50 artisan-card">No targets scanned yet.</div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'vulnerabilities' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <h2 className="text-4xl font-display font-bold text-[var(--color-peacock-blue)] mb-6">All Vulnerabilities</h2>
              <div className="grid gap-5">
                {allVulnerabilities.map(vuln => (
                  <div key={vuln.id} className="artisan-card p-6">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <div className="flex items-center gap-3 mb-3">
                           <span className={`px-4 py-1.5 rounded-lg text-sm font-bold uppercase tracking-wider ${getSeverityBadge(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                          <span className={`px-4 py-1.5 rounded-lg text-sm font-bold uppercase tracking-wider ${vuln.status === 'open' ? 'bg-terracotta/20 text-terracotta' : 'bg-jade-green/20 text-jade-green'}`}>
                            {vuln.status}
                          </span>
                        </div>
                        <h3 className="text-2xl font-display font-bold text-[var(--color-peacock-blue)]">{vuln.type}</h3>
                      </div>
                      <div className="text-right">
                        <div className="text-sm text-[var(--color-charcoal)]/60">First seen: {new Date(vuln.discovered_at).toLocaleDateString()}</div>
                        <div className="text-sm text-[var(--color-charcoal)]/60">Last seen: {new Date(vuln.last_seen_at).toLocaleDateString()}</div>
                        {vuln.closed_at && (
                          <div className="text-sm text-jade-green/80 font-medium mt-1">Closed: {new Date(vuln.closed_at).toLocaleDateString()}</div>
                        )}
                      </div>
                    </div>
                    <div className="font-mono text-md bg-sand p-3 rounded-lg border border-peacock-blue/10 mb-4 break-all">
                      {vuln.target_url}
                    </div>
                    <div className="flex justify-between items-end">
                      {vuln.fingerprint && (
                        <div className="text-xs text-[var(--color-charcoal)]/40 font-mono mb-2">
                          Fingerprint: {vuln.fingerprint}
                        </div>
                      )}
                      <button 
                        onClick={() => toggleVulnStatus(vuln.id, vuln.status)}
                        className={`px-5 py-2 rounded-lg text-sm font-bold transition-colors shadow-sm ${vuln.status === 'open' ? 'bg-[var(--color-jade-green)] text-white hover:bg-[var(--color-jade-green)]/90' : 'bg-white border border-charcoal/20 text-charcoal hover:bg-gray-50'}`}
                      >
                        {vuln.status === 'open' ? 'Mark as Resolved' : 'Reopen Issue'}
                      </button>
                    </div>
                  </div>
                ))}
                {allVulnerabilities.length === 0 && (
                  <div className="text-center p-16 text-[var(--color-charcoal)]/50 artisan-card">No vulnerabilities found across all scans.</div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'oob' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <h2 className="text-4xl font-display font-bold text-[var(--color-peacock-blue)] mb-6">Out-of-Band (OOB) Callbacks</h2>
              <div className="grid gap-5">
                {oobHits.map(hit => (
                  <div key={hit.id} className="artisan-card p-6 border-l-8 border-[var(--color-fuchsia)]">
                    <div className="flex justify-between items-start mb-2">
                      <h3 className="text-2xl font-display font-bold text-[var(--color-peacock-blue)]">{hit.vuln_type} Confirmed</h3>
                      <span className="text-sm text-[var(--color-charcoal)]/50 font-semibold">{new Date(hit.hit_at).toLocaleString()}</span>
                    </div>
                    <div className="font-mono text-md bg-sand p-3 rounded-lg border border-peacock-blue/10 mb-3 break-all">
                      {hit.target_url}
                    </div>
                    <p className="text-md text-[var(--color-charcoal)]/80 font-semibold">
                      <strong>Parameter:</strong> {hit.parameter} <br/>
                      <strong>Source IP:</strong> {hit.source_ip}
                    </p>
                  </div>
                ))}
                {oobHits.length === 0 && (
                  <div className="text-center p-16 text-[var(--color-charcoal)]/50 artisan-card">No OOB callbacks have been received.</div>
                )}
              </div>
            </motion.div>
          )}

          {currentView === 'analytics' && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
              <h2 className="text-4xl font-display font-bold text-[var(--color-peacock-blue)] mb-6">Threat Intelligence Analytics</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* Time to Fix Card */}
                <div className="artisan-card p-8">
                  <h3 className="text-2xl font-bold text-[var(--color-peacock-blue)] mb-6 flex items-center gap-3">
                    <BarChart3 className="w-6 h-6 text-[var(--color-marigold)]" />
                    Average Time to Remediate
                  </h3>
                  <div className="space-y-4">
                    {timeToFixStats.length > 0 ? (
                      timeToFixStats.map(stat => (
                        <div key={stat.severity} className="flex items-center justify-between gap-4">
                          <span className={`px-3 py-1 rounded-md text-xs font-bold uppercase tracking-wider w-24 text-center ${getSeverityBadge(stat.severity)}`}>
                            {stat.severity}
                          </span>
                          <div className="flex-1 h-3 bg-sand rounded-full overflow-hidden border border-peacock-blue/10">
                            <div 
                              className={`h-full bg-gradient-to-r from-marigold to-fuchsia`}
                              style={{ width: `${Math.min((stat.avg_days_to_fix / 30) * 100, 100)}%` }}
                            />
                          </div>
                          <span className="font-mono font-bold text-[var(--color-peacock-blue)] w-16 text-right text-lg">
                            {Math.round(stat.avg_days_to_fix * 10) / 10}d
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="text-md text-charcoal/50 text-center py-4">
                        No remediated vulnerabilities yet.
                      </div>
                    )}
                  </div>
                </div>

                {/* Trends Card */}
                <div className="artisan-card p-8">
                  <h3 className="text-2xl font-bold text-[var(--color-peacock-blue)] mb-6 flex items-center gap-3">
                    <Activity className="w-6 h-6 text-[var(--color-marigold)]" />
                    Monthly Vulnerability Trends
                  </h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center border-b-2 border-peacock-blue/10 pb-3">
                      <span className="text-sm font-bold text-charcoal/70">Month</span>
                      <div className="flex gap-6 text-sm font-bold">
                        <span className="text-terracotta">New</span>
                        <span className="text-jade-green">Resolved</span>
                      </div>
                    </div>
                    {trendStats.new.length > 0 || trendStats.resolved.length > 0 ? (
                      // Combine and sort months
                      Array.from(new Set([...trendStats.new.map(t => t.month), ...trendStats.resolved.map(t => t.month)])).sort().map(month => {
                        const newCount = trendStats.new.find(t => t.month === month)?.count || 0;
                        const resolvedCount = trendStats.resolved.find(t => t.month === month)?.count || 0;
                        return (
                          <div key={month} className="flex justify-between items-center">
                            <span className="font-mono text-md text-[var(--color-peacock-blue)] font-semibold">{month}</span>
                            <div className="flex gap-6 font-mono text-lg font-bold">
                              <span className="text-terracotta w-10 text-right">{newCount}</span>
                              <span className="text-jade-green w-10 text-right">{resolvedCount}</span>
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <div className="text-md text-charcoal/50 text-center py-4">
                        Not enough data to display trends.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Heatmaps */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="artisan-card p-8">
                  <h3 className="text-2xl font-bold text-[var(--color-peacock-blue)] mb-4 flex items-center gap-3">
                    <Grid className="w-6 h-6 text-[var(--color-marigold)]" />
                    Severity vs Confidence
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left">
                      <thead>
                        <tr>
                          <th className="p-2 border-b-2 border-peacock-blue/10 text-charcoal/70 font-bold">Severity</th>
                          {['High', 'Medium', 'Low'].map(conf => (
                            <th key={conf} className="p-2 border-b-2 border-peacock-blue/10 text-center text-charcoal/70 font-bold">{conf}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {['Critical', 'High', 'Medium', 'Low'].map(sev => (
                          <tr key={sev}>
                            <td className="p-2 border-b border-peacock-blue/5 font-bold text-[var(--color-peacock-blue)]">{sev}</td>
                            {['High', 'Medium', 'Low'].map(conf => {
                              const count = severityConfidenceHeatmap[sev]?.[conf] || 0;
                              const intensity = Math.min(count / 10, 1);
                              return (
                                <td key={conf} className="p-1 border-b border-peacock-blue/5">
                                  <div 
                                    className="w-full h-12 rounded-lg flex items-center justify-center font-mono text-lg font-bold transition-colors"
                                    style={{ 
                                      background: count > 0 ? `linear-gradient(135deg, var(--color-fuchsia), var(--color-marigold))`: 'transparent',
                                      opacity: count > 0 ? 0.1 + intensity * 0.9 : 0.2,
                                      color: 'white',
                                    }}
                                  >
                                    {count > 0 ? count : ''}
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

                <div className="artisan-card p-8">
                  <h3 className="text-2xl font-bold text-[var(--color-peacock-blue)] mb-4 flex items-center gap-3">
                    <Grid className="w-6 h-6 text-[var(--color-marigold)]" />
                    Target vs Vulnerability Type
                  </h3>
                  <div className="overflow-x-auto">
                    {Object.keys(targetTypeHeatmap).length > 0 ? (
                      <table className="w-full text-sm text-left">
                        <thead>
                          <tr>
                            <th className="p-2 border-b-2 border-peacock-blue/10 text-charcoal/70 font-bold">Target</th>
                            {Array.from(new Set(Object.values(targetTypeHeatmap).flatMap(types => Object.keys(types)))).map(type => (
                              <th key={type} className="p-2 border-b-2 border-peacock-blue/10 text-center text-charcoal/70 font-bold">{type}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {Object.keys(targetTypeHeatmap).map(target => {
                            const types = Array.from(new Set(Object.values(targetTypeHeatmap).flatMap(t => Object.keys(t))));
                            return (
                              <tr key={target}>
                                <td className="p-2 border-b border-peacock-blue/5 font-mono text-xs text-[var(--color-peacock-blue)] truncate max-w-[150px]" title={target}>
                                  {target.replace(/^https?:\/\//, '')}
                                </td>
                                {types.map(type => {
                                  const count = targetTypeHeatmap[target]?.[type] || 0;
                                  const intensity = Math.min(count / 5, 1);
                                  return (
                                    <td key={type} className="p-1 border-b border-peacock-blue/5">
                                      <div 
                                        className="w-full h-12 rounded-lg flex items-center justify-center font-mono text-lg font-bold transition-colors"
                                        style={{ 
                                          backgroundColor: count > 0 ? `rgba(0, 168, 150, ${0.1 + intensity * 0.9})` : 'transparent',
                                          color: 'white',
                                        }}
                                      >
                                        {count > 0 ? count : ''}
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
                      <div className="text-md text-charcoal/50 text-center py-4">
                        No vulnerability data available for targets.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="artisan-card p-8 mt-8">
                <HeatmapWithWAF />
              </div>

            </motion.div>
          )}
        </div>
      </main>
    </div>
  );
}
