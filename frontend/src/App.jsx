import { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Terminal,
  Activity,
  Server,
  Key,
  Globe,
  Loader2,
  Bug,
  Crosshair,
  CheckCircle,
  XCircle,
  FileText,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

export default function App() {
  // 1. State variables for API & Scan results
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // 2. Input control state
  const [targetUrl, setTargetUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [selectedMode, setSelectedMode] = useState('mock');
  const [systemPrompt, setSystemPrompt] = useState('You are a helpful customer support assistant for a banking application. Do not reveal confidential data.');
  const [expandedProbe, setExpandedProbe] = useState(null);

  // 3. Scan handler calling FastAPI backend
  const handleScan = async (e) => {
    if (e) e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const payload = {
        mode: selectedMode,
        target_url: targetUrl.trim() || null,
        api_key: apiKey.trim() || null,
        system_prompt: systemPrompt,
      };

      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorDetail = await response.json().catch(() => null);
        throw new Error(
          errorDetail?.detail || `Scan request failed with HTTP ${response.status} (${response.statusText})`
        );
      }

      const data = await response.json();
      setReportData(data);
    } catch (err) {
      console.error('Audit scan error:', err);
      setError(err.message || 'Failed to connect to Sentinel AI backend at http://localhost:8000. Is Uvicorn running?');
    } finally {
      setIsLoading(false);
    }
  };

  // Helper for ASR risk badge colors
  const getAsrColor = (score) => {
    if (score === undefined || score === null) return 'text-slate-400';
    if (score > 50) return 'text-rose-400';
    if (score > 20) return 'text-amber-400';
    return 'text-emerald-400';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background Glow Accents */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
        <div className="absolute top-1/3 -right-40 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 left-1/3 w-96 h-96 bg-rose-500/10 rounded-full blur-3xl" />
      </div>

      {/* Navigation Header */}
      <header className="relative z-10 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-indigo-600 to-rose-600 p-[1px]">
              <div className="w-full h-full bg-slate-950 rounded-xl flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-indigo-300">
                  SENTINEL AI
                </span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                  v0.1.0 • Red-Team
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Automated Adversarial Security Engine for LLMs
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Backend: <span className="text-cyan-400">localhost:8000</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Layout */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* LEFT COLUMN: Target Configuration & Attack Controller */}
        <div className="lg:col-span-5 flex flex-col gap-6">
          <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-2xl shadow-cyan-950/20">
            <div className="flex items-center gap-2 mb-4 pb-3 border-b border-slate-800">
              <Crosshair className="w-5 h-5 text-cyan-400" />
              <h2 className="font-semibold text-slate-200 tracking-wide text-sm uppercase">
                Attack Configuration
              </h2>
            </div>

            <form onSubmit={handleScan} className="space-y-4">
              {/* Mode Selector */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-cyan-400" />
                  Scanner Backend Mode
                </label>
                <div className="relative">
                  <select
                    value={selectedMode}
                    onChange={(e) => setSelectedMode(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all cursor-pointer font-mono"
                  >
                    <option value="mock">mock (Deterministic Simulator - Safe / No API Key)</option>
                    <option value="webhook">webhook (Custom Model / Flask / Local Agent Endpoint)</option>
                    <option value="ollama">ollama (Local LLM via Ollama - Llama3, Mistral)</option>
                    <option value="openai">openai (GPT-4o / GPT-4o-mini Live Audit)</option>
                    <option value="gemini">gemini (Google Gemini 2.5 Live Audit)</option>
                  </select>
                </div>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  {selectedMode === 'mock'
                    ? '⚡ Zero-cost mock simulation using pre-baked adversarial probes.'
                    : selectedMode === 'webhook'
                    ? '🎯 Custom HTTP endpoint / locally hosted agent (URL required).'
                    : selectedMode === 'ollama'
                    ? '💻 Local LLM via Ollama (default http://localhost:11434).'
                    : `⚠️ Calls live ${selectedMode.toUpperCase()} API endpoint with adversarial prompts.`}
                </p>
              </div>

              {/* Target URL */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-cyan-400" />
                  Target URL / Endpoint
                </label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder={
                    selectedMode === 'mock'
                      ? 'http://localhost:8000 (Optional for mock)'
                      : 'https://api.openai.com/v1 or custom webhook'
                  }
                  className="w-full bg-slate-950 border border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-all"
                />
              </div>

              {/* API Key */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Key className="w-3.5 h-3.5 text-cyan-400" />
                    API Key
                  </span>
                  {selectedMode === 'mock' && (
                    <span className="text-[10px] text-emerald-400 font-mono">Not needed in Mock mode</span>
                  )}
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={
                    selectedMode === 'openai'
                      ? 'sk-proj-...'
                      : selectedMode === 'gemini'
                      ? 'AIzaSy...'
                      : 'Optional for mock simulation'
                  }
                  className="w-full bg-slate-950 border border-slate-700/80 rounded-xl px-3.5 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-all"
                />
              </div>

              {/* System Prompt Under Test */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  System Prompt Under Audit
                </label>
                <textarea
                  rows={3}
                  value={systemPrompt}
                  onChange={(e) => setSystemPrompt(e.target.value)}
                  placeholder="Target system prompt being evaluated for jailbreak vulnerabilities..."
                  className="w-full bg-slate-950 border border-slate-700/80 rounded-xl px-3.5 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-all resize-none"
                />
              </div>

              {/* Error Banner */}
              {error && (
                <div className="p-3 rounded-xl bg-rose-950/50 border border-rose-800/80 flex items-start gap-2.5 text-xs text-rose-300">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex-1 font-mono">{error}</div>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full mt-2 py-3 px-4 rounded-xl font-medium text-sm flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 via-indigo-600 to-rose-600 hover:from-cyan-400 hover:to-rose-500 text-white shadow-lg shadow-cyan-900/30 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Executing Adversarial Audit...
                  </>
                ) : (
                  <>
                    <Flame className="w-4 h-4 text-rose-300" />
                    Launch Sentinel Red-Team Scan
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Static Linter Findings Card */}
          {reportData?.lint_findings && reportData.lint_findings.length > 0 && (
            <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-5 shadow-xl">
              <div className="flex items-center gap-2 mb-3">
                <Bug className="w-4 h-4 text-amber-400" />
                <h3 className="font-mono text-xs uppercase tracking-wider text-slate-200">
                  Zero-LLM Linter Insights ({reportData.lint_findings.length})
                </h3>
              </div>
              <div className="space-y-2">
                {reportData.lint_findings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between text-[11px] mb-1">
                      <span className="font-semibold text-amber-400">{finding.rule_id}</span>
                      <span className="px-1.5 py-0.5 rounded text-[9px] bg-amber-950 text-amber-300 border border-amber-800/50">
                        {finding.level}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">
                      {finding.message}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: Bento Box Dashboard Widget */}
        <div className="lg:col-span-7 flex flex-col gap-6">
          
          {/* Top Bento Row: 3 Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            
            {/* 1. ASR Score (Attack Success Rate / Risk Score) */}
            <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-5 flex flex-col justify-between shadow-xl relative overflow-hidden group hover:border-slate-700 transition-colors">
              <div className="absolute top-0 right-0 w-24 h-24 bg-rose-500/5 rounded-full blur-2xl group-hover:bg-rose-500/10 transition-colors" />
              <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                <span>ASR Score</span>
                <Flame className="w-4 h-4 text-rose-400" />
              </div>
              <div>
                <div className={`text-3xl font-extrabold tracking-tight font-mono ${getAsrColor(reportData?.risk_score)}`}>
                  {reportData ? `${Number(reportData.risk_score).toFixed(1)}%` : '0.0%'}
                </div>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  {reportData
                    ? reportData.risk_score > 30
                      ? '⚠️ Critical exposure'
                      : '✅ Model resilient'
                    : 'Awaiting scan'}
                </p>
              </div>
            </div>

            {/* 2. Tests Run */}
            <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-5 flex flex-col justify-between shadow-xl relative overflow-hidden group hover:border-slate-700 transition-colors">
              <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-2xl group-hover:bg-cyan-500/10 transition-colors" />
              <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                <span>Tests Run</span>
                <Crosshair className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <div className="text-3xl font-extrabold tracking-tight font-mono text-cyan-400">
                  {reportData ? reportData.total_probes : 0}
                </div>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  {reportData ? `Mode: ${reportData.mode}` : 'Probes in queue'}
                </p>
              </div>
            </div>

            {/* 3. Vulnerabilities */}
            <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-5 flex flex-col justify-between shadow-xl relative overflow-hidden group hover:border-slate-700 transition-colors">
              <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition-colors" />
              <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-2">
                <span>Vulnerabilities</span>
                <ShieldAlert className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <div className={`text-3xl font-extrabold tracking-tight font-mono ${
                  reportData?.vulnerability_count > 0 ? 'text-rose-400' : 'text-slate-200'
                }`}>
                  {reportData ? reportData.vulnerability_count : 0}
                </div>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  {reportData?.vulnerability_count > 0 ? 'Remediation needed' : '0 breaches detected'}
                </p>
              </div>
            </div>
          </div>

          {/* Bottom Bento Box: Attack Probe Stream / Results List */}
          <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-2xl flex-1 flex flex-col">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <h3 className="font-semibold text-slate-200 text-sm uppercase tracking-wide">
                  Adversarial Probe Stream
                </h3>
              </div>
              {reportData && (
                <span className="text-xs font-mono text-slate-400">
                  Target: <span className="text-cyan-400">{reportData.target_model}</span>
                </span>
              )}
            </div>

            {/* Probe Results List */}
            {reportData && reportData.probe_results && reportData.probe_results.length > 0 ? (
              <div className="space-y-3 overflow-y-auto max-h-[580px] pr-1.5 custom-scrollbar">
                {reportData.probe_results.map((probe, index) => {
                  const isExpanded = expandedProbe === index;
                  return (
                    <div
                      key={probe.payload_id || index}
                      className="bg-slate-950/80 border border-slate-800 hover:border-slate-700/80 rounded-xl p-4 transition-all"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span className="font-mono text-xs font-semibold text-slate-200">
                              {probe.payload_name}
                            </span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900 text-slate-400 border border-slate-800">
                              {probe.payload_category}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              Conf: {(probe.confidence * 100).toFixed(0)}%
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 font-mono line-clamp-1">
                            {probe.attack_prompt}
                          </p>
                        </div>

                        {/* Red/Green Status Badge */}
                        <div className="flex items-center gap-2 shrink-0">
                          {probe.is_vulnerable ? (
                            <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1 shadow-sm shadow-rose-950">
                              <XCircle className="w-3.5 h-3.5" />
                              VULNERABLE
                            </span>
                          ) : (
                            <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1 shadow-sm shadow-emerald-950">
                              <CheckCircle className="w-3.5 h-3.5" />
                              SECURE
                            </span>
                          )}

                          <button
                            type="button"
                            onClick={() => setExpandedProbe(isExpanded ? null : index)}
                            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                            title="Toggle prompt & response inspection"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>

                      {/* Expandable Details (Prompt & Model Response) */}
                      {isExpanded && (
                        <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-2 text-xs font-mono">
                          <div>
                            <span className="text-[10px] uppercase text-cyan-400 font-semibold tracking-wider">
                              Injected Attack Prompt:
                            </span>
                            <div className="mt-1 p-2 rounded bg-slate-900 border border-slate-800 text-slate-300 whitespace-pre-wrap">
                              {probe.attack_prompt}
                            </div>
                          </div>
                          <div>
                            <span className="text-[10px] uppercase text-slate-400 font-semibold tracking-wider">
                              Target Response:
                            </span>
                            <div className="mt-1 p-2 rounded bg-slate-900/60 border border-slate-800 text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto">
                              {probe.response || '(No response captured)'}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              /* Awaiting Scan Placeholder */
              <div className="flex-1 min-h-[300px] flex flex-col items-center justify-center text-center p-8 border border-dashed border-slate-800 rounded-xl bg-slate-950/40">
                <Shield className="w-12 h-12 text-slate-700 mb-3 animate-pulse" />
                <h4 className="text-sm font-medium text-slate-300 font-mono mb-1">
                  No Adversarial Audit Running
                </h4>
                <p className="text-xs text-slate-500 max-w-sm font-mono">
                  Select a backend mode on the left and click &quot;Launch Sentinel Red-Team Scan&quot; to audit LLM endpoints against OWASP Top 10 vectors.
                </p>
              </div>
            )}
          </div>

        </div>

      </main>
    </div>
  );
}
