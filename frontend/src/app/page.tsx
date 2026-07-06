"use client";

import React, { useState, useEffect, useRef } from "react";
import io from "socket.io-client";
import { 
  Shield, 
  Mail, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Send, 
  RefreshCw, 
  FileText, 
  ArrowRight, 
  Cpu, 
  HelpCircle, 
  ChevronDown, 
  ChevronUp, 
  MessageSquare, 
  Info,
  Server,
  Code
} from "lucide-react";

// Templates for quick testing
const EMAIL_TEMPLATES = [
  {
    name: "PayPal Phishing Alert",
    description: "Brand impersonation, bad URL, high urgency",
    text: `From: PayPal Security <security@paypaI.com>
Subject: URGENT: Your PayPal account has been restricted!
Date: July 6, 2026

Dear customer, 

We noticed unusual login attempts on your account from an unrecognized IP address in Moscow, Russia. To protect your funds, we have temporarily restricted your account.

You must verify your identity within 24 hours. Failure to do so will result in permanent suspension of your funds.

Please click the secure link below to update your login credentials immediately:
http://192.168.4.21/paypal-security/login.php

Thank you,
PayPal Security Team`
  },
  {
    name: "Microsoft 365 Pass Expiry",
    description: "Mismatched reply-to, missing auth headers",
    text: `From: Microsoft IT Admin <admin@micros0ft-portal.net>
Reply-To: support-admin@gmail.com
Subject: ACTION REQUIRED: Your Office 365 password expires today!
Date: July 6, 2026

Hi Team,

Your Microsoft Office 365 corporate account password is set to expire in 4 hours. 

To keep your current password and avoid losing access to your Outlook inbox and Teams chats, please confirm your current credentials at our IT self-service center:

Click Here to Renew Password: http://verify.micros0ft-portal.net/renew/corporate

This is an automated system notification. Please do not reply directly.`
  },
  {
    name: "Legitimate Sync Invitation",
    description: "Clean text, safe domains, standard template",
    text: `From: Sarah Jenkins <sjenkins@company.com>
Subject: Project Roadmap & Weekly Sync Meeting
Date: July 6, 2026

Hi Team,

Hope you all had a great weekend.

I've updated the project roadmap with our milestones for Q3. Please review the attached document before our weekly sync meeting tomorrow.

Meeting Details:
Time: Tuesday, 10:00 AM EST
Link: https://meet.google.com/abc-defg-hij

Let me know if anyone needs to reschedule.

Best regards,
Sarah Jenkins
Project Manager`
  }
];

const BACKEND_URL = "http://localhost:5000";

export default function Home() {
  const [rawEmail, setRawEmail] = useState("");
  const [scanning, setScanning] = useState(false);
  const [jobId, setJobId] = useState("");
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");
  const [verdict, setVerdict] = useState<any>(null);
  
  // RAG Chat analyst state
  const [chatHistory, setChatHistory] = useState<Array<{ role: string; text: string }>>([]);
  const [chatQuery, setChatQuery] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  
  // DB list of previous scans
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [expandedReason, setExpandedReason] = useState<number | null>(null);
  const [apiStatus, setApiStatus] = useState<"connected" | "disconnected" | "checking">("checking");

  const socketRef = useRef<any>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Fetch scan history and check API health
  const fetchScanHistory = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/v1/scans`);
      if (res.ok) {
        const data = await res.json();
        setScanHistory(data);
        setApiStatus("connected");
      } else {
        setApiStatus("disconnected");
      }
    } catch (e) {
      console.warn("Could not connect to Express API:", e);
      setApiStatus("disconnected");
    }
  };

  useEffect(() => {
    fetchScanHistory();
    const interval = setInterval(fetchScanHistory, 10000);
    return () => clearInterval(interval);
  }, []);

  // Scroll to bottom of chat when new message arrives
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatHistory, chatLoading]);

  // Handle socket connections and scan submission
  const startScan = async () => {
    if (!rawEmail.trim()) return;

    setScanning(true);
    setVerdict(null);
    setProgress(0);
    setJobId("");
    setChatHistory([]);
    setStatusMessage("Submitting scan job to queue...");

    try {
      // 1. POST raw email to Express backend
      const res = await fetch(`${BACKEND_URL}/api/v1/scan/paste`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_email: rawEmail }),
      });

      if (!res.ok) {
        throw new Error("API server responded with error");
      }

      const { job_id } = await res.json();
      setJobId(job_id);
      setStatusMessage("Job accepted. Subscribing to updates...");

      // 2. Connect socket client to receive real-time queue states
      if (!socketRef.current) {
        socketRef.current = io(BACKEND_URL);
      } else if (!socketRef.current.connected) {
        socketRef.current.connect();
      }

      socketRef.current.emit("subscribe", { jobId: job_id });

      // 3. Set up event listeners
      socketRef.current.on("active", () => {
        setStatusMessage("Worker picked up job. Initializing analyzer...");
        setProgress(5);
      });

      socketRef.current.on("progress", (data: { jobId: string; progress: number }) => {
        if (data.jobId !== job_id) return;
        setProgress(data.progress);
        
        // Map progress numbers to status stages
        if (data.progress < 30) {
          setStatusMessage("Extracting MIME structure & parsing headers...");
        } else if (data.progress < 50) {
          setStatusMessage("Extracting hyperlinks & running URL threat intelligence checks...");
        } else if (data.progress < 70) {
          setStatusMessage("Evaluating SPF, DKIM, and DMARC alignments...");
        } else if (data.progress < 90) {
          setStatusMessage("Running NLP semantic classifiers for urgency & brand homoglyphs...");
        } else if (data.progress < 100) {
          setStatusMessage("Invoking ensemble ML prediction models & LLM explainability agents...");
        }
      });

      socketRef.current.on("completed", (data: { jobId: string; result: any }) => {
        if (data.jobId !== job_id) return;
        setProgress(100);
        setStatusMessage("Analysis completed successfully!");
        setVerdict(data.result);
        setScanning(false);
        fetchScanHistory();
        
        // Load default welcome message from AI analyst
        setChatHistory([
          {
            role: "analyst",
            text: `Hello! I am your PhishShield Forensic AI Analyst. I have dissected this email and flagged it with a threat risk score of **${data.result.risk_score}/100**. You can ask me questions about specific parts of this report, such as 'Why did the SPF fail?', 'Are the links malicious?', or 'What should I do next?'`
          }
        ]);
        
        // Cleanup socket listeners
        socketRef.current.off("active");
        socketRef.current.off("progress");
        socketRef.current.off("completed");
        socketRef.current.off("failed");
      });

      socketRef.current.on("failed", (data: { jobId: string; error: string }) => {
        if (data.jobId !== job_id) return;
        setStatusMessage(`Analysis failed: ${data.error}`);
        setScanning(false);
        socketRef.current.off("active");
        socketRef.current.off("progress");
        socketRef.current.off("completed");
        socketRef.current.off("failed");
      });

    } catch (err: any) {
      setStatusMessage(`Connection failed: Make sure the server at ${BACKEND_URL} is running.`);
      setScanning(false);
    }
  };

  // Submit query to RAG chat analyst
  const sendChatQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatQuery.trim() || chatLoading || !verdict) return;

    const userMsg = chatQuery;
    setChatQuery("");
    setChatHistory(prev => [...prev, { role: "user", text: userMsg }]);
    setChatLoading(true);

    try {
      const res = await fetch(`${BACKEND_URL}/api/v1/ai/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          analysis_id: verdict._id,
          query: userMsg
        })
      });

      if (!res.ok) throw new Error("Failed to receive analyst feedback");

      const { reply } = await res.json();
      setChatHistory(prev => [...prev, { role: "analyst", text: reply }]);
    } catch (error) {
      setChatHistory(prev => [...prev, { role: "analyst", text: "Error: I'm currently unable to process queries. Check if the backend sidecar is online." }]);
    } finally {
      setChatLoading(false);
    }
  };

  // Load sample template into paste area
  const loadTemplate = (text: string) => {
    setRawEmail(text);
    setVerdict(null);
  };

  // Select historical scan to display
  const loadHistoryItem = (item: any) => {
    setVerdict(item);
    setRawEmail(item.raw_headers ? JSON.stringify(item.raw_headers, null, 2) : "Stored headers not displayable.");
    setChatHistory([
      {
        role: "analyst",
        text: `Loaded previous audit report for subject: **${item.email_subject}**.\n\nRisk Score: **${item.risk_score}/100**.\nVerdict: **${item.verdict}**.\n\nAsk me any questions you have regarding this scan!`
      }
    ]);
  };

  const getVerdictStyles = (score: number) => {
    if (score > 70) return {
      color: "text-red-400",
      border: "border-red-500/30",
      bg: "bg-red-500/10",
      glow: "shadow-red-500/20",
      label: "CRITICAL PHISHING THREAT"
    };
    if (score > 40) return {
      color: "text-amber-400",
      border: "border-amber-500/30",
      bg: "bg-amber-500/10",
      glow: "shadow-amber-500/20",
      label: "SUSPICIOUS / WARN"
    };
    return {
      color: "text-emerald-400",
      border: "border-emerald-500/30",
      bg: "bg-emerald-500/10",
      glow: "shadow-emerald-500/20",
      label: "LEGITIMATE / SAFE"
    };
  };

  return (
    <main className="min-h-screen relative px-4 md:px-8 py-6 max-w-7xl mx-auto flex flex-col gap-6">
      {/* Decorative Neon Glow Blobs */}
      <div className="ambient-glow-1" />
      <div className="ambient-glow-2" />

      {/* Top Banner Header */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-600 flex items-center justify-center shadow-lg shadow-purple-600/30">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              PhishShield <span className="text-purple-400 font-extrabold text-xs tracking-widest px-2 py-0.5 rounded-full border border-purple-500/30 bg-purple-500/10">AI</span>
            </h1>
            <p className="text-xs text-zinc-400">Agentic Hybrid Email Forensics Scanner &amp; XAI Explanation Engine</p>
          </div>
        </div>
        
        {/* API Connection Indicator */}
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2 bg-zinc-900 px-3 py-1.5 rounded-full border border-white/5">
            <Server className="w-3.5 h-3.5 text-zinc-400" />
            <span className="text-zinc-400">Express Queue:</span>
            {apiStatus === "checking" && <span className="text-zinc-500 flex items-center gap-1"><RefreshCw className="w-3 h-3 animate-spin" /> Checking</span>}
            {apiStatus === "connected" && <span className="text-emerald-400 font-semibold flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" /> Online</span>}
            {apiStatus === "disconnected" && <span className="text-red-400 font-semibold flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-400" /> Offline (Using Local Fallback)</span>}
          </div>
        </div>
      </header>

      {/* Main Content Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Column: Editor, Templates, and History (5/12 cols) */}
        <div className="lg:col-span-5 flex flex-col gap-6">
          
          {/* Email pasting workspace */}
          <div className="glass-panel p-6 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase flex items-center gap-2">
                <Code className="w-4 h-4 text-purple-400" /> Email Payload Input
              </h2>
              <button 
                onClick={() => setRawEmail("")} 
                className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                Clear
              </button>
            </div>

            <textarea
              className="w-full h-80 bg-zinc-950/60 rounded-xl border border-white/10 p-4 text-xs font-mono text-zinc-300 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/20 transition-all resize-none shadow-inner"
              placeholder="Paste raw email MIME headers and body text here..."
              value={rawEmail}
              onChange={(e) => setRawEmail(e.target.value)}
              disabled={scanning}
            />

            {/* Quick Templates Loader */}
            <div className="flex flex-col gap-2">
              <label className="text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">Quick Sample Loaders</label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {EMAIL_TEMPLATES.map((tmpl, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => loadTemplate(tmpl.text)}
                    className="p-2.5 text-left rounded-lg bg-white/5 border border-white/5 hover:border-purple-500/30 hover:bg-purple-500/5 transition-all text-xs flex flex-col justify-between h-20 group"
                    disabled={scanning}
                  >
                    <span className="font-semibold text-zinc-300 group-hover:text-purple-400 transition-colors">{tmpl.name}</span>
                    <span className="text-[9px] text-zinc-500 block truncate">{tmpl.description}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Submit / Trigger Button */}
            <button
              onClick={startScan}
              disabled={scanning || !rawEmail.trim()}
              className={`w-full py-3.5 btn-neon-primary flex items-center justify-center gap-2 text-sm font-semibold rounded-xl ${
                scanning || !rawEmail.trim() ? "opacity-50 pointer-events-none shadow-none" : ""
              }`}
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Processing Analysis...</span>
                </>
              ) : (
                <>
                  <Cpu className="w-4 h-4 text-white" />
                  <span>Analyze Email with Hybrid Agents</span>
                </>
              )}
            </button>
          </div>

          {/* Past Scan History Document Logs */}
          <div className="glass-panel p-6 flex flex-col gap-4">
            <h2 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase flex items-center gap-2">
              <Clock className="w-4 h-4 text-purple-400" /> Audit Ledger History
            </h2>
            <div className="flex flex-col gap-2 max-h-52 overflow-y-auto pr-1">
              {scanHistory.length === 0 ? (
                <div className="text-xs text-zinc-500 py-6 text-center italic border border-dashed border-white/5 rounded-xl">
                  No scan entries in DB. Paste an email above to create one.
                </div>
              ) : (
                scanHistory.map((item) => {
                  const cardStyles = getVerdictStyles(item.risk_score);
                  return (
                    <div
                      key={item._id}
                      onClick={() => loadHistoryItem(item)}
                      className="p-3 rounded-lg border border-white/5 hover:border-white/10 bg-white/2 cursor-pointer flex items-center justify-between gap-3 hover:bg-white/5 transition-all"
                    >
                      <div className="flex flex-col gap-0.5 truncate">
                        <span className="text-xs font-semibold text-zinc-300 truncate">{item.email_subject}</span>
                        <span className="text-[10px] text-zinc-500">{new Date(item.created_at).toLocaleString()}</span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${cardStyles.border} ${cardStyles.bg} ${cardStyles.color}`}>
                          {item.risk_score}%
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Execution Output & RAG Assistant (7/12 cols) */}
        <div className="lg:col-span-7 flex flex-col gap-6">
          
          {/* Active progress tracking / Dynamic checkpoint timeline */}
          {scanning && (
            <div className="glass-panel p-6 flex flex-col gap-6 glow-active">
              <div className="flex justify-between items-center">
                <h3 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-purple-400" /> Agent Orchestrator Running
                </h3>
                <span className="text-xs font-bold text-purple-400">{progress}%</span>
              </div>
              
              {/* Outer progress bar */}
              <div className="w-full bg-zinc-950 rounded-full h-2 overflow-hidden border border-white/5">
                <div 
                  className="bg-gradient-to-r from-purple-500 to-blue-500 h-full rounded-full transition-all duration-500 ease-out" 
                  style={{ width: `${progress}%` }}
                />
              </div>

              {/* Step Timeline Indicator */}
              <div className="grid grid-cols-5 gap-1 text-[10px] text-zinc-500 font-semibold tracking-wider text-center">
                <div className={progress >= 10 ? "text-purple-400" : ""}>MIME PARSE</div>
                <div className={progress >= 35 ? "text-purple-400" : ""}>URL INTEL</div>
                <div className={progress >= 60 ? "text-purple-400" : ""}>AUTH CHECKS</div>
                <div className={progress >= 80 ? "text-purple-400" : ""}>NLP INTENT</div>
                <div className={progress >= 90 ? "text-purple-400" : ""}>AI LOGIC</div>
              </div>

              <div className="flex items-start gap-3 bg-zinc-950/40 p-4 rounded-xl border border-white/5 text-xs text-zinc-400">
                <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>{statusMessage}</span>
              </div>
            </div>
          )}

          {/* Results Audit Output Display */}
          {verdict && !scanning && (
            <div className="flex flex-col gap-6">
              
              {/* Verdict Header Glow Card */}
              {(() => {
                const styles = getVerdictStyles(verdict.risk_score);
                return (
                  <div className={`glass-panel p-6 border ${styles.border} ${styles.bg} shadow-lg ${styles.glow} relative overflow-hidden`}>
                    
                    {/* Background indicator blur */}
                    <div className="absolute right-[-5%] top-[-10%] w-32 h-32 rounded-full opacity-20 filter blur-xl bg-current" />

                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex items-start gap-4">
                        <div className="mt-1">
                          {verdict.risk_score > 70 ? (
                            <AlertTriangle className="w-10 h-10 text-red-500" />
                          ) : verdict.risk_score > 40 ? (
                            <AlertTriangle className="w-10 h-10 text-amber-500" />
                          ) : (
                            <CheckCircle className="w-10 h-10 text-emerald-500" />
                          )}
                        </div>
                        <div>
                          <div className="text-[10px] font-bold tracking-widest text-zinc-400 uppercase">Analysis Verdict</div>
                          <h3 className={`text-xl font-black tracking-tight ${styles.color} mt-0.5`}>
                            {styles.label}
                          </h3>
                          <p className="text-xs text-zinc-400 mt-1">Subject: <span className="font-semibold text-zinc-200">{verdict.email_subject}</span></p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 bg-zinc-950/50 px-5 py-3 rounded-2xl border border-white/5 self-start md:self-center">
                        <div className="flex flex-col text-right">
                          <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-widest">Risk Score</span>
                          <span className={`text-2xl font-black ${styles.color}`}>{verdict.risk_score}%</span>
                        </div>
                        {/* Radial threat meter representation */}
                        <div className="relative w-10 h-10">
                          <svg className="w-full h-full transform -rotate-90">
                            <circle cx="20" cy="20" r="16" stroke="rgba(255,255,255,0.05)" strokeWidth="3" fill="transparent" />
                            <circle cx="20" cy="20" r="16" stroke="currentColor" strokeWidth="3" fill="transparent"
                              className={styles.color}
                              strokeDasharray={100}
                              strokeDashoffset={100 - verdict.risk_score}
                            />
                          </svg>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Explainability Segment (LLM Breakdown Markdown) */}
              <div className="glass-panel p-6 flex flex-col gap-4">
                <h3 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase flex items-center gap-2">
                  <FileText className="w-4 h-4 text-purple-400" /> Forensic Executive Explanation
                </h3>
                <div className="p-4 bg-zinc-950/60 border border-white/5 rounded-xl text-xs leading-relaxed text-zinc-300 font-sans whitespace-pre-line">
                  {verdict.llm_explanation}
                </div>
              </div>

              {/* Collapsible Explanatory Trigger list */}
              <div className="glass-panel p-6 flex flex-col gap-4">
                <h3 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-purple-400" /> Specific Threat Signatures ({verdict.explanation_tree.length})
                </h3>
                <div className="flex flex-col gap-3">
                  {verdict.explanation_tree.map((item: any, idx: number) => (
                    <div 
                      key={idx} 
                      className="border border-white/5 rounded-xl bg-zinc-950/30 overflow-hidden"
                    >
                      <button
                        type="button"
                        onClick={() => setExpandedReason(expandedReason === idx ? null : idx)}
                        className="w-full p-4 text-left flex items-center justify-between gap-4 hover:bg-white/2 transition-all"
                      >
                        <div className="flex items-center gap-3">
                          <span className="w-1.5 h-1.5 rounded-full bg-purple-500" />
                          <span className="text-xs font-semibold text-zinc-300">{item.reason}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] font-bold text-zinc-500">
                            Confidence: {Math.round(item.confidence * 100)}%
                          </span>
                          {expandedReason === idx ? (
                            <ChevronUp className="w-4 h-4 text-zinc-500" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-zinc-500" />
                          )}
                        </div>
                      </button>
                      {expandedReason === idx && (
                        <div className="px-4 pb-4 pt-1 border-t border-white/5 text-xs text-zinc-400 leading-relaxed bg-zinc-950/50">
                          {item.detail}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Interactive RAG chat analyst panel */}
              <div className="glass-panel p-6 flex flex-col gap-4">
                <h3 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-purple-400" /> Ask PhishShield Analyst (RAG-Chat)
                </h3>
                
                {/* Chat Message viewport */}
                <div className="w-full h-64 bg-zinc-950/80 rounded-xl border border-white/10 p-4 overflow-y-auto flex flex-col gap-4">
                  {chatHistory.map((msg, idx) => (
                    <div 
                      key={idx} 
                      className={`flex flex-col max-w-[85%] ${
                        msg.role === "user" ? "self-end items-end" : "self-start items-start"
                      }`}
                    >
                      <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-widest mb-1">
                        {msg.role === "user" ? "You" : "PhishShield Analyst"}
                      </span>
                      <div className={`p-3 rounded-2xl text-xs leading-relaxed whitespace-pre-line ${
                        msg.role === "user" 
                          ? "bg-purple-600/90 text-white rounded-tr-none" 
                          : "bg-white/5 border border-white/5 text-zinc-300 rounded-tl-none"
                      }`}>
                        {msg.text}
                      </div>
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="self-start flex flex-col items-start max-w-[85%]">
                      <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-widest mb-1">PhishShield Analyst</span>
                      <div className="p-3 rounded-2xl text-xs bg-white/5 border border-white/5 text-zinc-400 rounded-tl-none flex items-center gap-2">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Thinking...
                      </div>
                    </div>
                  )}
                  <div ref={chatBottomRef} />
                </div>

                {/* Input form query */}
                <form onSubmit={sendChatQuery} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Why failed SPF authentication? / Are the links safe?"
                    className="flex-1 bg-zinc-950 rounded-xl border border-white/10 px-4 py-2.5 text-xs text-zinc-300 focus:outline-none focus:border-purple-500 transition-all shadow-inner"
                    value={chatQuery}
                    onChange={(e) => setChatQuery(e.target.value)}
                    disabled={chatLoading}
                  />
                  <button
                    type="submit"
                    className="px-4 py-2.5 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-xl text-xs transition-colors flex items-center justify-center gap-1.5 shadow-lg shadow-purple-600/10"
                    disabled={chatLoading || !chatQuery.trim()}
                  >
                    <Send className="w-3.5 h-3.5" /> Send
                  </button>
                </form>
              </div>

            </div>
          )}

          {/* Idle screen state */}
          {!verdict && !scanning && (
            <div className="glass-panel p-10 flex flex-col items-center justify-center text-center gap-4 h-full min-h-[450px]">
              <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center border border-white/5 text-purple-400 shadow-inner">
                <Mail className="w-8 h-8" />
              </div>
              <div className="flex flex-col gap-1 max-w-sm">
                <h3 className="text-base font-bold text-white">Awaiting Email Forensic Source</h3>
                <p className="text-xs text-zinc-500 leading-relaxed">
                  Paste a raw email or click one of the quick loaders on the left to start the LangGraph stateful analysis pipeline.
                </p>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-semibold text-zinc-500 mt-2 bg-zinc-950/60 px-3 py-1.5 rounded-full border border-white/5">
                <Cpu className="w-3.5 h-3.5" /> Uses Random Forest + Scikit-Learn TF-IDF classification
              </div>
            </div>
          )}

        </div>

      </div>
    </main>
  );
}
