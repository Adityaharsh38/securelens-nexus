import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  Database,
  GitBranch,
  History,
  LoaderCircle,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
  Workflow,
  XCircle,
} from "lucide-react";
import "./App.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:4000/api";

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(localStorage.getItem("securelens_token")
        ? { Authorization: `Bearer ${localStorage.getItem("securelens_token")}` }
        : {}),
      ...(options.headers || {}),
    },
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      data.details || data.error || data.message || `Request failed (${response.status})`
    );
  }
  return data;
}

function IconBadge({ children, tone = "mint" }) {
  return <span className={`icon-badge icon-badge-${tone}`}>{children}</span>;
}

function Pill({ children, tone = "neutral" }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

function SectionHeading({ eyebrow, title, description, action }) {
  return (
    <div className="section-heading">
      <div>
        {eyebrow && <div className="section-eyebrow">{eyebrow}</div>}
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone = "mint" }) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <IconBadge tone={tone}><Icon size={17} /></IconBadge>
        <span className="metric-label">{label}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  );
}

function FlowPath({ title, description, items = [], safe = false }) {
  const row = items[0] || {};
  const steps = safe
    ? [row.input, row.protection, row.function, row.sink].filter(Boolean)
    : [row.input, row.function, row.sink, row.asset].filter(Boolean);

  return (
    <article className={`panel flow-panel ${safe ? "flow-panel-safe" : "flow-panel-risk"}`}>
      <div className="panel-title-row">
        <div className="panel-title-main">
          <IconBadge tone={safe ? "mint" : "amber"}>
            {safe ? <ShieldCheck size={17} /> : <GitBranch size={17} />}
          </IconBadge>
          <div>
            <h3>{title}</h3>
            <p>{description}</p>
          </div>
        </div>
        <Pill tone={safe ? "mint" : "amber"}>{safe ? "Protected model" : "Potential risk"}</Pill>
      </div>

      {steps.length ? (
        <div className="flow-track">
          {steps.map((step, index) => (
            <div className="flow-track-item" key={`${step}-${index}`}>
              <div className={`flow-node ${index === steps.length - 1 && !safe ? "flow-node-risk" : ""}`}>
                <span className="flow-node-index">{String(index + 1).padStart(2, "0")}</span>
                <span>{step}</span>
              </div>
              {index < steps.length - 1 && <ArrowRight className="flow-track-arrow" size={15} />}
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-inline">No path returned. Seed the demo graph to populate this view.</div>
      )}

      {!safe && row.sensitivity && (
        <div className="flow-footnote">
          <Database size={15} />
          <span>Destination asset</span>
          <strong>{row.asset}</strong>
          <Pill tone="amber">{row.sensitivity} sensitivity</Pill>
        </div>
      )}
    </article>
  );
}

function AssetPanel({ data, loading, onRetry }) {
  const assets = data?.assets || [];
  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title-main">
          <IconBadge tone="violet"><Target size={17} /></IconBadge>
          <div>
            <h3>Blast-radius analysis</h3>
            <p>Which modeled assets are reachable from the untrusted input?</p>
          </div>
        </div>
        <button className="button button-quiet" onClick={onRetry} disabled={loading}>
          {loading ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}
          Re-analyze
        </button>
      </div>

      {loading && !data ? (
        <div className="empty-state"><LoaderCircle className="spin" size={18} /> Tracing reachable assets…</div>
      ) : data ? (
        <>
          <div className="asset-summary">
            <div className="asset-summary-number">{data.count ?? assets.length}</div>
            <div>
              <strong>Reachable asset{(data.count ?? assets.length) === 1 ? "" : "s"}</strong>
              <p>Returned by a query against FalkorDB</p>
            </div>
            <div className="asset-summary-status"><span className="status-dot" /> Graph query complete</div>
          </div>

          {assets.length ? (
            <div className="asset-list">
              {assets.map((asset, index) => (
                <div className="asset-row" key={asset.assetId || `${asset.asset}-${index}`}>
                  <IconBadge tone="blue"><Database size={17} /></IconBadge>
                  <div className="asset-copy">
                    <strong>{asset.asset || "Unnamed asset"}</strong>
                    <span>{asset.source || "HTTP request parameter"} <ArrowRight size={12} /> {asset.sink || "SQL query execution"}</span>
                    <small>Asset ID · {asset.assetId || "Not provided"}</small>
                  </div>
                  <Pill tone={String(asset.sensitivity).toLowerCase() === "high" ? "amber" : "mint"}>
                    {asset.sensitivity || "Unknown"} sensitivity
                  </Pill>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={19} />
              No matching asset path was found. This does not prove the application is safe.
            </div>
          )}
          {data.explanation && <p className="panel-note">{data.explanation}</p>}
          {data.limitation && <p className="disclaimer">{data.limitation}</p>}
        </>
      ) : (
        <div className="empty-state">Blast-radius data is not available. Run Analyze to retry.</div>
      )}
    </section>
  );
}

function FindingCard({ finding, index }) {
  const severity = String(finding.severity || "medium").toLowerCase();
  return (
    <article className="finding-card" key={`${finding.ruleId || finding.type}-${finding.file}-${index}`}>
      <div className="finding-top">
        <IconBadge tone="amber"><AlertTriangle size={17} /></IconBadge>
        <div className="finding-main">
          <div className="finding-name-row">
            <strong>{finding.type || finding.ruleId || "Security finding"}</strong>
            <Pill tone={severity === "high" || severity === "critical" ? "amber" : "neutral"}>{severity}</Pill>
          </div>
          <p>{finding.file || "Unknown file"}{finding.line != null ? ` · Line ${finding.line}` : ""}</p>
        </div>
      </div>
      {finding.message && <p className="finding-message">{finding.message}</p>}
      {finding.evidence && (
        <div className="code-evidence">
          <div className="code-evidence-label"><Code2 size={13} /> Source evidence</div>
          <code>{finding.evidence}</code>
        </div>
      )}
      <div className="finding-context">
        <div><span>Sink</span><strong>{finding.sink || "Not modeled"}</strong></div>
        <div><span>Asset</span><strong>{finding.asset || "Not modeled"}</strong></div>
        <div><span>Sensitivity</span><strong>{finding.sensitivity || "Unknown"}</strong></div>
      </div>
      {finding.recommendation && (
        <div className="recommendation">
          <Sparkles size={15} />
          <p><strong>Suggested mitigation</strong><br />{finding.recommendation}</p>
        </div>
      )}
    </article>
  );
}


function InvestigationResult({ data }) {
  if (!data) return null;

  const findings = data.findings || [];
  const evidence = data.evidence || [];
  const steps = data.steps || [];

  // Scan investigations are identified by the scan-specific API response.
  // Do not display the shared synthetic demo path as evidence for submitted code.
  const isScanInvestigation = Boolean(data.scanId || data.fileId);

  const statusTone =
    data.status === "potential-risk" ? "amber" : "mint";

  return (
    <section className="panel result-panel">
      <div className="result-header">
        <div className="panel-title-main">
          <IconBadge tone="mint">
            <Workflow size={17} />
          </IconBadge>

          <div>
            <div className="section-eyebrow">LATEST RUN</div>
            <h3>Investigation result</h3>
            <p className="mono result-id">
              {data.id || "Investigation completed"}
            </p>
          </div>
        </div>

        <Pill tone={statusTone}>
          {data.status || "completed"}
        </Pill>
      </div>

      <p className="result-summary">
        {data.finding ||
          data.summary ||
          "The investigation completed."}
      </p>

      {/* Findings retrieved specifically for this scan */}
      <div className="result-subsection">
        <div className="subsection-label">
          Scan evidence ({findings.length} findings)
        </div>

        {findings.length > 0 ? (
          <div className="findings-grid">
            {findings.map((finding, index) => (
              <FindingCard
                key={
                  finding.findingId ||
                  finding.ruleId ||
                  `finding-${index}`
                }
                finding={{
                  ...finding,
                  file:
                    finding.file ||
                    data.fileName ||
                    "Submitted source",
                  sink:
                    finding.sink ||
                    "Not modeled by this scan",
                  asset:
                    finding.asset ||
                    "Not established by this scan",
                  sensitivity:
                    finding.sensitivity || "Unknown",
                }}
                index={index}
              />
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <ShieldCheck size={19} />
            <div>
              <strong>No findings returned for this scan</strong>
              <p>
                This does not prove the submitted code is secure.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Only display attack paths returned by the backend */}
      {data.attackPaths?.length > 0 && (
        <div className="result-subsection">
          <div className="subsection-label">
            Attack path evidence
          </div>

          {data.attackPaths.map((path, index) => (
            <div className="path-evidence" key={index}>
              <div className="path-evidence-icon">
                <GitBranch size={15} />
              </div>
              <div>
                <strong>
                  {path.path ||
                    path.description ||
                    "Modeled input-to-sink path"}
                </strong>
                <p>{path.asset || path.sink || ""}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Show a path only when the backend returned actual path evidence.
          Scan investigations must never inherit the synthetic demo path. */}
      {isScanInvestigation ? (
        <div className="result-subsection">
          <div className="subsection-label">Observed graph path</div>
          {data.attackPaths?.length > 0 ? (
            data.attackPaths.map((path, index) => (
              <div className="evidence-path-row" key={index}>
                {(Array.isArray(path.path) ? path.path : [
                  path.input,
                  path.function,
                  path.sink,
                  path.asset,
                ]).filter(Boolean).map((node, nodeIndex, nodes) => (
                  <span className="evidence-path-node" key={`${node}-${nodeIndex}`}>
                    {nodeIndex > 0 && <ChevronRight size={14} />}
                    <span>{node}</span>
                  </span>
                ))}
              </div>
            ))
          ) : (
            <div className="empty-state">
              <CircleDot size={18} />
              <div>
                <strong>No modeled attack path for this scan</strong>
                <p>
                  The scan has findings, but no scan-specific path from a source
                  through a sink to an affected asset has been established.
                  Synthetic demo relationships are not used as evidence here.
                </p>
              </div>
            </div>
          )}
        </div>
      ) : evidence.length > 0 ? (
        <div className="result-subsection">
          <div className="subsection-label">Observed graph path</div>
          {evidence.map((item, index) => (
            <div className="evidence-path-row" key={index}>
              <span>{item.input || item.source || "Input"}</span>
              <ChevronRight size={14} />
              <span>{item.function || item.nodeType || "Function"}</span>
              <ChevronRight size={14} />
              <span>{item.sink || "Sink"}</span>
              <ChevronRight size={14} />
              <span>{item.asset || "Asset"}</span>
            </div>
          ))}
        </div>
      ) : null}

      {/* Agent tool trace */}
      {steps.length > 0 && (
        <div className="result-subsection">
          <div className="subsection-label">
            Agent reasoning and tool trace
          </div>

          <div className="tool-trace">
            {steps.map((step, index) => (
              <div
                className="tool-trace-row"
                key={`${step.tool || step.name || "tool"}-${index}`}
              >
                <div className="trace-check">
                  {step.status === "not-modeled" ? (
                    <CircleDot size={13} />
                  ) : (
                    <Check size={13} />
                  )}
                </div>

                <div className="trace-copy">
                  <strong>
                    {step.tool ||
                      step.name ||
                      `Step ${index + 1}`}
                  </strong>
                  <span>
                    {step.purpose ||
                      step.description ||
                      "Investigation step"}
                    {step.resultCount != null
                      ? ` · ${step.resultCount} result(s)`
                      : ""}
                  </span>
                  {step.decision && (
                    <span>{step.decision}</span>
                  )}
                </div>

                <Pill
                  tone={
                    step.status === "not-modeled"
                      ? "neutral"
                      : "mint"
                  }
                >
                  {step.status || "completed"}
                </Pill>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.recommendation && (
        <div className="recommendation">
          <Sparkles size={15} />
          <p>
            <strong>Recommended next step</strong>
            <br />
            {data.recommendation}
          </p>
        </div>
      )}

      {data.limitation && (
        <p className="disclaimer">{data.limitation}</p>
      )}
    </section>
  );
}


function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function Dashboard({ user, onLogout }) {
  const [comparison, setComparison] = useState(null);
  const [history, setHistory] = useState([]);
  const [latest, setLatest] = useState(null);
  const [blastRadius, setBlastRadius] = useState(null);
  const [blastLoading, setBlastLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [graphEvidence, setGraphEvidence] = useState([]);
  const [activeView, setActiveView] = useState("investigation");
  const [searchTerm, setSearchTerm] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [sourceCode, setSourceCode] = useState("");
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisBusy, setAnalysisBusy] = useState(false);
  const [investigationBusy, setInvestigationBusy] = useState(false);

  const loadBlastRadius = useCallback(async () => {
    setBlastLoading(true);
    try {
      setBlastRadius(await request("/investigations/blast-radius"));
    } catch (e) {
      setError(`Blast-radius analysis: ${e.message}`);
    } finally {
      setBlastLoading(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    setError("");
    try {
      const [compareData, historyData, evidenceData] = await Promise.all([
        request("/investigations/compare"),
        request("/investigations/history"),
        request("/graph/evidence"),
      ]);
      setComparison(compareData);
      setHistory(historyData.investigations || []);
      setGraphEvidence(evidenceData.findings || []);
      setLastUpdated(new Date());
    } catch (e) {
      setError(e.message);
    }
    await loadBlastRadius();
  }, [loadBlastRadius]);

  useEffect(() => { refresh(); }, [refresh]);

  async function runAction(action) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      if (action === "seed") {
        const data = await request("/investigations/seed", { method: "POST" });
        setMessage(data.message || "Demo graph seeded.");
      } else {
        const data = await request("/investigations/run", { method: "POST" });
        setLatest(data);
        setActiveView("investigation");
        setMessage("Investigation completed and saved to graph memory.");
      }
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function analyzePastedCode() {
    if (!sourceCode.trim()) {
      setError("Paste JavaScript code before starting the analysis.");
      return;
    }

    setAnalysisBusy(true);
    setError("");
    setMessage("");
    setAnalysisResult(null);

    try {
      const data = await request("/analyzer/code", {
        method: "POST",
        body: JSON.stringify({ code: sourceCode, filename: "pasted-code.js" }),
      });
      setAnalysisResult(data);
      setMessage("Static analysis completed. Review the findings and limitations below.");
    } catch (e) {
      setError(e.message || "Code analysis failed.");
    } finally {
      setAnalysisBusy(false);
    }
  }

  async function investigateCurrentScan() {
    const scanId = analysisResult?.graph?.scanId;

    if (!scanId) {
      setError("No scan ID found. Analyze the code again first.");
      return;
    }

    setInvestigationBusy(true);
    setError("");
    setMessage("");

    try {
      const data = await request(
        `/investigations/scan/${encodeURIComponent(scanId)}`,
        { method: "POST" }
      );

      setLatest(data);
      setActiveView("investigation");
      setMessage(`Investigation completed for scan ${scanId}.`);
      await refresh();
    } catch (e) {
      setError(e.message || "Scan investigation failed.");
    } finally {
      setInvestigationBusy(false);
    }
  }

  const analysis = analysisResult?.analysis || analysisResult;
  const codeFindings = analysis?.findings || [];
  const vulnerable = comparison?.vulnerableFlow || [];
  const safer = comparison?.saferFlow || [];
  const risks = history.filter((item) => item.status === "potential-risk").length;
  const filteredHistory = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return history;
    return history.filter((item) =>
      [item.id, item.status, item.finding].some((value) => String(value || "").toLowerCase().includes(q))
    );
  }, [history, searchTerm]);

  const navItems = [
    { id: "investigation", label: "Investigation", icon: Activity },
    { id: "attack-paths", label: "Attack paths", icon: GitBranch },
    { id: "findings", label: "Findings", icon: ShieldAlert },
    { id: "memory", label: "Investigation history", icon: History },
  ];

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" aria-label="SecureLens Nexus home">
          <span className="brand-mark"><ShieldCheck size={21} /></span>
          <span className="brand-copy">
            <strong>SecureLens<span> Nexus</span></strong>
            <small>GRAPH SECURITY INTELLIGENCE</small>
          </span>
        </a>

        <div className="sidebar-section-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Workspace navigation">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              className={`nav-item ${activeView === id ? "active" : ""}`}
              key={id}
              onClick={() => setActiveView(id)}
            >
              <Icon size={17} />
              <span>{label}</span>
              {id === "findings" && graphEvidence.length > 0 && <span className="nav-count">{graphEvidence.length}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-heading"><span className="status-dot" /> Graph connection</div>
          <div className="connection-main"><Database size={16} /><strong>FalkorDB</strong><Pill tone="mint">API verified</Pill></div>
          <p>Cloud graph · synthetic demo dataset</p>
          <div className="connection-divider" />
          <div className="connection-foot"><Shield size={13} /> Credentials remain server-side</div>
        </div>
      </aside>

      <div className="main-column" id="top">
        <header className="topbar">
          <div className="breadcrumbs"><span>SecureLens Nexus</span><ChevronRight size={13} /><strong>{navItems.find((item) => item.id === activeView)?.label || "Investigation"}</strong></div>
          <div className="topbar-right">
            <span className="live-indicator"><span className="status-dot" /> API workspace</span>
            <button className="button button-quiet refresh-button" onClick={refresh} disabled={busy || blastLoading}>
              {busy || blastLoading ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}
              Refresh
            </button>
            <div className="user-menu">
              <span className="user-avatar">{(user?.name || user?.email || "U").trim().charAt(0).toUpperCase()}</span>
              <span className="user-identity"><strong>{user?.name || "Workspace user"}</strong><small>{user?.email || "Personal workspace"}</small></span>
              <button className="button button-quiet logout-button" onClick={onLogout}>Sign out</button>
            </div>
          </div>
        </header>

        <main className="content">
          <section className="welcome-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS <span className="eyebrow-separator">/</span> GRAPH INTELLIGENCE</div>
              <h1>Investigate what <span>connects.</span></h1>
              <p className="welcome-description">Trace untrusted inputs through modeled code paths, uncover reachable assets, and keep every finding tied to graph evidence.</p>
            </div>
            <div className="welcome-actions">
              <button className="button button-primary" onClick={() => runAction("run")} disabled={busy}>
                {busy ? <LoaderCircle className="spin" size={16} /> : <Play size={16} fill="currentColor" />}
                Run investigation
              </button>
              <button className="button button-secondary" onClick={() => runAction("seed")} disabled={busy}>
                <Database size={16} /> Seed demo
              </button>
            </div>
          </section>

          {(error || message) && (
            <div className={`notice ${error ? "notice-error" : "notice-success"}`} role="status">
              {error ? <XCircle size={17} /> : <CheckCircle2 size={17} />}
              <span>{error || message}</span>
              <button aria-label="Dismiss notice" onClick={() => { setError(""); setMessage(""); }}><XCircle size={15} /></button>
            </div>
          )}

          <section className="metrics-grid" aria-label="Workspace metrics">
            <MetricCard icon={ShieldAlert} label="Potential-risk cases" value={risks} detail="Saved investigation records" tone="amber" />
            <MetricCard icon={GitBranch} label="Modeled flows" value={vulnerable.length + safer.length} detail="Vulnerable + protected examples" tone="violet" />
            <MetricCard icon={History} label="Investigation history" value={history.length} detail="Latest records in FalkorDB" tone="blue" />
            <MetricCard icon={Database} label="Graph status" value="Connected" detail="Verified through the API" tone="mint" />
          </section>

          {activeView === "investigation" && (
            <>
              <section className="section-block">
                <SectionHeading
                  eyebrow="SOURCE CODE ANALYSIS"
                  title="Scan your JavaScript"
                  description="Paste code to check for supported SQL-injection patterns. The analyzer reads source text; it does not execute your code."
                  action={<Pill tone="neutral">JS-SQLI-001</Pill>}
                />
                <div className="panel code-scan-panel">
                  <div className="code-scan-toolbar">
                    <span><Code2 size={14} /> JavaScript source</span>
                    <span>Maximum 20,000 characters</span>
                  </div>
                  <textarea
                    className="code-input"
                    aria-label="JavaScript source code to analyze"
                    value={sourceCode}
                    onChange={(event) => {
                      setSourceCode(event.target.value.slice(0, 20000));
                      setAnalysisResult(null);
                    }}
                    maxLength={20000}
                    rows={11}
                    spellCheck={false}
                    placeholder={'const userId = req.query.id;\\nconst sql = `SELECT * FROM users WHERE id = ${userId}`;\\ndb.query(sql);'}
                  />
                  <div className="code-scan-actions">
                    <span>{sourceCode.length.toLocaleString()} / 20,000 characters</span>
                    <button
                      className="button button-primary"
                      onClick={analyzePastedCode}
                      disabled={analysisBusy || !sourceCode.trim()}
                    >
                      {analysisBusy ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />}
                      {analysisBusy ? "Analyzing…" : "Analyze code"}
                    </button>
                  </div>
                </div>

                {analysisResult && (
                  <div className="code-analysis-results">
                    <div className="panel code-analysis-summary">
                      <div className="panel-title-main">
                        <IconBadge tone={codeFindings.length ? "amber" : "mint"}>
                          {codeFindings.length ? <AlertTriangle size={17} /> : <ShieldCheck size={17} />}
                        </IconBadge>
                        <div>
                          <h3>{codeFindings.length ? `${codeFindings.length} potential finding${codeFindings.length === 1 ? "" : "s"}` : "No matching patterns detected"}</h3>
                          <p>File: {analysis?.file || "pasted-code.js"} · Analysis: {analysis?.analysis || "heuristic"}</p>
                        </div>
                      </div>
                      {analysis?.limitation && <p className="disclaimer">{analysis.limitation}</p>}
                      {analysisResult?.graph && (
                        <p className="panel-note">
                          Graph ingestion: {analysisResult.graph.findingsStored ?? codeFindings.length} finding(s) reported as stored.
                        </p>
                      )}
                      {analysisResult?.graph?.scanId && (
                        <div className="code-scan-actions">
                          <span>Scan ID: {analysisResult.graph.scanId}</span>
                          <button
                            className="button button-secondary"
                            onClick={investigateCurrentScan}
                            disabled={investigationBusy}
                          >
                            {investigationBusy ? (
                              <LoaderCircle className="spin" size={16} />
                            ) : (
                              <GitBranch size={16} />
                            )}
                            {investigationBusy ? "Investigating…" : "Investigate findings"}
                          </button>
                        </div>
                      )}
                    </div>

                    {codeFindings.length > 0 ? (
                      <div className="findings-grid">
                        {codeFindings.map((finding, index) => (
                          <FindingCard
                            key={`${finding.ruleId || finding.type}-${finding.line}-${index}`}
                            finding={{
                              ...finding,
                              file: analysis?.file || "pasted-code.js",
                              sink: "Not confirmed by static analysis",
                              asset: "Not established",
                              sensitivity: "Unknown",
                            }}
                            index={index}
                          />
                        ))}
                      </div>
                    ) : (
                      <div className="panel empty-state">
                        <ShieldCheck size={20} />
                        No findings matched the current rule. This does not prove the code is secure.
                      </div>
                    )}
                  </div>
                )}
              </section>

              <section className="section-block">
                <SectionHeading
                  eyebrow="INVESTIGATION"
                  title="Attack-path overview"
                  description="Compare the modeled vulnerable route with a parameterized, safer route."
                  action={<Pill tone="neutral"><CircleDot size={11} /> Synthetic demo</Pill>}
                />
                <div className="flows-grid">
                  <FlowPath title="Untrusted input to sensitive asset" description="A modeled route through a SQL execution sink" items={vulnerable} />
                  <FlowPath title="Parameterized query flow" description="A safer modeled route using query binding" items={safer} safe />
                </div>
              </section>

              <section className="section-block">
                <AssetPanel data={blastRadius} loading={blastLoading} onRetry={loadBlastRadius} />
              </section>

              {latest && <section className="section-block"><InvestigationResult data={latest} /></section>}

              <section className="section-block">
                <SectionHeading
                  eyebrow="EVIDENCE"
                  title="Graph-backed findings"
                  description="Findings linked to modeled sinks and assets in FalkorDB."
                  action={<Pill tone={graphEvidence.length ? "amber" : "mint"}>{graphEvidence.length} {graphEvidence.length === 1 ? "finding" : "findings"}</Pill>}
                />
                {graphEvidence.length ? (
                  <div className="findings-grid">{graphEvidence.map((finding, index) => <FindingCard finding={finding} index={index} key={`${finding.ruleId || finding.type}-${finding.file}-${index}`} />)}</div>
                ) : (
                  <div className="panel empty-state"><ShieldCheck size={20} /><div><strong>No graph findings returned</strong><p>Run the vulnerable demo analyzer and refresh to load evidence.</p></div></div>
                )}
              </section>

              <section className="section-block">
                <SectionHeading eyebrow="PERSISTENT MEMORY" title="Recent investigations" description="Investigation records stored in the graph, available for review." action={<button className="text-button" onClick={() => setActiveView("memory")}>View history <ArrowRight size={14} /></button>} />
                <HistoryTable history={history.slice(0, 4)} />
              </section>
            </>
          )}

          {activeView === "attack-paths" && (
            <section className="section-block">
              <SectionHeading eyebrow="GRAPH EXPLORER" title="Attack paths" description="Inspect the modeled routes between inputs, execution sinks, and affected assets." />
              <div className="flows-grid">
                <FlowPath title="Potentially vulnerable path" description="Untrusted input can reach the modeled SQL sink" items={vulnerable} />
                <FlowPath title="Protected path" description="Parameterized query binding appears in the modeled flow" items={safer} safe />
              </div>
              <div className="section-block-inner"><AssetPanel data={blastRadius} loading={blastLoading} onRetry={loadBlastRadius} /></div>
            </section>
          )}

          {activeView === "findings" && (
            <section className="section-block">
              <SectionHeading eyebrow="EVIDENCE REGISTER" title="Security findings" description="Source patterns and graph context associated with the demo findings." action={<Pill tone={graphEvidence.length ? "amber" : "mint"}>{graphEvidence.length} records</Pill>} />
              {graphEvidence.length ? <div className="findings-grid">{graphEvidence.map((finding, index) => <FindingCard finding={finding} index={index} key={`${finding.ruleId || finding.type}-${finding.file}-${index}`} />)}</div> : <div className="panel empty-state">No findings yet. Run the vulnerable demo analysis first.</div>}
              <p className="disclaimer global-disclaimer">Pattern-based findings require review. A modeled path is not proof of runtime exploitability, and no findings does not prove code is safe.</p>
            </section>
          )}

          {activeView === "memory" && (
            <section className="section-block">
              <SectionHeading eyebrow="PERSISTENT MEMORY" title="Investigation history" description="Search and review investigation records persisted in FalkorDB." />
              <div className="panel history-panel">
                <label className="search-field"><Search size={16} /><input value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Search ID, status, or finding…" /></label>
                <HistoryTable history={filteredHistory} />
                {!filteredHistory.length && <div className="empty-state">No matching investigation records.</div>}
              </div>
            </section>
          )}

          <footer className="app-footer">
            <div className="footer-brand"><span className="footer-mark"><ShieldCheck size={14} /></span> SECURELENS NEXUS</div>
            <div className="footer-meta"><span>SYNTHETIC DEMO DATA</span><i /> <span>EVIDENCE-LED SECURITY</span>{lastUpdated && <><i /><span>Updated {lastUpdated.toLocaleTimeString()}</span></>}</div>
          </footer>
        </main>
      </div>
    </main>
  );
}

function HistoryTable({ history }) {
  return (
    <div className="table-wrap">
      <table className="history-table">
        <thead><tr><th>Investigation</th><th>Status</th><th>Summary</th><th>Created</th></tr></thead>
        <tbody>
          {history.map((item) => (
            <tr key={item.id}>
              <td><span className="table-id">{item.id}</span></td>
              <td><Pill tone={item.status === "potential-risk" ? "amber" : "mint"}>{item.status || "completed"}</Pill></td>
              <td className="table-summary">{item.finding || "No summary provided"}</td>
              <td className="table-date"><Clock3 size={13} /> {formatDate(item.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


function AuthScreen({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = await request(mode === "login" ? "/auth/login" : "/auth/register", {
        method: "POST",
        body: JSON.stringify(mode === "login" ? { email, password } : { name, email, password }),
        headers: {},
      });
      if (!data.token || !data.user) {
        throw new Error("The authentication API response is incomplete.");
      }
      localStorage.setItem("securelens_token", data.token);
      onAuthenticated(data.user);
    } catch (e) {
      setError(e.message || "Unable to authenticate.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <div className="auth-glow auth-glow-one" />
      <div className="auth-glow auth-glow-two" />
      <section className="auth-brand-panel">
        <a className="brand auth-brand" href="#login">
          <span className="brand-mark"><ShieldCheck size={22} /></span>
          <span className="brand-copy">
            <strong>SecureLens<span> Nexus</span></strong>
            <small>GRAPH SECURITY INTELLIGENCE</small>
          </span>
        </a>
        <div className="auth-pitch">
          <div className="eyebrow"><span className="eyebrow-line" /> GRAPH-NATIVE SECURITY</div>
          <h1>See the risk<br />behind the <span>relationships.</span></h1>
          <p>Investigate how code flows connect to sensitive assets. Every path, finding, and recommendation stays grounded in graph evidence.</p>
          <div className="auth-feature-list">
            <div><IconBadge tone="mint"><GitBranch size={17} /></IconBadge><span><strong>Multi-hop attack paths</strong><small>Follow modeled input-to-sink relationships.</small></span></div>
            <div><IconBadge tone="violet"><Database size={17} /></IconBadge><span><strong>Graph-backed evidence</strong><small>Trace findings to their connected assets.</small></span></div>
            <div><IconBadge tone="blue"><ShieldCheck size={17} /></IconBadge><span><strong>Private workspace</strong><small>Keep each user's investigation history isolated.</small></span></div>
          </div>
        </div>
        <div className="auth-footer-note"><span className="status-dot" /> FalkorDB-powered investigation workspace <span className="auth-footer-separator">·</span> Synthetic demo data</div>
      </section>

      <section className="auth-form-side">
        <div className="auth-form-card">
          <div className="auth-form-icon"><ShieldCheck size={22} /></div>
          <div className="section-eyebrow">{mode === "login" ? "WELCOME BACK" : "GET STARTED"}</div>
          <h2>{mode === "login" ? "Sign in to SecureLens" : "Create your workspace"}</h2>
          <p className="auth-subtitle">{mode === "login" ? "Continue to your security investigation workspace." : "Create an account to save and review your investigations."}</p>

          <div className="auth-mode-switch">
            <button className={mode === "login" ? "selected" : ""} onClick={() => { setMode("login"); setError(""); }}>Sign in</button>
            <button className={mode === "register" ? "selected" : ""} onClick={() => { setMode("register"); setError(""); }}>Create account</button>
          </div>

          <form className="auth-form" onSubmit={submit}>
            {mode === "register" && (
              <label className="auth-label">Full name
                <input value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" placeholder="Your name" minLength={2} maxLength={80} required />
              </label>
            )}
            <label className="auth-label">Email address
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" placeholder="you@example.com" maxLength={254} required />
            </label>
            <label className="auth-label">Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === "login" ? "current-password" : "new-password"} placeholder={mode === "register" ? "At least 10 characters" : "Enter your password"} minLength={mode === "register" ? 10 : 1} required />
            </label>
            {error && <div className="auth-error"><AlertTriangle size={16} />{error}</div>}
            <button className="button button-primary auth-submit" type="submit" disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={17} /> : <ArrowRight size={17} />}
              {busy ? "Please wait…" : mode === "login" ? "Sign in securely" : "Create account"}
            </button>
          </form>
          <div className="auth-security-note"><Shield size={15} /><span>Account credentials should be handled by the backend and never stored in the graph.</span></div>
          <p className="auth-demo-note">Hackathon demo · Use a test account. Do not enter a password you use elsewhere.</p>
        </div>
      </section>
    </main>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [checkingSession, setCheckingSession] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("securelens_token");
    if (!token) {
      setCheckingSession(false);
      return;
    }
    request("/auth/me")
      .then((data) => {
        if (!data.user) throw new Error("Session expired");
        setUser(data.user);
      })
      .catch(() => {
        localStorage.removeItem("securelens_token");
        setUser(null);
      })
      .finally(() => setCheckingSession(false));
  }, []);

  function logout() {
    localStorage.removeItem("securelens_token");
    setUser(null);
  }

  if (checkingSession) {
    return <main className="auth-loading"><LoaderCircle className="spin" size={22} /><span>Checking your session…</span></main>;
  }

  return user
    ? <Dashboard user={user} onLogout={logout} />
    : <AuthScreen onAuthenticated={setUser} />;
}
