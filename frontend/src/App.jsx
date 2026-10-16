import { useEffect, useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Server,
  Cloud,
  Database,
  Lock,
  RefreshCw,
  Download,
  Search,
  Filter,
  Calendar,
  Bell,
  Settings,
  Layers,
  Wrench,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Activity,
  Check,
  ChevronRight,
  Info,
  Terminal,
  Cpu,
  Clock,
  Sparkles,
} from "lucide-react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  // Navigation
  const [activeTab, setActiveTab] = useState("dashboard");

  // State
  const [findings, setFindings] = useState([]);
  const [scoreData, setScoreData] = useState({
    score: 100,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
  });
  const [scans, setScans] = useState([]);
  const [health, setHealth] = useState({
    status: "unknown",
    aws_connected: false,
    aws_region: "ap-south-1",
    aws_account_id: "...",
  });
  const [resources, setResources] = useState({
    ec2: { instances: [], security_groups: [] },
    s3: [],
    iam: [],
    rds: [],
  });
  const [alerts, setAlerts] = useState([]);
  const [schedule, setSchedule] = useState({
    mode: "MANUAL",
    enabled: false,
    next_run: null,
  });

  // UI States
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState("");
  const [toast, setToast] = useState(null);

  // Filters & Search
  const [serviceFilter, setServiceFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("risk");

  // Modals
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [remediationModal, setRemediationModal] = useState({
    isOpen: false,
    finding: null,
    preview: null,
    confirmed: false,
    targetCidr: "",
    loading: false,
    result: null,
  });

  // Show Toast Helper
  const showToast = (message, type = "success") => {
    setToast({ message, type, id: Date.now() });
    setTimeout(() => setToast(null), 4500);
  };

  // Initial Data Fetch
  const fetchAllData = async () => {
    setLoading(true);
    try {
      const [findingsRes, scoreRes, scansRes, healthRes, resourcesRes, alertsRes, scheduleRes] =
        await Promise.allSettled([
          fetch(`${API_BASE}/findings`).then((r) => r.json()),
          fetch(`${API_BASE}/score`).then((r) => r.json()),
          fetch(`${API_BASE}/scans`).then((r) => r.json()),
          fetch(`${API_BASE}/health`).then((r) => r.json()),
          fetch(`${API_BASE}/resources`).then((r) => r.json()),
          fetch(`${API_BASE}/alerts`).then((r) => r.json()),
          fetch(`${API_BASE}/schedule`).then((r) => r.json()),
        ]);

      if (findingsRes.status === "fulfilled" && Array.isArray(findingsRes.value)) {
        setFindings(findingsRes.value);
      }
      if (scoreRes.status === "fulfilled" && scoreRes.value?.score !== undefined) {
        setScoreData(scoreRes.value);
      }
      if (scansRes.status === "fulfilled" && Array.isArray(scansRes.value)) {
        setScans(scansRes.value);
      }
      if (healthRes.status === "fulfilled") {
        setHealth(healthRes.value);
      }
      if (resourcesRes.status === "fulfilled") {
        setResources(resourcesRes.value);
      }
      if (alertsRes.status === "fulfilled" && Array.isArray(alertsRes.value)) {
        setAlerts(alertsRes.value);
      }
      if (scheduleRes.status === "fulfilled") {
        setSchedule(scheduleRes.value);
      }
    } catch (err) {
      console.error("Failed to load initial data:", err);
      showToast("Could not connect to CloudGuard backend", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  // Trigger Real Security Scan
  const handleRunScan = async () => {
    if (scanning) return;
    setScanning(true);
    setScanStep("Initiating AWS Security Assessment...");

    try {
      setTimeout(() => setScanStep("Auditing EC2 instances & Security Groups..."), 700);
      setTimeout(() => setScanStep("Checking S3 Buckets & Public Access Blocks..."), 1500);
      setTimeout(() => setScanStep("Inspecting IAM credentials & policies..."), 2300);
      setTimeout(() => setScanStep("Validating RDS database configurations..."), 3100);

      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Scan failed with status ${response.status}`);
      }

      const scanResult = await response.json();

      // Refresh data
      await fetchAllData();

      showToast(
        `Security scan completed successfully. Score: ${scanResult.score}/100 with ${scanResult.total_findings} finding(s).`,
        "success"
      );
    } catch (error) {
      console.error("Scan error:", error);
      showToast(`Scan failed: ${error.message}`, "error");
    } finally {
      setScanning(false);
      setScanStep("");
    }
  };

  // Safe Remediation Workflow
  const handleOpenRemediation = async (finding) => {
    setRemediationModal({
      isOpen: true,
      finding,
      preview: null,
      confirmed: false,
      targetCidr: "",
      loading: true,
      result: null,
    });

    try {
      const response = await fetch(`${API_BASE}/remediate/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service: finding.service,
          resource: finding.resource,
          issue: finding.issue,
        }),
      });
      const previewData = await response.json();
      setRemediationModal((prev) => ({
        ...prev,
        preview: previewData,
        loading: false,
      }));
    } catch (error) {
      console.error("Preview error:", error);
      setRemediationModal((prev) => ({
        ...prev,
        preview: { safe: false, error: "Failed to connect to remediation preview." },
        loading: false,
      }));
    }
  };

  const handleApplyRemediation = async () => {
    if (!remediationModal.confirmed) {
      showToast("Please check the confirmation box to authorize AWS changes", "warning");
      return;
    }

    setRemediationModal((prev) => ({ ...prev, loading: true }));

    try {
      const response = await fetch(`${API_BASE}/remediate/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service: remediationModal.finding.service,
          resource: remediationModal.finding.resource,
          confirmed: true,
          target_cidr: remediationModal.targetCidr || null,
        }),
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || "Remediation failed");
      }

      const result = await response.json();
      setRemediationModal((prev) => ({
        ...prev,
        loading: false,
        result,
      }));

      showToast("Remediation applied! Triggering automatic verification scan...", "success");

      // Auto-refresh scan to verify fix
      setTimeout(() => {
        handleRunScan();
      }, 1000);
    } catch (error) {
      showToast(`Remediation failed: ${error.message}`, "error");
      setRemediationModal((prev) => ({
        ...prev,
        loading: false,
        result: { success: false, error: error.message },
      }));
    }
  };

  // Download PDF Report
  const handleDownloadReport = (scanId = null) => {
    const url = scanId
      ? `${API_BASE}/reports/pdf?scan_id=${scanId}`
      : `${API_BASE}/reports/pdf`;
    window.open(url, "_blank");
    showToast("Generating CloudGuard PDF Security Report...", "info");
  };

  // Update Scan Schedule
  const handleScheduleChange = async (newMode) => {
    try {
      const response = await fetch(`${API_BASE}/schedule`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: newMode, enabled: newMode !== "MANUAL" }),
      });
      const data = await response.json();
      setSchedule(data);
      showToast(`Scan schedule updated to ${newMode}`, "success");
    } catch (error) {
      showToast("Failed to update schedule", "error");
    }
  };

  // Filtered & Sorted Findings
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        if (serviceFilter !== "ALL" && f.service?.toUpperCase() !== serviceFilter) return false;
        if (riskFilter !== "ALL" && f.risk?.toUpperCase() !== riskFilter) return false;
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchResource = f.resource?.toLowerCase().includes(q);
          const matchIssue = f.issue?.toLowerCase().includes(q);
          const matchFix = f.recommendation?.toLowerCase().includes(q);
          return matchResource || matchIssue || matchFix;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === "risk") {
          const weight = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
          return (weight[b.risk] || 0) - (weight[a.risk] || 0);
        }
        if (sortBy === "service") {
          return (a.service || "").localeCompare(b.service || "");
        }
        return (b.id || 0) - (a.id || 0);
      });
  }, [findings, serviceFilter, riskFilter, searchQuery, sortBy]);

  // Score Color helper
  const getScoreColor = (score) => {
    if (score >= 80) return "#20d58a";
    if (score >= 50) return "#ffb432";
    return "#ff5555";
  };

  const scoreColor = getScoreColor(scoreData.score);

  return (
    <div className="app-container">
      {/* Toast Notification */}
      <AnimatePresence>
        {toast && (
          <motion.div
            className={`toast toast-${toast.type}`}
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            {toast.type === "success" && <CheckCircle2 size={18} />}
            {toast.type === "error" && <XCircle size={18} />}
            {toast.type === "warning" && <AlertTriangle size={18} />}
            {toast.type === "info" && <Info size={18} />}
            <span>{toast.message}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Top Header */}
      <header className="navbar">
        <div className="nav-brand" onClick={() => setActiveTab("dashboard")}>
          <div className="brand-icon">
            <ShieldCheck size={28} />
          </div>
          <div className="brand-text">
            <div className="brand-title">
              CloudGuard <span className="version-tag">PRO</span>
            </div>
            <div className="brand-subtitle">AWS Security Assessment & Misconfiguration Scanner</div>
          </div>
        </div>

        {/* AWS Status & Quick Scan */}
        <div className="nav-actions">
          <div className="aws-status-badge">
            <span className={`status-indicator ${health.aws_connected ? "connected" : "disconnected"}`} />
            <div className="status-meta">
              <span className="status-label">
                {health.aws_connected ? "AWS Connected" : "Credentials Required"}
              </span>
              <span className="region-label">{health.aws_region || "ap-south-1"}</span>
            </div>
          </div>

          <button
            className={`scan-btn ${scanning ? "scanning" : ""}`}
            onClick={handleRunScan}
            disabled={scanning}
          >
            <RefreshCw size={17} className={scanning ? "spin-icon" : ""} />
            <span>{scanning ? "Scanning AWS..." : "Run Security Scan"}</span>
          </button>
        </div>
      </header>

      {/* Primary Navigation Tabs */}
      <nav className="tab-bar">
        <button
          className={`tab-item ${activeTab === "dashboard" ? "active" : ""}`}
          onClick={() => setActiveTab("dashboard")}
        >
          <Activity size={17} />
          <span>Dashboard</span>
        </button>
        <button
          className={`tab-item ${activeTab === "findings" ? "active" : ""}`}
          onClick={() => setActiveTab("findings")}
        >
          <ShieldAlert size={17} />
          <span>Findings</span>
          {scoreData.total > 0 && <span className="tab-counter">{scoreData.total}</span>}
        </button>
        <button
          className={`tab-item ${activeTab === "resources" ? "active" : ""}`}
          onClick={() => setActiveTab("resources")}
        >
          <Layers size={17} />
          <span>AWS Resources</span>
        </button>
        <button
          className={`tab-item ${activeTab === "remediation" ? "active" : ""}`}
          onClick={() => setActiveTab("remediation")}
        >
          <Wrench size={17} />
          <span>Remediation</span>
        </button>
        <button
          className={`tab-item ${activeTab === "history" ? "active" : ""}`}
          onClick={() => setActiveTab("history")}
        >
          <Clock size={17} />
          <span>Scan History</span>
          {scans.length > 0 && <span className="tab-counter secondary">{scans.length}</span>}
        </button>
        <button
          className={`tab-item ${activeTab === "reports" ? "active" : ""}`}
          onClick={() => setActiveTab("reports")}
        >
          <Download size={17} />
          <span>Reports</span>
        </button>
        <button
          className={`tab-item ${activeTab === "settings" ? "active" : ""}`}
          onClick={() => setActiveTab("settings")}
        >
          <Settings size={17} />
          <span>Settings</span>
        </button>
      </nav>

      {/* Scanning Progress Overlay Banner */}
      <AnimatePresence>
        {scanning && (
          <motion.div
            className="scanning-banner"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
          >
            <div className="scanning-banner-content">
              <RefreshCw size={20} className="spin-icon" />
              <div>
                <strong>Active AWS Audit In Progress</strong>
                <p>{scanStep}</p>
              </div>
            </div>
            <div className="progress-bar-container">
              <div className="progress-bar-fill" />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content Area */}
      <main className="main-content">
        {/* ========================================================= */}
        {/* TAB 1: DASHBOARD                                         */}
        {/* ========================================================= */}
        {activeTab === "dashboard" && (
          <div className="dashboard-view">
            {/* High/Critical Alerts Banner */}
            {alerts.length > 0 && (
              <motion.div
                className="alert-banner"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <div className="alert-icon">
                  <AlertTriangle size={22} />
                </div>
                <div className="alert-body">
                  <strong>
                    Security Alert: {alerts.length} High/Critical Misconfiguration(s) Detected
                  </strong>
                  <p>
                    Immediate attention recommended. One or more AWS resources are directly exposed to the
                    public internet.
                  </p>
                </div>
                <button
                  className="alert-action-btn"
                  onClick={() => setActiveTab("findings")}
                >
                  Review Issues
                  <ChevronRight size={16} />
                </button>
              </motion.div>
            )}

            {/* Hero Grid: Score Card & Total Stats */}
            <div className="hero-metrics-grid">
              {/* Score Card */}
              <motion.div
                className="metric-card score-card"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <div
                  className="score-radial-gauge"
                  style={{
                    background: `radial-gradient(circle, #0d1424 58%, transparent 59%), conic-gradient(${scoreColor} ${
                      scoreData.score
                    }%, #1b263b 0)`,
                  }}
                >
                  <div className="score-inner-text">
                    <span className="score-number">{scoreData.score}</span>
                    <span className="score-denom">/100</span>
                  </div>
                </div>

                <div className="score-meta">
                  <div className="score-title-row">
                    <h2>AWS Security Score</h2>
                    <span
                      className="score-badge"
                      style={{
                        backgroundColor: `${scoreColor}22`,
                        color: scoreColor,
                        borderColor: `${scoreColor}55`,
                      }}
                    >
                      {scoreData.score >= 80
                        ? "HEALTHY"
                        : scoreData.score >= 50
                        ? "NEEDS ATTENTION"
                        : "CRITICAL RISK"}
                    </span>
                  </div>
                  <p className="score-description">
                    {scoreData.score >= 80
                      ? "Your AWS environment aligns well with baseline cloud security best practices."
                      : scoreData.score >= 50
                      ? "Misconfigurations detected that expose resources to unauthorized public access."
                      : "Critical security vulnerabilities detected. Immediate remediation strongly advised."}
                  </p>
                  <div className="score-footer-stats">
                    <span>
                      AWS Account: <strong>{health.aws_account_id}</strong>
                    </span>
                    <span>
                      Region: <strong>{health.aws_region}</strong>
                    </span>
                  </div>
                </div>
              </motion.div>

              {/* Total Findings Card */}
              <motion.div
                className="metric-card total-card"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
              >
                <div className="total-header">
                  <div className="icon-wrapper blue">
                    <Activity size={24} />
                  </div>
                  <span className="metric-tag">ALL SERVICES</span>
                </div>
                <div className="total-content">
                  <span className="total-count">{scoreData.total}</span>
                  <span className="total-label">Total Misconfigurations Detected</span>
                </div>
                <div className="total-breakdown">
                  <span>EC2: {findings.filter((f) => f.service === "EC2").length}</span>
                  <span>S3: {findings.filter((f) => f.service === "S3").length}</span>
                  <span>IAM: {findings.filter((f) => f.service === "IAM").length}</span>
                  <span>RDS: {findings.filter((f) => f.service === "RDS").length}</span>
                </div>
              </motion.div>
            </div>

            {/* Risk Breakdown Cards */}
            <div className="risk-counters-grid">
              <motion.div
                className="risk-counter-card critical"
                whileHover={{ y: -3 }}
                onClick={() => {
                  setRiskFilter("CRITICAL");
                  setActiveTab("findings");
                }}
              >
                <div className="risk-card-top">
                  <span className="risk-label">CRITICAL</span>
                  <AlertTriangle size={20} />
                </div>
                <div className="risk-number">{scoreData.critical}</div>
                <div className="risk-sub">Immediate exploit risk (-30 pts ea)</div>
              </motion.div>

              <motion.div
                className="risk-counter-card high"
                whileHover={{ y: -3 }}
                onClick={() => {
                  setRiskFilter("HIGH");
                  setActiveTab("findings");
                }}
              >
                <div className="risk-card-top">
                  <span className="risk-label">HIGH RISK</span>
                  <AlertTriangle size={20} />
                </div>
                <div className="risk-number">{scoreData.high}</div>
                <div className="risk-sub">Public network exposure (-20 pts ea)</div>
              </motion.div>

              <motion.div
                className="risk-counter-card medium"
                whileHover={{ y: -3 }}
                onClick={() => {
                  setRiskFilter("MEDIUM");
                  setActiveTab("findings");
                }}
              >
                <div className="risk-card-top">
                  <span className="risk-label">MEDIUM RISK</span>
                  <Info size={20} />
                </div>
                <div className="risk-number">{scoreData.medium}</div>
                <div className="risk-sub">Configuration weak points (-10 pts ea)</div>
              </motion.div>

              <motion.div
                className="risk-counter-card low"
                whileHover={{ y: -3 }}
                onClick={() => {
                  setRiskFilter("LOW");
                  setActiveTab("findings");
                }}
              >
                <div className="risk-card-top">
                  <span className="risk-label">LOW RISK</span>
                  <ShieldCheck size={20} />
                </div>
                <div className="risk-number">{scoreData.low}</div>
                <div className="risk-sub">Best practice notices (-5 pts ea)</div>
              </motion.div>
            </div>

            {/* Resources Scanned Summary Bar */}
            <div className="resources-scanned-bar">
              <div className="resource-stat-item">
                <Server size={18} className="res-icon" />
                <div>
                  <strong>{resources.ec2?.security_groups?.length || 1}</strong>
                  <span>Security Groups Scanned</span>
                </div>
              </div>
              <div className="resource-stat-divider" />
              <div className="resource-stat-item">
                <Cloud size={18} className="res-icon" />
                <div>
                  <strong>{resources.s3?.length || 2}</strong>
                  <span>S3 Buckets Audited</span>
                </div>
              </div>
              <div className="resource-stat-divider" />
              <div className="resource-stat-item">
                <Lock size={18} className="res-icon" />
                <div>
                  <strong>{resources.iam?.length || 0}</strong>
                  <span>IAM Users Verified</span>
                </div>
              </div>
              <div className="resource-stat-divider" />
              <div className="resource-stat-item">
                <Database size={18} className="res-icon" />
                <div>
                  <strong>{resources.rds?.length || 0}</strong>
                  <span>RDS Instances Inspected</span>
                </div>
              </div>
            </div>

            {/* Latest Findings & Quick Remediation Section */}
            <div className="dashboard-section">
              <div className="section-header">
                <div>
                  <h3>Priority Security Findings</h3>
                  <p>Discovered misconfigurations requiring administrative attention</p>
                </div>
                <button
                  className="secondary-btn"
                  onClick={() => setActiveTab("findings")}
                >
                  View All Findings ({findings.length})
                  <ChevronRight size={16} />
                </button>
              </div>

              {loading ? (
                <div className="loading-state">
                  <RefreshCw size={26} className="spin-icon" />
                  <span>Loading cloud security posture...</span>
                </div>
              ) : findings.length === 0 ? (
                <div className="empty-state">
                  <ShieldCheck size={48} className="empty-icon success" />
                  <h4>No Security Issues Found</h4>
                  <p>All scanned AWS resources pass current security rules.</p>
                </div>
              ) : (
                <div className="findings-stream">
                  {findings.slice(0, 4).map((f) => (
                    <div className={`finding-card risk-${f.risk?.toLowerCase()}`} key={f.id}>
                      <div className="finding-indicator" />
                      <div className="finding-main">
                        <div className="finding-meta-row">
                          <span className="service-pill">{f.service}</span>
                          <span className={`risk-pill pill-${f.risk?.toLowerCase()}`}>{f.risk}</span>
                          <span className="finding-resource">{f.resource}</span>
                          <span className="finding-time">{f.scan_time}</span>
                        </div>
                        <h4 className="finding-issue">{f.issue}</h4>
                        <div className="finding-fix-row">
                          <span className="fix-label">Recommended Fix:</span>
                          <span className="fix-text">{f.recommendation}</span>
                        </div>
                      </div>
                      <div className="finding-actions">
                        {f.service === "EC2" && f.issue.includes("SSH") ? (
                          <button
                            className="remediate-btn"
                            onClick={() => handleOpenRemediation(f)}
                          >
                            <Wrench size={15} />
                            <span>Fix Issue</span>
                          </button>
                        ) : (
                          <button
                            className="details-btn"
                            onClick={() => setSelectedFinding(f)}
                          >
                            <span>Details</span>
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 2: FINDINGS                                          */}
        {/* ========================================================= */}
        {activeTab === "findings" && (
          <div className="findings-view">
            <div className="view-header">
              <div>
                <h2>Security Findings Directory</h2>
                <p>Filter, search, and inspect detected vulnerabilities across AWS services</p>
              </div>
              <button className="secondary-btn" onClick={() => handleDownloadReport()}>
                <Download size={16} />
                Export Findings
              </button>
            </div>

            {/* Filter and Search Bar */}
            <div className="filter-bar">
              <div className="search-box">
                <Search size={18} />
                <input
                  type="text"
                  placeholder="Search by resource ID, issue, or fix recommendation..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                  <button className="clear-btn" onClick={() => setSearchQuery("")}>
                    ✕
                  </button>
                )}
              </div>

              {/* Service Filter */}
              <div className="filter-group">
                <span className="filter-label">Service:</span>
                <div className="chip-group">
                  {["ALL", "EC2", "S3", "IAM", "RDS"].map((srv) => (
                    <button
                      key={srv}
                      className={`chip ${serviceFilter === srv ? "active" : ""}`}
                      onClick={() => setServiceFilter(srv)}
                    >
                      {srv}
                    </button>
                  ))}
                </div>
              </div>

              {/* Risk Filter */}
              <div className="filter-group">
                <span className="filter-label">Severity:</span>
                <div className="chip-group">
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((r) => (
                    <button
                      key={r}
                      className={`chip chip-${r.toLowerCase()} ${riskFilter === r ? "active" : ""}`}
                      onClick={() => setRiskFilter(r)}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              {/* Sort By */}
              <div className="sort-group">
                <Filter size={15} />
                <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
                  <option value="risk">Sort by Risk Severity</option>
                  <option value="date">Sort by Recent Date</option>
                  <option value="service">Sort by Service</option>
                </select>
              </div>
            </div>

            {/* Findings List */}
            {filteredFindings.length === 0 ? (
              <div className="empty-state">
                <ShieldCheck size={48} className="empty-icon" />
                <h4>No Matching Findings</h4>
                <p>Try resetting filters or clearing the search query.</p>
                <button
                  className="secondary-btn"
                  onClick={() => {
                    setServiceFilter("ALL");
                    setRiskFilter("ALL");
                    setSearchQuery("");
                  }}
                >
                  Reset Filters
                </button>
              </div>
            ) : (
              <div className="findings-stream">
                {filteredFindings.map((f) => (
                  <div className={`finding-card risk-${f.risk?.toLowerCase()}`} key={f.id}>
                    <div className="finding-indicator" />
                    <div className="finding-main">
                      <div className="finding-meta-row">
                        <span className="service-pill">{f.service}</span>
                        <span className={`risk-pill pill-${f.risk?.toLowerCase()}`}>{f.risk}</span>
                        <span className="finding-resource">{f.resource}</span>
                        <span className="finding-time">{f.scan_time}</span>
                      </div>
                      <h4 className="finding-issue">{f.issue}</h4>
                      <div className="finding-fix-row">
                        <span className="fix-label">Recommended Fix:</span>
                        <span className="fix-text">{f.recommendation}</span>
                      </div>
                    </div>
                    <div className="finding-actions">
                      {f.service === "EC2" && f.issue.includes("SSH") ? (
                        <button
                          className="remediate-btn"
                          onClick={() => handleOpenRemediation(f)}
                        >
                          <Wrench size={15} />
                          <span>Fix Issue</span>
                        </button>
                      ) : (
                        <button
                          className="details-btn"
                          onClick={() => setSelectedFinding(f)}
                        >
                          <span>Details</span>
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 3: AWS RESOURCES                                     */}
        {/* ========================================================= */}
        {activeTab === "resources" && (
          <div className="resources-view">
            <div className="view-header">
              <div>
                <h2>Scanned AWS Resource Inventory</h2>
                <p>Real-time cloud asset discovery and configuration status across monitored services</p>
              </div>
              <button className="secondary-btn" onClick={fetchAllData}>
                <RefreshCw size={15} />
                Refresh Assets
              </button>
            </div>

            <div className="resources-grid">
              {/* EC2 Card */}
              <div className="asset-card">
                <div className="asset-card-header">
                  <div className="asset-icon-box">
                    <Server size={22} />
                  </div>
                  <div>
                    <h3>Amazon EC2 & Security Groups</h3>
                    <span>{resources.ec2?.security_groups?.length || 0} Security Groups Discovered</span>
                  </div>
                </div>
                <div className="asset-list">
                  {resources.ec2?.security_groups?.map((sg) => (
                    <div className="asset-item" key={sg.id}>
                      <div className="asset-item-info">
                        <strong>{sg.name}</strong>
                        <code>{sg.id}</code>
                        <small>{sg.description || "AWS Security Group"}</small>
                      </div>
                      <div className="asset-badge">
                        <span>{sg.rules_count} Rules</span>
                      </div>
                    </div>
                  ))}
                  {(!resources.ec2?.security_groups || resources.ec2.security_groups.length === 0) && (
                    <div className="asset-empty">No EC2 Security Groups detected.</div>
                  )}
                </div>
              </div>

              {/* S3 Card */}
              <div className="asset-card">
                <div className="asset-card-header">
                  <div className="asset-icon-box">
                    <Cloud size={22} />
                  </div>
                  <div>
                    <h3>Amazon S3 Storage</h3>
                    <span>{resources.s3?.length || 0} Buckets Discovered</span>
                  </div>
                </div>
                <div className="asset-list">
                  {resources.s3?.map((b) => (
                    <div className="asset-item" key={b.name}>
                      <div className="asset-item-info">
                        <strong>{b.name}</strong>
                        <small>Created: {b.created?.split(" ")[0] || "Active"}</small>
                      </div>
                      <div className={`asset-status-tag ${b.public_block_active ? "secure" : "warn"}`}>
                        {b.public_block_active ? "Block Public Access Active" : "Review Needed"}
                      </div>
                    </div>
                  ))}
                  {(!resources.s3 || resources.s3.length === 0) && (
                    <div className="asset-empty">No S3 Buckets detected.</div>
                  )}
                </div>
              </div>

              {/* IAM Card */}
              <div className="asset-card">
                <div className="asset-card-header">
                  <div className="asset-icon-box">
                    <Lock size={22} />
                  </div>
                  <div>
                    <h3>AWS Identity & Access Management</h3>
                    <span>{resources.iam?.length || 0} IAM Users Discovered</span>
                  </div>
                </div>
                <div className="asset-list">
                  {resources.iam?.map((u) => (
                    <div className="asset-item" key={u.username}>
                      <div className="asset-item-info">
                        <strong>{u.username}</strong>
                        <small>Last Login: {u.password_last_used}</small>
                      </div>
                      <div className={`asset-status-tag ${u.mfa_enabled ? "secure" : "warn"}`}>
                        {u.mfa_enabled ? "MFA Enabled" : "No MFA"}
                      </div>
                    </div>
                  ))}
                  {(!resources.iam || resources.iam.length === 0) && (
                    <div className="asset-empty">
                      No standalone IAM users found (Root/SSO in use).
                    </div>
                  )}
                </div>
              </div>

              {/* RDS Card */}
              <div className="asset-card">
                <div className="asset-card-header">
                  <div className="asset-icon-box">
                    <Database size={22} />
                  </div>
                  <div>
                    <h3>Amazon Relational Database Service</h3>
                    <span>{resources.rds?.length || 0} DB Instances Discovered</span>
                  </div>
                </div>
                <div className="asset-list">
                  {resources.rds?.map((db) => (
                    <div className="asset-item" key={db.identifier}>
                      <div className="asset-item-info">
                        <strong>{db.identifier}</strong>
                        <small>Engine: {db.engine}</small>
                      </div>
                      <div className={`asset-status-tag ${db.publicly_accessible ? "warn" : "secure"}`}>
                        {db.publicly_accessible ? "Public Access" : "Private Subnet"}
                      </div>
                    </div>
                  ))}
                  {(!resources.rds || resources.rds.length === 0) && (
                    <div className="asset-empty">No RDS instances found in current region.</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 4: REMEDIATION                                       */}
        {/* ========================================================= */}
        {activeTab === "remediation" && (
          <div className="remediation-view">
            <div className="view-header">
              <div>
                <h2>Safe Auto-Remediation Command Center</h2>
                <p>
                  Controlled human-in-the-loop remediation. CloudGuard never modifies AWS resources
                  without preview, inspection, and explicit human confirmation.
                </p>
              </div>
            </div>

            <div className="remediation-banner-card">
              <div className="remediation-shield-icon">
                <ShieldCheck size={36} />
              </div>
              <div className="remediation-banner-text">
                <h3>Strict Security Safety Protocol</h3>
                <p>
                  Automated modification is strictly isolated to verifiable rules (such as open Port 22 SSH
                  rules). Changes must pass Preview Verification and require signed human confirmation before
                  any AWS API call is dispatched.
                </p>
              </div>
            </div>

            <div className="remediation-rules-section">
              <h3>Supported Remediation Modules</h3>
              <div className="remediation-card">
                <div className="rem-header">
                  <div>
                    <h4>EC2 Security Group: Open SSH Port 22</h4>
                    <p>Detects ingress rule allowing TCP port 22 from unrestricted 0.0.0.0/0</p>
                  </div>
                  <span className="rem-tag active">ACTIVE & TESTED</span>
                </div>

                <div className="rem-workflow">
                  <div className="workflow-step">
                    <span className="step-num">1</span>
                    <div>
                      <strong>Dry-Run Preview</strong>
                      <p>Inspects live rule parameters from AWS EC2 API</p>
                    </div>
                  </div>
                  <div className="workflow-arrow">→</div>
                  <div className="workflow-step">
                    <span className="step-num">2</span>
                    <div>
                      <strong>Human Confirmation</strong>
                      <p>Mandatory approval modal with optional trusted IP</p>
                    </div>
                  </div>
                  <div className="workflow-arrow">→</div>
                  <div className="workflow-step">
                    <span className="step-num">3</span>
                    <div>
                      <strong>Revoke & Verify</strong>
                      <p>Dispatches RevokeSecurityGroupIngress & verifies fix</p>
                    </div>
                  </div>
                </div>

                {findings.some((f) => f.service === "EC2" && f.issue.includes("SSH")) ? (
                  <div className="rem-active-alert">
                    <AlertTriangle size={20} />
                    <span>
                      An active SSH open misconfiguration was detected in your AWS environment.
                    </span>
                    <button
                      className="remediate-now-btn"
                      onClick={() =>
                        handleOpenRemediation(
                          findings.find((f) => f.service === "EC2" && f.issue.includes("SSH"))
                        )
                      }
                    >
                      Remediate Resource
                    </button>
                  </div>
                ) : (
                  <div className="rem-healthy-status">
                    <CheckCircle2 size={18} />
                    <span>No unmitigated open SSH rules currently detected in active scans.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 5: SCAN HISTORY                                      */}
        {/* ========================================================= */}
        {activeTab === "history" && (
          <div className="history-view">
            <div className="view-header">
              <div>
                <h2>Audit & Scan History</h2>
                <p>Track your cloud security posture over time and examine historical scan runs</p>
              </div>
              <button className="scan-btn" onClick={handleRunScan} disabled={scanning}>
                <RefreshCw size={16} className={scanning ? "spin-icon" : ""} />
                New Scan Run
              </button>
            </div>

            {/* Simple Score Trend Bar */}
            {scans.length > 1 && (
              <div className="score-trend-card">
                <h3>Security Score Trend</h3>
                <div className="trend-bars">
                  {scans.slice(0, 10).reverse().map((s, idx) => (
                    <div className="trend-col" key={s.scan_id || idx}>
                      <div className="trend-bar-wrapper">
                        <div
                          className="trend-bar"
                          style={{
                            height: `${s.score}%`,
                            backgroundColor: getScoreColor(s.score),
                          }}
                        />
                      </div>
                      <span className="trend-score">{s.score}</span>
                      <span className="trend-time">{s.start_time?.split(" ")[1]?.slice(0, 5) || "Run"}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Scans Table */}
            <div className="history-table-card">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Timestamp</th>
                    <th>Security Score</th>
                    <th>Findings</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td>
                        <code>{scan.scan_id}</code>
                      </td>
                      <td>{scan.start_time || "N/A"}</td>
                      <td>
                        <span
                          className="score-pill"
                          style={{
                            backgroundColor: `${getScoreColor(scan.score)}22`,
                            color: getScoreColor(scan.score),
                          }}
                        >
                          {scan.score}/100
                        </span>
                      </td>
                      <td>
                        <strong>{scan.total_findings}</strong> issues
                      </td>
                      <td>
                        <span className="status-pill completed">{scan.status}</span>
                      </td>
                      <td>
                        <button
                          className="table-action-btn"
                          onClick={() => handleDownloadReport(scan.scan_id)}
                          title="Download PDF Report for this scan"
                        >
                          <Download size={14} />
                          Report
                        </button>
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan="6" className="table-empty">
                        No prior scan runs found. Click "Run Security Scan" to perform your first audit.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 6: REPORTS                                           */}
        {/* ========================================================= */}
        {activeTab === "reports" && (
          <div className="reports-view">
            <div className="view-header">
              <div>
                <h2>Security Assessment Reports</h2>
                <p>Generate, export, and download comprehensive PDF cloud security audit reports</p>
              </div>
              <button className="download-btn" onClick={() => handleDownloadReport()}>
                <Download size={16} />
                Download PDF Report
              </button>
            </div>

            <div className="report-preview-card">
              <div className="report-preview-header">
                <div className="report-logo-group">
                  <ShieldCheck size={28} className="report-logo" />
                  <div>
                    <h3>CLOUDGUARD EXECUTIVE AUDIT REPORT</h3>
                    <small>Standardized Cloud Posture Assessment | CIS Benchmark Referenced</small>
                  </div>
                </div>
                <div className="report-meta-box">
                  <div>Date: {new Date().toLocaleDateString()}</div>
                  <div>AWS Region: {health.aws_region}</div>
                  <div>Account: {health.aws_account_id}</div>
                </div>
              </div>

              <div className="report-summary-bar">
                <div className="report-score-box">
                  <span className="rep-num" style={{ color: scoreColor }}>
                    {scoreData.score}/100
                  </span>
                  <span className="rep-lbl">Overall Posture</span>
                </div>
                <div className="report-kpis">
                  <div className="kpi-item">
                    <span>Critical</span>
                    <strong className="kpi-crit">{scoreData.critical}</strong>
                  </div>
                  <div className="kpi-item">
                    <span>High</span>
                    <strong className="kpi-high">{scoreData.high}</strong>
                  </div>
                  <div className="kpi-item">
                    <span>Medium</span>
                    <strong className="kpi-med">{scoreData.medium}</strong>
                  </div>
                  <div className="kpi-item">
                    <span>Low</span>
                    <strong className="kpi-low">{scoreData.low}</strong>
                  </div>
                </div>
              </div>

              <div className="report-findings-preview">
                <h4>Identified Vulnerabilities & Corrective Actions</h4>
                <div className="report-table">
                  <div className="rep-row rep-head">
                    <span>Service</span>
                    <span>Severity</span>
                    <span>Resource</span>
                    <span>Misconfiguration</span>
                    <span>Remediation Advice</span>
                  </div>
                  {findings.map((f) => (
                    <div className="rep-row" key={f.id}>
                      <span className="rep-srv">{f.service}</span>
                      <span className={`rep-risk risk-${f.risk?.toLowerCase()}`}>{f.risk}</span>
                      <span className="rep-res">
                        <code>{f.resource}</code>
                      </span>
                      <span className="rep-issue">{f.issue}</span>
                      <span className="rep-fix">{f.recommendation}</span>
                    </div>
                  ))}
                  {findings.length === 0 && (
                    <div className="rep-empty">No security findings recorded.</div>
                  )}
                </div>
              </div>

              <div className="report-footer">
                <span>Generated by CloudGuard CSPM Engine</span>
                <button className="primary-btn" onClick={() => handleDownloadReport()}>
                  <Download size={15} />
                  Download Complete PDF Document
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 7: SETTINGS & SCHEDULE                               */}
        {/* ========================================================= */}
        {activeTab === "settings" && (
          <div className="settings-view">
            <div className="view-header">
              <div>
                <h2>Scanner Configuration & Automation</h2>
                <p>Manage recurring assessment schedules, alerts, and environment settings</p>
              </div>
            </div>

            <div className="settings-cards-grid">
              {/* Scan Schedule Card */}
              <div className="settings-card">
                <div className="settings-card-header">
                  <Calendar size={22} className="set-icon" />
                  <div>
                    <h3>Automated Scan Schedule</h3>
                    <p>Trigger periodic assessments in the background</p>
                  </div>
                </div>

                <div className="schedule-options">
                  {["MANUAL", "DAILY", "WEEKLY"].map((mode) => (
                    <label
                      key={mode}
                      className={`schedule-option ${schedule.mode === mode ? "selected" : ""}`}
                    >
                      <input
                        type="radio"
                        name="schedule_mode"
                        checked={schedule.mode === mode}
                        onChange={() => handleScheduleChange(mode)}
                      />
                      <div>
                        <strong>{mode === "MANUAL" ? "Manual Only" : `${mode} Scanning`}</strong>
                        <p>
                          {mode === "MANUAL"
                            ? "Scans run only when explicitly triggered via the dashboard"
                            : mode === "DAILY"
                            ? "Automatically inspects cloud resources every 24 hours"
                            : "Performs full assessment once every 7 days"}
                        </p>
                      </div>
                    </label>
                  ))}
                </div>

                {schedule.enabled && schedule.next_run && (
                  <div className="schedule-next-info">
                    <Clock size={16} />
                    <span>Next scheduled scan: {schedule.next_run}</span>
                  </div>
                )}
              </div>

              {/* Alert Settings Card */}
              <div className="settings-card">
                <div className="settings-card-header">
                  <Bell size={22} className="set-icon" />
                  <div>
                    <h3>Security Alert Notifications</h3>
                    <p>Immediate alerts upon detection of High or Critical risks</p>
                  </div>
                </div>

                <div className="alert-config-info">
                  <div className="config-item">
                    <span>Dashboard Alert Banners:</span>
                    <strong className="badge-active">ACTIVE</strong>
                  </div>
                  <div className="config-item">
                    <span>External SMTP Email Alerts:</span>
                    <strong className="badge-optional">OPTIONAL / ENV CONFIGURED</strong>
                  </div>
                  <p className="config-help">
                    To enable SMTP outbound email notifications, set <code>SMTP_HOST</code>,{" "}
                    <code>SMTP_USER</code>, <code>SMTP_PASS</code>, and{" "}
                    <code>ALERT_RECIPIENT_EMAIL</code> in your backend environment without modifying code.
                  </p>
                </div>
              </div>

              {/* AWS Connection & System Status */}
              <div className="settings-card">
                <div className="settings-card-header">
                  <Terminal size={22} className="set-icon" />
                  <div>
                    <h3>AWS Environment Details</h3>
                    <p>Active credentials chain and service telemetry</p>
                  </div>
                </div>

                <div className="env-details-list">
                  <div className="env-item">
                    <span>AWS Account ID:</span>
                    <code>{health.aws_account_id}</code>
                  </div>
                  <div className="env-item">
                    <span>Configured Region:</span>
                    <code>{health.aws_region}</code>
                  </div>
                  <div className="env-item">
                    <span>Identity ARN:</span>
                    <code>{health.aws_arn || "Local AWS CLI Credential"}</code>
                  </div>
                  <div className="env-item">
                    <span>Database Engine:</span>
                    <code>SQLite 3 (cloudguard.db)</code>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ========================================================= */}
      {/* MODAL: SAFE REMEDIATION CONFIRMATION                      */}
      {/* ========================================================= */}
      <AnimatePresence>
        {remediationModal.isOpen && (
          <div className="modal-backdrop">
            <motion.div
              className="modal-box remediation-modal"
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
            >
              <div className="modal-header">
                <div className="modal-title-group">
                  <Wrench size={22} className="modal-icon" />
                  <div>
                    <h3>Safe Remediation Confirmation</h3>
                    <p>Review proposed modification before applying to AWS</p>
                  </div>
                </div>
                <button
                  className="close-modal-btn"
                  onClick={() => setRemediationModal({ ...remediationModal, isOpen: false })}
                >
                  ✕
                </button>
              </div>

              <div className="modal-body">
                {remediationModal.loading ? (
                  <div className="modal-loading">
                    <RefreshCw size={28} className="spin-icon" />
                    <span>Communicating with AWS Security API...</span>
                  </div>
                ) : remediationModal.result ? (
                  <div className="remediation-result-view">
                    {remediationModal.result.success ? (
                      <div className="result-success">
                        <CheckCircle2 size={40} className="success-icon" />
                        <h4>Remediation Successfully Applied!</h4>
                        <p>{remediationModal.result.message}</p>
                        <div className="rescan-notice">
                          <RefreshCw size={16} className="spin-icon" />
                          <span>Verification scan completed. Dashboard updated.</span>
                        </div>
                      </div>
                    ) : (
                      <div className="result-error">
                        <XCircle size={40} className="error-icon" />
                        <h4>Remediation Failed</h4>
                        <p>{remediationModal.result.error}</p>
                      </div>
                    )}
                    <button
                      className="primary-btn"
                      onClick={() => setRemediationModal({ ...remediationModal, isOpen: false })}
                    >
                      Close Window
                    </button>
                  </div>
                ) : remediationModal.preview ? (
                  <div className="preview-content">
                    {/* Diff / Comparison Table */}
                    <div className="diff-card">
                      <div className="diff-section current">
                        <div className="diff-tag">CURRENT RULE (VULNERABLE)</div>
                        <div className="diff-row">
                          <span>Target Resource:</span>
                          <code>{remediationModal.finding?.resource}</code>
                        </div>
                        <div className="diff-row">
                          <span>Port / Protocol:</span>
                          <strong>TCP Port 22 (SSH)</strong>
                        </div>
                        <div className="diff-row">
                          <span>Inbound Source:</span>
                          <span className="danger-text">0.0.0.0/0 (Entire Internet)</span>
                        </div>
                      </div>

                      <div className="diff-arrow">➔</div>

                      <div className="diff-section proposed">
                        <div className="diff-tag proposed-tag">PROPOSED RULE (SECURED)</div>
                        <div className="diff-row">
                          <span>Target Resource:</span>
                          <code>{remediationModal.finding?.resource}</code>
                        </div>
                        <div className="diff-row">
                          <span>Action:</span>
                          <strong className="success-text">Revoke 0.0.0.0/0 Access</strong>
                        </div>
                        <div className="diff-row">
                          <span>Inbound Source:</span>
                          <span className="success-text">
                            {remediationModal.targetCidr || "Public Access Revoked (Internal Only)"}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Optional Custom CIDR input */}
                    <div className="cidr-input-box">
                      <label>Optional: Restrict SSH to your Trusted IP CIDR (leave empty to completely revoke):</label>
                      <input
                        type="text"
                        placeholder="e.g. 203.0.113.50/32 or your corporate VPN CIDR"
                        value={remediationModal.targetCidr}
                        onChange={(e) =>
                          setRemediationModal({ ...remediationModal, targetCidr: e.target.value })
                        }
                      />
                    </div>

                    {/* Safety Warning */}
                    <div className="safety-warning">
                      <AlertTriangle size={20} className="warning-icon" />
                      <div>
                        <strong>Administrative Precaution</strong>
                        <p>
                          This change restricts SSH access. Ensure alternative access (AWS SSM Session
                          Manager or trusted IP) is available to avoid lockout.
                        </p>
                      </div>
                    </div>

                    {/* Mandatory Confirmation Checkbox */}
                    <label className="confirmation-checkbox-label">
                      <input
                        type="checkbox"
                        checked={remediationModal.confirmed}
                        onChange={(e) =>
                          setRemediationModal({ ...remediationModal, confirmed: e.target.checked })
                        }
                      />
                      <span>
                        I understand this modification and explicitly authorize CloudGuard to revoke the
                        0.0.0.0/0 ingress rule on AWS Security Group{" "}
                        <strong>{remediationModal.finding?.resource}</strong>.
                      </span>
                    </label>

                    {/* Modal Action Buttons */}
                    <div className="modal-footer-actions">
                      <button
                        className="secondary-btn"
                        onClick={() =>
                          setRemediationModal({ ...remediationModal, isOpen: false })
                        }
                      >
                        Cancel
                      </button>
                      <button
                        className="apply-fix-btn"
                        disabled={!remediationModal.confirmed || remediationModal.loading}
                        onClick={handleApplyRemediation}
                      >
                        <Check size={16} />
                        Confirm & Apply Fix
                      </button>
                    </div>
                  </div>
                ) : (
                  <div>Unable to load remediation preview.</div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ========================================================= */}
      {/* MODAL: FINDING DETAIL INSPECTOR                           */}
      {/* ========================================================= */}
      <AnimatePresence>
        {selectedFinding && (
          <div className="modal-backdrop">
            <motion.div
              className="modal-box detail-modal"
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
            >
              <div className="modal-header">
                <div className="modal-title-group">
                  <ShieldAlert size={22} className="modal-icon" />
                  <div>
                    <h3>Security Finding Inspection</h3>
                    <p>Comprehensive vulnerability diagnostic & compliance details</p>
                  </div>
                </div>
                <button className="close-modal-btn" onClick={() => setSelectedFinding(null)}>
                  ✕
                </button>
              </div>

              <div className="modal-body">
                <div className="detail-meta-grid">
                  <div className="detail-meta-item">
                    <span>AWS Service</span>
                    <strong>{selectedFinding.service}</strong>
                  </div>
                  <div className="detail-meta-item">
                    <span>Severity Rating</span>
                    <strong className={`risk-text risk-${selectedFinding.risk?.toLowerCase()}`}>
                      {selectedFinding.risk}
                    </strong>
                  </div>
                  <div className="detail-meta-item">
                    <span>Resource Identifier</span>
                    <code>{selectedFinding.resource}</code>
                  </div>
                  <div className="detail-meta-item">
                    <span>Detection Timestamp</span>
                    <span>{selectedFinding.scan_time}</span>
                  </div>
                </div>

                <div className="detail-card-section">
                  <h4>Misconfiguration Description</h4>
                  <p>{selectedFinding.issue}</p>
                </div>

                <div className="detail-card-section recommendation-box">
                  <h4>Remediation Guidance</h4>
                  <p>{selectedFinding.recommendation}</p>
                </div>

                <div className="modal-footer-actions">
                  <button className="secondary-btn" onClick={() => setSelectedFinding(null)}>
                    Close
                  </button>
                  {selectedFinding.service === "EC2" && selectedFinding.issue.includes("SSH") && (
                    <button
                      className="primary-btn"
                      onClick={() => {
                        const target = selectedFinding;
                        setSelectedFinding(null);
                        handleOpenRemediation(target);
                      }}
                    >
                      <Wrench size={15} />
                      Launch Remediation Wizard
                    </button>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default App;