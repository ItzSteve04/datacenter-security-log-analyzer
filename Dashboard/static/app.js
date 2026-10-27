//Fetches JSON data from the backend and throws detailed errors for failed or non-JSON responses
async function getJSON(url, opts = {}) {
  const res = await fetch(url, opts);

  const ct = res.headers.get("content-type") || "";

  if (ct.includes("application/json")) {
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.output || "Request failed");
    return data;
  }

  const text = await res.text();
  throw new Error(
    `Non-JSON response from ${url} (status ${res.status}). First 200 chars:\n${text.slice(0, 200)}`
  );
}

//Updates text content of a page element by ID
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

//Returns CSS class used for severity badge styling
function badgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "badge badge-critical";
  if (s === "high") return "badge badge-high";
  if (s === "medium") return "badge badge-medium";
  return "badge badge-low";
}

//Escapes HTML special characters to prevent rendering issues or injection
function escapeHTML(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

//Stores dashboard data and chart instances across page updates
let ALL_ALERTS = [];
let cachedAlerts = [];
let cachedTopSources = [];
let trafficChart = null;
let donutChart = null;
let rawTrafficChart = null;

//Registers Chart.js datalabels plugin if available
if (window.ChartDataLabels) {
  Chart.register(ChartDataLabels);
}

//Populates dropdown filters while preserving current selection when possible
function populateDropdown(selectId, values, defaultLabel) {
  const select = document.getElementById(selectId);
  if (!select) return;

  const currentValue = select.value;
  select.innerHTML = `<option value="">${escapeHTML(defaultLabel)}</option>`;

  values.forEach(value => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });

  const stillExists = [...select.options].some(opt => opt.value === currentValue);
  if (stillExists) select.value = currentValue;
}

//Reads current dashboard alert filter values from the UI
function getDashboardFilters() {
  return {
    timeFrom: document.getElementById("dash-alert-time-from")?.value || "",
    timeTo: document.getElementById("dash-alert-time-to")?.value || "",
    alertType: (document.getElementById("dash-alert-type-filter")?.value || "").trim().toLowerCase(),
    srcIp: (document.getElementById("dash-alert-src-filter")?.value || "").trim().toLowerCase(),
    severity: (document.getElementById("dash-alert-severity-filter")?.value || "").trim().toLowerCase(),
    details: (document.getElementById("dash-alert-details-filter")?.value || "").trim().toLowerCase()
  };
}

//Parses dashboard alert timestamp
function parseDashboardAlertTime(row) {
  const raw = row.time || row.window_start || "";
  if (!raw) return null;

  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Checks whether a dashboard alert row matches current filter conditions
function dashboardRowMatches(row, filters) {
  const rowTime = parseDashboardAlertTime(row);
  const alertType = String(row.alert_type || "").toLowerCase().trim();
  const srcIp = String(row.src_ip || "").toLowerCase().trim();
  const severity = String(row.severity || "").toLowerCase().trim();
  const details = String(row.details || "").toLowerCase().trim();

  if (filters.alertType && alertType !== filters.alertType) return false;
  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.severity && severity !== filters.severity) return false;
  if (filters.details && !details.includes(filters.details)) return false;

  if (filters.timeFrom) {
    const from = new Date(filters.timeFrom);
    if (!Number.isNaN(from.getTime()) && rowTime && rowTime < from) return false;
  }

  if (filters.timeTo) {
    const to = new Date(filters.timeTo);
    if (!Number.isNaN(to.getTime()) && rowTime && rowTime > to) return false;
  }

  return true;
}

//Populates dashboard filter dropdowns using available alert values
function populateDashboardDropdowns(rows) {
  const alertTypes = [...new Set(
    rows.map(r => String(r.alert_type || "").trim()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  const severities = [...new Set(
    rows.map(r => String(r.severity || "").trim().toLowerCase()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("dash-alert-type-filter", alertTypes, "All Alert Types");
  populateDropdown("dash-alert-severity-filter", severities, "All Severities");
}

//Loads dashboard alerts and applies current filters
function renderAlerts(alerts) {
  ALL_ALERTS = alerts || [];
  populateDashboardDropdowns(ALL_ALERTS);
  applyFilters();
}

//Applies dashboard alert filters and renders filtered rows into the summary table
function applyFilters() {
  const filters = getDashboardFilters();

  const filtered = ALL_ALERTS.filter(a => dashboardRowMatches(a, filters));

  const tbody = document.getElementById("alerts-tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  for (const a of filtered) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHTML(a.time || "")}</td>
      <td>${escapeHTML(a.alert_type || "")}</td>
      <td><span class="mono">${escapeHTML(a.src_ip || "")}</span></td>
      <td><span class="${badgeClass(a.severity)}">${escapeHTML(a.severity || "")}</span></td>
      <td>${escapeHTML(a.details || "")}</td>
    `;
    tbody.appendChild(tr);
  }

  setText("table-count", `Showing ${filtered.length} alerts`);
}

//Wires dashboard alert filter inputs and clear button
function wireDashboardFilters() {
  const ids = [
    "dash-alert-time-from",
    "dash-alert-time-to",
    "dash-alert-type-filter",
    "dash-alert-src-filter",
    "dash-alert-severity-filter",
    "dash-alert-details-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;

    el.addEventListener("input", applyFilters);
    el.addEventListener("change", applyFilters);
  });

  const clearBtn = document.getElementById("dash-clear-alert-filters");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = "";
      });
      applyFilters();
    });
  }
}

//Destroys existing charts before redrawing updated ones
function destroyCharts() {
  if (trafficChart) {
    trafficChart.destroy();
    trafficChart = null;
  }
  if (donutChart) {
    donutChart.destroy();
    donutChart = null;
  }
  if (rawTrafficChart) {
    rawTrafficChart.destroy();
    rawTrafficChart = null;
  }
}

//Renders text-based breakdown of alert type proportions
function renderBreakdown(typeBreakdown) {
  const el = document.getElementById("breakdown-list");
  if (!el) return;

  el.innerHTML = "";

  const order = ["firewall", "auth", "ids", "dns"];
  const pills = {
    firewall: "pill pill-fw",
    auth: "pill pill-auth",
    ids: "pill pill-ids",
    dns: "pill pill-dns",
  };

  for (const key of order) {
    if (!(key in typeBreakdown)) continue;
    const pct = typeBreakdown[key];
    const row = document.createElement("div");
    row.className = "breakdown-item";
    row.innerHTML = `
      <span class="${pills[key]}"></span>
      <span class="breakdown-name">${key.toUpperCase()}</span>
      <span class="breakdown-val">${pct}%</span>
    `;
    el.appendChild(row);
  }
}

//Renders top source IPs as horizontal bar rows
function renderTopSources(topSources) {
  const wrap = document.getElementById("top-sources");
  if (!wrap) return;

  wrap.innerHTML = "";
  cachedTopSources = topSources || [];

  if (!cachedTopSources.length) {
    wrap.innerHTML = `<div class="muted" style="padding:10px 14px 14px;">No data yet.</div>`;
    return;
  }

  for (const row of cachedTopSources) {
    const pct = Number(row.pct ?? 0);
    const count = Number(row.count ?? 0);

    const div = document.createElement("div");
    div.className = "bar-row";

    div.innerHTML = `
      <div class="bar-label mono">${escapeHTML(row.src_ip || "")}</div>
      <div class="bar">
        <div class="bar-fill ids" style="width:${pct}%;"></div>
      </div>
      <div class="bar-metric muted">${count}</div>
    `;

    wrap.appendChild(div);
  }
}

//Returns severity badge class for recent activity panel
function sevPill(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "badge badge-critical";
  if (s === "high") return "badge badge-high";
  if (s === "medium") return "badge badge-medium";
  return "badge badge-low";
}

//Renders recent alert activity feed on the dashboard
function renderRecentActivity(items) {
  const ul = document.getElementById("recent-activity");
  if (!ul) return;

  ul.innerHTML = "";

  if (!items.length) {
    ul.innerHTML = `<li class="muted" style="padding:10px 14px 14px;">No recent activity yet.</li>`;
    return;
  }

  for (const x of items) {
    const li = document.createElement("li");
    li.className = "activity-item";

    li.innerHTML = `
      <div class="activity-main">
        <div class="activity-top">
          <span class="activity-tag">${(x.event_type || "").toUpperCase()}</span>
          <span class="activity-title">${escapeHTML(x.alert_type || "")}</span>
          <span class="${sevPill(x.severity)}">${escapeHTML(x.severity || "")}</span>
          <span class="activity-time muted" style="margin-left:auto;">${escapeHTML(x.time || "")}</span>
        </div>

        <div class="activity-bottom">
          <span class="muted mono">${escapeHTML(x.src_ip || "")}</span>
          <span class="activity-details">${escapeHTML(x.details_short || x.details || "")}</span>
        </div>
      </div>
    `;

    ul.appendChild(li);
  }
}

//Renders chart showing raw log volume across all log sources over time
function renderRawTrafficChart(series) {
  const ctx = document.getElementById("rawTrafficChart");
  if (!ctx || !series || !series.labels) return;

  const data = {
    labels: series.labels,
    datasets: [
      { label: "Firewall", data: series.firewall || [], borderColor: "#ffb020", tension: 0.25 },
      { label: "Auth",     data: series.auth || [],     borderColor: "#ff5d6c", tension: 0.25 },
      { label: "IDS",      data: series.ids || [],      borderColor: "#4aa3ff", tension: 0.25 },
      { label: "DNS",      data: series.dns || [],      borderColor: "#22c55e", tension: 0.25 },
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: "rgba(255,255,255,0.75)" } }
    },
    scales: {
      x: {
        ticks: { color: "rgba(255,255,255,0.55)", maxTicksLimit: 8 },
        grid: { color: "rgba(255,255,255,0.08)" }
      },
      y: {
        ticks: { color: "rgba(255,255,255,0.55)" },
        grid: { color: "rgba(255,255,255,0.08)" }
      }
    }
  };

  rawTrafficChart = new Chart(ctx, { type: "line", data, options });
}

//Renders alert activity chart across firewall, auth, IDS, and DNS alerts
function renderTrafficChart(series) {
  const ctx = document.getElementById("trafficChart");
  if (!ctx || !series || !series.labels) return;

  const data = {
    labels: series.labels,
    datasets: [
      { label: "Firewall", data: series.firewall || [], borderColor: "#ffb020", tension: 0.25 },
      { label: "Auth",     data: series.auth || [],     borderColor: "#ff5d6c", tension: 0.25 },
      { label: "IDS",      data: series.ids || [],      borderColor: "#4aa3ff", tension: 0.25 },
      { label: "DNS",      data: series.dns || [],      borderColor: "#22c55e", tension: 0.25 },
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: "rgba(255,255,255,0.75)" } }
    },
    scales: {
      x: { ticks: { color: "rgba(255,255,255,0.55)" }, grid: { color: "rgba(255,255,255,0.08)" } },
      y: { ticks: { color: "rgba(255,255,255,0.55)" }, grid: { color: "rgba(255,255,255,0.08)" } }
    }
  };

  if (trafficChart) {
    trafficChart.data = data;
    trafficChart.update();
    return;
  }

  trafficChart = new Chart(ctx, { type: "line", data, options });
}

//Renders donut chart for alert type distribution
function renderDonutChart(typeCounts) {
  const ctx = document.getElementById("typeDonut");
  if (!ctx || !typeCounts) return;

  const labels = ["firewall", "auth", "ids", "dns"];
  const values = labels.map(k => typeCounts[k] || 0);
  const total = values.reduce((a, b) => a + b, 0);

  //Custom plugin to draw total alert count in the center of donut chart
  const centerTextPlugin = {
    id: "centerTextPlugin",
    afterDraw(chart) {
      const { ctx, chartArea } = chart;
      if (!chartArea) return;

      const x = (chartArea.left + chartArea.right) / 2;
      const y = (chartArea.top + chartArea.bottom) / 2;

      ctx.save();
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      ctx.fillStyle = "rgba(255,255,255,0.95)";
      ctx.font = "700 26px Inter, sans-serif";
      ctx.fillText(String(total), x, y - 10);

      ctx.fillStyle = "rgba(255,255,255,0.65)";
      ctx.font = "600 12px Inter, sans-serif";
      ctx.fillText("Total Alerts", x, y + 18);

      ctx.restore();
    }
  };

  const data = {
    labels: labels.map(x => x.toUpperCase()),
    datasets: [{
      data: values,
      backgroundColor: ["#ffb020", "#ff5d6c", "#4aa3ff", "#22c55e"],
      borderWidth: 0,
      hoverOffset: 6
    }]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    plugins: {
      legend: { display: false },
      datalabels: { display: false }
    }
  };

  if (donutChart) {
    donutChart.destroy();
    donutChart = null;
  }

  donutChart = new Chart(ctx, {
    type: "doughnut",
    data,
    options,
    plugins: [centerTextPlugin]
  });
}

//Updates console output area in the dashboard UI
function setConsole(text) {
  const el = document.getElementById("console-output");
  if (el) el.textContent = text || "";
}

//Loads available generator scripts into the generator dropdown
async function loadGenerators() {
  const sel = document.getElementById("generator-select");
  if (!sel) return;

  const data = await getJSON("/api/generators");
  sel.innerHTML = "";

  for (const g of data.generators) {
    const opt = document.createElement("option");
    opt.value = g;
    opt.textContent = g;
    sel.appendChild(opt);
  }

  if (data.generators.includes("gen_chain_all.py")) {
    sel.value = "gen_chain_all.py";
  }
}

//Refreshes the main dashboard with latest data from backend
async function refreshDashboard() {
  setText("status-text", "Loading…");
  const data = await getJSON("/api/dashboard");

  setText("last-updated", data.last_updated ? `Last updated: ${data.last_updated}` : `No outputs yet`);
  setText("kpi-critical", data.kpis.critical);
  setText("kpi-high", data.kpis.high);
  setText("kpi-medium", data.kpis.medium);
  setText("kpi-low", data.kpis.low);

  cachedAlerts = data.alerts || [];
  renderAlerts(cachedAlerts);
  renderBreakdown(data.type_breakdown || {});
  renderTopSources(data.top_sources || []);
  renderRecentActivity(data.recent_activity || []);
  destroyCharts();
  renderRawTrafficChart(data.raw_traffic_series);
  renderTrafficChart(data.traffic_series);
  renderDonutChart(data.type_counts_raw);

  setText(
    "status-text",
    data.exists ? "Loaded from outputs/global/alerts_summary.csv" : "Run analysis to generate outputs"
  );
}

//Runs selected generator script from the dashboard UI
async function runGenerator() {
  const sel = document.getElementById("generator-select");
  const script = sel ? sel.value : "";
  setConsole(`Running generator: ${script}\n`);
  setText("status-text", "Generating test data…");

  const res = await getJSON("/api/run-generator", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ script }),
  });

  setConsole(res.output || "Done.");
  setText("status-text", res.ok ? "Test data generated (see /data)" : "Generator failed");
}

//Runs the main analysis pipeline from the dashboard UI and refreshes all dashboard content
async function runAnalysis() {
  setConsole("Running analysis: python src/main.py\n");
  setText("status-text", "Running analysis…");

  const res = await getJSON("/api/run-analysis", { method: "POST" });
  setConsole(res.output || "Done.");

  const data = res.dashboard;

  setText("last-updated", data.last_updated ? `Last updated: ${data.last_updated}` : `No outputs yet`);
  setText("kpi-critical", data.kpis.critical);
  setText("kpi-high", data.kpis.high);
  setText("kpi-medium", data.kpis.medium);
  setText("kpi-low", data.kpis.low);

  cachedAlerts = data.alerts || [];
  renderAlerts(cachedAlerts);
  renderBreakdown(data.type_breakdown || {});
  renderTopSources(data.top_sources || []);
  renderRecentActivity(data.recent_activity || []);
  destroyCharts();
  renderRawTrafficChart(data.raw_traffic_series);
  renderTrafficChart(data.traffic_series);
  renderDonutChart(data.type_counts_raw);

  setText("status-text", res.ok ? "Analysis completed" : "Analysis failed (see console)");
}

//Uploads a CSV log file to the backend
async function uploadLog(logType, file) {
  const formData = new FormData();
  formData.append("log_type", logType);
  formData.append("file", file);

  const res = await fetch("/api/upload-log", {
    method: "POST",
    body: formData
  });

  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    const text = await res.text();
    throw new Error(`Upload failed: ${text.slice(0, 200)}`);
  }

  const data = await res.json();
  if (!res.ok || !data.ok) {
    throw new Error(data.error || "Upload failed");
  }

  return data;
}

//Wires upload input for a specific log type
function wireUploadInput(inputId, logType) {
  const el = document.getElementById(inputId);
  if (!el) return;

  el.addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      setConsole(`Uploading ${file.name} as ${logType}...\n`);
      const res = await uploadLog(logType, file);
      setConsole(`${res.message}\nReady to run analysis.`);
      setText("status-text", `${logType.toUpperCase()} CSV uploaded`);
    } catch (err) {
      setConsole(String(err));
      setText("status-text", "Upload failed");
    } finally {
      e.target.value = "";
    }
  });
}

//Wires all interactive dashboard controls
function wireUI() {
  const btnGenerate = document.getElementById("btn-generate");
  if (btnGenerate) {
    btnGenerate.addEventListener("click", () => {
      runGenerator().catch(e => setConsole(String(e)));
    });
  }

  const btnRun = document.getElementById("btn-run");
  if (btnRun) {
    btnRun.addEventListener("click", () => {
      runAnalysis().catch(e => setConsole(String(e)));
    });
  }

  const btnExport = document.getElementById("btn-export-alerts");
  if (btnExport) {
    btnExport.addEventListener("click", () => {
      window.open("/outputs/global/alerts_summary.csv", "_blank");
    });
  }

  wireUploadInput("upload-firewall", "firewall");
  wireUploadInput("upload-auth", "auth");
  wireUploadInput("upload-ids", "ids");
  wireUploadInput("upload-dns", "dns");
  wireDashboardFilters();
}

//Initialises the main dashboard page on load
(async function init() {
  try {
    wireUI();
    await loadGenerators();
    await refreshDashboard();
  } catch (e) {
    setConsole(String(e));
  }
})();