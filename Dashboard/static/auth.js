//Fetches JSON data from the backend and throws an error for failed or non-JSON responses
async function getJSON(url, opts = {}) {
  const res = await fetch(url, opts);
  const ct = res.headers.get("content-type") || "";

  if (ct.includes("application/json")) {
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  const text = await res.text();
  throw new Error(`Non-JSON response from ${url}: ${text.slice(0, 200)}`);
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

//Updates text content of a page element by ID
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

//Returns CSS class for alert severity badge styling
function badgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "badge badge-critical";
  if (s === "high") return "badge badge-high";
  if (s === "medium") return "badge badge-medium";
  return "badge badge-low";
}

//Stores page-wide auth data, current active tab, and chart instance
let PAGE_DATA = null;
let ACTIVE_TAB = "raw";
let authActivityChart = null;

//Builds and renders the authentication activity chart
//Shows total logs, successful logins, and failed logins over time
function renderAuthActivityChart(series) {
  const ctx = document.getElementById("auth-activity-chart");
  if (!ctx || !series || !series.labels) return;

  const data = {
    labels: series.labels,
    datasets: [
      {
        label: "Total Logs",
        data: series.total || [],
        borderColor: "#4aa3ff",
        tension: 0.25
      },
      {
        label: "Successful",
        data: series.success || [],
        borderColor: "#22c55e",
        tension: 0.25
      },
      {
        label: "Failed",
        data: series.failed || [],
        borderColor: "#ff2020",
        tension: 0.25
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: "rgba(255,255,255,0.75)" }
      }
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

  if (authActivityChart) {
    authActivityChart.destroy();
  }

  authActivityChart = new Chart(ctx, { type: "line", data, options });
}

//Returns rows for the currently active tab (raw or normalized)
function currentRows() {
  if (!PAGE_DATA) return [];
  return ACTIVE_TAB === "raw"
    ? (PAGE_DATA.raw_rows || [])
    : (PAGE_DATA.normalized_rows || []);
}

//Returns columns for the currently active tab
function currentColumns() {
  if (!PAGE_DATA) return [];
  return ACTIVE_TAB === "raw"
    ? (PAGE_DATA.raw_columns || [])
    : (PAGE_DATA.normalized_columns || []);
}

//Renders authentication alerts into the alerts table
function renderAlerts(rows) {
  const tbody = document.getElementById("auth-alerts-body");
  if (!tbody) return;

  tbody.innerHTML = "";

  for (const row of rows || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHTML(row.time || "")}</td>
      <td>${escapeHTML(row.alert_type || "")}</td>
      <td>${escapeHTML(row.user || "")}</td>
      <td><span class="mono">${escapeHTML(row.src_ip || "")}</span></td>
      <td><span class="${badgeClass(row.severity)}">${escapeHTML(row.severity || "")}</span></td>
      <td>${escapeHTML(row.details || "")}</td>
    `;
    tbody.appendChild(tr);
  }
}

//Renders raw or normalized auth log rows into the log table
function renderTable(columns, rows) {
  const thead = document.getElementById("auth-table-head");
  const tbody = document.getElementById("auth-table-body");
  const count = document.getElementById("auth-table-count");

  if (!thead || !tbody) return;

  thead.innerHTML = "";
  tbody.innerHTML = "";

  const headRow = document.createElement("tr");
  headRow.innerHTML = columns.map(col => `<th>${escapeHTML(col)}</th>`).join("");
  thead.appendChild(headRow);

  for (const row of rows || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = columns.map(col => `<td>${escapeHTML(row[col] ?? "")}</td>`).join("");
    tbody.appendChild(tr);
  }

  if (count) count.textContent = `${rows.length} rows shown`;
}

//Populates dropdown filter options while preserving current selection where possible
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

//Gets first non-empty value from a row across possible field names
function getValue(row, keys) {
  for (const key of keys) {
    if (row[key] !== undefined && row[key] !== null && String(row[key]).trim() !== "") {
      return String(row[key]);
    }
  }
  return "";
}

//Parses timestamp from an authentication log row
function parseRowTime(row) {
  const raw = getValue(row, ["timestamp", "event_time", "time"]);
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads current authentication log filter values from the UI
function getLogFilterValues() {
  return {
    timeFrom: document.getElementById("auth-time-from")?.value || "",
    timeTo: document.getElementById("auth-time-to")?.value || "",
    user: (document.getElementById("auth-user-filter")?.value || "").trim().toLowerCase(),
    srcIp: (document.getElementById("auth-src-filter")?.value || "").trim().toLowerCase(),
    status: (document.getElementById("auth-status-filter")?.value || "").trim().toLowerCase(),
    host: (document.getElementById("auth-host-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks whether an auth log row matches the current log filters
function rowMatches(row, filters) {
  const user = getValue(row, ["user", "username"]).toLowerCase();
  const srcIp = getValue(row, ["src_ip", "client_ip", "source_ip", "ip"]).toLowerCase();
  const status = getValue(row, ["status", "result", "action", "outcome"]).toLowerCase();
  const host = getValue(row, ["host","hostname","device","server","system","computer","machine","target_host","dest_host", "dst_ip"]).toLowerCase();
  const rowTime = parseRowTime(row);

  if (filters.user && !user.includes(filters.user)) return false;
  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.status && status !== filters.status) return false;
  if (filters.host && !host.includes(filters.host)) return false;

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

//Returns filtered auth log rows
function filteredRows() {
  const rows = currentRows();
  const filters = getLogFilterValues();
  return rows.filter(row => rowMatches(row, filters));
}

//Refreshes auth log filter dropdowns based on current data
function refreshLogFilterOptions() {
  const rows = currentRows();

  const statuses = [...new Set(
    rows
      .map(row => getValue(row, ["status", "result", "action", "outcome"]).trim().toLowerCase())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("auth-status-filter", statuses, "All Statuses");
}

//Renders the currently active auth tab view
function renderActiveTab() {
  if (!PAGE_DATA) return;
  refreshLogFilterOptions();
  renderTable(currentColumns(), filteredRows());
}

//Parses timestamp from an auth alert row
function parseAlertTime(row) {
  const raw = row.time || "";
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads current authentication alert filter values from the UI
function getAlertFilterValues() {
  return {
    timeFrom: document.getElementById("auth-alert-time-from")?.value || "",
    timeTo: document.getElementById("auth-alert-time-to")?.value || "",
    alertType: (document.getElementById("auth-alert-type-filter")?.value || "").trim().toLowerCase(),
    user: (document.getElementById("auth-alert-user-filter")?.value || "").trim().toLowerCase(),
    srcIp: (document.getElementById("auth-alert-src-filter")?.value || "").trim().toLowerCase(),
    severity: (document.getElementById("auth-alert-severity-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks whether an auth alert row matches the current alert filters
function alertMatches(row, filters) {
  const alertType = String(row.alert_type || "").toLowerCase().trim();
  const user = String(row.user || "").toLowerCase().trim();
  const srcIp = String(row.src_ip || "").toLowerCase().trim();
  const severity = String(row.severity || "").toLowerCase().trim();
  const rowTime = parseAlertTime(row);

  if (filters.alertType && alertType !== filters.alertType) return false;
  if (filters.user && !user.includes(filters.user)) return false;
  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.severity && severity !== filters.severity) return false;

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

//Returns filtered authentication alerts
function filteredAlerts() {
  const alerts = PAGE_DATA?.alerts || [];
  const filters = getAlertFilterValues();
  return alerts.filter(row => alertMatches(row, filters));
}

//Refreshes auth alert filter dropdowns based on available alert values
function refreshAlertFilterOptions() {
  const alerts = PAGE_DATA?.alerts || [];

  const alertTypes = [...new Set(
    alerts.map(row => String(row.alert_type || "").trim()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  const severities = [...new Set(
    alerts.map(row => String(row.severity || "").trim().toLowerCase()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("auth-alert-type-filter", alertTypes, "All Alert Types");
  populateDropdown("auth-alert-severity-filter", severities, "All Severities");
}

//Renders filtered authentication alerts and updates count
function renderFilteredAlerts() {
  refreshAlertFilterOptions();

  const rows = filteredAlerts();
  renderAlerts(rows);

  const count = document.getElementById("auth-alerts-count");
  if (count) count.textContent = `${rows.length} alerts shown`;
}

//Wires tab switching between raw and normalized auth logs
function wireTabs() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-tab]");
    if (!btn) return;

    ACTIVE_TAB = btn.dataset.tab;

    document.querySelectorAll("[data-tab]").forEach(tabBtn => {
      tabBtn.classList.toggle("active", tabBtn.dataset.tab === ACTIVE_TAB);
    });

    renderActiveTab();
  });
}

//Wires authentication log filters and clear button
function wireLogFilters() {
  const ids = [
    "auth-time-from",
    "auth-time-to",
    "auth-user-filter",
    "auth-src-filter",
    "auth-status-filter",
    "auth-host-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", renderActiveTab);
    el.addEventListener("change", renderActiveTab);
  });

  const clearBtn = document.getElementById("auth-clear-filters");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = "";
      });
      renderActiveTab();
    });
  }
}

//Wires authentication alert filters and clear button
function wireAlertFilters() {
  const ids = [
    "auth-alert-time-from",
    "auth-alert-time-to",
    "auth-alert-type-filter",
    "auth-alert-user-filter",
    "auth-alert-src-filter",
    "auth-alert-severity-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", renderFilteredAlerts);
    el.addEventListener("change", renderFilteredAlerts);
  });

  const clearBtn = document.getElementById("auth-clear-alert-filters");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = "";
      });
      renderFilteredAlerts();
    });
  }
}

//Wires export buttons for raw and normalized auth CSV downloads
function wireExports() {
  const rawBtn = document.getElementById("btn-export-raw");
  const normBtn = document.getElementById("btn-export-normalized");

  if (rawBtn) {
    rawBtn.addEventListener("click", () => {
      window.open("/data/auth.csv", "_blank");
    });
  }

  if (normBtn) {
    normBtn.addEventListener("click", () => {
      window.open("/outputs/auth/normalised_auth.csv", "_blank");
    });
  }
}

//Loads authentication page data from backend and triggers full render
async function loadAuthPage() {
  const data = await getJSON("/api/auth");
  PAGE_DATA = data;

  setText("auth-total-count", data.summary?.total_logs ?? data.summary?.raw_count ?? 0);
  setText("auth-alert-count", data.summary?.alert_count ?? 0);
  setText("auth-failed-count", data.summary?.failed_count ?? 0);
  setText("auth-success-count", data.summary?.success_count ?? 0);

  renderAuthActivityChart(data.log_activity || {});
  renderFilteredAlerts();
  renderActiveTab();
}

//Initialises auth page behaviour when loaded
(async function init() {
  try {
    wireTabs();
    wireLogFilters();
    wireAlertFilters();
    wireExports();
    await loadAuthPage();
  } catch (err) {
    console.error(err);
    const count = document.getElementById("auth-table-count");
    if (count) count.textContent = String(err);
  }
})();