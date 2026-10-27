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

//Returns CSS badge class for alert severity styling
function badgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "badge badge-critical";
  if (s === "high") return "badge badge-high";
  if (s === "medium") return "badge badge-medium";
  return "badge badge-low";
}

//Stores page-wide firewall data, current active tab, and chart instance
let PAGE_DATA = null;
let ACTIVE_TAB = "raw";
let firewallActivityChart = null;

//Builds and renders the firewall line chart showing total, allowed, and denied traffic over time
function renderFirewallActivityChart(series){
  const ctx = document.getElementById("fw-activity-chart");
  if (!ctx || !series || !series.labels) return;

  const data = {
    labels: series.labels,
    datasets: [
      {
        label: "Total Logs",
        data: series.total || [],
        borderColor: "#007cf9",
        tension: 0.25
      },
      {
        label: "Allowed",
        data: series.allow || [],
        borderColor: "#22c55e",
        tension: 0.25
      },
      {
        label: "Denied",
        data: series.deny || [],
        borderColor: "#ff0000",
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
        ticks: {
          color: "rgba(255,255,255,0.55)",
          maxTicksLimit: 8
        },
        grid: {
          color: "rgba(255,255,255,0.08)"
        }
      },
      y: {
        ticks: {
          color: "rgba(255,255,255,0.55)"
        },
        grid: {
          color: "rgba(255,255,255,0.08)"
        }
      }
    }
  };

  if (firewallActivityChart) {
    firewallActivityChart.destroy();
  }

  firewallActivityChart = new Chart(ctx, {
    type: "line",
    data,
    options
  });
}

//Returns currently selected dataset rows based on active tab (raw or normalized)
function currentRows() {
  if (!PAGE_DATA) return [];
  return ACTIVE_TAB === "raw"
    ? (PAGE_DATA.raw_rows || [])
    : (PAGE_DATA.normalized_rows || []);
}

//Returns current table columns based on active tab
function currentColumns() {
  if (!PAGE_DATA) return [];
  return ACTIVE_TAB === "raw"
    ? (PAGE_DATA.raw_columns || [])
    : (PAGE_DATA.normalized_columns || []);
}

//Renders firewall alerts into the alerts table
function renderAlerts(alerts) {
  const tbody = document.getElementById("fw-alerts-body");
  if (!tbody) return;

  tbody.innerHTML = "";

  for (const row of alerts || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHTML(row.time || "")}</td>
      <td>${escapeHTML(row.alert_type || "")}</td>
      <td><span class="mono">${escapeHTML(row.src_ip || "")}</span></td>
      <td><span class="${badgeClass(row.severity)}">${escapeHTML(row.severity || "")}</span></td>
      <td>${escapeHTML(row.details || "")}</td>
    `;
    tbody.appendChild(tr);
  }
}

//Parses alert timestamp value
function parseAlertTime(row) {
  const raw = row.time || "";
  if (!raw) return null;

  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads current firewall alert filter values from the UI
function getAlertFilterValues() {
  return {
    timeFrom: document.getElementById("fw-alert-time-from")?.value || "",
    timeTo: document.getElementById("fw-alert-time-to")?.value || "",
    alertType: (document.getElementById("fw-alert-type-filter")?.value || "").trim().toLowerCase(),
    srcIp: (document.getElementById("fw-alert-src-filter")?.value || "").trim().toLowerCase(),
    severity: (document.getElementById("fw-alert-severity-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks whether an alert row matches the current firewall alert filters
function alertMatches(row, filters) {
  const alertType = String(row.alert_type || "").toLowerCase().trim();
  const srcIp = String(row.src_ip || "").toLowerCase().trim();
  const severity = String(row.severity || "").toLowerCase().trim();
  const rowTime = parseAlertTime(row);

  if (filters.alertType && alertType !== filters.alertType) return false;
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

//Returns filtered firewall alert rows
function filteredAlerts() {
  const alerts = PAGE_DATA?.alerts || [];
  const filters = getAlertFilterValues();
  return alerts.filter(row => alertMatches(row, filters));
}

//Refreshes firewall alert filter dropdowns based on available alert values
function refreshAlertFilterOptions() {
  const alerts = PAGE_DATA?.alerts || [];

  const alertTypes = [...new Set(
    alerts.map(row => String(row.alert_type || "").trim()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  const severities = [...new Set(
    alerts.map(row => String(row.severity || "").trim().toLowerCase()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("fw-alert-type-filter", alertTypes, "All Alert Types");
  populateDropdown("fw-alert-severity-filter", severities, "All Severities");
}

//Renders filtered firewall alerts and updates count
function renderFilteredAlerts() {
  refreshAlertFilterOptions();

  const rows = filteredAlerts();
  renderAlerts(rows);

  const count = document.getElementById("fw-alerts-count");
  if (count) {
    count.textContent = `${rows.length} alerts shown`;
  }
}

//Renders raw or normalised firewall log rows into the log table
function renderTable(columns, rows) {
  const thead = document.getElementById("fw-table-head");
  const tbody = document.getElementById("fw-table-body");
  const count = document.getElementById("fw-table-count");

  if (!thead || !tbody) return;

  thead.innerHTML = "";
  tbody.innerHTML = "";

  const headRow = document.createElement("tr");
  headRow.innerHTML = columns.map(col => `<th>${escapeHTML(col)}</th>`).join("");
  thead.appendChild(headRow);

  for (const row of rows || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = columns.map(col => {
      const value = row[col] ?? "";
      return `<td>${escapeHTML(value)}</td>`;
    }).join("");
    tbody.appendChild(tr);
  }

  if (count) {
    count.textContent = `${rows.length} rows shown`;
  }
}

//Reads current firewall log filter values from the UI
function getFilterValues() {
  return {
    timeFrom: document.getElementById("fw-time-from")?.value || "",
    timeTo: document.getElementById("fw-time-to")?.value || "",
    srcIp: (document.getElementById("fw-src-filter")?.value || "").trim().toLowerCase(),
    dstIp: (document.getElementById("fw-dst-filter")?.value || "").trim().toLowerCase(),
    port: document.getElementById("fw-port-filter")?.value || "",
    action: (document.getElementById("fw-action-filter")?.value || "").trim().toLowerCase()
  };
}

//Parses timestamp from a firewall log row
function parseRowTime(row) {
  const raw = row.timestamp || row.event_time || row.time || "";
  if (!raw) return null;

  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Checks whether a firewall log row matches the current log filters
function rowMatches(row, filters) {
  const srcIp = String(row.src_ip || "").toLowerCase();
  const dstIp = String(row.dst_ip || "").toLowerCase();
  const dstPort = String(row.dst_port || row.port || "").trim();
  const action = String(row.action || "").toLowerCase().trim();
  const rowTime = parseRowTime(row);

  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.dstIp && !dstIp.includes(filters.dstIp)) return false;
  if (filters.port && dstPort !== filters.port) return false;
  if (filters.action && action !== filters.action) return false;

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

//Returns filtered firewall log rows for the active tab
function filteredRows() {
  const rows = currentRows();
  const filters = getFilterValues();
  return rows.filter(row => rowMatches(row, filters));
}

//Populates a dropdown filter with values while preserving current selection if possible
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
  if (stillExists) {
    select.value = currentValue;
  }
}

//Refreshes firewall log filter dropdowns using values from current rows
function refreshFilterOptions() {
  const rows = currentRows();

  const ports = [...new Set(
    rows
      .map(row => String(row.dst_port || row.port || "").trim())
      .filter(Boolean)
  )].sort((a, b) => {
    const na = Number(a);
    const nb = Number(b);

    if (!Number.isNaN(na) && !Number.isNaN(nb)) return na - nb;
    return a.localeCompare(b);
  });

  const actions = [...new Set(
    rows
      .map(row => String(row.action || "").trim().toLowerCase())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("fw-port-filter", ports, "All Ports");
  populateDropdown("fw-action-filter", actions, "All Actions");
}

//Renders currently active firewall log table view
function renderActiveTab() {
  if (!PAGE_DATA) return;

  refreshFilterOptions();
  renderTable(currentColumns(), filteredRows());
}

//Wires firewall alert filters and clear button
function wireAlertFilters() {
  const ids = [
    "fw-alert-time-from",
    "fw-alert-time-to",
    "fw-alert-type-filter",
    "fw-alert-src-filter",
    "fw-alert-severity-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;

    el.addEventListener("input", renderFilteredAlerts);
    el.addEventListener("change", renderFilteredAlerts);
  });

  const clearBtn = document.getElementById("fw-clear-alert-filters");
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

//Wires raw / normalised tab switching
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

//Wires firewall log filters and clear button
function wireFilters() {
  const ids = [
    "fw-time-from",
    "fw-time-to",
    "fw-src-filter",
    "fw-dst-filter",
    "fw-port-filter",
    "fw-action-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;

    el.addEventListener("input", renderActiveTab);
    el.addEventListener("change", renderActiveTab);
  });

  const clearBtn = document.getElementById("fw-clear-filters");
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

//Wires export buttons for raw and normalised firewall CSVs
function wireExports() {
  const rawBtn = document.getElementById("btn-export-raw");
  const normBtn = document.getElementById("btn-export-normalized");

  if (rawBtn) {
    rawBtn.addEventListener("click", () => {
      window.open("/data/firewall.csv", "_blank");
    });
  }

  if (normBtn) {
    normBtn.addEventListener("click", () => {
      window.open("/outputs/firewall/normalised_firewall.csv", "_blank");
    });
  }
}

//Loads firewall page data from backend and triggers full page render
async function loadFirewallPage() {
  const data = await getJSON("/api/firewall");
  PAGE_DATA = data;

  setText("fw-total-count", data.summary?.total_logs ?? data.summary?.raw_count ?? 0);
  setText("fw-alert-count", data.summary?.alert_count ?? 0);
  setText("fw-deny-count", data.summary?.deny_count ?? 0);
  setText("fw-allow-count", data.summary?.allow_count ?? 0);

  renderFirewallActivityChart(data.log_activity || {});
  renderFilteredAlerts();
  renderActiveTab();
}

//Initialises firewall page behaviour when loaded
(async function init() {
  try {
    wireTabs();
    wireFilters();
    wireAlertFilters();
    wireExports();
    await loadFirewallPage();
  } catch (err) {
    console.error(err);
    const count = document.getElementById("fw-table-count");
    if (count) count.textContent = String(err);
  }
})();