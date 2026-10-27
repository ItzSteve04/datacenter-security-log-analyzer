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

//Returns CSS badge class based on severity value
function badgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "badge badge-critical";
  if (s === "high") return "badge badge-high";
  if (s === "medium") return "badge badge-medium";
  return "badge badge-low";
}

//Stores page-wide IDS data, current active tab, and chart instance
let PAGE_DATA = null;
let ACTIVE_TAB = "raw";
let idsActivityChart = null;

//Builds and renders the IDS line chart showing total logs vs alerts over time
function renderIdsActivityChart(series) {
  const ctx = document.getElementById("ids-activity-chart");
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
        label: "Alerts",
        data: series.alert || [],
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

  if (idsActivityChart) {
    idsActivityChart.destroy();
  }

  idsActivityChart = new Chart(ctx, { type: "line", data, options });
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

//Renders IDS alerts into the alerts table
function renderAlerts(rows) {
  const tbody = document.getElementById("ids-alerts-body");
  if (!tbody) return;

  tbody.innerHTML = "";

  for (const row of rows || []) {
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

//Renders raw or normalised IDS log rows into the log table
function renderTable(columns, rows) {
  const thead = document.getElementById("ids-table-head");
  const tbody = document.getElementById("ids-table-body");
  const count = document.getElementById("ids-table-count");

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

//Populates a dropdown filter with unique values while preserving current selection if possible
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

//Returns first non-empty value from a row using a list of candidate keys
function getValue(row, keys) {
  for (const key of keys) {
    if (row[key] !== undefined && row[key] !== null && String(row[key]).trim() !== "") {
      return String(row[key]);
    }
  }
  return "";
}

//Parses timestamp from a log row
function parseRowTime(row) {
  const raw = getValue(row, ["timestamp", "event_time", "time"]);
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads current IDS log filter values from the UI
function getLogFilterValues() {
  return {
    timeFrom: document.getElementById("ids-time-from")?.value || "",
    timeTo: document.getElementById("ids-time-to")?.value || "",
    srcIp: (document.getElementById("ids-src-filter")?.value || "").trim().toLowerCase(),
    dstIp: (document.getElementById("ids-dst-filter")?.value || "").trim().toLowerCase(),
    signature: (document.getElementById("ids-signature-filter")?.value || "").trim().toLowerCase(),
    severity: (document.getElementById("ids-severity-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks whether a log row matches the current IDS log filters
function rowMatches(row, filters) {
  const srcIp = getValue(row, ["src_ip", "source_ip", "src"]).toLowerCase();
  const dstIp = getValue(row, ["dst_ip", "dest_ip", "destination_ip", "dst"]).toLowerCase();
  const signature = getValue(row, ["signature", "alert", "alert_type", "message", "msg"]).toLowerCase();
  const severity = getValue(row, ["severity", "priority"]).toLowerCase();
  const rowTime = parseRowTime(row);

  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.dstIp && !dstIp.includes(filters.dstIp)) return false;
  if (filters.signature && !signature.includes(filters.signature)) return false;
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

//Returns filtered IDS log rows for the active tab
function filteredRows() {
  const rows = currentRows();
  const filters = getLogFilterValues();
  return rows.filter(row => rowMatches(row, filters));
}

//Refreshes IDS log filter dropdown values based on current data
function refreshLogFilterOptions() {
  const rows = currentRows();

  const severities = [...new Set(
    rows
      .map(row => getValue(row, ["severity", "priority"]).trim().toLowerCase())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("ids-severity-filter", severities, "All Severities");
}

//Renders currently active log table view
function renderActiveTab() {
  if (!PAGE_DATA) return;
  refreshLogFilterOptions();
  renderTable(currentColumns(), filteredRows());
}

//Parses alert timestamp value
function parseAlertTime(row) {
  const raw = row.time || "";
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads current IDS alert filter values from the UI
function getAlertFilterValues() {
  return {
    timeFrom: document.getElementById("ids-alert-time-from")?.value || "",
    timeTo: document.getElementById("ids-alert-time-to")?.value || "",
    alertType: (document.getElementById("ids-alert-type-filter")?.value || "").trim().toLowerCase(),
    srcIp: (document.getElementById("ids-alert-src-filter")?.value || "").trim().toLowerCase(),
    severity: (document.getElementById("ids-alert-severity-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks whether an alert row matches the current IDS alert filters
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

//Returns filtered IDS alert rows
function filteredAlerts() {
  const alerts = PAGE_DATA?.alerts || [];
  const filters = getAlertFilterValues();
  return alerts.filter(row => alertMatches(row, filters));
}

//Refreshes IDS alert filter dropdowns based on available alert values
function refreshAlertFilterOptions() {
  const alerts = PAGE_DATA?.alerts || [];

  const alertTypes = [...new Set(
    alerts.map(row => String(row.alert_type || "").trim()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  const severities = [...new Set(
    alerts.map(row => String(row.severity || "").trim().toLowerCase()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("ids-alert-type-filter", alertTypes, "All Alert Types");
  populateDropdown("ids-alert-severity-filter", severities, "All Severities");
}

//Renders filtered IDS alerts and updates count
function renderFilteredAlerts() {
  refreshAlertFilterOptions();

  const rows = filteredAlerts();
  renderAlerts(rows);

  const count = document.getElementById("ids-alerts-count");
  if (count) count.textContent = `${rows.length} alerts shown`;
}

//Wires tab switching between raw and normalized IDS logs
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

//Wires all IDS log filter inputs and clear button
function wireLogFilters() {
  const ids = [
    "ids-time-from",
    "ids-time-to",
    "ids-src-filter",
    "ids-dst-filter",
    "ids-signature-filter",
    "ids-severity-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", renderActiveTab);
    el.addEventListener("change", renderActiveTab);
  });

  const clearBtn = document.getElementById("ids-clear-filters");
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

//Wires IDS alert filter inputs and clear button
function wireAlertFilters() {
  const ids = [
    "ids-alert-time-from",
    "ids-alert-time-to",
    "ids-alert-type-filter",
    "ids-alert-src-filter",
    "ids-alert-severity-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", renderFilteredAlerts);
    el.addEventListener("change", renderFilteredAlerts);
  });

  const clearBtn = document.getElementById("ids-clear-alert-filters");
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

//Wires export buttons for raw and normalised IDS CSVs
function wireExports() {
  const rawBtn = document.getElementById("btn-export-raw");
  const normBtn = document.getElementById("btn-export-normalized");

  if (rawBtn) {
    rawBtn.addEventListener("click", () => {
      window.open("/data/ids.csv", "_blank");
    });
  }

  if (normBtn) {
    normBtn.addEventListener("click", () => {
      window.open("/outputs/ids/normalised_ids.csv", "_blank");
    });
  }
}

//Loads IDS page data from backend and triggers full page render
async function loadIdsPage() {
  const data = await getJSON("/api/ids");
  PAGE_DATA = data;

  setText("ids-total-count", data.summary?.total_logs ?? data.summary?.raw_count ?? 0);
  setText("ids-alert-count", data.summary?.alert_count ?? 0);
  setText("ids-high-count", data.summary?.high_alert_count ?? 0);
  setText("ids-low-count", data.summary?.low_alert_count ?? 0);

  renderIdsActivityChart(data.log_activity || {});
  renderFilteredAlerts();
  renderActiveTab();
}

//Initialises IDS page behaviour when loaded
(async function init() {
  try {
    wireTabs();
    wireLogFilters();
    wireAlertFilters();
    wireExports();
    await loadIdsPage();
  } catch (err) {
    console.error(err);
    const count = document.getElementById("ids-table-count");
    if (count) count.textContent = String(err);
  }
})();