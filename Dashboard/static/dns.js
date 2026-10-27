//Fetches JSON data from backend and handles errors or non-JSON responses
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

//Escapes HTML characters to prevent rendering issues or injection
function escapeHTML(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

//Updates text content of an element by ID
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

//Returns CSS class for severity badge styling
function badgeClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "badge badge-critical";
  if (s === "high") return "badge badge-high";
  if (s === "medium") return "badge badge-medium";
  return "badge badge-low";
}

//Stores page-wide DNS data, current tab state, and chart instance
let PAGE_DATA = null;
let ACTIVE_TAB = "raw";
let dnsActivityChart = null;

//Builds and renders DNS activity chart (total logs vs alerts over time)
function renderDnsActivityChart(series) {
  const ctx = document.getElementById("dns-activity-chart");
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
        borderColor: "#c52222",
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

  if (dnsActivityChart) {
    dnsActivityChart.destroy();
  }

  dnsActivityChart = new Chart(ctx, { type: "line", data, options });
}

//Returns rows based on active tab (raw or normalized DNS logs)
function currentRows() {
  if (!PAGE_DATA) return [];
  return ACTIVE_TAB === "raw"
    ? (PAGE_DATA.raw_rows || [])
    : (PAGE_DATA.normalized_rows || []);
}

//Returns table columns based on active tab
function currentColumns() {
  if (!PAGE_DATA) return [];
  return ACTIVE_TAB === "raw"
    ? (PAGE_DATA.raw_columns || [])
    : (PAGE_DATA.normalized_columns || []);
}

//Renders DNS alerts into the alerts table
function renderAlerts(rows) {
  const tbody = document.getElementById("dns-alerts-body");
  if (!tbody) return;

  tbody.innerHTML = "";

  for (const row of rows || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHTML(row.time || "")}</td>
      <td>${escapeHTML(row.alert_type || "")}</td>
      <td><span class="mono">${escapeHTML(row.src_ip || "")}</span></td>
      <td>${escapeHTML(row.domain || "")}</td>
      <td><span class="${badgeClass(row.severity)}">${escapeHTML(row.severity || "")}</span></td>
      <td>${escapeHTML(row.details || "")}</td>
    `;
    tbody.appendChild(tr);
  }
}

//Renders DNS log table (raw or normalized)
function renderTable(columns, rows) {
  const thead = document.getElementById("dns-table-head");
  const tbody = document.getElementById("dns-table-body");
  const count = document.getElementById("dns-table-count");

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

//Populates dropdown filters with available values
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

//Gets first available value from multiple possible field names (handles schema differences)
function getValue(row, keys) {
  for (const key of keys) {
    if (row[key] !== undefined && row[key] !== null && String(row[key]).trim() !== "") {
      return String(row[key]);
    }
  }
  return "";
}

//Parses timestamp from DNS log row
function parseRowTime(row) {
  const raw = getValue(row, ["timestamp", "event_time", "time"]);
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads current DNS log filter values from UI
function getLogFilterValues() {
  return {
    timeFrom: document.getElementById("dns-time-from")?.value || "",
    timeTo: document.getElementById("dns-time-to")?.value || "",
    srcIp: (document.getElementById("dns-src-filter")?.value || "").trim().toLowerCase(),
    domain: (document.getElementById("dns-domain-filter")?.value || "").trim().toLowerCase(),
    queryType: (document.getElementById("dns-query-type-filter")?.value || "").trim().toLowerCase(),
    response: (document.getElementById("dns-response-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks if a DNS log row matches filter conditions
function rowMatches(row, filters) {
  const srcIp = getValue(row, ["src_ip", "source_ip", "ip"]).toLowerCase();
  const domain = getValue(row, ["query", "domain", "qname", "hostname"]).toLowerCase();
  const queryType = getValue(row, ["query_type", "qtype", "type"]).toLowerCase();
  const response = getValue(row, ["response_code", "rcode", "answer", "status"]).toLowerCase();
  const rowTime = parseRowTime(row);

  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.domain && !domain.includes(filters.domain)) return false;
  if (filters.queryType && queryType !== filters.queryType) return false;
  if (filters.response && response !== filters.response) return false;

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

//Returns filtered DNS log rows
function filteredRows() {
  const rows = currentRows();
  const filters = getLogFilterValues();
  return rows.filter(row => rowMatches(row, filters));
}

//Refreshes dropdown options for DNS log filters
function refreshLogFilterOptions() {
  const rows = currentRows();

  const queryTypes = [...new Set(
    rows
      .map(row => getValue(row, ["query_type", "qtype", "type"]).trim().toLowerCase())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  const responses = [...new Set(
    rows
      .map(row => getValue(row, ["response_code", "rcode", "answer", "status"]).trim().toLowerCase())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("dns-query-type-filter", queryTypes, "All Query Types");
  populateDropdown("dns-response-filter", responses, "All Response Codes");
}

//Renders active DNS tab (raw/normalized logs)
function renderActiveTab() {
  if (!PAGE_DATA) return;
  refreshLogFilterOptions();
  renderTable(currentColumns(), filteredRows());
}

//Parses alert timestamp
function parseAlertTime(row) {
  const raw = row.time || "";
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

//Reads DNS alert filter values from UI
function getAlertFilterValues() {
  return {
    timeFrom: document.getElementById("dns-alert-time-from")?.value || "",
    timeTo: document.getElementById("dns-alert-time-to")?.value || "",
    alertType: (document.getElementById("dns-alert-type-filter")?.value || "").trim().toLowerCase(),
    srcIp: (document.getElementById("dns-alert-src-filter")?.value || "").trim().toLowerCase(),
    domain: (document.getElementById("dns-alert-domain-filter")?.value || "").trim().toLowerCase(),
    severity: (document.getElementById("dns-alert-severity-filter")?.value || "").trim().toLowerCase()
  };
}

//Checks if alert matches DNS alert filters
function alertMatches(row, filters) {
  const alertType = String(row.alert_type || "").toLowerCase().trim();
  const srcIp = String(row.src_ip || "").toLowerCase().trim();
  const domain = String(row.domain || "").toLowerCase().trim();
  const severity = String(row.severity || "").toLowerCase().trim();
  const rowTime = parseAlertTime(row);

  if (filters.alertType && alertType !== filters.alertType) return false;
  if (filters.srcIp && !srcIp.includes(filters.srcIp)) return false;
  if (filters.domain && !domain.includes(filters.domain)) return false;
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

//Returns filtered DNS alerts
function filteredAlerts() {
  const alerts = PAGE_DATA?.alerts || [];
  const filters = getAlertFilterValues();
  return alerts.filter(row => alertMatches(row, filters));
}

//Refreshes DNS alert filter dropdowns
function refreshAlertFilterOptions() {
  const alerts = PAGE_DATA?.alerts || [];

  const alertTypes = [...new Set(
    alerts.map(row => String(row.alert_type || "").trim()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  const severities = [...new Set(
    alerts.map(row => String(row.severity || "").trim().toLowerCase()).filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));

  populateDropdown("dns-alert-type-filter", alertTypes, "All Alert Types");
  populateDropdown("dns-alert-severity-filter", severities, "All Severities");
}

//Renders filtered DNS alerts and updates count
function renderFilteredAlerts() {
  refreshAlertFilterOptions();

  const rows = filteredAlerts();
  renderAlerts(rows);

  const count = document.getElementById("dns-alerts-count");
  if (count) count.textContent = `${rows.length} alerts shown`;
}

//Wires tab switching between raw and normalized DNS logs
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

//Wires DNS log filters and clear button
function wireLogFilters() {
  const ids = [
    "dns-time-from",
    "dns-time-to",
    "dns-src-filter",
    "dns-domain-filter",
    "dns-query-type-filter",
    "dns-response-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", renderActiveTab);
    el.addEventListener("change", renderActiveTab);
  });

  const clearBtn = document.getElementById("dns-clear-filters");
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

//Wires DNS alert filters and clear button
function wireAlertFilters() {
  const ids = [
    "dns-alert-time-from",
    "dns-alert-time-to",
    "dns-alert-type-filter",
    "dns-alert-src-filter",
    "dns-alert-domain-filter",
    "dns-alert-severity-filter"
  ];

  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", renderFilteredAlerts);
    el.addEventListener("change", renderFilteredAlerts);
  });

  const clearBtn = document.getElementById("dns-clear-alert-filters");
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

//Wires export buttons for DNS CSV downloads
function wireExports() {
  const rawBtn = document.getElementById("btn-export-raw");
  const normBtn = document.getElementById("btn-export-normalized");

  if (rawBtn) {
    rawBtn.addEventListener("click", () => {
      window.open("/data/dns.csv", "_blank");
    });
  }

  if (normBtn) {
    normBtn.addEventListener("click", () => {
      window.open("/outputs/dns/normalised_dns.csv", "_blank");
    });
  }
}

//Loads DNS page data from backend and triggers full render
async function loadDnsPage() {
  const data = await getJSON("/api/dns");
  PAGE_DATA = data;

  setText("dns-total-count", data.summary?.total_logs ?? data.summary?.raw_count ?? 0);
  setText("dns-alert-count", data.summary?.alert_count ?? 0);
  setText("dns-high-count", data.summary?.high_alert_count ?? 0);
  setText("dns-low-count", data.summary?.low_alert_count ?? 0);

  renderDnsActivityChart(data.log_activity || {});
  renderFilteredAlerts();
  renderActiveTab();
}

//Initialises DNS page behaviour on load
(async function init() {
  try {
    wireTabs();
    wireLogFilters();
    wireAlertFilters();
    wireExports();
    await loadDnsPage();
  } catch (err) {
    console.error(err);
    const count = document.getElementById("dns-table-count");
    if (count) count.textContent = String(err);
  }
})();