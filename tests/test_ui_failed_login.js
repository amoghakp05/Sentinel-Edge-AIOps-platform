/**
 * tests/test_ui_failed_login.js
 * ─────────────────────────────
 * Headless regression test for dashboard UI:
 * Verifies that entering a wrong viewer token completely purges
 * previous tenant charts, tables, counters, and stored credentials from the DOM.
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const htmlPath = path.resolve(__dirname, "../dashboard/index.html");
const htmlContent = fs.readFileSync(htmlPath, "utf-8");

// Extract the script body
const scriptMatch = htmlContent.match(/<script>([\s\S]*?)<\/script>/);
if (!scriptMatch) {
  console.error("Could not find <script> block in dashboard/index.html");
  process.exit(1);
}
const scriptBody = scriptMatch[1];

// Mock sessionStorage
const storage = {};
const sessionStorage = {
  getItem: (k) => (k in storage ? storage[k] : null),
  setItem: (k, v) => { storage[k] = String(v); },
  removeItem: (k) => { delete storage[k]; },
  clear: () => { Object.keys(storage).forEach(k => delete storage[k]); },
};

// Mock DOM elements
class MockElement {
  constructor(id, tag = "div") {
    this.id = id;
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.style = {};
    this.className = "";
    this._textContent = undefined;
    this.innerText = "";
    this.value = "";
  }
  get textContent() {
    if (this._textContent !== undefined) return this._textContent;
    return this.children.map(c => c.textContent).join("");
  }
  set textContent(val) {
    this._textContent = val;
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  replaceChildren(...newChildren) {
    this.children = [...newChildren];
  }
  querySelectorAll() {
    return [];
  }
  classList = {
    add: () => {},
    remove: () => {},
    contains: () => false,
  };
  getContext() {
    return {};
  }
}

const elements = {};
function getOrCreate(id, tag = "div") {
  if (!elements[id]) {
    elements[id] = new MockElement(id, tag);
  }
  return elements[id];
}

// Pre-create standard elements expected by dashboard
[
  "viewerTokenInput", "authBadge", "sseStatus", "tenantSelect",
  "regionLabel", "latencyDisplay", "staleIndicator", "lastUpdateTime",
  "tzSelect", "countExcellent", "countGood", "countFair", "countPoor",
  "secFailedCount", "secRiskScore", "secAlertCount", "collectorSummary",
  "entityHealthBody", "collectorsBody", "incidentsBody", "historyBody",
  "securityEventsBody", "thresholdsTableBody", "remediationBody",
  "remediationAuditBody", "mockStateViewer", "chaosConsole",
  "chartCpu", "chartMem", "chartDisk", "chartLatency", "chartPacketLoss",
  "chartBandwidth", "chartConnectivity", "whyDrawer", "drawerContent"
].forEach(id => getOrCreate(id));

const documentMock = {
  getElementById: (id) => getOrCreate(id),
  createElement: (tag) => new MockElement("", tag),
  querySelectorAll: () => [],
};

const windowMock = {
  addEventListener: () => {},
};

let closedSse = false;
class MockEventSource {
  constructor(url) {
    this.url = url;
  }
  addEventListener() {}
  close() {
    closedSse = true;
  }
}

let chartInstances = [];
class MockChart {
  constructor(ctx, config) {
    this.ctx = ctx;
    this.data = config.data || { labels: [], datasets: [] };
    this.options = config.options || {};
    chartInstances.push(this);
  }
  update() {}
}

const sandbox = {
  document: documentMock,
  window: windowMock,
  sessionStorage: sessionStorage,
  EventSource: MockEventSource,
  Chart: MockChart,
  fetch: null,
  console: console,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  setInterval: setInterval,
  clearInterval: clearInterval,
  Date: Date,
  Math: Math,
  JSON: JSON,
  encodeURIComponent: encodeURIComponent,
};

// Convert top-level let to var so they attach to the sandbox global object
const runnableScript = scriptBody.replace(/\blet\s+/g, "var ");

vm.createContext(sandbox);
vm.runInContext(runnableScript, sandbox);

// ── Test Execution ────────────────────────────────────────────────────────────

// 1. Setup mock initialized state as Acme with existing rendered data
storage["sentinel_viewer_token"] = "valid-acme-viewer-token";
elements["authBadge"].textContent = "Authenticated";
elements["authBadge"].className = "badge badge-excellent";
elements["countExcellent"].innerText = "12";
elements["countGood"].innerText = "4";
elements["secFailedCount"].innerText = "8";
elements["collectorSummary"].innerText = "3 total (0 offline)";

// Populate table with Acme records
const acmeRow = documentMock.createElement("tr");
const acmeCell = documentMock.createElement("td");
acmeCell.textContent = "srv-acme-prod-01";
acmeRow.appendChild(acmeCell);
elements["entityHealthBody"].appendChild(acmeRow);

// Populate charts with data
sandbox.initCharts();
Object.values(sandbox.charts).forEach(ch => {
  if (ch && ch.data) {
    ch.data.labels = ["10:00:00", "10:01:00", "10:02:00"];
    ch.data.datasets = [
      { data: [45.2, 58.1, 72.4] },
      { data: [80, 80, 80] },
      { data: [20, 20, 20] },
    ];
  }
});

console.log("[Setup] Verified pre-existing Acme data in DOM:");
console.log(`  entityHealthBody rows: ${elements["entityHealthBody"].children.length}`);
console.log(`  chartCpu labels: ${sandbox.charts["cpu"].data.labels.length}`);
console.log(`  countExcellent: ${elements["countExcellent"].innerText}`);
console.log(`  stored token: ${storage["sentinel_viewer_token"]}`);

if (elements["entityHealthBody"].children.length === 0 || sandbox.charts["cpu"].data.labels.length === 0) {
  console.error("Test setup error: Pre-existing data not populated");
  process.exit(1);
}

// 2. User enters wrong viewer token
elements["viewerTokenInput"].value = "wrong-invalid-token";

// Mock fetch returning 401 Unauthorized for the wrong token
sandbox.fetch = async function(url, opts) {
  return {
    status: 401,
    ok: false,
    statusText: "Unauthorized",
    json: async () => ({ error: "Unauthorized: invalid viewer or collector credential" }),
  };
};

// 3. User clicks Login -> saveViewerToken() executes
sandbox.saveViewerToken().then(() => {
  console.log("\n[After Failed Login] Checking DOM purged state:");

  // Check stored token is purged
  const currentStoredToken = storage["sentinel_viewer_token"];
  console.log(`  stored token in sessionStorage: ${currentStoredToken}`);
  if (currentStoredToken !== undefined && currentStoredToken !== null) {
    console.error("FAIL: Stored token was not purged from sessionStorage!");
    process.exit(1);
  }

  // Check auth badge shows Unauthorized
  console.log(`  authBadge: ${elements["authBadge"].textContent}`);
  if (!elements["authBadge"].textContent.includes("Unauthorized")) {
    console.error("FAIL: authBadge did not update to Unauthorized");
    process.exit(1);
  }

  // Check charts emptied
  Object.entries(sandbox.charts).forEach(([key, ch]) => {
    if (ch.data.labels.length !== 0) {
      console.error(`FAIL: Chart '${key}' labels not emptied! length=${ch.data.labels.length}`);
      process.exit(1);
    }
    if (ch.data.datasets.some(ds => ds.data.length !== 0)) {
      console.error(`FAIL: Chart '${key}' dataset data not emptied!`);
      process.exit(1);
    }
  });
  console.log("  all 7 charts emptied: labels=[], datasets=[].data=[]");

  // Check counters reset to 0
  if (elements["countExcellent"].innerText !== "0" || elements["countGood"].innerText !== "0") {
    console.error("FAIL: Fleet counters not reset to 0");
    process.exit(1);
  }
  if (elements["secFailedCount"].innerText !== "0") {
    console.error("FAIL: Security counters not reset to 0");
    process.exit(1);
  }
  console.log("  all fleet and security counters reset to 0");

  // Check table contains no previous data rows (only 1 placeholder row)
  const healthRows = elements["entityHealthBody"].children;
  if (healthRows.length !== 1 || !healthRows[0].textContent.includes("Unauthorized")) {
    console.error("FAIL: entityHealthBody does not contain lone Unauthorized placeholder");
    process.exit(1);
  }
  if (healthRows[0].textContent.includes("srv-acme-prod-01")) {
    console.error("FAIL: Previous Acme entity data still present in table!");
    process.exit(1);
  }
  console.log("  entityHealthBody previous data wiped; placeholder present");

  // Check all other tables have placeholders
  [
    "collectorsBody", "incidentsBody", "historyBody", "securityEventsBody",
    "thresholdsTableBody", "remediationBody", "remediationAuditBody"
  ].forEach(tbId => {
    const rows = elements[tbId].children;
    if (rows.length !== 1 || !rows[0].textContent.includes("Unauthorized")) {
      console.error(`FAIL: Table ${tbId} does not have Unauthorized placeholder`);
      process.exit(1);
    }
  });
  console.log("  all 8 table bodies wiped and set to Unauthorized placeholder");

  console.log("\nPASS: All DOM state, charts, tables, counters, and session storage purged on failed login.");
  process.exit(0);
}).catch(err => {
  console.error("Unexpected error in saveViewerToken:", err);
  process.exit(1);
});
