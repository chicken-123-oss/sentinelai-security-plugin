const ENTRY_I18N = {
  en: {
    title: "SentinelAI Status",
    tokenPlaceholder: "Bearer token",
    load: "Load",
    openConsole: "Open Console",
    incidents: "Incidents",
    visitors: "Visitors",
    noData: "No data.",
    tokenRequired: "Paste an admin, auditor, or ingest token to load the managed-site entry.",
    online: "ONLINE",
    incidentsMetric: "Incidents",
    visitorsMetric: "Visitors",
    agentsMetric: "Agents",
    modelMetric: "Model"
  },
  "zh-CN": {
    title: "SentinelAI 状态",
    tokenPlaceholder: "Bearer Token",
    load: "加载",
    openConsole: "打开控制台",
    incidents: "事件",
    visitors: "访客",
    noData: "暂无数据。",
    tokenRequired: "请粘贴管理员、审计员或采集 Token 以加载托管网站入口。",
    online: "在线",
    incidentsMetric: "事件",
    visitorsMetric: "访客",
    agentsMetric: "代理",
    modelMetric: "模型"
  }
};

const entryState = {
  lang: localStorage.getItem("sentinelai_lang") || "en",
  token: new URLSearchParams(window.location.search).get("token") || localStorage.getItem("sentinelai_token") || "",
  summary: null
};

const entryEls = {
  token: document.getElementById("entryToken"),
  form: document.getElementById("entryAuthForm"),
  openConsole: document.getElementById("openConsoleBtn"),
  status: document.getElementById("entryStatus"),
  metrics: document.getElementById("entryMetrics"),
  incidents: document.getElementById("entryIncidents"),
  visitors: document.getElementById("entryVisitors")
};

document.querySelectorAll("[data-lang]").forEach((button) => {
  button.addEventListener("click", () => setEntryLanguage(button.dataset.lang));
});

entryEls.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  entryState.token = entryEls.token.value.trim();
  localStorage.setItem("sentinelai_token", entryState.token);
  await loadEntrySummary();
});

entryEls.openConsole.addEventListener("click", () => {
  const target = entryState.summary?.redirectButton?.url || entryState.summary?.consoleUrl || "/";
  window.location.href = target;
});

initEntry();

async function initEntry() {
  entryEls.token.value = entryState.token;
  setEntryLanguage(entryState.lang);
  if (entryState.token) {
    await loadEntrySummary();
  } else {
    entryEls.status.textContent = tEntry("tokenRequired");
    renderEntrySummary();
  }
}

function setEntryLanguage(lang) {
  entryState.lang = lang === "zh-CN" ? "zh-CN" : "en";
  localStorage.setItem("sentinelai_lang", entryState.lang);
  document.documentElement.lang = entryState.lang;
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = tEntry(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", tEntry(node.dataset.i18nPlaceholder));
  });
  document.querySelectorAll("[data-lang]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.lang === entryState.lang);
  });
  renderEntrySummary();
}

async function loadEntrySummary() {
  if (!entryState.token) {
    entryEls.status.textContent = tEntry("tokenRequired");
    return;
  }
  try {
    const response = await fetch("/api/v1/managed-site/summary", {
      headers: {
        Authorization: `Bearer ${entryState.token}`,
        "Content-Type": "application/json"
      }
    });
    const data = await response.json();
    if (!response.ok) {
      const zhMessage = [data.messageZh, data.detailsZh, data.hintZh].filter(Boolean).join(" ");
      throw new Error((entryState.lang === "zh-CN" && zhMessage) ? zhMessage : (data.error || `HTTP ${response.status}`));
    }
    entryState.summary = data;
    renderEntrySummary();
  } catch (error) {
    entryEls.status.textContent = error.message;
  }
}

function renderEntrySummary() {
  const summary = entryState.summary;
  if (!summary) {
    entryEls.metrics.innerHTML = "";
    entryEls.incidents.innerHTML = `<p class="muted">${tEntry("noData")}</p>`;
    entryEls.visitors.innerHTML = `<p class="muted">${tEntry("noData")}</p>`;
    return;
  }
  const counts = summary.status?.counts || {};
  const activeProvider = summary.activeProvider || {};
  entryEls.status.textContent = `${tEntry("online")} // ${summary.status?.version || "local"}`;
  entryEls.metrics.innerHTML = [
    metric(tEntry("incidentsMetric"), counts.incidents || 0),
    metric(tEntry("visitorsMetric"), counts.visitors || 0),
    metric(tEntry("agentsMetric"), counts.agents || (summary.agents || []).length),
    metric(tEntry("modelMetric"), activeProvider.model || "offline")
  ].join("");
  entryEls.incidents.innerHTML = renderIncidents(summary.incidents || []);
  entryEls.visitors.innerHTML = renderVisitors(summary.visitors || []);
}

function renderIncidents(items) {
  if (!items.length) return `<p class="muted">${tEntry("noData")}</p>`;
  return items.map((incident) => `
    <article class="stack-row">
      <div class="badge-line">
        <span class="badge severity-${escapeHtml(incident.severity)}">${escapeHtml(incident.severity)}</span>
        <span class="badge severity-${escapeHtml(incident.status)}">${escapeHtml(incident.status)}</span>
      </div>
      <strong>${escapeHtml(incident.title)}</strong>
      <span class="muted">${escapeHtml(incident.createdAt)}</span>
    </article>
  `).join("");
}

function renderVisitors(items) {
  if (!items.length) return `<p class="muted">${tEntry("noData")}</p>`;
  return items.map((visitor) => `
    <div class="stack-row">
      <strong>${escapeHtml(visitor.ip)}</strong>
      <span>${escapeHtml(visitor.method)} ${escapeHtml(visitor.path)}</span>
      <span class="muted">${escapeHtml(visitor.lastSeen || visitor.createdAt)} / x${escapeHtml(visitor.visitCount || 1)}</span>
    </div>
  `).join("");
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function tEntry(key) {
  return ENTRY_I18N[entryState.lang][key] || ENTRY_I18N.en[key] || key;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
